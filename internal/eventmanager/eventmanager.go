package eventmanager

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/elastic/go-sysinfo"
	"github.com/hitzhangjie/go-ftrace/elf"
	"github.com/hitzhangjie/go-ftrace/internal/bpf"
	"github.com/hitzhangjie/go-ftrace/internal/uprobe"
)

// event.Location values, aligned with internal/bpf/ftrace.c (ENTPOINT/RETPOINT).
const (
	eventLocationEntry         uint8 = 0 // function entry
	eventLocationRet           uint8 = 1 // function return
	eventLocationGoroutineExit uint8 = 2 // goroutine exit

	traceFlagStart uint8 = 1
	traceFlagEnd   uint8 = 2
	traceFlagAbort uint8 = 4

	maxAggregatePIDs       = 64
	maxAggregateRetvals    = 64
	maxAggregateSuppressed = 10000
	estimatedEventBytes    = 2048
	aggEventBudgetDiv      = 4
)

// Event represents a func enter/ret event, see ftrace.c event
type Event struct {
	bpf.GoftraceEvent
	uprobe    *uprobe.Uprobe
	argString string
}

type traceKey struct {
	pid  uint32
	goid uint64
}

// EventManager manages events
type EventManager struct {
	elf     *elf.ELF
	uprobes map[string]uprobe.Uprobe

	drilldown  string
	trimprefix string
	aggregate  bool

	// adaptive enables the memory backpressure applied in every mode: root-call
	// sampling (with the denominator driven by userspace heap usage), a hard cap
	// on in-flight events, and LRU eviction of stale per-pid state. aggregate
	// only changes the output (aggregated summary vs per-call stack printing).
	adaptive bool

	// pidMu guards pids, which is lazily populated as new process instances
	// are observed. Each process maintains its own complete set of
	// goroutine-local state so that goroutine IDs (which reset per-process)
	// never collide across processes.
	pidMu sync.RWMutex
	pids  map[uint32]*pidState
	seq   uint64

	maxPendingEvents  uint64
	pendingEvents     uint64
	droppedStacks     uint64
	droppedIncomplete uint64
	droppedAborted    uint64
	droppedOverBudget uint64
	evictedPIDs       uint64
	suppressed        map[traceKey]struct{}

	bootTime time.Time
}

// pidState holds the complete goroutine-local tracing state of a single
// process. All the maps that were previously keyed by goid alone now live
// under a per-pid instance, keeping storage organized by process hierarchy
// instead of a flat (pid, goid) composite key.
type pidState struct {
	goEvents     map[uint64][]Event // k=goid,v=[]event
	goEventStack map[uint64][]uint64
	invalid      map[uint64]bool
	lastSeen     uint64

	// agg holds per-function aggregation statistics keyed by function name.
	// Aggregation is scoped per-pid so concurrently running processes do not
	// mix latency/return-value distributions. PID reuse remains a known boundary.
	agg map[string]*funcAgg
}

func newPidState() *pidState {
	return &pidState{
		goEvents:     map[uint64][]Event{},
		goEventStack: map[uint64][]uint64{},
		invalid:      map[uint64]bool{},
		agg:          map[string]*funcAgg{},
	}
}

// pidState returns the per-process state for pid, creating it lazily on first
// use. It is safe for concurrent use from both the arg-dispatch goroutine and
// the event-handling goroutine.
func (m *EventManager) existingPidState(pid uint32) *pidState {
	m.pidMu.RLock()
	defer m.pidMu.RUnlock()
	return m.pids[pid]
}

func (m *EventManager) pidState(pid uint32) *pidState {
	m.pidMu.Lock()
	defer m.pidMu.Unlock()

	m.seq++
	if s := m.pids[pid]; s != nil {
		s.lastSeen = m.seq
		return s
	}

	if m.adaptive && len(m.pids) >= maxAggregatePIDs {
		var oldestPID uint32
		var oldest *pidState
		for candidatePID, candidate := range m.pids {
			if oldest == nil || candidate.lastSeen < oldest.lastSeen {
				oldestPID, oldest = candidatePID, candidate
			}
		}
		if oldest != nil {
			var released uint64
			for _, events := range oldest.goEvents {
				released += uint64(len(events))
			}
			if released >= m.pendingEvents {
				m.pendingEvents = 0
			} else {
				m.pendingEvents -= released
			}
			delete(m.pids, oldestPID)
			for key := range m.suppressed {
				if key.pid == oldestPID {
					delete(m.suppressed, key)
				}
			}
			m.evictedPIDs++
		}
	}

	s := newPidState()
	s.lastSeen = m.seq
	m.pids[pid] = s
	return s
}

// snapshotPids returns a snapshot of the current per-process states. It is
// used only at shutdown (PrintRemaining) after the event loop has stopped, so
// the returned map is stable.
func (m *EventManager) snapshotPids() map[uint32]*pidState {
	m.pidMu.RLock()
	defer m.pidMu.RUnlock()
	out := make(map[uint32]*pidState, len(m.pids))
	for pid, s := range m.pids {
		out[pid] = s
	}
	return out
}

// latencyBuckets defines the upper bound (inclusive) of each latency histogram
// bucket. The final overflow bucket captures durations larger than the last
// edge.
var latencyBuckets = []struct {
	edge  time.Duration
	label string
}{
	{1 * time.Microsecond, "<=1us"},
	{10 * time.Microsecond, "<=10us"},
	{100 * time.Microsecond, "<=100us"},
	{1 * time.Millisecond, "<=1ms"},
	{10 * time.Millisecond, "<=10ms"},
	{100 * time.Millisecond, "<=100ms"},
	{1 * time.Second, "<=1s"},
	{10 * time.Second, "<=10s"},
}

// funcAgg accumulates aggregation statistics for a single traced function.
type retvalCount struct {
	count         uint64
	weightedCount uint64
	weightedError uint64
}

type funcAgg struct {
	calls             uint64
	weightedCalls     uint64
	latencies         []uint64 // len(latencyBuckets)+1, last element is the overflow bucket
	weightedLatencies []uint64
	retvals           map[string]retvalCount
}

func newFuncAgg() *funcAgg {
	return &funcAgg{
		latencies:         make([]uint64, len(latencyBuckets)+1),
		weightedLatencies: make([]uint64, len(latencyBuckets)+1),
		retvals:           map[string]retvalCount{},
	}
}

// New create a new EventManager, which receives events via `ch`
func New(uprobes []uprobe.Uprobe, elf *elf.ELF, drilldown, trimprefix string, aggregate, adaptive bool, memoryLimit uint64) (_ *EventManager, err error) {
	host, err := sysinfo.Host()
	if err != nil {
		return
	}
	bootTime := host.Info().BootTime
	uprobesMap := map[string]uprobe.Uprobe{}
	for _, up := range uprobes {
		uprobesMap[fmt.Sprintf("%s+%d", up.Funcname, up.RelOffset)] = up
	}
	m := &EventManager{
		elf:        elf,
		uprobes:    uprobesMap,
		drilldown:  drilldown,
		trimprefix: trimprefix,
		aggregate:  aggregate,
		adaptive:   adaptive,
		pids:       map[uint32]*pidState{},
		suppressed: map[traceKey]struct{}{},
		bootTime:   bootTime,
	}
	if adaptive {
		m.maxPendingEvents = memoryLimit / aggEventBudgetDiv / estimatedEventBytes
		if m.maxPendingEvents == 0 {
			m.maxPendingEvents = 1
		}
	}
	return m, err
}

// GetUprobe returns the uprobe of the given event
func (m *EventManager) GetUprobe(event bpf.GoftraceEvent) (_ uprobe.Uprobe, err error) {
	syms, offset, err := m.elf.ResolveAddress(event.Ip)
	if err != nil {
		return
	}
	for _, sym := range syms {
		uprobe, ok := m.uprobes[fmt.Sprintf("%s+%d", sym.Name, offset)]
		if ok {
			return uprobe, nil
		}
	}
	err = errors.New("uprobe not found")
	return
}
