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
	log "github.com/sirupsen/logrus"
)

// event.Location values, aligned with internal/bpf/ftrace.c (ENTPOINT/RETPOINT).
const (
	eventLocationEntry         uint8 = 0 // function entry
	eventLocationRet           uint8 = 1 // function return
	eventLocationGoroutineExit uint8 = 2 // goroutine exit
)

// Event represents a func enter/ret event, see ftrace.c event
type Event struct {
	bpf.GoftraceEvent
	uprobe    *uprobe.Uprobe
	argString string
}

// EventManager manages events
type EventManager struct {
	elf     *elf.ELF
	argCh   <-chan bpf.GoftraceArgData
	uprobes map[string]uprobe.Uprobe

	drilldown  string
	trimprefix string
	cluster    bool

	// pidMu guards pids, which is lazily populated as new process instances
	// are observed. Each process maintains its own complete set of
	// goroutine-local state so that goroutine IDs (which reset per-process)
	// never collide across processes.
	pidMu sync.RWMutex
	pids  map[uint32]*pidState

	bootTime time.Time
}

// pidState holds the complete goroutine-local tracing state of a single
// process. All the maps that were previously keyed by goid alone now live
// under a per-pid instance, keeping storage organized by process hierarchy
// instead of a flat (pid, goid) composite key.
type pidState struct {
	goEvents     map[uint64][]Event // k=goid,v=[]event
	goEventStack map[uint64]uint64

	// argMu guards goArgs, which is written by the arg-dispatch goroutine
	// (handleArg) and read by the event-handling goroutine (nextArg).
	argMu  sync.RWMutex
	goArgs map[uint64]chan bpf.GoftraceArgData

	// agg holds per-function clustering statistics keyed by function name.
	// Clustering is scoped per-pid so that the summary never mixes the
	// latency/return-value distributions of different process instances.
	agg map[string]*funcAgg
}

func newPidState() *pidState {
	return &pidState{
		goEvents:     map[uint64][]Event{},
		goEventStack: map[uint64]uint64{},
		goArgs:       map[uint64]chan bpf.GoftraceArgData{},
		agg:          map[string]*funcAgg{},
	}
}

// pidState returns the per-process state for pid, creating it lazily on first
// use. It is safe for concurrent use from both the arg-dispatch goroutine and
// the event-handling goroutine.
func (m *EventManager) pidState(pid uint32) *pidState {
	m.pidMu.RLock()
	s := m.pids[pid]
	m.pidMu.RUnlock()
	if s != nil {
		return s
	}

	m.pidMu.Lock()
	defer m.pidMu.Unlock()
	if s = m.pids[pid]; s == nil {
		s = newPidState()
		m.pids[pid] = s
	}
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

// funcAgg accumulates clustering statistics for a single traced function.
type funcAgg struct {
	calls     uint64
	latencies []uint64 // len(latencyBuckets)+1, last element is the overflow bucket
	retvals   map[string]uint64
}

func newFuncAgg() *funcAgg {
	return &funcAgg{
		latencies: make([]uint64, len(latencyBuckets)+1),
		retvals:   map[string]uint64{},
	}
}

// New create a new EventManager, which receives events via `ch`
func New(uprobes []uprobe.Uprobe, elf *elf.ELF, ch <-chan bpf.GoftraceArgData, drilldown, trimprefix string, cluster bool) (_ *EventManager, err error) {
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
		argCh:      ch,
		uprobes:    uprobesMap,
		drilldown:  drilldown,
		trimprefix: trimprefix,
		cluster:    cluster,
		pids:       map[uint32]*pidState{},
		bootTime:   bootTime,
	}
	go m.handleArg()
	return m, err
}

// dispatches arguments to the per-goroutine channel of the process they belong
// to. args are keyed by (pid, goid) via the per-pid state hierarchy.
func (m *EventManager) handleArg() {
	for arg := range m.argCh {
		ch := m.pidState(arg.Pid).ensureArgChan(arg.Goid)
		log.Debugf("add arg %+v", arg)
		ch <- arg
	}
}

// ensureArgChan returns the per-goroutine arg channel of the given process,
// creating it lazily if it does not yet exist.
func (s *pidState) ensureArgChan(goid uint64) chan bpf.GoftraceArgData {
	s.argMu.RLock()
	ch := s.goArgs[goid]
	s.argMu.RUnlock()
	if ch != nil {
		return ch
	}

	s.argMu.Lock()
	defer s.argMu.Unlock()
	// double-checked locking: another goroutine may have created it between
	// the RUnlock above and the Lock here.
	if ch = s.goArgs[goid]; ch == nil {
		ch = make(chan bpf.GoftraceArgData, 1000)
		s.goArgs[goid] = ch
	}
	return ch
}

// argChan returns the per-goroutine arg channel of the given process, or nil
// if it has not been created yet.
func (s *pidState) argChan(goid uint64) chan bpf.GoftraceArgData {
	s.argMu.RLock()
	defer s.argMu.RUnlock()
	return s.goArgs[goid]
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
