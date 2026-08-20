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

	goEvents     map[uint64][]Event // k=goid,v=[]event
	goEventStack map[uint64]uint64

	// argMu guards goArgs, which is written by the arg-dispatch goroutine
	// (handleArg) and read by the event-handling goroutine (nextArg).
	argMu  sync.RWMutex
	goArgs map[uint64]chan bpf.GoftraceArgData

	// agg holds per-function clustering statistics keyed by function name.
	agg map[string]*funcAgg

	bootTime time.Time
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
		elf:          elf,
		argCh:        ch,
		uprobes:      uprobesMap,
		drilldown:    drilldown,
		trimprefix:   trimprefix,
		cluster:      cluster,
		goEvents:     map[uint64][]Event{},
		goEventStack: map[uint64]uint64{},
		goArgs:       map[uint64]chan bpf.GoftraceArgData{},
		agg:          map[string]*funcAgg{},
		bootTime:     bootTime,
	}
	go m.handleArg()
	return m, err
}

// dispatches events belonging to the same goroutine to the same channel key'd by goid
func (m *EventManager) handleArg() {
	for arg := range m.argCh {
		ch := m.ensureArgChan(arg.Goid)
		log.Debugf("add arg %+v", arg)
		ch <- arg
	}
}

// ensureArgChan returns the per-goroutine arg channel, creating it lazily if
// it does not yet exist.
func (m *EventManager) ensureArgChan(goid uint64) chan bpf.GoftraceArgData {
	m.argMu.RLock()
	ch := m.goArgs[goid]
	m.argMu.RUnlock()
	if ch != nil {
		return ch
	}

	m.argMu.Lock()
	defer m.argMu.Unlock()
	// double-checked locking: another goroutine may have created it between
	// the RUnlock above and the Lock here.
	if ch = m.goArgs[goid]; ch == nil {
		ch = make(chan bpf.GoftraceArgData, 1000)
		m.goArgs[goid] = ch
	}
	return ch
}

// argChan returns the per-goroutine arg channel, or nil if it has not been
// created yet.
func (m *EventManager) argChan(goid uint64) chan bpf.GoftraceArgData {
	m.argMu.RLock()
	defer m.argMu.RUnlock()
	return m.goArgs[goid]
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
