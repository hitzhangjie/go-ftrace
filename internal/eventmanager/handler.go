package eventmanager

import (
	"fmt"
	"strings"
	"time"
	"unsafe"

	"github.com/hitzhangjie/go-ftrace/internal/bpf"
	up "github.com/hitzhangjie/go-ftrace/internal/uprobe"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// Handle handles the event
func (m *EventManager) Handle(event bpf.GoftraceEvent) error {
	// goroutine 退出事件：回收该 goroutine 的残留调用栈。
	if event.Location == eventLocationGoroutineExit {
		m.onGoroutineExit(event.Pid, event.Goid)
		return nil
	}
	if m.adaptive && event.TraceFlags&traceFlagAbort != 0 {
		delete(m.suppressed, traceKey{pid: event.Pid, goid: event.Goid})
		m.dropStack(event.Pid, event.Goid)
		m.droppedStacks++
		m.droppedAborted++
		return nil
	}
	if !m.Add(event) {
		return nil
	}
	log.Debugf("added event: %+v", event)
	if m.CloseStack(event) {
		// 有错没错都要清空栈
		defer m.ClearStack(event)

		// 聚合模式：不再逐条打印调用栈，而是按函数聚合延迟与返回值分布，
		// 避免高频调用刷屏，同时降低与 grep/tee 等管道结合时的内存占用。
		if m.aggregate {
			s := m.pidState(event.Pid)
			if s.invalid[event.Goid] || len(s.goEventStack[event.Goid]) != 0 {
				m.droppedStacks++
				m.droppedIncomplete++
				return nil
			}
			m.AggregateStack(event.Pid, event.Goid)
			return nil
		}

		var needPrint bool

		// drilldown特定函数
		if m.drilldown == "" {
			needPrint = true
		} else {
			syms, _, err := m.elf.ResolveAddress(event.Ip)
			if err != nil {
				return err
			}
			fnName := syms[0].Name
			needPrint = (fnName == m.drilldown)
		}

		if !needPrint {
			return nil
		}
		return m.PrintStack(event.Pid, event.Goid)
	}
	return nil
}

func (m *EventManager) resetStaleSample(event bpf.GoftraceEvent) {
	if event.TraceFlags&traceFlagStart == 0 {
		return
	}
	if s := m.existingPidState(event.Pid); s != nil && len(s.goEvents[event.Goid]) > 0 {
		m.dropStack(event.Pid, event.Goid)
		m.droppedStacks++
		m.droppedIncomplete++
	}
}

func (m *EventManager) Add(event bpf.GoftraceEvent) bool {
	key := traceKey{pid: event.Pid, goid: event.Goid}
	if m.adaptive {
		m.resetStaleSample(event)
		if _, ok := m.suppressed[key]; ok {
			if event.TraceFlags&traceFlagStart != 0 {
				delete(m.suppressed, key)
			} else {
				if event.TraceFlags&traceFlagEnd != 0 {
					delete(m.suppressed, key)
				}
				return false
			}
		}
		if m.pendingEvents >= m.maxPendingEvents {
			m.dropStack(event.Pid, event.Goid)
			if event.TraceFlags&traceFlagEnd == 0 {
				if len(m.suppressed) >= maxAggregateSuppressed {
					for suppressedKey := range m.suppressed {
						delete(m.suppressed, suppressedKey)
					}
				}
				m.suppressed[key] = struct{}{}
			}
			m.droppedStacks++
			m.droppedOverBudget++
			return false
		}
	}

	// Resolve the probe before rendering its argument leaves embedded in this event.
	probe, err := m.GetUprobe(event)
	if err != nil {
		log.Errorf("failed to get uprobe for event %+v: %+v", event, err)
		return false
	}
	up.BindInterfaceMemory(probe.Values, processMemoryReader(event.Pid))

	s := m.pidState(event.Pid)
	length := len(s.goEvents[event.Goid])
	if length == 0 {
		if event.Location != eventLocationEntry {
			// Orphaned return: its arguments are part of this same event record, so
			// dropping it cannot desynchronize subsequent events.
			return false
		}
		if m.adaptive && event.TraceFlags&traceFlagStart == 0 {
			// The root entry was lost or deliberately suppressed. Do not retain a
			// partial nested call tree that can never be trusted as a sample.
			return false
		}
	}
	if length > 0 {
		lastEvent := s.goEvents[event.Goid][length-1]
		if lastEvent.Location == event.Location && lastEvent.Ip == event.Ip && lastEvent.Bp != event.CallerBp {
			// duplicated entry event due to stack expansion/shrinkage
			log.Debugf("duplicated entry event: %+v", event)
			s.goEvents[event.Goid][length-1].GoftraceEvent = event
			return true
		}
	}

	argString := renderEventArgs(probe, event)
	s.goEvents[event.Goid] = append(s.goEvents[event.Goid], Event{
		GoftraceEvent: event,
		uprobe:        &probe,
		argString:     argString,
	})
	if m.adaptive {
		m.pendingEvents++
	}
	m.updateObservedStack(s, event, probe)
	return true
}

func (m *EventManager) updateObservedStack(s *pidState, event bpf.GoftraceEvent, probe up.Uprobe) {
	switch event.Location {
	case eventLocationEntry:
		s.goEventStack[event.Goid] = append(s.goEventStack[event.Goid], event.Ip)
	case eventLocationRet:
		stack := s.goEventStack[event.Goid]
		if m.aggregate && (len(stack) == 0 || stack[len(stack)-1] != probe.Address-probe.RelOffset) {
			s.invalid[event.Goid] = true
		} else if len(stack) > 0 {
			s.goEventStack[event.Goid] = stack[:len(stack)-1]
		}
	}
}

func renderEventArgs(uprobe up.Uprobe, event bpf.GoftraceEvent) string {
	expected := len(uprobe.FetchArgs)
	actual := int(event.ArgCount)
	if actual != expected || actual > len(event.Args) {
		log.Warnf("drop arguments for %s: event contains %d leaves, expected %d", uprobe.Funcname, actual, expected)
		return "<unavailable>"
	}

	leafData := make([]up.LeafData, actual)
	for i := 0; i < actual; i++ {
		arg := event.Args[i]
		leafData[i] = up.LeafData{
			Data:        arg.Data[:],
			IsNil:       arg.IsNil != 0,
			Unavailable: arg.ReadError != 0,
		}
	}

	if len(uprobe.Values) > 0 {
		return up.RenderValues(uprobe.Values, leafData)
	}

	args := make([]string, 0, actual)
	for i, fetchArg := range uprobe.FetchArgs {
		if i > 0 {
			args = append(args, ", ")
		}
		value := "<unavailable>"
		if !leafData[i].Unavailable {
			value = fetchArg.SprintValue(leafData[i].Data)
		}
		args = append(args, fetchArg.Varname, "=", value)
	}
	return strings.Join(args, "")
}

func processMemoryReader(pid uint32) func(uint64, []byte) error {
	return func(addr uint64, dst []byte) error {
		if len(dst) == 0 {
			return nil
		}
		local := unix.Iovec{Base: (*byte)(unsafe.Pointer(&dst[0]))}
		local.SetLen(len(dst))
		n, err := unix.ProcessVMReadv(int(pid), []unix.Iovec{local}, []unix.RemoteIovec{{Base: uintptr(addr), Len: len(dst)}}, 0)
		if err != nil {
			return err
		}
		if n != len(dst) {
			return fmt.Errorf("short process memory read: got %d, want %d", n, len(dst))
		}
		return nil
	}
}

// CloseStack it means the traced function and its children functions
// have returned on the goroutine stack, so we can print the stack now.
//
// And later the goroutine may call other functions, and the stack will
// be expanded and shrinked again, and we will print the stack again, too.
func (m *EventManager) CloseStack(event bpf.GoftraceEvent) bool {
	s := m.pidState(event.Pid)
	if m.aggregate && m.adaptive {
		// In adaptive mode the BPF side marks the sample with TRACE_END when
		// the wanted root call returns.
		return event.TraceFlags&traceFlagEnd != 0
	}
	// Without adaptive sampling the BPF side never emits TRACE_START/TRACE_END,
	// so fall back to the plain stack-depth check used by the print path.
	return len(s.goEventStack[event.Goid]) == 0 && len(s.goEvents[event.Goid]) > 0
}

func (m *EventManager) ClearStack(event bpf.GoftraceEvent) {
	m.dropStack(event.Pid, event.Goid)
}

func (m *EventManager) dropStack(pid uint32, goid uint64) {
	m.pidMu.RLock()
	s := m.pids[pid]
	m.pidMu.RUnlock()
	if s == nil {
		return
	}
	if m.adaptive {
		released := uint64(len(s.goEvents[goid]))
		if released >= m.pendingEvents {
			m.pendingEvents = 0
		} else {
			m.pendingEvents -= released
		}
	}
	delete(s.goEvents, goid)
	delete(s.goEventStack, goid)
	delete(s.invalid, goid)
}

// onGoroutineExit clears any incomplete call stack retained for a goroutine.
// Arguments need no separate cleanup because they are embedded in each event.
func (m *EventManager) onGoroutineExit(pid uint32, goid uint64) {
	delete(m.suppressed, traceKey{pid: pid, goid: goid})
	m.dropStack(pid, goid)
}

// AggregateStack aggregates the latency and return-value distributions of the
// functions recorded on the given goroutine instead of printing each call.
// Entry/ret events are paired in LIFO order to derive per-call latency, and
// the flattened return-value string is counted for frequency distribution.
func (m *EventManager) AggregateStack(pid uint32, goid uint64) {
	s := m.pidState(pid)
	type frame struct {
		entryIP uint64
		start   uint64
		weight  uint64
	}
	var frames []frame
	for _, event := range s.goEvents[goid] {
		switch event.Location {
		case eventLocationEntry:
			weight := uint64(event.SampleDenominator)
			if weight == 0 {
				weight = 1
			}
			frames = append(frames, frame{entryIP: event.Ip, start: event.TimeNs, weight: weight})
		case eventLocationRet:
			if len(frames) == 0 || frames[len(frames)-1].entryIP != event.uprobe.Address-event.uprobe.RelOffset {
				return
			}
			current := frames[len(frames)-1]
			frames = frames[:len(frames)-1]
			elapsed := event.TimeNs - current.start
			s.recordAgg(event.uprobe.Funcname, time.Duration(elapsed), event.argString, current.weight)
		}
	}
}

// recordAgg updates the aggregation counters for a single traced function.
func (s *pidState) recordAgg(funcname string, elapsed time.Duration, retval string, weight uint64) {
	agg := s.agg[funcname]
	if agg == nil {
		agg = newFuncAgg()
		s.agg[funcname] = agg
	}
	if weight == 0 {
		weight = 1
	}
	agg.calls++
	agg.weightedCalls += weight
	idx := len(latencyBuckets) // overflow bucket
	for i, b := range latencyBuckets {
		if elapsed <= b.edge {
			idx = i
			break
		}
	}
	agg.latencies[idx]++
	agg.weightedLatencies[idx] += weight
	if retval != "" {
		agg.recordRetval(retval, weight)
	}
}

// recordRetval implements the bounded Space-Saving heavy-hitter algorithm.
// Existing values remain exact until the fixed table fills; afterwards the
// least frequent candidate is replaced, keeping memory bounded while retaining
// likely top return values.
func (a *funcAgg) recordRetval(retval string, weight uint64) {
	if weight == 0 {
		weight = 1
	}
	if current, ok := a.retvals[retval]; ok {
		current.count++
		current.weightedCount += weight
		a.retvals[retval] = current
		return
	}
	if len(a.retvals) < maxAggregateRetvals {
		a.retvals[retval] = retvalCount{count: 1, weightedCount: weight}
		return
	}

	var minimumValue string
	var minimum retvalCount
	first := true
	for value, count := range a.retvals {
		if first || count.weightedCount < minimum.weightedCount {
			minimumValue, minimum, first = value, count, false
		}
	}
	delete(a.retvals, minimumValue)
	a.retvals[retval] = retvalCount{
		count:         1,
		weightedCount: minimum.weightedCount + weight,
		weightedError: minimum.weightedCount,
	}
}
