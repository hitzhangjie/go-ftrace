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
	m.Add(event)
	log.Debugf("added event: %+v", event)
	if m.CloseStack(event) {
		// 有错没错都要清空栈
		defer m.ClearStack(event)

		// 聚类模式：不再逐条打印调用栈，而是按函数聚合延迟与返回值分布，
		// 避免高频调用刷屏，同时降低与 grep/tee 等管道结合时的内存占用。
		if m.cluster {
			m.ClusterStack(event.Pid, event.Goid)
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

func (m *EventManager) Add(event bpf.GoftraceEvent) {
	// get the associated uprobe first, since we need to know how many args
	// should be consumed from the per-goroutine arg channel
	uprobe, err := m.GetUprobe(event)
	if err != nil {
		log.Errorf("failed to get uprobe for event %+v: %+v", event, err)
		return
	}
	up.BindInterfaceMemory(uprobe.Values, processMemoryReader(event.Pid))

	s := m.pidState(event.Pid)

	length := len(s.goEvents[event.Goid])
	if length == 0 && event.Location != eventLocationEntry {
		// Orphaned return: its arguments are part of this same event record, so
		// dropping it cannot desynchronize subsequent events.
		return
	}
	if length > 0 {
		lastEvent := s.goEvents[event.Goid][length-1]
		if lastEvent.Location == event.Location && lastEvent.Ip == event.Ip && lastEvent.Bp != event.CallerBp {
			// duplicated entry event due to stack expansion/shrinkage
			log.Debugf("duplicated entry event: %+v", event)
			s.goEvents[event.Goid][length-1].GoftraceEvent = event
			return
		}
	}

	argString := renderEventArgs(uprobe, event)

	// append new event
	s.goEvents[event.Goid] = append(s.goEvents[event.Goid], Event{
		GoftraceEvent: event,
		uprobe:        &uprobe,
		argString:     argString,
	})
	switch event.Location {
	case eventLocationEntry:
		s.goEventStack[event.Goid]++
	case eventLocationRet:
		s.goEventStack[event.Goid]--
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
	return s.goEventStack[event.Goid] == 0 && len(s.goEvents[event.Goid]) > 0
}

func (m *EventManager) ClearStack(event bpf.GoftraceEvent) {
	s := m.pidState(event.Pid)
	delete(s.goEvents, event.Goid)
	delete(s.goEventStack, event.Goid)
}

// onGoroutineExit clears any incomplete call stack retained for a goroutine.
// Arguments need no separate cleanup because they are embedded in each event.
func (m *EventManager) onGoroutineExit(pid uint32, goid uint64) {
	s := m.pidState(pid)
	delete(s.goEvents, goid)
	delete(s.goEventStack, goid)
}

// ClusterStack aggregates the latency and return-value distributions of the
// functions recorded on the given goroutine instead of printing each call.
// Entry/ret events are paired in LIFO order to derive per-call latency, and
// the flattened return-value string is counted for frequency distribution.
func (m *EventManager) ClusterStack(pid uint32, goid uint64) {
	s := m.pidState(pid)
	var startTimes []uint64
	for _, event := range s.goEvents[goid] {
		switch event.Location {
		case eventLocationEntry:
			startTimes = append(startTimes, event.TimeNs)
		case eventLocationRet:
			if len(startTimes) == 0 {
				continue
			}
			elapsed := event.TimeNs - startTimes[len(startTimes)-1]
			startTimes = startTimes[:len(startTimes)-1]
			s.recordCluster(event.uprobe.Funcname, time.Duration(elapsed), event.argString)
		}
	}
}

// recordCluster updates the aggregation counters for a single traced function.
func (s *pidState) recordCluster(funcname string, elapsed time.Duration, retval string) {
	agg := s.agg[funcname]
	if agg == nil {
		agg = newFuncAgg()
		s.agg[funcname] = agg
	}
	agg.calls++
	idx := len(latencyBuckets) // overflow bucket
	for i, b := range latencyBuckets {
		if elapsed <= b.edge {
			idx = i
			break
		}
	}
	agg.latencies[idx]++
	if retval != "" {
		agg.retvals[retval]++
	}
}
