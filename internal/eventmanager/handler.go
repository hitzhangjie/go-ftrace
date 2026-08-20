package eventmanager

import (
	"strings"
	"time"

	"github.com/hitzhangjie/go-ftrace/internal/bpf"
	log "github.com/sirupsen/logrus"
)

// Handle handles the event
func (m *EventManager) Handle(event bpf.GoftraceEvent) error {
	// goroutine 退出事件：回收该 goroutine 的参数 channel 与残留栈，避免
	// goArgs 等 map 只增不减导致 OOM（详见 onGoroutineExit 注释）。
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

	s := m.pidState(event.Pid)

	length := len(s.goEvents[event.Goid])
	if length == 0 && event.Location != eventLocationEntry {
		// orphaned ret event (no matching entry recorded), drop it but still
		// consume its args to keep the arg stream aligned
		s.consumeArgs(event.Goid, len(uprobe.FetchArgs))
		return
	}
	if length > 0 {
		lastEvent := s.goEvents[event.Goid][length-1]
		if lastEvent.Location == event.Location && lastEvent.Ip == event.Ip && lastEvent.Bp != event.CallerBp {
			// duplicated entry event due to stack expansion/shrinkage
			log.Debugf("duplicated entry event: %+v", event)
			s.goEvents[event.Goid][length-1].GoftraceEvent = event
			s.consumeArgs(event.Goid, len(uprobe.FetchArgs))
			return
		}
	}
	// we need to fetch `len(uprobe.FetchArgs)` args
	args := []string{}
	printedNil := map[string]bool{}
	for _, fetchArg := range uprobe.FetchArgs {
		arg := s.nextArg(event.Goid)
		// A nil-checked leaf belongs to a possibly-nil pointer (e.g. a struct
		// pointer return value). When the pointer is nil, collapse the whole
		// group of flattened fields into a single "root = nil" instead of
		// printing each dereferenced field as garbage/zero.
		if fetchArg.NilCheck && arg.IsNil != 0 {
			if printedNil[fetchArg.NilRoot] {
				continue
			}
			printedNil[fetchArg.NilRoot] = true
			if len(args) > 0 {
				args = append(args, ", ")
			}
			args = append(args, fetchArg.NilRoot, "=", "nil")
			continue
		}
		if len(args) > 0 {
			args = append(args, ", ")
		}
		// varname = value
		args = append(args, fetchArg.Varname, "=", fetchArg.SprintValue(arg.Data[:]))
	}
	// append new event
	s.goEvents[event.Goid] = append(s.goEvents[event.Goid], Event{
		GoftraceEvent: event,
		uprobe:        &uprobe,
		argString:     strings.Join(args, ""),
	})
	switch event.Location {
	case eventLocationEntry:
		s.goEventStack[event.Goid]++
	case eventLocationRet:
		s.goEventStack[event.Goid]--
	}
}

// nextArg reads the next argument of the given goroutine from its arg channel.
func (s *pidState) nextArg(goid uint64) bpf.GoftraceArgData {
	var ch chan bpf.GoftraceArgData
	for ch == nil {
		ch = s.argChan(goid)
		if ch == nil {
			time.Sleep(time.Millisecond)
		}
	}
	return <-ch
}

// consumeArgs drops `n` arguments of the given goroutine from its arg channel.
func (s *pidState) consumeArgs(goid uint64, n int) {
	for i := 0; i < n; i++ {
		s.nextArg(goid)
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

// onGoroutineExit 回收已退出 goroutine 的相关资源，防止 goArgs 无限增长。
//
// 内核 goroutine_exit 探针在 goroutine 真正退出时触发：此时该 goroutine 不会再产生
// 任何 ent/ret 事件与参数，且其此前产生的参数也已在对应的 ent/ret 事件处理中配对
// 消费完毕（事件与参数严格 1:1 配对）。因此其参数 channel 此刻一定为空，可安全删除。
//
// 这里只 delete 不 close：goroutine 退出后 arg_queue 中已无该 goid 的存量参数，
// handleArg 不会再向该 channel 发送，delete 后 channel 失去引用即被 GC 回收；
// 若 close 则可能与 handleArg 的并发发送竞争触发 "send on closed channel" panic。
func (m *EventManager) onGoroutineExit(pid uint32, goid uint64) {
	s := m.pidState(pid)
	s.argMu.Lock()
	delete(s.goArgs, goid)
	s.argMu.Unlock()
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
