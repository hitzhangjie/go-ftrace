package eventmanager

import (
	"strings"
	"time"

	"github.com/hitzhangjie/go-ftrace/internal/bpf"
	log "github.com/sirupsen/logrus"
)

// Handle handles the event
func (m *EventManager) Handle(event bpf.GoftraceEvent) error {
	m.Add(event)
	log.Debugf("added event: %+v", event)
	if m.CloseStack(event) {
		// 有错没错都要清空栈
		defer m.ClearStack(event)

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
		return m.PrintStack(event.Goid)
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

	length := len(m.goEvents[event.Goid])
	if length == 0 && event.Location != eventLocationEntry {
		// orphaned ret event (no matching entry recorded), drop it but still
		// consume its args to keep the arg stream aligned
		m.consumeArgs(event.Goid, len(uprobe.FetchArgs))
		return
	}
	if length > 0 {
		lastEvent := m.goEvents[event.Goid][length-1]
		if lastEvent.Location == event.Location && lastEvent.Ip == event.Ip && lastEvent.Bp != event.CallerBp {
			// duplicated entry event due to stack expansion/shrinkage
			log.Debugf("duplicated entry event: %+v", event)
			m.goEvents[event.Goid][length-1].GoftraceEvent = event
			m.consumeArgs(event.Goid, len(uprobe.FetchArgs))
			return
		}
	}
	// we need to fetch `len(uprobe.FetchArgs)` args
	args := []string{}
	printedNil := map[string]bool{}
	for _, fetchArg := range uprobe.FetchArgs {
		arg := m.nextArg(event.Goid)
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
	m.goEvents[event.Goid] = append(m.goEvents[event.Goid], Event{
		GoftraceEvent: event,
		uprobe:        &uprobe,
		argString:     strings.Join(args, ""),
	})
	switch event.Location {
	case eventLocationEntry:
		m.goEventStack[event.Goid]++
	case eventLocationRet:
		m.goEventStack[event.Goid]--
	}
}

// nextArg reads the next argument of the given goroutine from its arg channel.
func (m *EventManager) nextArg(goid uint64) bpf.GoftraceArgData {
	var ch chan bpf.GoftraceArgData
	for ch == nil {
		ch = m.argChan(goid)
		if ch == nil {
			time.Sleep(time.Millisecond)
		}
	}
	return <-ch
}

// consumeArgs drops `n` arguments of the given goroutine from its arg channel.
func (m *EventManager) consumeArgs(goid uint64, n int) {
	for i := 0; i < n; i++ {
		m.nextArg(goid)
	}
}

// CloseStack it means the traced function and its children functions
// have returned on the goroutine stack, so we can print the stack now.
//
// And later the goroutine may call other functions, and the stack will
// be expanded and shrinked again, and we will print the stack again, too.
func (m *EventManager) CloseStack(event bpf.GoftraceEvent) bool {
	return m.goEventStack[event.Goid] == 0 && len(m.goEvents[event.Goid]) > 0
}

func (m *EventManager) ClearStack(event bpf.GoftraceEvent) {
	delete(m.goEvents, event.Goid)
	delete(m.goEventStack, event.Goid)
}
