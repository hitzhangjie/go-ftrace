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
	length := len(m.goEvents[event.Goid])
	if length == 0 && event.Location != 0 {
		return
	}
	// get the associated uprobe
	uprobe, err := m.GetUprobe(event)
	if err != nil {
		log.Errorf("failed to get uprobe for event %+v: %+v", event, err)
		return
	}
	if length > 0 {
		lastEvent := m.goEvents[event.Goid][length-1]
		if lastEvent.Location == event.Location && lastEvent.Ip == event.Ip && lastEvent.Bp != event.CallerBp {
			// duplicated entry event due to stack expansion/shrinkage
			log.Debugf("duplicated entry event: %+v", event)
			m.goEvents[event.Goid][length-1].GoftraceEvent = event
			for range uprobe.FetchArgs {
				for m.goArgs[event.Goid] == nil {
					time.Sleep(time.Millisecond)
				}
				<-m.goArgs[event.Goid]
			}
			return
		}
	}
	// we need to fetch `len(uprobe.FetchArgs)` args
	args := []string{}
	for _, fetchArg := range uprobe.FetchArgs {
		for m.goArgs[event.Goid] == nil {
			time.Sleep(time.Millisecond)
		}
		arg := <-m.goArgs[event.Goid]
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
	case 0: // entry
		m.goEventStack[event.Goid]++
	case 1: // ret
		m.goEventStack[event.Goid]--
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
