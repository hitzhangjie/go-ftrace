package eventmanager

import (
	"errors"
	"fmt"
	"time"

	"github.com/elastic/go-sysinfo"
	"github.com/hitzhangjie/go-ftrace/elf"
	"github.com/hitzhangjie/go-ftrace/internal/bpf"
	"github.com/hitzhangjie/go-ftrace/internal/uprobe"
	log "github.com/sirupsen/logrus"
)

type Event struct {
	bpf.GoftraceEvent
	uprobe    *uprobe.Uprobe
	argString string
}

type EventManager struct {
	elf     *elf.ELF
	argCh   <-chan bpf.GoftraceArgData
	uprobes map[string]uprobe.Uprobe

	goEvents     map[uint64][]Event
	goEventStack map[uint64]uint64
	goArgs       map[uint64]chan bpf.GoftraceArgData

	bootTime time.Time
}

func New(uprobes []uprobe.Uprobe, elf *elf.ELF, ch <-chan bpf.GoftraceArgData) (_ *EventManager, err error) {
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
		goEvents:     map[uint64][]Event{},
		goEventStack: map[uint64]uint64{},
		goArgs:       map[uint64]chan bpf.GoftraceArgData{},
		bootTime:     bootTime,
	}
	go m.handleArg()
	return m, err
}

func (m *EventManager) handleArg() {
	for arg := range m.argCh {
		if _, ok := m.goArgs[arg.Goid]; !ok {
			m.goArgs[arg.Goid] = make(chan bpf.GoftraceArgData, 1000)
		}
		log.Debugf("add arg %+v", arg)
		m.goArgs[arg.Goid] <- arg
	}
}

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