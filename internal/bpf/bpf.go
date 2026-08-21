package bpf

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/hitzhangjie/go-ftrace/internal/uprobe"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/semaphore"
)

const (
	EventDataOffset int64 = 436
	VacantR10Offset int64 = -96
)

var RegisterConstants = map[string]uint8{
	"ax":  0,
	"dx":  1,
	"cx":  2,
	"bx":  3,
	"si":  4,
	"di":  5,
	"bp":  6,
	"sp":  7,
	"r8":  8,
	"r9":  9,
	"r10": 10,
	"r11": 11,
	"r12": 12,
	"r13": 13,
	"r14": 14,
	"r15": 15,
}

type LoadOptions struct {
	GoidOffset       int64
	GOffset          int64
	AdaptiveSampling bool
}

type BPF struct {
	objs      *GoftraceObjects
	closers   []io.Closer
	linksOnce sync.Once
	closeOnce sync.Once
}

func New() *BPF {
	return &BPF{}
}

func (b *BPF) BpfConfig(fetchArgs, adaptiveSampling bool, goidOffset, gOffset int64) interface{} {
	return struct {
		GoidOffset, GOffset int64
		FetchArgs           bool
		AdaptiveSampling    bool
		Padding             [6]byte
	}{
		GoidOffset:       goidOffset,
		GOffset:          gOffset,
		FetchArgs:        fetchArgs,
		AdaptiveSampling: adaptiveSampling,
	}
}

func (b *BPF) Load(uprobes []uprobe.Uprobe, opts LoadOptions) (err error) {
	spec, err := LoadGoftrace()
	if err != nil {
		return err
	}

	b.objs = &GoftraceObjects{}

	fetchArgs := false
	for _, uprobe := range uprobes {
		if len(uprobe.FetchArgs) > 0 {
			fetchArgs = true
			break
		}
	}
	cfg := b.BpfConfig(fetchArgs, opts.AdaptiveSampling, opts.GoidOffset, opts.GOffset)
	if err = spec.RewriteConstants(map[string]interface{}{"CONFIG": cfg}); err != nil {
		return
	}
	if err = spec.LoadAndAssign(b.objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSize: ebpf.DefaultVerifierLogSize * 4},
	}); err != nil {
		return
	}
	defer func() {
		if err != nil {
			b.objs.Close()
			b.objs = nil
		}
	}()

	wantedEntries := make(map[string]uint64)
	for _, probe := range uprobes {
		if probe.Wanted && probe.Location == uprobe.AtEntry {
			wantedEntries[probe.Funcname] = probe.Address
			if err = b.setWanted(probe); err != nil {
				return
			}
		}
	}
	for _, probe := range uprobes {
		if len(probe.FetchArgs) > 0 {
			if err = b.setArgRules(probe.Address, probe.FetchArgs); err != nil {
				return
			}
		}
		if opts.AdaptiveSampling && probe.Wanted && probe.Location == uprobe.AtRet {
			if err = b.setWantedRet(probe.Address, wantedEntries[probe.Funcname]); err != nil {
				return
			}
		}
	}
	return
}

func (b *BPF) setArgRules(pc uint64, fetchArgs []*uprobe.FetchArg) (err error) {
	if len(fetchArgs) > uprobe.MaxFetchArgs {
		return fmt.Errorf("too many fetch args: %d > %d", len(fetchArgs), uprobe.MaxFetchArgs)
	}
	argRules := GoftraceArgRules{Length: uint8(len(fetchArgs))}
	for idx, fetchArg := range fetchArgs {
		if len(fetchArg.Rules) > uprobe.MaxFetchArgRules {
			return fmt.Errorf("too many rules: %d > %d", len(fetchArg.Rules), uprobe.MaxFetchArgRules)
		}
		rule := GoftraceArgRule{
			Type:   uint8(fetchArg.Rules[len(fetchArg.Rules)-1].From),
			Reg:    RegisterConstants[fetchArg.Rules[0].Register],
			Size:   uint8(fetchArg.Size),
			Length: uint8(len(fetchArg.Rules) - 1),
		}
		if fetchArg.NilCheck {
			rule.NilCheck = 1
		}

		j := 0
		for _, r := range fetchArg.Rules {
			if r.From == uprobe.Stack {
				rule.Offsets[j] = int16(r.Offset)
				if r.Dereference {
					rule.Dereference[j] = 1
				}
				j++
			}
		}
		argRules.Rules[idx] = rule
		fmt.Printf("add arg rule at %x: %+v\n", pc, rule)
	}
	return b.objs.ArgRulesMap.Update(pc, argRules, ebpf.UpdateNoExist)
}

func (b *BPF) setWanted(uprobe uprobe.Uprobe) (err error) {
	return b.objs.ShouldTraceRip.Update(uprobe.Address, true, ebpf.UpdateNoExist)
}

func (b *BPF) setWantedRet(retAddress, entryAddress uint64) error {
	return b.objs.ShouldTraceRet.Update(retAddress, entryAddress, ebpf.UpdateNoExist)
}

// SetSampleDenominator updates the sampling probability. A value
// of N admits approximately one out of every N wanted root calls.
func (b *BPF) SetSampleDenominator(denominator uint32) error {
	if denominator == 0 {
		denominator = 1
	}
	key := uint32(0)
	cfg := GoftraceSampleConfig{Denominator: denominator}
	return b.objs.SampleConfigMap.Update(key, cfg, ebpf.UpdateAny)
}

type RuntimeStats struct {
	WantedRoots         uint64
	AdmittedRoots       uint64
	SampledOutRoots     uint64
	EmittedEvents       uint64
	DroppedEvents       uint64
	AbortedRoots        uint64
	StateInsertFailures uint64
}

func (b *BPF) ReadRuntimeStats() (RuntimeStats, error) {
	var values []GoftraceRuntimeStats
	key := uint32(0)
	if err := b.objs.RuntimeStatsMap.Lookup(key, &values); err != nil {
		return RuntimeStats{}, err
	}

	var total RuntimeStats
	for _, value := range values {
		total.WantedRoots += value.WantedRoots
		total.AdmittedRoots += value.AdmittedRoots
		total.SampledOutRoots += value.SampledOutRoots
		total.EmittedEvents += value.EmittedEvents
		total.DroppedEvents += value.DroppedEvents
		total.AbortedRoots += value.AbortedRoots
		total.StateInsertFailures += value.StateInsertFailures
	}
	return total, nil
}

func (b *BPF) Attach(bin string, uprobes []uprobe.Uprobe) (err error) {
	ex, err := link.OpenExecutable(bin)
	if err != nil {
		return
	}
	for i, up := range uprobes {
		var prog *ebpf.Program
		switch up.Location {
		case uprobe.AtEntry:
			prog = b.objs.Ent
		case uprobe.AtRet:
			prog = b.objs.Ret
		case uprobe.AtGoroutineExit:
			prog = b.objs.GoroutineExit
		}
		fmt.Printf("attaching %d/%d\r", i+1, len(uprobes))
		up, err := ex.Uprobe("", prog, &link.UprobeOptions{Offset: up.AbsOffset})
		if err != nil {
			return err
		}
		b.closers = append(b.closers, up)

	}
	return
}

func (b *BPF) StopTracing() {
	b.linksOnce.Do(func() {
		log.Info("start detaching\n")
		sem := semaphore.NewWeighted(10)
		for i, closer := range b.closers {
			fmt.Printf("detaching %d/%d\r", i+1, len(b.closers))
			_ = sem.Acquire(context.Background(), 1)
			go func(closer io.Closer) {
				defer sem.Release(1)
				_ = closer.Close()
			}(closer)
		}
		_ = sem.Acquire(context.Background(), 10)
		sem.Release(10)
		fmt.Println()
	})
}

func (b *BPF) Detach() {
	b.closeOnce.Do(func() {
		b.StopTracing()
		if b.objs != nil {
			_ = b.objs.Close()
			b.objs = nil
		}
	})
}

type PollResult struct {
	Event GoftraceEvent
	Err   error
}

func (b *BPF) PollEvents(ctx context.Context) <-chan PollResult {
	ch := make(chan PollResult)

	go func() {
		defer close(ch)
		idleTicker := time.NewTicker(time.Millisecond)
		defer idleTicker.Stop()
		draining := false
		for {
			if !draining {
				select {
				case <-ctx.Done():
					draining = true
				default:
				}
			}

			event := GoftraceEvent{}
			if err := b.objs.EventQueue.LookupAndDelete(nil, &event); err != nil {
				if !errors.Is(err, ebpf.ErrKeyNotExist) {
					ch <- PollResult{Err: err}
					return
				}
				if draining {
					return
				}
				select {
				case <-ctx.Done():
					draining = true
				case <-idleTicker.C:
				}
				continue
			}

			if draining {
				ch <- PollResult{Event: event}
				continue
			}
			select {
			case <-ctx.Done():
				draining = true
				ch <- PollResult{Event: event}
			case ch <- PollResult{Event: event}:
			}
		}
	}()
	return ch
}
