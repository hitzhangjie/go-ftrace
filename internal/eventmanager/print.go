package eventmanager

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/hitzhangjie/go-ftrace/internal/bpf"
	"github.com/hitzhangjie/go-ftrace/internal/uprobe"
)

const placeholder = "        "

// PrintStack print the callstack of a traced function
func (m *EventManager) PrintStack(pid uint32, goid uint64) (err error) {
	indent := ""
	fmt.Println()
	startTimeStack := []uint64{}
	for _, event := range m.pidState(pid).goEvents[goid] {
		lineInfo := "?:?"
		t := m.bootTime.Add(time.Duration(event.TimeNs)).Format("02 15:04:05.0000")
		syms, offset, err := m.elf.ResolveAddress(event.Ip)
		if err != nil {
			return err
		}

		switch event.Location {
		case eventLocationEntry:
			startTimeStack = append(startTimeStack, event.TimeNs)
			callChain, err := m.SprintCallChain(event)
			if err != nil {
				return err
			}
			if filename, line, err := m.elf.LineInfoForPc(event.CallerIp); err == nil {
				lineInfo = fmt.Sprintf("%s:%d", filename, line)
				if m.trimprefix != "" {
					lineInfo = strings.TrimPrefix(lineInfo, m.trimprefix)
				}
			}

			fmt.Printf("%s %s %s %s(%s) { %s %s\n",
				color.YellowString(t),
				placeholder,
				indent,
				color.RedString(event.uprobe.Funcname),
				color.MagentaString(event.argString),
				color.GreenString(callChain),
				color.CyanString(lineInfo))
			indent += "  "

		case eventLocationRet:
			if len(indent) == 0 {
				continue
			}
			if filename, line, err := m.elf.LineInfoForPc(event.Ip); err == nil {
				lineInfo = fmt.Sprintf("%s:%d", filename, line)
				if m.trimprefix != "" {
					lineInfo = strings.TrimPrefix(lineInfo, m.trimprefix)
				}
			}
			elapsed := event.TimeNs - startTimeStack[len(startTimeStack)-1]
			startTimeStack = startTimeStack[:len(startTimeStack)-1]
			indent = indent[:len(indent)-2]

			retval := ""
			if event.argString != "" {
				retval = " => " + color.MagentaString(event.argString)
			}
			fmt.Printf("%s %08.4f %s } %s+%d%s %s\n",
				color.YellowString(t),
				time.Duration(elapsed).Seconds(),
				indent,
				color.RedString(syms[0].Name),
				offset,
				retval,
				color.CyanString(lineInfo))
		}
	}
	return
}

func (m *EventManager) SprintCallChain(event Event) (chain string, err error) {
	if event.CallerIp == 0 {
		return "", nil
	}
	syms, off, err := m.elf.ResolveAddress(event.CallerIp)
	if err != nil {
		return
	}
	return fmt.Sprintf("%s+%d", syms[0].Name, off), nil
}

func (m *EventManager) SprintArg(arg *uprobe.FetchArg, data []uint8) (_ string, err error) {
	value := arg.SprintValue(data)
	if arg.Varname != "__call__" {
		return fmt.Sprintf("%s=%s", arg.Varname, value), nil
	}
	addr, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return "", err
	}
	syms, offset, err := m.elf.ResolveAddress(addr)
	if err != nil {
		return "", err
	}
	if offset != 0 {
		return "", fmt.Errorf("not a valid __call__ target: %d", addr)
	}
	return fmt.Sprintf("__call__=%s", syms[0].Name), nil
}

func (m *EventManager) PrintRemaining(stats bpf.RuntimeStats) (err error) {
	pids := m.snapshotPids()
	if m.cluster {
		// Only complete root calls are valid samples. Incomplete stacks can be
		// caused by queue overwrite or shutdown and must not bias aggregation.
		for pid, s := range pids {
			for goid := range s.goEvents {
				m.droppedStacks++
				m.dropStack(pid, goid)
			}
		}
		m.PrintClusterSummary(stats)
		return nil
	}
	for pid, s := range pids {
		for goid := range s.goEvents {
			if err = m.PrintStack(pid, goid); err != nil {
				break
			}
		}
	}
	return
}

func samplingEstimate(weighted uint64) float64 {
	return float64(weighted)
}

func printRuntimeStats(stats bpf.RuntimeStats) {
	sampledOutRate := 0.0
	if stats.WantedRoots > 0 {
		sampledOutRate = float64(stats.SampledOutRoots) * 100 / float64(stats.WantedRoots)
	}
	eventLossRate := 0.0
	if stats.DroppedEvents > 0 {
		eventLossRate = 100 / (1 + float64(stats.EmittedEvents)/float64(stats.DroppedEvents))
	}

	fmt.Printf("sampling: wanted roots=%d, admitted=%d, sampled out=%d (%.2f%%), state insert failures=%d\n",
		stats.WantedRoots, stats.AdmittedRoots, stats.SampledOutRoots, sampledOutRate, stats.StateInsertFailures)
	fmt.Printf("events: emitted=%d, dropped=%d (%.2f%%), aborted roots=%d\n",
		stats.EmittedEvents, stats.DroppedEvents, eventLossRate, stats.AbortedRoots)
	fmt.Println("estimate: inverse root-sampling weights only; queue event loss and invalid/memory-discarded stacks are reported but not extrapolated")
}

// PrintClusterSummary prints the aggregated per-function latency distribution
// and top-10 return-value frequency distribution.
func (m *EventManager) PrintClusterSummary(stats bpf.RuntimeStats) {
	pids := m.snapshotPids()

	fmt.Println()
	fmt.Println("==================== function latency & return-value summary ====================")
	printRuntimeStats(stats)
	if m.droppedStacks > 0 {
		fmt.Printf("samples: discarded=%d (incomplete, aborted, or over memory budget)\n", m.droppedStacks)
	}
	if m.evictedPIDs > 0 {
		fmt.Printf("memory guard: evicted %d least-recently-used PID summaries\n", m.evictedPIDs)
	}

	// Sort pids for deterministic output. When only a single process is
	// traced, keep the previous compact format (no pid section headers).
	if len(pids) == 1 {
		for _, s := range pids {
			m.printClusterSummary(s.agg)
		}
		return
	}

	ordered := make([]uint32, 0, len(pids))
	for pid := range pids {
		ordered = append(ordered, pid)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })

	for _, pid := range ordered {
		fmt.Printf("\n########## pid=%d ##########\n", pid)
		m.printClusterSummary(pids[pid].agg)
	}
}

// printClusterSummary renders the aggregation map for a single pidState.
func (m *EventManager) printClusterSummary(agg map[string]*funcAgg) {
	funcs := make([]string, 0, len(agg))
	for fn := range agg {
		funcs = append(funcs, fn)
	}
	sort.Strings(funcs)

	for _, fn := range funcs {
		a := agg[fn]
		fmt.Printf("\n%s  (calls observed=%d, estimated≈%.0f)\n", fn, a.calls, samplingEstimate(a.weightedCalls))

		fmt.Println("  latency distribution (observed, estimated):")
		for i, b := range latencyBuckets {
			fmt.Printf("    %-10s %d, ≈%.0f\n", b.label, a.latencies[i], samplingEstimate(a.weightedLatencies[i]))
		}
		overflow := ">" + latencyBuckets[len(latencyBuckets)-1].edge.String()
		fmt.Printf("    %-10s %d, ≈%.0f\n", overflow, a.latencies[len(latencyBuckets)], samplingEstimate(a.weightedLatencies[len(latencyBuckets)]))

		if len(a.retvals) > 0 {
			type kv struct {
				v     string
				count retvalCount
			}
			kvs := make([]kv, 0, len(a.retvals))
			for v, count := range a.retvals {
				kvs = append(kvs, kv{v: v, count: count})
			}
			sort.Slice(kvs, func(i, j int) bool {
				if kvs[i].count.weightedCount != kvs[j].count.weightedCount {
					return kvs[i].count.weightedCount > kvs[j].count.weightedCount
				}
				return kvs[i].v < kvs[j].v
			})
			top := kvs
			if len(top) > 10 {
				top = top[:10]
			}
			fmt.Printf("  return values (top %d; observed, estimated):\n", len(top))
			for _, e := range top {
				estimated := samplingEstimate(e.count.weightedCount)
				if e.count.weightedError == 0 {
					fmt.Printf("    %-40s %d, ≈%.0f\n", e.v, e.count.count, estimated)
				} else {
					fmt.Printf("    %-40s >=%d, ≈%.0f (estimated error <= %.0f)\n", e.v, e.count.count, estimated, samplingEstimate(e.count.weightedError))
				}
			}
		}
	}
}
