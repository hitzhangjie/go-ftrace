package eventmanager

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
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
		return "", fmt.Errorf("not a valid __call__ target: %lld", addr)
	}
	return fmt.Sprintf("__call__=%s", syms[0].Name), nil
}

func (m *EventManager) PrintRemaining() (err error) {
	pids := m.snapshotPids()
	if m.cluster {
		// 收尾时把尚未闭合的栈也聚合进去，再输出聚类汇总。
		for pid, s := range pids {
			for goid := range s.goEvents {
				m.ClusterStack(pid, goid)
			}
		}
		m.PrintClusterSummary()
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

// PrintClusterSummary prints the aggregated per-function latency distribution
// and top-10 return-value frequency distribution.
func (m *EventManager) PrintClusterSummary() {
	pids := m.snapshotPids()

	fmt.Println()
	fmt.Println("==================== function latency & return-value summary ====================")

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
		fmt.Printf("\n%s  (calls=%d)\n", fn, a.calls)

		fmt.Println("  latency distribution:")
		for i, b := range latencyBuckets {
			fmt.Printf("    %-10s %d\n", b.label, a.latencies[i])
		}
		overflow := ">" + latencyBuckets[len(latencyBuckets)-1].edge.String()
		fmt.Printf("    %-10s %d\n", overflow, a.latencies[len(latencyBuckets)])

		if len(a.retvals) > 0 {
			type kv struct {
				v string
				n uint64
			}
			kvs := make([]kv, 0, len(a.retvals))
			for v, n := range a.retvals {
				kvs = append(kvs, kv{v, n})
			}
			sort.Slice(kvs, func(i, j int) bool {
				if kvs[i].n != kvs[j].n {
					return kvs[i].n > kvs[j].n
				}
				return kvs[i].v < kvs[j].v
			})
			top := kvs
			if len(top) > 10 {
				top = top[:10]
			}
			fmt.Printf("  return values (top %d of %d distinct):\n", len(top), len(a.retvals))
			for _, e := range top {
				fmt.Printf("    %-40s %d\n", e.v, e.n)
			}
		}
	}
}
