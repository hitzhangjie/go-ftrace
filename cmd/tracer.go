package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"time"

	"github.com/hitzhangjie/go-ftrace/elf"
	"github.com/hitzhangjie/go-ftrace/internal/bpf"
	"github.com/hitzhangjie/go-ftrace/internal/eventmanager"
	"github.com/hitzhangjie/go-ftrace/internal/uprobe"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// Tracer ELF bpf tracer
type Tracer struct {
	bin string
	elf *elf.ELF
	cfg *Config
	bpf *bpf.BPF
}

type Config struct {
	// uprobes
	uprobeWildcards []string
	drilldown       string
	trimprefix      string
	excludeVendor   bool

	// args/rets fetch rules
	fargs         []string
	frets         []string
	autoFetchArgs bool
	autoFetchRets bool

	// cluster
	cluster         bool
	clusterInterval time.Duration

	// sampling
	adaptiveSample bool
	memoryLimitMB  uint64
}

// NewTracer create a new tracer for ELF executable `bin`, it attach uprobes listed in `uprobeWildcards`,
// and output statistics of functions filtered by fetch
//
// `drilldown` means only show the callstack of the specified function.
// TODO should we define it as a wildcast pattern, maybe a []string or []patterns?
func NewTracer(bin string, cfg *Config) (_ *Tracer, err error) {
	if cfg == nil {
		return nil, errors.New("invalid config: cfg is nil")
	}
	if cfg.memoryLimitMB == 0 {
		return nil, errors.New("invalid config: memory limit must be greater than zero")
	}
	if cfg.memoryLimitMB > ^uint64(0)>>20 {
		return nil, errors.New("invalid config: memory limit is too large")
	}
	elf, err := elf.New(bin)
	if err != nil {
		return
	}

	tracer := &Tracer{
		bin: bin,
		elf: elf,
		cfg: cfg,
		bpf: bpf.New(),
	}
	return tracer, nil
}

// Parse parse the args `ftrace [flags] binary <args>`
//
// @return funcs       : the function names to trace
// @return fetchArgs   : the function name => entry parameters (ordered <EA_expr>:<type>)
// @return retFetchArgs: the function name => return values (ordered <EA_expr>:<type>)
// @return err         : return err if <args> is invalid
//
// Here `EA_expr` is the expression of effective address, based on register and memory addressing mode.
func (t *Tracer) Parse() (funcs []string, fetchArgs, retFetchArgs map[string][]uprobe.FetchArgExpr, err error) {
	fetchArgs = map[string][]uprobe.FetchArgExpr{}
	retFetchArgs = map[string][]uprobe.FetchArgExpr{}

	for _, s := range t.cfg.fargs {
		funcname, vars, err := parseFetchExpr(s)
		if err != nil {
			return nil, nil, nil, err
		}
		funcs = append(funcs, funcname)
		if len(vars) > 0 {
			fetchArgs[funcname] = vars
		}
	}

	for _, s := range t.cfg.frets {
		funcname, vars, err := parseFetchExpr(s)
		if err != nil {
			return nil, nil, nil, err
		}
		funcs = append(funcs, funcname)
		if len(vars) > 0 {
			retFetchArgs[funcname] = vars
		}
	}
	return
}

// parseFetchExpr parses a single fetch rule expression.
//
// It returns:
//   - funcname: the function name to trace
//   - vars:     the parsed variable expressions in declaration order, nil if the expression is just a plain function name
//
// Two forms are supported:
//   - main.(*Student).String
//   - main.(*Student).String(s.name=(*+0(%ax)):c64, s.name.len=(+8(%ax)):s64, s.age=(+16(%ax)):s64)
func parseFetchExpr(s string) (funcname string, vars []uprobe.FetchArgExpr, err error) {
	// see: main.(*Student).String
	if s[len(s)-1] != ')' {
		return s, nil, nil
	}

	// see: main.(*Student).String(s.name=(*+0(%ax)):c64, s.name.len=(+8(%ax)):s64, s.age=(+16(%ax)):s64)
	stack := []byte{')'}
	for i := len(s) - 2; i >= 0; i-- {
		// verifying the balance parenthese of expression:
		// .String(s.name=(*+0(%ax)):c64, s.name.len=(+8(%ax)):s64, s.age=(+16(%ax)):s64)
		if s[i] == ')' {
			stack = append(stack, ')')
		} else if s[i] == '(' {
			if len(stack) > 0 && stack[len(stack)-1] == ')' {
				stack = stack[:len(stack)-1]
			} else {
				err = fmt.Errorf("imbalanced parenthese: %s", s)
				return
			}
		}

		// when stack becomes empty again, then we find the funcname s[:i]
		if len(stack) != 0 {
			continue
		}

		funcname = s[:i]
		vars = []uprobe.FetchArgExpr{}

		// keep parsing the (s.name= , s.name.len= , s.age=...), preserving order
		for _, part := range strings.Split(s[i+1:len(s)-1], ",") {
			vals := strings.Split(part, "=")
			if len(vals) != 2 {
				err = fmt.Errorf("invalid variable statement: %s", vals)
				return
			}
			argName := strings.TrimSpace(vals[0])
			argExpr := strings.TrimSpace(vals[1])
			vars = append(vars, uprobe.FetchArgExpr{Varname: argName, Expr: argExpr})
		}
		break
	}
	if len(stack) > 0 {
		err = fmt.Errorf("imbalanced parenthese: %s", s)
		return
	}
	return
}

// Start start tracing
func (t *Tracer) Start() (err error) {
	// create sampler
	var sampler sampler
	var memoryLimit = t.cfg.memoryLimitMB << 20
	if t.cfg.adaptiveSample {
		sampler = newAdaptiveSampler(memoryLimit)
	} else {
		sampler = noopSampler{}
	}

	funcs, fetchArgs, retFetchArgs, err := t.Parse()
	if err != nil {
		return
	}
	// parse uprobes
	uprobes, err := uprobe.Parse(t.elf, &uprobe.ParseOptions{
		ExcludeVendor:    t.cfg.excludeVendor,
		UprobeWildcards:  t.cfg.uprobeWildcards,
		FuncNames:        funcs,
		FetchFuncArgs:    fetchArgs,
		RetFetchFuncArgs: retFetchArgs,
		AutoFetchArgs:    t.cfg.autoFetchArgs,
		AutoFetchRets:    t.cfg.autoFetchRets,
	})
	if err != nil {
		return
	}

	// let user confirm yes/no to trace
requireConfirm:
	fmt.Fprintf(os.Stdout, "found %d uprobes, large number of uprobes (>1000) need long time for attaching and detaching, continue? [Y/n]\n", len(uprobes))
	input, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return errors.WithStack(err)
	}
	switch strings.TrimSpace(input) {
	case "n", "N":
		return
	case "y", "Y":
		break
	default:
		goto requireConfirm
	}

	// find the runtime.g->goid offset, and runtime.g offset to TLS
	goidOffset, err := t.elf.FindGoidOffset()
	if err != nil {
		return
	}
	gOffset, err := t.elf.FindGOffset()
	if err != nil {
		return
	}
	log.Debugf("offset of goid from g is %d, offset of g from fs is -0x%x\n", goidOffset, -gOffset)

	// load bpf programme and setup bpf programme config
	if err = t.bpf.Load(uprobes, bpf.LoadOptions{
		GoidOffset:       goidOffset,
		GOffset:          gOffset,
		AdaptiveSampling: t.cfg.adaptiveSample,
	}); err != nil {
		return
	}
	defer t.bpf.Detach()

	// attach uprobes (and detach when exit). The initial adjust reports a
	// change only when adaptive sampling is active, so the no-op sampler never
	// writes the sample-config map.
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	denominator, changed := sampler.adjust(memory.HeapAlloc)
	if changed {
		if err = t.bpf.SetSampleDenominator(denominator); err != nil {
			return fmt.Errorf("initialize adaptive sampling: %w", err)
		}
	}
	if sampler.active() {
		log.Infof("memory target %d MiB, initial sampling 1/%d", t.cfg.memoryLimitMB, denominator)
	} else {
		log.Infof("adaptive sampling disabled, collecting every root call")
	}
	if err = t.bpf.Attach(t.bin, uprobes); err != nil {
		return
	}

	log.Info("start tracing\n")

	// Stop probe production first on SIGINT, then drain all events already in
	// the queue before reading final loss counters and printing the summary.
	signalCtx, stopSignal := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stopSignal()
	pollCtx, stopPolling := context.WithCancel(context.Background())
	defer stopPolling()
	signalCh := signalCtx.Done()

	// create eventmanager to poll events, prepare the callstack and print
	mgr, err := eventmanager.New(uprobes, t.elf,
		t.cfg.drilldown,
		t.cfg.trimprefix,
		t.cfg.cluster,
		t.cfg.adaptiveSample,
		memoryLimit)
	if err != nil {
		return
	}

	// 聚类模式下按固定周期打印中间汇总（累计统计，不重置），
	// 避免长时间运行时只能靠 Ctrl+C 才能看到结果。
	var summaryCh <-chan time.Time
	if t.cfg.cluster && t.cfg.clusterInterval > 0 {
		ticker := time.NewTicker(t.cfg.clusterInterval)
		summaryCh = ticker.C
		defer ticker.Stop()
	}

	// The sampling ticker always runs; the no-op sampler reports no change
	// every second, so when adaptive sampling is disabled this loop is a no-op.
	samplingTicker := time.NewTicker(time.Second)
	defer samplingTicker.Stop()
	samplingCh := samplingTicker.C

	// PollEvents must be called exactly once. Calling it in the select expression
	// would create and strand a new goroutine and channel on every loop iteration.
	events := t.bpf.PollEvents(pollCtx)

	// 轮询并处理事件，更新统计并周期性打印
loop:
	for {
		select {
		case <-signalCh:
			t.bpf.StopTracing()
			stopPolling()
			signalCh = nil
			summaryCh = nil
			samplingCh = nil
		case result, ok := <-events:
			if !ok {
				break loop
			}
			if result.Err != nil {
				return fmt.Errorf("poll BPF events: %w", result.Err)
			}
			if err = mgr.Handle(result.Event); err != nil {
				return
			}
		case <-summaryCh:
			stats, statsErr := t.bpf.ReadRuntimeStats()
			if statsErr != nil {
				return fmt.Errorf("read cluster runtime stats: %w", statsErr)
			}
			if sampler.active() {
				fmt.Printf("\n[%s] cluster summary (cumulative, sampling 1/%d)\n", time.Now().Format("15:04:05"), sampler.denominator())
			} else {
				fmt.Printf("\n[%s] cluster summary (cumulative)\n", time.Now().Format("15:04:05"))
			}
			mgr.PrintClusterSummary(stats)
		case <-samplingCh:
			var memory runtime.MemStats
			runtime.ReadMemStats(&memory)
			denominator, changed := sampler.adjust(memory.HeapAlloc)
			if !changed {
				continue
			}
			if err = t.bpf.SetSampleDenominator(denominator); err != nil {
				return fmt.Errorf("update adaptive sampling: %w", err)
			}
			log.Warnf("heap %d MiB, target %d MiB, sampling set to 1/%d", memory.HeapAlloc>>20, t.cfg.memoryLimitMB, denominator)
		}
	}
	stats, err := t.bpf.ReadRuntimeStats()
	if err != nil {
		return fmt.Errorf("read final runtime stats: %w", err)
	}
	return mgr.PrintRemaining(stats)
}
