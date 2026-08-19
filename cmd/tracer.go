package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"

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
	excludeVendor   bool
	uprobeWildcards []string
	fargs           []string
	frets           []string
	drilldown       string
	trimprefix      string
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
		GoidOffset: goidOffset,
		GOffset:    gOffset,
	}); err != nil {
		return
	}

	// attach uprobes (and detach when exit)
	if err = t.bpf.Attach(t.bin, uprobes); err != nil {
		return
	}

	defer t.bpf.Detach()
	log.Info("start tracing\n")

	// exit when receive SIGINT
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// create eventmanager to poll events, prepare the callstack and print
	mgr, err := eventmanager.New(uprobes, t.elf, t.bpf.PollArg(ctx),
		t.cfg.drilldown,
		t.cfg.trimprefix)
	if err != nil {
		return
	}
	for event := range t.bpf.PollEvents(ctx) {
		if err = mgr.Handle(event); err != nil {
			return
		}
	}
	return mgr.PrintRemaining()
}
