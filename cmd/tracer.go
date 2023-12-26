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
	bin             string
	elf             *elf.ELF
	excludeVendor   bool
	uprobeWildcards []string
	fetch           []string
	drilldown       string

	bpf *bpf.BPF
}

// NewTracer create a new tracer for ELF executable `bin`, it attach uprobes listed in `uprobeWildcards`,
// and output statistics of functions filtered by fetch
//
// `drilldown` means only show the callstack of the specified function.
// TODO should we define it as a wildcast pattern, maybe a []string or []patterns?
func NewTracer(bin string, excludeVendor bool, uprobeWildcards, fetch []string, drilldown string) (_ *Tracer, err error) {
	elf, err := elf.New(bin)
	if err != nil {
		return
	}

	tracer := &Tracer{
		bin:             bin,
		elf:             elf,
		excludeVendor:   excludeVendor,
		uprobeWildcards: uprobeWildcards,
		fetch:           fetch,
		drilldown:       drilldown,
		bpf:             bpf.New(),
	}
	return tracer, nil
}

// Parse parse the args `ftrace [flags] binary <args>`
//
// @return funcs    : the function names to trace
// @return fetchArgs: the function name => parameters (parameter name => parameter <EA_expr>:<type>)
// @return err      : return err if <args> is invalid
//
// Here `EA_expr` is the expression of effective address, based on register and memory addressing mode.
func (t *Tracer) Parse() (funcs []string, fetchArgs map[string]map[string]string, err error) {
	fetchArgs = map[string]map[string]string{}
	for _, s := range t.fetch {
		// see: main.(*Student).String
		if s[len(s)-1] != ')' {
			funcs = append(funcs, s)
			continue
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

			funcname := s[:i]
			fetchArgs[funcname] = map[string]string{}

			// keep parsing the (s.name= , s.name.len= , s.age=...)
			for _, part := range strings.Split(s[i+1:len(s)-1], ",") {
				vals := strings.Split(part, "=")
				if len(vals) != 2 {
					err = fmt.Errorf("invalid variable statement: %s", vals)
					return
				}
				argName := strings.TrimSpace(vals[0])
				argExpr := strings.TrimSpace(vals[1])
				fetchArgs[funcname][argName] = argExpr
			}
			// now shrink s to function name
			s = s[:i]
			break
		}
		if len(stack) > 0 {
			err = fmt.Errorf("imbalanced parenthese: %s", s)
			return
		}
		// see: main.(*Student).String
		funcs = append(funcs, s)
	}
	return
}

// Start start tracing
func (t *Tracer) Start() (err error) {
	funcs, fetchArgs, err := t.Parse()
	if err != nil {
		return
	}
	// parse uprobes
	uprobes, err := uprobe.Parse(t.elf, &uprobe.ParseOptions{
		ExcludeVendor:   t.excludeVendor,
		UprobeWildcards: t.uprobeWildcards,
		FuncNames:       funcs,
		FetchFuncArgs:   fetchArgs,
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
	eventManager, err := eventmanager.New(uprobes, t.drilldown, t.elf, t.bpf.PollArg(ctx))
	if err != nil {
		return
	}
	for event := range t.bpf.PollEvents(ctx) {
		if err = eventManager.Handle(event); err != nil {
			return
		}
	}
	return eventManager.PrintRemaining()
}
