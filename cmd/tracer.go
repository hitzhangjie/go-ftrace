package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"strings"

	"github.com/hitzhangjie/go-ftrace/elf"
	"github.com/hitzhangjie/go-ftrace/internal/bpf"
	"github.com/hitzhangjie/go-ftrace/internal/eventmanager"
	"github.com/hitzhangjie/go-ftrace/internal/uprobe"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

var (
	OffsetPattern *regexp.Regexp
)

func init() {
	OffsetPattern = regexp.MustCompile(`\+\d+$`)
}

type Tracer struct {
	bin             string
	elf             *elf.ELF
	excludeVendor   bool
	uprobeWildcards []string
	fetch           []string

	bpf *bpf.BPF
}

// NewTracer create a new tracer for ELF executable `bin`, it attach uprobes listed in `uprobeWildcards`,
// and output statistics of functions filtered by fetch
func NewTracer(bin string, excludeVendor bool, uprobeWildcards, fetch []string) (_ *Tracer, err error) {
	elf, err := elf.New(bin)
	if err != nil {
		return
	}

	return &Tracer{
		bin:             bin,
		elf:             elf,
		excludeVendor:   excludeVendor,
		uprobeWildcards: uprobeWildcards,
		fetch:           fetch,

		bpf: bpf.New(),
	}, nil
}

// Parse parse the args `ftrace [flags] binary <args>`
//
// @return out: the function names to output
// @return fetch: the function name => parameters (parameter name => parameter value)
// @return err: return err if <args> is invalid
func (t *Tracer) Parse() (funcs []string, fetchArgs map[string]map[string]string, err error) {
	fetchArgs = map[string]map[string]string{}
	for _, s := range t.fetch {

		// see: go.etcd.io/etcd/client/v3/concurrency.(*Mutex).tryAcquire(pfx=+0(+8(%ax)):c512, n_pfx=+16(%ax):u64, m.s.id=16(0(%ax)):u64 )
		if s[len(s)-1] == ')' {
			stack := []byte{')'}
			for i := len(s) - 2; i >= 0; i-- {
				// verifying the balance parenthese of expression ...tryAcquire.(pfx=, n_pfx=, ...)
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
				if len(stack) == 0 {
					funcname := s[:i]
					fetchArgs[funcname] = map[string]string{}
					// keep parsing the (pfx= , n_pfx= , ...)
					for _, part := range strings.Split(s[i+1:len(s)-1], ",") {
						varState := strings.Split(part, "=")
						if len(varState) != 2 {
							err = fmt.Errorf("invalid variable statement: %s", varState)
							return
						}
						fetchArgs[funcname][strings.TrimSpace(varState[0])] = strings.TrimSpace(varState[1])
					}
					// now shrink s to function name
					s = s[:i]
					break
				}
			}
			if len(stack) > 0 {
				err = fmt.Errorf("imbalanced parenthese: %s", s)
				return
			}
		}
		// see: go.etcd.io/etcd/client/v3/concurrency.(*Mutex).tryAcquire
		funcs = append(funcs, s)
	}
	return
}

func (t *Tracer) Start() (err error) {
	funcs, fetchArgs, err := t.Parse()
	if err != nil {
		return
	}
	uprobes, err := uprobe.Parse(t.elf, &uprobe.ParseOptions{
		ExcludeVendor:   t.excludeVendor,
		UprobeWildcards: t.uprobeWildcards,
		FuncNames:       funcs,
		FetchFuncArgs:   fetchArgs,
	})
	if err != nil {
		return
	}

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

	goidOffset, err := t.elf.FindGoidOffset()
	if err != nil {
		return
	}
	gOffset, err := t.elf.FindGOffset()
	if err != nil {
		return
	}
	log.Debugf("offset of goid from g is %d, offset of g from fs is -0x%x\n", goidOffset, -gOffset)
	if err = t.bpf.Load(uprobes, bpf.LoadOptions{
		GoidOffset: goidOffset,
		GOffset:    gOffset,
	}); err != nil {
		return
	}
	if err = t.bpf.Attach(t.bin, uprobes); err != nil {
		return
	}

	defer t.bpf.Detach()
	log.Info("start tracing\n")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	eventManager, err := eventmanager.New(uprobes, t.elf, t.bpf.PollArg(ctx))
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
