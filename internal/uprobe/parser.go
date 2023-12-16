package uprobe

import (
	"bytes"
	debugelf "debug/elf"
	"errors"
	"fmt"
	"strings"

	"github.com/hitzhangjie/go-ftrace/elf"
	log "github.com/sirupsen/logrus"
)

type ParseOptions struct {
	ExcludeVendor   bool
	UprobeWildcards []string
	FuncNames       []string
	FetchFuncArgs   map[string]map[string]string // funcname: varname: expression
}

// Parse parses the wanted function names (and its parameters), and parse DWARF info, ELF info
// to determine the addresses of all wanted functions' entry and (multiple) return instruction,
// then build the uprobes that will be attached.
func Parse(elf *elf.ELF, opts *ParseOptions) (uprobes []Uprobe, err error) {
	fetchArgs, err := parseFetchArgs(opts.FetchFuncArgs)
	if err != nil {
		return
	}

	symbols, _, err := elf.Symbols()
	if err != nil {
		return
	}

	wantedFuncs := map[string]interface{}{}
	attachFuncs := []string{}

	funcs := append(opts.UprobeWildcards, opts.FuncNames...)
	for _, symbol := range symbols {
		if debugelf.ST_TYPE(symbol.Info) != debugelf.STT_FUNC {
			continue
		}
		for _, fn := range funcs {
			if !MatchWildcard(fn, symbol.Name) {
				continue
			}
			if opts.ExcludeVendor && strings.Contains(symbol.Name, "/vendor/") {
				continue
			}
			// record the function name that will be traced
			attachFuncs = append(attachFuncs, symbol.Name)
			// record the function arguments that will be traced
			if len(opts.FuncNames) == 0 {
				wantedFuncs[symbol.Name] = true
			} else {
				for _, fn := range opts.FuncNames {
					if MatchWildcard(fn, symbol.Name) {
						wantedFuncs[symbol.Name] = true
						break
					}
				}
			}
			break
		}
	}

	sym, err := elf.ResolveSymbol("runtime.goexit1")
	if err != nil {
		return nil, err
	}
	entOffset, err := elf.FuncOffset("runtime.goexit1")
	if err != nil {
		return nil, err
	}
	uprobes = append(uprobes, Uprobe{
		Funcname:  "runtime.goexit1",
		Location:  AtGoroutineExit,
		Address:   sym.Value,
		AbsOffset: entOffset,
	})

	for _, funcname := range attachFuncs {
		message := &bytes.Buffer{}
		fmt.Fprintf(message, "add uprobes for %s: ", funcname)

		sym, err := elf.ResolveSymbol(funcname)
		if err != nil {
			return nil, err
		}

		entOffset, err := elf.FuncOffset(funcname)
		if err != nil {
			return nil, err
		}
		_, wanted := wantedFuncs[funcname]
		fmt.Fprintf(message, "0x%x -> ", entOffset)

		// uprobes for function entry
		uprobes = append(uprobes, Uprobe{
			Funcname:  funcname,
			Location:  AtEntry,
			Address:   sym.Value,
			AbsOffset: entOffset,
			RelOffset: 0,
			FetchArgs: fetchArgs[funcname],
			Wanted:    wanted,
		})

		// uprobes for function return (may have multiple return statements)
		retOffsets, err := elf.FuncRetOffsets(funcname)
		if err == nil && len(retOffsets) == 0 {
			err = errors.New("no ret offsets")
		}
		if err != nil {
			log.Warnf("skip %s, failed to get ret offsets: %v", funcname, err)
			uprobes = uprobes[:len(uprobes)-1]
			continue
		}
		fmt.Fprintf(message, "[ ")
		for _, retOffset := range retOffsets {
			fmt.Fprintf(message, "0x%x ", retOffset)
			uprobes = append(uprobes, Uprobe{
				Funcname:  funcname,
				Location:  AtRet,
				AbsOffset: retOffset,
				RelOffset: retOffset - entOffset,
			})
		}
		fmt.Fprintf(message, "]")
		if wanted {
			fmt.Fprintf(message, " *")
		}
		fmt.Fprintf(message, "\n")
		log.Debug(message.String())
	}
	return
}
