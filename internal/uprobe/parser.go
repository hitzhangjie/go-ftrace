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

// FetchArgExpr is a single variable fetch expression, kept in the order the
// user declared it, so the printed argument order matches the rule order.
type FetchArgExpr struct {
	Varname string
	Expr    string
}

type ParseOptions struct {
	ExcludeVendor    bool
	UprobeWildcards  []string
	FuncNames        []string
	FetchFuncArgs    map[string][]FetchArgExpr // funcname: ordered var exprs (entry args)
	RetFetchFuncArgs map[string][]FetchArgExpr // funcname: ordered var exprs (return values)

	// AutoFetchArgs enables automatic derivation of entry-argument fetch
	// rules from DWARF debug info for functions that do not have an explicit
	// --fargs rule.
	AutoFetchArgs bool

	// AutoFetchRets enables automatic derivation of return-value fetch rules
	// from DWARF debug info for functions that do not have an explicit
	// --frets rule.
	AutoFetchRets bool
}

// Parse parses the wanted function names (and its parameters), and parse DWARF info, ELF info
// to determine the addresses of all wanted functions' entry and (multiple) return instruction,
// then build the uprobes that will be attached.
func Parse(elf *elf.ELF, opts *ParseOptions) (uprobes []Uprobe, err error) {
	fetchArgs, err := parseFetchArgs(opts.FetchFuncArgs)
	if err != nil {
		return
	}
	retFetchArgs, err := parseFetchArgs(opts.RetFetchFuncArgs)
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

	// Fill in automatically derived fetch rules (and their type-aware value
	// trees) for functions that do not have explicit --fargs/--frets rules.
	argValues := map[string][]*Value{}
	retValues := map[string][]*Value{}
	fillAutoFetch(elf, attachFuncs, fetchArgs, retFetchArgs, argValues, retValues, opts.AutoFetchArgs, opts.AutoFetchRets)

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
			Values:    argValues[funcname],
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
				Funcname: funcname,
				Location: AtRet,
				// the absolute virtual address of the RET instruction, used as
				// the key of arg_rules_map when fetching return values
				Address:   sym.Value + (retOffset - entOffset),
				AbsOffset: retOffset,
				RelOffset: retOffset - entOffset,
				FetchArgs: retFetchArgs[funcname],
				Values:    retValues[funcname],
				Wanted:    wanted,
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
