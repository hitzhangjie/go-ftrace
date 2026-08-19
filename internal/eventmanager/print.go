package eventmanager

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/hitzhangjie/go-ftrace/internal/uprobe"
)

const placeholder = "        "

// PrintStack print the callstack of a traced function
func (m *EventManager) PrintStack(goid uint64) (err error) {
	indent := ""
	fmt.Println()
	startTimeStack := []uint64{}
	for _, event := range m.goEvents[goid] {
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
	for goid := range m.goEvents {
		if err = m.PrintStack(goid); err != nil {
			break
		}
	}
	return
}
