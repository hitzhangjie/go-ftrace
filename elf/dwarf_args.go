package elf

import (
	"debug/dwarf"
	"fmt"
	"strings"
)

// Variable describes a single function parameter or return value that has
// been extracted from the DWARF debug information.
//
// The concrete location of a value is deliberately not resolved here. Go's
// register-based ABI (regabi) assigns arguments and return values to integer
// registers in a fixed, deterministic order, so the caller can reconstruct the
// location from the declaration order plus the type tree alone.
type Variable struct {
	Name  string
	IsRet bool
	Type  dwarf.Type
}

// FunctionVariables extracts the parameters and return values of funcname.
//
// Return values are identified by the Go DWARF convention: they carry a
// DW_AT_variable_parameter flag and/or are named ~r0, ~r1, ... The returned
// slices preserve DWARF declaration order.
func (e *ELF) FunctionVariables(funcname string) (args, rets []*Variable, err error) {
	dies, err := e.NonInlinedSubprogramDIEs()
	if err != nil {
		return nil, nil, err
	}
	die, ok := dies[funcname]
	if !ok {
		return nil, nil, fmt.Errorf("%s: %s", DIENotFoundError, funcname)
	}

	for _, child := range e.dieChildren(die) {
		if child.Tag != dwarf.TagFormalParameter {
			continue
		}
		name, _ := child.Val(dwarf.AttrName).(string)
		varp, _ := child.Val(dwarf.AttrVarParam).(bool)
		toff, ok := child.Val(dwarf.AttrType).(dwarf.Offset)
		if !ok {
			continue
		}
		typ, err := e.dwarfData.Type(toff)
		if err != nil {
			continue
		}

		// A parameter is a return value if it is marked with
		// DW_AT_variable_parameter or follows Go's ~rN naming convention.
		isRet := varp || strings.HasPrefix(name, "~r")
		v := &Variable{Name: name, IsRet: isRet, Type: typ}
		if isRet {
			rets = append(rets, v)
		} else {
			args = append(args, v)
		}
	}
	return args, rets, nil
}

// dieChildren returns the direct children of die.
func (e *ELF) dieChildren(die *dwarf.Entry) []*dwarf.Entry {
	if die == nil || !die.Children {
		return nil
	}
	r := e.dwarfData.Reader()
	r.Seek(die.Offset)
	if _, err := r.Next(); err != nil { // consume die itself
		return nil
	}

	var out []*dwarf.Entry
	depth := 0
	for {
		c, err := r.Next()
		if err != nil || c == nil {
			break
		}
		if c.Tag == 0 { // null entry terminates a sibling list
			if depth == 0 {
				break
			}
			depth--
			continue
		}
		out = append(out, c)
		if c.Children {
			depth++
		}
	}
	return out
}
