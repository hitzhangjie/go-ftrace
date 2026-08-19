package uprobe

import (
	"debug/dwarf"
	"fmt"
	"strings"

	"github.com/hitzhangjie/go-ftrace/elf"
	log "github.com/sirupsen/logrus"
)

// maxAutoFetchArgs is the hard limit imposed by the BPF arg_rules map (it
// holds at most 8 arg_rule entries per uprobe).
const maxAutoFetchArgs = 8

// abiRegs is the Go ABI (regabi) assignment order for integer/pointer
// arguments and return values on amd64.
var abiRegs = []string{"ax", "bx", "cx", "di", "si", "r8", "r9", "r10", "r11"}

// argSpec describes a single leaf value that will be fetched and printed.
type argSpec struct {
	name string
	size int
	typ  string // "s8"..."s64", "u8"..."u64", "c64"

	// location. When mem is false the value is read directly from the
	// register reg. When mem is true the value is read from memory at
	// (reg + offset), with an optional pointer dereference beforehand.
	reg    string
	mem    bool
	offset int64
	deref  bool
}

func (s argSpec) fetchArg() *FetchArg {
	rules := []*ArgRule{{From: Register, Register: s.reg}}
	if s.mem {
		rules = append(rules, &ArgRule{From: Stack, Offset: s.offset, Dereference: s.deref})
	}
	return &FetchArg{
		Varname: s.name,
		Type:    s.typ,
		Size:    s.size,
		Rules:   rules,
	}
}

// fillAutoFetch derives fetch rules for every traced function that does not
// already have explicit rules. Explicit rules always win.
func fillAutoFetch(e *elf.ELF, funcnames []string, fetchArgs, retFetchArgs map[string][]*FetchArg) {
	for _, fn := range funcnames {
		needEntry := len(fetchArgs[fn]) == 0
		needRet := len(retFetchArgs[fn]) == 0
		if !needEntry && !needRet {
			continue
		}
		ea, ra := autoFetchArgs(e, fn)
		if needEntry && len(ea) > 0 {
			fetchArgs[fn] = ea
		}
		if needRet && len(ra) > 0 {
			retFetchArgs[fn] = ra
		}
	}
}

// autoFetchArgs derives the entry-argument and return-value fetch rules for
// funcname from its DWARF debug information.
func autoFetchArgs(elf *elf.ELF, funcname string) (entryArgs, retArgs []*FetchArg) {
	args, rets, err := elf.FunctionVariables(funcname)
	if err != nil {
		log.Debugf("auto-fetch: skip %s: %v", funcname, err)
		return nil, nil
	}

	entryArgs = deriveArgs(args)
	retArgs = deriveRets(rets)
	return entryArgs, retArgs
}

// deriveArgs builds FetchArgs for input parameters by flattening each type
// tree into words and assigning them to integer registers in Go ABI order.
func deriveArgs(vars []*elf.Variable) []*FetchArg {
	ctx := &flatCtx{out: []argSpec{}, words: abiRegs, wi: 0}
	for _, v := range vars {
		if ctx.full() {
			break
		}
		flattenWord(v.Type, v.Name, ctx)
	}
	return ctx.build()
}

// deriveRets builds FetchArgs for return values by assigning the flattened
// return words to registers in Go ABI order.
func deriveRets(vars []*elf.Variable) []*FetchArg {
	ctx := &flatCtx{out: []argSpec{}, words: abiRegs, wi: 0}
	for _, v := range vars {
		if ctx.full() {
			break
		}
		flattenWord(v.Type, retName(v.Name), ctx)
	}
	return ctx.build()
}

// retName renders Go's ~rN return-value names into something more readable.
func retName(name string) string {
	if strings.HasPrefix(name, "~r") {
		return "ret" + strings.TrimPrefix(name, "~r")
	}
	return name
}

// flatCtx tracks register word consumption while flattening types.
type flatCtx struct {
	words  []string
	wi     int
	out    []argSpec
	broken bool
}

func (c *flatCtx) full() bool { return len(c.out) >= maxAutoFetchArgs }

func (c *flatCtx) nextWord() string {
	if c.wi >= len(c.words) {
		c.broken = true
		return ""
	}
	r := c.words[c.wi]
	c.wi++
	return r
}

func (c *flatCtx) build() []*FetchArg {
	if c.broken {
		log.Warnf("auto-fetch: too many words, some arguments were skipped")
	}
	out := make([]*FetchArg, 0, len(c.out))
	for _, s := range c.out {
		out = append(out, s.fetchArg())
	}
	return out
}

// flattenWord flattens a value that lives in one or more registers (the Go
// ABI layout at function entry / exit).
func flattenWord(t dwarf.Type, name string, c *flatCtx) {
	t = underlying(t)
	switch tt := t.(type) {
	case *dwarf.PtrType:
		if _, ok := underlying(tt.Type).(*dwarf.StructType); ok {
			// pointer to struct: consume the pointer word, then dereference
			// and flatten the struct fields.
			reg := c.nextWord()
			if reg == "" {
				return
			}
			flattenMemory(tt.Type, name, reg, 0, c)
			return
		}
		if size, signed, ok := scalarInfo(t); ok {
			c.emitScalar(name, size, signed)
			return
		}
		// fallthrough: treat unknown pointer pointee as an opaque word
		reg := c.nextWord()
		if reg != "" {
			c.out = append(c.out, argSpec{name: name, size: 8, typ: "u64", reg: reg})
		}

	case *dwarf.StructType:
		switch {
		case isString(tt):
			data := c.nextWord()
			ln := c.nextWord()
			if data == "" || ln == "" {
				return
			}
			c.out = append(c.out, stringDataSpec(name+".data", data, 0, false))
			c.out = append(c.out, scalarRegSpec(name+".len", 8, "s", ln))
		case isSlice(tt):
			data := c.nextWord()
			ln := c.nextWord()
			cap := c.nextWord()
			if data == "" || ln == "" || cap == "" {
				return
			}
			c.out = append(c.out, scalarRegSpec(name+".data", 8, "u", data))
			c.out = append(c.out, scalarRegSpec(name+".len", 8, "s", ln))
			c.out = append(c.out, scalarRegSpec(name+".cap", 8, "s", cap))
		case isInterface(tt):
			itab := c.nextWord()
			data := c.nextWord()
			if itab == "" || data == "" {
				return
			}
			c.out = append(c.out, scalarRegSpec(name+".itab", 8, "u", itab))
			c.out = append(c.out, scalarRegSpec(name+".data", 8, "u", data))
		default:
			for _, f := range tt.Field {
				if c.full() {
					return
				}
				flattenWord(f.Type, name+"."+f.Name, c)
			}
		}

	default:
		if size, signed, ok := scalarInfo(t); ok {
			c.emitScalar(name, size, signed)
			return
		}
		log.Debugf("auto-fetch: unsupported type %s (%T) for %q, skipped", t.String(), t, name)
	}
}

// flattenMemory flattens a value located at memory address (base + offset).
// It is used to dereference a struct pointer.
func flattenMemory(t dwarf.Type, name string, base string, offset int64, c *flatCtx) {
	t = underlying(t)
	switch tt := t.(type) {
	case *dwarf.StructType:
		switch {
		case isString(tt):
			c.out = append(c.out, stringDataSpec(name+".data", base, offset, true))
			c.out = append(c.out, memScalarSpec(name+".len", 8, "s", base, offset+8))
		case isSlice(tt):
			c.out = append(c.out, memScalarSpec(name+".data", 8, "u", base, offset))
			c.out = append(c.out, memScalarSpec(name+".len", 8, "s", base, offset+8))
			c.out = append(c.out, memScalarSpec(name+".cap", 8, "s", base, offset+16))
		case isInterface(tt):
			c.out = append(c.out, memScalarSpec(name+".itab", 8, "u", base, offset))
			c.out = append(c.out, memScalarSpec(name+".data", 8, "u", base, offset+8))
		default:
			for _, f := range tt.Field {
				if c.full() {
					return
				}
				flattenMemory(f.Type, name+"."+f.Name, base, offset+f.ByteOffset, c)
			}
		}
	case *dwarf.PtrType:
		// nested pointer: print its value, no further dereferencing.
		c.out = append(c.out, memScalarSpec(name, 8, "u", base, offset))
	default:
		if size, signed, ok := scalarInfo(t); ok {
			c.out = append(c.out, memScalarSpec(name, size, signed, base, offset))
			return
		}
		log.Debugf("auto-fetch: unsupported nested type %s (%T) for %q, skipped", t.String(), t, name)
	}
}

func (c *flatCtx) emitScalar(name string, size int, signed string) {
	reg := c.nextWord()
	if reg == "" {
		return
	}
	c.out = append(c.out, scalarRegSpec(name, size, signed, reg))
}

func scalarRegSpec(name string, size int, signed, reg string) argSpec {
	return argSpec{name: name, size: size, typ: typeStr(signed, size), reg: reg}
}

func memScalarSpec(name string, size int, signed, base string, offset int64) argSpec {
	return argSpec{name: name, size: size, typ: typeStr(signed, size), reg: base, mem: true, offset: offset}
}

func stringDataSpec(name, reg string, offset int64, deref bool) argSpec {
	return argSpec{name: name, size: 8, typ: "c64", reg: reg, mem: true, offset: offset, deref: deref}
}

func typeStr(signed string, size int) string {
	return fmt.Sprintf("%s%d", signed, size*8)
}

// underlying unwraps typedef and qualifier chains.
func underlying(t dwarf.Type) dwarf.Type {
	for {
		switch tt := t.(type) {
		case *dwarf.TypedefType:
			t = tt.Type
		case *dwarf.QualType:
			t = tt.Type
		default:
			return t
		}
	}
}

// scalarInfo reports the byte size and signedness of a scalar type.
func scalarInfo(t dwarf.Type) (size int, signed string, ok bool) {
	switch tt := t.(type) {
	case *dwarf.IntType:
		return int(tt.Common().ByteSize), "s", true
	case *dwarf.UintType:
		return int(tt.Common().ByteSize), "u", true
	case *dwarf.UcharType:
		return int(tt.Common().ByteSize), "u", true
	case *dwarf.CharType:
		return int(tt.Common().ByteSize), "s", true
	case *dwarf.BoolType:
		return int(tt.Common().ByteSize), "u", true
	case *dwarf.EnumType:
		return int(tt.Common().ByteSize), "s", true
	case *dwarf.PtrType:
		return 8, "u", true
	}
	return 0, "", false
}

func isString(st *dwarf.StructType) bool {
	return st.StructName == "string"
}

func isSlice(st *dwarf.StructType) bool {
	if strings.HasPrefix(st.StructName, "[]") {
		return true
	}
	// Fallback for toolchains that don't name slice types after their element.
	return hasFields(st, "array", "len", "cap")
}

func isInterface(st *dwarf.StructType) bool {
	if st.StructName == "runtime.iface" || st.StructName == "runtime.eface" {
		return true
	}
	return hasFields(st, "tab", "data") || hasFields(st, "_type", "data")
}

func hasFields(st *dwarf.StructType, names ...string) bool {
	if len(st.Field) != len(names) {
		return false
	}
	for i, n := range names {
		if st.Field[i].Name != n {
			return false
		}
	}
	return true
}
