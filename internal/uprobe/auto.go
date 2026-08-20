package uprobe

import (
	"debug/dwarf"
	"strconv"
	"strings"

	"github.com/hitzhangjie/go-ftrace/elf"
	log "github.com/sirupsen/logrus"
)

// abiRegs is the Go ABI (regabi) assignment order for integer/pointer
// arguments and return values on amd64.
var abiRegs = []string{"ax", "bx", "cx", "di", "si", "r8", "r9", "r10", "r11"}

// autoStringSize is how many bytes of a Go string's backing array are fetched.
// It matches the BPF arg_data payload size (MAX_DATA_SIZE) so short strings are
// captured in full; the printed content is truncated to the string's runtime
// length during rendering.
const autoStringSize = 64

// argSpec describes a single leaf value that will be fetched and printed. It is
// the flat, BPF-facing representation; the parallel Value tree (see value.go)
// carries the type structure needed for debugger-style rendering.
type argSpec struct {
	name string
	size int
	typ  string // "s8"..."s64", "u8"..."u64", "f32","f64", "bool", "c512"

	// location. When rules is empty, the compact reg/mem fields describe a
	// direct register or one-step memory read. rules is used for paths that
	// need multiple dereferences, notably an interface's dynamic data word.
	reg    string
	mem    bool
	offset int64
	deref  bool
	rules  []*ArgRule

	// nilCheck marks a value whose base register holds a possibly-nil
	// pointer; the BPF program reports the fetched value as nil (is_nil=1)
	// instead of dereferencing address 0.
	nilCheck bool
}

func (s argSpec) fetchArg() *FetchArg {
	rules := s.rules
	if len(rules) == 0 {
		rules = []*ArgRule{{From: Register, Register: s.reg}}
		if s.mem {
			rules = append(rules, &ArgRule{From: Stack, Offset: s.offset, Dereference: s.deref})
		}
	}
	return &FetchArg{
		Varname:  s.name,
		Type:     s.typ,
		Size:     s.size,
		Rules:    rules,
		NilCheck: s.nilCheck,
	}
}

// fillAutoFetch derives fetch rules (and their type-aware value trees) for
// every traced function that does not already have explicit rules. Explicit
// rules always win.
//
// autoArgs / autoRets independently control whether entry arguments and return
// values are derived, respectively.
func fillAutoFetch(e *elf.ELF, funcnames []string,
	fetchArgs, retFetchArgs map[string][]*FetchArg,
	argValues, retValues map[string][]*Value,
	autoArgs, autoRets bool) {

	if !autoArgs && !autoRets {
		return
	}
	for _, fn := range funcnames {
		needEntry := autoArgs && len(fetchArgs[fn]) == 0
		needRet := autoRets && len(retFetchArgs[fn]) == 0
		if !needEntry && !needRet {
			continue
		}
		ea, ev, ra, rv := autoFetchArgs(e, fn)
		if needEntry && len(ea) > 0 {
			fetchArgs[fn] = ea
			argValues[fn] = ev
		}
		if needRet && len(ra) > 0 {
			retFetchArgs[fn] = ra
			retValues[fn] = rv
		}
	}
}

// autoFetchArgs derives the entry-argument and return-value fetch rules (and
// value trees) for funcname from its DWARF debug information.
func autoFetchArgs(elf *elf.ELF, funcname string) (entryArgs []*FetchArg, entryValues []*Value, retArgs []*FetchArg, retValues []*Value) {
	args, rets, err := elf.FunctionVariables(funcname)
	if err != nil {
		log.Debugf("auto-fetch: skip %s: %v", funcname, err)
		return nil, nil, nil, nil
	}

	entryArgs, entryValues = deriveArgs(elf, args)
	retArgs, retValues = deriveRets(elf, rets)
	return entryArgs, entryValues, retArgs, retValues
}

// deriveArgs builds FetchArgs for input parameters by flattening each type
// tree into words and assigning them to integer registers in Go ABI order.
// It also builds the type-aware value tree used for debugger-style rendering.
func deriveArgs(elf *elf.ELF, vars []*elf.Variable) ([]*FetchArg, []*Value) {
	ctx := &flatCtx{out: []argSpec{}, words: abiRegs, wi: 0, elf: elf}
	var values []*Value
	for _, v := range vars {
		if ctx.full() {
			break
		}
		if node := flattenWord(v.Type, v.Name, ctx); node != nil {
			values = append(values, node)
		}
	}
	return ctx.build(), values
}

// deriveRets builds FetchArgs for return values by assigning the flattened
// return words to registers in Go ABI order, together with the value tree.
func deriveRets(elf *elf.ELF, vars []*elf.Variable) ([]*FetchArg, []*Value) {
	ctx := &flatCtx{out: []argSpec{}, words: abiRegs, wi: 0, elf: elf}
	var values []*Value
	for _, v := range vars {
		if ctx.full() {
			break
		}
		if node := flattenWord(v.Type, retName(v.Name), ctx); node != nil {
			values = append(values, node)
		}
	}
	return ctx.build(), values
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
	elf    *elf.ELF
}

func (c *flatCtx) full() bool { return len(c.out) >= MaxFetchArgs }

func (c *flatCtx) reserve(n int) bool {
	if len(c.out)+n <= MaxFetchArgs {
		return true
	}
	c.broken = true
	return false
}

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
		log.Warnf("auto-fetch: register or fetch-argument limit reached, some values were skipped")
	}
	out := make([]*FetchArg, 0, len(c.out))
	for _, s := range c.out {
		out = append(out, s.fetchArg())
	}
	return out
}

// leaf appends an argSpec to the flat output and wraps it in a leaf Value.
func (c *flatCtx) leaf(spec argSpec, kind ValueKind) *Value {
	c.out = append(c.out, spec)
	return &Value{Kind: kind, Name: spec.name, Typ: spec.typ, Size: spec.size}
}

// scalarRegLeaf consumes a register and emits a scalar leaf of the given kind.
func (c *flatCtx) scalarRegLeaf(name string, kind ValueKind, typ string, size int, reg string) *Value {
	return c.leaf(scalarRegSpec(name, size, typ, reg), kind)
}

// flattenWord flattens a value that lives in one or more registers (the Go ABI
// layout at function entry / exit) and returns its Value tree node.
func flattenWord(t dwarf.Type, name string, c *flatCtx) *Value {
	t = underlying(t)
	switch tt := t.(type) {
	case *dwarf.PtrType:
		pointee := underlying(tt.Type)
		if st, ok := pointee.(*dwarf.StructType); ok && !isRuntimeStruct(st) {
			// pointer to struct: consume the pointer word, then dereference
			// and flatten the struct fields. The pointer may be nil, so every
			// field is marked for nil-checking against this word.
			reg := c.nextWord()
			if reg == "" {
				return nil
			}
			node := flattenMemory(tt.Type, name, reg, 0, true, c)
			if node == nil || (c.broken && node.leafCount() == 0) {
				return nil
			}
			return &Value{Kind: KindStructPtr, Name: name, Fields: node.Fields, StructName: node.StructName}
		}
		// opaque pointer: scalar pointer, map, chan, func, etc. Print the
		// address (or nil), without dereferencing.
		reg := c.nextWord()
		if reg == "" {
			return nil
		}
		return c.scalarRegLeaf(name, KindPointer, "u64", 8, reg)

	case *dwarf.StructType:
		switch {
		case isString(tt):
			if !c.reserve(2) {
				return nil
			}
			data := c.nextWord()
			ln := c.nextWord()
			if data == "" || ln == "" {
				return nil
			}
			c.out = append(c.out, stringDataSpec(name+".data", data, 0, false, false))
			c.out = append(c.out, scalarRegSpec(name+".len", 8, "s64", ln))
			return &Value{Kind: KindString, Name: name}
		case isSlice(tt):
			if !c.reserve(3) {
				return nil
			}
			data := c.nextWord()
			ln := c.nextWord()
			cap := c.nextWord()
			if data == "" || ln == "" || cap == "" {
				return nil
			}
			c.out = append(c.out, scalarRegSpec(name+".data", 8, "u64", data))
			c.out = append(c.out, scalarRegSpec(name+".len", 8, "s64", ln))
			c.out = append(c.out, scalarRegSpec(name+".cap", 8, "s64", cap))
			return &Value{Kind: KindSlice, Name: name, ElemType: tt.StructName}
		case isInterface(tt):
			if !c.reserve(3) {
				return nil
			}
			typeReg := c.nextWord()
			dataReg := c.nextWord()
			if typeReg == "" || dataReg == "" {
				return nil
			}
			return flattenInterfaceWord(tt, name, typeReg, dataReg, c)
		default:
			var fields []*Value
			for _, f := range tt.Field {
				if c.full() {
					break
				}
				if child := flattenWord(f.Type, name+"."+f.Name, c); child != nil {
					fields = append(fields, child)
				} else if c.broken {
					break
				}
			}
			return &Value{Kind: KindStruct, Name: name, Fields: fields, StructName: tt.StructName}
		}

	default:
		kind, typ, size, ok := scalarValue(t)
		if !ok {
			log.Debugf("auto-fetch: unsupported type %s (%T) for %q, skipped", t.String(), t, name)
			return nil
		}
		reg := c.nextWord()
		if reg == "" {
			return nil
		}
		return c.scalarRegLeaf(name, kind, typ, size, reg)
	}
}

// flattenMemory flattens a value located at memory address (base + offset) and
// returns its Value tree node. It is used to dereference a struct pointer.
// nilCheck is propagated to every leaf value so that, when the base pointer is
// nil, the BPF program reports the value as nil instead of dereferencing
// address 0.
func flattenMemory(t dwarf.Type, name string, base string, offset int64, nilCheck bool, c *flatCtx) *Value {
	t = underlying(t)
	switch tt := t.(type) {
	case *dwarf.StructType:
		switch {
		case isString(tt):
			if !c.reserve(2) {
				return nil
			}
			c.out = append(c.out, stringDataSpec(name+".data", base, offset, true, nilCheck))
			c.out = append(c.out, memScalarSpec(name+".len", 8, "s64", base, offset+8, nilCheck))
			return &Value{Kind: KindString, Name: name}
		case isSlice(tt):
			if !c.reserve(3) {
				return nil
			}
			c.out = append(c.out, memScalarSpec(name+".data", 8, "u64", base, offset, nilCheck))
			c.out = append(c.out, memScalarSpec(name+".len", 8, "s64", base, offset+8, nilCheck))
			c.out = append(c.out, memScalarSpec(name+".cap", 8, "s64", base, offset+16, nilCheck))
			return &Value{Kind: KindSlice, Name: name, ElemType: tt.StructName}
		case isInterface(tt):
			if !c.reserve(3) {
				return nil
			}
			return flattenInterfaceMemory(tt, name, base, offset, nilCheck, c)
		default:
			var fields []*Value
			for _, f := range tt.Field {
				if c.full() {
					break
				}
				if child := flattenMemory(f.Type, name+"."+f.Name, base, offset+f.ByteOffset, nilCheck, c); child != nil {
					fields = append(fields, child)
				} else if c.broken {
					break
				}
			}
			return &Value{Kind: KindStruct, Name: name, Fields: fields, StructName: tt.StructName}
		}
	case *dwarf.PtrType:
		// nested pointer: print its value, no further dereferencing.
		c.out = append(c.out, memScalarSpec(name, 8, "u64", base, offset, nilCheck))
		return &Value{Kind: KindPointer, Name: name, Typ: "u64", Size: 8}
	default:
		kind, typ, size, ok := scalarValue(t)
		if !ok {
			log.Debugf("auto-fetch: unsupported nested type %s (%T) for %q, skipped", t.String(), t, name)
			return nil
		}
		c.out = append(c.out, memScalarSpec(name, size, typ, base, offset, nilCheck))
		return &Value{Kind: kind, Name: name, Typ: typ, Size: size}
	}
}

func scalarRegSpec(name string, size int, typ, reg string) argSpec {
	return argSpec{name: name, size: size, typ: typ, reg: reg}
}

func memScalarSpec(name string, size int, typ, base string, offset int64, nilCheck bool) argSpec {
	return argSpec{name: name, size: size, typ: typ, reg: base, mem: true, offset: offset, nilCheck: nilCheck}
}

func stringDataSpec(name, reg string, offset int64, deref bool, nilCheck bool) argSpec {
	return argSpec{name: name, size: autoStringSize, typ: "c" + strconv.Itoa(autoStringSize*8), reg: reg, mem: true, offset: offset, deref: deref, nilCheck: nilCheck}
}

func rulesSpec(name string, size int, typ string, rules []*ArgRule, nilCheck bool) argSpec {
	return argSpec{name: name, size: size, typ: typ, rules: rules, nilCheck: nilCheck}
}

func flattenInterfaceWord(st *dwarf.StructType, name, typeReg, dataReg string, c *flatCtx) *Value {
	nonEmpty := interfaceIsNonEmpty(st)
	typeRules := []*ArgRule{{From: Register, Register: typeReg}}
	if nonEmpty {
		// iface.tab points to abi.ITab; ITab.Type is the second pointer word.
		typeRules = append(typeRules, &ArgRule{From: Stack, Offset: 8, Dereference: false})
	}
	c.out = append(c.out, rulesSpec(name+".type", 8, "u64", typeRules, false))
	c.out = append(c.out, scalarRegSpec(name+".data", 8, "u64", dataReg))
	// Capture a stable prefix of the concrete value while the target thread is
	// stopped at the probe. Nested pointer-backed data can then be completed by
	// the userspace memory reader during recursive rendering.
	c.out = append(c.out, rulesSpec(name+".value", autoStringSize, "c512", []*ArgRule{
		{From: Register, Register: dataReg},
		{From: Stack, Offset: 0, Dereference: false},
	}, false))
	return &Value{Kind: KindInterface, Name: name, InterfaceNonEmpty: nonEmpty, RuntimeType: c.elf.RuntimeType}
}

func flattenInterfaceMemory(st *dwarf.StructType, name, base string, offset int64, nilCheck bool, c *flatCtx) *Value {
	nonEmpty := interfaceIsNonEmpty(st)
	typeRules := []*ArgRule{{From: Register, Register: base}}
	if nonEmpty {
		// *(base+offset) is the itab pointer; its second word is the concrete type.
		typeRules = append(typeRules,
			&ArgRule{From: Stack, Offset: offset, Dereference: true},
			&ArgRule{From: Stack, Offset: 8, Dereference: false})
	} else {
		// eface._type is already the concrete type pointer stored at base+offset.
		typeRules = append(typeRules, &ArgRule{From: Stack, Offset: offset, Dereference: false})
	}
	c.out = append(c.out, rulesSpec(name+".type", 8, "u64", typeRules, nilCheck))
	c.out = append(c.out, memScalarSpec(name+".data", 8, "u64", base, offset+8, nilCheck))
	c.out = append(c.out, rulesSpec(name+".value", autoStringSize, "c512", []*ArgRule{
		{From: Register, Register: base},
		{From: Stack, Offset: offset + 8, Dereference: true},
		{From: Stack, Offset: 0, Dereference: false},
	}, nilCheck))
	return &Value{Kind: KindInterface, Name: name, InterfaceNonEmpty: nonEmpty, RuntimeType: c.elf.RuntimeType}
}

func interfaceIsNonEmpty(st *dwarf.StructType) bool {
	return st.StructName == "runtime.iface" || hasFields(st, "tab", "data")
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

// scalarValue classifies a scalar DWARF type into a render kind and a decode
// type string. It reports ok=false for non-scalar types (pointers, structs,
// arrays, functions, ...), which are handled by the callers.
func scalarValue(t dwarf.Type) (kind ValueKind, typ string, size int, ok bool) {
	switch tt := t.(type) {
	case *dwarf.BoolType:
		size = int(tt.Common().ByteSize)
		return KindBool, "bool", size, true
	case *dwarf.FloatType:
		size = int(tt.Common().ByteSize)
		return KindFloat, "f" + strconv.Itoa(size*8), size, true
	case *dwarf.IntType:
		size = int(tt.Common().ByteSize)
		return KindScalar, "s" + strconv.Itoa(size*8), size, true
	case *dwarf.UintType:
		size = int(tt.Common().ByteSize)
		return KindScalar, "u" + strconv.Itoa(size*8), size, true
	case *dwarf.UcharType:
		size = int(tt.Common().ByteSize)
		return KindScalar, "u" + strconv.Itoa(size*8), size, true
	case *dwarf.CharType:
		size = int(tt.Common().ByteSize)
		return KindScalar, "s" + strconv.Itoa(size*8), size, true
	case *dwarf.EnumType:
		size = int(tt.Common().ByteSize)
		return KindScalar, "s" + strconv.Itoa(size*8), size, true
	}
	return 0, "", 0, false
}

// isRuntimeStruct reports whether st is a runtime-internal struct (map, chan)
// that should be printed as an opaque pointer instead of being flattened.
func isRuntimeStruct(st *dwarf.StructType) bool {
	switch st.StructName {
	case "runtime.hmap", "runtime.hchan":
		return true
	}
	return false
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
