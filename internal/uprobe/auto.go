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

// autoStringSize is how many bytes of pointed-to memory are captured at
// probe time. It matches the BPF arg_data payload size (MAX_DATA_SIZE).
const autoStringSize = 64

var blobType = "c" + strconv.Itoa(autoStringSize*8)

// argSpec describes one BPF leaf compiled from dwarf.Type. Auto mode uses
// Type as a fetch planner: every heap/stack byte that rendering will need
// is copied when the uprobe fires, not when userspace later reads the event.
type argSpec struct {
	name     string
	size     int
	typ      string
	reg      string
	mem      bool
	offset   int64
	deref    bool
	nilCheck bool
	rules    []*ArgRule
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

// memLoc is a probe-time address computed from a base register and a sequence
// of add/deref steps. It is the addressing half of a FetchArg.
type memLoc struct {
	reg      string
	steps    []ArgRule
	nilCheck bool
}

func (l memLoc) add(off int64) memLoc {
	if off == 0 {
		return l
	}
	steps := append([]ArgRule(nil), l.steps...)
	steps = append(steps, ArgRule{From: Stack, Offset: off, Dereference: false})
	l.steps = steps
	return l
}

func (l memLoc) deref(off int64) memLoc {
	steps := append([]ArgRule(nil), l.steps...)
	steps = append(steps, ArgRule{From: Stack, Offset: off, Dereference: true})
	l.steps = steps
	return l
}

func locSpec(name string, loc memLoc, size int, typ string) argSpec {
	rules := []*ArgRule{{From: Register, Register: loc.reg}}
	if len(loc.steps) == 0 {
		rules = append(rules, &ArgRule{From: Stack, Offset: 0, Dereference: false})
	} else {
		for i := range loc.steps {
			step := loc.steps[i]
			rules = append(rules, &step)
		}
	}
	return argSpec{name: name, size: size, typ: typ, rules: rules, nilCheck: loc.nilCheck}
}

func blobAt(name string, loc memLoc) argSpec {
	return locSpec(name, loc, autoStringSize, blobType)
}

// fillAutoFetch derives fetch rules (and their type-aware value trees) for
// every traced function that does not already have explicit rules. Explicit
// rules always win.
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

func deriveArgs(elf *elf.ELF, vars []*elf.Variable) ([]*FetchArg, []*Value) {
	ctx := &flatCtx{out: []argSpec{}, words: abiRegs, wi: 0, elf: elf}
	var values []*Value
	for _, v := range vars {
		if ctx.full() {
			break
		}
		if node := planValue(v.Type, v.Name, ctx); node != nil {
			values = append(values, node)
		}
	}
	args := ctx.build()
	markIfaceSlots(args)
	return args, values
}

func deriveRets(elf *elf.ELF, vars []*elf.Variable) ([]*FetchArg, []*Value) {
	ctx := &flatCtx{out: []argSpec{}, words: abiRegs, wi: 0, elf: elf}
	var values []*Value
	for _, v := range vars {
		if ctx.full() {
			break
		}
		if node := planValue(v.Type, retName(v.Name), ctx); node != nil {
			values = append(values, node)
		}
	}
	args := ctx.build()
	markIfaceSlots(args)
	return args, values
}

func retName(name string) string {
	if strings.HasPrefix(name, "~r") {
		return "ret" + strings.TrimPrefix(name, "~r")
	}
	return name
}

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

func (c *flatCtx) runtimeType() func(uint64) (dwarf.Type, error) {
	if c.elf == nil {
		return nil
	}
	return c.elf.RuntimeType
}

// planValue compiles dwarf.Type into ABI-word fetches plus probe-time memory
// captures for anything rendering will dereference (string bytes, *T objects,
// interface concrete values, one extra pointer chase for unknown dynamic types).
func planValue(t dwarf.Type, name string, c *flatCtx) *Value {
	orig := t
	t = underlying(t)
	rt := c.runtimeType()

	switch tt := t.(type) {
	case *dwarf.PtrType:
		pointee := underlying(tt.Type)
		if st, ok := pointee.(*dwarf.StructType); ok && !isRuntimeStruct(st) {
			extras := extraCaptures(tt.Type, true)
			if !c.reserve(2 + extras) {
				return nil
			}
			reg := c.nextWord()
			if reg == "" {
				return nil
			}
			loc := memLoc{reg: reg, nilCheck: true}
			c.out = append(c.out, scalarRegSpec(name, 8, "u64", reg))
			c.out = append(c.out, blobAt(name+".obj", loc))
			emitMemCaptures(tt.Type, name, loc, c)
			return &Value{Name: name, Type: orig, WordCount: 1, Captures: 1 + extras, RuntimeType: rt}
		}
		reg := c.nextWord()
		if reg == "" {
			return nil
		}
		c.out = append(c.out, scalarRegSpec(name, 8, "u64", reg))
		return &Value{Name: name, Type: orig, WordCount: 1, RuntimeType: rt}

	case *dwarf.StructType:
		switch {
		case isString(tt):
			if !c.reserve(3) {
				return nil
			}
			data := c.nextWord()
			ln := c.nextWord()
			if data == "" || ln == "" {
				return nil
			}
			c.out = append(c.out, scalarRegSpec(name+".data", 8, "u64", data))
			c.out = append(c.out, scalarRegSpec(name+".len", 8, "s64", ln))
			c.out = append(c.out, blobAt(name+".str", memLoc{reg: data}))
			return &Value{Name: name, Type: orig, WordCount: 2, Captures: 1, RuntimeType: rt}

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
			return &Value{Name: name, Type: orig, WordCount: 3, RuntimeType: rt}

		case isInterface(tt):
			if !c.reserve(3) {
				return nil
			}
			typeReg := c.nextWord()
			dataReg := c.nextWord()
			if typeReg == "" || dataReg == "" {
				return nil
			}
			if interfaceIsNonEmpty(tt) {
				c.out = append(c.out, argSpec{name: name + ".type", size: 8, typ: "u64", reg: typeReg, mem: true, offset: 8, nilCheck: true})
			} else {
				c.out = append(c.out, scalarRegSpec(name+".type", 8, "u64", typeReg))
			}
			c.out = append(c.out, scalarRegSpec(name+".data", 8, "u64", dataReg))
			c.out = append(c.out, blobAt(name+".value", memLoc{reg: dataReg, nilCheck: true}))
			return &Value{Name: name, Type: orig, WordCount: 2, Captures: 1, RuntimeType: rt}

		default:
			n := abiWordCount(tt)
			extras := extraCaptures(tt, false)
			if n == 0 {
				log.Debugf("auto-fetch: unsupported type %s (%T) for %q, skipped", t.String(), t, name)
				return nil
			}
			if !c.reserve(n + extras) {
				return nil
			}
			jobs := emitABI(tt, name, c)
			for _, job := range jobs {
				emitRegCaptures(job, c)
			}
			return &Value{Name: name, Type: orig, WordCount: n, Captures: extras, RuntimeType: rt}
		}

	default:
		_, typ, size, ok := scalarValue(t)
		if !ok {
			log.Debugf("auto-fetch: unsupported type %s (%T) for %q, skipped", t.String(), t, name)
			return nil
		}
		reg := c.nextWord()
		if reg == "" {
			return nil
		}
		c.out = append(c.out, scalarRegSpec(name, size, typ, reg))
		return &Value{Name: name, Type: orig, WordCount: 1, RuntimeType: rt}
	}
}

type captureJob struct {
	name string
	typ  dwarf.Type
	loc  memLoc
}

func emitABI(t dwarf.Type, name string, c *flatCtx) []captureJob {
	t = underlying(t)
	switch tt := t.(type) {
	case *dwarf.StructType:
		switch {
		case isString(tt):
			data := c.nextWord()
			ln := c.nextWord()
			c.out = append(c.out, scalarRegSpec(name+".data", 8, "u64", data))
			c.out = append(c.out, scalarRegSpec(name+".len", 8, "s64", ln))
			return []captureJob{{name: name + ".str", typ: tt, loc: memLoc{reg: data}}}
		case isSlice(tt):
			data := c.nextWord()
			ln := c.nextWord()
			cap := c.nextWord()
			c.out = append(c.out, scalarRegSpec(name+".data", 8, "u64", data))
			c.out = append(c.out, scalarRegSpec(name+".len", 8, "s64", ln))
			c.out = append(c.out, scalarRegSpec(name+".cap", 8, "s64", cap))
			return nil
		case isInterface(tt):
			typeReg := c.nextWord()
			dataReg := c.nextWord()
			if interfaceIsNonEmpty(tt) {
				c.out = append(c.out, argSpec{name: name + ".type", size: 8, typ: "u64", reg: typeReg, mem: true, offset: 8, nilCheck: true})
			} else {
				c.out = append(c.out, scalarRegSpec(name+".type", 8, "u64", typeReg))
			}
			c.out = append(c.out, scalarRegSpec(name+".data", 8, "u64", dataReg))
			return []captureJob{{name: name, typ: tt, loc: memLoc{reg: dataReg, nilCheck: true}}}
		default:
			var jobs []captureJob
			for _, f := range tt.Field {
				jobs = append(jobs, emitABI(f.Type, name+"."+f.Name, c)...)
			}
			return jobs
		}
	case *dwarf.PtrType:
		reg := c.nextWord()
		c.out = append(c.out, scalarRegSpec(name, 8, "u64", reg))
		return nil
	default:
		_, typ, size, ok := scalarValue(t)
		if !ok {
			reg := c.nextWord()
			c.out = append(c.out, scalarRegSpec(name, 8, "u64", reg))
			return nil
		}
		reg := c.nextWord()
		c.out = append(c.out, scalarRegSpec(name, size, typ, reg))
		return nil
	}
}

func emitRegCaptures(job captureJob, c *flatCtx) {
	t := underlying(job.typ)
	st, ok := t.(*dwarf.StructType)
	if !ok {
		return
	}
	switch {
	case isString(st):
		c.out = append(c.out, blobAt(job.name, job.loc))
	case isInterface(st):
		c.out = append(c.out, blobAt(job.name+".value", job.loc))
	}
}

func emitMemCaptures(t dwarf.Type, name string, loc memLoc, c *flatCtx) {
	t = underlying(t)
	st, ok := t.(*dwarf.StructType)
	if !ok {
		return
	}
	switch {
	case isString(st):
		c.out = append(c.out, blobAt(name+".str", loc.deref(0)))
	case isSlice(st):
		return
	case isInterface(st):
		if interfaceIsNonEmpty(st) {
			c.out = append(c.out, locSpec(name+".type", loc.deref(0).add(8), 8, "u64"))
		}
		c.out = append(c.out, locSpec(name+".data", loc.add(8), 8, "u64"))
		c.out = append(c.out, blobAt(name+".value", loc.deref(8)))
	default:
		for _, f := range st.Field {
			emitMemCaptures(f.Type, name+"."+f.Name, loc.add(f.ByteOffset), c)
		}
	}
}

// extraCaptures is the number of probe-time memory leaves beyond ABI words.
// inMemory is true when t lives in a *T object (fields addressed from a
// pointer); false when t is in registers.
func extraCaptures(t dwarf.Type, inMemory bool) int {
	t = underlying(t)
	st, ok := t.(*dwarf.StructType)
	if !ok {
		return 0
	}
	switch {
	case isString(st):
		return 1
	case isSlice(st):
		return 0
	case isInterface(st):
		if !inMemory {
			return 1 // *data prefix; type+data are ABI words
		}
		n := 2 // data word + *data prefix
		if interfaceIsNonEmpty(st) {
			n++ // itab → concrete type
		}
		return n
	default:
		n := 0
		for _, f := range st.Field {
			n += extraCaptures(f.Type, inMemory)
		}
		return n
	}
}

func markIfaceSlots(args []*FetchArg) {
	typeIdx := make(map[string]int)
	for i, a := range args {
		if strings.HasSuffix(a.Varname, ".type") {
			typeIdx[strings.TrimSuffix(a.Varname, ".type")] = i
		}
	}
	for i, a := range args {
		if !strings.HasSuffix(a.Varname, ".data") {
			continue
		}
		prefix := strings.TrimSuffix(a.Varname, ".data")
		ti, ok := typeIdx[prefix]
		if !ok {
			continue
		}
		args[i].IfaceData = true
		args[i].TypeIndex = ti
	}
}

func scalarRegSpec(name string, size int, typ, reg string) argSpec {
	return argSpec{name: name, size: size, typ: typ, reg: reg}
}

func abiWordCount(t dwarf.Type) int {
	t = underlying(t)
	switch tt := t.(type) {
	case *dwarf.PtrType:
		return 1
	case *dwarf.StructType:
		if isString(tt) || isInterface(tt) {
			return 2
		}
		if isSlice(tt) {
			return 3
		}
		n := 0
		for _, f := range tt.Field {
			w := abiWordCount(f.Type)
			if w == 0 {
				return 0
			}
			n += w
		}
		return n
	default:
		if _, _, _, ok := scalarValue(t); ok {
			return 1
		}
		return 0
	}
}

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
