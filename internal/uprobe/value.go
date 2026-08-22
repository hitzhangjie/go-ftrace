package uprobe

import (
	"debug/dwarf"
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// ValueKind classifies a scalar for renderLeaf. Composite values are
// interpreted by walking dwarf.Type instead of a parallel Kind tree.
type ValueKind int

const (
	KindScalar  ValueKind = iota // signed/unsigned integer, rendered in decimal
	KindBool                     // Go bool, rendered as true/false
	KindFloat                    // float32/float64
	KindPointer                  // opaque pointer, rendered as 0x... or nil
)

// maxReadSize caps a snapshot read while walking dwarf.Type.
const maxReadSize = 4096

// Value is one auto-fetched argument or return value. Auto mode compiles
// dwarf.Type into FetchArgs at startup; BPF copies those bytes at the probe.
// Rendering walks the same Type over that snapshot only.
type Value struct {
	Name string
	Type dwarf.Type

	// WordCount is the number of ABI-word leaves. Captures is the number of
	// extra probe-time memory leaves (object prefix, string bytes, interface
	// concrete value and one pointer chase) that follow the ABI words.
	WordCount int
	Captures  int

	// RuntimeType maps a captured runtime type pointer to its DWARF definition.
	RuntimeType func(uint64) (dwarf.Type, error)
}

// LeafData carries the raw bytes and nil marker of one fetched leaf value.
type LeafData struct {
	Data        []byte
	IsNil       bool
	Unavailable bool
}

// RenderValues renders a list of top-level values into a single
// comma-separated, debugger-style string. data must provide one LeafData per
// leaf in fetch order (the same order as the compiled FetchArgs).
func RenderValues(values []*Value, data []LeafData) string {
	return RenderValuesRecipes(values, data, nil)
}

// RenderValuesRecipes is RenderValues plus type-specialized extra leaves that
// BPF appended after the generic snapshot (see type_recipes_map).
func RenderValuesRecipes(values []*Value, data []LeafData, recipes map[uint64][]RelRule) string {
	generic := 0
	for _, v := range values {
		generic += v.leafCount()
	}
	extraCur := generic
	cur := 0
	parts := make([]string, 0, len(values))
	for _, v := range values {
		parts = append(parts, v.Name+"="+renderAuto(v, data, &cur, data, &extraCur, recipes))
	}
	return strings.Join(parts, ", ")
}

func renderAuto(v *Value, data []LeafData, cur *int, all []LeafData, extraCur *int, recipes map[uint64][]RelRule) string {
	n := v.leafCount()
	if n == 0 || *cur+n > len(data) {
		if n > 0 {
			*cur += n
			if *cur > len(data) {
				*cur = len(data)
			}
		}
		return "<unavailable>"
	}

	words := data[*cur : *cur+v.WordCount]
	*cur += v.WordCount
	captures := data[*cur : *cur+v.Captures]
	*cur += v.Captures

	t := underlying(v.Type)
	if st, ok := t.(*dwarf.StructType); ok && isInterface(st) && len(words) > 0 {
		if words[0].IsNil || readUint(words[0].Data) == 0 {
			return "nil"
		}
	}
	for _, w := range words {
		if w.Unavailable {
			return "<unavailable>"
		}
	}
	if v.Captures > 0 && captures[0].IsNil {
		if _, ok := t.(*dwarf.PtrType); ok {
			return "nil"
		}
	}

	header := concatLeaves(words)
	if len(header) == 0 {
		return "<unavailable>"
	}

	snap := &memSnapshot{}
	if pt, ok := t.(*dwarf.PtrType); ok {
		ptr := readUint(header)
		if ptr == 0 {
			return "nil"
		}
		pointee := underlying(pt.Type)
		if st, ok := pointee.(*dwarf.StructType); ok && !isRuntimeStruct(st) {
			if len(captures) == 0 || captures[0].Unavailable {
				return typeName(pt) + "(<unavailable>)"
			}
			obj := captures[0].Data
			snap.put(ptr, captures[0])
			consumeMemCaptures(pt.Type, obj, ptr, captures[1:], snap)
			applyNestedRecipes(pt.Type, obj, recipes, all, extraCur, snap)
			return "&" + renderDynamicValue(pt.Type, obj, ptr, v.RuntimeType, snap.read, 0)
		}
		return fmt.Sprintf("0x%x", ptr)
	}

	if st, ok := t.(*dwarf.StructType); ok && !isString(st) && !isSlice(st) && !isInterface(st) {
		header = scatterWords(v.Type, header)
		consumeRegCaptures(v.Type, header, captures, snap)
		return renderDynamicValue(v.Type, header, 0, v.RuntimeType, snap.read, 0)
	}

	if st, ok := t.(*dwarf.StructType); ok && isString(st) {
		if len(captures) > 0 {
			snap.put(readUint(header), captures[0])
		}
		return renderDynamicValue(v.Type, header, 0, v.RuntimeType, snap.read, 0)
	}

	if st, ok := t.(*dwarf.StructType); ok && isInterface(st) {
		bindIfaceCaptures(header, captures, snap)
		if len(header) >= 16 {
			applyRecipeExtras(readUint(header), readUint(header[8:]), all, extraCur, recipes, snap)
		}
		return renderDynamicValue(v.Type, header, 0, v.RuntimeType, snap.read, 0)
	}

	return renderDynamicValue(v.Type, header, 0, v.RuntimeType, snap.read, 0)
}

func bindIfaceCaptures(header []byte, captures []LeafData, snap *memSnapshot) {
	if len(header) < 16 || len(captures) == 0 {
		return
	}
	snap.put(readUint(header[8:]), captures[0])
}

func evalRel(base uint64, steps []ArgRule, snap *memSnapshot) uint64 {
	addr := base
	for _, s := range steps {
		if s.Dereference {
			var p [8]byte
			if snap.read(addr+uint64(s.Offset), p[:]) != nil {
				return 0
			}
			addr = readUint(p[:])
			continue
		}
		addr += uint64(s.Offset)
	}
	return addr
}

func applyRecipeExtras(typeAddr, dataPtr uint64, all []LeafData, extraCur *int, recipes map[uint64][]RelRule, snap *memSnapshot) {
	if recipes == nil || extraCur == nil || typeAddr == 0 {
		return
	}
	rec := recipes[typeAddr]
	for _, r := range rec {
		if *extraCur >= len(all) {
			return
		}
		addr := evalRel(dataPtr, r.Steps, snap)
		snap.put(addr, all[*extraCur])
		*extraCur++
	}
}

func applyNestedRecipes(t dwarf.Type, mem []byte, recipes map[uint64][]RelRule, all []LeafData, extraCur *int, snap *memSnapshot) {
	t = underlying(t)
	st, ok := t.(*dwarf.StructType)
	if !ok {
		return
	}
	switch {
	case isInterface(st):
		typeAddr := uint64(0)
		if len(mem) >= 8 {
			typeAddr = readUint(mem)
		}
		if interfaceIsNonEmpty(st) && typeAddr != 0 {
			var p [8]byte
			if snap.read(typeAddr+8, p[:]) == nil {
				typeAddr = readUint(p[:])
			}
		}
		dataPtr := uint64(0)
		if len(mem) >= 16 {
			dataPtr = readUint(mem[8:])
		}
		applyRecipeExtras(typeAddr, dataPtr, all, extraCur, recipes, snap)
	case isString(st), isSlice(st):
		return
	default:
		for _, f := range st.Field {
			start := int(f.ByteOffset)
			var fieldMem []byte
			if start >= 0 && start < len(mem) {
				fieldMem = mem[start:]
			}
			applyNestedRecipes(f.Type, fieldMem, recipes, all, extraCur, snap)
		}
	}
}

func concatLeaves(leaves []LeafData) []byte {
	var b []byte
	for _, l := range leaves {
		b = append(b, l.Data...)
	}
	return b
}

type snapChunk struct {
	addr uint64
	data []byte
}

type memSnapshot struct {
	chunks []snapChunk
}

func (s *memSnapshot) put(addr uint64, leaf LeafData) {
	if s == nil || addr == 0 || leaf.Unavailable || leaf.IsNil || len(leaf.Data) == 0 {
		return
	}
	s.chunks = append(s.chunks, snapChunk{addr: addr, data: leaf.Data})
}

func (s *memSnapshot) read(addr uint64, dst []byte) error {
	if s == nil {
		return fmt.Errorf("address %#x not in probe snapshot", addr)
	}
	for _, c := range s.chunks {
		if addr >= c.addr && addr < c.addr+uint64(len(c.data)) {
			n := copy(dst, c.data[addr-c.addr:])
			if n == len(dst) {
				return nil
			}
			return fmt.Errorf("short snapshot read at %#x", addr)
		}
	}
	return fmt.Errorf("address %#x not in probe snapshot", addr)
}

func consumeMemCaptures(t dwarf.Type, mem []byte, addr uint64, captures []LeafData, snap *memSnapshot) []LeafData {
	t = underlying(t)
	st, ok := t.(*dwarf.StructType)
	if !ok {
		return captures
	}
	switch {
	case isString(st):
		if len(captures) == 0 {
			return captures
		}
		if len(mem) >= 8 {
			snap.put(readUint(mem), captures[0])
		}
		return captures[1:]
	case isSlice(st):
		return captures
	case isInterface(st):
		need := 2
		if interfaceIsNonEmpty(st) {
			need = 3
		}
		if len(captures) < need {
			return captures
		}
		if interfaceIsNonEmpty(st) {
			if len(mem) >= 8 {
				snap.put(readUint(mem)+8, captures[0])
			}
			captures = captures[1:]
		}
		dataPtr := uint64(0)
		if len(mem) >= 16 {
			dataPtr = readUint(mem[8:])
		}
		captures = captures[1:] // skip the data-word leaf; value blob follows
		if len(captures) == 0 {
			return captures
		}
		snap.put(dataPtr, captures[0])
		return captures[1:]
	default:
		for _, f := range st.Field {
			start := int(f.ByteOffset)
			var fieldMem []byte
			if start >= 0 && start < len(mem) {
				fieldMem = mem[start:]
			}
			captures = consumeMemCaptures(f.Type, fieldMem, addr+uint64(f.ByteOffset), captures, snap)
		}
		return captures
	}
}

func consumeRegCaptures(t dwarf.Type, img []byte, captures []LeafData, snap *memSnapshot) []LeafData {
	t = underlying(t)
	st, ok := t.(*dwarf.StructType)
	if !ok {
		return captures
	}
	switch {
	case isString(st):
		if len(captures) == 0 {
			return captures
		}
		if len(img) >= 8 {
			snap.put(readUint(img), captures[0])
		}
		return captures[1:]
	case isSlice(st):
		return captures
	case isInterface(st):
		bindIfaceCaptures(img, captures, snap)
		if len(captures) >= 1 {
			return captures[1:]
		}
		return nil
	default:
		for _, f := range st.Field {
			start := int(f.ByteOffset)
			var fieldMem []byte
			if start >= 0 && start < len(img) {
				fieldMem = img[start:]
			}
			captures = consumeRegCaptures(f.Type, fieldMem, captures, snap)
		}
		return captures
	}
}

// scatterWords places ABI register words into a memory image using DWARF
// field offsets. A bool occupies a full register but only one byte in memory;
// copying each field to ByteOffset reconstructs the in-memory layout that
// renderDynamicValue expects.
func scatterWords(t dwarf.Type, words []byte) []byte {
	size := t.Size()
	if size <= 0 {
		return words
	}
	img := make([]byte, size)
	consume := 0
	var walk func(dwarf.Type, int64)
	walk = func(typ dwarf.Type, base int64) {
		typ = underlying(typ)
		switch tt := typ.(type) {
		case *dwarf.StructType:
			if isString(tt) || isSlice(tt) || isInterface(tt) {
				n := abiWordCount(tt) * 8
				if consume+n <= len(words) && int(base)+n <= len(img) {
					copy(img[base:], words[consume:consume+n])
				}
				consume += n
				return
			}
			for _, f := range tt.Field {
				walk(f.Type, base+f.ByteOffset)
			}
		default:
			sz := int(typ.Size())
			if sz <= 0 {
				sz = 8
			}
			if sz > 8 {
				sz = 8
			}
			if consume+sz <= len(words) && int(base)+sz <= len(img) {
				copy(img[base:int(base)+sz], words[consume:consume+sz])
			}
			consume += 8
		}
	}
	walk(t, 0)
	return img
}

const maxDynamicDepth = 8

type runtimeTypeResolver func(uint64) (dwarf.Type, error)
type memoryReader func(uint64, []byte) error

// typeIsDirect approximates Go's DirectIface flag from DWARF so rendering
// does not need a live read of the runtime type header.
func typeIsDirect(t dwarf.Type) bool {
	t = underlying(t)
	switch tt := t.(type) {
	case *dwarf.PtrType:
		return true
	case *dwarf.FuncType:
		return true
	case *dwarf.StructType:
		if isString(tt) || isSlice(tt) || isInterface(tt) {
			return false
		}
		if isRuntimeStruct(tt) {
			return true
		}
		if tt.Size() > 8 {
			return false
		}
		if tt.Size() == 8 && len(tt.Field) > 0 {
			if _, ok := underlying(tt.Field[0].Type).(*dwarf.PtrType); ok {
				return true
			}
		}
		return tt.Size() > 0 && tt.Size() <= 8 && len(tt.Field) == 0
	default:
		size := tt.Size()
		return size > 0 && size <= 8
	}
}

func objectBytes(t dwarf.Type, data []byte, addr uint64, readMemory memoryReader) []byte {
	size := int(t.Size())
	if size <= 0 {
		return data
	}
	if readMemory != nil && addr != 0 && size <= maxReadSize {
		buf := make([]byte, size)
		if err := readMemory(addr, buf); err == nil {
			return buf
		}
	}
	if len(data) >= size {
		return data[:size]
	}
	return data
}

func renderDynamicValue(t dwarf.Type, data []byte, addr uint64, resolveType runtimeTypeResolver, readMemory memoryReader, depth int) string {
	if depth >= maxDynamicDepth {
		return "<max-depth>"
	}
	t = underlying(t)
	switch tt := t.(type) {
	case *dwarf.PtrType:
		ptr := readUint(data)
		if ptr == 0 {
			return "nil"
		}
		pointee := underlying(tt.Type)
		size := int(pointee.Size())
		if readMemory == nil || size <= 0 || size > maxReadSize {
			return typeName(tt) + "(<unavailable>)"
		}
		buf := make([]byte, size)
		if err := readMemory(ptr, buf); err != nil {
			return typeName(tt) + "(<unavailable>)"
		}
		return "&" + renderDynamicValue(tt.Type, buf, ptr, resolveType, readMemory, depth+1)
	case *dwarf.StructType:
		switch {
		case isString(tt):
			if len(data) < 16 {
				return `"<unavailable>"`
			}
			strAddr := readUint(data)
			strLen := int64(binary.LittleEndian.Uint64(data[8:16]))
			if strLen == 0 {
				return `""`
			}
			if strLen < 0 || readMemory == nil {
				return `"<unavailable>"`
			}
			n := strLen
			truncated := false
			if n > autoStringSize {
				n = autoStringSize
				truncated = true
			}
			buf := make([]byte, n)
			if err := readMemory(strAddr, buf); err != nil {
				return `"<unavailable>"`
			}
			q := strconv.Quote(string(buf))
			if truncated {
				q = q[:len(q)-1] + "...\""
			}
			return q
		case isSlice(tt):
			if len(data) < 24 {
				return tt.StructName + "(<unavailable>)"
			}
			return fmt.Sprintf("%s(len=%d, cap=%d)", tt.StructName,
				int64(binary.LittleEndian.Uint64(data[8:16])),
				int64(binary.LittleEndian.Uint64(data[16:24])))
		case isInterface(tt):
			if len(data) < 16 {
				return "interface{type=<unknown>, value=<unavailable>}"
			}
			typeAddr := readUint(data)
			dataAddr := readUint(data[8:])
			if typeAddr == 0 {
				return "nil"
			}
			if resolveType == nil {
				return "interface{type=<unknown>, value=<unavailable>}"
			}
			dynamicType, err := resolveType(typeAddr)
			if err != nil && interfaceIsNonEmpty(tt) {
				if readMemory == nil {
					return "interface{type=<unknown>, value=<unavailable>}"
				}
				var typeWord [8]byte
				if err := readMemory(typeAddr+8, typeWord[:]); err != nil {
					return "interface{type=<unknown>, value=<unavailable>}"
				}
				typeAddr = readUint(typeWord[:])
				dynamicType, err = resolveType(typeAddr)
			}
			if err != nil {
				return "interface{type=<unknown>, value=<unavailable>}"
			}
			if typeIsDirect(dynamicType) {
				var word [8]byte
				binary.LittleEndian.PutUint64(word[:], dataAddr)
				return renderDynamicValue(dynamicType, word[:], dataAddr, resolveType, readMemory, depth+1)
			}
			size := int(dynamicType.Size())
			if size <= 0 || size > maxReadSize {
				size = autoStringSize
			}
			value := objectBytes(dynamicType, nil, dataAddr, readMemory)
			if len(value) == 0 {
				return typeName(dynamicType) + "(<unavailable>)"
			}
			return renderDynamicValue(dynamicType, value, dataAddr, resolveType, readMemory, depth+1)
		default:
			data = objectBytes(tt, data, addr, readMemory)
			var b strings.Builder
			b.WriteString(tt.StructName)
			b.WriteByte('{')
			for i, f := range tt.Field {
				if i > 0 {
					b.WriteString(", ")
				}
				b.WriteString(f.Name)
				b.WriteByte(':')
				b.WriteString(renderStructField(f, data, addr, resolveType, readMemory, depth+1))
			}
			b.WriteByte('}')
			return b.String()
		}
	default:
		kind, typ, size, ok := scalarValue(t)
		if !ok || size > len(data) {
			return "<unavailable>"
		}
		return renderLeaf(&leafValue{Kind: kind, Typ: typ, Size: size}, data[:size])
	}
}

func renderStructField(f *dwarf.StructField, data []byte, addr uint64, resolveType runtimeTypeResolver, readMemory memoryReader, depth int) string {
	start := int(f.ByteOffset)
	if start < 0 {
		return "<unavailable>"
	}
	fieldSize := int(f.Type.Size())
	var fieldData []byte
	if start < len(data) {
		fieldData = data[start:]
	}
	if fieldSize > 0 && len(fieldData) < fieldSize && readMemory != nil && addr != 0 {
		buf := make([]byte, fieldSize)
		if err := readMemory(addr+uint64(f.ByteOffset), buf); err == nil {
			fieldData = buf
		}
	}
	if len(fieldData) == 0 {
		return "<unavailable>"
	}
	return renderDynamicValue(f.Type, fieldData, addr+uint64(f.ByteOffset), resolveType, readMemory, depth)
}

func interfaceIsNonEmpty(st *dwarf.StructType) bool {
	return st.StructName == "runtime.iface" || hasFields(st, "tab", "data")
}

func typeName(t dwarf.Type) string {
	if t == nil {
		return "<unknown>"
	}
	if n := t.Common().Name; n != "" {
		return n
	}
	switch tt := underlying(t).(type) {
	case *dwarf.PtrType:
		return "*" + typeName(tt.Type)
	case *dwarf.StructType:
		if tt.StructName != "" {
			return tt.StructName
		}
	}
	return t.String()
}

type leafValue struct {
	Kind ValueKind
	Typ  string
	Size int
}

func renderLeaf(v *leafValue, data []byte) string {
	switch v.Kind {
	case KindBool:
		if len(data) > 0 && data[0] != 0 {
			return "true"
		}
		return "false"
	case KindFloat:
		switch v.Typ {
		case "f32":
			f := math.Float32frombits(binary.LittleEndian.Uint32(data))
			return strconv.FormatFloat(float64(f), 'g', -1, 32)
		case "f64":
			f := math.Float64frombits(binary.LittleEndian.Uint64(data))
			return strconv.FormatFloat(f, 'g', -1, 64)
		}
	case KindPointer:
		addr := readUint(data)
		if addr == 0 {
			return "nil"
		}
		return fmt.Sprintf("0x%x", addr)
	}
	switch v.Typ {
	case "s8":
		return strconv.FormatInt(int64(int8(data[0])), 10)
	case "s16":
		return strconv.FormatInt(int64(int16(binary.LittleEndian.Uint16(data))), 10)
	case "s32":
		return strconv.FormatInt(int64(int32(binary.LittleEndian.Uint32(data))), 10)
	case "s64":
		return strconv.FormatInt(int64(binary.LittleEndian.Uint64(data)), 10)
	case "u8":
		return strconv.FormatUint(uint64(data[0]), 10)
	case "u16":
		return strconv.FormatUint(uint64(binary.LittleEndian.Uint16(data)), 10)
	case "u32":
		return strconv.FormatUint(uint64(binary.LittleEndian.Uint32(data)), 10)
	case "u64":
		return strconv.FormatUint(binary.LittleEndian.Uint64(data), 10)
	}
	return strconv.FormatUint(readUint(data), 10)
}

// leafCount returns the number of fetched leaves under this node.
func (v *Value) leafCount() int {
	return v.WordCount + v.Captures
}

func readUint(data []byte) uint64 {
	if len(data) >= 8 {
		return binary.LittleEndian.Uint64(data[:8])
	}
	var b [8]byte
	copy(b[:], data)
	return binary.LittleEndian.Uint64(b[:])
}
