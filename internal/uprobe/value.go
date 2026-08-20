package uprobe

import (
	"debug/dwarf"
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// ValueKind classifies a Value node so the renderer knows how to format it.
type ValueKind int

const (
	KindScalar    ValueKind = iota // signed/unsigned integer, rendered in decimal
	KindBool                       // Go bool, rendered as true/false
	KindFloat                      // float32/float64
	KindPointer                    // opaque pointer, rendered as 0x... or nil
	KindString                     // Go string, rendered as a quoted string
	KindSlice                      // Go slice, rendered as []T(len=.., cap=..)
	KindInterface                  // Go interface, rendered as nil or interface{...}
	KindStruct                     // inline struct, rendered as T{...}
	KindStructPtr                  // *struct, rendered as &T{...} or nil
)

// Value is a node in the type-aware value tree for one argument or return
// value. Leaves (KindScalar/KindBool/KindFloat/KindPointer) carry the decode
// type/size of a single fetched word; composite nodes group their fields in
// fetch order (the same order as the flattened FetchArgs).
type Value struct {
	Kind ValueKind
	Name string

	// Leaf decode info (KindScalar/KindBool/KindFloat/KindPointer).
	Typ  string // "u8".."u64", "s8".."s64", "f32","f64", "bool"
	Size int

	// Struct fields, in fetch order (KindStruct / KindStructPtr).
	Fields []*Value

	// Rendering annotations.
	StructName string // KindStruct / KindStructPtr
	ElemType   string // KindSlice (slice type name, e.g. "[]int")

	// Interface metadata. RuntimeType maps the captured runtime type pointer to
	// its DWARF definition; it is deliberately excluded from leaf accounting.
	InterfaceNonEmpty bool
	RuntimeType       func(uint64) (dwarf.Type, error)
	ReadMemory        func(uint64, []byte) error
}

// LeafData carries the raw bytes and nil marker of one fetched leaf value.
type LeafData struct {
	Data        []byte
	IsNil       bool
	Unavailable bool
}

// BindInterfaceMemory attaches a process-specific memory reader to every
// interface node, including interfaces nested in structs. Static values are
// fully described and fetched by their precomputed rules, while an interface's
// concrete type is known only at runtime and may require following pointers to
// render its dynamic value.
func BindInterfaceMemory(values []*Value, readMemory func(uint64, []byte) error) {
	var bind func(*Value)
	bind = func(v *Value) {
		if v.Kind == KindInterface {
			v.ReadMemory = readMemory
		}
		for _, field := range v.Fields {
			bind(field)
		}
	}
	for _, v := range values {
		bind(v)
	}
}

// RenderValues renders a list of top-level values into a single
// comma-separated, debugger-style string. data must provide one LeafData per
// leaf in fetch order (the same order as the flattened FetchArgs).
func RenderValues(values []*Value, data []LeafData) string {
	cur := 0
	parts := make([]string, 0, len(values))
	for _, v := range values {
		parts = append(parts, v.Name+"="+renderNode(v, data, &cur))
	}
	return strings.Join(parts, ", ")
}

func renderNode(v *Value, data []LeafData, cur *int) string {
	leaves := v.leafCount()
	if leaves > 0 && *cur+leaves > len(data) {
		*cur = len(data)
		return "<unavailable>"
	}

	if v.Kind != KindStruct && v.Kind != KindStructPtr {
		for i := 0; i < leaves; i++ {
			if data[*cur+i].Unavailable {
				*cur += leaves
				return "<unavailable>"
			}
		}
	}

	switch v.Kind {
	case KindScalar, KindBool, KindFloat, KindPointer:
		d := data[*cur]
		*cur++
		return renderLeaf(v, d.Data)

	case KindString:
		// string data (raw backing-array bytes) then length.
		raw := data[*cur]
		*cur++
		lenD := data[*cur]
		*cur++
		n := int(int64(binary.LittleEndian.Uint64(lenD.Data)))
		if n < 0 {
			n = 0
		}
		truncated := false
		if n > len(raw.Data) {
			n = len(raw.Data)
			truncated = true
		}
		q := strconv.Quote(string(raw.Data[:n]))
		if truncated {
			q = q[:len(q)-1] + "...\""
		}
		return q

	case KindSlice:
		// data pointer (not dereferenced here), len, cap.
		_ = data[*cur]
		*cur++
		lenD := data[*cur]
		*cur++
		capD := data[*cur]
		*cur++
		ln := int64(binary.LittleEndian.Uint64(lenD.Data))
		cp := int64(binary.LittleEndian.Uint64(capD.Data))
		typ := v.ElemType
		if typ == "" {
			typ = "[]"
		}
		return fmt.Sprintf("%s(len=%d, cap=%d)", typ, ln, cp)

	case KindInterface:
		typeD := data[*cur]
		*cur++
		dataD := data[*cur]
		*cur++
		valueD := data[*cur]
		*cur++
		typeAddr := readUint(typeD.Data)
		dataAddr := readUint(dataD.Data)
		if typeAddr == 0 {
			return "nil"
		}
		if v.RuntimeType == nil {
			return "interface{type=<unknown>, value=<unavailable>}"
		}
		t, err := v.RuntimeType(typeAddr)
		if err != nil {
			return "interface{type=<unknown>, value=<unavailable>}"
		}
		direct, err := runtimeTypeIsDirect(typeAddr, v.ReadMemory)
		if err != nil {
			return t.String() + "(<unavailable>)"
		}
		if direct {
			if ptr, ok := underlying(t).(*dwarf.PtrType); ok {
				if dataAddr == 0 {
					return "nil"
				}
				return "&" + renderDynamicValue(ptr.Type, valueD.Data, dataAddr, v.RuntimeType, v.ReadMemory, 1)
			}
			return renderDynamicValue(t, dataD.Data, dataAddr, v.RuntimeType, v.ReadMemory, 0)
		}
		return renderDynamicValue(t, valueD.Data, dataAddr, v.RuntimeType, v.ReadMemory, 0)

	case KindStruct:
		return renderStruct(v, data, cur)

	case KindStructPtr:
		if v.leafCount() == 0 {
			return "&" + structName(v) + "{}"
		}
		if data[*cur].IsNil {
			*cur += v.leafCount()
			return "nil"
		}
		return "&" + structName(v) + renderFields(v, data, cur)
	}
	return ""
}

func renderStruct(v *Value, data []LeafData, cur *int) string {
	return structName(v) + renderFields(v, data, cur)
}

func renderFields(v *Value, data []LeafData, cur *int) string {
	var b strings.Builder
	b.WriteByte('{')
	for i, f := range v.Fields {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(shortName(f.Name))
		b.WriteByte(':')
		b.WriteString(renderNode(f, data, cur))
	}
	b.WriteByte('}')
	return b.String()
}

func structName(v *Value) string {
	if v.StructName != "" {
		return v.StructName
	}
	return "struct"
}

// shortName strips the dotted prefix so a nested field renders with only its
// own identifier (e.g. "req.Id" -> "Id").
func shortName(name string) string {
	if i := strings.LastIndex(name, "."); i >= 0 {
		return name[i+1:]
	}
	return name
}

const maxDynamicDepth = 8

type runtimeTypeResolver func(uint64) (dwarf.Type, error)
type memoryReader func(uint64, []byte) error

// runtimeTypeIsDirect supports both Go <=1.25 (direct bit in Kind at +23)
// and Go >=1.26 (direct bit in TFlag at +20). The common runtime type prefix
// has kept these byte offsets stable on amd64.
func runtimeTypeIsDirect(typeAddr uint64, readMemory memoryReader) (bool, error) {
	if readMemory == nil {
		return false, fmt.Errorf("process memory reader unavailable")
	}
	var header [24]byte
	if err := readMemory(typeAddr, header[:]); err != nil {
		return false, err
	}
	const directIface = byte(1 << 5)
	return header[20]&directIface != 0 || header[23]&directIface != 0, nil
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
		if readMemory == nil || pointee.Size() <= 0 || pointee.Size() > autoStringSize {
			return tt.String() + "(<unavailable>)"
		}
		buf := make([]byte, pointee.Size())
		if err := readMemory(ptr, buf); err != nil {
			return tt.String() + "(<unavailable>)"
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
				int64(binary.LittleEndian.Uint64(data[8:16])), int64(binary.LittleEndian.Uint64(data[16:24])))
		case isInterface(tt):
			if len(data) < 16 {
				return "interface{type=<unknown>, value=<unavailable>}"
			}
			typeAddr := readUint(data)
			dataAddr := readUint(data[8:])
			if typeAddr == 0 {
				return "nil"
			}
			if resolveType == nil || readMemory == nil {
				return "interface{type=<unknown>, value=<unavailable>}"
			}
			if interfaceIsNonEmpty(tt) {
				var typeWord [8]byte
				if err := readMemory(typeAddr+8, typeWord[:]); err != nil {
					return "interface{type=<unknown>, value=<unavailable>}"
				}
				typeAddr = readUint(typeWord[:])
			}
			dynamicType, err := resolveType(typeAddr)
			if err != nil {
				return "interface{type=<unknown>, value=<unavailable>}"
			}
			direct, err := runtimeTypeIsDirect(typeAddr, readMemory)
			if err != nil {
				return dynamicType.String() + "(<unavailable>)"
			}
			if direct {
				var word [8]byte
				binary.LittleEndian.PutUint64(word[:], dataAddr)
				return renderDynamicValue(dynamicType, word[:], dataAddr, resolveType, readMemory, depth+1)
			}
			size := dynamicType.Size()
			if size <= 0 || size > autoStringSize {
				size = autoStringSize
			}
			value := make([]byte, size)
			if dataAddr == 0 || readMemory(dataAddr, value) != nil {
				return dynamicType.String() + "(<unavailable>)"
			}
			return renderDynamicValue(dynamicType, value, dataAddr, resolveType, readMemory, depth+1)
		default:
			var b strings.Builder
			b.WriteString(tt.StructName)
			b.WriteByte('{')
			for i, f := range tt.Field {
				if i > 0 {
					b.WriteString(", ")
				}
				b.WriteString(f.Name)
				b.WriteByte(':')
				start := int(f.ByteOffset)
				if start < 0 || start >= len(data) {
					b.WriteString("<unavailable>")
					continue
				}
				b.WriteString(renderDynamicValue(f.Type, data[start:], addr+uint64(start), resolveType, readMemory, depth+1))
			}
			b.WriteByte('}')
			return b.String()
		}
	default:
		kind, typ, size, ok := scalarValue(t)
		if !ok || size > len(data) {
			return "<unavailable>"
		}
		return renderLeaf(&Value{Kind: kind, Typ: typ, Size: size}, data[:size])
	}
}

func renderLeaf(v *Value, data []byte) string {
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
	// KindScalar
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
	switch v.Kind {
	case KindScalar, KindBool, KindFloat, KindPointer:
		return 1
	case KindString:
		return 2
	case KindInterface:
		return 3
	case KindSlice:
		return 3
	case KindStruct, KindStructPtr:
		n := 0
		for _, f := range v.Fields {
			n += f.leafCount()
		}
		return n
	}
	return 0
}

func readUint(data []byte) uint64 {
	if len(data) >= 8 {
		return binary.LittleEndian.Uint64(data[:8])
	}
	var b [8]byte
	copy(b[:], data)
	return binary.LittleEndian.Uint64(b[:])
}
