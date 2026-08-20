package uprobe

import (
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
}

// LeafData carries the raw bytes and nil marker of one fetched leaf value.
type LeafData struct {
	Data  []byte
	IsNil bool
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
		tab := data[*cur]
		*cur++
		val := data[*cur]
		*cur++
		tv := binary.LittleEndian.Uint64(tab.Data)
		vv := binary.LittleEndian.Uint64(val.Data)
		if tv == 0 && vv == 0 {
			return "nil"
		}
		return fmt.Sprintf("interface{tab=0x%x, data=0x%x}", tv, vv)

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
	case KindString, KindInterface:
		return 2
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
