package uprobe

import (
	"debug/dwarf"
	"encoding/binary"
	"fmt"
	"testing"
)

func u64data(v uint64) LeafData {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	return LeafData{Data: b[:]}
}

func TestInterfaceRenderingConverges(t *testing.T) {
	value := &Value{
		Kind: KindInterface,
		Name: "err",
		RuntimeType: func(addr uint64) (dwarf.Type, error) {
			return &dwarf.IntType{BasicType: dwarf.BasicType{CommonType: dwarf.CommonType{Name: "main.Code", ByteSize: 8}}}, nil
		},
		ReadMemory: func(addr uint64, dst []byte) error {
			return nil // indirect interface: direct bit is clear
		},
	}
	first := RenderValues([]*Value{value}, []LeafData{u64data(0x1234), u64data(0xc0001000), u64data(500)})
	second := RenderValues([]*Value{value}, []LeafData{u64data(0x1234), u64data(0xc0002000), u64data(500)})
	if first != second || first != "err=500" {
		t.Fatalf("interface render did not converge: first=%q second=%q", first, second)
	}
}

func TestRenderValues(t *testing.T) {
	cases := []struct {
		name   string
		values []*Value
		data   []LeafData
		want   string
	}{
		{
			name:   "scalar",
			values: []*Value{{Kind: KindScalar, Name: "a", Typ: "s64", Size: 8}},
			data:   []LeafData{u64data(42)},
			want:   "a=42",
		},
		{
			name:   "bool",
			values: []*Value{{Kind: KindBool, Name: "ok", Typ: "bool", Size: 1}},
			data:   []LeafData{{Data: []byte{1}}},
			want:   "ok=true",
		},
		{
			name:   "pointer-nil",
			values: []*Value{{Kind: KindPointer, Name: "p", Typ: "u64", Size: 8}},
			data:   []LeafData{u64data(0)},
			want:   "p=nil",
		},
		{
			name:   "pointer-addr",
			values: []*Value{{Kind: KindPointer, Name: "p", Typ: "u64", Size: 8}},
			data:   []LeafData{u64data(0xc0001234)},
			want:   "p=0xc0001234",
		},
		{
			name:   "string",
			values: []*Value{{Kind: KindString, Name: "name"}},
			data:   []LeafData{{Data: []byte("hello")}, u64data(5)},
			want:   `name="hello"`,
		},
		{
			name:   "string-truncated",
			values: []*Value{{Kind: KindString, Name: "name"}},
			data:   []LeafData{{Data: []byte("hello")}, u64data(10)},
			want:   `name="hello..."`,
		},
		{
			name:   "slice",
			values: []*Value{{Kind: KindSlice, Name: "nums", ElemType: "[]int"}},
			data:   []LeafData{u64data(0), u64data(3), u64data(5)},
			want:   "nums=[]int(len=3, cap=5)",
		},
		{
			name:   "interface-nil",
			values: []*Value{{Kind: KindInterface, Name: "err"}},
			data:   []LeafData{u64data(0), u64data(0), u64data(0)},
			want:   "err=nil",
		},
		{
			name: "interface-dynamic-struct",
			values: []*Value{{
				Kind: KindInterface,
				Name: "err",
				RuntimeType: func(addr uint64) (dwarf.Type, error) {
					return &dwarf.StructType{
						CommonType: dwarf.CommonType{Name: "main.MeshError", ByteSize: 16},
						StructName: "main.MeshError",
						Field: []*dwarf.StructField{
							{Name: "Code", ByteOffset: 0, Type: &dwarf.IntType{BasicType: dwarf.BasicType{CommonType: dwarf.CommonType{ByteSize: 8}}}},
							{Name: "Retry", ByteOffset: 8, Type: &dwarf.BoolType{BasicType: dwarf.BasicType{CommonType: dwarf.CommonType{ByteSize: 1}}}},
						},
					}, nil
				},
				ReadMemory: func(addr uint64, dst []byte) error {
					if addr != 0x1234 {
						return fmt.Errorf("unexpected read %#x", addr)
					}
					return nil // indirect interface: direct bit is clear
				},
			}},
			data: func() []LeafData {
				value := make([]byte, 64)
				binary.LittleEndian.PutUint64(value, 500)
				value[8] = 1
				return []LeafData{u64data(0x1234), u64data(0x5678), {Data: value}}
			}(),
			want: "err=main.MeshError{Code:500, Retry:true}",
		},
		{
			name: "interface-direct-pointer",
			values: []*Value{{
				Kind: KindInterface,
				Name: "err",
				RuntimeType: func(addr uint64) (dwarf.Type, error) {
					st := &dwarf.StructType{
						CommonType: dwarf.CommonType{Name: "main.MeshError", ByteSize: 8},
						StructName: "main.MeshError",
						Field: []*dwarf.StructField{{
							Name: "Code",
							Type: &dwarf.IntType{BasicType: dwarf.BasicType{CommonType: dwarf.CommonType{ByteSize: 8}}},
						}},
					}
					return &dwarf.PtrType{CommonType: dwarf.CommonType{Name: "*main.MeshError", ByteSize: 8}, Type: st}, nil
				},
				ReadMemory: func(addr uint64, dst []byte) error {
					if addr != 0x1234 {
						return fmt.Errorf("unexpected read %#x", addr)
					}
					dst[20] = 1 << 5
					return nil
				},
			}},
			data: func() []LeafData {
				value := make([]byte, 64)
				binary.LittleEndian.PutUint64(value, 500)
				return []LeafData{u64data(0x1234), u64data(0xc0005000), {Data: value}}
			}(),
			want: "err=&main.MeshError{Code:500}",
		},
		{
			name: "interface-nested-interface",
			values: []*Value{{
				Kind: KindInterface,
				Name: "v",
				RuntimeType: func(addr uint64) (dwarf.Type, error) {
					switch addr {
					case 0x111:
						return &dwarf.StructType{
							CommonType: dwarf.CommonType{Name: "main.Outer", ByteSize: 16},
							StructName: "main.Outer",
							Field: []*dwarf.StructField{{
								Name: "Inner",
								Type: &dwarf.StructType{
									CommonType: dwarf.CommonType{Name: "runtime.iface", ByteSize: 16},
									StructName: "runtime.iface",
									Field:      []*dwarf.StructField{{Name: "tab"}, {Name: "data", ByteOffset: 8}},
								},
							}},
						}, nil
					case 0x222:
						return &dwarf.IntType{BasicType: dwarf.BasicType{CommonType: dwarf.CommonType{Name: "main.Code", ByteSize: 8}}}, nil
					default:
						return nil, fmt.Errorf("unknown runtime type %#x", addr)
					}
				},
				ReadMemory: func(addr uint64, dst []byte) error {
					switch addr {
					case 0x111, 0x222:
						// Both concrete types are indirect; leave direct bits clear.
					case 0x3008:
						binary.LittleEndian.PutUint64(dst, 0x222)
					case 0x4000:
						binary.LittleEndian.PutUint64(dst, 42)
					default:
						return fmt.Errorf("unexpected read %#x", addr)
					}
					return nil
				},
			}},
			data: func() []LeafData {
				value := make([]byte, 64)
				binary.LittleEndian.PutUint64(value, 0x3000)
				binary.LittleEndian.PutUint64(value[8:], 0x4000)
				return []LeafData{u64data(0x111), u64data(0x2000), {Data: value}}
			}(),
			want: "v=main.Outer{Inner:42}",
		},
		{
			name: "interface-same-value-converges",
			values: []*Value{{
				Kind: KindInterface,
				Name: "err",
				RuntimeType: func(addr uint64) (dwarf.Type, error) {
					return &dwarf.IntType{BasicType: dwarf.BasicType{CommonType: dwarf.CommonType{Name: "main.Code", ByteSize: 8}}}, nil
				},
				ReadMemory: func(addr uint64, dst []byte) error {
					if addr != 0x1234 {
						return fmt.Errorf("unexpected read %#x", addr)
					}
					return nil
				},
			}},
			data: []LeafData{u64data(0x1234), u64data(0xc0009999), u64data(500)},
			want: "err=500",
		},
		{
			name: "struct",
			values: []*Value{{
				Kind:       KindStruct,
				Name:       "pt",
				StructName: "Point",
				Fields: []*Value{
					{Kind: KindScalar, Name: "pt.X", Typ: "s64", Size: 8},
					{Kind: KindScalar, Name: "pt.Y", Typ: "s64", Size: 8},
				},
			}},
			data: []LeafData{u64data(1), u64data(2)},
			want: "pt=Point{X:1, Y:2}",
		},
		{
			name: "struct-ptr-nil",
			values: []*Value{{
				Kind:       KindStructPtr,
				Name:       "p",
				StructName: "Point",
				Fields: []*Value{
					{Kind: KindScalar, Name: "p.X", Typ: "s64", Size: 8},
					{Kind: KindScalar, Name: "p.Y", Typ: "s64", Size: 8},
				},
			}},
			data: []LeafData{
				{Data: u64data(0).Data, IsNil: true},
				{Data: u64data(0).Data, IsNil: true},
			},
			want: "p=nil",
		},
		{
			name: "struct-ptr",
			values: []*Value{{
				Kind:       KindStructPtr,
				Name:       "p",
				StructName: "Point",
				Fields: []*Value{
					{Kind: KindScalar, Name: "p.X", Typ: "s64", Size: 8},
					{Kind: KindScalar, Name: "p.Y", Typ: "s64", Size: 8},
				},
			}},
			data: []LeafData{u64data(1), u64data(2)},
			want: "p=&Point{X:1, Y:2}",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := RenderValues(c.values, c.data); got != c.want {
				t.Errorf("RenderValues() = %q, want %q", got, c.want)
			}
		})
	}
}
