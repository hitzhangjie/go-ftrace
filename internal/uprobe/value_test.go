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

func intType(name string) dwarf.Type {
	return &dwarf.IntType{BasicType: dwarf.BasicType{CommonType: dwarf.CommonType{Name: name, ByteSize: 8}}}
}

func boolType() dwarf.Type {
	return &dwarf.BoolType{BasicType: dwarf.BasicType{CommonType: dwarf.CommonType{Name: "bool", ByteSize: 1}}}
}

func ptrType(name string, elem dwarf.Type) dwarf.Type {
	return &dwarf.PtrType{CommonType: dwarf.CommonType{Name: name, ByteSize: 8}, Type: elem}
}

func stringType() dwarf.Type {
	return &dwarf.StructType{
		CommonType: dwarf.CommonType{Name: "string", ByteSize: 16},
		StructName: "string",
		Field: []*dwarf.StructField{
			{Name: "str", ByteOffset: 0, Type: ptrType("*uint8", &dwarf.UintType{BasicType: dwarf.BasicType{CommonType: dwarf.CommonType{ByteSize: 1}}})},
			{Name: "len", ByteOffset: 8, Type: intType("int")},
		},
	}
}

func sliceType(name string) dwarf.Type {
	return &dwarf.StructType{
		CommonType: dwarf.CommonType{Name: name, ByteSize: 24},
		StructName: name,
		Field: []*dwarf.StructField{
			{Name: "array", ByteOffset: 0},
			{Name: "len", ByteOffset: 8, Type: intType("int")},
			{Name: "cap", ByteOffset: 16, Type: intType("int")},
		},
	}
}

func ifaceType() dwarf.Type {
	return &dwarf.StructType{
		CommonType: dwarf.CommonType{Name: "runtime.iface", ByteSize: 16},
		StructName: "runtime.iface",
		Field: []*dwarf.StructField{
			{Name: "tab", ByteOffset: 0},
			{Name: "data", ByteOffset: 8},
		},
	}
}

func errorStringType() dwarf.Type {
	return &dwarf.StructType{
		CommonType: dwarf.CommonType{Name: "errors.errorString", ByteSize: 16},
		StructName: "errors.errorString",
		Field: []*dwarf.StructField{
			{Name: "s", ByteOffset: 0, Type: stringType()},
		},
	}
}

func meshErrorType() dwarf.Type {
	return &dwarf.StructType{
		CommonType: dwarf.CommonType{Name: "main.MeshError", ByteSize: 24},
		StructName: "main.MeshError",
		Field: []*dwarf.StructField{
			{Name: "Code", ByteOffset: 0, Type: intType("main.MeshErrorCode")},
			{Name: "Detail", ByteOffset: 8, Type: ifaceType()},
		},
	}
}

func blobData(b []byte) LeafData {
	if len(b) >= autoStringSize {
		return LeafData{Data: b[:autoStringSize]}
	}
	out := make([]byte, autoStringSize)
	copy(out, b)
	return LeafData{Data: out}
}

func emptyBlob() LeafData {
	return LeafData{Data: make([]byte, autoStringSize)}
}

func TestInterfaceRenderingConverges(t *testing.T) {
	value := &Value{
		Name:      "err",
		Type:      ifaceType(),
		WordCount: 2,
		Captures:  2,
		RuntimeType: func(addr uint64) (dwarf.Type, error) {
			return intType("main.Code"), nil
		},
	}
	first := RenderValues([]*Value{value}, []LeafData{u64data(0x1234), u64data(500), emptyBlob(), emptyBlob()})
	second := RenderValues([]*Value{value}, []LeafData{u64data(0x1234), u64data(500), emptyBlob(), emptyBlob()})
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
			values: []*Value{{Name: "a", Type: intType("int"), WordCount: 1}},
			data:   []LeafData{u64data(42)},
			want:   "a=42",
		},
		{
			name:   "bool",
			values: []*Value{{Name: "ok", Type: boolType(), WordCount: 1}},
			data:   []LeafData{{Data: []byte{1}}},
			want:   "ok=true",
		},
		{
			name:   "pointer-nil",
			values: []*Value{{Name: "p", Type: ptrType("*int", intType("int")), WordCount: 1}},
			data:   []LeafData{u64data(0)},
			want:   "p=nil",
		},
		{
			name:   "pointer-addr",
			values: []*Value{{Name: "p", Type: ptrType("*int", intType("int")), WordCount: 1}},
			data:   []LeafData{u64data(0xc0001234)},
			want:   "p=0xc0001234",
		},
		{
			name:   "string",
			values: []*Value{{Name: "name", Type: stringType(), WordCount: 2, Captures: 1}},
			data:   []LeafData{u64data(0x1000), u64data(5), blobData([]byte("hello"))},
			want:   `name="hello"`,
		},
		{
			name:   "string-truncated",
			values: []*Value{{Name: "name", Type: stringType(), WordCount: 2, Captures: 1}},
			data:   []LeafData{u64data(0x1000), u64data(80), blobData(bytesOf('x', autoStringSize))},
			want:   `name="` + string(bytesOf('x', autoStringSize)) + `..."`,
		},
		{
			name:   "slice",
			values: []*Value{{Name: "nums", Type: sliceType("[]int"), WordCount: 3}},
			data:   []LeafData{u64data(0), u64data(3), u64data(5)},
			want:   "nums=[]int(len=3, cap=5)",
		},
		{
			name:   "interface-nil",
			values: []*Value{{Name: "err", Type: ifaceType(), WordCount: 2, Captures: 1}},
			data:   []LeafData{u64data(0), u64data(0), {IsNil: true}},
			want:   "err=nil",
		},
		{
			name:   "interface-nil-type-read-skipped",
			values: []*Value{{Name: "err", Type: ifaceType(), WordCount: 2, Captures: 1}},
			data:   []LeafData{{IsNil: true}, u64data(0), {IsNil: true}},
			want:   "err=nil",
		},
		{
			name:   "interface-nil-type-unavailable",
			values: []*Value{{Name: "err", Type: ifaceType(), WordCount: 2, Captures: 1}},
			data:   []LeafData{{Unavailable: true}, u64data(0), {Unavailable: true}},
			want:   "err=nil",
		},
		{
			name: "interface-dynamic-struct",
			values: []*Value{{
				Name:      "err",
				Type:      ifaceType(),
				WordCount: 2,
				Captures:  2,
				RuntimeType: func(addr uint64) (dwarf.Type, error) {
					return &dwarf.StructType{
						CommonType: dwarf.CommonType{Name: "main.MeshError", ByteSize: 16},
						StructName: "main.MeshError",
						Field: []*dwarf.StructField{
							{Name: "Code", ByteOffset: 0, Type: intType("int")},
							{Name: "Retry", ByteOffset: 8, Type: boolType()},
						},
					}, nil
				},
			}},
			data: func() []LeafData {
				value := make([]byte, autoStringSize)
				binary.LittleEndian.PutUint64(value, 500)
				value[8] = 1
				return []LeafData{u64data(0x1234), u64data(0x5678), blobData(value), emptyBlob()}
			}(),
			want: "err=main.MeshError{Code:500, Retry:true}",
		},
		{
			name: "interface-direct-pointer",
			values: []*Value{{
				Name:      "err",
				Type:      ifaceType(),
				WordCount: 2,
				Captures:  2,
				RuntimeType: func(addr uint64) (dwarf.Type, error) {
					st := &dwarf.StructType{
						CommonType: dwarf.CommonType{Name: "main.MeshError", ByteSize: 8},
						StructName: "main.MeshError",
						Field:      []*dwarf.StructField{{Name: "Code", Type: intType("int")}},
					}
					return ptrType("*main.MeshError", st), nil
				},
			}},
			data: func() []LeafData {
				value := make([]byte, autoStringSize)
				binary.LittleEndian.PutUint64(value, 500)
				return []LeafData{u64data(0x1234), u64data(0xc0005000), blobData(value), emptyBlob()}
			}(),
			want: "err=&main.MeshError{Code:500}",
		},
		{
			name: "interface-nested-interface",
			values: []*Value{{
				Name:      "v",
				Type:      ifaceType(),
				WordCount: 2,
				Captures:  2,
				RuntimeType: func(addr uint64) (dwarf.Type, error) {
					switch addr {
					case 0x111:
						return &dwarf.StructType{
							CommonType: dwarf.CommonType{Name: "main.Outer", ByteSize: 16},
							StructName: "main.Outer",
							Field: []*dwarf.StructField{{
								Name: "Inner",
								Type: ifaceType(),
							}},
						}, nil
					case 0x222:
						return intType("main.Code"), nil
					default:
						return nil, fmt.Errorf("unknown runtime type %#x", addr)
					}
				},
			}},
			data: func() []LeafData {
				outer := make([]byte, autoStringSize)
				binary.LittleEndian.PutUint64(outer, 0x3000)
				binary.LittleEndian.PutUint64(outer[8:], 42)
				chase := make([]byte, autoStringSize)
				binary.LittleEndian.PutUint64(chase[8:], 0x222)
				return []LeafData{u64data(0x111), u64data(0x2000), blobData(outer), blobData(chase)}
			}(),
			want: "v=main.Outer{Inner:interface{type=<unknown>, value=<unavailable>}}",
		},
		{
			name: "interface-same-value-converges",
			values: []*Value{{
				Name:      "err",
				Type:      ifaceType(),
				WordCount: 2,
				Captures:  2,
				RuntimeType: func(addr uint64) (dwarf.Type, error) {
					return intType("main.Code"), nil
				},
			}},
			data: []LeafData{u64data(0x1234), u64data(500), emptyBlob(), emptyBlob()},
			want: "err=500",
		},
		{
			name: "struct",
			values: []*Value{{
				Name: "pt",
				Type: &dwarf.StructType{
					CommonType: dwarf.CommonType{Name: "Point", ByteSize: 16},
					StructName: "Point",
					Field: []*dwarf.StructField{
						{Name: "X", ByteOffset: 0, Type: intType("int")},
						{Name: "Y", ByteOffset: 8, Type: intType("int")},
					},
				},
				WordCount: 2,
			}},
			data: []LeafData{u64data(1), u64data(2)},
			want: "pt=Point{X:1, Y:2}",
		},
		{
			name: "struct-ptr-nil",
			values: []*Value{{
				Name:      "p",
				Type:      ptrType("*Point", &dwarf.StructType{StructName: "Point"}),
				WordCount: 1,
				Captures:  1,
			}},
			data: []LeafData{u64data(0), {IsNil: true}},
			want: "p=nil",
		},
		{
			name: "struct-ptr",
			values: []*Value{{
				Name: "p",
				Type: ptrType("*Point", &dwarf.StructType{
					CommonType: dwarf.CommonType{Name: "Point", ByteSize: 16},
					StructName: "Point",
					Field: []*dwarf.StructField{
						{Name: "X", ByteOffset: 0, Type: intType("int")},
						{Name: "Y", ByteOffset: 8, Type: intType("int")},
					},
				}),
				WordCount: 1,
				Captures:  1,
			}},
			data: func() []LeafData {
				blob := make([]byte, autoStringSize)
				binary.LittleEndian.PutUint64(blob, 1)
				binary.LittleEndian.PutUint64(blob[8:], 2)
				return []LeafData{u64data(0xc0001000), blobData(blob)}
			}(),
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

func bytesOf(ch byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = ch
	}
	return b
}

func TestMeshErrorCodeAndDetailShareTypeWalk(t *testing.T) {
	const (
		meshPtr    = 0xc0001000
		itabAddr   = 0x46f9c0
		typeAddr   = 0x470000
		dataAddr   = 0xc0002000
		strAddr    = 0xc0003000
		strContent = "send failed"
	)

	obj := make([]byte, autoStringSize)
	binary.LittleEndian.PutUint64(obj, 500)
	binary.LittleEndian.PutUint64(obj[8:], itabAddr)
	binary.LittleEndian.PutUint64(obj[16:], dataAddr)

	typeLeaf := u64data(typeAddr)

	value := make([]byte, autoStringSize)
	binary.LittleEndian.PutUint64(value, strAddr)
	binary.LittleEndian.PutUint64(value[8:], uint64(len(strContent)))

	v := &Value{
		Name:      "ret0",
		Type:      ptrType("*main.MeshError", meshErrorType()),
		WordCount: 1,
		Captures:  4,
		RuntimeType: func(addr uint64) (dwarf.Type, error) {
			if addr != typeAddr {
				return nil, fmt.Errorf("unknown runtime type %#x", addr)
			}
			return ptrType("*errors.errorString", errorStringType()), nil
		},
	}
	concrete := ptrType("*errors.errorString", errorStringType())
	got := RenderValuesRecipes([]*Value{v}, []LeafData{
		u64data(meshPtr),
		blobData(obj),
		typeLeaf,
		u64data(dataAddr),
		blobData(value),
		blobData([]byte(strContent)),
	}, map[uint64][]RelRule{typeAddr: CompileTypeRecipe(concrete)})
	want := `ret0=&main.MeshError{Code:500, Detail:&errors.errorString{s:"send failed"}}`
	if got != want {
		t.Fatalf("RenderValues() = %q, want %q", got, want)
	}
}

func TestMeshErrorDetailUnavailableStillShowsCode(t *testing.T) {
	obj := make([]byte, autoStringSize)
	binary.LittleEndian.PutUint64(obj, 500)
	binary.LittleEndian.PutUint64(obj[8:], 0x46f9c0)
	binary.LittleEndian.PutUint64(obj[16:], 0xc0002000)

	v := &Value{
		Name:      "ret0",
		Type:      ptrType("*main.MeshError", meshErrorType()),
		WordCount: 1,
		Captures:  4,
		RuntimeType: func(uint64) (dwarf.Type, error) {
			return ptrType("*errors.errorString", errorStringType()), nil
		},
	}

	got := RenderValues([]*Value{v}, []LeafData{
		u64data(0xc0001000),
		blobData(obj),
		{Unavailable: true},
		{Unavailable: true},
		{Unavailable: true},
	})
	want := "ret0=&main.MeshError{Code:500, Detail:*errors.errorString(<unavailable>)}"
	if got != want {
		t.Fatalf("RenderValues() = %q, want %q", got, want)
	}
}
