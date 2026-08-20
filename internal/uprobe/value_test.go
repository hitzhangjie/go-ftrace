package uprobe

import (
	"encoding/binary"
	"testing"
)

func u64data(v uint64) LeafData {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	return LeafData{Data: b[:]}
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
			data:   []LeafData{u64data(0), u64data(0)},
			want:   "err=nil",
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
