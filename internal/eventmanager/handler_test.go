package eventmanager

import (
	"debug/dwarf"
	"encoding/binary"
	"testing"

	"github.com/hitzhangjie/go-ftrace/internal/bpf"
	"github.com/hitzhangjie/go-ftrace/internal/uprobe"
)

func TestRenderEventArgsKeepsLeavesAtomic(t *testing.T) {
	meshError := &uprobe.Value{
		Kind:       uprobe.KindStructPtr,
		Name:       "ret0",
		StructName: "main.MeshError",
		Fields: []*uprobe.Value{
			{Kind: uprobe.KindScalar, Name: "ret0.Code", Typ: "s64", Size: 8},
			{
				Kind: uprobe.KindInterface,
				Name: "ret0.Detail",
				RuntimeType: func(uint64) (dwarf.Type, error) {
					return &dwarf.PtrType{
						CommonType: dwarf.CommonType{Name: "*errors.errorString", ByteSize: 8},
						Type: &dwarf.StructType{
							CommonType: dwarf.CommonType{Name: "errors.errorString", ByteSize: 16},
							StructName: "errors.errorString",
						},
					}, nil
				},
			},
		},
	}
	fetchArgs := []*uprobe.FetchArg{
		{Varname: "ret0.Code"},
		{Varname: "ret0.Detail.type"},
		{Varname: "ret0.Detail.data"},
		{Varname: "ret0.Detail.value"},
	}
	up := uprobe.Uprobe{Funcname: "main.send", FetchArgs: fetchArgs, Values: []*uprobe.Value{meshError}}

	var event bpf.GoftraceEvent
	event.ArgCount = 4
	binary.LittleEndian.PutUint64(event.Args[0].Data[:], 500)
	binary.LittleEndian.PutUint64(event.Args[1].Data[:], 0x46f9c0)
	binary.LittleEndian.PutUint64(event.Args[2].Data[:], 0xc0001000)
	event.Args[3].ReadError = 1

	if got := renderEventArgs(up, event); got != "ret0=&main.MeshError{Code:500, Detail:<unavailable>}" {
		t.Fatalf("renderEventArgs() = %q", got)
	}
}

func TestRenderEventArgsRejectsCountMismatch(t *testing.T) {
	up := uprobe.Uprobe{
		Funcname: "main.send",
		FetchArgs: []*uprobe.FetchArg{
			{Varname: "ret0.Code"},
			{Varname: "ret0.Detail.type"},
		},
		Values: []*uprobe.Value{{Kind: uprobe.KindScalar, Name: "ret0", Typ: "s64", Size: 8}},
	}
	event := bpf.GoftraceEvent{ArgCount: 1}
	binary.LittleEndian.PutUint64(event.Args[0].Data[:], 1)

	if got := renderEventArgs(up, event); got != "<unavailable>" {
		t.Fatalf("renderEventArgs() = %q, want unavailable", got)
	}
}

func TestRenderEventArgsDoesNotReusePreviousLeafData(t *testing.T) {
	up := uprobe.Uprobe{
		Funcname:  "main.send",
		FetchArgs: []*uprobe.FetchArg{{Varname: "ret0.Code"}},
		Values: []*uprobe.Value{{
			Kind: uprobe.KindScalar,
			Name: "ret0.Code",
			Typ:  "s64",
			Size: 8,
		}},
	}

	first := bpf.GoftraceEvent{ArgCount: 1}
	binary.LittleEndian.PutUint64(first.Args[0].Data[:], 500)
	if got := renderEventArgs(up, first); got != "ret0.Code=500" {
		t.Fatalf("first render = %q", got)
	}

	second := bpf.GoftraceEvent{ArgCount: 1}
	second.Args[0].ReadError = 1
	if got := renderEventArgs(up, second); got != "ret0.Code=<unavailable>" {
		t.Fatalf("failed read reused data: %q", got)
	}
}
