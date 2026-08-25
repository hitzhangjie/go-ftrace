package bpf

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func TestDisableNsPidHelper(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			"ent": {
				Instructions: asm.Instructions{
					asm.LoadImm(asm.R1, 0, asm.DWord),
					asm.FnGetNsCurrentPidTgid.Call(),
					asm.FnGetCurrentPidTgid.Call(),
					asm.Return(),
				},
			},
			"ret": {
				Instructions: asm.Instructions{
					asm.FnGetNsCurrentPidTgid.Call(),
					asm.Return(),
				},
			},
		},
	}

	n := disableNsPidHelper(spec)
	if n != 2 {
		t.Fatalf("patched %d calls, want 2", n)
	}

	want := asm.Mov.Imm(asm.R0, -1)
	ent := spec.Programs["ent"].Instructions
	if ent[1].OpCode != want.OpCode || ent[1].Dst != want.Dst || ent[1].Constant != want.Constant {
		t.Fatalf("ent call 0: got %+v, want %+v", ent[1], want)
	}
	if ent[2].OpCode.JumpOp() != asm.Call || ent[2].Constant != int64(asm.FnGetCurrentPidTgid) {
		t.Fatalf("unrelated helper was patched: %+v", ent[2])
	}
	ret := spec.Programs["ret"].Instructions
	if ret[0].OpCode != want.OpCode || ret[0].Constant != want.Constant {
		t.Fatalf("ret call 0: got %+v, want %+v", ret[0], want)
	}

	if disableNsPidHelper(spec) != 0 {
		t.Fatal("second pass should find no remaining ns-pid helper calls")
	}
	if disableNsPidHelper(nil) != 0 {
		t.Fatal("nil spec should patch nothing")
	}
}

func TestNspidCount(t *testing.T) {
	tests := []struct {
		name   string
		status string
		want   int
	}{
		{name: "init ns", status: "Name:\tftrace\nNSpid:\t123\nPPid:\t1\n", want: 1},
		{name: "nested", status: "Name:\tftrace\nNSpid:\t76675\t6779\nPPid:\t1\n", want: 2},
		{name: "three levels", status: "NSpid:\t10\t20\t30\n", want: 3},
		{name: "spaces", status: "NSpid:  42  99\n", want: 2},
		{name: "missing", status: "Name:\tftrace\nPPid:\t1\n", want: 0},
		{name: "empty", status: "", want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := nspidCount(tt.status); got != tt.want {
				t.Fatalf("nspidCount() = %d, want %d", got, tt.want)
			}
		})
	}
}
