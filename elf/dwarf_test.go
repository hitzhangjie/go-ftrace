package elf

import (
	"debug/dwarf"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/go-delve/delve/pkg/dwarf/godwarf"
)

func TestRuntimeType(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module fixture\n\ngo 1.20\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(`package main
import "errors"
func main() { var err error = errors.New("boom"); _ = err }
`), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "main")
	cmd := exec.Command("go", "build", "-gcflags", "all=-N -l", "-o", bin, ".")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build fixture: %v\n%s", err, out)
	}

	e, err := New(bin)
	if err != nil {
		t.Fatal(err)
	}
	base, err := e.ResolveSymbol("runtime.types")
	if err != nil {
		t.Fatal(err)
	}

	var addr uint64
	for die := range e.IterDebugInfo() {
		name, _ := die.Val(dwarf.AttrName).(string)
		if name != "*errors.errorString" {
			continue
		}
		if off, ok := die.Val(godwarf.AttrGoRuntimeType).(uint64); ok {
			addr = base.Value + off
			break
		}
	}
	if addr == 0 {
		t.Fatal("runtime type address for *errors.errorString not found")
	}

	typ, err := e.RuntimeType(addr)
	if err != nil {
		t.Fatal(err)
	}
	if got := typ.String(); got != "*errors.errorString" {
		t.Fatalf("RuntimeType(%#x) = %q, want %q", addr, got, "*errors.errorString")
	}
}
