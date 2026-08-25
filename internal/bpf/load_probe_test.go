package bpf

import (
	"testing"
)

func TestLoadCollection(t *testing.T) {
	raiseMemlock(t)
	if _, err := haveNsPidHelper(); err != nil {
		t.Skipf("cannot probe BPF helpers: %v", err)
	}
	b := New()
	err := b.Load(nil, LoadOptions{GoidOffset: 152, GOffset: -8})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	t.Cleanup(b.Detach)
}
