package bpf

import (
	"os"
	"testing"
)

func TestCurrentPidNamespace(t *testing.T) {
	dev, ino, err := currentPidNamespace()
	if err != nil {
		t.Fatal(err)
	}
	if dev == 0 || ino == 0 {
		t.Fatalf("currentPidNamespace() = dev=%d ino=%d, want non-zero", dev, ino)
	}
	link, err := os.Readlink("/proc/self/ns/pid")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("pid ns %s dev=%d ino=%d", link, dev, ino)
}
