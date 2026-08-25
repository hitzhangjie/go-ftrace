package bpf

import (
	"os"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func raiseMemlock(t *testing.T) {
	t.Helper()
	rlimit := syscall.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY}
	_ = syscall.Setrlimit(unix.RLIMIT_MEMLOCK, &rlimit)
}

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

func TestHaveNsPidHelper(t *testing.T) {
	raiseMemlock(t)
	ok, err := haveNsPidHelper()
	if err != nil {
		t.Logf("haveNsPidHelper: %v (inconclusive; CAP_BPF / CAP_SYS_ADMIN may be required)", err)
		return
	}
	t.Logf("bpf_get_ns_current_pid_tgid available=%v nested_pidns=%v", ok, nestedPidNamespace())
}
