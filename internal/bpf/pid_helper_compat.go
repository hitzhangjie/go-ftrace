package bpf

import (
	"errors"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	log "github.com/sirupsen/logrus"
)

// haveNsPidHelper reports whether bpf_get_ns_current_pid_tgid is available to
// kprobe/uprobe programs on this kernel.
//
// A nil error is conclusive: ok is true iff the helper exists.
// Any other error (for example EPERM) is inconclusive — the caller must not
// treat that as "helper missing".
func haveNsPidHelper() (ok bool, err error) {
	err = features.HaveProgramHelper(ebpf.Kprobe, asm.FnGetNsCurrentPidTgid)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, ebpf.ErrNotSupported) {
		return false, nil
	}
	return false, err
}

// disableNsPidHelper rewrites every bpf_get_ns_current_pid_tgid call into
// `r0 = -1` so the existing C fallback in get_pid() runs. The 5.4 verifier
// rejects unknown helper IDs even on branches that C treats as dead, so the
// Call instruction itself has to disappear before LoadAndAssign.
func disableNsPidHelper(spec *ebpf.CollectionSpec) int {
	if spec == nil {
		return 0
	}
	n := 0
	for _, prog := range spec.Programs {
		if prog == nil {
			continue
		}
		for i, ins := range prog.Instructions {
			if ins.OpCode.JumpOp() != asm.Call || ins.Constant != int64(asm.FnGetNsCurrentPidTgid) {
				continue
			}
			patched := asm.Mov.Imm(asm.R0, -1)
			patched.Metadata = ins.Metadata
			prog.Instructions[i] = patched
			n++
		}
	}
	return n
}

// nestedPidNamespace reports whether this process is in a nested pid
// namespace. /proc/self/status NSpid lists one id per nesting level, innermost
// first; a single field means we are in the init pid ns (as seen by this
// task). Comparing /proc/self/ns/pid to /proc/1/ns/pid is not sufficient:
// WSL2 systemd is pid 1 in the same nested ns as ftrace.
func nestedPidNamespace() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	return nspidCount(string(data)) > 1
}

func nspidCount(status string) int {
	for _, line := range strings.Split(status, "\n") {
		rest, ok := strings.CutPrefix(line, "NSpid:")
		if !ok {
			continue
		}
		return len(strings.Fields(rest))
	}
	return 0
}

// selectPidHelper probes the running kernel and, when the namespaced-pid
// helper is missing, patches the collection so it can still load on 5.4.
func selectPidHelper(spec *ebpf.CollectionSpec) {
	ok, err := haveNsPidHelper()
	if err != nil {
		log.Warnf("cannot probe bpf_get_ns_current_pid_tgid (%v); loading program as-is", err)
		return
	}
	if ok {
		log.Info("pid helper: bpf_get_ns_current_pid_tgid")
		return
	}
	n := disableNsPidHelper(spec)
	log.Infof("pid helper: bpf_get_current_pid_tgid (kernel lacks namespaced pid helper; patched %d call(s))", n)
	if nestedPidNamespace() {
		log.Warn("nested pid namespace on a kernel without bpf_get_ns_current_pid_tgid (needs Linux 5.8+); event PIDs are init-namespace TGIDs and may not match /proc or process_vm_readv")
	}
}
