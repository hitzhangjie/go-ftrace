## Questions & Answers

### why do interface return values show `*errors.errorString(<unavailable>)` on WSL2 but not on a cloud VM?

The uprobe captured the value. `bpf_get_current_pid_tgid()` reports the init-namespace TGID, while userspace `process_vm_readv` looks up PIDs in the caller's namespace. With systemd-enabled WSL2 those numbers differ, even though ftrace and the target share the same namespace. Write-up (Chinese): [BPF 事件 PID 与 pid namespace](./BpfPidNamespace.zh_CN.md).

### why `ftrace -u` not using regexp instead of wildcards?

Regexp isn't that convenient as wildcards if you use it frequently. For example, if there're functions `main.fn1, main.fn2, main.fn3`, then you want to trace them all, you may prefer `-u main.fn*` to `-u main.fn.*`.

Even though regexp can do this matching task, but it's not that simple to use.

### will it delay your application logic heavily?

No, Linux eBPF verifier verifies the ebpf programme, it doesn't allow heavy logic in the ebpf programme, so the uprobe callback logic is very simple, just records the events in the maps. It may import several microseconds. You may not care that, right?

Polling events and printing the callstack is done in the usermode part. This part runs concurrently with your logic. While uprobes will trigger exception and context-switched to kernel mode to execute the callback.

ps: both kprobe callback and uprobe callback run in kernel mode.
