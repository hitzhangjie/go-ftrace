# 常见问题

### 为什么在 WSL2 上接口返回值会显示 `*errors.errorString(<unavailable>)`，而云主机上正常？

不是 uprobe 没抓到返回值，也不是 ftrace 和被观测进程不在同一个 namespace。BPF helper `bpf_get_current_pid_tgid()` 给出的是 init pid namespace 的 TGID，用户态 `process_vm_readv` 却按当前 ns 的 PID 查找，两套编号在 WSL2（systemd 嵌套 pid ns）里对不上。完整排查、内核细节和修复见 [BPF 事件 PID 与 pid namespace](./BpfPidNamespace.zh_CN.md)。

### 为什么 `ftrace -u` 使用通配符而不是正则表达式？

如果你频繁使用它，正则表达式并不像通配符那样方便。例如，如果存在 `main.fn1, main.fn2, main.fn3` 这几个函数，你想把它们全部跟踪，你可能会更喜欢 `-u main.fn*` 而不是 `-u main.fn.*`。

尽管正则表达式也能完成这种匹配任务，但使用起来并不那么简洁。

### 它会给你的应用程序逻辑带来严重的延迟吗？

不会。Linux eBPF 验证器会验证 eBPF 程序，它不允许在 eBPF 程序中出现繁重的逻辑，所以 uprobe 回调的逻辑非常简单，只是把事件记录到 maps 中。这可能会引入几微秒的延迟。你应该不会在意这一点，对吧？

轮询事件和打印调用栈是在用户态部分完成的。这部分与你的逻辑并发运行。而 uprobe 会触发异常并切换到内核态来执行回调。

附注：kprobe 回调和 uprobe 回调都运行在内核态。
