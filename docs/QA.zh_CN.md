# 常见问题

### 为什么在 WSL2 上接口返回值会显示 `*errors.errorString(<unavailable>)`，而云主机上正常？

不是 uprobe 没抓到返回值，也不是 ftrace 和被观测进程不在同一个 namespace。BPF helper `bpf_get_current_pid_tgid()` 给出的是 init pid namespace 的 TGID，用户态 `process_vm_readv` 却按当前 ns 的 PID 查找，两套编号在 WSL2（systemd 嵌套 pid ns）里对不上。完整排查、内核细节和修复见 [BPF 事件 PID 与 pid namespace](./BpfPidNamespace.zh_CN.md)。

### 为什么在 5.4 内核上会报 `unknown func bpf_get_ns_current_pid_tgid`？

`bpf_get_ns_current_pid_tgid` 是 Linux 5.8 才加入的 BPF helper。5.4 验证器只要看到 `call 120` 就会拒绝加载，即使 C 里有 `if` 回退——验证器会走两条分支。加载时会探测该 helper：新内核继续用它拿 namespaced PID（WSL2/容器需要）；旧内核在加载前把这条 call 改掉，回退到 `bpf_get_current_pid_tgid`。详见 [BPF 事件 PID 与 pid namespace](./BpfPidNamespace.zh_CN.md) 第 8 节。需要重新编译安装 **ftrace 自身**（不是 `examples/main`）。

### 为什么 5.4 上还会报 `math between map_value pointer and register with unbounded min value is not allowed`？

这是过了 unknown helper 之后，5.4 验证器的下一关。`event` 在 per-CPU map 里，`e->args[e->arg_count]` 是对 map 值的变址；helper 调用后验证器会丢掉偏移的下界。接口 recipe 先抓到栈上，再用常量下标写回 `args[0..7]`。见 `internal/bpf/ftrace.c` 里的 `load_arg_word` / `store_arg`。

### 为什么 `ftrace -u` 使用通配符而不是正则表达式？

如果你频繁使用它，正则表达式并不像通配符那样方便。例如，如果存在 `main.fn1, main.fn2, main.fn3` 这几个函数，你想把它们全部跟踪，你可能会更喜欢 `-u main.fn*` 而不是 `-u main.fn.*`。

尽管正则表达式也能完成这种匹配任务，但使用起来并不那么简洁。

### 它会给你的应用程序逻辑带来严重的延迟吗？

不会。Linux eBPF 验证器会验证 eBPF 程序，它不允许在 eBPF 程序中出现繁重的逻辑，所以 uprobe 回调的逻辑非常简单，只是把事件记录到 maps 中。这可能会引入几微秒的延迟。你应该不会在意这一点，对吧？

轮询事件和打印调用栈是在用户态部分完成的。这部分与你的逻辑并发运行。而 uprobe 会触发异常并切换到内核态来执行回调。

附注：kprobe 回调和 uprobe 回调都运行在内核态。
