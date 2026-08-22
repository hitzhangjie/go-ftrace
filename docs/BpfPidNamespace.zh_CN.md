# BPF 事件 PID 与 pid namespace

本文记录一次真实排查：同一套 go-ftrace 在云主机上能完整打印接口返回值，在 WSL2（systemd、内核 6.6）上却把已经识别出的动态类型显示成 `<unavailable>`。根因不是 uprobe 失效，也不是 ftrace 与被观测进程不在同一个 namespace，而是 **BPF helper 与用户态系统调用使用了两套 PID 编号**。

## 1. 现象

跟踪 `testdata/rets` 里的 `main.send`（由 `go1.22.2` 以非 PIE 方式构建）时，云主机输出：

```text
ret0=&main.MeshError{Code:500, Detail:&errors.errorString{s:"send failed"}}
```

WSL2 上变成：

```text
ret0=&main.MeshError{Code:500, Detail:*errors.errorString(<unavailable>)}
```

容易误判成「这台机器的 BPF / 内核 6.6 读返回值失败」。把输出拆开后并不是这样：

| 片段 | 谁负责 | WSL2 上 |
|---|---|---|
| `Code:500` | BPF 在 `RET` 点读 `*(AX+0)` | 成功 |
| 动态类型 `*errors.errorString` | BPF 读 itab，用户态用 DWARF `RuntimeType` 反查 ELF | 成功 |
| 字符串 `"send failed"` | 用户态 `process_vm_readv` 读目标进程内存 | 失败 |

如果是 BPF 叶子读取失败，渲染器会写成 `Detail:<unavailable>`，**不会**带上已经解析出的类型名。`*errors.errorString(<unavailable>)` 来自 `runtimeTypeIsDirect()`：类型已经认出，但跟读 runtime type header 失败，于是把 `t.String()` 和 `(<unavailable>)` 拼在一起。

## 2. 返回值是怎么走到 `<unavailable>` 的

接口字段（这里是 `error`）在 auto 模式下会抓三个叶子：`.type`、`.data`、`.value`（data word 指向对象的 64 字节前缀）。BPF 在探针触发时完成这三次读取，结果随事件一起送到用户态。

用户态渲染 `KindInterface` 时：

1. 用 `.type` 地址查 DWARF，得到 `*errors.errorString`（只读 ELF，不需要 PID）；
2. 调用 `process_vm_readv(event.Pid, typeAddr, 24)` 读 runtime type header，判断 DirectIface；
3. 再按是否 direct，解释 `.value` 前缀，并可能继续 `process_vm_readv` 读字符串内容。

第 2 步失败就会停在 `*errors.errorString(<unavailable>)`，即使 BPF 已经把 64 字节前缀带回来了。

`--debug` 下可以看到：

```text
process_vm_readv pid=6779 addr=0x471400 len=24: no such process
```

`ESRCH` 表示这个 PID 在 **ftrace 所在的 pid namespace** 里不存在，而不是目标地址不可读。

## 3. 常见误解：两个进程不在同一个 namespace

ftrace 和被观测程序都在 WSL2 发行版里启动，**它们确实处于同一个 pid namespace**。问题不在这两个进程之间。

真正错开的是 **同一进程的两套 PID**：

| 谁在问 | 得到的编号 |
|---|---|
| `getpid()` / `ps` / `process_vm_readv(pid)` / `/proc/<pid>` | 调用者当前 pid namespace 里的 PID |
| `bpf_get_current_pid_tgid()` | **init pid namespace** 里的 TGID |

内核里该 helper 的实现等价于：

```c
return (u64) current->tgid << 32 | current->pid;
```

`task_struct->pid` / `->tgid` 在 fork 时用 `pid_nr()` 填入，取的是 `pid->numbers[0]`，也就是 **init namespace 的全局编号**。它不会自动换成「当前 task 所在 ns 里的号」。

用户态则相反：`process_vm_readv(pid)` 在 **调用者** 的 pid namespace 里查找 `pid`。ftrace 在发行版 ns 里，就会按发行版的编号表去查。

开启 `systemd=true` 的 WSL2 实际是两层：

```text
WSL2 VM  (init pid ns)           PID 1 = Microsoft mini_init
 └── 发行版 (嵌套 pid ns)         PID 1 = systemd
      ├── ftrace
      └── testdata/rets/main
```

两个用户进程同 ns；BPF 报告的却是外层编号。一次实测：

```text
./main  在发行版里的 PID = 76675     ← ps、process_vm_readv 认这个
BPF 事件里的 Pid      = 6779      ← 同一进程在 init ns 里的 TGID
/proc/6779                       ← 发行版里不存在 → ESRCH
```

云主机通常没有这层嵌套，init ns 就是你看到的 ns，两套数字重合，所以同一套二进制在 CVM 上正常。

这和内核 6.6、Yama、`CONFIG_CROSS_MEMORY_ATTACH`、Go 1.26 type header 布局都无关。fixture 与 `ftrace` 均由 Makefile 中的 `GO ?= go1.22.2` 构建；本机默认 `go` 若是更新版本，不要用它来复现或安装。

## 4. 为什么 uprobe 本身不受影响

uprobe 挂在可执行文件的 inode/offset 上，回调跑在被观测线程的上下文里。读寄存器、`bpf_probe_read_user` 跟的是 **当前 task 的地址空间**，不经过 PID 查找。

因此会出现这种「一半好、一半坏」：

```text
RET 探针触发                         ✅ 同 ns，与 PID 无关
BPF 抓 Code / itab / data / 前缀     ✅ 读 current 的用户内存
事件.pid = init-ns TGID              ❌ 外层编号
用户态 RuntimeType(itab)             ✅ 读 ELF
process_vm_readv(错误 PID)           ❌ 内层 ns 里查不到
```

`goid` 只在单进程内唯一，内核状态机用 `(pid, goid)` 做 key。即使用了 init-ns PID，**内核内部仍然自洽**，调用栈重建也不会因此错乱；坏的只是事后跟读进程内存。

## 5. 修复

Linux 5.8 起提供 `bpf_get_ns_current_pid_tgid(dev, ino, ...)`：传入某个 pid namespace 的 nsfs `st_dev` / `st_ino`，返回 **当前 task 在该 ns 中的 pid/tgid**。若 `dev/ino` 与当前 task 的 pid ns 不一致，helper 返回 `-EINVAL`。

go-ftrace 在加载 BPF 时对 `/proc/self/ns/pid` 做 `fstat`，把结果写入 `CONFIG`：

```go
// internal/bpf/bpf.go
dev, ino, err := currentPidNamespace() // fstat(/proc/self/ns/pid)
```

探针里优先用这个 ns 取 TGID，失败再回退到旧 helper：

```c
// internal/bpf/ftrace.c
if (CONFIG.pidns_dev && CONFIG.pidns_ino) {
    if (!bpf_get_ns_current_pid_tgid(CONFIG.pidns_dev, CONFIG.pidns_ino, &ns, sizeof(ns)) && ns.tgid)
        return ns.tgid;
}
return bpf_get_current_pid_tgid() >> 32;
```

因为 ftrace 与被观测进程同 ns，helper 给出的就是 `process_vm_readv` 能查到的那个 PID。云主机上两套编号本来就相同，行为与修复前一致。

## 6. 如何确认

1. 用 `go1.22.2` 构建（`make build` / `make install`），不要用本机默认的更新 Go。
2. `ftrace -d -u 'main.send' testdata/rets/main`，对照：
   - 事件里的 `Pid:` 是否等于 `ps` 里目标进程的 PID；
   - 是否出现 `process_vm_readv pid=... no such process`；
   - 成功时应为 `Detail:&errors.errorString{s:"send failed"}`。
3. `cat /etc/wsl.conf` 若有 `systemd=true`，发行版 PID 1 是 systemd，就存在本文描述的嵌套 ns。普通云主机上 `bpf_get_current_pid_tgid()` 的高 32 位通常已等于 `getpid()`，不会触发这个问题。

容器里情况相同：容器有自己的 pid ns，`bpf_get_current_pid_tgid()` 仍报宿主/init ns 编号。只要 ftrace 与目标同 ns，上述修复同样适用。

## 7. 仍然要注意的边界

- uprobe 按 inode 挂载，**不会**按 PID 过滤。同一二进制的其他进程实例也会出事件。若某个实例与 ftrace 不在同一 pid ns，helper 会回退到 init-ns PID，对该实例的 `process_vm_readv` 仍可能 `ESRCH`。这是挂载模型的既有行为，不是本次回归。
- 接口动态值里，字符串内容、嵌套指针仍然依赖事后 `process_vm_readv`。PID 对上之后，目标内存已释放或映射不可读时，仍会局部显示 `<unavailable>`。见 [Auto 模式原理](./AutoFetch.zh_CN.md)。
- DirectIface 标志的字节位置随 Go 版本变化（1.25 及以前在 Kind `+23`，1.26 起在 TFlag `+20`）。这与 pid namespace 是独立问题；当前渲染器两处都检查。
