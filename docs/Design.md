# go-ftrace 设计与实现

> 本文面向 go-ftrace 的使用者和贡献者，说明项目的设计目标、关键取舍、完整执行流程与当前实现边界。
>
> 项目早期的设计背景和基础原理可参考：[观测 Go 函数调用：go-ftrace 设计实现](https://www.hitzhangjie.pro/blog/2023-12-12-%E8%A7%82%E6%B5%8Bgo%E5%87%BD%E6%95%B0%E8%B0%83%E7%94%A8go-ftrace%E8%AE%BE%E8%AE%A1%E5%AE%9E%E7%8E%B0/)。本文以仓库当前代码为准，补充了自动参数推导、多进程隔离、goroutine 退出回收和聚类输出等后续演进。

## 1. 项目定位

go-ftrace 是一个面向 Go ELF 可执行文件的无侵入函数调用观测工具。它不要求修改业务源码，也不需要重新编译插桩，而是：

1. 在用户态解析目标二进制的 ELF、符号表、DWARF 和机器指令；
2. 找到待观测函数的入口以及所有 `RET` 指令；
3. 使用 eBPF `uprobe` 在这些位置采集函数进入、返回、参数和时间戳；
4. 按进程和 goroutine 重建已观测函数的嵌套关系；
5. 输出调用位置、源码位置、耗时、参数与返回值，或生成聚合统计。

需要先明确三个边界：

- 项目名中的 “ftrace” 表示它提供类似 function graph tracer 的体验，当前实现并未接入 Linux tracefs/ftrace 子系统；底层使用的是 `bpf(2)`、eBPF 和 uprobe。
- 输出的“调用链”只包含已经挂载 uprobe 的函数。未被 `-u` 或参数规则选中的函数不会产生事件，因此不会出现在调用链中。
- 当前返回点没有使用 `link.Uretprobe`，而是反汇编函数体，并在每一条 `RET` 指令上挂普通 uprobe。

## 2. 设计目标与取舍

### 2.1 设计目标

- **无侵入**：不修改目标进程，不依赖业务代码埋点。
- **按 goroutine 组织事件**：Go 调度器会让 goroutine 在线程间迁移，调用关系不能只按线程 ID 归组。
- **可观测函数图**：同时采集入口和返回事件，在用户态还原嵌套关系并计算耗时。
- **参数可解释**：支持显式寻址规则，也能从 DWARF 类型信息和 Go 寄存器 ABI 自动生成常见类型的抓取规则。
- **控制高频输出**：除逐条打印外，支持按函数聚合延迟和返回值分布。
- **支持同一二进制的多个进程实例**：所有 goroutine 状态均以 PID 隔离，避免不同进程中相同 goid 串扰。

### 2.2 关键取舍

#### 用户态做复杂解析，内核态只做有界采集

ELF/DWARF 解析、指令反汇编、规则生成、符号化和格式化都放在用户态；eBPF 程序只完成状态判断、寄存器/内存读取以及向固定容量队列写入。这样既满足 verifier 对程序复杂度的限制，也使展示逻辑更容易扩展。

#### 以 goroutine 为跟踪状态，而不是逐函数独立过滤

`should_trace_rip` 只决定“哪个函数可以启动一次 goroutine 跟踪”。goroutine 命中触发函数后，会进入 `should_trace_goid`，随后它执行到的所有已挂载函数都会被记录，直至 `runtime.goexit1` 清理该状态。

这可以保留触发函数之后的已挂载调用链，但也意味着跟踪状态不是在触发函数返回时结束。一个长生命周期 goroutine 一旦被触发，之后执行到的其他已挂载函数仍会被采集。

#### 返回点使用每条 `RET` 上的普通 uprobe

Go 函数可能有多个返回出口。当前实现通过 x86-64 反汇编找出全部 `RET`，逐点挂载同一个返回处理程序。这让返回点地址可以直接作为返回值抓取规则的 key，也避免把实现依赖在 `uretprobe` 的返回关联机制上。

## 3. 总体架构

```mermaid
flowchart LR
    subgraph U["用户态 · Go"]
        CLI["Cobra CLI\ncmd/root.go"]
        TR["Tracer\ncmd/tracer.go"]
        ELF["ELF / DWARF / 反汇编\nelf/"]
        UP["探针与参数规则生成\ninternal/uprobe/"]
        BL["加载与挂载\ninternal/bpf/bpf.go"]
        EM["事件归组、栈重建、输出\ninternal/eventmanager/"]

        CLI --> TR
        TR --> ELF
        ELF --> UP
        UP --> BL
        BL --> EM
    end

    subgraph K["内核态 · eBPF"]
        ENT["uprobe/ent"]
        RET["uprobe/ret"]
        EXIT["uprobe/goroutine_exit"]
        STATE["should_trace_rip\nshould_trace_goid"]
        RULES["arg_rules_map"]
        QUEUES["event_queue\n完整 event+args"]

        ENT <--> STATE
        RET <--> STATE
        EXIT --> STATE
        ENT --> RULES
        RET --> RULES
        ENT --> QUEUES
        RET --> QUEUES
        EXIT --> QUEUES
    end

    BL -- "加载程序、写入 map、attach" --> K
    QUEUES -- "轮询" --> EM
```

代码按职责分为：

| 目录 | 职责 |
| --- | --- |
| `cmd/` | 命令行、资源限制、启动流程、信号处理 |
| `elf/` | ELF/DWARF 读取、符号解析、PC/文件偏移转换、反汇编、Go runtime 偏移解析 |
| `internal/uprobe/` | 函数匹配、探针描述、手动规则解析、自动规则推导 |
| `internal/bpf/` | eBPF C 程序、bpf2go 产物、map 初始化、uprobe 挂载和队列轮询 |
| `internal/eventmanager/` | 参数配对、按 PID/goid 维护状态、调用栈闭合、逐条打印和聚合统计 |

## 4. 从命令行到探针列表

### 4.1 CLI 配置

入口为 `cmd/ftrace/main.go`，Cobra 命令定义在 `cmd/root.go`。与设计直接相关的参数如下：

| 参数 | 含义 |
| --- | --- |
| `-u, --uprobe-wildcards` | 必填；选择需要挂载探针的函数，支持多次指定和通配符 |
| `-x, --exclude-vendor` | 默认开启；排除名字中含 `/vendor/` 的函数 |
| `-f, --fargs` | 显式指定函数入口参数抓取规则 |
| `-r, --frets` | 显式指定函数返回值抓取规则 |
| `-A, --fargs-auto` | 默认开启；自动推导入口参数规则 |
| `-R, --frets-auto` | 默认开启；自动推导返回值规则 |
| `--hide-unexported` | 默认关闭；打印自动抓取的结构体时隐藏未导出字段 |
| `-D, --drilldown` | 仅打印根函数名与指定值相同的闭合调用栈 |
| `-P, --trimprefix` | 去掉输出源码路径的公共前缀 |
| `-c, --aggregate` | 不逐条打印，改为聚合函数耗时和返回值；动态采样与有界内存保护在所有模式下均启用 |
| `--aggregate-interval` | 聚合结果的周期输出间隔，默认 `5s`；设为 0 时只在退出时输出 |
| `--memory-limit` | Go 堆目标，默认 `256` MiB；用于自适应采样和未闭合事件硬上限 |
| `--adaptive-sample` | 默认开启；按 Go 堆占用动态调整根调用采样率，并对未闭合事件、PID 数设上限。设为 `false` 时始终采集每个根调用（不降采样，也无用户态内存保护） |

显式出现 `--fargs` 时，入口参数的自动推导会整体关闭；显式出现 `--frets` 时，返回值自动推导会整体关闭。两类开关相互独立。

### 4.2 `attach` 与 `wanted` 是两个不同概念

这是理解当前实现最重要的区分。

- **attach 集合**：真正挂载入口和返回探针的函数集合。
- **wanted 集合**：可以把 goroutine 置为“正在跟踪”状态的触发函数集合。

`internal/uprobe/parser.go` 的规则是：

```text
attach = 匹配 (-u 模式 ∪ --fargs/--frets 中的函数名) 的全部函数

如果没有 --fargs/--frets 函数名：
    wanted = attach
否则：
    wanted = attach 中匹配 --fargs/--frets 函数名的函数
```

例如：

```bash
ftrace -u 'main.*' ./app \
  --fargs 'main.Handle(req=(%ax):u64)'
```

此时 `main.*` 中可解析的函数都会 attach，但只有 `main.Handle` 是 wanted 触发点。`main.Handle` 命中后，同一 goroutine 后续执行到的其他已挂载 `main.*` 函数才会被记录。

`-u` 当前仍是必填项，即使 `--fargs` 或 `--frets` 已经给出了函数名也不能省略。

### 4.3 符号匹配

`uprobe.Parse` 遍历 ELF `.symtab`：

1. 只保留 `STT_FUNC`；
2. 使用项目的 wildcard 规则匹配函数名；
3. 按配置排除 `/vendor/`；
4. 形成去生成探针的函数列表。

因此目标文件必须保留 `.symtab`。被完全内联且没有独立函数符号/函数体的代码无法按普通函数挂载。

## 5. ELF、DWARF 与探针地址

uprobe 注册需要的是指令相对 ELF 文件开头的偏移，而不是进程虚拟地址。对于 `.text` 中的符号：

\[
\text{fileOffset} = \text{symbol.Value} - \text{textSection.Addr} + \text{textSection.Offset}
\]

`elf.FuncOffset` 实现了这项转换。

### 5.1 函数入口

入口探针描述同时保存：

- `Address`：函数入口虚拟地址，用于 `should_trace_rip` 和入口参数规则；
- `AbsOffset`：入口相对 ELF 文件开头的偏移，用于注册 uprobe；
- `RelOffset = 0`：用于用户态反查探针。

### 5.2 函数返回点

`elf.FuncRawInstructions` 优先用 DWARF 的 `lowpc/highpc` 确定函数范围，失败时回退到符号表推断；`elf.FuncRetOffsets` 使用 `x86asm.Decode` 反汇编并收集全部 `RET`。

每个返回点保存：

- `AbsOffset`：`RET` 相对 ELF 文件开头的偏移；
- `RelOffset`：`RET` 相对函数入口的偏移；
- `Address`：`RET` 的虚拟地址，用于返回值抓取规则。

如果函数体中没有解析到 `RET`，当前实现会跳过该函数的入口和返回探针。常见原因包括无返回函数、尾调用或无法可靠确定/解码函数范围。

### 5.3 为什么保留虚拟地址和文件偏移两套值

两者用途不同：

- `link.UprobeOptions.Offset` 需要文件偏移；
- uprobe 触发时 `ctx->ip` 是虚拟地址；
- eBPF map 以触发时可直接取得的虚拟地址作为 key；
- 用户态通过虚拟地址反查符号、函数内偏移和源码行号。

当前仅支持非 PIE 二进制，因此静态虚拟地址可以直接与运行时 IP 对应，不需要额外处理加载基址重定位。

## 6. 参数与返回值抓取

### 6.1 手动规则

手动规则采用如下形式：

```text
functionName(name=(address-expression):type, ...)
```

例如：

```text
main.(*Student).String(
    s.name=(*+0(%ax)):c64,
    s.name.len=(+8(%ax)):s64,
    s.age=(+16(%ax)):s64
)
```

规则从一个寄存器开始，再执行最多若干步偏移或解引用：

- `(%ax)`：直接读取寄存器 AX；
- `(+16(%ax))`：读取地址 `AX + 16` 处的数据；
- `(*+0(%ax))`：先从 `AX + 0` 读取一个指针，再从该指针指向的地址取值。

支持的输出类型为：

- `s8/s16/s32/s64`：有符号整数；
- `u8/u16/u32/u64`：无符号整数；
- `c8/c16/c32/c64/c128/c256/c512`：固定字节数的字符数据。

规则还有两个容易忽略的实现约束：内存偏移写入 BPF 结构时使用 `int16`，应限制在 `[-32768, 32767]`；寄存器读取路径一次只复制 8 字节，因此 `c128/c256/c512` 必须使用内存寻址，不能用 `(%reg)` 直接读取完整值。

完整语法见 [`FetchArgRule.zh_CN.md`](./FetchArgRule.zh_CN.md) 和 [`FetchArgExamples.zh_CN.md`](./FetchArgExamples.zh_CN.md)。

### 6.2 自动规则

自动推导分成两步：

1. `elf.FunctionVariables` 从目标函数 DWARF DIE 的直接子节点中读取形参和返回值类型；返回值通过 `DW_AT_variable_parameter` 或 Go 的 `~rN` 命名识别。
2. `internal/uprobe/auto.go` 按 Go amd64 寄存器 ABI 为每个参数分配 ABI word，编译面向 BPF 的通用 `FetchArg`。用户态保存 `dwarf.Type`，只解码探针时打进 event 的快照，不对堆/栈做事后 `process_vm_readv`。

接口的具体类型启动时未知。通用规则只拷 type/data 和一块 `*data` 前缀；用户态第一次见到某个运行时 `_type` 地址后，把相对 data 指针的展开规则写入 `type_recipes_map`，之后同类型在探针当下追加拷贝。

这里没有求值 DWARF location expression。不覆盖 ABI0、栈传参/栈返回、浮点寄存器，以及寄存器耗尽后的完整栈回退。对这些函数应关闭自动推导并编写经过验证的手动规则。

| Go 类型 | 抓取方式 |
| --- | --- |
| 整数、布尔、枚举、普通指针 | 一个整数寄存器 word，用户态按 `dwarf.Type` 解码 |
| `string` | data/len 两个 ABI word，探针时拷 backing array 最多 64 字节 |
| slice | `.data/.len/.cap`，探针时拷 backing array 最多 64 字节；`[]byte` 按字符串显示 |
| interface | 通用：type/data/`*data` 前缀；见到具体 `_type` 后再学相对规则 |
| struct | 按 ABI 抓 word，渲染时按字段偏移还原 |
| `*struct` | 指针 + 对象前缀 + 静态可确定的嵌套捕获；`NilCheck` |

nil `error`（itab 为 0）的 type 规则也必须 `NilCheck`，否则会读地址 8 并显示 `<unavailable>`。

完整原理、接口在线特化、以及废弃过的方案见 [`AutoFetch.zh_CN.md`](./AutoFetch.zh_CN.md)。

### 6.3 规则在 BPF map 中的表示

每个 probe point 对应一组 `arg_rules`，写入 `arg_rules_map`：

- 入口参数以函数入口虚拟地址为 key；
- 返回值以每条 `RET` 的虚拟地址为 key；
- BPF 结构最多容纳 8 个叶子值；
- 每个值的 Go 侧 `Rules` 最多为 8 条，其中第一条是基址寄存器，因此后续最多 7 步偏移/解引用；
- 单个抓取结果最多保存 64 字节。

手动规则超过上限时会在加载阶段报错。自动展开会为 string、slice、interface 这类复合值预留完整叶子容量，空间不足时整项跳过，避免只生成半个值；达到叶子或寄存器上限后会告警并保留此前已经成功生成的值。

通用 `arg_rules_map` 在加载时写入。接口动态类型的相对规则写入 `type_recipes_map`，用户态在第一次观测到某个 `_type` 后更新，不需要重新 attach。

### 6.4 内核态取值

`fetch_args` 根据规则分两类执行：

- `ARG_RULE_REG`：从 `pt_regs` 直接读取指定寄存器；
- `ARG_RULE_MEMORY`：以寄存器值为基址，逐步执行“加偏移”或“解引用”，最后用 `bpf_probe_read_user` 读取目标内存。

每个叶子形成一条 `arg_data`，包含数据、nil 标记和读取失败标记。所有叶子与事件头一起在 per-CPU `event_buffer` 中组装为完整 `event`，随后整体压入 `event_queue`，避免事件与参数在独立队列中发生错配。Linux 5.4 验证器不允许对 map 值做变址（`e->args[e->arg_count]`），helper 调用后还会丢掉偏移下界，因此接口 recipe 先写到栈上，再用常量下标拷回 `args[0..7]`。

## 7. 获取 goroutine ID

线程 ID 不能代表 goroutine：goroutine 可能在不同 OS 线程上继续执行。为按 goroutine 重建调用关系，eBPF 处理程序需要读取当前 `runtime.g.goid`。

在 Linux x86-64 上，读取路径是：

```text
bpf_get_current_task()
  -> task_struct.thread.fsbase       获取 TLS 基址
  -> *(TLS + CONFIG.g_offset)        获取 runtime.g 指针
  -> *(g + CONFIG.goid_offset)       获取 goid
```

两个偏移由用户态在加载前确定：

- `goid_offset`：从 DWARF 中找到 `runtime.g` 的 `goid` 成员偏移；
- `g_offset`：纯 Go 内部链接程序通常为 `-8`；外部链接时结合 `runtime.tlsg` 和 `PT_TLS` 计算。

随后 `bpf.Load` 通过 `spec.RewriteConstants` 把它们写入 eBPF 的只读 `CONFIG`。

进程 ID 优先取 `bpf_get_ns_current_pid_tgid(ftrace 的 pid ns)` 返回的 TGID，这样用户态 `process_vm_readv` / `/proc/<pid>` 能在 WSL2（systemd 嵌套 pid namespace）或容器里解析到同一个进程。该 helper 是 Linux 5.8 加入的；加载时用 `features.HaveProgramHelper` 探测，缺失则在 `LoadAndAssign` 之前把 `call 120` 改成 `r0 = -1`，让 C 里已有的 `bpf_get_current_pid_tgid() >> 32` 回退生效（仅改 CONFIG 不够：5.4 验证器仍会验证 unknown helper）。嵌套 pid ns 只用于告警（看 `/proc/self/status` 的 `NSpid`）。因为 goid 只在单个进程内有意义，所有跟踪状态都必须使用 `(pid, goid)` 而不是单独使用 goid。WSL2 上接口返回值显示 `<unavailable>` 的排查过程见 [BPF 事件 PID 与 pid namespace](./BpfPidNamespace.zh_CN.md)。

## 8. eBPF 程序与状态机

内核程序在 `internal/bpf/ftrace.c`，由 `bpf2go` 编译和生成 Go binding。三个入口分别位于：

- `uprobe/ent`：已挂载函数入口；
- `uprobe/ret`：已挂载函数的 `RET`；
- `uprobe/goroutine_exit`：`runtime.goexit1` 入口。

### 8.1 BPF maps

| map | 类型 | key/value | 用途 |
| --- | --- | --- | --- |
| `should_trace_rip` | HASH | 入口 IP → bool | 用户态写入的静态 wanted 触发点集合 |
| `should_trace_ret` | HASH | wanted RET IP → 函数入口 IP | 标识 aggregate 样本的根调用返回边界 |
| `should_trace_goid` | HASH | `(pid, goid)` → `trace_state` | 内核态动态维护的已采样根调用状态 |
| `sample_config_map` | ARRAY | 固定 key 0 → 采样分母 | 用户态运行中动态写入，`N` 表示约采 `1/N` 个 wanted 根调用 |
| `runtime_stats_map` | PERCPU_ARRAY | 固定 key 0 → 运行统计 | 统计 wanted/admitted/sampled-out roots、状态插入失败，以及成功/失败投递的事件数和中止样本数 |
| `arg_rules_map` | HASH | probe IP → `arg_rules` | 入口参数及返回值抓取规则 |
| `event_buffer` | PERCPU_ARRAY | 固定 key 0 → 完整 `event` | 每 CPU 的事件组装暂存区，避免占用过多 BPF 栈 |
| `event_queue` | QUEUE | 完整 `event` | 原子传递事件头及最多 8 个参数叶子 |

`should_trace_rip`、`should_trace_ret` 在启动阶段由用户态写入，运行时只读；`should_trace_goid` 由 eBPF 在运行时增删；`sample_config_map` 则由用户态闭环控制器动态更新。`runtime_stats_map` 使用 per-CPU value，避免超高频路径上的共享计数竞争，打印时由用户态求和。

### 8.2 入口事件

所有模式（含普通逐条打印）均按**完整 wanted 根调用**采样，避免逐事件采样破坏调用栈配对：

```text
(pid, goid) 已处于某个采样根调用中？
  是：继续采集其嵌套入口
  否：当前 IP 不是 wanted → 忽略
      当前 IP 是 wanted → 按 sample_config_map 的 1/N 概率准入
                         → 准入后记录 root_ip/root_depth 并标记 TRACE_START
```

采样决策只发生在根入口；一旦准入，该根调用内所有已挂载入口/返回都会整体采集，避免逐事件采样破坏调用栈配对。准入时的分母会固定保存到 `trace_state` 并随事件传递，即使运行中动态调节采样率，该完整样本仍使用同一个估计权重。递归进入同一 wanted 函数时用 `root_depth` 延迟样本结束。

通过过滤后，入口事件记录：

- `pid`、`goid`；
- 当前入口 IP；
- `bpf_ktime_get_ns()` 时间戳；
- 当前/调用者栈基址；
- 从栈顶返回地址读取的 `caller_ip`；
- 可选入口参数。

最后事件进入 `event_queue`。

### 8.3 返回事件

`ret` 只检查 `(pid, goid)` 是否已处于跟踪状态。通过后记录当前 `RET` IP、时间戳和可选返回值，然后写入 `event_queue`。自适应模式下若 `should_trace_ret` 表明这是采样根函数的最终返回，则事件带 `TRACE_END`，投递后删除该 `(pid, goid)` 的跟踪状态。

入口和返回都先把参数叶子写入同一个完整 `event`，再一次性投递。因此 queue 过载只会拒绝完整事件，不会把某个事件与另一个事件的参数错误配对。

### 8.4 goroutine 退出

`runtime.goexit1` 先检查 `(pid, goid)` 是否处于跟踪状态；只有被跟踪的 goroutine 才会删除内核状态并投递 `GOROUTINE_EXIT`。用户态收到后释放残留调用栈和预算。这样未被采样的 goroutine 退出不会占用 `event_queue`；若退出通知因 queue 满而丢失，用户态的未闭合事件硬上限仍能阻止状态无限增长。

### 8.5 跟踪生命周期示例

以下是普通模式示例。假设 attach 了 `main.A/main.B/main.C`，只有 `main.A` 是 wanted：

```text
G 调用 main.B       未触发，忽略
G 调用 main.A       命中 wanted，标记 G；记录 A
G 调用 main.B       G 已被标记；记录 B
A/B 全部返回        用户态栈深回到 0，打印本次闭合调用栈
G 稍后调用 main.C   G 仍被标记；记录并打印 C
G 执行 goexit1      清除 G 的内核态和用户态状态
```

因此，“调用栈闭合并打印”和“停止跟踪 goroutine”是两件不同的事。

## 9. 加载与挂载

`internal/bpf/bpf.go` 的加载过程为：

1. `LoadGoftrace()` 读取由 bpf2go 内嵌的 eBPF ELF 对象；
2. 检查是否存在任意参数规则，设置 `CONFIG.fetch_args`；
3. 通过 `RewriteConstants` 注入 `g_offset/goid_offset`；
4. `LoadAndAssign` 让内核 verifier 校验并加载程序与 maps；
5. 写入 `arg_rules_map`；
6. 写入 `should_trace_rip`；
7. `link.OpenExecutable` 打开目标文件；
8. 对每个描述项调用 `Executable.Uprobe`，使用 `AbsOffset` 绑定相应 eBPF 程序。

挂载项包括函数入口、每条 `RET` 以及一个 `runtime.goexit1`。退出时保存的 link/map closer 会被关闭，从而解除探针。

在机制层面，uprobe 由内核管理目标指令处的断点与异常处理。目标线程执行到探针位置时陷入内核，执行关联的 eBPF 程序，再恢复原程序；业务进程不需要主动配合。

## 10. 用户态事件处理

### 10.1 单事件队列

`PollEvents` 只启动一个 goroutine 轮询 `event_queue`。每条 queue 元素已经包含事件头和最多 8 个参数叶子，用户态不需要第二条参数队列或按 goid 分发参数。

用户态结构按 PID 分层：

```text
EventManager
  pids[pid] -> pidState
                 goEvents[goid]       已采集事件序列
                 goEventStack[goid]   当前已观测嵌套深度
                 agg[funcname]        聚合统计
  suppressed[(pid,goid)]              因硬预算整段抑制的样本
```

这种结构与内核 `should_trace_goid` 的复合 key 一起，保证同一二进制同时运行的不同 PID 中相同 goid 不会串扰；它不包含进程启动时间，极端 PID 复用场景仍需视为已知边界。

### 10.2 参数配对

每个事件先通过 IP 反查 `Uprobe`，校验 `event.arg_count` 与该位置的抓取规则数量一致，再直接渲染事件内嵌的 `arg_data[]`。内核在 per-CPU `event_buffer` 中组装完成后只 push 一次，因此参数与事件具有原子传输关系；读取失败由每个叶子的 `read_error` 独立标记为 `<unavailable>`。

### 10.3 调用栈闭合

对每个 `(pid, goid)`，入口事件使 `goEventStack` 加一，返回事件使其减一。当深度回到 0 且已经积累事件时，表示当前最外层的**已观测调用**闭合：

- 普通模式：立即打印这段事件序列并清空；
- 聚合模式：按 LIFO 配对入口/返回，累计函数级统计后清空。

这里维护的是“已挂载函数形成的观测栈”，不等价于 Go runtime 的完整物理调用栈。

实现还会丢弃没有对应入口的孤立返回事件，并消费其参数，尽量保持两条流对齐；对疑似栈扩缩导致的重复入口事件也有去重处理。

### 10.4 符号化与耗时

逐条输出时：

- 入口 IP 解析为被调用函数；
- `caller_ip` 解析为调用者和调用源码行；
- 返回 IP 解析为函数内 `RET` 偏移和源码行；
- 时间戳使用开机时间加 `bpf_ktime_get_ns()` 转成墙上时间；
- 入口时间戳按栈保存，返回时用 LIFO 配对计算耗时。

符号名和偏移来自 `.symtab`，源码位置来自 DWARF line table。当前 `LineInfoForPc` 使用简单的全局排序和二分查找，未完整处理精确命中、首条记录及 `EndSequence` 边界；边界地址可能得到前一条源码记录，极端情况下还存在越界风险。因此源码行号应作为辅助定位信息，而不是严格的审计结果。

`--drilldown` 只影响闭合后是否打印，不改变探针集合和内核采集范围。

### 10.5 聚合模式

`--aggregate` 不逐条打印调用栈，而是在每个 PID 内按函数名累计：

- 调用次数；
- `<=1us` 到 `<=10s` 以及 `>10s` 的固定延迟直方图；
- 返回值字符串的重频候选，展示频次最高的前 10 项。

返回值使用固定 64 候选的加权 Space-Saving 算法；候选表未满时观测计数精确，发生替换后 observed 显示候选驻留期间实际看到的下界 `>=count`，estimated 显示加权值及误差上界。它避免高基数返回值让 map 无限增长。

摘要同时输出 `observed` 和 `estimated`。`observed` 是实际收到且完整闭合的样本值；`estimated` 把每个观测调用按其根样本准入分母 `N` 做逆概率加权。queue 丢失通常呈突发相关性，而且完整调用树的存活概率不能由单个全局事件丢失率可靠还原，因此 `dropped_events` 只单独报告，不强行乘进函数估计；失效栈、内存保护丢弃和 PID LRU 淘汰同样不具备可靠的逐函数归因。estimated 是量级估算，不是无损审计结果。摘要顶部会分别展示主动 `sampled out` 根调用数、queue `dropped` 事件数、异常中止根调用数和用户态丢弃样本数。

所有模式（`--adaptive-sample=false` 时除外）每秒读取 Go `HeapAlloc`，以 `--memory-limit` 为目标，通过迟滞控制动态调整内核采样分母：达到 70%/85%/100% 时目标分母分别为 `8/64/1048576`，相同水位不会继续累乘；回落到 45% 后每秒减半直至恢复全采。采样率改变会写入 `sample_config_map`，后续 wanted 根调用立即使用新概率；已经准入的调用仍完整采完。

动态采样是降低输入速率的闭环，不单独充当硬上限。每个内核采样根调用最多产生 4096 个事件，超限时发送 `TRACE_ABORT` 并回收状态，用于兜底 panic 跨帧、异常展开和超长调用。用户态另外把预算的四分之一按每事件 2048 字节的保守估算换算成未闭合事件上限；触顶时整段抑制该 `(pid, goid)` 直到 `TRACE_END`，若结束事件丢失则下一次 `TRACE_START` 会重置旧抑制。只有收到 `TRACE_END` 且入口/返回函数身份栈完全匹配的样本才会聚合（aggregate 模式）。PID 状态最多保留 64 个进程，超过后 LRU 淘汰会丢弃该 PID 的未闭合栈/历史汇总并在输出中报告；抑制表最多 10000 项，返回值候选固定 64 项。这些边界共同保证所有模式下 go-ftrace 的可增长容器有界；非 aggregate 模式退出时同样输出采样与丢失统计。这里限制的是 go-ftrace 自身数据结构，不是操作系统级 RSS/cgroup 硬限制。

统计默认每 5 秒输出一次累计快照，并在退出时输出最终结果。周期输出不清零。收到退出信号后先解除 links 停止生产，再排空 `event_queue`，最后读取累计丢失计数并打印，确保最终 observed 与运行统计覆盖同一批事件。`--aggregate` 与 `--drilldown` 同时使用时，当前聚合路径不应用 drilldown 过滤。

## 11. 完整时序

```mermaid
sequenceDiagram
    participant CLI as Tracer
    participant ELF as ELF/DWARF
    participant BPF as BPF Loader
    participant K as eBPF/uprobe
    participant EM as EventManager

    CLI->>ELF: 匹配函数、解析入口和 RET
    CLI->>ELF: 解析 g_offset/goid_offset
    ELF-->>CLI: Uprobe 列表与运行时偏移
    CLI->>BPF: Load(uprobes, offsets)
    BPF->>K: 加载程序和 maps
    BPF->>K: 写 arg_rules_map/should_trace_rip
    BPF->>K: attach 入口、RET、goexit1

    loop 目标程序运行
        K->>K: 读取 pid/goid 并判断跟踪状态
        K->>K: 可选抓取参数/返回值并组装完整事件
        K-->>EM: event_queue（event+args）
        EM->>EM: 按 pid/goid 配对、更新观测栈
        alt 深度归零且普通模式
            EM->>EM: 符号化并打印调用链
        else 深度归零且聚合模式
            EM->>EM: 累计耗时和返回值分布
        end
    end

    CLI->>BPF: Ctrl+C / context cancel
    EM->>EM: 打印未闭合数据或最终聚合
    BPF->>K: 关闭 links，解除探针
```

## 12. 正确性依赖与实现限制

### 12.1 支持范围

当前 CLI 明确限定：

- Linux，内核具备项目使用的 eBPF、uprobe、`BPF_MAP_TYPE_QUEUE` 及相关 helper 能力；`bpf_get_ns_current_pid_tgid` 在加载时探测，不可用则回退到 `bpf_get_current_pid_tgid`。已在 Linux 5.4 与 6.6 上验证同一套二进制；更早内核未测，能否运行以加载时的 helper/验证器为准（发行版常 backport，不能只看 `uname`）；
- x86-64 little-endian；
- Go ELF 可执行文件；
- 非 PIE；
- 保留 `.symtab`；
- 保留 DWARF 调试信息，至少需要 `.(z)debug_info`，源码行和自动参数推导还依赖相关 DWARF sections。

此外，`task_struct.thread.fsbase` 的偏移由仓库内预生成的 `internal/bpf/headers/vmlinux.h` 在编译期通过 `offsetof` 固化，当前代码没有使用 CO-RE 字段重定位。目标内核的数据结构布局必须与该头文件兼容，否则可能读到错误的 TLS、`runtime.g` 和 goid。仅满足“支持 eBPF 和 uprobe”并不足以保证可运行。

实现中的寄存器表、TLS 读取、`pt_regs` 字段、x86 指令解码和小端数据解释也与上述限制绑定，不能只修改编译目标就扩展到其他架构。

### 12.2 自动抓取的 ABI 边界

自动抓取只实现了 Go amd64 整数寄存器序列，没有检查目标函数实际使用的 ABI，也没有处理 ABI0、栈传参/栈返回、浮点/复数寄存器。寄存器耗尽时只会标记规则不完整；对于跨越容量边界的聚合值，当前展开过程也不会按 Go ABI 做“整体回退到栈”，已有字段规则可能不再对应真实位置。因此自动抓取适合常见、较小的参数列表，复杂签名必须结合目标 Go 版本和反汇编结果验证。

### 12.3 内联与编译优化

只有拥有独立符号和可定位机器码范围的函数才能挂载。编译器内联可能让期望的函数没有独立入口，或让 DWARF 结构更复杂。排查问题时可使用 `-gcflags='all=-N -l'` 构建测试二进制，但这会改变程序性能特征，不应把关闭优化后的耗时直接等同于生产构建。

### 12.4 固定容量与事件丢失

当前主要上限为：

- `arg_rules_map`：100 个 probe point；
- `should_trace_rip`：10000 个触发入口；
- `should_trace_goid`：10000 个正在跟踪的 goroutine/root call；
- `should_trace_ret`：10000 个 wanted 返回点；
- `event_queue`：10000 条完整事件；
- 每个 probe 最多 8 个抓取值；每个值包含 1 条寄存器基址规则和最多 7 步后续寻址；数据最多 64 字节；
- aggregate：最多 64 个 PID、每函数 64 个返回值重频候选、10000 个整段抑制状态，未闭合事件数由内存目标计算。

queue 使用 `BPF_ANY` push。满载时保留已入队事件、拒绝新事件，并在 per-CPU `runtime_stats_map.dropped_events` 中精确累计失败次数；相比 `BPF_EXIST` 静默覆盖旧元素，这让事件损失可观测。高频调用或用户态处理阻塞仍可能形成孤立事件或未闭合观测栈。参数已内嵌，不会发生跨事件错配或等待参数卡死；aggregate 要求 `TRACE_END` 和入口/返回函数身份栈同时完整，否则整段丢弃，并受未闭合事件硬上限保护。go-ftrace 是观测工具，不提供无损审计语义。

### 12.5 运行开销

开销主要来自：

- 每个已挂载位置触发 uprobe 的陷入/恢复；
- eBPF map 查询、用户内存读取和 queue 写入；
- 用户态符号化与终端输出。

探针数量和命中频率比单个处理程序的代码量更影响整体成本。大范围 `-u`、自动抓取复杂结构体以及逐条输出都应谨慎用于高流量生产进程。高频场景优先使用 `--aggregate`，并缩小函数匹配范围。

### 12.6 多进程语义

uprobe 挂在可执行文件 inode/offset 上，并未限定某个 PID；只要进程映射并执行该文件，对应位置就可能触发。当前实现会按 PID 隔离事件和统计，但 CLI 没有 `--pid` 过滤选项。因此“多进程隔离”表示不会串栈，不表示只观测某个指定实例。

### 12.7 权限与资源限制

加载 eBPF 和创建 uprobe 需要相应权限。项目安装方式会将程序安装到 `/usr/sbin/ftrace` 并设置所需权限；具体安全考虑和部署方式见 [`../INSTALLATION.zh_CN.md`](../INSTALLATION.zh_CN.md)。

程序把 `RLIMIT_MEMLOCK` 设为无限制，并提高 `RLIMIT_NOFILE` 以容纳大量 probe link。

## 13. 关键设计不变量

修改实现时应保持以下约束：

1. **地址一致性**：注册探针使用 ELF 文件偏移；BPF map 和事件匹配使用运行时虚拟地址。
2. **返回点一致性**：每条 `RET` 的 `Address`、`AbsOffset` 和 `RelOffset` 必须指向同一条指令。
3. **规则顺序一致性**：内核推送参数的顺序必须与 `Uprobe.FetchArgs` 顺序一致。
4. **结构布局一致性**：`ftrace.c` 的 `event/arg_rule/arg_rules/arg_data` 与 bpf2go 生成的 Go 类型必须同步；修改 C 结构后必须重新生成 `.o` 和 Go binding。
5. **枚举一致性**：C 的 `ENTPOINT/RETPOINT/GOROUTINE_EXIT` 与 Go 的 event location 常量保持一致；`ARG_RULE_REG/ARG_RULE_MEMORY` 与 `ArgLocation` 保持一致。
6. **进程隔离**：内核状态和用户态状态都必须按 PID + goid 隔离，不能退化为只用 goid。
7. **生命周期回收**：`runtime.goexit1` 删除内核跟踪标记，并尽力通过退出事件通知用户态释放 goroutine 状态；设计不能假定通知一定送达。
8. **有界执行**：eBPF 循环、规则数、数据长度和 map 容量必须保持 verifier 可接受的静态上限。

## 14. 构建与验证

`internal/bpf/gen.go` 使用 bpf2go 从 `internal/bpf/ftrace.c` 同时生成：

- `internal/bpf/goftrace_bpfel_x86.o`：eBPF ELF 对象；
- `internal/bpf/goftrace_bpfel_x86.go`：Go binding，并内嵌上述对象。

修改 C 程序、共享结构或 BPF map 后，需要重新执行生成流程。`Makefile` 已把 C 源码、生成器和 headers 设置为生成产物的依赖。

当前自动参数推导的测试位于 `internal/uprobe/auto_test.go`，会临时编译测试 Go 程序并验证：

- 标量、字符串、切片和结构体指针入参；
- 单/多返回值和 interface；
- 指针返回值 nil 元数据；
- 显式规则优先级。

涉及事件状态机或多进程隔离的改动，还应通过实际 Linux uprobe/eBPF 集成场景验证，因为单元测试无法覆盖内核 attach、队列丢失和真实调度时序。

## 15. 源码索引

| 主题 | 主要实现 |
| --- | --- |
| CLI 与资源限制 | `cmd/root.go` |
| 启动、加载、轮询主循环 | `cmd/tracer.go` |
| ELF/DWARF 初始化 | `elf/elf.go` |
| 符号与文件偏移 | `elf/symtab.go` |
| 函数范围与指令读取 | `elf/text.go` |
| x86-64 `RET` 扫描 | `elf/asm.go` |
| `runtime.g` 与源码行 | `elf/dwarf.go` |
| TLS 中 `g` 的偏移 | `elf/tls.go` |
| 函数参数/返回值 DIE | `elf/dwarf_args.go` |
| attach/wanted 与 probe 生成 | `internal/uprobe/parser.go` |
| 手动抓取规则 | `internal/uprobe/fetcharg.go` |
| 自动抓取规则 | `internal/uprobe/auto.go` |
| eBPF 内核程序与 maps | `internal/bpf/ftrace.c` |
| BPF 加载、map 写入、attach、poll | `internal/bpf/bpf.go` |
| PID/goid 状态与参数分发 | `internal/eventmanager/eventmanager.go` |
| 事件状态机与聚合 | `internal/eventmanager/handler.go` |
| 调用栈和聚合输出 | `internal/eventmanager/print.go` |

## 16. 延伸阅读

- [原始设计博客：观测 Go 函数调用：go-ftrace 设计实现](https://www.hitzhangjie.pro/blog/2023-12-12-%E8%A7%82%E6%B5%8Bgo%E5%87%BD%E6%95%B0%E8%B0%83%E7%94%A8go-ftrace%E8%AE%BE%E8%AE%A1%E5%AE%9E%E7%8E%B0/)
- [参数抓取规则](./FetchArgRule.zh_CN.md)
- [参数抓取示例](./FetchArgExamples.zh_CN.md)
- [常见问题](./QA.zh_CN.md)
- [中文 README](../README.zh_CN.md)
