# go-ftrace 设计实现总览（Big Picture）

> 本文面向贡献者与用户，用一张「全景图」讲清楚 go-ftrace 的工作原理，
> 并重点标注那些**最容易遗忘、最容易混淆**的设计点。
>
> 更完整的实现细节（go 运行时数据结构、uprobe 挂载底层原理、DWARF 解析、
> 参数表达式求值等）请阅读详细设计文档：
> [观测 Go 函数调用：go-ftrace 设计实现](https://www.hitzhangjie.pro/blog/2023-12-12-%E8%A7%82%E6%B5%8Bgo%E5%87%BD%E6%95%B0%E8%B0%83%E7%94%A8go-ftrace%E8%AE%BE%E8%AE%A1%E5%AE%9E%E7%8E%B0/)

---

## 一句话概括

go-ftrace 用 eBPF `uprobe` 挂在 Go 二进制的函数入口/返回点，在**内核态**采集
「哪个 goroutine、在哪个函数、何时进出」，再由**用户态**重建调用栈，打印出带
源码位置、耗时与参数/返回值的调用链。

它最核心（也最反直觉）的设计是：**以 goroutine 为追踪粒度，而不是以函数为粒度**。

---

## 整体架构与数据流

```
                        用户态 (Go)                            内核态 (eBPF/C)
 ┌─────────────────────────────────────────────┐   ┌──────────────────────────────────┐
 │ cmd/tracer.go                               │   │                                  │
 │  1. 解析命令行 (-u / --fargs / --frets)      │   │  uprobe/ent      函数入口        │
 │  2. 解析 ELF + DWARF (elf/)                  │   │  uprobe/ret      函数返回        │
 │  3. uprobe.Parse() 生成挂载点 (internal/uprobe)│   │  uprobe/goroutine_exit 协程退出  │
 │  4. bpf.Load() 载入程序、填充 map             │   │                                  │
 │  5. bpf.Attach() 逐点 attach uprobe          │──▶│  get_goid(): task → TLS → g → goid│
 │  6. PollEvents()/PollArg() 轮询队列          │◀──│  fetch_args(): 按规则抓参          │
 │  7. EventManager 重建调用栈、打印            │   │  event_queue / arg_queue 推数据   │
 └─────────────────────────────────────────────┘   └──────────────────────────────────┘
```

关键数据流：内核态把事件 push 进 `event_queue`（参数进 `arg_queue`），用户态
`PollEvents`/`PollArg` 轮询取出，交给 `EventManager` 按 goroutine 归组、重建栈、
打印。

---

## 核心设计点（重点）

### 1. goroutine 级追踪模型 —— 整个工具的灵魂

**不是**「逐函数过滤」：不是每个被挂的函数都独立判断要不要记录。
而是：

```
某个 goroutine 执行到「触发点函数」的入口
        │
        ▼
把这个 goroutine 标记进 should_trace_goid
        │
        ▼
此后该 goroutine 调用的【所有】被挂载函数，入口/返回全被记录
        │
        ▼
goroutine 退出 (runtime.goexit1) 时，从 should_trace_goid 删除
```

这样一次命中触发点，就能还原出「触发点函数及其完整调用链」，避免了只挂单个函数
导致的调用链断裂问题。见 `internal/bpf/ftrace.c` 的 `ent` 探针。

### 2. attach vs wanted —— 最容易混淆的点 ⚠️

这是最容易搞错的地方。`internal/uprobe/parser.go` 里有两个**相互独立**的概念：

| 概念 | 由谁决定 | 含义 | 落点 |
|---|---|---|---|
| **attach** | `-u` 通配符 ∪ `--fargs/--frets` 函数名 | 哪些函数挂 uprobe | 每个函数的 `Uprobe`（ent + 多个 ret） |
| **wanted** | 见下方规则 | 哪些函数是「追踪触发点」 | 写入 `should_trace_rip` map |

`wanted` 的判定（`parser.go` 的 `wantedFuncs`）：

```
if 没有写 --fargs/--frets (FuncNames 为空):
    wanted = 所有被 -u 匹配到的函数
else:
    wanted = 只收敛到 --fargs/--frets 里点名的函数
            （-u 匹配到的其余函数只 attach，不作触发点）
```

**设计意图（易用性）**：`-u` 负责「广撒网」——用户往往不知道具体函数清单，
只想写个简单的通配规则；`--fargs/--frets` 负责「精准点名」——用户只想看某几个
函数的参数/返回值。一旦用户点名了（`FuncNames` 非空），触发点就以点名为准，
避免把 `-u` 匹配到的所有函数都误当作触发点。

> 注意：项目里**没有** `--func` 参数，只有 `-u/--uprobe-wildcards` 和
> `--fargs`/`--frets`。`FuncNames` 的来源是 `--fargs`/`--frets` 里写出的函数名
> （见 `cmd/tracer.go` 的 `Parse()`）。

### 3. 两张追踪表的维护方式截然不同 ⚠️

| map | 写入方 | 时机 | 语义 |
|---|---|---|---|
| `should_trace_rip` | **用户态** | 程序启动时一次性写入 | 静态「触发点」表，此后只读 |
| `should_trace_goid` | **内核态** | 运行期动态增删 | 动态「被追踪 goroutine」表 |

- `should_trace_rip`：由 `bpf.setWanted()` 以 `ShouldTraceRip.Update(addr, true, UpdateNoExist)`
  写入，key 是函数入口地址。
- `should_trace_goid`：`ent` 探针命中触发点时 `update`，`goroutine_exit` 探针 `delete`。

### 4. pid 维度隔离 —— 近期新增，容易被遗忘 ⚠️

goroutine ID（goid）**在每个进程内从 1 开始重新编号**。同一个二进制的多个进程实例，
可能都各自有一个 goid = 42 的 goroutine。若只用 goid 做 key，跨进程会串号。

因此：
- 内核态 `should_trace_goid` 的 key 是 `struct goid_key{ pid, _pad, goid }`
  （见 `ftrace.c`）。
- 用户态 `EventManager` 用 `map[pid]*pidState` 分层，每个进程维护独立的
  `goEvents`/`goEventStack`/`goArgs`（见 `eventmanager.go`）。

### 5. goid 的获取 —— 三段式读取 ⚠️

`get_goid()`（`ftrace.c`）不是直接读，而是三段跳：

```
bpf_get_current_task()
   → task_struct->thread_struct->fsbase    （TLS 基址，x86 用 FS 寄存器）
   → TLS + CONFIG.g_offset                  （得到 runtime.g 地址）
   → g + CONFIG.goid_offset                 （得到 goid）
```

其中 `g_offset`（`g` 在 TLS 里的偏移）和 `goid_offset`（goid 在 `g` 里的偏移）
由用户态 `elf.FindGOffset()` / `elf.FindGoidOffset()` 解析，通过
`spec.RewriteConstants` 注入内核态 `CONFIG`（`volatile const`，避免被优化进寄存器）。

### 6. 参数抓取：寄存器 + 内存寻址

- 用户在 `--fargs`/`--frets` 里写形如
  `main.(*Student).String(s.name=(*+0(%ax)):c64, ...)` 的表达式，
  或开启自动推导（默认，`--fargs-auto`/`--frets-auto`）从 DWARF 按 Go 的
  regabi 寄存器约定自动生成规则。
- 每条规则被编译成 `struct arg_rule`（`ftrace.c`），存入 `arg_rules_map`，
  key 是函数入口地址（返回值的 key 是 RET 指令地址）。
- 内核态 `fetch_args()` 按规则：
  - `ARG_RULE_REG`：直接从寄存器读值；
  - `ARG_RULE_MEMORY`：以寄存器值为基址，依次做「解引用 / 加偏移」，得到有效地址
    后 `bpf_probe_read_user` 读内存（含 `nil_check` 处理可空指针）。
- 结果 push 进 `arg_queue`，与事件按 goroutine 1:1 配对消费。

### 7. 事件流与调用栈重建

内核态用 `PERCPU_ARRAY`（`event_stack`/`arg_stack`）做临时缓冲避免栈溢出，写满后
push 进 `QUEUE`（`event_queue`/`arg_queue`）。用户态 `EventManager`：

1. `Handle()` 收到事件，`Add()` 按 `(pid, goid)` 归组。
2. `goEventStack` 记录当前 goroutine 的「嵌套深度」：ent 则 +1，ret 则 -1。
3. 当深度回到 0 且栈非空（`CloseStack()`），说明该 goroutine 最顶层的被追踪函数
   已返回，此时打印整条调用链，然后 `ClearStack()`。
4. 打印时用 DWARF 行号表/符号表把地址还原成源码位置（`print.go`）。

另有 `--drilldown`（只打印以某函数为根的调用链）和 `--cluster`（按函数聚合
延迟/返回值分布，避免高频刷屏）两种输出模式。

---

## 完整流程串联

```
启动:  Parse() 解析参数 → uprobe.Parse() 决定 attach/wanted
       → FindGoidOffset/FindGOffset 解析偏移
       → bpf.Load() 载入程序、RewriteConstants、填充 arg_rules_map + should_trace_rip
       → bpf.Attach() 逐点 attach uprobe

运行:  ent 命中触发点 → 标记 should_trace_goid → 该 goroutine 全量记录
       ent/ret 采集事件(时间戳/栈帧/ip) + 可选抓参 → push 队列

输出:  用户态轮询队列 → EventManager 按 (pid,goid) 重建栈
       → 深度归零时打印调用链(源码位置/耗时/参数) → 清空栈

退出:  Ctrl+C → detach → goroutine_exit 探针清理 should_trace_goid
       → 用户态回收 goArgs/goEvents，防止 map 无限增长
```

---

## 相关文档

- 详细设计与实现：<https://www.hitzhangjie.pro/blog/2023-12-12-%E8%A7%82%E6%B5%8Bgo%E5%87%BD%E6%95%B0%E8%B0%83%E7%94%A8go-ftrace%E8%AE%BE%E8%AE%A1%E5%AE%9E%E7%8E%B0/>
- 参数抓取规则：[`docs/FetchArgRule.md`](./FetchArgRule.md) / [`docs/FetchArgRule.zh_CN.md`](./FetchArgRule.zh_CN.md)
- 参数抓取示例：[`docs/FetchArgExamples.md`](./FetchArgExamples.md) / [`docs/FetchArgExamples.zh_CN.md`](./FetchArgExamples.zh_CN.md)
- 使用方式与示例：[`README.zh_CN.md`](../README.zh_CN.md)
