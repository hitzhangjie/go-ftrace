# 自适应采样与内存背压设计说明

本文说明 go-ftrace 的自适应采样机制、entry/ret 的配对语义，以及统计输出中各类"丢弃"指标的含义，便于后续阅读与排查。

## 1. 背景

被追踪的 uprobe 可能被极高频命中，导致事件生产速度远大于用户态消费（打印/聚合）速度。若不加约束，事件会在进程内不断积压，内存持续上涨，最终 OOM kill，甚至影响同机其他进程。

go-ftrace 通过两层机制控制：

- **生产端限速**：按完整根调用做概率采样（自适应），从源头减少事件量；
- **消费端有界**：未闭合事件数、进程状态数、返回值重频候选均设上限，保证用户态数据结构有界。

该机制对**所有模式**生效（aggregate 聚合与普通逐条打印），`--memory-limit` 为内存目标。若用户不希望动态降采样，可用 `--adaptive-sample=false` 关闭：此时 BPF 侧不做采样决策，用户态也不启用抑制/预算等内存保护，始终采集每个根调用（高频场景下事件仍可能因队列溢出而丢失）。

## 2. 采样决策只在根 entry 发生

采样决策（`should_sample`）**只发生一次**：在 `ent` 探针中，当该 `(pid, goid)` 尚无跟踪状态（`should_trace_goid` 无记录）且当前 IP 是 wanted 入口时，才按 `sample_config_map` 中的分母做 1/N 概率准入。

```c
// internal/bpf/ftrace.c, ent
struct trace_state *state = bpf_map_lookup_elem(&should_trace_goid, &gkey);
if (!state) {
    if (!wanted) return 0;
    if (CONFIG.adaptive_sampling) {
        denominator = current_sample_denominator();
        if (!should_sample(denominator)) { ... return 0; }  // 跳过
    }
    // 准入：写入 trace_state，事件带 TRACE_START
}
```

准入后为 `(pid, goid)` 创建 `trace_state`，**此后该 goroutine 上所有已挂探针的 entry/return 无条件全采**，不再逐事件做采样决策，直到：

- 根函数最终返回（`TRACE_END`，删除状态）；
- 单个根调用事件数超过 4096（`TRACE_ABORT`，删除状态）；
- goroutine 退出（`GOROUTINE_EXIT`，删除状态）。

`ret` 探针只检查 `should_trace_goid` 是否存在，存在即采样，不做二次决策：

```c
// internal/bpf/ftrace.c, ret
struct trace_state *state = bpf_map_lookup_elem(&should_trace_goid, &gkey);
if (!state) return 0;
```

因此**决策层面 entry/ret 天然配对**：不存在"entry 单独采了、ret 单独没采"的错配。采样率变化只影响后续新根调用，已准入的样本保持同一 `sample_denominator` 权重采完。

## 3. 事件层面仍可能 entry/ret 不配对

决策虽配对，但事件送达层面存在三种不配对来源：

### 3.1 队列溢出丢事件（最常见）

`event_queue` 容量 10000，生产 > 消费时满则丢。BPF 决定采了、也 `push_event` 了，但事件没送达用户态。缺 ret 的样本在用户态表现为"栈不闭合"，残留到下一次 `TRACE_START` 重置或 goroutine 退出才清理，计入 `samples discarded`（incomplete）。

### 3.2 TRACE_ABORT 作废后续事件

某个根调用事件数超 4096（panic 跨帧、异常展开、超长调用等）时，事件带 `TRACE_ABORT` 并删除跟踪状态。此后该 goroutine 的 ret 因无状态而不再采集。这是有意为之：样本已作废，后续事件没有意义。

### 3.3 采样窗口边界产生孤儿 ret

```text
时间线（同一 goroutine）：
  B.entry   ← 状态不存在，B 非 wanted → 忽略（未采）
  根 A.entry ← wanted，采样命中 → 创建跟踪状态
  B.ret     ← 状态已存在 → 采样（采了！）
```

`B.entry` 发生在采样窗口开始前，`B.ret` 落在窗口内，产生**孤儿 ret**。用户态对孤儿 ret 直接丢弃，不污染后续配对：

```go
// internal/eventmanager/handler.go, Add
length := len(s.goEvents[event.Goid])
if length == 0 {
    if event.Location != eventLocationEntry {
        // Orphaned return: dropping it cannot desynchronize subsequent events.
        return false
    }
    ...
}
```

## 4. 统计指标口径

退出（或 Ctrl+C）时输出以下指标，三者发生在不同阶段：

| 指标 | 阶段 | 含义 |
| --- | --- | --- |
| `skipped` | 样本开始前（BPF） | 根 entry 采样决策主动跳过，`should_sample` 未命中 |
| `dropped (queue full)` | 采集后、进用户态前（BPF） | 事件已组装，`event_queue` 满被挤掉 |
| `samples discarded` | 进用户态后（用户态） | 收到但残缺/异常/超预算，无法构成有效样本 |

聚合模式下，每个 `--aggregate-interval` 周期（默认 3s）的 summary 会额外输出一行 **`window:`** 前缀的本窗口增量统计（距上次 summary 的 `detected/skipped/queued/dropped` 及比例），用于观察自适应采样随时间的实际效果——例如采样分母调高后，`dropped` 是否逐窗口下降、`skipped` 是否上升。该行反映的是窗口内的即时速率，不受累计值稀释。

`samples discarded` 细分三个原因：

| 原因 | 触发点 |
| --- | --- |
| incomplete | 队列丢事件导致的残留栈重置（`resetStaleSample`）、aggregate 下栈身份不匹配、退出时残留栈 |
| aborted | BPF 单根调用事件数超 4096 发 `TRACE_ABORT` |
| over memory budget | 用户态未闭合事件数超过预算（`pendingEvents >= maxPendingEvents`），整段抑制该 `(pid, goid)` |

> 说明：孤儿 ret（3.3）在用户态被静默丢弃，已包含在 `samples discarded` 中，不再单独计数。

## 5. 背压闭环

1. 每秒读取 Go `HeapAlloc`，以 `--memory-limit` 为目标，通过迟滞控制调整采样分母：达到 70%/85%/100% 目标时分母为 `8/64/1048576`，回落到 45% 以下逐步恢复全采。
2. 每秒读取 BPF `runtime_stats_map`，用 `emitted/dropped` 的窗口增量计算近期队列丢包率；丢包率超过 2% 噪声阈值时，**基于当前分母缩放**计算跳升目标 `ceil(den * 1.5 / (1-lossRate))`（在实测饱和点之上保留 1.5 倍余量，且至少前进 1 步），与堆压力目标**取更激进者**写入 `sample_config_map`，后续根入口立即生效；已准入样本保持原权重采完。
3. 用户态按 `memoryLimit / 4 / 2048` 估算未闭合事件上限，触顶时抑制该 `(pid, goid)` 直到 `TRACE_END` 或下次 `TRACE_START` 重置。
4. 进程状态最多保留 64 个，超过后 LRU 淘汰；抑制表上限 10000；返回值重频候选固定 64 项。

**综合机制**：堆水位与丢包率两路压力输出同一个采样分母，取其中更激进的作为当前目标，再走同一套迟滞逻辑：

- **跳升**（目标高于当前分母）：一步跳到位；
- **恢复**（目标低于当前分母）：**必须连续 5 个低丢包窗口（`recoverStableWindows`）才减半一次**，防止"一低丢包就立即恢复"导致的震荡；
- **不安全下限**（`unsafeDen`）：在某个分母上观察到过丢包就将其记为不安全，恢复时**不得回到该值及以下**——否则 `den=2` 时丢包跳升到 `4`，`4` 稳定后又立刻试探 `2`，循环震荡。只有连续 15 个低丢包窗口（`unlockStableWindows`）才相信消费端有余量，把不安全下限减半放开，允许再次试探更低采样率。

因此：

- 事件积压导致堆上涨时，内存路径主导降采样（原有行为不变）；
- 堆不高但 `event_queue` 满丢事件时，丢包路径接管，一步跳到安全分母并记住不安全区，稳定期后才逐步试探恢复；
- 两者都缓解后分母逐步回落到全采（试探失败则立即跳回安全区，不再持续震荡）。

这闭合了"队列泄压掩盖生产-消费失衡"的边界：即使事件未进用户态堆，丢包率本身也会触发降采样，且不会围绕消费端饱和点来回震荡。
