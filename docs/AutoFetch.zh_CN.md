# Auto 模式原理：从 DWARF 类型到探针时快照

`--fargs` / `--frets` 是手动模式：用户写出 fetchrule，BPF 在 uprobe 命中当下拷那些字节，用户态按叶子打印。

`--fargs-auto` / `--frets-auto` 是自动模式：启动时用 DWARF 里的 `dwarf.Type`（相当于目标程序的 `reflect.Type`）**编译出 FetchArg**；BPF 在探针命中时立刻执行这套规则，把字节打进 event；用户态从 `event_queue` 取出后，只用 event 里的快照和同一棵 `dwarf.Type` 按结构显示。

tracing 和 debugging 的差别贯穿全文：被观测程序不会停住。能信任的堆/栈字节，只有探针那一拍拷下来的。用户态不再对参数值做 `process_vm_readv`。

本文面向两类读者：

- 想理解 auto 为什么能自动显示参数和返回值的用户；
- 维护 `elf/`、`internal/uprobe/auto.go`、`internal/uprobe/value.go`、`internal/uprobe/recipe.go` 和 BPF 取值链路的开发者。

手动规则语法见 [FetchArgRule.zh_CN.md](./FetchArgRule.zh_CN.md)，示例见 [FetchArgExamples.zh_CN.md](./FetchArgExamples.zh_CN.md)。本文第 13 节记录了做过、后来废弃的尝试。

## 1. 先用 Go 反射理解 DWARF

### 1.1 类型描述和值是两件事

Go 反射里有两个容易分开的概念：

- `reflect.Type` 描述类型：是结构体还是指针、字段名、字段类型、偏移；
- `reflect.Value` 是某一次运行中的具体值，可以按 `reflect.Type` 解释这块数据。

DWARF 可以先近似看成编译器和链接器写进可执行文件的一套静态反射元数据。它描述函数签名、参数类型、结构体字段的大小和字节偏移。例如：

```go
type MeshError struct {
    Code   MeshErrorCode
    Detail error
}

func send(ok bool) *MeshError
```

在 DWARF 里可以理解为：

```text
函数 send
├── 形参 ok     ───────→ bool
└── 返回值 ~r0  ───────→ 指针类型 *MeshError
                          └── MeshError
                              ├── Code:   int,   offset=0
                              └── Detail: error/iface, offset=8
```

go-ftrace 不自己实现 DWARF 解码器。标准库 `debug/dwarf` 已经把类型 DIE 变成 `dwarf.Type`（`IntType`、`PtrType`、`StructType` 等）。`dwarf.Data.Type(offset)` 很像“根据类型 ID 取得只读的类型描述”。Auto 把这棵树保存在 `Value.Type` 上，渲染时直接遍历它。

### 1.2 为什么不构造 `reflect.Type`

理论上可以遍历 DWARF，再用 `reflect.StructOf` 在 ftrace 进程里造一棵相似的反射类型。没有必要：ftrace 不创建目标程序的真实对象，也不调用它的方法；命名类型、未导出字段、方法集和运行时类型身份也很难完整还原。`dwarf.Type` 已经带齐种类、字段名、大小、偏移。

### 1.3 DWARF 只解决了一半问题

知道 `Code` 在 `MeshError+0` 是 `int64`，并不等于已经知道这次调用的值。还需要：

```text
1. 类型：返回值是 *MeshError
2. 位置：RET 时指针在哪个寄存器
3. 取值：探针触发时读寄存器，再读目标内存
4. 解码：按 little-endian 和字段偏移显示
```

当前 auto **不求值 `DW_AT_location`**。位置按 Go amd64 寄存器 ABI 自行推导。所以它不是通用调试器，而是「DWARF 类型 + 已知 Go ABI + eBPF 探针时取值 + 用户态解码快照」。

## 2. 当前总体数据流

```text
启动（静态）
  dwarf.Type 编译通用 FetchArg
  写入 arg_rules_map[入口 IP 或 RET IP]

探针命中（唯一允许读堆/栈的时刻）
  按通用规则拷 ABI word 和已知内存块
  若叶子标了 iface_data：用已拷到的 type 地址查 type_recipes_map
      命中 → 相对 data 指针再拷若干叶子
      未命中 → 只留下通用前缀
  整条 event 进入 event_queue

用户态
  用 dwarf.Type 解释快照并打印
  若第一次见到某个运行时类型：CompileTypeRecipe，写入 type_recipes_map
  同类型的后续命中才能在探针当下拷全
```

| 环节 | 主要代码 |
| --- | --- |
| CLI 开关与优先级 | `cmd/root.go` |
| 选择函数、构造探针 | `internal/uprobe/parser.go` |
| 提取函数 DWARF 变量 | `elf/dwarf_args.go` |
| 静态类型 → FetchArg | `internal/uprobe/auto.go` |
| 动态类型 → 相对规则 | `internal/uprobe/recipe.go` |
| 快照解码与打印 | `internal/uprobe/value.go` |
| 规则写入 BPF map | `internal/bpf/bpf.go` |
| 内核态执行 | `internal/bpf/ftrace.c` |
| 事件配对、学习新类型 | `internal/eventmanager/handler.go` |

## 3. 如何从 DWARF 找到函数参数

`elf.New` 打开目标 ELF，加载普通或压缩 DWARF，并注册 DWARF 5 的 `.debug_addr`、`.debug_line_str` 等 section。被 `-s -w` 剥离调试信息的二进制无法做 auto。

`NonInlinedSubprogramDIEs` 只保留能挂 uprobe 的真实函数：有名字、`lowpc`/`highpc`，且 `.symtab` 中同名符号地址与 `lowpc` 相同。内联实例会被丢掉。

`FunctionVariables` 只看函数 DIE 的直接子节点里的 `DW_TAG_formal_parameter`，读取 `DW_AT_name`、`DW_AT_type`、`DW_AT_variable_parameter`。带 `DW_AT_variable_parameter` 或名称以 `~r` 开头的视为返回值，显示时 `~r0` 改成 `ret0`。含 `defer` 的函数可能出现重复的同名返回值 DIE，按名称去重，避免多消费一个返回寄存器。

中间结果故意不保存“变量在哪”：

```go
type Variable struct {
    Name  string
    IsRet bool
    Type  dwarf.Type
}
```

## 4. 如何推导参数位于哪个寄存器

入口和返回值各自从下列整数寄存器重新数起：

```text
AX, BX, CX, DI, SI, R8, R9, R10, R11
```

每遇到一个 ABI 需要直接传递的 machine word，就消费下一个寄存器。例如 `func F(a int64, s string, nums []int)`：

```text
a          -> AX
s.data     -> BX
s.len      -> CX
nums.data  -> DI
nums.len   -> SI
nums.cap   -> R8
```

不读 DWARF location expression。优点是实现简单，并与手动 fetchrule 共用 BPF 执行器。代价是不覆盖 ABI0、栈传参/栈返回、浮点寄存器、寄存器耗尽后的完整栈回退。

## 5. 手动 fetchrule 与 Auto 的分工

两条路径共用 BPF 执行器，用户态解释方式不同。

手动模式每条规则就是一个打印叶子：

```text
--frets 'main.send(Code=(+0(%ax)):s64, Detail.itab=(+8(%ax)):u64, Detail.data=(+16(%ax)):u64)'
```

Auto 不为结构体字段生成「给打印用的」独立规则。`func send() *MeshError` 的通用计划是：

```text
ret0=(%ax):u64                              // 指针
ret0.obj=(+0(%ax)):c512                     // *MeshError 前缀（含 Code、Detail 头）
ret0.Detail.type=(+8(*+0(+8(%ax)))):u64     // itab+8 → 具体 _type
ret0.Detail.data=(+8(+8(%ax))):u64          // Detail.data，并标成 iface_data
ret0.Detail.value=(*+8(+8(%ax))):c512       // *data 前缀
```

`Value.Type` 是 `*main.MeshError`。用户态按类型树解释快照：`Code` 在前缀 offset 0；`Detail` 是前缀里的接口。字符串 backing array 不在通用计划里，要等见过该动态类型、recipe 装上之后，由 BPF 按相对规则追加拷贝。

不变量：

> 通用 `FetchArg` 的数量与顺序必须与 `Value.leafCount()` 以及 event 里**前面那一段**叶子一致。BPF 可能在后面再追加 type recipe 叶子；那些叶子按 `_type` 地址解释，不占用静态 `FetchArg` 槽位。

## 6. 各类 Go 类型的静态捕获计划

| Go 类型 | 静态 FetchArg |
| --- | --- |
| 整数、布尔、枚举 | 一个寄存器 word |
| 普通指针 / map / chan / func | 一个寄存器，只显示地址或 nil |
| `string` | data、len 两个 ABI word，再探针时拷 backing array 最多 64 字节 |
| slice | data / len / cap，只显示头部 |
| struct 值 | 按 ABI 消费若干寄存器 word，渲染时按字段偏移散射成内存镜像 |
| `*struct` | 指针 word + 对象前缀（`NilCheck`）+ 类型里能确定的嵌套捕获（如内部 string 的 backing array、内部 interface 的 type/data/`*data`） |
| interface | type（非空接口从 itab+8 取 `_type`，带 `NilCheck`）、data、`*data` 前缀。具体类型的深层字段见第 7 节 |

`*T` 为 0 时 BPF 不解引用，显示 `nil`。结构体内再出现的普通指针只显示地址，避免无限递归。runtime 内部的 `hmap` / `hchan` 当不透明指针。

顶层 `error` 为 nil（itab 和 data 都是 0）时，跟 `itab+8` 的规则必须 `NilCheck`：否则会去读地址 8，整项变成 `<unavailable>`。用户态只要 type word 为 0 就显示 `nil`。这是 `mayFail` 返回 `nil` 时的路径。

## 7. 接口：静态通用规则 + 在线特化

### 7.1 为什么静态规则展不开动态值

`error` 在 DWARF 里永远是 `{itab, data}`。这次可能是 `*errors.errorString`，下次可能是 `*fmt.wrapError`。启动时不知道，写不出 `Detail.s.data=...` 这种字段规则。

### 7.2 运行时类型身份

Go 里每个类型在模块中只有一个 `abi.Type` / `_type`，地址唯一。DWARF `DW_AT_go_runtime_type` 是相对 `runtime.types` 的偏移，非 PIE 下可与探针里看到的地址直接对应。`elf.RuntimeType` 做的就是这张表。

itab 是「接口类型 × 具体类型」一对一 intern 的：

- 所有 `error` 里的 `*errors.errorString` 共用同一个 itab；
- 同一具体类型若还出现在 `fmt.Stringer` 或空接口里，itab 指针不同；
- 但 `itab.Type`（itab 第二个指针 word）都指向**同一个** `_type`。

因此 recipe 的 key 是具体类型地址，不是 itab。规则必须相对 **data 指针**，不能写成 `(%bx)` 或 `(+16(%ax))`：`mayFail` 的 data 在 `BX`，`send.Detail` 的 data 在 `*(AX+16)`，具体类型却是同一个。

DirectIface（data 是值本身还是指向值的指针）是类型的属性。当前用 DWARF 近似：指针/func 为 direct；多 word 的 string/slice/struct 为 indirect。不必事后读 runtime type header。

### 7.3 第一次见到某种动态类型

通用规则已经把 `_type` 地址和 data 指针拷进 event。用户态 `RuntimeType` 只读 ELF，得到 `*errors.errorString`。`CompileTypeRecipe` 按该类型生成相对 data 的拷贝（对 `*errorString` 通常是再跟一层字符串 backing array），写入 `type_recipes_map[type_addr]`。

这一次事件没有那些额外叶子，只能解前缀（对象头、长度），backing array 可能是 `<unavailable>`。这是发现样本。

### 7.4 同类型的后续命中

BPF 在通用规则之后，对标了 `iface_data` 的叶子：取出 type 地址，查 `type_recipes_map`，以 data 指针为基址执行相对规则，把额外叶子追加到 `event.args[]`（总数仍不超过 8）。用户态用同一份 recipe 把这些叶子按地址放进快照，再按 `dwarf.Type` 渲染。

空接口不会在启动时爆炸：表里只有真正出现过的类型，上限 256。动态值里再套接口，当前 recipe 不再展开（避免 BPF 递归查表）。

## 8. 抓取规则如何在 BPF 中执行

`arg_rules_map`：入口用函数入口虚拟地址做 key，返回值用每条 `RET` 的虚拟地址做 key。同一个函数可能有多份内容相同、key 不同的返回规则。

通用叶子：从 `pt_regs` 读寄存器，或从基址寄存器出发做加偏移/解引用，最后 `bpf_probe_read_user`。`nil_check` 在基址为 0 时不解引用，标 `is_nil`。任一步失败标 `read_error`。

`type_recipes_map`：key 为 `_type` 地址，value 为最多 4 条相对 data 指针的规则。用户态在运行中 `Update`，不需要重启探针。

事件头和最多 8 个叶子在 per-CPU `event_buffer` 里组装完成后只 push 一次，避免事件与参数错配。

返回值挂在函数内每条 `RET` 上，而不是通用 `uretprobe`，这样返回寄存器里的值还在。

## 9. 用户态如何重建

`event.arg_count` 可以 **大于** `len(FetchArgs)`：多出来的是 type recipe 叶子。小于则丢弃参数显示。

手动模式没有 `Value`，按 `FetchArg` 逐条 `SprintValue`。Auto 调用 `RenderValuesRecipes`：通用叶子拼快照，recipe 叶子按相对规则的目标地址补进快照，再 `renderDynamicValue`。快照里没有的地址显示 `<unavailable>`，不去读活进程。

```text
a=42
ok=true
name="alice"
nums=[]int(len=3, cap=8)
req=&main.Request{ID:7, Name:"alice"}
ret0=&main.MeshError{Code:500, Detail:&errors.errorString{s:"send failed"}}
ret0=nil
```

## 10. Auto 与手动规则的关系

```text
-A, --fargs-auto   默认开；自动推导入口参数
-R, --frets-auto   默认开；自动推导返回值
```

`fillAutoFetch`：某个函数、某个方向已有显式规则时不覆盖该方向。CLI 更强：命令行只要出现任意 `--fargs`，本次运行入口 auto 整体关闭；出现任意 `--frets`，返回 auto 整体关闭。两个方向互不影响。

## 11. 边界和失败方式

- 平台：Linux、x86-64、Go ELF、非 PIE、保留 `.symtab` 和 DWARF。建议 `-gcflags='all=-N -l'`。
- 不是完整 Go ABI：无 ABI0、栈传参/栈返回、XMM、完整栈回退。浮点不要依赖 auto。
- 类型覆盖：数组、复数、slice 元素、map/chan 内容、嵌套在动态值里的接口，不会完整重建。签名中间出现不支持类型时，后续参数的寄存器推导也可能错。
- 容量：每个 probe 最多 8 个叶子（含 recipe 追加）；每叶最多 8 步、64 字节；`arg_rules_map` 100 个 probe；`type_recipes_map` 256 种动态类型；偏移 `int16`。
- 失败是局部降级：找不到 DIE 就该函数没有 auto；BPF 读失败或快照没有那块地址就 `<unavailable>`；nil 接口显示 `nil`，不要把读地址 0 的失败当成业务值。

## 12. 完整示例

```go
func send(ok bool) *MeshError
func mayFail(code int) error
```

`send(false)` 返回 `&MeshError{Code:500, Detail: errors.New("send failed")}`：

1. 通用规则拷指针、24 字节对象前缀、Detail 的 `_type` 和 data、`*data` 前缀（即 `errorString` 头）。
2. 第一次：用户态认出 `*errors.errorString`，学会 recipe，本次字符串可能仍 `<unavailable>`。
3. 之后：BPF 相对 data 再拷 backing array，打印 `Detail:&errors.errorString{s:"send failed"}`。

`send(true)` 返回 nil 指针：对象前缀 `NilCheck`，显示 `ret0=nil`。

`mayFail(42)` 返回 nil `error`：itab 为 0，type 规则 `NilCheck`，显示 `ret0=nil`，不会去读 `itab+8`。

## 13. 做过的尝试，以及为什么废弃

正确实现是上面各节。下面这些路径都真实走过，留下的教训比代码更值钱。

### 13.1 按字段扁平化成 FetchArg，接口另走 Type 树

最早 auto 把 `*MeshError` 展成：

```text
ret0.Code=(+0(%ax)):s64
ret0.Detail.type=...
ret0.Detail.data=...
ret0.Detail.value=...
```

`Code` 是一条命名 fetchrule，BPF 在 RET 点直接读。`Detail` 是接口，用户态再用 `dwarf.Type` 解释动态类型。表面上都能打印结构体，其实是两套逻辑。WSL 上曾出现 `Code:500` 正常、`Detail:*errors.errorString(<unavailable>)`：标量走探针时拷贝，动态值的 backing array 走事后读内存。废弃原因：同一结构体里的字段不该有两种时间语义；也解释不清「为什么 code 有值、字符串没有」。

### 13.2 用户态当调试器：`process_vm_readv` 跟着 `dwarf.Type` 走

为了统一成 Type 遍历，一度只在探针时抓 ABI word（再加一块前缀），嵌套指针留到用户态 `process_vm_readv`。渲染路径是单一的 `renderDynamicValue`，看起来很干净。

tracing 里目标不会停。event 在 queue 里时，栈可能已复用，堆可能被 GC 或 span 复用。事后读到的既可能失败，也可能是**别人的内存**。PID namespace 再叠一层：BPF `bpf_get_current_pid_tgid()` 报 init ns 的 TGID，用户态按当前 ns 查 PID，WSL2 systemd 下会 `ESRCH`。见 [BPF 事件 PID 与 pid namespace](./BpfPidNamespace.zh_CN.md)。

废弃原因：调试器假设不成立。`dwarf.Type` 可以当快照解码器，不能当活指针 walker。用户态不再为参数值读堆/栈。

### 13.3 启动时对接口做类型无关的 `**data` 启发式

既然动态类型未知，就在启动时无脑多跟一层：拷 `*data` 再拷 `**data`。对 `*errors.errorString` 碰巧就是对象头 + 字符串内容。

这不是按类型展开。动态值若是 `{code int; msg string}`，第一层指针并不是字符串。`int` 的 direct iface 会把 500 当地址去读。废弃原因：启发式不能冒充类型系统；正确做法是见到真实 `_type` 再编译相对规则。

### 13.4 启动时为接口的每一种可能实现预生成规则

若要在**第一次命中**就按真实类型拷全，只能预存所有实现的展开规则。`error` 的实现可能很多，空接口几乎是二进制里所有类型；动态值里再套接口还要递归。表会爆，BPF 也做不到任意深的查表展开。

在线特化是它的收敛版：不预存全集，只为**观测到的** `_type` 写相对规则。代价是每种具体类型的第一次样本不完整。这是 tracing 里可接受的发现成本，不是再去做事后读。

### 13.5 用 itab 地址当 recipe key

itab 随「接口类型 × 具体类型」变化，`_type` 不随接口变化。若 key 用 itab，`error` 和 `fmt.Stringer` 里的同一 `*errors.errorString` 会学两套相同规则。相对 data 的规则只依赖具体类型，key 用 `_type` 地址即可。

## 14. 开发者维护指南

修改 auto 时检查：

1. 通用 `FetchArgs` 数量不超过 `MaxFetchArgs`；recipe 追加后 event 总叶子仍 ≤ 8。
2. string / slice / interface / `*T` 必须原子预留，不能生成半个值。
3. `Value.leafCount()` 之和等于通用 `FetchArgs` 数量；recipe 叶子不算进这个数。
4. `IfaceData` 只标在接口的 `.data` 叶子上，不要标到 string 的 `.data`。
5. 非空接口的 type 规则必须 `NilCheck`，nil `error` 不能读地址 8。
6. recipe 相对 data 指针，key 为 `_type` 地址。
7. 修改 `struct event`、`arg_rule`、`type_recipe` 或 map 后必须重新 `go generate ./internal/bpf`。

测试：

- `internal/uprobe/auto_test.go`：静态计划、`NilCheck`、叶子上限、iface 槽位标记；
- `internal/uprobe/recipe_test.go`：`*errorString` 相对规则、int 无额外拷贝；
- `internal/uprobe/value_test.go`：快照渲染、nil 接口、recipe 补齐字符串；
- `elf/dwarf_test.go`：`RuntimeType(*errors.errorString)`；
- `internal/eventmanager/handler_test.go`：arg_count 与叶子一致性。

## 15. 总结

```text
手动：用户写 fetchrule，探针时拷，按叶子打印

Auto 静态部分：dwarf.Type 编译 FetchArg，探针时拷，按类型树解码快照

Auto 接口动态部分：通用规则只保证头和前缀；
  见到 _type 后再学相对规则，下次探针时拷全
```

DWARF 不会直接给出运行时值。能打印出来的每一个堆/栈字节，都应该能回答：它是不是探针那一拍拷下来的。
