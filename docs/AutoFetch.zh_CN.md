# Auto 模式原理：从 DWARF 类型到运行时参数值

`--fargs` 和 `--frets` 的手动模式很好理解：用户明确告诉 go-ftrace 从哪个寄存器或内存地址读取多少字节。Auto 模式做的事情本质上并没有不同，它只是把“分析函数签名、理解 Go 类型、计算寄存器和内存位置、生成抓取规则”这部分工作自动化了。

本文面向两类读者：

- 只想理解 auto 模式为什么能够自动显示参数和返回值的用户；
- 希望维护 `elf/`、`internal/uprobe/auto.go`、`internal/uprobe/value.go` 和 BPF 取值链路的开发者。

完整的手动规则语法见 [FetchArgRule.zh_CN.md](./FetchArgRule.zh_CN.md)，常见手动规则示例见 [FetchArgExamples.zh_CN.md](./FetchArgExamples.zh_CN.md)。

## 1. 先用 Go 反射理解 DWARF

### 1.1 类型描述和值是两件事

Go 反射中有两个容易区分的概念：

- `reflect.Type` 描述类型本身，例如它是结构体还是指针、字段叫什么、字段类型是什么、字段偏移是多少；
- `reflect.Value` 表示某一次运行中的具体值，并允许按照 `reflect.Type` 解释这块数据。

DWARF 可以先近似理解为编译器和链接器写进可执行文件的一套“静态反射元数据”。它会描述：

- 有哪些函数；
- 函数有哪些形参和返回值；
- 参数引用了什么类型；
- 一个类型是整数、指针、结构体还是其他类型；
- 结构体有哪些字段，各字段的类型、大小和字节偏移是什么；
- 类型之间如何相互引用。

例如，源代码中的：

```go
type Request struct {
    ID   int64
    Name string
}

func Handle(req *Request) (int64, error)
```

在 DWARF 中可以抽象地理解为：

```text
函数 Handle
├── 形参 req  ───────→ 指针类型 *Request
│                       └── 目标类型 Request
│                           ├── ID:   int64,  offset=0
│                           └── Name: string, offset=8
├── 返回值 ~r0 ─────→ int64
└── 返回值 ~r1 ─────→ error/interface
```

真实 DWARF 使用 DIE（Debugging Information Entry）和属性来编码这些信息。go-ftrace 不需要自己实现完整的 DWARF 解码器；Go 标准库 `debug/dwarf` 已经可以把类型 DIE 转换为 `dwarf.Type`，例如：

- `*dwarf.IntType`；
- `*dwarf.UintType`；
- `*dwarf.BoolType`；
- `*dwarf.FloatType`；
- `*dwarf.PtrType`；
- `*dwarf.StructType`。

因此，`dwarf.Data.Type(offset)` 很像是“根据类型 ID 取得一个只读的类型描述”。`internal/uprobe/auto.go` 再把这棵 `dwarf.Type` 树翻译成 go-ftrace 自己的 `Value` 树。

### 1.2 为什么不直接构造 `reflect.Type`

理论上，可以遍历 DWARF 并借助 `reflect.StructOf` 等 API 构造一棵相似的反射类型。但 go-ftrace 并不需要在自己的进程里创建目标程序的真实 Go 对象，也不需要调用它的方法，因此这样做没有必要，而且也很难完整还原命名类型、未导出字段、方法集以及运行时内部类型身份。

当前实现使用 `Value` 作为一个更小、更适合可观测场景的“反射模型”：

```text
Value
├── Kind：整数、布尔、指针、字符串、切片、接口、结构体……
├── Name：参数名或字段名
├── Typ / Size：叶子值如何解码
└── Fields：复合类型的子字段
```

它只保留“如何把采集到的字节还原并展示出来”所需的信息。

### 1.3 DWARF 只解决了一半问题

知道 `req.ID` 是一个位于 `Request+0` 的 `int64`，并不等于已经知道本次调用中 `req.ID` 的值。要得到一个运行时值，至少需要四步：

```text
1. 类型：req 是 *Request，Request.ID 是 offset=0 的 int64
2. 位置：函数入口时 req 指针位于哪个寄存器或栈位置
3. 取值：在探针触发时读取寄存器，再读取目标进程内存
4. 解码：把 8 个字节按 little-endian int64 显示
```

DWARF 可以同时携带类型和位置描述，但当前 auto 模式只使用其中的函数签名与类型信息，**没有求值 `DW_AT_location` location expression**。值的位置由 go-ftrace 按当前支持的 Go amd64 寄存器 ABI 自行推导。

这一区别非常重要：auto 模式不是通用调试器，而是“DWARF 类型系统 + 已知 Go ABI + eBPF 运行时取值”的组合。

## 2. 总体数据流

Auto 模式从启动到打印经历两个阶段。

### 2.1 启动时：静态分析并生成规则

```text
命令行默认开启 -A/--fargs-auto 和 -R/--frets-auto
        │
        ▼
选择需要 attach 的 ELF 函数符号
        │
        ▼
查找函数对应的 DWARF subprogram DIE
        │
        ▼
读取形参、返回值名称及 dwarf.Type
        │
        ▼
按 Go amd64 regabi 递归展开类型
        │
        ├── 生成扁平 FetchArg 列表：交给 BPF 取值
        └── 生成结构化 Value 树：交给用户态还原和打印
        │
        ▼
以函数入口地址或每条 RET 地址为 key，写入 arg_rules_map
```

### 2.2 探针触发时：采集并还原值

```text
uprobe 在函数入口或 RET 指令触发
        │
        ▼
根据当前 IP 从 arg_rules_map 找到规则
        │
        ▼
从 pt_regs 读取寄存器，必要时追踪偏移和指针
        │
        ▼
每个叶子最多复制 64 字节到 event.args[]
        │
        ▼
完整 event 一次性进入 event_queue
        │
        ▼
用户态按 Value 树消费叶子数据并重新组合
        │
        ▼
打印成接近 Go/调试器风格的参数或返回值
```

代码入口对应关系如下：

| 环节 | 主要代码 |
| --- | --- |
| CLI 开关与优先级 | `cmd/root.go` |
| 参数传入解析器 | `cmd/tracer.go` |
| 选择函数和构造入口/返回探针 | `internal/uprobe/parser.go` |
| 提取函数 DWARF 变量 | `elf/dwarf_args.go` |
| DWARF 类型到抓取规则/值树 | `internal/uprobe/auto.go` |
| 结构化值还原和格式化 | `internal/uprobe/value.go` |
| 规则写入 BPF map | `internal/bpf/bpf.go` |
| 内核态执行规则 | `internal/bpf/ftrace.c` |
| 事件与值树配对 | `internal/eventmanager/handler.go` |

## 3. 如何从 DWARF 找到函数参数

### 3.1 加载 DWARF

`elf.New` 打开目标 ELF，并读取普通或压缩形式的 DWARF section。除传统 section 外，它还向 `debug/dwarf.Data` 注册 DWARF 5 使用的 `.debug_addr`、`.debug_line_str`、`.debug_str_offsets`、`.debug_rnglists`、`.debug_loclists` 等 section。

这也是为什么目标程序必须保留 DWARF 调试信息。被 `-s -w` 等方式剥离调试信息的二进制无法完成 auto 推导。

### 3.2 排除内联 DIE 和不可挂载函数

同一个源代码函数可能同时出现真实函数 DIE 和内联实例。`NonInlinedSubprogramDIEs` 只保留满足以下条件的 `DW_TAG_subprogram`：

1. 有函数名、`lowpc` 和 `highpc`；
2. `.symtab` 中存在同名函数；
3. 符号地址与 DWARF 的 `lowpc` 相同。

这样得到的是具有真实机器码入口、可以挂载 uprobe 的函数，而不是只存在于调用者内部的内联实例。

### 3.3 只读取函数 DIE 的直接子节点

`FunctionVariables` 只检查函数 DIE 的直接子节点，并只接受 `DW_TAG_formal_parameter`。它不会把以下内容误当成当前函数参数：

- 词法块中的局部变量；
- 内联子程序自己的参数；
- 更深层级的其他 DIE。

对每个参数 DIE，它读取：

- `DW_AT_name`：参数名；
- `DW_AT_type`：类型 DIE 的偏移；
- `DW_AT_variable_parameter`：是否为输出参数。

Go 编译器常把匿名返回值命名为 `~r0`、`~r1`。因此满足以下任一条件时会被识别为返回值：

- 带有 `DW_AT_variable_parameter`；
- 名称以 `~r` 开头。

显示时，`~r0` 会改成更直观的 `ret0`。此外，含 `defer` 的函数可能出现重复的同名返回值 DIE，代码会按名称去重，避免错误地多消费一个返回寄存器。

最后得到的中间结果很简单：

```go
type Variable struct {
    Name  string
    IsRet bool
    Type  dwarf.Type
}
```

这里故意没有保存“变量在哪”。位置在下一步按 ABI 计算。

## 4. 如何推导参数位于哪个寄存器

### 4.1 当前实现使用的寄存器序列

对入口参数和返回值，当前实现都分别从第一个寄存器开始，使用以下整数寄存器顺序：

```text
AX, BX, CX, DI, SI, R8, R9, R10, R11
```

入口参数和返回值各自创建独立的 `flatCtx`，所以两边都会从 `AX` 开始。

Auto 模式把一个 Go 类型递归展开成若干 machine word，每遇到一个需要由 ABI 直接传递的 word，就消费序列中的下一个寄存器。例如：

```go
func F(a int64, s string, nums []int)
```

当前推导结果是：

```text
a          -> AX
s.data     -> BX
s.len      -> CX
nums.data  -> DI
nums.len   -> SI
nums.cap   -> R8
```

这里的“展开”与反射遍历结构非常相似，只是遍历时还会同步推进 ABI 寄存器游标。

### 4.2 为什么不读取 DWARF location

DWARF location expression 可以描述变量在不同 PC 范围内位于寄存器、栈、常量或更复杂的位置。完整求值需要处理 location list、DWARF 栈机、架构寄存器编号、优化后变量分片等问题。

当前实现采用了更窄但更直接的方案：

- 从 DWARF 取得声明顺序和类型树；
- 从 Go amd64 regabi 规则推导位置；
- 直接生成 go-ftrace 已有的寄存器/内存抓取规则。

优点是实现简单，并且能与手动 `--fargs`/`--frets` 共用同一套 BPF 执行器。代价是它不能覆盖所有 ABI 情形，具体限制见后文。

## 5. 为什么同时需要 `FetchArg` 和 `Value`

一个复杂参数会被表示两次。

### 5.1 `FetchArg`：给 BPF 的扁平叶子列表

BPF 侧使用固定大小结构，无法接收任意深度的 Go 类型树。因此每个复杂值必须先展开为有序叶子：

```text
req=&Request{ID:7, Name:"alice"}
```

可以展开为：

```text
req.ID
req.Name.data
req.Name.len
```

每个 `FetchArg` 说明：

- 叶子名称；
- 从哪个寄存器开始；
- 后续执行哪些加偏移/解引用操作；
- 最终读取多少字节；
- 是否需要对基础指针做 nil 检查。

`argSpec` 是 auto 推导期间使用的内部中间表示，最终由 `fetchArg()` 转成与手动规则相同的 `FetchArg`。

### 5.2 `Value`：给用户态的结构化类型树

仅有扁平叶子无法知道它们原来属于一个字符串、切片还是结构体。因此 auto 模式同步建立 `Value` 树：

```text
Value(KindStructPtr, Name=req, StructName=main.Request)
├── Value(KindScalar, Name=req.ID, Typ=s64)
└── Value(KindString, Name=req.Name)
```

运行时，`RenderValues` 按树的叶子遍历顺序消费 `event.args[]`，重新组合为：

```text
req=&main.Request{ID:7, Name:"alice"}
```

最重要的不变量是：

> `Value` 树从左到右的叶子顺序，必须与 `FetchArg` 列表以及 BPF `event.args[]` 的顺序完全一致。

因此类型递归和扁平规则生成在同一个过程中完成，而不是各算一遍。

## 6. 各类 Go 类型如何展开

### 6.1 整数、布尔和枚举

标量消费一个整数寄存器，并根据 DWARF 字节大小生成解码类型：

| DWARF 类型 | 叶子类型 |
| --- | --- |
| `IntType` / `CharType` | `s8/s16/s32/s64` |
| `UintType` / `UcharType` | `u8/u16/u32/u64` |
| `BoolType` | `bool` |
| `EnumType` | 对应大小的有符号整数 |

用户态按 little-endian 解码并打印。

### 6.2 普通指针、map、chan、func

普通指针消费一个寄存器，只显示地址：

```text
p=0xc000012340
p=nil
```

map 和 chan 的 DWARF 底层可能指向 `runtime.hmap`、`runtime.hchan`。这些运行时内部结构不会被递归展开，而是作为不透明指针显示。函数值及其他未专门支持的指针形态也按地址处理。

### 6.3 `string`

Go 字符串头由两个 word 组成：

```text
string = { data pointer, len }
```

因此 auto 模式消费两个 ABI 寄存器，同时生成两个抓取叶子：

```text
name.data = 从 data pointer 指向的内存读取前 64 字节
name.len  = 读取长度 word
```

用户态使用真实长度截取内容，并用 Go 引号格式化。超过 64 字节时显示前缀并追加 `...`。

这里的 64 字节是 BPF `MAX_DATA_SIZE`，对应内部类型 `c512`，不是 64 bit。

### 6.4 slice

slice 头由三个 word 组成：

```text
slice = { data pointer, len, cap }
```

因此消费三个寄存器并生成 `.data/.len/.cap` 三个叶子。当前只显示头部信息，不遍历底层数组：

```text
nums=[]int(len=3, cap=8)
```

### 6.5 struct 值

普通结构体按字段顺序递归展开。字段本身可能继续是标量、字符串、slice、interface 或嵌套结构体。

这对应 Go 内部 ABI 对聚合类型的递归分解思路，但当前实现只维护整数寄存器游标，不实现 ABI 的完整寄存器分配和栈回退规则。因此只有在签名确实落入当前支持范围时，结果才可靠。

### 6.6 `*struct`

指向普通结构体的指针只消费一个 ABI 寄存器。之后各字段不再消费寄存器，而是以该指针为统一基址，使用 DWARF 的 `StructField.ByteOffset` 从目标进程内存读取。

例如：

```go
type Request struct {
    ID   int64  // offset 0
    Name string // offset 8
}

func Handle(req *Request)
```

假设 `req` 在 `AX`，概念上的规则是：

```text
req.ID        = memory[AX + 0]
req.Name.data = memory[memory[AX + 8] + 0 ... +64]
req.Name.len  = memory[AX + 16]
```

对于可能为 nil 的基础结构体指针，每个叶子规则都会携带 `NilCheck`。BPF 发现基础寄存器为 0 时不解引用，而是设置 `is_nil`；用户态再把多个扁平叶子合并成一个 `req=nil`。

为避免无限递归，结构体内再次出现的普通指针目前只显示地址，不继续展开。

### 6.7 interface：为什么最复杂

接口的静态类型只说明“这里是一个接口”，真正的动态类型只有运行时才知道。

空接口可抽象为：

```text
eface = { _type, data }
```

非空接口可抽象为：

```text
iface = { tab, data }
tab.Type 位于 itab 的第二个指针 word，即 tab + 8
```

Auto 模式为一个接口生成三个抓取叶子：

1. `.type`：具体 runtime type descriptor 的地址；
2. `.data`：接口 data word；
3. `.value`：从 data 指向的位置同步抓取最多 64 字节的具体值前缀。

注意：接口在 ABI 上仍只消费两个寄存器；第三个 `.value` 是从第二个寄存器指向的内存额外读取的数据，并不消费第三个 ABI 寄存器。

用户态还原动态类型的过程是：

```text
运行时 type descriptor 地址
        │
        ▼
runtime.types 符号地址 + DW_AT_go_runtime_type 偏移表
        │
        ▼
找到对应 dwarf.Type
        │
        ▼
检查 runtime type header 的 DirectIface 标志
        │
        ▼
判断 data word 是值本身、指针，还是指向间接存储
        │
        ▼
按动态 dwarf.Type 递归解释 .value 或继续读取目标进程内存
```

`elf.RuntimeType` 会扫描类型 DIE 上的 Go 扩展属性 `DW_AT_go_runtime_type`，建立：

```text
runtime type descriptor 绝对地址 -> dwarf.Type
```

由于当前只支持非 PIE 二进制，探针中观察到的地址可以直接与 `runtime.types + offset` 对应。

对接口动态值中的指针、字符串或嵌套接口，用户态可能通过 `process_vm_readv` 继续读取目标进程内存。递归深度最多为 8；单次需要追踪的指针目标大于 64 字节时通常显示 `<unavailable>`。这部分读取发生在事件到达用户态之后，目标内存可能已经变化或释放，因此同步保存在事件中的 64 字节前缀比事后读取更稳定，而更深层的指针数据仍然是尽力而为。

渲染器把 type descriptor 地址为 0 的接口识别为 `nil`。不过当前 BPF 仍会尝试从接口的 data word 抓取 `.value` 前缀；如果 nil 接口的 data 为 0，这次读取可能先被标记为失败，使整项显示为 `<unavailable>`。这是当前接口 nil 路径的实现边界，不应把 `<unavailable>` 当成一个非 nil 的业务值。

## 7. 抓取规则如何在 BPF 中执行

### 7.1 规则编码

`bpf.Load` 把每个 probe point 的 `FetchArgs` 写入 `arg_rules_map`：

- 函数入口规则以入口虚拟地址为 key；
- 返回值规则以每一条实际 `RET` 指令的虚拟地址为 key。

因此同一个函数可能只有一个入口规则，却有多份内容相同、key 不同的返回规则。

每个叶子规则包含：

- 基础寄存器编号；
- 最终读取大小；
- 若干 `offset`；
- 每一步是“只加偏移”还是“读取该地址保存的下一级指针”；
- 是否检查基础指针为 nil。

### 7.2 寄存器规则

如果值就是寄存器中的标量，BPF 从 `pt_regs` 直接复制寄存器内容：

```text
AX -> event.args[i].data
```

### 7.3 内存规则

内存规则先取得基础寄存器值，再逐步执行地址计算。例如：

```text
base = AX
base = *(base + 8)   // Dereference=true
base = base + 16     // Dereference=false
read memory[base]
```

中间解引用和最终读取都使用 `bpf_probe_read_user`。任一步失败都会设置 `read_error`，用户态显示 `<unavailable>`，而不会把清零的数据误当成真实值。

### 7.4 为什么在 RET 指令上取返回值

该项目不是只在函数退出后触发一个通用 `uretprobe`，而是解析函数内所有 `RET` 指令并逐个挂载。探针触发时，返回值仍位于函数返回 ABI 规定的寄存器中，因此返回 auto 可以使用与入口参数相同的寄存器序列推导方法。

### 7.5 事件与参数必须原子地排队

BPF 使用单槽 per-CPU `event_buffer` 组装一个完整事件。事件头和最多 8 个参数叶子位于同一个 `event` 中，最后整体压入 `event_queue`。

这样即使队列满导致丢事件，也只会丢掉一个完整事件，不会出现“事件队列和参数队列分别覆盖，导致 A 事件配上 B 参数”的永久错位。

## 8. 用户态如何重建复杂值

`eventmanager` 根据事件 IP 找到对应 `Uprobe`，并检查：

```text
event.arg_count == len(uprobe.FetchArgs)
```

然后把每个 BPF `arg_data` 转为 `LeafData`：

- `Data`：原始字节；
- `IsNil`：基础结构体指针为 nil；
- `Unavailable`：内存读取失败。

手动模式没有 `Value` 树，仍按每条 `FetchArg` 独立打印。Auto 模式存在 `Value` 树，因此调用 `RenderValues`，按树结构重新组合。

几个典型结果是：

```text
a=42
ok=true
name="alice"
nums=[]int(len=3, cap=8)
req=&main.Request{ID:7, Name:"alice"}
err=&main.MeshError{Code:500, Detail:"timeout"}
```

如果数据不足、BPF 读取失败、运行时类型无法解析或事后读取进程内存失败，会尽量在局部显示 `<unavailable>`，而不是放弃整条调用事件。

## 9. Auto 与手动规则的关系

两个开关默认都为 true：

```text
-A, --fargs-auto   自动推导入口参数
-R, --frets-auto   自动推导返回值
```

可以独立关闭：

```bash
sudo ftrace -u 'main.Handle' --fargs-auto=false ./app
sudo ftrace -u 'main.Handle' --frets-auto=false ./app
```

内部 API `fillAutoFetch` 的策略是：某个函数、某个方向已经有显式规则时，不覆盖该方向的规则。

CLI 还有一层更强的全局策略：

- 命令行只要显式出现任意 `--fargs`，本次运行的入口 auto 整体关闭；
- 命令行只要显式出现任意 `--frets`，本次运行的返回 auto 整体关闭；
- 两个方向互不影响。

例如，下面的命令不只是让 `main.F` 使用手动入口规则，而是关闭本次运行所有函数的入口 auto：

```bash
sudo ftrace -u 'main.*' ./app \
  --fargs 'main.F(a=(%ax):s64)'
```

返回 auto 仍保持开启，除非同时显式提供 `--frets`。

## 10. 当前实现的边界和失败方式

理解这些限制比理解正常路径更重要。

### 10.1 平台和二进制限制

当前整体项目要求：

- Linux；
- x86-64 little-endian；
- Go ELF 可执行文件；
- 非 PIE；
- 保留 `.symtab`；
- 保留 DWARF 调试信息。

建议使用 `-gcflags='all=-N -l'` 构建用于验证的目标程序，以减少优化和内联带来的干扰。实际生产二进制即使保留 DWARF，也可能因为函数内联、裁剪或 ABI 细节而无法自动提取。

### 10.2 不是完整的 Go ABI 实现

当前只维护一组 amd64 整数寄存器游标，没有实现：

- ABI0；
- 栈参数和栈返回值；
- 整数寄存器不足时的完整栈回退规则；
- 浮点寄存器分配；
- 复数参数；
- 混合整数/浮点聚合类型的完整分配算法。

尤其是结构体值靠近寄存器容量上限时，真实 Go ABI 可能撤销该聚合值的寄存器分配并把它整体放到栈上；当前递归展开没有为任意结构体实现同样的回滚，因此已经生成的部分字段也可能位置错误。相比之下，string、slice 和 interface 只是在 go-ftrace 的“8 个抓取叶子”容量上做了原子预留，这不能替代完整 ABI 回滚。

虽然代码能够从 DWARF 识别 `float32/float64` 并解码 `f32/f64`，但当前位置推导仍会错误地把它们分配到整数寄存器，而不是 XMM 寄存器，因此不要依赖浮点 auto 结果。

当签名超出支持范围时，应关闭对应 auto，并使用反汇编、Go ABI 信息和实际验证过的 `--fargs`/`--frets` 规则。

### 10.3 类型覆盖不完整

当前重点支持：

- 整数、无符号整数、布尔、枚举；
- 普通指针；
- string；
- slice 头；
- interface；
- struct；
- `*struct`。

数组、复数、函数值内部结构、map/chan 内容、slice 元素等不会被完整重建。遇到无法分类的类型时，该节点会被跳过，并在 debug 日志中记录。

这里的“跳过”不等同于完整 ABI 分配器中的“正确跨过该参数”：当前实现不会计算一个不支持的顶层类型本应占用多少寄存器或栈空间。因此，如果函数签名中间出现数组、复数等不支持类型，后续参数的寄存器位置也可能随之推导错误；不能只忽略那个字段后继续相信后面的结果。

### 10.4 固定容量限制

BPF 数据结构决定了以下上限：

- 每个 probe point 最多 8 个抓取叶子；
- 每个叶子最多 8 条规则，其中第一条是基础寄存器；
- 每个叶子最多保存 64 字节；
- `arg_rules_map` 当前最多保存 100 个 probe point 的规则；
- BPF 规则中的内存偏移是 `int16`。

Auto 展开接近 8 个叶子时会按复合类型所需叶子数做容量预留；string 需要 2 个、slice 和 interface 各需要 3 个，避免生成半个复合值。达到叶子或寄存器上限后会告警，并只保留已经成功生成的部分值。

字段偏移超过 `int16` 范围时当前没有专门的校验，写入 BPF 结构时会发生窄化；超大结构体需要特别警惕。

### 10.5 接口解析依赖 Go 运行时布局

接口动态类型解析依赖：

- `runtime.types`；
- Go DWARF 扩展属性 `DW_AT_go_runtime_type`；
- runtime type header 中 DirectIface 标志的已知字节位置；
- `itab.Type` 位于第二个指针 word；
- 读取目标进程内存的权限（`process_vm_readv` 使用的 PID 必须是 ftrace 所在 pid namespace 中的编号，见 [BPF 事件 PID 与 pid namespace](./BpfPidNamespace.zh_CN.md)）。

当前代码同时检查 Go 1.25 及以前的 Kind 标志位置和 Go 1.26 起的 TFlag 位置，但未来 Go 运行时布局变化仍可能需要同步适配。

### 10.6 失败通常是“局部降级”

Auto 模式尽量不因为某个函数无法推导而阻止整个跟踪启动：

- 找不到函数 DIE：该函数没有 auto 参数，debug 日志记录原因；
- 不支持某个字段类型：跳过该字段；
- 超过寄存器或叶子上限：告警并保留前面已经生成的值；
- BPF 内存读取失败：对应叶子显示 `<unavailable>`；
- 接口动态类型解析失败：显示未知类型或 `<unavailable>`。

排查 auto 结果时建议启用 `--debug`，并与手动规则、反汇编和一个最小测试程序交叉验证。

## 11. 一个完整示例

假设有：

```go
type Request struct {
    ID   int64
    Name string
}

type Result struct {
    Code int64
}

//go:noinline
func Handle(req *Request, retry bool) (*Result, error)
```

### 11.1 静态类型恢复

`FunctionVariables` 得到：

```text
args:
  req   *main.Request
  retry bool
rets:
  ~r0   *main.Result
  ~r1   error/runtime.iface
```

### 11.2 入口 ABI 分配

`req` 是 `*struct`，消费 `AX`，字段从内存展开；`retry` 接着消费 `BX`：

```text
req.ID        <- memory[AX+0]
req.Name.data <- memory[memory[AX+8] ... 最多64字节]
req.Name.len  <- memory[AX+16]
retry         <- BX 的低1字节
```

相应 `Value` 树保留：

```text
req = &main.Request{ID:..., Name:...}
retry = bool
```

### 11.3 返回 ABI 分配

返回值重新从 `AX` 分配：

```text
~r0 *Result -> AX
~r1 error   -> BX(type/itab), CX(data)
```

其中 `~r0.Code` 从 `memory[AX+0]` 读取；error 还会从 `BX` 解析动态类型，并从 `CX` 指向的内存同步抓取具体值前缀。

### 11.4 运行时输出

如果调用时 `req=&Request{7,"alice"}`、`retry=true`，返回 `&Result{200}, nil`，用户态可能重建为：

```text
Handle(req=&main.Request{ID:7, Name:"alice"}, retry=true)
...
Handle(ret0=&main.Result{Code:200}, ret1=nil)
```

这里用户看到的是结构化 Go 值，但内核实际传输的仍只是固定数量、固定大小、严格有序的扁平字节叶子。

## 12. 开发者维护指南

修改 auto 模式时，应始终检查下面几条不变量：

1. `FetchArgs` 数量不能超过 `MaxFetchArgs`；
2. 每个复合节点必须原子预留全部叶子，不能只生成一半 string/slice/interface；
3. `Value.leafCount()` 必须等于对应 `FetchArgs` 数量；
4. `Value` 深度优先遍历的叶子顺序必须等于 `FetchArgs` 顺序；
5. Go 侧 `ArgLocation`、寄存器编号和 C 侧枚举必须同步；
6. 入口地址和每条 RET 地址必须分别写入规则；
7. 新的内存读取路径必须正确传播 nil 与 read error；
8. 修改 `struct event`、`arg_data`、map 或常量后，必须重新生成 BPF object 和 Go binding。

现有测试主要覆盖：

- 标量、string、slice、bool 和结构体指针入口参数；
- 单返回值、多返回值、interface 和结构体指针返回值；
- nil 结构体指针；
- 复合值接近 8 叶子上限时的原子截断；
- 空接口与非空接口的 type 路径；
- 接口动态结构体、动态指针和嵌套接口的渲染；
- `FetchArg` 与 `Value` 叶子数量一致性；
- 显式规则不被内部 auto 填充逻辑覆盖。

主要测试文件为：

- `internal/uprobe/auto_test.go`；
- `internal/uprobe/value_test.go`；
- `elf/dwarf_test.go`；
- `internal/eventmanager/handler_test.go`。

## 13. 总结

可以把 auto 模式记成一句话：

> DWARF 提供类似静态反射的类型树，Go ABI 告诉我们值位于哪里，eBPF 在函数入口或返回点复制原始字节，用户态再按同一棵类型树把扁平字节重建成可读的 Go 值。

它并没有神奇地“从 DWARF 直接读出运行时值”。真正的核心是把四件事准确连接起来：

```text
DWARF 类型描述
  + Go amd64 ABI 位置推导
  + BPF 寄存器/内存取值
  + 用户态类型化解码与重建
```

只要把“类型形状”和“具体值”分开理解，再把 `Value` 看作 go-ftrace 内部的一棵轻量反射树，`auto.go` 的整体设计就会清晰很多。
