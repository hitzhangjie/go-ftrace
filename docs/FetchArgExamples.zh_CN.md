# Fetch 规则示例

本文汇总了常见 Go 参数 / 返回值约定下可直接使用的 `--fargs` / `--frets` 规则，
内容提炼自 [`testdata/`](../testdata) 下的测试程序。完整语法说明见
[FetchArgRule.zh_CN.md](./FetchArgRule.zh_CN.md)。

## 语法速记

```
funcname(var=(expr):type, ...)
```

- `(%ax)` — 直接读取寄存器值本身（整数、指针）。
- `(+N(%ax))` — 读取 `*(AX+N)`（单次解引用，如结构体字段）。
- `(*+N(%ax))` — 读取 `*(*(AX+N))`（双重解引用，如 string 数据指针）。
- 类型：`s64` / `u64`（整数）、`u8`（bool）、`c64`（8 字节字符串）。

## ABI 寄存器速查（Go 1.17+，linux/amd64）

入口参数与返回值使用相同的寄存器序列：`AX, BX, CX, DI, SI, R8, R9, R10, R11`。

| 类型 | 布局 |
| ---- | ---- |
| 整数 / 指针 | 1 word：`AX` |
| string | 2 words：data（`AX`）、len（`BX`） |
| slice | 3 words：data（`AX`）、len（`BX`）、cap（`CX`） |
| 方法接收者 | 第 1 个参数（`AX`） |
| error（接口） | 2 words：itab（`AX`）、data（`BX`） |
| struct 值 | 走栈传递 —— 寄存器规则**不适用** |

## 入口参数（`--fargs`）

### 整数

```bash
--fargs 'main.add(a=(%ax):s64, b=(%bx):s64)'
```

`a -> AX`、`b -> BX`。

### string

```bash
--fargs 'main.greet(name.data=(+0(%ax)):c64, name.len=(%bx):s64)'
```

`name.data` 是指针，存储在 `AX` 中，直接用 `(+0(%ax))` 读取并按 `c64` 解码；
`name.len -> BX`。

### 方法接收者（指针）

```bash
--fargs 'main.(*Student).String(s.name.data=(*+0(%ax)):c64, s.name.len=(+8(%ax)):s64, s.age=(+16(%ax)):s64)'
```

接收者 `*Student` 位于 `AX`。`s.name.data` 是 `+0` 处的 string 数据指针，需要
额外一次解引用 `(*+0(%ax))`；`len`（`+8`）、`age`（`+16`）则是直接读取的普通值。

### slice

```bash
--fargs 'main.sum(nums.data=(%ax):u64, nums.len=(%bx):s64, nums.cap=(%cx):s64)'
```

`nums.data -> AX`、`nums.len -> BX`、`nums.cap -> CX`。

### bool

```bash
--fargs 'main.toggle(on=(%ax):u8)'
```

bool 只占 1 字节（`AL`）。

## 返回值（`--frets`）

### 整数

```bash
--frets 'main.add(result=(%ax):s64)'
```

### string

```bash
--frets 'main.makeGreeting(result.data=(%ax):u64, result.len=(%bx):s64)'
```

### 指针

```bash
--frets 'main.newStudentPtr(ptr=(%ax):u64)'
```

### error 接口

```bash
--frets 'main.mayFail(err.itab=(%ax):u64, err.data=(%bx):u64)'
```

`error` 接口是两个 word：itab（`AX`）、data（`BX`）。

### 多返回值

```bash
--frets 'main.divmod(quotient=(%ax):s64, remainder=(%bx):s64)'
```

### 结构体指针

```bash
--frets 'main.send(Code=(+0(%ax)):s64, Detail.itab=(+8(%ax)):u64, Detail.data=(+16(%ax)):u64)'
```

`send` 返回 `*MeshError`，位于 `AX`。`Code` 是 `+0` 处的普通值，直接读为
`(+0(%ax))`；`Detail.itab`（`+8`）、`Detail.data`（`+16`）同样是普通值。

### 结构体值（寄存器规则不适用）

结构体值类型的返回值走栈传递（Go ABI），不在寄存器中，因此基于寄存器的
`--frets` 规则不适用。
