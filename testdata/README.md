# testdata fixtures

本目录存放用于 go-ftrace 集成测试的 fixture 源码。每个 fixture 都是独立的
`package main`，包含若干带 `//go:noinline` 的函数调用，用于在 go1.22、go1.26
等不同 Go 工具链版本下稳定地测试符号解析、uprobe 挂载、入口参数抓取
(`--fargs`) 与返回值抓取 (`--frets`) 等功能。

## 目录结构

| 目录    | 用途 |
| ------- | ---- |
| `basic` | 嵌套函数调用链，用于测试函数图 / 耗时统计 |
| `args`  | 各种参数类型（int/string/slice/方法/指针），手写 `--fargs` 的 ABI 速查 |
| `rets`  | 各种返回值类型（int/string/struct/指针/error/多返回值），手写 `--frets` 的 ABI 速查 |
| `auto`  | 自动提取（DWARF）的综合目录：入参、出参，以及 `error`、`fmt.Stringer`、`proto.Message` 等常见接口。单元测试编译的是这一份 |

`args` / `rets` 里各函数注释里的 fetch 规则，是手动模式的速查；提炼版见
[`docs/FetchArgExamples.zh_CN.md`](../docs/FetchArgExamples.zh_CN.md)。
自动模式的行为以 `auto` 和 `internal/uprobe/auto_test.go` 为准。

## 编译

fixture 必须编译为**非 PIE、未 strip、保留符号表与调试信息**的二进制，
否则 go-ftrace 无法解析符号或挂载 uprobe。构建参数为：

```bash
go build -gcflags 'all=-N -l' -ldflags '-linkmode=external -extldflags=-no-pie' -o main .
```

一次性编译所有 fixture：

```bash
make -C testdata
```

生成的二进制分别为 `testdata/basic/main`、`testdata/args/main`、
`testdata/rets/main`、`testdata/auto/main`。`auto` 自带 `go.mod`（protobuf），
首次编译会拉取 `google.golang.org/protobuf`。

## 使用示例

### 函数图 / 耗时（basic）

```bash
ftrace -u 'main.outer' -u 'main.inner1' -u 'main.inner2' \
       -u 'main.double' -u 'main.echo' ./testdata/basic/main
```

### 自动提取（auto，默认）

不写 `--fargs` / `--frets`，DWARF 会推导常见类型：

```bash
ftrace -u 'main.add' ./testdata/auto/main
ftrace -u 'main.(*Student).String' ./testdata/auto/main
ftrace -u 'main.send' ./testdata/auto/main
ftrace -u 'main.stringify' ./testdata/auto/main
ftrace -u 'main.unmarshalMsg' ./testdata/auto/main
```

### 手写规则（args / rets）

完整 fetch 规则（含 ABI 寄存器布局）已标注在 `args` 与 `rets` 各函数的源码
注释中。

```bash
# 整数参数：a -> AX, b -> BX
ftrace -u 'main.add' ./testdata/args/main \
  --fargs 'main.add(a=(%ax):s64, b=(%bx):s64)'

# 方法接收者（指针）位于 AX，读取其字段
ftrace -u 'main.(*Student).String' ./testdata/args/main \
  --fargs 'main.(*Student).String(s.name.data=(*+0(%ax)):c64, s.name.len=(+8(%ax)):s64, s.age=(+16(%ax)):s64)'

# 整数返回值
ftrace -u 'main.add' ./testdata/rets/main \
  --frets 'main.add(result=(%ax):s64)'

# 自定义错误指针：Code 位于 +0，Detail.itab +8，Detail.data +16
ftrace -u 'main.send' ./testdata/rets/main \
  --frets 'main.send(Code=(+0(%ax)):s64, Detail.itab=(+8(%ax)):u64, Detail.data=(+16(%ax)):u64)'
```

## 跨版本注意事项

- `basic` / `args` / `rets` 只使用稳定的标准库与语言特性。
- `auto` 额外依赖 `google.golang.org/protobuf`，用于 `proto.Message`。
- 关键函数统一标注 `//go:noinline`，确保函数边界与 RET 指令稳定存在。
- 编译时统一使用 `-gcflags 'all=-N -l'` 关闭优化与内联，避免不同版本优化
  策略差异导致的符号/偏移变化。
