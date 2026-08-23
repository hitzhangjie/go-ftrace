# go-ftrace

go-ftrace 是一个基于Linux bpf(2) 的类似内核工具 ftrace(1) 的函数调用跟踪、耗时统计工具，它主要是面向go应用程序的。

**限制: 因为设计实现的原因，当前go-ftrace只支持满足如下限制条件的go程序跟踪、统计：**

- Linux内核：支持 bpf(2) 和 uprobe 的Linux内核
- 处理器架构: x86-64架构（little-endian字节序）
- 二进制程序：只能是go ELF可执行程序（非PIE模式），未剔除符号表.symtab，未剔除调试信息.(z)debug_info，

# 使用方式

项目在 [`examples/`](./examples) 下提供了一个嵌套调用的演示程序（`make -C examples`），
可以执行如下几种测试来了解 go-ftrace 的使用。

跟踪函数：

```
  示例1: 跟踪一个自定义函数 main.add:
    ftrace -u main.add ./main

  示例2: 跟踪所有的匹配函数 main.add*:
    ftrace -u 'main.add*' ./main

  示例3: 跟踪多个模式匹配的函数 main.add* 或 main.minus*:
    ftrace -u 'main.add*' -u 'main.minus*' ./main

  示例4: 跟踪一个自定义函数 main.add 以及内置函数 runtime.chan*:
    ftrace -u 'main.add' -u 'runtime.chan*' ./main

  示例5: 跟踪一个自定义类型的方法:
    ftrace -u 'main.(*Student).String' ./main
```

高频函数建议使用 aggregate 模式，并设置 go-ftrace 的堆内存目标：

```bash
sudo ftrace -c --memory-limit 256 -u 'main.hotPath' ./main
```

自适应采样与内存背压对**所有模式**（包括非 aggregate 的逐条打印）生效：事件按完整根调用采样，而不是独立丢弃入口/返回事件；它每秒依据实际 Go 堆占用动态调整采样率，并对未闭合事件、PID 数、返回值重频候选设置固定上限，防止高频命中时 go-ftrace 自身内存无限增长。`--memory-limit` 即该内存目标，`--adaptive-sample=false` 可关闭动态采样（始终采集每个根调用）。aggregate 与普通模式的差异只在输出形式（按函数聚合汇总 vs 逐条打印调用栈）。结束（或 Ctrl+C）时统计会显示采样跳过数、队列溢出丢失数、异常中止数和被丢弃的调用样本数；aggregate 的每项聚合结果同时显示实际计数 `counted` 与按采样率推算的量级估算 `estimated`。估算值使用样本准入时的采样分母做逆概率加权；队列溢出丢失的事件具有相关性，只单独报告而不强行计入估算，因此结果不应视为无损审计数据。该参数约束的是 go-ftrace 自身的数据结构和采样目标，不等同于操作系统级 RSS/cgroup 硬限制。

想了解更多用法（自动提取、手写 fetch 规则、采样等）请看 [`docs/`](./docs)。

ps: 你可以在启动被测试程序 ./main 之前或者之后启动 ftrace，两种方式都可以正常工作，这主要是跟ebpf程序的加载、触发机制有关。

## 自动提取函数参数与返回值（默认）

自动提取**默认开启**。ftrace 读 DWARF、编译抓取规则，在 uprobe 命中当下拷贝，再打印成接近 Go 的结构化值。常见类型（整数、布尔、字符串、切片、结构体指针、接口）不需要 `--fargs` / `--frets`。

先编译 fixture（`make -C testdata`）。下面用 `testdata/args`、`testdata/rets`。
单元测试编译的是 [`testdata/auto`](./testdata/auto)，同一份程序还覆盖
`error`、`fmt.Stringer`、`proto.Message`：

```bash
sudo ftrace -u 'main.add' ./testdata/args/main
```

```text
22 12:24:47.9955           main.add(a=1, b=2) { main.main+134 testdata/args/main.go:27
22 12:24:47.9955 000.0000  } main.add+38 => ret0=3 testdata/args/main.go:47
```

```bash
sudo ftrace -u 'main.(*Student).String' ./testdata/args/main
```

```text
22 12:25:14.0021           main.(*Student).String(s=&main.Student{Name:"zhang", Age:100}) { main.main+165 testdata/args/main.go:29
22 12:25:14.0021 000.0000  } main.(*Student).String+349 => ret0="" testdata/args/main.go:70
```

```bash
sudo ftrace -u 'main.send' ./testdata/rets/main
```

```text
22 12:25:21.5756           main.send(ok=true) { main.main+156 testdata/rets/main.go:32
22 12:25:21.5756 000.0000  } main.send+149 => ret0=nil testdata/rets/main.go:121
22 12:25:21.5756           main.send(ok=false) { main.main+165 testdata/rets/main.go:33
22 12:25:21.5756 000.0000  } main.send+282 => ret0=&main.MeshError{Code:500, Detail:&errors.errorString{s:"<unavailable>"}} testdata/rets/main.go:119
22 12:25:22.1226           main.send(ok=false) { main.main+165 testdata/rets/main.go:33
22 12:25:22.1226 000.0000  } main.send+282 => ret0=&main.MeshError{Code:500, Detail:&errors.errorString{s:"send failed"}} testdata/rets/main.go:119
```

`--fargs-auto` / `--frets-auto` 可分别关闭。nil 的 `error` 显示为 `nil`。某种接口具体类型第一次出现时，嵌套字节（例如 `error` 里的字符串）可能是 `<unavailable>`，同类型后续命中会拷全。`--hide-unexported`（默认关闭）打印时隐藏未导出结构体字段，适合 `proto.Message` 这类生成类型。原理见 [Auto 模式原理：从 DWARF 类型到探针时快照](./docs/AutoFetch.zh_CN.md)。

## 手写 fetch 规则（可选）

手写 `--fargs` / `--frets` 适合 auto 太吵的时候：只要某一个字段、聚合直方图更干净，或 auto 覆盖不了的布局。命令行出现任意 `--fargs` 时，本次运行的入口 auto 整体关闭；出现任意 `--frets` 时，返回 auto 整体关闭。

```bash
sudo ftrace -u 'main.add' ./testdata/args/main \
  --fargs 'main.add(a=(%ax):s64, b=(%bx):s64)'
```

```text
22 12:27:15.0151           main.add(a=1, b=2) { main.main+134 testdata/args/main.go:27
22 12:27:15.0151 000.0000  } main.add+38 => ret0=3 testdata/args/main.go:47
```

规则语法见 [FetchArgRule.zh_CN.md](./docs/FetchArgRule.zh_CN.md)，现成例子见 [FetchArgExamples.zh_CN.md](./docs/FetchArgExamples.zh_CN.md)。更多用法见 [`docs/`](./docs)。

# 安装方法

## root 用户

最简单的方式是直接安装并运行：

```bash
go install github.com/hitzhangjie/go-ftrace/cmd/ftrace@latest
# 或者，在源码目录下
make install
```

## 非 root 用户

如果希望非 root 用户（无需 sudo）也能运行，请使用 `make install`，它会完成普通用户
运行所需的提权设置（软链、属主、setuid）：

```bash
make install
```

也可以手动执行 Makefile 里的相关设置，详见 [INSTALLATION.md](./INSTALLATION.md)。

> 安装细节与背后的考虑请参考 [INSTALLATION.md](./INSTALLATION.md)。

# 使用案例

你可以将其用于go程序的函数调用关系的跟踪，以及耗时相关的统计观测。

以下面的示例代码为例（详见 `examples/main.go`），说明下工具的使用、执行效果：

```go
func main() {
 for {
  doSomething()
 }
}

...

func doSomething() {
 add(1, 2)
 minus(1, 2)

 s := &Student{"zhang", 100}
 fmt.Printf("student: %s\n", s)

 time.Sleep(time.Second)
}
```

如果我们要观察 `doSomething` 的调用关系和耗时，默认的自动提取就够了，不必手写 `--fargs`：

```bash
sudo ftrace -u 'main.*' -u 'fmt.Print*' ./main
```

从输出里可以看到：

- 整棵调用树：谁在何时调用了谁
- 每一层的入参与返回值（DWARF 自动推导，不必手写规则）
- 每一层返回时的耗时（秒），会沿着栈往上累加
- 方法接收者被还原成结构体
- 同一二进制里其他 goroutine 的调用也会出现

```text
                           🔬 嵌套调用：谁调用了谁，以及每一层的参数和返回值
22 12:31:44.0081           main.doSomething() { main.main+31 /home/zhangjie/hitzhangjie/go-ftrace/examples/main.go:16
22 12:31:44.0081             main.add(a=1, b=2) { main.doSomething+37 /home/zhangjie/hitzhangjie/go-ftrace/examples/main.go:21
22 12:31:44.0081               main.add1(a=1, b=2) { main.add+151 /home/zhangjie/hitzhangjie/go-ftrace/examples/main.go:33
22 12:31:44.1083                 main.add2(a=1, b=2) { main.add1+165 /home/zhangjie/hitzhangjie/go-ftrace/examples/main.go:40
22 12:31:44.3087                   main.add3(a=1, b=2) { main.add2+52 /home/zhangjie/hitzhangjie/go-ftrace/examples/main.go:48

                                 ⏱️ 每一层返回时打出耗时，会沿着调用栈往上累加
22 12:31:44.6092 000.3005          } main.add3+175 => ret0=3 /home/zhangjie/hitzhangjie/go-ftrace/examples/main.go:55
22 12:31:44.6092 000.5009        } main.add2+57 => ret0=3 /home/zhangjie/hitzhangjie/go-ftrace/examples/main.go:48
22 12:31:44.6092 000.6011      } main.add1+170 => ret0=3 /home/zhangjie/hitzhangjie/go-ftrace/examples/main.go:40
22 12:31:44.6092 000.6011    } main.add+156 => ret0=3 /home/zhangjie/hitzhangjie/go-ftrace/examples/main.go:33
22 12:31:44.6092             main.minus(a=1, b=2) { main.doSomething+52 /home/zhangjie/hitzhangjie/go-ftrace/examples/main.go:22
22 12:31:44.6594 000.0502    } main.minus+55 => ret0=-1 /home/zhangjie/hitzhangjie/go-ftrace/examples/main.go:61

                            🔍 接收者由 DWARF 自动推导（*Student 在 AX，展开成结构体）
22 12:31:44.6594             main.(*Student).String(s=&main.Student{name:"zhang", age:100}) { fmt.(*pp).handleMethods+756 /opt/go/src/fmt/print.go:674
22 12:31:44.6695 000.0101    } main.(*Student).String+156 => ret0="" /home/zhangjie/hitzhangjie/go-ftrace/examples/main.go:75
22 12:31:45.6699 001.6618  } main.doSomething+172 /home/zhangjie/hitzhangjie/go-ftrace/examples/main.go:28

                           🧵 同一二进制里另一个 goroutine（main 里那段循环）
22 12:31:45.8854           main.add3(a=1, b=1) { main.main.func1+37 /home/zhangjie/hitzhangjie/go-ftrace/examples/main.go:12
22 12:31:46.1860 000.3006  } main.add3+175 => ret0=2 /home/zhangjie/hitzhangjie/go-ftrace/examples/main.go:55
```

只有在你只关心某几个字段（例如让聚合直方图更干净）时，才需要手写 `--fargs` / `--frets`。

# 设计实现

如果对go-ftrace的设计实现感兴趣，请阅读 [go-ftrace设计实现](https://www.hitzhangjie.pro/blog/2023-12-12-%E8%A7%82%E6%B5%8Bgo%E5%87%BD%E6%95%B0%E8%B0%83%E7%94%A8go-ftrace%E8%AE%BE%E8%AE%A1%E5%AE%9E%E7%8E%B0/) 来了解更多。

# 致谢

该项目fork自 [jschwinger233/gofuncgraph](https://github.com/jschwinger233/gofuncgraph), 在此基础上做了一些优化、bugfix相关的工作来改善工具的易用性、健壮性。

感谢原作者的贡献!

ps：如果你对C/C++/Rust/Python相关的ftrace工具感兴趣的话，可以了解下 [namhyung/uftrace](https://github.com/namhyung/uftrace)，如果你对内核的ftrace工具感兴趣，可以了解下 [kernel ftrace](https://www.kernel.org/doc/html/v4.17/trace/ftrace.html)。
