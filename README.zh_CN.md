# go-ftrace

go-ftrace 是一个基于Linux bpf(2) 的类似内核工具 ftrace(1) 的函数调用跟踪、耗时统计工具，它主要是面向go应用程序的。

**限制: 因为设计实现的原因，当前go-ftrace只支持满足如下限制条件的go程序跟踪、统计：**

- Linux内核：支持 bpf(2) 和 uprobe 的Linux内核
- 处理器架构: x86-64架构（little-endian字节序）
- 二进制程序：只能是go ELF可执行程序（非PIE模式），未剔除符号表.symtab，未剔除调试信息.(z)debug_info，

# 使用方式

项目中提供了测试程序 `examples/main.go` ，可以执行如下几种测试来了解go-ftrace的使用:

  ```
  示例1: 跟踪一个自定义函数 main.add:
    ftrace -u main.add ./main

  示例2: 跟踪所有的匹配函数 main.add*:
    ftrace -u 'main.add*' ./main

  示例3: 跟踪多个模式匹配的函数 main.add* 或 main.minus*:
    ftrace -u 'main.add*' -u 'main.minus*' ./main

  示例4: 跟踪一个自定义函数 "main.add 以及 内置函数 runtime.chan*:
    ftrace -u 'main.add' -u 'runtime.chan*' ./main

  示例5: 跟踪一个自定义类型的方法:
    ftrace -u 'main.(*Student).String ./main    

  示例6: 跟踪一个自定义类型的方法，并试图提取关心的参数:
    ftrace -u 'main.(*Student).String' ./main \
      --fargs 'main.(*Student).String(s.name=(*+0(%ax)):c64, s.name.len=(+8(%ax)):s64, s.age=(+16(%ax)):s64)'

  示例7: 在函数返回点提取返回值:
    ftrace -u 'main.(*serviceMesh).send' ./main \
      --frets 'main.(*serviceMesh).send(Code=(+0(%ax)):s64, Detail.itab=(+8(%ax)):u64, Detail.data=(+16(%ax)):u64)'
  ```

示例目录下同时提供了一个 `examples/Makefile`, 你也可以执行 `make <target>` 来快速执行对应的命令（对应上面示例）来进行测试.

ps: 你可以在启动被测试程序 ./main 之前或者之后启动 ftrace，两种方式都可以正常工作，这主要是跟ebpf程序的加载、触发机制有关。

## 自动提取函数参数与返回值

示例6、示例7 展示了如何通过 `--fargs` / `--frets` 手动指定要提取的参数和返回值。
对于常见的 Go 类型（整数、指针、字符串、切片、接口，以及指向结构体的指针等），
ftrace 现在可以从 DWARF 调试信息中自动推导出对应的提取规则，无需再手写表达式：

```bash
# 无需 --fargs / --frets，自动提取 main.(*Student).String 的参数与返回值
sudo ftrace -u 'main.(*Student).String' ./main
```

自动推导默认开启，且入参与返回值可分别独立控制（`--fargs-auto` 与 `--frets-auto`），其规则如下：

- 依据 Go 的寄存器 ABI（regabi），将函数入参按声明顺序映射到 `ax, bx, cx, di, si, r8...` 等寄存器；
- 字符串展开为 `.data`（以 c64 读取字符串内容）与 `.len`；
- 切片展开为 `.data / .len / .cap`；
- 接口展开为 `.itab / .data`；
- 指向结构体的指针会解引用并展开其字段；
- 返回值同样按返回顺序映射到寄存器（`~r0/ret0`、`~r1/ret1` …）。

如果某个函数已经显式给出了 `--fargs` / `--frets`，则显式规则优先，不会被覆盖；
如需关闭自动推导，可分别传入 `--fargs-auto=false` 或 `--frets-auto=false`。

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

如果我们要观察函数 `doSomething` 执行过程中的函数调用关系，以及耗时情况，我们可以这样做：

```bash
sudo ftrace -u 'main.*' -u 'fmt.Print*' ./main \
  --fargs 'main.(*Student).String(s.name=(*+0(%ax)):c64, s.name.len=(+8(%ax)):s64, s.age=(+16(%ax)):s64)'
```

`ftrace` 将输出如下信息，从中可以看到：

- 函数启动、停止时的绝对时间
- 函数执行的耗时信息，单位“秒(s)”
- 函数定义所在的源码位置
- 函数被发起调用时的位置
- 函数指令数据末尾的偏移量
- 想获取的函数参数信息

```bash
$ sudo ftrace -u 'main.*' -u 'fmt.Print*' ./main --fargs 'main.(*Student).String(s.name=(*+0(%ax)):c64, s.name.len=(+8(%ax)):s64, s.age=(+16(%ax)):s64)'
WARN[0000] skip main.main, failed to get ret offsets: no ret offsets 
found 14 uprobes, large number of uprobes (>1000) need long time for attaching and detaching, continue? [Y/n]

>>> press `y` to continue
y
add arg rule at 47cc40: {Type:1 Reg:0 Size:8 Length:1 Offsets:[0 0 0 0 0 0 0 0] Deference:[1 0 0 0 0 0 0 0]}
add arg rule at 47cc40: {Type:1 Reg:0 Size:8 Length:1 Offsets:[8 0 0 0 0 0 0 0] Deference:[0 0 0 0 0 0 0 0]}
add arg rule at 47cc40: {Type:1 Reg:0 Size:8 Length:1 Offsets:[16 0 0 0 0 0 0 0] Deference:[0 0 0 0 0 0 0 0]}
INFO[0002] start tracing                                
...
                           🔬 You can inspect all nested function calls, when and where started or finished
23 17:11:00.0890           main.doSomething() { main.main+15 /home/zhangjie/github/go-ftrace/examples/main.go:10
23 17:11:00.0890             main.add() { main.doSomething+37 /home/zhangjie/github/go-ftrace/examples/main.go:15
23 17:11:00.0890               main.add1() { main.add+149 /home/zhangjie/github/go-ftrace/examples/main.go:27
23 17:11:00.0890                 main.add3() { main.add1+149 /home/zhangjie/github/go-ftrace/examples/main.go:40
23 17:11:00.0890 000.0000        } main.add3+148 /home/zhangjie/github/go-ftrace/examples/main.go:46
23 17:11:00.0890 000.0000      } main.add1+154 /home/zhangjie/github/go-ftrace/examples/main.go:33
23 17:11:00.0890 000.0001    } main.add+154 /home/zhangjie/github/go-ftrace/examples/main.go:27
23 17:11:00.0890             main.minus() { main.doSomething+52 /home/zhangjie/github/go-ftrace/examples/main.go:16
23 17:11:00.0890 000.0000    } main.minus+3 /home/zhangjie/github/go-ftrace/examples/main.go:51

                            🔍 Here, member fields of function receiver extracted, receiver is the 1st argument actually.
23 17:11:00.0891             main.(*Student).String(s.name=zhang<ni, s.name.len=5, s.age=100) { fmt.(*pp).handleMethods+690 /opt/go/src/fmt/print.go:673
23 17:11:00.0891 000.0000    } main.(*Student).String+138 /home/zhangjie/github/go-ftrace/examples/main.go:64
23 17:11:01.0895 001.0005  } main.doSomething+180 /home/zhangjie/github/go-ftrace/examples/main.go:22
                 ⏱️ Here, timecost is displayed at the end of the function call
...

>>> press `Ctrl+C` to quit.

INFO[0007] start detaching                              
detaching 16/16
```

# 设计实现

如果对go-ftrace的设计实现感兴趣，请阅读 [go-ftrace设计实现](https://www.hitzhangjie.pro/blog/2023-12-12-%E8%A7%82%E6%B5%8Bgo%E5%87%BD%E6%95%B0%E8%B0%83%E7%94%A8go-ftrace%E8%AE%BE%E8%AE%A1%E5%AE%9E%E7%8E%B0/) 来了解更多。

# 致谢

该项目fork自 [jschwinger233/gofuncgraph](https://github.com/jschwinger233/gofuncgraph), 在此基础上做了一些优化、bugfix相关的工作来改善工具的易用性、健壮性。

感谢原作者的贡献!

ps：如果你对C/C++/Rust/Python相关的ftrace工具感兴趣的话，可以了解下 [namhyung/uftrace](https://github.com/namhyung/uftrace)，如果你对内核的ftrace工具感兴趣，可以了解下 [kernel ftrace](https://www.kernel.org/doc/html/v4.17/trace/ftrace.html)。
