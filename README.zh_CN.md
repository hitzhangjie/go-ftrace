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
      'main.(*Student).String(s.name=(*+0(%ax)):c64, s.name.len=(+8(%ax)):s64, s.age=(+16(%ax)):s64)'
  ```

示例目录下同时提供了一个 `examples/Makefile`, 你也可以执行 `make <target>` 来快速执行对应的命令（对应上面示例）来进行测试.

ps: 你可以在启动被测试程序 ./main 之前或者之后启动 ftrace，两种方式都可以正常工作，这主要是跟ebpf程序的加载、触发机制有关。

# 安装方法

## 方式1

首先编译安装到 $GOBIN 或者 $GOPATH/bin，注意将 $GOBIN，$GOPATH/bin 设置到程序搜索路径 PATH 中。

```bash
go install github.com/hitzhangjie/go-ftrace/cmd/ftrace@latest
```

bpf tool require special permission, so we need run ftrace as root, like `sudo ftrace ...`,
and we must make sure ftrace is searchable by sudo, so link it to the searchpath by `sudo`

bpf程序的加载、执行需要特殊的权限，为了方便测试，我们先使用 `sudo` 来执行 `sudo ftrace ...`，由于 `sudo` 对安全性有要求，
为了执行 `sudo ftrace` 时能正常搜索到 `ftrace`，现在还需要添加个软链到 `/usr/sbin/`。

```bash
sudo ln -s ~/go/bin/ftrace /usr/sbin/
```

经过这些设置后，就可以通过 `sudo ftrace ...` 对程序进行跟踪了:

```bash
sudo ftrace -u 'go.etcd.io/etcd/client/v3/concurrency.(*Mutex).tryAcquire' ./a.out
```

## 方式2

为了简化安装，项目根目录下也提供了一个 `Makefile` 文件，可以执行 `make && make install` 来完成安装。

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
  'main.(*Student).String(s.name=(*+0(%ax)):c64, s.name.len=(+8(%ax)):s64, s.age=(+16(%ax)):s64)'
```

`ftrace` 将输出如下信息，从中可以看到：

- 函数启动、停止时的绝对时间
- 函数执行的耗时信息，单位“秒(s)”
- 函数定义所在的源码位置
- 函数被发起调用时的位置
- 函数指令数据末尾的偏移量
- 想获取的函数参数信息

```bash
$ sudo ftrace -u 'main.*' -u 'fmt.Print*' ./main 'main.(*Student).String(s.name=(*+0(%ax)):c64, s.name.len=(+8(%ax)):s64, s.age=(+16(%ax)):s64)'
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



# 致谢

该项目fork自 [jschwinger233/gofuncgraph](https://github.com/jschwinger233/gofuncgraph), 在此基础上做了一些优化、bugfix相关的工作来改善工具的易用性、健壮性。

感谢原作者的贡献!

ps：如果你对C/C++/Rust/Python相关的ftrace工具感兴趣的话，可以了解下 [namhyung/uftrace](https://github.com/namhyung/uftrace)，如果你对内核的ftrace工具感兴趣，可以了解下 [kernel ftrace](https://www.kernel.org/doc/html/v4.17/trace/ftrace.html)。
