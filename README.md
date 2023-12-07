# go-ftrace

go-ftrace is an bpf(2)-based ftrace(1)-like function graph tracer for Golang processes.

**Limits: for now, only support following cases**
- OS: Linux, with support for bpf(2) and uprobe
- Arch: x86-64 little endian
- Binary: go ELF executable, non-stripped, built with non-PIE mode,
          ELF sections .symtab, .(z)debug_info are required

# Usage

`examples` provide two examples to show how to use go-ftrace.

## Trace functions

Check `examples/trace_funcs`, try following tracing tests:

  ```
  example: trace a specific function: "main.add":
    ftrace -u main.add ./main

  example: trace all functions like main.add*:
    ftrace -u 'main.add*' ./main

  example: trace all functions like main.add* or main.minus*:
    ftrace -u 'main.add*' -u 'main.minus*' ./main

  example: trace a specific function and include runtime.chan* builtins:
    ftrace -u 'main.add' -u 'runtime.chan*' ./main

  example: trace a specific method of specific type:
    ftrace -u 'main.(*Student).String ./main    
  ```

## Trace functions and arguments

Check `examples/trace_funcs_arguments`, try following tracing tests:

  ```
  example: trace a specific method of specific type, and fetch its receiver argument:
    ftrace -u 'main.(*Student).String' ./main \
      'main.(*Student).String(s.name=(*+0(%ax)):c64, s.name.len=(+8(%ax)):s64, s.age=(+16(%ax)):s64)'
  
  example: trace a specific method of specific type, and fetch its arguments list:
    ftrace -u 'main.(*Student).BuyBook' ./main \
      'main.(*Student).BuyBook(s.book=(+0(%bx)):c128, s.book.len=(%cx):s64, s.num=(%di):s64)'
  ```

>ps: `Makefile` is provided, you can run `make <target>` to quickly test it.
>
> And tracing by ftrace can be done either before or after launching ./main, both approaches will work.

# Installation

## Method 1

install into your $GOBIN or $GOPATH/bin, please add $GOBIN, $GOPATH/bin to your PATH

```bash
go install github.com/hitzhangjie/go-ftrace/cmd/ftrace@latest
```

bpf tool require special permission, so we need run ftrace as root, like `sudo ftrace ...`,
and we must make sure ftrace is searchable by sudo, so link it to the searchpath by `sudo`

```bash
sudo ln -s ~/go/bin/ftrace /usr/sbin/
```

then we can run it with sudo:

```bash
sudo ftrace -u 'go.etcd.io/etcd/client/v3/concurrency.(*Mutex).tryAcquire' ./a.out
```

## Method 2

Also, `Makefile` is provided, run `make && make install` is enough.

# Use cases

- Wall time profiling;
- Execution flow observing;

Here's an example when tracing `examples/main.go`, here's the code snippet:
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

if we want to observing the details of `doSomething`, we can trace like ths:

```bash
sudo ftrace -u 'main.*' -u 'fmt.Print*' ./main \
  'main.(*Student).String(s.name=(*+0(%ax)):c64, s.name.len=(+8(%ax)):s64, s.age=(+16(%ax)):s64)'
```

ftrace will output the details:

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


# Acknowledgments

This repo is forked from [jschwinger233/gofuncgraph](https://github.com/jschwinger233/gofuncgraph), with some modifications to improve usability and fix the bugs of fetching arguments. 

Thanks for the original work!

ps：if you want to know more about go-ftrace alternatives to C, C++, Rust and Python, or kernel ftrace tool, you can see: 
- [namhyung/uftrace](https://github.com/namhyung/uftrace), https://github.com/namhyung/uftrace
- [kernel ftrace](https://www.kernel.org/doc/html/v4.17/trace/ftrace.html), https://www.kernel.org/doc/html/v4.17/trace/ftrace.html
