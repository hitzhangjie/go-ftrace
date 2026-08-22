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
    ftrace -u 'main.(*Student).String' ./main
```

## Fetch arguments and return values (automatic, default)

Auto fetching is **on by default**. ftrace reads DWARF, compiles fetch rules,
copies values when the uprobe fires, and prints them as Go-like structured
values. You do not need `--fargs` / `--frets` for common types (integers,
bools, strings, slices, pointers to structs, interfaces).

Build the fixtures once (`make -C testdata`), then:

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

`--fargs-auto` / `--frets-auto` can be turned off independently. A nil `error`
prints as `nil`. The first hit of a new interface concrete type may show
`<unavailable>` for nested bytes (the string inside `error`); the same type
is captured in full on later hits. Details: [Auto-fetch design](./docs/AutoFetch.zh_CN.md).

## Manual fetch rules (optional)

Hand-written `--fargs` / `--frets` are for when auto is too noisy: you only
want one field, cleaner aggregate histograms, or a layout auto does not
cover. Any `--fargs` on the command line turns off entry auto for the whole
run; any `--frets` turns off return auto.

```bash
sudo ftrace -u 'main.add' ./testdata/args/main \
  --fargs 'main.add(a=(%ax):s64, b=(%bx):s64)'
```

```text
22 12:27:15.0151           main.add(a=1, b=2) { main.main+134 testdata/args/main.go:27
22 12:27:15.0151 000.0000  } main.add+38 => ret0=3 testdata/args/main.go:47
```

Rule syntax: [FetchArgRule.md](./docs/FetchArgRule.md). Ready-made examples:
[FetchArgExamples.md](./docs/FetchArgExamples.md).

> `Makefile`s under `examples/` and `testdata/` let you `make <target>` quickly.
> Tracing can start before or after `./main`; both work.

# Installation

## As root

The simplest way is to install and run it directly:

```bash
go install github.com/hitzhangjie/go-ftrace/cmd/ftrace@latest
# or, from a source checkout
make install
```

## As a non-root user

To run `ftrace` without `sudo`, use `make install`, which performs the
privilege setup (symlink, ownership, setuid) required for regular users:

```bash
make install
```

Alternatively, apply those settings manually as described in
[INSTALLATION.md](./INSTALLATION.md).

> See [INSTALLATION.md](./INSTALLATION.md) for details and the rationale behind
> the privilege-related setup.

# Use cases

- Wall time profiling;
- Execution flow observing;

Here's an example when tracing `examples/trace_funcs/main.go`, here's the code snippet:

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

If we want to observe `doSomething`, auto-fetch is enough — no `--fargs`:

```bash
sudo ftrace -u 'main.*' -u 'fmt.Print*' ./main
```

The output shows:

- the full call tree: who called whom and when
- arguments and return values on every frame (from DWARF, no hand-written rules)
- per-frame latency in seconds, accumulating as the stack unwinds
- method receivers reconstructed as structs
- calls from other goroutines of the same binary

```text
                           🔬 Nested calls: who called whom, args, and return values
22 12:31:44.0081           main.doSomething() { main.main+31 /home/zhangjie/hitzhangjie/go-ftrace/examples/trace_funcs/main.go:16
22 12:31:44.0081             main.add(a=1, b=2) { main.doSomething+37 /home/zhangjie/hitzhangjie/go-ftrace/examples/trace_funcs/main.go:21
22 12:31:44.0081               main.add1(a=1, b=2) { main.add+151 /home/zhangjie/hitzhangjie/go-ftrace/examples/trace_funcs/main.go:33
22 12:31:44.1083                 main.add2(a=1, b=2) { main.add1+165 /home/zhangjie/hitzhangjie/go-ftrace/examples/trace_funcs/main.go:40
22 12:31:44.3087                   main.add3(a=1, b=2) { main.add2+52 /home/zhangjie/hitzhangjie/go-ftrace/examples/trace_funcs/main.go:48
                                
                                  ⏱️ Latency stacks up as each frame returns
22 12:31:44.6092 000.3005          } main.add3+175 => ret0=3 /home/zhangjie/hitzhangjie/go-ftrace/examples/trace_funcs/main.go:55
22 12:31:44.6092 000.5009        } main.add2+57 => ret0=3 /home/zhangjie/hitzhangjie/go-ftrace/examples/trace_funcs/main.go:48
22 12:31:44.6092 000.6011      } main.add1+170 => ret0=3 /home/zhangjie/hitzhangjie/go-ftrace/examples/trace_funcs/main.go:40
22 12:31:44.6092 000.6011    } main.add+156 => ret0=3 /home/zhangjie/hitzhangjie/go-ftrace/examples/trace_funcs/main.go:33
22 12:31:44.6092             main.minus(a=1, b=2) { main.doSomething+52 /home/zhangjie/hitzhangjie/go-ftrace/examples/trace_funcs/main.go:22
22 12:31:44.6594 000.0502    } main.minus+55 => ret0=-1 /home/zhangjie/hitzhangjie/go-ftrace/examples/trace_funcs/main.go:61

                            🔍 Receiver reconstructed from DWARF (*Student in AX)
22 12:31:44.6594             main.(*Student).String(s=&main.Student{name:"zhang", age:100}) { fmt.(*pp).handleMethods+756 /opt/go/src/fmt/print.go:674
22 12:31:44.6695 000.0101    } main.(*Student).String+156 => ret0="" /home/zhangjie/hitzhangjie/go-ftrace/examples/trace_funcs/main.go:75
22 12:31:45.6699 001.6618  } main.doSomething+172 /home/zhangjie/hitzhangjie/go-ftrace/examples/trace_funcs/main.go:28

                           🧵 Same binary, another goroutine (the loop in main)
22 12:31:45.8854           main.add3(a=1, b=1) { main.main.func1+37 /home/zhangjie/hitzhangjie/go-ftrace/examples/trace_funcs/main.go:12
22 12:31:46.1860 000.3006  } main.add3+175 => ret0=2 /home/zhangjie/hitzhangjie/go-ftrace/examples/trace_funcs/main.go:55
```

Hand-write `--fargs` / `--frets` only if you want a subset of fields (for example a smaller aggregate histogram).

# Design & Implemention

If you're interested in the implmention internals, please read: [go-ftrace internals](https://www.hitzhangjie.pro/blog/2023-12-12-%E8%A7%82%E6%B5%8Bgo%E5%87%BD%E6%95%B0%E8%B0%83%E7%94%A8go-ftrace%E8%AE%BE%E8%AE%A1%E5%AE%9E%E7%8E%B0/).

# Acknowledgments

This repo is forked from [jschwinger233/gofuncgraph](https://github.com/jschwinger233/gofuncgraph), with some modifications to improve usability and fix the bugs of fetching arguments.

Thanks for the original work!

ps：if you want to know more about go-ftrace alternatives to C, C++, Rust and Python, or kernel ftrace tool, you can see:

- [namhyung/uftrace](https://github.com/namhyung/uftrace), https://github.com/namhyung/uftrace
- [kernel ftrace](https://www.kernel.org/doc/html/v4.17/trace/ftrace.html), https://www.kernel.org/doc/html/v4.17/trace/ftrace.html
