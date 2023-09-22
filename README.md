# go-ftrace

go-ftrace is an bpf(2)-based ftrace(1)-like function graph tracer for Golang processes.

**Limits: for now, only support following cases**
- OS: Linux, with support for bpf(2) and uprobe
- Arch: x86-64 little endian
- Binary: go ELF executable, non-stripped, built with non-PIE mode,
          ELF sections .symtab, .(z)debug_info are required

# Usage

`examples/main.go` is provided for testing, try following tracing tests:

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

  example: trace a specific method of specific type, and fetch its arguemnts:
    ftrace -u 'main.(*Student).String' ./main \
      'main.(*Student).String(s.name=(*+0(%ax)):c64, s.name.len=(+8(%ax)):s64, s.age=(+16(%ax)):s64)'
  ```

`examples/Makefile` is provided, you can run `make <target>` to quickly test it.

ps: Tracing with ftrace can be done either before or after launching ./main, both approaches will work.

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

# Acknowledgments

This repo is forked from [jschwinger233/gofuncgraph](https://github.com/jschwinger233/gofuncgraph), with some modifications to improve usability and fix the bugs of fetching arguments. 

Thanks for the original work!
