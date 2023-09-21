# go-ftrace

go-ftrace is an eBPF(2)-based ftrace(1)-like function graph tracer for Golang processes.

**Limits: for now, only support following cases**
- OS: Linux, with support for bpf(2) and uprobe
- Arch: x86-64 little endian
- Binary: go ELF executable, non-stripped, built with non-PIE mode,
          ELF sections .symtab, .(z)debug_info are required

# Usage

```
   example: trace a specific function in etcd client "go.etcd.io/etcd/client/v3/concurrency.(*Mutex).tryAcquire"
     ftrace -u 'go.etcd.io/etcd/client/v3/concurrency.(*Mutex).tryAcquire' ./a.out

   example: trace all functions in etcd client
     ftrace -u 'go.etcd.io/etcd/client/v3/*' ./a.out

   example: trace a specific function and include runtime.chan* builtins
     ftrace -u 'go.etcd.io/etcd/client/v3/concurrency.(*Mutex).tryAcquire' 'runtime.chan*' ./a.out

   example: trace a specific function with some arguemnts
     ftrace -u 'go.etcd.io/etcd/client/v3/concurrency.(*Mutex).tryAcquire(pfx=+0(+8(%ax)):c512, n_pfx=+16(%ax):u64, m.s.id=16(0(%ax)):u64)' ./a.out
```

# Installation

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

# Use cases

- Wall time profiling;
- Execution flow observing;

# Acknowledgments

This repo is forked from [jschwinger233/gofuncgraph](https://github.com/jschwinger233/gofuncgraph), with some modifications to improve usability. 

Thanks for the original work!