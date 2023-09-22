package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target native -type event -type arg_rules -type arg_rule -type arg_data Goftrace ./ftrace.c -- -I./headers
