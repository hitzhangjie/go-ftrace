package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -target native -type event -type arg_rules -type arg_rule -type arg_data -type sample_config -type trace_state -type runtime_stats -type type_recipe -type rel_rule Goftrace ./ftrace.c -- -I./headers
