// Package main is a test fixture for go-ftrace.
//
// It exercises a nested function call graph so that the function graph,
// timing statistics, and call-stack features can be tested consistently
// across Go toolchain versions (e.g. go1.22, go1.26).
//
// Build as a non-PIE, non-stripped binary with debug info preserved:
//
//	go build -gcflags 'all=-N -l' -ldflags '-linkmode=external -extldflags=-no-pie' -o main main.go
package main

import (
	"fmt"
	"time"
)

func main() {
	for {
		outer()
		time.Sleep(time.Second)
	}
}

//go:noinline
func outer() {
	a := inner1(10)
	b := inner2("hello")
	fmt.Println(a, b)
}

//go:noinline
func inner1(x int) int {
	return double(x)
}

//go:noinline
func double(x int) int {
	return x * 2
}

//go:noinline
func inner2(s string) string {
	return echo(s)
}

//go:noinline
func echo(s string) string {
	time.Sleep(time.Millisecond * 10)
	return s
}
