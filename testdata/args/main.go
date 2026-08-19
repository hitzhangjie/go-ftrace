// Package main is a test fixture for go-ftrace.
//
// It exercises various Go argument-passing conventions so that the
// `--fargs` fetch rules can be tested consistently across Go toolchain
// versions (e.g. go1.22, go1.26).
//
// Build as a non-PIE, non-stripped binary with debug info preserved:
//
//	go build -gcflags 'all=-N -l' -ldflags '-linkmode=external -extldflags=-no-pie' -o main main.go
//
// Register-based ABI (Go 1.17+, linux/amd64) quick reference:
//
//	integer args : AX, BX, CX, DI, SI, R8, R9, R10, R11
//	string arg   : two words -> data (AX), len (BX)
//	slice arg    : three words -> data (AX), len (BX), cap (CX)
//	method       : receiver is the first argument (AX)
package main

import (
	"fmt"
	"time"
)

func main() {
	stu := &Student{Name: "zhang", Age: 100}
	for {
		_ = add(1, 2) // a -> AX, b -> BX
		_ = greet("world")
		_ = stu.String() // receiver -> AX
		_ = sum([]int{1, 2, 3, 4, 5})
		_ = toggle(true)
		time.Sleep(time.Second)
	}
}

type Student struct {
	Name string
	Age  int
}

// fetch: --fargs 'main.add(a=(%ax):s64, b=(%bx):s64)'
//
//	a -> AX, b -> BX (integer args, register ABI)
//
//go:noinline
func add(a, b int) int {
	return a + b
}

// fetch: --fargs 'main.greet(name.data=(+0(%ax)):c64, name.len=(%bx):s64)'
//
//	name.data -> AX (pointer), name.len -> BX (string = two words)
//
//go:noinline
func greet(name string) string {
	return fmt.Sprintf("hello, %s", name)
}

// fetch: --fargs 'main.(*Student).String(s.name.data=(*+0(%ax)):c64, s.name.len=(+8(%ax)):s64, s.age=(+16(%ax)):s64)'
//
//	receiver -> AX (*Student). String data is a pointer stored at +0, so it
//	needs an extra dereference (*+0(%ax)); len (+8) and age (+16) are plain
//	values read directly.
//
//go:noinline
func (s *Student) String() string {
	if s == nil {
		return "<nil>"
	}
	return fmt.Sprintf("name: %s, age: %d", s.Name, s.Age)
}

// fetch: --fargs 'main.sum(nums.data=(%ax):u64, nums.len=(%bx):s64, nums.cap=(%cx):s64)'
//
//	nums.data -> AX, nums.len -> BX, nums.cap -> CX (slice = three words)
//
//go:noinline
func sum(nums []int) int {
	total := 0
	for _, n := range nums {
		total += n
	}
	return total
}

// fetch: --fargs 'main.toggle(on=(%ax):u8)'
//
//	on -> AX (bool occupies one byte, AL)
//
//go:noinline
func toggle(on bool) bool {
	return !on
}
