package main

import (
	"fmt"
	"time"
)

func main() {
	for {
		doSomething()
	}
}

func doSomething() {
	add(1, 2)
	minus(1, 2)

	s := &Student{"zhang", 100}
	fmt.Printf("student: %s\n", s)

	time.Sleep(time.Second)
}

//go:noinline
func add(a, b int) int {
	fmt.Printf("add: %d + %d\n", a, b)
	return add1(a, b)
}

//go:noinline
func add1(a, b int) int {
	fmt.Printf("add1: %d + %d\n", a, b)
	time.Sleep(time.Millisecond * 100)
	return add2(a, b)
}

// inline strategy and rules,
// see: https://github.com/golang/go/wiki/CompilerOptimizations#function-inlining
func add2(a, b int) int {
	//fmt.Printf("add2: %d + %d\n", a, b)
	time.Sleep(time.Millisecond * 200)
	return add3(a, b)
}

//go:noinline
func add3(a, b int) int {
	fmt.Printf("add3: %d + %d\n", a, b)
	time.Sleep(time.Millisecond * 300)
	return a + b
}

//go:noinline
func minus(a, b int) int {
	time.Sleep(time.Millisecond * 50)
	return a - b
}

type Student struct {
	name string
	age  int
}

//go:noinline
func (s *Student) String() string {
	if s == nil {
		return "<nil>"
	}
	time.Sleep(time.Millisecond * 10)
	return fmt.Sprintf("name: %s, age: %d", s.name, s.age)
}
