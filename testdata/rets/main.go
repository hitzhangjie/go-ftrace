// Package main is a test fixture for go-ftrace.
//
// It exercises various Go return-value conventions so that the `--frets`
// fetch rules can be tested consistently across Go toolchain versions
// (e.g. go1.22, go1.26).
//
// Build as a non-PIE, non-stripped binary with debug info preserved:
//
//	go build -gcflags 'all=-N -l' -ldflags '-linkmode=external -extldflags=-no-pie' -o main main.go
//
// Return-value ABI (Go 1.17+, linux/amd64) quick reference:
//
//	results : AX, BX, CX, DI, SI, R8, R9, R10, R11
//	int/ptr : single word in AX
//	string  : two words -> data (AX), len (BX)
//	error   : interface -> itab (AX), data (BX)
package main

import (
	"errors"
	"time"
)

func main() {
	for {
		_ = add(3, 4)
		_ = makeGreeting("ftrace")
		_ = newStudent("lee", 20)
		_ = newStudentPtr("wang", 30)
		_ = mayFail(42)
		_, _ = divmod(17, 5)
		_ = send(true)
		_ = send(false)
		time.Sleep(time.Second)
	}
}

type Student struct {
	Name string
	Age  int
}

// MeshErrorCode is a user-defined int enum, mirroring a common real-world
// error-code field.
type MeshErrorCode int

// MeshError mirrors the layout of the struct in the motivating use case:
//
//	type MeshError struct {
//		Code   MeshErrorCode
//		Detail error
//	}
//
// Field offsets: Code at +0, Detail.itab at +8, Detail.data at +16.
type MeshError struct {
	Code   MeshErrorCode
	Detail error
}

// fetch: --frets 'main.add(result=(%ax):s64)'
//
//	result -> AX (single int result)
//
//go:noinline
func add(a, b int) int { return a + b }

// fetch: --frets 'main.makeGreeting(result.data=(%ax):u64, result.len=(%bx):s64)'
//
//	result.data -> AX (pointer), result.len -> BX (string = two words)
//
//go:noinline
func makeGreeting(name string) string { return "hello " + name }

// fetch: struct-valued results are passed back on the stack (Go ABI), not in
// registers, so register-based --frets rules do not apply here. Use the other
// fixtures in this package for return-value fetching.
//
//go:noinline
func newStudent(name string, age int) Student { return Student{Name: name, Age: age} }

// fetch: --frets 'main.newStudentPtr(ptr=(%ax):u64)'
//
//	ptr -> AX (*Student)
//
//go:noinline
func newStudentPtr(name string, age int) *Student { return &Student{Name: name, Age: age} }

// fetch: --frets 'main.mayFail(err.itab=(%ax):u64, err.data=(%bx):u64)'
//
//	error interface -> two words: itab (AX), data (BX)
//
//go:noinline
func mayFail(code int) error {
	if code < 0 {
		return errors.New("negative code")
	}
	return nil
}

// fetch: --frets 'main.divmod(quotient=(%ax):s64, remainder=(%bx):s64)'
//
//	quotient -> AX, remainder -> BX (multiple results)
//
//go:noinline
func divmod(a, b int) (int, int) { return a / b, a % b }

// fetch: --frets 'main.send(Code=(+0(%ax)):s64, Detail.itab=(+8(%ax)):u64, Detail.data=(+16(%ax)):u64)'
//
//	result -> AX (*MeshError). Code is a plain value at +0, so it is read
//	directly as (+0(%ax)); Detail.itab (+8) and Detail.data (+16) are also
//	plain values.
//
//go:noinline
func send(ok bool) *MeshError {
	if !ok {
		return &MeshError{Code: 500, Detail: errors.New("send failed")}
	}
	return nil
}
