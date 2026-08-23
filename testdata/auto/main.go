// Package main is the auto-fetch fixture for go-ftrace.
//
// It gathers the argument, return-value, and interface layouts that
// automatic DWARF fetch is expected to cover: integers, bools, strings,
// slices, pointer receivers / Stringer methods, error, empty interface,
// fmt.Stringer as a parameter, and protobuf's proto.Message.
//
// testdata/args and testdata/rets remain the ABI cheatsheets for hand-written
// --fargs / --frets rules. This package is what unit tests compile.
//
// Build as a non-PIE, non-stripped binary with debug info preserved:
//
//	go build -gcflags 'all=-N -l' -ldflags '-linkmode=external -extldflags=-no-pie' -o main .
package main

import (
	"auto/pb"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"
)

func main() {
	stu := &Student{Name: "zhang", Age: 100}
	msg := &pb.HelloRequest{Msg: "hello world"}
	for {
		_ = add(1, 2)
		_ = greet("world")
		_ = stu.String()
		_ = sum([]int{1, 2, 3, 4, 5})
		_ = toggle(true)

		_ = makeGreeting("ftrace")
		_ = newStudent("lee", 20)
		_ = newStudentPtr("wang", 30)
		_ = mayFail(42)
		_, _ = divmod(17, 5)
		_ = send(true)
		_ = send(false)

		_ = stringify(stu)
		_ = handleError(nil)
		_ = handleError(errors.New("boom"))
		_ = wrapError(errors.New("boom"))
		printAny("hello")
		printAny(stu)

		data, _ := marshalMsg(msg)
		_ = unmarshalMsg(data, &pb.HelloRequest{})
		data2, _ := proto.Marshal(msg)
		_ = proto.Unmarshal(data2, &pb.HelloRequest{})

		time.Sleep(time.Second)
	}
}

type Student struct {
	Name string
	Age  int
}

type MeshErrorCode int

type MeshError struct {
	Code   MeshErrorCode
	Detail error
}

//go:noinline
func add(a, b int) int { return a + b }

//go:noinline
func greet(name string) string { return fmt.Sprintf("hello, %s", name) }

//go:noinline
func (s *Student) String() string {
	if s == nil {
		return "<nil>"
	}
	return fmt.Sprintf("name: %s, age: %d", s.Name, s.Age)
}

//go:noinline
func sum(nums []int) int {
	total := 0
	for _, n := range nums {
		total += n
	}
	return total
}

//go:noinline
func toggle(on bool) bool { return !on }

//go:noinline
func makeGreeting(name string) string { return "hello " + name }

//go:noinline
func newStudent(name string, age int) Student { return Student{Name: name, Age: age} }

//go:noinline
func newStudentPtr(name string, age int) *Student { return &Student{Name: name, Age: age} }

//go:noinline
func mayFail(code int) error {
	if code < 0 {
		return errors.New("negative code")
	}
	return nil
}

//go:noinline
func divmod(a, b int) (int, int) { return a / b, a % b }

//go:noinline
func send(ok bool) *MeshError {
	if !ok {
		return &MeshError{Code: 500, Detail: errors.New("send failed")}
	}
	return nil
}

// stringify takes fmt.Stringer as a named interface argument.
//
//go:noinline
func stringify(s fmt.Stringer) string {
	if s == nil {
		return "<nil>"
	}
	return s.String()
}

// handleError takes error as a named interface argument.
//
//go:noinline
func handleError(err error) bool { return err == nil }

// wrapError takes and returns error.
//
//go:noinline
func wrapError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("wrap: %w", err)
}

// printAny takes the empty interface (any / interface{}).
//
//go:noinline
func printAny(v any) { _ = v }

// unmarshalMsg mirrors proto.Unmarshal([]byte, proto.Message) error.
//
//go:noinline
func unmarshalMsg(b []byte, m proto.Message) error { return proto.Unmarshal(b, m) }

// marshalMsg mirrors proto.Marshal(proto.Message) ([]byte, error).
//
//go:noinline
func marshalMsg(m proto.Message) ([]byte, error) { return proto.Marshal(m) }
