package main

import (
	"fmt"
	"math/rand"
	"time"
)

func main() {
	for {
		s := &Student{"zhang", 100}
		fmt.Printf("student: %s\n", s)

		s.BuyBook("go-programming", rand.Int()%10)
		time.Sleep(time.Second)
	}
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

func (s *Student) BuyBook(name string, num int) {
	fmt.Printf("%s is buying %d <<%s>>\n", s.name, num, name)
}
