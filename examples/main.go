package main
import "time"
import "fmt"
import "os"

func main() {
	for {
		add(1,2)
		time.Sleep(time.Second)
		fmt.Println("pid:", os.Getpid())
	}
}

//go:noinline
func add(a, b int) int {
	return a+b
}
