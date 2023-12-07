all: main.go
	go build -o main main.go

trace_add:
	sudo ftrace -u main.add ./main

trace_addall:
	sudo ftrace -u main.add* ./main

trace_addminus:
	sudo ftrace -u main.add* -u main.minus* ./main

trace_student:
	sudo ftrace -u 'main.(*Student).String' ./main

clean:
	rm -f ./main

.PHONY: clean trace_add trace_addall trace_addminus trace_student
