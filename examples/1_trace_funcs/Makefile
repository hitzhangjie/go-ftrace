all: main.go
	go build -o main main.go

trace_add:
	sudo ftrace -u main.add ./main

trace_alladd:
	sudo ftrace -u main.add* ./main

trace_alladdminus:
	sudo ftrace -u main.add* -u main.minus* ./main

trace_student:
	sudo ftrace -u 'main.(*Student).String' ./main

clean:
	rm -f ./main

.PHONY: clean trace_add trace_alladd trace_alladdminus trace_student
