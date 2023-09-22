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

trace_studentparams:
	#../scripts/offsets.py --bin ./main --expr 'main.Student->name->str' : +0(_)
	#../scripts/offsets.py --bin ./main --expr 'main.Student->name->len' : +8(_)
	#../scripts/offsets.py --bin ./main --expr 'main.Student->age'       : +16(_)
	sudo ftrace -u 'main.(*Student).String' ./main 'main.(*Student).String(s.name=(*+0(%ax)):c64, s.name.len=(+8(%ax)):s64, s.age=(+16(%ax)):s64)' 

.PHONY: trace_add trace_alladd trace_alladdminus trace_student trace_studentparams
