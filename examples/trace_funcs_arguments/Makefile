all: main.go
	go build -o main main.go

trace_string:
	#../scripts/offsets.py --bin ./main --expr 'main.Student->name->str' : +0(_)
	#../scripts/offsets.py --bin ./main --expr 'main.Student->name->len' : +8(_)
	#../scripts/offsets.py --bin ./main --expr 'main.Student->age'       : +16(_)
	sudo ftrace -u 'main.(*Student).String' ./main 'main.(*Student).String(s.name=(*+0(%ax)):c64, s.name.len=(+8(%ax)):s64, s.age=(+16(%ax)):s64)' 

trace_buybook:
	sudo ftrace -u 'main.(*Student).BuyBook' ./main 'main.(*Student).BuyBook(s.book=(+0(%bx)):c128, s.book.len=(%cx):s64, s.num=(%di):s64)'

clean:
	rm -rf ./main

.PHONY: clean trace_string trace_buybook
