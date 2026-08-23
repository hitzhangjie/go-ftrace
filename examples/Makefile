GO ?= go
BUILD_FLAGS := -gcflags 'all=-N -l' -ldflags '-linkmode=external -extldflags=-no-pie'

all:
	$(GO) build $(BUILD_FLAGS) -o main main.go

clean:
	rm -f ./main

.PHONY: all clean
