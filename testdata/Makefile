GO ?= go1.22.2

# Build fixtures as non-PIE, non-stripped binaries with the symbol table and
# debug info preserved. These are the requirements for go-ftrace to resolve
# symbols and attach uprobes. See README.md for details.
BUILD_FLAGS := -gcflags 'all=-N -l' -ldflags '-linkmode=external -extldflags=-no-pie'

FIXTURES := basic args rets auto

all: $(FIXTURES)

basic:
	cd basic && $(GO) build $(BUILD_FLAGS) -o main main.go

args:
	cd args && $(GO) build $(BUILD_FLAGS) -o main main.go

rets:
	cd rets && $(GO) build $(BUILD_FLAGS) -o main main.go

auto:
	cd auto && $(GO) build $(BUILD_FLAGS) -o main .

clean:
	rm -f basic/main args/main rets/main auto/main

.PHONY: all $(FIXTURES) clean
