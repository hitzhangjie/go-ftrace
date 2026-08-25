# Warn: To load an ebpf program into the kernel requires special privileges,
# so the binary is installed to /usr/sbin owned by root with the setuid bit.
GO ?= go

build: internal/bpf/goftrace_bpfel_x86.go internal/bpf/goftrace_bpfel_x86.o
	cd cmd/ftrace && $(GO) build -v

# Regenerate the eBPF Go binding only when its C source or generator changes.
# Both the .go and .o are produced by bpf2go in one shot; the .go embeds the .o.
internal/bpf/goftrace_bpfel_x86.go internal/bpf/goftrace_bpfel_x86.o: internal/bpf/ftrace.c internal/bpf/gen.go internal/bpf/headers/*.h
	$(GO) generate ./...

# Build to a temporary file, then install into /usr/sbin in one step.
# This avoids `go install` leaving a duplicate copy in GOBIN.
#
# `sudo install` command does the same thing as the install target
#sudo chown root:root cmd/ftrace/ftrace
#sudo chmod u+s cmd/ftrace/ftrace
#sudo mv cmd/ftrace/ftrace /usr/sbin/ftrace
install: build
	sudo install -o root -g root -m 4755 cmd/ftrace/ftrace /usr/sbin/ftrace
	rm -f cmd/ftrace/ftrace

uninstall:
	sudo rm -f /usr/sbin/ftrace

clean:
	rm -f cmd/ftrace/ftrace

.PHONY: clean install
