# Warn: 
# 1. To load ebpf program into kernel require special privileges, 
#    we just use `sudo` to do that.
# 2. You may modify and build ths tool again, so you may want to 
#    avoid copying the binary to /usr/sbin again and again, which
#    is searchable by `sudo`, so we use `ln -sf` to create a symbolic
#    link to ~/go/bin/ftrace instead.
all:
	cd cmd/ftrace && go build -v

install:
	cd cmd/ftrace && go install -v
	sudo ln -sf ~/go/bin/ftrace /usr/sbin
	sudo chmod u+s /usr/sbin/ftrace
