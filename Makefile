BINARY     := chainscope
CLANG      := clang
BPF_SRC    := bpf/chainscope.c
VMLINUX    := bpf/vmlinux.h
ARCH       := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/arm.*/arm/')

# Compiler flags for the eBPF C program
BPF_CFLAGS := -O2 -g -Wall -Werror \
              -target bpf \
              -D__TARGET_ARCH_$(ARCH) \
              -I./bpf

.PHONY: all clean generate build vmlinux lint

all: vmlinux generate build

# Generate vmlinux.h from the running kernel's BTF.
# Requires: bpftool   →  sudo apt install bpftool
#           clang/llvm →  sudo apt install clang llvm
vmlinux: $(VMLINUX)

$(VMLINUX):
	@if ! command -v bpftool >/dev/null 2>&1; then \
		echo "bpftool not found. Run: sudo apt install bpftool"; exit 1; fi
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# bpf2go compiles chainscope.c and generates Go bindings in internal/loader/.
# Requires: clang, llvm
generate: $(VMLINUX)
	cd internal/loader && go generate

# Build the userspace binary.
build:
	go build -o $(BINARY) ./cmd/chainscope/...

# Full rebuild from scratch (useful after kernel header changes).
clean:
	rm -f $(BINARY)
	rm -f internal/loader/chainscope_bpf*.go
	rm -f internal/loader/chainscope_bpf*.o
	rm -f $(VMLINUX)

lint:
	staticcheck ./...

# Quick check: verify the eBPF C compiles without full Go generation.
check-bpf: $(VMLINUX)
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_SRC) -o /dev/null

# Run as root (required for CAP_BPF)
run: $(BINARY)
	sudo ./$(BINARY) $(ARGS)

run-verbose: $(BINARY)
	sudo ./$(BINARY) -v $(ARGS)

run-json: $(BINARY)
	sudo ./$(BINARY) -json $(ARGS)
