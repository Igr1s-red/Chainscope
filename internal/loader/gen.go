package loader

// bpf2go generates chainscopeObjects and related types into this package.
// Run `make generate` (or `go generate`) before building.
//
// $GOARCH is set by `go generate` to the host architecture (e.g. amd64).
// bpf2go maps amd64 → -D__TARGET_ARCH_x86 so PT_REGS_PARM1 works in uprobes.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target $GOARCH chainscope ../../bpf/chainscope.c -- -O2 -g -Wall -I../../bpf
