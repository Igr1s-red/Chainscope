# ---- builder ----
FROM golang:1.22-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm bpftool make ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Generate vmlinux.h from the host kernel BTF before building.
# When building inside a container this requires the builder to run with
# --privileged and a bind-mount of /sys/kernel/btf from the target host.
RUN bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h \
    && cd internal/loader && go generate \
    && cd /src && go build -o /chainscope ./cmd/chainscope/...

# ---- runtime ----
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /chainscope /usr/local/bin/chainscope

# Default policy — override by mounting /etc/chainscope/policy.yaml
COPY policy/default.yaml /etc/chainscope/policy.yaml

ENTRYPOINT ["/usr/local/bin/chainscope"]
CMD ["-policy", "/etc/chainscope/policy.yaml", "-metrics-addr", ":9090"]
