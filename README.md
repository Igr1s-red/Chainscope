# chainscope

eBPF-based supply chain security monitor for Linux.

Attaches to the kernel at runtime and tracks every process spawned by a package
manager (`pip`, `npm`, `cargo`, `apt`, …) and its build-tool descendants.
Every event is attributed to the originating package manager invocation
(**causal phase attribution**) — the thing that makes chainscope alerts
actionable rather than just noisy.

## What it detects

| Rule | Trigger | Severity |
|------|---------|----------|
| `ld-preload-injection` | `LD_PRELOAD` set when a child process is exec'd | CRITICAL |
| `shell-stdin-pipe` | Shell (`bash`, `sh`, …) exec'd with stdin connected to a pipe (curl\|bash) | CRITICAL |
| `execveat-anon` | `execveat(AT_EMPTY_PATH)` — execution from an anonymous `memfd` | CRITICAL |
| `compiler-network` | `gcc`/`clang`/`rustc`/`ld` opens a network connection | CRITICAL |
| `compiler-dns-lookup` | Compiler or linker calls `getaddrinfo` | CRITICAL |
| `bpf-prog-load` | `BPF_PROG_LOAD` from inside a tracked process | CRITICAL |
| `exec-from-temp` | Executable launched from `/tmp`, `/dev/shm`, `/var/tmp`, `/run` | HIGH |
| `ld-library-path-redirect` | `LD_LIBRARY_PATH` set at exec time | HIGH |
| `credential-in-env` | `AWS_ACCESS_KEY_ID`, `GITHUB_TOKEN`, `NPM_TOKEN`, … set at exec time | HIGH |
| `sensitive-file-read` | Build script reads `~/.ssh/`, `~/.aws/`, `.env`, `/etc/shadow`, … | HIGH |
| `build-writes-system-path` | Compiler/build tool writes to `/usr/bin`, `/etc`, … | HIGH |
| `chmod-suid-sgid` | `chmod` sets SUID or SGID bits | CRITICAL / HIGH |
| `chmod-exec-bit` | `chmod` sets execute bits | MEDIUM |
| `postinst-writes-system-path` | Post-install script writes to system paths | HIGH |
| `memfd-create` | Anonymous in-memory file created (fileless staging) | HIGH |
| `unknown-network` | Connection to IP not in the policy allow-list | MEDIUM / HIGH |
| `unexpected-phase-network` | Connection to a known registry from wrong phase | LOW |
| `baseline-deviation` | Any behavior not seen during a reference (learn-mode) run | MEDIUM |

## Requirements

- Linux kernel **5.8+** with BTF enabled (`/sys/kernel/btf/vmlinux` must exist)
- `CAP_BPF` + `CAP_PERFMON`, or run as **root**
- Build: `clang`, `llvm`, `bpftool`, Go ≥ 1.22

```
sudo apt install clang llvm bpftool
```

## Build

```bash
make           # vmlinux → generate → build (full)
make vmlinux   # regenerate bpf/vmlinux.h from running kernel BTF
make generate  # recompile BPF C and regenerate Go bindings
make build     # compile the Go binary only
make clean     # remove binary and generated files
```

The compiled binary is `./chainscope`.

## Usage

### Monitor mode (default)

```bash
sudo ./chainscope
sudo ./chainscope -v                              # verbose: print all events, not just alerts
sudo ./chainscope -json                           # newline-delimited JSON output
sudo ./chainscope -policy policy/default.yaml    # load registry allow-list
```

Ctrl+C to stop.

### CI mode

Wrap a build command; chainscope exits non-zero if any HIGH+ alert fires:

```bash
sudo ./chainscope ci -- pip install -r requirements.txt
sudo ./chainscope ci -policy policy/default.yaml -min-sev critical -- npm ci
sudo ./chainscope ci -json -- cargo build --release
```

Flags before `--` apply to chainscope; everything after `--` is the monitored
command. The command's stdout/stderr pass through unchanged; chainscope's own
alerts go to stderr.

Exit codes:
- `0` — command succeeded, no alerts at or above `--min-sev` (default: `high`)
- `1` — one or more security alerts triggered
- command's own exit code — if the command failed but no security alerts fired

### Baseline / enforce mode

**Learn** a reference profile during a known-good install:

```bash
sudo ./chainscope --learn baseline.json -- # then run your install manually, Ctrl+C when done
# or:
sudo ./chainscope --learn baseline.json &
pip install my-package
kill %1   # sends SIGTERM → profile is saved
```

**Enforce** the profile on subsequent runs:

```bash
sudo ./chainscope --enforce baseline.json -v
```

Any behaviour not seen during the learn run triggers a `baseline-deviation`
(MEDIUM) alert.

## Policy file

`policy/default.yaml` contains IP CIDRs for known-good package registries.
Connections to these IPs during `download`/`install` phases are suppressed;
connections from other phases produce LOW alerts; connections to unknown IPs
produce MEDIUM or HIGH alerts.

```yaml
registries:
  pypi:
    name: "PyPI"
    cidrs:
      - "151.101.0.0/16"    # Fastly CDN
      - "146.75.0.0/16"
  npm:
    name: "npm registry"
    cidrs:
      - "104.16.0.0/13"     # Cloudflare
      - "172.64.0.0/13"
  # … cargo, rubygems, debian_apt, kali_apt, ubuntu_apt
```

Pass it with `-policy policy/default.yaml`. Without a policy file, all network
connections from tracked processes produce alerts.

## Output

### Text (default)

```
[07:12:03.441 CRITICAL] pip (phase=download) opened network connection to 151.101.64.1:443 — compilers must not make network calls. Chain: pip(1234)
[07:12:04.112 HIGH]     gcc (phase=compile) read sensitive path "/root/.ssh/id_rsa". Chain: pip(1234) → make(1301) → gcc(1389)
[07:12:05.009 CRITICAL] bash executed with piped stdin — possible curl|bash attack. Chain: pip(1234) → postinst.sh(1422) → bash(1430)
```

Colours: red = CRITICAL/HIGH, yellow = MEDIUM, cyan = LOW/INFO.

### JSON (`-json`)

```json
{"time":"2026-05-22T07:12:03Z","rule":"compiler-network","severity":"critical","pid":1389,"comm":"gcc","root_comm":"pip","phase":"compile","description":"..."}
```

Pipe to `jq` for filtering:

```bash
sudo ./chainscope -json | jq 'select(.severity == "critical")'
```

## Architecture

```
┌─────────────────── kernel space ──────────────────────────────┐
│                                                               │
│  sys_enter_execve ──► trace_execve                            │
│    argv capture, LD_PRELOAD scan, stdin-pipe check,           │
│    exec-from-temp                                             │
│                                                               │
│  sys_exit_execve ───► trace_execve_exit  (restore on failure) │
│  sched_process_exit ► trace_exit         (clean up proc_tree) │
│  sys_enter_openat ──► trace_openat       (cred reads, writes) │
│  sys_enter_connect ─► trace_connect      (IPv4 + IPv6)        │
│  sys_enter_memfd_create ► trace_memfd_create                  │
│  sys_enter_execveat ──► trace_execveat   (AT_EMPTY_PATH)      │
│  sys_enter_fchmodat ──► trace_fchmodat   (chmod)              │
│  sys_enter_bpf ────────► trace_bpf       (BPF_PROG_LOAD)      │
│  uprobe:libc:getaddrinfo ► trace_getaddrinfo  (DNS)           │
│                                                               │
│  Maps: proc_tree (pid→proc_info), saved_execs, events ringbuf │
└──────────────────────────────────────────┬────────────────────┘
                                           │ ring buffer
┌──────────────────── userspace ───────────▼────────────────────┐
│  loader   — attaches hooks, reads ring buffer                 │
│  proctree — userspace process ancestry cache                  │
│  detector — all alert rules (no kernel recompile needed)      │
│  policy   — registry CIDR allow-list                          │
│  baseline — learn/enforce profile (JSON)                      │
│  output   — coloured text or newline-delimited JSON           │
└───────────────────────────────────────────────────────────────┘
```

### Phase attribution

Every event carries a `phase` tag derived from the basename of the executing
process:

| Phase | Processes |
|-------|-----------|
| `download` | pip, npm, yarn, cargo, gem, apt, dpkg |
| `build` | make, cmake, ninja, meson, setup.py |
| `compile` | gcc, g++, clang, rustc |
| `link` | ld, lld, gold |
| `install` | (child of a package manager in install stage) |
| `postinstall` | postinst scripts |

Children inherit their parent's phase unless they themselves match a known tool.

### BPF stack discipline

The 512-byte BPF stack limit is managed carefully:

- `argv` capture uses `#pragma unroll` over 8 fixed-stride (12-byte) slots,
  writing directly into the ring buffer reservation at compile-time-constant
  offsets — no stack allocation.
- `envp` scanning uses a `BPF_MAP_TYPE_PERCPU_ARRAY` scratch map (32 bytes)
  instead of a stack buffer, freeing ~32 bytes of stack headroom.
- `emit()` calls `__builtin_memset(evt, 0, sizeof(*evt))` on the ring buffer
  slot before populating it, so unrelated fields are always zero-clean.

## Extending

**Add a new detection rule** — edit `internal/detector/detector.go`:
```go
case types.EvtFileOpen:
    alerts = append(alerts, d.checkFileRead(evt)...)
    alerts = append(alerts, d.checkMyNewRule(evt)...)   // ← add here
```
No kernel recompilation needed.

**Add a new BPF hook** — three steps:
1. Write `SEC("tracepoint/syscalls/sys_enter_foo") int trace_foo(…)` in `bpf/chainscope.c`
2. Add a new constant to `bpf/chainscope.h` and `internal/types/types.go`
3. Attach the hook in `internal/loader/loader.go` and run `make generate && make build`

## Files

```
chainscope/
├── bpf/
│   ├── chainscope.h        # shared C/Go event struct + constants (520 bytes)
│   └── chainscope.c        # all eBPF programs (tracepoints + uprobe)
├── internal/
│   ├── loader/
│   │   ├── gen.go          # //go:generate bpf2go directive
│   │   └── loader.go       # loads BPF, attaches hooks, SeedPID for CI mode
│   ├── types/types.go      # Go mirror of chain_event + all constants
│   ├── detector/detector.go# all alert rules
│   ├── baseline/baseline.go# learn/enforce profile
│   ├── output/output.go    # coloured text + JSON formatting
│   ├── policy/policy.go    # YAML registry allow-list
│   └── proctree/proctree.go# userspace ancestry cache
├── cmd/chainscope/main.go  # CLI: monitor / ci / --learn / --enforce
├── policy/default.yaml     # bundled registry CIDR allow-list
└── Makefile
```
