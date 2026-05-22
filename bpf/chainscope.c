// SPDX-License-Identifier: GPL-2.0
//
// chainscope — supply chain security monitor
//
// Tracks all processes spawned by package managers and their build-tool
// descendants, flagging:
//   - compiler/linker making network connections
//   - install scripts reading credentials or SSH keys
//   - writes to system binary paths from unexpected phases
//   - fileless execution (memfd_create + execveat AT_EMPTY_PATH)
//   - argv + LD_PRELOAD capture at execve
//   - exec from /tmp, /dev/shm (dropper detection)
//   - pipe stdin to shell (curl|bash detection)
//   - chmod setting exec/SUID bits
//   - DNS hostname lookups (getaddrinfo uprobe)
//   - BPF program loads from inside tracked processes

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "chainscope.h"

char LICENSE[] SEC("license") = "GPL";

// ---------------------------------------------------------------------------
// Maps
// ---------------------------------------------------------------------------

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key,   __u32);
	__type(value, struct proc_info);
} proc_tree SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key,   __u32);
	__type(value, struct proc_info);
} saved_execs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18); // 256 KB
} events SEC(".maps");

// Per-CPU scratch buffer for envp key scanning.
// trace_execve already uses ~300 bytes of BPF stack (fname[256] + proc_info).
// Allocating another 32-byte key buffer on-stack would push us close to the
// 512-byte hard limit. PERCPU_ARRAY gives per-CPU heap memory instead.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key,   __u32);
	__type(value, char[32]);
} env_scratch SEC(".maps");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static __always_inline __u32 get_ppid(void)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	return BPF_CORE_READ(task, real_parent, tgid);
}

static __always_inline __u8 phase_from_comm(const char *c)
{
	// Package managers → DOWNLOAD
	if (c[0]=='p' && c[1]=='i' && c[2]=='p')
		return PHASE_DOWNLOAD; // pip, pip3, pipenv, pipx…
	if (c[0]=='n' && c[1]=='p' && c[2]=='m' && c[3]==0)
		return PHASE_DOWNLOAD;
	if (c[0]=='y' && c[1]=='a' && c[2]=='r' && c[3]=='n' && c[4]==0)
		return PHASE_DOWNLOAD;
	if (c[0]=='p' && c[1]=='n' && c[2]=='p' && c[3]=='m' && c[4]==0)
		return PHASE_DOWNLOAD;
	if (c[0]=='c' && c[1]=='a' && c[2]=='r' && c[3]=='g' && c[4]=='o' && c[5]==0)
		return PHASE_DOWNLOAD;
	if (c[0]=='g' && c[1]=='e' && c[2]=='m' && c[3]==0)
		return PHASE_DOWNLOAD;
	if (c[0]=='a' && c[1]=='p' && c[2]=='t')
		return PHASE_DOWNLOAD; // apt, apt-get
	if (c[0]=='d' && c[1]=='p' && c[2]=='k' && c[3]=='g')
		return PHASE_DOWNLOAD;

	// Build systems → BUILD
	if (c[0]=='m' && c[1]=='a' && c[2]=='k' && c[3]=='e' && c[4]==0)
		return PHASE_BUILD;
	if (c[0]=='c' && c[1]=='m' && c[2]=='a' && c[3]=='k' && c[4]=='e')
		return PHASE_BUILD;
	if (c[0]=='n' && c[1]=='i' && c[2]=='n' && c[3]=='j' && c[4]=='a')
		return PHASE_BUILD;
	if (c[0]=='m' && c[1]=='e' && c[2]=='s' && c[3]=='o' && c[4]=='n')
		return PHASE_BUILD;
	if (c[0]=='s' && c[1]=='e' && c[2]=='t' && c[3]=='u' && c[4]=='p' && c[5]=='.')
		return PHASE_BUILD; // setup.py

	// Compilers → COMPILE
	if (c[0]=='g' && c[1]=='c' && c[2]=='c' && c[3]==0)
		return PHASE_COMPILE;
	if (c[0]=='g' && c[1]=='+' && c[2]=='+' && c[3]==0)
		return PHASE_COMPILE;
	if (c[0]=='c' && c[1]=='c' && c[2]=='1' && c[3]==0)
		return PHASE_COMPILE;
	if (c[0]=='c' && c[1]=='l' && c[2]=='a' && c[3]=='n' && c[4]=='g')
		return PHASE_COMPILE; // clang, clang++
	if (c[0]=='r' && c[1]=='u' && c[2]=='s' && c[3]=='t' && c[4]=='c')
		return PHASE_COMPILE;

	// Linkers → LINK
	if (c[0]=='l' && c[1]=='d' && c[2]==0)
		return PHASE_LINK;
	if (c[0]=='l' && c[1]=='l' && c[2]=='d' && c[3]==0)
		return PHASE_LINK;
	if (c[0]=='g' && c[1]=='o' && c[2]=='l' && c[3]=='d' && c[4]==0)
		return PHASE_LINK;

	// Postinst scripts → POSTINST
	if (c[0]=='p' && c[1]=='o' && c[2]=='s' && c[3]=='t' && c[4]=='i' && c[5]=='n' && c[6]=='s' && c[7]=='t')
		return PHASE_POSTINST;

	return PHASE_UNKNOWN;
}

static __always_inline const char *basename_of(char *buf, int len)
{
	int last = 0;
	for (int i = 0; i < len; i++) {
		if (buf[i] == 0)
			break;
		if (buf[i] == '/')
			last = i + 1;
	}
	return buf + last;
}

static __always_inline bool is_install_path(const char *p)
{
	if (p[0] != '/')
		return false;
	if (p[1]=='u' && p[2]=='s' && p[3]=='r' && p[4]=='/')
		return true;
	if (p[1]=='b' && p[2]=='i' && p[3]=='n' && p[4]=='/')
		return true;
	if (p[1]=='s' && p[2]=='b' && p[3]=='i' && p[4]=='n')
		return true;
	if (p[1]=='e' && p[2]=='t' && p[3]=='c' && p[4]=='/')
		return true;
	return false;
}

static __always_inline bool is_sensitive_read_path(const char *p)
{
	if (p[0]=='/' && p[1]=='e' && p[2]=='t' && p[3]=='c' && p[4]=='/') {
		if (p[5]=='s' && p[6]=='h' && p[7]=='a' && p[8]=='d' && p[9]=='o' && p[10]=='w')
			return true;
		if (p[5]=='p' && p[6]=='a' && p[7]=='s' && p[8]=='s' && p[9]=='w')
			return true;
	}
	if (p[0]=='/' && p[1]=='r' && p[2]=='o' && p[3]=='o' && p[4]=='t' && p[5]=='/' && p[6]=='.')
		return true;

	for (int i = 1; i < 192; i++) {
		if (p[i] == 0)
			break;
		if (p[i-1] == '/' && p[i] == '.') {
			if (p[i+1]=='s' && p[i+2]=='s' && p[i+3]=='h' && p[i+4]=='/')
				return true;
			if (p[i+1]=='a' && p[i+2]=='w' && p[i+3]=='s')
				return true;
			if (p[i+1]=='g' && p[i+2]=='n' && p[i+3]=='u' && p[i+4]=='p' && p[i+5]=='g')
				return true;
			if (p[i+1]=='e' && p[i+2]=='n' && p[i+3]=='v' && (p[i+4]==0 || p[i+4]=='/'))
				return true;
		}
	}
	return false;
}

// Returns true if path is a writable temp/scratch filesystem.
static __always_inline bool is_temp_path(const char *p)
{
	if (p[0] != '/')
		return false;
	if (p[1]=='t' && p[2]=='m' && p[3]=='p' && p[4]=='/')
		return true;
	if (p[1]=='d' && p[2]=='e' && p[3]=='v' && p[4]=='/' &&
	    p[5]=='s' && p[6]=='h' && p[7]=='m')
		return true;
	if (p[1]=='v' && p[2]=='a' && p[3]=='r' && p[4]=='/' &&
	    p[5]=='t' && p[6]=='m' && p[7]=='p')
		return true;
	if (p[1]=='r' && p[2]=='u' && p[3]=='n' && p[4]=='/')
		return true;
	return false;
}

// Returns true if basename is a known Unix shell.
static __always_inline bool is_shell_comm(const char *c)
{
	if (c[0]=='s' && c[1]=='h' && c[2]==0) return true;
	if (c[0]=='b' && c[1]=='a' && c[2]=='s' && c[3]=='h' && c[4]==0) return true;
	if (c[0]=='d' && c[1]=='a' && c[2]=='s' && c[3]=='h' && c[4]==0) return true;
	if (c[0]=='z' && c[1]=='s' && c[2]=='h' && c[3]==0) return true;
	if (c[0]=='f' && c[1]=='i' && c[2]=='s' && c[3]=='h' && c[4]==0) return true;
	if (c[0]=='k' && c[1]=='s' && c[2]=='h' && c[3]==0) return true;
	if (c[0]=='c' && c[1]=='s' && c[2]=='h' && c[3]==0) return true;
	return false;
}

// Checks whether fd 0 of the current task is a FIFO/pipe (S_ISFIFO).
// Uses CO-RE to walk task_struct → files → fdt → fd[0] → inode → i_mode.
static __always_inline bool stdin_is_pipe(void)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct files_struct *files = BPF_CORE_READ(task, files);
	if (!files)
		return false;
	struct fdtable *fdt = BPF_CORE_READ(files, fdt);
	if (!fdt)
		return false;
	struct file **fd_arr = BPF_CORE_READ(fdt, fd);
	if (!fd_arr)
		return false;
	struct file *f = NULL;
	if (bpf_core_read(&f, sizeof(f), &fd_arr[0]) || !f)
		return false;
	struct inode *inode = BPF_CORE_READ(f, f_inode);
	if (!inode)
		return false;
	umode_t mode = BPF_CORE_READ(inode, i_mode);
	return (mode & 0xF000) == 0x1000; // S_ISFIFO
}

// Scans up to 32 bytes of an env variable key for known sensitive patterns.
// Returns ENV_FLAG_* bits to OR into env_flags.
static __always_inline __u32 check_env_flags(const char *e)
{
	__u32 flags = 0;

	// LD_PRELOAD=
	if (e[0]=='L' && e[1]=='D' && e[2]=='_' &&
	    e[3]=='P' && e[4]=='R' && e[5]=='E' && e[6]=='L' &&
	    e[7]=='O' && e[8]=='A' && e[9]=='D' && e[10]=='=')
		flags |= ENV_FLAG_LD_PRELOAD;

	// LD_LIBRARY_PATH=
	if (e[0]=='L' && e[1]=='D' && e[2]=='_' &&
	    e[3]=='L' && e[4]=='I' && e[5]=='B' && e[6]=='R' &&
	    e[7]=='A' && e[8]=='R' && e[9]=='Y')
		flags |= ENV_FLAG_LD_LIBRARY;

	// AWS_ACCESS_KEY_ID=
	if (e[0]=='A' && e[1]=='W' && e[2]=='S' && e[3]=='_' &&
	    e[4]=='A' && e[5]=='C' && e[6]=='C' && e[7]=='E' && e[8]=='S' && e[9]=='S')
		flags |= ENV_FLAG_AWS_KEY;

	// GITHUB_TOKEN=
	if (e[0]=='G' && e[1]=='I' && e[2]=='T' && e[3]=='H' && e[4]=='U' &&
	    e[5]=='B' && e[6]=='_' && e[7]=='T' && e[8]=='O' && e[9]=='K' &&
	    e[10]=='E' && e[11]=='N' && e[12]=='=')
		flags |= ENV_FLAG_GIT_TOKEN;

	// NPM_TOKEN=
	if (e[0]=='N' && e[1]=='P' && e[2]=='M' && e[3]=='_' &&
	    e[4]=='T' && e[5]=='O' && e[6]=='K' && e[7]=='E' && e[8]=='N' && e[9]=='=')
		flags |= ENV_FLAG_NPM_TOKEN;

	// PYPI_TOKEN=
	if (e[0]=='P' && e[1]=='Y' && e[2]=='P' && e[3]=='I' && e[4]=='_' &&
	    e[5]=='T' && e[6]=='O' && e[7]=='K' && e[8]=='E' && e[9]=='N' && e[10]=='=')
		flags |= ENV_FLAG_PYPI_TOKEN;

	// CARGO_REGISTRY_TOKEN (check first 9 chars to stay within 32-byte buf)
	if (e[0]=='C' && e[1]=='A' && e[2]=='R' && e[3]=='G' && e[4]=='O' &&
	    e[5]=='_' && e[6]=='R' && e[7]=='E' && e[8]=='G')
		flags |= ENV_FLAG_CARGO_TOKEN;

	// Generic: scan key bytes for "SECRET", "PASSWD" before '='
	for (int i = 0; i < 26; i++) {
		if (e[i] == '=' || e[i] == 0)
			break;
		if (e[i]=='S' && e[i+1]=='E' && e[i+2]=='C' && e[i+3]=='R' && e[i+4]=='E' && e[i+5]=='T')
			flags |= ENV_FLAG_GENERIC_SEC;
		if (e[i]=='P' && e[i+1]=='A' && e[i+2]=='S' && e[i+3]=='S' && e[i+4]=='W')
			flags |= ENV_FLAG_GENERIC_SEC;
	}

	return flags;
}

// Ring buffer reservations are NOT zeroed by the kernel, so any field we
// don't explicitly set contains stale data from previous allocations.
// Zero the full struct upfront rather than zeroing each unused field per
// handler — cleaner and the verifier can prove all offsets are in-bounds
// because it knows the reservation is exactly sizeof(struct chain_event).
static __always_inline void zero_event(struct chain_event *evt)
{
	__builtin_memset(evt, 0, sizeof(*evt));
}

static __always_inline void emit(struct chain_event *evt, __u8 type, __u8 phase,
				 __u8 severity, __u32 pid, __u32 ppid,
				 struct proc_info *info)
{
	zero_event(evt);
	evt->timestamp  = bpf_ktime_get_ns();
	evt->pid        = pid;
	evt->ppid       = ppid;
	evt->root_pid   = info->root_pid;
	evt->event_type = type;
	evt->phase      = phase;
	evt->severity   = severity;
	__builtin_memcpy(evt->comm,      info->comm,      TASK_COMM_LEN);
	__builtin_memcpy(evt->root_comm, info->root_comm, TASK_COMM_LEN);
}

// ---------------------------------------------------------------------------
// Process tracking: sys_enter_execve + sys_exit_execve
// ---------------------------------------------------------------------------

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
	__u32 pid  = bpf_get_current_pid_tgid() >> 32;
	__u32 ppid = get_ppid();

	char fname[PATH_LEN] = {};
	bpf_probe_read_user_str(fname, sizeof(fname), (const char *)ctx->args[0]);
	const char *base = basename_of(fname, sizeof(fname));

	struct proc_info *parent = bpf_map_lookup_elem(&proc_tree, &ppid);
	__u8 own_phase = phase_from_comm(base);

	// Early exit: only track processes that are either descendants of a known
	// package manager (parent in proc_tree) OR are themselves a known tool
	// (own_phase != UNKNOWN). This keeps the proc_tree small and avoids
	// emitting events for the 99% of system activity we don't care about.
	if (!parent && own_phase == PHASE_UNKNOWN)
		return 0;

	// Save any existing entry so sys_exit_execve can restore on failure.
	struct proc_info *existing = bpf_map_lookup_elem(&proc_tree, &pid);
	if (existing)
		bpf_map_update_elem(&saved_execs, &pid, existing, BPF_ANY);

	struct proc_info info = {};
	info.ppid = ppid;

	if (parent) {
		info.root_pid = parent->root_pid;
		info.phase    = (own_phase != PHASE_UNKNOWN) ? own_phase : parent->phase;
		__builtin_memcpy(info.root_comm, parent->root_comm, TASK_COMM_LEN);
	} else {
		info.root_pid = pid;
		info.phase    = own_phase;
		__builtin_memcpy(info.root_comm, base, TASK_COMM_LEN);
	}
	__builtin_memcpy(info.comm, base, TASK_COMM_LEN);
	bpf_map_update_elem(&proc_tree, &pid, &info, BPF_ANY);

	struct chain_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	emit(evt, EVT_EXEC, info.phase, SEV_INFO, pid, ppid, &info);
	__builtin_memcpy(evt->path, fname, sizeof(evt->path));

	// Exec-from-temp and shell/stdin-pipe detection.
	__u32 exec_flags = 0;
	if (is_temp_path(fname))
		exec_flags |= EXEC_FLAG_TEMP_PATH;
	if (is_shell_comm(base)) {
		exec_flags |= EXEC_FLAG_IS_SHELL;
		if (stdin_is_pipe())
			exec_flags |= EXEC_FLAG_STDIN_PIPE;
	}
	evt->exec_flags = exec_flags;

	// Capture argv[1..MAX_ARGV_ARGS] directly into evt->argv at fixed strides.
	// #pragma unroll ensures each access uses a compile-time-constant offset,
	// keeping the BPF verifier happy.
	const char * const *argv_ptr = (const char * const *)ctx->args[1];
	#pragma unroll
	for (int i = 0; i < MAX_ARGV_ARGS; i++) {
		const char *arg = NULL;
		if (bpf_probe_read_user(&arg, sizeof(arg), &argv_ptr[i + 1]) || !arg)
			break;
		bpf_probe_read_user_str(evt->argv + i * ARGV_STRIDE, ARGV_STRIDE, arg);
	}

	// Scan envp for sensitive keys using per-CPU scratch to avoid stack pressure.
	__u32 env_flags = 0;
	__u32 zero = 0;
	char *ekbuf = bpf_map_lookup_elem(&env_scratch, &zero);
	if (ekbuf) {
		const char * const *envp_ptr = (const char * const *)ctx->args[2];
		for (int i = 0; i < 32; i++) {
			const char *ep = NULL;
			if (bpf_probe_read_user(&ep, sizeof(ep), &envp_ptr[i]) || !ep)
				break;
			__builtin_memset(ekbuf, 0, 32);
			bpf_probe_read_user_str(ekbuf, 32, ep);
			env_flags |= check_env_flags(ekbuf);
		}
	}
	evt->env_flags = env_flags;

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

// sys_exit_execve: repair proc_tree when execve fails.
//
// trace_execve speculatively updates proc_tree at entry before knowing whether
// execve will succeed. On failure (ret < 0) the process image is unchanged, so
// we must restore the pre-exec entry. Without this, a failed exec of "gcc"
// would leave the process permanently classified as PHASE_COMPILE even though
// it's still running as whatever it was before.
SEC("tracepoint/syscalls/sys_exit_execve")
int trace_execve_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	if (ctx->ret == 0) {
		// Success: image replaced, speculative entry is now correct.
		bpf_map_delete_elem(&saved_execs, &pid);
		return 0;
	}

	// Failure: restore pre-exec state, or remove the speculative entry entirely
	// if this process wasn't tracked before the failed exec attempt.
	struct proc_info *saved = bpf_map_lookup_elem(&saved_execs, &pid);
	if (saved)
		bpf_map_update_elem(&proc_tree, &pid, saved, BPF_ANY);
	else
		bpf_map_delete_elem(&proc_tree, &pid);

	bpf_map_delete_elem(&saved_execs, &pid);
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_exit(struct trace_event_raw_sched_process_template *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	bpf_map_delete_elem(&proc_tree, &pid);
	bpf_map_delete_elem(&saved_execs, &pid);
	return 0;
}

// ---------------------------------------------------------------------------
// File access: openat for credential reads and install-path writes
// ---------------------------------------------------------------------------

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct proc_info *info = bpf_map_lookup_elem(&proc_tree, &pid);
	if (!info)
		return 0;

	char path[PATH_LEN] = {};
	bpf_probe_read_user_str(path, sizeof(path), (const char *)ctx->args[1]);
	__s32 flags = (__s32)ctx->args[2];

	bool is_write = (flags & O_ACCMODE) != O_RDONLY;

	__u8 evt_type, sev;
	if (is_write && is_install_path(path)) {
		evt_type = EVT_FILE_WRITE;
		sev = (info->phase == PHASE_INSTALL) ? SEV_LOW : SEV_MEDIUM;
		if (info->phase == PHASE_COMPILE || info->phase == PHASE_BUILD)
			sev = SEV_HIGH;
	} else if (!is_write && is_sensitive_read_path(path)) {
		evt_type = EVT_FILE_OPEN;
		sev = SEV_INFO;
	} else {
		return 0;
	}

	struct chain_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	__u32 ppid = get_ppid();
	emit(evt, evt_type, info->phase, sev, pid, ppid, info);
	__builtin_memcpy(evt->path, path, PATH_LEN);
	evt->open_flags = flags;
	bpf_ringbuf_submit(evt, 0);
	return 0;
}

// ---------------------------------------------------------------------------
// Network: IPv4 and IPv6 connections
// ---------------------------------------------------------------------------

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct proc_info *info = bpf_map_lookup_elem(&proc_tree, &pid);
	if (!info)
		return 0;

	__u16 family = 0;
	bpf_probe_read_user(&family, sizeof(family), (void *)ctx->args[1]);
	if (family != AF_INET && family != AF_INET6)
		return 0;

	__u8 sev = SEV_INFO;
	if (info->phase == PHASE_COMPILE || info->phase == PHASE_LINK)
		sev = SEV_CRITICAL;

	struct chain_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	__u32 ppid = get_ppid();
	emit(evt, EVT_NET_CONNECT, info->phase, sev, pid, ppid, info);

	if (family == AF_INET) {
		struct sockaddr_in sa4 = {};
		bpf_probe_read_user(&sa4, sizeof(sa4), (void *)ctx->args[1]);
		__builtin_memcpy(evt->daddr, &sa4.sin_addr.s_addr, 4);
		evt->dport   = __builtin_bswap16(sa4.sin_port);
		evt->proto   = IPPROTO_TCP;
		evt->is_ipv6 = 0;
	} else {
		struct sockaddr_in6 sa6 = {};
		bpf_probe_read_user(&sa6, sizeof(sa6), (void *)ctx->args[1]);
		__builtin_memcpy(evt->daddr, sa6.sin6_addr.in6_u.u6_addr8, 16);
		evt->dport   = __builtin_bswap16(sa6.sin6_port);
		evt->proto   = IPPROTO_TCP;
		evt->is_ipv6 = 1;
	}

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

// ---------------------------------------------------------------------------
// Fileless execution detection
// ---------------------------------------------------------------------------

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int trace_memfd_create(struct trace_event_raw_sys_enter *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct proc_info *info = bpf_map_lookup_elem(&proc_tree, &pid);
	if (!info)
		return 0;

	struct chain_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	__u32 ppid = get_ppid();
	emit(evt, EVT_MEMFD_CREATE, info->phase, SEV_HIGH, pid, ppid, info);
	bpf_probe_read_user_str(evt->memfd_name, sizeof(evt->memfd_name),
				(const char *)ctx->args[0]);
	evt->memfd_flags = (__u32)ctx->args[1];
	bpf_ringbuf_submit(evt, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int trace_execveat(struct trace_event_raw_sys_enter *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct proc_info *info = bpf_map_lookup_elem(&proc_tree, &pid);
	if (!info)
		return 0;

	if (!((int)ctx->args[4] & AT_EMPTY_PATH))
		return 0;

	struct chain_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	__u32 ppid = get_ppid();
	emit(evt, EVT_EXECVEAT, info->phase, SEV_CRITICAL, pid, ppid, info);
	bpf_ringbuf_submit(evt, 0);
	return 0;
}

// ---------------------------------------------------------------------------
// chmod: detect SUID/SGID or exec-bit changes
// ---------------------------------------------------------------------------

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int trace_fchmodat(struct trace_event_raw_sys_enter *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct proc_info *info = bpf_map_lookup_elem(&proc_tree, &pid);
	if (!info)
		return 0;

	__u32 mode = (__u32)ctx->args[2];
	// Only track SUID/SGID bits or any exec bit.
	if (!((mode & 06000) || (mode & 0111)))
		return 0;

	char path[PATH_LEN] = {};
	bpf_probe_read_user_str(path, sizeof(path), (const char *)ctx->args[1]);

	struct chain_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	__u32 ppid = get_ppid();
	__u8 sev = is_install_path(path) ? SEV_HIGH : SEV_MEDIUM;
	emit(evt, EVT_CHMOD, info->phase, sev, pid, ppid, info);
	__builtin_memcpy(evt->path, path, PATH_LEN);
	evt->new_mode = mode;
	bpf_ringbuf_submit(evt, 0);
	return 0;
}

// ---------------------------------------------------------------------------
// BPF self-load detection
// ---------------------------------------------------------------------------

SEC("tracepoint/syscalls/sys_enter_bpf")
int trace_bpf(struct trace_event_raw_sys_enter *ctx)
{
	// Only interested in BPF_PROG_LOAD (cmd=5).
	if ((__u32)ctx->args[0] != BPF_PROG_LOAD)
		return 0;

	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct proc_info *info = bpf_map_lookup_elem(&proc_tree, &pid);
	if (!info)
		return 0;

	struct chain_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	__u32 ppid = get_ppid();
	emit(evt, EVT_BPF_LOAD, info->phase, SEV_CRITICAL, pid, ppid, info);
	bpf_ringbuf_submit(evt, 0);
	return 0;
}

// ---------------------------------------------------------------------------
// DNS uprobe: getaddrinfo(node, service, hints, res)
// Attached programmatically from Go to libc:getaddrinfo.
// ---------------------------------------------------------------------------

SEC("uprobe")
int trace_getaddrinfo(struct pt_regs *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct proc_info *info = bpf_map_lookup_elem(&proc_tree, &pid);
	if (!info)
		return 0;

	// PARM1 = first argument = const char *node (hostname)
	const char *node = (const char *)PT_REGS_PARM1(ctx);
	if (!node)
		return 0;

	struct chain_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	__u32 ppid = get_ppid();
	emit(evt, EVT_DNS_LOOKUP, info->phase, SEV_INFO, pid, ppid, info);
	bpf_probe_read_user_str(evt->path, PATH_LEN, node);
	bpf_ringbuf_submit(evt, 0);
	return 0;
}
