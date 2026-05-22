#pragma once

#define TASK_COMM_LEN  16
#define PATH_LEN       256
#define MEMFD_NAME_LEN 64
#define ARGV_LEN       96    /* 8 args × 12 bytes each */
#define ARGV_STRIDE    12
#define MAX_ARGV_ARGS  8

#ifndef AF_INET
#define AF_INET   2
#define AF_INET6  10
#endif

#ifndef O_WRONLY
#define O_ACCMODE 0x3
#define O_RDONLY  0x0
#define O_WRONLY  0x1
#define O_RDWR    0x2
#endif

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

#define BPF_PROG_LOAD 5   /* sys_bpf(BPF_PROG_LOAD, …) */

/*
 * Use #defines instead of enums to avoid tag-namespace conflicts with
 * vmlinux.h, which may define struct/union types with the same names
 * (e.g. "struct severity" at line 110573 of the 6.19 vmlinux.h).
 */

/* event_type values */
#define EVT_EXEC         1
#define EVT_FILE_OPEN    2
#define EVT_NET_CONNECT  3
#define EVT_MEMFD_CREATE 4
#define EVT_EXECVEAT     5
#define EVT_FILE_WRITE   6
#define EVT_CHMOD        7   /* chmod/fchmodat with exec or SUID bit */
#define EVT_DNS_LOOKUP   8   /* getaddrinfo uprobe — hostname in path */
#define EVT_BPF_LOAD     9   /* BPF_PROG_LOAD from inside tracked process */

/* phase values */
#define PHASE_UNKNOWN  0
#define PHASE_DOWNLOAD 1
#define PHASE_EXTRACT  2
#define PHASE_BUILD    3
#define PHASE_COMPILE  4
#define PHASE_LINK     5
#define PHASE_INSTALL  6
#define PHASE_POSTINST 7

/* severity values */
#define SEV_INFO     0
#define SEV_LOW      1
#define SEV_MEDIUM   2
#define SEV_HIGH     3
#define SEV_CRITICAL 4

/* exec_flags bits — set in EVT_EXEC events */
#define EXEC_FLAG_TEMP_PATH  (1 << 0)  /* exec from /tmp, /dev/shm, /var/tmp, /run */
#define EXEC_FLAG_STDIN_PIPE (1 << 1)  /* stdin fd is a FIFO/pipe at exec time */
#define EXEC_FLAG_IS_SHELL   (1 << 2)  /* target basename is sh/bash/dash/zsh/fish/ksh */

/* env_flags bits — set in EVT_EXEC events */
#define ENV_FLAG_LD_PRELOAD  (1 << 0)  /* LD_PRELOAD= found in envp */
#define ENV_FLAG_LD_LIBRARY  (1 << 1)  /* LD_LIBRARY_PATH= */
#define ENV_FLAG_AWS_KEY     (1 << 2)  /* AWS_ACCESS_KEY_ID= */
#define ENV_FLAG_GIT_TOKEN   (1 << 3)  /* GITHUB_TOKEN= */
#define ENV_FLAG_NPM_TOKEN   (1 << 4)  /* NPM_TOKEN= */
#define ENV_FLAG_PYPI_TOKEN  (1 << 5)  /* PYPI_TOKEN= */
#define ENV_FLAG_CARGO_TOKEN (1 << 6)  /* CARGO_REGISTRY_TOKEN= */
#define ENV_FLAG_GENERIC_SEC (1 << 7)  /* generic *SECRET*, *PASSWD*, *TOKEN* key */

struct proc_info {
	__u32 ppid;
	__u32 root_pid;
	__u8  phase;
	char  comm[TASK_COMM_LEN];
	char  root_comm[TASK_COMM_LEN];
};

/*
 * Flat event struct — no union, so bpf2go generates a clean Go mirror.
 * All fields coexist; only the relevant subset is populated per event type.
 *
 * Size: 520 bytes, no implicit padding anywhere.
 * Go mirror in internal/types/types.go must match exactly.
 *
 * Offset map:
 *   0   timestamp(8)  pid(4)  ppid(4)  root_pid(4)
 *  20   event_type(1) phase(1) severity(1) _pad(1)
 *  24   comm[16]  root_comm[16]
 *  56   path[256]
 * 312   open_flags(4)
 * 316   argv[96]    ← EVT_EXEC: argv[1..8], stride=12 bytes/arg
 * 412   env_flags(4)← EVT_EXEC: ENV_FLAG_* bitmask
 * 416   exec_flags(4)← EVT_EXEC: EXEC_FLAG_* bitmask
 * 420   daddr[16]   ← EVT_NET_CONNECT
 * 436   dport(2) proto(1) is_ipv6(1)
 * 440   new_mode(4) _pad2(4)  ← EVT_CHMOD
 * 448   memfd_name[64] memfd_flags(4) _pad3(4)  ← EVT_MEMFD_CREATE
 * 520   ← total
 */
struct chain_event {
	__u64 timestamp;
	__u32 pid;
	__u32 ppid;
	__u32 root_pid;
	__u8  event_type;
	__u8  phase;
	__u8  severity;
	__u8  _pad;
	char  comm[TASK_COMM_LEN];
	char  root_comm[TASK_COMM_LEN];
	char  path[PATH_LEN];
	__s32 open_flags;
	char  argv[ARGV_LEN];
	__u32 env_flags;
	__u32 exec_flags;
	__u8  daddr[16];
	__u16 dport;
	__u8  proto;
	__u8  is_ipv6;
	__u32 new_mode;
	__u32 _pad2;
	char  memfd_name[MEMFD_NAME_LEN];
	__u32 memfd_flags;
	__u32 _pad3;
};
