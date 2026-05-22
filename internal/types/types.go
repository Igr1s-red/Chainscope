package types

import (
	"fmt"
	"net"
	"strings"
)

type EventType uint8
type Phase uint8
type Severity uint8

const (
	EvtExec        EventType = 1
	EvtFileOpen    EventType = 2
	EvtNetConnect  EventType = 3
	EvtMemfdCreate EventType = 4
	EvtExecveat    EventType = 5
	EvtFileWrite   EventType = 6
	EvtChmod       EventType = 7
	EvtDnsLookup   EventType = 8
	EvtBpfLoad     EventType = 9
)

const (
	PhaseUnknown  Phase = 0
	PhaseDownload Phase = 1
	PhaseExtract  Phase = 2
	PhaseBuild    Phase = 3
	PhaseCompile  Phase = 4
	PhaseLink     Phase = 5
	PhaseInstall  Phase = 6
	PhasePostinst Phase = 7
)

const (
	SevInfo     Severity = 0
	SevLow      Severity = 1
	SevMedium   Severity = 2
	SevHigh     Severity = 3
	SevCritical Severity = 4
)

// ExecFlags bits — set in EVT_EXEC events.
const (
	ExecFlagTempPath  uint32 = 1 << 0 // exec from /tmp, /dev/shm, /var/tmp, /run
	ExecFlagStdinPipe uint32 = 1 << 1 // stdin is a FIFO/pipe at exec time
	ExecFlagIsShell   uint32 = 1 << 2 // target is sh/bash/dash/zsh/fish/ksh
)

// EnvFlags bits — set in EVT_EXEC events.
const (
	EnvFlagLdPreload  uint32 = 1 << 0 // LD_PRELOAD=
	EnvFlagLdLibrary  uint32 = 1 << 1 // LD_LIBRARY_PATH=
	EnvFlagAwsKey     uint32 = 1 << 2 // AWS_ACCESS_KEY_ID=
	EnvFlagGitToken   uint32 = 1 << 3 // GITHUB_TOKEN=
	EnvFlagNpmToken   uint32 = 1 << 4 // NPM_TOKEN=
	EnvFlagPypiToken  uint32 = 1 << 5 // PYPI_TOKEN=
	EnvFlagCargoToken uint32 = 1 << 6 // CARGO_REGISTRY_TOKEN=
	EnvFlagGenericSec uint32 = 1 << 7 // generic SECRET/PASSWD key
)

func (e EventType) String() string {
	switch e {
	case EvtExec:
		return "exec"
	case EvtFileOpen:
		return "file_open"
	case EvtNetConnect:
		return "net_connect"
	case EvtMemfdCreate:
		return "memfd_create"
	case EvtExecveat:
		return "execveat_anon"
	case EvtFileWrite:
		return "file_write"
	case EvtChmod:
		return "chmod"
	case EvtDnsLookup:
		return "dns_lookup"
	case EvtBpfLoad:
		return "bpf_load"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(e))
	}
}

func (p Phase) String() string {
	switch p {
	case PhaseDownload:
		return "download"
	case PhaseExtract:
		return "extract"
	case PhaseBuild:
		return "build"
	case PhaseCompile:
		return "compile"
	case PhaseLink:
		return "link"
	case PhaseInstall:
		return "install"
	case PhasePostinst:
		return "postinstall"
	default:
		return "unknown"
	}
}

func (s Severity) String() string {
	switch s {
	case SevInfo:
		return "info"
	case SevLow:
		return "low"
	case SevMedium:
		return "medium"
	case SevHigh:
		return "high"
	case SevCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// ChainEvent is the Go mirror of struct chain_event in chainscope.h.
// Layout must match the C struct exactly — parsed from ring buffer via binary.Read.
//
// Total size: 520 bytes (verified: no implicit padding in C or Go).
type ChainEvent struct {
	Timestamp uint64
	Pid       uint32
	Ppid      uint32
	RootPid   uint32
	EventType uint8
	Phase     uint8
	Severity  uint8
	Pad       uint8
	Comm      [16]byte
	RootComm  [16]byte
	Path      [256]byte
	OpenFlags int32
	// Argv holds argv[1..8], each slot ARGV_STRIDE (12) bytes wide.
	Argv      [96]byte
	EnvFlags  uint32 // ENV_FLAG_* bitmask
	ExecFlags uint32 // EXEC_FLAG_* bitmask
	// Daddr holds 4 bytes (IPv4) or 16 bytes (IPv6); consult IsIPv6.
	Daddr    [16]byte
	Dport    uint16
	Proto    uint8
	IsIPv6   uint8
	NewMode  uint32 // for EVT_CHMOD: the new file mode
	Pad2     uint32
	MemfdName  [64]byte
	MemfdFlags uint32
	Pad3       uint32
}

func (e *ChainEvent) CommStr() string      { return cstring(e.Comm[:]) }
func (e *ChainEvent) RootCommStr() string  { return cstring(e.RootComm[:]) }
func (e *ChainEvent) PathStr() string      { return cstring(e.Path[:]) }
func (e *ChainEvent) MemfdNameStr() string { return cstring(e.MemfdName[:]) }

// ArgvStr reconstructs the argument vector as a space-separated string.
// Each slot is ARGV_STRIDE (12) bytes; an all-zero slot signals end of args.
func (e *ChainEvent) ArgvStr() string {
	const stride = 12
	parts := make([]string, 0, 8)
	for i := 0; i < 8; i++ {
		slot := e.Argv[i*stride : (i+1)*stride]
		s := cstring(slot)
		if s == "" {
			break
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, " ")
}

// EnvFlagNames returns human-readable names for set ENV_FLAG_* bits.
func (e *ChainEvent) EnvFlagNames() []string {
	var names []string
	if e.EnvFlags&EnvFlagLdPreload != 0 {
		names = append(names, "LD_PRELOAD")
	}
	if e.EnvFlags&EnvFlagLdLibrary != 0 {
		names = append(names, "LD_LIBRARY_PATH")
	}
	if e.EnvFlags&EnvFlagAwsKey != 0 {
		names = append(names, "AWS_ACCESS_KEY_ID")
	}
	if e.EnvFlags&EnvFlagGitToken != 0 {
		names = append(names, "GITHUB_TOKEN")
	}
	if e.EnvFlags&EnvFlagNpmToken != 0 {
		names = append(names, "NPM_TOKEN")
	}
	if e.EnvFlags&EnvFlagPypiToken != 0 {
		names = append(names, "PYPI_TOKEN")
	}
	if e.EnvFlags&EnvFlagCargoToken != 0 {
		names = append(names, "CARGO_REGISTRY_TOKEN")
	}
	if e.EnvFlags&EnvFlagGenericSec != 0 {
		names = append(names, "*SECRET*/*PASSWD*")
	}
	return names
}

// DstIP returns the destination IP as a net.IP, handling both IPv4 and IPv6.
func (e *ChainEvent) DstIP() net.IP {
	if e.IsIPv6 != 0 {
		ip := make([]byte, 16)
		copy(ip, e.Daddr[:])
		return net.IP(ip)
	}
	return net.IP(e.Daddr[:4])
}

func cstring(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// Alert is produced by the detector for events that violate policy.
type Alert struct {
	Event       *ChainEvent
	Rule        string
	Description string
	Severity    Severity
}
