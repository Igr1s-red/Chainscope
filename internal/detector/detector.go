// Package detector applies detection rules to chain events and emits alerts.
package detector

import (
	"fmt"
	"strings"

	"github.com/chainscope/chainscope/internal/policy"
	"github.com/chainscope/chainscope/internal/proctree"
	"github.com/chainscope/chainscope/internal/types"
)

var sensitivePathPrefixes = []string{
	"/root/.ssh/",
	"/.ssh/",
	"/.aws/",
	"/.gcp/",
	"/.gnupg/",
	"/etc/shadow",
	"/etc/gshadow",
}

var sensitivePathSuffixes = []string{
	"id_rsa", "id_ecdsa", "id_ed25519",
	".pem", ".key",
	"credentials", "secret", "token",
}

var sensitivePathContains = []string{".env"}

// installPaths are system locations where unexpected writes indicate potential
// binary injection or hijacking.
var installPathPrefixes = []string{
	"/usr/bin/", "/usr/sbin/", "/usr/local/bin/", "/usr/local/sbin/",
	"/bin/", "/sbin/",
	"/etc/",
}

// Detector holds the rule engine.
type Detector struct {
	tree   *proctree.Tree
	policy *policy.Policy // may be nil if no policy file was loaded
}

func New(tree *proctree.Tree, pol *policy.Policy) *Detector {
	return &Detector{tree: tree, policy: pol}
}

// Check evaluates all rules against evt and returns any triggered alerts.
func (d *Detector) Check(evt *types.ChainEvent) []types.Alert {
	var alerts []types.Alert
	switch types.EventType(evt.EventType) {
	case types.EvtExec:
		alerts = append(alerts, d.checkExec(evt)...)
	case types.EvtNetConnect:
		alerts = append(alerts, d.checkNet(evt)...)
	case types.EvtFileOpen:
		alerts = append(alerts, d.checkFileRead(evt)...)
	case types.EvtFileWrite:
		alerts = append(alerts, d.checkFileWrite(evt)...)
	case types.EvtMemfdCreate:
		alerts = append(alerts, d.checkMemfd(evt)...)
	case types.EvtExecveat:
		alerts = append(alerts, d.checkExecveat(evt)...)
	case types.EvtChmod:
		alerts = append(alerts, d.checkChmod(evt)...)
	case types.EvtDnsLookup:
		alerts = append(alerts, d.checkDns(evt)...)
	case types.EvtBpfLoad:
		alerts = append(alerts, d.checkBpfLoad(evt)...)
	}
	return alerts
}

// checkExec fires on exec-from-temp, pipe+shell (curl|bash), and LD_PRELOAD.
func (d *Detector) checkExec(evt *types.ChainEvent) []types.Alert {
	var alerts []types.Alert
	comm := evt.CommStr()
	chain := d.tree.FormatChain(evt.Pid)
	argv := evt.ArgvStr()
	if argv != "" {
		argv = " " + argv
	}

	// Exec from /tmp, /dev/shm, /var/tmp, /run — dropper pattern.
	if evt.ExecFlags&types.ExecFlagTempPath != 0 {
		alerts = append(alerts, types.Alert{
			Event:    evt,
			Rule:     "exec-from-temp",
			Severity: types.SevHigh,
			Description: fmt.Sprintf(
				"%s%s executed from temporary filesystem path %q. Chain: %s",
				comm, argv, evt.PathStr(), chain,
			),
		})
	}

	// Shell with piped stdin — curl | bash / wget | sh pattern.
	if evt.ExecFlags&types.ExecFlagIsShell != 0 && evt.ExecFlags&types.ExecFlagStdinPipe != 0 {
		alerts = append(alerts, types.Alert{
			Event:    evt,
			Rule:     "shell-stdin-pipe",
			Severity: types.SevCritical,
			Description: fmt.Sprintf(
				"%s%s executed with piped stdin — possible curl|bash attack. Chain: %s",
				comm, argv, chain,
			),
		})
	}

	// LD_PRELOAD injection — XZ/liblzma-class attack.
	if evt.EnvFlags&types.EnvFlagLdPreload != 0 {
		alerts = append(alerts, types.Alert{
			Event:    evt,
			Rule:     "ld-preload-injection",
			Severity: types.SevCritical,
			Description: fmt.Sprintf(
				"%s%s launched with LD_PRELOAD set — possible library injection. Chain: %s",
				comm, argv, chain,
			),
		})
	}

	// LD_LIBRARY_PATH redirect — similar class of attack.
	if evt.EnvFlags&types.EnvFlagLdLibrary != 0 {
		alerts = append(alerts, types.Alert{
			Event:    evt,
			Rule:     "ld-library-path-redirect",
			Severity: types.SevHigh,
			Description: fmt.Sprintf(
				"%s%s launched with LD_LIBRARY_PATH — possible linker hijack. Chain: %s",
				comm, argv, chain,
			),
		})
	}

	// Credential tokens in env — CI/CD secret leakage.
	if credFlags := evt.EnvFlags &^ (types.EnvFlagLdPreload | types.EnvFlagLdLibrary); credFlags != 0 {
		names := strings.Join(evt.EnvFlagNames(), ", ")
		alerts = append(alerts, types.Alert{
			Event:    evt,
			Rule:     "credential-in-env",
			Severity: types.SevHigh,
			Description: fmt.Sprintf(
				"%s%s launched with credential env vars [%s]. Chain: %s",
				comm, argv, names, chain,
			),
		})
	}

	return alerts
}

func (d *Detector) checkNet(evt *types.ChainEvent) []types.Alert {
	phase := types.Phase(evt.Phase)
	comm := evt.CommStr()
	chain := d.tree.FormatChain(evt.Pid)
	ip := evt.DstIP()
	ipStr := ip.String()

	// Compiler/linker network call — always critical regardless of destination.
	if phase == types.PhaseCompile || phase == types.PhaseLink {
		return []types.Alert{{
			Event:    evt,
			Rule:     "compiler-network",
			Severity: types.SevCritical,
			Description: fmt.Sprintf(
				"%s (phase=%s) opened network connection to %s:%d — compilers must not make network calls. Chain: %s",
				comm, phase, ipStr, evt.Dport, chain,
			),
		}}
	}

	// Check against known-good registry CIDRs.
	if d.policy != nil {
		if allowed, registry := d.policy.IsAllowedIP(ip); allowed {
			if phase == types.PhaseDownload || phase == types.PhaseInstall {
				return nil // expected package fetch
			}
			return []types.Alert{{
				Event:    evt,
				Rule:     "unexpected-phase-network",
				Severity: types.SevLow,
				Description: fmt.Sprintf(
					"%s (phase=%s) connected to known registry %s (%s:%d) outside download/install phase. Chain: %s",
					comm, phase, registry, ipStr, evt.Dport, chain,
				),
			}}
		}
	}

	// Unknown destination — severity depends on phase.
	sev := types.SevMedium
	if phase == types.PhasePostinst || phase == types.PhaseBuild {
		sev = types.SevHigh
	}

	return []types.Alert{{
		Event:    evt,
		Rule:     "unknown-network",
		Severity: sev,
		Description: fmt.Sprintf(
			"%s (phase=%s) connected to unknown IP %s:%d. Chain: %s",
			comm, phase, ipStr, evt.Dport, chain,
		),
	}}
}

func (d *Detector) checkFileRead(evt *types.ChainEvent) []types.Alert {
	path := evt.PathStr()
	comm := evt.CommStr()
	chain := d.tree.FormatChain(evt.Pid)

	if !isSensitivePath(path) {
		return nil
	}

	sev := types.SevHigh
	if types.Phase(evt.Phase) == types.PhaseCompile || types.Phase(evt.Phase) == types.PhaseLink {
		sev = types.SevCritical
	}

	return []types.Alert{{
		Event:    evt,
		Rule:     "sensitive-file-read",
		Severity: sev,
		Description: fmt.Sprintf(
			"%s (phase=%s) read sensitive path %q. Chain: %s",
			comm, types.Phase(evt.Phase), path, chain,
		),
	}}
}

func (d *Detector) checkFileWrite(evt *types.ChainEvent) []types.Alert {
	path := evt.PathStr()
	comm := evt.CommStr()
	phase := types.Phase(evt.Phase)
	chain := d.tree.FormatChain(evt.Pid)

	if !isInstallPath(path) {
		return nil
	}

	if phase == types.PhaseInstall {
		return nil // expected
	}

	sev := types.SevMedium
	rule := "unexpected-install-write"
	desc := fmt.Sprintf(
		"%s (phase=%s) opened %q for writing — unexpected write to system path. Chain: %s",
		comm, phase, path, chain,
	)

	if phase == types.PhaseCompile || phase == types.PhaseBuild {
		sev = types.SevHigh
		rule = "build-writes-system-path"
		desc = fmt.Sprintf(
			"%s (phase=%s) wrote to system binary path %q — possible binary injection. Chain: %s",
			comm, phase, path, chain,
		)
	}

	if phase == types.PhasePostinst {
		sev = types.SevHigh
		rule = "postinst-writes-system-path"
	}

	return []types.Alert{{
		Event:       evt,
		Rule:        rule,
		Severity:    sev,
		Description: desc,
	}}
}

func (d *Detector) checkMemfd(evt *types.ChainEvent) []types.Alert {
	comm := evt.CommStr()
	chain := d.tree.FormatChain(evt.Pid)
	return []types.Alert{{
		Event:    evt,
		Rule:     "memfd-create",
		Severity: types.SevHigh,
		Description: fmt.Sprintf(
			"%s created anonymous memory file %q (flags=0x%x) — possible fileless payload staging. Chain: %s",
			comm, evt.MemfdNameStr(), evt.MemfdFlags, chain,
		),
	}}
}

func (d *Detector) checkExecveat(evt *types.ChainEvent) []types.Alert {
	comm := evt.CommStr()
	chain := d.tree.FormatChain(evt.Pid)
	return []types.Alert{{
		Event:    evt,
		Rule:     "execveat-anon",
		Severity: types.SevCritical,
		Description: fmt.Sprintf(
			"%s executed from anonymous fd (AT_EMPTY_PATH) — fileless execution. Chain: %s",
			comm, chain,
		),
	}}
}

// checkChmod alerts on SUID/SGID or exec-bit changes on system paths.
func (d *Detector) checkChmod(evt *types.ChainEvent) []types.Alert {
	comm := evt.CommStr()
	path := evt.PathStr()
	chain := d.tree.FormatChain(evt.Pid)
	mode := evt.NewMode

	rule := "chmod-exec-bit"
	sev := types.Severity(evt.Severity)
	desc := fmt.Sprintf(
		"%s (phase=%s) chmod %04o on %q. Chain: %s",
		comm, types.Phase(evt.Phase), mode&0o7777, path, chain,
	)

	if mode&0o6000 != 0 {
		rule = "chmod-suid-sgid"
		sev = types.SevCritical
		desc = fmt.Sprintf(
			"%s (phase=%s) set SUID/SGID bits (mode=%04o) on %q — privilege escalation risk. Chain: %s",
			comm, types.Phase(evt.Phase), mode&0o7777, path, chain,
		)
	}

	return []types.Alert{{
		Event:       evt,
		Rule:        rule,
		Severity:    sev,
		Description: desc,
	}}
}

// checkDns logs DNS lookups at info level; at COMPILE/LINK phase it escalates.
func (d *Detector) checkDns(evt *types.ChainEvent) []types.Alert {
	phase := types.Phase(evt.Phase)
	comm := evt.CommStr()
	hostname := evt.PathStr()
	chain := d.tree.FormatChain(evt.Pid)

	if phase != types.PhaseCompile && phase != types.PhaseLink {
		return nil // DNS during download/install is normal
	}

	return []types.Alert{{
		Event:    evt,
		Rule:     "compiler-dns-lookup",
		Severity: types.SevCritical,
		Description: fmt.Sprintf(
			"%s (phase=%s) resolved hostname %q — compilers must not make DNS lookups. Chain: %s",
			comm, phase, hostname, chain,
		),
	}}
}

// checkBpfLoad fires whenever a tracked process loads a BPF program.
func (d *Detector) checkBpfLoad(evt *types.ChainEvent) []types.Alert {
	comm := evt.CommStr()
	chain := d.tree.FormatChain(evt.Pid)
	return []types.Alert{{
		Event:    evt,
		Rule:     "bpf-prog-load",
		Severity: types.SevCritical,
		Description: fmt.Sprintf(
			"%s (phase=%s) called BPF_PROG_LOAD — possible eBPF rootkit or backdoor. Chain: %s",
			comm, types.Phase(evt.Phase), chain,
		),
	}}
}

func isSensitivePath(path string) bool {
	for _, p := range sensitivePathPrefixes {
		if strings.Contains(path, p) {
			return true
		}
	}
	for _, s := range sensitivePathSuffixes {
		if strings.HasSuffix(path, s) {
			return true
		}
	}
	for _, c := range sensitivePathContains {
		if strings.Contains(path, c) {
			return true
		}
	}
	return false
}

func isInstallPath(path string) bool {
	for _, p := range installPathPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}
