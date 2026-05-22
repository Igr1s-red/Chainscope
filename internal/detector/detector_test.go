package detector

import (
	"testing"
	"time"

	"github.com/chainscope/chainscope/internal/proctree"
	"github.com/chainscope/chainscope/internal/types"
)

// makeEvt returns a minimal ChainEvent for the given type and phase.
func makeEvt(t types.EventType, phase types.Phase) *types.ChainEvent {
	return &types.ChainEvent{
		EventType: uint8(t),
		Phase:     uint8(phase),
		Pid:       1000,
		Ppid:      999,
		RootPid:   999,
	}
}

func setComm(evt *types.ChainEvent, comm string) {
	copy(evt.Comm[:], comm)
	copy(evt.RootComm[:], comm)
}

func setPath(evt *types.ChainEvent, path string) {
	copy(evt.Path[:], path)
}

func newDet() *Detector {
	return New(proctree.New(), nil)
}

// ---- exec rules ----

func TestExecFromTemp(t *testing.T) {
	d := newDet()
	evt := makeEvt(types.EvtExec, types.PhaseDownload)
	setPath(evt, "/tmp/dropper")
	evt.ExecFlags = types.ExecFlagTempPath

	alerts := d.checkExec(evt)
	if len(alerts) == 0 {
		t.Fatal("expected alert for exec-from-temp, got none")
	}
	if alerts[0].Rule != "exec-from-temp" {
		t.Errorf("wrong rule: got %q", alerts[0].Rule)
	}
	if alerts[0].Severity != types.SevHigh {
		t.Errorf("expected HIGH, got %v", alerts[0].Severity)
	}
}

func TestShellStdinPipe(t *testing.T) {
	d := newDet()
	evt := makeEvt(types.EvtExec, types.PhasePostinst)
	setComm(evt, "bash")
	evt.ExecFlags = types.ExecFlagIsShell | types.ExecFlagStdinPipe

	alerts := d.checkExec(evt)
	assertRule(t, alerts, "shell-stdin-pipe", types.SevCritical)
}

func TestLdPreload(t *testing.T) {
	d := newDet()
	evt := makeEvt(types.EvtExec, types.PhaseInstall)
	evt.EnvFlags = types.EnvFlagLdPreload

	alerts := d.checkExec(evt)
	assertRule(t, alerts, "ld-preload-injection", types.SevCritical)
}

func TestLdLibraryPath(t *testing.T) {
	d := newDet()
	evt := makeEvt(types.EvtExec, types.PhaseInstall)
	evt.EnvFlags = types.EnvFlagLdLibrary

	alerts := d.checkExec(evt)
	assertRule(t, alerts, "ld-library-path-redirect", types.SevHigh)
}

func TestCredentialInEnv(t *testing.T) {
	for _, flag := range []uint32{
		types.EnvFlagAwsKey,
		types.EnvFlagGitToken,
		types.EnvFlagNpmToken,
		types.EnvFlagPypiToken,
		types.EnvFlagCargoToken,
		types.EnvFlagGenericSec,
	} {
		d := newDet()
		evt := makeEvt(types.EvtExec, types.PhasePostinst)
		evt.EnvFlags = flag
		alerts := d.checkExec(evt)
		assertRule(t, alerts, "credential-in-env", types.SevHigh)
	}
}

func TestShellWithoutPipe_NoAlert(t *testing.T) {
	d := newDet()
	evt := makeEvt(types.EvtExec, types.PhasePostinst)
	setComm(evt, "bash")
	evt.ExecFlags = types.ExecFlagIsShell // pipe flag NOT set

	alerts := d.checkExec(evt)
	for _, a := range alerts {
		if a.Rule == "shell-stdin-pipe" {
			t.Errorf("unexpected shell-stdin-pipe alert without pipe flag")
		}
	}
}

// ---- network rules ----

func TestCompilerNetwork(t *testing.T) {
	d := newDet()
	for _, phase := range []types.Phase{types.PhaseCompile, types.PhaseLink} {
		evt := makeEvt(types.EvtNetConnect, phase)
		setComm(evt, "gcc")
		copy(evt.Daddr[:], []byte{8, 8, 8, 8})
		evt.Dport = 443

		alerts := d.checkNet(evt)
		assertRule(t, alerts, "compiler-network", types.SevCritical)
	}
}

func TestUnknownNetwork_BuildPhase(t *testing.T) {
	d := newDet()
	evt := makeEvt(types.EvtNetConnect, types.PhaseBuild)
	copy(evt.Daddr[:], []byte{1, 2, 3, 4})
	evt.Dport = 80

	alerts := d.checkNet(evt)
	assertRule(t, alerts, "unknown-network", types.SevHigh)
}

func TestUnknownNetwork_DownloadPhase(t *testing.T) {
	d := newDet()
	evt := makeEvt(types.EvtNetConnect, types.PhaseDownload)
	copy(evt.Daddr[:], []byte{1, 2, 3, 4})
	evt.Dport = 443

	alerts := d.checkNet(evt)
	assertRule(t, alerts, "unknown-network", types.SevMedium)
}

// ---- file read rules ----

func TestSensitiveRead_SSHKey(t *testing.T) {
	d := newDet()
	evt := makeEvt(types.EvtFileOpen, types.PhaseBuild)
	setPath(evt, "/root/.ssh/id_rsa")

	alerts := d.checkFileRead(evt)
	assertRule(t, alerts, "sensitive-file-read", types.SevHigh)
}

func TestSensitiveRead_CompilePhase_Escalates(t *testing.T) {
	d := newDet()
	evt := makeEvt(types.EvtFileOpen, types.PhaseCompile)
	setPath(evt, "/root/.ssh/id_rsa")

	alerts := d.checkFileRead(evt)
	assertRule(t, alerts, "sensitive-file-read", types.SevCritical)
}

func TestNonSensitiveRead_NoAlert(t *testing.T) {
	d := newDet()
	evt := makeEvt(types.EvtFileOpen, types.PhaseBuild)
	setPath(evt, "/usr/lib/python3/site-packages/foo.py")

	alerts := d.checkFileRead(evt)
	if len(alerts) != 0 {
		t.Errorf("unexpected alert for non-sensitive path: %v", alerts[0].Rule)
	}
}

// ---- file write rules ----

func TestBuildWritesSystemPath(t *testing.T) {
	d := newDet()
	for _, path := range []string{"/usr/bin/fake", "/usr/local/bin/fake", "/etc/cron.d/fake"} {
		evt := makeEvt(types.EvtFileWrite, types.PhaseBuild)
		setPath(evt, path)
		alerts := d.checkFileWrite(evt)
		assertRule(t, alerts, "build-writes-system-path", types.SevHigh)
	}
}

func TestInstallWritesSystemPath_Allowed(t *testing.T) {
	d := newDet()
	evt := makeEvt(types.EvtFileWrite, types.PhaseInstall)
	setPath(evt, "/usr/bin/mybin")

	alerts := d.checkFileWrite(evt)
	if len(alerts) != 0 {
		t.Errorf("install phase write should be allowed, got alert: %v", alerts[0].Rule)
	}
}

func TestNonSystemWrite_NoAlert(t *testing.T) {
	d := newDet()
	evt := makeEvt(types.EvtFileWrite, types.PhaseBuild)
	setPath(evt, "/home/user/project/output.o")

	if alerts := d.checkFileWrite(evt); len(alerts) != 0 {
		t.Errorf("unexpected alert for non-system path: %v", alerts[0].Rule)
	}
}

// ---- chmod rules ----

func TestChmodSUID(t *testing.T) {
	d := newDet()
	evt := makeEvt(types.EvtChmod, types.PhasePostinst)
	setPath(evt, "/usr/bin/something")
	evt.NewMode = 0o4755
	evt.Severity = uint8(types.SevCritical)

	alerts := d.checkChmod(evt)
	assertRule(t, alerts, "chmod-suid-sgid", types.SevCritical)
}

func TestChmodExecBit(t *testing.T) {
	d := newDet()
	evt := makeEvt(types.EvtChmod, types.PhasePostinst)
	setPath(evt, "/usr/local/bin/script")
	evt.NewMode = 0o755
	evt.Severity = uint8(types.SevMedium)

	alerts := d.checkChmod(evt)
	if len(alerts) == 0 {
		t.Fatal("expected chmod-exec-bit alert")
	}
	if alerts[0].Rule != "chmod-exec-bit" {
		t.Errorf("wrong rule: %q", alerts[0].Rule)
	}
}

// ---- DNS rules ----

func TestDnsLookup_CompilePhase(t *testing.T) {
	d := newDet()
	evt := makeEvt(types.EvtDnsLookup, types.PhaseCompile)
	setPath(evt, "evil.example.com")

	alerts := d.checkDns(evt)
	assertRule(t, alerts, "compiler-dns-lookup", types.SevCritical)
}

func TestDnsLookup_DownloadPhase_NoAlert(t *testing.T) {
	d := newDet()
	evt := makeEvt(types.EvtDnsLookup, types.PhaseDownload)
	setPath(evt, "pypi.org")

	if alerts := d.checkDns(evt); len(alerts) != 0 {
		t.Errorf("DNS during download should not alert, got: %v", alerts[0].Rule)
	}
}

// ---- BPF load rule ----

func TestBpfLoad(t *testing.T) {
	d := newDet()
	evt := makeEvt(types.EvtBpfLoad, types.PhasePostinst)
	setComm(evt, "postinst.sh")

	alerts := d.checkBpfLoad(evt)
	assertRule(t, alerts, "bpf-prog-load", types.SevCritical)
}

// ---- memfd / execveat rules ----

func TestMemfd(t *testing.T) {
	d := newDet()
	evt := makeEvt(types.EvtMemfdCreate, types.PhasePostinst)
	copy(evt.MemfdName[:], "payload")

	alerts := d.checkMemfd(evt)
	assertRule(t, alerts, "memfd-create", types.SevHigh)
}

func TestExecveat(t *testing.T) {
	d := newDet()
	evt := makeEvt(types.EvtExecveat, types.PhasePostinst)

	alerts := d.checkExecveat(evt)
	assertRule(t, alerts, "execveat-anon", types.SevCritical)
}

// ---- deduplicator ----

func TestDeduplicatorSuppressesRepeats(t *testing.T) {
	d := NewDeduplicator(5 * time.Second)
	evt := makeEvt(types.EvtBpfLoad, types.PhasePostinst)
	evt.RootPid = 42
	a := types.Alert{Event: evt, Rule: "bpf-prog-load", Severity: types.SevCritical}

	first := d.Filter([]types.Alert{a})
	if len(first) != 1 {
		t.Fatalf("expected first alert to pass through, got %d", len(first))
	}
	second := d.Filter([]types.Alert{a})
	if len(second) != 0 {
		t.Fatalf("expected second alert to be suppressed, got %d", len(second))
	}
}

func TestDeduplicatorDifferentRules(t *testing.T) {
	d := NewDeduplicator(5 * time.Second)
	evt := makeEvt(types.EvtExec, types.PhasePostinst)
	evt.RootPid = 42
	a1 := types.Alert{Event: evt, Rule: "rule-a", Severity: types.SevHigh}
	a2 := types.Alert{Event: evt, Rule: "rule-b", Severity: types.SevHigh}

	out := d.Filter([]types.Alert{a1, a2})
	if len(out) != 2 {
		t.Fatalf("different rules should both pass through, got %d", len(out))
	}
}

func TestDeduplicatorDifferentRootPids(t *testing.T) {
	d := NewDeduplicator(5 * time.Second)
	make1 := func(rootPid uint32) types.Alert {
		e := makeEvt(types.EvtBpfLoad, types.PhasePostinst)
		e.RootPid = rootPid
		return types.Alert{Event: e, Rule: "bpf-prog-load", Severity: types.SevCritical}
	}
	out := d.Filter([]types.Alert{make1(1), make1(2)})
	if len(out) != 2 {
		t.Fatalf("same rule but different root PIDs should both pass through, got %d", len(out))
	}
}

// ---- helper ----

func assertRule(t *testing.T, alerts []types.Alert, rule string, sev types.Severity) {
	t.Helper()
	for _, a := range alerts {
		if a.Rule == rule {
			if a.Severity != sev {
				t.Errorf("rule %q: expected severity %v, got %v", rule, sev, a.Severity)
			}
			return
		}
	}
	t.Errorf("expected alert with rule %q, got alerts: %v", rule, ruleNames(alerts))
}

func ruleNames(alerts []types.Alert) []string {
	var names []string
	for _, a := range alerts {
		names = append(names, a.Rule)
	}
	return names
}
