// chainscope — eBPF-based supply chain security monitor.
//
// Tracks every process spawned by a package manager (pip, npm, cargo, apt, …)
// and their descendants, alerting on:
//   - argv capture + LD_PRELOAD injection (XZ-class attacks)
//   - exec-from-temp (/tmp, /dev/shm)
//   - pipe+shell correlation (curl|bash)
//   - network connections from compilers or linkers
//   - credential/secret file reads during builds
//   - writes to system binary paths from unexpected phases
//   - fileless execution (memfd_create + execveat AT_EMPTY_PATH)
//   - chmod setting SUID/exec bits
//   - DNS lookups from compilers
//   - BPF program loads from tracked processes
//
// Requires: root or CAP_BPF + CAP_PERFMON. Kernel 5.8+ with BTF.
// Build:     make
// Run:       sudo ./chainscope [-policy policy/default.yaml]
// CI mode:   sudo ./chainscope ci [flags] -- command [args...]
// Learn:     sudo ./chainscope --learn profile.json [flags]
// Enforce:   sudo ./chainscope --enforce profile.json [flags]

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/chainscope/chainscope/internal/baseline"
	"github.com/chainscope/chainscope/internal/detector"
	"github.com/chainscope/chainscope/internal/loader"
	"github.com/chainscope/chainscope/internal/metrics"
	"github.com/chainscope/chainscope/internal/output"
	"github.com/chainscope/chainscope/internal/policy"
	"github.com/chainscope/chainscope/internal/proctree"
	"github.com/chainscope/chainscope/internal/types"
)

const dedupTTL = 5 * time.Second

func main() {
	// CI subcommand: chainscope ci [flags] -- command [args]
	if len(os.Args) > 1 && os.Args[1] == "ci" {
		os.Exit(runCI(os.Args[2:]))
	}

	jsonMode    := flag.Bool("json", false, "emit newline-delimited JSON instead of coloured text")
	verbose     := flag.Bool("v", false, "print all events, not just alerts")
	policyFile  := flag.String("policy", "", "path to policy YAML (e.g. policy/default.yaml)")
	learnPath   := flag.String("learn", "", "learn mode: write baseline profile to this path on exit")
	enforcePath := flag.String("enforce", "", "enforce mode: alert on behaviors not in this baseline profile")
	sarifPath   := flag.String("sarif", "", "write SARIF 2.1.0 report to this path on exit")
	metricsAddr := flag.String("metrics-addr", "", "start Prometheus metrics server on this address (e.g. :9090)")
	flag.Parse()

	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "chainscope must run as root (or with CAP_BPF + CAP_PERFMON)")
		os.Exit(1)
	}

	var pol *policy.Policy
	if *policyFile != "" {
		var err error
		pol, err = policy.Load(*policyFile)
		if err != nil {
			log.Fatalf("loading policy: %v", err)
		}
		fmt.Fprintf(os.Stderr, "policy loaded from %s\n", *policyFile)
	}

	var learner *baseline.Learner
	if *learnPath != "" {
		learner = baseline.NewLearner()
		fmt.Fprintf(os.Stderr, "learn mode: will write profile to %s on exit\n", *learnPath)
	}

	var enforcer *baseline.Enforcer
	if *enforcePath != "" {
		var err error
		enforcer, err = baseline.LoadProfile(*enforcePath)
		if err != nil {
			log.Fatalf("loading baseline profile: %v", err)
		}
		fmt.Fprintf(os.Stderr, "enforce mode: checking against %s\n", *enforcePath)
	}

	var sarifWriter *output.SARIFWriter
	if *sarifPath != "" {
		sarifWriter = output.NewSARIFWriter(*sarifPath)
		fmt.Fprintf(os.Stderr, "SARIF report will be written to %s on exit\n", *sarifPath)
	}

	var met *metrics.Server
	if *metricsAddr != "" {
		met = metrics.New()
		go func() {
			fmt.Fprintf(os.Stderr, "metrics server listening on %s\n", *metricsAddr)
			if err := met.ListenAndServe(*metricsAddr); err != nil {
				log.Printf("metrics server: %v", err)
			}
		}()
	}

	l, err := loader.New()
	if err != nil {
		log.Fatalf("failed to load BPF programs: %v\n\nHint: run `make` first to compile the eBPF object.", err)
	}
	defer l.Close()

	tree  := proctree.New()
	det   := detector.New(tree, pol)
	dedup := detector.NewDeduplicator(dedupTTL)
	out   := output.New(os.Stdout, *jsonMode)

	// Poll ring buffer drop counter into metrics every 5 seconds.
	if met != nil {
		go func() {
			tick := time.NewTicker(5 * time.Second)
			defer tick.Stop()
			for range tick.C {
				n := l.DroppedEvents()
				met.SetDropped(n)
				if n > 0 {
					log.Printf("WARNING: %d event(s) dropped due to ring buffer overflow — consider increasing ring buffer size", n)
				}
			}
		}()
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		if learner != nil && *learnPath != "" {
			if err := learner.Save(*learnPath); err != nil {
				fmt.Fprintf(os.Stderr, "writing baseline profile: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "baseline profile written to %s\n", *learnPath)
			}
		}
		if sarifWriter != nil {
			if err := sarifWriter.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "writing SARIF report: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "SARIF report written to %s\n", *sarifPath)
			}
		}
		l.Close()
	}()

	fmt.Fprintln(os.Stderr, "chainscope running — watching package managers and build tools. Ctrl+C to stop.")

	for {
		evt, err := l.ReadEvent()
		if err != nil {
			log.Printf("read error: %v", err)
			continue
		}
		if evt == nil {
			break
		}

		if met != nil {
			met.RecordEvent()
		}

		if types.EventType(evt.EventType) == types.EvtExec {
			tree.Add(evt)
			if met != nil {
				met.SetProcTreeSize(tree.Size())
			}
		}

		if learner != nil {
			learner.Learn(evt)
		}

		alerts := dedup.Filter(det.Check(evt))

		if enforcer != nil {
			if a := enforcer.Check(evt); a != nil {
				alerts = append(alerts, *a)
			}
		}

		// Enrich alerts with container context from the proctree node.
		if node := tree.Get(evt.Pid); node != nil && node.ContainerID != "" {
			for i := range alerts {
				alerts[i].ContainerID = node.ContainerID
				alerts[i].Runtime     = node.Runtime
				alerts[i].PodName     = node.PodName
				alerts[i].Namespace   = node.Namespace
			}
		}

		for _, a := range alerts {
			out.WriteAlert(&a)
			if sarifWriter != nil {
				sarifWriter.AddAlert(&a)
			}
			if met != nil {
				met.RecordAlert(a.Rule, a.Severity.String())
			}
		}

		if *verbose && len(alerts) == 0 {
			out.WriteEvent(evt)
		}
	}
}

// runCI implements `chainscope ci [flags] -- command [args...]`.
// It starts the given command, seeds the BPF proc tree, runs the event loop
// until the command exits, and returns 1 if any HIGH+ alert was triggered.
func runCI(args []string) int {
	fs := flag.NewFlagSet("ci", flag.ExitOnError)
	jsonMode    := fs.Bool("json", false, "emit JSON alerts")
	verbose     := fs.Bool("v", false, "print all events")
	policyFile  := fs.String("policy", "", "path to policy YAML")
	minSev      := fs.String("min-sev", "high", "minimum severity that causes non-zero exit (low|medium|high|critical)")
	sarifPath   := fs.String("sarif", "", "write SARIF 2.1.0 report to this path on exit")
	metricsAddr := fs.String("metrics-addr", "", "Prometheus metrics address (e.g. :9090)")

	// Find the "--" separator between chainscope flags and the command.
	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep < 0 || sep == len(args)-1 {
		fmt.Fprintln(os.Stderr, "usage: chainscope ci [flags] -- command [args...]")
		return 1
	}
	if err := fs.Parse(args[:sep]); err != nil {
		return 1
	}
	cmdArgs := args[sep+1:]

	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "chainscope must run as root")
		return 1
	}

	threshold := parseSeverity(*minSev)

	var pol *policy.Policy
	if *policyFile != "" {
		var err error
		pol, err = policy.Load(*policyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "loading policy: %v\n", err)
			return 1
		}
	}

	var sarifWriter *output.SARIFWriter
	if *sarifPath != "" {
		sarifWriter = output.NewSARIFWriter(*sarifPath)
	}

	var met *metrics.Server
	if *metricsAddr != "" {
		met = metrics.New()
		go func() {
			if err := met.ListenAndServe(*metricsAddr); err != nil {
				log.Printf("metrics server: %v", err)
			}
		}()
	}

	l, err := loader.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load BPF programs: %v\n", err)
		return 1
	}
	defer l.Close()

	tree  := proctree.New()
	det   := detector.New(tree, pol)
	dedup := detector.NewDeduplicator(dedupTTL)
	out   := output.New(os.Stderr, *jsonMode) // alerts → stderr in CI mode

	// Start the monitored command.
	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdin  = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "starting command: %v\n", err)
		return 1
	}

	// Seed proc tree so the command is immediately tracked.
	if err := l.SeedPID(uint32(cmd.Process.Pid), filepath.Base(cmdArgs[0])); err != nil {
		fmt.Fprintf(os.Stderr, "seeding proc tree: %v\n", err)
	}

	// Close the loader shortly after the command exits to flush ring buffer.
	cmdDone := make(chan int, 1)
	go func() {
		waitErr := cmd.Wait()
		code := 0
		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		}
		time.Sleep(300 * time.Millisecond) // drain remaining ring buffer events
		l.Close()
		cmdDone <- code
	}()

	var alertCount atomic.Int64

	if *verbose {
		fmt.Fprintln(os.Stderr, "chainscope ci: monitoring command:", cmdArgs)
	}

	for {
		evt, readErr := l.ReadEvent()
		if readErr != nil {
			log.Printf("read error: %v", readErr)
			continue
		}
		if evt == nil {
			break
		}

		if met != nil {
			met.RecordEvent()
		}

		if types.EventType(evt.EventType) == types.EvtExec {
			tree.Add(evt)
			if met != nil {
				met.SetProcTreeSize(tree.Size())
			}
		}

		alerts := dedup.Filter(det.Check(evt))

		// Enrich alerts with container context.
		if node := tree.Get(evt.Pid); node != nil && node.ContainerID != "" {
			for i := range alerts {
				alerts[i].ContainerID = node.ContainerID
				alerts[i].Runtime     = node.Runtime
				alerts[i].PodName     = node.PodName
				alerts[i].Namespace   = node.Namespace
			}
		}

		for _, a := range alerts {
			out.WriteAlert(&a)
			if sarifWriter != nil {
				sarifWriter.AddAlert(&a)
			}
			if met != nil {
				met.RecordAlert(a.Rule, a.Severity.String())
			}
			if a.Severity >= threshold {
				alertCount.Add(1)
			}
		}

		if *verbose {
			out.WriteEvent(evt)
		}
	}

	cmdExit := <-cmdDone

	if sarifWriter != nil {
		if err := sarifWriter.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "writing SARIF report: %v\n", err)
		}
	}

	n := alertCount.Load()
	if n > 0 {
		fmt.Fprintf(os.Stderr, "chainscope ci: FAIL — %d alert(s) at or above %s severity\n", n, *minSev)
		return 1
	}
	if cmdExit != 0 {
		fmt.Fprintf(os.Stderr, "chainscope ci: command exited %d (no security alerts)\n", cmdExit)
		return cmdExit
	}
	fmt.Fprintln(os.Stderr, "chainscope ci: PASS")
	return 0
}

func parseSeverity(s string) types.Severity {
	switch s {
	case "low":
		return types.SevLow
	case "medium":
		return types.SevMedium
	case "critical":
		return types.SevCritical
	default:
		return types.SevHigh
	}
}
