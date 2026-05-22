// Package baseline implements learn/enforce mode: build a profile of expected
// supply-chain behaviors during a reference run, then alert on deviations.
package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/chainscope/chainscope/internal/types"
)

// Profile is the on-disk representation of a learned baseline.
type Profile struct {
	Version   int             `json:"version"`
	CreatedAt string          `json:"created_at"`
	Seen      map[string]bool `json:"seen"`
}

// Learner accumulates observations from live events.
type Learner struct {
	mu      sync.Mutex
	profile Profile
}

// NewLearner returns a ready-to-use Learner.
func NewLearner() *Learner {
	return &Learner{
		profile: Profile{
			Version:   1,
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
			Seen:      make(map[string]bool),
		},
	}
}

// Learn records an event into the in-memory profile.
func (l *Learner) Learn(evt *types.ChainEvent) {
	key := makeKey(evt)
	if key == "" {
		return
	}
	l.mu.Lock()
	l.profile.Seen[key] = true
	l.mu.Unlock()
}

// Save writes the accumulated profile to path as JSON.
func (l *Learner) Save(path string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, err := json.MarshalIndent(l.profile, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling profile: %w", err)
	}
	return os.WriteFile(path, b, 0o644)
}

// Enforcer checks live events against a previously learned profile.
type Enforcer struct {
	profile Profile
}

// LoadProfile reads a JSON profile written by Learner.Save.
func LoadProfile(path string) (*Enforcer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading profile: %w", err)
	}
	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing profile: %w", err)
	}
	if p.Seen == nil {
		p.Seen = make(map[string]bool)
	}
	return &Enforcer{profile: p}, nil
}

// Check returns an alert if evt represents a behavior not seen during learning,
// or nil if it is within the baseline.
func (e *Enforcer) Check(evt *types.ChainEvent) *types.Alert {
	key := makeKey(evt)
	if key == "" || e.profile.Seen[key] {
		return nil
	}
	return &types.Alert{
		Event:       evt,
		Rule:        "baseline-deviation",
		Severity:    types.SevMedium,
		Description: fmt.Sprintf("behavior not seen in baseline (%s)", key),
	}
}

// makeKey produces a coarse-grained string key for an event suitable for
// baseline comparison. Returns "" for events that don't benefit from baselining.
//
// File paths use directory-level granularity to tolerate version-specific names.
// Network events use exact IP + port since those should be stable across runs.
func makeKey(evt *types.ChainEvent) string {
	evtType := types.EventType(evt.EventType)
	phase := types.Phase(evt.Phase).String()
	comm := evt.CommStr()

	switch evtType {
	case types.EvtNetConnect:
		return fmt.Sprintf("net|%s|%s|%s|%d", phase, comm, evt.DstIP(), evt.Dport)
	case types.EvtFileOpen, types.EvtFileWrite:
		dir := filepath.Dir(evt.PathStr())
		return fmt.Sprintf("file|%s|%s|%s", phase, comm, dir)
	case types.EvtExec:
		dir := filepath.Dir(evt.PathStr())
		return fmt.Sprintf("exec|%s|%s|%s", phase, comm, dir)
	case types.EvtChmod:
		return fmt.Sprintf("chmod|%s|%s|0%o", phase, comm, evt.NewMode&0o7777)
	case types.EvtDnsLookup:
		return fmt.Sprintf("dns|%s|%s|%s", phase, comm, evt.PathStr())
	default:
		return ""
	}
}
