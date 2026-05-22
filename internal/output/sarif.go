package output

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/chainscope/chainscope/internal/types"
)

// SARIFWriter accumulates alerts and writes a SARIF 2.1.0 document on Close.
// Used for GitHub Advanced Security integration.
type SARIFWriter struct {
	path    string
	mu      sync.Mutex
	results []sarifResult
	rules   map[string]sarifRule
}

func NewSARIFWriter(path string) *SARIFWriter {
	return &SARIFWriter{
		path:  path,
		rules: make(map[string]sarifRule),
	}
}

// AddAlert records one alert. Thread-safe.
func (w *SARIFWriter) AddAlert(a *types.Alert) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if _, exists := w.rules[a.Rule]; !exists {
		w.rules[a.Rule] = sarifRule{
			ID: a.Rule,
			ShortDescription: sarifMessage{
				Text: a.Rule,
			},
			Properties: sarifRuleProperties{
				SecuritySeverity: cvssScore(a.Severity),
			},
		}
	}

	loc := sarifLocation{
		PhysicalLocation: sarifPhysicalLocation{
			ArtifactLocation: sarifArtifactLocation{
				URI: artifactURI(a.Event),
			},
			Region: sarifRegion{StartLine: 1},
		},
	}

	w.results = append(w.results, sarifResult{
		RuleID:  a.Rule,
		Level:   sarifLevel(a.Severity),
		Message: sarifMessage{Text: a.Description},
		Locations: []sarifLocation{loc},
		// partialFingerprints lets GitHub deduplicate alerts across runs.
		// The fingerprint is stable: same rule + root_comm + artifact path
		// always produces the same hash regardless of PID or timestamp.
		PartialFingerprints: map[string]string{
			"primaryLocationLineHash/v1": alertFingerprint(a),
		},
		Properties: map[string]any{
			"pid":       a.Event.Pid,
			"comm":      a.Event.CommStr(),
			"root_comm": a.Event.RootCommStr(),
			"phase":     types.Phase(a.Event.Phase).String(),
			"severity":  a.Severity.String(),
		},
	})
}

// Close writes the SARIF document to the path given at construction.
func (w *SARIFWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	rules := make([]sarifRule, 0, len(w.rules))
	for _, r := range w.rules {
		rules = append(rules, r)
	}

	doc := sarifDocument{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:    "chainscope",
					Version: "0.1.0",
					InformationURI: "https://github.com/chainscope/chainscope",
					Rules: rules,
				},
			},
			Results: w.results,
		}},
	}

	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal SARIF: %w", err)
	}
	if err := os.WriteFile(w.path, b, 0o644); err != nil {
		return fmt.Errorf("write SARIF %s: %w", w.path, err)
	}
	return nil
}

func sarifLevel(s types.Severity) string {
	switch s {
	case types.SevCritical, types.SevHigh:
		return "error"
	case types.SevMedium:
		return "warning"
	default:
		return "note"
	}
}

func cvssScore(s types.Severity) string {
	switch s {
	case types.SevCritical:
		return "9.0"
	case types.SevHigh:
		return "7.0"
	case types.SevMedium:
		return "5.0"
	case types.SevLow:
		return "3.0"
	default:
		return "1.0"
	}
}

// alertFingerprint returns a stable 16-char hex string for deduplication.
// Inputs are rule, root_comm, and the primary artifact — all stable across runs.
func alertFingerprint(a *types.Alert) string {
	key := a.Rule + "\x00" + a.Event.RootCommStr() + "\x00" + artifactURI(a.Event)
	h := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%x", h[:8])
}

func artifactURI(evt *types.ChainEvent) string {
	if p := evt.PathStr(); p != "" {
		return p
	}
	return evt.CommStr()
}

// ---- SARIF 2.1.0 schema types (minimal) ----

type sarifDocument struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool    `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string              `json:"id"`
	ShortDescription sarifMessage        `json:"shortDescription"`
	Properties       sarifRuleProperties `json:"properties"`
}

type sarifRuleProperties struct {
	SecuritySeverity string `json:"security-severity"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}
