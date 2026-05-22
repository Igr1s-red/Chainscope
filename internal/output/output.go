// Package output formats and writes chainscope events and alerts.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/chainscope/chainscope/internal/types"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
)

// Writer handles output formatting.
type Writer struct {
	out  io.Writer
	json bool
}

func New(out io.Writer, jsonMode bool) *Writer {
	return &Writer{out: out, json: jsonMode}
}

// WriteAlert outputs a triggered alert.
func (w *Writer) WriteAlert(a *types.Alert) {
	if w.json {
		w.writeAlertJSON(a)
		return
	}
	w.writeAlertText(a)
}

// WriteEvent outputs a raw event (info-level, for verbose mode).
func (w *Writer) WriteEvent(evt *types.ChainEvent) {
	if w.json {
		w.writeEventJSON(evt)
		return
	}
	w.writeEventText(evt)
}

type jsonAlert struct {
	Time        string `json:"time"`
	Rule        string `json:"rule"`
	Severity    string `json:"severity"`
	Pid         uint32 `json:"pid"`
	Comm        string `json:"comm"`
	RootComm    string `json:"root_comm"`
	Phase       string `json:"phase"`
	Description string `json:"description"`
	ContainerID string `json:"container_id,omitempty"`
	Runtime     string `json:"runtime,omitempty"`
	PodName     string `json:"pod_name,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
}

type jsonEvent struct {
	Time      string `json:"time"`
	EventType string `json:"event_type"`
	Phase     string `json:"phase"`
	Pid       uint32 `json:"pid"`
	Comm      string `json:"comm"`
	RootComm  string `json:"root_comm"`
	Path      string `json:"path,omitempty"`
	Argv      string `json:"argv,omitempty"`
	EnvFlags  uint32 `json:"env_flags,omitempty"`
	ExecFlags uint32 `json:"exec_flags,omitempty"`
	DstIP     string `json:"dst_ip,omitempty"`
	DstPort   uint16 `json:"dst_port,omitempty"`
	NewMode   string `json:"new_mode,omitempty"`
}

func (w *Writer) writeAlertJSON(a *types.Alert) {
	evt := a.Event
	rec := jsonAlert{
		Time:        time.Now().UTC().Format(time.RFC3339),
		Rule:        a.Rule,
		Severity:    a.Severity.String(),
		Pid:         evt.Pid,
		Comm:        evt.CommStr(),
		RootComm:    evt.RootCommStr(),
		Phase:       types.Phase(evt.Phase).String(),
		Description: a.Description,
		ContainerID: a.ContainerID,
		Runtime:     a.Runtime,
		PodName:     a.PodName,
		Namespace:   a.Namespace,
	}
	b, _ := json.Marshal(rec)
	fmt.Fprintf(w.out, "%s\n", b)
}

func (w *Writer) writeAlertText(a *types.Alert) {
	ts := time.Now().Format("15:04:05.000")
	color := severityColor(a.Severity)
	suffix := ""
	if a.ContainerID != "" {
		suffix = fmt.Sprintf(" [%s/%s]", a.Runtime, a.ContainerID)
		if a.PodName != "" {
			suffix = fmt.Sprintf(" [%s pod=%s]", a.Runtime, a.PodName)
		}
	}
	fmt.Fprintf(w.out, "%s[%s %s] %s%s%s\n",
		color,
		ts,
		a.Severity.String(),
		a.Description,
		suffix,
		colorReset,
	)
}

func (w *Writer) writeEventJSON(evt *types.ChainEvent) {
	rec := jsonEvent{
		Time:      time.Now().UTC().Format(time.RFC3339),
		EventType: types.EventType(evt.EventType).String(),
		Phase:     types.Phase(evt.Phase).String(),
		Pid:       evt.Pid,
		Comm:      evt.CommStr(),
		RootComm:  evt.RootCommStr(),
	}
	switch types.EventType(evt.EventType) {
	case types.EvtExec:
		rec.Path = evt.PathStr()
		if argv := evt.ArgvStr(); argv != "" {
			rec.Argv = argv
		}
		rec.EnvFlags = evt.EnvFlags
		rec.ExecFlags = evt.ExecFlags
	case types.EvtFileOpen, types.EvtFileWrite, types.EvtDnsLookup:
		rec.Path = evt.PathStr()
	case types.EvtNetConnect:
		rec.DstIP = evt.DstIP().String()
		rec.DstPort = evt.Dport
	case types.EvtChmod:
		rec.Path = evt.PathStr()
		rec.NewMode = fmt.Sprintf("0%o", evt.NewMode&0o7777)
	}
	b, _ := json.Marshal(rec)
	fmt.Fprintf(w.out, "%s\n", b)
}

func (w *Writer) writeEventText(evt *types.ChainEvent) {
	ts := time.Now().Format("15:04:05.000")
	evtType := types.EventType(evt.EventType).String()
	phase := types.Phase(evt.Phase).String()
	comm := evt.CommStr()

	detail := ""
	switch types.EventType(evt.EventType) {
	case types.EvtExec:
		detail = evt.PathStr()
		if argv := evt.ArgvStr(); argv != "" {
			detail += " " + argv
		}
	case types.EvtFileOpen:
		detail = evt.PathStr()
	case types.EvtFileWrite:
		detail = "WRITE " + evt.PathStr()
	case types.EvtNetConnect:
		detail = fmt.Sprintf("%s:%d", evt.DstIP(), evt.Dport)
	case types.EvtMemfdCreate:
		detail = evt.MemfdNameStr()
	case types.EvtChmod:
		detail = fmt.Sprintf("%s mode=0%o", evt.PathStr(), evt.NewMode&0o7777)
	case types.EvtDnsLookup:
		detail = "resolve " + evt.PathStr()
	case types.EvtBpfLoad:
		detail = "BPF_PROG_LOAD"
	}

	fmt.Fprintf(w.out, "%s[%s] %-14s %-10s pid=%-6d comm=%-16s %s%s\n",
		colorGray, ts, evtType, phase, evt.Pid, comm, detail, colorReset)
}

func severityColor(s types.Severity) string {
	switch s {
	case types.SevCritical, types.SevHigh:
		return colorRed
	case types.SevMedium:
		return colorYellow
	default:
		return colorCyan
	}
}
