// Package metrics exposes Prometheus-compatible metrics over HTTP.
// No external dependencies — uses manual text/plain exposition format.
package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Server serves /metrics and /healthz.
type Server struct {
	eventCount   atomic.Int64
	procCount    atomic.Int64
	droppedCount atomic.Uint64 // ring buffer overflow drops
	alertCounts  sync.Map      // key: "rule\x00severity" → *atomic.Int64
}

func New() *Server { return &Server{} }

// RecordEvent increments the total event counter.
func (s *Server) RecordEvent() { s.eventCount.Add(1) }

// SetProcTreeSize updates the gauge tracking monitored process count.
func (s *Server) SetProcTreeSize(n int) { s.procCount.Store(int64(n)) }

// SetDropped updates the ring buffer drop counter (polled from Loader.DroppedEvents).
func (s *Server) SetDropped(n uint64) { s.droppedCount.Store(n) }

// RecordAlert increments the counter for the given rule+severity pair.
func (s *Server) RecordAlert(rule, severity string) {
	key := rule + "\x00" + severity
	v, _ := s.alertCounts.LoadOrStore(key, &atomic.Int64{})
	v.(*atomic.Int64).Add(1)
}

// ListenAndServe starts the HTTP server on addr (e.g. ":9090").
func (s *Server) ListenAndServe(addr string) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", s)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "ok\n")
	})
	return http.ListenAndServe(addr, mux)
}

// ServeHTTP writes Prometheus text format metrics.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	var sb strings.Builder

	// Total events processed.
	sb.WriteString("# HELP chainscope_events_total Total eBPF events processed.\n")
	sb.WriteString("# TYPE chainscope_events_total counter\n")
	fmt.Fprintf(&sb, "chainscope_events_total %d\n\n", s.eventCount.Load())

	// Process tree size (gauge).
	sb.WriteString("# HELP chainscope_proctree_size Number of processes currently tracked.\n")
	sb.WriteString("# TYPE chainscope_proctree_size gauge\n")
	fmt.Fprintf(&sb, "chainscope_proctree_size %d\n\n", s.procCount.Load())

	// Ring buffer drops (counter).
	sb.WriteString("# HELP chainscope_ringbuf_dropped_total Events dropped due to ring buffer overflow.\n")
	sb.WriteString("# TYPE chainscope_ringbuf_dropped_total counter\n")
	fmt.Fprintf(&sb, "chainscope_ringbuf_dropped_total %d\n\n", s.droppedCount.Load())

	// Per-rule alert counters — collected, sorted, then written.
	type kv struct{ key, rule, severity string; n int64 }
	var rows []kv
	s.alertCounts.Range(func(k, v any) bool {
		key := k.(string)
		parts := strings.SplitN(key, "\x00", 2)
		if len(parts) == 2 {
			rows = append(rows, kv{
				key:      key,
				rule:     parts[0],
				severity: parts[1],
				n:        v.(*atomic.Int64).Load(),
			})
		}
		return true
	})
	sort.Slice(rows, func(i, j int) bool { return rows[i].key < rows[j].key })

	if len(rows) > 0 {
		sb.WriteString("# HELP chainscope_alerts_total Alerts triggered, by rule and severity.\n")
		sb.WriteString("# TYPE chainscope_alerts_total counter\n")
		for _, row := range rows {
			fmt.Fprintf(&sb, "chainscope_alerts_total{rule=%q,severity=%q} %d\n",
				row.rule, row.severity, row.n)
		}
	}

	fmt.Fprint(w, sb.String())
}
