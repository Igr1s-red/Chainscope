package detector

import (
	"fmt"
	"sync"
	"time"

	"github.com/chainscope/chainscope/internal/types"
)

// Deduplicator suppresses repeated firings of the same rule within a rolling
// TTL window, keyed on rule + root_pid. A single attack pattern (e.g. every
// gcc invocation triggering compiler-network) fires once per package manager
// invocation per TTL period rather than hundreds of times.
type Deduplicator struct {
	mu  sync.Mutex
	seen map[string]time.Time
	ttl  time.Duration
}

func NewDeduplicator(ttl time.Duration) *Deduplicator {
	return &Deduplicator{
		seen: make(map[string]time.Time),
		ttl:  ttl,
	}
}

// Filter removes alerts that were already seen within the TTL window and
// returns the surviving alerts. Expired entries are evicted on each call.
func (d *Deduplicator) Filter(alerts []types.Alert) []types.Alert {
	if len(alerts) == 0 {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()

	// Evict stale entries to prevent unbounded map growth.
	for k, t := range d.seen {
		if now.Sub(t) >= d.ttl {
			delete(d.seen, k)
		}
	}

	var out []types.Alert
	for _, a := range alerts {
		key := a.Rule + "\x00" + fmt.Sprint(a.Event.RootPid)
		if t, exists := d.seen[key]; exists && now.Sub(t) < d.ttl {
			continue
		}
		d.seen[key] = now
		out = append(out, a)
	}
	return out
}
