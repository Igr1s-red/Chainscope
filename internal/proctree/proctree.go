// Package proctree maintains a userspace view of the process tree rooted at
// each package manager invocation, enriched with data from /proc.
package proctree

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/chainscope/chainscope/internal/types"
)

// Node represents one process in the tracked supply-chain subtree.
type Node struct {
	PID      uint32
	PPID     uint32
	RootPID  uint32
	Comm     string
	RootComm string
	Cmdline  string
	Phase    types.Phase
}

// Tree is a concurrent map of pid → Node for all tracked processes.
type Tree struct {
	mu    sync.RWMutex
	nodes map[uint32]*Node
}

func New() *Tree {
	return &Tree{nodes: make(map[uint32]*Node)}
}

// Add inserts or updates a node from an exec event.
func (t *Tree) Add(evt *types.ChainEvent) {
	cmdline := readCmdline(evt.Pid)
	node := &Node{
		PID:      evt.Pid,
		PPID:     evt.Ppid,
		RootPID:  evt.RootPid,
		Comm:     evt.CommStr(),
		RootComm: evt.RootCommStr(),
		Cmdline:  cmdline,
		Phase:    types.Phase(evt.Phase),
	}
	t.mu.Lock()
	t.nodes[evt.Pid] = node
	t.mu.Unlock()
}

// Remove cleans up on process exit.
func (t *Tree) Remove(pid uint32) {
	t.mu.Lock()
	delete(t.nodes, pid)
	t.mu.Unlock()
}

// Get returns the node for a PID, or nil.
func (t *Tree) Get(pid uint32) *Node {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.nodes[pid]
}

// Chain returns the ancestry chain from pid up to the root, oldest first.
func (t *Tree) Chain(pid uint32) []*Node {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var chain []*Node
	seen := make(map[uint32]bool)
	cur := pid
	for {
		if seen[cur] {
			break
		}
		seen[cur] = true
		n := t.nodes[cur]
		if n == nil {
			break
		}
		chain = append(chain, n)
		if n.PID == n.RootPID {
			break
		}
		cur = n.PPID
	}
	// Reverse so oldest is first.
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain
}

// FormatChain returns a human-readable process chain string.
func (t *Tree) FormatChain(pid uint32) string {
	chain := t.Chain(pid)
	parts := make([]string, 0, len(chain))
	for _, n := range chain {
		parts = append(parts, fmt.Sprintf("%s(%d)", n.Comm, n.PID))
	}
	return strings.Join(parts, " → ")
}

func readCmdline(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	// cmdline is NUL-separated; replace with spaces.
	for i, b := range data {
		if b == 0 {
			data[i] = ' '
		}
	}
	return strings.TrimSpace(string(data))
}
