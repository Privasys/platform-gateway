// Package routetable provides a thread-safe in-memory routing table
// mapping SNI hostnames to upstream backend addresses.
package routetable

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"sync/atomic"
)

// Route maps an SNI hostname to an upstream backend.
type Route struct {
	SNI      string `json:"sni"`
	Upstream string `json:"upstream"`
}

// Table is a lock-free routing table. Updates swap the entire map atomically.
type Table struct {
	routes  atomic.Pointer[map[string]string] // sni → upstream
	version atomic.Pointer[string]
	count   atomic.Int64
}

// New creates an empty routing table.
func New() *Table {
	t := &Table{}
	empty := make(map[string]string)
	t.routes.Store(&empty)
	v := ""
	t.version.Store(&v)
	return t
}

// Lookup returns the upstream address for the given SNI hostname.
// Returns ("", false) if no route exists.
func (t *Table) Lookup(sni string) (string, bool) {
	m := t.routes.Load()
	upstream, ok := (*m)[sni]
	return upstream, ok
}

// Update replaces the entire routing table with the given routes.
// Returns true if the table changed.
func (t *Table) Update(routes []Route, version string) bool {
	currentVersion := t.version.Load()
	if currentVersion != nil && *currentVersion == version && version != "" {
		return false
	}

	m := make(map[string]string, len(routes))
	for _, r := range routes {
		m[r.SNI] = r.Upstream
	}

	t.routes.Store(&m)
	t.version.Store(&version)
	t.count.Store(int64(len(routes)))
	return true
}

// Version returns the current routing table version (ETag).
func (t *Table) Version() string {
	v := t.version.Load()
	if v == nil {
		return ""
	}
	return *v
}

// Count returns the number of routes in the table.
func (t *Table) Count() int {
	return int(t.count.Load())
}

// ComputeVersion computes a deterministic version string from a set of routes.
func ComputeVersion(routes []Route) string {
	sorted := make([]Route, len(routes))
	copy(sorted, routes)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].SNI < sorted[j].SNI
	})

	h := sha256.New()
	for _, r := range sorted {
		fmt.Fprintf(h, "%s\x00%s\n", r.SNI, r.Upstream)
	}
	return fmt.Sprintf("sha256:%x", h.Sum(nil))
}
