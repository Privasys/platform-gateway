// Package routetable provides a thread-safe in-memory routing table
// mapping SNI hostnames to upstream backend addresses.
package routetable

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"sync/atomic"
)

// Route maps an SNI hostname to an upstream backend.
//
// Mode controls how the gateway handles inbound TLS for this SNI:
//   - "" or "splice" (default): pure L4 SNI splice; the enclave terminates
//     RA-TLS itself, the gateway never touches plaintext.
//   - "terminate": the gateway terminates TLS with a public LE wildcard
//     certificate, opens an internal RA-TLS connection to Upstream
//     (verified per AttestationPolicy), and forwards HTTP. Used to let
//     browsers reach enclave apps via the session-relay flow.
//
// AttestationPolicy is an opaque JSON document with the expected RA-TLS
// OID values to enforce on the internal leg in terminate mode. Shape:
//
//	{ "expected_oids": { "1.3.6.1.4.1.65230.2.5": "<hex>" } }
type Route struct {
	SNI               string          `json:"sni"`
	Upstream          string          `json:"upstream"`
	Mode              string          `json:"mode,omitempty"`
	AttestationPolicy json.RawMessage `json:"attestation_policy,omitempty"`
}

// Table is a lock-free routing table. Updates swap the entire map atomically.
type Table struct {
	routes  atomic.Pointer[map[string]Route]
	version atomic.Pointer[string]
	count   atomic.Int64
}

// New creates an empty routing table.
func New() *Table {
	t := &Table{}
	empty := make(map[string]Route)
	t.routes.Store(&empty)
	v := ""
	t.version.Store(&v)
	return t
}

// Lookup returns the route for the given SNI hostname.
// Returns (Route{}, false) if no route exists.
func (t *Table) Lookup(sni string) (Route, bool) {
	m := t.routes.Load()
	r, ok := (*m)[sni]
	return r, ok
}

// LookupUpstream is a compatibility helper that returns just the upstream
// address. Prefer Lookup when the caller needs the mode/policy as well.
func (t *Table) LookupUpstream(sni string) (string, bool) {
	r, ok := t.Lookup(sni)
	if !ok {
		return "", false
	}
	return r.Upstream, true
}

// Update replaces the entire routing table with the given routes.
// Returns true if the table changed.
func (t *Table) Update(routes []Route, version string) bool {
	currentVersion := t.version.Load()
	if currentVersion != nil && *currentVersion == version && version != "" {
		return false
	}

	m := make(map[string]Route, len(routes))
	for _, r := range routes {
		// Tie-break: if the same SNI appears multiple times (e.g. mgmt-service
		// returns both a legacy apps row and an app_deployments row),
		// prefer terminate over splice so the gateway serves the public
		// LE wildcard cert rather than splicing through to the enclave's
		// self-signed RA-TLS cert.
		if existing, ok := m[r.SNI]; ok && existing.Mode == "terminate" && r.Mode != "terminate" {
			continue
		}
		m[r.SNI] = r
	}

	t.routes.Store(&m)
	t.version.Store(&version)
	t.count.Store(int64(len(routes)))
	return true
}

// Snapshot returns a copy of the current routes (for diagnostics endpoints).
func (t *Table) Snapshot() []Route {
	m := t.routes.Load()
	if m == nil {
		return nil
	}
	out := make([]Route, 0, len(*m))
	for _, r := range *m {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SNI < out[j].SNI })
	return out
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
		fmt.Fprintf(h, "%s\x00%s\x00%s\x00%s\n", r.SNI, r.Upstream, r.Mode, string(r.AttestationPolicy))
	}
	return fmt.Sprintf("sha256:%x", h.Sum(nil))
}
