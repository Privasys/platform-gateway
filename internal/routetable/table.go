// Package routetable provides a thread-safe in-memory routing table
// mapping SNI hostnames to upstream backend addresses.
package routetable

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
)

// Route maps an SNI hostname to an upstream backend.
//
// The gateway picks splice vs. terminate transport per-connection based on
// the client's TLS ALPN list (clients that advertise `privasys-ratls/1`
// get spliced; everything else is terminated when a public LE wildcard
// cert is loaded). There is no per-app transport hint here.
//
// AttestationPolicy is an opaque JSON document with the expected RA-TLS
// OID values to enforce on the internal leg in terminate mode. Shape:
//
//	{ "expected_oids": { "1.3.6.1.4.1.65230.2.5": "<hex>" } }
type Route struct {
	SNI               string          `json:"sni"`
	Upstream          string          `json:"upstream"`
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
//
// SNI hostnames are ASCII case-insensitive per RFC 6066, and TLS clients
// (rustls, Go crypto/tls, browsers) typically lowercase the SNI before
// sending it. The lookup key is canonicalized to lowercase to match.
func (t *Table) Lookup(sni string) (Route, bool) {
	m := t.routes.Load()
	r, ok := (*m)[strings.ToLower(sni)]
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
		// Last write wins. Duplicate SNIs (e.g. legacy apps row + an
		// app_deployments row) are tolerated; mgmt-service is responsible
		// for not emitting conflicting upstreams.
		//
		// SNI is ASCII case-insensitive (RFC 6066); store keys lowercase
		// so Lookup matches what TLS clients actually transmit.
		m[strings.ToLower(r.SNI)] = r
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
		fmt.Fprintf(h, "%s\x00%s\x00%s\n", r.SNI, r.Upstream, string(r.AttestationPolicy))
	}
	return fmt.Sprintf("sha256:%x", h.Sum(nil))
}
