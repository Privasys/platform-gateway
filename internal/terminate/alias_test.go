package terminate

import (
	"net/http/httptest"
	"testing"

	"github.com/Privasys/platform-gateway/internal/routetable"
)

// The enclave has no route for an adopter's hostname: it only knows the
// canonical app hostname. The reverse proxy must therefore rewrite Host to
// the canonical name on an alias route, and leave it alone otherwise.
func TestProxyRewritesHostToCanonical(t *testing.T) {
	cases := []struct {
		name     string
		route    routetable.Route
		wantHost string
	}{
		{
			name:     "platform route keeps its own hostname",
			route:    routetable.Route{SNI: "harness.apps.privasys.org", Upstream: "10.0.0.1:443"},
			wantHost: "harness.apps.privasys.org",
		},
		{
			name:     "alias route presents the canonical hostname upstream",
			route:    routetable.Route{SNI: "harness.example.com", Upstream: "10.0.0.1:443", Canonical: "harness.apps.privasys.org"},
			wantHost: "harness.apps.privasys.org",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := New(Options{})
			rp, err := h.proxyFor(tc.route)
			if err != nil {
				t.Fatalf("proxyFor: %v", err)
			}
			req := httptest.NewRequest("GET", "https://"+tc.route.SNI+"/index.html", nil)
			rp.Director(req)
			if req.Host != tc.wantHost {
				t.Errorf("Host = %q, want %q", req.Host, tc.wantHost)
			}
			// The edge marker must survive the rewrite: it is what tells
			// the enclave that someone else terminated TLS on this leg.
			if got := req.Header.Get("X-Privasys-Edge"); got != "terminate" {
				t.Errorf("X-Privasys-Edge = %q, want %q", got, "terminate")
			}
		})
	}
}

// Two routes on the same upstream that differ only in canonical name must not
// share a cached proxy, or an alias would inherit the wrong Host rewrite.
func TestProxyCacheSeparatesAliasFromCanonical(t *testing.T) {
	h := New(Options{})
	canonical := routetable.Route{SNI: "harness.apps.privasys.org", Upstream: "10.0.0.1:443"}
	alias := routetable.Route{SNI: "harness.example.com", Upstream: "10.0.0.1:443", Canonical: "harness.apps.privasys.org"}

	if _, err := h.proxyFor(canonical); err != nil {
		t.Fatalf("proxyFor(canonical): %v", err)
	}
	rp, err := h.proxyFor(alias)
	if err != nil {
		t.Fatalf("proxyFor(alias): %v", err)
	}
	req := httptest.NewRequest("GET", "https://harness.example.com/", nil)
	rp.Director(req)
	if req.Host != "harness.apps.privasys.org" {
		t.Errorf("Host = %q, want the canonical hostname", req.Host)
	}
}
