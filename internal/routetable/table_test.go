package routetable

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestLookup(t *testing.T) {
	table := New()

	routes := []Route{
		{SNI: "app1.apps.privasys.org", Upstream: "141.94.219.130:8445"},
		{SNI: "app2.apps.privasys.org", Upstream: "198.244.201.58:8445"},
	}
	table.Update(routes, "v1")

	upstream, ok := table.LookupUpstream("app1.apps.privasys.org")
	if !ok {
		t.Fatal("expected route for app1")
	}
	if upstream != "141.94.219.130:8445" {
		t.Errorf("got %q, want 141.94.219.130:8445", upstream)
	}

	_, ok = table.LookupUpstream("unknown.apps.privasys.org")
	if ok {
		t.Fatal("expected no route for unknown app")
	}
}

func TestUpdateReturnsChanged(t *testing.T) {
	table := New()

	routes := []Route{{SNI: "a.example.com", Upstream: "1.2.3.4:443"}}
	if !table.Update(routes, "v1") {
		t.Fatal("first update should report changed")
	}
	if table.Update(routes, "v1") {
		t.Fatal("same version should report unchanged")
	}
	if !table.Update(routes, "v2") {
		t.Fatal("new version should report changed")
	}
}

func TestCount(t *testing.T) {
	table := New()
	if table.Count() != 0 {
		t.Fatalf("empty table count = %d", table.Count())
	}

	table.Update([]Route{
		{SNI: "a", Upstream: "1"},
		{SNI: "b", Upstream: "2"},
		{SNI: "c", Upstream: "3"},
	}, "v1")

	if table.Count() != 3 {
		t.Fatalf("count = %d, want 3", table.Count())
	}
}

func TestComputeVersion(t *testing.T) {
	a := []Route{{SNI: "b", Upstream: "2"}, {SNI: "a", Upstream: "1"}}
	b := []Route{{SNI: "a", Upstream: "1"}, {SNI: "b", Upstream: "2"}}

	va := ComputeVersion(a)
	vb := ComputeVersion(b)
	if va != vb {
		t.Errorf("order shouldn't matter: %q != %q", va, vb)
	}
}

// TestUpdateLastWriteWins covers the duplicate-SNI tolerance case: when the
// management-service emits the same SNI twice (legacy apps row + an
// app_deployments row), the second entry overwrites the first. Both rows
// must point at the same upstream for this to be safe; mgmt-service is
// responsible for not emitting conflicting upstreams.
func TestUpdateLastWriteWins(t *testing.T) {
	table := New()
	table.Update([]Route{
		{SNI: "app.example.com", Upstream: "10.0.0.1:443"},
		{SNI: "app.example.com", Upstream: "10.0.0.1:443"},
	}, "v1")
	r, ok := table.Lookup("app.example.com")
	if !ok {
		t.Fatal("expected route for app.example.com")
	}
	if r.Upstream != "10.0.0.1:443" {
		t.Errorf("upstream = %q, want 10.0.0.1:443", r.Upstream)
	}
}

// TestLookupCaseInsensitive ensures SNI lookup is ASCII case-insensitive
// (RFC 6066). Routes registered with mixed-case SNI (e.g. mgmt-service
// emits "DEV---eu-paris-1-mgr.apps-test.privasys.org" with uppercase env
// name) must be reachable when the TLS client lowercases the SNI before
// sending it (rustls, Go crypto/tls, browsers all do this).
func TestLookupCaseInsensitive(t *testing.T) {
	table := New()
	table.Update([]Route{
		{SNI: "DEV---eu-paris-1-mgr.apps-test.privasys.org", Upstream: "141.94.219.130:8446"},
	}, "v1")

	for _, q := range []string{
		"DEV---eu-paris-1-mgr.apps-test.privasys.org",
		"dev---eu-paris-1-mgr.apps-test.privasys.org",
		"Dev---Eu-Paris-1-Mgr.Apps-Test.Privasys.Org",
	} {
		r, ok := table.Lookup(q)
		if !ok {
			t.Errorf("Lookup(%q): no route", q)
			continue
		}
		if r.Upstream != "141.94.219.130:8446" {
			t.Errorf("Lookup(%q): upstream = %q", q, r.Upstream)
		}
	}
}

// TestRouteStateParsing covers the optional "state" field of the route
// feed: absent means active, "quarantined" marks the route, and an unknown
// value is treated as active.
func TestRouteStateParsing(t *testing.T) {
	var routes []Route
	feed := `[
		{"sni": "a.apps.privasys.org", "upstream": "10.0.0.1:443"},
		{"sni": "b.apps.privasys.org", "upstream": "10.0.0.2:443", "state": "quarantined"},
		{"sni": "c.apps.privasys.org", "upstream": "10.0.0.3:443", "state": "something-new"}
	]`
	if err := json.Unmarshal([]byte(feed), &routes); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	table := New()
	table.Update(routes, "v1")

	for sni, want := range map[string]bool{
		"a.apps.privasys.org": false,
		"b.apps.privasys.org": true,
		"c.apps.privasys.org": false,
	} {
		r, ok := table.Lookup(sni)
		if !ok {
			t.Fatalf("Lookup(%q): no route", sni)
		}
		if r.Quarantined() != want {
			t.Errorf("Lookup(%q).Quarantined() = %v, want %v", sni, r.Quarantined(), want)
		}
	}
	if got := table.QuarantinedCount(); got != 1 {
		t.Errorf("QuarantinedCount() = %d, want 1", got)
	}

	// An active route marshals without the field, so the shape of a
	// feed without quarantines is unchanged.
	out, err := json.Marshal(routes[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(out), "state") {
		t.Errorf("active route marshals a state: %s", out)
	}
}

// TestRouteStateRelease checks that a route whose state disappears from
// the feed is served as active again after the next update.
func TestRouteStateRelease(t *testing.T) {
	table := New()
	table.Update([]Route{{SNI: "a", Upstream: "1", State: StateQuarantined}}, "v1")
	if r, _ := table.Lookup("a"); !r.Quarantined() {
		t.Fatal("route should be quarantined")
	}
	table.Update([]Route{{SNI: "a", Upstream: "1"}}, "v2")
	if r, _ := table.Lookup("a"); r.Quarantined() {
		t.Fatal("route should be active after release")
	}
	if got := table.QuarantinedCount(); got != 0 {
		t.Errorf("QuarantinedCount() = %d, want 0", got)
	}
}

// TestComputeVersionState checks that the state moves the computed
// version, and that routes without a state keep the version they had
// before the field existed.
func TestComputeVersionState(t *testing.T) {
	active := []Route{{SNI: "a", Upstream: "1"}}
	quarantined := []Route{{SNI: "a", Upstream: "1", State: StateQuarantined}}
	if ComputeVersion(active) == ComputeVersion(quarantined) {
		t.Error("quarantine should change the version")
	}

	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%s\n", "a", "1", "")
	legacy := fmt.Sprintf("sha256:%x", h.Sum(nil))
	if got := ComputeVersion(active); got != legacy {
		t.Errorf("version without state = %q, want legacy %q", got, legacy)
	}
}

// TestOnQuarantine checks that the hook fires once per host newly marked
// quarantined, after the swap, and not for hosts already quarantined, new
// hosts or releases.
func TestOnQuarantine(t *testing.T) {
	table := New()
	var fired []string
	table.OnQuarantine(func(host string) {
		if r, _ := table.Lookup(host); !r.Quarantined() {
			t.Errorf("hook for %q ran before the swap", host)
		}
		fired = append(fired, host)
	})

	table.Update([]Route{
		{SNI: "A.example.com", Upstream: "1"},
		{SNI: "b.example.com", Upstream: "2"},
	}, "v1")
	table.Update([]Route{
		{SNI: "A.example.com", Upstream: "1", State: StateQuarantined},
		{SNI: "b.example.com", Upstream: "2"},
		{SNI: "new.example.com", Upstream: "3", State: StateQuarantined},
	}, "v2")
	if len(fired) != 1 || fired[0] != "a.example.com" {
		t.Fatalf("fired = %v, want [a.example.com]", fired)
	}

	// Still quarantined, then released: no new calls.
	table.Update([]Route{{SNI: "a.example.com", Upstream: "1", State: StateQuarantined}}, "v3")
	table.Update([]Route{{SNI: "a.example.com", Upstream: "1"}}, "v4")
	if len(fired) != 1 {
		t.Fatalf("fired = %v, want a single call", fired)
	}
}
