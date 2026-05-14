package routetable

import "testing"

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
