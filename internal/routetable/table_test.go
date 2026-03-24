package routetable

import "testing"

func TestLookup(t *testing.T) {
	table := New()

	routes := []Route{
		{SNI: "app1.apps.privasys.org", Upstream: "141.94.219.130:8445"},
		{SNI: "app2.apps.privasys.org", Upstream: "198.244.201.58:8445"},
	}
	table.Update(routes, "v1")

	upstream, ok := table.Lookup("app1.apps.privasys.org")
	if !ok {
		t.Fatal("expected route for app1")
	}
	if upstream != "141.94.219.130:8445" {
		t.Errorf("got %q, want 141.94.219.130:8445", upstream)
	}

	_, ok = table.Lookup("unknown.apps.privasys.org")
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
