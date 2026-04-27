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

// TestUpdateDeduplicatesPreferTerminate ensures that when the same SNI
// appears in the routes slice with both terminate and splice modes (which
// happens today when the management-service emits both an app_deployments
// row and a legacy apps row for the same app), the terminate entry wins.
// Otherwise the gateway would splice the connection, browsers would see
// the enclave's self-signed RA-TLS cert, and CORS preflight would never
// be intercepted.
func TestUpdateDeduplicatesPreferTerminate(t *testing.T) {
cases := []struct {
name   string
routes []Route
}{
{
name: "terminate first then splice",
routes: []Route{
{SNI: "app.example.com", Upstream: "10.0.0.1:443", Mode: "terminate"},
{SNI: "app.example.com", Upstream: "10.0.0.1:443", Mode: "splice"},
},
},
{
name: "splice first then terminate",
routes: []Route{
{SNI: "app.example.com", Upstream: "10.0.0.1:443", Mode: "splice"},
{SNI: "app.example.com", Upstream: "10.0.0.1:443", Mode: "terminate"},
},
},
}
for _, tc := range cases {
t.Run(tc.name, func(t *testing.T) {
table := New()
table.Update(tc.routes, "v1")
r, ok := table.Lookup("app.example.com")
if !ok {
t.Fatal("expected route for app.example.com")
}
if r.Mode != "terminate" {
t.Errorf("mode = %q, want terminate", r.Mode)
}
})
}
}
