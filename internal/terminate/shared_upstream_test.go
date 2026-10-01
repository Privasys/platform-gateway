package terminate

import (
	"net"
	"testing"

	"github.com/Privasys/platform-gateway/internal/routetable"
)

// A mutualised enclave serves many apps from one upstream address. Opening a
// sealed WebSocket to one of them must not close the mux connections, and so
// the browser sockets, of the others.
func TestMuxPoolSurvivesAnotherAppOnTheSameUpstream(t *testing.T) {
	h := New(Options{})
	a := routetable.Route{SNI: "a.apps.privasys.org", Upstream: "10.0.0.1:443"}
	b := routetable.Route{SNI: "b.apps.privasys.org", Upstream: "10.0.0.1:443"}

	poolA := h.muxPoolFor(a)
	client, server := net.Pipe()
	defer server.Close()
	connA := &gwMuxConn{conn: client, streams: map[muxKey]*gwStream{}, dead: make(chan struct{})}
	poolA.conns = append(poolA.conns, connA)

	h.muxPoolFor(b)

	if connA.isDead() {
		t.Fatal("a mux connection of app A was closed when app B got its pool")
	}
	if h.muxPoolFor(a) != poolA {
		t.Fatal("app A's pool was rebuilt")
	}
}

// A policy change for the same app still replaces its pool, so the new
// verifier applies.
func TestMuxPoolReplacedOnPolicyChange(t *testing.T) {
	h := New(Options{})
	r := routetable.Route{SNI: "a.apps.privasys.org", Upstream: "10.0.0.1:443"}

	old := h.muxPoolFor(r)
	client, server := net.Pipe()
	defer server.Close()
	c := &gwMuxConn{conn: client, streams: map[muxKey]*gwStream{}, dead: make(chan struct{})}
	old.conns = append(old.conns, c)

	r.AttestationPolicy = []byte(`{"oids":{}}`)
	if h.muxPoolFor(r) == old {
		t.Fatal("a policy change kept the old pool")
	}
	if !c.isDead() {
		t.Fatal("the pool under the previous policy was left open")
	}
	if len(h.muxPools) != 1 {
		t.Fatalf("%d pools cached, want 1", len(h.muxPools))
	}
}

// A retired route (app stopped, enclave moved) takes its cache entries with
// it; its neighbours on the same upstream keep theirs.
func TestForgetDropsOnlyTheRetiredRoute(t *testing.T) {
	h := New(Options{})
	a := routetable.Route{SNI: "a.apps.privasys.org", Upstream: "10.0.0.1:443"}
	b := routetable.Route{SNI: "b.apps.privasys.org", Upstream: "10.0.0.1:443"}

	poolA := h.muxPoolFor(a)
	client, server := net.Pipe()
	defer server.Close()
	connA := &gwMuxConn{conn: client, streams: map[muxKey]*gwStream{}, dead: make(chan struct{})}
	poolA.conns = append(poolA.conns, connA)
	poolB := h.muxPoolFor(b)
	if _, err := h.proxyFor(a); err != nil {
		t.Fatal(err)
	}
	rpB, err := h.proxyFor(b)
	if err != nil {
		t.Fatal(err)
	}

	h.Forget(a)

	if !connA.isDead() {
		t.Fatal("the retired route's mux connection was left open")
	}
	if len(h.muxPools) != 1 || len(h.proxies) != 1 {
		t.Fatalf("%d pools and %d proxies cached, want 1 and 1", len(h.muxPools), len(h.proxies))
	}
	if h.muxPoolFor(b) != poolB {
		t.Fatal("app B's pool was dropped with app A's route")
	}
	if again, _ := h.proxyFor(b); again != rpB {
		t.Fatal("app B's proxy was dropped with app A's route")
	}
	if h.muxPoolFor(a) == poolA {
		t.Fatal("app A's pool was not rebuilt after Forget")
	}
}

func TestProxyCacheKeepsOtherAppsOnTheSameUpstream(t *testing.T) {
	h := New(Options{})
	a := routetable.Route{SNI: "a.apps.privasys.org", Upstream: "10.0.0.1:443"}
	b := routetable.Route{SNI: "b.apps.privasys.org", Upstream: "10.0.0.1:443"}

	rpA, err := h.proxyFor(a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.proxyFor(b); err != nil {
		t.Fatal(err)
	}
	again, err := h.proxyFor(a)
	if err != nil {
		t.Fatal(err)
	}
	if again != rpA {
		t.Fatal("app A's proxy, and its pooled connections, were dropped for app B")
	}
}
