package terminate

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"testing"

	"github.com/Privasys/platform-gateway/internal/routetable"
)

// A "tunnel:<id>" upstream is not a host:port. Terminate mode must still
// build its reverse proxy and send every connection through the injected
// dialer with the route's upstream.
func TestTerminateTunnelUpstream(t *testing.T) {
	srv, hits := upstreamCounter(t)

	var mu sync.Mutex
	var dialed []string
	h := New(Options{
		TLSConfig:    &tls.Config{Certificates: []tls.Certificate{selfSignedTLS(t, quarantineTestHost)}},
		InsecureSkip: true,
		Dial: func(ctx context.Context, upstream, _ string) (net.Conn, error) {
			mu.Lock()
			dialed = append(dialed, upstream)
			mu.Unlock()
			var d net.Dialer
			return d.DialContext(ctx, "tcp", srv.Listener.Addr().String())
		},
	})
	route := routetable.Route{SNI: quarantineTestHost, Upstream: "tunnel:enc-1"}

	tc, br := terminatedClient(t, h, route)
	resp, body := roundTrip(t, tc, br, mustRequest(t, "GET", "application/json"))
	if resp.StatusCode != 200 || body != "from enclave" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	if hits.Load() != 1 {
		t.Fatalf("upstream hits = %d", hits.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(dialed) == 0 {
		t.Fatal("dialer not used")
	}
	for _, u := range dialed {
		if u != "tunnel:enc-1" {
			t.Fatalf("dialed %q, want tunnel:enc-1", u)
		}
	}
}
