package tunnel

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// countingAuth counts Authorize calls and denies them all.
type countingAuth struct{ calls atomic.Int32 }

func (c *countingAuth) Authorize(context.Context, AuthRequest) (string, error) {
	c.calls.Add(1)
	return "", fmt.Errorf("denied")
}

func TestOversizedTunnelOpenIsRefused(t *testing.T) {
	auth := &countingAuth{}
	addr, _, pool := startGateway(t, auth)
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		RootCAs: pool, ServerName: "tunnel.apps.test", NextProtos: []string{ALPN},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	go fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: tunnel.apps.test\r\nUpgrade: %s\r\nX-Pad: %s\r\n\r\n",
		Path, UpgradeProtocol, strings.Repeat("a", maxRequestHead+maxRequestBody+1))
	_, _ = io.Copy(io.Discard, conn)
	if n := auth.calls.Load(); n != 0 {
		t.Fatalf("Authorize called %d times for an oversized open", n)
	}
}

func TestSourceBuckets(t *testing.T) {
	now := time.Unix(1000, 0)
	s := newSourceBuckets(10, 5)
	s.now = func() time.Time { return now }
	for i := 0; i < 5; i++ {
		if !s.take("a") {
			t.Fatalf("attempt %d inside the burst refused", i)
		}
	}
	if s.take("a") {
		t.Fatal("attempt past the burst admitted")
	}
	if !s.take("b") {
		t.Fatal("another source must have its own bucket")
	}
	now = now.Add(6 * time.Second) // 10 a minute: one token
	if !s.take("a") || s.take("a") {
		t.Fatal("one token should have refilled in 6 s")
	}
	s.give("a")
	if !s.take("a") {
		t.Fatal("a returned token must be usable")
	}
}

func TestSourceKey(t *testing.T) {
	cases := map[string]string{
		"192.0.2.7:443":              "192.0.2.7",
		"[2001:db8:1:2::5]:443":      "2001:db8:1:2::/64",
		"[2001:db8:1:2:aaaa::9]:443": "2001:db8:1:2::/64",
		"pipe":                       "pipe",
	}
	for in, want := range cases {
		if got := sourceKey(in); got != want {
			t.Errorf("sourceKey(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestRefusedOpensAreRateLimited proves a source that keeps failing stops
// reaching the authorizer after the burst.
func TestRefusedOpensAreRateLimited(t *testing.T) {
	auth := &countingAuth{}
	addr, _, pool := startGateway(t, auth)
	statuses := make([]int, 0, authorizeBurst+2)
	for i := 0; i < authorizeBurst+2; i++ {
		code, _ := fakeEnclave(t, addr, pool, "enclave-x")
		statuses = append(statuses, code)
	}
	if n := auth.calls.Load(); n != authorizeBurst {
		t.Fatalf("Authorize called %d times, want %d", n, authorizeBurst)
	}
	if last := statuses[len(statuses)-1]; last != 429 {
		t.Fatalf("statuses = %v, want the last refused with 429", statuses)
	}
}
