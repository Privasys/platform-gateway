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
