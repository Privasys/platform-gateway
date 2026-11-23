package proxy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/Privasys/platform-gateway/internal/routetable"
)

// TestStopDoesNotWaitForLongConnections proves a stopping gateway returns
// within drainTimeout even when a client keeps its connection open, so a
// restart closes the port for seconds, not until the service manager kills
// the process.
func TestStopDoesNotWaitForLongConnections(t *testing.T) {
	old := drainTimeout
	drainTimeout = 200 * time.Millisecond
	defer func() { drainTimeout = old }()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	g := New(routetable.New(), addr, time.Second, time.Hour, 32768, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- g.Run(ctx) }()

	var conn net.Conn
	for i := 0; i < 50; i++ {
		if conn, err = net.Dial("tcp", addr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if conn == nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	time.Sleep(100 * time.Millisecond) // the gateway is now holding it open

	start := time.Now()
	cancel()
	select {
	case <-done:
		if took := time.Since(start); took > 2*time.Second {
			t.Fatalf("stop took %s", took)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the gateway waited for an open connection instead of stopping")
	}
}
