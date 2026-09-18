package terminate

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Privasys/platform-gateway/internal/quarantine"
	"github.com/Privasys/platform-gateway/internal/routetable"
	"github.com/coder/websocket"
)

// quarantineCutSetup returns a table wired to a tracker the way main wires
// them, with one active route, and a handler that uses both.
func quarantineCutSetup(t *testing.T, sni, upstream string) (*routetable.Table, *quarantine.Tracker, *Handler, routetable.Route) {
	t.Helper()
	table := routetable.New()
	tracker := quarantine.NewTracker()
	table.OnQuarantine(func(host string) { tracker.CutHost(host) })
	route := routetable.Route{SNI: sni, Upstream: upstream}
	table.Update([]routetable.Route{route}, "v1")
	h := New(Options{
		TLSConfig:    &tls.Config{Certificates: []tls.Certificate{selfSignedTLS(t, sni)}},
		InsecureSkip: true,
		Lookup:       table.Lookup,
		Tracker:      tracker,
	})
	return table, tracker, h, route
}

func quarantineRoute(table *routetable.Table, route routetable.Route) {
	route.State = routetable.StateQuarantined
	table.Update([]routetable.Route{route}, "v2")
}

func waitOpen(t *testing.T, tr *quarantine.Tracker, host string, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for tr.Open(host) != want {
		if time.Now().After(deadline) {
			t.Fatalf("tracked entries for %q = %d, want %d", host, tr.Open(host), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestQuarantineCutsSealedStream checks that an open sealed WebSocket
// stream is closed with 1013 (try again later) when its route turns
// quarantined.
func TestQuarantineCutsSealedStream(t *testing.T) {
	enclaveAddr, _ := fakeEnclave(t, http.StatusSwitchingProtocols)
	table, tracker, h, route := quarantineCutSetup(t, "app.test", enclaveAddr)
	gwAddr := startGateway(t, h, route)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "wss://app.test/live", &websocket.DialOptions{
		HTTPClient:   wsClient(t, gwAddr, "app.test"),
		Subprotocols: []string{sealedWSSubprotocol, "session-abc", "00000000000000aa"},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer ws.CloseNow()
	if err := ws.Write(ctx, websocket.MessageBinary, []byte("open")); err != nil {
		t.Fatalf("send open: %v", err)
	}
	if _, _, err := ws.Read(ctx); err != nil {
		t.Fatalf("ack: %v", err)
	}
	waitOpen(t, tracker, "app.test", 1)

	quarantineRoute(table, route)

	_, _, err = ws.Read(ctx)
	if err == nil {
		t.Fatal("stream still open after quarantine")
	}
	if code := websocket.CloseStatus(err); code != websocket.StatusTryAgainLater {
		t.Fatalf("close status = %v (%v), want 1013", code, err)
	}
	waitOpen(t, tracker, "app.test", 0)
}

// TestQuarantineCutsTunnelledWebSocket checks that a plain WebSocket
// tunnelled through the reverse proxy is cut on both legs when its route
// turns quarantined.
func TestQuarantineCutsTunnelledWebSocket(t *testing.T) {
	upstreamGone := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		for {
			typ, msg, err := c.Read(context.Background())
			if err != nil {
				close(upstreamGone)
				return
			}
			_ = c.Write(context.Background(), typ, msg)
		}
	}))
	defer srv.Close()
	table, tracker, h, route := quarantineCutSetup(t, "app.test", srv.Listener.Addr().String())
	gwAddr := startGateway(t, h, route)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "wss://app.test/plain", &websocket.DialOptions{HTTPClient: wsClient(t, gwAddr, "app.test")})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer ws.CloseNow()
	if err := ws.Write(ctx, websocket.MessageText, []byte("hi")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, msg, err := ws.Read(ctx); err != nil || string(msg) != "hi" {
		t.Fatalf("echo = %q (%v)", msg, err)
	}
	waitOpen(t, tracker, "app.test", 1)

	quarantineRoute(table, route)

	if _, _, err := ws.Read(ctx); err == nil {
		t.Fatal("tunnelled WebSocket still open after quarantine")
	} else if ctx.Err() != nil {
		t.Fatal("tunnelled WebSocket was not cut")
	}
	select {
	case <-upstreamGone:
	case <-time.After(5 * time.Second):
		t.Fatal("enclave side of the tunnel was not closed")
	}
	waitOpen(t, tracker, "app.test", 0)
}

// TestQuarantineCutsStreamingResponse checks that a response still
// streaming from the enclave is cut when its route turns quarantined.
func TestQuarantineCutsStreamingResponse(t *testing.T) {
	upstreamDone := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: first\n\n"))
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
			close(upstreamDone)
		case <-time.After(20 * time.Second):
		}
	}))
	defer srv.Close()
	table, tracker, h, route := quarantineCutSetup(t, quarantineTestHost, srv.Listener.Addr().String())
	tc, br := terminatedClient(t, h, route)

	req := mustRequest(t, http.MethodGet, "text/event-stream")
	if err := req.Write(tc); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	first := make([]byte, len("data: first\n\n"))
	if _, err := io.ReadFull(resp.Body, first); err != nil {
		t.Fatalf("first event: %v", err)
	}
	waitOpen(t, tracker, quarantineTestHost, 1)

	quarantineRoute(table, route)

	tc.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = io.ReadAll(resp.Body)
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("streaming response was not cut")
	}
	select {
	case <-upstreamDone:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream request was not cancelled")
	}
}
