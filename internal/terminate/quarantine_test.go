package terminate

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Privasys/platform-gateway/internal/routetable"
)

const quarantineTestHost = "app.example.com"

// terminatedClient runs h.Handle for route on one end of a pipe and returns
// a TLS client on the other end with a reader for its responses.
func terminatedClient(t *testing.T, h *Handler, route routetable.Route) (*tls.Conn, *bufio.Reader) {
	t.Helper()
	server, client := net.Pipe()
	go h.Handle(server, nil, route)
	tc := tls.Client(client, &tls.Config{InsecureSkipVerify: true, ServerName: quarantineTestHost})
	tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	t.Cleanup(func() { tc.Close() })
	return tc, bufio.NewReader(tc)
}

func roundTrip(t *testing.T, tc *tls.Conn, br *bufio.Reader, req *http.Request) (*http.Response, string) {
	t.Helper()
	if err := req.Write(tc); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, string(body)
}

func newTestHandler(t *testing.T, lookup func(string) (routetable.Route, bool)) *Handler {
	t.Helper()
	return New(Options{
		TLSConfig:    &tls.Config{Certificates: []tls.Certificate{selfSignedTLS(t, quarantineTestHost)}},
		InsecureSkip: true,
		CORSOrigins:  []string{"https://chat.privasys.org"},
		Lookup:       lookup,
	})
}

// upstreamCounter is an enclave stand-in that counts the requests it serves.
func upstreamCounter(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("from enclave"))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func mustRequest(t *testing.T, method, accept string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, "https://"+quarantineTestHost+"/api/thing", nil)
	if err != nil {
		t.Fatal(err)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	return req
}

func TestQuarantinedRouteAnswers503JSON(t *testing.T) {
	upstream, hits := upstreamCounter(t)
	route := routetable.Route{SNI: quarantineTestHost, Upstream: upstream.Listener.Addr().String(), State: routetable.StateQuarantined}
	tc, br := terminatedClient(t, newTestHandler(t, nil), route)

	req := mustRequest(t, http.MethodGet, "application/json")
	req.Header.Set("Origin", "https://chat.privasys.org")
	resp, body := roundTrip(t, tc, br, req)

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	if got := resp.Header.Get("Retry-After"); got != "300" {
		t.Errorf("Retry-After = %q, want 300", got)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://chat.privasys.org" {
		t.Errorf("Access-Control-Allow-Origin = %q", got)
	}
	var doc struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("body is not JSON: %v: %q", err, body)
	}
	if doc.Error != "enclave_quarantined" || doc.Message == "" {
		t.Errorf("body = %+v", doc)
	}
	if !resp.Close {
		t.Error("refusal should close the connection")
	}
	if hits.Load() != 0 {
		t.Errorf("upstream served %d requests, want 0", hits.Load())
	}
}

func TestQuarantinedRouteAnswers503HTMLForBrowsers(t *testing.T) {
	route := routetable.Route{SNI: quarantineTestHost, Upstream: "127.0.0.1:1", State: routetable.StateQuarantined}
	tc, br := terminatedClient(t, newTestHandler(t, nil), route)

	req := mustRequest(t, http.MethodGet, "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	resp, body := roundTrip(t, tc, br, req)

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Errorf("Content-Type = %q, want text/html", resp.Header.Get("Content-Type"))
	}
	if !strings.Contains(body, "temporarily unavailable") {
		t.Errorf("body = %q", body)
	}
	if resp.Header.Get("Retry-After") != "300" {
		t.Errorf("Retry-After = %q", resp.Header.Get("Retry-After"))
	}
}

func TestQuarantinedRouteRefusesSealedWebSocket(t *testing.T) {
	upstream, hits := upstreamCounter(t)
	route := routetable.Route{SNI: quarantineTestHost, Upstream: upstream.Listener.Addr().String(), State: routetable.StateQuarantined}
	tc, br := terminatedClient(t, newTestHandler(t, nil), route)

	req := mustRequest(t, http.MethodGet, "")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Protocol", sealedWSSubprotocol+", session-1, 0123456789abcdef")
	resp, _ := roundTrip(t, tc, br, req)

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	if hits.Load() != 0 {
		t.Errorf("upstream served %d requests, want 0", hits.Load())
	}
}

// TestQuarantineReachesOpenConnection checks that a route quarantined in
// the live table is refused on a keep-alive connection opened before, and
// that the released route serves again.
func TestQuarantineReachesOpenConnection(t *testing.T) {
	upstream, hits := upstreamCounter(t)
	active := routetable.Route{SNI: quarantineTestHost, Upstream: upstream.Listener.Addr().String()}
	table := routetable.New()
	table.Update([]routetable.Route{active}, "v1")
	h := newTestHandler(t, table.Lookup)

	tc, br := terminatedClient(t, h, active)
	if resp, body := roundTrip(t, tc, br, mustRequest(t, http.MethodGet, "")); resp.StatusCode != http.StatusOK || body != "from enclave" {
		t.Fatalf("before quarantine: status %d body %q", resp.StatusCode, body)
	}

	quarantined := active
	quarantined.State = routetable.StateQuarantined
	table.Update([]routetable.Route{quarantined}, "v2")
	if resp, _ := roundTrip(t, tc, br, mustRequest(t, http.MethodGet, "")); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("during quarantine: status %d, want 503", resp.StatusCode)
	}

	// Released: the state is gone from the feed, a new connection is
	// proxied to the enclave again.
	table.Update([]routetable.Route{active}, "v3")
	route, _ := table.Lookup(quarantineTestHost)
	tc2, br2 := terminatedClient(t, h, route)
	if resp, body := roundTrip(t, tc2, br2, mustRequest(t, http.MethodGet, "")); resp.StatusCode != http.StatusOK || body != "from enclave" {
		t.Fatalf("after release: status %d body %q", resp.StatusCode, body)
	}
	if hits.Load() != 2 {
		t.Errorf("upstream served %d requests, want 2", hits.Load())
	}
}
