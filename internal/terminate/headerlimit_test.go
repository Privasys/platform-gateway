package terminate

import (
	"net/http"
	"strings"
	"testing"

	"github.com/Privasys/platform-gateway/internal/routetable"
)

// TestRequestHeaderBudgetIsPerRequest proves the header budget is fresh for
// every request on a keep-alive connection, and that a request whose headers
// exceed it is refused before it reaches the enclave.
func TestRequestHeaderBudgetIsPerRequest(t *testing.T) {
	upstream, hits := upstreamCounter(t)
	route := routetable.Route{SNI: quarantineTestHost, Upstream: upstream.Listener.Addr().String()}
	tc, br := terminatedClient(t, newTestHandler(t, nil), route)

	// Two requests whose headers together exceed the budget, each within it.
	for i := 0; i < 2; i++ {
		req := mustRequest(t, http.MethodGet, "")
		req.Header.Set("X-Pad", strings.Repeat("a", maxRequestHeaderBytes*6/10))
		resp, body := roundTrip(t, tc, br, req)
		if resp.StatusCode != http.StatusOK || body != "from enclave" {
			t.Fatalf("request %d: status %d body %q", i, resp.StatusCode, body)
		}
	}

	req := mustRequest(t, http.MethodGet, "")
	req.Header.Set("X-Pad", strings.Repeat("a", maxRequestHeaderBytes+1))
	go func() { _ = req.Write(tc) }()
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("status = %d, want 431", resp.StatusCode)
	}
	if hits.Load() != 2 {
		t.Fatalf("upstream served %d requests, want 2", hits.Load())
	}
}

func TestHeaderLimitReaderLifts(t *testing.T) {
	lr := &headerLimitReader{r: strings.NewReader(strings.Repeat("x", 100))}
	lr.limit(10)
	buf := make([]byte, 64)
	n, err := lr.Read(buf)
	if n != 10 || err != nil {
		t.Fatalf("limited read = %d, %v", n, err)
	}
	if _, err := lr.Read(buf); err != errHeaderTooLarge {
		t.Fatalf("over budget err = %v", err)
	}
	lr.unlimit()
	if n, _ := lr.Read(buf); n != 64 {
		t.Fatalf("lifted read = %d, want 64", n)
	}
}
