package terminate

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
)

// TestEdgeMarkerSurvivesConnectionHeader proves a client cannot have the
// terminate marker or the forwarding headers dropped by naming them in its
// Connection header, while ordinary hop-by-hop tokens still work.
func TestEdgeMarkerSurvivesConnectionHeader(t *testing.T) {
	got := make(chan http.Header, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Clone()
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	rp := httputil.NewSingleHostReverseProxy(u)
	orig := rp.Director
	rp.Director = func(req *http.Request) {
		orig(req)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Del("X-Privasys-Edge")
		req.Header.Set("X-Privasys-Edge", "terminate")
		keepGatewayHeaders(req.Header)
	}

	for _, conn := range []string{
		"X-Privasys-Edge",
		"x-privasys-edge",
		"keep-alive, X-Privasys-Edge, X-Forwarded-Proto",
		"X-Custom, x-PRIVASYS-edge",
	} {
		req := httptest.NewRequest("GET", "https://app.test/api", nil)
		req.Header.Set("Connection", conn)
		req.Header.Set("X-Custom", "client")
		rp.ServeHTTP(httptest.NewRecorder(), req)
		h := <-got
		if h.Get("X-Privasys-Edge") != "terminate" {
			t.Errorf("Connection: %s dropped the terminate marker", conn)
		}
		if h.Get("X-Forwarded-Proto") != "https" {
			t.Errorf("Connection: %s dropped X-Forwarded-Proto", conn)
		}
		if conn == "X-Custom, x-PRIVASYS-edge" && h.Get("X-Custom") != "" {
			t.Errorf("an ordinary hop-by-hop header named in Connection was kept")
		}
	}
}
