package terminate

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Privasys/platform-gateway/internal/routetable"
)

// A response the enclave marked public keeps the runtime's open CORS ("*",
// no credentials) even when the gateway injected its per-origin echo first.
func TestReconcilePublicCORS(t *testing.T) {
	h := http.Header{}
	// What the gateway injected before the proxy ran.
	h.Set("Access-Control-Allow-Origin", "https://chat.privasys.org")
	h.Set("Vary", "Origin")
	h.Set("Access-Control-Allow-Credentials", "true")
	h.Set("Access-Control-Expose-Headers", "X-Privasys-Reason, X-Privasys-Edge")
	// What the runtime added.
	h.Add("Access-Control-Allow-Origin", "*")
	h.Add("Access-Control-Expose-Headers", "Content-Type, ETag, X-Privasys-Edge")
	h.Set(publicTransportHeader, "public")

	reconcilePublicCORS(h)

	if got := h.Values("Access-Control-Allow-Origin"); len(got) != 1 || got[0] != "*" {
		t.Errorf("Allow-Origin = %v, want a single *", got)
	}
	if h.Get("Access-Control-Allow-Credentials") != "" {
		t.Error("a public response never allows credentials")
	}
	if h.Get("Vary") != "" {
		t.Error("an open origin needs no Vary: Origin")
	}
	exp := h.Get("Access-Control-Expose-Headers")
	if strings.Count(exp, "X-Privasys-Edge") != 1 || !strings.Contains(exp, "ETag") || !strings.Contains(exp, "X-Privasys-Reason") {
		t.Errorf("Expose-Headers = %q", exp)
	}

	// A public static asset (no runtime CORS) keeps the gateway's echo but
	// still loses credentials.
	h2 := http.Header{}
	h2.Set("Access-Control-Allow-Origin", "https://chat.privasys.org")
	h2.Set("Access-Control-Allow-Credentials", "true")
	h2.Set(publicTransportHeader, "public")
	reconcilePublicCORS(h2)
	if h2.Get("Access-Control-Allow-Origin") != "https://chat.privasys.org" || h2.Get("Access-Control-Allow-Credentials") != "" {
		t.Errorf("static public: %v", h2)
	}

	// A sealed response is untouched.
	h3 := http.Header{}
	h3.Set("Access-Control-Allow-Origin", "https://chat.privasys.org")
	h3.Set("Access-Control-Allow-Credentials", "true")
	reconcilePublicCORS(h3)
	if h3.Get("Access-Control-Allow-Credentials") != "true" {
		t.Error("a non-public response keeps the gateway's credentials header")
	}
}

// The upstream CORS strip skips a public response, so the runtime's "*"
// survives to the writer.
func TestModifyResponseKeepsRuntimeCORSOnPublic(t *testing.T) {
	h := New(Options{})
	rp, err := h.proxyFor(routetable.Route{SNI: "web.apps.privasys.org", Upstream: "10.0.0.1:443"})
	if err != nil {
		t.Fatal(err)
	}
	pub := &http.Response{Header: http.Header{}}
	pub.Header.Set("Access-Control-Allow-Origin", "*")
	pub.Header.Set("Access-Control-Allow-Credentials", "true") // never from our runtime, dropped anyway
	pub.Header.Set(publicTransportHeader, "public")
	if err := rp.ModifyResponse(pub); err != nil {
		t.Fatal(err)
	}
	if pub.Header.Get("Access-Control-Allow-Origin") != "*" || pub.Header.Get("Access-Control-Allow-Credentials") != "" {
		t.Errorf("public: %v", pub.Header)
	}

	sealed := &http.Response{Header: http.Header{}}
	sealed.Header.Set("Access-Control-Allow-Origin", "*")
	if err := rp.ModifyResponse(sealed); err != nil {
		t.Fatal(err)
	}
	if sealed.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Error("an upstream's own CORS is still stripped on a non-public response")
	}
}

// The enclave rate-limits public routes by the last X-Forwarded-For entry,
// which this proxy appends from the connection it terminated. Pin it.
func TestProxyAppendsForwardedFor(t *testing.T) {
	var seen atomic.Value
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Store(r.Header.Get("X-Forwarded-For"))
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	h := New(Options{InsecureSkip: true})
	rp, err := h.proxyFor(routetable.Route{SNI: "web.apps.privasys.org", Upstream: upstream.Listener.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "https://web.apps.privasys.org/api/v1/public/feed", nil)
	req.RemoteAddr = "203.0.113.9:4242"
	req.Header.Set("X-Forwarded-For", "1.1.1.1") // a client cannot pre-empt the real address
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)
	got, _ := seen.Load().(string)
	if !strings.HasSuffix(got, "203.0.113.9") {
		t.Fatalf("X-Forwarded-For upstream = %q, want it to end with the terminated client", got)
	}
}

// Transit only, nothing retained: no log line on the terminate path may
// format a request header, query string or body. A route outcome with the
// method, the path and the SNI is the most a log line carries.
func TestTerminateLogsNoRequestContent(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	forbidden := []string{".Header", "RawQuery", ".Body", "RequestURI", "URL.String()", "Cookie", "Authorization"}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			if !strings.Contains(line, "log.Printf(") && !strings.Contains(line, "log.Println(") {
				continue
			}
			for _, bad := range forbidden {
				if strings.Contains(line, bad) {
					t.Errorf("%s:%d logs request content (%s): %s", f, i+1, bad, strings.TrimSpace(line))
				}
			}
		}
	}
}
