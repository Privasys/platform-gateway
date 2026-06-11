// Package terminate implements the gateway's TLS-termination path used
// by the session-relay flow. For routes whose Mode == "terminate":
//
//  1. The gateway terminates the public TLS handshake using a Let's
//     Encrypt wildcard certificate (loaded by certloader). This produces
//     a publicly-trusted cert path so browsers don't error on a
//     self-signed enclave RA-TLS leaf.
//  2. The gateway opens an internal RA-TLS connection to the upstream
//     enclave and verifies the deterministic-path leaf cert against the
//     route's attestation policy (a snapshot of expected RA-TLS OID
//     values originating from the management service).
//  3. HTTP requests are reverse-proxied across the internal leg. The
//     request body is opaque to the gateway: in the session-relay flow
//     the SDK seals the body with AES-256-GCM keyed by an ECDH-derived
//     session key the gateway never sees, so confidentiality remains
//     end-to-end SDK ↔ enclave even though the gateway terminates TLS.
//
// The gateway is therefore a routing convenience and a public-cert
// authority for browsers; it adds no new trust assumption beyond what
// it already carried in pure-splice mode (it sees the SNI on every
// connection either way).
package terminate

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Privasys/platform-gateway/internal/routetable"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	terminatedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "gateway_terminate_connections_total",
		Help: "TLS-terminated inbound connections",
	})
	terminateErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gateway_terminate_errors_total",
		Help: "Terminate-mode errors by reason",
	}, []string{"reason"})
	upstreamHandshakes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gateway_terminate_upstream_handshakes_total",
		Help: "Internal RA-TLS handshakes to enclaves by result",
	}, []string{"result"})
)

// PolicyDoc is the on-the-wire shape of attestation_policy.
type PolicyDoc struct {
	ExpectedOIDs map[string]string `json:"expected_oids,omitempty"`
}

// Handler implements proxy.Terminator.
type Handler struct {
	tlsConfig    *tls.Config
	dialTimeout  time.Duration
	idleTimeout  time.Duration
	caCertPool   *x509.CertPool
	insecureSkip bool
	// Exact-match allow-list (e.g. https://chat.privasys.org).
	corsOrigins map[string]struct{}
	// Wildcard suffix allow-list. Each entry was configured as
	// "*.privasys.org" or "https://*.privasys.org"; we store the
	// host suffix WITHOUT the leading dot, e.g. "privasys.org". An
	// origin matches when its host equals the suffix or ends with
	// "." + suffix. Scheme is not constrained at the suffix level
	// (browsers only send Origin for http/https anyway).
	corsSuffixes []string

	// One reverse proxy per upstream so connections are pooled. The
	// transport is reset whenever the route's policy changes.
	mu      sync.Mutex
	proxies map[string]*upstreamProxy
}

type upstreamProxy struct {
	policyHash string
	rp         *httputil.ReverseProxy
	cancel     context.CancelFunc
}

// Options configures the handler.
type Options struct {
	TLSConfig    *tls.Config
	DialTimeout  time.Duration
	IdleTimeout  time.Duration
	CACertPool   *x509.CertPool // pool used to validate upstream RA-TLS certs (the enclave's intermediary CA chain)
	InsecureSkip bool           // dev/test only: skip RA-TLS chain validation, only enforce expected-OID policy
	CORSOrigins  []string       // allowed CORS origins; empty disables CORS injection (enclave is expected to handle it)
}

// New creates a Handler. tlsConfig must be set up by the caller (typically
// from a certloader.Loader's TLSConfig()).
func New(opts Options) *Handler {
	if opts.DialTimeout == 0 {
		// Keep this short. The dev/demo enclaves run on Spot VMs that
		// are routinely stopped; when they are off the upstream IP
		// drops SYNs (no RST) and we'd otherwise wait the full
		// timeout before returning 502 to the browser — leaving the
		// user staring at a spinner for ~7 s on every prompt. A 2 s
		// cap is plenty for any healthy enclave we'd accept traffic
		// for: the upstream lives in the same region, and the
		// per-route reverse proxy keeps idle connections pooled so
		// the dial only happens on the very first request.
		opts.DialTimeout = 2 * time.Second
	}
	if opts.IdleTimeout == 0 {
		opts.IdleTimeout = 300 * time.Second
	}
	origins := make(map[string]struct{}, len(opts.CORSOrigins))
	var suffixes []string
	for _, o := range opts.CORSOrigins {
		o = strings.TrimSpace(o)
		if o == "" {
			continue
		}
		if suf, ok := parseWildcardOrigin(o); ok {
			suffixes = append(suffixes, suf)
			continue
		}
		origins[o] = struct{}{}
	}
	return &Handler{
		tlsConfig:    opts.TLSConfig,
		dialTimeout:  opts.DialTimeout,
		idleTimeout:  opts.IdleTimeout,
		caCertPool:   opts.CACertPool,
		insecureSkip: opts.InsecureSkip,
		corsOrigins:  origins,
		corsSuffixes: suffixes,
		proxies:      make(map[string]*upstreamProxy),
	}
}

// Handle implements proxy.Terminator. clientHello is the buffered bytes
// already consumed from clientConn during SNI extraction; they are replayed
// into the TLS server before the handshake.
func (h *Handler) Handle(clientConn net.Conn, clientHello []byte, route routetable.Route) {
	terminatedTotal.Inc()
	defer clientConn.Close()

	// Replay the ClientHello so the TLS server sees the original handshake.
	wrapped := newPrefixConn(clientConn, clientHello)
	tlsConn := tls.Server(wrapped, h.tlsConfig)
	tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		terminateErrors.WithLabelValues("tls_handshake").Inc()
		log.Printf("terminate: TLS handshake from %s for %q failed: %v", clientConn.RemoteAddr(), route.SNI, err)
		return
	}
	tlsConn.SetDeadline(time.Time{})

	rp, err := h.proxyFor(route)
	if err != nil {
		terminateErrors.WithLabelValues("upstream_setup").Inc()
		log.Printf("terminate: upstream setup for %q (%s): %v", route.SNI, route.Upstream, err)
		writeStatus(tlsConn, 502, "upstream RA-TLS setup failed")
		return
	}

	h.serveHTTP(tlsConn, route, rp)
}

// serveHTTP reads HTTP/1.1 requests off the terminated TLS conn and forwards
// each through the reverse proxy until the client hangs up.
func (h *Handler) serveHTTP(tlsConn *tls.Conn, route routetable.Route, rp *httputil.ReverseProxy) {
	br := bufio.NewReader(tlsConn)
	for {
		tlsConn.SetReadDeadline(time.Now().Add(h.idleTimeout))
		req, err := http.ReadRequest(br)
		if err != nil {
			if err != io.EOF && !isClosedConn(err) {
				log.Printf("terminate: read request from client for %q: %v", route.SNI, err)
			}
			return
		}
		tlsConn.SetReadDeadline(time.Time{})

		// CORS preflight short-circuit. Browsers issue OPTIONS with
		// Origin + Access-Control-Request-* headers before any
		// non-simple cross-origin request; the enclave never sees them
		// (gateway terminates), and most enclave servers don't speak
		// CORS anyway. We answer here when the origin is allowed.
		if req.Method == http.MethodOptions && h.isAllowedOrigin(req.Header.Get("Origin")) {
			writeCORSPreflight(tlsConn, req)
			continue
		}

		// Set the host header so the upstream sees the public hostname.
		req.URL.Host = route.Upstream
		req.URL.Scheme = "https"
		req.RequestURI = ""
		if req.Host == "" {
			req.Host = route.SNI
		}

		// We want to write the response back over the same TLS conn.
		w := newConnResponseWriter(tlsConn)
		// Inject CORS response headers for allowed origins so the
		// browser accepts the cross-origin response. The proxy strips
		// hop-by-hop headers; CORS headers are end-to-end and safe to
		// add at this layer.
		if origin := req.Header.Get("Origin"); origin != "" && h.isAllowedOrigin(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		rp.ServeHTTP(w, req)
		w.flushClose(req)

		// Honour Connection: close from either side.
		if strings.EqualFold(req.Header.Get("Connection"), "close") || w.closeRequested {
			return
		}
	}
}

// proxyFor returns the cached reverse proxy for this upstream, or builds
// one on first use / when the policy changes.
func (h *Handler) proxyFor(route routetable.Route) (*httputil.ReverseProxy, error) {
	policyHash := hashPolicy(route.AttestationPolicy)
	key := route.Upstream + "|" + policyHash

	h.mu.Lock()
	defer h.mu.Unlock()

	if existing, ok := h.proxies[key]; ok {
		return existing.rp, nil
	}
	// Drop any stale entry for the same upstream with a different policy.
	for k, p := range h.proxies {
		if strings.HasPrefix(k, route.Upstream+"|") {
			if p.cancel != nil {
				p.cancel()
			}
			delete(h.proxies, k)
		}
	}

	policy, err := parsePolicy(route.AttestationPolicy)
	if err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}

	target, err := url.Parse("https://" + route.Upstream)
	if err != nil {
		return nil, fmt.Errorf("parse upstream URL: %w", err)
	}

	transport := &http.Transport{
		DialContext: (&net.Dialer{Timeout: h.dialTimeout}).DialContext,
		TLSClientConfig: &tls.Config{
			// We deliberately use InsecureSkipVerify and validate the RA-TLS
			// cert in VerifyPeerCertificate: the upstream cert is signed by
			// the enclave's intermediary CA, not by a public CA, and the
			// extra OID-based policy enforcement is what actually pins the
			// expected enclave identity.
			InsecureSkipVerify:    true,
			VerifyPeerCertificate: makeRATLSVerifier(h.caCertPool, h.insecureSkip, policy, route.SNI),
			MinVersion:            tls.VersionTLS12,
			// ServerName drives the ClientHello SNI. The upstream is
			// usually an IP address, in which case Go would otherwise
			// default to the IP literal as SNI — many enclave TLS
			// servers reject that with "tls: internal error" because
			// their cert is bound to the public hostname.
			ServerName: route.SNI,
		},
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     h.idleTimeout,
		TLSHandshakeTimeout: 10 * time.Second,
		ForceAttemptHTTP2:   false, // enclave HTTP servers are usually HTTP/1.1
	}

	rp := httputil.NewSingleHostReverseProxy(target)
	rp.Transport = transport
	rp.ErrorLog = log.Default()
	rp.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
		log.Printf("terminate: reverse proxy error for %q: %v", route.SNI, err)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("502 Bad Gateway: upstream enclave unreachable\n"))
	}
	// CORS is owned at this gateway layer (see serveHTTP — we already
	// set Access-Control-Allow-* headers on the response writer for
	// allowed origins, and answer OPTIONS preflights ourselves). Some
	// upstream services (eg. confidential-ai) ship their own CORS
	// middleware so they remain usable in direct-access dev/test
	// scenarios; when proxied through here their headers would stack
	// on top of ours and the browser would reject the response with
	// "Multiple CORS header 'Access-Control-Allow-Origin' not
	// allowed". Strip the upstream copies so only the gateway's
	// values survive.
	rp.ModifyResponse = func(resp *http.Response) error {
		for _, h := range []string{
			"Access-Control-Allow-Origin",
			"Access-Control-Allow-Credentials",
			"Access-Control-Allow-Methods",
			"Access-Control-Allow-Headers",
			"Access-Control-Expose-Headers",
			"Access-Control-Max-Age",
		} {
			resp.Header.Del(h)
		}
		// Vary may legitimately include non-Origin tokens from the
		// upstream (Accept-Encoding etc). Strip just the Origin
		// token so the gateway's own "Vary: Origin" header is the
		// only mention of it.
		if vs := resp.Header.Values("Vary"); len(vs) > 0 {
			resp.Header.Del("Vary")
			for _, line := range vs {
				kept := make([]string, 0, 2)
				for _, tok := range strings.Split(line, ",") {
					t := strings.TrimSpace(tok)
					if t == "" || strings.EqualFold(t, "Origin") {
						continue
					}
					kept = append(kept, t)
				}
				if len(kept) > 0 {
					resp.Header.Add("Vary", strings.Join(kept, ", "))
				}
			}
		}
		return nil
	}
	// Strip hop-by-hop headers and inject session-relay-friendly defaults.
	originalDirector := rp.Director
	rp.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = route.SNI // upstream may use it for vhost routing
		req.Header.Del("X-Forwarded-Proto")
		req.Header.Set("X-Forwarded-Proto", "https")
		// Trusted terminate marker: tells the enclave that a party other
		// than the client terminated TLS on this leg, so plaintext app
		// bodies must be refused (sealed-CBOR only). Always strip any
		// client-supplied value first — clients must not be able to
		// unset it, and a client *setting* it only makes its own
		// requests stricter. Splice mode is pure L4 and cannot inject
		// headers, which is exactly what makes absence trustworthy.
		req.Header.Del("X-Privasys-Edge")
		req.Header.Set("X-Privasys-Edge", "terminate")
	}

	h.proxies[key] = &upstreamProxy{policyHash: policyHash, rp: rp}
	return rp, nil
}

// makeRATLSVerifier returns a VerifyPeerCertificate that enforces the
// expected-OID policy on the leaf cert. It deliberately does NOT verify
// challenge-response (deterministic-path certs only) — that path is
// reserved for RA-TLS-capable clients in splice mode.
func makeRATLSVerifier(caPool *x509.CertPool, insecureSkip bool, policy *PolicyDoc, sni string) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("upstream presented no certificate")
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			upstreamHandshakes.WithLabelValues("parse_error").Inc()
			return fmt.Errorf("parse leaf: %w", err)
		}

		// Optional CA-chain validation. Most deployments will configure a
		// pool with the platform's intermediary CA; tests can skip.
		if !insecureSkip && caPool != nil {
			intermediates := x509.NewCertPool()
			for _, raw := range rawCerts[1:] {
				if c, err := x509.ParseCertificate(raw); err == nil {
					intermediates.AddCert(c)
				}
			}
			opts := x509.VerifyOptions{
				Roots:         caPool,
				Intermediates: intermediates,
				CurrentTime:   time.Now(),
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}
			if _, err := leaf.Verify(opts); err != nil {
				upstreamHandshakes.WithLabelValues("chain_invalid").Inc()
				return fmt.Errorf("upstream chain invalid: %w", err)
			}
		}

		// Enforce expected OID policy. For each oid in the policy, the leaf
		// must carry an extension with the same value (hex-encoded match).
		if policy != nil && len(policy.ExpectedOIDs) > 0 {
			present := indexExtensions(leaf)
			for oid, expectedHex := range policy.ExpectedOIDs {
				got, ok := present[oid]
				if !ok {
					upstreamHandshakes.WithLabelValues("oid_missing").Inc()
					return fmt.Errorf("attestation policy: oid %s missing from upstream cert", oid)
				}
				want, err := hex.DecodeString(strings.TrimPrefix(expectedHex, "0x"))
				if err != nil {
					return fmt.Errorf("attestation policy: invalid hex for oid %s: %w", oid, err)
				}
				if !bytesEqual(got, want) {
					upstreamHandshakes.WithLabelValues("oid_mismatch").Inc()
					return fmt.Errorf("attestation policy: oid %s mismatch", oid)
				}
			}
		}
		upstreamHandshakes.WithLabelValues("ok").Inc()
		_ = sni
		return nil
	}
}

func indexExtensions(c *x509.Certificate) map[string][]byte {
	out := make(map[string][]byte, len(c.Extensions))
	for _, e := range c.Extensions {
		out[e.Id.String()] = e.Value
	}
	return out
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func parsePolicy(raw json.RawMessage) (*PolicyDoc, error) {
	if len(raw) == 0 {
		return &PolicyDoc{}, nil
	}
	var p PolicyDoc
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func hashPolicy(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "empty"
	}
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:8])
}

func isClosedConn(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "use of closed network connection") ||
		strings.Contains(s, "connection reset by peer")
}

func writeStatus(w io.Writer, code int, msg string) {
	body := fmt.Sprintf("%d %s\n", code, msg)
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(body), body)
}

// isAllowedOrigin reports whether origin is in the gateway's allow-list.
func (h *Handler) isAllowedOrigin(origin string) bool {
	if origin == "" {
		return false
	}
	if _, ok := h.corsOrigins[origin]; ok {
		return true
	}
	if len(h.corsSuffixes) == 0 {
		return false
	}
	host := originHost(origin)
	if host == "" {
		return false
	}
	for _, suf := range h.corsSuffixes {
		if host == suf || strings.HasSuffix(host, "."+suf) {
			return true
		}
	}
	return false
}

// parseWildcardOrigin recognises wildcard CORS entries of the form
// "*.example.com" or "https://*.example.com" and returns the bare
// host suffix (without the leading dot or scheme). Returns ok=false
// for plain origins so the caller falls back to exact match.
func parseWildcardOrigin(spec string) (string, bool) {
	s := strings.TrimSpace(spec)
	// Strip optional scheme://
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	// Strip optional :port (we only want the host suffix).
	if i := strings.Index(s, ":"); i >= 0 {
		s = s[:i]
	}
	// Strip optional trailing path (origin headers should not have
	// one but be defensive).
	if i := strings.Index(s, "/"); i >= 0 {
		s = s[:i]
	}
	if !strings.HasPrefix(s, "*.") {
		return "", false
	}
	suf := strings.ToLower(strings.TrimPrefix(s, "*."))
	if suf == "" {
		return "", false
	}
	return suf, true
}

// originHost extracts the host (no scheme, no port) from an Origin
// header value, lower-cased. Returns "" if the value is malformed.
func originHost(origin string) string {
	s := origin
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.Index(s, "/"); i >= 0 {
		s = s[:i]
	}
	if i := strings.Index(s, ":"); i >= 0 {
		s = s[:i]
	}
	return strings.ToLower(s)
}

// writeCORSPreflight writes a 204 response with the standard CORS
// preflight headers, echoing back the Access-Control-Request-* values
// the browser sent. Caller has already checked the origin is allowed.
func writeCORSPreflight(w io.Writer, req *http.Request) {
	origin := req.Header.Get("Origin")
	method := req.Header.Get("Access-Control-Request-Method")
	if method == "" {
		method = "GET, POST, PUT, DELETE, OPTIONS"
	}
	headers := req.Header.Get("Access-Control-Request-Headers")
	if headers == "" {
		headers = "Authorization, Content-Type, Accept"
	}
	fmt.Fprintf(w,
		"HTTP/1.1 204 No Content\r\n"+
			"Access-Control-Allow-Origin: %s\r\n"+
			"Access-Control-Allow-Methods: %s\r\n"+
			"Access-Control-Allow-Headers: %s\r\n"+
			"Access-Control-Allow-Credentials: true\r\n"+
			"Access-Control-Max-Age: 600\r\n"+
			"Vary: Origin\r\n"+
			"Content-Length: 0\r\n"+
			"\r\n",
		origin, method, headers,
	)
}
