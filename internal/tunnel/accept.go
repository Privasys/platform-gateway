package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/yamux"
)

const (
	handshakeTimeout = 10 * time.Second
	maxRequestBody   = 16 << 10
)

// AuthRequest is what the gateway forwards to the authorizer: the exact
// method, path, attestation headers and body the enclave signed, so the
// management service can verify the signature itself. The gateway holds no
// key material for enclaves and decides nothing on its own.
type AuthRequest struct {
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	Headers    map[string]string `json:"headers"`
	Body       []byte            `json:"body"`
	RemoteAddr string            `json:"remote_addr"`
}

// Authorizer verifies a tunnel request and returns the enclave id it
// authenticates.
type Authorizer interface {
	Authorize(ctx context.Context, req AuthRequest) (enclaveID string, err error)
}

// Acceptor terminates tunnel connections from enclaves.
type Acceptor struct {
	tlsConfig *tls.Config
	auth      Authorizer
	registry  *Registry
}

// NewAcceptor builds an Acceptor. base supplies the gateway's public
// certificate (the same resolver terminate mode uses); the tunnel ALPN is
// the only protocol negotiated.
func NewAcceptor(base *tls.Config, auth Authorizer, registry *Registry) *Acceptor {
	cfg := base.Clone()
	cfg.NextProtos = []string{ALPN}
	cfg.MinVersion = tls.VersionTLS13
	return &Acceptor{tlsConfig: cfg, auth: auth, registry: registry}
}

// Handle serves one enclave tunnel connection until it ends. clientHello is
// the already-consumed ClientHello, replayed to the TLS server.
func (a *Acceptor) Handle(conn net.Conn, clientHello []byte) {
	remote := conn.RemoteAddr().String()
	tlsConn := tls.Server(&prefixConn{Conn: conn, buf: clientHello}, a.tlsConfig)
	tlsConn.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := tlsConn.Handshake(); err != nil {
		sessionsTotal.WithLabelValues("tls_error").Inc()
		log.Printf("tunnel: TLS handshake from %s: %v", remote, err)
		return
	}
	if tlsConn.ConnectionState().NegotiatedProtocol != ALPN {
		sessionsTotal.WithLabelValues("alpn_mismatch").Inc()
		return
	}

	br := bufio.NewReader(tlsConn)
	req, err := http.ReadRequest(br)
	if err != nil {
		sessionsTotal.WithLabelValues("bad_request").Inc()
		log.Printf("tunnel: read request from %s: %v", remote, err)
		return
	}
	if req.Method != http.MethodPost || req.URL.Path != Path ||
		!strings.EqualFold(req.Header.Get("Upgrade"), UpgradeProtocol) {
		sessionsTotal.WithLabelValues("bad_request").Inc()
		writeStatus(tlsConn, http.StatusBadRequest, "expected POST "+Path+" with Upgrade: "+UpgradeProtocol)
		return
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, maxRequestBody+1))
	if err != nil || len(body) > maxRequestBody {
		sessionsTotal.WithLabelValues("bad_request").Inc()
		writeStatus(tlsConn, http.StatusBadRequest, "unreadable or oversized body")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	enclaveID, err := a.auth.Authorize(ctx, AuthRequest{
		Method:     req.Method,
		Path:       req.URL.Path,
		Headers:    authHeaders(req.Header),
		Body:       body,
		RemoteAddr: remote,
	})
	cancel()
	if err != nil || enclaveID == "" {
		sessionsTotal.WithLabelValues("unauthorized").Inc()
		log.Printf("tunnel: rejected %s (claims enclave %q): %v", remote, req.Header.Get("X-Enclave-Id"), err)
		writeStatus(tlsConn, http.StatusForbidden, "tunnel not authorized")
		return
	}

	if _, err := io.WriteString(tlsConn, "HTTP/1.1 101 Switching Protocols\r\n"+
		"Upgrade: "+UpgradeProtocol+"\r\nConnection: Upgrade\r\n\r\n"); err != nil {
		sessionsTotal.WithLabelValues("write_error").Inc()
		return
	}
	tlsConn.SetDeadline(time.Time{})

	// The enclave sends nothing after its request until it has read our 101,
	// but hand any buffered bytes to yamux rather than lose them.
	var transport net.Conn = tlsConn
	if n := br.Buffered(); n > 0 {
		pending, _ := br.Peek(n)
		transport = &prefixConn{Conn: tlsConn, buf: append([]byte(nil), pending...)}
	}
	sess, err := yamux.Client(transport, yamuxConfig())
	if err != nil {
		sessionsTotal.WithLabelValues("yamux_error").Inc()
		log.Printf("tunnel: yamux for enclave %s: %v", enclaveID, err)
		return
	}
	sessionsTotal.WithLabelValues("ok").Inc()
	unregister := a.registry.Register(enclaveID, sess)
	log.Printf("tunnel: enclave %s connected from %s", enclaveID, remote)

	<-sess.CloseChan()
	unregister()
	log.Printf("tunnel: enclave %s disconnected (%s)", enclaveID, remote)
}

// authHeaders keeps only what the authorizer needs: the enclaveauth headers
// and, for enclaves without a signer, a bearer.
func authHeaders(h http.Header) map[string]string {
	out := make(map[string]string)
	for k, v := range h {
		if len(v) == 0 {
			continue
		}
		ck := http.CanonicalHeaderKey(k)
		if strings.HasPrefix(ck, "X-Enclave-") || ck == "Authorization" {
			out[ck] = v[0]
		}
	}
	return out
}

func writeStatus(c net.Conn, code int, msg string) {
	c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(msg), msg)
}

// prefixConn replays buf before reading from the underlying connection.
type prefixConn struct {
	net.Conn
	buf []byte
}

func (c *prefixConn) Read(b []byte) (int, error) {
	if len(c.buf) > 0 {
		n := copy(b, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}
