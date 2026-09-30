// Package tunnel lets an enclave that accepts no inbound connections serve
// traffic through the gateway.
//
// The enclave dials OUT to every gateway instance and holds one long-lived
// connection per instance:
//
//	enclave ──TCP──► gateway :443
//	        TLS (gateway's public cert, ALPN privasys-tunnel/1)
//	        POST /__privasys/tunnel  Upgrade: privasys-tunnel/1
//	             X-Enclave-* headers (enclaveauth: quote-bound, CA-chained,
//	             signed over method/path/body)
//	gateway ──► management service: POST /api/v1/internal/tunnel/authorize
//	        ◄── {enclave_id}
//	gateway ──► 101 Switching Protocols
//	        yamux session; the GATEWAY opens streams, the enclave accepts
//
// A route whose upstream is "tunnel:<enclave_id>" is dialed by opening a
// stream on that enclave's session instead of a TCP connection. Each stream
// starts with a short preamble (below) and then carries exactly what a TCP
// connection to the enclave's :443 would: the spliced client ClientHello, or
// the gateway's own RA-TLS handshake in terminate and wsmux modes. TLS still
// ends inside the enclave, so the tunnel changes transport, not trust: the
// gateway sees the same ciphertext it splices today.
//
// Gateway instances share no state, so an enclave keeps a tunnel to each of
// them; whichever instance a client lands on then has a path.
package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	// ALPN is the protocol an enclave advertises when it dials in to open a
	// tunnel. The gateway recognises it in the ClientHello, before any route
	// lookup.
	ALPN = "privasys-tunnel/1"
	// Path is the upgrade request path.
	Path = "/__privasys/tunnel"
	// UpgradeProtocol is the Upgrade header value.
	UpgradeProtocol = "privasys-tunnel/1"
	// UpstreamPrefix marks a route upstream served over a tunnel:
	// "tunnel:<enclave_id>".
	UpstreamPrefix = "tunnel:"

	// preambleVersion is the first byte of every stream the gateway opens,
	// followed by a big-endian u16 length and the client's address (for the
	// enclave's logs only; it is not authenticated and grants nothing).
	preambleVersion  = 1
	maxPreambleField = 256
)

var (
	sessionsActive = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "gateway_tunnel_sessions_active",
		Help: "Enclave tunnel sessions currently connected",
	})
	sessionsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gateway_tunnel_sessions_total",
		Help: "Enclave tunnel session attempts by result",
	}, []string{"result"})
	streamsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gateway_tunnel_streams_total",
		Help: "Streams opened to enclaves over tunnels by result",
	}, []string{"result"})
)

// ErrNoTunnel is returned when a route points at an enclave that holds no
// tunnel to this gateway instance.
var ErrNoTunnel = errors.New("tunnel: enclave not connected to this gateway")

// EnclaveID returns the enclave id of a "tunnel:<id>" upstream.
func EnclaveID(upstream string) (string, bool) {
	if !strings.HasPrefix(upstream, UpstreamPrefix) {
		return "", false
	}
	id := strings.TrimPrefix(upstream, UpstreamPrefix)
	return id, id != ""
}

// Registry holds the live tunnel sessions, by enclave id.
type Registry struct {
	mu       sync.Mutex
	sessions map[string][]*entry
}

type entry struct {
	sess *yamux.Session
	at   time.Time
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{sessions: make(map[string][]*entry)}
}

// Register adds a session for an enclave and returns the function that
// removes it. An enclave may briefly hold two sessions to the same instance
// (a reconnect racing the old session's teardown); the newest is preferred.
func (r *Registry) Register(enclaveID string, sess *yamux.Session) func() {
	e := &entry{sess: sess, at: time.Now()}
	r.mu.Lock()
	r.sessions[enclaveID] = append(r.sessions[enclaveID], e)
	r.mu.Unlock()
	sessionsActive.Inc()
	return func() {
		r.mu.Lock()
		list := r.sessions[enclaveID]
		for i, x := range list {
			if x == e {
				list = append(list[:i], list[i+1:]...)
				break
			}
		}
		if len(list) == 0 {
			delete(r.sessions, enclaveID)
		} else {
			r.sessions[enclaveID] = list
		}
		r.mu.Unlock()
		sessionsActive.Dec()
	}
}

// Connected reports the number of enclaves holding at least one session.
func (r *Registry) Connected() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sessions)
}

func (r *Registry) pick(enclaveID string) *yamux.Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	var best *entry
	for _, e := range r.sessions[enclaveID] {
		if e.sess.IsClosed() {
			continue
		}
		if best == nil || e.at.After(best.at) {
			best = e
		}
	}
	if best == nil {
		return nil
	}
	return best.sess
}

// Open opens a stream to the enclave and writes the preamble. clientAddr is
// informational (the enclave logs it).
func (r *Registry) Open(ctx context.Context, enclaveID, clientAddr string) (net.Conn, error) {
	sess := r.pick(enclaveID)
	if sess == nil {
		streamsTotal.WithLabelValues("no_tunnel").Inc()
		return nil, ErrNoTunnel
	}
	type result struct {
		s   *yamux.Stream
		err error
	}
	ch := make(chan result, 1)
	go func() {
		s, err := sess.OpenStream()
		ch <- result{s, err}
	}()
	var s *yamux.Stream
	select {
	case res := <-ch:
		if res.err != nil {
			streamsTotal.WithLabelValues("open_error").Inc()
			return nil, fmt.Errorf("tunnel: open stream: %w", res.err)
		}
		s = res.s
	case <-ctx.Done():
		go func() {
			if res := <-ch; res.s != nil {
				res.s.Close()
			}
		}()
		streamsTotal.WithLabelValues("open_timeout").Inc()
		return nil, ctx.Err()
	}
	if err := writePreamble(s, clientAddr); err != nil {
		s.Close()
		streamsTotal.WithLabelValues("preamble_error").Inc()
		return nil, err
	}
	streamsTotal.WithLabelValues("ok").Inc()
	return &Stream{Stream: s}, nil
}

// Stream is a tunnel stream with TCP-like half-close: CloseWrite sends FIN
// (yamux's Close is already a half-close; reads continue until the enclave's
// FIN).
type Stream struct{ *yamux.Stream }

// CloseWrite half-closes the stream.
func (s *Stream) CloseWrite() error { return s.Stream.Close() }

func writePreamble(c net.Conn, clientAddr string) error {
	if len(clientAddr) > maxPreambleField {
		clientAddr = clientAddr[:maxPreambleField]
	}
	b := make([]byte, 3+len(clientAddr))
	b[0] = preambleVersion
	binary.BigEndian.PutUint16(b[1:3], uint16(len(clientAddr)))
	copy(b[3:], clientAddr)
	_, err := c.Write(b)
	return err
}

// Dialer opens a connection to a route upstream: a tunnel stream for
// "tunnel:<id>" upstreams, a TCP connection otherwise.
type Dialer struct {
	Registry *Registry
	Timeout  time.Duration
}

// DialUpstream dials upstream. clientAddr is forwarded to tunnelled
// enclaves for logging; it may be empty.
func (d *Dialer) DialUpstream(ctx context.Context, upstream, clientAddr string) (net.Conn, error) {
	if d.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.Timeout)
		defer cancel()
	}
	if id, ok := EnclaveID(upstream); ok {
		if d.Registry == nil {
			return nil, ErrNoTunnel
		}
		return d.Registry.Open(ctx, id, clientAddr)
	}
	var nd net.Dialer
	return nd.DialContext(ctx, "tcp", upstream)
}

// yamuxConfig is shared by the gateway (client) side. Keepalives detect a
// dead enclave path within ~30s so the registry stops routing to it.
func yamuxConfig() *yamux.Config {
	c := yamux.DefaultConfig()
	c.EnableKeepAlive = true
	c.KeepAliveInterval = 15 * time.Second
	c.ConnectionWriteTimeout = 15 * time.Second
	c.MaxStreamWindowSize = 1 << 20
	c.StreamOpenTimeout = 30 * time.Second
	c.LogOutput = nil
	c.Logger = discardLogger{}
	return c
}

type discardLogger struct{}

func (discardLogger) Print(...interface{})          {}
func (discardLogger) Printf(string, ...interface{}) {}
func (discardLogger) Println(...interface{})        {}
