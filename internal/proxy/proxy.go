// Package proxy implements the L4 TCP proxy that reads the TLS ClientHello
// SNI, looks up the upstream backend, and splices the connection.
package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Privasys/platform-gateway/internal/routetable"
	"github.com/Privasys/platform-gateway/internal/sni"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	connTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "gateway_connections_total",
		Help: "Total accepted connections",
	})
	connActive = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "gateway_connections_active",
		Help: "Currently active proxied connections",
	})
	connErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gateway_connection_errors_total",
		Help: "Connection errors by type",
	}, []string{"reason"})
	bytesTransferred = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gateway_bytes_total",
		Help: "Bytes transferred",
	}, []string{"direction"})
)

// Gateway is an L4/L7 TCP proxy that routes based on TLS ClientHello SNI.
//
// Per inbound connection, after the SNI/ALPN have been peeked from the
// ClientHello, the gateway picks a transport:
//
//   - splice (default): pure L4 SNI splice. The TLS handshake completes at
//     the upstream enclave (which presents an RA-TLS leaf cert) and the
//     gateway never sees plaintext. RA-TLS-aware clients opt into splice
//     by advertising the `privasys-ratls/1` ALPN protocol.
//
//   - terminate: when no `privasys-ratls/1` ALPN is offered AND a
//     terminator (LE wildcard cert) is configured, the gateway terminates
//     inbound TLS, opens an internal RA-TLS connection to the upstream
//     (verifying the enclave's quote per the per-route attestation
//     policy), and reverse-proxies HTTP. This lets browsers (which cannot
//     verify RA-TLS) reach enclave apps via the session-relay flow.
//
// If the terminator is not configured the gateway falls back to splice for
// every connection.
type Gateway struct {
	table       *routetable.Table
	listenAddr  string
	dialTimeout time.Duration
	idleTimeout time.Duration
	bufferSize  int
	fallbackTLS *tls.Config
	terminator  Terminator // optional, nil disables terminate mode

	listener net.Listener
	wg       sync.WaitGroup
	closed   atomic.Bool
}

// Terminator handles the terminate-mode path for a single inbound
// connection. Implementations are in the terminate package; pass nil to New
// to disable terminate mode (the gateway will splice every connection).
type Terminator interface {
	Handle(clientConn net.Conn, clientHello []byte, route routetable.Route)
}

// New creates a gateway. terminator may be nil to disable terminate mode.
func New(table *routetable.Table, listenAddr string, dialTimeout, idleTimeout time.Duration, bufferSize int, terminator Terminator) *Gateway {
	tlsCfg, err := selfSignedTLSConfig()
	if err != nil {
		log.Printf("warning: could not generate fallback TLS cert, unknown SNI will drop: %v", err)
	}
	return &Gateway{
		table:       table,
		listenAddr:  listenAddr,
		dialTimeout: dialTimeout,
		idleTimeout: idleTimeout,
		bufferSize:  bufferSize,
		fallbackTLS: tlsCfg,
		terminator:  terminator,
	}
}

// selfSignedTLSConfig generates an ephemeral self-signed certificate used
// only to complete a TLS handshake with clients that request an unknown SNI,
// so that the gateway can return a proper HTTP 404 response.
func selfSignedTLSConfig() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certDER},
			PrivateKey:  key,
		}},
	}, nil
}

// PrefixConn wraps a net.Conn and replays buffered bytes before reading
// from the underlying connection. This allows the TLS server to re-read
// the ClientHello that was already consumed for SNI extraction. Exported
// so the terminate package can reuse it.
type PrefixConn = prefixConn

// NewPrefixConn returns a PrefixConn that replays buf before reading conn.
func NewPrefixConn(conn net.Conn, buf []byte) *PrefixConn {
	return &prefixConn{Conn: conn, buf: buf}
}

// prefixConn wraps a net.Conn and replays buffered bytes before reading
// from the underlying connection. This allows the TLS server to re-read
// the ClientHello that was already consumed for SNI extraction.
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

// Run starts accepting connections. Blocks until ctx is cancelled.
func (g *Gateway) Run(ctx context.Context) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", g.listenAddr)
	if err != nil {
		return err
	}
	g.listener = ln
	log.Printf("gateway listening on %s", g.listenAddr)

	go func() {
		<-ctx.Done()
		g.closed.Store(true)
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if g.closed.Load() {
				break
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			return err
		}
		connTotal.Inc()
		g.wg.Add(1)
		go g.handleConn(conn)
	}

	g.wg.Wait()
	return nil
}

func (g *Gateway) handleConn(clientConn net.Conn) {
	defer g.wg.Done()
	defer clientConn.Close()
	connActive.Inc()
	defer connActive.Dec()

	// Read the ClientHello to extract SNI. TLS records can be up to 16KB,
	// and a large ClientHello (post-quantum key shares in Go 1.24+/Chrome
	// make ~1.7KB hellos routine) arrives split across TCP segments, so a
	// single Read often returns a truncated record. Keep reading until the
	// hello parses, the buffer fills, or the deadline expires.
	buf := make([]byte, g.bufferSize)

	// Deadline covers the whole ClientHello (5 seconds to send it)
	clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var (
		n        int
		hostname string
		alpns    []string
	)
	for {
		m, err := clientConn.Read(buf[n:])
		if err != nil {
			connErrors.WithLabelValues("client_read").Inc()
			return
		}
		n += m
		hostname, alpns, err = sni.ParseClientHello(buf[:n])
		if err == nil {
			break
		}
		if errors.Is(err, sni.ErrTruncated) && n < len(buf) {
			continue
		}
		connErrors.WithLabelValues("sni_parse").Inc()
		log.Printf("SNI parse error from %s: %v", clientConn.RemoteAddr(), err)
		return
	}
	// Clear the deadline
	clientConn.SetReadDeadline(time.Time{})

	route, ok := g.table.Lookup(hostname)
	if !ok {
		connErrors.WithLabelValues("no_route").Inc()
		log.Printf("no route for SNI %q from %s", hostname, clientConn.RemoteAddr())
		g.send404(clientConn, buf[:n], hostname)
		return
	}

	// Transport selection:
	//   - Clients that advertise the privasys-ratls/1 ALPN are RA-TLS-aware
	//     (e.g. the wallet's NativeRaTls module) — splice them through so the
	//     enclave terminates RA-TLS itself.
	//   - Everything else (browsers, curl) gets terminate when configured,
	//     so they see the LE wildcard cert and the gateway opens an internal
	//     RA-TLS connection to the enclave on their behalf.
	ratlsCapable := sni.HasALPN(alpns, "privasys-ratls/1")
	if !ratlsCapable && g.terminator != nil {
		g.terminator.Handle(clientConn, buf[:n], route)
		return
	}

	// Splice mode (default): pure L4 SNI splice.
	backendConn, err := net.DialTimeout("tcp", route.Upstream, g.dialTimeout)
	if err != nil {
		connErrors.WithLabelValues("dial_upstream").Inc()
		log.Printf("dial upstream %s for %q: %v", route.Upstream, hostname, err)
		return
	}
	defer backendConn.Close()

	// Replay the buffered ClientHello bytes to the backend
	if _, err := backendConn.Write(buf[:n]); err != nil {
		connErrors.WithLabelValues("write_upstream").Inc()
		return
	}

	// Splice the two connections
	g.splice(clientConn, backendConn)
}

func (g *Gateway) splice(client, backend net.Conn) {
	done := make(chan struct{}, 2)

	// client → backend
	go func() {
		n := g.copyWithIdleTimeout(backend, client)
		bytesTransferred.WithLabelValues("client_to_backend").Add(float64(n))
		if tc, ok := backend.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()

	// backend → client
	go func() {
		n := g.copyWithIdleTimeout(client, backend)
		bytesTransferred.WithLabelValues("backend_to_client").Add(float64(n))
		if tc, ok := client.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()

	// Wait for both directions to finish
	<-done
	<-done
}

func (g *Gateway) copyWithIdleTimeout(dst, src net.Conn) int64 {
	buf := make([]byte, 32*1024)
	var total int64
	for {
		src.SetReadDeadline(time.Now().Add(g.idleTimeout))
		nr, rerr := src.Read(buf)
		if nr > 0 {
			nw, werr := dst.Write(buf[:nr])
			total += int64(nw)
			if werr != nil {
				break
			}
		}
		if rerr != nil {
			break
		}
	}
	return total
}

const http404Body = `<!DOCTYPE html>
<html><head><title>404 Not Found</title></head>
<body><h1>404 Not Found</h1><p>The requested application does not exist.</p></body>
</html>`

// send404 completes a TLS handshake with a self-signed certificate and
// returns an HTTP 404 response. This allows clients connecting to an
// unknown SNI to receive a meaningful error instead of a connection reset.
func (g *Gateway) send404(conn net.Conn, clientHello []byte, hostname string) {
	if g.fallbackTLS == nil {
		return
	}
	wrapped := &prefixConn{Conn: conn, buf: clientHello}
	tlsConn := tls.Server(wrapped, g.fallbackTLS)
	tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	resp := fmt.Sprintf("HTTP/1.1 404 Not Found\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(http404Body), http404Body)
	tlsConn.Write([]byte(resp))
	tlsConn.Close()
}

// ActiveConnections returns the current count of active connections.
func ActiveConnections() float64 {
	// Read from the prometheus gauge — for health endpoint use
	ch := make(chan prometheus.Metric, 1)
	connActive.Collect(ch)
	return 0 // Use prometheus directly for actual value
}

// Drain stops accepting new connections but waits for existing ones to finish.
func (g *Gateway) Drain() {
	if g.listener != nil {
		g.listener.Close()
	}
	g.wg.Wait()
}
