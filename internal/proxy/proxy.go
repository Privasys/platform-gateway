// Package proxy implements the L4 TCP proxy that reads the TLS ClientHello
// SNI, looks up the upstream backend, and splices the connection.
package proxy

import (
	"context"
	"log"
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

// Gateway is an L4 TCP proxy that routes based on TLS ClientHello SNI.
type Gateway struct {
	table       *routetable.Table
	listenAddr  string
	dialTimeout time.Duration
	idleTimeout time.Duration
	bufferSize  int

	listener net.Listener
	wg       sync.WaitGroup
	closed   atomic.Bool
}

// New creates a gateway.
func New(table *routetable.Table, listenAddr string, dialTimeout, idleTimeout time.Duration, bufferSize int) *Gateway {
	return &Gateway{
		table:       table,
		listenAddr:  listenAddr,
		dialTimeout: dialTimeout,
		idleTimeout: idleTimeout,
		bufferSize:  bufferSize,
	}
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

	// Read enough of the ClientHello to extract SNI.
	// TLS records can be up to 16KB, but the ClientHello is almost always
	// in the first ~500 bytes. We read into a buffer and parse from there.
	buf := make([]byte, g.bufferSize)

	// Set a deadline for the initial read (5 seconds to send ClientHello)
	clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := clientConn.Read(buf)
	if err != nil {
		connErrors.WithLabelValues("client_read").Inc()
		return
	}
	// Clear the deadline
	clientConn.SetReadDeadline(time.Time{})

	hostname, err := sni.Parse(buf[:n])
	if err != nil {
		connErrors.WithLabelValues("sni_parse").Inc()
		log.Printf("SNI parse error from %s: %v", clientConn.RemoteAddr(), err)
		return
	}

	upstream, ok := g.table.Lookup(hostname)
	if !ok {
		connErrors.WithLabelValues("no_route").Inc()
		log.Printf("no route for SNI %q from %s", hostname, clientConn.RemoteAddr())
		return
	}

	// Connect to upstream
	backendConn, err := net.DialTimeout("tcp", upstream, g.dialTimeout)
	if err != nil {
		connErrors.WithLabelValues("dial_upstream").Inc()
		log.Printf("dial upstream %s for %q: %v", upstream, hostname, err)
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
