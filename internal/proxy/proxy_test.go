package proxy

import (
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/platform-gateway/internal/routetable"
)

const spliceTestHost = "app.example.com"

// fakeEnclave accepts TCP connections and reports the first bytes of each.
func fakeEnclave(t *testing.T) (string, <-chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	got := make(chan []byte, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			buf := make([]byte, 5)
			n, _ := io.ReadFull(c, buf)
			got <- buf[:n]
			c.Close()
		}
	}()
	return ln.Addr().String(), got
}

// spliceHandshake runs one RA-TLS-capable (spliced) client handshake through
// the gateway and returns the client's handshake error.
func spliceHandshake(t *testing.T, g *Gateway) error {
	t.Helper()
	server, client := net.Pipe()
	g.wg.Add(1)
	go g.handleConn(server)
	tc := tls.Client(client, &tls.Config{
		ServerName:         spliceTestHost,
		NextProtos:         []string{"privasys-ratls/1"},
		InsecureSkipVerify: true,
	})
	defer tc.Close()
	tc.SetDeadline(time.Now().Add(5 * time.Second))
	return tc.Handshake()
}

func TestSpliceRefusesQuarantinedRoute(t *testing.T) {
	upstream, got := fakeEnclave(t)
	table := routetable.New()
	table.Update([]routetable.Route{{SNI: spliceTestHost, Upstream: upstream, State: routetable.StateQuarantined}}, "v1")
	g := New(table, "", time.Second, time.Second, 32768, nil)

	err := spliceHandshake(t, g)
	if err == nil || !strings.Contains(err.Error(), "handshake failure") {
		t.Fatalf("handshake error = %v, want a handshake failure alert", err)
	}
	select {
	case b := <-got:
		t.Fatalf("quarantined upstream was dialed (got %x)", b)
	case <-time.After(200 * time.Millisecond):
	}

	// Released: the state is gone, the ClientHello reaches the enclave.
	table.Update([]routetable.Route{{SNI: spliceTestHost, Upstream: upstream}}, "v2")
	_ = spliceHandshake(t, g)
	select {
	case b := <-got:
		if len(b) == 0 || b[0] != 0x16 {
			t.Fatalf("enclave got %x, want a TLS handshake record", b)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("released route was not spliced to the enclave")
	}
}
