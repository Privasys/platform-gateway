package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/Privasys/platform-gateway/internal/routetable"
	"github.com/Privasys/platform-gateway/internal/tunnel"
	"github.com/hashicorp/yamux"
)

type allowAuth struct{}

func (allowAuth) Authorize(_ context.Context, r tunnel.AuthRequest) (string, error) {
	return r.Headers["X-Enclave-Id"], nil
}

// tunnelEnclave connects to the gateway the way an enclave behind a
// no-ingress firewall does, and pipes every stream to target.
func tunnelEnclave(t *testing.T, g *Gateway, enclaveID, target string) {
	t.Helper()
	server, client := net.Pipe()
	g.wg.Add(1)
	go g.handleConn(server)
	tc := tls.Client(client, &tls.Config{ServerName: "tunnel.apps.test", NextProtos: []string{tunnel.ALPN}, InsecureSkipVerify: true})
	t.Cleanup(func() { tc.Close() })
	body := fmt.Sprintf(`{"enclave_id":%q}`, enclaveID)
	fmt.Fprintf(tc, "POST %s HTTP/1.1\r\nHost: tunnel.apps.test\r\nUpgrade: %s\r\nX-Enclave-Id: %s\r\nContent-Length: %d\r\n\r\n%s",
		tunnel.Path, tunnel.UpgradeProtocol, enclaveID, len(body), body)
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("tunnel upgrade: %v %v", resp, err)
	}
	sess, err := yamux.Server(tc, nil)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			s, err := sess.AcceptStream()
			if err != nil {
				return
			}
			go func() {
				defer s.Close()
				var hdr [3]byte
				if _, err := io.ReadFull(s, hdr[:]); err != nil {
					return
				}
				io.CopyN(io.Discard, s, int64(binary.BigEndian.Uint16(hdr[1:])))
				up, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer up.Close()
				go io.Copy(up, s)
				io.Copy(s, up)
			}()
		}
	}()
}

// TestSpliceOverTunnel: an RA-TLS client reaches an enclave that accepts no
// inbound connections, through the enclave's own outbound tunnel.
func TestSpliceOverTunnel(t *testing.T) {
	upstream := echoEnclave(t)
	table := routetable.New()
	table.Update([]routetable.Route{{SNI: spliceTestHost, Upstream: "tunnel:enc-1"}}, "v1")
	g := New(table, "", 2*time.Second, 30*time.Second, 32768, nil)

	reg := tunnel.NewRegistry()
	g.SetDialer((&tunnel.Dialer{Registry: reg}).DialUpstream)
	g.SetTunnelAcceptor(tunnel.NewAcceptor(g.fallbackTLS, allowAuth{}, reg))

	tunnelEnclave(t, g, "enc-1", upstream)
	deadline := time.Now().Add(3 * time.Second)
	for reg.Connected() != 1 {
		if time.Now().After(deadline) {
			t.Fatal("tunnel never registered")
		}
		time.Sleep(10 * time.Millisecond)
	}

	server, client := net.Pipe()
	g.wg.Add(1)
	go g.handleConn(server)
	tc := tls.Client(client, &tls.Config{ServerName: spliceTestHost, NextProtos: []string{"privasys-ratls/1"}, InsecureSkipVerify: true})
	defer tc.Close()
	tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		t.Fatalf("handshake through tunnel: %v", err)
	}
	if _, err := tc.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(tc, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo = %q (%v)", buf, err)
	}
}

// TestSpliceTunnelNotConnected: a tunnel route whose enclave holds no tunnel
// here fails the dial instead of hanging.
func TestSpliceTunnelNotConnected(t *testing.T) {
	table := routetable.New()
	table.Update([]routetable.Route{{SNI: spliceTestHost, Upstream: "tunnel:absent"}}, "v1")
	g := New(table, "", time.Second, time.Second, 32768, nil)
	g.SetDialer((&tunnel.Dialer{Registry: tunnel.NewRegistry()}).DialUpstream)

	server, client := net.Pipe()
	g.wg.Add(1)
	go g.handleConn(server)
	tc := tls.Client(client, &tls.Config{ServerName: spliceTestHost, NextProtos: []string{"privasys-ratls/1"}, InsecureSkipVerify: true})
	defer tc.Close()
	tc.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tc.Handshake(); err == nil {
		t.Fatal("handshake succeeded with no tunnel")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("dial hung instead of failing")
	}
}
