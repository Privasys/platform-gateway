package tunnel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
)

// fakeAuth accepts exactly one enclave id, and checks the gateway forwarded
// the signed body and headers untouched.
type fakeAuth struct{ allow string }

func (f fakeAuth) Authorize(_ context.Context, r AuthRequest) (string, error) {
	if r.Method != http.MethodPost || r.Path != Path {
		return "", fmt.Errorf("unexpected %s %s", r.Method, r.Path)
	}
	if _, ok := r.Headers["X-Unrelated"]; ok {
		return "", errors.New("unrelated header forwarded")
	}
	id := r.Headers["X-Enclave-Id"]
	if id != f.allow || !bytes.Contains(r.Body, []byte(id)) {
		return "", errors.New("denied")
	}
	return id, nil
}

func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		DNSNames:              []string{"tunnel.apps.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

// startGateway runs an Acceptor on a loopback listener.
func startGateway(t *testing.T, auth Authorizer) (addr string, reg *Registry, pool *x509.CertPool) {
	t.Helper()
	cert, pool := testCert(t)
	reg = NewRegistry()
	acc := NewAcceptor(&tls.Config{Certificates: []tls.Certificate{cert}}, auth, reg)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); acc.Handle(c, nil) }()
		}
	}()
	return ln.Addr().String(), reg, pool
}

// fakeEnclave dials in as enclaveID and serves each stream by upper-casing
// what it reads. Returns the HTTP status of the upgrade and the preamble
// addresses it saw.
func fakeEnclave(t *testing.T, addr string, pool *x509.CertPool, enclaveID string) (int, chan string) {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		RootCAs: pool, ServerName: "tunnel.apps.test", NextProtos: []string{ALPN},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"enclave_id":%q}`, enclaveID)
	fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: tunnel.apps.test\r\nUpgrade: %s\r\nConnection: Upgrade\r\n"+
		"X-Enclave-Id: %s\r\nX-Unrelated: x\r\nContent-Length: %d\r\n\r\n%s",
		Path, UpgradeProtocol, enclaveID, len(body), body)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan string, 8)
	if resp.StatusCode != http.StatusSwitchingProtocols {
		conn.Close()
		return resp.StatusCode, seen
	}
	sess, err := yamux.Server(conn, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sess.Close() })
	go func() {
		for {
			s, err := sess.AcceptStream()
			if err != nil {
				return
			}
			go func() {
				defer s.Close()
				var hdr [3]byte
				if _, err := io.ReadFull(s, hdr[:]); err != nil || hdr[0] != preambleVersion {
					return
				}
				a := make([]byte, binary.BigEndian.Uint16(hdr[1:]))
				io.ReadFull(s, a)
				seen <- string(a)
				data, _ := io.ReadAll(s) // until the gateway's half-close
				s.Write([]byte(strings.ToUpper(string(data))))
			}()
		}
	}()
	return resp.StatusCode, seen
}

func waitConnected(t *testing.T, reg *Registry, n int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for reg.Connected() != n {
		if time.Now().After(deadline) {
			t.Fatalf("connected = %d, want %d", reg.Connected(), n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestTunnelEndToEnd(t *testing.T) {
	addr, reg, pool := startGateway(t, fakeAuth{allow: "enc-1"})
	code, seen := fakeEnclave(t, addr, pool, "enc-1")
	if code != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status %d", code)
	}
	waitConnected(t, reg, 1)

	d := &Dialer{Registry: reg, Timeout: 2 * time.Second}
	for i := 0; i < 3; i++ { // several streams on one session
		c, err := d.DialUpstream(context.Background(), "tunnel:enc-1", "203.0.113.7:4242")
		if err != nil {
			t.Fatal(err)
		}
		c.Write([]byte("hello tunnel"))
		c.(interface{ CloseWrite() error }).CloseWrite()
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		got, err := io.ReadAll(c)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "HELLO TUNNEL" {
			t.Fatalf("got %q", got)
		}
		c.Close()
		if a := <-seen; a != "203.0.113.7:4242" {
			t.Fatalf("preamble addr %q", a)
		}
	}
}

func TestTunnelUnauthorized(t *testing.T) {
	addr, reg, pool := startGateway(t, fakeAuth{allow: "enc-1"})
	code, _ := fakeEnclave(t, addr, pool, "enc-2")
	if code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", code)
	}
	if reg.Connected() != 0 {
		t.Fatal("unauthorized enclave registered")
	}
}

func TestDialNoTunnel(t *testing.T) {
	d := &Dialer{Registry: NewRegistry(), Timeout: time.Second}
	if _, err := d.DialUpstream(context.Background(), "tunnel:absent", ""); !errors.Is(err, ErrNoTunnel) {
		t.Fatalf("err = %v, want ErrNoTunnel", err)
	}
}

func TestSessionDropUnregisters(t *testing.T) {
	addr, reg, pool := startGateway(t, fakeAuth{allow: "enc-1"})
	conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: pool, ServerName: "tunnel.apps.test", NextProtos: []string{ALPN}})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"enclave_id":"enc-1"}`
	fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: x\r\nUpgrade: %s\r\nX-Enclave-Id: enc-1\r\nContent-Length: %d\r\n\r\n%s",
		Path, UpgradeProtocol, len(body), body)
	if resp, err := http.ReadResponse(bufio.NewReader(conn), nil); err != nil || resp.StatusCode != 101 {
		t.Fatalf("upgrade: %v", err)
	}
	sess, _ := yamux.Server(conn, nil)
	waitConnected(t, reg, 1)
	sess.Close()
	waitConnected(t, reg, 0)
}

func TestEnclaveID(t *testing.T) {
	if id, ok := EnclaveID("tunnel:abc"); !ok || id != "abc" {
		t.Fatal("tunnel:abc")
	}
	for _, s := range []string{"1.2.3.4:443", "tunnel:", ""} {
		if _, ok := EnclaveID(s); ok {
			t.Fatalf("%q parsed as tunnel", s)
		}
	}
}

func TestAuthHeadersNeverForwardBearer(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Bearer enclave-credential")
	h.Set("X-Enclave-Id", "3f2a9c1e-5b7d-4e8a-9c21-7d4e5f6a8b90")
	h.Set("X-Enclave-Sig", "c2ln")
	h.Set("Cookie", "a=b")
	got := authHeaders(h)
	if _, ok := got["Authorization"]; ok {
		t.Fatal("a bearer was forwarded to the authorizer")
	}
	if _, ok := got["Cookie"]; ok {
		t.Fatal("an unrelated header was forwarded")
	}
	if got["X-Enclave-Id"] == "" || got["X-Enclave-Sig"] == "" {
		t.Fatalf("enclaveauth headers dropped: %v", got)
	}
}
