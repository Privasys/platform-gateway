package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/Privasys/platform-gateway/internal/quarantine"
	"github.com/Privasys/platform-gateway/internal/routetable"
)

// echoEnclave is a TLS server that echoes what it reads, standing in for an
// enclave terminating RA-TLS behind a splice.
func echoEnclave(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
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
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

// TestQuarantineCutsOpenSplice checks that a spliced connection already
// open when its route turns quarantined is closed.
func TestQuarantineCutsOpenSplice(t *testing.T) {
	upstream := echoEnclave(t)
	table := routetable.New()
	tracker := quarantine.NewTracker()
	table.OnQuarantine(func(host string) { tracker.CutHost(host) })
	active := routetable.Route{SNI: spliceTestHost, Upstream: upstream}
	table.Update([]routetable.Route{active}, "v1")
	g := New(table, "", time.Second, 30*time.Second, 32768, nil)
	g.SetTracker(tracker)

	server, client := net.Pipe()
	g.wg.Add(1)
	go g.handleConn(server)
	tc := tls.Client(client, &tls.Config{ServerName: spliceTestHost, NextProtos: []string{"privasys-ratls/1"}, InsecureSkipVerify: true})
	defer tc.Close()
	tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if _, err := tc.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(tc, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo = %q (%v)", buf, err)
	}
	if tracker.Open(spliceTestHost) != 1 {
		t.Fatalf("tracked splices = %d, want 1", tracker.Open(spliceTestHost))
	}

	quarantined := active
	quarantined.State = routetable.StateQuarantined
	table.Update([]routetable.Route{quarantined}, "v2")

	tc.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := tc.Read(buf)
	if err == nil {
		t.Fatal("spliced connection still open after quarantine")
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("spliced connection was not cut")
	}
}
