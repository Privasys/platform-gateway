package sni

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name string
		sni  string
	}{
		{name: "simple hostname", sni: "example.com"},
		{name: "subdomain", sni: "myapp.apps.privasys.org"},
		{name: "long subdomain", sni: "very-long-app-name-123.apps.privasys.org"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hello := buildClientHello(t, tt.sni)
			got, err := Parse(hello)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if got != tt.sni {
				t.Errorf("Parse() = %q, want %q", got, tt.sni)
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want error
	}{
		{name: "empty", data: nil, want: ErrTruncated},
		{name: "too short", data: []byte{0x16, 0x03, 0x01}, want: ErrTruncated},
		{name: "not TLS", data: []byte{0x15, 0x03, 0x01, 0x00, 0x01, 0x00}, want: ErrNotTLS},
		{name: "not ClientHello", data: []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x02, 0x00, 0x00, 0x01, 0x00}, want: ErrNotClientHello},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.data)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if err != tt.want {
				t.Errorf("Parse() error = %v, want %v", err, tt.want)
			}
		})
	}
}

// buildClientHello creates a real TLS ClientHello by connecting through a pipe.
func buildClientHello(t *testing.T, serverName string) []byte {
	t.Helper()

	// Create a TCP listener to receive the ClientHello
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	clientHelloCh := make(chan []byte, 1)
	errCh := make(chan error, 1)

	// Server side: accept and read the raw ClientHello
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			errCh <- err
			return
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		clientHelloCh <- data
	}()

	// Client side: start a TLS handshake (will fail, but sends ClientHello)
	go func() {
		conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
		if err != nil {
			return
		}
		defer conn.Close()
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true,
		})
		tlsConn.SetDeadline(time.Now().Add(2 * time.Second))
		_ = tlsConn.Handshake() // Will fail — no server TLS
	}()

	select {
	case hello := <-clientHelloCh:
		return hello
	case err := <-errCh:
		t.Fatal(err)
		return nil
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for ClientHello")
		return nil
	}
}
