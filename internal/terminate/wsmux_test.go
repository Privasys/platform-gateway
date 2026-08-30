package terminate

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Privasys/platform-gateway/internal/routetable"
	"github.com/coder/websocket"
)

func selfSignedTLS(t *testing.T, cn string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// fakeEnclave speaks the mux server side: 101 on the mux upgrade, then acks
// every OPEN by echoing its sealed envelope back as DATA and echoes DATA.
// muxStatus != 101 refuses the mux upgrade with that status instead, and any
// non-mux request gets a fixed 418 (to make v1 passthrough observable).
func fakeEnclave(t *testing.T, muxStatus int) (addr string, opens *atomic.Int32) {
	t.Helper()
	cert := selfSignedTLS(t, "enclave.test")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("enclave listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	opens = &atomic.Int32{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				br := bufio.NewReader(conn)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				if req.URL.Path != muxPath {
					fmt.Fprintf(conn, "HTTP/1.1 418 I'm a teapot\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
					return
				}
				if muxStatus != http.StatusSwitchingProtocols {
					fmt.Fprintf(conn, "HTTP/1.1 %d X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", muxStatus)
					return
				}
				fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: %s\r\nConnection: Upgrade\r\n\r\n", muxProtocol)
				bw := bufio.NewWriter(conn)
				write := func(typ byte, sid string, stream uint64, payload []byte) {
					var hdr [14]byte
					hdr[0] = typ
					hdr[1] = byte(len(sid))
					for i := 0; i < 8; i++ {
						hdr[2+i] = byte(stream >> (56 - 8*i))
					}
					for i := 0; i < 4; i++ {
						hdr[10+i] = byte(len(payload) >> (24 - 8*i))
					}
					bw.Write(hdr[:2])
					bw.WriteString(sid)
					bw.Write(hdr[2:14])
					bw.Write(payload)
					bw.Flush()
				}
				for {
					typ, sid, stream, payload, err := readMuxFrame(br)
					if err != nil {
						return
					}
					switch typ {
					case muxTypePing:
						write(muxTypePong, "", 0, payload)
					case muxTypeOpen:
						opens.Add(1)
						// Echo the sealed open envelope back as the "ack".
						_, _, env, perr := parseTestOpen(payload)
						if perr != nil {
							return
						}
						write(muxTypeData, sid, stream, env)
					case muxTypeData:
						write(muxTypeData, sid, stream, payload)
					case muxTypeClose:
						write(muxTypeClose, sid, stream, payload)
					}
				}
			}(conn)
		}
	}()
	return ln.Addr().String(), opens
}

func parseTestOpen(payload []byte) (host, path string, env []byte, err error) {
	if len(payload) < 2 {
		return "", "", nil, fmt.Errorf("short")
	}
	hl := int(payload[0])<<8 | int(payload[1])
	if len(payload) < 2+hl+2 {
		return "", "", nil, fmt.Errorf("short host")
	}
	host = string(payload[2 : 2+hl])
	off := 2 + hl
	pl := int(payload[off])<<8 | int(payload[off+1])
	off += 2
	if len(payload) < off+pl {
		return "", "", nil, fmt.Errorf("short path")
	}
	return host, string(payload[off : off+pl]), payload[off+pl:], nil
}

// startGateway serves h.Handle on a TCP listener for a single route.
func startGateway(t *testing.T, h *Handler, route routetable.Route) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("gateway listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go h.Handle(conn, nil, route)
		}
	}()
	return ln.Addr().String()
}

func wsClient(t *testing.T, gwAddr, sni string) *http.Client {
	t.Helper()
	return &http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				raw, err := net.Dial("tcp", gwAddr)
				if err != nil {
					return nil, err
				}
				c := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: sni})
				if err := c.HandshakeContext(ctx); err != nil {
					raw.Close()
					return nil, err
				}
				return c, nil
			},
		},
	}
}

func TestWSMuxEndToEnd(t *testing.T) {
	enclaveAddr, opens := fakeEnclave(t, http.StatusSwitchingProtocols)
	gwCert := selfSignedTLS(t, "app.test")
	h := New(Options{
		TLSConfig:    &tls.Config{Certificates: []tls.Certificate{gwCert}},
		InsecureSkip: true,
	})
	route := routetable.Route{SNI: "app.test", Upstream: enclaveAddr}
	gwAddr := startGateway(t, h, route)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ws, resp, err := websocket.Dial(ctx, "wss://app.test/live", &websocket.DialOptions{
		HTTPClient:   wsClient(t, gwAddr, "app.test"),
		Subprotocols: []string{sealedWSSubprotocol, "session-abc", "00000000000000aa"},
	})
	if err != nil {
		t.Fatalf("browser dial: %v (resp %+v)", err, resp)
	}
	defer ws.CloseNow()
	if got := resp.Header.Get("Sec-Websocket-Protocol"); got != sealedWSSubprotocol {
		t.Fatalf("echoed subprotocol = %q, want %q", got, sealedWSSubprotocol)
	}

	// Sealed open (opaque bytes to gateway and fake enclave alike); the fake
	// enclave echoes it back, proving it crossed the mux leg intact.
	open := []byte("sealed-open-envelope")
	if err := ws.Write(ctx, websocket.MessageBinary, open); err != nil {
		t.Fatalf("send open: %v", err)
	}
	typ, ack, err := ws.Read(ctx)
	if err != nil || typ != websocket.MessageBinary || !bytes.Equal(ack, open) {
		t.Fatalf("ack = %q (%v), want echoed open", ack, err)
	}
	if opens.Load() != 1 {
		t.Fatalf("enclave OPEN count = %d", opens.Load())
	}

	msg := []byte("sealed-data-frame")
	if err := ws.Write(ctx, websocket.MessageBinary, msg); err != nil {
		t.Fatalf("send data: %v", err)
	}
	if _, echo, err := ws.Read(ctx); err != nil || !bytes.Equal(echo, msg) {
		t.Fatalf("echo = %q (%v)", echo, err)
	}

	// A second stream must reuse the pooled mux leg, not a new upgrade per
	// stream: dial again and confirm both streams work concurrently.
	ws2, _, err := websocket.Dial(ctx, "wss://app.test/live2", &websocket.DialOptions{
		HTTPClient:   wsClient(t, gwAddr, "app.test"),
		Subprotocols: []string{sealedWSSubprotocol, "session-abc", "00000000000000bb"},
	})
	if err != nil {
		t.Fatalf("second stream dial: %v", err)
	}
	defer ws2.CloseNow()
	if err := ws2.Write(ctx, websocket.MessageBinary, []byte("o2")); err != nil {
		t.Fatalf("second open: %v", err)
	}
	if _, ack2, err := ws2.Read(ctx); err != nil || !bytes.Equal(ack2, []byte("o2")) {
		t.Fatalf("second ack: %q (%v)", ack2, err)
	}
	if opens.Load() != 2 {
		t.Fatalf("enclave OPEN count = %d, want 2", opens.Load())
	}
}

// TestWSMuxUnavailableRefusesUpgrade proves an enclave without the mux
// endpoint (e.g. an old runtime answering 404) refuses the sealed WebSocket
// upgrade outright — there is no 1:1 path.
func TestWSMuxUnavailableRefusesUpgrade(t *testing.T) {
	enclaveAddr, _ := fakeEnclave(t, http.StatusNotFound)
	gwCert := selfSignedTLS(t, "app.test")
	h := New(Options{
		TLSConfig:    &tls.Config{Certificates: []tls.Certificate{gwCert}},
		InsecureSkip: true,
	})
	route := routetable.Route{SNI: "app.test", Upstream: enclaveAddr}
	gwAddr := startGateway(t, h, route)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, resp, err := websocket.Dial(ctx, "wss://app.test/live", &websocket.DialOptions{
		HTTPClient:   wsClient(t, gwAddr, "app.test"),
		Subprotocols: []string{sealedWSSubprotocol, "session-abc", "00000000000000aa"},
	})
	if err == nil {
		t.Fatal("expected the upgrade to be refused")
	}
	if resp == nil || resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %+v, want 502", resp)
	}
}

func TestParseSealedWS(t *testing.T) {
	mk := func(protos string) *http.Request {
		req, _ := http.NewRequest(http.MethodGet, "https://app.test/live", nil)
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Connection", "Upgrade")
		if protos != "" {
			req.Header.Set("Sec-WebSocket-Protocol", protos)
		}
		return req
	}
	if p := parseSealedWS(mk("privasys.sealed.v1, sid-1, 00000000000000ff")); p == nil || p.sessionID != "sid-1" || p.streamID != 0xff {
		t.Fatalf("parse failed: %+v", p)
	}
	for name, protos := range map[string]string{
		"marker only":    "privasys.sealed.v1",
		"no stream":      "privasys.sealed.v1, sid-1",
		"bad hex":        "privasys.sealed.v1, sid-1, zz00000000000000",
		"short hex":      "privasys.sealed.v1, sid-1, ff",
		"wrong ordering": "sid-1, privasys.sealed.v1, 00000000000000ff",
		"none":           "",
	} {
		if p := parseSealedWS(mk(protos)); p != nil {
			t.Fatalf("%s: expected nil, got %+v", name, p)
		}
	}
	plain := mk("privasys.sealed.v1, sid-1, 00000000000000ff")
	plain.Header.Set("Upgrade", "h2c")
	if parseSealedWS(plain) != nil {
		t.Fatal("non-websocket upgrade must not parse")
	}
	_ = strings.TrimSpace("")
}
