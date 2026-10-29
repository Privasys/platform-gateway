package proxy

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/Privasys/platform-gateway/internal/routetable"
)

const directTestHost = "app.adopter.example"

// recordingTerminator counts the connections handed to the terminate path
// and closes them, so the client handshake ends.
type recordingTerminator struct{ calls chan string }

func (r *recordingTerminator) Handle(c net.Conn, _ []byte, route routetable.Route) {
	r.calls <- route.SNI
	c.Close()
}

// handshakeWith runs one client handshake on directTestHost with the given
// ALPN list through the gateway. The result does not matter: the test reads
// which path received the connection.
func handshakeWith(g *Gateway, alpns []string) {
	server, client := net.Pipe()
	g.wg.Add(1)
	go g.handleConn(server)
	tc := tls.Client(client, &tls.Config{
		ServerName:         directTestHost,
		NextProtos:         alpns,
		InsecureSkipVerify: true,
	})
	defer tc.Close()
	tc.SetDeadline(time.Now().Add(2 * time.Second))
	_ = tc.Handshake()
}

// path reports where the last connection went: "splice", "terminate" or "".
func path(got <-chan []byte, term *recordingTerminator) string {
	select {
	case <-got:
		return "splice"
	case <-term.calls:
		return "terminate"
	case <-time.After(2 * time.Second):
		return ""
	}
}

func directGateway(t *testing.T, mode string) (*Gateway, <-chan []byte, *recordingTerminator) {
	t.Helper()
	upstream, got := fakeEnclave(t)
	table := routetable.New()
	table.Update([]routetable.Route{{
		SNI:       directTestHost,
		Upstream:  upstream,
		Canonical: "app.apps.privasys.org",
		Mode:      mode,
	}}, "v1")
	term := &recordingTerminator{calls: make(chan string, 4)}
	return New(table, "", time.Second, time.Second, 32768, term), got, term
}

// A direct name is spliced whatever the client offers: browsers, RA-TLS
// clients and the ACME validation all reach the enclave, never the terminator.
func TestDirectSplicesEveryALPN(t *testing.T) {
	g, got, term := directGateway(t, routetable.ModeDirect)
	for _, alpns := range [][]string{nil, {"h2", "http/1.1"}, {"privasys-ratls/1"}, {"acme-tls/1"}} {
		handshakeWith(g, alpns)
		if p := path(got, term); p != "splice" {
			t.Errorf("ALPN %v went to %q, want splice", alpns, p)
		}
	}
}

// While pending, only the TLS-ALPN-01 challenge is spliced; everything else
// is still an alias, terminated here.
func TestDirectPendingSplicesOnlyTheACMEChallenge(t *testing.T) {
	g, got, term := directGateway(t, routetable.ModeDirectPending)
	cases := []struct {
		alpns []string
		want  string
	}{
		{[]string{"acme-tls/1"}, "splice"},
		{[]string{"acme-tls/1", "h2"}, "terminate"},
		{[]string{"h2", "http/1.1"}, "terminate"},
		{nil, "terminate"},
		{[]string{"privasys-ratls/1"}, "terminate"},
	}
	for _, c := range cases {
		handshakeWith(g, c.alpns)
		if p := path(got, term); p != c.want {
			t.Errorf("ALPN %v went to %q, want %q", c.alpns, p, c.want)
		}
	}
}

// A direct route whose enclave is quarantined is refused like any splice:
// the upstream is never dialed.
func TestDirectRefusesQuarantinedRoute(t *testing.T) {
	upstream, got := fakeEnclave(t)
	table := routetable.New()
	table.Update([]routetable.Route{{
		SNI: directTestHost, Upstream: upstream, Canonical: "app.apps.privasys.org",
		Mode: routetable.ModeDirect, State: routetable.StateQuarantined,
	}}, "v1")
	term := &recordingTerminator{calls: make(chan string, 4)}
	g := New(table, "", time.Second, time.Second, 32768, term)
	handshakeWith(g, []string{"h2"})
	if p := path(got, term); p != "" {
		t.Fatalf("quarantined direct route went to %q, want refused", p)
	}
}
