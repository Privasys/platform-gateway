// Package certmgr resolves the public certificate for a terminated
// connection: the platform's own wildcard for `<app>.apps.privasys.org`,
// and a per-host Let's Encrypt certificate for an adopter's own hostname.
//
// An adopter's hostname reaches this gateway only as an ALIAS ROUTE in the
// table the control plane feeds. That table is therefore also the issuance
// gate: autocert asks HostPolicy before it will talk to the ACME server, and
// the answer is yes only for a hostname the control plane has verified and
// published. Nothing a client sends can make this gateway request a
// certificate for a name nobody registered.
//
// The challenge type is TLS-ALPN-01 exclusively, which suits an SNI router:
// the challenge arrives as a TLS connection for the very hostname being
// validated, on the port already being served. No port 80 is opened, and no
// access to the adopter's DNS is needed. Each gateway issues for itself, so
// there is no shared certificate storage; an app hostname resolves to every
// gateway in its environment, and a challenge may land on any of them.
package certmgr

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"strings"

	"github.com/Privasys/platform-gateway/internal/certloader"
	"github.com/Privasys/platform-gateway/internal/routetable"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// RouteLookup reads the live route table (typically routetable.Table.Lookup).
type RouteLookup func(host string) (routetable.Route, bool)

// Options configures a Resolver.
type Options struct {
	// Wildcard serves the platform's own hostnames. May be nil, in which
	// case every name must come from ACME.
	Wildcard *certloader.Loader
	// CacheDir stores issued certificates and the ACME account key. Empty
	// disables ACME entirely: the resolver then serves the wildcard only,
	// exactly as the gateway did before adopter hostnames existed.
	CacheDir string
	// Email is the ACME account contact address. Optional.
	Email string
	// DirectoryURL overrides the ACME directory (staging, or a test CA).
	// Empty uses Let's Encrypt production.
	DirectoryURL string
	// Lookup gates issuance. Required when CacheDir is set.
	Lookup RouteLookup
}

// Resolver picks a certificate per ClientHello.
type Resolver struct {
	wildcard *certloader.Loader
	manager  *autocert.Manager
	lookup   RouteLookup
}

// New builds a Resolver. With no CacheDir it is a thin wrapper over the
// wildcard loader.
func New(opts Options) (*Resolver, error) {
	r := &Resolver{wildcard: opts.Wildcard, lookup: opts.Lookup}
	if opts.CacheDir == "" {
		return r, nil
	}
	if opts.Lookup == nil {
		return nil, fmt.Errorf("certmgr: a route lookup is required to gate issuance")
	}
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(opts.CacheDir),
		HostPolicy: r.hostPolicy,
		Email:      opts.Email,
	}
	if opts.DirectoryURL != "" {
		m.Client = &acme.Client{DirectoryURL: opts.DirectoryURL}
	}
	r.manager = m
	return r, nil
}

// ACMEEnabled reports whether per-host issuance is configured.
func (r *Resolver) ACMEEnabled() bool { return r.manager != nil }

// hostPolicy authorises issuance for published alias hostnames only.
func (r *Resolver) hostPolicy(_ context.Context, host string) error {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	route, ok := r.lookup(host)
	if !ok {
		return fmt.Errorf("certmgr: %q has no route", host)
	}
	if !route.IsAlias() {
		return fmt.Errorf("certmgr: %q is not an adopter hostname", host)
	}
	return nil
}

// GetCertificate is a tls.Config.GetCertificate callback.
func (r *Resolver) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// A TLS-ALPN-01 challenge must reach autocert whatever the name is:
	// the client offers only the acme-tls/1 protocol and expects the
	// challenge certificate rather than the real one.
	if r.manager != nil && isACMEChallenge(hello) {
		return r.manager.GetCertificate(hello)
	}
	if cert := r.wildcardFor(hello.ServerName); cert != nil {
		return cert, nil
	}
	if r.manager == nil {
		return nil, fmt.Errorf("certmgr: no certificate for %q", hello.ServerName)
	}
	cert, err := r.manager.GetCertificate(hello)
	if err != nil {
		// Worth a line: this is where a mis-delegated adopter domain or a
		// rate limit shows up, and it is otherwise invisible to the
		// adopter (the browser just sees a handshake failure).
		log.Printf("certmgr: no certificate for %q: %v", hello.ServerName, err)
	}
	return cert, err
}

// wildcardFor returns the loaded platform certificate when it covers name.
func (r *Resolver) wildcardFor(name string) *tls.Certificate {
	if r.wildcard == nil {
		return nil
	}
	cert, err := r.wildcard.GetCertificate(nil)
	if err != nil || cert == nil {
		return nil
	}
	// No SNI at all (an IP-literal client, a health probe): keep the old
	// behaviour of answering with the platform certificate.
	if name == "" {
		return cert
	}
	leaf := cert.Leaf
	if leaf == nil {
		parsed, perr := x509.ParseCertificate(cert.Certificate[0])
		if perr != nil {
			return nil
		}
		leaf = parsed
	}
	if leaf.VerifyHostname(strings.TrimSuffix(name, ".")) != nil {
		return nil
	}
	return cert
}

// TLSConfig returns the server config for terminate mode. acme-tls/1 is
// advertised so a TLS-ALPN-01 challenge can negotiate it; browsers never
// offer it, so ordinary traffic is unaffected.
func (r *Resolver) TLSConfig() *tls.Config {
	protos := []string{"http/1.1"}
	if r.manager != nil {
		protos = append(protos, acme.ALPNProto)
	}
	return &tls.Config{
		GetCertificate: r.GetCertificate,
		MinVersion:     tls.VersionTLS12,
		NextProtos:     protos,
	}
}

func isACMEChallenge(hello *tls.ClientHelloInfo) bool {
	for _, p := range hello.SupportedProtos {
		if p == acme.ALPNProto {
			return true
		}
	}
	return false
}
