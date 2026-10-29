// Package certmgr resolves the certificate for each terminated ClientHello:
// the platform wildcard for the platform's own hostnames, and nothing else.
//
// An adopter's own hostname is served in direct mode only: the gateway
// splices it to the enclave, which obtains and holds its own certificate. The
// gateway therefore never issues for an adopter hostname, and holds no
// certificate for one (it used to, for the alias mode, which is gone).
package certmgr

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/Privasys/platform-gateway/internal/certloader"
)

// Options configures a Resolver.
type Options struct {
	// Wildcard serves the platform's own hostnames.
	Wildcard *certloader.Loader
}

// Resolver picks the certificate for a terminated connection.
type Resolver struct {
	wildcard *certloader.Loader
}

// New builds a Resolver over the wildcard loader.
func New(opts Options) (*Resolver, error) {
	return &Resolver{wildcard: opts.Wildcard}, nil
}

// GetCertificate is a tls.Config.GetCertificate callback.
func (r *Resolver) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if cert := r.wildcardFor(hello.ServerName); cert != nil {
		return cert, nil
	}
	return nil, fmt.Errorf("certmgr: no certificate for %q", hello.ServerName)
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

// TLSConfig returns the server config for terminate mode.
func (r *Resolver) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: r.GetCertificate,
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"http/1.1"},
	}
}
