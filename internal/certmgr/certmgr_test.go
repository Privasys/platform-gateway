package certmgr

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Privasys/platform-gateway/internal/certloader"
	"github.com/Privasys/platform-gateway/internal/routetable"
	"golang.org/x/crypto/acme"
)

// writeWildcard writes a self-signed *.apps.privasys.org certificate and
// returns its paths.
func writeWildcard(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "*.apps.privasys.org"},
		DNSNames:     []string{"*.apps.privasys.org"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "wildcard.crt")
	keyPath := filepath.Join(dir, "wildcard.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

func testLookup(routes map[string]routetable.Route) RouteLookup {
	return func(host string) (routetable.Route, bool) {
		r, ok := routes[host]
		return r, ok
	}
}

// The platform wildcard answers for platform hostnames and nothing else: an
// adopter hostname must fall through to ACME rather than be served a
// certificate that does not name it.
func TestWildcardCoversOnlyPlatformNames(t *testing.T) {
	certPath, keyPath := writeWildcard(t)
	loader, err := certloader.New(certPath, keyPath)
	if err != nil {
		t.Fatalf("certloader: %v", err)
	}
	r, err := New(Options{Wildcard: loader})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if r.ACMEEnabled() {
		t.Error("ACME should be disabled without a cache directory")
	}
	if got := r.wildcardFor("harness.apps.privasys.org"); got == nil {
		t.Error("wildcard should cover a platform hostname")
	}
	if got := r.wildcardFor("harness.example.com"); got != nil {
		t.Error("wildcard must not be served for an adopter hostname")
	}
	// Without ACME configured there is simply no certificate for an
	// adopter hostname, and the handshake fails rather than presenting a
	// certificate for the wrong name.
	if _, err := r.GetCertificate(&tls.ClientHelloInfo{ServerName: "harness.example.com"}); err == nil {
		t.Error("expected an error for an adopter hostname with ACME disabled")
	}
}

// Issuance is gated on the route table: only a hostname the control plane
// publishes as an alias may cause this gateway to ask a CA for anything.
func TestHostPolicyAllowsPublishedAliasesOnly(t *testing.T) {
	certPath, keyPath := writeWildcard(t)
	loader, err := certloader.New(certPath, keyPath)
	if err != nil {
		t.Fatalf("certloader: %v", err)
	}
	routes := map[string]routetable.Route{
		"harness.example.com":       {SNI: "harness.example.com", Canonical: "harness.apps.privasys.org"},
		"harness.apps.privasys.org": {SNI: "harness.apps.privasys.org"},
	}
	r, err := New(Options{
		Wildcard: loader,
		CacheDir: t.TempDir(),
		Lookup:   testLookup(routes),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !r.ACMEEnabled() {
		t.Fatal("ACME should be enabled with a cache directory")
	}
	if err := r.hostPolicy(context.Background(), "harness.example.com"); err != nil {
		t.Errorf("published alias refused: %v", err)
	}
	if err := r.hostPolicy(context.Background(), "HARNESS.EXAMPLE.COM."); err != nil {
		t.Errorf("alias refused when the name arrives upper-cased and rooted: %v", err)
	}
	if err := r.hostPolicy(context.Background(), "harness.apps.privasys.org"); err == nil {
		t.Error("a platform route is served by the wildcard and must not be issued for")
	}
	if err := r.hostPolicy(context.Background(), "bank.example"); err == nil {
		t.Error("a hostname with no route must never be issued for")
	}
}

// A cache directory without a way to check the route table would issue for
// anything that resolved to us, so it is refused at construction.
func TestACMERequiresARouteLookup(t *testing.T) {
	if _, err := New(Options{CacheDir: t.TempDir()}); err == nil {
		t.Fatal("expected New to refuse ACME without a route lookup")
	}
}

// The ALPN challenge must reach the ACME manager even for a platform
// hostname the wildcard could otherwise answer.
func TestChallengeDetection(t *testing.T) {
	if !isACMEChallenge(&tls.ClientHelloInfo{SupportedProtos: []string{acme.ALPNProto}}) {
		t.Error("acme-tls/1 should be recognised as a challenge")
	}
	if isACMEChallenge(&tls.ClientHelloInfo{SupportedProtos: []string{"h2", "http/1.1"}}) {
		t.Error("ordinary browser protocols must not be treated as a challenge")
	}
}
