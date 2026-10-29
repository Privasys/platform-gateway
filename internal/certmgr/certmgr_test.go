package certmgr

import (
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

// The platform wildcard answers for platform hostnames and nothing else: an
// adopter hostname gets no certificate here at all (it is spliced to its
// enclave), rather than one that does not name it.
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
	if got := r.wildcardFor("harness.apps.privasys.org"); got == nil {
		t.Error("wildcard should cover a platform hostname")
	}
	if got := r.wildcardFor("harness.example.com"); got != nil {
		t.Error("wildcard must not be served for an adopter hostname")
	}
	// There is no certificate for an adopter hostname here: such a name is
	// only ever spliced to its enclave, which holds its own.
	if _, err := r.GetCertificate(&tls.ClientHelloInfo{ServerName: "harness.example.com"}); err == nil {
		t.Error("expected an error for an adopter hostname")
	}
}
