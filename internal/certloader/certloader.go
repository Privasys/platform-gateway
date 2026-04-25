// Package certloader loads a TLS certificate + key from disk and reloads
// on SIGHUP. Used by the gateway to serve a publicly-trusted Let's Encrypt
// wildcard certificate for *.apps.privasys.org / *.apps-test.privasys.org
// while a separate ACME client (lego, certbot, etc.) handles renewal.
package certloader

import (
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
)

// Loader holds the most recent successfully loaded certificate and reloads
// on SIGHUP. Safe for concurrent use; reads are lock-free via atomic.Pointer.
type Loader struct {
	certPath string
	keyPath  string
	cert     atomic.Pointer[tls.Certificate]
}

// New loads the initial certificate and starts a SIGHUP watcher.
// Returns an error if the initial load fails.
func New(certPath, keyPath string) (*Loader, error) {
	l := &Loader{certPath: certPath, keyPath: keyPath}
	if err := l.reload(); err != nil {
		return nil, fmt.Errorf("initial cert load: %w", err)
	}
	go l.watchSIGHUP()
	return l, nil
}

func (l *Loader) reload() error {
	cert, err := tls.LoadX509KeyPair(l.certPath, l.keyPath)
	if err != nil {
		return err
	}
	l.cert.Store(&cert)
	notAfter := "unknown"
	if cert.Leaf != nil {
		notAfter = cert.Leaf.NotAfter.Format("2006-01-02T15:04:05Z")
	}
	log.Printf("certloader: loaded %s (NotAfter=%s)", l.certPath, notAfter)
	return nil
}

func (l *Loader) watchSIGHUP() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	for range ch {
		if err := l.reload(); err != nil {
			log.Printf("certloader: SIGHUP reload failed: %v", err)
		} else {
			log.Printf("certloader: cert reloaded via SIGHUP")
		}
	}
}

// GetCertificate is a tls.Config.GetCertificate callback.
func (l *Loader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c := l.cert.Load()
	if c == nil {
		return nil, fmt.Errorf("certloader: no certificate loaded")
	}
	return c, nil
}

// TLSConfig returns a tls.Config that serves the loaded certificate.
// HTTP/1.1 only — HTTP/2 over the public TLS leg is a future improvement.
func (l *Loader) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: l.GetCertificate,
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"http/1.1"},
	}
}
