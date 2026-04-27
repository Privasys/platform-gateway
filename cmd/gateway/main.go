package main

import (
	"context"
	"crypto/x509"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Privasys/platform-gateway/internal/certloader"
	"github.com/Privasys/platform-gateway/internal/config"
	"github.com/Privasys/platform-gateway/internal/health"
	"github.com/Privasys/platform-gateway/internal/proxy"
	"github.com/Privasys/platform-gateway/internal/routetable"
	routesync "github.com/Privasys/platform-gateway/internal/sync"
	"github.com/Privasys/platform-gateway/internal/terminate"
)

// Set at build time via -ldflags
var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildTime = "unknown"
)

func main() {
	log.Printf("platform-gateway %s (commit=%s built=%s)", Version, GitCommit, BuildTime)

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Route table
	table := routetable.New()

	// Route syncer
	syncer := routesync.New(table, cfg.ManagementURL, cfg.AuthToken, cfg.PollInterval)

	// Health/metrics server
	healthSrv := health.New(table, syncer)
	httpSrv := &http.Server{
		Addr:         cfg.HealthAddr,
		Handler:      healthSrv.Handler(),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	// Optional terminate-mode handler. Enabled when wildcard cert paths
	// are configured. Reloads on SIGHUP via certloader's signal handler.
	var terminator proxy.Terminator
	if cfg.TLSCertPath != "" {
		loader, err := certloader.New(cfg.TLSCertPath, cfg.TLSKeyPath)
		if err != nil {
			log.Fatalf("certloader: %v", err)
		}
		var caPool *x509.CertPool
		if cfg.UpstreamCA != "" {
			caBytes, err := os.ReadFile(cfg.UpstreamCA)
			if err != nil {
				log.Fatalf("read upstream-ca %s: %v", cfg.UpstreamCA, err)
			}
			caPool = x509.NewCertPool()
			if !caPool.AppendCertsFromPEM(caBytes) {
				log.Fatalf("upstream-ca: no certificates parsed from %s", cfg.UpstreamCA)
			}
		}
		terminator = terminate.New(terminate.Options{
			TLSConfig:    loader.TLSConfig(),
			DialTimeout:  cfg.DialTimeout,
			IdleTimeout:  cfg.IdleTimeout,
			CACertPool:   caPool,
			InsecureSkip: caPool == nil, // no CA pool ⇒ rely on OID policy only
			CORSOrigins:  splitAndTrim(cfg.CORSOrigins),
		})
		log.Printf("terminate mode enabled (cert=%s key=%s upstream-ca=%q cors=%q)", cfg.TLSCertPath, cfg.TLSKeyPath, cfg.UpstreamCA, cfg.CORSOrigins)
	} else {
		log.Printf("terminate mode disabled (no -tls-cert configured); routes requesting Mode=terminate will be dropped")
	}

	// L4 gateway
	gw := proxy.New(table, cfg.ListenAddr, cfg.DialTimeout, cfg.IdleTimeout, cfg.BufferSize, terminator)

	// Start route syncer in background
	go syncer.Run(ctx)

	// Start health/metrics HTTP server
	go func() {
		log.Printf("health/metrics listening on %s", cfg.HealthAddr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("health server: %v", err)
		}
	}()

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("shutting down...")
		cancel()

		// Stop health server
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		httpSrv.Shutdown(shutdownCtx)

		// Drain active connections
		gw.Drain()
	}()

	// Run gateway (blocks)
	if err := gw.Run(ctx); err != nil {
		log.Fatalf("gateway: %v", err)
	}

	log.Println("gateway stopped")
}

// splitAndTrim splits a comma-separated list, trimming whitespace and
// dropping empty entries. Used for -cors-origins.
func splitAndTrim(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
