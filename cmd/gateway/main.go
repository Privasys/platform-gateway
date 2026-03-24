package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Privasys/platform-gateway/internal/config"
	"github.com/Privasys/platform-gateway/internal/health"
	"github.com/Privasys/platform-gateway/internal/proxy"
	"github.com/Privasys/platform-gateway/internal/routetable"
	routesync "github.com/Privasys/platform-gateway/internal/sync"
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

	// L4 gateway
	gw := proxy.New(table, cfg.ListenAddr, cfg.DialTimeout, cfg.IdleTimeout, cfg.BufferSize)

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
