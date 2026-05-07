// Package config provides configuration loading for the gateway.
package config

import (
	"flag"
	"fmt"
	"os"
	"time"
)

// Config holds all gateway configuration.
type Config struct {
	ListenAddr    string        // TCP address to listen on (e.g. ":443")
	HealthAddr    string        // HTTP address for health/metrics (e.g. ":9090")
	ManagementURL string        // Management service URL (e.g. "https://api.developer.privasys.org")
	AuthToken     string        // Bearer token for management service (monitoring+ role)
	PollInterval  time.Duration // How often to sync routes
	DialTimeout   time.Duration // Timeout for connecting to upstream backends
	IdleTimeout   time.Duration // Close idle upstream connections after this duration
	BufferSize    int           // Read buffer size in bytes

	// Terminate-mode (session-relay) options. When TLSCertPath is set,
	// the gateway will terminate inbound TLS for any connection that
	// does NOT advertise the `privasys-ratls/1` ALPN, using the loaded
	// wildcard cert (LE-issued). RA-TLS-aware clients always splice.
	// Empty = terminate mode disabled (gateway is splice-only).
	TLSCertPath string // path to wildcard cert PEM (e.g. /etc/privasys/tls/wildcard.crt)
	TLSKeyPath  string // path to wildcard cert key PEM
	UpstreamCA  string // optional CA bundle to validate enclave RA-TLS chains; empty enforces only OID policy
	CORSOrigins string // comma-separated list of allowed CORS origins for terminate-mode routes; empty disables CORS
}

// Load parses configuration from CLI flags with env var fallbacks.
func Load() (*Config, error) {
	cfg := &Config{}

	flag.StringVar(&cfg.ListenAddr, "listen", envOr("GATEWAY_LISTEN", ":443"), "TCP listen address")
	flag.StringVar(&cfg.HealthAddr, "health", envOr("GATEWAY_HEALTH", ":9090"), "Health/metrics HTTP address")
	flag.StringVar(&cfg.ManagementURL, "management-url", envOr("GATEWAY_MANAGEMENT_URL", ""), "Management service URL")
	flag.StringVar(&cfg.AuthToken, "auth-token", envOr("GATEWAY_AUTH_TOKEN", ""), "Bearer token for management service")
	pollSec := flag.Int("poll-interval", envOrInt("GATEWAY_POLL_INTERVAL", 5), "Route sync poll interval in seconds")
	dialSec := flag.Int("dial-timeout", envOrInt("GATEWAY_DIAL_TIMEOUT", 2), "Upstream dial timeout in seconds")
	idleSec := flag.Int("idle-timeout", envOrInt("GATEWAY_IDLE_TIMEOUT", 300), "Idle connection timeout in seconds")
	flag.IntVar(&cfg.BufferSize, "buffer-size", envOrInt("GATEWAY_BUFFER_SIZE", 32768), "Read buffer size in bytes")
	flag.StringVar(&cfg.TLSCertPath, "tls-cert", envOr("GATEWAY_TLS_CERT", ""), "Path to public TLS wildcard certificate PEM (enables terminate mode)")
	flag.StringVar(&cfg.TLSKeyPath, "tls-key", envOr("GATEWAY_TLS_KEY", ""), "Path to public TLS wildcard certificate key PEM")
	flag.StringVar(&cfg.UpstreamCA, "upstream-ca", envOr("GATEWAY_UPSTREAM_CA", ""), "Optional CA bundle to validate enclave RA-TLS chains in terminate mode")
	flag.StringVar(&cfg.CORSOrigins, "cors-origins", envOr("GATEWAY_CORS_ORIGINS", ""), "Comma-separated list of allowed CORS origins for terminate-mode routes. Supports exact origins (https://chat.privasys.org) and wildcard suffixes (*.privasys.org or https://*.privasys.org). Empty disables CORS.")

	flag.Parse()

	cfg.PollInterval = time.Duration(*pollSec) * time.Second
	cfg.DialTimeout = time.Duration(*dialSec) * time.Second
	cfg.IdleTimeout = time.Duration(*idleSec) * time.Second

	if cfg.ManagementURL == "" {
		return nil, fmt.Errorf("management-url is required (set -management-url or GATEWAY_MANAGEMENT_URL)")
	}
	if (cfg.TLSCertPath == "") != (cfg.TLSKeyPath == "") {
		return nil, fmt.Errorf("tls-cert and tls-key must both be set or both empty")
	}

	return cfg, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envOrInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
		return n
	}
	return fallback
}
