// Package sync polls the management service for route updates.
package sync

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/Privasys/platform-gateway/internal/routetable"
)

// RoutesResponse is the JSON response from GET /api/v1/internal/routes.
type RoutesResponse struct {
	Routes  []routetable.Route `json:"routes"`
	Version string             `json:"version"`
}

// Syncer periodically fetches routes from the management service.
type Syncer struct {
	table    *routetable.Table
	client   *http.Client
	url      string
	token    string
	interval time.Duration

	// Metrics
	lastSync   time.Time
	lastErr    error
	syncCount  int64
	errorCount int64
}

// New creates a route syncer.
func New(table *routetable.Table, managementURL, authToken string, interval time.Duration) *Syncer {
	return &Syncer{
		table:    table,
		url:      managementURL + "/api/v1/internal/routes",
		token:    authToken,
		interval: interval,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
				MaxIdleConns:    2,
				IdleConnTimeout: 90 * time.Second,
			},
		},
	}
}

// Run starts the polling loop. Blocks until ctx is cancelled.
func (s *Syncer) Run(ctx context.Context) {
	// Immediate first sync
	s.fetchOnce(ctx)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.fetchOnce(ctx)
		}
	}
}

func (s *Syncer) fetchOnce(ctx context.Context) {
	s.syncCount++

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		s.recordError(err)
		return
	}

	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}

	// ETag for conditional requests
	if v := s.table.Version(); v != "" {
		req.Header.Set("If-None-Match", `"`+v+`"`)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		s.recordError(fmt.Errorf("fetch routes: %w", err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		s.lastSync = time.Now()
		s.lastErr = nil
		return
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		s.recordError(fmt.Errorf("fetch routes: HTTP %d: %s", resp.StatusCode, body))
		return
	}

	var result RoutesResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		s.recordError(fmt.Errorf("decode routes: %w", err))
		return
	}

	if result.Version == "" {
		result.Version = routetable.ComputeVersion(result.Routes)
	}

	changed := s.table.Update(result.Routes, result.Version)
	s.lastSync = time.Now()
	s.lastErr = nil

	if changed {
		log.Printf("routes updated: %d routes, version=%s", len(result.Routes), result.Version)
	}
}

func (s *Syncer) recordError(err error) {
	s.errorCount++
	s.lastErr = err
	log.Printf("sync error: %v", err)
}

// LastSync returns the time of the last successful sync.
func (s *Syncer) LastSync() time.Time { return s.lastSync }

// LastError returns the last sync error, or nil.
func (s *Syncer) LastError() error { return s.lastErr }

// SyncCount returns the total number of sync attempts.
func (s *Syncer) SyncCount() int64 { return s.syncCount }

// ErrorCount returns the total number of sync errors.
func (s *Syncer) ErrorCount() int64 { return s.errorCount }
