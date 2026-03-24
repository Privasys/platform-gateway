// Package health exposes a health check and Prometheus metrics HTTP server.
package health

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Privasys/platform-gateway/internal/routetable"
	routesync "github.com/Privasys/platform-gateway/internal/sync"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Server serves health checks and Prometheus metrics.
type Server struct {
	table  *routetable.Table
	syncer *routesync.Syncer
	mux    *http.ServeMux
}

// New creates a health/metrics server.
func New(table *routetable.Table, syncer *routesync.Syncer) *Server {
	s := &Server{
		table:  table,
		syncer: syncer,
		mux:    http.NewServeMux(),
	}

	s.mux.HandleFunc("/healthz", s.handleHealth)
	s.mux.HandleFunc("/readyz", s.handleReady)
	s.mux.Handle("/metrics", promhttp.Handler())

	return s
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "ok",
		"routes":     s.table.Count(),
		"version":    s.table.Version(),
		"last_sync":  formatTime(s.syncer.LastSync()),
		"last_error": formatError(s.syncer.LastError()),
		"syncs":      s.syncer.SyncCount(),
		"errors":     s.syncer.ErrorCount(),
	})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Ready if we have at least one successful sync
	if s.syncer.LastSync().IsZero() {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "not ready",
			"reason": "no successful sync yet",
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ready",
	})
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format(time.RFC3339)
}

func formatError(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
