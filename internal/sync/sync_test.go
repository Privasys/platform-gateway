package sync

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Privasys/platform-gateway/internal/routetable"
)

// TestFetchCarriesState checks that the syncer carries the optional route
// state from the feed into the table, and that dropping it releases the
// route.
func TestFetchCarriesState(t *testing.T) {
	var feed atomic.Value
	feed.Store(`{"version": "v1", "routes": [
		{"sni": "a.apps.privasys.org", "upstream": "10.0.0.1:443", "state": "quarantined"},
		{"sni": "b.apps.privasys.org", "upstream": "10.0.0.2:443"}
	]}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(feed.Load().(string)))
	}))
	defer srv.Close()

	table := routetable.New()
	s := New(table, srv.URL, "", time.Second)
	s.fetchOnce(context.Background())

	if r, ok := table.Lookup("a.apps.privasys.org"); !ok || !r.Quarantined() {
		t.Fatalf("a: route = %+v ok=%v, want quarantined", r, ok)
	}
	if r, ok := table.Lookup("b.apps.privasys.org"); !ok || r.Quarantined() {
		t.Fatalf("b: route = %+v ok=%v, want active", r, ok)
	}

	var released RoutesResponse
	released.Version = "v2"
	released.Routes = []routetable.Route{
		{SNI: "a.apps.privasys.org", Upstream: "10.0.0.1:443"},
		{SNI: "b.apps.privasys.org", Upstream: "10.0.0.2:443"},
	}
	b, _ := json.Marshal(released)
	feed.Store(string(b))
	s.fetchOnce(context.Background())

	if r, ok := table.Lookup("a.apps.privasys.org"); !ok || r.Quarantined() {
		t.Fatalf("a after release: route = %+v ok=%v, want active", r, ok)
	}
	if s.LastError() != nil {
		t.Fatalf("sync error: %v", s.LastError())
	}
}
