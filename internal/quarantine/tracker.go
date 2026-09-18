package quarantine

import (
	"log"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Kinds of open traffic a Tracker cuts, used as the "mode" label of
// gateway_quarantine_cuts_total.
const (
	KindSplice    = "splice"    // spliced RA-TLS connection
	KindHTTP      = "http"      // in-flight terminated request (streamed responses)
	KindWebSocket = "websocket" // WebSocket tunnelled through the reverse proxy
	KindSealedWS  = "sealed_ws" // sealed WebSocket stream on the enclave mux
)

var cuts = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "gateway_quarantine_cuts_total",
	Help: "Open connections and streams closed because their route became quarantined, by host and kind",
}, []string{"host", "mode"})

// Tracker keeps the open traffic of every hostname so it can be cut the
// moment the host's route turns quarantined. Refusing new connections is
// not enough: RA-TLS SDKs and sealed WebSockets hold long-lived
// connections that would otherwise keep reaching the enclave.
//
// A nil *Tracker is valid and tracks nothing.
//
// Callers must check the route again after Track returns: CutHost runs
// after the table swap, so a connection registered after the cut sees the
// quarantined route on that check, and one registered before is cut.
type Tracker struct {
	mu    sync.Mutex
	next  uint64
	hosts map[string]map[uint64]tracked
}

type tracked struct {
	kind  string
	close func()
}

// NewTracker returns an empty tracker.
func NewTracker() *Tracker {
	return &Tracker{hosts: make(map[string]map[uint64]tracked)}
}

// Track registers open traffic of the given kind for host. closeFn must
// tear it down and may block (it runs on its own goroutine). The returned
// release removes the entry and must be called when the traffic ends.
func (t *Tracker) Track(host, kind string, closeFn func()) (release func()) {
	if t == nil {
		return func() {}
	}
	host = strings.ToLower(host)
	t.mu.Lock()
	t.next++
	id := t.next
	m := t.hosts[host]
	if m == nil {
		m = make(map[uint64]tracked)
		t.hosts[host] = m
	}
	m[id] = tracked{kind: kind, close: closeFn}
	t.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			t.mu.Lock()
			defer t.mu.Unlock()
			if m := t.hosts[host]; m != nil {
				delete(m, id)
				if len(m) == 0 {
					delete(t.hosts, host)
				}
			}
		})
	}
}

// Open returns the number of tracked entries for host.
func (t *Tracker) Open(host string) int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.hosts[strings.ToLower(host)])
}

// CutHost closes everything open to host and returns how many entries it
// cut. The close functions run asynchronously so a slow close handshake
// never holds up the route table swap.
func (t *Tracker) CutHost(host string) int {
	if t == nil {
		return 0
	}
	host = strings.ToLower(host)
	t.mu.Lock()
	m := t.hosts[host]
	delete(t.hosts, host)
	t.mu.Unlock()

	byKind := make(map[string]int)
	for _, e := range m {
		byKind[e.kind]++
		cuts.WithLabelValues(host, e.kind).Inc()
		go e.close()
	}
	if len(m) > 0 {
		log.Printf("route %q quarantined: cut %d open (%v)", host, len(m), byKind)
	}
	return len(m)
}
