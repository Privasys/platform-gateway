package tunnel

import (
	"net"
	"sync"
	"time"
)

// Default per-source budget for tunnel opens that reach the authorizer.
const (
	authorizeRatePerMinute = 10
	authorizeBurst         = 5
	// maxTrackedSources bounds the bucket map; past it, sources whose
	// bucket has refilled are forgotten.
	maxTrackedSources = 10000
)

// sourceBuckets is a token bucket per source address (an IPv4 address or an
// IPv6 /64), refilled continuously at rate tokens per second up to burst.
type sourceBuckets struct {
	rate  float64
	burst float64
	now   func() time.Time

	mu sync.Mutex
	m  map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newSourceBuckets(perMinute, burst int) *sourceBuckets {
	return &sourceBuckets{
		rate:  float64(perMinute) / 60,
		burst: float64(burst),
		now:   time.Now,
		m:     make(map[string]*bucket),
	}
}

// take spends one token of key's bucket, reporting whether one was left.
func (s *sourceBuckets) take(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	b := s.refill(key, now)
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// give returns a token to key's bucket (a tunnel that was authorized does
// not count against its source).
func (s *sourceBuckets) give(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.refill(key, s.now())
	b.tokens = min(s.burst, b.tokens+1)
}

func (s *sourceBuckets) refill(key string, now time.Time) *bucket {
	b, ok := s.m[key]
	if !ok {
		if len(s.m) >= maxTrackedSources {
			s.prune(now)
		}
		b = &bucket{tokens: s.burst, last: now}
		s.m[key] = b
		return b
	}
	b.tokens = min(s.burst, b.tokens+now.Sub(b.last).Seconds()*s.rate)
	b.last = now
	return b
}

// prune forgets every source whose bucket would be full by now.
func (s *sourceBuckets) prune(now time.Time) {
	for k, b := range s.m {
		if b.tokens+now.Sub(b.last).Seconds()*s.rate >= s.burst {
			delete(s.m, k)
		}
	}
}

// sourceKey is the bucket a remote address counts against: the IPv4 address
// or the IPv6 /64, or the whole address string when it carries no IP.
func sourceKey(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return remote
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}
