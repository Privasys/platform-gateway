package proxy

import (
	"net"
	"sync"
)

// Default connection caps (see SetConnLimits).
const (
	DefaultMaxConns      = 20000
	DefaultMaxConnsPerIP = 256
)

// connLimiter caps concurrent connections in total and per source address.
// IPv6 sources are counted per /64, the smallest block one client is
// usually given. A zero or negative cap disables that bound.
type connLimiter struct {
	max   int
	perIP int

	mu    sync.Mutex
	total int
	byIP  map[string]int
}

func newConnLimiter(max, perIP int) *connLimiter {
	return &connLimiter{max: max, perIP: perIP, byIP: make(map[string]int)}
}

// acquire admits a connection from addr. On success it returns the release
// to call when the connection ends; otherwise reason names the bound hit.
func (l *connLimiter) acquire(addr net.Addr) (release func(), reason string, ok bool) {
	key := sourceKey(addr)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.max > 0 && l.total >= l.max {
		return nil, "conn_limit", false
	}
	if l.perIP > 0 && key != "" && l.byIP[key] >= l.perIP {
		return nil, "ip_conn_limit", false
	}
	l.total++
	if key != "" {
		l.byIP[key]++
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.total--
			if key != "" {
				if l.byIP[key] <= 1 {
					delete(l.byIP, key)
				} else {
					l.byIP[key]--
				}
			}
		})
	}, "", true
}

// sourceKey is the bucket a connection's source address counts against: the
// IPv4 address, or the IPv6 /64. Empty when addr carries no IP.
func sourceKey(addr net.Addr) string {
	var ip net.IP
	switch a := addr.(type) {
	case *net.TCPAddr:
		ip = a.IP
	default:
		if addr == nil {
			return ""
		}
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return ""
		}
		ip = net.ParseIP(host)
	}
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}
