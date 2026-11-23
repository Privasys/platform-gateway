// Package terminate — multiplexed sealed-WebSocket leg ("privasys-mux/1").
//
// Sealed WebSockets terminate at the GATEWAY: it owns the browser-side
// fan-in, the WebSocket protocol state and admission control, and carries
// each sealed message as a framed unit over a small pool of long-lived
// RA-TLS connections to the enclave, demuxed per (session_id, stream_id) —
// so the (memory-bounded) enclave holds a few pooled connections instead of
// one per client. The gateway never holds the session key: every payload it
// relays is the SDK's or the enclave's sealed AES-GCM envelope, and the
// per-stream keystream and AAD are derived from ids the SDK chose and sealed
// into the stream open, so the routing header the gateway writes is
// authenticated end-to-end.
//
// The wire format mirrors the enclave relay (enclave-os-virtual
// internal/sessionrelay/mux.go — the authoritative comment):
//
//	u8 type (1=OPEN 2=DATA 3=CLOSE 4=PING 5=PONG) | u8 sidLen | sid |
//	u64 streamID | u32 len | payload
package terminate

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Privasys/platform-gateway/internal/quarantine"
	"github.com/Privasys/platform-gateway/internal/routetable"
	"github.com/coder/websocket"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	// sealedWSSubprotocol marks a sealed session-relay WebSocket; the SDK
	// advertises [marker, sessionId, streamHex] and the gateway echoes the
	// marker after terminating the socket.
	sealedWSSubprotocol = "privasys.sealed.v1"

	muxPath     = "/__privasys/ws-mux"
	muxProtocol = "privasys-mux/1"

	muxTypeOpen  byte = 1
	muxTypeData  byte = 2
	muxTypeClose byte = 3
	muxTypePing  byte = 4
	muxTypePong  byte = 5

	// muxMaxFrame mirrors the enclave's cap (16 MiB sealed message plus
	// envelope/routing headroom).
	muxMaxFrame = 16*1024*1024 + 64*1024
	// gwMuxPoolSize is the number of mux connections kept per upstream.
	// Every browser WebSocket for that enclave rides one of these.
	gwMuxPoolSize = 2
	// gwMuxStreamQueue and gwMuxStreamQueueBytes bound the per-stream
	// enclave->browser buffer: a browser that stops draining gets its stream
	// closed rather than stalling the shared connection. The bound is in
	// bytes, with a frame count only as a backstop: an agent UI streams
	// hundreds of small frames in a burst (reasoning deltas, a large tool
	// result), and a 32-frame buffer closed healthy streams whenever a busy
	// tab fell a moment behind.
	gwMuxStreamQueue      = 4096
	gwMuxStreamQueueBytes = 8 << 20
	// gwMuxPingEvery / gwMuxReadIdle: the gateway pings each mux conn and
	// expects SOME frame well inside the idle window.
	gwMuxPingEvery = 30 * time.Second
	gwMuxReadIdle  = 2 * time.Minute
	// gwMuxWriteTimeout bounds one frame write toward the enclave.
	gwMuxWriteTimeout = 30 * time.Second
	// gwMuxOpenTimeout bounds the wait for the SDK's sealed stream open
	// (its first binary message after the browser upgrade).
	gwMuxOpenTimeout = 10 * time.Second
	// gwMuxOpenMaxBytes bounds the SDK's sealed stream open, the one browser
	// message read before the enclave has seen the stream. A real open is a
	// few dozen bytes.
	gwMuxOpenMaxBytes = 4 << 10
	// gwBrowserInflightBudget bounds the browser message bytes held by the
	// gateway at once, across every sealed WebSocket: a message is read in
	// gwBrowserReadChunk steps, each reserved from this budget, and released
	// once it has been handed to the enclave. A socket that would cross it is
	// closed, so memory follows bytes received and stays bounded however many
	// sockets are open.
	gwBrowserInflightBudget = 256 << 20
	gwBrowserReadChunk      = 64 << 10
	// gwBrowserSourceBudget is one client's share of that budget (an IPv4
	// address or an IPv6 /64), so a single client cannot take it all.
	gwBrowserSourceBudget = 32 << 20
	// gwMuxAnswerTimeout bounds the wait for the enclave's answer to a stream
	// open. Longer than the enclave's own dial to the app's socket (10 s),
	// so a slow app is not cut off by the gateway first.
	gwMuxAnswerTimeout = 20 * time.Second
	// muxMaxSIDLen mirrors the enclave's bound on a session id; the frame
	// header carries the length in one byte.
	muxMaxSIDLen = 64
)

var (
	muxStreamsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gateway_wsmux_streams_total",
		Help: "Multiplexed sealed WebSocket streams by result",
	}, []string{"result"})
	muxConnsActive = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "gateway_wsmux_conns_active",
		Help: "Live gateway->enclave mux connections",
	})
)

// sealedWSParams holds the parsed browser-side parameters of a sealed
// WebSocket upgrade.
type sealedWSParams struct {
	sessionID string
	streamID  uint64
	streamHex string
}

// parseSealedWS returns the parameters when req is a sealed WebSocket
// upgrade advertising the subprotocol list [marker, sessionId, streamHex],
// or nil otherwise (the request then follows the normal proxy path).
func parseSealedWS(req *http.Request) *sealedWSParams {
	if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		return nil
	}
	var tokens []string
	for _, line := range req.Header.Values("Sec-WebSocket-Protocol") {
		for _, tok := range strings.Split(line, ",") {
			if t := strings.TrimSpace(tok); t != "" {
				tokens = append(tokens, t)
			}
		}
	}
	if len(tokens) < 3 || tokens[0] != sealedWSSubprotocol {
		return nil
	}
	if !validSessionID(tokens[1]) {
		return nil
	}
	hex := strings.ToLower(tokens[2])
	if len(hex) != 16 {
		return nil
	}
	id, err := strconv.ParseUint(hex, 16, 64)
	if err != nil {
		return nil
	}
	return &sealedWSParams{sessionID: tokens[1], streamID: id, streamHex: hex}
}

// validSessionID reports whether sid has the shape of a session id the
// enclave issues: a non-empty base64url string of at most muxMaxSIDLen bytes.
func validSessionID(sid string) bool {
	if sid == "" || len(sid) > muxMaxSIDLen {
		return false
	}
	for i := 0; i < len(sid); i++ {
		c := sid[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// serveSealedWSMux terminates a sealed WebSocket at the gateway and relays
// it as a mux stream. The connection is consumed in all cases.
func (h *Handler) serveSealedWSMux(w *connResponseWriter, req *http.Request, route routetable.Route, p *sealedWSParams) {
	// Acquire the mux leg BEFORE accepting the browser socket so an
	// unreachable enclave refuses the upgrade instead of opening a socket
	// that can never carry a frame.
	mc, err := h.muxPoolFor(route).get()
	if err != nil {
		log.Printf("terminate: wsmux for %q unavailable: %v", route.SNI, err)
		writeStatus(w.conn, http.StatusBadGateway, "enclave mux unavailable")
		muxStreamsTotal.WithLabelValues("mux_unavailable").Inc()
		return
	}

	// The SDK's WebSocket opens from the privasys.id iframe, so its Origin
	// never matches the app host; enforce the gateway's CORS allow-list
	// instead of the library's same-origin default. Sealed transport does
	// not rest on this — no ambient credentials cross this leg — it only
	// keeps arbitrary web pages from holding gateway resources.
	// The app's own pages (same origin as the route) are always allowed.
	if origin := req.Header.Get("Origin"); origin != "" && !h.isAllowedOrigin(origin) && !strings.EqualFold(originHost(origin), route.SNI) {
		writeStatus(w.conn, http.StatusForbidden, "origin not allowed")
		return
	}

	// The enclave picks the app by the stream open's host: always the name
	// the route pins upstream, as the HTTP path does, never the client's Host.
	host := route.UpstreamName()
	uri := req.URL.RequestURI()

	browser, err := websocket.Accept(w, req, &websocket.AcceptOptions{
		Subprotocols:       []string{sealedWSSubprotocol}, // echo only the marker
		InsecureSkipVerify: true,                          // origin enforced above
	})
	if err != nil {
		muxStreamsTotal.WithLabelValues("accept_error").Inc()
		return
	}
	defer browser.CloseNow()

	// First browser message is the SDK's sealed stream open (ctr 0). It is
	// read before the enclave has seen the stream, so the library holds it
	// to a few KiB; the full message size applies only once the enclave
	// answers.
	browser.SetReadLimit(gwMuxOpenMaxBytes)
	reader := newBrowserReader(browser, browserSource(w.conn.RemoteAddr().String()))
	openCtx, cancelOpen := context.WithTimeout(context.Background(), gwMuxOpenTimeout)
	openEnv, held, err := reader.read(openCtx)
	cancelOpen()
	releaseBrowserBytes(reader.source, held)
	if err != nil {
		browser.Close(websocket.StatusProtocolError, "sealed stream open expected")
		muxStreamsTotal.WithLabelValues("no_open").Inc()
		return
	}

	st := &gwStream{
		key:      muxKey{sid: p.sessionID, stream: p.streamID},
		browser:  browser,
		outbound: make(chan []byte, gwMuxStreamQueue),
		done:     make(chan struct{}),
		answered: make(chan struct{}),
	}
	if !mc.register(st) {
		browser.Close(websocket.StatusProtocolError, "duplicate stream id")
		muxStreamsTotal.WithLabelValues("duplicate").Inc()
		return
	}
	defer mc.unregister(st, true)

	// Track the stream so a quarantine cuts it (telling the enclave and
	// the browser), then check again: a quarantine that landed while the
	// socket was being accepted is caught here.
	closeQuarantined := func() {
		_ = mc.writeFrame(muxTypeClose, p.sessionID, p.streamID, encodeMuxClose(websocket.StatusTryAgainLater, ""))
		st.finish(websocket.StatusTryAgainLater, "enclave quarantined")
	}
	release := h.tracker.Track(route.SNI, quarantine.KindSealedWS, closeQuarantined)
	defer release()
	if h.quarantined(route) {
		quarantine.Refused(route.SNI, quarantine.ModeTerminate)
		log.Printf("terminate: refused sealed WebSocket for %q: route quarantined", route.SNI)
		st.finish(websocket.StatusTryAgainLater, "enclave quarantined")
		muxStreamsTotal.WithLabelValues("quarantined").Inc()
		return
	}

	openPayload, err := encodeMuxOpen(host, uri, openEnv)
	if err != nil {
		browser.Close(websocket.StatusPolicyViolation, "request target too long")
		muxStreamsTotal.WithLabelValues("open_too_long").Inc()
		return
	}
	if err := mc.writeFrame(muxTypeOpen, p.sessionID, p.streamID, openPayload); err != nil {
		browser.Close(websocket.StatusBadGateway, "enclave mux unavailable")
		muxStreamsTotal.WithLabelValues("open_write_error").Inc()
		return
	}
	muxStreamsTotal.WithLabelValues("opened").Inc()

	// enclave -> browser pump.
	go func() {
		for {
			var payload []byte
			select {
			case <-st.done:
				return
			case payload = <-st.outbound:
				st.queued.Add(-int64(len(payload)))
				st.markAnswered()
			}
			wctx, cancel := context.WithTimeout(context.Background(), gwMuxWriteTimeout)
			err := browser.Write(wctx, websocket.MessageBinary, payload)
			cancel()
			if err != nil {
				st.finish(websocket.StatusNormalClosure, "")
				return
			}
		}
	}()

	// Nothing more is read from the browser until the enclave has answered
	// the open: a stream the enclave refuses (no such session, a replayed
	// open) never gets to send the gateway full-size messages.
	answerTimer := time.NewTimer(gwMuxAnswerTimeout)
	select {
	case <-st.answered:
		answerTimer.Stop()
		browser.SetReadLimit(muxMaxFrame)
	case <-st.done:
		answerTimer.Stop()
		return
	case <-answerTimer.C:
		_ = mc.writeFrame(muxTypeClose, p.sessionID, p.streamID, encodeMuxClose(websocket.StatusTryAgainLater, ""))
		st.finish(websocket.StatusTryAgainLater, "enclave did not answer the stream open")
		muxStreamsTotal.WithLabelValues("open_unanswered").Inc()
		return
	}

	// browser -> enclave pump (this goroutine owns the inbound TLS conn).
	for {
		data, held, err := reader.read(context.Background())
		if err != nil {
			releaseBrowserBytes(reader.source, held)
			if errors.Is(err, errNotBinary) {
				browser.Close(websocket.StatusUnsupportedData, "binary sealed frames only")
				_ = mc.writeFrame(muxTypeClose, p.sessionID, p.streamID, encodeMuxClose(websocket.StatusUnsupportedData, ""))
				return
			}
			if errors.Is(err, errBrowserBudget) {
				browser.Close(websocket.StatusTryAgainLater, "gateway busy")
				_ = mc.writeFrame(muxTypeClose, p.sessionID, p.streamID, encodeMuxClose(websocket.StatusGoingAway, ""))
				muxStreamsTotal.WithLabelValues("budget").Inc()
				return
			}
			code := websocket.CloseStatus(err)
			if code == -1 {
				code = websocket.StatusGoingAway
			}
			select {
			case <-st.done: // enclave side already closed the stream
			default:
				_ = mc.writeFrame(muxTypeClose, p.sessionID, p.streamID, encodeMuxClose(code, ""))
			}
			return
		}
		err = mc.writeFrame(muxTypeData, p.sessionID, p.streamID, data)
		releaseBrowserBytes(reader.source, held)
		if err != nil {
			browser.Close(websocket.StatusBadGateway, "enclave mux lost")
			return
		}
	}
}

// -----------------------------------------------------------------------------
// pool
// -----------------------------------------------------------------------------

type muxKey struct {
	sid    string
	stream uint64
}

type gwMuxPool struct {
	dialFn   func(ctx context.Context, upstream string) (net.Conn, error)
	upstream string
	sni      string
	tlsCfg   *tls.Config

	mu    sync.Mutex
	conns []*gwMuxConn
}

// muxPoolFor returns the mux pool for a route, keyed like proxyFor so a
// policy change builds a fresh pool with the new verifier.
func (h *Handler) muxPoolFor(route routetable.Route) *gwMuxPool {
	policyHash := hashPolicy(route.AttestationPolicy)
	app := route.Upstream + "|" + route.SNI + "|"
	key := app + policyHash

	h.muxMu.Lock()
	defer h.muxMu.Unlock()
	if p, ok := h.muxPools[key]; ok {
		return p
	}
	// Only this app's pool under its previous policy is stale. A mutualised
	// enclave serves many apps from one upstream: dropping their pools would
	// close every browser socket riding them.
	for k, p := range h.muxPools {
		if strings.HasPrefix(k, app) {
			p.closeAll()
			delete(h.muxPools, k)
		}
	}
	policy, err := parsePolicy(route.AttestationPolicy)
	if err != nil {
		policy = &PolicyDoc{}
	}
	p := &gwMuxPool{
		dialFn:   h.dialUpstream,
		upstream: route.Upstream,
		sni:      route.SNI,
		tlsCfg: &tls.Config{
			InsecureSkipVerify:    true, // RA-TLS verified in VerifyPeerCertificate
			VerifyPeerCertificate: makeRATLSVerifier(h.caCertPool, h.insecureSkip, policy, route.SNI),
			MinVersion:            tls.VersionTLS12,
			ServerName:            route.SNI,
		},
	}
	h.muxPools[key] = p
	return p
}

// get returns a live mux connection, dialing lazily up to the pool size.
func (p *gwMuxPool) get() (*gwMuxConn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	live := p.conns[:0]
	for _, c := range p.conns {
		if !c.isDead() {
			live = append(live, c)
		}
	}
	p.conns = live

	var best *gwMuxConn
	for _, c := range p.conns {
		if best == nil || c.streamCount() < best.streamCount() {
			best = c
		}
	}
	// Dial another pool member while under size and the best is carrying
	// streams (or none exists yet).
	if len(p.conns) < gwMuxPoolSize && (best == nil || best.streamCount() > 0) {
		c, err := p.dial()
		if err != nil {
			if best != nil {
				return best, nil // degrade to the existing member
			}
			return nil, err
		}
		p.conns = append(p.conns, c)
		return c, nil
	}
	if best == nil {
		return nil, errors.New("wsmux: no connection")
	}
	return best, nil
}

// dial opens one mux connection: RA-TLS to the enclave, then the
// privasys-mux/1 upgrade.
func (p *gwMuxPool) dial() (*gwMuxConn, error) {
	raw, err := p.dialFn(context.Background(), p.upstream)
	if err != nil {
		return nil, fmt.Errorf("wsmux dial: %w", err)
	}
	tlsConn := tls.Client(raw, p.tlsCfg)
	tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		raw.Close()
		return nil, fmt.Errorf("wsmux handshake: %w", err)
	}
	fmt.Fprintf(tlsConn, "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: %s\r\nConnection: Upgrade\r\n\r\n", muxPath, p.sni, muxProtocol)
	br := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("wsmux upgrade read: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		resp.Body.Close()
		tlsConn.Close()
		return nil, fmt.Errorf("wsmux upgrade: status %d", resp.StatusCode)
	}
	tlsConn.SetDeadline(time.Time{})

	c := &gwMuxConn{
		conn:    tlsConn,
		br:      br,
		bw:      bufio.NewWriter(tlsConn),
		streams: make(map[muxKey]*gwStream),
		dead:    make(chan struct{}),
	}
	muxConnsActive.Inc()
	go c.readLoop()
	go c.keepalive()
	return c, nil
}

func (p *gwMuxPool) closeAll() {
	p.mu.Lock()
	conns := p.conns
	p.conns = nil
	p.mu.Unlock()
	for _, c := range conns {
		c.kill()
	}
}

// -----------------------------------------------------------------------------
// mux connection
// -----------------------------------------------------------------------------

type gwMuxConn struct {
	conn net.Conn
	br   *bufio.Reader

	wmu sync.Mutex
	bw  *bufio.Writer

	smu     sync.Mutex
	streams map[muxKey]*gwStream

	dead     chan struct{}
	deadOnce sync.Once
}

type gwStream struct {
	key      muxKey
	browser  *websocket.Conn
	outbound chan []byte
	// queued is the bytes waiting in outbound (gwMuxStreamQueueBytes).
	queued atomic.Int64
	done   chan struct{}
	once   sync.Once
	// answered closes when the enclave sends the stream its first frame (the
	// sealed ack of the open): until then the gateway reads nothing more
	// from the browser.
	answered     chan struct{}
	answeredOnce sync.Once
}

// markAnswered records that the enclave has answered the stream's open.
func (st *gwStream) markAnswered() {
	st.answeredOnce.Do(func() { close(st.answered) })
}

// A browser message must finish within gwBrowserMessageGrace of its first
// frame plus one second per gwBrowserMinRate bytes received (a 16 MiB message
// gets 74 s at the floor rate of 256 KiB/s, about 2 Mbit/s, a slow mobile
// uplink). A slow or half-sent message would otherwise keep its bytes
// reserved; holding the budget now takes real upload bandwidth. Variables
// for tests.
var (
	gwBrowserMessageGrace       = 10 * time.Second
	gwBrowserMinRate      int64 = 256 << 10
)

// browserInflight is the bytes of browser messages read and not yet handed
// to the enclave, across every sealed WebSocket (gwBrowserInflightBudget).
var browserInflight atomic.Int64

// sourceInflight is the same, per client source (an IPv4 address or an IPv6
// /64), so one client cannot take the whole budget from everyone else
// (gwBrowserSourceBudget). An entry lives only while it holds bytes.
var sourceInflight = struct {
	mu sync.Mutex
	m  map[string]int64
}{m: map[string]int64{}}

// errBrowserBudget is returned when a browser message would take the gateway,
// or its client, past their budget.
var errBrowserBudget = errors.New("wsmux: browser message budget spent")

// reserveBrowserBytes takes n bytes from the gateway-wide budget and the
// source's share, or neither.
func reserveBrowserBytes(source string, n int64) bool {
	sourceInflight.mu.Lock()
	defer sourceInflight.mu.Unlock()
	if sourceInflight.m[source]+n > gwBrowserSourceBudget {
		return false
	}
	if browserInflight.Add(n) > gwBrowserInflightBudget {
		browserInflight.Add(-n)
		return false
	}
	sourceInflight.m[source] += n
	return true
}

// releaseBrowserBytes gives back n bytes reserved for source.
func releaseBrowserBytes(source string, n int64) {
	if n == 0 {
		return
	}
	sourceInflight.mu.Lock()
	defer sourceInflight.mu.Unlock()
	browserInflight.Add(-n)
	if left := sourceInflight.m[source] - n; left > 0 {
		sourceInflight.m[source] = left
	} else {
		delete(sourceInflight.m, source)
	}
}

// browserSource is the budget share a client counts against: its IPv4
// address, or its IPv6 /48 (one site, which a single client can split into
// many /64s), or the whole address when it carries no IP.
func browserSource(remote string) string {
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
	return ip.Mask(net.CIDRMask(48, 128)).String() + "/48"
}

// browserReader reads one sealed WebSocket's browser messages against the
// budgets. One per socket; its read buffer is reused for every message.
type browserReader struct {
	conn   *websocket.Conn
	source string
	chunk  []byte
}

func newBrowserReader(c *websocket.Conn, source string) *browserReader {
	return &browserReader{conn: c, source: source, chunk: make([]byte, gwBrowserReadChunk)}
}

// read returns one binary message. Its bytes are reserved exactly as they
// arrive and kept as separate parts, joined once at the end, so a large
// message costs one copy, not one per step. The caller releases the
// returned reservation once the message has been handed on, whatever the
// error. A message must keep arriving at gwBrowserMinRate after a grace of
// gwBrowserMessageGrace from its first frame, or the socket is closed: a
// slow or half-sent message cannot keep its reservation.
func (b *browserReader) read(ctx context.Context) (data []byte, reserved int64, err error) {
	typ, r, err := b.conn.Reader(ctx)
	if err != nil {
		return nil, 0, err
	}
	if typ != websocket.MessageBinary {
		return nil, 0, errNotBinary
	}
	start := time.Now()
	stall := time.AfterFunc(gwBrowserMessageGrace, func() { b.conn.CloseNow() })
	defer stall.Stop()
	var parts [][]byte
	for {
		m, rerr := r.Read(b.chunk)
		if m > 0 {
			if !reserveBrowserBytes(b.source, int64(m)) {
				return nil, reserved, errBrowserBudget
			}
			reserved += int64(m)
			parts = append(parts, append([]byte(nil), b.chunk[:m]...))
			// The deadline moves with the bytes received: grace plus one
			// second per gwBrowserMinRate bytes, measured from the start.
			allowed := gwBrowserMessageGrace + time.Duration(reserved*int64(time.Second)/gwBrowserMinRate)
			stall.Reset(time.Until(start.Add(allowed)))
		}
		if rerr == io.EOF {
			if len(parts) == 1 {
				return parts[0], reserved, nil
			}
			data = make([]byte, 0, reserved)
			for _, p := range parts {
				data = append(data, p...)
			}
			return data, reserved, nil
		}
		if rerr != nil {
			return nil, reserved, rerr
		}
	}
}

// errNotBinary is returned for a text message, refused before its body is
// read.
var errNotBinary = errors.New("wsmux: binary sealed frames only")

// finish closes the browser side exactly once and marks the stream done.
func (st *gwStream) finish(code websocket.StatusCode, reason string) {
	st.once.Do(func() {
		close(st.done)
		if err := st.browser.Close(code, reason); err != nil {
			st.browser.CloseNow()
		}
	})
}

func (c *gwMuxConn) register(st *gwStream) bool {
	c.smu.Lock()
	defer c.smu.Unlock()
	if _, dup := c.streams[st.key]; dup {
		return false
	}
	c.streams[st.key] = st
	return true
}

func (c *gwMuxConn) unregister(st *gwStream, finish bool) {
	c.smu.Lock()
	if c.streams[st.key] == st {
		delete(c.streams, st.key)
	}
	c.smu.Unlock()
	if finish {
		st.finish(websocket.StatusNormalClosure, "")
	}
}

func (c *gwMuxConn) streamCount() int {
	c.smu.Lock()
	defer c.smu.Unlock()
	return len(c.streams)
}

func (c *gwMuxConn) isDead() bool {
	select {
	case <-c.dead:
		return true
	default:
		return false
	}
}

// kill tears the connection down and closes every browser socket riding it.
func (c *gwMuxConn) kill() {
	c.deadOnce.Do(func() {
		close(c.dead)
		c.conn.Close()
		muxConnsActive.Dec()
		c.smu.Lock()
		streams := make([]*gwStream, 0, len(c.streams))
		for _, st := range c.streams {
			streams = append(streams, st)
		}
		c.streams = make(map[muxKey]*gwStream)
		c.smu.Unlock()
		for _, st := range streams {
			st.finish(websocket.StatusGoingAway, "enclave mux connection lost")
		}
	})
}

// readLoop demuxes enclave frames to streams. It never blocks on one slow
// browser: the per-stream buffer overflowing closes that stream only.
func (c *gwMuxConn) readLoop() {
	defer c.kill()
	for {
		_ = c.conn.SetReadDeadline(time.Now().Add(gwMuxReadIdle))
		typ, sid, stream, payload, err := readMuxFrame(c.br)
		if err != nil {
			return
		}
		switch typ {
		case muxTypePong:
			// Liveness only.
		case muxTypePing:
			_ = c.writeFrame(muxTypePong, "", 0, payload)
		case muxTypeData:
			key := muxKey{sid: sid, stream: stream}
			c.smu.Lock()
			st := c.streams[key]
			c.smu.Unlock()
			if st == nil {
				_ = c.writeFrame(muxTypeClose, sid, stream, encodeMuxClose(websocket.StatusProtocolError, "unknown stream"))
				continue
			}
			overflow := st.queued.Load()+int64(len(payload)) > gwMuxStreamQueueBytes
			if !overflow {
				select {
				case st.outbound <- payload:
					st.queued.Add(int64(len(payload)))
				default:
					overflow = true
				}
			}
			if overflow {
				log.Printf("wsmux: closing stream %s/%d: the browser fell %d bytes (%d frames) behind", shortSID(sid), stream, st.queued.Load(), len(st.outbound))
				_ = c.writeFrame(muxTypeClose, sid, stream, encodeMuxClose(websocket.StatusPolicyViolation, "browser backpressure overflow"))
				c.unregister(st, false)
				st.finish(websocket.StatusPolicyViolation, "backpressure overflow")
			}
		case muxTypeClose:
			key := muxKey{sid: sid, stream: stream}
			c.smu.Lock()
			st := c.streams[key]
			c.smu.Unlock()
			if st != nil {
				code, reason := parseMuxClose(payload)
				c.unregister(st, false)
				st.finish(code, reason)
			}
		default:
			return // protocol violation: drop the connection
		}
	}
}

// keepalive pings so half-dead connections are detected inside the enclave's
// and our own idle windows.
func (c *gwMuxConn) keepalive() {
	t := time.NewTicker(gwMuxPingEvery)
	defer t.Stop()
	for {
		select {
		case <-c.dead:
			return
		case <-t.C:
			if err := c.writeFrame(muxTypePing, "", 0, nil); err != nil {
				c.kill()
				return
			}
		}
	}
}

func (c *gwMuxConn) writeFrame(typ byte, sid string, stream uint64, payload []byte) error {
	if c.isDead() {
		return errors.New("wsmux: connection dead")
	}
	if len(sid) > 0xFF {
		return errors.New("wsmux: session id too long")
	}
	var hdr [14]byte
	hdr[0] = typ
	hdr[1] = byte(len(sid))
	binary.BigEndian.PutUint64(hdr[2:10], stream)
	binary.BigEndian.PutUint32(hdr[10:14], uint32(len(payload)))
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(gwMuxWriteTimeout))
	if _, err := c.bw.Write(hdr[:2]); err != nil {
		return err
	}
	if _, err := c.bw.WriteString(sid); err != nil {
		return err
	}
	if _, err := c.bw.Write(hdr[2:14]); err != nil {
		return err
	}
	if _, err := c.bw.Write(payload); err != nil {
		return err
	}
	return c.bw.Flush()
}

// -----------------------------------------------------------------------------
// frame codec (mirrors the enclave's mux.go)
// -----------------------------------------------------------------------------

func encodeMuxOpen(host, path string, openEnv []byte) ([]byte, error) {
	if len(host) > 0xFFFF || len(path) > 0xFFFF {
		return nil, errors.New("wsmux: host or path too long")
	}
	out := make([]byte, 2+len(host)+2+len(path)+len(openEnv))
	binary.BigEndian.PutUint16(out[:2], uint16(len(host)))
	copy(out[2:], host)
	off := 2 + len(host)
	binary.BigEndian.PutUint16(out[off:off+2], uint16(len(path)))
	copy(out[off+2:], path)
	copy(out[off+2+len(path):], openEnv)
	return out, nil
}

func encodeMuxClose(code websocket.StatusCode, reason string) []byte {
	out := make([]byte, 2+len(reason))
	binary.BigEndian.PutUint16(out[:2], uint16(code))
	copy(out[2:], reason)
	return out
}

func parseMuxClose(payload []byte) (websocket.StatusCode, string) {
	if len(payload) < 2 {
		return websocket.StatusNormalClosure, ""
	}
	code := websocket.StatusCode(binary.BigEndian.Uint16(payload[:2]))
	if code == 0 {
		code = websocket.StatusNormalClosure
	}
	return code, string(payload[2:])
}

func readMuxFrame(br *bufio.Reader) (typ byte, sid string, stream uint64, payload []byte, err error) {
	var pre [2]byte
	if _, err = io.ReadFull(br, pre[:]); err != nil {
		return 0, "", 0, nil, err
	}
	typ = pre[0]
	sidLen := int(pre[1])
	buf := make([]byte, sidLen+12)
	if _, err = io.ReadFull(br, buf); err != nil {
		return 0, "", 0, nil, err
	}
	sid = string(buf[:sidLen])
	stream = binary.BigEndian.Uint64(buf[sidLen : sidLen+8])
	plen := binary.BigEndian.Uint32(buf[sidLen+8 : sidLen+12])
	if plen > muxMaxFrame {
		return 0, "", 0, nil, errors.New("wsmux: frame too large")
	}
	payload = make([]byte, plen)
	if _, err = io.ReadFull(br, payload); err != nil {
		return 0, "", 0, nil, err
	}
	return typ, sid, stream, payload, nil
}

// shortSID is a session id as the log may carry it: enough to correlate,
// never enough to present.
func shortSID(sid string) string {
	if len(sid) > 8 {
		return sid[:8] + "…"
	}
	return sid
}
