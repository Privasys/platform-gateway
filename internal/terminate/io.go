package terminate

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// prefixConn wraps a net.Conn replaying buffered bytes from buf before
// reading from Conn. The terminate package needs its own copy because
// proxy.PrefixConn lives in a sibling package and we want to keep the
// type-assertion path clean for the TLS server.
type prefixConn struct {
	net.Conn
	buf []byte
}

func newPrefixConn(c net.Conn, buf []byte) *prefixConn {
	cp := make([]byte, len(buf))
	copy(cp, buf)
	return &prefixConn{Conn: c, buf: cp}
}

func (c *prefixConn) Read(b []byte) (int, error) {
	if len(c.buf) > 0 {
		n := copy(b, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

// connResponseWriter implements http.ResponseWriter by writing directly to
// the underlying TLS connection in HTTP/1.1 format. We use it instead of
// the stdlib http.Server because we already own the TLS conn (we
// terminated the handshake by hand so we could splice the ClientHello).
type connResponseWriter struct {
	conn           net.Conn
	br             *bufio.Reader
	bw             *bufio.Writer
	header         http.Header
	status         int
	wroteHeader    bool
	closeRequested bool
	chunked        bool
	bodyBuf        []byte
	bodyBuffered   bool
	hijacked       bool
}

func newConnResponseWriter(c net.Conn, br *bufio.Reader) *connResponseWriter {
	return &connResponseWriter{
		conn:   c,
		br:     br,
		bw:     bufio.NewWriter(c),
		header: make(http.Header),
		status: 200,
	}
}

// Hijack lets httputil.ReverseProxy take over the connection to proxy a
// WebSocket upgrade (a sealed session-relay WebSocket) through to the enclave.
// It returns the raw TLS conn plus a ReadWriter over the SAME request reader
// (so any bytes already buffered past the request headers are preserved) and
// the response writer. After this the serveHTTP loop must stop touching the
// conn — the proxy owns it. Clears the request deadline the loop set.
func (w *connResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.hijacked = true
	// Flush anything already written through this writer (the WebSocket
	// accept path writes its 101 via WriteHeader immediately before
	// hijacking and relies on the server to put it on the wire).
	if err := w.bw.Flush(); err != nil {
		return nil, nil, err
	}
	w.conn.SetReadDeadline(time.Time{})
	w.conn.SetWriteDeadline(time.Time{})
	return w.conn, bufio.NewReadWriter(w.br, w.bw), nil
}

func (w *connResponseWriter) Header() http.Header { return w.header }

func (w *connResponseWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.status = code

	// Decide on transfer encoding. If Content-Length is set, use it.
	// Otherwise fall back to chunked so we can stream SSE/long bodies.
	// 1xx responses (the 101 Switching Protocols written by the WebSocket
	// accept before hijacking) carry no body and must not be framed.
	if code >= 200 && w.header.Get("Content-Length") == "" && w.header.Get("Transfer-Encoding") == "" {
		w.chunked = true
		w.header.Set("Transfer-Encoding", "chunked")
	}
	if strings.EqualFold(w.header.Get("Connection"), "close") {
		w.closeRequested = true
	}

	w.conn.SetWriteDeadline(time.Now().Add(60 * time.Second))
	fmt.Fprintf(w.bw, "HTTP/1.1 %d %s\r\n", code, http.StatusText(code))
	for k, vs := range w.header {
		for _, v := range vs {
			fmt.Fprintf(w.bw, "%s: %s\r\n", k, v)
		}
	}
	w.bw.WriteString("\r\n")
}

func (w *connResponseWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(200)
	}
	if w.chunked {
		// Emit a single chunk per Write call.
		fmt.Fprintf(w.bw, "%s\r\n", strconv.FormatInt(int64(len(p)), 16))
		n, err := w.bw.Write(p)
		w.bw.WriteString("\r\n")
		// Streaming responses (SSE) need Flush after each chunk.
		_ = w.bw.Flush()
		return n, err
	}
	return w.bw.Write(p)
}

// Flush implements http.Flusher so streaming handlers (SSE) work.
func (w *connResponseWriter) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(200)
	}
	_ = w.bw.Flush()
}

// flushClose finalises the response (closes chunked stream) and flushes.
func (w *connResponseWriter) flushClose(req *http.Request) {
	if !w.wroteHeader {
		w.WriteHeader(200)
	}
	if w.chunked {
		w.bw.WriteString("0\r\n\r\n")
	}
	_ = w.bw.Flush()
	w.conn.SetWriteDeadline(time.Time{})
}
