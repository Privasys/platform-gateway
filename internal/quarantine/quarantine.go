// Package quarantine holds the gateway's answer to a quarantined route.
//
// A quarantined route stays in the table so the gateway can say why the
// application is unavailable instead of pretending it does not exist. The
// upstream enclave is never dialed:
//
//   - terminate mode answers HTTP 503 with Retry-After, as JSON for API
//     clients or a short HTML page for browsers (WriteHTTP);
//   - splice mode cannot speak HTTP (the TLS session belongs to the
//     enclave), so it sends a fatal TLS alert and closes (WriteTLSAlert).
package quarantine

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Transport labels for Refused.
const (
	ModeTerminate = "terminate"
	ModeSplice    = "splice"
)

// RetryAfterSeconds is the Retry-After value sent with every refusal.
const RetryAfterSeconds = 300

// ErrorCode is the machine-readable error of the JSON refusal body.
const ErrorCode = "enclave_quarantined"

// Message is the human-readable reason sent to clients.
const Message = "This application is temporarily unavailable while its enclave's clock is checked."

var refusals = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "gateway_quarantine_refusals_total",
	Help: "Requests and connections refused because their route is quarantined, by host and transport",
}, []string{"host", "mode"})

// Refused records one refusal for host in the given transport mode.
func Refused(host, mode string) {
	refusals.WithLabelValues(strings.ToLower(host), mode).Inc()
}

const jsonBody = `{"error":"` + ErrorCode + `","message":"` + Message + `"}` + "\n"

const htmlBody = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>503 Service Unavailable</title></head>
<body><h1>503 Service Unavailable</h1><p>` + Message + `</p><p>Please try again in a few minutes.</p></body>
</html>`

// WantsHTML reports whether the client asked for HTML ahead of any other
// representation. Browsers navigating to a page send text/html first;
// fetch(), curl and SDKs send */* or application/json and get JSON.
func WantsHTML(accept string) bool {
	for _, part := range strings.Split(accept, ",") {
		mt := strings.TrimSpace(strings.SplitN(part, ";", 2)[0])
		switch strings.ToLower(mt) {
		case "text/html", "application/xhtml+xml":
			return true
		case "", "*/*":
			continue
		default:
			return false
		}
	}
	return false
}

// WriteHTTP writes a complete HTTP/1.1 503 refusal for req to w and asks
// the client to close the connection. extra headers (for example the
// gateway's CORS headers) are added to the response.
func WriteHTTP(w io.Writer, req *http.Request, extra http.Header) error {
	contentType, body := "application/json", jsonBody
	if req != nil && WantsHTML(req.Header.Get("Accept")) {
		contentType, body = "text/html; charset=utf-8", htmlBody
	}

	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 503 Service Unavailable\r\n")
	fmt.Fprintf(&b, "Content-Type: %s\r\n", contentType)
	fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	fmt.Fprintf(&b, "Retry-After: %d\r\n", RetryAfterSeconds)
	fmt.Fprintf(&b, "Cache-Control: no-store\r\n")
	vary := "Accept"
	keys := make([]string, 0, len(extra))
	for k := range extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		vs := extra[k]
		if http.CanonicalHeaderKey(k) == "Vary" {
			vary = strings.Join(vs, ", ") + ", " + vary
			continue
		}
		for _, v := range vs {
			fmt.Fprintf(&b, "%s: %s\r\n", http.CanonicalHeaderKey(k), v)
		}
	}
	fmt.Fprintf(&b, "Vary: %s\r\n", vary)
	fmt.Fprintf(&b, "Connection: close\r\n\r\n")
	if req == nil || req.Method != http.MethodHead {
		b.WriteString(body)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// tlsAlert is a plaintext TLS record carrying a fatal handshake_failure
// alert. It is valid in reply to a ClientHello, before any ServerHello,
// so the client reports a handshake failure instead of a reset.
var tlsAlert = []byte{
	0x15,       // content type: alert
	0x03, 0x03, // legacy record version: TLS 1.2
	0x00, 0x02, // length
	0x02, // level: fatal
	0x28, // description: handshake_failure (40)
}

// WriteTLSAlert writes a fatal handshake_failure alert to w. The caller
// closes the connection afterwards.
func WriteTLSAlert(w io.Writer) error {
	_, err := w.Write(tlsAlert)
	return err
}
