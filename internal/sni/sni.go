// Package sni extracts the SNI hostname from a TLS ClientHello without
// terminating the TLS connection. The buffered bytes are preserved so
// they can be replayed to the upstream backend.
package sni

import (
	"errors"
	"fmt"
)

var (
	ErrNotTLS         = errors.New("not a TLS record")
	ErrNotClientHello = errors.New("not a ClientHello")
	ErrNoSNI          = errors.New("no SNI extension found")
	ErrTruncated      = errors.New("truncated TLS record")
)

// Parse extracts the SNI hostname from a raw TLS ClientHello message.
// The input must contain at least the complete ClientHello record.
// Returns the SNI hostname or an error.
func Parse(buf []byte) (string, error) {
	host, _, err := ParseClientHello(buf)
	return host, err
}

// ParseClientHello extracts the SNI hostname AND the ALPN protocol list
// from a raw TLS ClientHello. ALPN is returned as a possibly-empty slice;
// missing-ALPN-extension is not an error. The hostname behaves the same as
// in Parse — missing SNI returns ErrNoSNI.
func ParseClientHello(buf []byte) (hostname string, alpns []string, err error) {
	// TLS record header: type(1) + version(2) + length(2)
	if len(buf) < 5 {
		return "", nil, ErrTruncated
	}
	if buf[0] != 0x16 { // Handshake
		return "", nil, ErrNotTLS
	}
	recordLen := int(buf[3])<<8 | int(buf[4])
	if len(buf) < 5+recordLen {
		return "", nil, ErrTruncated
	}

	data := buf[5 : 5+recordLen]

	// Handshake header: type(1) + length(3)
	if len(data) < 4 {
		return "", nil, ErrTruncated
	}
	if data[0] != 0x01 { // ClientHello
		return "", nil, ErrNotClientHello
	}
	hsLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) < 4+hsLen {
		return "", nil, ErrTruncated
	}
	data = data[4 : 4+hsLen]

	// ClientHello body: version(2) + random(32) + session_id_len(1) + session_id(var)
	//                 + cipher_suites_len(2) + cipher_suites(var)
	//                 + compression_methods_len(1) + compression_methods(var)
	//                 + extensions_len(2) + extensions(var)
	if len(data) < 34 {
		return "", nil, ErrTruncated
	}
	pos := 34

	if pos >= len(data) {
		return "", nil, ErrTruncated
	}
	sidLen := int(data[pos])
	pos++
	pos += sidLen

	if pos+2 > len(data) {
		return "", nil, ErrTruncated
	}
	csLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2 + csLen

	if pos >= len(data) {
		return "", nil, ErrTruncated
	}
	cmLen := int(data[pos])
	pos += 1 + cmLen

	if pos+2 > len(data) {
		return "", nil, ErrNoSNI
	}
	extLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2

	end := pos + extLen
	if end > len(data) {
		return "", nil, ErrTruncated
	}

	for pos+4 <= end {
		extType := int(data[pos])<<8 | int(data[pos+1])
		extDataLen := int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4

		if pos+extDataLen > end {
			return "", nil, ErrTruncated
		}

		switch extType {
		case 0x0000: // server_name
			if h, perr := parseSNIExtension(data[pos : pos+extDataLen]); perr == nil {
				hostname = h
			}
		case 0x0010: // application_layer_protocol_negotiation (RFC 7301)
			alpns = parseALPNExtension(data[pos : pos+extDataLen])
		}
		pos += extDataLen
	}

	if hostname == "" {
		return "", alpns, ErrNoSNI
	}
	return hostname, alpns, nil
}

// parseALPNExtension decodes an ALPN extension body (RFC 7301):
//
//	protocol_name_list_len(2) + [name_len(1) + name(var)]*
//
// Returns nil on any parse error (ALPN is best-effort for routing).
func parseALPNExtension(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	listLen := int(data[0])<<8 | int(data[1])
	if 2+listLen > len(data) {
		return nil
	}
	pos := 2
	end := 2 + listLen
	var out []string
	for pos < end {
		if pos+1 > end {
			return out
		}
		nLen := int(data[pos])
		pos++
		if pos+nLen > end {
			return out
		}
		out = append(out, string(data[pos:pos+nLen]))
		pos += nLen
	}
	return out
}

// HasALPN reports whether proto appears in the parsed ALPN list.
func HasALPN(alpns []string, proto string) bool {
	for _, p := range alpns {
		if p == proto {
			return true
		}
	}
	return false
}

// parseSNIExtension parses the SNI extension data.
// Format: list_len(2) + [type(1) + name_len(2) + name(var)]*
func parseSNIExtension(data []byte) (string, error) {
	if len(data) < 2 {
		return "", ErrTruncated
	}
	listLen := int(data[0])<<8 | int(data[1])
	if len(data) < 2+listLen {
		return "", ErrTruncated
	}

	pos := 2
	listEnd := 2 + listLen

	for pos+3 <= listEnd {
		nameType := data[pos]
		nameLen := int(data[pos+1])<<8 | int(data[pos+2])
		pos += 3

		if pos+nameLen > listEnd {
			return "", ErrTruncated
		}

		if nameType == 0x00 { // host_name
			hostname := string(data[pos : pos+nameLen])
			if hostname == "" {
				return "", fmt.Errorf("empty SNI hostname")
			}
			return hostname, nil
		}

		pos += nameLen
	}

	return "", ErrNoSNI
}
