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
	// TLS record header: type(1) + version(2) + length(2)
	if len(buf) < 5 {
		return "", ErrTruncated
	}
	if buf[0] != 0x16 { // Handshake
		return "", ErrNotTLS
	}
	recordLen := int(buf[3])<<8 | int(buf[4])
	if len(buf) < 5+recordLen {
		return "", ErrTruncated
	}

	data := buf[5 : 5+recordLen]

	// Handshake header: type(1) + length(3)
	if len(data) < 4 {
		return "", ErrTruncated
	}
	if data[0] != 0x01 { // ClientHello
		return "", ErrNotClientHello
	}
	hsLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) < 4+hsLen {
		return "", ErrTruncated
	}
	data = data[4 : 4+hsLen]

	// ClientHello body:
	//   version(2) + random(32) + session_id_len(1) + session_id(var)
	//   + cipher_suites_len(2) + cipher_suites(var)
	//   + compression_methods_len(1) + compression_methods(var)
	//   + extensions_len(2) + extensions(var)
	if len(data) < 34 {
		return "", ErrTruncated
	}
	pos := 34 // skip version + random

	// Session ID
	if pos >= len(data) {
		return "", ErrTruncated
	}
	sidLen := int(data[pos])
	pos++
	pos += sidLen

	// Cipher suites
	if pos+2 > len(data) {
		return "", ErrTruncated
	}
	csLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2 + csLen

	// Compression methods
	if pos >= len(data) {
		return "", ErrTruncated
	}
	cmLen := int(data[pos])
	pos += 1 + cmLen

	// Extensions
	if pos+2 > len(data) {
		return "", ErrNoSNI
	}
	extLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2

	end := pos + extLen
	if end > len(data) {
		return "", ErrTruncated
	}

	for pos+4 <= end {
		extType := int(data[pos])<<8 | int(data[pos+1])
		extDataLen := int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4

		if pos+extDataLen > end {
			return "", ErrTruncated
		}

		if extType == 0x0000 { // server_name
			return parseSNIExtension(data[pos : pos+extDataLen])
		}

		pos += extDataLen
	}

	return "", ErrNoSNI
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
