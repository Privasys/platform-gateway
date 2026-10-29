package proxy

import (
	"encoding/binary"
	"fmt"
	"net"
)

// proxyV2Signature opens every PROXY protocol v2 header.
var proxyV2Signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// proxyV2Header builds a PROXY protocol v2 header (command PROXY, stream)
// carrying the client's address as seen here, so an enclave that terminates
// TLS itself still knows who it is talking to. Sent only on direct splices,
// where the enclave's rate limits would otherwise see every client as this
// gateway.
func proxyV2Header(src, dst net.Addr) ([]byte, error) {
	s, ok1 := src.(*net.TCPAddr)
	d, ok2 := dst.(*net.TCPAddr)
	if !ok1 || !ok2 {
		return nil, fmt.Errorf("proxy protocol: need TCP addresses, got %T and %T", src, dst)
	}
	hdr := append([]byte(nil), proxyV2Signature...)
	hdr = append(hdr, 0x21) // version 2, command PROXY
	s4, d4 := s.IP.To4(), d.IP.To4()
	var body []byte
	switch {
	case s4 != nil && d4 != nil:
		hdr = append(hdr, 0x11) // AF_INET, STREAM
		body = append(append(body, s4...), d4...)
	default:
		hdr = append(hdr, 0x21) // AF_INET6, STREAM
		body = append(append(body, s.IP.To16()...), d.IP.To16()...)
	}
	body = binary.BigEndian.AppendUint16(body, uint16(s.Port))
	body = binary.BigEndian.AppendUint16(body, uint16(d.Port))
	hdr = binary.BigEndian.AppendUint16(hdr, uint16(len(body)))
	return append(hdr, body...), nil
}
