package proxy

import (
	"bytes"
	"net"
	"testing"
)

func TestProxyV2Header(t *testing.T) {
	hdr, err := proxyV2Header(
		&net.TCPAddr{IP: net.ParseIP("198.51.100.7"), Port: 40001},
		&net.TCPAddr{IP: net.ParseIP("34.155.7.30"), Port: 443},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := append(append([]byte(nil), proxyV2Signature...),
		0x21, 0x11, 0x00, 0x0C,
		198, 51, 100, 7, 34, 155, 7, 30,
		0x9C, 0x41, 0x01, 0xBB)
	if !bytes.Equal(hdr, want) {
		t.Fatalf("header = % x\nwant   % x", hdr, want)
	}

	v6, err := proxyV2Header(
		&net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1},
		&net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 443},
	)
	if err != nil || v6[13] != 0x21 || len(v6) != 16+36 {
		t.Fatalf("IPv6 header: % x, %v", v6, err)
	}

	if _, err := proxyV2Header(&net.UnixAddr{}, &net.UnixAddr{}); err == nil {
		t.Fatal("a non-TCP address must give no header")
	}
}
