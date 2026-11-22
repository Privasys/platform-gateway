package proxy

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/platform-gateway/internal/routetable"
)

func tcpAddr(s string) net.Addr {
	a, err := net.ResolveTCPAddr("tcp", s)
	if err != nil {
		panic(err)
	}
	return a
}

func TestConnLimiterPerSource(t *testing.T) {
	l := newConnLimiter(0, 2)
	r1, _, ok1 := l.acquire(tcpAddr("192.0.2.1:1000"))
	_, _, ok2 := l.acquire(tcpAddr("192.0.2.1:1001"))
	if !ok1 || !ok2 {
		t.Fatal("two connections from one source must be admitted")
	}
	if _, reason, ok := l.acquire(tcpAddr("192.0.2.1:1002")); ok || reason != "ip_conn_limit" {
		t.Fatalf("third connection: ok=%v reason=%q", ok, reason)
	}
	if _, _, ok := l.acquire(tcpAddr("192.0.2.2:1000")); !ok {
		t.Fatal("another source must be admitted")
	}
	r1()
	r1() // release is idempotent
	if _, _, ok := l.acquire(tcpAddr("192.0.2.1:1003")); !ok {
		t.Fatal("a released slot must be reusable")
	}
	if _, _, ok := l.acquire(tcpAddr("192.0.2.1:1004")); ok {
		t.Fatal("a double release must not free two slots")
	}

	// IPv6 sources count per /64.
	_, _, a := l.acquire(tcpAddr("[2001:db8:1:2::1]:1"))
	_, _, b := l.acquire(tcpAddr("[2001:db8:1:2:ffff::9]:1"))
	_, _, c := l.acquire(tcpAddr("[2001:db8:1:2::3]:1"))
	_, _, d := l.acquire(tcpAddr("[2001:db8:1:3::1]:1"))
	if !a || !b || c || !d {
		t.Fatalf("IPv6 /64 grouping: %v %v %v %v, want true true false true", a, b, c, d)
	}
}

func TestConnLimiterTotal(t *testing.T) {
	l := newConnLimiter(2, 0)
	r, _, _ := l.acquire(tcpAddr("192.0.2.1:1"))
	l.acquire(tcpAddr("192.0.2.2:1"))
	if _, reason, ok := l.acquire(tcpAddr("192.0.2.3:1")); ok || reason != "conn_limit" {
		t.Fatalf("over the total: ok=%v reason=%q", ok, reason)
	}
	r()
	if _, _, ok := l.acquire(tcpAddr("192.0.2.3:1")); !ok {
		t.Fatal("a released slot must be reusable")
	}
}

func TestRunRefusesOverPerSourceCap(t *testing.T) {
	table := routetable.New()
	g := New(table, "127.0.0.1:0", time.Second, time.Second, 32768, nil)
	g.SetConnLimits(0, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	g.listenAddr = ln.Addr().String()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = g.Run(t.Context())
	}()
	var first net.Conn
	for i := 0; i < 50; i++ {
		if first, err = net.Dial("tcp", g.listenAddr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer first.Close()
	time.Sleep(50 * time.Millisecond) // let the first connection be admitted

	second, err := net.Dial("tcp", g.listenAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	second.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := second.Read(make([]byte, 1)); err != io.EOF && !strings.Contains(fmt.Sprint(err), "reset") {
		t.Fatalf("second connection read = %v, want it closed", err)
	}
}

// TestLargeClientHelloIsReplayedWhole proves the hello buffer grows past its
// initial size and the whole hello reaches the enclave.
func TestLargeClientHelloIsReplayedWhole(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan int, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		var hdr [5]byte
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			got <- -1
			return
		}
		body := make([]byte, binary.BigEndian.Uint16(hdr[3:5]))
		if _, err := io.ReadFull(c, body); err != nil {
			got <- -1
			return
		}
		got <- len(body)
	}()

	table := routetable.New()
	table.Update([]routetable.Route{{SNI: spliceTestHost, Upstream: ln.Addr().String()}}, "v1")
	g := New(table, "", time.Second, time.Second, 32768, nil)

	protos := []string{"privasys-ratls/1"}
	for i := 0; i < 40; i++ {
		protos = append(protos, strings.Repeat(string(rune('a'+i%26)), 200))
	}
	server, client := net.Pipe()
	g.wg.Add(1)
	go g.handleConn(server)
	tc := tls.Client(client, &tls.Config{ServerName: spliceTestHost, NextProtos: protos, InsecureSkipVerify: true})
	defer tc.Close()
	tc.SetDeadline(time.Now().Add(5 * time.Second))
	go tc.Handshake()

	select {
	case n := <-got:
		if n < 2*initialHelloBuffer {
			t.Fatalf("enclave got a %d-byte hello, want the whole large hello", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("hello never reached the enclave")
	}
}

func TestCopySwitchesToFullBuffer(t *testing.T) {
	g := New(routetable.New(), "", time.Second, 5*time.Second, 32768, nil)
	srcA, srcB := net.Pipe()
	dstA, dstB := net.Pipe()
	payload := make([]byte, 200*1024)
	rand.Read(payload)
	go func() {
		srcA.Write(payload)
		srcA.Close()
	}()
	recv := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(dstB)
		recv <- b
	}()
	n := g.copyWithIdleTimeout(dstA, srcB)
	dstA.Close()
	if n != int64(len(payload)) {
		t.Fatalf("copied %d bytes, want %d", n, len(payload))
	}
	if b := <-recv; !bytes.Equal(b, payload) {
		t.Fatal("copied bytes differ")
	}
}
