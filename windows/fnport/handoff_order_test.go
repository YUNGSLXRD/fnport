package main

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/YUNGSLXRD/fnport/windows/internal/wnet"
)

// A slow log write after installing the socket must not allow a fresh game
// datagram to overtake the initial queue. Exercise the actual engine and UDP.
func TestInitialGamePacketsKeepOrder(t *testing.T) {
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	dst := srv.LocalAddr().(*net.UDPAddr).AddrPort()
	observed := make(chan byte, 8)
	go func() {
		var b [2048]byte
		for {
			n, from, err := srv.ReadFromUDPAddrPort(b[:])
			if err != nil {
				return
			}
			if n == 7 && bytes.HasPrefix(b[:n], []byte("order:")) {
				observed <- b[6]
			}
			srv.WriteToUDPAddrPort(b[:n], from)
		}
	}()
	cfg := testConfig()
	cfg.fakes = nil
	cfg.pairOffset = 0
	cfg.gameRanges = [][2]uint16{{dst.Port(), dst.Port()}}
	e := newEngine(cfg, newChanDev(), clientIP, nil)
	defer e.close()
	e.prober.preProbe(dst, e.busy)
	packet := func(n byte) []byte { return append([]byte("order:"), n) }
	f := &uflow{key: flowKey{50000, dst, clientIP}, game: true, match: true,
		started: time.Now(), last: time.Now(), pending: [][]byte{packet(0), packet(1)}}
	e.mu.Lock()
	e.flows[f.key] = f
	e.mu.Unlock()
	logs.Lock()
	locked := true
	defer func() {
		if locked {
			logs.Unlock()
		}
	}()
	assigned := make(chan struct{})
	go func() { defer close(assigned); e.assign(f) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		f.mu.Lock()
		ready := f.conn != nil
		f.mu.Unlock()
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("socket was not installed")
		}
		time.Sleep(time.Millisecond)
	}
	e.udp(wnet.UDPPacket{Src: netip.AddrPortFrom(clientIP, 50000), Dst: dst, Payload: packet(2)})
	logs.Unlock()
	locked = false
	select {
	case <-assigned:
	case <-time.After(time.Second):
		t.Fatal("assignment blocked")
	}
	for want := byte(0); want < 3; want++ {
		select {
		case got := <-observed:
			if got != want {
				t.Fatalf("initial datagrams reordered: position %d got %d", want, got)
			}
		case <-time.After(time.Second):
			t.Fatal("missing datagram")
		}
	}
}
