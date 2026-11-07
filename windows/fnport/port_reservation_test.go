package main

import (
	"bytes"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/YUNGSLXRD/fnport/windows/internal/wnet"
)

// Real UDP probes pass on every candidate. Concurrent flows must keep those
// ports through the fake-to-game pause instead of colliding and falling back.
func TestConcurrentGamePortAssignment(t *testing.T) {
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	dst := srv.LocalAddr().(*net.UDPAddr).AddrPort()
	go func() {
		var b [2048]byte
		for {
			n, from, err := srv.ReadFromUDPAddrPort(b[:])
			if err != nil {
				return
			}
			// The fake normally expires before reaching a real game server.
			if n > 1000 && b[0]&0xc0 == 0xc0 {
				continue
			}
			srv.WriteToUDPAddrPort(b[:n], from)
		}
	}()
	cfg := testConfig()
	cfg.gameRanges = [][2]uint16{{dst.Port(), dst.Port()}}
	cfg.pairOffset = 0
	cfg.batch = 16
	dev := newChanDev()
	e := newEngine(cfg, dev, clientIP, nil)
	defer e.close()
	e.prober.preProbe(dst, e.busy)
	tested := map[int]bool{}
	e.prober.mu.Lock()
	for _, c := range e.prober.targets[dst].good {
		tested[c.port] = true
	}
	e.prober.mu.Unlock()
	if len(tested) != cfg.batch {
		t.Fatalf("expected %d probed ports, got %d", cfg.batch, len(tested))
	}

	send := func(port uint16) {
		e.udp(wnet.UDPPacket{Src: netip.AddrPortFrom(clientIP, port), Dst: dst, Payload: []byte("reservation game")})
	}
	receive := func(n int) {
		t.Helper()
		deadline := time.After(4 * time.Second)
		for i := 0; i < n; i++ {
			select {
			case packet := <-dev.out:
				p, err := wnet.ParseUDP4(packet)
				if err != nil || !bytes.Equal(p.Payload, []byte("reservation game")) {
					t.Fatalf("bad reply: %v", err)
				}
			case <-deadline:
				t.Fatal("game reply timeout")
			}
		}
	}
	const flows = 8
	for i := 0; i < flows; i++ {
		send(uint16(50000 + i))
	}
	receive(flows)
	check := func(n int) {
		t.Helper()
		used := map[int]bool{}
		for i := 0; i < n; i++ {
			f := flowOf(e, uint16(50000+i), dst)
			if f == nil {
				t.Fatal("missing flow")
			}
			info := f.info(true)
			if info.NoGood || !tested[info.Port] || used[info.Port] {
				t.Fatalf("lost tested port during concurrent assignment: %+v", info)
			}
			used[info.Port] = true
		}
		if e.stat.snapshot().NoGood != 0 {
			t.Fatal("unexpected untested port")
		}
	}
	check(flows)

	// A remap and a fresh flow share the same candidate pool and must also
	// exclude each other's port while sending the fake before game traffic.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); e.remap(flowOf(e, 50000, dst)) }()
	send(50000 + flows)
	receive(1)
	wg.Wait()
	check(flows + 1)
	if flowOf(e, 50000, dst).info(true).Remaps != 1 {
		t.Fatal("remap did not run")
	}
}
