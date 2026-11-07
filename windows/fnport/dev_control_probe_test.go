//go:build devtrace

package main

import (
	"bytes"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/YUNGSLXRD/fnport/windows/internal/wnet"
)

func TestControlProbeComparisonKeepsFakeAndMatchProbes(t *testing.T) {
	old := devControlProbes
	devControlProbes = "off"
	defer func() { devControlProbes = old }()
	type observedServer struct {
		addr          netip.AddrPort
		probes, fakes atomic.Int64
	}
	server := func() *observedServer {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		s := &observedServer{addr: c.LocalAddr().(*net.UDPAddr).AddrPort()}
		go func() {
			var b [2048]byte
			for {
				n, from, err := c.ReadFromUDPAddrPort(b[:])
				if err != nil {
					return
				}
				if n > 1000 && b[0]&0xc0 == 0xc0 {
					s.fakes.Add(1)
					continue
				}
				if bytes.Equal(b[:n], handshake) {
					s.probes.Add(1)
				}
				c.WriteToUDPAddrPort(b[:n], from)
			}
		}()
		return s
	}
	control, match := server(), server()
	cfg := testConfig()
	cfg.pairFrom = [2]uint16{control.addr.Port(), control.addr.Port()}
	cfg.pairOffset = int(match.addr.Port()) - int(control.addr.Port())
	cfg.gameRanges = [][2]uint16{{control.addr.Port(), control.addr.Port()}, {match.addr.Port(), match.addr.Port()}}
	dev := newChanDev()
	e := newEngine(cfg, dev, clientIP, nil)
	defer e.close()
	for i, dst := range []netip.AddrPort{control.addr, match.addr} {
		e.udp(wnet.UDPPacket{Src: netip.AddrPortFrom(clientIP, uint16(50000+i)), Dst: dst, Payload: []byte("actual game")})
	}
	for i := 0; i < 2; i++ {
		select {
		case b := <-dev.out:
			p, err := wnet.ParseUDP4(b)
			if err != nil || !bytes.Equal(p.Payload, []byte("actual game")) {
				t.Fatal("wrong game reply")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("missing game reply")
		}
	}
	if control.probes.Load() != 0 || control.fakes.Load() == 0 || match.probes.Load() < probePkts || match.fakes.Load() == 0 {
		t.Fatalf("comparison changed wrong factor: control probes=%d fake=%d, match probes=%d fake=%d", control.probes.Load(), control.fakes.Load(), match.probes.Load(), match.fakes.Load())
	}
	if !flowOf(e, 50000, control.addr).info(true).NoGood || flowOf(e, 50001, match.addr).info(true).NoGood {
		t.Fatal("probe provenance is wrong")
	}
}

func TestGamePacketMetadataIsBoundedAndNonblocking(t *testing.T) {
	trace := &networkTrace{done: make(chan struct{}), queue: make(chan networkTraceObservation, 1)}
	e := newEngine(testConfig(), newChanDev(), clientIP, nil)
	defer e.close()
	e.connection = &connectionRouter{trace: trace}
	f := &uflow{key: flowKey{50000, netip.MustParseAddrPort("127.0.0.1:15001"), clientIP}, game: true, started: time.Now()}
	for seq := int64(1); seq <= 100; seq++ {
		e.traceGamePacket(f, "tx", seq, 19, 25000, true, true)
	}
	if len(trace.queue) != 1 || trace.dropped.Load() != 7 {
		t.Fatal("metadata bound/overflow is wrong")
	}
	o := <-trace.queue
	if o.game == nil || o.game.Bytes != 19 || o.game.Sequence != 1 || o.game.LocalPort != 25000 || !o.game.Initial || !o.game.WriteOK {
		t.Fatal("lost packet metadata")
	}
	if o.domain != "" || o.source != "" {
		t.Fatal("packet metadata unexpectedly contains external strings")
	}
}
