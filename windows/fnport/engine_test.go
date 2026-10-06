package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/YUNGSLXRD/fnport/windows/internal/fakes"
	"github.com/YUNGSLXRD/fnport/windows/internal/wnet"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

var clientIP = netip.MustParseAddr("10.254.77.2")

// chanDev: the adapter as two queues
type chanDev struct {
	in, out chan []byte
	once    sync.Once
	done    chan struct{}
}

func newChanDev() *chanDev {
	return &chanDev{in: make(chan []byte, 1024), out: make(chan []byte, 4096), done: make(chan struct{})}
}

func (d *chanDev) ReadPacket(buf []byte) (int, error) {
	select {
	case p := <-d.in:
		return copy(buf, p), nil
	case <-d.done:
		return 0, net.ErrClosed
	}
}

func (d *chanDev) WritePacket(p []byte) error {
	select {
	case d.out <- append([]byte(nil), p...):
	case <-d.done:
		return net.ErrClosed
	}
	return nil
}

func (d *chanDev) Close() error { d.once.Do(func() { close(d.done) }); return nil }

// gameServer imitates a Fortnite server behind the TSPU on 127.0.0.1: echoes everything; a flow
// (source port) gets 25 replies, unless its first packet was the fake and the DPI node for the
// port lets the fake work (even ports); `cut` freezes a port at once
type gameServer struct {
	conn *net.UDPConn
	addr netip.AddrPort
	mu   sync.Mutex
	seen map[int]int // replies per source port; -1 = whitelisted
	cut  map[int]bool
}

func startGameServer(t *testing.T, port int) *gameServer {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Skipf("no UDP %d on localhost: %v", port, err)
	}
	s := &gameServer{conn: c, addr: netip.MustParseAddrPort(c.LocalAddr().String()), seen: map[int]int{}, cut: map[int]bool{}}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			s.mu.Lock()
			v, ok := s.seen[from.Port]
			if n > 1000 && buf[0]&0xc0 == 0xc0 {
				// the fake: a real server never gets it (its TTL ends past the DPI)
				if !ok && from.Port%2 == 0 {
					s.seen[from.Port] = -1
				}
				s.mu.Unlock()
				continue
			}
			if s.cut[from.Port] || (v >= 0 && v >= 25) {
				s.mu.Unlock()
				continue
			}
			if v >= 0 {
				s.seen[from.Port] = v + 1
			}
			s.mu.Unlock()
			c.WriteToUDP(buf[:n], from)
		}
	}()
	t.Cleanup(func() { c.Close() })
	return s
}

func testConfig() *config {
	return &config{
		gameRanges: [][2]uint16{{9000, 9999}, {15000, 15999}},
		pairFrom:   [2]uint16{15000, 15999},
		pairOffset: -6000,
		qosPort:    22222,
		batch:      2,
		maxRounds:  8,
		budget:     60,
		verdictTTL: 90 * time.Second,
		fakes:      fakes.Load(),
		fakeTTL:    5,
		routes:     []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
	}
}

// game sends n numbered datagrams from the game's port and counts what comes back to it
func game(t *testing.T, dev *chanDev, cport uint16, server netip.AddrPort, from, n int, gap time.Duration) int {
	for i := from; i < from+n; i++ {
		dev.in <- wnet.BuildUDP4(netip.AddrPortFrom(clientIP, cport), server, binary.BigEndian.AppendUint32([]byte("game"), uint32(i)), 1)
		time.Sleep(gap)
	}
	// replies come once the port is probed (rounds of ~1.3 s); stop after a quiet second
	got := 0
	deadline := time.After(12 * time.Second)
	for {
		if got > 0 {
			deadline = time.After(time.Second)
		}
		select {
		case p := <-dev.out:
			u, err := wnet.ParseUDP4(p)
			if err != nil || u.Src != server || u.Dst != netip.AddrPortFrom(clientIP, cport) || !bytes.HasPrefix(u.Payload, []byte("game")) {
				t.Fatalf("bad reply %+v %v", u, err)
			}
			got++
		case <-deadline:
			return got
		}
	}
}

func flowOf(e *engine, cport uint16, dst netip.AddrPort) *uflow {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.flows[flowKey{cport, dst}]
}

func TestGameFlowGetsGoodPort(t *testing.T) {
	srv := startGameServer(t, 15123)
	dev := newChanDev()
	e := newEngine(testConfig(), dev, clientIP, nil)
	defer e.close()
	go e.run()

	if got := game(t, dev, 50000, srv.addr, 0, 100, 2*time.Millisecond); got != 100 {
		t.Fatalf("replies %d of 100", got)
	}
	f := flowOf(e, 50000, srv.addr)
	f.mu.Lock()
	port := f.port
	f.mu.Unlock()
	if port%2 != 0 || port < portMin {
		t.Fatalf("flow on port %d", port)
	}
	e.stat.mu.Lock()
	tested, good := e.stat.tested, e.stat.good
	e.stat.mu.Unlock()
	if tested == 0 || good == 0 {
		t.Fatalf("no probes: %s", e.summary())
	}
	// the match port 9123 was probed ahead
	e.prober.mu.Lock()
	mt := e.prober.targets[netip.AddrPortFrom(srv.addr.Addr(), 9123)]
	e.prober.mu.Unlock()
	if mt == nil {
		t.Fatal("match port not probed ahead")
	}
}

func TestFrozenFlowRemapped(t *testing.T) {
	srv := startGameServer(t, 15124)
	dev := newChanDev()
	e := newEngine(testConfig(), dev, clientIP, nil)
	defer e.close()
	go e.run()

	// the DPI changes its mind about the port (verdicts drift): the flow stops at 20 replies
	if got := game(t, dev, 50001, srv.addr, 0, 20, 2*time.Millisecond); got != 20 {
		t.Fatalf("replies %d of 20", got)
	}
	f := flowOf(e, 50001, srv.addr)
	f.mu.Lock()
	first := f.port
	f.mu.Unlock()
	srv.mu.Lock()
	srv.cut[first] = true
	srv.mu.Unlock()
	game(t, dev, 50001, srv.addr, 20, 70, 2*time.Millisecond)
	time.Sleep(4 * time.Second) // the watcher looks every 2 s
	f.mu.Lock()
	now, remaps := f.port, f.remaps
	f.mu.Unlock()
	if remaps != 1 || now == first {
		t.Fatalf("remaps %d, port %d -> %d", remaps, first, now)
	}
	if got := game(t, dev, 50001, srv.addr, 100, 40, 2*time.Millisecond); got < 25 {
		t.Fatalf("after remap %d replies of 40", got)
	}
}

func TestOtherUDPPassesAsIs(t *testing.T) {
	srv := startGameServer(t, 22333) // not a game port: no probes, no fake
	srv.mu.Lock()
	srv.seen = map[int]int{}
	srv.mu.Unlock()
	dev := newChanDev()
	e := newEngine(testConfig(), dev, clientIP, nil)
	defer e.close()
	go e.run()
	if got := game(t, dev, 50002, srv.addr, 0, 20, time.Millisecond); got != 20 {
		t.Fatalf("replies %d of 20", got)
	}
	e.stat.mu.Lock()
	tested, games := e.stat.tested, e.stat.gameFlows
	e.stat.mu.Unlock()
	if tested != 0 || games != 0 {
		t.Fatalf("probed a non-game flow: %s", e.summary())
	}
}

// TCP: a second gVisor stack plays Windows on the other side of the adapter
func TestTCPThroughStack(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()

	dev := newChanDev()
	allowLoopback = true // the test server listens on 127.0.0.1
	defer func() { allowLoopback = false }()
	tr, err := newTCPRelay(dev)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.close()
	e := newEngine(testConfig(), dev, clientIP, tr)
	defer e.close()
	go e.run()

	win := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocolWithOptions(ipv4.Options{AllowExternalLoopbackTraffic: true})},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	wep := channel.New(1024, mtu, "")
	win.CreateNIC(1, wep)
	win.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4(clientIP.As4()).WithPrefix()}, stack.AddressProperties{})
	win.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { // Windows -> adapter
		for {
			pkt := wep.ReadContext(ctx)
			if pkt == nil {
				return
			}
			v := pkt.ToView()
			pkt.DecRef()
			dev.in <- append([]byte(nil), v.AsSlice()...)
			v.Release()
		}
	}()
	go func() { // adapter -> Windows
		for {
			select {
			case p := <-dev.out:
				pk := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(p)})
				wep.InjectInbound(ipv4.ProtocolNumber, pk)
				pk.DecRef()
			case <-ctx.Done():
				return
			}
		}
	}()

	dst := netip.MustParseAddrPort(ln.Addr().String())
	c, err := gonet.DialContextTCP(ctx, win, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(dst.Addr().As4()), Port: dst.Port()}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	msg := bytes.Repeat([]byte("fnport "), 20000) // 140 KB: several windows
	go c.Write(msg)
	got := make([]byte, len(msg))
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("echo through the stack: %v", err)
	}
	c.Close()
	if tr.total.Load() != 1 {
		t.Fatalf("relayed connections %d", tr.total.Load())
	}

	// a refused connection is refused to the game too
	ln2, _ := net.Listen("tcp4", "127.0.0.1:0")
	closed := netip.MustParseAddrPort(ln2.Addr().String())
	ln2.Close()
	if _, err := gonet.DialContextTCP(ctx, win, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(closed.Addr().As4()), Port: closed.Port()}, ipv4.ProtocolNumber); err == nil {
		t.Fatal("connection to a closed port succeeded")
	}
}

func TestPassthroughDoesNotProbe(t *testing.T) {
	srv := startGameServer(t, 15125)
	dev := newChanDev()
	cfg := testConfig()
	cfg.passthrough = true
	e := newEngine(cfg, dev, clientIP, nil)
	defer e.close()
	go e.run()
	// no fake, no good port: the imitated DPI freezes the flow at 25, as it would without fnport
	if got := game(t, dev, 50003, srv.addr, 0, 40, time.Millisecond); got != 25 {
		t.Fatalf("replies %d", got)
	}
	e.stat.mu.Lock()
	tested := e.stat.tested
	e.stat.mu.Unlock()
	if tested != 0 {
		t.Fatalf("probed in passthrough: %s", e.summary())
	}
}
