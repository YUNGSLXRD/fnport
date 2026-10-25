package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/YUNGSLXRD/fnport/windows/internal/wnet"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// TCP to the routed networks (Epic's HTTPS and whatever else lives on those AWS addresses) is
// not touched: a TCP stack in this program (gVisor, as in WireGuard and tun2socks) accepts the
// connection on the server's behalf and joins it to an ordinary connection of this PC.

type tcpRelay struct {
	stack  *stack.Stack
	ep     *channel.Endpoint
	ctx    context.Context
	cancel context.CancelFunc
	active atomic.Int64
	total  atomic.Int64
	failed atomic.Int64

	// WARP for Epic's services: nil until (unless) the tunnel is up
	warp      atomic.Pointer[warpTunnel]
	epicIPs   atomic.Pointer[map[netip.Addr]bool]
	names     atomic.Pointer[[]string] // the names that go through WARP
	seen      sync.Map                 // names already logged as going through WARP
	blocked   sync.Map                 // name -> when it did not answer directly
	always    atomic.Bool              // every listed name through WARP, not trying directly
	warpStall chan struct{}            // a connection through WARP stood still inside a record
	state     atomic.Value             // string: how WARP is doing, for the window and the report
}

// allowLoopback: tests only; the routes never send 127.0.0.0/8 into the adapter
var allowLoopback bool

func newTCPRelay(dev wnet.Dev) (*tcpRelay, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocolWithOptions(ipv4.Options{AllowExternalLoopbackTraffic: allowLoopback})},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	sack := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)
	ep := channel.New(1024, mtu, "")
	if err := s.CreateNIC(1, ep); err != nil {
		return nil, errorf("TCP: %v", err)
	}
	// take connections to any address, answer from any address
	s.SetPromiscuousMode(1, true)
	s.SetSpoofing(1, true)
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})

	ctx, cancel := context.WithCancel(context.Background())
	t := &tcpRelay{stack: s, ep: ep, ctx: ctx, cancel: cancel, warpStall: make(chan struct{}, 1)}
	fwd := tcp.NewForwarder(s, 0, 512, t.accept)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)

	go func() {
		for {
			pkt := ep.ReadContext(ctx)
			if pkt == nil {
				return
			}
			v := pkt.ToView()
			pkt.DecRef()
			dev.WritePacket(v.AsSlice())
			v.Release()
		}
	}()
	return t, nil
}

// inject: a TCP packet Windows routed into the adapter
func (t *tcpRelay) inject(b []byte) {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), b...))})
	t.ep.InjectInbound(ipv4.ProtocolNumber, pkt)
	pkt.DecRef()
}

// accept runs in its own goroutine: connect out first, so a refused connection is refused
// here too, then complete the handshake with the PC
func (t *tcpRelay) accept(r *tcp.ForwarderRequest) {
	id := r.ID()
	dst := netip.AddrPortFrom(netip.AddrFrom4(id.LocalAddress.As4()), id.LocalPort)
	if w := t.warp.Load(); w != nil && (dst.Port() == 443 || t.epicIP(dst.Addr())) {
		t.acceptSplit(r, dst, w)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	out, err := wnet.DialTCP(ctx, dst)
	cancel()
	if err != nil {
		t.failed.Add(1)
		r.Complete(true)
		return
	}
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		out.Close()
		r.Complete(true)
		return
	}
	r.Complete(false)
	in := gonet.NewTCPConn(&wq, ep)
	t.total.Add(1)
	t.active.Add(1)
	defer t.active.Add(-1)
	splice(in, out)
}

func (t *tcpRelay) warpName(h string) bool {
	n := t.names.Load()
	return n != nil && matchDomain(h, *n)
}

func (t *tcpRelay) epicIP(a netip.Addr) bool {
	m := t.epicIPs.Load()
	return m != nil && (*m)[a]
}

// acceptSplit: with WARP up, the handshake with the PC comes first, then the name it asks for
// decides. A listed name goes out directly first: when the server does not answer the
// ClientHello within seconds (blocked by name or address), the connection is made again through
// WARP, and the name goes through WARP for the next 10 minutes. Directly is the program's
// behaviour without WARP, so what works directly keeps working (WARP's addresses are not liked
// everywhere: Fortnite's content keys failed through it at home)
func (t *tcpRelay) acceptSplit(r *tcp.ForwarderRequest, dst netip.AddrPort, w *warpTunnel) {
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)
	in := gonet.NewTCPConn(&wq, ep)
	var hello []byte
	name := ""
	if dst.Port() == 443 {
		hello = readHello(in)
		name = sniOf(hello)
	}
	shown := name
	if shown == "" {
		shown = dst.String()
	}
	var out net.Conn
	var first []byte // the server's first answer, read while deciding
	sent := false    // the ClientHello went out on out already
	var counted *countConn
	listed, viaWarp := t.warpName(name) || (name == "" && t.epicIP(dst.Addr())), false
	if listed {
		viaWarp = t.always.Load() || t.blockedRecently(shown)
		if !viaWarp {
			if out, first = tryDirect(dst, hello); out != nil {
				sent = len(hello) > 0
				counted = &countConn{Conn: out, tls: len(hello) > 0}
				counted.feed(first) // the server's first bytes came before the count
				out = counted
			} else {
				viaWarp = true
				t.markBlocked(shown, "напрямую не отвечает — через WARP")
			}
		}
		if viaWarp {
			c, err := w.dial(dst)
			if err != nil && t.always.Load() {
				// directly it freezes here: the tunnel is likely frozen itself, so a new one, and
				// the connection waits for it rather than going the way that freezes
				w.fails.Add(1)
				select {
				case t.warpStall <- struct{}{}:
				default:
				}
				for i := 0; i < 15 && err != nil; i++ {
					time.Sleep(time.Second)
					if nw := t.warp.Load(); nw != nil && nw != w {
						w = nw
						c, err = w.dial(dst)
					}
				}
			}
			if err != nil {
				w.fails.Add(1)
				if _, dup := t.seen.LoadOrStore("fail "+shown, true); !dup {
					logf("WARP: %s не открылось через WARP (%v), пошло напрямую", maskAddresses(shown), err)
				}
			} else {
				counted = &countConn{Conn: c, tls: len(hello) > 0}
				out = counted
				w.conns.Add(1)
				if _, dup := t.seen.LoadOrStore(shown, true); !dup {
					logf("WARP: %s", maskAddresses(shown))
				}
			}
		}
	}
	if out == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		c, err := wnet.DialTCP(ctx, dst)
		cancel()
		if err != nil {
			t.failed.Add(1)
			in.Close()
			return
		}
		out = c
	}
	if len(hello) > 0 && !sent {
		if _, err := out.Write(hello); err != nil {
			in.Close()
			out.Close()
			return
		}
	}
	if len(first) > 0 {
		if _, err := in.Write(first); err != nil {
			in.Close()
			out.Close()
			return
		}
	}
	t.total.Add(1)
	t.active.Add(1)
	defer t.active.Add(-1)
	if listed && viaWarp && counted != nil && counted.tls {
		// through WARP the same stop inside a record is the tunnel frozen: a new one, other ports
		done := make(chan struct{})
		defer close(done)
		go func() {
			tk := time.NewTicker(time.Second)
			defer tk.Stop()
			for {
				select {
				case <-done:
					return
				case <-tk.C:
					if counted.stalled() > 6*time.Second {
						select {
						case t.warpStall <- struct{}{}:
						default:
						}
						in.Close()
						out.Close()
						return
					}
				}
			}
		}()
	}
	if listed && !viaWarp && counted != nil && counted.tls {
		// directly: the TSPU's freeze of foreign HTTPS stops the server's data in the middle of
		// a TLS record, which no server does by itself (an idle connection waits on a record's
		// end). Six seconds so: the connection is cut, the client asks again, and the site goes
		// through WARP from now on
		done := make(chan struct{})
		defer close(done)
		go func() {
			tk := time.NewTicker(time.Second)
			defer tk.Stop()
			for {
				select {
				case <-done:
					return
				case <-tk.C:
					if counted.stalled() > 6*time.Second {
						t.markBlocked(shown, fmt.Sprintf("напрямую замёрзло (получено %d КБ) — дальше через WARP",
							counted.n.Load()>>10))
						in.Close()
						out.Close()
						return
					}
				}
			}
		}()
	}
	splice(in, out)
	if listed && !viaWarp {
		return
	}
	if counted != nil && counted.n.Load() == 0 {
		w.fails.Add(1)
		if _, dup := t.seen.LoadOrStore("empty "+shown, true); !dup {
			logf("WARP: %s через WARP ничего не вернул", maskAddresses(shown))
		}
	}
}

// markBlocked: the site through WARP from now on, and the network is taken for one that freezes
// Epic: everything listed goes through WARP and the network is remembered. One site is enough:
// at home, learning them one by one left the content keys to freeze before their turn came
func (t *tcpRelay) markBlocked(name, why string) {
	if _, dup := t.blocked.Load(name); !dup {
		logf("WARP: %s %s", maskAddresses(name), why)
	}
	t.blocked.Store(name, time.Now())
	n := 0
	t.blocked.Range(func(_, _ any) bool { n++; return true })
	if n >= 1 && !t.always.Swap(true) {
		logf("WARP: сервисы Epic напрямую замерзают — всё из списка теперь через WARP, сеть запомнена на 3 дня")
		rememberNetworkFreezes()
	}
}

func (t *tcpRelay) blockedRecently(name string) bool {
	v, ok := t.blocked.Load(name)
	return ok && time.Since(v.(time.Time)) < 10*time.Minute
}

// tryDirect: a direct connection that answered the ClientHello, with the answer's first bytes;
// nil when it did not connect or kept silent. Without a ClientHello (not HTTPS) only connecting
// counts
func tryDirect(dst netip.AddrPort, hello []byte) (net.Conn, []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	c, err := wnet.DialTCP(ctx, dst)
	cancel()
	if err != nil {
		return nil, nil
	}
	if len(hello) == 0 {
		return c, nil
	}
	if _, err := c.Write(hello); err != nil {
		c.Close()
		return nil, nil
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 16<<10)
	n, err := c.Read(buf)
	c.SetReadDeadline(time.Time{})
	if n == 0 || err != nil && n == 0 {
		c.Close()
		return nil, nil
	}
	return c, buf[:n]
}

// countConn counts what came back and, for TLS, follows the records: whether the data stopped
// inside one, and since when
type countConn struct {
	net.Conn
	n   atomic.Int64
	tls bool

	mu    sync.Mutex
	hdr   []byte // a record header read in part
	left  int    // bytes of the current record still to come
	last  time.Time
	wrote time.Time // the client's last write through it
}

func (c *countConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.wrote = time.Now()
	c.mu.Unlock()
	return c.Conn.Write(b)
}

func (c *countConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.n.Add(int64(n))
	if c.tls && n > 0 {
		c.feed(b[:n])
	}
	return n, err
}

func (c *countConn) feed(b []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.last = time.Now()
	for len(b) > 0 {
		if c.left > 0 {
			k := min(c.left, len(b))
			c.left -= k
			b = b[k:]
			continue
		}
		k := min(5-len(c.hdr), len(b))
		c.hdr = append(c.hdr, b[:k]...)
		b = b[k:]
		if len(c.hdr) == 5 {
			c.left = int(c.hdr[3])<<8 | int(c.hdr[4])
			c.hdr = c.hdr[:0]
		}
	}
}

// stalled: how long the data has stood still inside a record, or a request has gone unanswered
// (counted from its 10th second, so a slow answer is not one); 0 otherwise
func (c *countConn) stalled() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.wrote.IsZero() && c.wrote.After(c.last) {
		if d := time.Since(c.wrote) - 4*time.Second; d > 0 {
			return d
		}
	}
	if c.left == 0 && len(c.hdr) == 0 || c.last.IsZero() {
		return 0
	}
	return time.Since(c.last)
}

func (c *countConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// splice copies both ways; when one side ends, the other gets the end too
func splice(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		if _, err := io.Copy(dst, src); err != nil {
			// a reset or a broken side: end both
			a.Close()
			b.Close()
			return
		}
		if c, ok := dst.(interface{ CloseWrite() error }); ok {
			c.CloseWrite()
		} else {
			dst.Close()
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
	a.Close()
	b.Close()
}

func (t *tcpRelay) close() {
	t.cancel()
	if w := t.warp.Swap(nil); w != nil {
		w.close()
	}
	t.stack.Close()
}
