package main

import (
	"context"
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
	cancel context.CancelFunc
	active atomic.Int64
	total  atomic.Int64
	failed atomic.Int64
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
	t := &tcpRelay{stack: s, ep: ep, cancel: cancel}
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
	t.stack.Close()
}
