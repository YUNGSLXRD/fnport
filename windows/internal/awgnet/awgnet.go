// Package awgnet: a TCP/IPv4 stack in this program for the AmneziaWG tunnel to WARP, so
// connections can be dialed through the tunnel without a second adapter in Windows.
// After wireguard-go's tun/netstack (MIT, WireGuard LLC), cut down to what fnport needs and
// built on the gVisor version the rest of the program uses.
package awgnet

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"syscall"

	"github.com/amnezia-vpn/amneziawg-go/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

type Net struct {
	ep       *channel.Endpoint
	stack    *stack.Stack
	events   chan tun.Event
	incoming chan *buffer.View
	mtu      int
}

// New: the stack with one IPv4 address; the returned device goes to the AWG device
func New(addr netip.Addr, mtu int) (tun.Device, *Net, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
		HandleLocal:        true,
	})
	n := &Net{ep: channel.New(1024, uint32(mtu), ""), stack: s, events: make(chan tun.Event, 10),
		incoming: make(chan *buffer.View), mtu: mtu}
	sack := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)
	n.ep.AddNotify(n)
	if err := s.CreateNIC(1, n.ep); err != nil {
		return nil, nil, fmt.Errorf("CreateNIC: %v", err)
	}
	pa := tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddrFromSlice(addr.AsSlice()).WithPrefix()}
	if err := s.AddProtocolAddress(1, pa, stack.AddressProperties{}); err != nil {
		return nil, nil, fmt.Errorf("AddProtocolAddress: %v", err)
	}
	s.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	n.events <- tun.EventUp
	return (*device)(n), n, nil
}

// DialTCP connects through the tunnel
func (n *Net) DialTCP(ctx context.Context, dst netip.AddrPort) (*gonet.TCPConn, error) {
	fa := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(dst.Addr().AsSlice()), Port: dst.Port()}
	return gonet.DialContextTCP(ctx, n.stack, fa, ipv4.ProtocolNumber)
}

// WriteNotify: the stack has a packet for the tunnel
func (n *Net) WriteNotify() {
	pkt := n.ep.Read()
	if pkt == nil {
		return
	}
	v := pkt.ToView()
	pkt.DecRef()
	n.incoming <- v
}

// device is the Net as AWG's tun.Device
type device Net

func (d *device) Name() (string, error)    { return "awgnet", nil }
func (d *device) File() *os.File           { return nil }
func (d *device) Events() <-chan tun.Event { return d.events }
func (d *device) MTU() (int, error)        { return d.mtu, nil }
func (d *device) BatchSize() int           { return 1 }

func (d *device) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	v, ok := <-d.incoming
	if !ok {
		return 0, os.ErrClosed
	}
	n, err := v.Read(bufs[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

func (d *device) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		p := b[offset:]
		if len(p) == 0 {
			continue
		}
		if p[0]>>4 != 4 {
			return 0, syscall.EAFNOSUPPORT
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(p)})
		d.ep.InjectInbound(header.IPv4ProtocolNumber, pkt)
		pkt.DecRef()
	}
	return len(bufs), nil
}

func (d *device) Close() error {
	d.stack.RemoveNIC(1)
	close(d.events)
	d.ep.Close()
	close(d.incoming)
	return nil
}
