package main

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// relay: the core of the future app. UDP datagrams that Windows routes into the adapter leave
// through ordinary sockets on the physical interface, one per flow, from a port this program
// picks (with the fake before the first packet); replies are written back into the adapter as if
// they came straight from the server.

type packetDev interface {
	ReadPacket(buf []byte) (int, error)
	WritePacket(pkt []byte) error
	Close() error
}

type flowPlan struct {
	fake []byte
	ttl  int
}

type flowKey struct {
	srcPort uint16
	dst     netip.AddrPort
}

type flow struct {
	conn    *net.UDPConn
	port    int
	out, in atomic.Int64
}

type relay struct {
	dev      packetDev
	clientIP netip.Addr
	open     func() (*net.UDPConn, error)

	mu    sync.Mutex
	plans map[uint16]flowPlan // by client source port
	flows map[flowKey]*flow
	wmu   sync.Mutex // the adapter takes one writer at a time
	ipID  atomic.Uint32
}

func newRelay(dev packetDev, clientIP netip.Addr, open func() (*net.UDPConn, error)) *relay {
	return &relay{dev: dev, clientIP: clientIP, open: open, plans: map[uint16]flowPlan{}, flows: map[flowKey]*flow{}}
}

func (r *relay) setPlan(clientPort uint16, p flowPlan) {
	r.mu.Lock()
	r.plans[clientPort] = p
	r.mu.Unlock()
}

func (r *relay) flowFor(srcPort uint16) *flow {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, f := range r.flows {
		if k.srcPort == srcPort {
			return f
		}
	}
	return nil
}

// run reads the adapter until it is closed
func (r *relay) run() {
	buf := make([]byte, 65536)
	for {
		n, err := r.dev.ReadPacket(buf)
		if err != nil {
			return
		}
		p, err := parseUDP4(buf[:n])
		if err != nil || p.src.Addr() != r.clientIP {
			continue // IPv6, ICMP, IGMP and other chatter Windows sends to any adapter
		}
		key := flowKey{p.src.Port(), p.dst}
		r.mu.Lock()
		f := r.flows[key]
		plan := r.plans[p.src.Port()]
		r.mu.Unlock()
		if f == nil {
			c, err := r.open()
			if err != nil {
				logf("  (relay: нет сокета: %v)", err)
				continue
			}
			f = &flow{conn: c, port: c.LocalAddr().(*net.UDPAddr).Port}
			if plan.fake != nil && plan.ttl > 0 {
				sendWithTTL(c, plan.fake, p.dst, plan.ttl)
				time.Sleep(fakeGap)
			}
			r.mu.Lock()
			r.flows[key] = f
			r.mu.Unlock()
			go r.back(f, key)
		}
		f.out.Add(1)
		f.conn.WriteToUDPAddrPort(p.payload, p.dst)
	}
}

// back carries the server's replies into the adapter
func (r *relay) back(f *flow, key flowKey) {
	buf := make([]byte, 65536)
	client := netip.AddrPortFrom(r.clientIP, key.srcPort)
	for {
		n, from, err := f.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue // ICMP errors and the like
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		if from != key.dst {
			continue
		}
		f.in.Add(1)
		pkt := buildUDP4(from, client, buf[:n], uint16(r.ipID.Add(1)))
		r.wmu.Lock()
		err = r.dev.WritePacket(pkt)
		r.wmu.Unlock()
		if err != nil {
			return
		}
	}
}

func (r *relay) close() {
	r.dev.Close()
	r.mu.Lock()
	for _, f := range r.flows {
		f.conn.Close()
	}
	r.mu.Unlock()
}
