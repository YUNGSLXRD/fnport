package main

import (
	"errors"
	"github.com/YUNGSLXRD/fnport/windows/internal/wnet"
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

	// timing: the server's RTT on the program's socket (by the first 4 payload bytes, the probe's
	// tag and sequence number) and the program's own time per datagram each way
	mu        sync.Mutex
	sent      map[string]time.Time
	rtts      []time.Duration
	fwd, back []time.Duration
}

const maxTimed = 256

func (f *flow) timeOut(payload []byte, read time.Time) {
	now := time.Now()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.fwd) < maxTimed {
		f.fwd = append(f.fwd, now.Sub(read))
	}
	if len(payload) >= 4 && len(f.sent) < maxTimed {
		f.sent[string(payload[:4])] = now
	}
}

func (f *flow) timeIn(payload []byte, got, written time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.back) < maxTimed {
		f.back = append(f.back, written.Sub(got))
	}
	if len(payload) >= 4 {
		if t, ok := f.sent[string(payload[:4])]; ok && len(f.rtts) < maxTimed {
			f.rtts = append(f.rtts, got.Sub(t))
		}
	}
}

type relay struct {
	dev      wnet.Dev
	clientIP netip.Addr
	open     func() (*net.UDPConn, error)
	routed   map[netip.Addr]bool // servers routed into the adapter; nil = any
	failLog  time.Time

	mu    sync.Mutex
	plans map[uint16]flowPlan // by client source port
	flows map[flowKey]*flow
	ipID  atomic.Uint32
}

func newRelay(dev wnet.Dev, clientIP netip.Addr, open func() (*net.UDPConn, error)) *relay {
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
		read := time.Now()
		p, err := wnet.ParseUDP4(buf[:n])
		if err != nil || p.Src.Addr() != r.clientIP {
			continue // IPv6, ICMP, IGMP and other chatter Windows sends to any adapter
		}
		if r.routed != nil && !r.routed[p.Dst.Addr()] {
			continue // broadcasts and multicast of network discovery (NetBIOS, LLMNR, SSDP, mDNS)
		}
		key := flowKey{p.Src.Port(), p.Dst}
		r.mu.Lock()
		f := r.flows[key]
		plan := r.plans[p.Src.Port()]
		r.mu.Unlock()
		if f == nil {
			c, err := r.open()
			if err != nil {
				if time.Since(r.failLog) > 5*time.Second {
					r.failLog = time.Now()
					logf("  (relay: нет сокета для %s: %v)", p.Dst, err)
				}
				continue
			}
			f = &flow{conn: c, port: c.LocalAddr().(*net.UDPAddr).Port, sent: map[string]time.Time{}}
			if plan.fake != nil && plan.ttl > 0 {
				wnet.SendWithTTL(c, plan.fake, p.Dst, plan.ttl)
				time.Sleep(fakeGap)
			}
			r.mu.Lock()
			r.flows[key] = f
			r.mu.Unlock()
			go r.back(f, key)
		}
		f.out.Add(1)
		read2 := read
		if plan.fake != nil && f.out.Load() == 1 {
			read2 = time.Now() // the pause after the fake is not the relay's speed
		}
		f.conn.WriteToUDPAddrPort(p.Payload, p.Dst)
		f.timeOut(p.Payload, read2)
	}
}

// back carries the server's replies into the adapter
func (r *relay) back(f *flow, key flowKey) {
	buf := make([]byte, 65536)
	client := netip.AddrPortFrom(r.clientIP, key.srcPort)
	for {
		n, from, err := f.conn.ReadFromUDPAddrPort(buf)
		got := time.Now()
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
		pkt := wnet.BuildUDP4(from, client, buf[:n], uint16(r.ipID.Add(1)))
		err = r.dev.WritePacket(pkt)
		if err != nil {
			return
		}
		f.timeIn(buf[:n], got, time.Now())
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
