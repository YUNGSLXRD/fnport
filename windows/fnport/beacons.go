package main

import (
	"context"
	"crypto/rand"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/YUNGSLXRD/fnport/windows/internal/geo"
	"github.com/YUNGSLXRD/fnport/windows/internal/wnet"
)

// Ping to Epic's QoS beacons (UDP echo on 22222), one per city, while the window is open:
// a few packets from a fresh socket every few seconds, far below the 25 that freeze a flow.

const (
	beaconName  = "ping-eu.ds.on.epicgames.com"
	pingEvery   = 5 * time.Second
	pingPackets = 3
	pingHigh    = 100 * time.Millisecond // from here on the ping shows yellow
)

var beaconFallback = []string{"3.66.90.173", "18.133.162.202", "13.37.148.3"}

type beacon struct {
	City    string // in Russian
	Addr    netip.Addr
	RTT     time.Duration // best of the last round; 0 = no reply
	Checked bool          // at least one round done
}

type pinger struct {
	mu   sync.Mutex
	list []beacon
}

func (p *pinger) snapshot() []beacon {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]beacon(nil), p.list...)
}

func resolveBeacons() []netip.Addr {
	try := func(server string) []netip.Addr {
		r := net.DefaultResolver
		if server != "" {
			r = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "udp", server)
			}}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		ips, _ := r.LookupNetIP(ctx, "ip4", beaconName)
		var out []netip.Addr
		for _, ip := range ips {
			if ip = ip.Unmap(); geo.IsPublic(ip) {
				out = append(out, ip)
			}
		}
		return out
	}
	ips := try("")
	for _, s := range []string{"77.88.8.8:53", "8.8.8.8:53"} {
		if len(ips) == 0 {
			ips = try(s)
		}
	}
	// the fallback fills in cities DNS did not give
	for _, s := range beaconFallback {
		ips = append(ips, netip.MustParseAddr(s))
	}
	order := map[string]int{"frankfurt": 0, "london": 1, "paris": 2}
	seen := map[string]bool{}
	var out []netip.Addr
	for _, ip := range ips {
		c := geo.City(ip)
		if _, known := order[c]; known && !seen[c] {
			seen[c] = true
			out = append(out, ip)
		}
	}
	sort.Slice(out, func(i, j int) bool { return order[geo.City(out[i])] < order[geo.City(out[j])] })
	return out
}

// run pings until ctx ends; onUpdate is called after every round
func (p *pinger) run(ctx context.Context, onUpdate func()) {
	p.mu.Lock()
	if len(p.list) == 0 {
		p.mu.Unlock()
		addrs := resolveBeacons()
		p.mu.Lock()
		for _, a := range addrs {
			p.list = append(p.list, beacon{City: geo.CityRU(a), Addr: a})
		}
	}
	p.mu.Unlock()
	for {
		var wg sync.WaitGroup
		for i, b := range p.snapshot() {
			wg.Add(1)
			go func(i int, a netip.Addr) {
				defer wg.Done()
				rtt := pingOnce(a)
				p.mu.Lock()
				p.list[i].RTT, p.list[i].Checked = rtt, true
				p.mu.Unlock()
			}(i, b.Addr)
		}
		wg.Wait()
		onUpdate()
		select {
		case <-ctx.Done():
			return
		case <-time.After(pingEvery):
		}
	}
}

// pingOnce: best RTT of a few echo packets from a fresh socket on the physical interface
// (the beacons' addresses are routed into the adapter while fnport is on); 0 without replies
func pingOnce(a netip.Addr) time.Duration {
	c, err := wnet.ListenUDP(0, true)
	if err != nil {
		return 0
	}
	defer c.Close()
	dst := netip.AddrPortFrom(a, 22222)
	var tag [2]byte
	rand.Read(tag[:])
	sent := make([]time.Time, pingPackets)
	for i := range sent {
		pkt := []byte{tag[0], tag[1], 0, byte(i), 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb}
		sent[i] = time.Now()
		c.WriteToUDPAddrPort(pkt, dst)
		time.Sleep(20 * time.Millisecond)
	}
	var best time.Duration
	buf := make([]byte, 512)
	c.SetReadDeadline(time.Now().Add(time.Second))
	for {
		n, from, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return best
			}
			continue
		}
		if from.Addr().Unmap() != a || n < 4 || buf[0] != tag[0] || buf[1] != tag[1] || int(buf[3]) >= pingPackets {
			continue
		}
		if rtt := time.Since(sent[buf[3]]); best == 0 || rtt < best {
			best = rtt
		}
	}
}
