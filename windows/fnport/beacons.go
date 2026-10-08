package main

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/YUNGSLXRD/fnport/windows/internal/geo"
	"github.com/YUNGSLXRD/fnport/windows/internal/qos"
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
	mu       sync.Mutex
	list     []beacon
	inRound  bool
	kick     chan struct{}
	kickOnce sync.Once
}

func (p *pinger) kickCh() chan struct{} {
	p.kickOnce.Do(func() { p.kick = make(chan struct{}, 1) })
	return p.kick
}

// kickNow: ping again now instead of waiting for the next round
func (p *pinger) kickNow() {
	select {
	case p.kickCh() <- struct{}{}:
	default:
	}
}

// busy: a round is running
func (p *pinger) busy() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.inRound
}

func (p *pinger) snapshot() []beacon {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]beacon(nil), p.list...)
}

// resolveName: addresses of a name from Windows' DNS (fakeip included, to be spotted)
func resolveName(name string) []netip.Addr {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ips, _ := net.DefaultResolver.LookupNetIP(ctx, "ip4", name)
	for i := range ips {
		ips[i] = ips[i].Unmap()
	}
	return ips
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
		p.mu.Lock()
		p.inRound = true
		p.mu.Unlock()
		onUpdate()
		var wg sync.WaitGroup
		for i, b := range p.snapshot() {
			wg.Add(1)
			go func(i int, a netip.Addr) {
				defer wg.Done()
				rtt := qos.Ping(a, pingPackets)
				p.mu.Lock()
				p.list[i].RTT, p.list[i].Checked = rtt, true
				p.mu.Unlock()
			}(i, b.Addr)
		}
		wg.Wait()
		p.mu.Lock()
		p.inRound = false
		p.mu.Unlock()
		onUpdate()
		select {
		case <-ctx.Done():
			return
		case <-time.After(pingEvery):
		case <-p.kickCh():
		}
	}
}
