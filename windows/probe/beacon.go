package main

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"time"
)

// Epic's QoS beacons answer every packet on UDP 22222: a test bed without the game.

const beaconName = "ping-eu.ds.on.epicgames.com"

// used when DNS gives nothing usable (fakeip of Podkop-like services, filtered DNS); Frankfurt first
var beaconFallback = []string{"3.66.90.173", "3.66.90.156", "18.133.162.202", "13.37.148.3"}

var publicDNS = []string{"77.88.8.8:53", "8.8.8.8:53"}

// isPublic: not private, not special, not the 198.18.0.0/15 fakeip range of Podkop and the like
func isPublic(a netip.Addr) bool {
	if !a.Is4() || a.IsPrivate() || a.IsLoopback() || a.IsMulticast() || a.IsUnspecified() || a.IsLinkLocalUnicast() {
		return false
	}
	o := a.As4()
	if o[0] == 0 || o[0] >= 224 || (o[0] == 100 && o[1] >= 64 && o[1] <= 127) || (o[0] == 198 && (o[1] == 18 || o[1] == 19)) {
		return false
	}
	return true
}

func isFakeIP(a netip.Addr) bool {
	o := a.As4()
	return a.Is4() && o[0] == 198 && (o[1] == 18 || o[1] == 19)
}

// city: AWS EU region by address prefix (the ones Epic's beacons and game servers use)
func city(a netip.Addr) string {
	o := a.As4()
	x, y := int(o[0]), int(o[1])
	switch {
	case (x == 3 && y >= 64 && y <= 79) || (x == 18 && y >= 153 && y <= 159) || (x == 35 && y >= 156 && y <= 159):
		return "frankfurt"
	case (x == 3 && y >= 8 && y <= 11) || (x == 18 && ((y >= 130 && y <= 135) || (y >= 168 && y <= 171))) ||
		(x == 13 && y >= 40 && y <= 43) || (x == 35 && y >= 176 && y <= 179):
		return "london"
	case (x == 13 && y >= 36 && y <= 39) || (x == 15 && (y == 188 || y == 236 || y == 237)) || (x == 35 && (y == 180 || y == 181)):
		return "paris"
	}
	return "eu"
}

var cityRU = map[string]string{"frankfurt": "Франкфурт", "london": "Лондон", "paris": "Париж", "eu": "Европа"}

func resolveWith(server string, name string) []netip.Addr {
	r := net.DefaultResolver
	if server != "" {
		r = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", server)
		}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ips, err := r.LookupNetIP(ctx, "ip4", name)
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, ip := range ips {
		ip = ip.Unmap()
		if isPublic(ip) {
			out = append(out, ip)
		}
	}
	return out
}

// beacons: up to three beacons in different cities, Frankfurt first
func beacons() ([]netip.Addr, string) {
	ips, source := resolveWith("", beaconName), "DNS Windows"
	for _, s := range publicDNS {
		if len(ips) > 0 {
			break
		}
		ips, source = resolveWith(s, beaconName), "публичный DNS "+s[:len(s)-3]
	}
	if len(ips) == 0 {
		for _, s := range beaconFallback {
			ips = append(ips, netip.MustParseAddr(s))
		}
		source = "встроенный список"
	}
	order := map[string]int{"frankfurt": 0, "london": 1, "paris": 2, "eu": 3}
	sort.SliceStable(ips, func(i, j int) bool { return order[city(ips[i])] < order[city(ips[j])] })
	seen := map[string]bool{}
	var out []netip.Addr
	for _, ip := range ips {
		if !seen[city(ip)] && len(out) < 3 {
			seen[city(ip)] = true
			out = append(out, ip)
		}
	}
	return out, source
}
