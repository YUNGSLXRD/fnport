//go:build !windows

package wnet

import (
	"errors"
	"net/netip"
)

var TunDNSAddr = netip.MustParseAddr("10.254.77.1")

func OpenTun(name string, routes []netip.Prefix) (Dev, netip.Addr, error) {
	return OpenTunWithDNS(name, routes, nil)
}

func OpenTunWithDNS(name string, routes []netip.Prefix, dns []netip.Addr) (Dev, netip.Addr, error) {
	return nil, netip.Addr{}, errors.New("адаптер Wintun есть только в Windows")
}
