//go:build !windows

package main

import (
	"errors"
	"net/netip"
)

func openTun(hosts []netip.Addr) (packetDev, netip.Addr, error) {
	return nil, netip.Addr{}, errors.New("адаптер Wintun есть только в Windows")
}
