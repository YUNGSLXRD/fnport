//go:build !windows

package wnet

import (
	"errors"
	"net/netip"
)

func OpenTun(name string, routes []netip.Prefix) (Dev, netip.Addr, error) {
	return nil, netip.Addr{}, errors.New("адаптер Wintun есть только в Windows")
}
