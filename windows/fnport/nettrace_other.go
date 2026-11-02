//go:build !windows

package main

import (
	"context"
	"net/netip"

	"github.com/YUNGSLXRD/fnport/windows/internal/wnet"
)

func networkTraceSupported() bool { return false }
func readNetworkTraceDNS(context.Context) (map[netip.Addr][]string, error) {
	return nil, wnet.ErrProcessUnsupported
}
