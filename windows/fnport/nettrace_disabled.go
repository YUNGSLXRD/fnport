//go:build !devtrace

package main

import (
	"context"
	"net"
	"net/netip"
	"time"
)

type networkTrace struct{}

func traceAvailable() bool                                                           { return false }
func defaultNetworkTraceSettings() networkTraceSettings                              { return networkTraceSettings{} }
func startNetworkTrace(context.Context, networkTraceSettings) (*networkTrace, error) { return nil, nil }
func (*networkTrace) close() error                                                   { return nil }
func (*networkTrace) observe(uint8, netip.AddrPort, netip.AddrPort, string, string)  {}

func (*networkTrace) udpStats(netip.AddrPort, netip.AddrPort, networkUDPStats) {}

func (*networkTrace) tcpConn(c net.Conn, _ netip.AddrPort, _ netip.AddrPort, _ string, _ string, _ time.Time, _ int) (net.Conn, func()) {
	return c, func() {}
}
