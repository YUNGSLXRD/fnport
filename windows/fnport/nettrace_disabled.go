//go:build !devtrace

package main

import (
	"context"
	"net/netip"
)

type networkTrace struct{}

func traceAvailable() bool                                                           { return false }
func defaultNetworkTraceSettings() networkTraceSettings                              { return networkTraceSettings{} }
func startNetworkTrace(context.Context, networkTraceSettings) (*networkTrace, error) { return nil, nil }
func (*networkTrace) close() error                                                   { return nil }
func (*networkTrace) observe(uint8, netip.AddrPort, netip.AddrPort, string, string)  {}
