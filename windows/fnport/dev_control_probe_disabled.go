//go:build !devtrace

package main

import "net/netip"

func devSkipControlProbes(*config, netip.AddrPort) bool { return false }
