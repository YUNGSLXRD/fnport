//go:build devtrace

package main

import "net/netip"

// Selected at build time only for a controlled A/B comparison. Not a setting.
var devControlProbes = "on"

func devSkipControlProbes(cfg *config, dst netip.AddrPort) bool {
	return devControlProbes == "off" && cfg.pairOffset != 0 &&
		dst.Port() >= cfg.pairFrom[0] && dst.Port() <= cfg.pairFrom[1]
}
