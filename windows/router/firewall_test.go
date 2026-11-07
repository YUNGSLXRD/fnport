package main

import (
	"strings"
	"testing"
)

func TestServiceRulesExcludeGameBeforeVoiceRanges(t *testing.T) {
	c := routerTestConfig()
	c.Discord = true
	c.Devices = append(c.Devices, "aa:bb:cc:dd:ee:02")
	text, err := firewallRules(c, []string{"35.192.0.0/12", "104.16.0.0/12"})
	if err != nil {
		t.Fatal(err)
	}
	game := strings.Index(text, "udp dport { 9000-9999, 15000-15999 } return")
	voice := strings.Index(text, "udp dport 50000-65535 ip daddr @voice4")
	if game < 0 || voice < game || strings.Contains(text, "meta l4proto tcp ip daddr @voice4") || strings.Contains(text, "elements = { 192.168.1.100") {
		t.Fatal("voice ranges can capture game/TCP or clients activate before readiness")
	}
	if !strings.Contains(text, "ether saddr @clients_mac") || !strings.Contains(text, "type nat hook prerouting") {
		t.Fatal("missing client-scoped DNS interception")
	}
}
