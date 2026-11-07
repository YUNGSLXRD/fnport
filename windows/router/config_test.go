package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func routerTestConfig() routerConfig {
	return routerConfig{Protocol: "socks", Profile: `{"type":"socks","server":"127.0.0.1","server_port":1080}`, Devices: []string{"192.168.1.100"}, Epic: true, WAN: "eth0", LAN: []string{"br-lan"}, FakeTTL: 3, DNSMode: "https", DNSProvider: "cloudflare"}
}
func TestRouterProfileCannotImportRoutingOrListeners(t *testing.T) {
	for _, field := range []string{"routing_mark", "auto_route", "listen_port", "external_controller", "netns", "detour"} {
		c := routerTestConfig()
		var node map[string]any
		json.Unmarshal([]byte(c.Profile), &node)
		node[field] = "private-secret"
		b, _ := json.Marshal(node)
		c.Profile = string(b)
		_, err := c.coreConfig()
		if err == nil || strings.Contains(err.Error(), "private-secret") {
			t.Fatalf("unsafe field accepted or leaked: %s", field)
		}
	}
}
func TestRouterSelectionIsLimitedToClientDevices(t *testing.T) {
	c := routerTestConfig()
	if err := c.validate(); err != nil || c.Devices[0] != "192.168.1.100/32" {
		t.Fatal("valid client rejected", err)
	}
	for _, bad := range []string{"0.0.0.0/0", "::/0", "192.168.1.0/8", "192.168.1.1; touch /tmp/pwn", "8.8.8.8"} {
		c := routerTestConfig()
		c.Devices = []string{bad}
		if c.validate() == nil {
			t.Fatal("invalid client accepted")
		}
	}
	for _, host := range []string{"discord.com.attacker.test", "notdiscord.com", "discord.com/../"} {
		if domainMatch(host, []string{"discord.com"}) {
			t.Fatal("domain escaped boundary")
		}
	}
	if !domainMatch("voice.discord.media", []string{"discord.media"}) {
		t.Fatal("voice suffix not selected")
	}
}
