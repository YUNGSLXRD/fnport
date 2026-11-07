package main

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Only our own table and tagged sockets are affected. Service destinations
// come from selected-domain DNS answers; voice ranges are limited to UDP ports.
func firewallRules(c routerConfig, voice []string) (string, error) {
	if err := c.validate(); err != nil {
		return "", err
	}
	var lan, nets []string
	for _, i := range c.LAN {
		lan = append(lan, fmt.Sprintf("%q", i))
	}
	for _, s := range voice {
		p, e := netip.ParsePrefix(s)
		if e != nil {
			return "", fmt.Errorf("invalid_voice_prefix")
		}
		if p.Addr().Is4() {
			nets = append(nets, p.Masked().String())
		}
	}
	sort.Strings(nets)
	var b strings.Builder
	fmt.Fprintf(&b, `table inet fnport_connections {
 comment "fnport-connections/v1";
 set lan { type ifname; elements = { %s }; }
 set clients4 { type ipv4_addr; flags interval,timeout; auto-merge; timeout 5s; }
 set clients_mac { type ether_addr; flags timeout; timeout 5s; }
 set services4 { type ipv4_addr; flags timeout; }
 set discord4 { type ipv4_addr; flags timeout; }
 set voice4 { type ipv4_addr; flags interval; auto-merge; }
 chain service {
  meta nfproto != ipv4 return
  udp dport { 9000-9999, 15000-15999 } return
  meta l4proto tcp ip daddr @services4 meta mark set %d tproxy ip to 127.0.0.1:%d accept
`, strings.Join(lan, ", "), proxyMark, proxyPort)
	if c.Epic {
		fmt.Fprintf(&b, "  udp dport 443 ip daddr @services4 meta mark set %d tproxy ip to 127.0.0.1:%d accept\n", proxyMark, proxyPort)
	}
	if c.Discord {
		fmt.Fprintf(&b, "  udp dport { 443, 50000-65535 } ip daddr @discord4 meta mark set %d tproxy ip to 127.0.0.1:%d accept\n", proxyMark, proxyPort)
		fmt.Fprintf(&b, "  udp dport 50000-65535 ip daddr @voice4 meta mark set %d tproxy ip to 127.0.0.1:%d accept\n", proxyMark, proxyPort)
	}
	fmt.Fprintf(&b, ` }
 chain prerouting {
  type filter hook prerouting priority mangle + 30; policy accept;
  iifname @lan ip saddr @clients4 jump service
  iifname @lan ether saddr @clients_mac jump service
 }
 chain dns {
  type nat hook prerouting priority dstnat - 5; policy accept;
  iifname @lan ip saddr @clients4 meta l4proto { tcp, udp } th dport 53 ct mark set 61811 redirect to :%d
  iifname @lan ether saddr @clients_mac meta l4proto { tcp, udp } th dport 53 ct mark set 61811 redirect to :%d
 }
 chain input {
  type filter hook input priority filter - 5; policy accept;
  iifname != @lan meta l4proto { tcp, udp } th dport 10553 drop
  iifname != "lo" meta l4proto { tcp, udp } th dport 10897 drop
 }
 chain output_before {
  type route hook output priority mangle - 20; policy accept;
  meta mark { %d, %d } ct mark set meta mark
 }
 chain output_after {
  type route hook output priority mangle + 20; policy accept;
  ct mark { %d, %d } meta mark set ct mark
 }
}
`, dnsPort, dnsPort, bypassMark, tunnelMark, bypassMark, tunnelMark)
	if len(nets) > 0 {
		fmt.Fprintf(&b, "add element inet fnport_connections voice4 { %s }\n", strings.Join(nets, ", "))
	}
	return b.String(), nil
}
