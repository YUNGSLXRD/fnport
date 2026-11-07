//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// No shell parses generated rules. Every inserted value is either a constant,
// a validated interface/MAC/prefix, or an address obtained from a DNS parser.
func nftInput(ctx context.Context, script string) error {
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if cmd.Run() != nil {
		return errors.New("firewall_update_failed")
	}
	return nil
}
func jsonCommand(ctx context.Context, name string, args ...string) ([]map[string]any, error) {
	b, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return nil, errors.New("network_state_unavailable")
	}
	var rows []map[string]any
	if json.Unmarshal(b, &rows) != nil {
		return nil, errors.New("network_state_unavailable")
	}
	return rows, nil
}
func routingAvailable(ctx context.Context) error {
	rules, err := jsonCommand(ctx, "ip", "-j", "-4", "rule", "show")
	if err != nil {
		return err
	}
	for _, r := range rules {
		pref, _ := r["priority"].(float64)
		if pref >= 78 && pref <= 81 {
			return errors.New("routing_priority_in_use")
		}
		table := fmt.Sprint(r["table"])
		if table == strconv.Itoa(proxyTable) || table == strconv.Itoa(tunnelTable) {
			return errors.New("routing_table_in_use")
		}
	}
	routes, err := jsonCommand(ctx, "ip", "-j", "-4", "route", "show", "table", "all")
	if err != nil {
		return err
	}
	for _, r := range routes {
		table := fmt.Sprint(r["table"])
		if table == strconv.Itoa(proxyTable) || table == strconv.Itoa(tunnelTable) {
			return errors.New("routing_table_in_use")
		}
	}
	return nil
}

type ownedFirewall struct {
	mu                          sync.Mutex
	config                      routerConfig
	cache                       *serviceAddresses
	table, route, bypass, proxy bool
}

func newOwnedFirewall(ctx context.Context, c routerConfig, voice []string, cache *serviceAddresses) (*ownedFirewall, error) {
	rules, err := firewallRules(c, voice)
	if err != nil {
		return nil, err
	}
	if err = routingAvailable(ctx); err != nil {
		return nil, err
	}
	existing, err := exec.CommandContext(ctx, "nft", "-j", "list", "tables").Output()
	if err != nil {
		return nil, errors.New("firewall_unavailable")
	}
	var state struct {
		NFTables []struct {
			Table struct {
				Name, Family string `json:",omitempty"`
			} `json:"table"`
		} `json:"nftables"`
	}
	if json.Unmarshal(existing, &state) != nil {
		return nil, errors.New("firewall_unavailable")
	}
	for _, row := range state.NFTables {
		if row.Table.Name == "fnport_connections" {
			return nil, errors.New("firewall_table_in_use")
		}
	}
	f := &ownedFirewall{config: c, cache: cache}
	keep := false
	defer func() {
		if !keep {
			f.close()
		}
	}()
	if nftInput(ctx, rules) != nil {
		return nil, errors.New("firewall_install_failed")
	}
	f.table = true
	if commandQuiet(ctx, "ip", "-4", "route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", strconv.Itoa(proxyTable)) != nil {
		return nil, errors.New("proxy_route_failed")
	}
	f.route = true
	if commandQuiet(ctx, "ip", "-4", "rule", "add", "pref", "78", "fwmark", strconv.Itoa(bypassMark), "lookup", "main") != nil {
		return nil, errors.New("bypass_rule_failed")
	}
	f.bypass = true
	if commandQuiet(ctx, "ip", "-4", "rule", "add", "pref", "79", "fwmark", strconv.Itoa(proxyMark), "lookup", strconv.Itoa(proxyTable)) != nil {
		return nil, errors.New("proxy_rule_failed")
	}
	f.proxy = true
	keep = true
	return f, nil
}
func (f *ownedFirewall) alive(ctx context.Context, healthy bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.table {
		return errors.New("firewall_stopped")
	}
	var ips, macs []string
	if healthy {
		for _, s := range f.config.Devices {
			if mac, e := net.ParseMAC(s); e == nil {
				macs = append(macs, mac.String()+" timeout 5s")
			} else {
				ips = append(ips, s+" timeout 5s")
			}
		}
	}
	text := "flush set inet fnport_connections clients4\nflush set inet fnport_connections clients_mac\n"
	if len(ips) > 0 {
		text += "add element inet fnport_connections clients4 { " + strings.Join(ips, ", ") + " }\n"
	}
	if len(macs) > 0 {
		text += "add element inet fnport_connections clients_mac { " + strings.Join(macs, ", ") + " }\n"
	}
	err := nftInput(ctx, text)
	if !healthy {
		clearDNSConntrack(ctx)
	}
	return err
}
func (f *ownedFirewall) publish(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.table {
		return errors.New("firewall_stopped")
	}
	now := time.Now()
	rows, changed := f.cache.snapshot(now)
	if !changed {
		return nil
	}
	services, discord := map[netip.Addr]int{}, map[netip.Addr]int{}
	for _, l := range rows {
		seconds := max(1, int(l.Until.Sub(now).Seconds()))
		services[l.IP] = max(services[l.IP], seconds)
		if l.Service == "discord" {
			discord[l.IP] = max(discord[l.IP], seconds)
		}
	}
	script := "flush set inet fnport_connections services4\nflush set inet fnport_connections discord4\n"
	for _, set := range []struct {
		name string
		rows map[netip.Addr]int
	}{{"services4", services}, {"discord4", discord}} {
		var values []string
		for ip, ttl := range set.rows {
			values = append(values, fmt.Sprintf("%s timeout %ds", ip, ttl))
		}
		sort.Strings(values)
		if len(values) > 0 {
			script += "add element inet fnport_connections " + set.name + " { " + strings.Join(values, ", ") + " }\n"
		}
	}
	if err := nftInput(ctx, script); err != nil {
		f.cache.Lock()
		f.cache.dirty = true
		f.cache.Unlock()
		return err
	}
	return nil
}
func (f *ownedFirewall) close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if f.table {
		nftInput(ctx, "flush set inet fnport_connections clients4\nflush set inet fnport_connections clients_mac\n")
		clearDNSConntrack(ctx)
	}
	if f.proxy {
		commandQuiet(ctx, "ip", "-4", "rule", "del", "pref", "79", "fwmark", strconv.Itoa(proxyMark), "lookup", strconv.Itoa(proxyTable))
		f.proxy = false
	}
	if f.bypass {
		commandQuiet(ctx, "ip", "-4", "rule", "del", "pref", "78", "fwmark", strconv.Itoa(bypassMark), "lookup", "main")
		f.bypass = false
	}
	if f.route {
		commandQuiet(ctx, "ip", "-4", "route", "del", "local", "0.0.0.0/0", "dev", "lo", "table", strconv.Itoa(proxyTable))
		f.route = false
	}
	if f.table {
		commandQuiet(ctx, "nft", "delete", "table", "inet", "fnport_connections")
		f.table = false
	}

}

type clientACL struct {
	mu        sync.RWMutex
	prefixes  []netip.Prefix
	macs      map[string]bool
	lan       map[string]bool
	neighbors map[netip.Addr]bool
}

func newClientACL(c routerConfig) *clientACL {
	a := &clientACL{macs: map[string]bool{}, lan: map[string]bool{}, neighbors: map[netip.Addr]bool{}}
	for _, i := range c.LAN {
		a.lan[i] = true
	}
	for _, s := range c.Devices {
		if mac, e := net.ParseMAC(s); e == nil {
			a.macs[mac.String()] = true
		} else if p, e := netip.ParsePrefix(s); e == nil {
			a.prefixes = append(a.prefixes, p)
		}
	}
	return a
}
func (a *clientACL) allow(ip netip.Addr) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	for _, p := range a.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return a.neighbors[ip]
}
func (a *clientACL) refresh(ctx context.Context) error {
	rows, err := jsonCommand(ctx, "ip", "-j", "neigh", "show")
	if err != nil {
		return err
	}
	next := map[netip.Addr]bool{}
	for _, row := range rows {
		dev, _ := row["dev"].(string)
		mac, _ := row["lladdr"].(string)
		dst, _ := row["dst"].(string)
		if !a.lan[dev] || !a.macs[strings.ToLower(mac)] {
			continue
		}
		if ip, err := netip.ParseAddr(dst); err == nil {
			next[ip.Unmap().WithZone("")] = true
		}
	}
	a.mu.Lock()
	a.neighbors = next
	a.mu.Unlock()
	return nil
}

// Called only while main holds the exclusive instance lock. A crashed instance's
// table must carry our exact ownership comment; foreign tables/rules are kept.
func recoverOwnedFirewall(ctx context.Context) error {
	raw, err := exec.CommandContext(ctx, "nft", "-j", "list", "table", "inet", "fnport_connections").Output()
	if err != nil {
		return nil
	}
	var state struct {
		NFTables []struct {
			Table struct{ Name, Comment string } `json:"table"`
		} `json:"nftables"`
	}
	if json.Unmarshal(raw, &state) != nil {
		return errors.New("firewall_state_invalid")
	}
	owned := false
	for _, r := range state.NFTables {
		if r.Table.Name == "fnport_connections" && r.Table.Comment == "fnport-connections/v1" {
			owned = true
		}
	}
	if !owned {
		return errors.New("firewall_table_in_use")
	}
	nftInput(ctx, "flush set inet fnport_connections clients4\nflush set inet fnport_connections clients_mac\n")
	clearDNSConntrack(ctx)
	commandQuiet(ctx, "ip", "-4", "rule", "del", "pref", "79", "fwmark", strconv.Itoa(proxyMark), "lookup", strconv.Itoa(proxyTable))
	commandQuiet(ctx, "ip", "-4", "rule", "del", "pref", "78", "fwmark", strconv.Itoa(bypassMark), "lookup", "main")
	commandQuiet(ctx, "ip", "-4", "rule", "del", "pref", "81", "oif", tunnelName, "lookup", strconv.Itoa(tunnelTable))
	commandQuiet(ctx, "ip", "-4", "route", "del", "local", "0.0.0.0/0", "dev", "lo", "table", strconv.Itoa(proxyTable))
	return commandQuiet(ctx, "nft", "delete", "table", "inet", "fnport_connections")
}

// MAC-selected clients can query DNS over IPv6 even though service routing is IPv4.
// Drop both families' owned NAT entries when interception stops.
func clearDNSConntrack(ctx context.Context) {
	for _, family := range []string{"ipv4", "ipv6"} {
		commandQuiet(ctx, "conntrack", "-D", "-f", family, "--mark", "61811")
	}
}
