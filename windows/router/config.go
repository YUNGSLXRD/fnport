package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

const coreVersion = "1.14.4"
const bypassMark = 0xf170
const proxyMark = 0xf171
const tunnelMark = 0xf172
const proxyTable = 49071
const tunnelTable = 49072
const proxyPort = 10897
const socksPort = 10898
const dnsPort = 10553
const tunnelName = "fnpwarp0"

// Only the administrator's private profile is persisted. Status never includes it.
type routerConfig struct {
	Protocol    string            `json:"protocol"`
	Profile     string            `json:"profile,omitempty"`
	Devices     []string          `json:"devices"`
	Epic        bool              `json:"epic"`
	Discord     bool              `json:"discord"`
	Domains     []string          `json:"domains,omitempty"`
	DNSMode     string            `json:"dns_mode"`
	DNSProvider string            `json:"dns_provider"`
	WAN         string            `json:"wan"`
	LAN         []string          `json:"lan"`
	Native      nativeAWGSettings `json:"native,omitempty"`
	FakeFile    string            `json:"fake_file"`
	FakeTTL     int               `json:"fake_ttl"`
}

var validIface = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,15}$`)
var validHost = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$`)
var routerProtocols = map[string]bool{"warp": true, "amneziawg": true, "wireguard": true, "socks": true, "http": true, "shadowsocks": true, "vmess": true, "vless": true, "trojan": true, "anytls": true, "snell": true, "hysteria": true, "hysteria2": true, "tuic": true, "ssh": true}

func domainName(s string) string {
	s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if len(s) > 253 || !validHost.MatchString(s) || strings.Contains(s, "..") || !strings.Contains(s, ".") {
		return ""
	}
	return s
}
func domainMatch(host string, domains []string) bool {
	host = domainName(host)
	if host == "" {
		return false
	}
	for _, name := range domains {
		if host == name || strings.HasSuffix(host, "."+name) {
			return true
		}
	}
	return false
}
func domainList(s string) []string {
	seen := map[string]bool{}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if n := domainName(line); n != "" {
			seen[n] = true
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
func (c *routerConfig) validate() error {
	if !routerProtocols[c.Protocol] || !validIface.MatchString(c.WAN) {
		return errors.New("invalid_protocol_or_interface")
	}
	if len(c.LAN) == 0 || len(c.LAN) > 16 {
		return errors.New("select_lan_interfaces")
	}
	for _, name := range c.LAN {
		if !validIface.MatchString(name) || name == c.WAN {
			return errors.New("invalid_lan_interface")
		}
	}
	if len(c.Devices) == 0 || len(c.Devices) > 128 {
		return errors.New("select_devices")
	}
	for i, s := range c.Devices {
		if !strings.Contains(s, "/") {
			s += "/32"
		}
		if mac, err := net.ParseMAC(strings.TrimSuffix(s, "/32")); err == nil && len(mac) == 6 {
			if mac[0]&1 != 0 {
				return errors.New("invalid_client_address")
			}
			c.Devices[i] = strings.ToLower(mac.String())
			continue
		}
		p, e := netip.ParsePrefix(s)
		if e != nil || !p.Addr().Is4() || !p.Addr().IsPrivate() || p.Bits() < 16 {
			return errors.New("invalid_client_address")
		}
		c.Devices[i] = p.Masked().String()
	}
	if !c.Epic && !c.Discord && len(c.Domains) == 0 {
		return errors.New("select_services")
	}
	if c.FakeTTL < 1 || c.FakeTTL > 16 {
		return errors.New("invalid_fake_ttl")
	}
	if c.DNSMode != "https" && c.DNSMode != "tls" && c.DNSMode != "plain" {
		return errors.New("invalid_dns_mode")
	}
	if _, ok := dnsProviders[c.DNSProvider]; !ok {
		return errors.New("invalid_dns_provider")
	}
	if len(c.Profile) > 1<<20 {
		return errors.New("profile_too_large")
	}
	for _, d := range c.Domains {
		if domainName(d) == "" {
			return errors.New("invalid_domain")
		}
	}
	return nil
}

func safeOutbound(v any, wan string) error {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if strings.HasSuffix(k, "_path") || k == "command" || k == "executable" || k == "arguments" {
				return errors.New("profile_file_or_command_not_allowed")
			}
			switch k {
			case "inbounds", "outbounds", "endpoints", "route", "dns", "experimental", "services", "log",
				"listen", "listen_port", "external_controller", "external_ui", "auto_route", "auto_redirect",
				"set_system_proxy", "netns", "routing_mark", "inet4_bind_address", "inet6_bind_address", "detour":
				return errors.New("profile_routing_or_listeners_not_allowed")
			case "system_interface", "system":
				if val != false {
					return errors.New("profile_system_interface_not_allowed")
				}
			case "bind_interface":
				x[k] = wan
			}
			if err := safeOutbound(val, wan); err != nil {
				return err
			}
		}
	case []any:
		for _, v := range x {
			if err := safeOutbound(v, wan); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c routerConfig) coreConfig() ([]byte, error) {
	var node map[string]any
	if c.Protocol == "warp" || c.Protocol == "amneziawg" || c.Protocol == "wireguard" {
		node = map[string]any{"type": "direct", "bind_interface": tunnelName, "routing_mark": tunnelMark}
	} else {
		raw, kind, err := importConnection(c.Profile, true)
		if err != nil || (kind != "" && kind != c.Protocol) {
			return nil, errors.New("invalid_profile")
		}
		if json.Unmarshal(raw, &node) != nil || node == nil || node["type"] != c.Protocol {
			return nil, errors.New("profile_type_mismatch")
		}
		if err := safeOutbound(node, c.WAN); err != nil {
			return nil, err
		}
		node["bind_interface"] = c.WAN
		node["routing_mark"] = bypassMark
	}
	node["tag"] = "selected"
	root := map[string]any{
		"log":      map[string]any{"disabled": true},
		"dns":      map[string]any{"servers": []any{map[string]any{"type": "udp", "tag": "bootstrap", "server": "77.88.8.8", "bind_interface": c.WAN, "routing_mark": bypassMark}}},
		"inbounds": []any{map[string]any{"type": "tproxy", "tag": "services", "listen": "0.0.0.0", "listen_port": proxyPort}, map[string]any{"type": "mixed", "tag": "local-dns", "listen": "127.0.0.1", "listen_port": socksPort}},
		"route":    map[string]any{"default_interface": c.WAN, "default_domain_resolver": "bootstrap", "final": "selected"},
	}
	root["outbounds"] = []any{node}
	return json.MarshalIndent(root, "", "  ")
}

type dnsProvider struct{ IP, Host, Path string }

var dnsProviders = map[string]dnsProvider{
	"cloudflare": {"1.1.1.1", "cloudflare-dns.com", "/dns-query"},
	"google":     {"8.8.8.8", "dns.google", "/dns-query"},
	"quad9":      {"9.9.9.9", "dns.quad9.net", "/dns-query"},
}

func jsonNative(s nativeAWGSettings) (json.RawMessage, error) { return json.Marshal(s) }
