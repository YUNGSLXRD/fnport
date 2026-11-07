package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

func looksLikeAWGConf(text string) bool {
	for _, line := range strings.Split(strings.TrimPrefix(text, "\ufeff"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		return strings.EqualFold(line, "[Interface]")
	}
	return false
}

// Exported INI configs are converted in memory. Never execute wg-quick hooks or
// include user-supplied lines, keys, endpoints or parser diagnostics in errors.
func importAWGConf(text string) (json.RawMessage, error) {
	out := map[string]any{}
	section := ""
	seen := map[string]bool{}
	hasInterface, hasPeer := false, false
	fail := func(line int) (json.RawMessage, error) {
		return nil, fmt.Errorf("неподдерживаемая или некорректная строка конфигурации AmneziaWG: %d", line)
	}
	for i, line := range strings.Split(strings.TrimPrefix(text, "\ufeff"), "\n") {
		line, _, _ = strings.Cut(line, "#")
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			switch strings.ToLower(line) {
			case "[interface]":
				if hasInterface || hasPeer {
					return fail(i + 1)
				}
				hasInterface = true
				section = "interface"
			case "[peer]":
				if !hasInterface || hasPeer {
					return nil, errors.New("поддерживается один раздел Interface и один Peer AmneziaWG")
				}
				hasPeer = true
				section = "peer"
			default:
				return fail(i + 1)
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key, value = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(value)
		id := section + "." + key
		if !ok || value == "" || seen[id] {
			return fail(i + 1)
		}
		seen[id] = true
		numeric := func(target string, bits int) error {
			n, err := strconv.ParseUint(value, 10, bits)
			if err != nil {
				return errors.New("invalid number")
			}
			out[target] = n
			return nil
		}
		switch section + "." + key {
		case "interface.privatekey":
			out["private_key"] = value
		case "interface.address":
			for _, address := range strings.Split(value, ",") {
				address = strings.TrimSpace(address)
				var a netip.Addr
				if strings.Contains(address, "/") {
					p, err := netip.ParsePrefix(address)
					if err != nil {
						return fail(i + 1)
					}
					a = p.Addr()
				} else {
					var err error
					a, err = netip.ParseAddr(address)
					if err != nil {
						return fail(i + 1)
					}
				}
				if a.Is4() && out["address"] == nil {
					out["address"] = a.String()
				}
			}
		case "interface.mtu":
			if numeric("mtu", 16) != nil {
				return fail(i + 1)
			}
		case "interface.jc", "interface.jmin", "interface.jmax", "interface.s1", "interface.s2":
			if numeric(key, 32) != nil {
				return fail(i + 1)
			}
		case "interface.h1", "interface.h2", "interface.h3", "interface.h4":
			if numeric(key, 32) != nil {
				return nil, errors.New("H1–H4 должны быть числами; диапазоны AmneziaWG 2.0 пока не поддерживаются")
			}
		case "interface.i1", "interface.i2", "interface.i3", "interface.i4", "interface.i5":
			out[key] = value
		case "interface.s3", "interface.s4":
			if value != "0" {
				return nil, errors.New("параметры S3/S4 AmneziaWG 2.0 пока не поддерживаются")
			}
		case "interface.dns": // Per-process routing keeps the PC's DNS configuration.
		case "peer.publickey":
			out["peer_key"] = value
		case "peer.presharedkey":
			out["preshared_key"] = value
		case "peer.endpoint":
			out["endpoint"] = value
		case "peer.persistentkeepalive":
			if numeric("persistent_keepalive", 16) != nil {
				return fail(i + 1)
			}
		case "peer.allowedips":
			for _, prefix := range strings.Split(value, ",") {
				if _, err := netip.ParsePrefix(strings.TrimSpace(prefix)); err != nil {
					return fail(i + 1)
				}
			}
		default:
			return fail(i + 1)
		}
	}
	if !hasInterface || !hasPeer {
		return nil, errors.New("нужны разделы Interface и Peer AmneziaWG")
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return nil, errors.New("не удалось прочитать конфигурацию AmneziaWG")
	}
	if err = validateNativeAWG(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func validateAWGEndpoint(value string) bool {
	host, port, err := net.SplitHostPort(value)
	if err != nil || host == "" {
		return false
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return false
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return a.Is4()
	}
	if len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
