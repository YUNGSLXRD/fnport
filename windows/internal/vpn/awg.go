package vpn

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// AWGConfig holds native AmneziaWG 1.5 or standard WireGuard parameters.
// Standard WireGuard uses Jc=0, S1=0, S2=0, H1=1, H2=2, H3=3, H4=4.
type AWGConfig struct {
	MTU          int    `json:"mtu,omitempty"`
	Keepalive    *int   `json:"persistent_keepalive,omitempty"`
	PrivateKey   string `json:"private_key"`
	Address      string `json:"address"`
	PeerKey      string `json:"peer_key"`
	Endpoint     string `json:"endpoint"`
	PresharedKey string `json:"preshared_key,omitempty"`
	Jc           int    `json:"jc"`
	Jmin         int    `json:"jmin"`
	Jmax         int    `json:"jmax"`
	S1           int    `json:"s1"`
	S2           int    `json:"s2"`
	H1           uint32 `json:"h1"`
	H2           uint32 `json:"h2"`
	H3           uint32 `json:"h3"`
	H4           uint32 `json:"h4"`
	I1           string `json:"i1,omitempty"`
	I2           string `json:"i2,omitempty"`
	I3           string `json:"i3,omitempty"`
	I4           string `json:"i4,omitempty"`
	I5           string `json:"i5,omitempty"`
}

// B64ToHexKey decodes a 32-byte base64 WireGuard key and returns its 64-char hex form.
func B64ToHexKey(s string) (string, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == 32 {
			return hex.EncodeToString(b), nil
		}
	}
	return "", errors.New("invalid_wireguard_key")
}

// ValidateEndpoint checks that value is a valid IPv4:port or domain:port.
func ValidateEndpoint(value string) bool {
	host, port, err := net.SplitHostPort(strings.TrimSpace(value))
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

// Validate validates an AWGConfig without leaking key material in errors.
func (s *AWGConfig) Validate(requireEndpoint bool) error {
	if s.H1 == 0 && s.H2 == 0 && s.H3 == 0 && s.H4 == 0 {
		s.H1, s.H2, s.H3, s.H4 = 1, 2, 3, 4
	}
	if _, err := B64ToHexKey(s.PrivateKey); err != nil {
		return errors.New("проверьте PrivateKey конфигурации WireGuard / AmneziaWG")
	}
	if _, err := B64ToHexKey(s.PeerKey); err != nil {
		return errors.New("проверьте PublicKey пира WireGuard / AmneziaWG")
	}
	if s.PresharedKey != "" {
		if _, err := B64ToHexKey(s.PresharedKey); err != nil {
			return errors.New("проверьте PresharedKey конфигурации WireGuard / AmneziaWG")
		}
	}
	if a, err := netip.ParseAddr(strings.TrimSpace(s.Address)); err != nil || !a.Is4() || !a.IsGlobalUnicast() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return errors.New("в конфигурации нужен адрес IPv4 (Address)")
	}
	if (requireEndpoint || s.Endpoint != "") && !ValidateEndpoint(s.Endpoint) {
		return errors.New("Endpoint должен быть вида IPv4:порт или домен:порт")
	}
	if s.MTU != 0 && (s.MTU < 576 || s.MTU > 1420) {
		return errors.New("MTU должен быть от 576 до 1420")
	}
	if s.Keepalive != nil && (*s.Keepalive < 0 || *s.Keepalive > 65535) {
		return errors.New("некорректный PersistentKeepalive")
	}
	if s.Jc < 0 || s.Jc > 128 || s.Jmin < 0 || s.Jmax < s.Jmin || s.Jmax > 1280 || s.S1 < 0 || s.S1 > 1024 || s.S2 < 0 || s.S2 > 1024 {
		return errors.New("некорректные параметры обфускации AmneziaWG")
	}
	missing := false
	for _, v := range []string{s.I1, s.I2, s.I3, s.I4, s.I5} {
		if v == "" {
			missing = true
			continue
		}
		if missing || !ValidPacketTemplate(v) {
			return errors.New("некорректные параметры обфускации I1–I5")
		}
	}
	return nil
}

var packetTagRe = regexp.MustCompile(`^<(b|r|wt|c|t)(?:[ \t]+([^<>]+))?>`)

// ValidPacketTemplate validates an AmneziaWG 1.5 CPS signature template before
// handing it to amneziawg-go, preventing malformed tag crashes or oversized allocations.
func ValidPacketTemplate(value string) bool {
	if len(value) > 4096 || strings.ContainsAny(value, "\r\n") {
		return false
	}
	size, wait := 0, 0
	unique := make(map[string]bool)
	for value != "" {
		m := packetTagRe.FindStringSubmatch(value)
		if m == nil {
			return false
		}
		kind, param := m[1], strings.TrimSpace(m[2])
		value = value[len(m[0]):]
		switch kind {
		case "b":
			if len(param) < 3 || !strings.HasPrefix(strings.ToLower(param), "0x") {
				return false
			}
			text := param[2:]
			if len(text)%2 != 0 {
				text = "0" + text
			}
			b, err := hex.DecodeString(text)
			if err != nil {
				return false
			}
			size += len(b)
		case "r", "wt":
			n, err := strconv.Atoi(param)
			if err != nil || n < 0 {
				return false
			}
			if kind == "r" {
				if n > 1000 {
					return false
				}
				size += n
			} else {
				if n > 5000 {
					return false
				}
				wait += n
			}
		case "c", "t":
			if param != "" || unique[kind] {
				return false
			}
			unique[kind] = true
			size += 8
		}
		if size > 1500 || wait > 5000 {
			return false
		}
	}
	return size > 0
}

// ParseAWGJSON parses and validates an AWGConfig JSON object.
func ParseAWGJSON(raw json.RawMessage) (AWGConfig, error) {
	return parseAWGJSONInternal(raw, true)
}

func parseAWGJSONInternal(raw json.RawMessage, requireEndpoint bool) (AWGConfig, error) {
	s := AWGConfig{H1: 1, H2: 2, H3: 3, H4: 4}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&s) != nil || d.Decode(new(any)) != io.EOF {
		return s, errors.New("нужна конфигурация WireGuard / AmneziaWG (.conf или JSON)")
	}
	if err := s.Validate(requireEndpoint); err != nil {
		return s, err
	}
	return s, nil
}

// LooksLikeWGConf reports whether text starts with a WireGuard/AmneziaWG [Interface] section.
func LooksLikeWGConf(text string) bool {
	for _, line := range strings.Split(strings.TrimPrefix(text, "\ufeff"), "\n") {
		line, _, _ = strings.Cut(line, "#")
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		return strings.EqualFold(line, "[Interface]")
	}
	return false
}

// ParseWGConf parses an exported WireGuard or AmneziaWG 1.5 .conf file in memory.
// wg-quick shell hooks (PreUp/PostUp/PreDown/PostDown) and client table fields are ignored, never executed.
func ParseWGConf(text string) (AWGConfig, error) {
	return parseWGConfInternal(text, true)
}

func parseWGConfInternal(text string, requireEndpoint bool) (AWGConfig, error) {
	cfg := AWGConfig{H1: 1, H2: 2, H3: 3, H4: 4}
	section := ""
	seen := make(map[string]bool)
	hasInterface, hasPeer := false, false
	fail := func(line int) (AWGConfig, error) {
		return AWGConfig{}, fmt.Errorf("некорректная строка конфигурации WireGuard / AmneziaWG: %d", line)
	}

	for i, rawLine := range strings.Split(strings.TrimPrefix(text, "\ufeff"), "\n") {
		line, _, _ := strings.Cut(rawLine, "#")
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
					return AWGConfig{}, errors.New("поддерживается один раздел [Interface] и один [Peer]")
				}
				hasPeer = true
				section = "peer"
			default:
				return fail(i + 1)
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || section == "" {
			return fail(i + 1)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		id := section + "." + key

		// Standard wg-quick client routing/DNS fields are ignored; shell hooks are rejected.
		switch id {
		case "interface.dns", "interface.listenport", "interface.table", "interface.saveconfig", "interface.fwmark":
			continue
		}
		if seen[id] {
			return fail(i + 1)
		}
		seen[id] = true

		// Optional AWG signature and key fields are often exported with empty values ("I2 =").
		if value == "" {
			switch id {
			case "interface.i1", "interface.i2", "interface.i3", "interface.i4", "interface.i5",
				"interface.mtu", "interface.jc", "interface.jmin", "interface.jmax", "interface.s1", "interface.s2",
				"peer.presharedkey", "peer.persistentkeepalive", "peer.allowedips":
				continue
			}
			return fail(i + 1)
		}

		parseUint := func(bits int) (uint64, error) {
			return strconv.ParseUint(value, 10, bits)
		}

		switch id {
		case "interface.privatekey":
			cfg.PrivateKey = value
		case "interface.address":
			for _, addrStr := range strings.Split(value, ",") {
				addrStr = strings.TrimSpace(addrStr)
				if addrStr == "" {
					continue
				}
				var a netip.Addr
				if strings.Contains(addrStr, "/") {
					p, err := netip.ParsePrefix(addrStr)
					if err != nil {
						return fail(i + 1)
					}
					a = p.Addr()
				} else {
					var err error
					a, err = netip.ParseAddr(addrStr)
					if err != nil {
						return fail(i + 1)
					}
				}
				if a.Is4() && cfg.Address == "" {
					cfg.Address = a.String()
				}
			}
		case "interface.mtu":
			n, err := parseUint(16)
			if err != nil {
				return fail(i + 1)
			}
			cfg.MTU = int(n)
		case "interface.jc":
			n, err := parseUint(16)
			if err != nil {
				return fail(i + 1)
			}
			cfg.Jc = int(n)
		case "interface.jmin":
			n, err := parseUint(16)
			if err != nil {
				return fail(i + 1)
			}
			cfg.Jmin = int(n)
		case "interface.jmax":
			n, err := parseUint(16)
			if err != nil {
				return fail(i + 1)
			}
			cfg.Jmax = int(n)
		case "interface.s1":
			n, err := parseUint(16)
			if err != nil {
				return fail(i + 1)
			}
			cfg.S1 = int(n)
		case "interface.s2":
			n, err := parseUint(16)
			if err != nil {
				return fail(i + 1)
			}
			cfg.S2 = int(n)
		case "interface.s3", "interface.s4":
			if value != "0" {
				return AWGConfig{}, errors.New("параметры S3/S4 AmneziaWG 2.0 пока не поддерживаются")
			}
		case "interface.h1":
			n, err := parseUint(32)
			if err != nil {
				return AWGConfig{}, errors.New("H1–H4 должны быть числами; диапазоны AmneziaWG 2.0 пока не поддерживаются")
			}
			cfg.H1 = uint32(n)
		case "interface.h2":
			n, err := parseUint(32)
			if err != nil {
				return AWGConfig{}, errors.New("H1–H4 должны быть числами; диапазоны AmneziaWG 2.0 пока не поддерживаются")
			}
			cfg.H2 = uint32(n)
		case "interface.h3":
			n, err := parseUint(32)
			if err != nil {
				return AWGConfig{}, errors.New("H1–H4 должны быть числами; диапазоны AmneziaWG 2.0 пока не поддерживаются")
			}
			cfg.H3 = uint32(n)
		case "interface.h4":
			n, err := parseUint(32)
			if err != nil {
				return AWGConfig{}, errors.New("H1–H4 должны быть числами; диапазоны AmneziaWG 2.0 пока не поддерживаются")
			}
			cfg.H4 = uint32(n)
		case "interface.i1":
			cfg.I1 = value
		case "interface.i2":
			cfg.I2 = value
		case "interface.i3":
			cfg.I3 = value
		case "interface.i4":
			cfg.I4 = value
		case "interface.i5":
			cfg.I5 = value
		case "peer.publickey":
			cfg.PeerKey = value
		case "peer.presharedkey":
			cfg.PresharedKey = value
		case "peer.endpoint":
			cfg.Endpoint = value
		case "peer.persistentkeepalive":
			n, err := parseUint(16)
			if err != nil {
				return fail(i + 1)
			}
			kv := int(n)
			cfg.Keepalive = &kv
		case "peer.allowedips":
			for _, prefix := range strings.Split(value, ",") {
				prefix = strings.TrimSpace(prefix)
				if prefix == "" {
					continue
				}
				if _, err := netip.ParsePrefix(prefix); err != nil {
					return fail(i + 1)
				}
			}
		default:
			return fail(i + 1)
		}
	}
	if !hasInterface || !hasPeer {
		return AWGConfig{}, errors.New("в конфигурации нужны разделы [Interface] и [Peer]")
	}
	if err := cfg.Validate(requireEndpoint); err != nil {
		return AWGConfig{}, err
	}
	return cfg, nil
}

// ParseWARPConf parses a WireGuard or AmneziaWG config intended for Cloudflare WARP,
// filling default junk packet parameters (Jc=4, Jmin=40, Jmax=70) when absent.
func ParseWARPConf(text string, defJc, defJmin, defJmax int) (AWGConfig, error) {
	var cfg AWGConfig
	var err error
	trimmed := strings.TrimSpace(text)
	if strings.HasPrefix(trimmed, "{") {
		cfg, err = parseAWGJSONInternal(json.RawMessage(trimmed), false)
	} else if LooksLikeWGConf(trimmed) {
		cfg, err = parseWGConfInternal(trimmed, false)
	} else {
		// Also accept bare key=value lines without section headers (legacy WARP paste).
		cfg, err = parseLooseWARPConf(trimmed)
	}
	if err != nil {
		return AWGConfig{}, err
	}
	if cfg.Jc == 0 {
		if defJc <= 0 {
			defJc, defJmin, defJmax = 4, 40, 70
		}
		cfg.Jc, cfg.Jmin, cfg.Jmax = defJc, defJmin, defJmax
	}
	// Resolve engage.cloudflareclient.com to blank so WARP probes Russia-working endpoints.
	if strings.HasPrefix(strings.ToLower(cfg.Endpoint), "engage.cloudflareclient.com:") {
		cfg.Endpoint = ""
	}
	return cfg, nil
}

func parseLooseWARPConf(text string) (AWGConfig, error) {
	cfg := AWGConfig{H1: 1, H2: 2, H3: 3, H4: 4}
	for _, line := range strings.Split(strings.TrimPrefix(text, "\ufeff"), "\n") {
		line, _, _ = strings.Cut(line, "#")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		num := func(d int) int {
			if n, err := strconv.Atoi(v); err == nil {
				return n
			}
			return d
		}
		switch k {
		case "privatekey":
			cfg.PrivateKey = v
		case "publickey":
			cfg.PeerKey = v
		case "address":
			for _, part := range strings.Split(v, ",") {
				part = strings.TrimSpace(strings.Split(part, "/")[0])
				if a, err := netip.ParseAddr(part); err == nil && a.Is4() {
					cfg.Address = a.String()
					break
				}
			}
		case "endpoint":
			if _, err := netip.ParseAddrPort(v); err == nil {
				cfg.Endpoint = v
			}
		case "mtu":
			cfg.MTU = num(cfg.MTU)
		case "jc":
			cfg.Jc = num(cfg.Jc)
		case "jmin":
			cfg.Jmin = num(cfg.Jmin)
		case "jmax":
			cfg.Jmax = num(cfg.Jmax)
		case "i1":
			cfg.I1 = v
		}
	}
	if err := cfg.Validate(false); err != nil {
		return AWGConfig{}, err
	}
	return cfg, nil
}

// ImportAWG parses either an INI .conf or JSON representation into canonical AWGConfig JSON.
func ImportAWG(text string) (AWGConfig, json.RawMessage, error) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return AWGConfig{}, nil, errors.New("вставьте конфигурацию .conf или импортируйте файл")
	}
	var cfg AWGConfig
	var err error
	if LooksLikeWGConf(trimmed) {
		cfg, err = ParseWGConf(trimmed)
	} else {
		cfg, err = ParseAWGJSON(json.RawMessage(trimmed))
	}
	if err != nil {
		return AWGConfig{}, nil, err
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return AWGConfig{}, nil, errors.New("не удалось сохранить конфигурацию WireGuard / AmneziaWG")
	}
	return cfg, raw, nil
}

// FormatWGConf renders an AWGConfig as a clean INI .conf for display in the editor.
func FormatWGConf(c AWGConfig) string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	if c.PrivateKey != "" {
		b.WriteString("PrivateKey = " + c.PrivateKey + "\n")
	}
	if c.Address != "" {
		b.WriteString("Address = " + c.Address + "/32\n")
	}
	if c.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", c.MTU)
	}
	if c.Jc > 0 {
		fmt.Fprintf(&b, "Jc = %d\nJmin = %d\nJmax = %d\n", c.Jc, c.Jmin, c.Jmax)
	}
	if c.S1 > 0 || c.S2 > 0 {
		fmt.Fprintf(&b, "S1 = %d\nS2 = %d\n", c.S1, c.S2)
	}
	if c.H1 != 0 && !(c.H1 == 1 && c.H2 == 2 && c.H3 == 3 && c.H4 == 4) {
		fmt.Fprintf(&b, "H1 = %d\nH2 = %d\nH3 = %d\nH4 = %d\n", c.H1, c.H2, c.H3, c.H4)
	}
	for idx, val := range []string{c.I1, c.I2, c.I3, c.I4, c.I5} {
		if val != "" {
			fmt.Fprintf(&b, "I%d = %s\n", idx+1, val)
		}
	}
	b.WriteString("\n[Peer]\n")
	if c.PeerKey != "" {
		b.WriteString("PublicKey = " + c.PeerKey + "\n")
	}
	if c.PresharedKey != "" {
		b.WriteString("PresharedKey = " + c.PresharedKey + "\n")
	}
	if c.Endpoint != "" {
		b.WriteString("Endpoint = " + c.Endpoint + "\n")
	}
	b.WriteString("AllowedIPs = 0.0.0.0/0\n")
	if c.Keepalive != nil && *c.Keepalive > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", *c.Keepalive)
	}
	return b.String()
}
