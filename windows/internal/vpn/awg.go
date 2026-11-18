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

// AWGHeader represents an AmneziaWG packet header identifier: either a single uint32 ("123")
// or an AmneziaWG 2.0/3.0 inclusive range ("100000-200000"). Single numbers marshal as JSON
// integers for backward compatibility; ranges marshal as JSON strings.
type AWGHeader string

func (h AWGHeader) MarshalJSON() ([]byte, error) {
	s := strings.TrimSpace(string(h))
	if s == "" {
		return []byte("0"), nil
	}
	if n, err := strconv.ParseUint(s, 10, 32); err == nil {
		return []byte(strconv.FormatUint(n, 10)), nil
	}
	return json.Marshal(s)
}

func (h *AWGHeader) UnmarshalJSON(b []byte) error {
	trimmed := bytes.TrimSpace(b)
	if bytes.Equal(trimmed, []byte("null")) {
		*h = ""
		return nil
	}
	if len(trimmed) > 0 && trimmed[0] == '"' {
		var s string
		if err := json.Unmarshal(trimmed, &s); err != nil {
			return err
		}
		*h = AWGHeader(strings.TrimSpace(s))
		return nil
	}
	var n uint32
	if err := json.Unmarshal(trimmed, &n); err != nil {
		return err
	}
	if n == 0 {
		*h = ""
	} else {
		*h = AWGHeader(strconv.FormatUint(uint64(n), 10))
	}
	return nil
}

// ParseUintRange parses a single uint32 ("123") or an inclusive range ("123-456") with lo <= hi.
func ParseUintRange(value string) (canon string, lo, hi uint32, err error) {
	s := strings.TrimSpace(value)
	if s == "" {
		return "", 0, 0, errors.New("empty_range")
	}
	if loStr, hiStr, ok := strings.Cut(s, "-"); ok {
		if strings.Contains(hiStr, "-") {
			return "", 0, 0, errors.New("invalid_range")
		}
		l, err1 := strconv.ParseUint(strings.TrimSpace(loStr), 10, 32)
		r, err2 := strconv.ParseUint(strings.TrimSpace(hiStr), 10, 32)
		if err1 != nil || err2 != nil || l > r {
			return "", 0, 0, errors.New("invalid_range")
		}
		lo, hi = uint32(l), uint32(r)
	} else {
		v, e := strconv.ParseUint(s, 10, 32)
		if e != nil {
			return "", 0, 0, errors.New("invalid_range")
		}
		lo, hi = uint32(v), uint32(v)
	}
	if lo == hi {
		return strconv.FormatUint(uint64(lo), 10), lo, hi, nil
	}
	return fmt.Sprintf("%d-%d", lo, hi), lo, hi, nil
}

// AWGConfig holds native AmneziaWG (1.5 / 2.0 / 3.0) or standard WireGuard parameters.
// Standard WireGuard uses Jc=0, S1..S4=0, H1="1", H2="2", H3="3", H4="4".
type AWGConfig struct {
	MTU                    int       `json:"mtu,omitempty"`
	Keepalive              *int      `json:"persistent_keepalive,omitempty"`
	KeepaliveRange         string    `json:"persistent_keepalive_range,omitempty"`
	PrivateKey             string    `json:"private_key"`
	Address                string    `json:"address"`
	PeerKey                string    `json:"peer_key"`
	Endpoint               string    `json:"endpoint"`
	PresharedKey           string    `json:"preshared_key,omitempty"`
	Jc                     int       `json:"jc"`
	Jmin                   int       `json:"jmin"`
	Jmax                   int       `json:"jmax"`
	S1                     int       `json:"s1"`
	S2                     int       `json:"s2"`
	S3                     int       `json:"s3,omitempty"`
	S4                     int       `json:"s4,omitempty"`
	H1                     AWGHeader `json:"h1"`
	H2                     AWGHeader `json:"h2"`
	H3                     AWGHeader `json:"h3"`
	H4                     AWGHeader `json:"h4"`
	I1                     string    `json:"i1,omitempty"`
	I2                     string    `json:"i2,omitempty"`
	I3                     string    `json:"i3,omitempty"`
	I4                     string    `json:"i4,omitempty"`
	I5                     string    `json:"i5,omitempty"`
	HeaderProtectionKey    string    `json:"header_protection_key,omitempty"`
	ContentPaddingAddition string    `json:"content_padding_addition,omitempty"`
	RandomTrailers         bool      `json:"random_trailers,omitempty"`
	DisableCookies         bool      `json:"disable_cookies,omitempty"`
	RekeyAfterTime         string    `json:"rekey_after_time,omitempty"`
	RekeyTimeout           string    `json:"rekey_timeout,omitempty"`
	RejectAfterTime        string    `json:"reject_after_time,omitempty"`
	KeepaliveTimeout       string    `json:"keepalive_timeout,omitempty"`
	MaxHandshakeAttempts   string    `json:"max_handshake_attempts,omitempty"`
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

// B64OrHexKey32 decodes either a 32-byte base64 key or a 64-char hex key into 64-char lowercase hex.
func B64OrHexKey32(s string) (string, error) {
	s = strings.TrimSpace(s)
	if h, err := B64ToHexKey(s); err == nil {
		return h, nil
	}
	if len(s) == 64 {
		if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
			return hex.EncodeToString(b), nil
		}
	}
	return "", errors.New("invalid_key_32")
}

func isZeroHex(h string) bool {
	for i := 0; i < len(h); i++ {
		if h[i] != '0' {
			return false
		}
	}
	return len(h) > 0
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

func isZeroHeader(h AWGHeader) bool {
	s := strings.TrimSpace(string(h))
	return s == "" || s == "0"
}

// HasCustomParameters reports whether s uses non-WireGuard AmneziaWG header/padding/obfuscation extensions.
func (s AWGConfig) HasCustomParameters() bool {
	h1, h2, h3, h4 := s.H1, s.H2, s.H3, s.H4
	if isZeroHeader(h1) && isZeroHeader(h2) && isZeroHeader(h3) && isZeroHeader(h4) {
		h1, h2, h3, h4 = "1", "2", "3", "4"
	}
	return s.S1 != 0 || s.S2 != 0 || s.S3 != 0 || s.S4 != 0 ||
		h1 != "1" || h2 != "2" || h3 != "3" || h4 != "4" ||
		s.I2 != "" || s.I3 != "" || s.I4 != "" || s.I5 != "" ||
		s.HeaderProtectionKey != "" || s.ContentPaddingAddition != "" ||
		s.RandomTrailers || s.DisableCookies ||
		s.RekeyAfterTime != "" || s.RekeyTimeout != "" ||
		s.RejectAfterTime != "" || s.KeepaliveTimeout != "" || s.MaxHandshakeAttempts != ""
}

// Validate validates an AWGConfig without leaking key material in errors.
func (s *AWGConfig) Validate(requireEndpoint bool) error {
	if isZeroHeader(s.H1) && isZeroHeader(s.H2) && isZeroHeader(s.H3) && isZeroHeader(s.H4) {
		s.H1, s.H2, s.H3, s.H4 = "1", "2", "3", "4"
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
	if s.KeepaliveRange != "" {
		canon, _, hi, err := ParseUintRange(s.KeepaliveRange)
		if err != nil || hi > 65535 {
			return errors.New("некорректный PersistentKeepalive")
		}
		s.KeepaliveRange = canon
	}
	if s.Jc < 0 || s.Jc > 128 || s.Jmin < 0 || s.Jmax < s.Jmin || s.Jmax > 1280 ||
		s.S1 < 0 || s.S1 > 1024 || s.S2 < 0 || s.S2 > 1024 || s.S3 < 0 || s.S3 > 1024 || s.S4 < 0 || s.S4 > 1024 {
		return errors.New("некорректные параметры обфускации AmneziaWG")
	}

	var hBounds [4][2]uint32
	hdrPtrs := [4]*AWGHeader{&s.H1, &s.H2, &s.H3, &s.H4}
	for idx, hp := range hdrPtrs {
		canon, lo, hi, err := ParseUintRange(string(*hp))
		if err != nil {
			return errors.New("некорректные заголовки H1–H4 AmneziaWG")
		}
		*hp = AWGHeader(canon)
		hBounds[idx] = [2]uint32{lo, hi}
	}
	for i := 0; i < 4; i++ {
		for j := i + 1; j < 4; j++ {
			if hBounds[i][0] <= hBounds[j][1] && hBounds[j][0] <= hBounds[i][1] {
				return errors.New("диапазоны заголовков H1–H4 AmneziaWG не должны пересекаться")
			}
		}
	}

	if s.HeaderProtectionKey != "" {
		hpHex, err := B64OrHexKey32(s.HeaderProtectionKey)
		if err != nil {
			return errors.New("проверьте HeaderProtectionKey конфигурации AmneziaWG")
		}
		if !isZeroHex(hpHex) && (s.S1 < 12 || s.S2 < 12 || s.S3 < 12 || s.S4 < 12) {
			return errors.New("при использовании HeaderProtectionKey параметры S1–S4 должны быть не меньше 12")
		}
	}
	if s.ContentPaddingAddition != "" {
		canon, _, hi, err := ParseUintRange(s.ContentPaddingAddition)
		if err != nil || hi > 1024 {
			return errors.New("некорректный ContentPaddingAddition конфигурации AmneziaWG")
		}
		s.ContentPaddingAddition = canon
	}
	for _, tp := range []*string{&s.RekeyAfterTime, &s.RekeyTimeout, &s.RejectAfterTime, &s.KeepaliveTimeout, &s.MaxHandshakeAttempts} {
		if *tp != "" {
			canon, lo, hi, err := ParseUintRange(*tp)
			if err != nil || lo == 0 || hi > 86400 {
				return errors.New("некорректные тайминги конфигурации AmneziaWG")
			}
			*tp = canon
		}
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

var packetTagRe = regexp.MustCompile(`^<(b|r|rc|rd|wt|c|t)(?:[ \t]+([^<>]+))?>`)

// ValidPacketTemplate validates an AmneziaWG 1.5 / 2.0 / 3.0 CPS signature template before
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
		case "r", "rc", "rd", "wt":
			n, err := strconv.Atoi(param)
			if err != nil || n < 0 {
				return false
			}
			if kind == "wt" {
				if n > 5000 {
					return false
				}
				wait += n
			} else {
				if n > 1000 {
					return false
				}
				size += n
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

// NormalizePacketTemplateForV3 adapts legacy AmneziaWG 1.5 CPS tags (<c> and <wt N>)
// to amneziawg-go/v3's obfChain syntax while preserving packet byte length.
func NormalizePacketTemplateForV3(value string) string {
	if value == "" {
		return ""
	}
	var out strings.Builder
	rem := value
	for rem != "" {
		m := packetTagRe.FindStringSubmatch(rem)
		if m == nil {
			out.WriteString(rem)
			break
		}
		kind := m[1]
		switch kind {
		case "c":
			out.WriteString("<r 8>")
		case "wt":
			// Stripped: v3 executes stateless obfChain generation without sleep tags.
		default:
			out.WriteString(m[0])
		}
		rem = rem[len(m[0]):]
	}
	return out.String()
}

// DeviceIPC formats the UAPI device configuration lines for amneziawg-go/v3.
func (s AWGConfig) DeviceIPC(privHex string) string {
	h1, h2, h3, h4 := s.H1, s.H2, s.H3, s.H4
	if isZeroHeader(h1) && isZeroHeader(h2) && isZeroHeader(h3) && isZeroHeader(h4) {
		h1, h2, h3, h4 = "1", "2", "3", "4"
	}
	var b strings.Builder
	if privHex != "" {
		fmt.Fprintf(&b, "private_key=%s\n", privHex)
	}
	fmt.Fprintf(&b, "jc=%d\njmin=%d\njmax=%d\ns1=%d\ns2=%d\ns3=%d\ns4=%d\nh1=%s\nh2=%s\nh3=%s\nh4=%s\n",
		s.Jc, s.Jmin, s.Jmax, s.S1, s.S2, s.S3, s.S4, h1, h2, h3, h4)
	if s.HeaderProtectionKey != "" {
		if hpHex, err := B64OrHexKey32(s.HeaderProtectionKey); err == nil {
			fmt.Fprintf(&b, "header_protection_key=%s\n", hpHex)
		}
	}
	if s.ContentPaddingAddition != "" {
		fmt.Fprintf(&b, "content_padding_addition=%s\n", s.ContentPaddingAddition)
	}
	if s.RandomTrailers {
		b.WriteString("random_trailers=true\n")
	}
	if s.DisableCookies {
		b.WriteString("disable_cookies=true\n")
	}
	if s.RekeyAfterTime != "" {
		fmt.Fprintf(&b, "rekey_after_time=%s\n", s.RekeyAfterTime)
	}
	if s.RekeyTimeout != "" {
		fmt.Fprintf(&b, "rekey_timeout=%s\n", s.RekeyTimeout)
	}
	if s.RejectAfterTime != "" {
		fmt.Fprintf(&b, "reject_after_time=%s\n", s.RejectAfterTime)
	}
	if s.KeepaliveTimeout != "" {
		fmt.Fprintf(&b, "keepalive_timeout=%s\n", s.KeepaliveTimeout)
	}
	if s.MaxHandshakeAttempts != "" {
		fmt.Fprintf(&b, "max_handshake_attempts=%s\n", s.MaxHandshakeAttempts)
	}
	for i, v := range []string{s.I1, s.I2, s.I3, s.I4, s.I5} {
		if norm := NormalizePacketTemplateForV3(v); norm != "" {
			fmt.Fprintf(&b, "i%d=%s\n", i+1, norm)
		}
	}
	return b.String()
}

// PeerIPC formats the UAPI peer configuration lines for amneziawg-go/v3.
func (s AWGConfig) PeerIPC(peerHex, endpoint string, defaultKeepalive int) string {
	keepalive := strconv.Itoa(defaultKeepalive)
	if s.KeepaliveRange != "" {
		keepalive = s.KeepaliveRange
	} else if s.Keepalive != nil {
		keepalive = strconv.Itoa(*s.Keepalive)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "replace_peers=true\npublic_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=%s\n",
		peerHex, endpoint, keepalive)
	if s.PresharedKey != "" {
		if psk, err := B64ToHexKey(s.PresharedKey); err == nil {
			fmt.Fprintf(&b, "preshared_key=%s\n", psk)
		}
	}
	return b.String()
}

// ParseAWGJSON parses and validates an AWGConfig JSON object.
func ParseAWGJSON(raw json.RawMessage) (AWGConfig, error) {
	return parseAWGJSONInternal(raw, true)
}

func parseAWGJSONInternal(raw json.RawMessage, requireEndpoint bool) (AWGConfig, error) {
	s := AWGConfig{H1: "1", H2: "2", H3: "3", H4: "4"}
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

// ParseWGConf parses an exported WireGuard or AmneziaWG (1.5 / 2.0 / 3.0) .conf file in memory.
// wg-quick shell hooks (PreUp/PostUp/PreDown/PostDown) and client table fields are rejected or ignored, never executed.
func ParseWGConf(text string) (AWGConfig, error) {
	return parseWGConfInternal(text, true)
}

func normalizeAWGKey(section, key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	if section == "interface" {
		switch key {
		case "headerprotectionkey":
			key = "header_protection_key"
		case "contentpaddingaddition":
			key = "content_padding_addition"
		case "randomtrailers":
			key = "random_trailers"
		case "disablecookies":
			key = "disable_cookies"
		case "rekeyaftertime":
			key = "rekey_after_time"
		case "rekeytimeout":
			key = "rekey_timeout"
		case "rejectaftertime":
			key = "reject_after_time"
		case "keepalivetimeout":
			key = "keepalive_timeout"
		case "maxhandshakeattempts":
			key = "max_handshake_attempts"
		}
	}
	return section + "." + key
}

func parseWGConfInternal(text string, requireEndpoint bool) (AWGConfig, error) {
	cfg := AWGConfig{H1: "1", H2: "2", H3: "3", H4: "4"}
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
		id := normalizeAWGKey(section, key)
		value = strings.TrimSpace(value)

		// Standard wg-quick client routing/DNS fields are ignored; shell hooks are rejected.
		switch id {
		case "interface.dns", "interface.listenport", "interface.table", "interface.saveconfig", "interface.fwmark":
			continue
		}
		if seen[id] {
			return fail(i + 1)
		}
		seen[id] = true

		// Optional AWG signature, padding, timing, and key fields are often exported with empty values ("I2 =").
		if value == "" {
			switch id {
			case "interface.i1", "interface.i2", "interface.i3", "interface.i4", "interface.i5",
				"interface.mtu", "interface.jc", "interface.jmin", "interface.jmax",
				"interface.s1", "interface.s2", "interface.s3", "interface.s4",
				"interface.h1", "interface.h2", "interface.h3", "interface.h4",
				"interface.header_protection_key", "interface.content_padding_addition",
				"interface.random_trailers", "interface.disable_cookies",
				"interface.rekey_after_time", "interface.rekey_timeout",
				"interface.reject_after_time", "interface.keepalive_timeout", "interface.max_handshake_attempts",
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
		case "interface.s3":
			n, err := parseUint(16)
			if err != nil {
				return fail(i + 1)
			}
			cfg.S3 = int(n)
		case "interface.s4":
			n, err := parseUint(16)
			if err != nil {
				return fail(i + 1)
			}
			cfg.S4 = int(n)
		case "interface.h1":
			canon, _, _, err := ParseUintRange(value)
			if err != nil {
				return AWGConfig{}, errors.New("некорректные заголовки H1–H4 AmneziaWG")
			}
			cfg.H1 = AWGHeader(canon)
		case "interface.h2":
			canon, _, _, err := ParseUintRange(value)
			if err != nil {
				return AWGConfig{}, errors.New("некорректные заголовки H1–H4 AmneziaWG")
			}
			cfg.H2 = AWGHeader(canon)
		case "interface.h3":
			canon, _, _, err := ParseUintRange(value)
			if err != nil {
				return AWGConfig{}, errors.New("некорректные заголовки H1–H4 AmneziaWG")
			}
			cfg.H3 = AWGHeader(canon)
		case "interface.h4":
			canon, _, _, err := ParseUintRange(value)
			if err != nil {
				return AWGConfig{}, errors.New("некорректные заголовки H1–H4 AmneziaWG")
			}
			cfg.H4 = AWGHeader(canon)
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
		case "interface.header_protection_key":
			cfg.HeaderProtectionKey = value
		case "interface.content_padding_addition":
			cfg.ContentPaddingAddition = value
		case "interface.random_trailers":
			bv, err := strconv.ParseBool(value)
			if err != nil {
				return fail(i + 1)
			}
			cfg.RandomTrailers = bv
		case "interface.disable_cookies":
			bv, err := strconv.ParseBool(value)
			if err != nil {
				return fail(i + 1)
			}
			cfg.DisableCookies = bv
		case "interface.rekey_after_time":
			cfg.RekeyAfterTime = value
		case "interface.rekey_timeout":
			cfg.RekeyTimeout = value
		case "interface.reject_after_time":
			cfg.RejectAfterTime = value
		case "interface.keepalive_timeout":
			cfg.KeepaliveTimeout = value
		case "interface.max_handshake_attempts":
			cfg.MaxHandshakeAttempts = value
		case "peer.publickey":
			cfg.PeerKey = value
		case "peer.presharedkey":
			cfg.PresharedKey = value
		case "peer.endpoint":
			cfg.Endpoint = value
		case "peer.persistentkeepalive":
			if n, err := parseUint(16); err == nil {
				kv := int(n)
				cfg.Keepalive = &kv
			} else if canon, _, hi, err := ParseUintRange(value); err == nil && hi <= 65535 {
				cfg.KeepaliveRange = canon
			} else {
				return fail(i + 1)
			}
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
	cfg := AWGConfig{H1: "1", H2: "2", H3: "3", H4: "4"}
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
	if c.S1 > 0 || c.S2 > 0 || c.S3 > 0 || c.S4 > 0 {
		fmt.Fprintf(&b, "S1 = %d\nS2 = %d\n", c.S1, c.S2)
		if c.S3 > 0 || c.S4 > 0 {
			fmt.Fprintf(&b, "S3 = %d\nS4 = %d\n", c.S3, c.S4)
		}
	}
	if !isZeroHeader(c.H1) && !(c.H1 == "1" && c.H2 == "2" && c.H3 == "3" && c.H4 == "4") {
		fmt.Fprintf(&b, "H1 = %s\nH2 = %s\nH3 = %s\nH4 = %s\n", c.H1, c.H2, c.H3, c.H4)
	}
	if c.HeaderProtectionKey != "" {
		b.WriteString("HeaderProtectionKey = " + c.HeaderProtectionKey + "\n")
	}
	if c.ContentPaddingAddition != "" {
		b.WriteString("ContentPaddingAddition = " + c.ContentPaddingAddition + "\n")
	}
	if c.RandomTrailers {
		b.WriteString("RandomTrailers = true\n")
	}
	if c.DisableCookies {
		b.WriteString("DisableCookies = true\n")
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
	if c.KeepaliveRange != "" {
		fmt.Fprintf(&b, "PersistentKeepalive = %s\n", c.KeepaliveRange)
	} else if c.Keepalive != nil && *c.Keepalive > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", *c.Keepalive)
	}
	return b.String()
}
