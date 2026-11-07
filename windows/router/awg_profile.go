package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// Native AWG 1.5, separate from Cloudflare endpoint discovery. This config must
// never be passed to sing-box's plain WireGuard endpoint.
type nativeAWGSettings struct {
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

func parseNativeAWG(raw json.RawMessage) (nativeAWGSettings, error) {
	s := nativeAWGSettings{H1: 1, H2: 2, H3: 3, H4: 4}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&s) != nil || d.Decode(new(any)) != io.EOF {
		return s, errors.New("нужен JSON конфигурации AmneziaWG 1.5; неизвестные параметры не поддерживаются")
	}
	if _, err := b64hex(s.PrivateKey); err != nil {
		return s, errors.New("проверьте private_key AmneziaWG")
	}
	if _, err := b64hex(s.PeerKey); err != nil {
		return s, errors.New("проверьте peer_key AmneziaWG")
	}
	if s.PresharedKey != "" {
		if _, err := b64hex(s.PresharedKey); err != nil {
			return s, errors.New("проверьте preshared_key AmneziaWG")
		}
	}
	if a, err := netip.ParseAddr(s.Address); err != nil || !a.Is4() || !a.IsGlobalUnicast() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return s, errors.New("address AmneziaWG должен быть IPv4 без маски")
	}
	if !validateAWGEndpoint(s.Endpoint) {
		return s, errors.New("endpoint AmneziaWG должен быть IPv4:порт или домен:порт")
	}
	if s.MTU != 0 && (s.MTU < 576 || s.MTU > 1420) {
		return s, errors.New("MTU AmneziaWG должен быть от 576 до 1420")
	}
	if s.Keepalive != nil && (*s.Keepalive < 0 || *s.Keepalive > 65535) {
		return s, errors.New("некорректный PersistentKeepalive AmneziaWG")
	}
	if s.Jc < 0 || s.Jc > 128 || s.Jmin < 0 || s.Jmax < s.Jmin || s.Jmax > 1280 || s.S1 < 0 || s.S1 > 1024 || s.S2 < 0 || s.S2 > 1024 {
		return s, errors.New("некорректные параметры пакетов AmneziaWG")
	}
	missing := false
	for _, v := range []string{s.I1, s.I2, s.I3, s.I4, s.I5} {
		if v == "" {
			missing = true
			continue
		}
		if missing || !validPacketTemplate(v) {
			return s, errors.New("invalid_native_packet_template")
		}
	}

	return s, nil
}

func validateNativeAWG(raw json.RawMessage) error { _, err := parseNativeAWG(raw); return err }

func b64hex(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return "", errors.New("invalid key")
	}
	return hex.EncodeToString(b), nil
}

var packetTag = regexp.MustCompile(`^<(b|r|wt|c|t)(?:[ \t]+([^<>]+))?>`)

func validPacketTemplate(value string) bool {
	if len(value) > 4096 {
		return false
	}
	size, wait := 0, 0
	unique := map[string]bool{}
	for value != "" {
		m := packetTag.FindStringSubmatch(value)
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
			b, e := hex.DecodeString(text)
			if e != nil {
				return false
			}
			size += len(b)
		case "r", "wt":
			n, e := strconv.Atoi(param)
			if e != nil || n < 0 {
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
