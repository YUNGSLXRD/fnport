package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
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
	if a, err := netip.ParseAddr(s.Address); err != nil || !a.Is4() {
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
	for _, v := range []string{s.I1, s.I2, s.I3, s.I4, s.I5} {
		if strings.ContainsAny(v, "\r\n") {
			return s, errors.New("параметры I1–I5 должны занимать одну строку")
		}
	}
	return s, nil
}

func validateNativeAWG(raw json.RawMessage) error { _, err := parseNativeAWG(raw); return err }

func nativeAWGConfig(raw json.RawMessage) (*warpTunnel, error) {
	s, err := parseNativeAWG(raw)
	if err != nil {
		return nil, err
	}
	w, err := newWarpDev(warpSettings{exclusive: true, PrivateKey: s.PrivateKey, Address: s.Address, PeerKey: s.PeerKey, Jc: s.Jc, Jmin: s.Jmin, Jmax: s.Jmax, MTU: s.MTU})
	if err != nil {
		return nil, errors.New("не удалось создать устройство AmneziaWG")
	}
	cfg := fmt.Sprintf("s1=%d\ns2=%d\nh1=%d\nh2=%d\nh3=%d\nh4=%d\n", s.S1, s.S2, s.H1, s.H2, s.H3, s.H4)
	for i, v := range []string{s.I1, s.I2, s.I3, s.I4, s.I5} {
		if v != "" {
			cfg += fmt.Sprintf("i%d=%s\n", i+1, v)
		}
	}
	if err := w.dev.IpcSet(cfg); err != nil {
		w.close()
		return nil, errors.New("не приняты параметры AmneziaWG 1.5")
	}
	endpoint := s.Endpoint
	host, port, _ := net.SplitHostPort(endpoint)
	if _, err := netip.ParseAddr(host); err != nil {
		ips := lookupAll(host)
		if len(ips) == 0 {
			w.close()
			return nil, errors.New("не найден IPv4 сервера AmneziaWG")
		}
		endpoint = net.JoinHostPort(ips[0].String(), port)
	}
	keepalive := 15
	if s.Keepalive != nil {
		keepalive = *s.Keepalive
	}
	peerCfg := "replace_peers=true\npublic_key=" + w.peer + "\nendpoint=" + endpoint + "\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=" + strconv.Itoa(keepalive) + "\n"
	if s.PresharedKey != "" {
		key, _ := b64hex(s.PresharedKey)
		peerCfg += "preshared_key=" + key + "\n"
	}
	if err := w.dev.IpcSet(peerCfg); err != nil {
		w.close()
		return nil, errors.New("не приняты параметры пира AmneziaWG")
	}

	return w, nil
}
