package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/YUNGSLXRD/fnport/windows/internal/vpn"
)

type nativeAWGSettings = vpn.AWGConfig

func parseNativeAWG(raw json.RawMessage) (nativeAWGSettings, error) {
	return vpn.ParseAWGJSON(raw)
}

func validateNativeAWG(raw json.RawMessage) error {
	_, err := vpn.ParseAWGJSON(raw)
	return err
}

func looksLikeAWGConf(text string) bool {
	return vpn.LooksLikeWGConf(text)
}

func importAWGConf(text string) (json.RawMessage, error) {
	_, raw, err := vpn.ImportAWG(text)
	return raw, err
}

func nativeAWGConfig(raw json.RawMessage, set settings, ttlNow func() int) (*warpTunnel, error) {
	s, err := vpn.ParseAWGJSON(raw)
	if err != nil {
		return nil, err
	}
	customHeaders := s.S1 != 0 || s.S2 != 0 || s.H1 != 1 || s.H2 != 2 || s.H3 != 3 || s.H4 != 4 ||
		s.I2 != "" || s.I3 != "" || s.I4 != "" || s.I5 != ""
	ws := warpSettings{
		exclusive:  customHeaders,
		PrivateKey: s.PrivateKey,
		Address:    s.Address,
		PeerKey:    s.PeerKey,
		Jc:         s.Jc,
		Jmin:       s.Jmin,
		Jmax:       s.Jmax,
		MTU:        s.MTU,
		I1:         s.I1,
		ttlNow:     ttlNow,
	}.withFake(set)

	w, err := newWarpDev(ws)
	if err != nil {
		return nil, errors.New("не удалось создать устройство WireGuard / AmneziaWG")
	}
	if customHeaders {
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
	}

	endpoint := s.Endpoint
	host, port, _ := net.SplitHostPort(endpoint)
	if _, err := netip.ParseAddr(host); err != nil {
		ips := lookupAll(host)
		if len(ips) == 0 {
			w.close()
			return nil, errors.New("не найден адрес IPv4 сервера WireGuard / AmneziaWG")
		}
		endpoint = net.JoinHostPort(ips[0].String(), port)
	}
	keepalive := 15
	if s.Keepalive != nil {
		keepalive = *s.Keepalive
	}
	peerCfg := "replace_peers=true\npublic_key=" + w.peer + "\nendpoint=" + endpoint +
		"\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=" + strconv.Itoa(keepalive) + "\n"
	if s.PresharedKey != "" {
		key, _ := b64hex(s.PresharedKey)
		peerCfg += "preshared_key=" + key + "\n"
	}
	if err := w.dev.IpcSet(peerCfg); err != nil {
		w.close()
		return nil, errors.New("не приняты параметры пира WireGuard / AmneziaWG")
	}
	w.endpoint.Store(endpoint)
	return w, nil
}
