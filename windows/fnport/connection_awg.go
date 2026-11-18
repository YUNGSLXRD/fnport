package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/netip"

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
	customHeaders := s.HasCustomParameters()
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
		if err := w.dev.IpcSet(s.DeviceIPC("")); err != nil {
			w.close()
			return nil, errors.New("не приняты параметры AmneziaWG")
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
	if err := w.dev.IpcSet(s.PeerIPC(w.peer, endpoint, 15)); err != nil {
		w.close()
		return nil, errors.New("не приняты параметры пира WireGuard / AmneziaWG")
	}
	w.endpoint.Store(endpoint)
	return w, nil
}
