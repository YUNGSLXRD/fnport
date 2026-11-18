//go:build linux

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"time"

	"github.com/YUNGSLXRD/fnport/windows/internal/vpn"
	"golang.org/x/sys/unix"
)

const warpAPIHost = "api.cloudflareclient.com"

func wanResolver(wan string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := &net.Dialer{Control: boundSocket(wan, bypassMark), Timeout: 4 * time.Second}
			return d.DialContext(ctx, "udp4", "77.88.8.8:53")
		},
	}
}

func wanHTTPClient(wan string, timeout time.Duration) *http.Client {
	resolver := wanResolver(wan)
	dialer := &net.Dialer{Control: boundSocket(wan, bypassMark), Timeout: 8 * time.Second}
	tr := &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			if ip, perr := netip.ParseAddr(host); perr == nil {
				if !ip.Is4() {
					return nil, errors.New("ipv4_required")
				}
				return dialer.DialContext(ctx, "tcp4", net.JoinHostPort(ip.String(), port))
			}
			ips, lerr := resolver.LookupNetIP(ctx, "ip4", host)
			if lerr != nil || len(ips) == 0 {
				ips, lerr = net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
			}
			if lerr == nil {
				for _, ip := range ips {
					if ip.IsGlobalUnicast() && !ip.IsPrivate() {
						return dialer.DialContext(ctx, "tcp4", net.JoinHostPort(ip.String(), port))
					}
				}
			}
			return dialer.DialContext(ctx, "tcp4", address)
		},
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}

func loadWarpProfile(filePath string) (nativeAWGSettings, error) {
	b, err := readPrivate(filePath, 1<<20)
	if err != nil {
		return nativeAWGSettings{}, errors.New("warp_key_missing")
	}
	p, err := vpn.ParseWARPConf(string(b), 4, 40, 70)
	if err != nil {
		return p, errors.New("warp_key_invalid")
	}
	if p.Endpoint == "162.159.192.1:2408" {
		p.Endpoint = ""
	}
	return p, nil
}

// registerRouterWarp creates and registers a fresh X25519 WARP key under an exclusive
// file lock, overwriting any previous or corrupt warp.json when explicitly requested.
func registerRouterWarp(ctx context.Context, wan, filePath string) error {
	if !validIface.MatchString(wan) {
		return errors.New("invalid_wan_interface")
	}
	if err := privateDir(privateConfigDir); err != nil {
		return err
	}
	lock, err := os.OpenFile(privateConfigDir+"/register.lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return errors.New("warp_registration_lock_failed")
	}
	defer lock.Close()
	if unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		return errors.New("warp_registration_running")
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)

	var extraIPs []netip.Addr
	dnsCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	if addresses, lerr := wanResolver(wan).LookupNetIP(dnsCtx, "ip4", warpAPIHost); lerr == nil {
		for _, ip := range addresses {
			if ip.IsGlobalUnicast() && !ip.IsPrivate() {
				extraIPs = append(extraIPs, ip.Unmap())
			}
		}
	}
	cancel()

	dialTCP := func(dctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		d := &net.Dialer{Control: boundSocket(wan, bypassMark), Timeout: 6 * time.Second}
		return d.DialContext(dctx, "tcp4", dst.String())
	}

	cfg, err := vpn.RegisterWARP(ctx, dialTCP, extraIPs)
	if err != nil {
		return errors.New("warp_registration_failed")
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return errors.New("warp_registration_invalid_profile")
	}
	if err := writePrivate(filePath, raw); err != nil {
		return err
	}
	_ = os.Remove(warpEndpointCachePath)
	return nil
}

func resolveNativeEndpoint(ctx context.Context, wan, endpoint string) (string, error) {
	if ip, err := netip.ParseAddrPort(endpoint); err == nil && ip.Addr().Is4() {
		return ip.String(), nil
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", errors.New("invalid_native_endpoint")
	}
	ips, err := wanResolver(wan).LookupNetIP(ctx, "ip4", host)
	if err == nil {
		for _, ip := range ips {
			if ip.IsGlobalUnicast() && !ip.IsPrivate() {
				return net.JoinHostPort(ip.String(), port), nil
			}
		}
	}
	return "", errors.New("native_endpoint_dns_failed")
}
