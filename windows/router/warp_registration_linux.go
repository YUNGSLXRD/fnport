//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/sys/unix"
)

const warpAPI = "api.cloudflareclient.com"
const warpAPIVersion = "v0a5641"

type warpReg struct {
	ID     string `json:"id"`
	Token  string `json:"token"`
	Config *struct {
		Peers []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				V4    string `json:"v4"`
				Ports []int  `json:"ports"`
			} `json:"endpoint"`
		} `json:"peers"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
			} `json:"addresses"`
		} `json:"interface"`
	} `json:"config"`
}

// warpHello: Cloudflare answers the registration only to a ClientHello like the Android app's.
// The spec is wgcf's (github.com/ViRb3/wgcf, MIT)
func warpHello() *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
		TLSVersMin:         utls.VersionTLS12,
		TLSVersMax:         utls.VersionTLS12,
		CipherSuites:       []uint16{utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
		CompressionMethods: []uint8{0},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateNever},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.X25519, utls.CurveP256, utls.CurveP384}},
			&utls.SupportedPointsExtension{SupportedPoints: []uint8{0}},
			&utls.SessionTicketExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}},
			&utls.StatusRequestExtension{},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256, utls.PSSWithSHA256, utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384, utls.PSSWithSHA384, utls.PKCS1WithSHA384,
				utls.PSSWithSHA512, utls.PKCS1WithSHA512, utls.PKCS1WithSHA1,
			}},
			&utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
		},
	}
}

type splitConn struct {
	net.Conn
	mark    []byte
	records bool // also cut the TLS record in two records, for a DPI that reassembles TCP
	done    bool
}

func (c *splitConn) Write(b []byte) (int, error) {
	if c.done {
		return c.Conn.Write(b)
	}
	c.done = true
	cut := bytes.Index(b, c.mark)
	if cut < 0 {
		cut = len(b) / 2
	} else {
		cut += len(c.mark) / 2
	}
	parts := [][]byte{b[:1], b[1:cut], b[cut:]}
	if c.records && len(b) > 5 && b[0] == 22 && cut > 5 && cut < len(b) {
		// one handshake message in two records: the same type and version, each its own length
		rec := func(body []byte) []byte {
			return append([]byte{b[0], b[1], b[2], byte(len(body) >> 8), byte(len(body))}, body...)
		}
		first, second := rec(b[5:cut]), rec(b[cut:])
		parts = [][]byte{first[:1], first[1:], second}
	}
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		if _, err := c.Conn.Write(part); err != nil {
			return 0, err
		}
		time.Sleep(15 * time.Millisecond)
	}
	return len(b), nil
}

func routerWarpCall(ctx context.Context, wan, method, path, token string, body []byte) ([]byte, error) {
	tc, err := routerWarpConnect(ctx, wan)
	if err != nil {
		return nil, err
	}
	defer tc.Close()
	stop := context.AfterFunc(ctx, func() { tc.Close() })
	defer stop()
	req, _ := http.NewRequest(method, "https://"+warpAPI+"/"+warpAPIVersion+path, bytes.NewReader(body))
	req.Header.Set("User-Agent", "1.1.1.1/6.38.9-5641 (Android 16.0.0)")
	req.Header.Set("CF-Client-Version", "a-6.38.9-5641")
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("Connection", "close")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if err := req.Write(tc); err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(tc), req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, errors.New("warp_registration_http_error")
	}
	return b, nil
}

func routerWarpConnect(ctx context.Context, wan string) (*utls.UConn, error) {
	ips := []string{"104.16.24.84", "104.16.192.82"}
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Control: boundSocket(wan, bypassMark)}).DialContext(ctx, "udp4", "77.88.8.8:53")
	}}
	dnsCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	if addresses, err := resolver.LookupNetIP(dnsCtx, "ip4", warpAPI); err == nil {
		for _, ip := range addresses {
			if ip.IsGlobalUnicast() && !ip.IsPrivate() {
				ips = append(ips, ip.String())
			}
		}
	}
	cancel()
	for _, records := range []bool{false, true} {
		seen := map[string]bool{}
		for _, ip := range ips {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if seen[ip] {
				continue
			}
			seen[ip] = true
			attempt, stop := context.WithTimeout(ctx, 6*time.Second)
			raw, err := (&net.Dialer{Control: boundSocket(wan, bypassMark)}).DialContext(attempt, "tcp4", net.JoinHostPort(ip, "443"))
			if err != nil {
				stop()
				continue
			}
			raw.SetDeadline(time.Now().Add(6 * time.Second))
			tls := utls.UClient(&splitConn{Conn: raw, mark: []byte(warpAPI), records: records}, &utls.Config{ServerName: warpAPI, NextProtos: []string{"http/1.1"}}, utls.HelloCustom)
			err = tls.ApplyPreset(warpHello())
			if err == nil {
				err = tls.HandshakeContext(attempt)
			}
			stop()
			if err == nil {
				raw.SetDeadline(time.Now().Add(15 * time.Second))
				return tls, nil
			}
			raw.Close()
		}
	}
	return nil, errors.New("warp_registration_unreachable")
}

func loadWarpProfile(path string) (nativeAWGSettings, error) {
	b, err := readPrivate(path, 1<<20)
	if err != nil {
		return nativeAWGSettings{}, errors.New("warp_key_missing")
	}
	p, err := parseNativeAWG(b)
	if err != nil {
		return p, errors.New("warp_key_invalid")
	}
	return p, nil
}

// Applying settings never registers a new device. Only this explicit action can
// create a key, and an existing valid key is reused under an exclusive file lock.
func registerRouterWarp(ctx context.Context, wan, path string) error {
	if !validIface.MatchString(wan) {
		return errors.New("invalid_wan_interface")
	}
	if err := privateDir(privateConfigDir); err != nil {
		return err
	}
	lock, err := os.OpenFile(privateConfigDir+"/register.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return errors.New("warp_registration_lock_failed")
	}
	defer lock.Close()
	if unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		return errors.New("warp_registration_running")
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	if _, err := loadWarpProfile(path); err == nil {
		return nil
	}
	if _, err := os.Lstat(path); err == nil {
		return errors.New("warp_key_invalid")
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return errors.New("key_generation_failed")
	}
	body, _ := json.Marshal(map[string]any{"fcm_token": "", "install_id": "", "key": base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), "locale": "en_US", "model": "PC", "tos": time.Now().Format(time.RFC3339Nano), "serial_number": "", "os_version": "16.0.0", "key_type": "curve25519", "tunnel_type": "wireguard"})
	reply, err := routerWarpCall(ctx, wan, "POST", "/reg", "", body)
	if err != nil {
		return errors.New("warp_registration_failed")
	}
	var reg warpReg
	if json.Unmarshal(reply, &reg) != nil {
		return errors.New("warp_registration_invalid_response")
	}
	if reg.Config == nil && reg.ID != "" {
		if strings.ContainsAny(reg.ID, "/?#\\\r\n") {
			return errors.New("warp_registration_invalid_response")
		}
		reply, err = routerWarpCall(ctx, wan, "GET", "/reg/"+reg.ID, reg.Token, nil)
		if err != nil || json.Unmarshal(reply, &reg) != nil {
			return errors.New("warp_registration_failed")
		}
	}
	if reg.Config == nil || len(reg.Config.Peers) == 0 {
		return errors.New("warp_registration_incomplete")
	}
	settings := nativeAWGSettings{MTU: 1280, PrivateKey: base64.StdEncoding.EncodeToString(key.Bytes()), PeerKey: reg.Config.Peers[0].PublicKey, Address: reg.Config.Interface.Addresses.V4, Endpoint: "162.159.192.1:2408", Jc: 4, Jmin: 40, Jmax: 70, H1: 1, H2: 2, H3: 3, H4: 4}
	raw, _ := json.Marshal(settings)
	if _, err := parseNativeAWG(raw); err != nil {
		return errors.New("warp_registration_invalid_profile")
	}
	return writePrivate(path, raw)
}

func resolveNativeEndpoint(ctx context.Context, wan, endpoint string) (string, error) {
	if ip, err := netip.ParseAddrPort(endpoint); err == nil && ip.Addr().Is4() {
		return ip.String(), nil
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", errors.New("invalid_native_endpoint")
	}
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Control: boundSocket(wan, bypassMark)}).DialContext(ctx, "udp4", "77.88.8.8:53")
	}}
	ips, err := resolver.LookupNetIP(ctx, "ip4", host)
	if err == nil {
		for _, ip := range ips {
			if ip.IsGlobalUnicast() && !ip.IsPrivate() {
				return net.JoinHostPort(ip.String(), port), nil
			}
		}
	}
	return "", errors.New("native_endpoint_dns_failed")
}
