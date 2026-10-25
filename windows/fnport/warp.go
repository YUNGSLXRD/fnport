package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/YUNGSLXRD/fnport/windows/internal/awgnet"
	"github.com/YUNGSLXRD/fnport/windows/internal/fakes"
	"github.com/YUNGSLXRD/fnport/windows/internal/wnet"
	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	utls "github.com/refraction-networking/utls"
)

// WARP for Epic's services: login, store, downloads go through Cloudflare WARP when the ISP
// chokes them, the game stays direct. The tunnel is AmneziaWG towards WARP: junk packets before
// the handshake (Jc, Jmin, Jmax, I1) hide it from the DPI, and the server, plain WireGuard, drops
// them. The key is the user's own, registered with Cloudflare from this PC by one button.

type warpSettings struct {
	Enabled    bool     `json:"enabled"`
	PrivateKey string   `json:"private_key,omitempty"` // base64; made on this PC, never sent
	Address    string   `json:"address,omitempty"`     // the tunnel's IPv4 address from Cloudflare
	PeerKey    string   `json:"peer_key,omitempty"`
	Endpoint   string   `json:"endpoint,omitempty"` // ip:port tried first; then the known ones
	Jc         int      `json:"jc"`
	Jmin       int      `json:"jmin"`
	Jmax       int      `json:"jmax"`
	I1         string   `json:"i1,omitempty"`      // AWG 1.5 signature packet, written as AmneziaWG does
	Domains    []string `json:"domains,omitempty"` // what goes through WARP; empty = Epic's (warpDomains)
	Always     bool     `json:"always"`            // through WARP at once, not trying directly first

	// fnport's fake before the tunnel's first packet to an endpoint, at the fake's TTL: the TSPU
	// freezes UDP to Cloudflare as to AWS, after the handshake and a few packets
	fake    []byte
	fakeTTL int
}

// withFake: the fake and TTL of the settings for the tunnel's UDP
func (w warpSettings) withFake(s settings) warpSettings {
	if s.Fake == "" || s.Passthrough {
		return w
	}
	for _, f := range fakes.List(fakesDir()) {
		if f.Name == s.Fake {
			w.fake, w.fakeTTL = f.Data, s.FakeTTL
		}
	}
	return w
}

func (w warpSettings) ready() bool { return w.PrivateKey != "" && w.Address != "" && w.PeerKey != "" }

// warpDomains: what goes through WARP by default. A line covers the name and everything under
// it; each line is also looked up and its addresses routed into the adapter, so the program
// sees those connections at all. Epic's own list of the launcher's hosts and what the store,
// login and downloads use besides: AWS in the US, Cloudflare, Akamai, CloudFront, Fastly
var warpDomains = []string{
	"epicgames.com", "epicgames.dev", "epicgames.net", "epicgamescdn.com", "unrealengine.com", "fortnite.com",
	"easyanticheat.net", "hcaptcha.com", "epicgames-download1.akamaized.net", "egdownload.fastly-edge.com",
	"account-public-service-prod.ol.epicgames.com", "account-public-service-prod03.ol.epicgames.com",
	"launcherwaitingroom-public-service-prod06.ol.epicgames.com", "launcher-public-service-prod06.ol.epicgames.com",
	"www.epicgames.com", "launcher-website-prod07.ol.epicgames.com", "tracking.epicgames.com",
	"accounts.launcher-website-prod07.ol.epicgames.com", "accounts.epicgames.com",
	"cdn1.epicgames.com", "cdn2.epicgames.com", "cdn1.unrealengine.com", "cdn2.unrealengine.com",
	"datarouter.ol.epicgames.com", "entitlement-public-service-prod08.ol.epicgames.com",
	"orderprocessor-public-service-ecomprod01.ol.epicgames.com", "catalog-public-service-prod06.ol.epicgames.com",
	"friends-public-service-prod.ol.epicgames.com", "friends-public-service-prod06.ol.epicgames.com",
	"lightswitch-public-service-prod.ol.epicgames.com", "lightswitch-public-service-prod06.ol.epicgames.com",
	"accountportal-website-prod07.ol.epicgames.com", "ut-public-service-prod10.ol.epicgames.com",
	"party-service-prod.ol.epicgames.com", "xmpp-service-prod.ol.epicgames.com",
	"fortnite-public-service-prod11.ol.epicgames.com", "events-public-service-live.ol.epicgames.com",
	"fngw-mcp-gc-livefn.ol.epicgames.com", "fortnite-matchmaking-public-service-live-eu.ol.epicgames.com",
	"eulatracking-public-service-prod-m.ol.epicgames.com", "statsproxy-public-service-live.ol.epicgames.com",
	"talon-service-prod.ecosec.on.epicgames.com", "fortnitecontent-website-prod07.ol.epicgames.com",
	"library-service.live.use1a.on.epicgames.com", "datastorage-public-service-liveegs.live.use1a.on.epicgames.com",
	"download.epicgames.com", "download2.epicgames.com", "download3.epicgames.com", "download4.epicgames.com",
	"fastly-download.epicgames.com", "cloudflare.epicgamescdn.com",
	"static-assets-prod.epicgames.com", "shared-static-prod.epicgames.com",
	"store-site-backend-static.ak.epicgames.com", "store-content.ak.epicgames.com",
	"store.epicgames.com", "launcher.store.epicgames.com", "egs-platform-service.store.epicgames.com",
	"api.epicgames.dev", "js.hcaptcha.com",
}

// cleanDomain: a line of the list as a bare name ("https://x.com/path", "*.x.com" -> "x.com")
func cleanDomain(l string) string {
	l = strings.ToLower(strings.TrimSpace(l))
	if i := strings.Index(l, "://"); i >= 0 {
		l = l[i+3:]
	}
	if i := strings.IndexAny(l, "/:? "); i >= 0 {
		l = l[:i]
	}
	l = strings.TrimPrefix(strings.TrimPrefix(l, "*."), ".")
	return strings.TrimSuffix(l, ".")
}

// domains: the user's list, or the default one
func (w warpSettings) domains() []string {
	src := w.Domains
	if len(src) == 0 {
		src = warpDomains
	}
	var out []string
	seen := map[string]bool{}
	for _, l := range src {
		if d := cleanDomain(l); d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

// matchDomain: h is one of the names or under one
func matchDomain(h string, names []string) bool {
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	if h == "" {
		return false
	}
	for _, s := range names {
		if h == s || strings.HasSuffix(h, "."+s) {
			return true
		}
	}
	return false
}

// lookupAll: every public IPv4 address of host from public DNS (past a router's fakeip) and from
// the system's: CDNs like Akamai answer by the resolver's location, and the launcher asks the
// system's
func lookupAll(host string) []netip.Addr {
	try := func(r *net.Resolver) []netip.Addr {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		ips, _ := r.LookupNetIP(ctx, "ip4", host)
		var out []netip.Addr
		for _, ip := range ips {
			if ip = ip.Unmap(); ip.Is4() && !ip.IsPrivate() && !ip.IsLoopback() && !isFakeIP(ip) {
				out = append(out, ip)
			}
		}
		return out
	}
	out := try(net.DefaultResolver)
	for _, server := range []string{"77.88.8.8:53", "8.8.8.8:53"} {
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", server)
		}}
		if ips := try(r); len(ips) > 0 {
			return append(out, ips...)
		}
	}
	return out
}

var fakeIPNet = netip.MustParsePrefix("198.18.0.0/15")

func isFakeIP(a netip.Addr) bool { return fakeIPNet.Contains(a) }

// ---- registration: the same request the 1.1.1.1 app for Android makes (as wgcf does it)

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

// warpAPIAddrs: the API's addresses as Google's DNS gives them. Russian resolvers answer with
// 8.47.69.0 and 8.6.112.0, which do not answer from Russia (October 2026)
var warpAPIAddrs = []netip.Addr{netip.MustParseAddr("104.16.24.84"), netip.MustParseAddr("104.16.192.82")}

// warpConnect: a TLS connection to the WARP API, trying its addresses in turn, the ClientHello
// cut in TCP segments first, then also in TLS records
func warpConnect() (*utls.UConn, error) {
	ips := append(append([]netip.Addr(nil), warpAPIAddrs...), lookupAll(warpAPI)...)
	var last error
	for _, records := range []bool{false, true} {
		tried := map[netip.Addr]bool{}
		for _, ip := range ips {
			if tried[ip] {
				continue
			}
			tried[ip] = true
			tc, err := warpTLS(ip, records)
			if err == nil {
				return tc, nil
			}
			last = err
		}
	}
	if last == nil {
		last = errors.New("не найден адрес " + warpAPI)
	}
	return nil, last
}

func warpTLS(ip netip.Addr, records bool) (*utls.UConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	raw, err := wnet.DialTCP(ctx, netip.AddrPortFrom(ip, 443))
	if err != nil {
		return nil, fmt.Errorf("не соединяется с Cloudflare: %w", err)
	}
	raw.SetDeadline(time.Now().Add(6 * time.Second))
	sc := &splitConn{Conn: raw, mark: []byte(warpAPI), records: records}
	tc := utls.UClient(sc, &utls.Config{ServerName: warpAPI, NextProtos: []string{"http/1.1"}}, utls.HelloCustom)
	if err := tc.ApplyPreset(warpHello()); err != nil {
		raw.Close()
		return nil, err
	}
	if err := tc.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("HTTPS к Cloudflare не прошёл (%v): похоже, провайдер блокирует регистрацию WARP. "+
			"Получите ключ в другой сети (дома, с телефона) — он сохранится в fnport.json — или вставьте готовый конфиг ниже", err)
	}
	raw.SetDeadline(time.Now().Add(20 * time.Second))
	return tc, nil
}

// splitConn: the first write (the ClientHello) goes out in three TCP segments, the cut in the
// middle of the server's name, a moment apart: a DPI that looks for the name in one packet
// does not find it
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

// parseWarpConf: a WireGuard or AmneziaWG config as the apps export it, over the old settings
func parseWarpConf(text string, old warpSettings) (warpSettings, error) {
	w := old
	w.Endpoint, w.I1 = "", ""
	for _, l := range strings.Split(text, "\n") {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		num := func(d int) int {
			var n int
			if _, err := fmt.Sscan(v, &n); err == nil {
				return n
			}
			return d
		}
		switch k {
		case "privatekey":
			w.PrivateKey = v
		case "publickey":
			w.PeerKey = v
		case "address":
			for _, a := range strings.Split(v, ",") {
				a, _, _ = strings.Cut(strings.TrimSpace(a), "/")
				if ip, err := netip.ParseAddr(a); err == nil && ip.Is4() {
					w.Address = ip.String()
					break
				}
			}
		case "endpoint":
			host, port, err := net.SplitHostPort(v)
			if err != nil {
				return old, fmt.Errorf("Endpoint «%s» непонятен", v)
			}
			if ip, err := netip.ParseAddr(host); err == nil {
				w.Endpoint = netip.AddrPortFrom(ip, 0).Addr().String() + ":" + port
			} else if ips := lookupAll(host); len(ips) > 0 {
				w.Endpoint = ips[0].String() + ":" + port
			}
		case "jc":
			w.Jc = num(w.Jc)
		case "jmin":
			w.Jmin = num(w.Jmin)
		case "jmax":
			w.Jmax = num(w.Jmax)
		case "i1":
			w.I1 = v
		}
	}
	if _, err := b64hex(w.PrivateKey); err != nil {
		return old, errors.New("в конфиге нет PrivateKey или он испорчен")
	}
	if _, err := b64hex(w.PeerKey); err != nil {
		return old, errors.New("в конфиге нет PublicKey или он испорчен")
	}
	if w.Address == "" {
		return old, errors.New("в конфиге нет адреса IPv4 (Address)")
	}
	return w, nil
}

// warpCall: one HTTPS request to the WARP API, straight out of the physical adapter
func warpCall(method, path, token string, body []byte) ([]byte, error) {
	tc, err := warpConnect()
	if err != nil {
		return nil, err
	}
	defer tc.Close()
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
		return nil, fmt.Errorf("Cloudflare ответил %s", resp.Status)
	}
	return b, nil
}

// registerWarp makes a key pair here and registers its public half as a new WARP device
func registerWarp(old warpSettings) (warpSettings, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return old, err
	}
	body, _ := json.Marshal(map[string]any{
		"fcm_token": "", "install_id": "", "key": base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()),
		"locale": "en_US", "model": "PC", "tos": time.Now().Format(time.RFC3339Nano), "serial_number": "",
		"os_version": "16.0.0", "key_type": "curve25519", "tunnel_type": "wireguard",
	})
	b, err := warpCall("POST", "/reg", "", body)
	if err != nil {
		return old, err
	}
	var reg warpReg
	if err := json.Unmarshal(b, &reg); err != nil {
		return old, fmt.Errorf("непонятный ответ Cloudflare: %w", err)
	}
	if reg.Config == nil && reg.ID != "" {
		if b, err = warpCall("GET", "/reg/"+reg.ID, reg.Token, nil); err == nil {
			json.Unmarshal(b, &reg)
		}
	}
	if reg.Config == nil || len(reg.Config.Peers) == 0 || reg.Config.Interface.Addresses.V4 == "" {
		return old, errors.New("Cloudflare не прислал настройки туннеля")
	}
	w := old
	w.PrivateKey = base64.StdEncoding.EncodeToString(priv.Bytes())
	w.PeerKey = reg.Config.Peers[0].PublicKey
	w.Address = reg.Config.Interface.Addresses.V4
	w.Endpoint = ""
	return w, nil
}

// ---- the tunnel

// warpEndpoints: the one from the settings, then those reported working in Russia (4PDA,
// October 2026: 188.114.96–97 everywhere, 98–99 and 162.159.192 not everywhere, 193 banned)
func warpEndpoints(first string) []string {
	var out []string
	if first != "" {
		out = append(out, first)
	}
	ranges := []string{"188.114.96", "188.114.97", "188.114.98", "188.114.99", "162.159.192"}
	ports := []int{2408, 500, 1701, 4500, 854, 878, 894, 7559, 3138}
	pick := func(net3 string, port int) string { return fmt.Sprintf("%s.%d:%d", net3, 1+mrand.IntN(254), port) }
	// one of each range first: the ranges lead to different points of Cloudflare
	for _, r := range ranges {
		out = append(out, pick(r, 2408))
	}
	for _, r := range ranges[:2] {
		for _, p := range ports[1:] {
			out = append(out, pick(r, p))
		}
	}
	for _, r := range ranges[2:] {
		for _, p := range ports[1:3] {
			out = append(out, pick(r, p))
		}
	}
	return out
}

type warpTunnel struct {
	dev      *device.Device
	net      *awgnet.Net
	peer     string // hex public key
	endpoint atomic.Value
	exitInfo atomic.Value // string from exit()
	exitKV   atomic.Value // [3]string: colo, loc, ip
	bind     *physBind
	conns    atomic.Int64
	fails    atomic.Int64
}

func b64hex(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != 32 {
		return "", errors.New("ключ WARP испорчен")
	}
	return hex.EncodeToString(b), nil
}

// newWarpDev: the AWG device with the key, up, no endpoint yet
func newWarpDev(ws warpSettings) (*warpTunnel, error) {
	addr, err := netip.ParseAddr(ws.Address)
	if err != nil {
		return nil, errors.New("адрес WARP испорчен")
	}
	priv, err := b64hex(ws.PrivateKey)
	if err != nil {
		return nil, err
	}
	peer, err := b64hex(ws.PeerKey)
	if err != nil {
		return nil, err
	}
	tdev, tnet, err := awgnet.New(addr, 1280)
	if err != nil {
		return nil, err
	}
	bind := &physBind{fake: ws.fake, ttl: ws.fakeTTL}
	dev := device.NewDevice(tdev, bind, device.NewLogger(device.LogLevelSilent, ""))
	cfg := fmt.Sprintf("private_key=%s\njc=%d\njmin=%d\njmax=%d\n", priv, ws.Jc, ws.Jmin, ws.Jmax)
	if ws.I1 != "" {
		cfg += "i1=" + ws.I1 + "\n"
	}
	if err := dev.IpcSet(cfg); err != nil {
		dev.Close()
		return nil, fmt.Errorf("настройки AWG: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}
	return &warpTunnel{dev: dev, net: tnet, peer: peer, bind: bind}, nil
}

// setEndpoint: the peer made anew with the endpoint. A new peer with keepalive sends its
// handshake at once; changing the endpoint of the old one waits for its retry timer (5 s)
func (w *warpTunnel) setEndpoint(ep string) bool {
	return w.dev.IpcSet(fmt.Sprintf("replace_peers=true\npublic_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\n"+
		"persistent_keepalive_interval=25\n", w.peer, ep)) == nil
}

// probeEndpoint: a tunnel to ep that carries a bulk of data, with the delay to Cloudflare's exit
// point and its code; nil when none does. The TSPU freezes the tunnel's UDP like a game flow,
// by source port: up to three ports are tried, as fnport does for the game (home, October 2026:
// the handshake and a few kilobytes passed, then the tunnel stood still)
func probeEndpoint(ws warpSettings, ep string) (*warpTunnel, time.Duration, string) {
	// without the fake the tunnel froze every time (home, October 2026): no try without it
	var whys []string
	for try := 0; try < 2; try++ {
		w, err := newWarpDev(ws)
		if err != nil {
			return nil, 0, ""
		}
		if !w.setEndpoint(ep) || !w.works() {
			w.close()
			return nil, 0, "" // no handshake: the address, not the port
		}
		var best time.Duration
		for i := 0; i < 3; i++ {
			t0 := time.Now()
			c, err := w.dial(netip.MustParseAddrPort("1.1.1.1:443"))
			if err != nil {
				continue
			}
			if d := time.Since(t0); best == 0 || d < best {
				best = d
			}
			c.Close()
		}
		why := "соединения с 1.1.1.1 не открываются"
		if best > 0 {
			w.exit()
			why = "выход не определился (HTTPS к 1.1.1.1 не прошёл)"
			if colo, _, _ := w.exitParts(); colo != "" {
				if why = w.bulk(); why == "" {
					w.endpoint.Store(ep)
					return w, best, colo
				}
			}
		}
		whys = append(whys, fmt.Sprintf("порт %d: %s", w.localPort(), why))
		w.close()
	}
	logf("WARP: %s не подошёл (%s)", ep, strings.Join(whys, "; "))
	return nil, 0, ""
}

// bulk: the first 256 KB of a large file through the tunnel within 8 s, a flow well past the 25
// packets a freeze lets by; "" when they came, else what went wrong. Two files: cachefly answered
// WARP with an empty 200 at home, cdnjs is Cloudflare's own (the ISP cannot see its name inside
// the tunnel). Not Cloudflare's speed test: it answers WARP with 403
func (w *warpTunnel) bulk() string {
	var whys []string
	for _, url := range []string{warpTestURL, speedTestURL} {
		why := w.bulkFrom(url)
		if why == "" {
			return ""
		}
		whys = append(whys, why)
	}
	return strings.Join(whys, "; ")
}

func (w *warpTunnel) bulkFrom(url string) string {
	tr := &http.Transport{DisableCompression: true, DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
		host, port, _ := net.SplitHostPort(addr)
		ips := lookupAll(host)
		if len(ips) == 0 {
			return nil, errors.New("не найден адрес " + host)
		}
		p := uint16(443)
		if port == "80" {
			p = 80
		}
		return w.dial(netip.AddrPortFrom(ips[0], p))
	}}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: 8 * time.Second}
	host := url[strings.Index(url, "//")+2:]
	host = host[:strings.Index(host, "/")]
	start := time.Now()
	resp, err := cl.Get(url)
	if err != nil {
		return fmt.Sprintf("%s: запрос не прошёл за %.1f с (%v)", host, time.Since(start).Seconds(), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Sprintf("%s ответил %s", host, resp.Status)
	}
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 256<<10))
	if n < 256<<10 {
		return fmt.Sprintf("%s: пришло %d КБ за %.1f с (%s, длина %d, сервер %q, %v)", host, n>>10,
			time.Since(start).Seconds(), resp.Proto, resp.ContentLength, resp.Header.Get("Server"), err)
	}
	return ""
}

// speedTestURL: a large file off Cloudflare for the direct speed; warpTestURL: one through WARP
// (Cloudflare's own cdnjs: cachefly answers WARP with an empty 200, Cloudflare's speed test
// with 403)
const (
	speedTestURL = "https://cachefly.cachefly.net/50mb.test"
	warpTestURL  = "https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js"
)

// quicI1: AWG's signature packet as the fake fnport opens game flows with, a QUIC Initial to a
// whitelisted name: before each handshake, so a DPI that blocks WireGuard may let the flow be
func quicI1() string {
	for _, f := range fakes.List(fakesDir()) {
		if f.Name == fakes.Default() {
			return "<b 0x" + hex.EncodeToString(f.Data) + ">"
		}
	}
	return ""
}

// startWarp: as it is first, then, if no endpoint answers, with the QUIC decoy before the handshake
func startWarp(ws warpSettings) (*warpTunnel, error) {
	w, err := startWarpWith(ws)
	if err == nil || ws.I1 != "" {
		return w, err
	}
	if ws.I1 = quicI1(); ws.I1 == "" {
		return nil, err
	}
	logf("WARP: ни один адрес не ответил, пробую с приманкой QUIC %s перед рукопожатием", fakes.Label(fakes.Default()))
	return startWarpWith(ws)
}

// startWarpWith brings the tunnel up through the nearest of a few endpoints that answer (they
// lead to different points of Cloudflare, depending on the ISP's routes); slow, so it runs in
// the background
//
// An exit in Russia is taken only when there is no other: from Cloudflare's point in Moscow
// the traffic goes on through Russian networks, and the TSPU freezes it there (home: Fortnite's
// content keys and any large download failed through DME, October 2026)
func startWarpWith(ws warpSettings) (*warpTunnel, error) {
	var best *warpTunnel
	var bestRTT time.Duration
	bestRU := true
	found, abroad := 0, 0
	for i, ep := range warpEndpoints(ws.Endpoint) {
		// every range first: they lead to different points (home: 96–97 Frankfurt, 98–99 Moscow,
		// 162.159.192 Helsinki)
		if found >= 4 && abroad > 0 && i >= 5 || i >= 16 {
			break
		}
		w, rtt, colo := probeEndpoint(ws, ep)
		if w == nil {
			continue
		}
		found++
		ru := coloCountry[colo] == "RU"
		if !ru {
			abroad++
		}
		where := coloCity[colo]
		if where == "" {
			where = colo
		}
		logf("WARP: %s ведёт в %s (%s), %d мс", ep, where, colo, rtt.Milliseconds())
		if best == nil || bestRU && !ru || bestRU == ru && rtt < bestRTT {
			if best != nil {
				best.close()
			}
			best, bestRTT, bestRU = w, rtt, ru
		} else {
			w.close()
		}
	}
	if best == nil {
		return nil, errors.New("ни один адрес WARP не пропустил данные")
	}
	if bestRU {
		logf("WARP: все найденные выходы в России, беру лучший из них — через него может не работать то же, что напрямую")
	}
	// the very tunnel that carried the bulk: another one would get another, untried port
	return best, nil
}

// findEndpoint: the first address of WARP the handshake goes through
func (w *warpTunnel) findEndpoint(first string) bool {
	for _, ep := range warpEndpoints(first) {
		if w.setEndpoint(ep) && w.works() {
			w.endpoint.Store(ep)
			return true
		}
	}
	return false
}

// exit: where WARP comes out, from Cloudflare's trace through the tunnel: "FRA, DE, 104.28.x.x"
func (w *warpTunnel) exit() string {
	raw, err := w.dial(netip.MustParseAddrPort("1.1.1.1:443"))
	if err != nil {
		return ""
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(8 * time.Second))
	// plain HTTP gets a redirect to HTTPS now
	c := tls.Client(raw, &tls.Config{ServerName: "one.one.one.one"})
	fmt.Fprint(c, "GET /cdn-cgi/trace HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\n\r\n")
	b, _ := io.ReadAll(io.LimitReader(c, 8192))
	kv := map[string]string{}
	for _, l := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok {
			kv[k] = v
		}
	}
	if kv["colo"] == "" {
		return ""
	}
	w.exitKV.Store([3]string{kv["colo"], kv["loc"], kv["ip"]})
	city := coloCity[kv["colo"]]
	if city == "" {
		city = kv["colo"]
	}
	country := coloCountry[kv["colo"]]
	if c := countryRU[country]; c != "" {
		country = c
	}
	return fmt.Sprintf("%s (%s), %s, адрес %s", city, kv["colo"], country, kv["ip"])
}

// exitParts: Cloudflare's point, the country, the address; "" before exit() learned them
func (w *warpTunnel) exitParts() (colo, loc, ip string) {
	p, _ := w.exitKV.Load().([3]string)
	return p[0], p[1], p[2]
}

// works: a TCP connection to 1.1.1.1 through the tunnel, which needs a finished handshake
func (w *warpTunnel) works() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	c, err := w.net.DialTCP(ctx, netip.MustParseAddrPort("1.1.1.1:443"))
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func (w *warpTunnel) dial(dst netip.AddrPort) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	return w.net.DialTCP(ctx, dst)
}

func (w *warpTunnel) where() string {
	s, _ := w.endpoint.Load().(string)
	return s
}

func (w *warpTunnel) close() { w.dev.Close() }

// localPort: the tunnel's own UDP port, for the log
func (w *warpTunnel) localPort() int {
	if w.bind == nil {
		return 0
	}
	w.bind.mu.Lock()
	defer w.bind.mu.Unlock()
	if w.bind.port == 0 && w.bind.c != nil {
		w.bind.port = w.bind.c.LocalAddr().(*net.UDPAddr).Port
	}
	return w.bind.port
}

// speedTest: up to 50 MB for 15 s, straight and through WARP; with fnport off, through a tunnel
// brought up for the test. Not Cloudflare's own speed test: ISPs block *.cloudflare.com by name
// (Dom.ru-like home ISP, October 2026), so straight it measured the block, not the line
func speedTest(w *warpTunnel, ws warpSettings) string {
	measure := func(url string, dial func(netip.AddrPort) (net.Conn, error)) string {
		tr := &http.Transport{DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			host, port, _ := net.SplitHostPort(addr)
			ips := lookupAll(host)
			if len(ips) == 0 {
				return nil, errors.New("не найден адрес " + host)
			}
			p := uint16(443)
			if port == "80" {
				p = 80
			}
			return dial(netip.AddrPortFrom(ips[0], p))
		}}
		tr.DisableCompression = true
		defer tr.CloseIdleConnections()
		// the file again and again for up to 15 s: through WARP it is a 1 MB one
		deadline := time.Now().Add(15 * time.Second)
		cl := &http.Client{Transport: tr, Timeout: 15 * time.Second}
		start := time.Now()
		var n int64
		for time.Now().Before(deadline) {
			resp, err := cl.Get(url)
			if err != nil {
				if n == 0 {
					return "ошибка: " + err.Error()
				}
				break
			}
			if resp.StatusCode != 200 {
				resp.Body.Close()
				return fmt.Sprintf("сервер ответил %s", resp.Status)
			}
			k, _ := io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			n += k
			if k == 0 {
				break
			}
		}
		d := time.Since(start).Seconds()
		if n == 0 || d <= 0 {
			return "ничего не скачалось"
		}
		return fmt.Sprintf("%.1f Мбит/с (%d КБ за %.0f с)", float64(n)*8/d/1e6, n/1024, d)
	}
	// the same file both ways, off Cloudflare: the ISP blocks Cloudflare's own names directly, and
	// Cloudflare's speed test answers WARP with 403
	direct := measure(speedTestURL, func(dst netip.AddrPort) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return wnet.DialTCP(ctx, dst)
	})
	res := "напрямую " + direct
	if w == nil && ws.ready() {
		if tmp, err := startWarp(ws); err == nil {
			defer tmp.close()
			w = tmp
			res += " (WARP поднят для замера через " + tmp.where() + ")"
		} else {
			res += ", WARP не подключился: " + err.Error()
		}
	}
	if w != nil {
		// cachefly answers WARP with an empty 200; cdnjs is Cloudflare's own
		res += ", через WARP " + measure(warpTestURL, w.dial)
	} else if !ws.ready() {
		res += ", ключа WARP нет"
	}
	logf("WARP: скорость %s", res)
	return res
}

// ---- the tunnel's own UDP: out of the physical adapter, like the game's

type physEndpoint netip.AddrPort

func (e physEndpoint) ClearSrc()           {}
func (e physEndpoint) SrcToString() string { return "" }
func (e physEndpoint) DstToString() string { return netip.AddrPort(e).String() }
func (e physEndpoint) DstToBytes() []byte  { b, _ := netip.AddrPort(e).MarshalBinary(); return b }
func (e physEndpoint) DstIP() netip.Addr   { return netip.AddrPort(e).Addr() }
func (e physEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

type physBind struct {
	mu   sync.Mutex
	c    *net.UDPConn
	port int    // kept after Close, for the log
	fake []byte // sent once per endpoint before anything else, at ttl
	ttl  int
	sent map[netip.AddrPort]bool
}

func (b *physBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.c != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	c, err := wnet.ListenUDP(int(port), true)
	if err != nil {
		return nil, 0, err
	}
	b.c = c
	recv := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		// an ICMP error from a dead endpoint surfaces as a read error: skip it, not the tunnel
		for fails := 0; ; fails++ {
			n, a, err := c.ReadFromUDPAddrPort(packets[0])
			if err == nil {
				sizes[0], eps[0] = n, physEndpoint(netip.AddrPortFrom(a.Addr().Unmap(), a.Port()))
				return 1, nil
			}
			if errors.Is(err, net.ErrClosed) || fails > 100 {
				return 0, err
			}
		}
	}
	return []conn.ReceiveFunc{recv}, uint16(c.LocalAddr().(*net.UDPAddr).Port), nil
}

func (b *physBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.c == nil {
		return nil
	}
	err := b.c.Close()
	b.c = nil
	return err
}

func (b *physBind) SetMark(uint32) error { return nil }
func (b *physBind) BatchSize() int       { return 1 }

func (b *physBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	return physEndpoint(ap), err
}

func (b *physBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	c := b.c
	b.mu.Unlock()
	if c == nil {
		return net.ErrClosed
	}
	pe, ok := ep.(physEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	if b.fake != nil && b.ttl > 0 {
		b.mu.Lock()
		if b.sent == nil {
			b.sent = map[netip.AddrPort]bool{}
		}
		first := !b.sent[netip.AddrPort(pe)]
		b.sent[netip.AddrPort(pe)] = true
		b.mu.Unlock()
		if first {
			wnet.SendWithTTL(c, b.fake, netip.AddrPort(pe), b.ttl)
		}
	}
	for _, p := range bufs {
		if _, err := c.WriteToUDPAddrPort(p, netip.AddrPort(pe)); err != nil {
			return err
		}
	}
	return nil
}

// runWarp: Epic's addresses routed into the adapter, then the tunnel. The addresses are looked
// up again every 10 minutes while fnport is on
func runWarp(ws warpSettings, dev wnet.Dev, routed []netip.Prefix, t *tcpRelay) {
	names := ws.domains()
	t.names.Store(&names)
	t.always.Store(ws.Always)
	if !ws.Always && networkFreezes() {
		t.always.Store(true)
		logf("WARP: в этой сети сервисы Epic напрямую замерзали — всё из списка сразу через WARP")
	}
	adder, _ := dev.(interface{ AddRoute(netip.Prefix) error })
	known := map[netip.Addr]bool{}
	refresh := func() {
		next := map[netip.Addr]bool{}
		for a := range known {
			next[a] = true
		}
		for _, h := range names {
			for _, a := range lookupAll(h) {
				if next[a] {
					continue
				}
				next[a] = true
				if adder != nil && !inPrefixes(a, routed) {
					adder.AddRoute(netip.PrefixFrom(a, 32))
				}
			}
		}
		known = next
		t.epicIPs.Store(&next)
	}
	t.state.Store("подключается…")
	changes.Add(1)
	logf("WARP: подключаюсь (сервисы Epic пока идут напрямую)")
	refresh()
	w, err := startWarp(ws)
	if t.ctx.Err() != nil {
		if w != nil {
			w.close()
		}
		return
	}
	if err != nil {
		t.state.Store("не подключился: " + err.Error())
		changes.Add(1)
		logf("WARP не подключился: %v. Сервисы Epic идут напрямую.", err)
		return
	}
	t.warp.Store(w)
	if t.ctx.Err() != nil { // fnport went off meanwhile
		if w := t.warp.Swap(nil); w != nil {
			w.close()
		}
		return
	}
	changes.Add(1)
	logf("WARP подключён через %s: сервисы Epic идут через него, игра — напрямую", w.where())
	if ex := w.exit(); ex != "" {
		w.exitInfo.Store(ex)
		logf("WARP: выход — %s", ex)
		changes.Add(1)
	}
	// the tunnel checked every minute: a dead endpoint makes every Epic connection wait and
	// fall back to direct, so another one is looked for
	health := time.NewTicker(time.Minute)
	defer health.Stop()
	tk := time.NewTicker(10 * time.Minute)
	defer tk.Stop()
	for {
		select {
		case <-t.ctx.Done():
			return
		case <-tk.C:
			refresh()
		case <-health.C:
			if w.works() {
				if colo, _, _ := w.exitParts(); colo == "" {
					if ex := w.exit(); ex != "" {
						w.exitInfo.Store(ex)
						logf("WARP: выход — %s", ex)
						changes.Add(1)
					}
				}
				continue
			}
			logf("WARP: туннель через %s не отвечает, поднимаю новый", w.where())
			w = t.rebuildWarp(ws, w)
			if w == nil {
				return
			}
		case <-t.warpStall:
			logf("WARP: соединение через %s встало посреди ответа — поднимаю туннель с другого порта", w.where())
			w = t.rebuildWarp(ws, w)
			if w == nil {
				return
			}
		}
	}
}

// The networks where Epic's sites froze directly, remembered for 3 days in warp-state.json next to
// the program: learning them site by site took restarts of the game every evening

func warpStatePath() string { return filepath.Join(appDir(), "warp-state.json") }

// networkKey: this PC's address on the adapter towards the internet, telling home from a club
func networkKey() string {
	if !wnet.PhysAddr.IsValid() {
		return ""
	}
	return wnet.PhysAddr.String()
}

func loadWarpState() map[string]time.Time {
	m := map[string]time.Time{}
	if b, err := os.ReadFile(warpStatePath()); err == nil {
		json.Unmarshal(b, &m)
	}
	return m
}

func networkFreezes() bool {
	k := networkKey()
	if k == "" {
		return false
	}
	at, ok := loadWarpState()[k]
	return ok && time.Since(at) < 72*time.Hour
}

func rememberNetworkFreezes() {
	k := networkKey()
	if k == "" {
		return
	}
	m := loadWarpState()
	m[k] = time.Now()
	for key, at := range m {
		if time.Since(at) > 72*time.Hour {
			delete(m, key)
		}
	}
	if b, err := json.Marshal(m); err == nil {
		os.WriteFile(warpStatePath(), b, 0o644)
	}
}

// rebuildWarp: a new tunnel (new ports, maybe another point) in place of old; Epic goes directly
// meanwhile. nil when fnport went off
func (t *tcpRelay) rebuildWarp(ws warpSettings, old *warpTunnel) *warpTunnel {
	t.warp.Store(nil)
	t.state.Store("переподключается…")
	changes.Add(1)
	old.close()
	for t.ctx.Err() == nil {
		if w, err := startWarp(ws); err == nil {
			if t.ctx.Err() != nil {
				w.close()
				return nil
			}
			if ex := w.exit(); ex != "" {
				w.exitInfo.Store(ex)
			}
			t.warp.Store(w)
			logf("WARP снова подключён, через %s", w.where())
			changes.Add(1)
			return w
		}
		t.state.Store("не подключается, пробую снова через 5 минут")
		logf("WARP не подключился: сервисы Epic идут напрямую, попробую снова через 5 минут")
		select {
		case <-t.ctx.Done():
		case <-time.After(5 * time.Minute):
		}
	}
	return nil
}

func inPrefixes(a netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// warpStatus: for the window and (full, with the exit) the report
func (t *tcpRelay) warpStatus(full bool) string {
	s, _ := t.state.Load().(string)
	if w := t.warp.Load(); w != nil {
		s = fmt.Sprintf("подключён через %s, через него %d соединений", w.where(), w.conns.Load())
		if n := w.fails.Load(); n > 0 {
			s += fmt.Sprintf(", не открылись %d", n)
		}
		if ex, _ := w.exitInfo.Load().(string); ex != "" && full {
			s += "; выход: " + ex
		}
	}
	return s
}

// ---- which connections go through it

// sniOf: the server name from a TLS ClientHello record, "" when there is none
func sniOf(b []byte) string {
	u16 := func(p []byte) int { return int(p[0])<<8 | int(p[1]) }
	if len(b) < 9 || b[0] != 22 || b[5] != 1 {
		return ""
	}
	p := b[9:]
	if len(p) < 35 {
		return ""
	}
	p = p[34:] // version, random
	skip := func(lenBytes int) bool {
		if len(p) < lenBytes {
			return false
		}
		n := int(p[0])
		if lenBytes == 2 {
			n = u16(p)
		}
		if len(p) < lenBytes+n {
			return false
		}
		p = p[lenBytes+n:]
		return true
	}
	if !skip(1) || !skip(2) || !skip(1) || len(p) < 2 { // session id, ciphers, compression
		return ""
	}
	p = p[2:]
	for len(p) >= 4 {
		typ, n := u16(p), u16(p[2:])
		p = p[4:]
		if len(p) < n {
			return ""
		}
		if e := p[:n]; typ == 0 && len(e) >= 5 && e[2] == 0 {
			if l := u16(e[3:]); len(e) >= 5+l {
				return string(e[5 : 5+l])
			}
		}
		p = p[n:]
	}
	return ""
}

// readHello: the whole first TLS record from the PC (a post-quantum ClientHello spans two
// segments), or what came within a few seconds
func readHello(c net.Conn) []byte {
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	defer c.SetReadDeadline(time.Time{})
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for len(buf) < 16<<10 {
		n, err := c.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if len(buf) >= 5 && (buf[0] != 22 || len(buf) >= 5+(int(buf[3])<<8|int(buf[4]))) {
			break
		}
		if err != nil {
			break
		}
	}
	return buf
}
