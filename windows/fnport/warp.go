package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/YUNGSLXRD/fnport/windows/internal/awgnet"
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
	Enabled    bool   `json:"enabled"`
	PrivateKey string `json:"private_key,omitempty"` // base64; made on this PC, never sent
	Address    string `json:"address,omitempty"`     // the tunnel's IPv4 address from Cloudflare
	PeerKey    string `json:"peer_key,omitempty"`
	Endpoint   string `json:"endpoint,omitempty"` // ip:port tried first; then the known ones
	Jc         int    `json:"jc"`
	Jmin       int    `json:"jmin"`
	Jmax       int    `json:"jmax"`
	I1         string `json:"i1,omitempty"` // AWG 1.5 signature packet, written as AmneziaWG does
}

func (w warpSettings) ready() bool { return w.PrivateKey != "" && w.Address != "" && w.PeerKey != "" }

// epicSuffixes: names whose connections go through WARP (and anything under them)
var epicSuffixes = []string{"epicgames.com", "epicgames.dev", "epicgames.net", "epicgamescdn.com",
	"unrealengine.com", "fortnite.com", "easyanticheat.net", "epicgames-download1.akamaized.net"}

func epicName(h string) bool {
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	for _, s := range epicSuffixes {
		if h == s || strings.HasSuffix(h, "."+s) {
			return true
		}
	}
	return false
}

// epicHosts: resolved now and then, their addresses routed into the adapter so the program sees
// those connections at all (AWS in the US for the login and friends, Cloudflare for the rest)
var epicHosts = []string{
	"account-public-service-prod.ol.epicgames.com", "account-public-service-prod03.ol.epicgames.com",
	"fortnite-public-service-prod11.ol.epicgames.com", "lightswitch-public-service-prod.ol.epicgames.com",
	"launcher-public-service-prod06.ol.epicgames.com", "catalog-public-service-prod06.ol.epicgames.com",
	"entitlement-public-service-prod08.ol.epicgames.com", "friends-public-service-prod.ol.epicgames.com",
	"party-service-prod.ol.epicgames.com", "xmpp-service-prod.ol.epicgames.com",
	"events-public-service-live.ol.epicgames.com", "fngw-mcp-gc-livefn.ol.epicgames.com",
	"fortnite-matchmaking-public-service-live-eu.ol.epicgames.com", "datarouter.ol.epicgames.com",
	"eulatracking-public-service-prod-m.ol.epicgames.com", "statsproxy-public-service-live.ol.epicgames.com",
	"www.epicgames.com", "store.epicgames.com", "egs-platform-service.store.epicgames.com", "api.epicgames.dev",
	"epicgames-download1.akamaized.net", "download.epicgames.com", "fastly-download.epicgames.com",
	"cloudflare.epicgamescdn.com", "store-site-backend-static.ak.epicgames.com",
}

// lookupAll: every public IPv4 address of host, from public DNS (past a router's fakeip), else
// from the system's
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
	for _, server := range []string{"77.88.8.8:53", "8.8.8.8:53"} {
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", server)
		}}
		if ips := try(r); len(ips) > 0 {
			return ips
		}
	}
	return try(net.DefaultResolver)
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

// warpCall: one HTTPS request to the WARP API, straight out of the physical adapter
func warpCall(method, path, token string, body []byte) ([]byte, error) {
	ips := lookupAll(warpAPI)
	if len(ips) == 0 {
		return nil, errors.New("не найден адрес " + warpAPI)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	raw, err := wnet.DialTCP(ctx, netip.AddrPortFrom(ips[0], 443))
	if err != nil {
		return nil, fmt.Errorf("не соединяется с Cloudflare: %w", err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(20 * time.Second))
	tc := utls.UClient(raw, &utls.Config{ServerName: warpAPI, NextProtos: []string{"http/1.1"}}, utls.HelloCustom)
	if err := tc.ApplyPreset(warpHello()); err != nil {
		return nil, err
	}
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("HTTPS к Cloudflare не прошёл: %w", err)
	}
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
	ports := []int{2408, 500, 1701, 4500, 854, 878, 894, 7559, 3138}
	for _, net3 := range []string{"188.114.96", "188.114.97"} {
		for _, p := range ports {
			out = append(out, fmt.Sprintf("%s.%d:%d", net3, 1+mrand.IntN(254), p))
		}
	}
	for _, net3 := range []string{"188.114.98", "188.114.99", "162.159.192"} {
		for _, p := range ports[:3] {
			out = append(out, fmt.Sprintf("%s.%d:%d", net3, 1+mrand.IntN(254), p))
		}
	}
	return out
}

type warpTunnel struct {
	dev      *device.Device
	net      *awgnet.Net
	peer     string // hex public key
	endpoint atomic.Value
	conns    atomic.Int64
}

func b64hex(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != 32 {
		return "", errors.New("ключ WARP испорчен")
	}
	return hex.EncodeToString(b), nil
}

// startWarp brings the tunnel up and looks for an endpoint that answers; slow (up to a minute
// or so when the DPI eats the first ones), so it runs in the background
func startWarp(ws warpSettings) (*warpTunnel, error) {
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
	dev := device.NewDevice(tdev, &physBind{}, device.NewLogger(device.LogLevelSilent, ""))
	cfg := fmt.Sprintf("private_key=%s\njc=%d\njmin=%d\njmax=%d\n", priv, ws.Jc, ws.Jmin, ws.Jmax)
	if ws.I1 != "" {
		cfg += "i1=" + ws.I1 + "\n"
	}
	cfg += fmt.Sprintf("public_key=%s\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=25\n", peer)
	if err := dev.IpcSet(cfg); err != nil {
		dev.Close()
		return nil, fmt.Errorf("настройки AWG: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}
	w := &warpTunnel{dev: dev, net: tnet, peer: peer}
	for _, ep := range warpEndpoints(ws.Endpoint) {
		if dev.IpcSet(fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=%s\n", peer, ep)) != nil {
			continue
		}
		if w.works() {
			w.endpoint.Store(ep)
			return w, nil
		}
	}
	dev.Close()
	return nil, errors.New("ни один адрес WARP не ответил")
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return w.net.DialTCP(ctx, dst)
}

func (w *warpTunnel) where() string {
	s, _ := w.endpoint.Load().(string)
	return s
}

func (w *warpTunnel) close() { w.dev.Close() }

// ---- the tunnel's own UDP: out of the physical adapter, like the game's

type physEndpoint netip.AddrPort

func (e physEndpoint) ClearSrc()           {}
func (e physEndpoint) SrcToString() string { return "" }
func (e physEndpoint) DstToString() string { return netip.AddrPort(e).String() }
func (e physEndpoint) DstToBytes() []byte  { b, _ := netip.AddrPort(e).MarshalBinary(); return b }
func (e physEndpoint) DstIP() netip.Addr   { return netip.AddrPort(e).Addr() }
func (e physEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

type physBind struct {
	mu sync.Mutex
	c  *net.UDPConn
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
	adder, _ := dev.(interface{ AddRoute(netip.Prefix) error })
	known := map[netip.Addr]bool{}
	refresh := func() {
		next := map[netip.Addr]bool{}
		for a := range known {
			next[a] = true
		}
		for _, h := range epicHosts {
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
	t.state.Store("подключён через " + w.where())
	changes.Add(1)
	logf("WARP подключён через %s: сервисы Epic идут через него, игра — напрямую", w.where())
	tk := time.NewTicker(10 * time.Minute)
	defer tk.Stop()
	for {
		select {
		case <-t.ctx.Done():
			return
		case <-tk.C:
			refresh()
		}
	}
}

func inPrefixes(a netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// warpStatus: for the window and the report
func (t *tcpRelay) warpStatus() string {
	s, _ := t.state.Load().(string)
	if w := t.warp.Load(); w != nil {
		s = fmt.Sprintf("подключён через %s, через него %d соединений", w.where(), w.conns.Load())
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
