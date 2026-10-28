package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/YUNGSLXRD/fnport/windows/internal/geo"
	"github.com/YUNGSLXRD/fnport/windows/internal/wnet"
)

// The Epic services part of the ISP check: the login, Fortnite's services behind Cloudflare and a
// larger page, straight from this PC (public DNS, the physical interface, not fnport's adapter).
// It shows whether the ISP blocks Epic's HTTPS itself, apart from the freeze of the game's UDP.
// Six requests: nothing to punish.

type epicProbe struct {
	Label, Host, Path string
}

var epicProbes = []epicProbe{
	{"вход", "account-public-service-prod.ol.epicgames.com", "/account/api/oauth/verify"},
	{"сервисы Fortnite", "fortnite-public-service-prod11.ol.epicgames.com", "/fortnite/api/version"},
	// a page well past 16 KB: the TSPU stops foreign HTTPS at about that much
	{"загрузка", "www.epicgames.com", "/"},
	// what "Play" needs besides the game server: AWS in the US
	{"подбор матчей", "fortnite-matchmaking-public-service-live-eu.ol.epicgames.com", "/"},
	{"пати", "party-service-prod.ol.epicgames.com", "/"},
	{"чат и друзья", "xmpp-service-prod.ol.epicgames.com", "/"},
}

type epicResult struct {
	Label string
	State string // "ok", "dns", "connect", "tls", "frozen"
	Bytes int64
}

// publicLookup: the host's address from public DNS, past the router's own DNS, whose fakeip
// would send the request through the router's VPN and hide what the ISP does
func publicLookup(host string) netip.Addr {
	for _, server := range []string{"77.88.8.8:53", "8.8.8.8:53"} {
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", server)
		}}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		ips, _ := r.LookupNetIP(ctx, "ip4", host)
		cancel()
		for _, ip := range ips {
			if ip = ip.Unmap(); geo.IsPublic(ip) {
				return ip
			}
		}
	}
	return netip.Addr{}
}

// fetchDirect: one HTTPS GET to ip, read until the end or a stall. Bytes that stop coming before
// the end of the response mean the flow was frozen
func fetchDirect(p epicProbe, ip netip.Addr) (string, int64) {
	return fetchVia(p, ip, func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) { return wnet.DialTCP(ctx, dst) })
}

// fetchWarp: the same through the WARP tunnel
func fetchWarp(p epicProbe, ip netip.Addr, w *warpTunnel) (string, int64) {
	return fetchVia(p, ip, func(_ context.Context, dst netip.AddrPort) (net.Conn, error) { return w.dial(dst) })
}

func fetchVia(p epicProbe, ip netip.Addr, dial func(context.Context, netip.AddrPort) (net.Conn, error)) (string, int64) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	conn, err := dial(ctx, netip.AddrPortFrom(ip, 443))
	if err != nil {
		return "connect", 0
	}
	defer conn.Close()
	tc := tls.Client(conn, &tls.Config{ServerName: p.Host})
	tc.SetDeadline(time.Now().Add(8 * time.Second))
	if err := tc.HandshakeContext(ctx); err != nil {
		return "tls", 0
	}
	fmt.Fprintf(tc, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"+
		"Accept: */*\r\nConnection: close\r\n\r\n", p.Path, p.Host)
	n, err := io.Copy(io.Discard, io.LimitReader(tc, 1<<20))
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "frozen", n
	}
	if n == 0 {
		return "tls", 0
	}
	return "ok", n
}

// checkEpic: the services directly and, with a tunnel, through WARP: whether WARP helps where
// directly they freeze, and whether it works at all
func checkEpic(k *checker, w *warpTunnel) (direct, warp []epicResult) {
	k.say("Сервисы Epic напрямую (вход, сервисы Fortnite, загрузка, подбор матчей, пати, чат)…")
	ips := make([]netip.Addr, len(epicProbes))
	for i, p := range epicProbes {
		r := epicResult{Label: p.Label, State: "dns"}
		if ips[i] = publicLookup(p.Host); ips[i].IsValid() {
			r.State, r.Bytes = fetchDirect(p, ips[i])
		}
		k.say("  %s: %s", r.Label, epicStateRU(r))
		direct = append(direct, r)
	}
	if w == nil {
		return direct, nil
	}
	k.say("Те же сервисы через WARP (%s)…", w.where())
	for i, p := range epicProbes {
		r := epicResult{Label: p.Label, State: "dns"}
		if ips[i].IsValid() {
			r.State, r.Bytes = fetchWarp(p, ips[i], w)
		}
		k.say("  %s: %s", r.Label, epicStateRU(r))
		warp = append(warp, r)
	}
	return direct, warp
}

// warpVerdict: what WARP did for the services, for the summary; "" without a WARP check
func warpVerdict(direct, warp []epicResult) string {
	if len(warp) == 0 {
		return ""
	}
	var helped, still, broke []string
	for i, r := range warp {
		d := direct[i].State == "ok"
		switch {
		case !d && r.State == "ok":
			helped = append(helped, r.Label)
		case !d:
			still = append(still, r.Label)
		case r.State != "ok":
			broke = append(broke, r.Label)
		}
	}
	var out []string
	switch {
	case len(helped) > 0:
		out = append(out, fmt.Sprintf("WARP помогает: через него открывается то, что напрямую нет (%s).", strings.Join(helped, ", ")))
	case len(still) == 0 && len(broke) == 0:
		out = append(out, "Через WARP сервисы Epic открываются, но и напрямую тоже: сейчас WARP не нужен, и в режиме «Только то, что напрямую не открывается» он не мешает.")
	}
	if len(still) > 0 {
		out = append(out, fmt.Sprintf("Через WARP тоже не открывается: %s.", strings.Join(still, ", ")))
	}
	if len(broke) > 0 {
		out = append(out, fmt.Sprintf("Напрямую открывается, а через WARP нет: %s — режим «Всё из списка — всегда через WARP» здесь вреден.", strings.Join(broke, ", ")))
	}
	return strings.Join(out, " ")
}

func epicStateRU(r epicResult) string {
	switch r.State {
	case "ok":
		return fmt.Sprintf("открывается (%d КБ)", (r.Bytes+1023)/1024)
	case "dns":
		return "не найден адрес"
	case "connect":
		return "не соединяется"
	case "tls":
		return "соединяется, но HTTPS не проходит"
	case "frozen":
		return fmt.Sprintf("замерзает на %d КБ", (r.Bytes+1023)/1024)
	}
	return r.State
}

// epicBlocked: the services that do not work directly
func epicBlocked(rs []epicResult) []string {
	var out []string
	for _, r := range rs {
		if r.State != "ok" {
			out = append(out, r.Label)
		}
	}
	return out
}
