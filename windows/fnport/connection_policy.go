package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/YUNGSLXRD/fnport/windows/internal/vpn"
	"github.com/YUNGSLXRD/fnport/windows/internal/wnet"
)

var devTrace = "off"

var discordDomains = vpn.DiscordDomains

func selectedProcess(name string, names []string) bool {
	name = strings.ToLower(filepath.Base(strings.ReplaceAll(strings.TrimSpace(name), `\`, "/")))
	if name == "" {
		return false
	}
	for _, want := range names {
		if strings.EqualFold(name, strings.TrimSpace(want)) {
			return true
		}
	}
	return false
}

func (s connectionSettings) selects(owner wnet.ProcessOwner, domain string) bool {
	if !s.Enabled {
		return false
	}
	if s.Epic && vpn.MatchEpic(domain, nil) {
		return true
	}
	if s.Discord && (selectedProcess(owner.Name, []string{"Discord.exe", "DiscordPTB.exe", "DiscordCanary.exe"}) || vpn.MatchDomain(domain, vpn.DiscordDomains)) {
		return true
	}
	if vpn.MatchDomain(domain, s.Domains) {
		return true
	}
	return selectedProcess(owner.Name, s.Processes)
}

type connectionRouter struct {
	failuresMu  sync.Mutex
	failures    [2]connectionFailureWindow
	cancel      context.CancelFunc
	settings    connectionSettings
	transport   *connectionTransport
	native      *warpTunnel
	tcp         *tcpRelay
	leases      *vpn.LeaseCache
	trace       *networkTrace
	always      atomic.Bool
	conns       atomic.Int64
	fails       atomic.Int64
	exitReport  atomic.Pointer[vpn.ExitReport]
	ownerLookup func(uint8, netip.AddrPort, netip.AddrPort) (wnet.ProcessOwner, error)
}

func (r *connectionRouter) dial(ctx context.Context, dst netip.AddrPort, udp bool) (net.Conn, error) {
	if r.native != nil {
		var c net.Conn
		var err error
		if udp {
			c, err = r.native.net.DialUDP(dst)
		} else {
			c, err = r.native.net.DialTCP(ctx, dst)
		}
		if err != nil {
			r.fails.Add(1)
			r.native.fails.Add(1)
			return nil, err
		}
		r.conns.Add(1)
		r.native.conns.Add(1)
		return c, nil
	}
	if r.settings.Protocol == "warp" {
		w := r.tcp.waitWarpContext(ctx, nil, warpHold)
		if w == nil {
			return nil, connectionFailure("warp_wait", ctx.Err())
		}
		var c net.Conn
		var err error
		if udp {
			c, err = w.net.DialUDP(dst)
		} else {
			c, err = w.net.DialTCP(ctx, dst)
		}
		if err != nil {
			r.fails.Add(1)
			w.fails.Add(1)
			return nil, err
		}
		r.conns.Add(1)
		w.conns.Add(1)
		return c, nil
	}
	if r.transport == nil {
		return nil, fmt.Errorf("подключение недоступно")
	}
	var c net.Conn
	var err error
	if udp {
		c, err = r.transport.udp(ctx, dst)
	} else {
		c, err = r.transport.dial(ctx, dst)
	}
	if err != nil {
		r.fails.Add(1)
		return nil, err
	}
	r.conns.Add(1)
	return c, nil
}

// works checks whether the active tunnel can open a TCP connection to 1.1.1.1:443.
func (r *connectionRouter) works() bool {
	if r == nil {
		return false
	}
	if r.settings.Protocol == "warp" {
		if r.tcp != nil {
			if w := r.tcp.warp.Load(); w != nil {
				return w.works()
			}
		}
		return false
	}
	if r.native != nil {
		return r.native.works()
	}
	if r.transport != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := r.transport.dial(ctx, netip.MustParseAddrPort("1.1.1.1:443"))
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	}
	return false
}

// probeExit resolves exit location via Cloudflare's trace endpoint for non-WARP tunnels.
func (r *connectionRouter) probeExit(ctx context.Context) {
	if r == nil || r.settings.Protocol == "warp" {
		return
	}
	tctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	rep, err := vpn.TraceExit(tctx, func(cctx context.Context, addr string) (net.Conn, error) {
		ap, e := netip.ParseAddrPort(addr)
		if e != nil {
			return nil, e
		}
		return r.dial(cctx, ap, false)
	})
	if err == nil {
		r.exitReport.Store(&rep)
		changes.Add(1)
	}
}

func (r *connectionRouter) owner(proto uint8, src, dst netip.AddrPort) wnet.ProcessOwner {
	lookup := r.ownerLookup
	if lookup == nil {
		lookup = wnet.ConnectionOwner
	}
	for attempt := 0; ; attempt++ {
		o, err := lookup(proto, src, dst)
		if err == nil {
			return o
		}
		if !errors.Is(err, wnet.ErrOwnerNotFound) || attempt >= 2 {
			return wnet.ProcessOwner{}
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (r *connectionRouter) observe(proto uint8, src, dst netip.AddrPort, domain, source string) {
	if r != nil && r.trace != nil {
		r.trace.observe(proto, src, dst, domain, source)
	}
}

// selectedUDP decides whether a UDP flow enters the connection tunnel while keeping
// Fortnite match/control UDP direct through fnport's port prober.
func (r *connectionRouter) selectedUDP(src, dst netip.AddrPort, game bool) bool {
	if r == nil || !r.settings.Enabled {
		return false
	}
	matchPort := (dst.Port() >= 9000 && dst.Port() <= 9999) || (dst.Port() >= 15000 && dst.Port() <= 15999)
	if (game || matchPort) && len(r.settings.Processes) == 0 && r.ownerLookup == nil {
		return false
	}
	if !game && !matchPort {
		if r.settings.Discord && dst.Port() >= 50000 && dst.Port() <= 65535 && inPrefixes(dst.Addr(), vpn.DiscordVoicePrefixes) {
			return true
		}
		if svc := r.leases.ServiceOf(dst.Addr()); (svc == "discord" || svc == "extra") &&
			(dst.Port() == 443 || (dst.Port() >= 50000 && dst.Port() <= 65535)) {
			return true
		}
	}
	if len(r.settings.Processes) == 0 && r.ownerLookup == nil && !r.settings.Discord {
		return false
	}
	o := r.owner(17, src, dst)
	if (game || matchPort) && strings.HasPrefix(strings.ToLower(o.Name), "fortnite") {
		return false
	}
	return r.settings.selects(o, "")
}

func connectionContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, 12*time.Second)
}

func (c *controller) connectionStatus() string {
	c.mu.Lock()
	t := c.tcp
	c.mu.Unlock()
	if t == nil || t.connection == nil {
		return "Подключение выключено."
	}
	r := t.connection
	if r.settings.Protocol == "warp" {
		if st := t.warpStatus(false); st != "" {
			return st
		}
		return "ищет выход…"
	}
	if tr := r.transport; tr != nil {
		select {
		case <-tr.done:
			tr.mu.Lock()
			code := tr.exitCode
			tr.mu.Unlock()
			return fmt.Sprintf("ядро завершилось (код %d) — перезапустите fnport", code)
		default:
		}
	}
	n := r.conns.Load()
	if rep := r.exitReport.Load(); rep != nil && rep.Colo != "" {
		return fmt.Sprintf("подключено (%s), соединений: %d", vpn.ExitName(rep.Colo), n)
	}
	if n > 0 {
		return fmt.Sprintf("активно, соединений: %d", n)
	}
	return "готово к работе"
}

func (c *controller) connectionExit() *vpn.ExitReport {
	c.mu.Lock()
	t := c.tcp
	c.mu.Unlock()
	if t == nil || t.connection == nil {
		return nil
	}
	if t.connection.settings.Protocol == "warp" {
		if w := t.warp.Load(); w != nil {
			colo, loc, ip := w.exitParts()
			if colo != "" {
				country := vpn.ColoCountry[colo]
				if country == "" {
					country = loc
				}
				return &vpn.ExitReport{Colo: colo, Country: country, Address: ip}
			}
		}
		return nil
	}
	return t.connection.exitReport.Load()
}

func (c *controller) nativeAWGActive() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tcp != nil && c.tcp.connection != nil && c.tcp.connection.native != nil
}
