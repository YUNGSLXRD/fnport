package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/YUNGSLXRD/fnport/windows/internal/vpn"
	"github.com/YUNGSLXRD/fnport/windows/internal/wnet"
	"golang.org/x/net/dns/dnsmessage"
)

const dnsTypeHTTPS = dnsmessage.Type(65)

type winDNSBroker struct {
	router      *connectionRouter
	leases      *vpn.LeaseCache
	routed      []netip.Prefix
	addRoute    func(netip.Prefix) error
	dohPrimary  *vpn.DoHClient
	dohFallback *vpn.DoHClient
	sem         chan struct{}

	routeMu     sync.Mutex
	addedRoutes map[netip.Addr]bool
}

func newWinDNSBroker(router *connectionRouter, dev wnet.Dev, routed []netip.Prefix) *winDNSBroker {
	var addRoute func(netip.Prefix) error
	if adder, ok := dev.(interface{ AddRoute(netip.Prefix) error }); ok {
		addRoute = adder.AddRoute
	}
	dialTunnel := func(ctx context.Context, addr string) (net.Conn, error) {
		ap, err := netip.ParseAddrPort(addr)
		if err != nil {
			return nil, err
		}
		return router.dial(ctx, ap, false)
	}
	b := &winDNSBroker{
		router:      router,
		leases:      &vpn.LeaseCache{},
		routed:      append([]netip.Prefix(nil), routed...),
		addRoute:    addRoute,
		dohPrimary:  vpn.NewDoHClient("https", "cloudflare", dialTunnel),
		dohFallback: vpn.NewDoHClient("https", "google", dialTunnel),
		sem:         make(chan struct{}, 64),
		addedRoutes: make(map[netip.Addr]bool),
	}
	router.leases = b.leases
	return b
}

func (b *winDNSBroker) closeIdle() {
	if b == nil {
		return
	}
	b.dohPrimary.CloseIdle()
	b.dohFallback.CloseIdle()
}

func (b *winDNSBroker) service(host string) string {
	if b == nil || b.router == nil || !b.router.settings.Enabled {
		return ""
	}
	s := b.router.settings
	if s.Epic && vpn.MatchEpic(host, nil) {
		return "epic"
	}
	if s.Discord && vpn.MatchDomain(host, vpn.DiscordDomains) {
		return "discord"
	}
	if vpn.MatchDomain(host, s.Domains) {
		return "extra"
	}
	return ""
}

func (b *winDNSBroker) installIPs(service string, ips []netip.Addr) int {
	if len(ips) == 0 {
		return 0
	}
	b.routeMu.Lock()
	defer b.routeMu.Unlock()
	installed := 0
	for _, ip := range ips {
		ip = ip.Unmap()
		if !vpn.IsRoutableIPv4(ip) || b.addedRoutes[ip] {
			continue
		}
		b.addedRoutes[ip] = true
		if b.addRoute != nil && !inPrefixes(ip, b.routed) {
			if err := b.addRoute(netip.PrefixFrom(ip, 32)); err == nil {
				installed++
			}
		}
	}
	return installed
}

// Match the DNS socket itself. A shared Windows DNS Client socket cannot identify
// the original caller and keeps the existing domain-based policy.
func (b *winDNSBroker) selectedDNSProcess(proto uint8, src, dst netip.AddrPort) bool {
	processes := b.router.settings.Processes
	if len(processes) == 0 {
		return false
	}
	return selectedProcess(b.router.owner(proto, src, dst).Name, processes)
}

func (b *winDNSBroker) answer(parent context.Context, wire []byte, selectedProcess bool) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(wire)
	if err != nil || h.Response || h.OpCode != 0 {
		return nil
	}
	q, err := p.AllQuestions()
	if err != nil || len(q) != 1 {
		return vpn.DNSFailure(wire, dnsmessage.RCodeFormatError)
	}
	svc := b.service(q[0].Name.String())
	tunnelDNS := svc != "" || selectedProcess
	if tunnelDNS && (q[0].Type == dnsmessage.TypeAAAA || q[0].Type == dnsTypeHTTPS) {
		return vpn.DNSFailure(wire, dnsmessage.RCodeSuccess)
	}

	ctx, cancel := context.WithTimeout(parent, 6*time.Second)
	defer cancel()

	var reply []byte
	if tunnelDNS {
		reply, err = b.dohPrimary.Exchange(ctx, wire)
		if err != nil && ctx.Err() == nil {
			reply, err = b.dohFallback.Exchange(ctx, wire)
		}
		// While Epic is in direct-first mode and the tunnel is still starting up,
		// fall back to physical DNS and route the learned Epic IP into fnport.
		if err != nil && !selectedProcess && svc == "epic" && !b.router.always.Load() && ctx.Err() == nil {
			reply, err = forwardPhysicalDNS(ctx, wire)
		}
	} else {
		reply, err = forwardPhysicalDNS(ctx, wire)
	}
	if err != nil {
		return vpn.DNSFailure(wire, dnsmessage.RCodeServerFailure)
	}

	var rp dnsmessage.Parser
	rh, err := rp.Start(reply)
	if err != nil || !rh.Response || rh.ID != h.ID {
		return vpn.DNSFailure(wire, dnsmessage.RCodeServerFailure)
	}
	rq, err := rp.AllQuestions()
	if err != nil || len(rq) != 1 || rq[0].Type != q[0].Type || !strings.EqualFold(rq[0].Name.String(), q[0].Name.String()) {
		return vpn.DNSFailure(wire, dnsmessage.RCodeServerFailure)
	}
	if svc != "" {
		added := b.leases.Learn(svc, reply, time.Now())
		b.installIPs(svc, added)
	}
	return reply
}

func (b *winDNSBroker) handleUDPPacket(ctx context.Context, dev wnet.Dev, p wnet.UDPPacket, nextIPID func() uint16) {
	select {
	case b.sem <- struct{}{}:
	default:
		return
	}
	payload := append([]byte(nil), p.Payload...)
	src, dst := p.Src, p.Dst
	go func() {
		defer func() { <-b.sem }()
		reply := b.answer(ctx, payload, b.selectedDNSProcess(17, src, dst))
		if len(reply) > 0 {
			_ = dev.WritePacket(wnet.BuildUDP4(dst, src, reply, nextIPID()))
		}
	}()
}

func (b *winDNSBroker) serveTCPConn(ctx context.Context, c net.Conn, src, dst netip.AddrPort) {
	defer c.Close()
	selected := b.selectedDNSProcess(6, src, dst)
	_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	for {
		wire, err := vpn.ReadTCPDNS(c)
		if err != nil {
			return
		}
		reply := b.answer(ctx, wire, selected)
		if len(reply) == 0 {
			return
		}
		if err := vpn.WriteTCPDNS(c, reply); err != nil {
			return
		}
		_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	}
}

// refreshServiceRoutes pre-resolves configured service domains at startup and periodically
// so already-running Epic Launcher / Discord clients with cached DNS still enter the tunnel.
func (b *winDNSBroker) refreshServiceRoutes(ctx context.Context, tunnelReady bool) {
	if b == nil || b.router == nil || !b.router.settings.Enabled {
		return
	}
	s := b.router.settings
	resolveGroup := func(svc string, domains []string, useTunnelDoH bool) int {
		addedCount := 0
		for _, host := range domains {
			if ctx.Err() != nil {
				return addedCount
			}
			var ips []netip.Addr
			if useTunnelDoH && tunnelReady {
				ips = append(ips, b.dohPrimary.LookupA(ctx, host)...)
			}
			if !useTunnelDoH || len(ips) == 0 {
				ips = append(ips, lookupAllContext(ctx, host)...)
			}
			newIPs := b.leases.AddStatic(svc, ips, 15*time.Minute)
			addedCount += b.installIPs(svc, newIPs)
		}
		return addedCount
	}

	if s.Epic {
		if n := resolveGroup("epic", vpn.EpicDomains, false); n > 0 && tunnelReady {
			logf("Подключения: у сервисов Epic %d новых адресов направлены в адаптер", n)
		}
	}
	if s.Discord {
		discordList := append(append([]string(nil), vpn.DiscordPreResolveDomains...), vpn.DiscordDomains...)
		resolveGroup("discord", discordList, true)
	}
	if len(s.Domains) > 0 {
		resolveGroup("extra", s.Domains, true)
	}
}

func forwardPhysicalDNS(ctx context.Context, wire []byte) ([]byte, error) {
	servers := wnet.PhysicalDNS()
	var lastErr error
	for _, srv := range servers {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		dst := netip.AddrPortFrom(srv, 53)
		reply, truncated, err := exchangeUDPPhysical(ctx, dst, wire)
		if err == nil && !truncated {
			return reply, nil
		}
		if truncated {
			if tcpReply, tcpErr := exchangeTCPPhysical(ctx, dst, wire); tcpErr == nil {
				return tcpReply, nil
			}
		}
		if err == nil {
			return reply, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("physical_dns_unavailable")
	}
	return nil, lastErr
}

func exchangeUDPPhysical(parent context.Context, dst netip.AddrPort, wire []byte) ([]byte, bool, error) {
	ctx, cancel := context.WithTimeout(parent, 2500*time.Millisecond)
	defer cancel()
	c, err := wnet.DialUDP(ctx, dst)
	if err != nil {
		return nil, false, err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if _, err := c.Write(wire); err != nil {
		return nil, false, err
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		return nil, false, err
	}
	if n < 12 {
		return nil, false, io.ErrUnexpectedEOF
	}
	var p dnsmessage.Parser
	h, err := p.Start(buf[:n])
	if err != nil {
		return nil, false, err
	}
	return buf[:n], h.Truncated, nil
}

func exchangeTCPPhysical(parent context.Context, dst netip.AddrPort, wire []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, 4*time.Second)
	defer cancel()
	c, err := wnet.DialTCP(ctx, dst)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if err := vpn.WriteTCPDNS(c, wire); err != nil {
		return nil, err
	}
	return vpn.ReadTCPDNS(c)
}
