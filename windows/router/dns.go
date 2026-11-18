package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/YUNGSLXRD/fnport/windows/internal/vpn"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/proxy"
)

type addressLease = vpn.AddressLease

type serviceAddresses struct {
	vpn.LeaseCache
}

func (s *serviceAddresses) learn(service string, wire []byte, now time.Time) {
	s.Learn(service, wire, now)
}

func (s *serviceAddresses) snapshot(now time.Time) ([]addressLease, bool) {
	return s.Snapshot(now)
}

type dnsBroker struct {
	cfg     routerConfig
	epic    []string
	discord []string
	extra   []string
	cache   *serviceAddresses
	allow   func(netip.Addr) bool
	resolve func(context.Context, []byte, bool) ([]byte, error)
	publish func(context.Context) error
	ready   chan<- struct{}
	doh     *vpn.DoHClient
}

func newDNSBroker(c routerConfig, epic, discord []string, cache *serviceAddresses, allow func(netip.Addr) bool) *dnsBroker {
	b := &dnsBroker{
		cfg:     c,
		epic:    epic,
		discord: discord,
		extra:   c.Domains,
		cache:   cache,
		allow:   allow,
		doh:     vpn.NewDoHClient(c.DNSMode, c.DNSProvider, dialCore),
	}
	b.resolve = b.upstream
	return b
}

func (b *dnsBroker) service(host string) string {
	if b.cfg.Epic && !vpn.IsEpicBeacon(host) && domainMatch(host, b.epic) {
		return "epic"
	}
	if b.cfg.Discord && domainMatch(host, b.discord) {
		return "discord"
	}
	if domainMatch(host, b.extra) {
		return "extra"
	}
	return ""
}

func (b *dnsBroker) answer(parent context.Context, wire []byte) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(wire)
	if err != nil || h.Response || h.OpCode != 0 {
		return nil
	}
	q, err := p.AllQuestions()
	if err != nil || len(q) != 1 {
		return vpn.DNSFailure(wire, dnsmessage.RCodeFormatError)
	}
	service := b.service(q[0].Name.String())
	// The service tunnel is IPv4. Suppress only selected-service AAAA answers,
	// including queries received over IPv6 DNS; unrelated/local DNS is unchanged.
	if service != "" && q[0].Type == dnsmessage.TypeAAAA {
		return vpn.DNSFailure(wire, dnsmessage.RCodeSuccess)
	}
	ctx, cancel := context.WithTimeout(parent, 6*time.Second)
	defer cancel()
	reply, err := b.resolve(ctx, wire, service != "")
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
	if service != "" {
		b.cache.learn(service, reply, time.Now())
		// Publish routes before the client can open its first connection.
		if b.publish != nil && b.publish(ctx) != nil {
			return vpn.DNSFailure(wire, dnsmessage.RCodeServerFailure)
		}
	}
	return reply
}

func dialCore(ctx context.Context, addr string) (net.Conn, error) {
	d, err := proxy.SOCKS5("tcp", "127.0.0.1:"+strconv.Itoa(socksPort), nil, &net.Dialer{Timeout: 6 * time.Second})
	if err != nil {
		return nil, errors.New("local_proxy_unavailable")
	}
	return d.(proxy.ContextDialer).DialContext(ctx, "tcp", addr)
}

func forwardLocalDNS(ctx context.Context, wire []byte) ([]byte, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	if len(wire) <= 1232 {
		uc, err := d.DialContext(ctx, "udp4", "127.0.0.1:53")
		if err == nil {
			stop := context.AfterFunc(ctx, func() { _ = uc.Close() })
			if deadline, ok := ctx.Deadline(); ok {
				_ = uc.SetDeadline(deadline)
			} else {
				_ = uc.SetDeadline(time.Now().Add(4 * time.Second))
			}
			_, werr := uc.Write(wire)
			buf := make([]byte, 4096)
			var n int
			var rerr error
			if werr == nil {
				n, rerr = uc.Read(buf)
			}
			stop()
			_ = uc.Close()
			if werr == nil && rerr == nil && n >= 12 {
				var p dnsmessage.Parser
				if h, perr := p.Start(buf[:n]); perr == nil && !h.Truncated {
					return buf[:n], nil
				}
			}
		}
	}
	tc, err := d.DialContext(ctx, "tcp4", "127.0.0.1:53")
	if err != nil {
		return nil, errors.New("router_dns_unavailable")
	}
	defer tc.Close()
	stop := context.AfterFunc(ctx, func() { _ = tc.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = tc.SetDeadline(deadline)
	}
	if err := vpn.WriteTCPDNS(tc, wire); err != nil {
		return nil, err
	}
	return vpn.ReadTCPDNS(tc)
}

func (b *dnsBroker) upstream(ctx context.Context, wire []byte, selected bool) ([]byte, error) {
	if !selected {
		return forwardLocalDNS(ctx, wire)
	}
	return b.doh.Exchange(ctx, wire)
}

func (b *dnsBroker) preResolveServices(ctx context.Context) {
	if b.doh == nil {
		return
	}
	type target struct {
		service string
		domains []string
	}
	var targets []target
	if b.cfg.Discord {
		targets = append(targets, target{"discord", vpn.DiscordPreResolveDomains})
	}
	if len(b.extra) > 0 {
		limit := min(len(b.extra), 16)
		targets = append(targets, target{"extra", b.extra[:limit]})
	}
	changed := false
	for _, t := range targets {
		for _, dom := range t.domains {
			if ctx.Err() != nil {
				return
			}
			ips := b.doh.LookupA(ctx, dom)
			if len(b.cache.AddStatic(t.service, ips, 10*time.Minute)) > 0 {
				changed = true
			}
		}
	}
	if changed && b.publish != nil {
		pctx, cancel := context.WithTimeout(ctx, 4*time.Second)
		_ = b.publish(pctx)
		cancel()
	}
}

func (b *dnsBroker) serve(ctx context.Context, addr string) error {
	udp, err := net.ListenPacket("udp", addr)
	if err != nil {
		return errors.New("dns_port_unavailable")
	}
	tcp, err := net.Listen("tcp", addr)
	if err != nil {
		_ = udp.Close()
		return errors.New("dns_port_unavailable")
	}
	stop := context.AfterFunc(ctx, func() {
		_ = udp.Close()
		_ = tcp.Close()
		b.doh.CloseIdle()
	})
	defer stop()
	defer udp.Close()
	defer tcp.Close()
	if b.ready != nil {
		close(b.ready)
	}
	slots := make(chan struct{}, 64)
	allowed := func(a net.Addr) bool {
		host, _, err := net.SplitHostPort(a.String())
		if err != nil {
			return false
		}
		ip, err := netip.ParseAddr(host)
		return err == nil && b.allow != nil && b.allow(ip.Unmap().WithZone(""))
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			if !allowed(from) {
				continue
			}
			select {
			case slots <- struct{}{}:
			default:
				continue
			}
			wire := append([]byte(nil), buf[:n]...)
			go func() {
				defer func() { <-slots }()
				if reply := b.answer(ctx, wire); len(reply) > 0 {
					_, _ = udp.WriteTo(reply, from)
				}
			}()
		}
	}()
	for {
		c, err := tcp.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errors.New("dns_listener_failed")
		}
		if !allowed(c.RemoteAddr()) {
			_ = c.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = c.Close()
			continue
		}
		go func() {
			defer func() { _ = c.Close(); <-slots }()
			stopConn := context.AfterFunc(ctx, func() { _ = c.Close() })
			defer stopConn()
			for i := 0; i < 16; i++ {
				_ = c.SetDeadline(time.Now().Add(7 * time.Second))
				wire, err := vpn.ReadTCPDNS(c)
				if err != nil {
					return
				}
				reply := b.answer(ctx, wire)
				if len(reply) == 0 || vpn.WriteTCPDNS(c, reply) != nil {
					return
				}
			}
		}()
	}
}
