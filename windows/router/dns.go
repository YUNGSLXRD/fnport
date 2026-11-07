package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/proxy"
)

type addressLease struct {
	IP      netip.Addr
	Service string
	Until   time.Time
}
type serviceAddresses struct {
	sync.Mutex
	rows  map[string]addressLease
	dirty bool
}

func (s *serviceAddresses) learn(service string, wire []byte, now time.Time) {
	var p dnsmessage.Parser
	h, err := p.Start(wire)
	if err != nil || h.RCode != dnsmessage.RCodeSuccess {
		return
	}
	if _, err = p.AllQuestions(); err != nil {
		return
	}
	answers, err := p.AllAnswers()
	if err != nil {
		return
	}
	s.Lock()
	defer s.Unlock()
	if s.rows == nil {
		s.rows = map[string]addressLease{}
	}
	for key, l := range s.rows {
		if !l.Until.After(now) {
			delete(s.rows, key)
			s.dirty = true
		}
	}
	for _, a := range answers {
		body, ok := a.Body.(*dnsmessage.AResource)
		if !ok || a.Header.TTL == 0 {
			continue
		}
		ip := netip.AddrFrom4(body.A)
		if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || netip.MustParsePrefix("198.18.0.0/15").Contains(ip) {
			continue
		}
		key := service + "/" + ip.String()
		until := now.Add(time.Duration(min(a.Header.TTL, 3600)) * time.Second)
		if old, ok := s.rows[key]; ok && old.Until.After(until) {
			continue
		}
		if len(s.rows) >= 4096 {
			if _, exists := s.rows[key]; !exists {
				continue
			}
		}
		s.rows[key] = addressLease{ip, service, until}
		s.dirty = true
	}
}
func (s *serviceAddresses) snapshot(now time.Time) ([]addressLease, bool) {
	s.Lock()
	defer s.Unlock()
	for k, l := range s.rows {
		if !l.Until.After(now) {
			delete(s.rows, k)
			s.dirty = true
		}
	}
	out := make([]addressLease, 0, len(s.rows))
	for _, l := range s.rows {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Service != out[j].Service {
			return out[i].Service < out[j].Service
		}
		return out[i].IP.Less(out[j].IP)
	})
	changed := s.dirty
	s.dirty = false
	return out, changed
}

type dnsBroker struct {
	cfg                  routerConfig
	epic, discord, extra []string
	cache                *serviceAddresses
	allow                func(netip.Addr) bool
	resolve              func(context.Context, []byte, bool) ([]byte, error)
	publish              func(context.Context) error
	ready                chan<- struct{}
	transport            *http.Transport
	client               *http.Client
}

func newDNSBroker(c routerConfig, epic, discord []string, cache *serviceAddresses, allow func(netip.Addr) bool) *dnsBroker {
	b := &dnsBroker{cfg: c, epic: epic, discord: discord, extra: c.Domains, cache: cache, allow: allow}
	provider := dnsProviders[c.DNSProvider]
	b.transport = &http.Transport{ForceAttemptHTTP2: true, MaxIdleConnsPerHost: 4,
		TLSClientConfig: &tls.Config{ServerName: provider.Host, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialCore(ctx, net.JoinHostPort(provider.IP, "443"))
		}}
	b.client = &http.Client{Transport: b.transport, Timeout: 6 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("dns_redirect_rejected") }}
	b.resolve = b.upstream
	return b
}
func (b *dnsBroker) service(host string) string {
	if b.cfg.Epic && domainMatch(host, b.epic) {
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
func dnsFailure(wire []byte, code dnsmessage.RCode) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(wire)
	if err != nil {
		return nil
	}
	q, err := p.AllQuestions()
	if err != nil || len(q) != 1 {
		return nil
	}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionDesired: h.RecursionDesired, RecursionAvailable: true, RCode: code})
	if builder.StartQuestions() != nil || builder.Question(q[0]) != nil {
		return nil
	}
	out, _ := builder.Finish()
	return out
}
func (b *dnsBroker) answer(parent context.Context, wire []byte) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(wire)
	if err != nil || h.Response || h.OpCode != 0 {
		return nil
	}
	q, err := p.AllQuestions()
	if err != nil || len(q) != 1 {
		return dnsFailure(wire, dnsmessage.RCodeFormatError)
	}
	service := b.service(q[0].Name.String())
	// The service tunnel is IPv4. Suppress only selected-service AAAA answers,
	// including queries received over IPv6 DNS; unrelated/local DNS is unchanged.
	if service != "" && q[0].Type == dnsmessage.TypeAAAA {
		return dnsFailure(wire, dnsmessage.RCodeSuccess)
	}
	ctx, cancel := context.WithTimeout(parent, 6*time.Second)
	defer cancel()
	reply, err := b.resolve(ctx, wire, service != "")
	if err != nil {
		return dnsFailure(wire, dnsmessage.RCodeServerFailure)
	}
	var rp dnsmessage.Parser
	rh, err := rp.Start(reply)
	if err != nil || !rh.Response || rh.ID != h.ID {
		return dnsFailure(wire, dnsmessage.RCodeServerFailure)
	}
	rq, err := rp.AllQuestions()
	if err != nil || len(rq) != 1 || rq[0].Type != q[0].Type || !strings.EqualFold(rq[0].Name.String(), q[0].Name.String()) {
		return dnsFailure(wire, dnsmessage.RCodeServerFailure)
	}
	if service != "" {
		b.cache.learn(service, reply, time.Now())
		// Publish routes before the client can open its first connection.
		if b.publish != nil && b.publish(ctx) != nil {
			return dnsFailure(wire, dnsmessage.RCodeServerFailure)
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
func readDNS(c net.Conn) ([]byte, error) {
	var size [2]byte
	if _, err := io.ReadFull(c, size[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(size[:])
	if n < 12 {
		return nil, errors.New("short_dns_response")
	}
	b := make([]byte, n)
	_, err := io.ReadFull(c, b)
	return b, err
}
func writeDNS(c net.Conn, wire []byte) error {
	if len(wire) > 65535 {
		return errors.New("dns_message_too_large")
	}
	b := make([]byte, len(wire)+2)
	binary.BigEndian.PutUint16(b, uint16(len(wire)))
	copy(b[2:], wire)
	for len(b) > 0 {
		n, err := c.Write(b)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
func (b *dnsBroker) upstream(ctx context.Context, wire []byte, selected bool) ([]byte, error) {
	if !selected {
		// Keep the existing router resolver and local/Forkop domain policy.
		d := net.Dialer{Timeout: 6 * time.Second}
		c, err := d.DialContext(ctx, "tcp4", "127.0.0.1:53")
		if err != nil {
			return nil, errors.New("router_dns_unavailable")
		}
		defer c.Close()
		stop := context.AfterFunc(ctx, func() { c.Close() })
		defer stop()
		if deadline, ok := ctx.Deadline(); ok {
			c.SetDeadline(deadline)
		}
		if err := writeDNS(c, wire); err != nil {
			return nil, err
		}
		return readDNS(c)
	}
	provider := dnsProviders[b.cfg.DNSProvider]
	if b.cfg.DNSMode == "https" {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+provider.Host+provider.Path, bytes.NewReader(wire))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")
		res, err := b.client.Do(req)
		if err != nil {
			return nil, errors.New("dns_https_failed")
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			return nil, errors.New("dns_https_status")
		}
		out, err := io.ReadAll(io.LimitReader(res.Body, 65536))
		if len(out) > 65535 {
			return nil, errors.New("dns_message_too_large")
		}
		return out, err
	}
	port := "53"
	if b.cfg.DNSMode == "tls" {
		port = "853"
	}
	c, err := dialCore(ctx, net.JoinHostPort(provider.IP, port))
	if err != nil {
		return nil, err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		c.SetDeadline(deadline)
	}
	if b.cfg.DNSMode == "tls" {
		tc := tls.Client(c, &tls.Config{ServerName: provider.Host, MinVersion: tls.VersionTLS12})
		if tc.HandshakeContext(ctx) != nil {
			return nil, errors.New("dns_tls_failed")
		}
		c = tc
	}
	if err := writeDNS(c, wire); err != nil {
		return nil, err
	}
	return readDNS(c)
}

func (b *dnsBroker) serve(ctx context.Context, addr string) error {
	udp, err := net.ListenPacket("udp", addr)
	if err != nil {
		return errors.New("dns_port_unavailable")
	}
	tcp, err := net.Listen("tcp", addr)
	if err != nil {
		udp.Close()
		return errors.New("dns_port_unavailable")
	}
	stop := context.AfterFunc(ctx, func() { udp.Close(); tcp.Close(); b.transport.CloseIdleConnections() })
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
					udp.WriteTo(reply, from)
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
			c.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			c.Close()
			continue
		}
		go func() {
			defer func() { c.Close(); <-slots }()
			stop := context.AfterFunc(ctx, func() { c.Close() })
			defer stop()
			for i := 0; i < 16; i++ {
				c.SetDeadline(time.Now().Add(7 * time.Second))
				wire, err := readDNS(c)
				if err != nil {
					return
				}
				reply := b.answer(ctx, wire)
				if len(reply) == 0 || writeDNS(c, reply) != nil {
					return
				}
			}
		}()
	}
}
