package vpn

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
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var fakeIPRange = netip.MustParsePrefix("198.18.0.0/15")

// IsFakeIP reports whether a belongs to the benchmark/FakeIP range 198.18.0.0/15.
func IsFakeIP(a netip.Addr) bool {
	return fakeIPRange.Contains(a.Unmap())
}

// IsRoutableIPv4 reports whether ip is a public unicast IPv4 address outside FakeIP space.
func IsRoutableIPv4(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.Is4() && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !IsFakeIP(ip)
}

// DNSProvider describes an encrypted DNS resolver reachable through a tunnel.
type DNSProvider struct {
	IP   string
	Host string
	Path string
}

// DNSProviders maps provider IDs to their DoH/DoT endpoints.
var DNSProviders = map[string]DNSProvider{
	"cloudflare": {"1.1.1.1", "cloudflare-dns.com", "/dns-query"},
	"google":     {"8.8.8.8", "dns.google", "/dns-query"},
	"quad9":      {"9.9.9.9", "dns.quad9.net", "/dns-query"},
}

// AddressLease tracks an IPv4 address learned from a selected-service DNS reply.
type AddressLease struct {
	IP      netip.Addr
	Service string
	Until   time.Time
}

// LeaseCache stores learned service IPv4 leases and tracks structural changes
// without marking the set dirty on routine TTL extensions of existing addresses.
type LeaseCache struct {
	mu    sync.RWMutex
	rows  map[string]AddressLease
	byIP  map[netip.Addr]string
	dirty bool
}

// Learn parses A records from wire, updates leases for service, and returns newly added IPs.
func (c *LeaseCache) Learn(service string, wire []byte, now time.Time) []netip.Addr {
	var p dnsmessage.Parser
	h, err := p.Start(wire)
	if err != nil || h.RCode != dnsmessage.RCodeSuccess {
		return nil
	}
	if _, err := p.AllQuestions(); err != nil {
		return nil
	}
	answers, err := p.AllAnswers()
	if err != nil {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rows == nil {
		c.rows = make(map[string]AddressLease)
		c.byIP = make(map[netip.Addr]string)
	}
	c.pruneLocked(now)

	var added []netip.Addr
	for _, a := range answers {
		body, ok := a.Body.(*dnsmessage.AResource)
		if !ok || a.Header.TTL == 0 {
			continue
		}
		ip := netip.AddrFrom4(body.A)
		if !IsRoutableIPv4(ip) {
			continue
		}
		key := service + "/" + ip.String()
		ttlSec := max(uint32(1), min(a.Header.TTL, 3600))
		until := now.Add(time.Duration(ttlSec) * time.Second)
		old, exists := c.rows[key]
		if exists {
			if until.After(old.Until) {
				// Refresh nftables timeout only when less than a third of the new TTL remains.
				if old.Until.Sub(now) < time.Duration(ttlSec)*time.Second/3 {
					c.dirty = true
				}
				c.rows[key] = AddressLease{IP: ip, Service: service, Until: until}
			}
			continue
		}
		if len(c.rows) >= 4096 {
			continue
		}
		c.rows[key] = AddressLease{IP: ip, Service: service, Until: until}
		c.byIP[ip] = service
		c.dirty = true
		added = append(added, ip)
	}
	return added
}

// AddStatic registers pre-resolved IPv4 addresses for service with the given TTL.
func (c *LeaseCache) AddStatic(service string, ips []netip.Addr, ttl time.Duration) []netip.Addr {
	now := time.Now()
	until := now.Add(ttl)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rows == nil {
		c.rows = make(map[string]AddressLease)
		c.byIP = make(map[netip.Addr]string)
	}
	c.pruneLocked(now)
	var added []netip.Addr
	for _, ip := range ips {
		ip = ip.Unmap()
		if !IsRoutableIPv4(ip) {
			continue
		}
		key := service + "/" + ip.String()
		if old, exists := c.rows[key]; exists {
			if until.After(old.Until) {
				c.rows[key] = AddressLease{IP: ip, Service: service, Until: until}
			}
			continue
		}
		if len(c.rows) >= 4096 {
			continue
		}
		c.rows[key] = AddressLease{IP: ip, Service: service, Until: until}
		c.byIP[ip] = service
		c.dirty = true
		added = append(added, ip)
	}
	return added
}

// ServiceOf returns the service ("epic", "discord", "extra") that owns ip, or "".
func (c *LeaseCache) ServiceOf(ip netip.Addr) string {
	if c == nil {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.byIP[ip.Unmap()]
}

// Snapshot returns active leases sorted deterministically and whether the set changed.
func (c *LeaseCache) Snapshot(now time.Time) ([]AddressLease, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(now)
	out := make([]AddressLease, 0, len(c.rows))
	for _, l := range c.rows {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Service != out[j].Service {
			return out[i].Service < out[j].Service
		}
		return out[i].IP.Less(out[j].IP)
	})
	changed := c.dirty
	c.dirty = false
	return out, changed
}

// MarkDirty forces the next Snapshot call to report changed=true (e.g. after a transient firewall publish error).
func (c *LeaseCache) MarkDirty() {
	c.mu.Lock()
	c.dirty = true
	c.mu.Unlock()
}

func (c *LeaseCache) pruneLocked(now time.Time) {
	for key, l := range c.rows {
		if !l.Until.After(now) {
			delete(c.rows, key)
			delete(c.byIP, l.IP)
			c.dirty = true
		}
	}
}

// DNSFailure builds a minimal DNS response with the given RCode preserving the question.
func DNSFailure(wire []byte, code dnsmessage.RCode) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(wire)
	if err != nil {
		return nil
	}
	q, err := p.AllQuestions()
	if err != nil || len(q) != 1 {
		return nil
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 h.ID,
		Response:           true,
		RecursionDesired:   h.RecursionDesired,
		RecursionAvailable: true,
		RCode:              code,
	})
	if b.StartQuestions() != nil || b.Question(q[0]) != nil {
		return nil
	}
	out, _ := b.Finish()
	return out
}

// ReadTCPDNS reads a single length-prefixed DNS message from a TCP stream.
func ReadTCPDNS(c net.Conn) ([]byte, error) {
	var size [2]byte
	if _, err := io.ReadFull(c, size[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(size[:])
	if n < 12 {
		return nil, errors.New("short_dns_message")
	}
	b := make([]byte, n)
	_, err := io.ReadFull(c, b)
	return b, err
}

// WriteTCPDNS writes a single length-prefixed DNS message to a TCP stream.
func WriteTCPDNS(c net.Conn, wire []byte) error {
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

// DoHClient queries DNS-over-HTTPS (or DoT/plain DNS) through a tunnel dialer.
type DoHClient struct {
	Mode      string
	Provider  DNSProvider
	Dial      func(context.Context, string) (net.Conn, error)
	transport *http.Transport
	client    *http.Client
}

// NewDoHClient creates a tunnel-backed DNS resolver.
func NewDoHClient(mode, providerName string, dial func(context.Context, string) (net.Conn, error)) *DoHClient {
	if mode == "" {
		mode = "https"
	}
	p, ok := DNSProviders[providerName]
	if !ok {
		p = DNSProviders["cloudflare"]
	}
	tr := &http.Transport{
		ForceAttemptHTTP2:   true,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     60 * time.Second,
		TLSClientConfig:     &tls.Config{ServerName: p.Host, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dial(ctx, net.JoinHostPort(p.IP, "443"))
		},
	}
	cl := &http.Client{
		Transport: tr,
		Timeout:   6 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("dns_redirect_rejected")
		},
	}
	return &DoHClient{Mode: mode, Provider: p, Dial: dial, transport: tr, client: cl}
}

// CloseIdle closes any pooled DoH HTTP/2 connections (e.g. after a tunnel rebuild).
func (d *DoHClient) CloseIdle() {
	if d != nil && d.transport != nil {
		d.transport.CloseIdleConnections()
	}
}

// Exchange sends a raw DNS query wire packet through the tunnel.
func (d *DoHClient) Exchange(ctx context.Context, wire []byte) ([]byte, error) {
	if d.Mode == "https" {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+d.Provider.Host+d.Provider.Path, bytes.NewReader(wire))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")
		res, err := d.client.Do(req)
		if err != nil {
			return nil, errors.New("dns_https_failed")
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			return nil, errors.New("dns_https_status")
		}
		out, err := io.ReadAll(io.LimitReader(res.Body, 65536))
		if len(out) > 65535 {
			return nil, errors.New("dns_message_too_large")
		}
		return out, err
	}
	port := "53"
	if d.Mode == "tls" {
		port = "853"
	}
	c, err := d.Dial(ctx, net.JoinHostPort(d.Provider.IP, port))
	if err != nil {
		return nil, err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	}
	if d.Mode == "tls" {
		tc := tls.Client(c, &tls.Config{ServerName: d.Provider.Host, MinVersion: tls.VersionTLS12})
		if tc.HandshakeContext(ctx) != nil {
			return nil, errors.New("dns_tls_failed")
		}
		c = tc
	}
	if err := WriteTCPDNS(c, wire); err != nil {
		return nil, err
	}
	return ReadTCPDNS(c)
}

// LookupA queries A records for host via DoH through the tunnel and returns public IPv4 addresses.
func (d *DoHClient) LookupA(ctx context.Context, host string) []netip.Addr {
	name := strings.TrimSuffix(strings.TrimSpace(host), ".") + "."
	dn, err := dnsmessage.NewName(name)
	if err != nil {
		return nil
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, RecursionDesired: true})
	if b.StartQuestions() != nil || b.Question(dnsmessage.Question{Name: dn, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}) != nil {
		return nil
	}
	wire, err := b.Finish()
	if err != nil {
		return nil
	}
	qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	reply, err := d.Exchange(qctx, wire)
	if err != nil {
		return nil
	}
	var p dnsmessage.Parser
	if _, err := p.Start(reply); err != nil || p.SkipAllQuestions() != nil {
		return nil
	}
	answers, err := p.AllAnswers()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range answers {
		if body, ok := a.Body.(*dnsmessage.AResource); ok && a.Header.TTL > 0 {
			ip := netip.AddrFrom4(body.A)
			if IsRoutableIPv4(ip) {
				out = append(out, ip)
			}
		}
	}
	return out
}
