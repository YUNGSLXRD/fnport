package main

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// clientHello: the first record Go's TLS client sends for name (Go 1.24+ sends a post-quantum
// key share, so the record is past one TCP segment, like Chrome's)
func clientHello(t *testing.T, name string) []byte {
	a, b := net.Pipe()
	go tls.Client(a, &tls.Config{ServerName: name, InsecureSkipVerify: true}).Handshake()
	defer a.Close()
	defer b.Close()
	b.SetReadDeadline(time.Now().Add(5 * time.Second))
	return readHello(b)
}

func TestSNI(t *testing.T) {
	for _, name := range []string{"account-public-service-prod.ol.epicgames.com", "example.org"} {
		h := clientHello(t, name)
		if got := sniOf(h); got != name {
			t.Errorf("%s: got %q from %d bytes", name, got, len(h))
		}
	}
	if sniOf([]byte("GET / HTTP/1.1\r\n")) != "" || sniOf(nil) != "" {
		t.Error("a name from what is not a ClientHello")
	}
}

func TestWarpDomains(t *testing.T) {
	names := warpSettings{}.domains()
	for name, want := range map[string]bool{
		"account-public-service-prod.ol.epicgames.com": true, "store.epicgames.com.": true, "epicgames.com": true,
		"api.epicgames.dev": true, "epicgames-download1.akamaized.net": true, "a.akamaized.net": false,
		"notepicgames.com": false, "vk.com": false, "": false,
	} {
		if matchDomain(name, names) != want {
			t.Errorf("%q: want %v", name, want)
		}
	}
}

func TestWarpEndpoints(t *testing.T) {
	eps := warpEndpoints("1.2.3.4:500")
	if eps[0] != "1.2.3.4:500" || !strings.HasPrefix(eps[1], "188.114.96.") {
		t.Fatal(eps[:2])
	}
	for _, e := range eps {
		if strings.HasPrefix(e, "162.159.193.") {
			t.Fatal("a banned endpoint:", e)
		}
	}
}

func TestCleanDomain(t *testing.T) {
	for in, want := range map[string]string{"https://Store.EpicGames.com/": "store.epicgames.com", "*.discord.com": "discord.com",
		"https://static-assets-prod.epicgames.com/static/": "static-assets-prod.epicgames.com", " discord.gg ": "discord.gg", "x.com:443": "x.com"} {
		if got := cleanDomain(in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
	if d := (warpSettings{Domains: []string{"discord.com", "discord.com", ""}}).domains(); len(d) != 1 {
		t.Error(d)
	}
}

func TestParseWarpConf(t *testing.T) {
	conf := `[Interface]
PrivateKey = cGFzc3dvcmRwYXNzd29yZHBhc3N3b3JkcGFzc3dvcmQ=
Address = 172.16.0.2/32, 2606:4700:110:8a36::1/128
DNS = 1.1.1.1
MTU = 1280
Jc = 5
Jmin = 30
Jmax = 60
[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
AllowedIPs = 0.0.0.0/0
Endpoint = 188.114.97.3:500
`
	w, err := parseWarpConf(conf, warpSettings{Jc: 4, Jmin: 40, Jmax: 70, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if w.Address != "172.16.0.2" || w.Endpoint != "188.114.97.3:500" || w.Jc != 5 || w.Jmax != 60 || !w.Enabled || !w.ready() {
		t.Fatalf("%+v", w)
	}
	if _, err := parseWarpConf("[Interface]\nAddress = 1.2.3.4", warpSettings{}); err == nil {
		t.Error("a config without keys taken")
	}
}

func TestSplitConn(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	go func() {
		c := &splitConn{Conn: a, mark: []byte("api.example.com")}
		c.Write([]byte("hello api.example.com bye"))
	}()
	var got []byte
	buf := make([]byte, 64)
	for len(got) < 25 {
		n, err := b.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, buf[:n]...)
	}
	if string(got) != "hello api.example.com bye" {
		t.Fatal(string(got))
	}
}

// the record split keeps the handshake readable for a real TLS server
func TestSplitRecords(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	go func() {
		c := tls.Client(&splitConn{Conn: a, mark: []byte("example.org"), records: true}, &tls.Config{ServerName: "example.org", InsecureSkipVerify: true})
		c.Handshake()
	}()
	b.SetReadDeadline(time.Now().Add(5 * time.Second))
	first := readHello(b) // the first record only: up to the name's middle
	if first[0] != 22 || len(first) < 5 {
		t.Fatal(first)
	}
	if strings.Contains(string(first), "example.org") {
		t.Fatal("the whole name in the first record")
	}
}

// tryDirect: a server that answers the ClientHello is kept, a silent one is not
func TestTryDirect(t *testing.T) {
	listen := func(answer bool) netip.AddrPort {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					buf := make([]byte, 64)
					c.Read(buf)
					if answer {
						c.Write([]byte("server hello"))
					}
					time.Sleep(6 * time.Second)
					c.Close()
				}()
			}
		}()
		return netip.MustParseAddrPort(ln.Addr().String())
	}
	if c, first := tryDirect(listen(true), []byte("client hello")); c == nil || string(first) != "server hello" {
		t.Fatalf("an answering server dropped: %q", first)
	} else {
		c.Close()
	}
	if c, _ := tryDirect(listen(false), []byte("client hello")); c != nil {
		t.Fatal("a silent server kept")
	}
}

// a stop inside a TLS record is a freeze, a stop between records is not
func TestStalled(t *testing.T) {
	rec := func(n int) []byte { return append([]byte{23, 3, 3, byte(n >> 8), byte(n)}, make([]byte, n)...) }
	c := &countConn{tls: true}
	c.feed(rec(100))
	c.last = time.Now().Add(-10 * time.Second)
	if d, _ := c.stalled(); d != 0 {
		t.Error("idle between records taken for a freeze")
	}
	big := rec(16000)
	c.feed(big[:9000])
	c.last = time.Now().Add(-10 * time.Second)
	if d, in := c.stalled(); d < 9*time.Second || !in {
		t.Error("a stop inside a record not seen")
	}
	c.feed(big[9000:])
	if d, _ := c.stalled(); d != 0 {
		t.Error("the record's end not seen")
	}
	c.feed([]byte{23, 3})
	c.last = time.Now().Add(-10 * time.Second)
	if d, in := c.stalled(); d == 0 || !in {
		t.Error("a stop inside a record header not seen")
	}
}

// a request that gets no answer for 10 s is a stall too, but not one inside a record (through
// WARP it is no sign of a frozen tunnel); an answered one, then quiet, is not
func TestStalledRequest(t *testing.T) {
	c := &countConn{tls: true}
	c.feed([]byte{23, 3, 3, 0, 2, 1, 2})
	c.wrote = time.Now().Add(-11 * time.Second)
	c.last = time.Now().Add(-12 * time.Second)
	if d, in := c.stalled(); d < 6*time.Second || in {
		t.Error("an unanswered request not seen")
	}
	c.last = time.Now().Add(-10 * time.Second)
	c.wrote = time.Now().Add(-11 * time.Second)
	c.feed([]byte{23, 3, 3, 0, 1, 9}) // the answer, 6 s after the request, then 5 s of quiet
	c.last = time.Now().Add(-5 * time.Second)
	if d, _ := c.stalled(); d != 0 {
		t.Error("an answered request taken for a stall")
	}
}

// HTTP/2's window updates and pings get no answer: they are not requests
func TestSmallWriteNoRequest(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go io.Copy(io.Discard, b)
	c := &countConn{Conn: a, tls: true}
	c.Write(make([]byte, 35))
	if !c.wrote.IsZero() {
		t.Error("a window update taken for a request")
	}
	c.Write(make([]byte, 600))
	if c.wrote.IsZero() {
		t.Error("a request not noted")
	}
}

// a connection that has to go through WARP waits while the tunnel comes up, not while it gives up
func TestWaitWarp(t *testing.T) {
	r := &tcpRelay{ctx: context.Background()}
	if r.waitWarp(nil, time.Second) != nil {
		t.Fatal("waited with no tunnel coming")
	}
	r.warpWait.Store(true)
	w := &warpTunnel{}
	go func() {
		time.Sleep(300 * time.Millisecond)
		r.warp.Store(w)
	}()
	if got := r.waitWarp(nil, 5*time.Second); got != w {
		t.Fatal("the tunnel that came up not taken")
	}
	// the old tunnel is not the new one: wait for another, until the time runs out
	t0 := time.Now()
	if r.waitWarp(w, 500*time.Millisecond) != nil || time.Since(t0) < 400*time.Millisecond {
		t.Fatal("the old tunnel taken for a new one")
	}
	r.warpWait.Store(false)
	t0 = time.Now()
	if r.waitWarp(w, 5*time.Second) != nil || time.Since(t0) > time.Second {
		t.Fatal("waited after WARP gave up")
	}
}

// one frozen site sends this run through WARP; the network is written down only after two
func TestMarkBlocked(t *testing.T) {
	r := &tcpRelay{ctx: context.Background()}
	r.markBlocked("a.epicgames.com", "замёрзло")
	if !r.always.Load() || r.remembered.Load() {
		t.Fatal("one site: through WARP for this run, not remembered")
	}
	r.markBlocked("a.epicgames.com", "замёрзло")
	if r.remembered.Load() {
		t.Fatal("the same site twice remembered")
	}
	r.markBlocked("b.epicgames.com", "замёрзло")
	if !r.remembered.Load() {
		t.Fatal("two sites not remembered")
	}
}

// a name that failed through a working tunnel goes directly for a while
func TestWarpBad(t *testing.T) {
	r := &tcpRelay{ctx: context.Background()}
	if r.warpBadRecently("keys.epicgames.com") {
		t.Fatal("bad before failing")
	}
	r.markWarpBad("keys.epicgames.com", "ничего не вернул")
	if !r.warpBadRecently("keys.epicgames.com") || r.warpBadRecently("other.epicgames.com") {
		t.Fatal("the failed name not kept apart")
	}
	r.warpBad.Store("keys.epicgames.com", time.Now().Add(-11*time.Minute))
	if r.warpBadRecently("keys.epicgames.com") {
		t.Fatal("kept direct past 10 minutes")
	}
}

// the summary in the log: busiest name first, which way it went, empty and cut ones
func TestStatsSummary(t *testing.T) {
	r := &tcpRelay{ctx: context.Background()}
	if r.statsSummary() != "" {
		t.Fatal("a summary of nothing")
	}
	r.note("keys.epicgames.com", true, 0, false)
	r.note("keys.epicgames.com", true, 3000, false)
	r.note("keys.epicgames.com", false, 16000, true)
	r.note("login.epicgames.com", true, 900, false)
	got := r.statsSummary()
	want := "keys.epicgames.com: WARP 2, напрямую 1, пустых 1, оборвано 1, 19 КБ; login.epicgames.com: WARP 1, 1 КБ"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
	if r.statsSummary() != "" {
		t.Error("the summary not reset")
	}
}
