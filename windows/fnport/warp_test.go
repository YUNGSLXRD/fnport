package main

import (
	"crypto/tls"
	"net"
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
