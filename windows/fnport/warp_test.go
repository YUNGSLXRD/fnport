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
