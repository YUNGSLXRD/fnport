package wnet

import (
	"net"
	"net/netip"
	"testing"
)

func TestOwnUDPLifetime(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	rememberUDP(c)
	a := c.LocalAddr().(*net.UDPAddr).AddrPort()
	if !IsOwnUDP(a) {
		t.Fatal("relay socket not recognized")
	}
	c.Close()
	if IsOwnUDP(a) {
		t.Fatal("closed port would suppress a future application")
	}
	if IsOwnUDP(netip.MustParseAddrPort("127.0.0.1:1")) {
		t.Fatal("unrelated port excluded")
	}
}
