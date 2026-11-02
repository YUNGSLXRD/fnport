//go:build windows

package wnet

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Live Windows verification catches native layout/byte-order mistakes that a
// synthetic buffer cannot. No external hosts, shells or elevated rights needed.
func TestProcessNativeLoopbackOwnership(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			address := "127.0.0.1:0"
			if network == "tcp6" {
				address = "[::1]:0"
			}
			ln, err := net.Listen(network, address)
			if err != nil {
				if network == "tcp6" {
					t.Skipf("IPv6 unavailable: %v", err)
				}
				t.Fatal(err)
			}
			defer ln.Close()
			c, err := net.DialTimeout(network, ln.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			accepted, err := ln.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer accepted.Close()
			src := c.LocalAddr().(*net.TCPAddr).AddrPort()
			dst := c.RemoteAddr().(*net.TCPAddr).AddrPort()
			assertNativeOwner(t, 6, src, dst)
		})
	}
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			local := &net.UDPAddr{IP: net.ParseIP("127.0.0.1")}
			dst := netip.MustParseAddrPort("127.0.0.1:443")
			if network == "udp6" {
				local.IP = net.ParseIP("::1")
				dst = netip.MustParseAddrPort("[::1]:443")
			}
			c, err := net.ListenUDP(network, local)
			if err != nil {
				if network == "udp6" {
					t.Skipf("IPv6 unavailable: %v", err)
				}
				t.Fatal(err)
			}
			defer c.Close()
			assertNativeOwner(t, 17, c.LocalAddr().(*net.UDPAddr).AddrPort(), dst)
		})
	}
}

func assertNativeOwner(t *testing.T, proto uint8, src, dst netip.AddrPort) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var owner ProcessOwner
	var err error
	for {
		owner, err = ConnectionOwner(proto, src, dst)
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if owner.PID != uint32(os.Getpid()) || !strings.EqualFold(owner.Name, filepath.Base(exe)) {
		t.Fatalf("owner=%+v, want current process", owner)
	}
	names, err := ProcessNames()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if strings.EqualFold(name, filepath.Base(exe)) {
			return
		}
	}
	t.Fatal("ProcessNames omitted current executable")
}
