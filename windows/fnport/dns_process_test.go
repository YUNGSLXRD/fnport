package main

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/YUNGSLXRD/fnport/windows/internal/vpn"
	"github.com/YUNGSLXRD/fnport/windows/internal/wnet"
	"golang.org/x/net/dns/dnsmessage"
)

func TestSelectedProcessDNS(t *testing.T) {
	src := netip.MustParseAddrPort("10.254.77.2:44444")
	dst := netip.AddrPortFrom(wnet.TunDNSAddr, 53)
	router := &connectionRouter{settings: connectionSettings{Enabled: true, Processes: []string{"chrome.exe"}}}
	b := newWinDNSBroker(router, nil, nil)
	for _, proto := range []uint8{6, 17} {
		for _, name := range []string{"chrome.exe", "svchost.exe", "other.exe", ""} {
			router.ownerLookup = func(p uint8, s, d netip.AddrPort) (wnet.ProcessOwner, error) {
				if p != proto || s != src || d != dst {
					t.Fatal("DNS ownership lookup used the wrong endpoints")
				}
				return wnet.ProcessOwner{Name: name}, nil
			}
			if got := b.selectedDNSProcess(proto, src, dst); got != (name == "chrome.exe") {
				t.Fatalf("protocol %d owner %q: selected=%v", proto, name, got)
			}
		}
	}

	q := dnsmessage.Question{Name: dnsmessage.MustNewName("www.example.org."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	msg := dnsmessage.Message{Header: dnsmessage.Header{ID: 42}, Questions: []dnsmessage.Question{q}}
	wire, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	msg.Response = true
	msg.Answers = []dnsmessage.Resource{{
		Header: dnsmessage.ResourceHeader{Name: q.Name, Class: q.Class, Type: q.Type, TTL: 60},
		Body:   &dnsmessage.AResource{A: [4]byte{192, 0, 2, 42}},
	}}
	reply, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	b.dohPrimary = vpn.NewDoHClient("plain", "google", func(context.Context, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			if query, err := vpn.ReadTCPDNS(server); err == nil && bytes.Equal(query, wire) {
				_ = vpn.WriteTCPDNS(server, reply)
			}
		}()
		return client, nil
	})
	if got := b.answer(context.Background(), wire, true); !bytes.Equal(got, reply) {
		t.Fatal("query for an unlisted domain did not use the selected application's resolver")
	}
	if len(b.addedRoutes) != 0 || b.leases.ServiceOf(netip.MustParseAddr("192.0.2.42")) != "" {
		t.Fatal("an application query created routing policy for other applications")
	}
}
