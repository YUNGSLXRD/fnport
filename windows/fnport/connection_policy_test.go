package main

import (
	"context"
	"encoding/json"
	"github.com/YUNGSLXRD/fnport/windows/internal/wnet"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestConnectionPolicyIsolation(t *testing.T) {
	s := connectionSettings{Enabled: true, Discord: true, Processes: []string{"Browser.exe", "Other.exe"}}
	for _, tc := range []struct {
		name, domain string
		want         bool
	}{
		{"Discord.exe", "", true}, {"DISCORDPTB.EXE", "", true}, {"Browser.exe", "", true},
		{"Other.exe", "", true}, {"browser.exe.bad", "", false}, {"FortniteClient-Win64-Shipping.exe", "", false},
		{"", "gateway.discord.gg", true}, {"Browser2.exe", "cdn.discordapp.com", true},
		{"Browser2.exe", "discord.com.attacker.test", false}, {"Browser2.exe", "notdiscord.com", false},
	} {
		if got := s.selects(wnet.ProcessOwner{Name: tc.name}, tc.domain); got != tc.want {
			t.Errorf("%q/%q: %v", tc.name, tc.domain, got)
		}
	}
	s.Enabled = false
	if s.selects(wnet.ProcessOwner{Name: "Discord.exe"}, "discord.com") {
		t.Fatal("disabled selection")
	}
}

func TestConnectionPolicyKeepsFortniteUDPDirect(t *testing.T) {
	src := netip.MustParseAddrPort("10.254.77.2:12345")
	dst := netip.MustParseAddrPort("18.1.2.3:9000")
	r := &connectionRouter{settings: connectionSettings{Enabled: true, Processes: []string{"FortniteClient-Win64-Shipping.exe"}}}
	attempts := 0
	r.ownerLookup = func(uint8, netip.AddrPort, netip.AddrPort) (wnet.ProcessOwner, error) {
		attempts++
		if attempts == 1 {
			return wnet.ProcessOwner{}, wnet.ErrOwnerNotFound
		}
		return wnet.ProcessOwner{PID: 42, Name: "FortniteClient-Win64-Shipping.exe"}, nil
	}
	if r.selectedUDP(src, dst, true) {
		t.Fatal("Fortnite match entered tunnel")
	}
	if attempts != 2 {
		t.Fatal("new socket not retried")
	}
	if !r.selectedUDP(src, dst, false) {
		t.Fatal("selected non-game connection lost")
	}
	r.ownerLookup = func(uint8, netip.AddrPort, netip.AddrPort) (wnet.ProcessOwner, error) {
		return wnet.ProcessOwner{}, wnet.ErrOwnerAmbiguous
	}
	if r.selectedUDP(src, dst, false) {
		t.Fatal("ambiguous owner selected")
	}
}

func TestNativeAWGRejectsSecretsAndUnsupportedConfig(t *testing.T) {
	for _, raw := range []string{`{"private_key":"secret"}`, `{"unknown":"secret"}`, `{"endpoint":"secret"}`} {
		err := validateNativeAWG(json.RawMessage(raw))
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("invalid or leaked config", err)
		}
	}
}

func TestConnectionUDPRecoversWithoutDirectFallback(t *testing.T) {
	dev := newChanDev()
	e := newEngine(testConfig(), dev, clientIP, &tcpRelay{ctx: context.Background()})
	defer e.close()
	src := netip.MustParseAddrPort("192.168.1.10:54000")
	dst := netip.MustParseAddrPort("203.0.113.10:50000")
	router := &connectionRouter{settings: connectionSettings{Enabled: true, Protocol: "custom", Discord: true}}
	router.ownerLookup = func(uint8, netip.AddrPort, netip.AddrPort) (wnet.ProcessOwner, error) {
		return wnet.ProcessOwner{Name: "Discord.exe", PID: 42}, nil
	}
	e.connection = router
	f := &uflow{key: flowKey{src.Port(), dst, src.Addr()}, last: time.Now(), started: time.Now()}
	e.flows[f.key] = f
	e.assignConnection(f)
	f.mu.Lock()
	if !f.failed || f.conn != nil || f.tunnel != nil {
		t.Fatal("failed tunnel fell back to direct")
	}
	f.retryAfter = time.Now().Add(-time.Second)
	f.mu.Unlock()
	m := newTransportMock(t)
	m.start()
	router.transport = transportClient(m)
	defer router.transport.close()
	e.udp(wnet.UDPPacket{Src: src, Dst: dst, Payload: []byte("voice after recovery")})
	select {
	case packet := <-dev.out:
		reply, err := wnet.ParseUDP4(packet)
		if err != nil || reply.Dst != src || reply.Src != dst || string(reply.Payload) != "voice after recovery" {
			t.Fatalf("recovered datagram changed: %+v, %v", reply, err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("UDP did not recover after the selected transport became ready")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failed || f.conn != nil || f.tunnel == nil {
		t.Fatal("recovery used the wrong transport")
	}
}

func TestConnectionSettingsUpdatesAreSerialized(t *testing.T) {
	s := defaultSettings()
	s.Fake = ""
	c := newController(s)
	c.persist = func(settings) error { return nil }
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.update(func(s *settings) error { s.FakeTTL++; return nil }); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if got := c.settings().FakeTTL; got != 25 {
		t.Fatalf("concurrent updates lost: TTL %d", got)
	}
}

func TestAWGModeExcludesCustomHeaders(t *testing.T) {
	normal, err := acquireAWGMode(false)
	if err != nil {
		t.Fatal(err)
	}
	if release, err := acquireAWGMode(true); err == nil {
		release()
		normal()
		t.Fatal("native headers overlapped WARP")
	}
	normal()
	native, err := acquireAWGMode(true)
	if err != nil {
		t.Fatal(err)
	}
	if release, err := acquireAWGMode(false); err == nil {
		release()
		native()
		t.Fatal("WARP overlapped native headers")
	}
	native()
	release, err := acquireAWGMode(false)
	if err != nil {
		t.Fatal("lease not released", err)
	}
	release()
}

func TestTraceFailureStillForwardsInstalledRoutes(t *testing.T) {
	srv, err := wnet.ListenUDP(0, false)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	server := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(srv.LocalAddr().(*net.UDPAddr).Port))
	go func() {
		b := make([]byte, 256)
		n, peer, err := srv.ReadFromUDPAddrPort(b)
		if err == nil {
			srv.WriteToUDPAddrPort(b[:n], peer)
		}
	}()
	dev := newChanDev()
	cfg := testConfig()
	cfg.routes = []netip.Prefix{netip.MustParsePrefix("18.0.0.0/8")}
	cfg.captureAll = true
	e := newEngine(cfg, dev, clientIP, nil)
	e.connection = &connectionRouter{}
	defer e.close()
	go e.run()
	src := netip.AddrPortFrom(clientIP, 54001)
	dev.in <- wnet.BuildUDP4(src, server, []byte("forward even without trace"), 1)
	select {
	case b := <-dev.out:
		u, err := wnet.ParseUDP4(b)
		if err != nil || u.Dst != src || string(u.Payload) != "forward even without trace" {
			t.Fatalf("bad reply: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("trace failure blackholed non-AWS UDP")
	}
}

func TestCaptureRejectsMulticast(t *testing.T) {
	e := newEngine(&config{captureAll: true}, newChanDev(), clientIP, nil)
	defer e.close()
	for _, s := range []string{"239.255.255.250", "224.0.0.251", "224.0.0.252", "255.255.255.255", "0.0.0.0"} {
		if e.routed(netip.MustParseAddr(s)) {
			t.Errorf("non-unicast routed: %s", s)
		}
	}
	if !e.routed(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("public UDP blocked")
	}
}

func TestEpicResourceHostsAndDiscordPreset(t *testing.T) {
	s := connectionSettings{Enabled: true, Epic: true}
	for _, host := range []string{"fortnite-vod.akamaized.net", "fortnite-storage-live.s3.amazonaws.com"} {
		if !s.selects(wnet.ProcessOwner{}, host) {
			t.Errorf("Epic resource not selected: %s", host)
		}
	}
	for _, host := range []string{"unrelated.akamaized.net", "other.s3.amazonaws.com"} {
		if s.selects(wnet.ProcessOwner{}, host) {
			t.Errorf("unrelated resource selected: %s", host)
		}
	}
	owner := wnet.ProcessOwner{Name: "Discord.exe", PID: 1}
	preset := connectionSettings{Enabled: true, Discord: true}
	manual := connectionSettings{Enabled: true, Processes: []string{"Discord.exe"}}
	for _, host := range []string{"", "discord.com", "unrelated.example"} {
		if preset.selects(owner, host) != manual.selects(owner, host) {
			t.Fatal("Discord preset differs from manual executable selection")
		}
	}
}
