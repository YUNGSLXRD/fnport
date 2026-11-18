package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/YUNGSLXRD/fnport/windows/internal/awgnet"
	"github.com/YUNGSLXRD/fnport/windows/internal/fakes"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
)

// our tunnel (junk packets, the physical bind, our stack) against a plain WireGuard peer on
// this machine: the plumbing works end to end
func TestWarpTunnelLoopback(t *testing.T) {
	t.Run("plain", func(t *testing.T) { warpLoopback(t, "") })
	// the QUIC decoy before the handshake: the WireGuard end drops it and goes on
	fakes.Ensure(fakesDir())
	t.Run("i1", func(t *testing.T) { warpLoopback(t, quicI1()) })
	// fnport's fake before the first packet, as against the TSPU: dropped by the WireGuard end
	t.Run("fake", func(t *testing.T) { warpLoopback(t, "fake") })
}

func warpLoopback(t *testing.T, i1 string) {
	key := func() (*ecdh.PrivateKey, string) {
		k, _ := ecdh.X25519().GenerateKey(rand.Reader)
		return k, base64.StdEncoding.EncodeToString(k.Bytes())
	}
	srvKey, _ := key()
	port := 51990 + len(i1)%7
	cliKey, cliB64 := key()

	// the "Cloudflare" end: plain WireGuard, a TCP echo in its stack
	sdev, snet, err := awgnet.New(netip.MustParseAddr("10.9.0.1"), 1280)
	if err != nil {
		t.Fatal(err)
	}
	srv := device.NewDevice(sdev, &physBind{}, device.NewLogger(device.LogLevelSilent, ""))
	defer srv.Close()
	if err := srv.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\npublic_key=%s\nallowed_ip=10.9.0.2/32\n",
		hex.EncodeToString(srvKey.Bytes()), port, hex.EncodeToString(cliKey.PublicKey().Bytes()))); err != nil {
		t.Fatal(err)
	}
	srv.Up()
	ln, err := snet.ListenTCP(443)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()

	ws := warpSettings{PrivateKey: cliB64, Address: "10.9.0.2", Jc: 4, Jmin: 40, Jmax: 70,
		PeerKey: base64.StdEncoding.EncodeToString(srvKey.PublicKey().Bytes())}
	if i1 == "fake" {
		ws = ws.withFake(defaultSettings())
		if ws.fake == nil {
			t.Fatal("no fake")
		}
	} else {
		ws.I1 = i1
	}
	w, err := newWarpDev(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer w.close()
	if !w.setEndpoint(fmt.Sprintf("127.0.0.1:%d", port)) {
		t.Fatal("endpoint")
	}
	udpEcho, err := snet.ListenUDP(7777)
	if err != nil {
		t.Fatal(err)
	}
	defer udpEcho.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, peer, err := udpEcho.ReadFrom(buf)
			if err != nil {
				return
			}
			udpEcho.WriteTo(buf[:n], peer)
		}
	}()
	uc, err := w.net.DialUDP(netip.MustParseAddrPort("10.9.0.1:7777"))
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	uc.SetDeadline(time.Now().Add(5 * time.Second))
	for _, payload := range [][]byte{[]byte("voice"), make([]byte, 1200)} {
		if _, err := uc.Write(payload); err != nil {
			t.Fatal(err)
		}
		back := make([]byte, 2048)
		n, err := uc.Read(back)
		if err != nil || string(back[:n]) != string(payload) {
			t.Fatalf("UDP tunnel echo: %v", err)
		}
	}
	c, err := w.dial(netip.MustParseAddrPort("10.9.0.1:443"))
	if err != nil {
		t.Fatal("dial through the tunnel:", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	// a megabyte both ways: full-size packets, not only the handshake's small ones
	out := make([]byte, 1<<20)
	for i := range out {
		out[i] = byte(i * 7)
	}
	go c.Write(out)
	back := make([]byte, len(out))
	if _, err := io.ReadFull(c, back); err != nil || string(back) != string(out) {
		t.Fatalf("echo of 1 MB: %v", err)
	}
}

func TestAmneziaWG2And3TunnelLoopback(t *testing.T) {
	key := func() (*ecdh.PrivateKey, string, string) {
		k, _ := ecdh.X25519().GenerateKey(rand.Reader)
		return k, base64.StdEncoding.EncodeToString(k.Bytes()), hex.EncodeToString(k.Bytes())
	}
	srvKey, _, srvHex := key()
	cliKey, cliB64, _ := key()
	_, hpB64, hpHex := key()
	port := 52045

	sdev, snet, err := awgnet.New(netip.MustParseAddr("10.9.1.1"), 1280)
	if err != nil {
		t.Fatal(err)
	}
	srv := device.NewDevice(sdev, &physBind{}, device.NewLogger(device.LogLevelSilent, ""))
	defer srv.Close()
	srvIPC := fmt.Sprintf("private_key=%s\nlisten_port=%d\ns1=24\ns2=28\ns3=16\ns4=20\nh1=100000-199999\nh2=200000-299999\nh3=300000-399999\nh4=400000-499999\nheader_protection_key=%s\ncontent_padding_addition=0-32\nrandom_trailers=true\ndisable_cookies=true\npublic_key=%s\nallowed_ip=10.9.1.2/32\n",
		srvHex, port, hpHex, hex.EncodeToString(cliKey.PublicKey().Bytes()))
	if err := srv.IpcSet(srvIPC); err != nil {
		t.Fatalf("srv IpcSet: %v", err)
	}
	if err := srv.Up(); err != nil {
		t.Fatal(err)
	}
	ln, err := snet.ListenTCP(443)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()

	conf := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.9.1.2/32
Jc = 3
Jmin = 40
Jmax = 90
S1 = 24
S2 = 28
S3 = 16
S4 = 20
H1 = 100000-199999
H2 = 200000-299999
H3 = 300000-399999
H4 = 400000-499999
HeaderProtectionKey = %s
ContentPaddingAddition = 0-32
RandomTrailers = true
DisableCookies = true
I1 = <b 0xc000000001><rc 8><rd 4><t>

[Peer]
PublicKey = %s
Endpoint = 127.0.0.1:%d
AllowedIPs = 0.0.0.0/0
`, cliB64, hpB64, base64.StdEncoding.EncodeToString(srvKey.PublicKey().Bytes()), port)

	raw, err := importAWGConf(conf)
	if err != nil {
		t.Fatalf("importAWGConf: %v", err)
	}
	set := defaultSettings()
	set.Fake = ""
	w, err := nativeAWGConfig(raw, set, nil)
	if err != nil {
		t.Fatalf("nativeAWGConfig: %v", err)
	}
	defer w.close()

	c, err := w.dial(netip.MustParseAddrPort("10.9.1.1:443"))
	if err != nil {
		t.Fatalf("AWG 3.0 dial: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(8 * time.Second))
	msg := []byte("amneziawg 2.0 + 3.0 header protection roundtrip")
	go c.Write(msg)
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil || string(got) != string(msg) {
		t.Fatalf("AWG 3.0 echo mismatch: %v", err)
	}
}
