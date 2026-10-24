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
	"github.com/amnezia-vpn/amneziawg-go/device"
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
