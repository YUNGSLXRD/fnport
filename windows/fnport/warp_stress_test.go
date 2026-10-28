package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YUNGSLXRD/fnport/windows/internal/awgnet"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// a "Cloudflare" end on this machine: plain WireGuard with a TCP echo on 10.9.0.1:443
func loopbackPeer(t *testing.T, port int) (warpSettings, func()) {
	t.Helper()
	srvKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	cliKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	sdev, snet, err := awgnet.New(netip.MustParseAddr("10.9.0.1"), 1280)
	if err != nil {
		t.Fatal(err)
	}
	srv := device.NewDevice(sdev, &physBind{}, device.NewLogger(device.LogLevelSilent, ""))
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
	ws := warpSettings{PrivateKey: base64.StdEncoding.EncodeToString(cliKey.Bytes()), Address: "10.9.0.2",
		Jc: 4, Jmin: 40, Jmax: 70, PeerKey: base64.StdEncoding.EncodeToString(srvKey.PublicKey().Bytes())}
	return ws, func() { ln.Close(); srv.Close() }
}

// as at the game's start: dozens of connections at once through one tunnel, each echoing 256 KB
func TestWarpTunnelMany(t *testing.T) {
	ws, stop := loopbackPeer(t, 52011)
	defer stop()
	w, err := newWarpDev(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer w.close()
	w.setEndpoint("127.0.0.1:52011")
	var wg sync.WaitGroup
	errs := make(chan error, 40)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := w.dial(netip.MustParseAddrPort("10.9.0.1:443"))
			if err != nil {
				errs <- fmt.Errorf("%d dial: %v", i, err)
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(20 * time.Second))
			out := make([]byte, 256<<10)
			for j := range out {
				out[j] = byte(i + j*3)
			}
			go c.Write(out)
			back := make([]byte, len(out))
			if _, err := io.ReadFull(c, back); err != nil || string(back) != string(out) {
				errs <- fmt.Errorf("%d echo: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// the tunnel closed with transfers under way (a rebuild): no panic, the connections end
func TestWarpTunnelCloseBusy(t *testing.T) {
	ws, stop := loopbackPeer(t, 52012)
	defer stop()
	for round := 0; round < 5; round++ {
		w, err := newWarpDev(ws)
		if err != nil {
			t.Fatal(err)
		}
		w.setEndpoint("127.0.0.1:52012")
		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			c, err := w.dial(netip.MustParseAddrPort("10.9.0.1:443"))
			if err != nil {
				t.Fatal(err)
			}
			wg.Add(2)
			go func() {
				defer wg.Done()
				buf := make([]byte, 32<<10)
				for {
					if _, err := c.Write(buf); err != nil {
						return
					}
				}
			}()
			go func() {
				defer wg.Done()
				io.Copy(io.Discard, c)
			}()
			defer c.Close()
		}
		time.Sleep(300 * time.Millisecond)
		w.close()
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("round %d: connections still running 10 s after the tunnel closed", round)
		}
	}
}

// the whole way, as at the game's start: the PC's connections to Epic's names come into the
// adapter, the relay picks them by name and sends them through the WARP tunnel to the server.
// Data in TLS records, so the freeze watch sees what it sees in life and must not cut anything
func TestWarpWholePath(t *testing.T) {
	ws, stop := loopbackPeer(t, 52013)
	defer stop()
	w, err := newWarpDev(ws)
	if err != nil {
		t.Fatal(err)
	}
	w.setEndpoint("127.0.0.1:52013")

	dev := newChanDev()
	tr, err := newTCPRelay(dev)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.close()
	names := []string{"epicgames.com"}
	tr.names.Store(&names)
	tr.always.Store(true)
	tr.warpWait.Store(true)
	tr.warp.Store(w)

	win := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	wep := channel.New(1024, mtu, "")
	win.CreateNIC(1, wep)
	win.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4(clientIP.As4()).WithPrefix()}, stack.AddressProperties{})
	win.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { // Windows -> adapter -> the relay's stack
		for {
			pkt := wep.ReadContext(ctx)
			if pkt == nil {
				return
			}
			v := pkt.ToView()
			pkt.DecRef()
			tr.inject(v.AsSlice())
			v.Release()
		}
	}()
	go func() { // the relay's stack -> adapter -> Windows
		for {
			select {
			case p := <-dev.out:
				pk := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(p)})
				wep.InjectInbound(ipv4.ProtocolNumber, pk)
				pk.DecRef()
			case <-ctx.Done():
				return
			}
		}
	}()

	// application data in TLS records of up to 16 KB, 512 KB in all
	var data []byte
	for i := 0; len(data) < 512<<10; i++ {
		n := 16000 - i%7*1000
		rec := append([]byte{23, 3, 3, byte(n >> 8), byte(n)}, bytes.Repeat([]byte{byte(i)}, n)...)
		data = append(data, rec...)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			hello := clientHello(t, fmt.Sprintf("svc%d.ol.epicgames.com", i))
			c, err := gonet.DialContextTCP(ctx, win, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{10, 9, 0, 1}), Port: 443}, ipv4.ProtocolNumber)
			if err != nil {
				errs <- fmt.Errorf("%d dial: %v", i, err)
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(30 * time.Second))
			msg := append(append([]byte(nil), hello...), data...)
			go c.Write(msg)
			got := make([]byte, len(msg))
			if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, msg) {
				errs <- fmt.Errorf("%d echo through WARP: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if n := w.conns.Load(); n != 20 {
		t.Errorf("through WARP %d connections of 20", n)
	}
	if s := tr.statsSummary(); !strings.Contains(s, "WARP 1") || strings.Contains(s, "напрямую") || strings.Contains(s, "оборвано") {
		t.Errorf("summary: %s", s)
	}
}
