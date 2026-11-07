//go:build linux && (arm64 || amd64)

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
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/YUNGSLXRD/fnport/windows/internal/awgnet"
	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
)

func TestLinuxKernelTunnelRoundTrip(t *testing.T) {
	requireNetworkNamespace(t)
	runNetTest(t, "", "ip", "link", "set", "lo", "up")
	// The isolated fixture uses loopback as WAN. A router has a default route;
	// without one Linux's loose reverse-path filter rejects decoded replies.
	// Data sockets still use the helper's separate oif/mark routing table.
	runNetTest(t, "", "ip", "route", "add", "default", "dev", "lo")
	defer runNetTest(t, "", "ip", "route", "del", "default", "dev", "lo")
	serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tun, network, err := awgnet.New(netip.MustParseAddr("10.77.0.1"), 1280)
	if err != nil {
		t.Fatal(err)
	}
	server := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer server.Close()
	if err := server.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=34789\npublic_key=%s\nallowed_ip=10.77.0.2/32\n", hex.EncodeToString(serverKey.Bytes()), hex.EncodeToString(clientKey.PublicKey().Bytes()))); err != nil {
		t.Fatal("server config rejected")
	}
	if err := server.Up(); err != nil {
		t.Fatal(err)
	}
	listener, err := network.ListenTCP(443)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	c := routerTestConfig()
	c.Protocol, c.WAN = "amneziawg", "lo"
	c.Native = nativeAWGSettings{PrivateKey: base64.StdEncoding.EncodeToString(clientKey.Bytes()), PeerKey: base64.StdEncoding.EncodeToString(serverKey.PublicKey().Bytes()), Address: "10.77.0.2", Endpoint: "127.0.0.1:34789", H1: 1, H2: 2, H3: 3, H4: 4}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client, err := newNativeTunnel(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	defer client.close()
	if err := client.setEndpoint(c.Native.Endpoint); err != nil {
		t.Fatal(err)
	}
	tcp, err := client.dial(ctx, "10.77.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	tcp.SetDeadline(time.Now().Add(10 * time.Second))
	payload := make([]byte, 1<<20)
	rand.Read(payload)
	go func() { tcp.Write(payload) }()
	back := make([]byte, len(payload))
	if _, err := io.ReadFull(tcp, back); err != nil || !bytes.Equal(payload, back) {
		t.Fatal("kernel TUN TCP roundtrip failed", err)
	}
	udpServer, err := network.ListenUDP(50055)
	if err != nil {
		t.Fatal(err)
	}
	defer udpServer.Close()
	go func() {
		b := make([]byte, 1500)
		n, peer, e := udpServer.ReadFrom(b)
		if e == nil {
			udpServer.WriteTo(b[:n], peer)
		}
	}()
	udp, err := (&net.Dialer{Control: boundSocket(tunnelName, tunnelMark), LocalAddr: &net.UDPAddr{IP: net.ParseIP(client.profile.Address)}}).DialContext(ctx, "udp4", "10.77.0.1:50055")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	udp.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := udp.Write(payload[:1200]); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 1500)
	n, err := udp.Read(packet)
	if err != nil || !bytes.Equal(packet[:n], payload[:1200]) {
		t.Fatal("kernel TUN UDP roundtrip failed", err)
	}
	client.close()
	if _, err := net.InterfaceByName(tunnelName); err == nil {
		t.Fatal("tunnel interface leaked after close")
	}
}
