//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun"
	"golang.org/x/sys/unix"
)

func commandQuiet(ctx context.Context, name string, args ...string) error {
	if exec.CommandContext(ctx, name, args...).Run() != nil {
		return errors.New("network_command_failed")
	}
	return nil
}
func boundSocket(iface string, mark int) func(string, string, syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var socketErr error
		err := c.Control(func(fd uintptr) {
			if iface != "" {
				socketErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
			}
			if socketErr == nil && mark != 0 {
				socketErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, mark)
			}
		})
		if err != nil {
			return err
		}
		return socketErr
	}
}
func ifaceIPv4(name string) (netip.Addr, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return netip.Addr{}, errors.New("interface_unavailable")
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return netip.Addr{}, errors.New("interface_unavailable")
	}
	for _, a := range addresses {
		if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().Is4() {
			return p.Addr(), nil
		}
	}
	return netip.Addr{}, errors.New("interface_has_no_ipv4")
}
func readTunnelFake(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	dir, name := filepath.Dir(path), filepath.Base(path)
	if (dir != "/usr/share/fnport" && dir != "/etc/fnport") || !strings.HasSuffix(name, ".bin") || strings.Contains(name, "..") {
		return nil, errors.New("invalid_fake_path")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("fake_unavailable")
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 1501))
	if err != nil || len(b) == 0 || len(b) > 1500 {
		return nil, errors.New("invalid_fake_size")
	}
	return b, nil
}

type routerEndpoint netip.AddrPort

func (e routerEndpoint) ClearSrc()           {}
func (e routerEndpoint) SrcToString() string { return "" }
func (e routerEndpoint) DstToString() string { return netip.AddrPort(e).String() }
func (e routerEndpoint) DstToBytes() []byte  { b, _ := netip.AddrPort(e).MarshalBinary(); return b }
func (e routerEndpoint) DstIP() netip.Addr   { return netip.AddrPort(e).Addr() }
func (e routerEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

type nativeBind struct {
	mu      sync.Mutex
	sendMu  sync.Mutex
	sock    *net.UDPConn
	wan     string
	address netip.Addr
	fake    []byte
	ttl     int
	last    map[netip.AddrPort]time.Time
}

func (b *nativeBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sock != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	lc := net.ListenConfig{Control: boundSocket(b.wan, bypassMark)}
	pc, err := lc.ListenPacket(context.Background(), "udp4", netip.AddrPortFrom(b.address, port).String())
	if err != nil {
		return nil, 0, err
	}
	c := pc.(*net.UDPConn)
	b.sock = c
	receive := func(packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
		for failures := 0; ; failures++ {
			n, from, err := c.ReadFromUDPAddrPort(packets[0])
			if err == nil {
				sizes[0] = n
				endpoints[0] = routerEndpoint(netip.AddrPortFrom(from.Addr().Unmap(), from.Port()))
				return 1, nil
			}
			if errors.Is(err, net.ErrClosed) || failures > 100 {
				return 0, err
			}
		}
	}
	return []conn.ReceiveFunc{receive}, uint16(c.LocalAddr().(*net.UDPAddr).Port), nil
}
func (b *nativeBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sock == nil {
		return nil
	}
	err := b.sock.Close()
	b.sock = nil
	return err
}
func (b *nativeBind) SetMark(uint32) error { return nil }
func (b *nativeBind) BatchSize() int       { return 1 }
func (b *nativeBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	a, err := netip.ParseAddrPort(s)
	return routerEndpoint(a), err
}
func sendNativeFake(c *net.UDPConn, payload []byte, dst netip.AddrPort, ttl int) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	old := 64
	var socketErr error
	err = raw.Control(func(fd uintptr) {
		if v, e := unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL); e == nil {
			old = v
		}
		socketErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL, ttl)
	})
	if err != nil {
		return err
	}
	if socketErr != nil {
		return socketErr
	}
	_, sendErr := c.WriteToUDPAddrPort(payload, dst)
	restoreErr := raw.Control(func(fd uintptr) { socketErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL, old) })
	if sendErr != nil {
		return sendErr
	}
	if restoreErr != nil {
		return restoreErr
	}
	return socketErr
}
func (b *nativeBind) Send(packets [][]byte, endpoint conn.Endpoint) error {
	b.mu.Lock()
	c := b.sock
	b.mu.Unlock()
	if c == nil {
		return net.ErrClosed
	}
	e, ok := endpoint.(routerEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	dst := netip.AddrPort(e)
	b.sendMu.Lock()
	defer b.sendMu.Unlock()
	if len(b.fake) > 0 && b.ttl > 0 {
		if b.last == nil {
			b.last = map[netip.AddrPort]time.Time{}
		}
		if time.Since(b.last[dst]) > 20*time.Second {
			if err := sendNativeFake(c, b.fake, dst, b.ttl); err != nil {
				return err
			}
			b.last[dst] = time.Now()
		}
	}
	for _, p := range packets {
		if _, err := c.WriteToUDPAddrPort(p, dst); err != nil {
			return err
		}
	}
	return nil
}

type nativeTunnel struct {
	dev         *device.Device
	bind        *nativeBind
	profile     nativeAWGSettings
	route, rule bool
	once        sync.Once
}

func newNativeTunnel(ctx context.Context, c routerConfig) (*nativeTunnel, error) {
	if _, err := net.InterfaceByName(tunnelName); err == nil {
		return nil, errors.New("native_interface_already_exists")
	}
	raw, _ := jsonNative(c.Native)
	profile, err := parseNativeAWG(raw)
	if err != nil {
		return nil, errors.New("invalid_native_profile")
	}
	address, err := ifaceIPv4(c.WAN)
	if err != nil {
		return nil, err
	}
	fake, err := readTunnelFake(c.FakeFile)
	if err != nil {
		return nil, err
	}
	mtu := profile.MTU
	if mtu == 0 {
		mtu = 1280
	}
	tdev, err := tun.CreateTUN(tunnelName, mtu)
	if err != nil {
		return nil, errors.New("native_tun_unavailable")
	}
	b := &nativeBind{wan: c.WAN, address: address, fake: fake, ttl: c.FakeTTL}
	d := device.NewDevice(tdev, b, device.NewLogger(device.LogLevelSilent, ""))
	t := &nativeTunnel{dev: d, bind: b, profile: profile}
	keep := false
	defer func() {
		if !keep {
			t.close()
		}
	}()
	private, _ := b64hex(profile.PrivateKey)
	ipc := fmt.Sprintf("private_key=%s\njc=%d\njmin=%d\njmax=%d\ns1=%d\ns2=%d\nh1=%d\nh2=%d\nh3=%d\nh4=%d\n", private, profile.Jc, profile.Jmin, profile.Jmax, profile.S1, profile.S2, profile.H1, profile.H2, profile.H3, profile.H4)
	for i, v := range []string{profile.I1, profile.I2, profile.I3, profile.I4, profile.I5} {
		if v != "" {
			ipc += fmt.Sprintf("i%d=%s\n", i+1, v)
		}
	}
	if d.IpcSet(ipc) != nil {
		return nil, errors.New("native_settings_rejected")
	}
	for _, args := range [][]string{{"-4", "addr", "add", profile.Address + "/32", "dev", tunnelName}, {"link", "set", "dev", tunnelName, "mtu", strconv.Itoa(mtu), "up"}} {
		if commandQuiet(ctx, "ip", args...) != nil {
			return nil, errors.New("native_interface_setup_failed")
		}
	}
	if commandQuiet(ctx, "ip", "-4", "route", "add", "default", "dev", tunnelName, "table", strconv.Itoa(tunnelTable)) != nil {
		return nil, errors.New("native_route_conflict")
	}
	t.route = true
	if commandQuiet(ctx, "ip", "-4", "rule", "add", "pref", "81", "oif", tunnelName, "lookup", strconv.Itoa(tunnelTable)) != nil {
		return nil, errors.New("native_rule_conflict")
	}
	t.rule = true
	if d.Up() != nil {
		return nil, errors.New("native_device_start_failed")
	}
	keep = true
	return t, nil
}
func (t *nativeTunnel) setEndpoint(endpoint string) error {
	a, err := netip.ParseAddrPort(endpoint)
	if err != nil || !a.Addr().Is4() {
		return errors.New("invalid_native_endpoint")
	}
	peer, _ := b64hex(t.profile.PeerKey)
	keepalive := 15
	if t.profile.Keepalive != nil {
		keepalive = *t.profile.Keepalive
	}
	ipc := fmt.Sprintf("replace_peers=true\npublic_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=%d\n", peer, a.String(), keepalive)
	if t.profile.PresharedKey != "" {
		key, _ := b64hex(t.profile.PresharedKey)
		ipc += "preshared_key=" + key + "\n"
	}
	if t.dev.IpcSet(ipc) != nil {
		return errors.New("native_peer_settings_rejected")
	}
	return nil
}
func (t *nativeTunnel) dial(ctx context.Context, address string) (net.Conn, error) {
	d := net.Dialer{Control: boundSocket(tunnelName, tunnelMark), LocalAddr: &net.TCPAddr{IP: net.ParseIP(t.profile.Address)}, Timeout: 6 * time.Second}
	return d.DialContext(ctx, "tcp4", address)
}
func (t *nativeTunnel) close() {
	t.once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if t.rule {
			commandQuiet(ctx, "ip", "-4", "rule", "del", "pref", "81", "oif", tunnelName, "lookup", strconv.Itoa(tunnelTable))
		}
		if t.route {
			commandQuiet(ctx, "ip", "-4", "route", "del", "default", "dev", tunnelName, "table", strconv.Itoa(tunnelTable))
		}
		t.dev.Close()
	})
}
