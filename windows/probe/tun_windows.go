package main

import (
	"fmt"
	"net/netip"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const tunName = "fnport-probe"

// the adapter's own address; Windows uses it as the source of what it routes into the adapter
var tunAddr = netip.MustParsePrefix("10.254.77.2/24")

type wintunDev struct {
	nt    *tun.NativeTun
	bufs  [][]byte
	sizes []int
}

func (d *wintunDev) ReadPacket(buf []byte) (int, error) {
	d.bufs[0] = buf
	if _, err := d.nt.Read(d.bufs, d.sizes, 0); err != nil {
		return 0, err
	}
	return d.sizes[0], nil
}

func (d *wintunDev) WritePacket(pkt []byte) error {
	_, err := d.nt.Write([][]byte{pkt}, 0)
	return err
}

func (d *wintunDev) Close() error { return d.nt.Close() }

// openTun creates the adapter (removed again on Close) and routes the given hosts into it
func openTun(hosts []netip.Addr) (packetDev, netip.Addr, error) {
	tun.WintunTunnelType = "fnport" // the adapter shows as "fnport-probe", type fnport, not WireGuard
	dev, err := tun.CreateTUN(tunName, 1420)
	if err != nil {
		return nil, netip.Addr{}, fmt.Errorf("адаптер Wintun не создан: %w", err)
	}
	nt := dev.(*tun.NativeTun)
	luid := winipcfg.LUID(nt.LUID())
	fail := func(what string, err error) (packetDev, netip.Addr, error) {
		nt.Close()
		return nil, netip.Addr{}, fmt.Errorf("%s: %w", what, err)
	}
	if err := luid.SetIPAddressesForFamily(windows.AF_INET, []netip.Prefix{tunAddr}); err != nil {
		return fail("адрес адаптера", err)
	}
	ipif, err := luid.IPInterface(windows.AF_INET)
	if err != nil {
		return fail("настройки адаптера", err)
	}
	// no duplicate address detection: the address is usable at once
	ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
	ipif.DadTransmits = 0
	ipif.ManagedAddressConfigurationSupported = false
	ipif.OtherStatefulConfigurationSupported = false
	ipif.NLMTU = 1420
	if err := ipif.Set(); err != nil {
		return fail("настройки адаптера", err)
	}
	for _, h := range hosts {
		if err := luid.AddRoute(netip.PrefixFrom(h, 32), netip.IPv4Unspecified(), 0); err != nil {
			return fail("маршрут "+h.String(), err)
		}
	}
	// the adapter needs a moment before Windows sends through it
	time.Sleep(1500 * time.Millisecond)
	return &wintunDev{nt: nt, bufs: make([][]byte, 1), sizes: make([]int, 1)}, tunAddr.Addr(), nil
}
