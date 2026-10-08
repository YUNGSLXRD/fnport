package wnet

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// PhysIndex: the physical interface toward the internet; 0 = let Windows route.
// Sockets of the relay must not loop back into the adapter: the routes to the servers point there.
var PhysIndex uint32

const (
	ipUnicastIf    = 31         // IP_UNICAST_IF
	sioUDPNetReset = 0x9800000F // SIO_UDP_NETRESET: no errors on recv after ICMP "TTL exceeded"
	defaultTTLWin  = 128
)

func bindPhys(h windows.Handle) error {
	if PhysIndex == 0 {
		return nil
	}
	// MSDN wants the index in network byte order for IPv4
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], PhysIndex)
	return windows.SetsockoptInt(h, windows.IPPROTO_IP, ipUnicastIf, int(*(*uint32)(unsafe.Pointer(&b[0]))))
}

func sockControl(physical, udp bool) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			h := windows.Handle(fd)
			if udp {
				flag := uint32(0)
				var ret uint32
				windows.WSAIoctl(h, sioUDPNetReset, (*byte)(unsafe.Pointer(&flag)), 4, nil, 0, &ret, nil, 0)
			}
			if physical {
				serr = bindPhys(h)
			}
		})
		if err != nil {
			return err
		}
		return serr
	}
}

// ListenUDP opens a UDP socket on port (0 = any); physical sends it out of PhysIndex
func ListenUDP(port int, physical bool) (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: sockControl(physical, true)}
	pc, err := lc.ListenPacket(context.Background(), "udp4", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

// PhysAddr: the physical interface's own address, set with PhysIndex
var PhysAddr netip.Addr

// DialTCP connects out of the physical interface. Both the interface option and the source
// address pin it there: a connection looping back into the adapter would multiply itself.
func DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	d := net.Dialer{Control: sockControl(true, false), Timeout: 10 * time.Second}
	if PhysAddr.IsValid() {
		d.LocalAddr = &net.TCPAddr{IP: PhysAddr.AsSlice()}
	}
	return d.DialContext(ctx, "tcp4", dst.String())
}

// SendWithTTL sends one datagram with a small TTL and puts the socket's TTL back
func SendWithTTL(c *net.UDPConn, b []byte, dst netip.AddrPort, ttl int) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	old := defaultTTLWin
	var serr error
	rc.Control(func(fd uintptr) {
		if v, err := windows.GetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, windows.IP_TTL); err == nil && v > 0 {
			old = v
		}
		serr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, windows.IP_TTL, ttl)
	})
	if serr != nil {
		return serr
	}
	_, werr := c.WriteToUDPAddrPort(b, dst)
	rc.Control(func(fd uintptr) {
		serr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, windows.IP_TTL, old)
	})
	if werr != nil {
		return werr
	}
	return serr
}

type IfaceInfo struct {
	Index       uint32
	Addr        netip.Addr // its IPv4 address
	Alias, Desc string
	Tunnel      bool // looks like a VPN
}

// RouteInterface: the interface Windows uses toward an address
func RouteInterface(dst netip.Addr) (IfaceInfo, error) {
	var idx uint32
	if err := windows.GetBestInterfaceEx(&windows.SockaddrInet4{Addr: dst.As4()}, &idx); err != nil {
		return IfaceInfo{}, err
	}
	info := IfaceInfo{Index: idx}
	if ifc, err := net.InterfaceByIndex(int(idx)); err == nil {
		if addrs, err := ifc.Addrs(); err == nil {
			for _, a := range addrs {
				if pn, ok := a.(*net.IPNet); ok {
					if ip, ok := netip.AddrFromSlice(pn.IP.To4()); ok && pn.IP.To4() != nil && !ip.IsLinkLocalUnicast() {
						info.Addr = ip
						break
					}
				}
			}
		}
	}
	if luid, err := winipcfg.LUIDFromIndex(idx); err == nil {
		if row, err := luid.Interface(); err == nil {
			info.Alias, info.Desc = row.Alias(), row.Description()
			info.Tunnel = row.Type == winipcfg.IfTypePropVirtual || row.Type == winipcfg.IfTypeTunnel
		}
	}
	d := strings.ToLower(info.Alias + " " + info.Desc)
	for _, s := range []string{"warp", "wireguard", "wintun", "amnezia", "openvpn", "tap-windows", "vpn", "outline"} {
		if strings.Contains(d, s) {
			info.Tunnel = true
		}
	}
	return info, nil
}

func IsElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// RelaunchElevated starts this program again through UAC; false if the user said no
func RelaunchElevated() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	cwd, _ := os.Getwd()
	dir, _ := windows.UTF16PtrFromString(cwd)
	args, _ := windows.UTF16PtrFromString(strings.Join(os.Args[1:], " "))
	return windows.ShellExecute(0, verb, file, args, dir, windows.SW_NORMAL) == nil
}

func ConsoleUTF8() {
	windows.SetConsoleOutputCP(65001)
	windows.SetConsoleCP(65001)
}

var winmm = windows.NewLazySystemDLL("winmm.dll")

var timerHighRes bool

// SetTimerHighRes asks Windows for 1 ms timer resolution (timeBeginPeriod) or gives it back
func SetTimerHighRes(on bool) {
	if on == timerHighRes {
		return
	}
	proc := "timeEndPeriod"
	if on {
		proc = "timeBeginPeriod"
	}
	winmm.NewProc(proc).Call(1)
	timerHighRes = on
}

// Interfaces: network adapters that are up and have an IPv4 address, except fnport's own
func Interfaces() []IfaceInfo {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []IfaceInfo
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || strings.HasPrefix(ifc.Name, "fnport") {
			continue
		}
		info := IfaceInfo{Index: uint32(ifc.Index), Alias: ifc.Name}
		if addrs, err := ifc.Addrs(); err == nil {
			for _, a := range addrs {
				if pn, ok := a.(*net.IPNet); ok && pn.IP.To4() != nil {
					if ip, ok := netip.AddrFromSlice(pn.IP.To4()); ok && !ip.IsLinkLocalUnicast() {
						info.Addr = ip
						break
					}
				}
			}
		}
		if !info.Addr.IsValid() {
			continue
		}
		if luid, err := winipcfg.LUIDFromIndex(info.Index); err == nil {
			if row, err := luid.Interface(); err == nil {
				info.Desc = row.Description()
				info.Tunnel = row.Type == winipcfg.IfTypePropVirtual || row.Type == winipcfg.IfTypeTunnel
			}
		}
		d := strings.ToLower(info.Alias + " " + info.Desc)
		for _, s := range []string{"warp", "wireguard", "wintun", "amnezia", "openvpn", "tap-windows", "vpn", "outline"} {
			if strings.Contains(d, s) {
				info.Tunnel = true
			}
		}
		out = append(out, info)
	}
	return out
}
