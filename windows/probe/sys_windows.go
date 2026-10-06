package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// index of the physical interface toward the internet; 0 = let Windows route
var physIndex uint32

const (
	ipUnicastIf    = 31         // IP_UNICAST_IF
	sioUDPNetReset = 0x9800000F // SIO_UDP_NETRESET: no errors on recv after ICMP "TTL exceeded"
	defaultTTLWin  = 128
)

func sockControl(physical bool) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			h := windows.Handle(fd)
			flag := uint32(0)
			var ret uint32
			windows.WSAIoctl(h, sioUDPNetReset, (*byte)(unsafe.Pointer(&flag)), 4, nil, 0, &ret, nil, 0)
			if physical && physIndex != 0 {
				// sockets of the relay must not loop back into the adapter: the routes to the
				// servers point there. MSDN wants the index in network byte order for IPv4.
				var b [4]byte
				binary.BigEndian.PutUint32(b[:], physIndex)
				serr = windows.SetsockoptInt(h, windows.IPPROTO_IP, ipUnicastIf, int(*(*uint32)(unsafe.Pointer(&b[0]))))
			}
		})
		if err != nil {
			return err
		}
		return serr
	}
}

func listenUDP(port int, physical bool) (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: sockControl(physical)}
	pc, err := lc.ListenPacket(context.Background(), "udp4", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

// sendWithTTL sends one datagram with a small TTL and puts the socket's TTL back
func sendWithTTL(c *net.UDPConn, b []byte, dst netip.AddrPort, ttl int) error {
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

type ifaceInfo struct {
	index       uint32
	alias, desc string
	tunnel      bool
}

// routeInterface: the interface Windows uses toward an address
func routeInterface(dst netip.Addr) (ifaceInfo, error) {
	var idx uint32
	if err := windows.GetBestInterfaceEx(&windows.SockaddrInet4{Addr: dst.As4()}, &idx); err != nil {
		return ifaceInfo{}, err
	}
	info := ifaceInfo{index: idx}
	if luid, err := winipcfg.LUIDFromIndex(idx); err == nil {
		if row, err := luid.Interface(); err == nil {
			info.alias, info.desc = row.Alias(), row.Description()
			info.tunnel = row.Type == winipcfg.IfTypePropVirtual || row.Type == winipcfg.IfTypeTunnel
		}
	}
	d := strings.ToLower(info.alias + " " + info.desc)
	for _, s := range []string{"warp", "wireguard", "wintun", "amnezia", "openvpn", "tap-windows", "vpn", "outline"} {
		if strings.Contains(d, s) {
			info.tunnel = true
		}
	}
	return info, nil
}

func isElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// relaunchElevated starts this program again through UAC; false if the user said no
func relaunchElevated() bool {
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

func consoleUTF8() {
	windows.SetConsoleOutputCP(65001)
	windows.SetConsoleCP(65001)
}

var winmm = windows.NewLazySystemDLL("winmm.dll")

var timerHighRes bool

// setTimerHighRes asks Windows for 1 ms timer resolution (timeBeginPeriod) or gives it back
func setTimerHighRes(on bool) {
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
