//go:build !windows

package wnet

// Stand-ins so the platform-neutral parts build and run their tests on Linux and macOS.

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

var PhysIndex uint32

var PhysAddr netip.Addr

func ListenUDP(port int, physical bool) (*net.UDPConn, error) {
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(context.Background(), "udp4", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

func DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp4", dst.String())
}

func SendWithTTL(c *net.UDPConn, b []byte, dst netip.AddrPort, ttl int) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	rc.Control(func(fd uintptr) { syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl) })
	_, err = c.WriteToUDPAddrPort(b, dst)
	rc.Control(func(fd uintptr) { syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, 64) })
	return err
}

type IfaceInfo struct {
	Index       uint32
	Addr        netip.Addr
	Alias, Desc string
	Tunnel      bool
}

func RouteInterface(dst netip.Addr) (IfaceInfo, error) { return IfaceInfo{}, nil }
func IsElevated() bool                                 { return true }
func RelaunchElevated() bool                           { return false }
func ConsoleUTF8()                                     {}
func SetTimerHighRes(on bool)                          {}
