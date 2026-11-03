package wnet

import (
	"net"
	"net/netip"
	"sync"
)

var ownUDP struct {
	sync.Mutex
	sockets map[uint16]*net.UDPConn
}

func rememberUDP(c *net.UDPConn) {
	ownUDP.Lock()
	defer ownUDP.Unlock()
	if ownUDP.sockets == nil {
		ownUDP.sockets = map[uint16]*net.UDPConn{}
	}
	ownUDP.sockets[uint16(c.LocalAddr().(*net.UDPAddr).Port)] = c
}

// Closed entries are removed lazily so a reused application port is not excluded.
func IsOwnUDP(src netip.AddrPort) bool {
	ownUDP.Lock()
	defer ownUDP.Unlock()
	c := ownUDP.sockets[src.Port()]
	if c == nil {
		return false
	}
	rc, err := c.SyscallConn()
	if err == nil {
		err = rc.Control(func(uintptr) {})
	}
	if err != nil {
		delete(ownUDP.sockets, src.Port())
		return false
	}
	return true
}
