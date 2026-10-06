package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"time"
)

// STUN binding (RFC 5389): the address and port the outside world sees for a socket.
// If the port a STUN server reports equals the socket's own port, the routers on the way keep
// the source port, and the port this program picks is the one the ISP's DPI sees.

const stunMagic = 0x2112A442

func stunRequest() ([]byte, [12]byte) {
	var txid [12]byte
	rand.Read(txid[:])
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[0:2], 0x0001)
	binary.BigEndian.PutUint32(b[4:8], stunMagic)
	copy(b[8:20], txid[:])
	return b, txid
}

var errSTUN = errors.New("not a STUN binding response")

func parseSTUNResponse(b []byte, txid [12]byte) (netip.AddrPort, error) {
	if len(b) < 20 || binary.BigEndian.Uint16(b[0:2]) != 0x0101 ||
		binary.BigEndian.Uint32(b[4:8]) != stunMagic || [12]byte(b[8:20]) != txid {
		return netip.AddrPort{}, errSTUN
	}
	n := int(binary.BigEndian.Uint16(b[2:4]))
	if 20+n > len(b) {
		return netip.AddrPort{}, errSTUN
	}
	attrs := b[20 : 20+n]
	var mapped netip.AddrPort
	for len(attrs) >= 4 {
		t := binary.BigEndian.Uint16(attrs[0:2])
		l := int(binary.BigEndian.Uint16(attrs[2:4]))
		if 4+l > len(attrs) {
			break
		}
		v := attrs[4 : 4+l]
		if l >= 8 && v[1] == 0x01 {
			port := binary.BigEndian.Uint16(v[2:4])
			ip := [4]byte(v[4:8])
			switch t {
			case 0x0020: // XOR-MAPPED-ADDRESS wins
				port ^= stunMagic >> 16
				binary.BigEndian.PutUint32(ip[:], binary.BigEndian.Uint32(ip[:])^stunMagic)
				return netip.AddrPortFrom(netip.AddrFrom4(ip), port), nil
			case 0x0001: // MAPPED-ADDRESS from old servers
				mapped = netip.AddrPortFrom(netip.AddrFrom4(ip), port)
			}
		}
		attrs = attrs[4+(l+3)&^3:]
	}
	if mapped.IsValid() {
		return mapped, nil
	}
	return netip.AddrPort{}, errSTUN
}

// stunQuery asks one server, two tries
func stunQuery(c *net.UDPConn, server netip.AddrPort) (netip.AddrPort, error) {
	buf := make([]byte, 1500)
	for try := 0; try < 2; try++ {
		req, txid := stunRequest()
		if _, err := c.WriteToUDPAddrPort(req, server); err != nil {
			return netip.AddrPort{}, err
		}
		end := time.Now().Add(1200 * time.Millisecond)
		for {
			c.SetReadDeadline(end)
			n, from, err := c.ReadFromUDPAddrPort(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					break
				}
				if time.Now().After(end) {
					break
				}
				continue
			}
			if from.Addr().Unmap() != server.Addr() {
				continue
			}
			if m, err := parseSTUNResponse(buf[:n], txid); err == nil {
				return m, nil
			}
		}
	}
	return netip.AddrPort{}, errors.New("no answer")
}
