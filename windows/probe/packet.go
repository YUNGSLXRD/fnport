package main

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// Minimal IPv4/UDP handling for the packets that pass through the Wintun adapter.

type udpPacket struct {
	src, dst netip.AddrPort
	payload  []byte
}

var errNotUDP4 = errors.New("not an IPv4 UDP packet")

func parseUDP4(b []byte) (udpPacket, error) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return udpPacket{}, errNotUDP4
	}
	ihl := int(b[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if ihl < 20 || total < ihl+8 || total > len(b) || b[9] != 17 {
		return udpPacket{}, errNotUDP4
	}
	// fragments carry no complete UDP datagram
	if binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 {
		return udpPacket{}, errNotUDP4
	}
	u := b[ihl:total]
	ulen := int(binary.BigEndian.Uint16(u[4:6]))
	if ulen < 8 || ulen > len(u) {
		return udpPacket{}, errNotUDP4
	}
	src := netip.AddrFrom4([4]byte(b[12:16]))
	dst := netip.AddrFrom4([4]byte(b[16:20]))
	return udpPacket{
		src:     netip.AddrPortFrom(src, binary.BigEndian.Uint16(u[0:2])),
		dst:     netip.AddrPortFrom(dst, binary.BigEndian.Uint16(u[2:4])),
		payload: u[8:ulen],
	}, nil
}

func checksumAdd(sum uint32, b []byte) uint32 {
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	return sum
}

func checksumFold(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// buildUDP4 makes a complete IPv4 packet with valid header and UDP checksums:
// Windows drops injected datagrams with a bad UDP checksum.
func buildUDP4(src, dst netip.AddrPort, payload []byte, id uint16) []byte {
	ulen := 8 + len(payload)
	b := make([]byte, 20+ulen)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	binary.BigEndian.PutUint16(b[4:6], id)
	b[8] = 64
	b[9] = 17
	s4, d4 := src.Addr().As4(), dst.Addr().As4()
	copy(b[12:16], s4[:])
	copy(b[16:20], d4[:])
	binary.BigEndian.PutUint16(b[10:12], checksumFold(checksumAdd(0, b[:20])))

	u := b[20:]
	binary.BigEndian.PutUint16(u[0:2], src.Port())
	binary.BigEndian.PutUint16(u[2:4], dst.Port())
	binary.BigEndian.PutUint16(u[4:6], uint16(ulen))
	copy(u[8:], payload)
	sum := checksumAdd(0, s4[:])
	sum = checksumAdd(sum, d4[:])
	sum += 17 + uint32(ulen)
	c := checksumFold(checksumAdd(sum, u))
	if c == 0 {
		c = 0xffff
	}
	binary.BigEndian.PutUint16(u[6:8], c)
	return b
}
