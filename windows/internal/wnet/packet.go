// Package wnet: what the Windows probe and app share: IPv4/UDP packets, sockets on the
// physical interface, the Wintun adapter.
package wnet

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// Minimal IPv4/UDP handling for the packets that pass through the Wintun adapter.

type UDPPacket struct {
	Src, Dst netip.AddrPort
	Payload  []byte
}

var ErrNotUDP4 = errors.New("not an IPv4 UDP packet")

func ParseUDP4(b []byte) (UDPPacket, error) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return UDPPacket{}, ErrNotUDP4
	}
	ihl := int(b[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if ihl < 20 || total < ihl+8 || total > len(b) || b[9] != 17 {
		return UDPPacket{}, ErrNotUDP4
	}
	// fragments carry no complete UDP datagram
	if binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 {
		return UDPPacket{}, ErrNotUDP4
	}
	u := b[ihl:total]
	ulen := int(binary.BigEndian.Uint16(u[4:6]))
	if ulen < 8 || ulen > len(u) {
		return UDPPacket{}, ErrNotUDP4
	}
	src := netip.AddrFrom4([4]byte(b[12:16]))
	dst := netip.AddrFrom4([4]byte(b[16:20]))
	return UDPPacket{
		Src:     netip.AddrPortFrom(src, binary.BigEndian.Uint16(u[0:2])),
		Dst:     netip.AddrPortFrom(dst, binary.BigEndian.Uint16(u[2:4])),
		Payload: u[8:ulen],
	}, nil
}

func ChecksumAdd(sum uint32, b []byte) uint32 {
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	return sum
}

func ChecksumFold(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// BuildUDP4 makes a complete IPv4 packet with valid header and UDP checksums:
// Windows drops injected datagrams with a bad UDP checksum.
func BuildUDP4(src, dst netip.AddrPort, payload []byte, id uint16) []byte {
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
	binary.BigEndian.PutUint16(b[10:12], ChecksumFold(ChecksumAdd(0, b[:20])))

	u := b[20:]
	binary.BigEndian.PutUint16(u[0:2], src.Port())
	binary.BigEndian.PutUint16(u[2:4], dst.Port())
	binary.BigEndian.PutUint16(u[4:6], uint16(ulen))
	copy(u[8:], payload)
	sum := ChecksumAdd(0, s4[:])
	sum = ChecksumAdd(sum, d4[:])
	sum += 17 + uint32(ulen)
	c := ChecksumFold(ChecksumAdd(sum, u))
	if c == 0 {
		c = 0xffff
	}
	binary.BigEndian.PutUint16(u[6:8], c)
	return b
}

// IPv4Proto: the transport protocol of an IPv4 packet (6 TCP, 17 UDP), 0 for anything else
func IPv4Proto(b []byte) byte {
	if len(b) < 20 || b[0]>>4 != 4 {
		return 0
	}
	return b[9]
}
