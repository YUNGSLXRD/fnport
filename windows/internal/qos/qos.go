// Package qos: probes of Epic's QoS echo (UDP 22222), the same as the router's ISP check
// (fnport-check) and fnport-probe. A socket sends 30 tagged packets; the TSPU stops the replies
// at 25 when it freezes a flow. Also a single ping, and STUN for the port the outside sees.
package qos

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/YUNGSLXRD/fnport/windows/internal/wnet"
)

const (
	EchoPort  = 22222
	Pkts      = 30
	PassMin   = 26 // more than 25 replies: no freeze
	FrozenMin = 20 // a freeze stops at 24-25; far fewer is the echo's rate limit or loss
	pktGap    = 30 * time.Millisecond
	waitAfter = 400 * time.Millisecond
	fakeGap   = 30 * time.Millisecond
)

// packet: the format the router's check and the probe use (the echo answers it)
func packet(tag [2]byte, seq int) []byte {
	p := make([]byte, 0, 22)
	p = append(p, tag[:]...)
	p = binary.BigEndian.AppendUint16(p, uint16(seq))
	var r [10]byte
	rand.Read(r[:])
	p = append(p, r[:]...)
	return append(p, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb)
}

// Verdict: "pass", "frozen", "limited" (a few replies) or "silent"
func Verdict(got int) string {
	switch {
	case got >= PassMin:
		return "pass"
	case got >= FrozenMin:
		return "frozen"
	case got > 0:
		return "limited"
	}
	return "silent"
}

func Count(res []int, what string) int {
	n := 0
	for _, r := range res {
		if Verdict(r) == what {
			n++
		}
	}
	return n
}

// Probe: n fresh sockets on the physical interface, each (with the fake first, if given)
// sends Pkts packets to host's echo; replies per socket
func Probe(host netip.Addr, n int, fake []byte, ttl int) ([]int, error) {
	var cs []*net.UDPConn
	for i := 0; i < n; i++ {
		c, err := wnet.ListenUDP(0, true)
		if err != nil {
			for _, c := range cs {
				c.Close()
			}
			return nil, err
		}
		cs = append(cs, c)
	}
	defer func() {
		for _, c := range cs {
			c.Close()
		}
	}()
	dst := netip.AddrPortFrom(host, EchoPort)
	tags := make([][2]byte, n)
	got := make([]int, n)
	var mu sync.Mutex
	if fake != nil && ttl > 0 {
		for _, c := range cs {
			wnet.SendWithTTL(c, fake, dst, ttl)
		}
		time.Sleep(fakeGap)
	}
	end := time.Now().Add(Pkts*pktGap + waitAfter)
	var wg sync.WaitGroup
	for i, c := range cs {
		rand.Read(tags[i][:])
		wg.Add(1)
		go func(i int, c *net.UDPConn) {
			defer wg.Done()
			buf := make([]byte, 2048)
			for {
				c.SetReadDeadline(end)
				k, from, err := c.ReadFromUDPAddrPort(buf)
				if err != nil {
					if ne, ok := err.(net.Error); ok && ne.Timeout() || time.Now().After(end) {
						return
					}
					continue
				}
				if from.Addr().Unmap() == host && from.Port() == EchoPort && k >= 2 && buf[0] == tags[i][0] && buf[1] == tags[i][1] {
					mu.Lock()
					got[i]++
					mu.Unlock()
				}
			}
		}(i, c)
	}
	for seq := 0; seq < Pkts; seq++ {
		for i, c := range cs {
			c.WriteToUDPAddrPort(packet(tags[i], seq), dst)
		}
		time.Sleep(pktGap)
	}
	wg.Wait()
	return got, nil
}

// Ping: the best RTT of a few echo packets from a fresh socket on the physical interface;
// 0 without replies. Far below the 25 packets that freeze a flow.
func Ping(host netip.Addr, packets int) time.Duration {
	c, err := wnet.ListenUDP(0, true)
	if err != nil {
		return 0
	}
	defer c.Close()
	dst := netip.AddrPortFrom(host, EchoPort)
	var tag [2]byte
	rand.Read(tag[:])
	sent := make([]time.Time, packets)
	for i := range sent {
		sent[i] = time.Now()
		c.WriteToUDPAddrPort(packet(tag, i), dst)
		time.Sleep(20 * time.Millisecond)
	}
	var rtts []time.Duration
	buf := make([]byte, 2048)
	c.SetReadDeadline(time.Now().Add(time.Second))
	for {
		n, from, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				break
			}
			continue
		}
		if from.Addr().Unmap() != host || n < 4 || buf[0] != tag[0] || buf[1] != tag[1] {
			continue
		}
		if seq := int(binary.BigEndian.Uint16(buf[2:4])); seq < packets {
			rtts = append(rtts, time.Since(sent[seq]))
		}
	}
	if len(rtts) == 0 {
		return 0
	}
	sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
	return rtts[0]
}
