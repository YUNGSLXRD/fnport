package qos

import (
	"net"
	"net/netip"
	"testing"
)

// an echo on 127.0.0.1:22222 that stops answering a source port after 25 replies
func echo(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: EchoPort})
	if err != nil {
		t.Skipf("no UDP %d on localhost: %v", EchoPort, err)
	}
	t.Cleanup(func() { c.Close() })
	seen := map[int]int{}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n != 22 { // the beacons' format: tag, sequence, 10 random bytes, 8 marker bytes
				continue
			}
			if seen[from.Port]++; seen[from.Port] <= 25 {
				c.WriteToUDP(buf[:n], from)
			}
		}
	}()
}

func TestProbeAndPing(t *testing.T) {
	echo(t)
	host := netip.MustParseAddr("127.0.0.1")
	rs, err := Probe(host, 2, nil, 0)
	if err != nil || len(rs) != 2 || Count(rs, "frozen") != 2 {
		t.Fatalf("probe %v %v", rs, err)
	}
	if rtt := Ping(host, 3); rtt <= 0 {
		t.Fatal("no ping reply")
	}
}
