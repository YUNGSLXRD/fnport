package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestUDP4RoundTrip(t *testing.T) {
	src := netip.MustParseAddrPort("3.66.90.173:22222")
	dst := netip.MustParseAddrPort("10.254.77.2:50123")
	for _, payload := range [][]byte{nil, []byte("x"), bytes.Repeat([]byte{0xab}, 1201)} {
		pkt := buildUDP4(src, dst, payload, 7)
		if checksumFold(checksumAdd(0, pkt[:20])) != 0 {
			t.Fatal("bad IPv4 header checksum")
		}
		// UDP checksum over the pseudo header and the datagram sums to all ones
		s4, d4 := src.Addr().As4(), dst.Addr().As4()
		sum := checksumAdd(checksumAdd(0, s4[:]), d4[:]) + 17 + uint32(len(pkt)-20)
		if checksumFold(checksumAdd(sum, pkt[20:])) != 0 {
			t.Fatal("bad UDP checksum")
		}
		p, err := parseUDP4(pkt)
		if err != nil || p.src != src || p.dst != dst || !bytes.Equal(p.payload, payload) {
			t.Fatalf("round trip: %+v %v", p, err)
		}
	}
	// odd length: the checksum must match the textbook computation
	pkt := buildUDP4(netip.MustParseAddrPort("192.168.1.137:5000"), netip.MustParseAddrPort("3.66.90.173:22222"), []byte("hello"), 0x1234)
	if got := hex.EncodeToString(pkt[26:28]); got != udpCheck(pkt) {
		t.Fatalf("UDP checksum %s, want %s", got, udpCheck(pkt))
	}
}

// udpCheck recomputes the UDP checksum the textbook way (RFC 768) for comparison
func udpCheck(pkt []byte) string {
	var ph []byte
	ph = append(ph, pkt[12:20]...)
	ph = append(ph, 0, 17)
	ph = binary.BigEndian.AppendUint16(ph, uint16(len(pkt)-20))
	u := append([]byte{}, pkt[20:]...)
	u[6], u[7] = 0, 0
	all := append(ph, u...)
	if len(all)%2 == 1 {
		all = append(all, 0)
	}
	var sum uint32
	for i := 0; i < len(all); i += 2 {
		sum += uint32(all[i])<<8 | uint32(all[i+1])
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return hex.EncodeToString([]byte{byte(^sum >> 8), byte(^sum)})
}

func TestParseRejects(t *testing.T) {
	pkt := buildUDP4(netip.MustParseAddrPort("1.2.3.4:1"), netip.MustParseAddrPort("5.6.7.8:2"), []byte("abc"), 1)
	bad := append([]byte{}, pkt...)
	bad[9] = 6 // TCP
	if _, err := parseUDP4(bad); err == nil {
		t.Fatal("TCP accepted")
	}
	frag := append([]byte{}, pkt...)
	frag[6] = 0x20 // more fragments
	if _, err := parseUDP4(frag); err == nil {
		t.Fatal("fragment accepted")
	}
	if _, err := parseUDP4(pkt[:25]); err == nil {
		t.Fatal("truncated packet accepted")
	}
}

// RFC 5769, 2.2: sample IPv4 response
func TestSTUNVector(t *testing.T) {
	msg, _ := hex.DecodeString("0101003c2112a442b7e7a701bc34d686fa87dfae" +
		"8022000b7465737420766563746f7220" +
		"00200008" + "0001a147e112a643" +
		"00080014" + "2b91f599fd9e90c38c7489f92af9ba53f06be7d7" +
		"80280004" + "c07d4c96")
	var txid [12]byte
	copy(txid[:], msg[8:20])
	m, err := parseSTUNResponse(msg, txid)
	if err != nil || m != netip.MustParseAddrPort("192.0.2.1:32853") {
		t.Fatalf("got %v %v", m, err)
	}
	txid[0] ^= 1
	if _, err := parseSTUNResponse(msg, txid); err == nil {
		t.Fatal("foreign transaction accepted")
	}
}

func TestCityAndPublic(t *testing.T) {
	for ip, c := range map[string]string{"3.66.90.173": "frankfurt", "18.133.162.202": "london", "13.37.148.3": "paris", "52.1.1.1": "eu"} {
		if got := city(netip.MustParseAddr(ip)); got != c {
			t.Errorf("%s: %s", ip, got)
		}
	}
	for ip, pub := range map[string]bool{"3.66.90.173": true, "198.18.4.7": false, "192.168.1.1": false, "100.64.0.1": false, "10.1.1.1": false} {
		if isPublic(netip.MustParseAddr(ip)) != pub {
			t.Errorf("isPublic(%s)", ip)
		}
	}
}

// tspu imitates the echo behind the DPI on 127.0.0.1:22222: a flow (source port) gets 25
// replies, unless its first packet was the fake
type tspu struct {
	conn *net.UDPConn
	mu   sync.Mutex
	seen map[int]int // replies per source port; -1 = whitelisted
}

func startTSPU(t *testing.T) *tspu {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: echoPort})
	if err != nil {
		t.Skipf("no UDP %d on localhost: %v", echoPort, err)
	}
	s := &tspu{conn: c, seen: map[int]int{}}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			s.mu.Lock()
			v, ok := s.seen[from.Port]
			if !ok && n > 1000 && buf[0]&0xc0 == 0xc0 { // a QUIC Initial: the fake
				s.seen[from.Port] = -1
				s.mu.Unlock()
				continue
			}
			if v >= 0 {
				if v >= 25 {
					s.mu.Unlock()
					continue
				}
				s.seen[from.Port] = v + 1
			}
			s.mu.Unlock()
			c.WriteToUDP(buf[:n], from)
		}
	}()
	t.Cleanup(func() { c.Close() })
	return s
}

func testFake(t *testing.T) []byte {
	fs := loadFakes()
	if len(fs) == 0 {
		t.Fatal("no fakes embedded")
	}
	return fs[0].data
}

func TestProbeFreezeAndFake(t *testing.T) {
	startTSPU(t)
	host := netip.MustParseAddr("127.0.0.1")
	res, err := probeDirect(host, 2, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if count(res, "frozen") != 2 {
		t.Fatalf("without fake: %s", fmtResults(res))
	}
	res, err = probeDirect(host, 2, testFake(t), 3)
	if err != nil {
		t.Fatal(err)
	}
	if count(res, "pass") != 2 || res[0].rtt <= 0 {
		t.Fatalf("with fake: %s", fmtResults(res))
	}
	if !strings.Contains(fmtResults(res), "30/30 проходит") {
		t.Fatal(fmtResults(res))
	}
}

// chanDev: the adapter as two queues
type chanDev struct {
	in, out chan []byte
	once    sync.Once
	done    chan struct{}
}

func (d *chanDev) ReadPacket(buf []byte) (int, error) {
	select {
	case p := <-d.in:
		return copy(buf, p), nil
	case <-d.done:
		return 0, net.ErrClosed
	}
}

func (d *chanDev) WritePacket(p []byte) error {
	select {
	case d.out <- append([]byte{}, p...):
	case <-d.done:
		return net.ErrClosed
	}
	return nil
}

func (d *chanDev) Close() error { d.once.Do(func() { close(d.done) }); return nil }

func TestRelay(t *testing.T) {
	startTSPU(t)
	dev := &chanDev{in: make(chan []byte, 64), out: make(chan []byte, 256), done: make(chan struct{})}
	client := netip.MustParseAddr("10.254.77.2")
	rl := newRelay(dev, client, openDirect)
	defer rl.close()
	go rl.run()

	server := netip.MustParseAddrPort("127.0.0.1:22222")
	rl.setPlan(40001, flowPlan{testFake(t), 3})
	for seq := 0; seq < pkts; seq++ {
		for _, sp := range []uint16{40001, 40002} {
			payload := binary.BigEndian.AppendUint16([]byte("tg"), uint16(seq))
			dev.in <- buildUDP4(netip.AddrPortFrom(client, sp), server, payload, 1)
		}
		time.Sleep(5 * time.Millisecond)
	}
	got := map[uint16]int{}
	deadline := time.After(2 * time.Second)
loop:
	for {
		select {
		case p := <-dev.out:
			u, err := parseUDP4(p)
			if err != nil || u.src != server || u.dst.Addr() != client || !bytes.HasPrefix(u.payload, []byte("tg")) {
				t.Fatalf("bad reply %+v %v", u, err)
			}
			got[u.dst.Port()]++
		case <-deadline:
			break loop
		}
	}
	if got[40001] != pkts || got[40002] != 25 {
		t.Fatalf("replies: with fake %d, without %d", got[40001], got[40002])
	}
	f := rl.flowFor(40001)
	if f == nil || f.out.Load() != pkts || f.in.Load() != pkts || f.port < 20000 {
		t.Fatalf("flow %+v", f)
	}
}
