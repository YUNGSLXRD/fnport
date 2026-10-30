package qos

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"
)

// an echo that freezes after 25 packets looks frozen; one that drops packets here and there,
// answering the last ones too, is loss
func TestLossyOrFrozen(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:22222")
	if err != nil {
		t.Skip("port 22222 busy:", err)
	}
	defer pc.Close()
	mode := "frozen"
	var mu sync.Mutex
	getMode := func() string {
		mu.Lock()
		defer mu.Unlock()
		return mode
	}
	setMode := func(m string) {
		mu.Lock()
		mode = m
		mu.Unlock()
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			seq := binary.BigEndian.Uint16(buf[2:4])
			m := getMode()
			switch {
			case m == "frozen" && seq >= 25:
				continue
			case m == "lossy" && seq%6 == 3: // 5 of 30 lost, spread
				continue
			}
			pc.WriteTo(buf[:n], from)
		}
	}()
	host := netip.MustParseAddr("127.0.0.1")
	rs, err := Probe(host, 1, nil, 0)
	if err != nil || Verdict(rs[0]) != "frozen" || IsLossy(rs[0]) {
		t.Fatalf("frozen echo: %v %v", rs, err)
	}
	setMode("lossy")
	rs, err = Probe(host, 1, nil, 0)
	if err != nil || !IsLossy(rs[0]) || Got(rs[0]) != 25 || Verdict(rs[0]) != "pass" {
		t.Fatalf("lossy echo: %v %v", rs, err)
	}
}
