package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	mrand "math/rand/v2"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// Probes of Epic's QoS echo (UDP 22222), the same as the router's ISP check (fnport-check):
// a socket sends 30 tagged packets; the TSPU stops the replies at 25 when it freezes a flow.

const (
	echoPort  = 22222
	pkts      = 30
	passMin   = 26 // more than 25 replies: no freeze
	frozenMin = 20 // a freeze stops at 24-25; far fewer is the echo's rate limit or loss
	pktGap    = 30 * time.Millisecond
	waitAfter = 400 * time.Millisecond
	fakeGap   = 30 * time.Millisecond
	roundGap  = 2 * time.Second // pause between probe rounds: probing a lot gets the address punished
)

type sockResult struct {
	port int
	got  int
	rtt  time.Duration // median, 0 without replies
}

func verdict(got int) string {
	switch {
	case got >= passMin:
		return "pass"
	case got >= frozenMin:
		return "frozen"
	case got > 0:
		return "limited"
	}
	return "silent"
}

func count(rs []sockResult, what string) int {
	n := 0
	for _, r := range rs {
		if verdict(r.got) == what {
			n++
		}
	}
	return n
}

func fmtResults(rs []sockResult) string {
	var parts []string
	for _, r := range rs {
		s := fmt.Sprintf("%d/%d", r.got, pkts)
		switch verdict(r.got) {
		case "pass":
			s += " проходит"
		case "frozen":
			s += " заморозка"
		case "limited":
			s += " мало ответов"
		default:
			s += " нет ответа"
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ", ")
}

func medianRTT(rs []sockResult) time.Duration {
	var all []time.Duration
	for _, r := range rs {
		if r.rtt > 0 {
			all = append(all, r.rtt)
		}
	}
	if len(all) == 0 {
		return 0
	}
	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
	return all[len(all)/2]
}

// openDirect opens a UDP socket on a random high port, sent out of the physical interface
func openDirect() (*net.UDPConn, error) {
	var last error
	for i := 0; i < 20; i++ {
		port := 20000 + mrand.IntN(40000)
		c, err := listenUDP(port, true)
		if err == nil {
			return c, nil
		}
		last = err // Windows reserves port ranges (Hyper-V): take another
	}
	return nil, last
}

func openDirectN(n int) ([]*net.UDPConn, error) {
	var cs []*net.UDPConn
	for i := 0; i < n; i++ {
		c, err := openDirect()
		if err != nil {
			closeAll(cs)
			return nil, err
		}
		cs = append(cs, c)
	}
	return cs, nil
}

func closeAll(cs []*net.UDPConn) {
	for _, c := range cs {
		c.Close()
	}
}

// probe sends pkts tagged packets from every socket to host's echo and counts the replies.
// With a fake, each socket first sends it with the given TTL.
func probe(cs []*net.UDPConn, host netip.Addr, fake []byte, ttl int) []sockResult {
	dst := netip.AddrPortFrom(host, echoPort)
	type state struct {
		tag  [2]byte
		mu   sync.Mutex
		sent [pkts]time.Time
		rtts []time.Duration
		got  int
	}
	st := make([]*state, len(cs))
	for i := range cs {
		st[i] = &state{}
		rand.Read(st[i].tag[:])
	}
	if fake != nil && ttl > 0 {
		for _, c := range cs {
			if err := sendWithTTL(c, fake, dst, ttl); err != nil {
				logf("  (фейк не отправлен: %v)", err)
			}
		}
		time.Sleep(fakeGap)
	}

	end := time.Now().Add(time.Duration(pkts)*pktGap + waitAfter)
	var wg sync.WaitGroup
	for i, c := range cs {
		wg.Add(1)
		go func(c *net.UDPConn, s *state) {
			defer wg.Done()
			buf := make([]byte, 2048)
			for {
				c.SetReadDeadline(end)
				n, from, err := c.ReadFromUDPAddrPort(buf)
				if err != nil {
					if ne, ok := err.(net.Error); ok && ne.Timeout() || time.Now().After(end) {
						return
					}
					continue // ICMP errors and the like
				}
				if from.Addr().Unmap() != host || from.Port() != echoPort || n < 4 ||
					buf[0] != s.tag[0] || buf[1] != s.tag[1] {
					continue
				}
				seq := int(binary.BigEndian.Uint16(buf[2:4]))
				s.mu.Lock()
				s.got++
				if seq < pkts && !s.sent[seq].IsZero() {
					s.rtts = append(s.rtts, time.Since(s.sent[seq]))
				}
				s.mu.Unlock()
			}
		}(c, st[i])
	}

	for seq := 0; seq < pkts; seq++ {
		for i, c := range cs {
			p := make([]byte, 0, 22)
			p = append(p, st[i].tag[:]...)
			p = binary.BigEndian.AppendUint16(p, uint16(seq))
			var r [10]byte
			rand.Read(r[:])
			p = append(p, r[:]...)
			p = append(p, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb)
			st[i].mu.Lock()
			st[i].sent[seq] = time.Now()
			st[i].mu.Unlock()
			c.WriteToUDPAddrPort(p, dst)
		}
		time.Sleep(pktGap)
	}
	wg.Wait()

	res := make([]sockResult, len(cs))
	for i, c := range cs {
		s := st[i]
		res[i] = sockResult{port: c.LocalAddr().(*net.UDPAddr).Port, got: s.got}
		if len(s.rtts) > 0 {
			sort.Slice(s.rtts, func(a, b int) bool { return s.rtts[a] < s.rtts[b] })
			res[i].rtt = s.rtts[len(s.rtts)/2]
		}
	}
	return res
}

// probeDirect: n fresh sockets on the physical interface
func probeDirect(host netip.Addr, n int, fake []byte, ttl int) ([]sockResult, error) {
	cs, err := openDirectN(n)
	if err != nil {
		return nil, err
	}
	defer closeAll(cs)
	return probe(cs, host, fake, ttl), nil
}

type ttlStep struct {
	ttl int
	res []sockResult
}

type scanResult struct {
	verdict     string // fake_works, fake_kills, fake_fails
	worksFrom   int
	recommended int
	steps       []ttlStep
}

// scanTTL: the fake helps once its TTL takes it past the DPI. TTLs from lo up, 2 sockets each;
// a TTL with a pass gets 2 more and is taken with at least 2 passes out of 4 (as fnport-check).
func scanTTL(host netip.Addr, fake []byte, lo, hi int) (scanResult, error) {
	var r scanResult
	silentRun := 0
	for t := lo; t <= hi; t++ {
		time.Sleep(roundGap)
		res, err := probeDirect(host, 2, fake, t)
		if err != nil {
			return r, err
		}
		logf("  TTL %d: %s", t, fmtResults(res))
		if count(res, "pass") >= 1 {
			time.Sleep(roundGap)
			more, err := probeDirect(host, 2, fake, t)
			if err != nil {
				return r, err
			}
			logf("  TTL %d, ещё раз: %s", t, fmtResults(more))
			res = append(res, more...)
			r.steps = append(r.steps, ttlStep{t, res})
			if count(res, "pass") >= 2 {
				r.verdict, r.worksFrom, r.recommended = "fake_works", t, t
				// one hop of margin against route changes, unless the fake starts killing flows there
				if t < hi {
					time.Sleep(roundGap)
					m, err := probeDirect(host, 2, fake, t+1)
					if err == nil {
						logf("  TTL %d (запас): %s", t+1, fmtResults(m))
						r.steps = append(r.steps, ttlStep{t + 1, m})
						if count(m, "silent") < len(m) {
							r.recommended = t + 1
						}
					}
				}
				return r, nil
			}
			continue
		}
		r.steps = append(r.steps, ttlStep{t, res})
		// the whole flow dies once the fake reaches some DPI: going further only kills more
		if count(res, "silent") == len(res) {
			silentRun++
		} else {
			silentRun = 0
		}
		if silentRun >= 2 {
			r.verdict = "fake_kills"
			return r, nil
		}
	}
	r.verdict = "fake_fails"
	return r, nil
}
