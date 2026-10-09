package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	mrand "math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/YUNGSLXRD/fnport/windows/internal/fakes"
	"github.com/YUNGSLXRD/fnport/windows/internal/wnet"
)

// Port probing, as fnportd on the router does it: TSPU freezes a UDP flow to AWS after 25 packets
// depending on (source port, server ip, server port). Probe the server's own game port with
// Unreal handshake packets (the server answers them statelessly) from several candidate source
// ports, each preceded by the fake, and use a port that got all replies.

const (
	probePkts    = 30
	probePass    = 26 // more than 25: no freeze; the margin is for loss
	frozenMin    = 20 // a freeze stops at 24-25; far fewer is the server limiting or loss
	probeIv      = 30 * time.Millisecond
	probeWait    = 400 * time.Millisecond
	fakeGap      = 30 * time.Millisecond
	portMin      = 20000
	portRange    = 40000
	limitHoldoff = 15 * time.Minute // no handshake probes after a server capped our replies
	fakeHoldoff  = 30 * time.Minute // without the fake once it proved harmful here
	fakeTrial    = 16               // probe sockets with one fake before judging it
)

// first packet of the Unreal stateless handshake, as sent by the client
var handshake = func() []byte {
	b := []byte{0x47, 0x1a, 0x20, 0x00, 0x00, 0x70, 0x67, 0xb5, 0x5a, 0x05}
	b = append(b, make([]byte, 28)...)
	return append(b, 0x00, 0x90, 0xd6, 0xa2, 0xee, 0x35, 0x36, 0x85, 0x46, 0x10)
}()

type mode int

const (
	modeGame  mode = iota // handshakes to the game port
	modeQoS               // the server's QoS echo
	modeBlind             // untested ports: the fake does the work, remap catches the rest
)

type target struct {
	ts           time.Time
	good         []int
	tried        map[int]bool
	silentRounds int
	answered     bool // the server answered some probe: a silent round is its pause, not refusal
	mode         mode
}

type prober struct {
	cfg *config
	mu  sync.Mutex // one probe at a time, as on the router: bursts get the address punished

	targets      map[netip.AddrPort]*target
	gameOffUntil time.Time
	budgetWindow time.Time
	budgetUsed   int

	fmu          sync.Mutex // fake state: read by new flows while a probe holds mu
	fakes        []fakes.File
	fakeIdx      int
	fakeOffUntil time.Time
	fakeTries    int
	fakeGood     int

	stat *counters
}

func newProber(cfg *config, st *counters) *prober {
	return &prober{cfg: cfg, targets: map[netip.AddrPort]*target{}, fakes: cfg.fakes, stat: st}
}

func (p *prober) fakeOn() bool {
	p.fmu.Lock()
	defer p.fmu.Unlock()
	return len(p.fakes) > 0 && time.Now().After(p.fakeOffUntil)
}

// fake: the fake to send before a probe or a flow, nil when off
func (p *prober) fake() []byte {
	p.fmu.Lock()
	defer p.fmu.Unlock()
	if len(p.fakes) == 0 || time.Now().Before(p.fakeOffUntil) {
		return nil
	}
	return p.fakes[p.fakeIdx].Data
}

func (p *prober) fakeNow() []byte { return p.fake() }

func (p *prober) qosBatch() int {
	if p.fakeOn() {
		return 4 // the fake lets about half of the ports pass
	}
	return 12
}

// sendFake: one fake with a whitelisted SNI on this socket's flow, with a short TTL
func sendFake(c *net.UDPConn, fake []byte, dst netip.AddrPort, ttl int) bool {
	if fake == nil {
		return false
	}
	return wnet.SendWithTTL(c, fake, dst, ttl) == nil
}

func freshPorts(t *target, n int, busy func(int) bool) []int {
	var cand []int
	for tries := 0; len(cand) < n && tries < 1000; tries++ {
		p := portMin + mrand.IntN(portRange)
		if t.tried[p] || busy(p) || contains(cand, p) {
			continue
		}
		cand = append(cand, p)
	}
	return cand
}

func contains(s []int, v int) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// probe sends probePkts packets from each source port to dst and counts replies per port.
// Ports that cannot be bound (in use, reserved by Windows) are left out of the result.
func (p *prober) probe(dst netip.AddrPort, ports []int, qos bool, fake []byte) map[int]int {
	type sock struct {
		c    *net.UDPConn
		port int
		tag  [2]byte
		mu   sync.Mutex
		got  int
	}
	var socks []*sock
	for _, port := range ports {
		c, err := wnet.ListenUDP(port, true)
		if err != nil {
			continue
		}
		s := &sock{c: c, port: port}
		rand.Read(s.tag[:])
		socks = append(socks, s)
	}
	faked := false
	for _, s := range socks {
		if sendFake(s.c, fake, dst, p.cfg.fakeTTL) {
			faked = true
		}
	}
	if faked {
		time.Sleep(fakeGap)
	}
	end := time.Now().Add(probePkts*probeIv + probeWait)
	var wg sync.WaitGroup
	for _, s := range socks {
		wg.Add(1)
		go func(s *sock) {
			defer wg.Done()
			buf := make([]byte, 2048)
			for {
				s.c.SetReadDeadline(end)
				n, from, err := s.c.ReadFromUDPAddrPort(buf)
				if err != nil {
					if ne, ok := err.(net.Error); ok && ne.Timeout() || time.Now().After(end) {
						return
					}
					continue
				}
				// count only replies from the probed server
				if from.Addr().Unmap() != dst.Addr() || from.Port() != dst.Port() {
					continue
				}
				if qos && (n < 2 || buf[0] != s.tag[0] || buf[1] != s.tag[1]) {
					continue
				}
				s.mu.Lock()
				s.got++
				s.mu.Unlock()
			}
		}(s)
	}
	for i := 0; i < probePkts; i++ {
		for _, s := range socks {
			pkt := handshake
			if qos {
				pkt = binary.BigEndian.AppendUint16(append([]byte(nil), s.tag[:]...), uint16(i))
				var r [10]byte
				rand.Read(r[:])
				pkt = append(pkt, r[:]...)
				pkt = append(pkt, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb)
			}
			s.c.WriteToUDPAddrPort(pkt, dst)
		}
		time.Sleep(probeIv)
	}
	wg.Wait()
	res := map[int]int{}
	for _, s := range socks {
		s.c.Close()
		s.mu.Lock()
		res[s.port] = s.got
		s.mu.Unlock()
	}
	return res
}

// learn what game-port probes tell about the fake: switch to a spare when it does not work here
func (p *prober) learn(results []int) {
	tried, good := 0, 0
	for _, got := range results {
		if got >= probePass {
			tried++
			good++
		} else if got >= frozenMin {
			tried++ // 1-19 is the server limiting or loss, 0 is silence
		}
	}
	if tried == 0 {
		return
	}
	p.fakeTries += tried
	p.fakeGood += good
	if p.fakeTries >= fakeTrial && p.fakeGood <= 1 && len(p.fakes) > 1 {
		p.fmu.Lock()
		old := p.fakes[p.fakeIdx].Name
		p.fakeIdx = (p.fakeIdx + 1) % len(p.fakes)
		p.fmu.Unlock()
		logf("фейк %s здесь не работает (%d из %d проб прошли), переключаюсь на %s",
			old, p.fakeGood, p.fakeTries, p.fakes[p.fakeIdx].Name)
		p.stat.add(&p.stat.fakeSwitch, 1)
		p.fakeTries, p.fakeGood = 0, 0
	} else if p.fakeTries >= fakeTrial*4 {
		// judge by recent probes only
		p.fakeTries, p.fakeGood = p.fakeTries/2, p.fakeGood/2
	}
}

func (p *prober) budgetTake(n int) bool {
	if time.Since(p.budgetWindow) >= time.Minute {
		p.budgetWindow, p.budgetUsed = time.Now(), 0
	}
	if p.budgetUsed+n > p.cfg.budget {
		return false
	}
	p.budgetUsed += n
	return true
}

func (p *prober) target(dst netip.AddrPort) *target {
	t := p.targets[dst]
	if t == nil || time.Since(t.ts) > p.cfg.verdictTTL {
		m := modeGame
		if time.Now().Before(p.gameOffUntil) {
			m = modeQoS
			if p.fakeOn() {
				m = modeBlind
			}
		}
		t = &target{ts: time.Now(), tried: map[int]bool{}, mode: m}
		p.targets[dst] = t
	}
	return t
}

// refresh makes sure at least `want` good source ports are known for dst; busy tells which
// ports this PC already uses (they cannot be probed)
func (p *prober) refresh(dst netip.AddrPort, want int, busy func(int) bool) *target {
	t := p.target(dst)
	if len(t.good) >= want {
		return t
	}

	// the server does not answer probes: hand out untested ports. The fake sent before the flow
	// does the work, and a flow that freezes anyway gets remapped.
	if t.mode == modeBlind && !p.fakeOn() {
		t.mode = modeQoS // untested ports only make sense with the fake
	}
	if t.mode == modeBlind {
		cand := freshPorts(t, want-len(t.good), busy)
		for _, c := range cand {
			t.tried[c] = true
			t.good = append(t.good, c)
		}
		logf("сервер %s не отвечает на проверки, порты без проверки: %s", dst, joinInts(cand))
		return t
	}

	qos := t.mode == modeQoS
	n := p.cfg.batch
	if qos {
		n = p.qosBatch()
	}
	if !p.budgetTake(n) {
		logf("лимит проверок исчерпан (%d в минуту), %s не проверяю", p.cfg.budget, dst)
		return t
	}
	cand := freshPorts(t, n, busy)
	pdst := dst
	if qos {
		pdst = netip.AddrPortFrom(dst.Addr(), p.cfg.qosPort)
	}
	withFake := p.fakeOn()
	t0 := time.Now()
	res := p.probe(pdst, cand, qos, p.fake())
	var fresh, results []int
	frozen, silent := 0, 0
	counts := map[int]bool{}
	for _, c := range cand {
		t.tried[c] = true
		got, ok := res[c]
		if !ok {
			continue // not bound: no verdict
		}
		results = append(results, got)
		counts[got] = true
		switch {
		case got >= probePass:
			fresh = append(fresh, c)
		case got == 0:
			silent++
		default:
			frozen++
		}
	}
	t.good = append(t.good, fresh...)
	via := "игровой порт"
	if qos {
		via = "эхо"
	}
	logf("проверка %s через %s: годных %d, замёрзло %d, без ответа %d (%d мс)",
		dst, via, len(fresh), frozen, silent, time.Since(t0).Milliseconds())
	p.stat.add(&p.stat.tested, len(results))
	p.stat.add(&p.stat.good, len(fresh))
	if !qos && withFake {
		p.learn(results)
	}
	if len(results) == 0 {
		return t
	}
	if silent < len(results) {
		t.answered = true
	}

	// a server that answered before and now keeps quiet caps handshake replies for our address
	// for a while (seen: two silent rounds, then a good port). Try again after a pause rather than
	// handing out untested ports, which then freeze
	if !qos && silent == len(results) && t.answered {
		logf("сервер %s замолчал после ответов: похоже, ограничивает частые проверки; пауза и снова", dst)
		time.Sleep(time.Second)
		return t
	}

	// no reply at all with the fake: maybe it is the fake that gets the flow killed (some ISPs drop
	// flows once their DPI sees QUIC). One port without it tells this apart from a silent server.
	if !qos && silent == len(results) && withFake && p.budgetTake(1) {
		c := freshPorts(t, 1, busy)
		if len(c) == 1 {
			t.tried[c[0]] = true
			got := p.probe(dst, c, false, nil)[c[0]]
			// only a port passing without the fake proves the fake is the problem; a freeze without
			// it says the fake is needed, and the silence with it was the server's pause
			if got >= probePass {
				p.fmu.Lock()
				p.fakeOffUntil = time.Now().Add(fakeHoldoff)
				p.fmu.Unlock()
				logf("фейк ломает соединения в этой сети (%s: с ним нет ответов, без него %d), выключаю на %d мин",
					dst, got, int(fakeHoldoff.Minutes()))
				p.stat.add(&p.stat.fakeOff, 1)
				t.good = append(t.good, c[0])
				return t
			}
		}
	}

	// the server ignores handshakes: fall back to its QoS echo. With the fake a QoS verdict says
	// nothing about the game flow, so retry the game port once, then go blind.
	if !qos && silent == len(results) {
		if !p.fakeOn() {
			t.mode = modeQoS
		} else if t.silentRounds++; t.silentRounds >= 2 {
			t.mode = modeBlind
		}
	} else {
		t.silentRounds = 0
	}

	// every port stopped at the same count: that is the server capping handshake replies for our
	// address, not the DPI (whose verdict differs per port). Stop handshake probes for a while.
	if !qos && len(fresh) == 0 && len(results) >= 6 && frozen == len(results) && len(counts) == 1 {
		p.gameOffUntil = time.Now().Add(limitHoldoff)
		t.mode = modeQoS
		if p.fakeOn() {
			t.mode = modeBlind
		}
		logf("сервер ограничивает ответы на рукопожатия, %d мин без таких проверок", int(limitHoldoff.Minutes()))
		return p.refresh(dst, want, busy)
	}
	return t
}

// pick finds a good source port for a new flow to dst, probing up to maxRounds rounds;
// 0 when none was found
func (p *prober) pick(dst netip.AddrPort, busy func(int) bool) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	for round := 0; round < p.cfg.maxRounds; round++ {
		used := 0
		t := p.target(dst)
		for _, g := range t.good {
			if busy(g) {
				used++
			}
		}
		t = p.refresh(dst, used+1+round, busy)
		for _, g := range t.good {
			if !busy(g) {
				return g
			}
		}
	}
	return 0
}

// drop: a port that froze is no good for dst any more
func (p *prober) drop(dst netip.AddrPort, port int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if t := p.targets[dst]; t != nil {
		var keep []int
		for _, g := range t.good {
			if g != port {
				keep = append(keep, g)
			}
		}
		t.good = keep
		t.tried[port] = true
	}
}

// preProbe: Fortnite pairs the match port with the control port by suffix (15062 -> 9062):
// probe it now so the match connection does not wait for its own probe
func (p *prober) preProbe(dst netip.AddrPort, busy func(int) bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if t := p.targets[dst]; t != nil && time.Since(t.ts) <= p.cfg.verdictTTL {
		return
	}
	p.refresh(dst, 1, busy)
}

func joinInts(v []int) string {
	var s []string
	for _, x := range v {
		s = append(s, fmt.Sprint(x))
	}
	return strings.Join(s, " ")
}
