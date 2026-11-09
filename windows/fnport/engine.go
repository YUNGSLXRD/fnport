package main

import (
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/YUNGSLXRD/fnport/windows/internal/fakes"
	"github.com/YUNGSLXRD/fnport/windows/internal/wnet"
)

// The engine reads what Windows routes into the adapter. UDP leaves through this program's own
// sockets on the physical interface: game flows from a probed port with the fake first, the
// rest from any port. TCP goes to the TCP relay. Replies go back into the adapter as if they
// came straight from the server.

const (
	mtu               = 1420
	freezeOut         = 60 // a flow counts as frozen: >= this many packets out ...
	freezeIn          = 26 // ... while replies stay at or below this
	maxRemaps         = 4  // attempts to move one frozen flow to a fresh port
	idleAfter         = 3 * time.Minute
	maxProbeQueueWait = 5 * time.Second // waiting for other flows, not a partial-probe timeout
	maxPending        = 128             // packets held per flow while its port is being probed
)

type config struct {
	captureAll  bool // must match installed routes even if the optional trace fails
	passthrough bool // no probes, no fake: only through the adapter (fnport on the router does the rest)
	gameRanges  [][2]uint16
	pairFrom    [2]uint16
	pairOffset  int
	qosPort     uint16
	batch       int
	maxRounds   int
	budget      int
	verdictTTL  time.Duration
	fakes       []fakes.File
	fakeTTL     int
	routes      []netip.Prefix
}

func (c *config) gamePort(p uint16) bool {
	if c.passthrough {
		return false
	}
	for _, r := range c.gameRanges {
		if p >= r[0] && p <= r[1] {
			return true
		}
	}
	return false
}

type counters struct {
	mu                                       sync.Mutex
	flows, gameFlows, nogood, frozen, remaps int
	tested, good, fakeOff, fakeSwitch        int
}

func (c *counters) add(v *int, n int) {
	c.mu.Lock()
	*v += n
	c.mu.Unlock()
}

type flowKey struct {
	cport uint16
	dst   netip.AddrPort
	srcIP netip.Addr
}

type queuedUDP struct {
	payload []byte
	arrived time.Time
}

type uflow struct {
	key    flowKey
	game   bool
	match  bool // the match itself (9xxx), not the control connection
	noGood bool // no probed port was found: it went from an untested one

	mu             sync.Mutex
	retryAfter     time.Time
	traceAt        time.Time
	queueMaxNS     atomic.Int64
	writeMaxNS     atomic.Int64
	queueDrops     atomic.Uint64
	reported       bool
	send           chan queuedUDP
	failed         bool         // a selected transport failed: do not retry/log every game packet
	tunnel         net.Conn     // selected process datagrams through WARP or sing-box
	conn           *net.UDPConn // nil while the port is being chosen
	port           int
	pendingDropped int
	pending        [][]byte
	endLogged      bool
	remaps         int
	frozen         bool // reported, waiting for a remap
	last           time.Time
	started        time.Time

	writeFailures     atomic.Int64
	out, in           atomic.Int64 // since the current port
	totalOut, totalIn atomic.Int64
}

// flowInfo: a game flow for the summary
type flowInfo struct {
	Server        netip.AddrPort
	GamePort      uint16 // the game's own source port
	Port          int    // the port the server sees
	Out, In       int64
	Remaps        int
	Frozen        bool
	Match         bool
	NoGood        bool
	Started, Last time.Time
	Active        bool
}

func (f *uflow) info(active bool) flowInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	return flowInfo{Server: f.key.dst, GamePort: f.key.cport, Port: f.port, Out: f.totalOut.Load(), In: f.totalIn.Load(),
		Remaps: f.remaps, Frozen: f.frozen, Match: f.match, NoGood: f.noGood, Started: f.started, Last: f.last, Active: active}
}

type engine struct {
	connection *connectionRouter
	cfg        *config
	dev        wnet.Dev
	clientIP   netip.Addr
	prober     *prober
	tcp        *tcpRelay
	stat       *counters

	// Hold through game port selection, bind and socket installation, including
	// the fake pause. prober.mu alone ends before busy() can see the new port.
	// Never acquire while holding e.mu or a flow mutex.
	portMu sync.Mutex
	mu     sync.Mutex
	flows  map[flowKey]*uflow
	ipID   atomic.Uint32
	done   chan struct{}

	gone func(flowInfo) // a game flow ended (idle), for the summary
}

func newEngine(cfg *config, dev wnet.Dev, clientIP netip.Addr, tcp *tcpRelay) *engine {
	st := &counters{}
	return &engine{cfg: cfg, dev: dev, clientIP: clientIP, prober: newProber(cfg, st), tcp: tcp, stat: st,
		flows: map[flowKey]*uflow{}, done: make(chan struct{})}
}

// busy: source ports this program holds now (flows), so probes do not try to bind them
func (e *engine) busy(port int) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, f := range e.flows {
		f.mu.Lock()
		p := f.port
		f.mu.Unlock()
		if p == port {
			return true
		}
	}
	return false
}

func (e *engine) run() {
	go e.watch()
	buf := make([]byte, 65536)
	for {
		n, err := e.dev.ReadPacket(buf)
		if err != nil {
			return
		}
		pkt := buf[:n]
		switch wnet.IPv4Proto(pkt) {
		case 6:
			if e.tcp != nil {
				e.tcp.inject(pkt)
			}
		case 17:
			p, err := wnet.ParseUDP4(pkt)
			if err != nil || (p.Src.Addr() != e.clientIP && p.Src.Addr() != wnet.PhysAddr) || !e.routed(p.Dst.Addr()) {
				continue // broadcasts and multicast of network discovery
			}
			if p.Src.Addr() == wnet.PhysAddr && wnet.IsOwnUDP(p.Src) {
				continue
			}
			e.udp(p)
		}
	}
}

func (e *engine) routed(a netip.Addr) bool {
	if !a.IsValid() || a.IsMulticast() || a.IsUnspecified() || a == netip.MustParseAddr("255.255.255.255") {
		return false
	}
	if e.cfg.captureAll {
		return true
	}
	for _, r := range e.cfg.routes {
		if r.Contains(a) {
			return true
		}
	}
	return false
}

func (e *engine) udp(p wnet.UDPPacket) {
	key := flowKey{p.Src.Port(), p.Dst, p.Src.Addr()}
	e.mu.Lock()
	f := e.flows[key]
	isNew := f == nil
	if isNew {
		f = &uflow{key: key, game: e.cfg.gamePort(p.Dst.Port()) && inPrefixes(p.Dst.Addr(), e.cfg.routes), last: time.Now(), started: time.Now()}
		f.match = f.game && !(e.cfg.pairOffset != 0 && p.Dst.Port() >= e.cfg.pairFrom[0] && p.Dst.Port() <= e.cfg.pairFrom[1])
		e.flows[key] = f
	}
	e.mu.Unlock()
	if isNew {
		e.stat.add(&e.stat.flows, 1)
		if e.connection != nil {
			e.connection.observe(17, p.Src, p.Dst, "", "")
		}
	}

	f.mu.Lock()
	f.last = time.Now()
	if f.failed {
		if time.Now().Before(f.retryAfter) {
			f.mu.Unlock()
			return
		}
		f.failed = false
		f.pending = append(f.pending, append([]byte(nil), p.Payload...))
		f.mu.Unlock()
		go e.assignConnection(f)
		return
	}
	c, tunnel, send := f.conn, f.tunnel, f.send
	if c == nil && tunnel == nil {
		if len(f.pending) < maxPending {
			f.pending = append(f.pending, append([]byte(nil), p.Payload...))
		} else {
			f.pendingDropped++
		}
		f.mu.Unlock()
		if isNew {
			go e.assign(f)
		}
		return
	}
	f.mu.Unlock()
	if tunnel != nil {
		select {
		case send <- e.queued(p.Payload):
		default:
			if e.connection != nil && e.connection.trace != nil {
				f.queueDrops.Add(1)
			}
		}
	} else {
		e.sendDirect(f, c, p.Payload, false)
	}
}

// openPort binds port, or any free port when it is taken
func openPort(port int) (*net.UDPConn, int, error) {
	if port != 0 {
		if c, err := wnet.ListenUDP(port, true); err == nil {
			return c, port, nil
		}
	}
	var last error
	for i := 0; i < 20; i++ {
		p := portMin + mrand.IntN(portRange)
		c, err := wnet.ListenUDP(p, true)
		if err == nil {
			return c, p, nil
		}
		last = err
	}
	return nil, 0, last
}

// lockBefore bounds time spent queued behind another flow while preserving
// the lock through selection, binding, the fake and socket installation.
func lockBefore(mu *sync.Mutex, deadline time.Time, done <-chan struct{}) bool {
	for {
		select {
		case <-done:
			return false
		default:
		}
		if !time.Now().Before(deadline) {
			return false
		}
		if mu.TryLock() {
			return true
		}
		wait := time.NewTimer(min(10*time.Millisecond, time.Until(deadline)))
		select {
		case <-done:
			wait.Stop()
			return false
		case <-wait.C:
		}
	}
}

// assign picks the flow's source port (probing for game flows), sends what was held meanwhile
func (e *engine) assign(f *uflow) {
	dst := f.key.dst
	if e.connection != nil && e.connection.selectedUDP(netip.AddrPortFrom(f.key.srcIP, f.key.cport), dst, f.game) {
		e.assignConnection(f)
		return
	}
	var choice portChoice
	if f.game {
		deadline := f.started.Add(maxProbeQueueWait)
		if lockBefore(&e.portMu, deadline, e.done) {
			defer e.portMu.Unlock()
			if !devSkipControlProbes(e.cfg, dst) {
				choice = e.prober.pickBefore(dst, e.busy, deadline, e.done)
			} else {
				logf("дев-сравнение: контрольный порт %d без искусственных проб, фейк по текущим настройкам", dst.Port())
			}
		}
		select {
		case <-e.done:
			return
		default:
		}
		e.stat.add(&e.stat.gameFlows, 1)
	}
	c, port, err := openPort(choice.port)
	if err != nil {
		logf("соединение %s: нет сокета: %v", dst, err)
		e.mu.Lock()
		delete(e.flows, f.key)
		e.mu.Unlock()
		return
	}
	if f.game {
		if fake := e.prober.fakeNow(); fake != nil {
			// refresh the whitelist for this very flow: the probe may have been a while ago
			sendFake(c, fake, dst, e.prober.fakeTTL())
			time.Sleep(fakeGap)
		}
		if choice.port != port || choice.source == modeBlind {
			e.stat.add(&e.stat.nogood, 1)
			f.mu.Lock()
			f.noGood = true
			f.mu.Unlock()
		}
	}
	f.mu.Lock()
	f.conn, f.port = c, port
	held, dropped := f.pending, f.pendingDropped
	f.pending = nil
	// Keep the flow locked until its initial datagrams have left the socket.
	// Otherwise udp() can send a fresh packet ahead of held packets, especially
	// while the assignment log is waiting for a file/UI reader.
	for _, b := range held {
		e.sendDirect(f, c, b, true)
	}
	f.mu.Unlock()
	if f.game {
		logf("игра %s (у игры порт %d) -> локальный порт %d, %s; ожидание %d мс, в очереди %d, не поместилось %d",
			dst, f.key.cport, port, choice.description(port), time.Since(f.started).Milliseconds(), len(held), dropped)
	}
	go e.back(f, c)

	if f.game && e.cfg.pairOffset != 0 && dst.Port() >= e.cfg.pairFrom[0] && dst.Port() <= e.cfg.pairFrom[1] {
		mp := int(dst.Port()) + e.cfg.pairOffset
		if mp > 0 && mp < 65536 {
			mdst := netip.AddrPortFrom(dst.Addr(), uint16(mp))
			go e.prober.preProbe(mdst, e.busy)
		}
	}
}

// back carries the server's replies into the adapter
func (e *engine) back(f *uflow, c *net.UDPConn) {
	buf := make([]byte, 65536)
	client := netip.AddrPortFrom(f.key.srcIP, f.key.cport)
	for {
		n, from, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue // ICMP errors and the like
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		if from != f.key.dst {
			continue
		}
		f.in.Add(1)
		seq := f.totalIn.Add(1)
		f.mu.Lock()
		f.last = time.Now()
		f.mu.Unlock()
		writeErr := e.dev.WritePacket(wnet.BuildUDP4(from, client, buf[:n], uint16(e.ipID.Add(1))))
		e.traceGamePacket(f, "rx", seq, n, c.LocalAddr().(*net.UDPAddr).Port, false, writeErr == nil)
		if writeErr != nil {
			return
		}
	}
}

// watch: frozen game flows move to a fresh port, idle flows close
func (e *engine) watch() {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-e.done:
			return
		case <-tick.C:
		}
		e.mu.Lock()
		var all []*uflow
		for _, f := range e.flows {
			all = append(all, f)
		}
		e.mu.Unlock()
		for _, f := range all {
			f.mu.Lock()
			c, port, idle, frozen, remaps := f.conn, f.port, time.Since(f.last) > idleAfter, f.frozen, f.remaps
			tunnel := f.tunnel
			traceNow := tunnel != nil && e.connection != nil && e.connection.trace != nil && time.Since(f.traceAt) >= 10*time.Second
			if traceNow {
				f.traceAt = time.Now()
			}
			f.mu.Unlock()
			if traceNow {
				e.connection.trace.udpStats(netip.AddrPortFrom(f.key.srcIP, f.key.cport), f.key.dst, networkUDPStats{QueueMaxMS: float64(f.queueMaxNS.Swap(0)) / 1e6, WriteMaxMS: float64(f.writeMaxNS.Swap(0)) / 1e6, QueueDropped: f.queueDrops.Swap(0), Out: f.totalOut.Load(), In: f.totalIn.Load(), Queued: len(f.send)})
			}
			if c == nil && tunnel == nil {
				if idle {
					e.mu.Lock()
					delete(e.flows, f.key)
					e.mu.Unlock()
				}
				continue
			}
			if idle {
				f.mu.Lock()
				f.logGameEnd()
				f.mu.Unlock()
				if c != nil {
					c.Close()
				}
				if tunnel != nil {
					tunnel.Close()
				}
				e.mu.Lock()
				delete(e.flows, f.key)
				e.mu.Unlock()
				if f.game && tunnel == nil && e.gone != nil {
					e.gone(f.info(false))
				}
				continue
			}
			out, in := f.out.Load(), f.in.Load()
			if tunnel != nil || !f.game || out < freezeOut || in > freezeIn || frozen {
				continue
			}
			f.mu.Lock()
			f.frozen = true
			f.mu.Unlock()
			e.stat.add(&e.stat.frozen, 1)
			e.prober.drop(f.key.dst, port)
			logf("соединение %s с порта %d замёрзло (ушло %d, пришло %d)", f.key.dst, port, out, in)
			if remaps < maxRemaps {
				go e.remap(f)
			}
		}
	}
}

// remap moves a frozen flow to another port, the fake first. The game keeps its socket; only
// the port the server sees changes. A frozen flow is lost anyway.
func (e *engine) remap(f *uflow) {
	e.portMu.Lock()
	defer e.portMu.Unlock()
	dst := f.key.dst
	var choice portChoice
	e.prober.mu.Lock()
	if t := e.prober.targets[dst]; t != nil {
		for _, g := range t.good {
			if !e.busy(g.port) {
				choice = g
				break
			}
		}
	}
	e.prober.mu.Unlock()
	c, port, err := openPort(choice.port)
	if err != nil {
		logf("перевод %s: нет сокета: %v", dst, err)
		return
	}
	if fake := e.prober.fakeNow(); fake != nil {
		sendFake(c, fake, dst, e.prober.fakeTTL())
		time.Sleep(fakeGap)
	}
	f.mu.Lock()
	old := f.conn
	f.conn, f.port = c, port
	f.remaps++
	n := f.remaps
	f.frozen = false
	f.mu.Unlock()
	f.out.Store(0)
	f.in.Store(0)
	old.Close()
	go e.back(f, c)
	e.stat.add(&e.stat.remaps, 1)
	logf("соединение %s переведено на локальный порт %d (%s, попытка %d)", dst, port, choice.description(port), n)
}

// gameFlows: the game flows now
func (e *engine) gameFlows() []flowInfo {
	e.mu.Lock()
	var fs []*uflow
	for _, f := range e.flows {
		f.mu.Lock()
		game := f.game && f.tunnel == nil
		f.mu.Unlock()
		if game {
			fs = append(fs, f)
		}
	}
	e.mu.Unlock()
	out := make([]flowInfo, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.info(true))
	}
	return out
}

type statSnapshot struct {
	Flows, GameFlows, NoGood, Frozen, Remaps, Tested, Good, FakeOff, FakeSwitch int
}

func (c *counters) snapshot() statSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	return statSnapshot{c.flows, c.gameFlows, c.nogood, c.frozen, c.remaps, c.tested, c.good, c.fakeOff, c.fakeSwitch}
}

func (e *engine) close() {
	close(e.done)
	e.dev.Close()
	e.mu.Lock()
	for _, f := range e.flows {
		f.mu.Lock()
		f.logGameEnd()
		if f.conn != nil {
			f.conn.Close()
		}
		if f.tunnel != nil {
			f.tunnel.Close()
		}
		f.mu.Unlock()
	}
	e.mu.Unlock()
}

// Called with f.mu held when a game flow leaves the engine. Keep the final
// port separate from totals so a successful remap is visible in a dev log.
func (f *uflow) logGameEnd() {
	if devTrace != "on" || !f.game || f.endLogged {
		return
	}
	f.endLogged = true
	logf("закрыто игровое соединение %s (у игры порт %d): локальный порт %d, отправлено %d, получено %d; за все порты %d/%d, переводов %d",
		f.key.dst, f.key.cport, f.port, f.out.Load(), f.in.Load(), f.totalOut.Load(), f.totalIn.Load(), f.remaps)
}

func (e *engine) summary() string {
	s := e.stat
	s.mu.Lock()
	defer s.mu.Unlock()
	e.mu.Lock()
	active := len(e.flows)
	e.mu.Unlock()
	tcpActive, tcpTotal := int64(0), int64(0)
	if e.tcp != nil {
		tcpActive, tcpTotal = e.tcp.active.Load(), e.tcp.total.Load()
	}
	return fmt.Sprintf("UDP: сейчас %d, всего %d (игра %d, без годного порта %d, замёрзло %d, переводов %d); проверено портов %d, годных %d; TCP: сейчас %d, всего %d",
		active, s.flows, s.gameFlows, s.nogood, s.frozen, s.remaps, s.tested, s.good, tcpActive, tcpTotal)
}

func (e *engine) sendDirect(f *uflow, c *net.UDPConn, payload []byte, initial bool) {
	f.out.Add(1)
	seq := f.totalOut.Add(1)
	n, err := c.WriteToUDPAddrPort(payload, f.key.dst)
	ok := err == nil && n == len(payload)
	if !ok {
		f.writeFailures.Add(1)
	}
	e.traceGamePacket(f, "tx", seq, len(payload), c.LocalAddr().(*net.UDPAddr).Port, initial, ok)
}
