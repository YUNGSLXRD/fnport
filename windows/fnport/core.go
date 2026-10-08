package main

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/YUNGSLXRD/fnport/windows/internal/fakes"
	"github.com/YUNGSLXRD/fnport/windows/internal/wnet"
)

// The program around the engine: turning it on and off, the log, the summary of game flows,
// and a version number the window watches to know when to redraw.

var version = "dev"

// AWS in Europe where Epic's game servers and beacons live (the same list as fnport-routes.cmd)
var awsEU = []string{"3.0.0.0/8", "13.32.0.0/11", "15.0.0.0/8", "18.0.0.0/8", "35.156.0.0/14", "35.176.0.0/13"}

func defaultConfig() *config {
	cfg := &config{
		gameRanges: [][2]uint16{{9000, 9999}, {15000, 15999}},
		pairFrom:   [2]uint16{15000, 15999},
		pairOffset: -6000,
		qosPort:    22222,
		batch:      2,
		maxRounds:  8,
		budget:     24,
		verdictTTL: 90 * time.Second,
		fakes:      fakes.Load(),
		fakeTTL:    5,
	}
	for _, r := range awsEU {
		cfg.routes = append(cfg.routes, netip.MustParsePrefix(r))
	}
	return cfg
}

func errorf(format string, a ...any) error { return fmt.Errorf(format, a...) }

// ---- log: a file next to the program and the last lines in memory for the window

const logKeep = 1000

var logs struct {
	sync.Mutex
	lines []string
	file  *os.File
	path  string
}

// changes counts what the window shows; it redraws when the number moves
var changes atomic.Uint64

func logf(format string, a ...any) {
	s := time.Now().Format("15:04:05 ") + fmt.Sprintf(format, a...)
	logs.Lock()
	logs.lines = append(logs.lines, s)
	if len(logs.lines) > logKeep {
		logs.lines = append([]string(nil), logs.lines[len(logs.lines)-logKeep/2:]...)
	}
	if logs.file != nil {
		fmt.Fprint(logs.file, s+"\r\n")
	}
	logs.Unlock()
	changes.Add(1)
}

func logLines() []string {
	logs.Lock()
	defer logs.Unlock()
	return append([]string(nil), logs.lines...)
}

// openLog: fnport.log next to the program; the previous one becomes fnport.old.log at 2 MB
func openLog() {
	dir := "."
	if exe, err := os.Executable(); err == nil {
		dir = filepath.Dir(exe)
	}
	p := filepath.Join(dir, "fnport.log")
	if st, err := os.Stat(p); err == nil && st.Size() > 2<<20 {
		os.Rename(p, filepath.Join(dir, "fnport.old.log"))
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	logs.Lock()
	logs.file, logs.path = f, p
	logs.Unlock()
}

// ---- on and off

type state int

const (
	stateOff state = iota
	stateStarting
	stateOn
)

type controller struct {
	cfg *config

	mu      sync.Mutex
	st      state
	err     string
	iface   wnet.IfaceInfo
	dev     wnet.Dev
	tcp     *tcpRelay
	eng     *engine
	stats   statSnapshot // of the engines that ran before, added up
	history []flowInfo   // game flows that ended, newest last
	since   time.Time
	ticker  chan struct{}
}

const historyKeep = 60

func newController(cfg *config) *controller { return &controller{cfg: cfg} }

func (c *controller) state() (state, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.st, c.err
}

// start brings the adapter up and the engine in; a no-op when on
func (c *controller) start() {
	c.mu.Lock()
	if c.st != stateOff {
		c.mu.Unlock()
		return
	}
	c.st, c.err = stateStarting, ""
	c.mu.Unlock()
	changes.Add(1)

	fail := func(err error) {
		logf("не включилось: %v", err)
		c.mu.Lock()
		c.st, c.err = stateOff, err.Error()
		c.mu.Unlock()
		changes.Add(1)
	}
	// the physical way out, before the routes point into the adapter
	info, err := wnet.RouteInterface(netip.MustParseAddr("3.66.90.173"))
	if err != nil || info.Index == 0 {
		fail(errorf("не найден сетевой адаптер с выходом в интернет"))
		return
	}
	wnet.PhysIndex, wnet.PhysAddr = info.Index, info.Addr
	logf("интернет идёт через «%s» (%s)", info.Alias, info.Desc)
	if info.Tunnel {
		logf("ВНИМАНИЕ: похоже, это VPN. Игра пойдёт через него, а не напрямую: выключите VPN/WARP.")
	}
	dev, clientIP, err := wnet.OpenTun("fnport", c.cfg.routes)
	if err != nil {
		fail(err)
		return
	}
	tcp, err := newTCPRelay(dev)
	if err != nil {
		dev.Close()
		fail(err)
		return
	}
	e := newEngine(c.cfg, dev, clientIP, tcp)
	e.gone = c.addHistory
	go e.run()

	stop := make(chan struct{})
	c.mu.Lock()
	c.st, c.iface, c.dev, c.tcp, c.eng, c.since, c.ticker = stateOn, info, dev, tcp, e, time.Now(), stop
	c.mu.Unlock()
	if c.cfg.passthrough {
		logf("включено: только пропуск через адаптер, без проверок и фейка")
	} else {
		fake := "выключен"
		if len(c.cfg.fakes) > 0 {
			fake = fmt.Sprintf("%s, TTL %d", c.cfg.fakes[0].Name, c.cfg.fakeTTL)
		}
		logf("включено: адаптер «fnport», маршруты на AWS в Европе; фейк %s", fake)
	}
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				logf("%s", e.summary())
			}
		}
	}()
	changes.Add(1)
}

// stop takes the adapter and its routes down: everything goes direct again
func (c *controller) stop() {
	c.mu.Lock()
	if c.st != stateOn {
		c.mu.Unlock()
		return
	}
	e, tcp, ticker := c.eng, c.tcp, c.ticker
	c.mu.Unlock()

	flows := e.gameFlows()
	logf("выключено: %s", e.summary())
	e.close()
	tcp.close()
	close(ticker)

	c.mu.Lock()
	s := e.stat.snapshot()
	c.stats = addStats(c.stats, s)
	for _, f := range flows {
		f.Active = false
		c.history = append(c.history, f)
	}
	c.trimHistory()
	c.st, c.eng, c.tcp, c.dev = stateOff, nil, nil, nil
	c.mu.Unlock()
	changes.Add(1)
}

func (c *controller) toggle() {
	if st, _ := c.state(); st == stateOn {
		c.stop()
	} else if st == stateOff {
		c.start()
	}
}

func (c *controller) addHistory(f flowInfo) {
	c.mu.Lock()
	c.history = append(c.history, f)
	c.trimHistory()
	c.mu.Unlock()
	changes.Add(1)
}

func (c *controller) trimHistory() {
	if len(c.history) > historyKeep {
		c.history = append([]flowInfo(nil), c.history[len(c.history)-historyKeep:]...)
	}
}

// flows: game flows now and before, newest first
func (c *controller) flows() []flowInfo {
	c.mu.Lock()
	e := c.eng
	out := append([]flowInfo(nil), c.history...)
	c.mu.Unlock()
	if e != nil {
		out = append(out, e.gameFlows()...)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Started.After(out[j].Started) })
	return out
}

// totals: counters of this session (all the times it was on)
func (c *controller) totals() statSnapshot {
	c.mu.Lock()
	s, e := c.stats, c.eng
	c.mu.Unlock()
	if e != nil {
		s = addStats(s, e.stat.snapshot())
	}
	return s
}

// warn: something to show in yellow (a flow froze or found no port in the last 10 minutes)
func (c *controller) warn() bool {
	for _, f := range c.flows() {
		if time.Since(f.Last) < 10*time.Minute && (f.Frozen || f.Remaps > 0) {
			return true
		}
	}
	return false
}

func addStats(a, b statSnapshot) statSnapshot {
	return statSnapshot{a.Flows + b.Flows, a.GameFlows + b.GameFlows, a.NoGood + b.NoGood, a.Frozen + b.Frozen,
		a.Remaps + b.Remaps, a.Tested + b.Tested, a.Good + b.Good, a.FakeOff + b.FakeOff, a.FakeSwitch + b.FakeSwitch}
}

// fakeLabel: "vk.com, TTL 5" for the window
func (c *controller) fakeLabel() string {
	if c.cfg.passthrough {
		return "без проверок и фейка (работает fnport на роутере)"
	}
	if len(c.cfg.fakes) == 0 {
		return "фейк выключен"
	}
	n := strings.TrimSuffix(strings.TrimPrefix(c.cfg.fakes[0].Name, "quic_initial_"), ".bin")
	n = strings.ReplaceAll(n, "_", ".")
	return fmt.Sprintf("фейк %s, TTL %d", n, c.cfg.fakeTTL)
}
