package main

import (
	"bytes"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// Keep another assignment/probe running, as in a batch of regional connections
// from the real log. The queued flow must actually send UDP before that work
// releases its lock, while reporting its source port as untested.
func TestQueuedGameFlowSendsBeforeUnrelatedProbesFinish(t *testing.T) {
	for _, blocker := range []string{"assignment", "probe"} {
		t.Run(blocker, func(t *testing.T) {
			srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer srv.Close()
			cfg := testConfig()
			cfg.fakes = nil
			cfg.pairOffset = 0
			e := newEngine(cfg, newChanDev(), clientIP, nil)
			defer e.close()
			dst := srv.LocalAddr().(*net.UDPAddr).AddrPort()
			started := time.Now().Add(-maxProbeQueueWait + 100*time.Millisecond)
			payload := []byte("queued initial handshake")
			f := &uflow{key: flowKey{50000, dst, clientIP}, game: true, match: true, started: started, last: time.Now(), pending: [][]byte{payload}}
			e.flows[f.key] = f
			mu := &e.portMu
			if blocker == "probe" {
				mu = &e.prober.mu
			}
			mu.Lock()
			defer mu.Unlock()
			done := make(chan struct{})
			go func() { defer close(done); e.assign(f) }()
			srv.SetReadDeadline(time.Now().Add(time.Second))
			var buf [128]byte
			n, _, err := srv.ReadFromUDPAddrPort(buf[:])
			if err != nil {
				t.Fatalf("queued flow did not send while unrelated %s stayed blocked: %v", blocker, err)
			}
			if !bytes.Equal(buf[:n], payload) {
				t.Fatal("initial game datagram changed")
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("assignment did not finish")
			}
			info := f.info(true)
			if !info.NoGood || info.Port == 0 || e.stat.snapshot().Tested != 0 {
				t.Fatalf("untested fallback misreported: %+v", info)
			}
		})
	}
}

func TestGameProbeQueueStopsWithEngine(t *testing.T) {
	e := newEngine(testConfig(), newChanDev(), clientIP, nil)
	e.portMu.Lock()
	defer e.portMu.Unlock()
	dst := netip.MustParseAddrPort("127.0.0.1:15123")
	f := &uflow{key: flowKey{50000, dst, clientIP}, game: true, started: time.Now(), last: time.Now(), pending: [][]byte{[]byte("cancelled")}}
	e.flows[f.key] = f
	assigned := make(chan struct{})
	go func() { defer close(assigned); e.assign(f) }()
	e.close()
	select {
	case <-assigned:
	case <-time.After(time.Second):
		t.Fatal("stopping left an assignment waiting")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.conn != nil {
		t.Fatal("a queued assignment opened a socket after shutdown")
	}
}

func TestProbeBudgetReportsOnceWithoutSending(t *testing.T) {
	cfg := testConfig()
	p := newProber(cfg, &counters{})
	p.budgetWindow = time.Now()
	p.budgetUsed = cfg.budget
	before := len(logLines())
	for _, dst := range []string{"127.0.0.1:15001", "127.0.0.1:15002"} {
		if choice := p.pick(netip.MustParseAddrPort(dst), func(int) bool { return false }); choice.port != 0 {
			t.Fatal("budget exhausted but a port was reported as passing")
		}
	}
	lines := logLines()[before:]
	if got := strings.Count(strings.Join(lines, "\n"), "лимит проверок исчерпан"); got != 1 {
		t.Fatalf("budget message repeated %d times: %v", got, lines)
	}
	if p.stat.snapshot().Tested != 0 || p.budgetUsed != cfg.budget {
		t.Fatal("new probe sent after budget was exhausted")
	}
}

// A few replies at a neighboring TTL can be rate limiting or loss. They must
// not replace the current TTL merely because the current flow was silent.
func TestSparseTTLRepliesDoNotChangeRuntimeTTL(t *testing.T) {
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go func() {
		var b [2048]byte
		counts := map[int]int{}
		for {
			n, from, err := srv.ReadFromUDPAddrPort(b[:])
			if err != nil {
				return
			}
			if n > 1000 {
				continue
			}
			counts[int(from.Port())]++
			if counts[int(from.Port())] <= 6 {
				srv.WriteToUDPAddrPort(b[:n], from)
			}
		}
	}()
	cfg := testConfig()
	cfg.budget = 1
	p := newProber(cfg, &counters{})
	dst := srv.LocalAddr().(*net.UDPAddr).AddrPort()
	if _, ok := p.searchTTL(dst, p.target(dst), func(int) bool { return false }, true); ok {
		t.Fatal("limited replies accepted as a passing port")
	}
	if got := p.fakeTTL(); got != cfg.fakeTTL {
		t.Fatalf("TTL changed from %d to %d on only six replies", cfg.fakeTTL, got)
	}
	if p.stat.snapshot().Tested != 1 {
		t.Fatal("expected exactly one bounded local probe")
	}
}
