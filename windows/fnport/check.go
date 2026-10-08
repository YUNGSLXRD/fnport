package main

import (
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/YUNGSLXRD/fnport/windows/internal/fakes"
	"github.com/YUNGSLXRD/fnport/windows/internal/geo"
	"github.com/YUNGSLXRD/fnport/windows/internal/qos"
	"github.com/YUNGSLXRD/fnport/windows/internal/wnet"
)

// The ISP check, as the router's fnport-check: does the home router keep the source port (STUN),
// does the ISP freeze game UDP after 25 packets (Epic's beacons in three cities), and if so,
// does the fake lift the freeze from this PC, with which TTL, which fake. About 15-40 probe
// sockets spaced out by 2 s: probing a lot gets the address punished.

const (
	checkGap      = 2 * time.Second
	checkCooldown = 3 * time.Minute
	checkMaxTTL   = 9 // from the PC: one hop more than from the router
)

type checkResult struct {
	PortKept  string // "yes", "no", "unknown"
	Freeze    string // "yes", "no", "no_reply", "unclear"
	Fake      string // "works", "kills", "fails", "harmless", ""
	TTL       int    // recommended
	FakeFile  string // recommended fake
	Summary   []string
	Recommend *settings // what "Apply" sets; nil = nothing to change
}

type checker struct {
	mu       sync.Mutex
	running  bool
	lines    []string
	result   *checkResult
	finished time.Time
}

func (k *checker) state() (bool, []string, *checkResult, time.Duration) {
	k.mu.Lock()
	defer k.mu.Unlock()
	wait := time.Duration(0)
	if !k.finished.IsZero() {
		wait = checkCooldown - time.Since(k.finished)
	}
	return k.running, append([]string(nil), k.lines...), k.result, wait
}

func (k *checker) say(format string, a ...any) {
	s := fmt.Sprintf(format, a...)
	k.mu.Lock()
	k.lines = append(k.lines, s)
	k.mu.Unlock()
	logf("проверка провайдера: %s", strings.TrimSpace(s))
}

// start runs a check in the background; false while one runs or right after one
func (k *checker) start(cur settings) bool {
	k.mu.Lock()
	if k.running || (!k.finished.IsZero() && time.Since(k.finished) < checkCooldown) {
		k.mu.Unlock()
		return false
	}
	k.running, k.lines, k.result = true, nil, nil
	k.mu.Unlock()
	changes.Add(1)
	go func() {
		r := k.run(cur)
		k.mu.Lock()
		k.running, k.result, k.finished = false, r, time.Now()
		k.mu.Unlock()
		changes.Add(1)
	}()
	return true
}

func fmtReplies(rs []int) string {
	var p []string
	for _, r := range rs {
		s := map[string]string{"pass": "проходит", "frozen": "заморозка", "limited": "мало ответов", "silent": "нет ответа"}[qos.Verdict(r)]
		p = append(p, fmt.Sprintf("%d/%d %s", r, qos.Pkts, s))
	}
	return strings.Join(p, ", ")
}

func (k *checker) probe(host netip.Addr, fake []byte, ttl int) []int {
	time.Sleep(checkGap)
	rs, err := qos.Probe(host, 2, fake, ttl)
	if err != nil {
		k.say("  ошибка сокета: %v", err)
	}
	changes.Add(1)
	return rs
}

func (k *checker) run(cur settings) *checkResult {
	r := &checkResult{PortKept: "unknown"}
	usePhysical(cur.Adapter)

	k.say("Сохраняет ли роутер исходящий порт…")
	r.PortKept = checkPortKept(k)

	bs := resolveBeacons()
	if len(bs) == 0 {
		r.Freeze = "no_reply"
		return finish(r, cur)
	}
	k.say("Заморозка у провайдера: по 2 пробы без фейка на маяк Epic")
	var host netip.Addr
	worst, limited := 0, false
	var answered []netip.Addr
	for _, b := range bs {
		rs := k.probe(b, nil, 0)
		k.say("  %s: %s", geo.CityRU(b), fmtReplies(rs))
		if qos.Count(rs, "silent") < len(rs) {
			answered = append(answered, b)
		}
		if qos.Count(rs, "limited") > 0 {
			limited = true
		}
		if f := qos.Count(rs, "frozen"); f > worst {
			worst, host = f, b
		}
	}
	all := fakes.List(fakesDir())
	fakeData := func(name string) []byte {
		for _, f := range all {
			if f.Name == name {
				return f.Data
			}
		}
		return nil
	}
	switch {
	case len(answered) == 0:
		r.Freeze = "no_reply"
		return finish(r, cur)
	case worst == 0 && limited:
		r.Freeze = "unclear"
		return finish(r, cur)
	case worst == 0:
		r.Freeze = "no"
		// nothing freezes: only make sure the fake at the current TTL does not kill flows
		if d := fakeData(cur.Fake); d != nil {
			k.say("Заморозки нет. Не ломает ли фейк соединения (TTL %d):", cur.FakeTTL)
			rs := k.probe(answered[0], d, cur.FakeTTL)
			k.say("  %s: %s", geo.CityRU(answered[0]), fmtReplies(rs))
			r.Fake = "harmless"
			if qos.Count(rs, "silent") == len(rs) {
				r.Fake = "kills"
			}
		}
		return finish(r, cur)
	}
	r.Freeze = "yes"

	// the fake in use first (or the default), then up to two spares on a shorter TTL range
	order := []string{cur.Fake}
	if cur.Fake == "" || fakeData(cur.Fake) == nil {
		order = []string{fakes.Default()}
	}
	for _, f := range all {
		if f.Name != order[0] && len(order) < 3 {
			order = append(order, f.Name)
		}
	}
	for i, name := range order {
		d := fakeData(name)
		if d == nil {
			continue
		}
		lo, hi := 2, checkMaxTTL
		if i > 0 {
			lo, hi = 3, 6
		}
		k.say("Фейк %s: подбор TTL %d–%d на маяке %s", fakes.Label(name), lo, hi, geo.CityRU(host))
		verdict, works, rec := k.scanTTL(host, d, lo, hi)
		r.Fake, r.FakeFile = verdict, name
		if verdict == "works" {
			r.TTL = rec
			k.say("  срабатывает с TTL %d, рекомендую %d", works, rec)
			break
		}
		if verdict == "kills" {
			break
		}
	}
	return finish(r, cur)
}

// scanTTL: TTLs from lo up, 2 sockets each; a TTL with a pass gets 2 more and is taken with
// at least 2 passes of 4; then one hop of margin unless the fake starts killing flows there
func (k *checker) scanTTL(host netip.Addr, fake []byte, lo, hi int) (verdict string, works, rec int) {
	silentRun := 0
	for t := lo; t <= hi; t++ {
		rs := k.probe(host, fake, t)
		k.say("  TTL %d: %s", t, fmtReplies(rs))
		if qos.Count(rs, "pass") >= 1 {
			more := k.probe(host, fake, t)
			k.say("  TTL %d ещё раз: %s", t, fmtReplies(more))
			if qos.Count(append(rs, more...), "pass") >= 2 {
				rec = t
				if t < hi {
					m := k.probe(host, fake, t+1)
					k.say("  TTL %d (запас): %s", t+1, fmtReplies(m))
					if qos.Count(m, "silent") < len(m) {
						rec = t + 1
					}
				}
				return "works", t, rec
			}
			continue
		}
		if qos.Count(rs, "silent") == len(rs) {
			silentRun++
		} else {
			silentRun = 0
		}
		if silentRun >= 2 {
			return "kills", 0, 0
		}
	}
	return "fails", 0, 0
}

// checkPortKept: two random ports ask STUN servers which port the outside sees. A server whose
// name resolves to a fakeip goes through the router's VPN and does not count.
func checkPortKept(k *checker) string {
	servers := []struct {
		label, name string
		port        uint16
	}{{"sipnet.ru", "stun.sipnet.ru", 3478}, {"Google", "stun.l.google.com", 19302}}
	kept, changed := 0, 0
	var ext netip.Addr
	for _, sv := range servers {
		ips := resolveName(sv.name)
		if len(ips) == 0 || geo.IsFakeIP(ips[0]) {
			continue
		}
		for i := 0; i < 2; i++ {
			c, err := wnet.ListenUDP(20000+rand.IntN(40000), true)
			if err != nil {
				continue
			}
			local := c.LocalAddr().(*net.UDPAddr).Port
			m, err := qos.STUNQuery(c, netip.AddrPortFrom(ips[0], sv.port))
			c.Close()
			if err != nil {
				break
			}
			// the first answer's address is the direct one; others may come through a VPN
			if !ext.IsValid() {
				ext = m.Addr()
			}
			if m.Addr() != ext {
				continue
			}
			if int(m.Port()) == local {
				kept++
			} else {
				changed++
			}
		}
	}
	switch {
	case kept > 0 && changed == 0:
		k.say("  да, порт сохраняется")
		return "yes"
	case changed > 0:
		k.say("  нет: роутер меняет порт (%d из %d)", changed, kept+changed)
		return "no"
	}
	k.say("  не удалось узнать: STUN-серверы не ответили")
	return "unknown"
}

// finish writes the summary and what "Apply" would set
func finish(r *checkResult, cur settings) *checkResult {
	add := func(s string) { r.Summary = append(r.Summary, s) }
	switch r.PortKept {
	case "yes":
		add("Роутер сохраняет порт: fnport на ПК может выбирать порт сам.")
	case "no":
		add("Роутер МЕНЯЕТ порт: выбор порта на ПК не сработает, нужен fnport на роутере.")
	}
	rec := cur
	switch r.Freeze {
	case "no_reply":
		add("Маяки Epic не ответили: проверить заморозку не удалось.")
		return r
	case "unclear":
		add("Ответов мало (эхо Epic ограничивает или связь теряет пакеты): попробуйте позже.")
		return r
	case "no":
		add("Заморозки сейчас нет.")
		if r.Fake == "kills" {
			add("Фейк здесь убивает соединения — лучше его выключить.")
			rec.Fake = ""
		}
	case "yes":
		add("Заморозка у провайдера есть.")
		switch r.Fake {
		case "works":
			add(fmt.Sprintf("Фейк %s её снимает: TTL %d.", fakes.Label(r.FakeFile), r.TTL))
			rec.Fake, rec.FakeTTL = r.FakeFile, r.TTL
		case "kills":
			add("Фейк убивает соединения у этого провайдера: остаётся только проверка портов, без фейка.")
			rec.Fake = ""
		default:
			add("Фейк заморозку не снял: fnport будет искать порты без него.")
		}
	}
	if rec.Fake != cur.Fake || rec.FakeTTL != cur.FakeTTL {
		r.Recommend = &rec
	}
	return r
}
