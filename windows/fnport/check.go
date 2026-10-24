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

type cityReplies struct {
	City    string
	Replies []int
}

type ttlReplies struct {
	TTL     int
	Replies []int
}

type fakeScan struct {
	Fake  string
	Steps []ttlReplies
}

type checkResult struct {
	// raw results, for the report
	Control   []cityReplies
	Scans     []fakeScan
	FakeCheck *ttlReplies // no freeze: the fake at the current TTL
	FakeCity  string      // where the TTL was scanned
	WorksFrom int
	Settings  settings     // what the check ran with
	Epic      []epicResult // Epic's HTTPS services, straight from this PC

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
	// neither a pass nor a freeze: the beacon may be limiting replies to an address shared by
	// many people behind the provider's NAT, or just paused. Once more, three times slower; a
	// freeze still shows, and silence then is real (a fake that kills flows, not a busy beacon)
	if err == nil && qos.Count(rs, "pass")+qos.Count(rs, "frozen") == 0 {
		k.say("  (%s; повторяю медленнее)", fmtReplies(rs))
		time.Sleep(checkGap)
		if slow, err := qos.ProbeSlow(host, 2, fake, ttl); err == nil {
			rs = slow
		}
	}
	changes.Add(1)
	return rs
}

func (k *checker) run(cur settings) *checkResult {
	r := &checkResult{PortKept: "unknown", Settings: cur}
	usePhysical(cur.Adapter)

	k.say("Сохраняет ли роутер исходящий порт…")
	r.PortKept = checkPortKept(k)
	r.Epic = checkEpic(k)

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
		r.Control = append(r.Control, cityReplies{geo.CityRU(b), rs})
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
		// nothing freezes on the beacons: only make sure the fake at the current TTL does not kill
		// flows. With the fake off, the default one: game servers may freeze all the same, and
		// a fake that does no harm is better on
		name := cur.Fake
		if fakeData(name) == nil {
			name = fakes.Default()
		}
		if d := fakeData(name); d != nil {
			r.FakeFile = name
			k.say("Заморозки нет. Не ломает ли фейк %s соединения (TTL %d):", fakes.Label(name), cur.FakeTTL)
			rs := k.probe(answered[0], d, cur.FakeTTL)
			k.say("  %s: %s", geo.CityRU(answered[0]), fmtReplies(rs))
			r.FakeCheck = &ttlReplies{cur.FakeTTL, rs}
			r.Fake = "harmless"
			if qos.Count(rs, "silent") == len(rs) {
				r.Fake = "kills"
				// the fake reaches the DPI and kills the flow there: lower, it may still pass the
				// point that lifts the freeze of game servers (seen at Dom.ru: TTL 4 by day, then
				// 4 killing at night while 3 had worked)
				r.FakeCity = geo.CityRU(answered[0])
				scan := fakeScan{Fake: name}
				for t := cur.FakeTTL - 1; t >= 1; t-- {
					k.say("  ниже, TTL %d:", t)
					rs := k.probe(answered[0], d, t)
					k.say("  %s: %s", geo.CityRU(answered[0]), fmtReplies(rs))
					scan.Steps = append(scan.Steps, ttlReplies{t, rs})
					if qos.Count(rs, "silent") < len(rs) {
						r.Fake, r.TTL = "lower", t
						break
					}
				}
				r.Scans = append(r.Scans, scan)
			}
		}
		return finish(r, cur)
	}
	r.Freeze = "yes"
	r.FakeCity = geo.CityRU(host)

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
	// every fake gets its turn: a name the DPI kills a flow for may be one it lets another pass with
	first := ""
	for i, name := range order {
		d := fakeData(name)
		if d == nil {
			continue
		}
		lo, hi := 2, checkMaxTTL
		if i > 0 {
			hi = 6
		}
		k.say("Фейк %s: подбор TTL %d–%d на маяке %s", fakes.Label(name), lo, hi, geo.CityRU(host))
		scan := fakeScan{Fake: name}
		verdict, works, rec := k.scanTTL(host, d, lo, hi, &scan)
		r.Scans = append(r.Scans, scan)
		if verdict == "works" {
			r.Fake, r.FakeFile, r.WorksFrom, r.TTL = verdict, name, works, rec
			k.say("  срабатывает с TTL %d, рекомендую %d", works, rec)
			break
		}
		k.say("  %s", map[string]string{"kills": "убивает соединения", "fails": "не помогает"}[verdict])
		// none works: what the fake in use does decides (one that kills flows is to be switched off)
		if first == "" {
			first = verdict
			r.Fake, r.FakeFile = verdict, name
		}
	}
	return finish(r, cur)
}

// scanTTL: TTLs from lo up, 2 sockets each; a TTL with a pass gets 2 more and is taken with
// at least 2 passes of 4; then one hop of margin unless the fake starts killing flows there
func (k *checker) scanTTL(host netip.Addr, fake []byte, lo, hi int, scan *fakeScan) (verdict string, works, rec int) {
	silentRun := 0
	for t := lo; t <= hi; t++ {
		rs := k.probe(host, fake, t)
		k.say("  TTL %d: %s", t, fmtReplies(rs))
		scan.Steps = append(scan.Steps, ttlReplies{t, rs})
		if qos.Count(rs, "pass") >= 1 {
			more := k.probe(host, fake, t)
			k.say("  TTL %d ещё раз: %s", t, fmtReplies(more))
			scan.Steps[len(scan.Steps)-1].Replies = append(append([]int(nil), rs...), more...)
			if qos.Count(append(rs, more...), "pass") >= 2 {
				rec = t
				if t < hi {
					m := k.probe(host, fake, t+1)
					k.say("  TTL %d (запас): %s", t+1, fmtReplies(m))
					scan.Steps = append(scan.Steps, ttlReplies{t + 1, m})
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
	}{{"sipnet.ru", "stun.sipnet.ru", 3478}, {"Google", "stun.l.google.com", 19302},
		{"Google 2", "stun1.l.google.com", 19302}, {"Cloudflare", "stun.cloudflare.com", 3478}}
	kept, changed := 0, 0
	var ext netip.Addr
	for _, sv := range servers {
		if kept+changed >= 4 {
			break // enough answers; the rest of the list is for when some do not reply
		}
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

// finish writes the summary and what "Apply" would set. A changed port alone decides nothing:
// the fake goes out of the same socket as the game, so it still lifts the freeze if the check saw
// it do so from this PC, through every router and the ISP's NAT on the way
func finish(r *checkResult, cur settings) *checkResult {
	add := func(s string) { r.Summary = append(r.Summary, s) }
	rec := cur
	defer func() {
		if blocked := epicBlocked(r.Epic); len(blocked) > 0 {
			add(fmt.Sprintf("Сервисы Epic напрямую не открываются (%s): если не получается войти или скачать "+
				"обновление, причина может быть в этом.", strings.Join(blocked, ", ")))
		} else if len(r.Epic) > 0 {
			add("Сервисы Epic напрямую открываются.")
		}
		if rec.Fake != cur.Fake || rec.FakeTTL != cur.FakeTTL {
			r.Recommend = &rec
		}
	}()
	port := func() {
		switch {
		case r.PortKept == "yes":
			add("Роутер сохраняет порт: fnport на ПК подбирает порты сам.")
		case r.PortKept != "no":
		case r.Freeze == "no":
			add("Роутер или провайдер меняет порт, но заморозки на маяках нет — пока это не мешает.")
		case r.Freeze == "yes" && r.Fake == "works":
			add("Роутер или провайдер меняет порт, но фейк с ПК снимает заморозку: fnport на ПК работает, " +
				"только без подбора портов.")
		case r.Freeze == "yes":
			add("Роутер или провайдер меняет порт, а фейк не помогает: с ПК fnport мало что сделает. Если порт меняет " +
				"ваш роутер — fnport на роутере с OpenWrt; если провайдер («серый» IP) — белый IP, но это обычно платная услуга.")
		default:
			add("Роутер или провайдер меняет порт: поможет ли fnport на ПК, покажет проверка заморозки.")
		}
	}
	switch r.Freeze {
	case "no_reply":
		add("Маяки Epic не ответили: проверить заморозку не удалось.")
	case "unclear":
		add("Ответов мало (эхо Epic ограничивает или связь теряет пакеты): попробуйте позже.")
	case "no":
		// seen in a club: beacons 30/30, a game server in the same city froze two ports of four
		add("На маяках Epic заморозки сейчас нет. На игровых серверах она бывает и тогда: если матчи не находятся " +
			"или вылетают, оставьте fnport включённым — без заморозки он не мешает.")
		switch {
		case r.Fake == "lower":
			add(fmt.Sprintf("Фейк %s с TTL %d убивает соединения, с TTL %d — нет: «Применить» поставит TTL %d.",
				fakes.Label(r.FakeFile), cur.FakeTTL, r.TTL, r.TTL))
			rec.Fake, rec.FakeTTL = r.FakeFile, r.TTL
		case r.Fake == "kills" && cur.Fake != "":
			add("Фейк здесь убивает соединения при любом TTL — лучше его выключить.")
			rec.Fake = ""
		case r.Fake == "harmless" && cur.Fake == "":
			add(fmt.Sprintf("Фейк выключен, а соединения он не ломает: «Применить» включит %s.", fakes.Label(r.FakeFile)))
			rec.Fake = r.FakeFile
		}
	case "yes":
		add("Заморозка у провайдера есть.")
		switch r.Fake {
		case "works":
			add(fmt.Sprintf("Фейк %s её снимает: TTL %d.", fakes.Label(r.FakeFile), r.TTL))
			rec.Fake, rec.FakeTTL = r.FakeFile, r.TTL
		case "kills":
			add("Фейки убивают соединения у этого провайдера: остаётся только проверка портов, без фейка.")
			rec.Fake = ""
		default:
			add("Фейки заморозку не сняли: fnport будет искать порты без них.")
		}
	}
	port()
	return r
}
