// fnport-probe: a check on the gaming PC before the Windows app is built.
//
//  1. Does the home router keep the source port the PC picks (STUN)?
//  2. Does the ISP freeze game UDP after 25 packets (Epic's QoS beacons), and does the fake
//     QUIC Initial with a whitelisted SNI, sent from the PC with a small TTL, lift the freeze?
//  3. Does the path through a Wintun adapter work: Windows routes a beacon into the adapter,
//     the program sends the datagrams on from its own socket and port and writes the replies
//     back; and how much it adds to the ping.
//
// About 20-40 probe sockets in all, spaced out: probing a lot gets the address punished.
package main

import (
	"bufio"
	"context"
	"embed"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

var version = "dev"

//go:embed fakes/*.bin
var fakesFS embed.FS

type fakeFile struct {
	name string
	data []byte
}

func loadFakes() []fakeFile {
	var out []fakeFile
	for _, n := range []string{"quic_initial_vk_com.bin", "quic_initial_gosuslugi_ru.bin", "quic_initial_ozon_ru.bin"} {
		if b, err := fakesFS.ReadFile("fakes/" + n); err == nil {
			out = append(out, fakeFile{n, b})
		}
	}
	return out
}

var (
	logMu   sync.Mutex
	logFile *os.File
)

func logf(format string, a ...any) {
	s := fmt.Sprintf(format, a...)
	logMu.Lock()
	defer logMu.Unlock()
	fmt.Println(s)
	if logFile != nil {
		fmt.Fprint(logFile, s+"\r\n")
	}
}

var cleanup struct {
	sync.Mutex
	fn func()
}

func setCleanup(fn func()) {
	cleanup.Lock()
	cleanup.fn = fn
	cleanup.Unlock()
}

func runCleanup() {
	cleanup.Lock()
	fn := cleanup.fn
	cleanup.fn = nil
	cleanup.Unlock()
	if fn != nil {
		fn()
	}
}

func waitEnter() {
	fmt.Println()
	fmt.Println("Нажмите Enter, чтобы закрыть окно.")
	bufio.NewReader(os.Stdin).ReadString('\n')
}

func main() {
	consoleUTF8()
	noTun := false
	if !isElevated() {
		fmt.Println("Для проверки адаптера Wintun нужны права администратора. Сейчас Windows спросит разрешение.")
		if relaunchElevated() {
			return
		}
		fmt.Println("Без прав администратора: проверка адаптера будет пропущена.")
		noTun = true
	}

	dir := "."
	if exe, err := os.Executable(); err == nil {
		dir = filepath.Dir(exe)
	}
	name := filepath.Join(dir, "fnport-probe-"+time.Now().Format("20060102-150405")+".txt")
	if f, err := os.Create(name); err == nil {
		logFile = f
		defer f.Close()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		runCleanup()
		logf("\nПрервано.")
		os.Exit(1)
	}()

	logf("fnport-probe %s, %s, %s/%s", version, time.Now().Format("2006-01-02 15:04"), runtime.GOOS, runtime.GOARCH)
	logf("Перед запуском выключите VPN и WARP на этом ПК. Проверка займёт 2-4 минуты.")
	logf("")
	run(noTun)
	runCleanup()
	if logFile != nil {
		logf("\nОтчёт сохранён: %s", name)
	}
	waitEnter()
}

type summary struct {
	port       string // kept, changed, unknown
	freeze     string // yes, no, unclear, no_reply
	fake       string // works, kills, fails, ok (no freeze, fake harmless), not_checked
	fakeName   string
	fakeTTL    int
	tun        string // ok, partly, failed, skipped
	tunDetail  string
	directRTT  time.Duration
	tunRTT     time.Duration
	vpnWarning string
}

func run(noTun bool) {
	var s summary
	fakes := loadFakes()

	// 1. beacons and the way out
	bs, source := beacons()
	var names []string
	for _, b := range bs {
		names = append(names, fmt.Sprintf("%s (%s)", b, cityRU[city(b)]))
	}
	logf("Маяки Epic (%s): %s", source, strings.Join(names, ", "))
	if info, err := routeInterface(bs[0]); err == nil && info.index != 0 {
		physIndex = info.index
		logf("Интернет идёт через адаптер «%s» (%s)", info.alias, info.desc)
		if info.tunnel {
			s.vpnWarning = info.alias
			logf("ВНИМАНИЕ: похоже, это VPN. Выключите VPN/WARP и запустите проверку снова.")
		}
	}

	// 2. does the router keep the port
	logf("")
	logf("1. Сохраняет ли роутер исходящий порт (STUN)")
	s.port = checkPort()

	// 3. freeze and fake, straight from this PC
	logf("")
	logf("2. Заморозка у провайдера: по 2 пробы на маяк, без фейка")
	var host netip.Addr
	worst := 0
	var answered []netip.Addr
	direct := map[netip.Addr]time.Duration{}
	for _, b := range bs {
		time.Sleep(roundGap)
		res, err := probeDirect(b, 2, nil, 0)
		if err != nil {
			logf("  %s: ошибка сокета: %v", cityRU[city(b)], err)
			continue
		}
		logf("  %s: %s", cityRU[city(b)], fmtResults(res))
		if count(res, "silent") < len(res) {
			answered = append(answered, b)
			direct[b] = medianRTT(res)
		}
		if f := count(res, "frozen"); f > worst {
			worst, host = f, b
		}
	}
	switch {
	case len(answered) == 0:
		s.freeze = "no_reply"
	case worst > 0:
		s.freeze = "yes"
	default:
		s.freeze = "no"
	}

	if s.freeze == "no" && len(fakes) > 0 {
		s.fake = "not_checked"
		time.Sleep(roundGap)
		logf("  Заморозки нет. Не ломает ли фейк соединения (TTL 4):")
		if res, err := probeDirect(answered[0], 2, fakes[0].data, 4); err == nil {
			logf("  %s, фейк TTL 4: %s", cityRU[city(answered[0])], fmtResults(res))
			if count(res, "silent") == len(res) {
				s.fake = "kills"
			} else {
				s.fake = "ok"
			}
		}
	}
	if s.freeze == "yes" && len(fakes) > 0 {
		logf("")
		logf("3. Фейк %s с ПК: подбор TTL на маяке %s", fakes[0].name, cityRU[city(host)])
		r, err := scanTTL(host, fakes[0].data, 2, 9)
		if err != nil {
			logf("  ошибка: %v", err)
		}
		s.fakeName = fakes[0].name
		for i := 1; err == nil && r.verdict == "fake_fails" && i < len(fakes); i++ {
			logf("  Запасной фейк %s, TTL 3-6:", fakes[i].name)
			r, err = scanTTL(host, fakes[i].data, 3, 6)
			s.fakeName = fakes[i].name
		}
		switch r.verdict {
		case "fake_works":
			s.fake, s.fakeTTL = "works", r.recommended
		case "fake_kills":
			s.fake = "kills"
		default:
			s.fake = "fails"
		}
	}

	// 4. the path through the adapter
	logf("")
	logf("4. Путь через адаптер Wintun")
	switch {
	case noTun:
		s.tun = "skipped"
		logf("  пропущено: нет прав администратора")
	case len(answered) == 0:
		s.tun = "skipped"
		logf("  пропущено: маяки не отвечают")
	default:
		if !host.IsValid() {
			host = answered[0]
		}
		s.directRTT = direct[host]
		time.Sleep(roundGap)
		checkTun(&s, host, fakes)
	}

	printSummary(s)
}

type stunServer struct {
	label, name string
	port        uint16
}

var stunServers = []stunServer{
	{"sipnet.ru", "stun.sipnet.ru", 3478},
	{"Google", "stun.l.google.com", 19302},
	{"Cloudflare", "stun.cloudflare.com", 3478},
}

// checkPort: two sockets on random ports ask STUN servers which port the outside sees.
// Servers behind the router's VPN (fakeip, or another external address) do not count.
func checkPort() string {
	type answer struct {
		label  string
		local  int
		mapped netip.AddrPort
	}
	var answers []answer
	cs, err := openDirectN(2)
	if err != nil {
		logf("  ошибка сокета: %v", err)
		return "unknown"
	}
	defer closeAll(cs)
	for _, sv := range stunServers {
		ips := resolveAll(sv.name)
		if len(ips) == 0 {
			logf("  %s: адрес не найден", sv.label)
			continue
		}
		if isFakeIP(ips[0]) {
			logf("  %s: идёт через VPN роутера (fakeip), не считается", sv.label)
			continue
		}
		for _, c := range cs {
			local := c.LocalAddr().(*net.UDPAddr).Port
			m, err := stunQuery(c, netip.AddrPortFrom(ips[0], sv.port))
			if err != nil {
				logf("  %s: нет ответа", sv.label)
				break
			}
			answers = append(answers, answer{sv.label, local, m})
		}
	}
	if len(answers) == 0 {
		logf("  ни один STUN-сервер не ответил: проверить не удалось")
		return "unknown"
	}
	// the external address of the first server that answered (sipnet.ru, inside Russia, is first:
	// no router VPN sends it abroad) is the direct one; others may have come through a VPN
	ext := answers[0].mapped.Addr()
	kept, changed := 0, 0
	for _, a := range answers {
		if a.mapped.Addr() != ext {
			logf("  %s: другой внешний адрес (похоже, через VPN), не считается", a.label)
			continue
		}
		if int(a.mapped.Port()) == a.local {
			kept++
			logf("  %s: порт %d снаружи тот же", a.label, a.local)
		} else {
			changed++
			logf("  %s: порт %d снаружи стал %d", a.label, a.local, a.mapped.Port())
		}
	}
	switch {
	case changed == 0 && kept > 0:
		return "kept"
	case kept == 0 && changed > 0:
		return "changed"
	}
	return "mixed"
}

func resolveAll(name string) []netip.Addr {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", name)
	if err != nil {
		return nil
	}
	for i := range ips {
		ips[i] = ips[i].Unmap()
	}
	return ips
}

// checkTun routes one beacon into a Wintun adapter and probes it from ordinary sockets of this
// PC, the way the game will send: the relay re-sends from its own ports, with the fake on one flow
func checkTun(s *summary, host netip.Addr, fakes []fakeFile) {
	dev, clientIP, err := openTun([]netip.Addr{host})
	if err != nil {
		s.tun, s.tunDetail = "failed", err.Error()
		logf("  %v", err)
		return
	}
	rl := newRelay(dev, clientIP, openDirect)
	setCleanup(rl.close)
	go rl.run()

	var cs []*net.UDPConn
	for i := 0; i < 2; i++ {
		c, err := listenUDP(0, false)
		if err != nil {
			s.tun, s.tunDetail = "failed", err.Error()
			logf("  ошибка сокета: %v", err)
			closeAll(cs)
			return
		}
		cs = append(cs, c)
	}
	defer closeAll(cs)
	labels := []string{"без фейка", "без фейка"}
	if s.fake == "works" {
		var fk []byte
		for _, f := range fakes {
			if f.name == s.fakeName {
				fk = f.data
			}
		}
		rl.setPlan(uint16(cs[0].LocalAddr().(*net.UDPAddr).Port), flowPlan{fk, s.fakeTTL})
		labels[0] = fmt.Sprintf("с фейком, TTL %d", s.fakeTTL)
	}
	res := probe(cs, host, nil, 0)

	okFlows := 0
	for i, r := range res {
		f := rl.flowFor(uint16(r.port))
		line := fmt.Sprintf("  поток %d (%s): %s", i+1, labels[i], fmtResults([]sockResult{r}))
		switch {
		case f == nil:
			line += "; Windows не отправил пакеты в адаптер"
		default:
			line += fmt.Sprintf("; ушло с порта %d: %d пакетов, от сервера %d", f.port, f.out.Load(), f.in.Load())
			if f.in.Load() > 0 && r.got == 0 {
				line += "; ответы не дошли до программы (брандмауэр?)"
			}
		}
		if r.rtt > 0 {
			line += fmt.Sprintf("; пинг %d мс", r.rtt.Milliseconds())
		}
		logf("%s", line)
		if r.got > 0 {
			okFlows++
		}
	}
	s.tunRTT = medianRTT(res)
	switch {
	case okFlows == len(res):
		s.tun = "ok"
	case okFlows > 0:
		s.tun = "partly"
	default:
		s.tun = "failed"
	}
	rl.close()
	setCleanup(nil)
}

func printSummary(s summary) {
	logf("")
	logf("ИТОГ")
	if s.vpnWarning != "" {
		logf("- Интернет шёл через «%s» (похоже на VPN): результаты могут быть неверны.", s.vpnWarning)
	}
	switch s.port {
	case "kept":
		logf("- Роутер сохраняет исходящий порт: программа на ПК сможет выбирать порт сама.")
	case "changed":
		logf("- Роутер МЕНЯЕТ исходящий порт: выбор порта на ПК не сработает, нужен fnport на роутере.")
	case "mixed":
		logf("- Роутер сохраняет порт не всегда: см. подробности выше.")
	default:
		logf("- Сохраняет ли роутер порт, узнать не удалось.")
	}
	switch s.freeze {
	case "yes":
		logf("- Заморозка у провайдера есть.")
	case "no":
		logf("- Заморозки сейчас нет (у некоторых провайдеров она зависит от времени и сервера).")
	default:
		logf("- Маяки Epic не ответили: проверить заморозку не удалось.")
	}
	switch s.fake {
	case "works":
		logf("- Фейк %s с ПК снимает заморозку: TTL %d (на роутере было бы на 1 меньше).", s.fakeName, s.fakeTTL)
	case "kills":
		logf("- Фейк убивает соединения у этого провайдера: его нужно выключать.")
	case "fails":
		logf("- Фейк с ПК заморозку не снял.")
	case "ok":
		logf("- Фейк соединения не ломает.")
	}
	switch s.tun {
	case "ok":
		logf("- Адаптер Wintun работает: пакеты игры можно пускать через программу.")
	case "partly":
		logf("- Адаптер Wintun работает, но не все потоки получили ответы (см. выше).")
	case "failed":
		logf("- Адаптер Wintun не сработал: %s", s.tunDetail)
	default:
		logf("- Адаптер Wintun не проверялся.")
	}
	if s.directRTT > 0 && s.tunRTT > 0 {
		logf("- Пинг до маяка: напрямую %d мс, через адаптер %d мс.", s.directRTT.Milliseconds(), s.tunRTT.Milliseconds())
	}
}
