// fnport for Windows: fnport without an OpenWrt router, as a program on the gaming PC.
//
// Windows routes traffic to AWS in Europe into a Wintun adapter (like WireGuard or WARP do).
// UDP game flows leave through this program's own sockets on the physical interface, from a
// source port that passed a probe, with the fake QUIC Initial first; frozen flows move to a
// new port. TCP to the same addresses passes through unchanged. The game is not touched: no
// injection, no packet capture driver. When the program ends, Windows removes the adapter and
// its routes, and everything goes direct again.
package main

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/YUNGSLXRD/fnport/windows/internal/fakes"
	"github.com/YUNGSLXRD/fnport/windows/internal/wnet"
)

var version = "dev"

// AWS in Europe where Epic's game servers and beacons live (the same list as fnport-routes.cmd)
var awsEU = []string{"3.0.0.0/8", "13.32.0.0/11", "15.0.0.0/8", "18.0.0.0/8", "35.156.0.0/14", "35.176.0.0/13"}

var (
	logMu   sync.Mutex
	logFile *os.File
)

func logf(format string, a ...any) {
	s := time.Now().Format("15:04:05 ") + fmt.Sprintf(format, a...)
	logMu.Lock()
	defer logMu.Unlock()
	fmt.Println(s)
	if logFile != nil {
		fmt.Fprint(logFile, s+"\r\n")
	}
}

func errorf(format string, a ...any) error { return fmt.Errorf(format, a...) }

func usage() {
	fmt.Println("fnport.exe [-ttl N]")
	fmt.Println("  -ttl N   TTL фейка с этого ПК (по умолчанию 5; с ПК он на 1 больше, чем на роутере)")
}

func main() {
	wnet.ConsoleUTF8()
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
	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-ttl":
			if i+1 < len(os.Args) {
				if v, err := strconv.Atoi(os.Args[i+1]); err == nil && v >= 1 && v <= 16 {
					cfg.fakeTTL = v
					i++
					continue
				}
			}
			usage()
			return
		default:
			usage()
			return
		}
	}

	if !wnet.IsElevated() {
		fmt.Println("Для адаптера нужны права администратора. Сейчас Windows спросит разрешение.")
		if wnet.RelaunchElevated() {
			return
		}
		fmt.Println("Без прав администратора программа работать не может.")
		waitEnter()
		return
	}

	dir := "."
	if exe, err := os.Executable(); err == nil {
		dir = filepath.Dir(exe)
	}
	name := filepath.Join(dir, "fnport-"+time.Now().Format("20060102-150405")+".log")
	if f, err := os.Create(name); err == nil {
		logFile = f
		defer f.Close()
	}

	fmt.Println()
	fmt.Println("1 — полный режим: проверка портов и фейк на этом ПК")
	fmt.Println("    (fnport на роутере для этого ПК выключить: убрать ПК из «Устройств»)")
	fmt.Println("2 — только пропуск игры через адаптер, без проверок и фейка")
	fmt.Println("    (fnport на роутере работает как обычно; для проверки античита)")
	fmt.Print("Выбор [1]: ")
	choice, _ := stdin.ReadString('\n')
	cfg.passthrough = strings.TrimSpace(choice) == "2"

	logf("fnport для Windows %s, %s/%s, ядер %d", version, runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
	if cfg.passthrough {
		logf("режим: только пропуск через адаптер, без проверок и фейка")
	} else {
		fake := "выключен"
		if len(cfg.fakes) > 0 {
			fake = fmt.Sprintf("%s, TTL %d, запасных %d", cfg.fakes[0].Name, cfg.fakeTTL, len(cfg.fakes)-1)
		}
		logf("режим: полный; фейк: %s", fake)
	}

	// the physical way out, before the routes point into the adapter
	info, err := wnet.RouteInterface(netip.MustParseAddr("3.66.90.173"))
	if err != nil || info.Index == 0 {
		logf("не найден сетевой адаптер с выходом в интернет: %v", err)
		waitEnter()
		return
	}
	wnet.PhysIndex, wnet.PhysAddr = info.Index, info.Addr
	logf("интернет идёт через «%s» (%s)", info.Alias, info.Desc)
	if info.Tunnel {
		logf("ВНИМАНИЕ: похоже, это VPN. Игра пойдёт через него, а не напрямую: выключите VPN/WARP.")
	}

	dev, clientIP, err := wnet.OpenTun("fnport", cfg.routes)
	if err != nil {
		logf("%v", err)
		waitEnter()
		return
	}
	tcp, err := newTCPRelay(dev)
	if err != nil {
		dev.Close()
		logf("%v", err)
		waitEnter()
		return
	}
	e := newEngine(cfg, dev, clientIP, tcp)
	var once sync.Once
	stop := func() {
		once.Do(func() {
			logf("останавливаюсь: %s", e.summary())
			e.close()
			tcp.close()
		})
	}
	defer stop()

	sig := make(chan os.Signal, 1)
	// Ctrl+C, and closing the console window (Windows reports it as SIGTERM)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		stop()
		os.Exit(0)
	}()
	go func() {
		t := time.NewTicker(time.Minute)
		for range t.C {
			logf("%s", e.summary())
		}
	}()

	logf("работает: адаптер «fnport», маршруты на AWS в Европе (%d сетей).", len(cfg.routes))
	logf("Чтобы выключить, нажмите Enter или закройте окно. Журнал: %s", name)
	go e.run()
	stdin.ReadString('\n')
}

var stdin = bufio.NewReader(os.Stdin)

func waitEnter() {
	fmt.Println()
	fmt.Println("Нажмите Enter, чтобы закрыть окно.")
	stdin.ReadString('\n')
}
