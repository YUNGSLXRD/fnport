package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/YUNGSLXRD/fnport/windows/internal/fakes"
)

// Settings live in fnport.json next to the program, the fakes in the "fakes" folder there.
// Anything missing from the file takes its default.

type settings struct {
	Adapter     string   `json:"adapter"`  // network adapter by name; "" = the one Windows uses toward AWS
	Fake        string   `json:"fake"`     // file in the fakes folder; "" = no fake
	FakeTTL     int      `json:"fake_ttl"` // hops from this PC: past the ISP's DPI, before the server
	Routes      []string `json:"routes"`   // networks sent through fnport
	GamePorts   []string `json:"game_ports"`
	PairFrom    string   `json:"pair_from"`   // control ports whose match port is probed ahead
	PairOffset  int      `json:"pair_offset"` // 15062 -> 9062
	QoSPort     int      `json:"qos_port"`
	ProbeBatch  int      `json:"probe_batch"`  // ports probed at once
	MaxRounds   int      `json:"max_rounds"`   // rounds per flow
	ProbeBudget int      `json:"probe_budget"` // probe sockets per minute, all servers together
	VerdictTTL  int      `json:"verdict_ttl"`  // seconds a good port is trusted
	Passthrough bool     `json:"passthrough"`  // no probes, no fake: fnport on the router does the work
	Theme       string   `json:"theme"`        // "system", "dark", "light"
}

func defaultSettings() settings {
	return settings{
		Fake:        fakes.Default(),
		FakeTTL:     5,
		Routes:      append([]string(nil), awsEU...),
		GamePorts:   []string{"9000-9999", "15000-15999"},
		PairFrom:    "15000-15999",
		PairOffset:  -6000,
		QoSPort:     22222,
		ProbeBatch:  2,
		MaxRounds:   8,
		ProbeBudget: 24,
		VerdictTTL:  90,
		Theme:       "system",
	}
}

func appDir() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Dir(exe)
	}
	return "."
}

func settingsPath() string { return filepath.Join(appDir(), "fnport.json") }
func fakesDir() string     { return filepath.Join(appDir(), "fakes") }

// loadSettings reads the file over the defaults; a broken file is reported and ignored
func loadSettings() settings {
	s := defaultSettings()
	b, err := os.ReadFile(settingsPath())
	if err != nil {
		return s
	}
	if err := json.Unmarshal(b, &s); err != nil {
		logf("fnport.json не прочитан (%v), настройки по умолчанию", err)
		return defaultSettings()
	}
	return s
}

func (s settings) save() error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := settingsPath() + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, settingsPath())
}

func parseRange(r string) ([2]uint16, error) {
	r = strings.TrimSpace(r)
	lo, hi, found := strings.Cut(r, "-")
	if !found {
		hi = lo
	}
	a, err1 := strconv.Atoi(strings.TrimSpace(lo))
	b, err2 := strconv.Atoi(strings.TrimSpace(hi))
	if err1 != nil || err2 != nil || a < 1 || b > 65535 || a > b {
		return [2]uint16{}, fmt.Errorf("диапазон портов «%s»", r)
	}
	return [2]uint16{uint16(a), uint16(b)}, nil
}

// config checks the settings and turns them into what the engine runs with
func (s settings) config() (*config, error) {
	cfg := &config{passthrough: s.Passthrough, pairOffset: s.PairOffset, verdictTTL: time.Duration(s.VerdictTTL) * time.Second}
	in := func(v, lo, hi int, what string) error {
		if v < lo || v > hi {
			return fmt.Errorf("%s: от %d до %d", what, lo, hi)
		}
		return nil
	}
	for _, e := range []error{
		in(s.FakeTTL, 1, 32, "TTL фейка"), in(s.QoSPort, 1, 65535, "порт эха"), in(s.ProbeBatch, 1, 12, "портов за раунд"),
		in(s.MaxRounds, 1, 16, "раундов"), in(s.ProbeBudget, 4, 120, "проверок в минуту"), in(s.VerdictTTL, 10, 900, "время доверия порту"),
		in(s.PairOffset, -65535, 65535, "сдвиг порта матча"),
	} {
		if e != nil {
			return nil, e
		}
	}
	cfg.fakeTTL, cfg.qosPort, cfg.batch, cfg.maxRounds, cfg.budget = s.FakeTTL, uint16(s.QoSPort), s.ProbeBatch, s.MaxRounds, s.ProbeBudget
	for _, r := range s.Routes {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		p, err := netip.ParsePrefix(r)
		if err != nil || !p.Addr().Is4() || p.Bits() < 4 {
			return nil, fmt.Errorf("сеть «%s» (нужно вида 3.0.0.0/8, не шире /4)", r)
		}
		cfg.routes = append(cfg.routes, p.Masked())
	}
	if len(cfg.routes) == 0 {
		return nil, fmt.Errorf("нет ни одной сети")
	}
	for _, r := range s.GamePorts {
		if strings.TrimSpace(r) == "" {
			continue
		}
		g, err := parseRange(r)
		if err != nil {
			return nil, err
		}
		cfg.gameRanges = append(cfg.gameRanges, g)
	}
	if strings.TrimSpace(s.PairFrom) != "" {
		g, err := parseRange(s.PairFrom)
		if err != nil {
			return nil, err
		}
		cfg.pairFrom = g
	} else {
		cfg.pairOffset = 0
	}
	// the chosen fake first, the other files of the folder as spares
	if s.Fake != "" {
		all := fakes.List(fakesDir())
		for _, f := range all {
			if f.Name == s.Fake {
				cfg.fakes = append(cfg.fakes, f)
			}
		}
		if len(cfg.fakes) == 0 {
			return nil, fmt.Errorf("фейк «%s» не найден в папке fakes", s.Fake)
		}
		for _, f := range all {
			if f.Name != s.Fake {
				cfg.fakes = append(cfg.fakes, f)
			}
		}
	}
	return cfg, nil
}
