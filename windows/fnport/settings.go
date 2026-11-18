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
	"github.com/YUNGSLXRD/fnport/windows/internal/vpn"
)

// Settings live in fnport.json next to the program, with an automatic backup in
// %LOCALAPPDATA%\fnport\settings-backup.json so keys and subscriptions survive
// updates extracted into a new folder.

type settings struct {
	Adapter     string               `json:"adapter"`
	Fake        string               `json:"fake"`
	FakeTTL     int                  `json:"fake_ttl"`
	Routes      []string             `json:"routes"`
	GamePorts   []string             `json:"game_ports"`
	PairFrom    string               `json:"pair_from"`
	PairOffset  int                  `json:"pair_offset"`
	QoSPort     int                  `json:"qos_port"`
	ProbeBatch  int                  `json:"probe_batch"`
	MaxRounds   int                  `json:"max_rounds"`
	ProbeBudget int                  `json:"probe_budget"`
	VerdictTTL  int                  `json:"verdict_ttl"`
	Passthrough bool                 `json:"passthrough"`
	Theme       string               `json:"theme"`
	Connection  connectionSettings   `json:"connection"`
	Trace       networkTraceSettings `json:"network_trace"`
	Warp        warpSettings         `json:"warp"`
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
		Warp:        warpSettings{Jc: 4, Jmin: 40, Jmax: 70},
		Connection:  connectionSettings{Protocol: "warp", Epic: true},
		Trace:       defaultNetworkTraceSettings(),
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

// settingsBackupPath points to %LOCALAPPDATA%\fnport\settings-backup.json; overridden in tests.
var settingsBackupPath = func() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "fnport", "settings-backup.json")
}

// loadSettings reads local fnport.json over defaults, falling back to %LOCALAPPDATA% backup
// when starting in a freshly extracted release folder without a local fnport.json.
func loadSettings() settings {
	return loadSettingsFrom(settingsPath(), settingsBackupPath())
}

func loadSettingsFrom(localFile, backupFile string) settings {
	s := defaultSettings()
	b, err := os.ReadFile(localFile)
	restoredFromBackup := false
	if err != nil {
		if !os.IsNotExist(err) || backupFile == "" {
			return s
		}
		b, err = os.ReadFile(backupFile)
		if err != nil {
			return s
		}
		restoredFromBackup = true
	}
	if err := json.Unmarshal(b, &s); err != nil {
		if restoredFromBackup {
			return defaultSettings()
		}
		logf("fnport.json не прочитан (%v), настройки по умолчанию", err)
		return defaultSettings()
	}
	s.Routes = upgradeDefaultGameRoutes(s.Routes)
	migrateLegacyWarp(&s)
	if restoredFromBackup {
		if writeErr := writeSettingsAtomic(localFile, s); writeErr == nil {
			logf("настройки восстановлены из сохранённой копии профиля")
		}
	}
	return s
}

// migrateLegacyWarp folds 0.6.x s.Warp flags into the unified s.Connection model.
func migrateLegacyWarp(s *settings) {
	if s.Warp.Jc == 0 && s.Warp.Jmin == 0 && s.Warp.Jmax == 0 {
		s.Warp.Jc, s.Warp.Jmin, s.Warp.Jmax = 4, 40, 70
	}
	if !s.Connection.Enabled && s.Warp.Enabled {
		s.Connection.Enabled = true
		s.Connection.Protocol = "warp"
		s.Connection.Epic = true
		s.Connection.EpicAlways = s.Warp.Always
		if len(s.Warp.Domains) > 0 && len(s.Connection.Domains) == 0 {
			var extra []string
			for _, d := range s.Warp.Domains {
				d = vpn.CleanDomain(d)
				if d != "" && !vpn.MatchEpic(d, nil) {
					extra = append(extra, d)
				}
			}
			s.Connection.Domains = extra
		}
	}
	s.Warp.Enabled = false
}

// upgradeDefaultGameRoutes adds 51.44.0.0/16 (AWS Paris) only when the exact 6-prefix legacy default is intact.
func upgradeDefaultGameRoutes(routes []string) []string {
	legacy := map[string]bool{
		"3.0.0.0/8": true, "13.32.0.0/11": true, "15.0.0.0/8": true,
		"18.0.0.0/8": true, "35.156.0.0/14": true, "35.176.0.0/13": true,
	}
	if len(routes) != len(legacy) {
		return routes
	}
	for _, route := range routes {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(route))
		if err != nil || !legacy[prefix.Masked().String()] {
			return routes
		}
		delete(legacy, prefix.Masked().String())
	}
	return append(append([]string(nil), routes...), "51.44.0.0/16")
}

func writeSettingsAtomic(filePath string, s settings) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(filePath), 0o700); err != nil {
		return err
	}
	tmp := filePath + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filePath)
}

func (s settings) save() error {
	if err := writeSettingsAtomic(settingsPath(), s); err != nil {
		return err
	}
	if backup := settingsBackupPath(); backup != "" {
		_ = writeSettingsAtomic(backup, s)
	}
	return nil
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

// config checks the settings and turns them into what the engine runs with.
func (s settings) config() (*config, error) {
	if s.Connection.Enabled && s.Connection.Protocol == "amneziawg" && s.Warp.Enabled {
		return nil, fmt.Errorf("для AmneziaWG отключите одновременный режим WARP")
	}
	if err := s.Connection.validate(); err != nil {
		return nil, err
	}
	cfg := &config{passthrough: s.Passthrough, pairOffset: s.PairOffset, verdictTTL: time.Duration(s.VerdictTTL) * time.Second}
	in := func(v, lo, hi int, what string) error {
		if v < lo || v > hi {
			return fmt.Errorf("%s: от %d до %d", what, lo, hi)
		}
		return nil
	}
	for _, e := range []error{
		in(s.FakeTTL, 1, 32, "TTL фейка"),
		in(s.QoSPort, 1, 65535, "порт эха"),
		in(s.ProbeBatch, 1, 12, "портов за раунд"),
		in(s.MaxRounds, 1, 16, "раундов"),
		in(s.ProbeBudget, 4, 120, "проверок в минуту"),
		in(s.VerdictTTL, 10, 900, "время доверия порту"),
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
