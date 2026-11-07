//go:build preview

package main

// Renders the window's tabs with made-up data into PNG files, to look at the design without
// Windows: go test -tags preview -run TestPreview ./fnport/ (needs cgo, EGL and a display or
// Mesa's surfaceless platform). FNPORT_PREVIEW_DIR sets where the files go.

import (
	"image"
	"image/png"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gioui.org/gpu/headless"

	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/unit"
	"gioui.org/widget"
	"github.com/YUNGSLXRD/fnport/windows/internal/fakes"
)

func TestPreview(t *testing.T) {
	dir := os.Getenv("FNPORT_PREVIEW_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	fakes.Ensure(fakesDir())
	ctl := newController(defaultSettings())
	ctl.st = stateOn
	ctl.stats = statSnapshot{GameFlows: 12, Tested: 30, Good: 12, Frozen: 1, Remaps: 1}
	now := time.Now()
	game := uint16(60320)
	add := func(srv string, port int, out, in int64, ago time.Duration, active, frozen bool, remaps int) {
		game++
		ctl.history = append(ctl.history, flowInfo{Server: netip.MustParseAddrPort(srv), GamePort: game, Port: port, Out: out, In: in,
			Started: now.Add(-ago), Last: now, Active: active, Frozen: frozen, Remaps: remaps,
			Match: netip.MustParseAddrPort(srv).Port() < 10000})
	}
	add("18.157.38.117:15036", 42844, 1204, 1187, 14*time.Minute, false, false, 0)
	add("18.157.38.117:9036", 25403, 41522, 88310, 13*time.Minute, false, false, 0)
	add("18.156.212.171:15106", 36036, 980, 975, 9*time.Minute, false, false, 0)
	add("18.156.212.171:9106", 43648, 35210, 71988, 8*time.Minute, false, false, 1)
	add("13.41.10.112:15082", 23702, 312, 310, 3*time.Minute, true, false, 0)
	add("13.41.10.112:9082", 44270, 6120, 12804, 2*time.Minute, true, false, 0)
	add("35.181.9.118:15094", 51220, 64, 25, time.Minute, true, true, 4)
	ping := &pinger{list: []beacon{
		{City: "Франкфурт", Addr: netip.MustParseAddr("3.66.90.173"), RTT: 61 * time.Millisecond, Checked: true},
		{City: "Лондон", Addr: netip.MustParseAddr("18.133.162.202"), RTT: 112 * time.Millisecond, Checked: true},
		{City: "Париж", Addr: netip.MustParseAddr("13.37.148.3"), Checked: true},
	}}
	for _, l := range []string{
		"fnport для Windows dev запущен",
		"интернет идёт через «Ethernet» (Realtek Gaming 2.5GbE Family Controller)",
		"включено: адаптер «fnport», маршруты на AWS в Европе; фейк quic_initial_vk_com.bin, TTL 5",
		"проверка 18.157.38.117:15036 через игровой порт: годных 1, замёрзло 1, без ответа 0 (1330 мс)",
		"игра 18.157.38.117:15036 (у игры порт 60325) -> порт 42844, порт проверен за 3993 мс",
		"соединение 18.156.212.171:9106 с порта 51101 замёрзло (ушло 64, пришло 25)",
		"соединение 18.156.212.171:9106 переведено на порт 43648 (попытка 1)",
	} {
		logf("%s", l)
	}

	chk := &checker{lines: []string{
		"Сохраняет ли роутер исходящий порт…", "  да, порт сохраняется",
		"Заморозка у провайдера: по 2 пробы без фейка на маяк Epic",
		"  Франкфурт: 25/30 заморозка, 25/30 заморозка", "  Лондон: 25/30 заморозка, 24/30 заморозка",
		"  Париж: 25/30 заморозка, 25/30 заморозка", "Фейк vk.com: подбор TTL 2–9 на маяке Франкфурт",
		"  TTL 2: 25/30 заморозка, 25/30 заморозка", "  TTL 3: 30/30 проходит, 25/30 заморозка",
		"  TTL 3 ещё раз: 25/30 заморозка, 30/30 проходит", "  TTL 4 (запас): 30/30 проходит, 25/30 заморозка",
		"  срабатывает с TTL 3, рекомендую 4"}}
	rec := defaultSettings()
	rec.FakeTTL = 4
	chk.result = finish(&checkResult{PortKept: "yes", Freeze: "yes", Fake: "works", TTL: 4, FakeFile: fakes.Default()}, defaultSettings())
	chk.result.Recommend = &rec
	chk.finished = time.Now()

	const scale = 1.25
	w, h := int(880*scale), int(660*scale)
	win, err := headless.NewWindow(w, h)
	if err != nil {
		t.Skipf("no headless GPU: %v", err)
	}
	defer win.Release()
	v := newView(ctl, ping, chk, nil, func() {})
	for _, tc := range []struct {
		name  string
		tab   tab
		st    state
		theme string
	}{{"main-on", tabMain, stateOn, "dark"}, {"main-off", tabMain, stateOff, "dark"}, {"summary", tabSummary, stateOn, "dark"},
		{"log", tabLog, stateOn, "dark"}, {"warp", tabWarp, stateOff, "dark"}, {"connections-vless", tabWarp, stateOff, "dark"}, {"connections-awg", tabWarp, stateOff, "dark"}, {"connections-subscription", tabWarp, stateOff, "dark"}, {"connections-servers", tabWarp, stateOff, "dark"}, {"connections-menu", tabWarp, stateOff, "dark"}, {"connections-processes", tabWarp, stateOff, "dark"}, {"switch-middle", tabWarp, stateOff, "dark"}, {"settings", tabSettings, stateOff, "dark"}, {"settings2", tabSettings, stateOff, "dark"},
		{"main-light", tabMain, stateOn, "light"}, {"main-starting", tabMain, stateStarting, "dark"}, {"summary-light", tabSummary, stateOn, "light"},
		{"check-no-change", tabSettings, stateOff, "dark"},
		{"check-unclear", tabSettings, stateOff, "dark"},
		{"check-on", tabSettings, stateOn, "dark"},
		{"readme", tabMain, stateOn, "dark"}} {
		if tc.name == "readme" {
			// the README's picture: a calm evening, no freezes left in the last minutes
			for i := range ctl.history {
				ctl.history[i].Frozen, ctl.history[i].Remaps = false, 0
			}
			ctl.stats.Frozen, ctl.stats.Remaps, version = 0, 0, "0.6.0"
			ping.list[1].RTT, ping.list[2].RTT = 78*time.Millisecond, 72*time.Millisecond
		}
		v.tab, ctl.st, ctl.set.Theme = tc.tab, tc.st, tc.theme
		if tc.name == "connections-subscription" || tc.name == "connections-servers" || tc.name == "connections-awg" || tc.name == "connections-vless" || tc.name == "connections-menu" || tc.name == "connections-processes" || tc.name == "switch-middle" {
			v.connections.load(ctl.settings())
			v.connections.protocol = "vless"
			v.connections.enabled.Value = true
			v.pickAWGFile = func() (string, error) { return "", nil }
			if tc.name == "connections-subscription" || tc.name == "connections-servers" {
				nodes, _, _ := parseSubscription([]byte(testSubLinks))
				v.connections.config.SetText("https://subscription.example/profile")
				v.connections.loadSubscriptionView(&connectionSubscription{URL: "https://subscription.example/profile", Nodes: nodes, Selected: nodes[0].ID})
				v.connections.imports.serverOpen = tc.name == "connections-servers"
			}
			if tc.name == "connections-awg" {
				v.connections.protocol = "amneziawg"
				v.connections.config.SingleLine = false
				v.connections.config.SetText(sampleAWGConf)
			}
			if tc.name == "switch-middle" {
				v.switches = map[*widget.Bool]*switchMotion{&v.connections.epic: {from: 0, to: 1, start: time.Now().Add(-60 * time.Millisecond), ready: true}}
			}
			if tc.name == "connections-menu" {
				v.connections.protocolOpen = true
			}
			if tc.name == "connections-processes" {
				v.warpPage.Position.Offset = 420
				v.warpPage.Position.BeforeEnd = true
				v.connections.advancedOpen = true
				v.connections.picker.open = true
				for _, name := range []string{"Discord.exe", "EpicGamesLauncher.exe", "FortniteClient-Win64-Shipping.exe", "chrome.exe", "firefox.exe"} {
					v.connections.picker.rows = append(v.connections.picker.rows, &connectionProcessChoice{name: name})
				}
			}
		}
		if tc.name == "check-no-change" || tc.name == "check-on" || tc.name == "check-unclear" {
			chk.result = &checkResult{Freeze: "no", Summary: []string{"На маяках Epic заморозки сейчас нет."}}
			if tc.name == "check-unclear" {
				chk.result.Freeze = "unclear"
				chk.result.Summary = []string{"Ответов мало, проверить заморозку не удалось."}
			}
			v.page.Position.First, v.page.Position.Offset = 0, 0
		}
		v.ringAnim, v.glyphAnim, v.fillAnim, v.titleAnim = colorAnim{}, colorAnim{}, colorAnim{}, colorAnim{}
		if tc.name == "settings2" {
			v.page.Position.First, v.page.Position.Offset = 0, int(720*scale)
		}
		var ops op.Ops
		// two frames: lists settle their scroll position in the first
		for i := 0; i < 2; i++ {
			ops.Reset()
			gtx := layout.Context{Ops: &ops, Now: now, Metric: unit.Metric{PxPerDp: scale, PxPerSp: scale},
				Constraints: layout.Exact(image.Pt(w, h))}
			v.frame(gtx)
			if err := win.Frame(&ops); err != nil {
				t.Fatal(err)
			}
		}
		img := image.NewRGBA(image.Rect(0, 0, w, h))
		if err := win.Screenshot(img); err != nil {
			t.Fatal(err)
		}
		f, _ := os.Create(filepath.Join(dir, tc.name+".png"))
		png.Encode(f, img)
		f.Close()
	}
}
