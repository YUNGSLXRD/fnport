package main

import (
	"strings"
	"testing"
)

// A changed port alone is no verdict: what the fake did from this PC is
func TestFinishPortByFact(t *testing.T) {
	ok := []epicResult{{"вход", "ok", 900}}
	cases := []struct {
		r          checkResult
		want, not  string
		recommends bool
	}{
		{checkResult{PortKept: "no", Freeze: "yes", Fake: "works", TTL: 3, FakeFile: "quic_initial_vk_com.bin"},
			"фейк с ПК снимает заморозку", "OpenWrt", true},
		{checkResult{PortKept: "no", Freeze: "yes", Fake: "kills"}, "платная услуга", "", true},
		{checkResult{PortKept: "no", Freeze: "no", Fake: "harmless"}, "заморозки на маяках нет — пока это не мешает", "OpenWrt", false},
		{checkResult{PortKept: "yes", Freeze: "yes", Fake: "fails"}, "подбирает порты сам", "белый IP", false},
		{checkResult{PortKept: "no", Freeze: "unclear", Epic: []epicResult{{"вход", "frozen", 16000}}},
			"Сервисы Epic напрямую не открываются (вход)", "", false},
		{checkResult{PortKept: "yes", Freeze: "no", Epic: ok}, "Сервисы Epic напрямую открываются", "", false},
		{checkResult{PortKept: "no", Freeze: "no", Fake: "kills", FakeFile: "quic_initial_vk_com.bin"}, "убивает", "", true},
	}
	for i, c := range cases {
		r := c.r
		got := strings.Join(finish(&r, defaultSettings()).Summary, "\n")
		if !strings.Contains(got, c.want) || c.not != "" && strings.Contains(got, c.not) {
			t.Errorf("%d: want %q, not %q:\n%s", i, c.want, c.not, got)
		}
		if (r.Recommend != nil) != c.recommends {
			t.Errorf("%d: recommend %v", i, r.Recommend)
		}
	}
	// nothing to apply: the summary says so, unless there is nothing to turn on either
	nothing := "кнопки «Применить» нет"
	for i, c := range []struct {
		r    checkResult
		says bool
	}{
		{checkResult{PortKept: "yes", Freeze: "yes", Fake: "works", TTL: 5, FakeFile: "quic_initial_vk_com.bin"}, true},
		{checkResult{PortKept: "yes", Freeze: "no", Fake: "harmless", FakeFile: "quic_initial_vk_com.bin"}, true},
		{checkResult{PortKept: "no", Freeze: "yes", Fake: "fails"}, false},
		{checkResult{Freeze: "no_reply"}, false},
		{checkResult{PortKept: "no", Freeze: "no", Fake: "kills", FakeFile: "quic_initial_vk_com.bin"}, false},
	} {
		r := c.r
		got := strings.Join(finish(&r, defaultSettings()).Summary, "\n")
		if strings.Contains(got, nothing) != c.says {
			t.Errorf("nothing to apply %d: want %v:\n%s", i, c.says, got)
		}
	}
	// the fake kills at the TTL in use, not lower: "Apply" lowers it
	r0 := finish(&checkResult{Freeze: "no", Fake: "lower", TTL: 3, FakeFile: "quic_initial_vk_com.bin"}, defaultSettings())
	if r0.Recommend == nil || r0.Recommend.FakeTTL != 3 || r0.Recommend.Fake == "" {
		t.Errorf("the lower TTL not recommended: %+v", r0.Recommend)
	}
	// the fake off and harmless: "Apply" turns it on
	off := defaultSettings()
	off.Fake = ""
	r := finish(&checkResult{Freeze: "no", Fake: "harmless", FakeFile: "quic_initial_vk_com.bin"}, off)
	if r.Recommend == nil || r.Recommend.Fake != "quic_initial_vk_com.bin" {
		t.Errorf("the fake not recommended: %+v", r.Recommend)
	}
}

// with a WARP check, the summary says whether WARP helps
func TestWarpVerdict(t *testing.T) {
	d := []epicResult{{"вход", "ok", 900}, {"загрузка", "frozen", 16000}}
	cases := []struct {
		warp []epicResult
		want string
	}{
		{[]epicResult{{"вход", "ok", 900}, {"загрузка", "ok", 90000}}, "WARP помогает: через него открывается то, что напрямую нет (загрузка)"},
		{[]epicResult{{"вход", "ok", 900}, {"загрузка", "frozen", 3000}}, "Через WARP тоже не открывается: загрузка"},
		{[]epicResult{{"вход", "tls", 0}, {"загрузка", "ok", 90000}}, "а через WARP нет: вход"},
	}
	for i, c := range cases {
		if got := warpVerdict(d, c.warp); !strings.Contains(got, c.want) {
			t.Errorf("%d: %q", i, got)
		}
	}
	if warpVerdict(d, nil) != "" {
		t.Error("a verdict without a WARP check")
	}
	ok := []epicResult{{"вход", "ok", 900}}
	if got := warpVerdict(ok, ok); !strings.Contains(got, "сейчас WARP не нужен") {
		t.Errorf("both open: %q", got)
	}
}
