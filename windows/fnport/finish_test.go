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
		{checkResult{PortKept: "no", Freeze: "no", Fake: "harmless"}, "заморозки нет — это не мешает", "OpenWrt", false},
		{checkResult{PortKept: "yes", Freeze: "yes", Fake: "fails"}, "подбирает порты сам", "белый IP", false},
		{checkResult{PortKept: "no", Freeze: "unclear", Epic: []epicResult{{"вход", "frozen", 16000}}},
			"Сервисы Epic напрямую не работают (вход)", "", false},
		{checkResult{PortKept: "yes", Freeze: "no", Epic: ok}, "ошибки #1 и #3 не от блокировки", "", false},
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
}
