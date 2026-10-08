package main

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/YUNGSLXRD/fnport/windows/internal/fakes"
	"github.com/YUNGSLXRD/fnport/windows/internal/geo"
)

// The report for a GitHub issue, as the router's ISP check makes it: the check's results, the
// settings and the counters, and the recent log with every address replaced by its AWS city
// or x.x.x.x. Nothing in it points at the user's network.

const issueURL = "https://github.com/YUNGSLXRD/fnport/issues/new?template=provider-report.yml"

// winVersion: "Windows 10.0.22631" (set by main_windows.go)
var winVersion = func() string { return "" }

var ipRe = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)

// maskAddresses: servers become aws-frankfurt and the like, every other address x.x.x.x
func maskAddresses(line string) string {
	return ipRe.ReplaceAllStringFunc(line, func(s string) string {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return "x.x.x.x"
		}
		if c := geo.City(a); c != "eu" {
			return "aws-" + c
		}
		return "x.x.x.x"
	})
}

func joinReplies(rs []int) string {
	var p []string
	for _, r := range rs {
		p = append(p, fmt.Sprint(r))
	}
	return strings.Join(p, ", ")
}

func (c *controller) report(r *checkResult) string {
	var b strings.Builder
	line := func(k, v string) { fmt.Fprintf(&b, "**%s**: %s\n", k, v) }
	head := "**fnport для Windows** " + version
	if v := winVersion(); v != "" {
		head += ", " + v
	}
	b.WriteString(head + "\n")
	line("Провайдер, город, тип подключения", "<впишите>")
	s := r.Settings
	if info, err := physical(s.Adapter); err == nil {
		kind := info.Alias
		if info.Tunnel {
			kind += " (похоже на VPN)"
		}
		line("Сетевой адаптер", kind)
	}
	line("Роутер сохраняет порт", map[string]string{"yes": "да", "no": "нет, меняет", "unknown": "не удалось узнать"}[r.PortKept])
	var ctl []string
	for _, c := range r.Control {
		ctl = append(ctl, c.City+" "+joinReplies(c.Replies))
	}
	line("Без фейка (ответов из 30)", strings.Join(ctl, "; "))
	for i, sc := range r.Scans {
		var st []string
		for _, t := range sc.Steps {
			st = append(st, fmt.Sprintf("TTL %d: %s", t.TTL, joinReplies(t.Replies)))
		}
		k := "С фейком " + fakes.Label(sc.Fake)
		if i > 0 {
			k = "Запасной фейк " + fakes.Label(sc.Fake)
		}
		line(k+" ("+r.FakeCity+")", strings.Join(st, "; "))
	}
	if r.FakeCheck != nil {
		line("Фейк при текущем TTL", fmt.Sprintf("TTL %d: %s", r.FakeCheck.TTL, joinReplies(r.FakeCheck.Replies)))
	}
	res := map[string]string{"yes": "заморозка есть", "no": "заморозки нет", "no_reply": "маяки не ответили", "unclear": "неясно"}[r.Freeze]
	if f := map[string]string{"works": "фейк работает", "kills": "фейк убивает соединения", "fails": "фейк не помогает",
		"harmless": "фейк не мешает"}[r.Fake]; f != "" {
		res += ", " + f
	}
	if r.TTL > 0 {
		res += fmt.Sprintf(", TTL %d (срабатывает с %d)", r.TTL, r.WorksFrom)
	}
	line("Итог", res)
	set := fmt.Sprintf("TTL %d, ", s.FakeTTL)
	if s.Fake == "" {
		set += "фейк выключен"
	} else {
		set += "фейк " + fakes.Label(s.Fake)
	}
	if s.Passthrough {
		set += ", только пропуск"
	}
	line("Настройки", set)
	t := c.totals()
	line("За этот запуск", fmt.Sprintf("%d соединений игры, %d без годного порта, %d замёрзло, %d переведено на новый порт, "+
		"%d из %d проверенных портов прошли", t.GameFlows, t.NoGood, t.Frozen, t.Remaps, t.Good, t.Tested))

	var recent []string
	for _, l := range logLines() {
		if !strings.Contains(l, "проверка провайдера:") {
			recent = append(recent, maskAddresses(l))
		}
	}
	if len(recent) > 40 {
		recent = recent[len(recent)-40:]
	}
	b.WriteString("\n<details><summary>Последние события (адреса скрыты)</summary>\n\n```\n")
	b.WriteString(strings.Join(recent, "\n"))
	b.WriteString("\n```\n</details>\n")
	return b.String()
}
