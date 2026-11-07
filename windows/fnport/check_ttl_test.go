package main

import (
	"reflect"
	"strings"
	"testing"
)

// Replay the actual mixed result that recommended 2 in dev14B. The settings
// used by the successful A run were 3; one mixed round must not replace them.
func TestCheckTTLRetainsCurrentOnMixedReplies(t *testing.T) {
	for _, rounds := range [][][]int{{{30, 25}, {30, 25}}, {{30, 30}, {30, 25}}, {{30, 25}, {25, 25}}, {{1030, 1024}, {25, 30}}} {
		scan := fakeScan{Fake: "quic_initial_vk_com.bin"}
		calls := []int{}
		index := 0
		verdict, _, rec := selectCheckTTL(2, 9, 3, true, &scan, func(ttl int) []int {
			calls = append(calls, ttl)
			if ttl != 3 || index >= len(rounds) {
				t.Fatal("mixed current TTL triggered additional probes", calls)
			}
			result := rounds[index]
			index++
			return result
		})
		if verdict != "partial" || rec != 0 || !reflect.DeepEqual(calls, []int{3, 3}) {
			t.Fatal("mixed TTL changed settings", verdict, rec, calls)
		}
		s := defaultSettings()
		s.FakeTTL = 3
		r := finish(&checkResult{Settings: s, Freeze: "yes", PortKept: "yes", Fake: verdict, FakeFile: s.Fake, Scans: []fakeScan{scan}}, s)
		if r.Recommend != nil {
			t.Fatal("mixed replies offered new settings", r.Recommend)
		}
	}
}
func TestCheckTTLRequiresTwoFullRoundsForChange(t *testing.T) {
	for _, candidate := range []struct {
		rounds [][]int
		want   string
		rec    int
	}{
		{[][]int{{30, 30}, {30, 30}}, "works", 2},
		{[][]int{{30, 25}, {30, 25}}, "partial", 0},
		{[][]int{{30, 30}, {30}}, "partial", 0},
		{[][]int{{30, 30}, nil}, "partial", 0},
	} {
		scan := fakeScan{}
		at := 0
		verdict, _, rec := selectCheckTTL(2, 3, 3, true, &scan, func(ttl int) []int {
			if ttl == 3 {
				return []int{25, 25}
			}
			if ttl != 2 || at >= len(candidate.rounds) {
				t.Fatal("unexpected probe", ttl)
			}
			result := candidate.rounds[at]
			at++
			return result
		})
		if verdict != candidate.want || rec != candidate.rec {
			t.Fatal("weak series accepted", verdict, rec)
		}
	}
}
func TestCheckTTLSilenceNeedsLiveControl(t *testing.T) {
	for _, tc := range []struct {
		control []int
		want    string
	}{{[]int{30, 25}, "kills"}, {[]int{2, 0}, "unclear"}, {nil, "unclear"}} {
		scan := fakeScan{}
		verdict, _, rec := selectCheckTTL(2, 3, 4, true, &scan, func(ttl int) []int {
			if ttl == 0 {
				return tc.control
			}
			return []int{0, 0}
		})
		if verdict != tc.want || rec != 0 || !reflect.DeepEqual(scan.KillControl, tc.control) {
			t.Fatal("silent beacon blamed on fake", verdict, rec)
		}
	}
	scan := fakeScan{}
	verdict, _, rec := selectCheckTTL(2, 3, 3, true, &scan, func(int) []int { return nil })
	if verdict != "unclear" || rec != 0 {
		t.Fatal("failed sockets produced recommendation")
	}
}
func TestCheckRecommendationDoesNotChangeRunningTTL(t *testing.T) {
	s := defaultSettings()
	s.FakeTTL = 3
	cfg := testConfig()
	cfg.fakeTTL = 3
	dev := newChanDev()
	engine := newEngine(cfg, dev, clientIP, nil)
	defer engine.close()
	c := newController(s)
	c.eng = engine
	c.st = stateOn
	result := finish(&checkResult{Settings: s, Freeze: "yes", PortKept: "yes", Fake: "works", TTL: 2, WorksFrom: 2, FakeFile: s.Fake}, s)
	if result.Recommend == nil || result.Recommend.FakeTTL != 2 {
		t.Fatal("missing explicit recommendation")
	}
	if c.settings().FakeTTL != 3 || engine.prober.fakeTTL() != 3 {
		t.Fatal("check changed active TTL")
	}
	report := c.report(result)
	if !strings.Contains(report, "TTL 2 (две полные серии)") || !strings.Contains(report, "TTL сейчас (в работе)**: фейк vk.com, TTL 3") || !strings.Contains(report, "только по кнопке") {
		t.Fatal(report)
	}
	engine.prober.setTTL(4, "local test")
	report = c.report(result)
	if !strings.Contains(report, "TTL сейчас (в работе)**: фейк vk.com, TTL 4") || !strings.Contains(report, "Настройки при проверке**: TTL 3") {
		t.Fatal("configured and runtime TTL conflated", report)
	}
}
