package main

import (
	"strings"
	"testing"
)

func TestReportHidesAddresses(t *testing.T) {
	if got := maskAddresses("игра 18.157.38.117:15036 (у игры порт 60325) с 192.168.1.137 и 5.6.7.8"); got !=
		"игра aws-frankfurt:15036 (у игры порт 60325) с x.x.x.x и x.x.x.x" {
		t.Fatal(got)
	}
	logf("соединение 13.41.10.112:9082 с порта 44270 замёрзло (ушло 64, пришло 25), ПК 192.168.1.137")
	c := newController(defaultSettings())
	r := finish(&checkResult{PortKept: "yes", Freeze: "yes", Fake: "works", TTL: 4, WorksFrom: 3, FakeFile: "quic_initial_vk_com.bin",
		FakeCity: "Франкфурт", Control: []cityReplies{{"Франкфурт", []int{25, 25}}},
		Scans: []fakeScan{{"quic_initial_vk_com.bin", []ttlReplies{{3, []int{30, 25, 25, 30}}}}}, Settings: defaultSettings()}, defaultSettings())
	rep := c.report(r)
	for _, want := range []string{"**Роутер сохраняет порт**: да", "Франкфурт 25, 25", "TTL 3: 30, 25, 25, 30", "TTL 4 (срабатывает с 3)",
		"aws-london:9082", "ПК x.x.x.x"} {
		if !strings.Contains(rep, want) {
			t.Errorf("no %q in\n%s", want, rep)
		}
	}
	if strings.Contains(rep, "192.168.") || strings.Contains(rep, "13.41.10.112") {
		t.Errorf("an address leaked:\n%s", rep)
	}
}
