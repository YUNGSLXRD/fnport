package main

import (
	"fmt"
	"github.com/YUNGSLXRD/fnport/windows/internal/wnet"
	"net"
	"net/netip"
	"sort"
	"time"
)

// Latency of the adapter path: a direct socket and a flow through the adapter probe the same
// beacon in the same round, packet for packet; the relay times the server on its own socket and
// its own work, so what the adapter path adds is split into the network and this PC.

type durStats struct {
	n           int
	min, median time.Duration
	p90, max    time.Duration
}

func stats(ds []time.Duration) durStats {
	if len(ds) == 0 {
		return durStats{}
	}
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return durStats{len(s), s[0], s[len(s)/2], s[len(s)*9/10], s[len(s)-1]}
}

func ms(d time.Duration) string {
	return fmt.Sprintf("%.1f", float64(d.Microseconds())/1000)
}

func fmtStats(s durStats) string {
	if s.n == 0 {
		return "нет данных"
	}
	return fmt.Sprintf("мин %s, медиана %s, 90%% %s, макс %s мс (%d)", ms(s.min), ms(s.median), ms(s.p90), ms(s.max), s.n)
}

func checkLatency(bs []netip.Addr) {
	host := bs[0]
	logf("Задержка через адаптер: маяк %s (%s), 4 раунда по 2 потока без фейка", host, cityRU[city(host)])
	dev, clientIP, err := wnet.OpenTun("fnport-probe", []netip.Prefix{netip.PrefixFrom(host, 32)})
	if err != nil {
		logf("  %v", err)
		return
	}
	rl := newRelay(dev, clientIP, openDirect)
	rl.routed = map[netip.Addr]bool{host: true}
	setCleanup(rl.close)
	defer func() { rl.close(); setCleanup(nil) }()
	go rl.run()

	type row struct {
		round               int
		direct, tun, server durStats
	}
	var rows []row
	for round := 1; round <= 4; round++ {
		hires := round > 2
		wnet.SetTimerHighRes(hires)
		time.Sleep(roundGap)
		d, err := openDirect()
		if err != nil {
			logf("  ошибка сокета: %v", err)
			return
		}
		c, err := wnet.ListenUDP(0, false)
		if err != nil {
			d.Close()
			logf("  ошибка сокета: %v", err)
			return
		}
		res := probe([]*net.UDPConn{d, c}, host, nil, 0)
		cport := uint16(c.LocalAddr().(*net.UDPAddr).Port)
		dr, tr := res[0].rtts, res[1].rtts
		d.Close()
		c.Close()
		f := rl.flowFor(cport)
		if f == nil {
			logf("  раунд %d: Windows не отправил пакеты в адаптер", round)
			continue
		}
		f.mu.Lock()
		r := row{round, stats(dr), stats(tr), stats(f.rtts)}
		fwd, back := stats(f.fwd), stats(f.back)
		f.mu.Unlock()
		rows = append(rows, r)
		timer := "обычный таймер"
		if hires {
			timer = "таймер 1 мс"
		}
		logf("  раунд %d (%s): ответы напрямую %d/%d, через адаптер %d/%d", round, timer, res[0].got, pkts, res[1].got, pkts)
		logf("    напрямую:                 %s", fmtStats(r.direct))
		logf("    через адаптер:            %s", fmtStats(r.tun))
		logf("    сервер (сокет программы): %s", fmtStats(r.server))
		logf("    программа: адаптер→сеть %s; сеть→адаптер %s", fmtStats(fwd), fmtStats(back))
	}
	wnet.SetTimerHighRes(false)

	logf("")
	logf("ИТОГ (по минимальному пингу, он меньше всего зависит от сети)")
	for _, r := range rows {
		if r.direct.n == 0 || r.tun.n == 0 {
			continue
		}
		logf("- раунд %d: напрямую %s, через адаптер %s, добавка %s мс; из неё на ПК (адаптер и Windows) %s мс",
			r.round, ms(r.direct.min), ms(r.tun.min), ms(r.tun.min-r.direct.min), ms(r.tun.min-r.server.min))
	}
}
