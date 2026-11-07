package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/YUNGSLXRD/fnport/windows/internal/wnet"
)

var devTrace = "off"

// Names are matched as DNS suffixes, never as arbitrary substrings. Shared CDN
// address ranges must not turn unrelated applications into tunnel users.
var discordDomains = []string{"discord.com", "discord.gg", "discord.media", "discordapp.com", "discordapp.net", "dis.gd", "discord.gift", "discord.gifts", "discord-activities.com", "discordactivities.com", "discordpartygames.com", "discordsays.com", "discord-attachments-uploads-prd.storage.googleapis.com"}

func selectedProcess(name string, names []string) bool {
	name = strings.ToLower(filepath.Base(strings.ReplaceAll(strings.TrimSpace(name), `\`, "/")))
	if name == "" {
		return false
	}
	for _, want := range names {
		if strings.EqualFold(name, strings.TrimSpace(want)) {
			return true
		}
	}
	return false
}

func (s connectionSettings) selects(owner wnet.ProcessOwner, domain string) bool {
	if !s.Enabled {
		return false
	}
	if s.Epic && matchDomain(domain, warpDomains) {
		return true
	}
	if s.Discord && (selectedProcess(owner.Name, []string{"Discord.exe", "DiscordPTB.exe", "DiscordCanary.exe"}) || matchDomain(domain, discordDomains)) {
		return true
	}
	return selectedProcess(owner.Name, s.Processes)
}

type connectionRouter struct {
	failuresMu  sync.Mutex
	failures    [2]connectionFailureWindow
	cancel      context.CancelFunc
	settings    connectionSettings
	transport   *connectionTransport
	native      *warpTunnel
	tcp         *tcpRelay
	trace       *networkTrace
	ownerLookup func(uint8, netip.AddrPort, netip.AddrPort) (wnet.ProcessOwner, error)
}

func (r *connectionRouter) dial(ctx context.Context, dst netip.AddrPort, udp bool) (net.Conn, error) {
	if r.native != nil {
		if udp {
			return r.native.net.DialUDP(dst)
		}
		return r.native.net.DialTCP(ctx, dst)
	}
	if r.settings.Protocol == "warp" {
		w := r.tcp.waitWarpContext(ctx, nil, warpHold)
		if w == nil {
			return nil, connectionFailure("warp_wait", ctx.Err())
		}
		var conn net.Conn
		var err error
		if udp {
			conn, err = w.net.DialUDP(dst)
		} else {
			conn, err = w.net.DialTCP(ctx, dst)
		}
		if err != nil {
			w.fails.Add(1)
			return nil, err
		}
		w.conns.Add(1)
		return conn, nil
	}
	if r.transport == nil {
		return nil, fmt.Errorf("подключение недоступно")
	}
	if udp {
		return r.transport.udp(ctx, dst)
	}
	return r.transport.dial(ctx, dst)
}

func (r *connectionRouter) owner(proto uint8, src, dst netip.AddrPort) wnet.ProcessOwner {
	lookup := r.ownerLookup
	if lookup == nil {
		lookup = wnet.ConnectionOwner
	}
	for attempt := 0; ; attempt++ {
		o, err := lookup(proto, src, dst)
		if err == nil {
			return o
		}
		if !errors.Is(err, wnet.ErrOwnerNotFound) || attempt >= 2 {
			return wnet.ProcessOwner{}
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (r *connectionRouter) observe(proto uint8, src, dst netip.AddrPort, domain, source string) {
	if r != nil && r.trace != nil {
		r.trace.observe(proto, src, dst, domain, source)
	}
}

// Match-game UDP always uses fnport even if Fortnite is selected for its TCP services.
func (r *connectionRouter) selectedUDP(src, dst netip.AddrPort, game bool) bool {
	if r == nil || !r.settings.Enabled {
		return false
	}
	o := r.owner(17, src, dst)
	if game && strings.HasPrefix(strings.ToLower(o.Name), "fortnite") {
		return false
	}
	return r.settings.selects(o, "")
}

// independent timeout so a failed transport does not leave a pending UDP flow forever.
func connectionContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, 12*time.Second)
}

func (c *controller) connectionStatus() string {
	c.mu.Lock()
	t := c.tcp
	c.mu.Unlock()
	if t == nil || t.connection == nil {
		return "Подключение выключено."
	}
	tr := t.connection.transport
	if tr != nil {
		select {
		case <-tr.done:
			tr.mu.Lock()
			code := tr.exitCode
			tr.mu.Unlock()
			return fmt.Sprintf("Ядро завершилось (код %d). Выключите и включите fnport для повторного запуска.", code)
		default:
		}
	}
	return "Локальное ядро готово. Доступность сервера определяется при подключении."
}

func (c *controller) nativeAWGActive() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tcp != nil && c.tcp.connection != nil && c.tcp.connection.native != nil
}
