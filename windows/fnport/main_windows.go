// fnport for Windows: fnport without an OpenWrt router, as a program on the gaming PC.
//
// Windows routes traffic to AWS in Europe into a Wintun adapter (like WireGuard or WARP do).
// UDP game flows leave through this program's own sockets on the physical interface, from a
// source port that passed a probe, with the fake QUIC Initial first; frozen flows move to a
// new port. TCP to the same addresses passes through unchanged. The game is not touched: no
// injection, no packet capture driver. When fnport is turned off or the program ends, Windows
// removes the adapter and its routes, and everything goes direct again.
package main

import (
	"os"
	"time"

	"gioui.org/app"

	"github.com/YUNGSLXRD/fnport/windows/internal/fakes"
	"github.com/YUNGSLXRD/fnport/windows/internal/icon"
	"github.com/YUNGSLXRD/fnport/windows/internal/wnet"
)

func main() {
	// a second start shows the window of the first one
	if otherInstance() {
		return
	}
	openLog()
	logf("fnport для Windows %s запущен", version)
	// the fakes live in a folder next to the program; a new or empty one gets the package's own
	if err := fakes.Ensure(fakesDir()); err != nil {
		logf("папка fakes не создана: %v", err)
	}
	set := loadSettings()
	if !wnet.IsElevated() {
		// the manifest asks for administrator rights; without them the adapter cannot be made
		logf("нет прав администратора: включить fnport не получится")
	}
	// pings to the beacons leave by the physical interface even while the adapter is up
	usePhysical(set.Adapter)

	ctl := newController(set)
	g := &gui{ctl: ctl}
	t := &tray{onOpen: g.show, onToggle: ctl.toggle, onQuit: g.quitApp, accent: icon.Gray, tip: "fnport: выключен",
		isOn: func() bool { st, _ := ctl.state(); return st == stateOn }}
	g.tray = t
	go t.run()
	// the tray icon's colour follows the state
	go func() {
		for {
			st, _ := ctl.state()
			accent, tip := icon.Gray, "fnport: выключен"
			if st == stateOn {
				accent, tip = icon.Green, "fnport: работает"
				if ctl.warn() {
					accent, tip = icon.Yellow, "fnport: работает, были заморозки"
				}
			}
			t.set(accent, tip)
			time.Sleep(time.Second)
		}
	}()
	g.show()
	app.Main()
}

// quitApp turns fnport off (the adapter and its routes go) and ends the program
func (g *gui) quitApp() {
	g.mu.Lock()
	g.exiting = true
	g.mu.Unlock()
	g.ctl.stop()
	g.tray.remove()
	logf("выход")
	os.Exit(0)
}
