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
	"path/filepath"
	"time"
	"unsafe"

	"gioui.org/app"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

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
	registerAppID()
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

// appID is the name Windows files fnport's notifications under. Without one it goes by the exe's
// path and keeps the icon it saw first there (an older build's) for good; with one, the name and
// icon come from the registry, written here on every start.
const appID = "YUNGSLXRD.fnport"

func registerAppID() {
	dir, err := os.UserCacheDir() // %LOCALAPPDATA%
	if err != nil {
		return
	}
	dir = filepath.Join(dir, "fnport")
	png := filepath.Join(dir, "fnport.png")
	if os.MkdirAll(dir, 0o755) != nil || os.WriteFile(png, icon.PNG(256, icon.None), 0o644) != nil {
		return
	}
	k, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Classes\AppUserModelId\`+appID, registry.SET_VALUE)
	if err != nil {
		return
	}
	k.SetStringValue("DisplayName", "fnport")
	k.SetStringValue("IconUri", png)
	k.Close()
	id, _ := windows.UTF16PtrFromString(appID)
	windows.NewLazySystemDLL("shell32.dll").NewProc("SetCurrentProcessExplicitAppUserModelID").Call(uintptr(unsafe.Pointer(id)))
}
