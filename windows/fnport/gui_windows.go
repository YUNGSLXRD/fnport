package main

import (
	"context"
	"image/color"
	"unsafe"

	"sync"
	"time"

	"golang.org/x/sys/windows"

	"gioui.org/app"
	"gioui.org/io/system"
	"gioui.org/op"
	"gioui.org/unit"
)

// The window. It exists only while open: closing it destroys it (GPU resources go with it) and
// the program stays in the tray. It draws only when something changed, at most twice a second.

type window struct {
	g *gui
	w *app.Window
	v *view
}

type gui struct {
	ctl   *controller
	tray  *tray
	ping  pinger
	check checker

	mu      sync.Mutex
	open    *window
	exiting bool
}

// show opens the window, or brings it to the front
func (g *gui) show() {
	g.mu.Lock()
	if g.open != nil {
		w := g.open.w
		g.mu.Unlock()
		w.Option(app.Windowed.Option())
		w.Perform(system.ActionRaise)
		return
	}
	win := &window{g: g, w: new(app.Window), v: newView(g.ctl, &g.ping, &g.check, openPath, func() { g.quitApp() })}
	g.open = win
	g.mu.Unlock()
	go win.run()
}

func (win *window) run() {
	win.w.Option(app.Title("fnport"), app.Size(unit.Dp(880), unit.Dp(660)), app.MinSize(unit.Dp(760), unit.Dp(560)))

	ctx, cancel := context.WithCancel(context.Background())
	go win.g.ping.run(ctx, func() { changes.Add(1) })
	// redraw when something changed; while fnport is on, the summary's packet counts move on
	// their own, so that tab redraws once a second
	go func() {
		last := changes.Load()
		t := time.NewTicker(500 * time.Millisecond)
		defer t.Stop()
		n := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			n++
			st, _ := win.g.ctl.state()
			running, _, _, wait := win.g.check.state()
			if c := changes.Load(); c != last || (st == stateOn && win.v.tab == tabSummary && n%2 == 0) ||
				(win.v.tab == tabSettings && (running || wait > 0) && n%2 == 0) {
				last = c
				win.w.Invalidate()
			}
		}
	}()

	var ops op.Ops
	for {
		switch e := win.w.Event().(type) {
		case app.Win32ViewEvent:
			if e.HWND != 0 {
				darkTitleBar(e.HWND)
			}
		case app.DestroyEvent:
			cancel()
			win.g.closed(win)
			return
		case app.FrameEvent:
			gtx := app.NewContext(&ops, e)
			win.v.frame(gtx)
			e.Frame(gtx.Ops)
		}
	}
}

func (g *gui) closed(win *window) {
	g.mu.Lock()
	if g.open == win {
		g.open = nil
	}
	exiting := g.exiting
	g.mu.Unlock()
	if exiting {
		return
	}
	text := "Свёрнуто в трей. Нажмите на значок, чтобы открыть окно."
	if st, _ := g.ctl.state(); st == stateOn {
		text = "Работает в трее. Нажмите на значок, чтобы открыть окно."
	}
	g.tray.balloon("fnport", text)
}

var (
	dwmapi                 = windows.NewLazySystemDLL("dwmapi.dll")
	pDwmSetWindowAttribute = dwmapi.NewProc("DwmSetWindowAttribute")
)

// darkTitleBar paints the window's title bar in the app's colours (Windows 10 2004+, 11)
func darkTitleBar(hwnd uintptr) {
	set := func(attr uint32, v uint32) {
		pDwmSetWindowAttribute.Call(hwnd, uintptr(attr), uintptr(unsafe.Pointer(&v)), 4)
	}
	set(20, 1) // DWMWA_USE_IMMERSIVE_DARK_MODE
	set(19, 1) // the same attribute on Windows 10 before 20H1
	// Windows 11: exactly the window's background and text colours (COLORREF is 0x00BBGGRR)
	cref := func(c color.NRGBA) uint32 { return uint32(c.B)<<16 | uint32(c.G)<<8 | uint32(c.R) }
	set(35, cref(colBg))   // DWMWA_CAPTION_COLOR
	set(36, cref(colText)) // DWMWA_TEXT_COLOR
	set(34, cref(colBg))   // DWMWA_BORDER_COLOR
}

// openPath opens a file or folder the way Explorer would
func openPath(path string) {
	verb, _ := windows.UTF16PtrFromString("open")
	file, _ := windows.UTF16PtrFromString(path)
	windows.ShellExecute(0, verb, file, nil, nil, windows.SW_SHOWNORMAL)
}
