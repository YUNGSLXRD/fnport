package main

import (
	"context"
	"image/color"
	"unsafe"

	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

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
				(win.v.tab == tabMain && (running || wait > 0) && n%2 == 0) {
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
				hwnd := e.HWND
				smoothMove(hwnd)
				win.v.onTheme = func(dark bool) { titleBar(hwnd, dark) }
				titleBar(hwnd, win.v.dark)
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

// titleBar paints the window's title bar for the theme (Windows 10 2004+, 11): dark or light
// mode, and on Windows 11 a caption a shade apart from the window
func titleBar(hwnd uintptr, dark bool) {
	set := func(attr uint32, v uint32) {
		pDwmSetWindowAttribute.Call(hwnd, uintptr(attr), uintptr(unsafe.Pointer(&v)), 4)
	}
	d := uint32(0)
	if dark {
		d = 1
	}
	set(20, d)                                                                                   // DWMWA_USE_IMMERSIVE_DARK_MODE
	set(19, d)                                                                                   // the same attribute on Windows 10 before 20H1
	cref := func(c color.NRGBA) uint32 { return uint32(c.B)<<16 | uint32(c.G)<<8 | uint32(c.R) } // COLORREF
	set(35, cref(colTitle))                                                                      // DWMWA_CAPTION_COLOR
	set(36, cref(colText))                                                                       // DWMWA_TEXT_COLOR
	set(34, cref(colLine))                                                                       // DWMWA_BORDER_COLOR
}

func init() {
	// Windows remembers the apps' theme as AppsUseLightTheme = 1 or 0
	systemLight = func() bool {
		k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`, registry.QUERY_VALUE)
		if err != nil {
			return false
		}
		defer k.Close()
		v, _, err := k.GetIntegerValue("AppsUseLightTheme")
		return err == nil && v == 1
	}
}

// openPath opens a file or folder the way Explorer would
func openPath(path string) {
	verb, _ := windows.UTF16PtrFromString("open")
	file, _ := windows.UTF16PtrFromString(path)
	windows.ShellExecute(0, verb, file, nil, nil, windows.SW_SHOWNORMAL)
}

// Gio redraws the whole window, synchronously and waiting for the screen's refresh, on every
// WM_WINDOWPOSCHANGED, and dragging the window sends dozens of them a second: the drag stutters.
// A move alone changes nothing inside the window, so those messages skip Gio.

var (
	pSetWindowLongPtrW = user32.NewProc("SetWindowLongPtrW")
	pCallWindowProcW   = user32.NewProc("CallWindowProcW")
	pGetWindowLongPtrW = user32.NewProc("GetWindowLongPtrW")
	oldProcs           sync.Map // hwnd -> Gio's window procedure
	moveProc           = windows.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
		old, _ := oldProcs.Load(hwnd)
		if msg == 0x0047 { // WM_WINDOWPOSCHANGED
			type windowPos struct {
				hwnd, after  uintptr
				x, y, cx, cy int32
				flags        uint32
			}
			const swpNoSize, swpFrameChanged, swpShow, swpHide = 0x1, 0x20, 0x40, 0x80
			p := (*windowPos)(unsafe.Add(nil, lParam)) // lParam points to a WINDOWPOS
			if p.flags&swpNoSize != 0 && p.flags&(swpFrameChanged|swpShow|swpHide) == 0 {
				return 0
			}
		}
		r, _, _ := pCallWindowProcW.Call(old.(uintptr), hwnd, msg, wParam, lParam)
		if msg == 0x0082 { // WM_NCDESTROY: the window is gone
			oldProcs.Delete(hwnd)
		}
		return r
	})
)

func smoothMove(hwnd uintptr) {
	if _, ok := oldProcs.Load(hwnd); ok {
		return
	}
	gwlpWndProc := -4
	// Gio's procedure is stored before ours takes over, so no message finds it missing
	old, _, _ := pGetWindowLongPtrW.Call(hwnd, uintptr(gwlpWndProc))
	if old == 0 {
		return
	}
	oldProcs.Store(hwnd, old)
	pSetWindowLongPtrW.Call(hwnd, uintptr(gwlpWndProc), moveProc)
}
