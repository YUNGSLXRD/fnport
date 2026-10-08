package main

import (
	"context"
	"sync"
	"time"

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
	ctl  *controller
	tray *tray
	ping pinger

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
	win := &window{g: g, w: new(app.Window), v: newView(g.ctl, &g.ping, func() { g.quitApp() })}
	g.open = win
	g.mu.Unlock()
	go win.run()
}

func (win *window) run() {
	win.w.Option(app.Title("fnport"), app.Size(unit.Dp(660), unit.Dp(600)), app.MinSize(unit.Dp(560), unit.Dp(480)))

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
			if c := changes.Load(); c != last || (st == stateOn && win.v.tab == tabSummary && n%2 == 0) {
				last = c
				win.w.Invalidate()
			}
		}
	}()

	var ops op.Ops
	for {
		switch e := win.w.Event().(type) {
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
