package main

import (
	"fmt"
	"image"
	"image/color"
	"io"
	"math"
	"strconv"
	"strings"
	"time"

	"gioui.org/f32"
	"gioui.org/font"
	"gioui.org/io/clipboard"
	"gioui.org/io/event"
	"gioui.org/io/pointer"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	"github.com/YUNGSLXRD/fnport/windows/internal/fakes"
	"github.com/YUNGSLXRD/fnport/windows/internal/fonts"
	"github.com/YUNGSLXRD/fnport/windows/internal/geo"
	"github.com/YUNGSLXRD/fnport/windows/internal/icon"
	"github.com/YUNGSLXRD/fnport/windows/internal/wnet"
)

// What the window draws. The window itself (gui_windows.go) exists only while open; this part
// draws a frame from the controller's state and does nothing between frames.

type (
	C = layout.Context
	D = layout.Dimensions
)

// The two themes. The package variables below hold the current one; only the window's
// goroutine draws, so switching them between frames is safe.
type palette struct {
	dark                                                    bool
	bg, side, card, field, line, hover, title               color.NRGBA
	text, muted, gray, green, greenBg, yellow, red, onGreen color.NRGBA
	btnHover, primaryHover, ringHover                       color.NRGBA
}

var (
	darkPalette = palette{dark: true,
		bg: rgb(0x111113), side: rgb(0x18181b), card: rgb(0x1d1d21), field: rgb(0x121214), line: rgb(0x2c2c33),
		hover: rgb(0x222227), title: rgb(0x26262b),
		text: rgb(0xececf0), muted: rgb(0x9a9aa4), gray: rgb(0x5a5a64), green: rgb(0x22c55e),
		greenBg: color.NRGBA{0x22, 0xc5, 0x5e, 0x24}, yellow: rgb(0xeab308), red: rgb(0xef4444), onGreen: rgb(0x0c0c0d),
		btnHover: rgb(0x3a3a42), primaryHover: rgb(0x16a34a), ringHover: rgb(0x2f6b45)}
	lightPalette = palette{
		bg: rgb(0xf4f4f6), side: rgb(0xe9e9ee), card: rgb(0xffffff), field: rgb(0xf4f4f6), line: rgb(0xdcdce3),
		hover: rgb(0xdedee5), title: rgb(0xdfdfe6),
		text: rgb(0x18181b), muted: rgb(0x66666f), gray: rgb(0xa1a1aa), green: rgb(0x16a34a),
		greenBg: color.NRGBA{0x16, 0xa3, 0x4a, 0x1c}, yellow: rgb(0xca8a04), red: rgb(0xdc2626), onGreen: rgb(0xffffff),
		btnHover: rgb(0xcfcfd8), primaryHover: rgb(0x15803d), ringHover: rgb(0x86c79d)}
)

var (
	colBg, colSide, colCard, colField, colLine, colHover, colTitle      color.NRGBA
	colText, colMuted, colGray, colGreen, colGreenBg, colYellow, colRed color.NRGBA
	colOnGreen, colBtnHover, colPrimaryHover, colRingHover              color.NRGBA
	themeDark                                                           bool
)

func usePalette(p palette) {
	colBg, colSide, colCard, colField, colLine, colHover, colTitle = p.bg, p.side, p.card, p.field, p.line, p.hover, p.title
	colText, colMuted, colGray, colGreen, colGreenBg, colYellow, colRed = p.text, p.muted, p.gray, p.green, p.greenBg, p.yellow, p.red
	colOnGreen, colBtnHover, colPrimaryHover, colRingHover = p.onGreen, p.btnHover, p.primaryHover, p.ringHover
	themeDark = p.dark
}

func init() { usePalette(darkPalette) }

// systemLight: whether Windows apps use the light theme (set by gui_windows.go)
var systemLight = func() bool { return false }

func rgb(v uint32) color.NRGBA {
	return color.NRGBA{R: uint8(v >> 16), G: uint8(v >> 8), B: uint8(v), A: 0xff}
}

type tab int

const (
	tabMain tab = iota
	tabSummary
	tabLog
	tabSettings
)

var tabNames = []string{"Главная", "Сводка", "Журнал", "Настройки"}

type view struct {
	ctl    *controller
	ping   *pinger
	check  *checker
	open   func(path string) // opens a file or folder in Windows
	onQuit func()

	onTheme func(dark bool) // the window repaints its title bar

	th         *material.Theme
	logo       paint.ImageOp
	tab        tab
	prevTab    tab
	tabSince   time.Time
	tabs       [4]widget.Clickable
	navItemH   int
	animating  bool // a transition is running: ask for the next frame
	dark       bool
	themed     bool
	sysLight   bool
	sysChecked time.Time
	ringAnim   colorAnim
	glyphAnim  colorAnim
	fillAnim   colorAnim
	titleAnim  colorAnim
	pingNow    widget.Clickable
	copyReport widget.Clickable
	openIssue  widget.Clickable
	reportMsg  string
	scrolls    map[*widget.List]*smoothScroll
	theme      widget.Enum

	power    widget.Clickable
	flowList widget.List
	mainList widget.List
	logs     widget.List
	openLog  widget.Clickable

	// settings: a draft edited here, applied with "Save"
	page       widget.List
	draftFor   uint64 // changes counter when the draft was taken; 0 = take it again
	adapter    widget.Enum
	fake       widget.Enum
	ttl        int
	ttlMinus   widget.Clickable
	ttlPlus    widget.Clickable
	routes     widget.Editor
	ports      widget.Editor
	batch      widget.Editor
	rounds     widget.Editor
	budget     widget.Editor
	passthru   widget.Bool
	save       widget.Clickable
	reset      widget.Clickable
	openFakes  widget.Clickable
	runCheck   widget.Clickable
	applyCheck widget.Clickable
	adapters   []wnet.IfaceInfo
	fakeFiles  []fakes.File
	saveMsg    string
	saveErr    bool
}

func newView(ctl *controller, ping *pinger, check *checker, open func(string), onQuit func()) *view {
	th := material.NewTheme()
	th.Shaper = text.NewShaper(text.NoSystemFonts(), text.WithCollection(fonts.Collection()))
	th.Face = fonts.UI
	th.TextSize = unit.Sp(14)
	v := &view{ctl: ctl, ping: ping, check: check, open: open, onQuit: onQuit, th: th}
	v.logo = paint.NewImageOp(icon.Draw(96, icon.None))
	v.flowList.Axis = layout.Vertical
	v.mainList.Axis = layout.Vertical
	v.logs.Axis = layout.Vertical
	v.page.Axis = layout.Vertical
	v.ports.SingleLine = true
	for _, e := range []*widget.Editor{&v.batch, &v.rounds, &v.budget} {
		e.SingleLine, e.Filter = true, "0123456789"
	}
	return v
}

// ---- small helpers

func fill(gtx C, c color.NRGBA, r int) D {
	sz := gtx.Constraints.Min
	paint.FillShape(gtx.Ops, c, clip.UniformRRect(image.Rectangle{Max: sz}, r).Op(gtx.Ops))
	return D{Size: sz}
}

func (v *view) card(gtx C, w layout.Widget) D {
	gtx.Constraints.Min.X = gtx.Constraints.Max.X
	return layout.Background{}.Layout(gtx,
		func(gtx C) D { return fill(gtx, colCard, gtx.Dp(12)) },
		func(gtx C) D { return layout.UniformInset(unit.Dp(18)).Layout(gtx, w) })
}

func (v *view) label(size float32, c color.NRGBA, s string) material.LabelStyle {
	l := material.Label(v.th, unit.Sp(size), s)
	l.Color = c
	return l
}

func bold(l material.LabelStyle) material.LabelStyle {
	l.Font.Weight = font.Bold
	return l
}

func mono(l material.LabelStyle) material.LabelStyle {
	l.Font.Typeface = fonts.Mono
	return l
}

func dot(gtx C, c color.NRGBA, d unit.Dp) D {
	s := gtx.Dp(d)
	paint.FillShape(gtx.Ops, c, clip.Ellipse{Max: image.Pt(s, s)}.Op(gtx.Ops))
	return D{Size: image.Pt(s, s)}
}

func vspace(dp unit.Dp) layout.FlexChild { return layout.Rigid(layout.Spacer{Height: dp}.Layout) }
func hspace(dp unit.Dp) layout.FlexChild { return layout.Rigid(layout.Spacer{Width: dp}.Layout) }

// button: a rounded button; primary is filled green
func (v *view) button(gtx C, c *widget.Clickable, s string, primary, enabled bool) D {
	bg, fg := colLine, colText
	if primary {
		bg, fg = colGreen, colOnGreen
	}
	if !enabled {
		bg, fg = colLine, colGray
	} else if c.Hovered() {
		if primary {
			bg = colPrimaryHover
		} else {
			bg = colBtnHover
		}
	}
	return c.Layout(gtx, func(gtx C) D {
		return layout.Background{}.Layout(gtx,
			func(gtx C) D { return fill(gtx, bg, gtx.Dp(8)) },
			func(gtx C) D {
				return layout.Inset{Top: 8, Bottom: 8, Left: 16, Right: 16}.Layout(gtx, bold(v.label(14, fg, s)).Layout)
			})
	})
}

// ---- vector icons in a 24x24 box, drawn as strokes

type glyph int

const (
	glyphHome glyph = iota
	glyphList
	glyphLog
	glyphGear
	glyphPower
)

func drawGlyph(gtx C, g glyph, c color.NRGBA, size unit.Dp, width float32) D {
	px := float32(gtx.Dp(size))
	k := px / 24
	var p clip.Path
	p.Begin(gtx.Ops)
	pt := func(x, y float32) f32.Point { return f32.Pt(x*k, y*k) }
	line := func(pts ...[2]float32) {
		p.MoveTo(pt(pts[0][0], pts[0][1]))
		for _, q := range pts[1:] {
			p.LineTo(pt(q[0], q[1]))
		}
	}
	arc := func(cx, cy, r, from, to float32) {
		const steps = 28
		for i := 0; i <= steps; i++ {
			a := float64(from + (to-from)*float32(i)/steps)
			x, y := cx+r*float32(math.Sin(a)), cy-r*float32(math.Cos(a))
			if i == 0 {
				p.MoveTo(pt(x, y))
			} else {
				p.LineTo(pt(x, y))
			}
		}
	}
	switch g {
	case glyphHome:
		line([2]float32{3, 11.5}, [2]float32{12, 3.5}, [2]float32{21, 11.5})
		line([2]float32{5.5, 10}, [2]float32{5.5, 20.5}, [2]float32{18.5, 20.5}, [2]float32{18.5, 10})
		line([2]float32{10, 20.5}, [2]float32{10, 15}, [2]float32{14, 15}, [2]float32{14, 20.5})
	case glyphList:
		for _, y := range []float32{6, 12, 18} {
			line([2]float32{9, y}, [2]float32{21, y})
			arc(4.5, y, 0.9, 0, 2*math.Pi)
		}
	case glyphLog:
		line([2]float32{6, 3}, [2]float32{14, 3}, [2]float32{19, 8}, [2]float32{19, 21}, [2]float32{6, 21}, [2]float32{6, 3})
		line([2]float32{14, 3}, [2]float32{14, 8}, [2]float32{19, 8})
		for _, y := range []float32{12, 16} {
			line([2]float32{9, y}, [2]float32{16, y})
		}
	case glyphGear:
		arc(12, 12, 3, 0, 2*math.Pi)
		arc(12, 12, 7, 0, 2*math.Pi)
		for i := 0; i < 8; i++ {
			a := float64(i) * math.Pi / 4
			s, cs := float32(math.Sin(a)), float32(math.Cos(a))
			line([2]float32{12 + 7*s, 12 - 7*cs}, [2]float32{12 + 10*s, 12 - 10*cs})
		}
	case glyphPower:
		arc(12, 13, 8, 0.62, 2*math.Pi-0.62)
		line([2]float32{12, 2.5}, [2]float32{12, 11.5})
	}
	paint.FillShape(gtx.Ops, c, clip.Stroke{Path: p.End(), Width: width * k}.Op())
	return D{Size: image.Pt(int(px), int(px))}
}

// ---- animation

const (
	tabAnim   = 220 * time.Millisecond
	powerAnim = 280 * time.Millisecond
)

// easeOut: fast start, soft landing
func easeOut(t float64) float64 {
	t = math.Max(0, math.Min(1, t))
	return 1 - math.Pow(1-t, 3)
}

func mix(a, b color.NRGBA, t float64) color.NRGBA {
	t = math.Max(0, math.Min(1, t))
	m := func(x, y uint8) uint8 { return uint8(float64(x)*(1-t) + float64(y)*t + 0.5) }
	return color.NRGBA{m(a.R, b.R), m(a.G, b.G), m(a.B, b.B), m(a.A, b.A)}
}

// colorAnim moves a colour to a new target over powerAnim
type colorAnim struct {
	from, to color.NRGBA
	start    time.Time
	set      bool
}

func (a *colorAnim) at(now time.Time, target color.NRGBA) (color.NRGBA, bool) {
	if !a.set {
		a.from, a.to, a.set = target, target, true
	}
	if target != a.to {
		a.from, _ = a.at(now, a.to)
		a.to, a.start = target, now
	}
	t := float64(now.Sub(a.start)) / float64(powerAnim)
	if t >= 1 {
		return a.to, false
	}
	return mix(a.from, a.to, easeOut(t)), true
}

// ---- the frame: sidebar and page

func (v *view) themeDark() bool {
	switch v.ctl.settings().Theme {
	case "light":
		return false
	case "dark":
		return true
	}
	if time.Since(v.sysChecked) > 3*time.Second {
		v.sysLight, v.sysChecked = systemLight(), time.Now()
	}
	return !v.sysLight
}

func (v *view) frame(gtx C) {
	if dark := v.themeDark(); dark != v.dark || !v.themed {
		v.dark, v.themed = dark, true
		if dark {
			usePalette(darkPalette)
		} else {
			usePalette(lightPalette)
		}
		v.th.Palette = material.Palette{Bg: colBg, Fg: colText, ContrastBg: colGreen, ContrastFg: colOnGreen}
		if v.onTheme != nil {
			v.onTheme(dark)
		}
	}
	for i := range v.tabs {
		if v.tabs[i].Clicked(gtx) && v.tab != tab(i) {
			v.prevTab, v.tab, v.tabSince = v.tab, tab(i), gtx.Now
			if v.tab == tabSettings {
				v.draftFor = 0
			}
		}
	}
	if v.power.Clicked(gtx) {
		go v.ctl.toggle()
	}
	if v.openLog.Clicked(gtx) {
		logs.Lock()
		p := logs.path
		logs.Unlock()
		if p != "" && v.open != nil {
			v.open(p)
		}
	}
	v.animating = false
	paint.Fill(gtx.Ops, colBg)
	layout.Flex{}.Layout(gtx,
		layout.Rigid(v.sidebar),
		layout.Flexed(1, func(gtx C) D {
			// the page fades in and slides up a little after a tab switch
			// (no layer at all once the transition is over: an opacity layer costs a render pass)
			if t := easeOut(float64(gtx.Now.Sub(v.tabSince)) / float64(tabAnim)); t < 1 {
				v.animating = true
				defer paint.PushOpacity(gtx.Ops, float32(0.35+0.65*t)).Pop()
				defer pushOffset(gtx, 0, int(float64(gtx.Dp(14))*(1-t))).Pop()
			}
			return layout.UniformInset(unit.Dp(24)).Layout(gtx, func(gtx C) D {
				switch v.tab {
				case tabSummary:
					return v.summary(gtx)
				case tabLog:
					return v.logTab(gtx)
				case tabSettings:
					return v.settingsTab(gtx)
				}
				return v.mainTab(gtx)
			})
		}))
	if v.animating {
		gtx.Execute(op.InvalidateCmd{})
	}
}

func (v *view) sidebar(gtx C) D {
	w := gtx.Dp(200)
	gtx.Constraints = layout.Exact(image.Pt(w, gtx.Constraints.Max.Y))
	paint.FillShape(gtx.Ops, colSide, clip.Rect{Max: gtx.Constraints.Max}.Op())
	glyphs := []glyph{glyphHome, glyphList, glyphLog, glyphGear}
	return layout.Inset{Top: 22, Bottom: 18, Left: 14, Right: 14}.Layout(gtx, func(gtx C) D {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx C) D {
				return layout.Inset{Left: 6, Bottom: 24}.Layout(gtx, func(gtx C) D {
					return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
						// 96 image pixels shown as 38 dp
						layout.Rigid(widget.Image{Src: v.logo, Scale: 38.0 / 96}.Layout),
						hspace(10),
						layout.Rigid(func(gtx C) D {
							return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
								layout.Rigid(bold(v.label(18, colText, "fnport")).Layout),
								layout.Rigid(v.label(11, colMuted, version).Layout))
						}))
				})
			}),
			layout.Rigid(func(gtx C) D { return v.nav(gtx, glyphs) }),
			layout.Flexed(1, func(gtx C) D { return D{Size: image.Pt(0, gtx.Constraints.Min.Y)} }),
			layout.Rigid(func(gtx C) D {
				c, s := v.stateLook()
				return layout.Inset{Left: 8}.Layout(gtx, func(gtx C) D {
					return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
						layout.Rigid(func(gtx C) D { return dot(gtx, c, 8) }),
						hspace(8),
						layout.Flexed(1, v.label(13, colMuted, s).Layout))
				})
			}))
	})
}

// nav: the tab buttons; the highlight slides from the old tab to the new one
func (v *view) nav(gtx C, glyphs []glyph) D {
	gap := gtx.Dp(4)
	h := v.navItemH
	if h == 0 {
		h = gtx.Dp(42)
	}
	t := easeOut(float64(gtx.Now.Sub(v.tabSince)) / float64(tabAnim))
	if t < 1 {
		v.animating = true
	}
	y := float64(int(v.prevTab)*(h+gap))*(1-t) + float64(int(v.tab)*(h+gap))*t
	hl := clip.UniformRRect(image.Rect(0, int(y), gtx.Constraints.Max.X, int(y)+h), gtx.Dp(10))
	paint.FillShape(gtx.Ops, colCard, hl.Op(gtx.Ops))

	var kids []layout.FlexChild
	for i := range tabNames {
		i := i
		kids = append(kids, layout.Rigid(func(gtx C) D {
			active := v.tab == tab(i)
			return layout.Inset{Bottom: unit.Dp(4)}.Layout(gtx, func(gtx C) D {
				d := v.tabs[i].Layout(gtx, func(gtx C) D {
					gtx.Constraints.Min.X = gtx.Constraints.Max.X
					return layout.Stack{}.Layout(gtx,
						layout.Expanded(func(gtx C) D {
							if v.tabs[i].Hovered() && !active {
								return fill(gtx, colHover, gtx.Dp(10))
							}
							return D{Size: gtx.Constraints.Min}
						}),
						layout.Stacked(func(gtx C) D {
							c, gc := colMuted, colMuted
							if active {
								c, gc = colText, colGreen
							}
							return layout.Inset{Top: 11, Bottom: 11, Left: 12, Right: 12}.Layout(gtx, func(gtx C) D {
								return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
									layout.Rigid(func(gtx C) D { return drawGlyph(gtx, glyphs[i], gc, 20, 1.8) }),
									hspace(12),
									layout.Rigid(v.label(15, c, tabNames[i]).Layout))
							})
						}))
				})
				v.navItemH = d.Size.Y
				return d
			})
		}))
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx, kids...)
}

func (v *view) stateLook() (color.NRGBA, string) {
	st, _ := v.ctl.state()
	switch st {
	case stateStarting:
		return colYellow, "Включается…"
	case stateOn:
		if v.ctl.warn() {
			return colYellow, "Работает, были заморозки"
		}
		return colGreen, "Работает"
	}
	return colMuted, "Выключено"
}

func (v *view) title(s string) layout.FlexChild {
	return layout.Rigid(func(gtx C) D {
		return layout.Inset{Bottom: 16}.Layout(gtx, bold(v.label(22, colText, s)).Layout)
	})
}

// ---- main page: the switch, the beacons, the counters

func (v *view) mainTab(gtx C) D {
	st, errText := v.ctl.state()
	c, s := v.stateLook()
	sub, subC := "Игра идёт напрямую, без fnport.", colMuted
	switch st {
	case stateStarting:
		sub = "Создаю адаптер…"
	case stateOn:
		sub = "Игра идёт через fnport: " + v.ctl.fakeLabel() + "."
	}
	if errText != "" && st == stateOff {
		sub, subC = "Не включилось: "+errText, colRed
	}
	titleC, more := v.titleAnim.at(gtx.Now, c)
	v.animating = v.animating || more
	// a list, so the page scrolls when the check's results make it taller than the window
	return v.list(gtx, &v.mainList, 1, func(gtx C, _ int) D {
		return layout.Inset{Right: 10}.Layout(gtx, func(gtx C) D { return v.mainColumn(gtx, st, titleC, s, sub, subC) })
	})
}

func (v *view) mainColumn(gtx C, st state, titleC color.NRGBA, s, sub string, subC color.NRGBA) D {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		vspace(6),
		layout.Rigid(func(gtx C) D { return layout.Center.Layout(gtx, func(gtx C) D { return v.powerButton(gtx, st) }) }),
		vspace(14),
		layout.Rigid(func(gtx C) D {
			return layout.Center.Layout(gtx, bold(v.label(20, titleC, s)).Layout)
		}),
		vspace(4),
		layout.Rigid(func(gtx C) D {
			l := v.label(13, subC, sub)
			l.Alignment = text.Middle
			return layout.Center.Layout(gtx, l.Layout)
		}),
		vspace(22),
		layout.Rigid(v.beaconsCard),
		vspace(12),
		layout.Rigid(v.countersCard))
}

// powerButton: a round button with the power symbol; its colours glide between states, and a
// bright arc runs around the ring while fnport starts
func (v *view) powerButton(gtx C, st state) D {
	ring, glyphC, bg := colLine, colMuted, colCard
	switch st {
	case stateStarting:
		ring, glyphC = colLine, colYellow
	case stateOn:
		ring, glyphC, bg = colGreen, colGreen, colGreenBg
	}
	if v.power.Hovered() && st == stateOff {
		ring, glyphC = colRingHover, colText
	}
	var m1, m2, m3 bool
	ring, m1 = v.ringAnim.at(gtx.Now, ring)
	glyphC, m2 = v.glyphAnim.at(gtx.Now, glyphC)
	bg, m3 = v.fillAnim.at(gtx.Now, bg)
	v.animating = v.animating || m1 || m2 || m3 || st == stateStarting
	return v.power.Layout(gtx, func(gtx C) D {
		d := gtx.Dp(132)
		sz := image.Pt(d, d)
		paint.FillShape(gtx.Ops, bg, clip.Ellipse{Max: sz}.Op(gtx.Ops))
		w := float32(gtx.Dp(3))
		r := float32(d)/2 - w/2
		circle := func(c color.NRGBA, from, to float64) {
			var p clip.Path
			p.Begin(gtx.Ops)
			const steps = 72
			for i := 0; i <= steps; i++ {
				a := from + (to-from)*float64(i)/steps
				q := f32.Pt(float32(d)/2+r*float32(math.Sin(a)), float32(d)/2-r*float32(math.Cos(a)))
				if i == 0 {
					p.MoveTo(q)
				} else {
					p.LineTo(q)
				}
			}
			paint.FillShape(gtx.Ops, c, clip.Stroke{Path: p.End(), Width: w}.Op())
		}
		circle(ring, 0, 2*math.Pi)
		if st == stateStarting {
			a := float64(gtx.Now.UnixMilli()%1000) / 1000 * 2 * math.Pi
			circle(colYellow, a, a+math.Pi*0.6)
		}
		g := gtx.Dp(56)
		off := (d - g) / 2
		defer pushOffset(gtx, off, off).Pop()
		drawGlyph(gtx, glyphPower, glyphC, 56, 2.4)
		return D{Size: sz}
	})
}

func pingColor(b beacon) (color.NRGBA, string) {
	switch {
	case !b.Checked:
		return colGray, "…"
	case b.RTT == 0:
		return colRed, "нет ответа"
	case b.RTT >= pingHigh:
		return colYellow, fmt.Sprintf("%d мс", b.RTT.Milliseconds())
	}
	return colGreen, fmt.Sprintf("%d мс", b.RTT.Milliseconds())
}

// beaconsCard: the ping to each city; "Проверить" pings again at once
func (v *view) beaconsCard(gtx C) D {
	if v.pingNow.Clicked(gtx) {
		v.ping.kickNow()
	}
	bs := v.ping.snapshot()
	busy := v.ping.busy()
	label := "Проверить"
	if busy {
		label = "Проверяю…"
	}
	return v.card(gtx, func(gtx C) D {
		kids := []layout.FlexChild{
			layout.Rigid(func(gtx C) D {
				return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
					layout.Flexed(1, bold(v.label(14, colText, "Пинг до серверов Epic")).Layout),
					layout.Rigid(func(gtx C) D { return v.button(gtx, &v.pingNow, label, false, !busy) }))
			}),
			vspace(8),
		}
		if len(bs) == 0 {
			kids = append(kids, layout.Rigid(v.label(13, colMuted, "Ищу маяки…").Layout))
		}
		for _, b := range bs {
			b := b
			c, s := pingColor(b)
			kids = append(kids, layout.Rigid(func(gtx C) D {
				return layout.Inset{Top: 4, Bottom: 4}.Layout(gtx, func(gtx C) D {
					return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
						layout.Rigid(func(gtx C) D { return dot(gtx, c, 10) }),
						hspace(10),
						layout.Flexed(1, v.label(14, colText, b.City).Layout),
						layout.Rigid(bold(v.label(14, c, s)).Layout))
				})
			}))
		}
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, kids...)
	})
}

func (v *view) countersCard(gtx C) D {
	s := v.ctl.totals()
	stat := func(value, name string, c color.NRGBA) layout.FlexChild {
		return layout.Flexed(1, func(gtx C) D {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(bold(v.label(20, c, value)).Layout),
				layout.Rigid(v.label(12, colMuted, name).Layout))
		})
	}
	warnIf := func(n int) color.NRGBA {
		if n > 0 {
			return colYellow
		}
		return colText
	}
	return v.card(gtx, func(gtx C) D {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(bold(v.label(14, colText, "За этот запуск")).Layout),
			vspace(10),
			layout.Rigid(func(gtx C) D {
				return layout.Flex{}.Layout(gtx,
					stat(fmt.Sprint(s.GameFlows), "соединений игры", colText),
					stat(fmt.Sprintf("%d / %d", s.Good, s.Tested), "годных портов / проверено", colText),
					stat(fmt.Sprint(s.Frozen), "замёрзло", warnIf(s.Frozen)),
					stat(fmt.Sprint(s.Remaps), "переводов на новый порт", warnIf(s.Remaps)))
			}))
	})
}

// ---- summary: game servers

var cols = []float32{0.22, 0.13, 0.20, 0.17, 0.09, 0.19}

func (v *view) tableRow(gtx C, cells []material.LabelStyle) D {
	var kids []layout.FlexChild
	for i, c := range cells {
		c := c
		c.MaxLines = 1
		kids = append(kids, layout.Flexed(cols[i], c.Layout))
	}
	return layout.Flex{Alignment: layout.Middle}.Layout(gtx, kids...)
}

type cityStat struct {
	city                                string
	matches, flows, ok, rescued, failed int
}

// byCity: how the game's connections went in each city
func byCity(flows []flowInfo) []cityStat {
	order := []string{"Франкфурт", "Лондон", "Париж", "Европа"}
	m := map[string]*cityStat{}
	for _, f := range flows {
		c := geo.CityRU(f.Server.Addr())
		st := m[c]
		if st == nil {
			st = &cityStat{city: c}
			m[c] = st
		}
		st.flows++
		if f.Match {
			st.matches++
		}
		switch {
		case f.Frozen:
			st.failed++
		case f.Remaps > 0:
			st.rescued++
		default:
			st.ok++
		}
	}
	var out []cityStat
	for _, c := range order {
		if st := m[c]; st != nil {
			out = append(out, *st)
		}
	}
	return out
}

var cityCols = []float32{0.22, 0.13, 0.16, 0.16, 0.18, 0.15}

func (v *view) citiesCard(gtx C, flows []flowInfo) D {
	cs := byCity(flows)
	return v.card(gtx, func(gtx C) D {
		row := func(gtx C, cells []material.LabelStyle, c *color.NRGBA) D {
			var kids []layout.FlexChild
			for i, l := range cells {
				i, l := i, l
				l.MaxLines = 1
				kids = append(kids, layout.Flexed(cityCols[i], func(gtx C) D {
					if i > 0 || c == nil {
						return l.Layout(gtx)
					}
					return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
						layout.Rigid(func(gtx C) D { return dot(gtx, *c, 9) }), hspace(8), layout.Rigid(l.Layout))
				}))
			}
			return layout.Flex{Alignment: layout.Middle}.Layout(gtx, kids...)
		}
		head := func(s string) material.LabelStyle { return v.label(12, colMuted, s) }
		kids := []layout.FlexChild{
			layout.Rigid(func(gtx C) D {
				return row(gtx, []material.LabelStyle{head("Город"), head("Матчей"), head("Соединений"), head("Без проблем"),
					head("Переведено"), head("Не удалось")}, nil)
			}),
			vspace(6),
		}
		for _, st := range cs {
			st := st
			c := colGreen
			if st.rescued > 0 {
				c = colYellow
			}
			if st.failed > 0 {
				c = colRed
			}
			num := func(n int, warn color.NRGBA) material.LabelStyle {
				col := colText
				if n > 0 {
					col = warn
				}
				return bold(v.label(14, col, fmt.Sprint(n)))
			}
			kids = append(kids, layout.Rigid(func(gtx C) D {
				return layout.Inset{Top: 5, Bottom: 5}.Layout(gtx, func(gtx C) D {
					return row(gtx, []material.LabelStyle{v.label(14, colText, st.city), bold(v.label(14, colText, fmt.Sprint(st.matches))),
						bold(v.label(14, colText, fmt.Sprint(st.flows))), num(st.ok, colGreen), num(st.rescued, colYellow), num(st.failed, colRed)}, &c)
				})
			}))
		}
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, kids...)
	})
}

func (v *view) summary(gtx C) D {
	flows := v.ctl.flows()
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		v.title("Сводка"),
		layout.Rigid(func(gtx C) D {
			if len(flows) == 0 {
				return D{}
			}
			return layout.Inset{Bottom: 12}.Layout(gtx, func(gtx C) D { return v.citiesCard(gtx, flows) })
		}),
		layout.Flexed(1, func(gtx C) D {
			if len(flows) == 0 {
				return v.card(gtx, v.label(14, colMuted, "Соединений игры пока не было. Включите fnport и зайдите в матч: здесь появятся "+
					"серверы, их города и порты, которые нашёл fnport.").Layout)
			}
			head := func(s string) material.LabelStyle { return v.label(12, colMuted, s) }
			gtx.Constraints.Min = gtx.Constraints.Max
			return v.card(gtx, func(gtx C) D {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx C) D {
						return v.tableRow(gtx, []material.LabelStyle{head("Сервер"), head("Город"), head("Порт игры → fnport"),
							head("Пакеты ↑ / ↓"), head("Начало"), head("Состояние")})
					}),
					vspace(8),
					layout.Rigid(func(gtx C) D {
						sz := image.Pt(gtx.Constraints.Max.X, gtx.Dp(1))
						paint.FillShape(gtx.Ops, colLine, clip.Rect{Max: sz}.Op())
						return D{Size: sz}
					}),
					layout.Flexed(1, func(gtx C) D {
						return v.list(gtx, &v.flowList, len(flows), func(gtx C, i int) D {
							f := flows[i]
							stC, stS := colMuted, "завершено"
							switch {
							case f.Active && f.Frozen:
								stC, stS = colRed, "замёрзло"
							case f.Remaps > 0:
								stC, stS = colYellow, fmt.Sprintf("переведено ×%d", f.Remaps)
							case f.Active:
								stC, stS = colGreen, "идёт"
							}
							tc := colText
							if !f.Active {
								tc = colMuted
							}
							port := fmt.Sprintf("%d → …", f.GamePort)
							if f.Port != 0 {
								port = fmt.Sprintf("%d → %d", f.GamePort, f.Port)
							}
							return layout.Inset{Top: 7, Bottom: 7}.Layout(gtx, func(gtx C) D {
								return v.tableRow(gtx, []material.LabelStyle{
									v.label(13, tc, f.Server.String()),
									v.label(13, tc, geo.CityRU(f.Server.Addr())),
									v.label(13, tc, port),
									v.label(13, tc, fmt.Sprintf("%s / %s", short(f.Out), short(f.In))),
									v.label(13, tc, f.Started.Format("15:04")),
									bold(v.label(13, stC, stS)),
								})
							})
						})
					}))
			})
		}))
}

// short: 12345 -> "12,3к"
func short(n int64) string {
	switch {
	case n >= 1_000_000:
		return strings.Replace(fmt.Sprintf("%.1fМ", float64(n)/1e6), ".", ",", 1)
	case n >= 10_000:
		return strings.Replace(fmt.Sprintf("%.1fк", float64(n)/1e3), ".", ",", 1)
	}
	return fmt.Sprint(n)
}

// ---- log

func (v *view) logTab(gtx C) D {
	lines := logLines()
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx C) D {
			return layout.Inset{Bottom: 16}.Layout(gtx, func(gtx C) D {
				return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
					layout.Flexed(1, bold(v.label(22, colText, "Журнал")).Layout),
					layout.Rigid(func(gtx C) D { return v.button(gtx, &v.openLog, "Открыть файл", false, true) }))
			})
		}),
		layout.Flexed(1, func(gtx C) D {
			gtx.Constraints.Min = gtx.Constraints.Max
			return v.card(gtx, func(gtx C) D {
				if len(lines) == 0 {
					return v.label(13, colMuted, "Журнал пуст.").Layout(gtx)
				}
				// stick to the newest line only once the lines fill the card; a short log starts at the top
				v.logs.ScrollToEnd = len(lines)*gtx.Dp(19) > gtx.Constraints.Max.Y
				return v.list(gtx, &v.logs, len(lines), func(gtx C, i int) D {
					l := mono(v.label(12, colText, lines[i]))
					if warnLine(lines[i]) {
						l.Color = colYellow
					}
					return layout.Inset{Bottom: 3}.Layout(gtx, l.Layout)
				})
			})
		}))
}

// warnLine: log lines worth yellow (a flow froze or moved, a warning, a failure)
func warnLine(l string) bool {
	for _, s := range []string{"замёрзло (", "переведено на порт", "ВНИМАНИЕ", "не включилось", "нет сокета", "ломает", "не прочитан"} {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

// ---- settings

// takeDraft fills the settings page from the saved settings
func (v *view) takeDraft() {
	s := v.ctl.settings()
	v.adapters = wnet.Interfaces()
	v.fakeFiles = fakes.List(fakesDir())
	v.adapter.Value = s.Adapter
	v.fake.Value = s.Fake
	v.ttl = s.FakeTTL
	v.routes.SetText(strings.Join(s.Routes, "\n"))
	v.ports.SetText(strings.Join(s.GamePorts, ", "))
	v.batch.SetText(fmt.Sprint(s.ProbeBatch))
	v.rounds.SetText(fmt.Sprint(s.MaxRounds))
	v.budget.SetText(fmt.Sprint(s.ProbeBudget))
	v.passthru.Value = s.Passthrough
	v.theme.Value = s.Theme
	if v.theme.Value == "" {
		v.theme.Value = "system"
	}
}

// draft: the settings as edited on the page
func (v *view) draft() settings {
	s := v.ctl.settings()
	s.Adapter, s.Fake, s.FakeTTL, s.Passthrough, s.Theme = v.adapter.Value, v.fake.Value, v.ttl, v.passthru.Value, v.theme.Value
	s.Routes = nil
	for _, l := range strings.Split(v.routes.Text(), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			s.Routes = append(s.Routes, l)
		}
	}
	s.GamePorts = nil
	for _, p := range strings.FieldsFunc(v.ports.Text(), func(r rune) bool { return r == ',' || r == ';' || r == ' ' }) {
		s.GamePorts = append(s.GamePorts, p)
	}
	num := func(e *widget.Editor, d int) int {
		if n, err := strconv.Atoi(strings.TrimSpace(e.Text())); err == nil {
			return n
		}
		return d
	}
	s.ProbeBatch, s.MaxRounds, s.ProbeBudget = num(&v.batch, s.ProbeBatch), num(&v.rounds, s.MaxRounds), num(&v.budget, s.ProbeBudget)
	return s
}

func (v *view) settingsTab(gtx C) D {
	if v.draftFor == 0 {
		v.takeDraft()
		v.draftFor = 1
	}
	if v.ttlMinus.Clicked(gtx) && v.ttl > 1 {
		v.ttl--
	}
	if v.ttlPlus.Clicked(gtx) && v.ttl < 32 {
		v.ttl++
	}
	if v.openFakes.Clicked(gtx) && v.open != nil {
		v.open(fakesDir())
	}
	if v.reset.Clicked(gtx) {
		v.takeDraft()
		v.saveMsg = ""
	}
	if v.save.Clicked(gtx) {
		s := v.draft()
		go func() {
			if err := v.ctl.apply(s); err != nil {
				v.saveMsg, v.saveErr = err.Error(), true
			} else {
				v.saveMsg, v.saveErr = "Сохранено.", false
			}
			changes.Add(1)
		}()
	}
	running, lines, res, wait := v.check.state()
	if v.runCheck.Clicked(gtx) && !running && wait <= 0 {
		v.check.start(v.ctl.settings())
		v.reportMsg = ""
	}
	if v.copyReport.Clicked(gtx) && res != nil {
		gtx.Execute(clipboard.WriteCmd{Type: "application/text", Data: io.NopCloser(strings.NewReader(v.ctl.report(res)))})
		v.reportMsg = "Отчёт скопирован."
	}
	if v.openIssue.Clicked(gtx) && v.open != nil {
		v.open(issueURL)
	}
	if v.applyCheck.Clicked(gtx) && res != nil && res.Recommend != nil {
		rec := *res.Recommend
		go func() {
			if err := v.ctl.apply(rec); err == nil {
				v.saveMsg, v.saveErr = "Рекомендация применена и сохранена.", false
				v.draftFor = 0
			} else {
				v.saveMsg, v.saveErr = err.Error(), true
			}
			changes.Add(1)
		}()
	}
	sections := []layout.Widget{
		func(gtx C) D { return v.checkCard(gtx, running, lines, res, wait) },
		v.themeCard,
		v.adapterCard,
		v.fakeCard,
		v.advancedCard,
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		v.title("Настройки"),
		layout.Flexed(1, func(gtx C) D {
			return v.list(gtx, &v.page, len(sections), func(gtx C, i int) D {
				return layout.Inset{Bottom: 12, Right: 10}.Layout(gtx, sections[i])
			})
		}),
		vspace(10),
		layout.Rigid(func(gtx C) D {
			msgC := colGreen
			if v.saveErr {
				msgC = colRed
			}
			return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx C) D { return v.button(gtx, &v.save, "Сохранить", true, true) }),
				hspace(10),
				layout.Rigid(func(gtx C) D { return v.button(gtx, &v.reset, "Отменить изменения", false, true) }),
				hspace(14),
				layout.Flexed(1, v.label(13, msgC, v.saveMsg).Layout))
		}))
}

func (v *view) sectionTitle(s, hint string) []layout.FlexChild {
	kids := []layout.FlexChild{layout.Rigid(bold(v.label(15, colText, s)).Layout)}
	if hint != "" {
		kids = append(kids, vspace(4), layout.Rigid(v.label(12, colMuted, hint).Layout))
	}
	return append(kids, vspace(12))
}

func (v *view) checkCard(gtx C, running bool, lines []string, res *checkResult, wait time.Duration) D {
	return v.card(gtx, func(gtx C) D {
		kids := v.sectionTitle("Проверка провайдера", "Сохраняет ли роутер порт, есть ли заморозка, какие фейк и TTL подходят. "+
			"Около 1–3 минут, пробы с паузами, чтобы не насторожить провайдера.")
		label := "Проверить"
		enabled := !running && wait <= 0
		if running {
			label = "Идёт проверка…"
		} else if wait > 0 {
			label = fmt.Sprintf("Снова можно через %d с", int(wait.Seconds())+1)
		}
		kids = append(kids, layout.Rigid(func(gtx C) D {
			return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx C) D { return v.button(gtx, &v.runCheck, label, false, enabled) }),
				hspace(10),
				layout.Rigid(func(gtx C) D {
					if res == nil || res.Recommend == nil || running {
						return D{}
					}
					return v.button(gtx, &v.applyCheck, "Применить", true, true)
				}))
		}))
		if len(lines) > 0 {
			show := lines
			if len(show) > 14 {
				show = show[len(show)-14:]
			}
			kids = append(kids, vspace(12))
			for _, l := range show {
				l := l
				kids = append(kids, layout.Rigid(mono(v.label(12, colMuted, l)).Layout))
			}
		}
		if res != nil {
			kids = append(kids, vspace(10))
			for _, l := range res.Summary {
				l := l
				c := colText
				if strings.Contains(l, "МЕНЯЕТ") || strings.Contains(l, "убивает") {
					c = colYellow
				}
				kids = append(kids, layout.Rigid(func(gtx C) D {
					return layout.Inset{Bottom: 3}.Layout(gtx, v.label(13, c, "• "+l).Layout)
				}))
			}
			if !running {
				kids = append(kids, vspace(12), layout.Rigid(func(gtx C) D {
					return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
						layout.Rigid(func(gtx C) D { return v.button(gtx, &v.copyReport, "Скопировать отчёт", false, true) }),
						hspace(10),
						layout.Rigid(func(gtx C) D { return v.button(gtx, &v.openIssue, "Открыть issue на GitHub", false, true) }),
						hspace(12),
						layout.Flexed(1, v.label(13, colGreen, v.reportMsg).Layout))
				}), vspace(6), layout.Rigid(v.label(12, colMuted, "Адресов вашей сети в отчёте нет: серверы показаны городами. "+
					"Вставьте отчёт в issue и впишите провайдера и город — отчёты от разных провайдеров помогают подобрать настройки.").Layout))
			}
		}
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, kids...)
	})
}

func (v *view) themeCard(gtx C) D {
	return v.card(gtx, func(gtx C) D {
		kids := v.sectionTitle("Оформление", "")
		kids = append(kids, layout.Rigid(func(gtx C) D {
			return layout.Flex{}.Layout(gtx,
				v.radio("system", "Как в Windows", &v.theme), hspace(18),
				v.radio("dark", "Тёмная", &v.theme), hspace(18),
				v.radio("light", "Светлая", &v.theme))
		}))
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, kids...)
	})
}

func (v *view) radio(key, text string, group *widget.Enum) layout.FlexChild {
	return layout.Rigid(func(gtx C) D {
		rb := material.RadioButton(v.th, group, key, text)
		rb.Color, rb.IconColor, rb.Size = colText, colGreen, unit.Dp(20)
		return rb.Layout(gtx)
	})
}

func (v *view) adapterCard(gtx C) D {
	auto := "Автоматически"
	if info, err := physical(""); err == nil {
		auto = fmt.Sprintf("Автоматически (сейчас «%s»)", info.Alias)
	}
	return v.card(gtx, func(gtx C) D {
		kids := v.sectionTitle("Сетевой адаптер", "Через какой адаптер fnport выходит в интернет.")
		kids = append(kids, v.radio("", auto, &v.adapter))
		for _, a := range v.adapters {
			s := a.Alias
			if a.Desc != "" {
				s += " — " + a.Desc
			}
			if a.Tunnel {
				s += " (похоже на VPN)"
			}
			kids = append(kids, v.radio(a.Alias, s, &v.adapter))
		}
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, kids...)
	})
}

func (v *view) fakeCard(gtx C) D {
	return v.card(gtx, func(gtx C) D {
		kids := v.sectionTitle("Фейк", "Файлы из папки fakes рядом с программой. Выбранный — основной, остальные — запасные.")
		kids = append(kids, v.radio("", "Без фейка", &v.fake))
		for _, f := range v.fakeFiles {
			kids = append(kids, v.radio(f.Name, fmt.Sprintf("%s   (%s)", fakes.Label(f.Name), f.Name), &v.fake))
		}
		kids = append(kids, vspace(12), layout.Rigid(func(gtx C) D {
			return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(v.label(14, colText, "TTL фейка").Layout),
				hspace(14),
				layout.Rigid(func(gtx C) D { return v.button(gtx, &v.ttlMinus, "−", false, v.ttl > 1) }),
				layout.Rigid(func(gtx C) D {
					return layout.Inset{Left: 14, Right: 14}.Layout(gtx, bold(v.label(16, colText, fmt.Sprint(v.ttl))).Layout)
				}),
				layout.Rigid(func(gtx C) D { return v.button(gtx, &v.ttlPlus, "+", false, v.ttl < 32) }),
				layout.Flexed(1, func(gtx C) D { return D{Size: image.Pt(gtx.Constraints.Min.X, 0)} }),
				layout.Rigid(func(gtx C) D { return v.button(gtx, &v.openFakes, "Открыть папку", false, true) }))
		}))
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, kids...)
	})
}

// field: an editor on a dark rounded background
func (v *view) field(gtx C, e *widget.Editor, hint string, minLines int) D {
	return layout.Background{}.Layout(gtx,
		func(gtx C) D { return fill(gtx, colField, gtx.Dp(8)) },
		func(gtx C) D {
			return layout.UniformInset(unit.Dp(10)).Layout(gtx, func(gtx C) D {
				ed := material.Editor(v.th, e, hint)
				ed.Color, ed.HintColor, ed.SelectionColor = colText, colGray, color.NRGBA{colGreen.R, colGreen.G, colGreen.B, 0x55}
				ed.TextSize = unit.Sp(13)
				ed.Font.Typeface = fonts.Mono
				gtx.Constraints.Min.X = gtx.Constraints.Max.X
				gtx.Constraints.Min.Y = gtx.Dp(unit.Dp(18 * minLines))
				return ed.Layout(gtx)
			})
		})
}

func (v *view) advancedCard(gtx C) D {
	labeled := func(name string, w layout.Widget) layout.FlexChild {
		return layout.Rigid(func(gtx C) D {
			return layout.Inset{Bottom: 12}.Layout(gtx, func(gtx C) D {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(v.label(13, colMuted, name).Layout),
					vspace(6),
					layout.Rigid(w))
			})
		})
	}
	small := func(name string, e *widget.Editor) layout.FlexChild {
		return layout.Flexed(1, func(gtx C) D {
			return layout.Inset{Right: 10}.Layout(gtx, func(gtx C) D {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(v.label(13, colMuted, name).Layout),
					vspace(6),
					layout.Rigid(func(gtx C) D { return v.field(gtx, e, "", 1) }))
			})
		})
	}
	return v.card(gtx, func(gtx C) D {
		kids := v.sectionTitle("Дополнительно", "Менять, только если понимаете зачем. «Отменить изменения» вернёт сохранённое.")
		kids = append(kids,
			labeled("Сети, которые идут через fnport (по одной в строке)", func(gtx C) D { return v.field(gtx, &v.routes, "3.0.0.0/8", 6) }),
			labeled("Порты игровых серверов", func(gtx C) D { return v.field(gtx, &v.ports, "9000-9999, 15000-15999", 1) }),
			layout.Rigid(func(gtx C) D {
				return layout.Flex{}.Layout(gtx,
					small("Портов за раунд", &v.batch),
					small("Раундов на соединение", &v.rounds),
					small("Проверок в минуту", &v.budget))
			}),
			vspace(12),
			layout.Rigid(func(gtx C) D {
				cb := material.CheckBox(v.th, &v.passthru, "Только пропуск через адаптер, без проверок и фейка (их делает fnport на роутере)")
				cb.Color, cb.IconColor, cb.Size = colText, colGreen, unit.Dp(20)
				return cb.Layout(gtx)
			}))
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, kids...)
	})
}

func pushOffset(gtx C, x, y int) op.TransformStack {
	return op.Offset(image.Pt(x, y)).Push(gtx.Ops)
}

// ---- smooth scrolling: a wheel notch moves a list by 120 px at once; here it glides

type smoothScroll struct {
	remain float32 // pixels still to scroll
}

func (v *view) scrollOf(l *widget.List) *smoothScroll {
	if v.scrolls == nil {
		v.scrolls = map[*widget.List]*smoothScroll{}
	}
	ss := v.scrolls[l]
	if ss == nil {
		ss = &smoothScroll{}
		v.scrolls[l] = ss
	}
	return ss
}

// list lays out a scrollable list whose mouse wheel glides over a few frames
func (v *view) list(gtx C, l *widget.List, n int, el layout.ListElement) D {
	ss := v.scrollOf(l)
	for {
		ev, ok := gtx.Event(pointer.Filter{Target: ss, Kinds: pointer.Scroll, ScrollY: pointer.ScrollRange{Min: -1 << 20, Max: 1 << 20}})
		if !ok {
			break
		}
		if e, ok := ev.(pointer.Event); ok && e.Kind == pointer.Scroll {
			ss.remain += e.Scroll.Y
		}
	}
	first, off := l.Position.First, l.Position.Offset
	if ss.remain != 0 {
		// a third of what is left each frame: fast at first, soft at the end
		step := ss.remain / 3
		if math.Abs(float64(step)) < 1 {
			step = ss.remain
		}
		px := int(math.Round(float64(step)))
		if px == 0 {
			px = int(math.Copysign(1, float64(ss.remain)))
		}
		l.Position.Offset += px
		ss.remain -= float32(px)
		if math.Abs(float64(ss.remain)) < 0.5 {
			ss.remain = 0
		}
		if px < 0 {
			l.Position.BeforeEnd = true // a list that sticks to its end must let go when scrolled up
		}
		v.animating = true
	}
	d := material.List(v.th, l).Layout(gtx, n, el)
	// the list stopped at an end: drop the rest
	if ss.remain != 0 && l.Position.First == first && l.Position.Offset == off {
		ss.remain = 0
	}
	// the wheel area on top of the list takes the whole scroll, so the list's own scrolling never
	// sees the wheel; pass-through, or it would also swallow every click on what lies under it
	defer clip.Rect{Max: d.Size}.Push(gtx.Ops).Pop()
	defer pointer.PassOp{}.Push(gtx.Ops).Pop()
	event.Op(gtx.Ops, ss)
	return d
}
