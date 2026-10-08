package main

import (
	"fmt"
	"image"
	"image/color"
	"strings"

	"gioui.org/font"
	"gioui.org/font/gofont"
	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	"github.com/YUNGSLXRD/fnport/windows/internal/geo"
)

// What the window draws. The window itself (gui_windows.go) exists only while open; this part
// draws a frame from the controller's state and does nothing between frames.

type (
	C = layout.Context
	D = layout.Dimensions
)

var (
	colBg      = rgb(0x0b1220)
	colCard    = rgb(0x111a2e)
	colLine    = rgb(0x1e293b)
	colText    = rgb(0xe2e8f0)
	colMuted   = rgb(0x94a3b8)
	colGreen   = rgb(0x22c55e)
	colYellow  = rgb(0xeab308)
	colRed     = rgb(0xef4444)
	colGray    = rgb(0x475569)
	colOffBtn  = rgb(0x1f2a40)
	colGreenHi = rgb(0x16a34a)
)

func rgb(v uint32) color.NRGBA {
	return color.NRGBA{R: uint8(v >> 16), G: uint8(v >> 8), B: uint8(v), A: 0xff}
}

type tab int

const (
	tabMain tab = iota
	tabSummary
	tabLog
)

type view struct {
	ctl    *controller
	ping   *pinger
	onQuit func()

	th    *material.Theme
	tab   tab
	tabs  [3]widget.Clickable
	power widget.Clickable
	quit  widget.Clickable
	list  widget.List
	logs  widget.List
}

func newView(ctl *controller, ping *pinger, onQuit func()) *view {
	th := material.NewTheme()
	th.Shaper = text.NewShaper(text.WithCollection(gofont.Collection()))
	th.Palette = material.Palette{Bg: colBg, Fg: colText, ContrastBg: colGreen, ContrastFg: colBg}
	th.TextSize = unit.Sp(14)
	v := &view{ctl: ctl, ping: ping, onQuit: onQuit, th: th}
	v.list.Axis = layout.Vertical
	v.logs.Axis = layout.Vertical
	v.logs.ScrollToEnd = true
	return v
}

// ---- drawing helpers

func fill(gtx C, c color.NRGBA, r int) D {
	sz := gtx.Constraints.Min
	paint.FillShape(gtx.Ops, c, clip.UniformRRect(image.Rectangle{Max: sz}, r).Op(gtx.Ops))
	return D{Size: sz}
}

func (v *view) card(gtx C, w layout.Widget) D {
	return layout.Background{}.Layout(gtx,
		func(gtx C) D { return fill(gtx, colCard, gtx.Dp(12)) },
		func(gtx C) D { return layout.UniformInset(unit.Dp(16)).Layout(gtx, w) })
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

func dot(gtx C, c color.NRGBA, d unit.Dp) D {
	s := gtx.Dp(d)
	paint.FillShape(gtx.Ops, c, clip.Ellipse{Max: image.Pt(s, s)}.Op(gtx.Ops))
	return D{Size: image.Pt(s, s)}
}

// row: a dot and a label, centred on each other
func (v *view) dotLabel(gtx C, c color.NRGBA, l material.LabelStyle) D {
	return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
		layout.Rigid(func(gtx C) D { return dot(gtx, c, 8) }),
		layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
		layout.Rigid(l.Layout))
}

var vspace = func(dp unit.Dp) layout.FlexChild { return layout.Rigid(layout.Spacer{Height: dp}.Layout) }

// ---- the frame

func (v *view) frame(gtx C) {
	for i := range v.tabs {
		if v.tabs[i].Clicked(gtx) {
			v.tab = tab(i)
		}
	}
	if v.power.Clicked(gtx) {
		go v.ctl.toggle()
	}
	if v.quit.Clicked(gtx) {
		go v.onQuit()
	}
	paint.Fill(gtx.Ops, colBg)
	layout.UniformInset(unit.Dp(20)).Layout(gtx, func(gtx C) D {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(v.header),
			vspace(14),
			layout.Rigid(v.tabBar),
			vspace(16),
			layout.Flexed(1, func(gtx C) D {
				switch v.tab {
				case tabSummary:
					return v.summary(gtx)
				case tabLog:
					return v.logTab(gtx)
				}
				return v.mainTab(gtx)
			}))
	})
}

func (v *view) header(gtx C) D {
	st, _ := v.ctl.state()
	c, s := colGray, "Выключено"
	switch st {
	case stateStarting:
		c, s = colYellow, "Включается…"
	case stateOn:
		c, s = colGreen, "Работает"
		if v.ctl.warn() {
			c = colYellow
		}
	}
	return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
		layout.Rigid(bold(v.label(22, colText, "fnport")).Layout),
		layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
		layout.Rigid(v.label(12, colMuted, version).Layout),
		layout.Flexed(1, func(gtx C) D { return D{Size: image.Pt(gtx.Constraints.Min.X, 0)} }),
		layout.Rigid(func(gtx C) D {
			return layout.Background{}.Layout(gtx,
				func(gtx C) D { return fill(gtx, colCard, gtx.Dp(14)) },
				func(gtx C) D {
					return layout.Inset{Top: 6, Bottom: 6, Left: 12, Right: 14}.Layout(gtx, func(gtx C) D {
						return v.dotLabel(gtx, c, v.label(13, colText, s))
					})
				})
		}))
}

func (v *view) tabBar(gtx C) D {
	names := []string{"Главная", "Сводка", "Журнал"}
	var kids []layout.FlexChild
	for i := range names {
		i := i
		kids = append(kids, layout.Rigid(func(gtx C) D {
			return v.tabs[i].Layout(gtx, func(gtx C) D {
				active := v.tab == tab(i)
				c := colMuted
				if active {
					c = colText
				}
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx C) D {
						return layout.Inset{Bottom: 6, Right: 22}.Layout(gtx, v.label(15, c, names[i]).Layout)
					}),
					layout.Rigid(func(gtx C) D {
						if !active {
							return D{Size: image.Pt(0, gtx.Dp(2))}
						}
						sz := image.Pt(gtx.Dp(28), gtx.Dp(2))
						paint.FillShape(gtx.Ops, colGreen, clip.Rect{Max: sz}.Op())
						return D{Size: sz}
					}))
			})
		}))
	}
	return layout.Flex{}.Layout(gtx, kids...)
}

// ---- main tab: the switch, the beacons, the counters

func (v *view) mainTab(gtx C) D {
	ctl := v.ctl
	st, errText := ctl.state()
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx C) D { return v.powerButton(gtx, st) }),
		vspace(8),
		layout.Rigid(func(gtx C) D {
			s := "Игра идёт напрямую, без fnport."
			c := colMuted
			switch st {
			case stateStarting:
				s = "Создаю адаптер…"
			case stateOn:
				s = "Игра идёт через fnport: " + ctl.fakeLabel() + "."
			}
			if errText != "" && st == stateOff {
				s, c = "Не включилось: "+errText, colRed
			}
			return layout.Center.Layout(gtx, v.label(13, c, s).Layout)
		}),
		vspace(16),
		layout.Rigid(v.beaconsCard),
		vspace(12),
		layout.Rigid(v.countersCard),
		layout.Flexed(1, func(gtx C) D { return D{Size: gtx.Constraints.Min} }),
		layout.Rigid(func(gtx C) D {
			return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
				layout.Flexed(1, v.label(12, colMuted, "Крестик сворачивает в трей. Выход — здесь или в меню значка.").Layout),
				layout.Rigid(func(gtx C) D {
					return v.quit.Layout(gtx, func(gtx C) D {
						return layout.Inset{Top: 4, Bottom: 4, Left: 10}.Layout(gtx, v.label(13, colRed, "Выйти").Layout)
					})
				}))
		}))
}

func (v *view) powerButton(gtx C, st state) D {
	bg, fg, s := colGreen, colBg, "Включить"
	switch st {
	case stateStarting:
		bg, fg, s = colOffBtn, colMuted, "Включается…"
	case stateOn:
		bg, fg, s = colOffBtn, colText, "Выключить"
	}
	if v.power.Hovered() && st != stateStarting {
		if st == stateOff {
			bg = colGreenHi
		} else {
			bg = colLine
		}
	}
	return v.power.Layout(gtx, func(gtx C) D {
		gtx.Constraints.Min.X = gtx.Constraints.Max.X
		return layout.Background{}.Layout(gtx,
			func(gtx C) D { return fill(gtx, bg, gtx.Dp(14)) },
			func(gtx C) D {
				return layout.Inset{Top: 16, Bottom: 16}.Layout(gtx, func(gtx C) D {
					return layout.Center.Layout(gtx, bold(v.label(18, fg, s)).Layout)
				})
			})
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

func (v *view) beaconsCard(gtx C) D {
	bs := v.ping.snapshot()
	return v.card(gtx, func(gtx C) D {
		kids := []layout.FlexChild{
			layout.Rigid(bold(v.label(14, colText, "Пинг до серверов Epic")).Layout),
			vspace(10),
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
						layout.Rigid(layout.Spacer{Width: unit.Dp(10)}.Layout),
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
	frozenCol, remapCol := colText, colText
	if s.Frozen > 0 {
		frozenCol = colYellow
	}
	if s.Remaps > 0 {
		remapCol = colYellow
	}
	return v.card(gtx, func(gtx C) D {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(bold(v.label(14, colText, "За этот запуск")).Layout),
			vspace(10),
			layout.Rigid(func(gtx C) D {
				return layout.Flex{}.Layout(gtx,
					stat(fmt.Sprint(s.GameFlows), "соединений игры", colText),
					stat(fmt.Sprintf("%d / %d", s.Good, s.Tested), "годных портов / проверено", colText),
					stat(fmt.Sprint(s.Frozen), "замёрзло", frozenCol),
					stat(fmt.Sprint(s.Remaps), "переводов на новый порт", remapCol))
			}))
	})
}

// ---- summary tab: game servers

var cols = []float32{0.27, 0.15, 0.10, 0.20, 0.10, 0.18}

func (v *view) tableRow(gtx C, cells []material.LabelStyle) D {
	var kids []layout.FlexChild
	for i, c := range cells {
		c := c
		c.MaxLines = 1
		kids = append(kids, layout.Flexed(cols[i], c.Layout))
	}
	return layout.Flex{Alignment: layout.Middle}.Layout(gtx, kids...)
}

func (v *view) summary(gtx C) D {
	flows := v.ctl.flows()
	if len(flows) == 0 {
		return v.card(gtx, func(gtx C) D {
			return v.label(14, colMuted, "Соединений игры пока не было. Включите fnport и зайдите в матч: здесь появятся серверы, "+
				"их города и порты, которые нашёл fnport.").Layout(gtx)
		})
	}
	head := func(s string) material.LabelStyle { return v.label(12, colMuted, s) }
	return v.card(gtx, func(gtx C) D {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx C) D {
				return v.tableRow(gtx, []material.LabelStyle{head("Сервер"), head("Город"), head("Порт"),
					head("Пакеты ↑ / ↓"), head("Начало"), head("Состояние")})
			}),
			vspace(8),
			layout.Rigid(func(gtx C) D {
				sz := image.Pt(gtx.Constraints.Max.X, gtx.Dp(1))
				paint.FillShape(gtx.Ops, colLine, clip.Rect{Max: sz}.Op())
				return D{Size: sz}
			}),
			layout.Flexed(1, func(gtx C) D {
				return material.List(v.th, &v.list).Layout(gtx, len(flows), func(gtx C, i int) D {
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
					text := colText
					if !f.Active {
						text = colMuted
					}
					port := "—"
					if f.Port != 0 {
						port = fmt.Sprint(f.Port)
					}
					return layout.Inset{Top: 7, Bottom: 7}.Layout(gtx, func(gtx C) D {
						return v.tableRow(gtx, []material.LabelStyle{
							v.label(13, text, f.Server.String()),
							v.label(13, text, geo.CityRU(f.Server.Addr())),
							v.label(13, text, port),
							v.label(13, text, fmt.Sprintf("%s / %s", short(f.Out), short(f.In))),
							v.label(13, text, f.Started.Format("15:04")),
							bold(v.label(13, stC, stS)),
						})
					})
				})
			}))
	})
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

// ---- log tab

func (v *view) logTab(gtx C) D {
	lines := logLines()
	return v.card(gtx, func(gtx C) D {
		if len(lines) == 0 {
			return v.label(13, colMuted, "Журнал пуст.").Layout(gtx)
		}
		// stick to the newest line only once the lines fill the card; a short log starts at the top
		v.logs.ScrollToEnd = len(lines)*gtx.Dp(19) > gtx.Constraints.Max.Y
		return material.List(v.th, &v.logs).Layout(gtx, len(lines), func(gtx C, i int) D {
			l := v.label(12, colText, lines[i])
			l.Font.Typeface = "Go Mono"
			if warnLine(lines[i]) {
				l.Color = colYellow
			}
			return layout.Inset{Bottom: 3}.Layout(gtx, l.Layout)
		})
	})
}

// warnLine: log lines worth yellow (a flow froze or moved, a warning, a failure)
func warnLine(l string) bool {
	for _, s := range []string{"замёрзло (", "переведено на порт", "ВНИМАНИЕ", "не включилось", "нет сокета", "ломает"} {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}
