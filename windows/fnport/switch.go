package main

import (
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"
	"image"
	"time"
)

const switchDuration = 170 * time.Millisecond

type switchMotion struct {
	from, to float64
	start    time.Time
	ready    bool
}

func (a *switchMotion) at(now time.Time, on bool) (float64, bool) {
	target := float64(0)
	if on {
		target = 1
	}
	if !a.ready {
		a.from, a.to, a.start, a.ready = target, target, now, true
	}
	value := func() float64 {
		t := float64(now.Sub(a.start)) / float64(switchDuration)
		if t >= 1 {
			return a.to
		}
		if t < 0 {
			t = 0
		}
		return a.from + (a.to-a.from)*easeOut(t)
	}
	if target != a.to {
		a.from = value()
		a.to = target
		a.start = now
	}
	t := float64(now.Sub(a.start)) / float64(switchDuration)
	return value(), t < 1 && a.from != a.to
}

// The label and switch form one hit target; state and animation stay on the UI thread.
func (v *view) switchRow(gtx C, state *widget.Bool, label, detail string) D {
	state.Update(gtx)
	if v.switches == nil {
		v.switches = map[*widget.Bool]*switchMotion{}
	}
	a := v.switches[state]
	if a == nil {
		a = &switchMotion{}
		v.switches[state] = a
	}
	t, active := a.at(gtx.Now, state.Value)
	if active {
		v.animating = true
		gtx.Execute(op.InvalidateCmd{})
	}
	return state.Layout(gtx, func(gtx C) D {
		return layout.Inset{Top: 9, Bottom: 9}.Layout(gtx, func(gtx C) D {
			return layout.Flex{Alignment: layout.Middle}.Layout(gtx, layout.Flexed(1, func(gtx C) D {
				kids := []layout.FlexChild{layout.Rigid(v.label(14, colText, label).Layout)}
				if detail != "" {
					kids = append(kids, vspace(3), layout.Rigid(v.label(12, colMuted, detail).Layout))
				}
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx, kids...)
			}), hspace(20), layout.Rigid(func(gtx C) D {
				w, h := gtx.Dp(40), gtx.Dp(24)
				track := mix(colGray, colGreen, t)
				if !gtx.Enabled() {
					track = mix(track, colCard, 0.45)
				}
				shape := clip.UniformRRect(image.Rect(0, 0, w, h), h/2)
				paint.FillShape(gtx.Ops, track, shape.Op(gtx.Ops))
				r := gtx.Dp(unit.Dp(9))
				pad := gtx.Dp(3)
				x := pad + int(float64(w-2*pad-2*r)*t)
				y := (h - 2*r) / 2
				paint.FillShape(gtx.Ops, rgb(0xffffff), clip.Ellipse{Min: image.Pt(x, y), Max: image.Pt(x+2*r, y+2*r)}.Op(gtx.Ops))
				return D{Size: image.Pt(w, h)}
			}))
		})
	})
}
