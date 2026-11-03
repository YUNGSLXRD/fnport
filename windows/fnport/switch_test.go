package main

import (
	"gioui.org/f32"
	"gioui.org/io/input"
	"gioui.org/io/pointer"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/unit"
	"gioui.org/widget"
	"image"
	"testing"
	"time"
)

func TestSwitchAnimationAndReversal(t *testing.T) {
	var a switchMotion
	now := time.Now()
	a.at(now, false)
	start, active := a.at(now, true)
	if start != 0 || !active {
		t.Fatal("switch jumped to enabled")
	}
	mid, active := a.at(now.Add(70*time.Millisecond), true)
	if mid <= 0 || mid >= 1 || !active {
		t.Fatal("no intermediate switch position")
	}
	reverse, _ := a.at(now.Add(70*time.Millisecond), false)
	if reverse != mid {
		t.Fatal("reversal jumped")
	}
	end, active := a.at(now.Add(70*time.Millisecond+switchDuration), false)
	if end != 0 || active {
		t.Fatal("animation did not settle")
	}
}
func TestSwitchWholeRowClickable(t *testing.T) {
	v := newView(newController(defaultSettings()), &pinger{}, &checker{}, nil, func() {})
	r := new(input.Router)
	state := new(widget.Bool)
	frame := func(disabled bool) {
		ops := new(op.Ops)
		gtx := layout.Context{Ops: ops, Source: r.Source(), Now: time.Now(), Metric: unit.Metric{PxPerDp: 1, PxPerSp: 1}, Constraints: layout.Exact(image.Pt(350, 60))}
		if disabled {
			gtx = gtx.Disabled()
		}
		v.switchRow(gtx, state, "Epic", "Вход и магазин")
		r.Frame(ops)
	}
	click := func() {
		p := f32.Pt(20, 20)
		r.Queue(pointer.Event{Kind: pointer.Press, Source: pointer.Mouse, Buttons: pointer.ButtonPrimary, Position: p}, pointer.Event{Kind: pointer.Release, Source: pointer.Mouse, Position: p})
	}
	frame(false)
	click()
	frame(false)
	if !state.Value {
		t.Fatal("label did not toggle switch")
	}
	frame(true)
	click()
	frame(true)
	if !state.Value {
		t.Fatal("disabled row reacted")
	}
}
