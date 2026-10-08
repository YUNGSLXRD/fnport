package main

import (
	"image"
	"testing"
	"time"

	"gioui.org/f32"
	"gioui.org/io/input"
	"gioui.org/io/pointer"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/unit"
	"gioui.org/widget"
)

// a list with a button in it: clicks reach the button, the wheel glides the list
func TestListClicksAndWheel(t *testing.T) {
	v := newView(newController(defaultSettings()), &pinger{}, &checker{}, nil, func() {})
	var btn widget.Clickable
	var l widget.List
	l.Axis = layout.Vertical
	r := new(input.Router)
	frame := func() bool {
		ops := new(op.Ops)
		gtx := layout.Context{Ops: ops, Source: r.Source(), Now: time.Now(),
			Metric: unit.Metric{PxPerDp: 1, PxPerSp: 1}, Constraints: layout.Exact(image.Pt(300, 200))}
		clicked := btn.Clicked(gtx)
		v.list(gtx, &l, 20, func(gtx C, i int) D {
			if i == 0 {
				return btn.Layout(gtx, func(gtx C) D { return D{Size: image.Pt(100, 50)} })
			}
			return D{Size: image.Pt(100, 50)}
		})
		r.Frame(ops)
		return clicked
	}
	frame()
	at := f32.Pt(20, 20)
	r.Queue(pointer.Event{Kind: pointer.Press, Source: pointer.Mouse, Buttons: pointer.ButtonPrimary, Position: at},
		pointer.Event{Kind: pointer.Release, Source: pointer.Mouse, Position: at})
	if !frame() {
		t.Fatal("a click on the button inside the list did not reach it")
	}

	r.Queue(pointer.Event{Kind: pointer.Scroll, Source: pointer.Mouse, Position: at, Scroll: f32.Pt(0, 120)})
	frame()
	first := l.Position.Offset
	if first <= 0 || first >= 120 {
		t.Fatalf("after one frame the list moved %d px: it should glide, not jump", first)
	}
	for i := 0; i < 40; i++ {
		frame()
	}
	if got := l.Position.First*50 + l.Position.Offset; got != 120 {
		t.Fatalf("the list ended %d px down, want 120", got)
	}
}
