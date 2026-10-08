// Package icon draws fnport's icon: the letters FP, tall, slanted and gold on a dark rounded
// square, in the spirit of a game logo but its own. The tray adds a dot in the state's colour.
package icon

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math"
)

var (
	Green  = color.NRGBA{0x22, 0xc5, 0x5e, 0xff}
	Yellow = color.NRGBA{0xea, 0xb3, 0x08, 0xff}
	Gray   = color.NRGBA{0x94, 0xa3, 0xb8, 0xff}
	None   = color.NRGBA{} // no dot

	bgTop    = color.NRGBA{0x1a, 0x1d, 0x2e, 0xff}
	bgBottom = color.NRGBA{0x08, 0x09, 0x10, 0xff}
	goldTop  = color.NRGBA{0xff, 0xe4, 0x8f, 0xff}
	goldBot  = color.NRGBA{0xd9, 0x8f, 0x12, 0xff}
	edge     = color.NRGBA{0x08, 0x09, 0x10, 0xff}
)

type pt struct{ x, y float64 }

// letters in a 100x100 box before the slant; P has a hole for its bowl
var (
	letterF = []pt{{14, 22}, {47, 16}, {46, 31}, {28, 33}, {28, 46}, {43, 45}, {42, 58}, {28, 59}, {28, 86}, {14, 87}}
	letterP = []pt{{52, 15}, {77, 13}, {86, 20}, {87, 48}, {80, 56}, {66, 57}, {66, 86}, {52, 87}}
	holeP   = []pt{{66, 27}, {73, 27}, {73, 44}, {66, 45}}
)

// slant leans the letters to the right like an italic
func slant(p pt) pt { return pt{p.x + (50-p.y)*0.13, p.y} }

func inside(poly []pt, x, y float64) bool {
	in := false
	for i, j := 0, len(poly)-1; i < len(poly); j, i = i, i+1 {
		a, b := slant(poly[i]), slant(poly[j])
		if (a.y > y) != (b.y > y) && x < (b.x-a.x)*(y-a.y)/(b.y-a.y)+a.x {
			in = !in
		}
	}
	return in
}

func lerp(a, b color.NRGBA, t float64) color.NRGBA {
	t = math.Max(0, math.Min(1, t))
	m := func(x, y uint8) uint8 { return uint8(float64(x)*(1-t) + float64(y)*t + 0.5) }
	return color.NRGBA{m(a.R, b.R), m(a.G, b.G), m(a.B, b.B), 0xff}
}

// Draw renders the icon at size×size (4×4 supersampling); dot != None adds the state dot
func Draw(size int, dot color.NRGBA) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	k := 100 / float64(size)
	const n = 4
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			var r, g, b, a float64
			for sy := 0; sy < n; sy++ {
				for sx := 0; sx < n; sx++ {
					x := (float64(px) + (float64(sx)+0.5)/n) * k
					y := (float64(py) + (float64(sy)+0.5)/n) * k
					c, ok := sample(x, y, dot)
					if !ok {
						continue
					}
					r, g, b, a = r+float64(c.R), g+float64(c.G), b+float64(c.B), a+1
				}
			}
			if a == 0 {
				continue
			}
			img.SetNRGBA(px, py, color.NRGBA{uint8(r/a + 0.5), uint8(g/a + 0.5), uint8(b/a + 0.5), uint8(a/(n*n)*255 + 0.5)})
		}
	}
	return img
}

// sample: the colour at (x, y) in the 100x100 box; false outside the icon
func sample(x, y float64, dot color.NRGBA) (color.NRGBA, bool) {
	if dot != None {
		const cx, cy, r = 80, 80, 17
		d := math.Hypot(x-cx, y-cy)
		if d <= r {
			return dot, true
		}
		if d <= r+5 {
			return edge, true // a ring of background keeps the dot apart from the letters
		}
	}
	if !inRoundRect(x, y, 100, 22) {
		return color.NRGBA{}, false
	}
	if (inside(letterF, x, y) || inside(letterP, x, y)) && !inside(holeP, x, y) {
		return lerp(goldTop, goldBot, (y-14)/74), true
	}
	return lerp(bgTop, bgBottom, y/100), true
}

func inRoundRect(x, y, s, r float64) bool {
	cx := math.Max(r, math.Min(s-r, x))
	cy := math.Max(r, math.Min(s-r, y))
	return math.Hypot(x-cx, y-cy) <= r
}

// PNG: the icon as PNG bytes
func PNG(size int, dot color.NRGBA) []byte {
	var b bytes.Buffer
	png.Encode(&b, Draw(size, dot))
	return b.Bytes()
}
