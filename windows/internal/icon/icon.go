// Package icon draws fnport's icon: a power symbol on a dark rounded square, in the colour of
// the state (the exe and window icon are the green one).
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
	bg     = color.NRGBA{0x0f, 0x17, 0x2a, 0xff}
)

// Draw renders the icon at size×size with 4×4 supersampling
func Draw(size int, accent color.NRGBA) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	s := float64(size)
	c := s / 2
	corner := s * 0.22
	R, w := s*0.27, s*0.095 // ring radius and stroke
	const n = 4
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			var inBg, inFg int
			for sy := 0; sy < n; sy++ {
				for sx := 0; sx < n; sx++ {
					x := float64(px) + (float64(sx)+0.5)/n
					y := float64(py) + (float64(sy)+0.5)/n
					if !inRoundRect(x, y, s, corner) {
						continue
					}
					inBg++
					dx, dy := x-c, y-c
					r := math.Hypot(dx, dy)
					// the ring, open at the top
					ang := math.Abs(math.Atan2(dx, -dy)) // 0 at the top
					ring := math.Abs(r-R) <= w/2 && ang > 0.62
					// round ends of the ring's gap
					for _, sgn := range []float64{-1, 1} {
						ex, ey := c+sgn*R*math.Sin(0.62), c-R*math.Cos(0.62)
						if math.Hypot(x-ex, y-ey) <= w/2 {
							ring = true
						}
					}
					// the bar from above the ring down to its middle, round ends
					top, bot := c-R-w*0.35, c-R*0.15
					bar := math.Abs(dx) <= w/2 && y >= top && y <= bot ||
						math.Hypot(dx, y-top) <= w/2 || math.Hypot(dx, y-bot) <= w/2
					if ring || bar {
						inFg++
					}
				}
			}
			if inBg == 0 {
				continue
			}
			// foreground over background, coverage as alpha of the whole pixel
			f := float64(inFg) / float64(inBg)
			mix := func(a, b uint8) uint8 { return uint8(float64(a)*(1-f) + float64(b)*f + 0.5) }
			img.SetNRGBA(px, py, color.NRGBA{mix(bg.R, accent.R), mix(bg.G, accent.G), mix(bg.B, accent.B),
				uint8(float64(inBg)/(n*n)*255 + 0.5)})
		}
	}
	return img
}

func inRoundRect(x, y, s, r float64) bool {
	cx := math.Max(r, math.Min(s-r, x))
	cy := math.Max(r, math.Min(s-r, y))
	return math.Hypot(x-cx, y-cy) <= r
}

// PNG: the icon as PNG bytes
func PNG(size int, accent color.NRGBA) []byte {
	var b bytes.Buffer
	png.Encode(&b, Draw(size, accent))
	return b.Bytes()
}
