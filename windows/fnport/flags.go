package main

import (
	"image"
	"image/color"
	"math"

	"gioui.org/f32"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
)

// Small country flags drawn as shapes: Windows has no flag emoji, and the program's font none.
// The countries of Epic's European servers and of Cloudflare's points near Russia.

type flagSpec struct {
	stripes  []color.NRGBA // equal stripes
	vertical bool
	cross    []color.NRGBA // Nordic cross: background, cross[, inner cross]
	draw     func(gtx C, w, h float32)
}

var (
	fWhite = rgb(0xffffff)
	fRed   = rgb(0xd52b1e)
	fBlue  = rgb(0x0039a6)
)

var flags = map[string]flagSpec{
	"DE": {stripes: []color.NRGBA{rgb(0x000000), rgb(0xdd0000), rgb(0xffce00)}},
	"NL": {stripes: []color.NRGBA{rgb(0xae1c28), fWhite, rgb(0x21468b)}},
	"RU": {stripes: []color.NRGBA{fWhite, fBlue, fRed}},
	"AT": {stripes: []color.NRGBA{rgb(0xc8102e), fWhite, rgb(0xc8102e)}},
	"LT": {stripes: []color.NRGBA{rgb(0xfdb913), rgb(0x006a44), rgb(0xc1272d)}},
	"EE": {stripes: []color.NRGBA{rgb(0x0072ce), rgb(0x000000), fWhite}},
	"LV": {stripes: []color.NRGBA{rgb(0x9e3039), rgb(0x9e3039), fWhite, rgb(0x9e3039), rgb(0x9e3039)}},
	"BG": {stripes: []color.NRGBA{fWhite, rgb(0x00966e), rgb(0xd62612)}},
	"HU": {stripes: []color.NRGBA{rgb(0xce2939), fWhite, rgb(0x477050)}},
	"UA": {stripes: []color.NRGBA{rgb(0x0057b7), rgb(0xffd700)}},
	"PL": {stripes: []color.NRGBA{fWhite, rgb(0xdc143c)}},
	"LU": {stripes: []color.NRGBA{rgb(0xed2939), fWhite, rgb(0x00a1de)}},
	"AM": {stripes: []color.NRGBA{rgb(0xd90012), rgb(0x0033a0), rgb(0xf2a800)}},
	"FR": {stripes: []color.NRGBA{rgb(0x0055a4), fWhite, rgb(0xef4135)}, vertical: true},
	"IT": {stripes: []color.NRGBA{rgb(0x009246), fWhite, rgb(0xce2b37)}, vertical: true},
	"IE": {stripes: []color.NRGBA{rgb(0x169b62), fWhite, rgb(0xff883e)}, vertical: true},
	"BE": {stripes: []color.NRGBA{rgb(0x000000), rgb(0xfae042), rgb(0xed2939)}, vertical: true},
	"RO": {stripes: []color.NRGBA{rgb(0x002b7f), rgb(0xfcd116), rgb(0xce1126)}, vertical: true},
	"SE": {cross: []color.NRGBA{rgb(0x006aa7), rgb(0xfecc00)}},
	"FI": {cross: []color.NRGBA{fWhite, rgb(0x002f6c)}},
	"DK": {cross: []color.NRGBA{rgb(0xc8102e), fWhite}},
	"NO": {cross: []color.NRGBA{rgb(0xba0c2f), fWhite, rgb(0x00205b)}},
	"CH": {draw: drawSwiss},
	"GB": {draw: drawUK},
	"EU": {draw: drawEU},
	"US": {draw: drawUS},
	"ES": {draw: func(gtx C, w, h float32) {
		rect(gtx, 0, 0, w, h, rgb(0xaa151b))
		rect(gtx, 0, h/4, w, h*3/4, rgb(0xf1bf00))
	}},
	"KZ": {draw: func(gtx C, w, h float32) {
		rect(gtx, 0, 0, w, h, rgb(0x00afca))
		disc(gtx, w/2, h/2, h*0.22, rgb(0xfec50c))
	}},
	"TR": {draw: func(gtx C, w, h float32) {
		rect(gtx, 0, 0, w, h, rgb(0xe30a17))
		disc(gtx, w*0.4, h/2, h*0.25, fWhite)
		disc(gtx, w*0.45, h/2, h*0.2, rgb(0xe30a17))
	}},
	"CZ": {draw: func(gtx C, w, h float32) {
		rect(gtx, 0, 0, w, h/2, fWhite)
		rect(gtx, 0, h/2, w, h, rgb(0xd7141a))
		var p clip.Path
		p.Begin(gtx.Ops)
		p.MoveTo(f32.Pt(0, 0))
		p.LineTo(f32.Pt(w/2, h/2))
		p.LineTo(f32.Pt(0, h))
		p.Close()
		paint.FillShape(gtx.Ops, rgb(0x11457e), clip.Outline{Path: p.End()}.Op())
	}},
}

// cityCountry: the country of a city as the program names it
var cityCountry = map[string]string{"Франкфурт": "DE", "Лондон": "GB", "Париж": "FR", "Европа": "EU"}

func rect(gtx C, x0, y0, x1, y1 float32, c color.NRGBA) {
	paint.FillShape(gtx.Ops, c, clip.Rect{Min: image.Pt(int(x0+0.5), int(y0+0.5)), Max: image.Pt(int(x1+0.5), int(y1+0.5))}.Op())
}

func disc(gtx C, x, y, r float32, c color.NRGBA) {
	paint.FillShape(gtx.Ops, c, clip.Ellipse{Min: image.Pt(int(x-r), int(y-r)), Max: image.Pt(int(x+r+0.5), int(y+r+0.5))}.Op(gtx.Ops))
}

func strokeLine(gtx C, x0, y0, x1, y1, width float32, c color.NRGBA) {
	var p clip.Path
	p.Begin(gtx.Ops)
	p.MoveTo(f32.Pt(x0, y0))
	p.LineTo(f32.Pt(x1, y1))
	paint.FillShape(gtx.Ops, c, clip.Stroke{Path: p.End(), Width: width}.Op())
}

func drawSwiss(gtx C, w, h float32) {
	rect(gtx, 0, 0, w, h, rgb(0xda291c))
	a := h * 0.18
	rect(gtx, w/2-a/2, h*0.2, w/2+a/2, h*0.8, fWhite)
	rect(gtx, w/2-h*0.3, h/2-a/2, w/2+h*0.3, h/2+a/2, fWhite)
}

func drawUK(gtx C, w, h float32) {
	blue, red := rgb(0x012169), rgb(0xc8102e)
	rect(gtx, 0, 0, w, h, blue)
	strokeLine(gtx, 0, 0, w, h, h*0.2, fWhite)
	strokeLine(gtx, w, 0, 0, h, h*0.2, fWhite)
	strokeLine(gtx, 0, 0, w, h, h*0.07, red)
	strokeLine(gtx, w, 0, 0, h, h*0.07, red)
	rect(gtx, w/2-h*0.17, 0, w/2+h*0.17, h, fWhite)
	rect(gtx, 0, h/2-h*0.17, w, h/2+h*0.17, fWhite)
	rect(gtx, w/2-h*0.1, 0, w/2+h*0.1, h, red)
	rect(gtx, 0, h/2-h*0.1, w, h/2+h*0.1, red)
}

func drawEU(gtx C, w, h float32) {
	rect(gtx, 0, 0, w, h, rgb(0x003399))
	for i := 0; i < 12; i++ {
		a := float64(i) * math.Pi / 6
		disc(gtx, w/2+h*0.3*float32(math.Sin(a)), h/2-h*0.3*float32(math.Cos(a)), h*0.055, rgb(0xffcc00))
	}
}

func drawUS(gtx C, w, h float32) {
	for i := 0; i < 7; i++ {
		c := rgb(0xb22234)
		if i%2 == 1 {
			c = fWhite
		}
		rect(gtx, 0, h*float32(i)/7, w, h*float32(i+1)/7, c)
	}
	rect(gtx, 0, 0, w*0.42, h*4/7, rgb(0x3c3b6e))
}

// drawFlag: a flag 1.5:1 with rounded corners; nothing for a country without one here
func drawFlag(gtx C, code string, height unit.Dp) D {
	f, ok := flags[code]
	if !ok {
		return D{}
	}
	hh := gtx.Dp(height)
	ww := hh * 3 / 2
	w, h := float32(ww), float32(hh)
	defer clip.UniformRRect(image.Rect(0, 0, ww, hh), gtx.Dp(2)).Push(gtx.Ops).Pop()
	switch {
	case f.draw != nil:
		f.draw(gtx, w, h)
	case f.cross != nil:
		rect(gtx, 0, 0, w, h, f.cross[0])
		t := h * 0.22
		cx := w * 0.36
		rect(gtx, cx-t/2, 0, cx+t/2, h, f.cross[1])
		rect(gtx, 0, h/2-t/2, w, h/2+t/2, f.cross[1])
		if len(f.cross) > 2 {
			t2 := t * 0.5
			rect(gtx, cx-t2/2, 0, cx+t2/2, h, f.cross[2])
			rect(gtx, 0, h/2-t2/2, w, h/2+t2/2, f.cross[2])
		}
	default:
		n := float32(len(f.stripes))
		for i, c := range f.stripes {
			a, b := float32(i)/n, float32(i+1)/n
			if f.vertical {
				rect(gtx, w*a, 0, w*b, h, c)
			} else {
				rect(gtx, 0, h*a, w, h*b, c)
			}
		}
	}
	// a hairline edge so white stripes do not melt into a light card
	paint.FillShape(gtx.Ops, color.NRGBA{A: 0x30}, clip.Stroke{Path: clip.UniformRRect(image.Rect(0, 0, ww, hh), gtx.Dp(2)).Path(gtx.Ops), Width: 1}.Op())
	return D{Size: image.Pt(ww, hh)}
}

// Cloudflare's points (airport codes) near Russia and in Europe, and the countries
var coloCity = map[string]string{
	"FRA": "Франкфурт", "AMS": "Амстердам", "ARN": "Стокгольм", "HEL": "Хельсинки", "WAW": "Варшава",
	"LHR": "Лондон", "MAN": "Манчестер", "CDG": "Париж", "MRS": "Марсель", "DME": "Москва", "SVO": "Москва",
	"LED": "Санкт-Петербург", "KJA": "Красноярск", "SVX": "Екатеринбург", "OVB": "Новосибирск", "KZN": "Казань",
	"RIX": "Рига", "TLL": "Таллин", "VNO": "Вильнюс", "PRG": "Прага", "VIE": "Вена", "MUC": "Мюнхен",
	"DUS": "Дюссельдорф", "HAM": "Гамбург", "BER": "Берлин", "TXL": "Берлин", "STR": "Штутгарт",
	"CPH": "Копенгаген", "OSL": "Осло", "MAD": "Мадрид", "BCN": "Барселона", "MXP": "Милан", "FCO": "Рим",
	"ZRH": "Цюрих", "GVA": "Женева", "KBP": "Киев", "OTP": "Бухарест", "SOF": "София", "BUD": "Будапешт",
	"IST": "Стамбул", "ALA": "Алматы", "NQZ": "Астана", "TBS": "Тбилиси", "EVN": "Ереван", "DUB": "Дублин",
	"BRU": "Брюссель", "LUX": "Люксембург", "KIV": "Кишинёв", "MSQ": "Минск",
}

var countryRU = map[string]string{
	"DE": "Германия", "NL": "Нидерланды", "SE": "Швеция", "FI": "Финляндия", "PL": "Польша", "GB": "Великобритания",
	"FR": "Франция", "RU": "Россия", "LV": "Латвия", "EE": "Эстония", "LT": "Литва", "CZ": "Чехия", "AT": "Австрия",
	"DK": "Дания", "NO": "Норвегия", "ES": "Испания", "IT": "Италия", "CH": "Швейцария", "UA": "Украина",
	"RO": "Румыния", "BG": "Болгария", "HU": "Венгрия", "TR": "Турция", "KZ": "Казахстан", "GE": "Грузия",
	"AM": "Армения", "IE": "Ирландия", "BE": "Бельгия", "LU": "Люксембург", "US": "США",
}
