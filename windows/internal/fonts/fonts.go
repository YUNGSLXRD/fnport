// Package fonts: Inter (regular and semibold, Latin and Cyrillic; see make.sh) for the window,
// and Go Mono for the log. Inter is under the SIL Open Font License, OFL.txt here.
package fonts

import (
	_ "embed"

	"gioui.org/font"
	"gioui.org/font/gofont"
	"gioui.org/font/opentype"
)

var (
	//go:embed Inter-Regular.ttf
	regular []byte
	//go:embed Inter-SemiBold.ttf
	semibold []byte
)

const (
	UI   font.Typeface = "Inter"
	Mono font.Typeface = "Go Mono"
)

// Collection: the faces the window's text shaper gets
func Collection() []font.FontFace {
	var out []font.FontFace
	for _, b := range [][]byte{regular, semibold} {
		if fs, err := opentype.ParseCollection(b); err == nil {
			out = append(out, fs...)
		}
	}
	for _, f := range gofont.Collection() {
		if f.Font.Typeface == Mono {
			out = append(out, f)
		}
	}
	return out
}
