package fonts

import (
	"testing"

	"gioui.org/font"
)

func TestCollection(t *testing.T) {
	var inter, bold, mono bool
	for _, f := range Collection() {
		switch {
		case f.Font.Typeface == UI && f.Font.Weight == font.Normal:
			inter = true
		case f.Font.Typeface == UI && f.Font.Weight == font.SemiBold:
			bold = true
		case f.Font.Typeface == Mono:
			mono = true
		}
	}
	if !inter || !bold || !mono {
		for _, f := range Collection() {
			t.Logf("%q weight %d style %d", f.Font.Typeface, f.Font.Weight, f.Font.Style)
		}
		t.Fatalf("inter %v, semibold %v, mono %v", inter, bold, mono)
	}
}
