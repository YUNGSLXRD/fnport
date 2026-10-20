package main

import (
	_ "embed"
	"os"
	"path/filepath"
)

// licenses.txt: the license texts of everything built into the program and shipped with it (Go
// and its modules, Wintun, the Inter font, the fakes), written by build.sh before the build. The
// zip carries no loose license files; Settings → «Лицензии» shows this text.
//
//go:embed licenses.txt
var licensesText string

// writeLicenses: the texts as a file Notepad can open
func writeLicenses() (string, error) {
	p := filepath.Join(os.TempDir(), "fnport-licenses.txt")
	return p, os.WriteFile(p, []byte(licensesText), 0o644)
}
