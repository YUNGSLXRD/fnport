package wnet

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Wintun is loaded from the program's own folder only. Users ran fnport.exe straight from the
// zip (Windows unpacks the exe alone) or an antivirus took the DLL away, and got
// "Error loading wintun.dll DLL"; these say what to do instead.

const wintunUnpack = "распакуйте архив целиком в обычную папку и запускайте fnport.exe оттуда, не из архива. " +
	"Если файл пропадает после распаковки, его убирает антивирус: верните его из карантина и добавьте папку в исключения."

// WintunProblem: why the adapter cannot be made from dir, or "" when wintun.dll is there
func WintunProblem(dir string) string {
	st, err := os.Stat(filepath.Join(dir, "wintun.dll"))
	switch {
	case err == nil && st.Size() > 0:
		return ""
	case err == nil || errors.Is(err, os.ErrNotExist):
		return "Рядом с fnport.exe нет wintun.dll: " + wintunUnpack
	}
	return fmt.Sprintf("wintun.dll рядом с fnport.exe не читается (%v): %s", err, wintunUnpack)
}

// WintunMissing: WintunProblem for the running program's folder
func WintunMissing() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return WintunProblem(filepath.Dir(exe))
}

// wintunErr explains a failure to load the DLL that is there (damaged, blocked, another architecture)
func wintunErr(err error) error {
	if !strings.Contains(strings.ToLower(err.Error()), "wintun.dll") {
		return fmt.Errorf("адаптер Wintun не создан: %w", err)
	}
	return fmt.Errorf("wintun.dll не загрузился (%w): %s", err, wintunUnpack)
}
