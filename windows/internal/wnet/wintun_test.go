package wnet

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWintunProblem(t *testing.T) {
	dir := t.TempDir()
	if p := WintunProblem(dir); !strings.Contains(p, "нет wintun.dll") || !strings.Contains(p, "не из архива") {
		t.Errorf("missing: %q", p)
	}
	// an antivirus may leave the file empty
	dll := filepath.Join(dir, "wintun.dll")
	if err := os.WriteFile(dll, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if p := WintunProblem(dir); !strings.Contains(p, "нет wintun.dll") {
		t.Errorf("empty: %q", p)
	}
	if err := os.WriteFile(dll, []byte("MZ"), 0o644); err != nil {
		t.Fatal(err)
	}
	if p := WintunProblem(dir); p != "" {
		t.Errorf("present: %q", p)
	}
	if e := wintunErr(errors.New("Error loading wintun.dll DLL: Access is denied.")); !strings.Contains(e.Error(), "антивирус") {
		t.Errorf("load error: %v", e)
	}
	if e := wintunErr(errors.New("Error creating interface: Access is denied.")); strings.Contains(e.Error(), "антивирус") {
		t.Errorf("other error: %v", e)
	}
}
