package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestImportAWGFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private-secret.conf")
	if os.WriteFile(path, []byte(sampleAWGConf), 0600) != nil {
		t.Fatal("write fixture")
	}
	text, err := readAWGConfigFile(path)
	if err != nil || text != sampleAWGConf {
		t.Fatal("file import failed", err)
	}
	if os.WriteFile(path, []byte("private-secret"), 0600) != nil {
		t.Fatal("write fixture")
	}
	if _, err = readAWGConfigFile(path); err == nil || strings.Contains(err.Error(), "private-secret") {
		t.Fatal("invalid input/path leaked")
	}
	if os.WriteFile(path, []byte(strings.Repeat("x", (1<<20)+1)), 0600) != nil {
		t.Fatal("write fixture")
	}
	if _, err = readAWGConfigFile(path); err == nil {
		t.Fatal("oversized config accepted")
	}
}
