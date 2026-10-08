// Package fakes: fake QUIC Initials with whitelisted SNIs. The program keeps them as files in a
// "fakes" folder next to itself, so they can be changed without a new build; the package's own
// files (copied here by build.sh from fnport/files) fill a new or empty folder.
package fakes

import (
	"embed"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

//go:embed *.bin LICENSE.txt
var fs embed.FS

const MaxSize = 1500 // a fake is one datagram

type File struct {
	Name string
	Data []byte
}

// order of the package's fakes: the first one is the default
var order = []string{"quic_initial_vk_com.bin", "quic_initial_gosuslugi_ru.bin", "quic_initial_ozon_ru.bin"}

// Load: the package's own fakes, default first
func Load() []File {
	var out []File
	for _, n := range order {
		if b, err := fs.ReadFile(n); err == nil {
			out = append(out, File{n, b})
		}
	}
	return out
}

// Default: the name of the default fake
func Default() string { return order[0] }

// Ensure makes dir and puts the package's fakes there if it has none
func Ensure(dir string) error {
	if len(List(dir)) > 0 {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, f := range Load() {
		if err := os.WriteFile(filepath.Join(dir, f.Name), f.Data, 0o644); err != nil {
			return err
		}
	}
	lic, _ := fs.ReadFile("LICENSE.txt")
	return os.WriteFile(filepath.Join(dir, "LICENSE.txt"), lic, 0o644)
}

// List: the usable fakes in dir (*.bin, 1 to 1500 bytes), by name
func List(dir string) []File {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []File
	for _, e := range ents {
		if e.IsDir() || !strings.EqualFold(filepath.Ext(e.Name()), ".bin") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil || len(b) == 0 || len(b) > MaxSize {
			continue
		}
		out = append(out, File{e.Name(), b})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Label: "quic_initial_vk_com.bin" -> "vk.com"
func Label(name string) string {
	n := strings.TrimSuffix(strings.TrimPrefix(name, "quic_initial_"), ".bin")
	return strings.ReplaceAll(n, "_", ".")
}
