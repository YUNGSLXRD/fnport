// Package fakes: the package's fake QUIC Initials with whitelisted SNIs, copied here by build.sh
// from fnport/files and embedded into the programs. The first one is used, the others are spares.
package fakes

import "embed"

//go:embed *.bin
var fs embed.FS

type File struct {
	Name string
	Data []byte
}

var order = []string{"quic_initial_vk_com.bin", "quic_initial_gosuslugi_ru.bin", "quic_initial_ozon_ru.bin"}

func Load() []File {
	var out []File
	for _, n := range order {
		if b, err := fs.ReadFile(n); err == nil {
			out = append(out, File{n, b})
		}
	}
	return out
}
