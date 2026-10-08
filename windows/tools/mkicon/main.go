// mkicon writes the exe icon's PNG sizes into a directory, for go-winres.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/YUNGSLXRD/fnport/windows/internal/icon"
)

func main() {
	dir := os.Args[1]
	for _, s := range []int{256, 64, 48, 32, 16} {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("icon%d.png", s)), icon.PNG(s, icon.Green), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
