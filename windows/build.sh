#!/bin/sh
# Builds dist/fnport-<version>.zip (the program) and dist/fnport-probe-<version>.zip (the probe)
# for Windows x64, each with wintun.dll.
# Needs Go (the version in go.mod or newer) and zip; runs on Linux and macOS.
set -eu
cd "$(dirname "$0")"
VER=${1:-$(git describe --tags --always 2>/dev/null || echo dev)}
export GOTOOLCHAIN=local CGO_ENABLED=0

# the fakes are the package's own files, embedded into the program
cp ../fnport/files/quic_initial_*.bin internal/fakes/

go vet ./...
GOOS=windows GOARCH=amd64 go vet ./...
go test -count=1 ./...

# wintun.dll 0.14.1, signed by WireGuard LLC, taken unmodified from the sing-tun Go module:
# the Go checksum database vouches for the module, the hash pins the file
WINTUN_MOD=github.com/sagernet/sing-tun@v0.9.6
WINTUN_SHA256=e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# (the module's zip: extracting it would need the module's newer Go)
modzip=$(cd "$tmp" && GOFLAGS= go mod download -json "$WINTUN_MOD" | sed -n 's/^[[:space:]]*"Zip": "\(.*\)",$/\1/p')
dll="$tmp/wintun.dll"
unzip -p "$modzip" "$WINTUN_MOD/internal/wintun/amd64/wintun.dll" > "$dll"
echo "$WINTUN_SHA256  $dll" | sha256sum -c - >/dev/null

# the program's icon and manifest (administrator rights, sharp on scaled screens) into the exe
go run ./tools/mkicon fnport/winres
(cd fnport && go run github.com/tc-hib/go-winres@v0.3.3 make --in winres/winres.json --arch amd64)

# pack NAME PKG [LDFLAGS]: dist/NAME-<version>.zip with NAME.exe, wintun.dll and the notices
pack() {
	out="$tmp/$1"
	mkdir -p "$out" dist
	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.version=$VER ${3:-}" -o "$out/$1.exe" "./$2"
	cp "$dll" "$out/wintun.dll"
	cp third_party/wintun-LICENSE.txt "$out/wintun-LICENSE.txt"
	cp ../fnport/files/quic_initial_vk_com.bin.LICENSE "$out/quic-fakes-LICENSE.txt"
	rm -f "dist/$1-$VER.zip"
	(cd "$tmp" && zip -qr - "$1") > "dist/$1-$VER.zip"
	ls -l "dist/$1-$VER.zip"
}
pack fnport-probe probe
# the program has a window, not a console
pack fnport fnport "-H windowsgui"
