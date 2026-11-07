#!/bin/sh
# Builds dist/fnport-windows-<version>.zip (the program) and dist/fnport-windows-probe-<version>.zip
# (the probe) for Windows x64, each with wintun.dll. The version is the first argument, else git describe.
# Needs Go (the version in go.mod or newer) and zip; runs on Linux and macOS.
set -eu
cd "$(dirname "$0")"
VER=${1:-$(git describe --tags --always 2>/dev/null || echo dev)}
mkdir -p dist
# Keep cached upstream modules out of the application-wide ./... pattern.
printf 'module fnport.invalid/build-artifacts\n' > dist/go.mod
export GOTOOLCHAIN=local CGO_ENABLED=0
BUILD_TAGS=
DEV_LDFLAGS=
if [ "${FNPORT_DEV_TRACE:-off}" = on ]; then
 BUILD_TAGS=devtrace
 DEV_LDFLAGS="-X main.devControlProbes=${FNPORT_DEV_CONTROL_PROBES:-on}"
fi

# the fakes are the package's own files, embedded into the program
cp ../fnport/files/quic_initial_*.bin internal/fakes/

# licenses PKG: the license texts of Go and of every module compiled into PKG for Windows
licenses() {
	printf '%s\n\n' "Licenses of the Go code compiled into this program."
	go_license="$(go env GOROOT)/LICENSE"
 if [ ! -f "$go_license" ]; then go_license="$(go env GOROOT)/../LICENSE"; fi
 test -f "$go_license" || { echo "Go license not found" >&2; exit 1; }
 printf '%s\n\n%s\n\n' "== Go $(go env GOVERSION | sed 's/^go//') (standard library and runtime)" "$(cat "$go_license")"
	GOOS=windows GOARCH=amd64 go list -tags "$BUILD_TAGS" -deps -f '{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}} {{.Dir}}{{end}}{{end}}' "$1" |
		sort -u | while read -r path ver dir; do
			f=$(ls "$dir" | grep -i -E '^(licen[cs]e|copying|unlicense)' | head -n 1)
			test -n "$f" || { echo "no license file in $path" >&2; exit 1; }
			printf '%s\n\n%s\n\n' "== $path $ver" "$(cat "$dir/$f")"
		done
}

# every license text the program ships, built into fnport.exe (Settings → «Лицензии»):
# the zip itself carries no loose license files
{
	licenses ./fnport
	printf '%s\n\n%s\n\n' "== Wintun (wintun.dll), WireGuard LLC" "$(cat third_party/wintun-LICENSE.txt)"
	printf '%s\n\n%s\n\n' "== wgcf (the WARP registration request and TLS fingerprint), ViRb3" "$(cat third_party/wgcf-LICENSE.txt)"
	printf '%s\n\n%s\n\n' "== Inter font" "$(cat internal/fonts/OFL.txt)"
	printf '%s\n\n%s\n' "== Fake QUIC Initials (fakes/*.bin), from zapret" "$(cat ../fnport/files/quic_initial_vk_com.bin.LICENSE)"
} > fnport/licenses.txt

go vet -tags "$BUILD_TAGS" ./...
GOOS=windows GOARCH=amd64 go vet -tags "$BUILD_TAGS" ./...
go test -tags "$BUILD_TAGS" -count=1 ./...

# wintun.dll 0.14.1, signed by WireGuard LLC, taken unmodified from the sing-tun Go module:
# the Go checksum database vouches for the module, the hash pins the file
WINTUN_MOD=github.com/sagernet/sing-tun@v0.9.6
WINTUN_SHA256=e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce
mkdir -p dist
tmp=$(mktemp -d "$PWD/dist/build.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
# (the module's zip: extracting it would need the module's newer Go)
modzip=$(cd "$tmp" && GOFLAGS= go mod download -json "$WINTUN_MOD" | sed -n 's/^[[:space:]]*"Zip": "\(.*\)",$/\1/p')
dll="$tmp/wintun.dll"
unzip -p "$modzip" "$WINTUN_MOD/internal/wintun/amd64/wintun.dll" > "$dll"
echo "$WINTUN_SHA256  $dll" | sha256sum -c - >/dev/null

# the program's icon and manifest (administrator rights, sharp on scaled screens) into the exe
go run ./tools/mkicon fnport/winres
(cd fnport && go run github.com/tc-hib/go-winres@v0.3.3 make --in winres/winres.json --arch amd64)

# pack NAME PKG ZIP [LDFLAGS]: dist/ZIP-<version>.zip with NAME.exe and wintun.dll. The program
# carries its license texts inside; the probe, a plain console tool, gets them as files
pack() {
	out="$tmp/$1"
	mkdir -p "$out" dist
	GOOS=windows GOARCH=amd64 go build -tags "$BUILD_TAGS" -trimpath -ldflags "-s -w -X main.version=$VER -X main.devTrace=${FNPORT_DEV_TRACE:-off} $DEV_LDFLAGS ${4:-}" -o "$out/$1.exe" "./$2"
	cp "$dll" "$out/wintun.dll"
 if [ "$1" = fnport ] && [ -n "${FNPORT_SING_BOX_DIR:-}" ]; then
  cp "$FNPORT_SING_BOX_DIR/sing-box.exe" "$out/sing-box.exe"
  cp "$FNPORT_SING_BOX_DIR/LICENSE" "$out/sing-box-LICENSE.txt"
  if [ -f "$FNPORT_SING_BOX_DIR/libcronet.dll" ]; then cp "$FNPORT_SING_BOX_DIR/libcronet.dll" "$out/libcronet.dll"; fi
  cat "$FNPORT_SING_BOX_DIR/LICENSE" third_party/sing-box-GPL-3.0.txt third_party/sing-box-SOURCES.txt > "$out/sing-box-LICENSE.txt"
  if [ "${FNPORT_DEV_TRACE:-off}" = on ]; then
   cp ../docs/connections-dev.md "$out/README-dev.md"
  else
   cp ../docs/connections.md "$out/README.md"
  fi
 fi
	if [ "$1" != fnport ]; then
		cp third_party/wintun-LICENSE.txt "$out/wintun-LICENSE.txt"
		cp ../fnport/files/quic_initial_vk_com.bin.LICENSE "$out/quic-fakes-LICENSE.txt"
		licenses "./$2" > "$out/third-party-licenses.txt"
	fi
	rm -f "dist/$3-$VER.zip"
	(cd "$tmp" && zip -qr - "$1") > "dist/$3-$VER.zip"
	ls -l "dist/$3-$VER.zip"
}
pack fnport-probe probe fnport-windows-probe
# the program has a window, not a console; its fakes sit in a folder next to it
mkdir -p "$tmp/fnport/fakes"
cp internal/fakes/*.bin "$tmp/fnport/fakes/"
pack fnport fnport fnport-windows "-H windowsgui"
