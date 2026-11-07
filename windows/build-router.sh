#!/bin/sh
set -eu
cd "$(dirname "$0")"
version=${1:-dev}
case "$version" in *[!A-Za-z0-9._-]*|'') echo 'Invalid version' >&2; exit 1;; esac
export CGO_ENABLED=0 GOTOOLCHAIN=local
mkdir -p dist/router-build/tmp dist/router-build/gocache
export TMPDIR="$PWD/dist/router-build/tmp" GOCACHE="$PWD/dist/router-build/gocache"
work=$(mktemp -d "$PWD/dist/router-build/bundle.XXXXXX")
trap 'rm -rf "$work"' EXIT
printf '%s\n' 'fnport router connection helper, source: https://github.com/YUNGSLXRD/fnport' "Version: $version" 'Native AmneziaWG: github.com/amnezia-vpn/amneziawg-go v1.0.4' 'WARP registration/TLS fingerprint: wgcf, ViRb3 (MIT)' > "$work/SOURCES.txt"
cat ../LICENSE third_party/wgcf-LICENSE.txt > "$work/LICENSES.txt"
go_license="$(go env GOROOT)/LICENSE"
[ -f "$go_license" ] || go_license="$(go env GOROOT)/../LICENSE"
cat "$go_license" >> "$work/LICENSES.txt"
GOOS=linux GOARCH=arm64 go list -deps -f '{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}} {{.Dir}}{{end}}{{end}}' ./router | sort -u | while read -r name revision directory; do
 file=$(ls "$directory" | grep -i -E '^(licen[cs]e|copying|unlicense)' | head -n 1)
 [ -n "$file" ] || { echo "Missing license: $name" >&2; exit 1; }
 printf '\n== %s %s\n' "$name" "$revision" >> "$work/LICENSES.txt"
 cat "$directory/$file" >> "$work/LICENSES.txt"
 printf '%s %s\n' "$name" "$revision" >> "$work/SOURCES.txt"
done
for target in ${FNPORT_ROUTER_TARGETS:-amd64 arm64 armv5 armv6 armv7 mips-softfloat mipsle-softfloat}; do
 unset GOARM GOMIPS
 case "$target" in
  amd64|arm64) export GOARCH=$target;;
  armv5|armv6|armv7) export GOARCH=arm GOARM=${target#armv};;
  mips-softfloat) export GOARCH=mips GOMIPS=softfloat;;
  mipsle-softfloat) export GOARCH=mipsle GOMIPS=softfloat;;
  *) echo 'Unsupported target' >&2; exit 1;;
 esac
 GOOS=linux go build -trimpath -ldflags "-s -w -X main.version=$version" -o "$work/fnport-connections-helper" ./router
 tar -czf "dist/fnport-connections-linux-$target.tar.gz" -C "$work" fnport-connections-helper LICENSES.txt SOURCES.txt
done
