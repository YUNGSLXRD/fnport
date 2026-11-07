#!/bin/sh
# Static OpenWrt core. The upstream generic Linux archive needs a glibc loader.
set -eu
cd "$(dirname "$0")"
revision=c005f35300ce76427dc285481ec5695f5b179cd2
source_hash=1c4d2b3bf261a8d98e1b026be0bbcddbcb3f53bbca77eb15e8f25f7d4e602e59
core_version=1.14.4
cache="$PWD/dist/router-core"
mkdir -p "$cache/tmp" "$cache/gocache" "$cache/gomodcache"
export TMPDIR="$cache/tmp" GOCACHE="$cache/gocache" GOMODCACHE="$cache/gomodcache" CGO_ENABLED=0 GOTOOLCHAIN=go1.26.10
archive="$cache/sing-box-$revision.tar.gz"
if [ ! -f "$archive" ]; then
 curl --fail --location --retry 3 --output "$archive.partial" "https://github.com/SagerNet/sing-box/archive/$revision.tar.gz"
 mv "$archive.partial" "$archive"
fi
printf '%s  %s\n' "$source_hash" "$archive" | shasum -a 256 -c -
tar -xzf "$archive" -C "$cache"
source_dir="$cache/sing-box-$revision"
work=$(mktemp -d "$cache/bundle.XXXXXX")
trap 'rm -rf "$work"' EXIT
cat "$source_dir/LICENSE" third_party/sing-box-GPL-3.0.txt > "$work/LICENSE"
cp "$archive" "dist/fnport-router-core-source-$core_version.tar.gz"
tags=with_quic,with_utls,badlinkname,tfogo_checklinkname0
printf '%s\n' "sing-box $core_version, static OpenWrt build" "Source: https://github.com/SagerNet/sing-box/tree/$revision" "Source archive SHA256: $source_hash" "Toolchain: go1.26.10, CGO_ENABLED=0" "Build tags: $tags" 'Build script: windows/build-router-core.sh in the corresponding fnport release source' > "$work/SOURCES.txt"
for target in ${FNPORT_ROUTER_TARGETS:-amd64 arm64 armv5 armv6 armv7 mips-softfloat mipsle-softfloat}; do
 unset GOARM GOMIPS
 case "$target" in
  amd64|arm64) export GOARCH=$target;;
  armv5|armv6|armv7) export GOARCH=arm GOARM=${target#armv};;
  mips-softfloat) export GOARCH=mips GOMIPS=softfloat;;
  mipsle-softfloat) export GOARCH=mipsle GOMIPS=softfloat;;
  *) echo 'Unsupported target' >&2; exit 1;;
 esac
 GOOS=linux go -C "$source_dir" build -buildvcs=false -trimpath -tags "$tags" -ldflags "-s -w -buildid= -checklinkname=0 -X github.com/sagernet/sing-box/constant.Version=$core_version -X runtime.godebugDefault=multipathtcp=0,tlssha1=1" -o "$work/sing-box" ./cmd/sing-box
 file "$work/sing-box" | grep 'statically linked' > /dev/null || { echo 'Router core requires a dynamic loader' >&2; exit 1; }
 tar -czf "dist/fnport-sing-box-linux-$target.tar.gz" -C "$work" sing-box LICENSE SOURCES.txt
done
