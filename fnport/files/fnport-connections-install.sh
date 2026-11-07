#!/bin/sh
# An explicit LuCI action installs an independent pinned core. Existing VPN
# installations, configs and services are never reused or changed.
set -eu
umask 077
RUN=/var/run/fnport-connections
DEST=/usr/lib/fnport-connections
fail() { printf '{"state":"failed","error":"%s"}\n' "$1" > "$RUN/action.json"; exit 1; }
mkdir -p "$RUN" "$DEST"
chmod 700 "$RUN"
version=$(cat /usr/share/fnport/version)
version=${version%%-r*}
case "$version" in ''|*[!0-9.]*) fail invalid_package_version;; esac
architecture=$(ubus call system board | jsonfilter -e '@.release.architecture')
case "$architecture" in
 x86_64*) target=linux-amd64;;
 aarch64*) target=linux-arm64;;
 arm*) target=linux-armv5;;
 mipsel*|mipsle*) target=linux-mipsle-softfloat;;
 mips*) target=linux-mips-softfloat;;
 *) fail unsupported_architecture;;
esac
# Download/extract on the destination filesystem, never into scarce tmpfs RAM.
free_kb=$(df -Pk "$DEST" | awk 'NR==2 {print $4}')
[ "${free_kb:-0}" -ge 140000 ] || fail insufficient_storage
work=$(mktemp -d "$DEST/.install.XXXXXX")
cleanup() { rm -rf "$work"; }
trap cleanup EXIT
trap 'exit 1' INT TERM
base="https://github.com/YUNGSLXRD/fnport/releases/download/components-v$version"
helper="fnport-connections-$target.tar.gz"
fetch() { uclient-fetch -q --timeout=90 -O "$2" "$1"; }
fetch "$base/SHA256SUMS.txt" "$work/SHA256SUMS.txt" || fail release_unreachable
fetch "$base/$helper" "$work/$helper" || fail helper_download_failed
hash=$(awk -v file="$helper" '$2==file {print $1}' "$work/SHA256SUMS.txt")
[ ${#hash} -eq 64 ] || fail helper_hash_missing
printf '%s  %s\n' "$hash" "$work/$helper" | sha256sum -c - > /dev/null || fail helper_checksum_failed
core=$(jsonfilter -i /usr/share/fnport/connections-cores.json -e "@.targets[\"$target\"].archive")
case "$core" in "fnport-sing-box-$target.tar.gz") ;; *) fail core_manifest_invalid;; esac
core_hash=$(awk -v file="$core" '$2==file {print $1}' "$work/SHA256SUMS.txt")
[ ${#core_hash} -eq 64 ] || fail core_hash_missing
fetch "$base/$core" "$work/core.tar.gz" || fail core_download_failed
printf '%s  %s\n' "$core_hash" "$work/core.tar.gz" | sha256sum -c - > /dev/null || fail core_checksum_failed
mkdir "$work/helper" "$work/core"
tar -xzf "$work/$helper" -C "$work/helper" fnport-connections-helper LICENSES.txt SOURCES.txt || fail helper_archive_invalid
tar -xzf "$work/core.tar.gz" -C "$work/core" sing-box LICENSE SOURCES.txt || fail core_archive_invalid
# The official libcronet Linux library targets glibc, while OpenWrt uses musl.
# Native Naive is not offered here. Other protocols do not load that library.
[ -s "$work/helper/fnport-connections-helper" ] && [ -s "$work/core/sing-box" ] || fail components_missing
/etc/init.d/fnport-connections stop || true
chmod 755 "$work/helper/fnport-connections-helper" "$work/core/sing-box"
cp "$work/helper/fnport-connections-helper" /usr/libexec/fnport-connections-helper.new
mv "$work/core/sing-box" "$DEST/sing-box"
mv /usr/libexec/fnport-connections-helper.new /usr/libexec/fnport-connections-helper
cp "$work/helper/LICENSES.txt" "$DEST/helper-LICENSES.txt"
cp "$work/helper/SOURCES.txt" "$DEST/helper-SOURCES.txt"
cp "$work/core/LICENSE" "$DEST/sing-box-LICENSE.txt"
cp "$work/core/SOURCES.txt" "$DEST/sing-box-SOURCES.txt"
