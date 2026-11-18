#!/bin/sh
# An explicit LuCI action installs an independent pinned core. Existing VPN
# installations, configs and services are never reused or changed.
set -eu
umask 077

RUN=/var/run/fnport-connections
DEST=/usr/lib/fnport-connections

fail() {
	printf '{"state":"failed","error":"%s"}\n' "$1" > "$RUN/action.json"
	exit 1
}

mkdir -p "$RUN" "$DEST"
chmod 700 "$RUN"

version=$(cat /usr/share/fnport/version)
version=${version%%-r*}
case "$version" in ''|*[!0-9.]*) fail invalid_package_version ;; esac

architecture=$(ubus call system board | jsonfilter -e '@.release.architecture')
case "$architecture" in
	x86_64*) target=linux-amd64 ;;
	aarch64*) target=linux-arm64 ;;
	arm_cortex-a*|armv7*|arm_mpcore*) target=linux-armv7 ;;
	arm_arm11*|armv6*) target=linux-armv6 ;;
	arm*) target=linux-armv5 ;;
	mipsel*|mipsle*) target=linux-mipsle-softfloat ;;
	mips*) target=linux-mips-softfloat ;;
	*) fail unsupported_architecture ;;
esac

# Download/extract on the destination filesystem, never into scarce tmpfs RAM.
free_kb=$(df -Pk "$DEST" | awk 'NR==2 {print $4}')
[ "${free_kb:-0}" -ge 140000 ] || fail insufficient_storage

ensure_deps() {
	[ "${FNPORT_TEST_ROOTFS:-0}" != 1 ] || return 0
	need_pkgs=
	[ -e /etc/ssl/certs/ca-certificates.crt ] || need_pkgs="$need_pkgs ca-bundle"
	ip -j -4 rule show >/dev/null 2>&1 || need_pkgs="$need_pkgs ip-full"
	[ -e /dev/net/tun ] || [ -d /sys/module/tun ] || need_pkgs="$need_pkgs kmod-tun"
	[ -d /sys/module/nft_tproxy ] || modprobe -q nft_tproxy 2>/dev/null || need_pkgs="$need_pkgs kmod-nft-tproxy"
	[ -n "$need_pkgs" ] || return 0

	if command -v apk >/dev/null 2>&1; then
		apk update >/dev/null 2>&1 || fail deps_install_failed
		# shellcheck disable=SC2086
		apk add $need_pkgs >/dev/null 2>&1 || fail deps_install_failed
	elif command -v opkg >/dev/null 2>&1; then
		opkg update >/dev/null 2>&1 || fail deps_install_failed
		# shellcheck disable=SC2086
		opkg install $need_pkgs >/dev/null 2>&1 || fail deps_install_failed
	fi
}

ensure_deps

work=$(mktemp -d "$DEST/.install.XXXXXX")
cleanup() { rm -rf "$work"; }
trap cleanup EXIT
trap 'exit 1' INT TERM

base="https://github.com/YUNGSLXRD/fnport/releases/download/components-v$version"
api_meta="https://api.github.com/repos/YUNGSLXRD/fnport/releases/tags/components-v$version"
helper="fnport-connections-$target.tar.gz"

fetch() {
	media=${3:-}
	if command -v uclient-fetch >/dev/null 2>&1; then
		if [ -n "$media" ]; then
			uclient-fetch -q --timeout=90 --header="Accept: $media" -O "$2" "$1"
		else
			uclient-fetch -q --timeout=90 -O "$2" "$1"
		fi
	elif command -v wget >/dev/null 2>&1; then
		if [ -n "$media" ]; then
			wget -q -T 90 --header="Accept: $media" -O "$2" "$1"
		else
			wget -q -T 90 -O "$2" "$1"
		fi
	else
		if [ -n "$media" ]; then
			curl -fsSL --connect-timeout 15 --max-time 90 -H "Accept: $media" -o "$2" "$1"
		else
			curl -fsSL --connect-timeout 15 --max-time 90 -o "$2" "$1"
		fi
	fi
}

fetch_component() {
	asset_name=$1
	dest_file=$2
	if fetch "$base/$asset_name" "$dest_file"; then
		return 0
	fi
	if [ ! -s "$work/release.json" ]; then
		fetch "$api_meta" "$work/release.json" "application/vnd.github+json" || return 1
	fi
	asset_api=$(jsonfilter -i "$work/release.json" -e "@.assets[@.name=\"$asset_name\"].url" 2>/dev/null || true)
	case "$asset_api" in
		https://api.github.com/repos/YUNGSLXRD/fnport/releases/assets/*)
			fetch "$asset_api" "$dest_file" "application/octet-stream"
			;;
		*)
			return 1
			;;
	esac
}

fetch_component "SHA256SUMS.txt" "$work/SHA256SUMS.txt" || fail release_unreachable
fetch_component "$helper" "$work/$helper" || fail helper_download_failed

hash=$(awk -v file="$helper" '$2==file {print $1}' "$work/SHA256SUMS.txt")
[ "${#hash}" -eq 64 ] || fail helper_hash_missing
printf '%s  %s\n' "$hash" "$work/$helper" | sha256sum -c - > /dev/null || fail helper_checksum_failed

core=$(jsonfilter -i /usr/share/fnport/connections-cores.json -e "@.targets[\"$target\"].archive")
case "$core" in
	"fnport-sing-box-$target.tar.gz") ;;
	*) fail core_manifest_invalid ;;
esac

core_hash=$(awk -v file="$core" '$2==file {print $1}' "$work/SHA256SUMS.txt")
[ "${#core_hash}" -eq 64 ] || fail core_hash_missing
fetch_component "$core" "$work/core.tar.gz" || fail core_download_failed
printf '%s  %s\n' "$core_hash" "$work/core.tar.gz" | sha256sum -c - > /dev/null || fail core_checksum_failed

mkdir "$work/helper" "$work/core"
tar -xzf "$work/$helper" -C "$work/helper" fnport-connections-helper LICENSES.txt SOURCES.txt || fail helper_archive_invalid
tar -xzf "$work/core.tar.gz" -C "$work/core" sing-box LICENSE SOURCES.txt || fail core_archive_invalid

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
