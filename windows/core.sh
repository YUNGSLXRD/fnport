#!/bin/sh
# Sourced by build wrappers. Builds a minimal static sing-box 1.14.4 core (without
# Chromium/libcronet) from the pinned upstream source archive.
prepare_core() {
	case "$1" in
		windows-amd64)
			fnport_core_os=windows
			fnport_core_arch=amd64
			fnport_core_bin=sing-box.exe
			;;
		darwin-arm64)
			fnport_core_os=darwin
			fnport_core_arch=arm64
			fnport_core_bin=sing-box
			;;
		linux-amd64)
			fnport_core_os=linux
			fnport_core_arch=amd64
			fnport_core_bin=sing-box
			;;
		*)
			echo "Unsupported native core target: $1" >&2
			return 1
			;;
	esac

	fnport_core_ver=1.14.4
	fnport_core_rev=c005f35300ce76427dc285481ec5695f5b179cd2
	fnport_core_src_hash=1c4d2b3bf261a8d98e1b026be0bbcddbcb3f53bbca77eb15e8f25f7d4e602e59
	fnport_core_tags=with_quic,with_utls,badlinkname,tfogo_checklinkname0
	fnport_core_cache="$PWD/dist/router-core"
	fnport_core_archive="$fnport_core_cache/sing-box-$fnport_core_rev.tar.gz"
	fnport_core_src="$fnport_core_cache/sing-box-$fnport_core_rev"
	fnport_core_out="$fnport_core_cache/minimal-$1"

	mkdir -p "$fnport_core_cache/tmp" "$fnport_core_cache/gocache" "$fnport_core_cache/gomodcache" "$fnport_core_out"

	if [ ! -f "$fnport_core_archive" ]; then
		curl --fail --location --retry 3 --output "$fnport_core_archive.partial" \
			"https://github.com/SagerNet/sing-box/archive/$fnport_core_rev.tar.gz"
		mv "$fnport_core_archive.partial" "$fnport_core_archive"
	fi
	printf '%s  %s\n' "$fnport_core_src_hash" "$fnport_core_archive" | shasum -a 256 -c -

	if [ ! -d "$fnport_core_src" ]; then
		tar -xzf "$fnport_core_archive" -C "$fnport_core_cache"
	fi

	if [ ! -x "$fnport_core_out/$fnport_core_bin" ] && [ ! -f "$fnport_core_out/$fnport_core_bin" ]; then
		(
			export TMPDIR="$fnport_core_cache/tmp"
			export GOCACHE="$fnport_core_cache/gocache"
			export GOMODCACHE="$fnport_core_cache/gomodcache"
			export CGO_ENABLED=0
			export GOTOOLCHAIN=go1.26.10
			export GOOS="$fnport_core_os"
			export GOARCH="$fnport_core_arch"
			go -C "$fnport_core_src" build -buildvcs=false -trimpath -tags "$fnport_core_tags" \
				-ldflags "-s -w -buildid= -checklinkname=0 -X github.com/sagernet/sing-box/constant.Version=$fnport_core_ver -X runtime.godebugDefault=multipathtcp=0,tlssha1=1" \
				-o "$fnport_core_out/$fnport_core_bin" ./cmd/sing-box
		)
	fi

	cp "$fnport_core_src/LICENSE" "$fnport_core_out/LICENSE"
	FNPORT_PREPARED_CORE="$fnport_core_out"
}
