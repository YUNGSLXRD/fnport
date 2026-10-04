#!/bin/sh
# fnport installer:
#   wget -O /tmp/fnport-install.sh https://raw.githubusercontent.com/YUNGSLXRD/fnport/main/install.sh && sh /tmp/fnport-install.sh
set -e

REPO="YUNGSLXRD/fnport"
API="https://api.github.com/repos/$REPO/releases/latest"
TMP="/tmp/fnport-install"

fetch() {
	if command -v uclient-fetch >/dev/null 2>&1; then uclient-fetch -q -O "$2" "$1"
	elif command -v wget >/dev/null 2>&1; then wget -q -O "$2" "$1"
	else curl -fsSL -o "$2" "$1"; fi
}

if command -v apk >/dev/null 2>&1; then
	PM=apk; EXT=apk
elif command -v opkg >/dev/null 2>&1; then
	PM=opkg; EXT=ipk
else
	echo "Neither apk nor opkg found: is this OpenWrt?" >&2
	exit 1
fi

rm -rf "$TMP"; mkdir -p "$TMP"
echo "Looking up the latest release of $REPO..."
fetch "$API" "$TMP/release.json"

URLS="$(jsonfilter -i "$TMP/release.json" -e '@.assets[*].browser_download_url' | grep "\.$EXT\$" | grep -E '/(fnport|luci-app-fnport|luci-i18n-fnport-ru)[-_]')"
[ -n "$URLS" ] || { echo "No .$EXT packages in the latest release" >&2; exit 1; }

for u in $URLS; do
	echo "Downloading ${u##*/}"
	fetch "$u" "$TMP/${u##*/}"
done

echo "Installing..."
if [ "$PM" = apk ]; then
	apk update >/dev/null
	apk add --allow-untrusted "$TMP"/fnport-*.apk "$TMP"/luci-app-fnport-*.apk "$TMP"/luci-i18n-fnport-ru-*.apk
else
	opkg update >/dev/null
	opkg install "$TMP"/fnport_*.ipk "$TMP"/luci-app-fnport_*.ipk "$TMP"/luci-i18n-fnport-ru_*.ipk
fi

rm -rf "$TMP"
echo
echo "Done. Open LuCI -> Services -> fnport, add your game PC and enable the service."
