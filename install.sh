#!/bin/sh
# fnport installer and updater: installs the latest release, or updates an installed fnport to it.
# Settings in /etc/config/fnport are kept.
#   wget -O /tmp/fnport-install.sh https://raw.githubusercontent.com/YUNGSLXRD/fnport/main/install.sh && sh /tmp/fnport-install.sh
# Add -f to reinstall even if the latest version is already installed.
set -e

REPO="YUNGSLXRD/fnport"
API="https://api.github.com/repos/$REPO/releases/latest"
TMP="/tmp/fnport-install"
CONF="/etc/config/fnport"

FORCE=0
[ "$1" = "-f" ] && FORCE=1

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

# installed fnport version, empty if not installed (apk: 0.3.2-r1, opkg: 0.3.2-r1 or 0.3.2-1)
installed_version() {
	if [ "$PM" = apk ]; then
		apk list -I fnport 2>/dev/null | awk '$1 ~ /^fnport-[0-9]/ { sub(/^fnport-/, "", $1); print $1; exit }'
	else
		opkg status fnport 2>/dev/null | sed -n 's/^Version: //p'
	fi
}

rm -rf "$TMP"; mkdir -p "$TMP"
echo "Looking up the latest release of $REPO..."
fetch "$API" "$TMP/release.json"

URLS="$(jsonfilter -i "$TMP/release.json" -e '@.assets[*].browser_download_url' | grep "\.$EXT\$" | grep -E '/(fnport|luci-app-fnport|luci-i18n-fnport-ru)[-_]')"
[ -n "$URLS" ] || { echo "No .$EXT packages in the latest release" >&2; exit 1; }

# version of the release, from the fnport package name: fnport-0.3.3-r1.apk / fnport_0.3.3-r1_all.ipk
LATEST="$(echo "$URLS" | sed -n 's#.*/fnport[-_]\([0-9][^_]*\)\(_all\)\{0,1\}\.'"$EXT"'$#\1#p' | head -n1)"
CURRENT="$(installed_version)"

if [ -n "$CURRENT" ]; then
	if [ "$(echo "$CURRENT" | sed 's/-r/-/')" = "$(echo "$LATEST" | sed 's/-r/-/')" ] && [ "$FORCE" = 0 ]; then
		echo "fnport $CURRENT is already the latest version. Run with -f to reinstall."
		rm -rf "$TMP"
		exit 0
	fi
	echo "Updating fnport $CURRENT -> $LATEST"
else
	echo "Installing fnport $LATEST"
fi

for u in $URLS; do
	echo "Downloading ${u##*/}"
	fetch "$u" "$TMP/${u##*/}"
done

# keep the settings: the package manager normally does, but not over files it did not install
HAD_CONF=0
[ -f "$CONF" ] && { cp -p "$CONF" "$TMP/fnport.conf"; HAD_CONF=1; }

echo "Installing..."
if [ "$PM" = apk ]; then
	apk update >/dev/null
	apk add --allow-untrusted "$TMP"/fnport-*.apk "$TMP"/luci-app-fnport-*.apk "$TMP"/luci-i18n-fnport-ru-*.apk
else
	opkg update >/dev/null
	opkg install "$TMP"/fnport_*.ipk "$TMP"/luci-app-fnport_*.ipk "$TMP"/luci-i18n-fnport-ru_*.ipk
fi

if [ "$HAD_CONF" = 1 ]; then
	if ! cmp -s "$TMP/fnport.conf" "$CONF"; then
		cp -p "$TMP/fnport.conf" "$CONF"
		echo "Settings restored from before the update"
	fi
	# the package's default config, set aside next to the kept one
	rm -f "$CONF.apk-new" "$CONF-opkg"
fi

rm -rf /tmp/luci-indexcache* /tmp/luci-modulecache
rm -rf "$TMP"

echo
if [ "$(uci -q get fnport.main.enabled)" = 1 ]; then
	/etc/init.d/fnport enable
	/etc/init.d/fnport restart
	echo "Done: fnport $(installed_version) is running."
elif [ -z "$CURRENT" ] && [ "$HAD_CONF" = 0 ]; then
	echo "Done. Open LuCI -> Services -> fnport, add your game PC and enable the service."
else
	echo "Done: fnport $(installed_version) is installed. It is off: enable it in LuCI -> Services -> fnport."
fi
