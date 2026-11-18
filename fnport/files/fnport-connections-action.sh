#!/bin/sh
set -eu
umask 077

RUN=/var/run/fnport-connections
mkdir -p "$RUN"
chmod 700 "$RUN"
echo $$ > "$RUN/action.pid"

cleanup() {
	rm -f "$RUN/action.pid" "$RUN/register.tmp" "$RUN/sub.tmp" "$RUN/sub.url"
	rmdir "$RUN/action.lock" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 1' INT TERM

resolve_wan_dev() {
	. /lib/functions.sh
	config_load fnport_connections
	config_get wan main wan_interface wan
	case "$wan" in ''|*[!A-Za-z0-9_.-]*) exit 1 ;; esac
	wan_dev=$(ubus call "network.interface.$wan" status | jsonfilter -e '@.l3_device')
	case "$wan_dev" in ''|*[!A-Za-z0-9_.@-]*) exit 1 ;; esac
}

if [ "$1" = install ]; then
	if /usr/libexec/fnport-connections-install > /dev/null 2>&1; then
		echo '{"state":"done","action":"install"}' > "$RUN/action.json"
	else
		[ -s "$RUN/action.json" ] || echo '{"state":"failed","error":"install_failed"}' > "$RUN/action.json"
		exit 1
	fi
elif [ "$1" = register ]; then
	resolve_wan_dev
	if /usr/libexec/fnport-connections-helper register-warp "$wan_dev" > "$RUN/register.tmp" 2>/dev/null; then
		echo '{"state":"done","action":"register"}' > "$RUN/action.json"
	else
		code=$(jsonfilter -i "$RUN/register.tmp" -e '@.error' 2>/dev/null || true)
		case "$code" in ''|*[!a-z_0-9]*) code=warp_registration_failed ;; esac
		printf '{"state":"failed","error":"%s"}\n' "$code" > "$RUN/action.json"
		exit 1
	fi
elif [ "$1" = subscription ]; then
	resolve_wan_dev
	profile_val=$(uci -q get fnport_connections.main.profile || true)
	printf '%s\n' "$profile_val" > "$RUN/sub.url"
	chmod 600 "$RUN/sub.url"
	if /usr/libexec/fnport-connections-helper fetch-subscription "$wan_dev" "$RUN/sub.url" > "$RUN/sub.tmp" 2>/dev/null; then
		rm -f "$RUN/sub.url"
		echo '{"state":"done","action":"subscription"}' > "$RUN/action.json"
		if [ "$(uci -q get fnport_connections.main.enabled || echo 0)" = 1 ]; then
			/etc/init.d/fnport-connections restart >/dev/null 2>&1 || true
		fi
	else
		rm -f "$RUN/sub.url"
		code=$(jsonfilter -i "$RUN/sub.tmp" -e '@.error' 2>/dev/null || true)
		case "$code" in ''|*[!a-z_0-9]*) code=subscription_fetch_failed ;; esac
		printf '{"state":"failed","error":"%s"}\n' "$code" > "$RUN/action.json"
		exit 1
	fi
else
	exit 2
fi
