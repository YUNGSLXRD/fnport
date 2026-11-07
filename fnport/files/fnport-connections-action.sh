#!/bin/sh
set -eu
umask 077
RUN=/var/run/fnport-connections
mkdir -p "$RUN"
chmod 700 "$RUN"
echo $$ > "$RUN/action.pid"
cleanup() { rm -f "$RUN/action.pid"; rmdir "$RUN/action.lock" 2>/dev/null || true; }
trap cleanup EXIT
trap 'exit 1' INT TERM
if [ "$1" = install ]; then
 if /usr/libexec/fnport-connections-install > /dev/null 2>&1; then
  echo '{"state":"done","action":"install"}' > "$RUN/action.json"
 else
  [ -s "$RUN/action.json" ] || echo '{"state":"failed","error":"install_failed"}' > "$RUN/action.json"
  exit 1
 fi
elif [ "$1" = register ]; then
 . /lib/functions.sh
 config_load fnport_connections
 config_get wan main wan_interface wan
 case "$wan" in ''|*[!A-Za-z0-9_.-]*) exit 1;; esac
 wan_dev=$(ubus call "network.interface.$wan" status | jsonfilter -e '@.l3_device')
 case "$wan_dev" in ''|*[!A-Za-z0-9_.@-]*) exit 1;; esac
 if /usr/libexec/fnport-connections-helper register-warp "$wan_dev" > "$RUN/register.tmp" 2>/dev/null; then
  echo '{"state":"done","action":"register"}' > "$RUN/action.json"
 else
  # Helper emits structured, secret-free error codes only. No stderr/profile is exposed.
  code=$(jsonfilter -i "$RUN/register.tmp" -e '@.error' 2>/dev/null || true)
  case "$code" in ''|*[!a-z_0-9]*) code=warp_registration_failed;; esac
  printf '{"state":"failed","error":"%s"}\n' "$code" > "$RUN/action.json"
  rm -f "$RUN/register.tmp"
  exit 1
 fi
 rm -f "$RUN/register.tmp"
else
 exit 2
fi
