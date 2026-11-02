#!/bin/sh
# All artifacts, caches and temporary files stay in this repository.
set -eu
cd "$(dirname "$0")"
ROOT="$PWD"
DEV_DIR="$ROOT/dist/connections-dev"
mkdir -p "$DEV_DIR/tmp" "$DEV_DIR/gocache"
export TMPDIR="$DEV_DIR/tmp" GOCACHE="$DEV_DIR/gocache"
CORE="$DEV_DIR/core-downloads/sing-box-1.14.4-windows-amd64"
test -f "$CORE/sing-box.exe" || {
 echo 'Missing pinned sing-box core. See docs/connections-dev.md.' >&2; exit 1;
}
printf '%s  %s\n' '8f30682ee198855440d2a7fe070d5d3653793b2d01bb8c85eea88f93bbe7c8b9' "$CORE/sing-box.exe" | shasum -a 256 -c -
printf '%s  %s\n' '3217c6260fbca5f16072e0b79735742f40109a63bb0ff88fd6b96dd6b54a2928' "$CORE/libcronet.dll" | shasum -a 256 -c -
export FNPORT_SING_BOX_DIR="$CORE" FNPORT_DEV_TRACE=on
exec sh "$ROOT/build.sh" "${1:-connections-dev1}"
