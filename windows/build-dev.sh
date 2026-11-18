#!/bin/sh
# All artifacts, caches and temporary files stay in this repository.
set -eu
cd "$(dirname "$0")"
ROOT="$PWD"
DEV_DIR="$ROOT/dist/connections-dev"
mkdir -p "$DEV_DIR/tmp" "$DEV_DIR/gocache"
export TMPDIR="$DEV_DIR/tmp" GOCACHE="$DEV_DIR/gocache"
. ./core.sh
prepare_core windows-amd64
export FNPORT_SING_BOX_DIR="$FNPORT_PREPARED_CORE" FNPORT_DEV_TRACE=on
exec sh "$ROOT/build.sh" "${1:-connections-dev1}"
