#!/bin/sh
# Public Windows build: pinned core, native core integration tests, no dev trace.
set -eu
cd "$(dirname "$0")"
mkdir -p "$PWD/dist/connections-dev/tmp" "$PWD/dist/connections-dev/gocache"
export TMPDIR="$PWD/dist/connections-dev/tmp" GOCACHE="$PWD/dist/connections-dev/gocache"
. ./core.sh
prepare_core windows-amd64
export FNPORT_SING_BOX_DIR="$FNPORT_PREPARED_CORE"
case "$(uname -s)-$(uname -m)" in
 Linux-x86_64) prepare_core linux-amd64 ;;
 Darwin-arm64) prepare_core darwin-arm64 ;;
 *) echo 'Native core integration tests need Linux x64 or macOS arm64.' >&2; exit 1 ;;
esac
export FNPORT_TEST_SING_BOX="$FNPORT_PREPARED_CORE/sing-box" FNPORT_DEV_TRACE=off
exec sh ./build.sh "$@"
