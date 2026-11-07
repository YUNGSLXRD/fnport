#!/bin/sh
# Sourced by build wrappers. Official archives are pinned, rechecked and extracted.
prepare_core() {
 case "$1" in
  windows-amd64) fnport_core_hash=99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df; fnport_core_ext=zip ;;
  darwin-arm64) fnport_core_hash=0d8c7f5ed5d587b0f1a5e9772a708ec3bfa4ac4c9329604b01d8d9c2ba406838; fnport_core_ext=tar.gz ;;
  linux-amd64) fnport_core_hash=699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968; fnport_core_ext=tar.gz ;;
  *) echo "Unsupported native core target: $1" >&2; return 1 ;;
 esac
 fnport_core_name="sing-box-1.14.4-$1"
 fnport_core_cache="$PWD/dist/connections-dev/core-downloads"
 fnport_core_archive="$fnport_core_cache/$fnport_core_name.$fnport_core_ext"
 mkdir -p "$fnport_core_cache"
 if [ ! -f "$fnport_core_archive" ]; then
  curl --fail --location --retry 3 --output "$fnport_core_archive.partial" "https://github.com/SagerNet/sing-box/releases/download/v1.14.4/$fnport_core_name.$fnport_core_ext"
  printf '%s  %s\n' "$fnport_core_hash" "$fnport_core_archive.partial" | shasum -a 256 -c -
  mv "$fnport_core_archive.partial" "$fnport_core_archive"
 fi
 printf '%s  %s\n' "$fnport_core_hash" "$fnport_core_archive" | shasum -a 256 -c -
 if [ "$fnport_core_ext" = zip ]; then
  unzip -oq "$fnport_core_archive" -d "$fnport_core_cache"
 else
  tar -xzf "$fnport_core_archive" -C "$fnport_core_cache"
 fi
 FNPORT_PREPARED_CORE="$fnport_core_cache/$fnport_core_name"
 if [ "$1" = windows-amd64 ]; then
  printf '%s  %s\n' 8f30682ee198855440d2a7fe070d5d3653793b2d01bb8c85eea88f93bbe7c8b9 "$FNPORT_PREPARED_CORE/sing-box.exe" | shasum -a 256 -c -
  printf '%s  %s\n' 3217c6260fbca5f16072e0b79735742f40109a63bb0ff88fd6b96dd6b54a2928 "$FNPORT_PREPARED_CORE/libcronet.dll" | shasum -a 256 -c -
 fi
}
