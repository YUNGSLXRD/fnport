#!/bin/sh
# Build only in a disposable GitHub runner; never change a developer's file ownership.
set -eu
[ "${GITHUB_ACTIONS:-}" = true ] || { echo 'This SDK wrapper runs in GitHub Actions only.' >&2; exit 2; }
: "${GITHUB_WORKSPACE:?}" "${SDK_IMAGE:?}"
printf '%s\n' "$SDK_IMAGE" | grep -Eq '^ghcr[.]io/openwrt/sdk:x86_64-[0-9]+[.][0-9]+[.][0-9]+@sha256:[a-f0-9]{64}$' || exit 2
workspace=$GITHUB_WORKSPACE
mkdir -p "$workspace/windows/dist"
entry=$(mktemp "$workspace/windows/dist/sdk-entrypoint.XXXXXX")
owned=0
cleanup() {
 result=$?
 trap - EXIT
 if [ "$owned" = 1 ]; then
  sudo chown -R --reference="$workspace/.." "$workspace" || result=1
 fi
 rm -f "$entry" || result=1
 exit "$result"
}
trap cleanup EXIT
trap 'exit 1' INT TERM
# Keep the official package checks and feed handling, pinned to reviewed upstream code.
curl --fail --location --retry 2 --connect-timeout 10 --max-time 45 \
 'https://raw.githubusercontent.com/openwrt/gh-action-sdk/f5813d30eeef3534b58ac7e79c5d8842b6035434/entrypoint.sh' -o "$entry"
printf '%s  %s\n' e78cc3ca3ffe9a15d47096e2e9a2aa07399a22a77acdca31f4e5aef2fa0e6a9c "$entry" | sha256sum -c -
chmod 644 "$entry"
sudo chown -R 1000:1000 "$workspace"
owned=1
docker run --rm \
 --env FEEDNAME --env PACKAGES --env NO_REFRESH_CHECK --env NO_SHFMT_CHECK \
 -v "$workspace:/artifacts" -v "$workspace:/feed" -v "$entry:/ci-entrypoint.sh:ro" \
 --entrypoint /bin/sh "$SDK_IMAGE" -ec '
  cd /builder
  test -x scripts/feeds || { echo "Prepared SDK is missing from the pinned image" >&2; exit 1; }
  # SDK is already present and verified as part of the pinned official image.
  # The upstream bootstrap would otherwise fetch it again from a snapshot mirror.
  rm -f setup.sh
  exec /bin/bash /ci-entrypoint.sh
 '
