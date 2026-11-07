#!/bin/sh
# Run as root inside an unshared network namespace. Never run on a live router.
set -eu
[ "${FNPORT_TEST_ROOTFS:-}" = 1 ] || exit 2
root=$1
[ -f "$root/etc/openwrt_release" ] || exit 2
[ "$(readlink /proc/self/ns/net)" != "$(readlink /proc/1/ns/net)" ] || exit 2
mkdir -p "$root/root/fnport-tests/fnport" "$root/root/fnport-tests/tests" "$root/tmp"
cp -R fnport/files "$root/root/fnport-tests/fnport/"
cp tests/*.uc tests/openwrt-config.sh tests/openwrt-install.sh "$root/root/fnport-tests/tests/"
case "$(uname -m)" in x86_64) target=linux-amd64;; aarch64|arm64) target=linux-arm64;; *) exit 2;; esac
mkdir -p "$root/root/fnport-tests/components"
cp "windows/dist/fnport-connections-$target.tar.gz" "windows/dist/fnport-sing-box-$target.tar.gz" "$root/root/fnport-tests/components/"
chroot "$root" /usr/bin/ucode /root/fnport-tests/tests/check-policy.uc
chroot "$root" /usr/bin/ucode /root/fnport-tests/tests/udp-policy.uc
chroot "$root" /usr/bin/env FNPORT_TEST_ROOTFS=1 /bin/sh /root/fnport-tests/tests/openwrt-config.sh
chroot "$root" /usr/bin/ucode -c -o /tmp/daemon.ucb /root/fnport-tests/fnport/files/fnportd.uc

chroot "$root" /usr/bin/env FNPORT_TEST_ROOTFS=1 /bin/sh /root/fnport-tests/tests/openwrt-install.sh
