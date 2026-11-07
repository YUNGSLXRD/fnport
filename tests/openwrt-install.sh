#!/bin/sh
# Only the disposable OpenWrt test rootfs may run these installation fixtures.
set -eu
[ "${FNPORT_TEST_ROOTFS:-}" = 1 ] && [ -f /root/fnport-tests/tests/openwrt-config.sh ] || exit 2
FIX=/root/fnport-tests/components
case "$(uname -m)" in aarch64|arm64) target=linux-arm64; arch=aarch64_generic;; x86_64) target=linux-amd64; arch=x86_64;; *) exit 2;; esac
helper=fnport-connections-$target.tar.gz
core=fnport-sing-box-$target.tar.gz
[ -s "$FIX/$helper" ] && [ -s "$FIX/$core" ] || exit 2
(cd "$FIX" && sha256sum "$helper" "$core" > SHA256SUMS.txt)
mkdir -p /root/fnport-tests/install-bin /usr/share/fnport /usr/libexec /etc/init.d /etc/fnport/connections
cp /root/fnport-tests/fnport/files/connections-cores.json /usr/share/fnport/
printf '0.7.0-r1\n' > /usr/share/fnport/version
printf 'test-persistent-profile\n' > /etc/fnport/connections/install-fixture
cat > /root/fnport-tests/install-bin/ubus <<MOCK
#!/bin/sh
printf '{"release":{"architecture":"$arch"}}\n'
MOCK
cat > /root/fnport-tests/install-bin/df <<'MOCK'
#!/bin/sh
printf 'Filesystem 1024-blocks Used Available Capacity Mounted\n'
printf 'fixture 1000000 0 %s 0%% /\n' "${FNPORT_FREE_KB:-500000}"
MOCK
cat > /root/fnport-tests/install-bin/uclient-fetch <<'MOCK'
#!/bin/sh
set -eu
url= dest=
while [ "$#" -gt 0 ]; do
 case "$1" in -O) dest=$2; shift 2;; -*) shift;; *) url=$1; shift;; esac
done
case "$url" in https://github.com/YUNGSLXRD/fnport/releases/download/components-v0.7.0/*) ;; *) exit 3;; esac
name=${url##*/}
case "$name" in SHA256SUMS.txt|fnport-connections-linux-*.tar.gz|fnport-sing-box-linux-*.tar.gz) ;; *) exit 2;; esac
if [ "${FNPORT_BAD_HASH:-0}" = 1 ] && [ "$name" = SHA256SUMS.txt ]; then
 awk '{print "0000000000000000000000000000000000000000000000000000000000000000  " $2}' "/root/fnport-tests/components/$name" > "$dest"
else
 cp "/root/fnport-tests/components/$name" "$dest"
fi
MOCK
cat > /etc/init.d/fnport-connections <<'MOCK'
#!/bin/sh
[ "$1" = stop ] || exit 2
printf 'stop\n' >> /root/fnport-tests/installer-stops
MOCK
chmod 700 /root/fnport-tests/install-bin/* /etc/init.d/fnport-connections
export PATH=/root/fnport-tests/install-bin:/usr/sbin:/usr/bin:/sbin:/bin
: > /root/fnport-tests/installer-stops
installer=/root/fnport-tests/fnport/files/fnport-connections-install.sh
sh "$installer"
[ -x /usr/libexec/fnport-connections-helper ] && [ -x /usr/lib/fnport-connections/sing-box ]
[ "$(/usr/libexec/fnport-connections-helper version)" != '' ]
/usr/lib/fnport-connections/sing-box version >/dev/null
[ "$(cat /etc/fnport/connections/install-fixture)" = test-persistent-profile ]
[ "$(wc -l < /root/fnport-tests/installer-stops)" -eq 1 ]
before=$(sha256sum /usr/libexec/fnport-connections-helper /usr/lib/fnport-connections/sing-box)
if FNPORT_BAD_HASH=1 sh "$installer" 2>/dev/null; then echo 'bad hash accepted' >&2; exit 1; fi
grep -q helper_checksum_failed /var/run/fnport-connections/action.json
[ "$before" = "$(sha256sum /usr/libexec/fnport-connections-helper /usr/lib/fnport-connections/sing-box)" ]
[ "$(wc -l < /root/fnport-tests/installer-stops)" -eq 1 ]
if FNPORT_FREE_KB=1 sh "$installer"; then echo 'low storage accepted' >&2; exit 1; fi
grep -q insufficient_storage /var/run/fnport-connections/action.json
[ "$before" = "$(sha256sum /usr/libexec/fnport-connections-helper /usr/lib/fnport-connections/sing-box)" ]
[ "$(find /usr/lib/fnport-connections -maxdepth 1 -type d -name '.install.*' | wc -l)" -eq 0 ]
printf 'component installation, checksum rejection and storage protection: passed\n'
