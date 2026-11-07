#!/bin/sh
set -eu
[ "${FNPORT_TEST_ROOTFS:-}" = 1 ] && [ -f /root/fnport-tests/tests/check-policy.uc ] || exit 2
mkdir -p /root/fnport-tests/mock-bin /tmp /var/run/fnport-connections
chmod 700 /var/run/fnport-connections
cat > /root/fnport-tests/mock-bin/ubus <<'MOCK'
#!/bin/sh
case "$2" in
 network.interface.wan) echo '{"up":true,"l3_device":"eth0"}';;
 network.interface.lan) echo '{"up":true,"l3_device":"br-lan"}';;
 *) exit 1;;
esac
MOCK
chmod 700 /root/fnport-tests/mock-bin/ubus
export PATH=/root/fnport-tests/mock-bin:/usr/sbin:/usr/bin:/sbin:/bin
cat > /etc/config/fnport_connections <<'CONFIG'
config connections 'main'
 option enabled '1'
 option protocol 'vless'
 option profile 'fixture-profile'
 list device '02:00:00:00:00:01'
 option epic '1'
 option discord '1'
 option dns_mode 'https'
 option dns_provider 'quad9'
 option wan_interface 'wan'
 list lan_interface 'lan'
 option fake_ttl '3'
CONFIG
chmod 600 /etc/config/fnport_connections
ucode /root/fnport-tests/fnport/files/connections-config.uc > /tmp/connections-config.json
ucode -e 'import {readfile} from "fs";let c=json(readfile("/tmp/connections-config.json"));if(c.wan!="eth0"||c.lan[0]!="br-lan"||!c.discord||c.profile!="fixture-profile"||c.devices[0]!="02:00:00:00:00:01"||c.dns_provider!="quad9")die("UCI conversion failed");printf("UCI conversion: passed\n");'
ucode /root/fnport-tests/fnport/files/fnport-connectionsctl.uc status > /tmp/connection-status.json
ucode -e 'import {readfile} from "fs";let c=json(readfile("/tmp/connection-status.json"));if(c.state!="stopped"||c.profile!=null||c.private_key!=null)die("unsafe status");printf("status fields: passed\n");'
for file in fnport-check.uc connections-config.uc fnport-connectionsctl.uc; do
 ucode -c -o /tmp/fnport-test.ucb "/root/fnport-tests/fnport/files/$file"
done
