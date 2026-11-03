# Connections developer build

Experimental Windows x64 build. Not a stable release. Uses one fnport Wintun
adapter and a separate unmodified sing-box 1.14.4 executable for selected TCP/UDP
connections. Native WARP and AmneziaWG 1.5 use the existing AWG implementation.

## Run and capture Fortnite

Extract the entire ZIP to a writable folder, start fnport.exe, open Подключения.
The developer build enables network tracing by default on a fresh configuration.
The collector is compiled only with the devtrace build tag. Regular builds have
no tracing UI, collector implementation or default Fortnite process list.
Trace-only operation does not install catch-all routes. Process lists stay
collapsed until explicitly opened.
If an older fnport.json has tracing disabled, enable Записывать сетевой след and
save. Enable fnport on the main page, restart Fortnite and reproduce the problem,
then turn fnport off to finish writing the log. No tunnel is needed for tracing.
Network records are in network-trace beside fnport.exe. Up to eight 32 MiB JSONL
files are retained; archive the whole folder. Normal fnport.log is separate.

The trace includes native TCP/UDP endpoint snapshots, observed IPv4 destinations,
TLS SNI when visible, process names/PIDs and possible DNS names from the Windows
system cache. DNS correlation does not prove which application queried a name.
No payloads, URLs, credentials, private keys or process command lines are recorded.
Short-lived connections, application-local DoH, ECH, QUIC names and direct IP
connections may have no hostname. IPv6 TCP endpoints can appear in snapshots,
but IPv6 traffic is not redirected or inspected. Restarting the game is useful
for observing connections created before tracing began. Existing DNS cache is
read; the program does not clear it or issue bulk hostname probes.

## Select a connection (dev8)

Open Подключения, select WARP or one VPN protocol (Выключено disables the connection).
For WARP use Получить ключ WARP. For VLESS paste a vless:// link (TLS/Reality,
TCP, WebSocket, HTTPUpgrade and gRPC supported) or an outbound JSON object.
AmneziaWG 1.5 accepts the contents of an exported .conf file or JSON. Other
protocols currently accept JSON. Imported links are never logged.
Select Сервисы Epic for login/store/downloads, Discord for Discord, or both.
Press the fixed Применить button below the page. With fnport enabled, restart
Fortnite so existing service connections use the newly selected route.
There is only one selected service transport. The old separate WARP switches
are no longer displayed; applying this page disables legacy WARP service routing.
The game's UDP on configured Fortnite ports keeps using fnport directly.
Extra process selection and JSON exit tags are under additional settings.
Network tracing has a separate expandable section and does not select tunnel routes.
IPv6 remains direct. Unknown/ambiguous owners cannot safely select process rules.
WARP can take time to connect; wait for its state on the main page before testing.
Native AWG 1.5 JSON remains supported. Exported configs normalize an IPv4 address
from Address (with or without prefix); endpoint accepts IPv4:port or hostname:port.
Hostname resolution runs when starting, outside the UI thread. MTU 576–1420 and
PersistentKeepalive are preserved. DNS and AllowedIPs do not install system-wide
DNS/routes: fnport keeps routing only selected services/processes. One peer is
supported. Nonzero S3/S4 and H1–H4 ranges require AWG 2.0 and are rejected explicitly. Native AWG and WARP cannot coexist because of library-global
protocol headers. The application enforces this isolation.

## Core provenance and local build

Official unmodified core: https://github.com/SagerNet/sing-box/releases/tag/v1.14.4
Source: https://github.com/SagerNet/sing-box/tree/v1.14.4
License: GPL-3.0-or-later and the project's additional terms, included beside it.
The official Windows archive also contains libcronet.dll used by Naive.
This local developer bundle does not imply that public redistribution compliance
has been reviewed. Do that before a public release.

Download sing-box-1.14.4-windows-amd64.zip from that official release, verify SHA256:
99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df
Extract under windows/dist/connections-dev/core-downloads, keeping its directory.
Run sh windows/build-dev.sh connections-dev1. The resulting ZIP is in windows/dist.
All artifacts and temporary build directories stay inside fnport-openwrt.

## Validation limits

The regular Go test suite, host/Windows vet, Windows cross-build, native AWG UDP
loopback, real sing-box TCP/UDP echo, and targeted race tests for the new transport,
process routing, settings updates, trace, and UI controls passed locally.
A live Windows Discord/Fortnite session has not been tested. A broader earlier
race run reported an amneziawg-go race in TestWarpTunnelCloseBusy and failures in
TestWarpTunnelMany/TestWarpWholePath; the complete application is not claimed to
pass the entire race-enabled stress suite. Keep this build experimental.

## Focused latency and resource diagnosis (dev5)

When tracing is enabled, Discord desktop processes are included automatically.
The trace emits udp_stats for tunnelled datagrams every ten seconds, with the
maximum time waiting inside fnport, maximum local socket-write duration, queue
occupancy and queue drops. These are local timings, not an Internet RTT.
TCP progress records include the selected route, bytes received/sent, elapsed
connection time and first-response time after acceptance. They do not contain
HTTP bodies, authorization headers or TLS plaintext. A first-response value of
-1 means no server bytes have been observed yet. Domain DNS-cache associations
remain candidates, not evidence of application queries or successful downloads.

## Core failure diagnosis (dev6)

Unexpected core termination is recorded immediately, with numeric exit code,
process lifetime and a fixed runtime diagnostic category. Raw stderr, core
configuration and credentials are never logged. Normal requested shutdown is
not reported as a crash. TCP/UDP setup failures identify the local SOCKS phase,
numeric OS or SOCKS reply code, and timeout flag. Repeated failures are counted
and logged at most once per ten seconds for each protocol, rather than once
per application retry. This build diagnoses the dev5 outage; it does not yet
claim to fix its root cause or the Discord Internet RTT.

## UI spacing (dev7)

Removed the extra bottom inset below the Discord switch row. The following
Fortnite note now uses the same text spacing as the Epic description.

## WARP exit selection (dev8)

Only LV, PL, EE and FI are preferred. The lowest measured TCP connect RTT among
qualified preferred candidates wins; DE is a fallback only. Other and unknown
locations are rejected. If no usable allowed exit is found, connection fails
instead of silently selecting another country. This filters observed Cloudflare
colo values; it cannot force Cloudflare anycast to offer a particular country.

Up to sixteen addresses are tried, covering the initial ranges and comparing
three preferred successes when available. Each accepted candidate must deliver
one MiB within the existing eight-second HTTP deadline; small bursts followed
by a stall no longer qualify. Transfer rate and selected RTT are logged. This
startup check is not a sustained speed guarantee. Cancellation stops selection
and closes the currently probed tunnel. The game's direct route is unchanged.
