# Connections developer build

Experimental Windows x64 build. Not a stable release. Uses one fnport Wintun
adapter and a separate unmodified sing-box 1.14.4 executable for selected TCP/UDP
connections. Native WARP and AmneziaWG 1.5 use the existing AWG implementation.

## Run and capture Fortnite

Extract the entire ZIP to a writable folder, start fnport.exe, open Подключения.
The developer build enables network tracing by default on a fresh configuration.
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

## Select a connection

Choose a protocol, enable the connection, select Discord or enter multiple
executable basenames (one per line). The picker can select running applications.
The trace process list is independent and never selects applications for tunnelling.
Native AmneziaWG and native WARP cannot run together in this developer build because
the embedded library shares protocol-header state. Disable WARP for Epic before
selecting AmneziaWG; a WARP speed check must also finish first.
Fortnite UDP on configured game ports keeps fnport processing even when the
Fortnite process is selected for its TCP services. Other processes go directly.
Only IPv4 routing is supported in this developer build; IPv6 remains direct.
A missing or ambiguous process owner cannot safely select a process rule.

WARP uses the key from the existing WARP card. Its Epic-service switch is separate:
WARP can serve Discord while Epic rules stay disabled. It connects asynchronously;
Discord connections may fail while WARP starts. Wait for connection before testing.
Other protocols use a sing-box outbound JSON object with its type, or a JSON object
containing outbounds/endpoints and optionally DNS. For multiple tagged objects,
enter the final outbound tag in the UI. fnport owns listeners, routing and local
SOCKS authentication; importing an exported whole config with inbounds/route is
not supported. Protocol-specific options remain available in JSON. URI links and
AmneziaWG .conf import are not implemented in this developer build.

TCP-only transports cannot carry Discord voice. Unknown custom protocols are
accepted for TCP but do not advertise UDP support. Core validation also checks
compiled features and parameters; a listed protocol does not establish server
reachability. Selecting Discord routes its desktop processes and visible Discord
TLS names in browsers. Browser voice routing is not guaranteed when UDP ownership
belongs to a shared browser process; select that browser explicitly if appropriate.
Process selection then includes its other tabs too.

AmneziaWG native JSON uses private_key, peer_key, address (IPv4 without mask),
endpoint (IPv4:port), optional preshared_key, jc/jmin/jmax, s1/s2, numeric h1–h4,
and i1–i5. It supports the parameters of the embedded AWG 1.5 library, not AWG 2.0.
Configuration is hidden by default and stored locally in fnport.json. Never share
that file or paste it into an issue. sing-box gets its runtime config through stdin;
its raw diagnostics are not added to logs because they can contain credentials.

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
