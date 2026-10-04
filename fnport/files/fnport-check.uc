#!/usr/bin/env ucode
// fnport-check: gentle test of the path to Epic's QoS beacons, started from LuCI
// (Services -> fnport -> ISP check). Finds out whether the ISP freezes game UDP after
// 25 packets, and if so whether the whitelist fake lifts the freeze and with which TTL.
// About 10-25 probe sockets in all, spaced out over 20-60 s: probing a lot gets the address punished.
//
//   fnport-check start   run a check in the background (refused while one runs or right after one)
//   fnport-check status  print the state and the result as JSON
//   fnport-check apply   set fake_ttl (and the fake, if it is off) to the check's recommendation

import * as socket from 'socket';
import { rand } from 'math';
import { popen, readfile, writefile, rename, access } from 'fs';
import { cursor } from 'uci';

const SELF = '/usr/libexec/fnport-check';
const STATE = '/var/run/fnport-check.json';   // root-only directory: no symlink games
const PIDFILE = '/var/run/fnport-check.pid';
const BEACON_NAME = 'ping-eu.ds.on.epicgames.com';
const BEACON_PORT = 22222;
// used when DNS gives nothing usable (fakeip of Podkop-like services, filtered DNS); Frankfurt first
const BEACON_FALLBACK = [ '3.66.90.173', '3.66.90.156', '18.133.162.202', '13.37.148.3' ];
const PUBLIC_DNS = [ '77.88.8.8', '8.8.8.8' ];
const DEFAULT_FAKE = '/usr/share/fnport/quic_initial_vk_com.bin';
const PKTS = 30, PASS = 26;     // TSPU stops replies at 25, so more than 25 means no freeze
const IV_MS = 30, WAIT_MS = 400, FAKE_GAP_MS = 30;
const GAP_MS = 2000;            // pause between probe rounds
const MAX_TTL = 8;              // the DPI sits inside the ISP, a few hops out
const COOLDOWN = 180;           // seconds between checks

function sh(cmd) {
	let p = popen(cmd, 'r');
	if (!p) return '';
	let out = p.read('all');
	p.close();
	return out ?? '';
}

function now_ms() {
	let c = clock();
	return c[0] * 1000 + int(c[1] / 1000000);
}

function sleep_ms(ms) {
	let end = now_ms() + ms;
	while (now_ms() < end) socket.poll(end - now_ms());
}

function octets(a) {
	let m = match(`${a}`, /^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/);
	if (!m) return null;
	let o = [ +m[1], +m[2], +m[3], +m[4] ];
	for (let x in o) if (x > 255) return null;
	return o;
}

// kind of address without the address itself: what the report may show
function addr_kind(a) {
	let o = octets(a);
	if (!o) return 'none';
	if (o[0] == 192 && o[1] == 168) return 'lan';
	if (o[0] == 10 || (o[0] == 172 && o[1] >= 16 && o[1] <= 31) || (o[0] == 100 && o[1] >= 64 && o[1] <= 127)) return 'private';
	if (o[0] == 127 || o[0] == 0 || (o[0] == 198 && (o[1] == 18 || o[1] == 19)) || o[0] >= 224) return 'special';
	return 'public';
}

// AWS EU regions by address prefix (the ones Epic's beacons and game servers use)
function city(a) {
	let o = octets(a);
	if (!o) return 'eu';
	let x = o[0], y = o[1];
	if ((x == 3 && y >= 64 && y <= 79) || (x == 18 && y >= 153 && y <= 159) || (x == 35 && y >= 156 && y <= 159)) return 'frankfurt';
	if ((x == 3 && y >= 8 && y <= 11) || (x == 18 && ((y >= 130 && y <= 135) || (y >= 168 && y <= 171))) ||
	    (x == 13 && y >= 40 && y <= 43) || (x == 35 && y >= 176 && y <= 179)) return 'london';
	if ((x == 13 && y >= 36 && y <= 39) || (x == 15 && (y == 188 || y == 236 || y == 237)) || (x == 35 && (y == 180 || y == 181))) return 'paris';
	return 'eu';
}

function lookup(server) {
	let ips = [];
	for (let l in split(sh(`nslookup -type=a ${BEACON_NAME} ${server ?? ''} 2>/dev/null`), '\n')) {
		// the server's own "Address: 127.0.0.1:53" line carries a port and does not match
		let m = match(l, /^Address:[ \t]*([0-9.]+)[ \t]*$/);
		if (m && addr_kind(m[1]) == 'public' && !(m[1] in ips)) push(ips, m[1]);
	}
	return ips;
}

// up to three beacons in different cities, Frankfurt first
function beacons() {
	let ips = lookup(null), source = 'dns';
	for (let i = 0; !length(ips) && i < length(PUBLIC_DNS); i++) { ips = lookup(PUBLIC_DNS[i]); source = 'public_dns'; }
	if (!length(ips)) { ips = BEACON_FALLBACK; source = 'builtin'; }
	let order = { frankfurt: 0, london: 1, paris: 2, eu: 3 }, seen = {}, out = [];
	for (let ip in sort([ ...ips ], (a, b) => order[city(a)] - order[city(b)]))
		if (!seen[city(ip)]) { seen[city(ip)] = true; push(out, ip); }
	return { list: slice(out, 0, 3), source };
}

// n sockets in parallel, each sends PKTS tagged packets to the QoS echo; with ttl, one fake first
function probe(host, n, fake, ttl) {
	let socks = [];
	for (let i = 0; i < n; i++) {
		let s = socket.create(socket.AF_INET, socket.SOCK_DGRAM | socket.SOCK_NONBLOCK);
		if (!s) continue;
		if (!s.bind({ address: '0.0.0.0', port: 0 })) { s.close(); continue; }
		push(socks, { s, tag: chr(rand() % 256, rand() % 256), got: 0 });
	}
	let pollset = map(socks, o => [ o.s, socket.POLLIN ]);
	if (ttl) {
		for (let o in socks) {
			o.s.setopt(socket.IPPROTO_IP, socket.IP_TTL, ttl);
			o.s.send(fake, 0, { address: host, port: BEACON_PORT });
			o.s.setopt(socket.IPPROTO_IP, socket.IP_TTL, 64);
		}
		sleep_ms(FAKE_GAP_MS);
	}
	let drain = () => {
		for (let o in socks) {
			let d, from = {};
			while ((d = o.s.recv(2048, 0, from)) != null && length(d) > 0)
				if (from.address == host && from.port == BEACON_PORT && substr(d, 0, 2) == o.tag)
					o.got++;
		}
	};
	for (let i = 0; i < PKTS; i++) {
		for (let o in socks) {
			let pkt = o.tag + chr(i >> 8, i & 255);
			for (let j = 0; j < 10; j++) pkt += chr(rand() % 256);
			pkt += chr(0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb);
			o.s.send(pkt, 0, { address: host, port: BEACON_PORT });
		}
		let end = now_ms() + IV_MS;
		while (now_ms() < end) { socket.poll(end - now_ms(), ...pollset); drain(); }
	}
	let end = now_ms() + WAIT_MS;
	while (now_ms() < end) { socket.poll(50, ...pollset); drain(); }
	let res = [];
	for (let o in socks) { push(res, o.got); o.s.close(); }
	return res;
}

function count(replies, what) {
	let n = 0;
	for (let r in replies)
		if (what == 'pass' ? r >= PASS : (what == 'silent' ? r == 0 : (r > 0 && r < PASS))) n++;
	return n;
}

function load_state() {
	return json(readfile(STATE) ?? 'null');
}

function save(st) {
	writefile(STATE + '.tmp', sprintf('%J', st));
	rename(STATE + '.tmp', STATE);
}

function check_running() {
	let pid = trim(readfile(PIDFILE) ?? '');
	return match(pid, /^[0-9]+$/) && index(readfile(`/proc/${pid}/cmdline`) ?? '', 'fnport-check') >= 0;
}

function release_info() {
	let r = {};
	for (let l in split(readfile('/etc/openwrt_release') ?? '', '\n')) {
		let m = match(l, /^DISTRIB_(RELEASE|TARGET)='([^']*)'/);
		if (m) r[lc(m[1])] = m[2];
	}
	return r;
}

// the configured fake if the service would accept it, else the bundled one
function fake_file(uci) {
	let p = uci.get('fnport', 'main', 'whitelist_fake') ?? '';
	if (match(p, /^\/(usr\/share|etc)\/fnport\/[A-Za-z0-9_-][A-Za-z0-9._-]*$/)) {
		let d = readfile(p, 1501);
		if (d != null && length(d) > 0 && length(d) <= 1500) return { path: p, data: d };
	}
	return { path: DEFAULT_FAKE, data: readfile(DEFAULT_FAKE, 1501) };
}

function run() {
	writefile(PIDFILE, split(readfile('/proc/self/stat') ?? '', ' ')[0]);
	let uci = cursor();
	let ff = fake_file(uci), fake = ff.data;
	let cur_ttl = +(uci.get('fnport', 'main', 'fake_ttl') ?? 3);
	let rel = release_info();
	let st = {
		state: 'running', step: 'resolve', started: time(),
		version: trim(readfile('/usr/share/fnport/version') ?? 'unknown'),
		openwrt: rel.release, target: rel.target,
		fake: replace(ff.path, /.*\//, ''),
		fake_enabled: (uci.get('fnport', 'main', 'whitelist_fake') ?? '') != '',
		current_ttl: cur_ttl
	};
	// interface names only: it ends up in a shell command
	let iface = uci.get('fnport', 'main', 'wan_interface') ?? 'wan';
	if (!match(iface, /^[A-Za-z0-9_.-]{1,15}$/)) iface = 'wan';
	let wan = json(sh(`ubus call network.interface.${iface} status 2>/dev/null`) || 'null');
	st.wan_kind = addr_kind(wan?.['ipv4-address']?.[0]?.address);
	save(st);

	let finish = (verdict) => {
		st.state = 'done'; st.step = 'done'; st.verdict = verdict; st.finished = time();
		save(st);
	};

	let b = beacons();
	st.beacon_source = b.source;

	// no fake: is there a freeze at all? The DPI's verdict differs per city, so ask each one
	st.step = 'control'; st.control = []; save(st);
	let host = null, worst = 0;
	for (let ip in b.list) {
		sleep_ms(GAP_MS);
		let r = probe(ip, 2, null, null);
		push(st.control, { city: city(ip), replies: r });
		save(st);
		if (count(r, 'frozen') > worst) { worst = count(r, 'frozen'); host = ip; }
	}
	let answered = filter(b.list, (ip, i) => count(st.control[i].replies, 'silent') < 2);
	if (!length(answered)) return finish('no_reply');

	if (!host) {
		// no freeze here: only make sure the fake at the current TTL does not kill flows
		if (st.fake_enabled && fake) {
			st.step = 'fake'; save(st);
			sleep_ms(GAP_MS);
			st.fake_check = { ttl: cur_ttl, replies: probe(answered[0], 2, fake, cur_ttl) };
		}
		return finish('no_freeze');
	}
	st.beacon = city(host);
	if (!fake) return finish('freeze_no_fake');

	// freeze: the fake helps once its TTL takes it past the DPI. Scan up from 1, 2 sockets per
	// TTL; a TTL with a pass gets 2 more and is taken with at least 2 passes out of 4
	st.ttl = [];
	let silent_run = 0;
	for (let t = 1; t <= MAX_TTL; t++) {
		st.step = 'ttl'; st.ttl_now = t; save(st);
		sleep_ms(GAP_MS);
		let e = { ttl: t, replies: probe(host, 2, fake, t) };
		push(st.ttl, e);
		if (count(e.replies, 'pass') >= 1) {
			save(st);
			sleep_ms(GAP_MS);
			e.replies = [ ...e.replies, ...probe(host, 2, fake, t) ];
			if (count(e.replies, 'pass') >= 2) {
				// any TTL from here on gets past the DPI; recommend one hop of margin against
				// route changes, unless the fake starts killing flows there
				st.works_from = t;
				st.recommended_ttl = t;
				if (t < MAX_TTL) {
					st.ttl_now = t + 1; save(st);
					sleep_ms(GAP_MS);
					let m = { ttl: t + 1, replies: probe(host, 2, fake, t + 1) };
					push(st.ttl, m);
					if (count(m.replies, 'silent') < length(m.replies)) st.recommended_ttl = t + 1;
				}
				return finish('fake_works');
			}
		}
		// the whole flow dies once the fake reaches some DPI: going further only kills more
		silent_run = count(e.replies, 'silent') == length(e.replies) ? silent_run + 1 : 0;
		if (silent_run >= 2) {
			st.fake_kills_from = t - 1;
			return finish('fake_kills');
		}
	}
	return finish('fake_fails');
}

let cmd = ARGV[0];
if (cmd == 'status') {
	let st = load_state() ?? { state: 'none' };
	// a check that died (reboot, kill) must not look like it still runs
	if (st.state == 'running' && !check_running()) st.state = 'failed';
	printf('%J\n', st);
}
else if (cmd == 'start') {
	let st = load_state();
	if (check_running()) { printf('%J\n', { error: 'running' }); exit(1); }
	if (st?.finished && time() - st.finished < COOLDOWN) {
		printf('%J\n', { error: 'cooldown', wait: COOLDOWN - (time() - st.finished) });
		exit(1);
	}
	save({ state: 'running', step: 'start', started: time() });
	system(`${SELF} run </dev/null >/dev/null 2>&1 &`);
	printf('%J\n', { started: true });
}
else if (cmd == 'run') {
	try {
		run();
	}
	catch (e) {
		save({ state: 'failed', error: `${e}`, finished: time() });
	}
}
else if (cmd == 'apply') {
	let st = load_state();
	let t = +(st?.recommended_ttl ?? 0);
	if (st?.state != 'done' || t < 1 || t > 16) { printf('%J\n', { error: 'nothing to apply' }); exit(1); }
	let uci = cursor();
	uci.set('fnport', 'main', 'fake_ttl', `${t}`);
	if ((uci.get('fnport', 'main', 'whitelist_fake') ?? '') == '')
		uci.set('fnport', 'main', 'whitelist_fake', DEFAULT_FAKE);
	uci.commit('fnport');
	system('/etc/init.d/fnport reload >/dev/null 2>&1');
	printf('%J\n', { applied: t });
}
else {
	warn('usage: fnport-check start|status|apply\n');
	exit(2);
}
