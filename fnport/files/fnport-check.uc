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
import { verdict, count, both_passed, both_answered, all_silent, compare_fake, measured_ttl, select_ttl } from './fnport-check-policy.uc';

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
const FROZEN_MIN = 20;          // a freeze stops at 24-25; far fewer is the echo's rate limit or loss
const LOSSY = 1000;             // added to a count that is loss, not a freeze
const IV_MS = 30, WAIT_MS = 400, FAKE_GAP_MS = 30;
const SLOW_IV_MS = 100;           // about 0.5 KB/s: well under the echo's limit for one address
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
	if ((x == 13 && y >= 36 && y <= 39) || (x == 15 && (y == 188 || y == 236 || y == 237)) || (x == 35 && (y == 180 || y == 181)) || (x == 51 && y == 44)) return 'paris';
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
function probe(host, n, fake, ttl, iv) {
	let socks = [];
	for (let i = 0; i < n; i++) {
		let s = socket.create(socket.AF_INET, socket.SOCK_DGRAM | socket.SOCK_NONBLOCK);
		if (!s) continue;
		if (!s.bind({ address: '0.0.0.0', port: 0 })) { s.close(); continue; }
		push(socks, { s, tag: chr(rand() % 256, rand() % 256), got: 0, late: false });
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
				if (from.address == host && from.port == BEACON_PORT && substr(d, 0, 2) == o.tag) {
					o.got++;
					// a reply to a packet past the 25th: whatever is missing, the flow was not frozen
					if (length(d) >= 4 && (ord(d, 2) << 8 | ord(d, 3)) >= 25) o.late = true;
				}
		}
	};
	for (let i = 0; i < PKTS; i++) {
		for (let o in socks) {
			let pkt = o.tag + chr(i >> 8, i & 255);
			for (let j = 0; j < 10; j++) pkt += chr(rand() % 256);
			pkt += chr(0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb);
			o.s.send(pkt, 0, { address: host, port: BEACON_PORT });
		}
		let end = now_ms() + (iv ?? IV_MS);
		while (now_ms() < end) { socket.poll(end - now_ms(), ...pollset); drain(); }
	}
	let end = now_ms() + WAIT_MS;
	while (now_ms() < end) { socket.poll(50, ...pollset); drain(); }
	let res = [];
	// 20-25 replies, some to packets past the 25th: the line lost packets, no freeze. Marked
	// with LOSSY added (LuCI shows the count and "loss")
	for (let o in socks) {
		push(res, o.late && o.got >= FROZEN_MIN && o.got < PASS ? o.got + LOSSY : o.got);
		o.s.close();
	}
	return res;
}

// a probe with neither a pass nor a freeze: the beacon may be limiting replies to an address
// shared by many people behind the provider's NAT, or just paused. Once more, three times
// slower; a freeze is counted in packets, not speed, so it still shows, and silence then is
// still inconclusive on their own (busy beacon, filtering, or a fake).
function probe_check(host, n, fake, ttl) {
	let r = probe(host, n, fake, ttl, IV_MS);
	if (count(r, 'pass') + count(r, 'frozen') == 0) {
		sleep_ms(GAP_MS);
		r = probe(host, n, fake, ttl, SLOW_IV_MS);
	}
	return r;
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

function fake_list(uci) {
	let v = uci.get('fnport', 'main', 'whitelist_fake');
	return v == null ? [] : (type(v) == 'array' ? v : [ v ]);
}

// the configured fakes the service would accept (the first is in use, the rest are spares),
// else the bundled one
function fake_files(uci) {
	let out = [];
	for (let p in fake_list(uci)) {
		if (!match(p, /^\/(usr\/share|etc)\/fnport\/[A-Za-z0-9_-][A-Za-z0-9._-]*$/)) continue;
		let d = readfile(p, 1501);
		if (d != null && length(d) > 0 && length(d) <= 1500) push(out, { name: replace(p, /.*\//, ''), data: d });
	}
	if (!length(out)) {
		let d = readfile(DEFAULT_FAKE, 1501);
		if (d) push(out, { name: replace(DEFAULT_FAKE, /.*\//, ''), data: d });
	}
	return out;
}

// Current TTL first. Mixed passing/frozen results retain the active settings;
// a different TTL requires two complete rounds. This only records a proposal.
function scan_ttl(r,host,fake,lo,hi,st){
 st=st??r;
 return select_ttl(lo,hi,st.current_ttl,r.fake==st.fake&&st.fake_enabled,r,(ttl)=>{
  st.step=ttl?'ttl':'control';st.ttl_now=ttl;st.fake_now=r.fake;save(st);
  sleep_ms(GAP_MS);
  return probe_check(host,2,ttl?fake:null,ttl?ttl:null);
 });
}

function run() {
	writefile(PIDFILE, split(readfile('/proc/self/stat') ?? '', ' ')[0]);
	let uci = cursor();
	let fakes = fake_files(uci), fake = fakes[0]?.data;
	let cur_ttl = +(uci.get('fnport', 'main', 'fake_ttl') ?? 3);
	let rel = release_info();
	let st = {
		state: 'running', step: 'resolve', started: time(), policy: 3,
		version: trim(readfile('/usr/share/fnport/version') ?? 'unknown'),
		openwrt: rel.release, target: rel.target,
		fake: fakes[0]?.name,
		fake_enabled: length(fake_list(uci)) > 0,
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
		let r = probe_check(ip, 2, null, null);
		push(st.control, { city: city(ip), replies: r });
		save(st);
		if (count(r, 'frozen') > worst) { worst = count(r, 'frozen'); host = ip; }
	}
	let answered = filter(b.list, (ip, i) => length(st.control[i].replies) > 0 && count(st.control[i].replies, 'silent') < length(st.control[i].replies));
	if (!length(answered)) return finish('no_reply');

	// nothing frozen, but not every beacon answered in full: the echo limits us or the link loses
	// packets, and a freeze can hide behind that
	if (!host && length(filter(st.control, c => count(c.replies, 'limited') > 0)))
		return finish('unclear');

	if (!host) {
		// Same-beacon comparison only. Limited or mixed baselines are inconclusive.
  if (fake) {
   let target = filter(answered, (ip) => both_passed(st.control[index(b.list, ip)].replies))[0] ?? answered[0];
   let baseline = st.control[index(b.list, target)].replies;
   st.step = 'fake'; save(st);
   sleep_ms(GAP_MS);
   let replies = probe_check(target, 2, fake, cur_ttl);
   st.fake_check = { city: city(target), control: baseline, ttl: cur_ttl, replies, verdict: compare_fake(baseline, replies) };
  }
		return finish('no_freeze');
	}
	st.beacon = city(host);
	if (!fake) return finish('freeze_no_fake');

	// freeze: try the fake in use, then the spares on a shorter TTL range, also after one that
	// kills flows (the DPI may treat another name differently). Unless a spare works, the verdict
	// is the fake in use's
	let res = scan_ttl(st, host, fake, 1, MAX_TTL);
 if(res=='fake_partial'&&st.fake_enabled)return finish(res);
	for (let i = 1; res != 'fake_works' && i < length(fakes) && i <= 2; i++) {
		st.spares = st.spares ?? [];
		let sp = { fake: fakes[i].name };
		push(st.spares, sp);
		if (scan_ttl(sp, host, fakes[i].data, 2, 6, st) == 'fake_works') {
			res = 'spare_works';
			st.recommended_ttl = sp.recommended_ttl;
			st.works_from = sp.works_from;
			st.recommended_fake = fakes[i].name;
   break;
		}
	}
	return finish(res == 'spare_works' ? 'fake_works' : res);
}

let cmd = ARGV[0];
if (cmd == 'status') {
	let st = load_state() ?? { state: 'none' };
	// a check that died (reboot, kill) must not look like it still runs
	if (st.state == 'running' && !check_running()) st.state = 'failed';
	// settings as they are now, not as they were during the check
	let uci = cursor();
	st.now_ttl = +(uci.get('fnport', 'main', 'fake_ttl') ?? 3);
	let current_fakes = fake_list(uci);
 st.now_fake = length(current_fakes) > 0;
 st.now_fake_name = current_fakes[0] ? replace(current_fakes[0], /.*\//, '') : null;
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
	// fully detached (own session, stdio on /dev/null): the caller, LuCI's rpcd, must not wait for it
	system([ 'start-stop-daemon', '-S', '-b', '-x', SELF, '--', 'run' ]);
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
	if (st?.state != 'done' || st.policy != 3 || st.verdict != 'fake_works' || t < 1 || t > 16 || !measured_ttl(st, t)) { printf('%J\n', { error: 'nothing to apply' }); exit(1); }
	let uci = cursor();
	let list = fake_list(uci);
 if (!length(list)) list = [DEFAULT_FAKE];
 let tested = st.recommended_fake ?? st.fake;
 let p = filter(list, x => replace(x, /.*\//, '') == tested)[0];
 if (!p) {printf('%J\n',{error:'fake_changed_repeat_check'});exit(1);}
 list = [p,...filter(list,x=>x!=p)];
 uci.set('fnport','main','fake_ttl',`${t}`);
	uci.set('fnport', 'main', 'whitelist_fake', list);
	uci.commit('fnport');
	system('/etc/init.d/fnport reload >/dev/null 2>&1');
	printf('%J\n', { applied: t });
}
else {
	warn('usage: fnport-check start|status|apply\n');
	exit(2);
}
