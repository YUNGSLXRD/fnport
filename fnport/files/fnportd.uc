#!/usr/bin/env ucode
// fnportd: assigns "good" source ports to new game UDP flows from selected LAN devices.
// Started by /etc/init.d/fnport with the WAN L3 device as the only argument;
// settings come from /etc/config/fnport.
//
// TSPU freezes a UDP flow to AWS after 25 packets depending on (source port,
// server ip, server port). For each held flow we probe the server's own game
// port with Unreal handshake packets (the server answers them statelessly) from
// several candidate source ports, and map the flow to one that got all replies.
// If the server does not answer handshakes, its QoS echo (UDP 22222) is used.
//
// TSPU does not freeze flows in which it saw a whitelisted SNI. So each probe socket
// and each flow handed to the PC first sends one fake QUIC Initial with such an SNI
// and a TTL that expires after the TSPU, before reaching the server.
//
// Where nothing freezes (probes pass without the fake), fnport stands by: flows pass
// as they are until a frozen one shows up. What it learnt about the network (standby,
// a harmful fake, the fake that works) is kept per network across restarts.

import * as socket from 'socket';
import { rand } from 'math';
import { popen, readfile, writefile, rename, mkdir } from 'fs';
import { cursor } from 'uci';

// interface names only: it ends up in a shell command
const WAN_DEV = match(ARGV[0] ?? '', /^[A-Za-z0-9._@-]{1,15}$/) ? ARGV[0] : null;
const uci = cursor();

function cfg(opt, dflt) {
	let v = uci.get('fnport', 'main', opt);
	return (v == null || v == '') ? dflt : v;
}

// numeric option clamped to [lo, hi]; anything else falls back to the default
function num(opt, dflt, lo, hi) {
	let v = cfg(opt, null);
	if (v == null || !match(`${v}`, /^-?[0-9]+$/)) return dflt;
	v = +v;
	return (v < lo || v > hi) ? dflt : v;
}

function as_list(v) {
	return v == null ? [] : (type(v) == 'array' ? v : [ v ]);
}

function parse_range(r) {
	let m = match(`${r}`, /^([0-9]{1,5})(-([0-9]{1,5}))?$/);
	if (!m) return null;
	let lo = +m[1], hi = +(m[3] ?? m[1]);
	return (lo >= 1 && hi <= 65535 && lo <= hi) ? [ lo, hi ] : null;
}

// the fake is read as root and sent to the network: only our own small files
function load_fake(path) {
	if (!path) return null;
	path = `${path}`;
	if (!match(path, /^\/(usr\/share|etc)\/fnport\/[A-Za-z0-9_-][A-Za-z0-9._-]*$/)) {
		system([ 'logger', '-t', 'fnport', 'whitelist fake rejected: must be a file in /usr/share/fnport or /etc/fnport' ]);
		return null;
	}
	let d = readfile(path, 1501);
	if (d == null || length(d) == 0 || length(d) > 1500) {
		system([ 'logger', '-t', 'fnport', 'whitelist fake rejected: missing, empty or larger than 1500 bytes' ]);
		return null;
	}
	return d;
}

function ipv4(a) {
	let m = match(`${a}`, /^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/);
	return m && +m[1] <= 255 && +m[2] <= 255 && +m[3] <= 255 && +m[4] <= 255;
}

const PCS = filter(as_list(cfg('device')), ipv4);
const PORT_RANGES = filter(map(as_list(cfg('port_range', [ '9000-9999', '15000-15999' ])), parse_range), r => r);
const PAIR_FROM = parse_range(cfg('pair_from', ''));
const PAIR_OFFSET = num('pair_offset', 0, -65535, 65535);
const QOS_PORT = num('qos_port', 22222, 1, 65535);
const GAME_BATCH = num('probe_batch', 2, 1, 12);     // parallel handshake probes per round
const MAX_ROUNDS = num('max_rounds', 8, 1, 16);      // rounds per flow when most ports freeze
const PROBE_BUDGET = num('probe_budget', 24, 4, 120);  // probe sockets per minute, all servers together
const LIMIT_HOLDOFF = 900;                   // seconds to avoid handshake probes after the server limited us
const GOOD_TTL = num('verdict_ttl', 90, 10, 900);  // verdicts drift within ~10-20 min
const PROBE_PKTS = 30;        // TSPU stops replies at 25, so more than 25 means no freeze;
const PROBE_PASS = 26;        // the margin is for loss on poor links, not for the DPI
const FROZEN_MIN = 20;        // a freeze stops at 24-25; far fewer is the server limiting or loss
const PROBE_IV_MS = 30;       // per-socket spacing; denser bursts get rate-limited by the server
const PROBE_WAIT_MS = 400;
const FREEZE_OUT = 60;        // flow counts as frozen: >= this many packets out ...
const FREEZE_IN = 26;         // ... while replies stay at or below this
const PORT_MIN = 20000, PORT_RANGE = 40000;
// the first fake is used; the others are spares for when it stops working here
const FAKES = map(filter(map(as_list(cfg('whitelist_fake', null)), p => ({ path: `${p}`, data: load_fake(p) })), f => f.data != null),
	f => ({ name: replace(f.path, /.*\//, ''), data: f.data }));
const FAKE_TTL = num('fake_ttl', 3, 1, 16);  // hops from the router: expires past the TSPU, before the server
const FAKE_GAP_MS = 30;                // let the fake reach the TSPU before the real packets
const FAKE_HOLDOFF = 1800;             // seconds without the fake once it proved harmful here
const MAX_REMAPS = 4;                  // attempts to move one frozen flow to a fresh port
const FAKE_TRIAL = 16;                 // probe sockets with one fake before judging it
const STANDBY = cfg('standby', '1') != '0';
const STANDBY_EVIDENCE = 6;            // probe sockets without the fake, nearly all passing, to stand by
const CONTROL_STREAK = 8;              // passes in a row with the fake before trying once without it
const CONTROL_HOLDOFF = 6 * 3600;      // after a control that froze, do not try again for a while
const STATS_RUN = '/var/run/fnport-stats.json';  // read by the status page
const STATS_SAVED = '/etc/fnport/stats.json';     // flash: written rarely
const MEMORY = '/etc/fnport/memory.json';         // what was learnt per network
const STATS_HOURS = 168;
const VERSION = trim(readfile('/usr/share/fnport/version') ?? 'unknown');

function game_port(p) {
	for (let r in PORT_RANGES)
		if (p >= r[0] && p <= r[1]) return true;
	return false;
}

// first packet of the Unreal stateless handshake, as sent by the client
let HANDSHAKE = chr(0x47, 0x1a, 0x20, 0x00, 0x00, 0x70, 0x67, 0xb5, 0x5a, 0x05);
for (let i = 0; i < 28; i++) HANDSHAKE += chr(0);
HANDSHAKE += chr(0x00, 0x90, 0xd6, 0xa2, 0xee, 0x35, 0x36, 0x85, 0x46, 0x10);

let targets = {};             // "ip|port" -> { ts, good: [ports], tried: { port: true }, mode }
let game_probe_off_until = 0; // Epic caps handshake replies per source IP when probed too often
let budget_window = 0, budget_used = 0;  // probing too much gets our address punished by the DPI
let last_alive = 0;
let last_check = 0;
let reported = {};            // "ip|wanport" -> true, frozen flows already handled
let remaps = {};              // "pc|cport|ip|sport" -> remap attempts
let fake_off_until = 0;       // some ISPs kill a whole flow once their DPI sees the fake
let fake_idx = 0;             // which of FAKES is in use
let fake_tries = 0, fake_good = 0;  // probe sockets with the current fake and how many passed
let standby = false;          // no freeze on this network: flows pass as they are
let nofake_tries = 0, nofake_good = 0;  // probe sockets without the fake
let pass_streak = 0;          // probe sockets in a row that passed with the fake
let control_after = 0;
let net_key = null;
let stats = { hours: {} }, stats_dirty = true, stats_written = 0, stats_saved = time();
const STARTED = time();

function fake_on() {
	return length(FAKES) > 0 && time() >= fake_off_until && !standby;
}

function qos_batch() {
	return fake_on() ? 4 : 12;  // the fake lets about half of the ports pass
}

function now_ms() {
	let c = clock();
	return c[0] * 1000 + int(c[1] / 1000000);
}

// one fake with a whitelisted SNI on this socket's flow, sent with a short TTL
function send_fake(s, host, dport) {
	if (!fake_on()) return false;
	s.setopt(socket.IPPROTO_IP, socket.IP_TTL, FAKE_TTL);
	s.send(FAKES[fake_idx].data, 0, { address: host, port: dport });
	s.setopt(socket.IPPROTO_IP, socket.IP_TTL, 64);
	return true;
}

// fake from our own socket on `port`, then drop the router conntrack entry it left,
// so the PC's flow can be mapped to that very port
function fake_from(port, host, dport) {
	let s = socket.create(socket.AF_INET, socket.SOCK_DGRAM | socket.SOCK_NONBLOCK);
	if (s && s.bind({ address: '0.0.0.0', port: port })) {
		send_fake(s, host, dport);
		socket.poll(FAKE_GAP_MS);
	}
	s?.close();
	system(`conntrack -D -p udp --orig-port-src ${port} --orig-dst ${host} --orig-port-dst ${dport} >/dev/null 2>&1`);
}

function sh(cmd) {
	let p = popen(cmd, 'r');
	if (!p) return '';
	let out = p.read('all');
	p.close();
	return out ?? '';
}

function log(msg) {
	system(['logger', '-t', 'fnport', msg]);
}

function nft(cmds) {
	let p = popen('nft -f - 2>&1', 'w');
	p.write(join('\n', cmds) + '\n');
	p.close();
}

function wan_ip() {
	let m = match(sh('ip -4 -o addr show dev ' + WAN_DEV), /inet ([0-9.]+)/);
	return m ? m[1] : null;
}

function save_json(path, data) {
	if (!writefile(path + '.tmp', sprintf('%J', data))) return false;
	return rename(path + '.tmp', path);
}

// hourly counters for the status page; kept for a week
function stat(name, n) {
	let h = `${int(time() / 3600) * 3600}`;
	if (!stats.hours[h]) stats.hours[h] = {};
	stats.hours[h][name] = (stats.hours[h][name] ?? 0) + (n ?? 1);
	stats_dirty = true;
}

function load_stats() {
	// the RAM copy survives daemon restarts, the flash copy survives reboots
	let s = json(readfile(STATS_RUN) ?? 'null') ?? json(readfile(STATS_SAVED) ?? 'null');
	if (type(s?.hours) == 'object') stats.hours = s.hours;
}

function write_stats(to_flash) {
	let cut = time() - STATS_HOURS * 3600;
	for (let h in keys(stats.hours))
		if (+h < cut) delete stats.hours[h];
	stats.now = {
		version: VERSION, started: STARTED, updated: time(),
		standby, fake: length(FAKES) ? FAKES[fake_idx].name : null,
		fake_off_until: fake_off_until > time() ? fake_off_until : 0,
		probe_off_until: game_probe_off_until > time() ? game_probe_off_until : 0
	};
	save_json(STATS_RUN, stats);
	stats_dirty = false; stats_written = time();
	if (to_flash) {
		mkdir('/etc/fnport');
		save_json(STATS_SAVED, { hours: stats.hours });
		stats_saved = time();
	}
}

function tick_stats() {
	if (stats_dirty && time() - stats_written >= 60) write_stats(false);
	if (time() - stats_saved >= 6 * 3600) write_stats(true);
}

// the network behind the WAN: its gateway (or PPP peer) and the gateway's MAC
function network_key() {
	let gw = match(sh('ip -4 route show default dev ' + WAN_DEV), /via ([0-9.]+)/)?.[1];
	if (!gw) gw = match(sh('ip -4 addr show dev ' + WAN_DEV), /peer ([0-9.]+)/)?.[1];
	if (!gw) return WAN_DEV;
	let mac = match(sh('ip neigh show ' + gw), /lladdr ([0-9a-f:]+)/)?.[1];
	return mac ? `${gw}|${mac}` : gw;
}

function load_memory() {
	let all = json(readfile(MEMORY) ?? 'null');
	return type(all) == 'object' ? all : {};
}

function remember() {
	let all = load_memory();
	all[net_key] = { standby, fake: length(FAKES) ? FAKES[fake_idx].name : null,
		fake_off_until: fake_off_until > time() ? fake_off_until : 0, updated: time() };
	// a handful of networks is plenty (a router that moves between home and elsewhere)
	let ks = sort(keys(all), (a, b) => (all[b].updated ?? 0) - (all[a].updated ?? 0));
	for (let i = 8; i < length(ks); i++) delete all[ks[i]];
	mkdir('/etc/fnport');
	save_json(MEMORY, all);
}

function recall() {
	net_key = network_key();
	let m = load_memory()[net_key];
	if (!m) return;
	standby = STANDBY && !!m.standby;
	for (let i = 0; i < length(FAKES); i++)
		if (FAKES[i].name == m.fake) fake_idx = i;
	if (+(m.fake_off_until ?? 0) > time()) fake_off_until = +m.fake_off_until;
	log(sprintf('this network was seen before:%s fake %s%s', standby ? ' no freeze, standing by;' : '',
		length(FAKES) ? FAKES[fake_idx].name : 'none', fake_off_until > time() ? ' (off for now)' : ''));
}

function set_standby(on, why) {
	if (standby == on) return;
	standby = on;
	log(on ? `no freeze on this network (${why}): standing by, flows pass as they are`
		: `freeze seen (${why}): standby off`);
	stat(on ? 'standby_on' : 'standby_off');
	remember();
	write_stats(false);
}

// unwrap nft JSON set/map element into [ip, port, port]
function elem_key(e) {
	while (type(e) == 'object' && e.elem != null) e = e.elem;
	if (type(e) == 'object' && e.val != null) e = e.val;
	return (type(e) == 'object' && e.concat != null) ? e.concat : e;
}

function list_elems(kind, name) {
	let j = json(sh(`nft -j list ${kind} ip fnport ${name} 2>/dev/null`) || '{}');
	for (let obj in (j?.nftables ?? []))
		if (obj[kind]?.name == name)
			return obj[kind].elem ?? [];
	return [];
}

// send PROBE_PKTS packets from each source port to host:dport, count replies per port
function probe(host, dport, ports, qos, nofake) {
	let socks = [];
	for (let p in ports) {
		let s = socket.create(socket.AF_INET, socket.SOCK_DGRAM | socket.SOCK_NONBLOCK);
		if (!s) continue;
		if (!s.bind({ address: '0.0.0.0', port: p })) { s.close(); continue; }
		push(socks, { s, p, tag: chr(rand() % 256, rand() % 256), got: 0 });
	}
	let pollset = map(socks, o => [o.s, socket.POLLIN]);
	let faked = false;
	for (let o in socks)
		if (!nofake && send_fake(o.s, host, dport)) faked = true;
	if (faked) socket.poll(FAKE_GAP_MS);
	// count only replies from the probed server: the sockets listen on all addresses
	let drain = () => {
		for (let o in socks) {
			let d, from = {};
			while ((d = o.s.recv(2048, 0, from)) != null && length(d) > 0)
				if (from.address == host && from.port == dport && (!qos || substr(d, 0, 2) == o.tag))
					o.got++;
		}
	};
	for (let i = 0; i < PROBE_PKTS; i++) {
		for (let o in socks) {
			let pkt = HANDSHAKE;
			if (qos) {
				pkt = o.tag + chr(i >> 8, i & 255);
				for (let j = 0; j < 10; j++) pkt += chr(rand() % 256);
				pkt += chr(0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb);
			}
			o.s.send(pkt, 0, { address: host, port: dport });
		}
		let end = now_ms() + PROBE_IV_MS;
		while (now_ms() < end) { socket.poll(end - now_ms(), ...pollset); drain(); }
	}
	let end = now_ms() + PROBE_WAIT_MS;
	while (now_ms() < end) { socket.poll(50, ...pollset); drain(); }
	let res = {};
	for (let o in socks) { res[o.p] = o.got; o.s.close(); }
	return res;
}

function fresh_ports(t, n) {
	let cand = [];
	while (length(cand) < n) {
		let p = PORT_MIN + rand() % PORT_RANGE;
		if (!t.tried[p] && !(p in cand)) push(cand, p);
	}
	return cand;
}

// what probes of a game port tell about the network: does the fake work, is there a freeze at all
function learn(results, with_fake) {
	let tried = 0, good = 0;
	for (let got in results) {
		if (got >= PROBE_PASS) { tried++; good++; }
		else if (got >= FROZEN_MIN) tried++;  // 1-19 is the server limiting or loss, 0 is silence
	}
	if (!tried) return;
	if (with_fake) {
		fake_tries += tried; fake_good += good;
		pass_streak = (good == tried) ? pass_streak + good : 0;
		if (fake_tries >= FAKE_TRIAL && fake_good <= 1 && length(FAKES) > 1) {
			let old = FAKES[fake_idx].name;
			fake_idx = (fake_idx + 1) % length(FAKES);
			log(sprintf('fake %s does not work here (%d of %d probes passed), switching to %s',
				old, fake_good, fake_tries, FAKES[fake_idx].name));
			stat('fakeswitch');
			fake_tries = fake_good = 0;
			remember();
		}
		else if (fake_tries >= FAKE_TRIAL * 4) {
			// judge by recent probes only
			fake_tries = int(fake_tries / 2); fake_good = int(fake_good / 2);
		}
	}
	else {
		// one freeze without the fake rules standby out
		if (good < tried) nofake_tries = nofake_good = 0;
		else { nofake_tries += tried; nofake_good += good; }
		if (STANDBY && nofake_tries >= STANDBY_EVIDENCE)
			set_standby(true, sprintf('%d probes without the fake passed', nofake_tries));
	}
}

// make sure we know at least `want` good source ports for ip:dport
function refresh_target(ip, dport, want) {
	let key = `${ip}|${dport}`;
	let t = targets[key];
	if (!t || time() - t.ts > GOOD_TTL)
		t = targets[key] = { ts: time(), good: [], tried: {}, silent_rounds: 0,
			mode: time() < game_probe_off_until ? (fake_on() ? 'blind' : 'qos') : 'game' };
	if (length(t.good) >= want) return t;

	// the server does not answer probes: hand out untested ports. The fake sent before
	// the flow does the work, and a flow that freezes anyway gets remapped.
	if (t.mode == 'blind' && !fake_on())
		t.mode = 'qos';  // untested ports only make sense with the fake
	if (t.mode == 'blind') {
		let cand = fresh_ports(t, want - length(t.good));
		for (let p in cand) { t.tried[p] = true; push(t.good, p); }
		log(sprintf('server %s:%d does not answer probes, untested ports %s', ip, dport, join(' ', cand)));
		return t;
	}

	let qos = (t.mode == 'qos');
	let n = qos ? qos_batch() : GAME_BATCH;
	if (time() - budget_window >= 60) { budget_window = time(); budget_used = 0; }
	if (budget_used + n > PROBE_BUDGET) {
		log(sprintf('probe budget exhausted (%d/min), not probing %s:%d', PROBE_BUDGET, ip, dport));
		return t;
	}
	budget_used += n;
	let cand = fresh_ports(t, n);
	let t0 = now_ms();
	let with_fake = fake_on();
	let res = probe(ip, qos ? QOS_PORT : dport, cand, qos);
	let fresh = [], frozen = 0, silent = 0, counts = {};
	for (let p in cand) {
		t.tried[p] = true;
		let got = res[p] ?? 0;
		counts[got] = true;
		if (got >= PROBE_PASS) push(fresh, p);
		else if (got == 0) silent++;
		else frozen++;
	}
	for (let p in fresh) push(t.good, p);
	log(sprintf('probe %s:%d via %s: %d good, %d frozen, %d silent (%dms)',
		ip, dport, qos ? 'qos' : 'game port', length(fresh), frozen, silent, now_ms() - t0));
	stat('tested', length(cand));
	stat('good', length(fresh));
	if (!qos) learn(map(cand, p => res[p] ?? 0), with_fake);

	// everything passes with the fake: maybe nothing freezes here at all. Two ports without
	// it now and then tell; passing ports are good ports either way
	if (!qos && STANDBY && fake_on() && pass_streak >= CONTROL_STREAK && time() >= control_after &&
	    budget_used + 2 <= PROBE_BUDGET) {
		pass_streak = 0;
		budget_used += 2;
		let cc = fresh_ports(t, 2);
		let r = probe(ip, dport, cc, false, true);
		let vals = map(cc, p => r[p] ?? 0);
		for (let p in cc) {
			t.tried[p] = true;
			if ((r[p] ?? 0) >= PROBE_PASS) push(t.good, p);
		}
		log(sprintf('control without the fake %s:%d: %s replies', ip, dport, join(', ', vals)));
		learn(vals, false);
		if (!standby && length(filter(vals, v => v >= PROBE_PASS)) < 2)
			control_after = time() + CONTROL_HOLDOFF;
	}

	// no reply at all with the fake: maybe it is the fake that gets the flow killed (some ISPs drop
	// flows once their DPI sees QUIC). One port without it tells this apart from a silent server.
	if (!qos && silent == length(cand) && fake_on() && budget_used < PROBE_BUDGET) {
		budget_used++;
		let p = fresh_ports(t, 1)[0];
		t.tried[p] = true;
		let got = probe(ip, dport, [ p ], false, true)[p] ?? 0;
		learn([ got ], false);
		if (got > 0) {
			fake_off_until = time() + FAKE_HOLDOFF;
			log(sprintf('whitelist fake breaks flows on this network (%s:%d: no replies with it, %d without), fake off for %d min',
				ip, dport, got, FAKE_HOLDOFF / 60));
			stat('fakeoff');
			remember();
			if (got >= PROBE_PASS) push(t.good, p);
			return t;
		}
	}

	// server ignores handshakes: fall back to its QoS echo. With the fake a QoS verdict says
	// nothing about the game flow, so retry the game port once, then go blind.
	if (!qos && silent == length(cand)) {
		if (!fake_on()) t.mode = 'qos';
		else if (++t.silent_rounds >= 2) t.mode = 'blind';
	}
	else
		t.silent_rounds = 0;

	// every port stopped at the same count: that is the server capping handshake replies
	// for our address, not the DPI (whose verdict differs per port). Stop handshake probes.
	if (!qos && !length(fresh) && length(cand) >= 6 && frozen == length(cand) && length(keys(counts)) == 1) {
		game_probe_off_until = time() + LIMIT_HOLDOFF;
		t.mode = fake_on() ? 'blind' : 'qos';
		log(sprintf('server limits handshake replies (all ports got %s), %s for %d min',
			keys(counts)[0], fake_on() ? 'untested ports' : 'using qos echo', LIMIT_HOLDOFF / 60));
		return refresh_target(ip, dport, want);
	}
	return t;
}

// move a frozen flow to a fresh source port preceded by the fake. The PC keeps its socket,
// only the address the server sees changes; a frozen flow is lost anyway.
function remap(pc, cport, ip, sport) {
	let wan = wan_ip();
	if (!wan) return;
	let t = targets[`${ip}|${sport}`];
	let used = {}, mapped = false;
	for (let e in list_elems('map', 'assign')) {
		let k = elem_key(e[0]), v = elem_key(e[1]);
		if (k[0] != ip || k[2] != sport) continue;
		used[v[1]] = true;
		if (k[1] == cport) mapped = true;
	}
	let pick = null;
	if (t)
		for (let p in t.good)
			if (!used[p]) { pick = p; break; }
	if (pick == null) {
		pick = fresh_ports(t ?? { tried: {} }, 1)[0];
		if (t) t.tried[pick] = true;
	}
	fake_from(pick, ip, sport);
	let tuple = `${ip} . ${cport} . ${sport}`;
	let cmds = [];
	if (mapped) push(cmds, `delete element ip fnport assign { ${tuple} }`);
	push(cmds, `add element ip fnport assign { ${tuple} : ${wan} . ${pick} }`);
	push(cmds, `add element ip fnport assigned { ${tuple} }`);
	nft(cmds);
	// the PC's next packet creates a new conntrack entry, which takes the new mapping
	system(`conntrack -D -p udp --orig-src ${pc} --orig-port-src ${cport} --orig-dst ${ip} --orig-port-dst ${sport} >/dev/null 2>&1`);
	log(sprintf('flow %s:%d (pc:%d) remapped -> wan port %d (attempt %d)',
		ip, sport, cport, pick, remaps[`${pc}|${cport}|${ip}|${sport}`]));
	stat('remaps');
}

// a mapped flow that froze anyway: stop handing out its port for that target, try another port
function check_frozen() {
	if (time() - last_check < 2) return;
	last_check = time();
	let pat = join('|', map(PCS, a => `src=${a} `));
	for (let line in split(sh(`grep -E "${pat}" /proc/net/nf_conntrack`), '\n')) {
		if (index(line, ' udp ') < 0) continue;
		let src = match(line, /src=([0-9.]+)/), cp = match(line, /sport=([0-9]+)/);
		let dst = match(line, /dst=([0-9.]+)/), sp = match(line, /dport=([0-9]+)/);
		let pk = match(line, /packets=([0-9]+).*packets=([0-9]+)/);
		let wp = match(line, /dport=[0-9]+ .*dport=([0-9]+)/);
		if (!src || !cp || !dst || !sp || !pk || !wp) continue;
		let sport = +sp[1];
		if (!game_port(sport)) continue;
		let ip = dst[1], wport = +wp[1], out = +pk[1], inn = +pk[2];
		let rkey = `${ip}|${wport}`;
		if (out < FREEZE_OUT || inn > FREEZE_IN || reported[rkey]) continue;
		reported[rkey] = true;
		let t = targets[`${ip}|${sport}`];
		if (t) {
			t.good = filter(t.good, p => p != wport);
			t.tried[wport] = true;
		}
		log(sprintf('frozen flow %s:%d via wan port %d (out %d, in %d) - port dropped', ip, sport, wport, out, inn));
		stat('frozen');
		set_standby(false, sprintf('%s:%d', ip, sport));
		nofake_tries = nofake_good = 0;
		let fkey = `${src[1]}|${+cp[1]}|${ip}|${sport}`;
		remaps[fkey] = (remaps[fkey] ?? 0) + 1;
		if (remaps[fkey] <= MAX_REMAPS)
			remap(src[1], +cp[1], ip, sport);
	}
}

function keep_alive() {
	if (time() - last_alive >= 1) {
		// re-adding an existing element does not extend its timeout; replace it atomically
		nft([ 'flush set ip fnport alive', `add element ip fnport alive { ${join(', ', PCS)} }` ]);
		last_alive = time();
	}
}

if (!WAN_DEV || !length(PCS) || !length(PORT_RANGES)) {
	log('nothing to do: no WAN device, devices or port ranges configured');
	exit(0);
}

load_stats();
recall();
// a restart or shutdown keeps the counters: procd stops the daemon with SIGTERM
if (type(signal) == 'function')
	for (let sig in [ 'SIGTERM', 'SIGINT' ])
		signal(sig, () => { write_stats(true); exit(0); });

log(sprintf('started: wan %s, devices %s, whitelist fake %s', WAN_DEV, join(' ', PCS),
	length(FAKES) ? sprintf('%s, ttl %d%s', FAKES[fake_idx].name, FAKE_TTL,
		length(FAKES) > 1 ? sprintf(' (%d spare)', length(FAKES) - 1) : '') : 'off'));
write_stats(false);
while (true) {
	keep_alive();
	check_frozen();
	tick_stats();

	let pending = map(list_elems('set', 'pending'), elem_key);
	if (length(pending)) {
		let wan = wan_ip();
		// source ports already handed out per server . server port
		let used = {};
		for (let e in list_elems('map', 'assign')) {
			let k = elem_key(e[0]), v = elem_key(e[1]);
			if (!used[`${k[0]}|${k[2]}`]) used[`${k[0]}|${k[2]}`] = {};
			used[`${k[0]}|${k[2]}`][v[1]] = true;
		}

		for (let f in pending) {
			let ip = f[0], cport = f[1], sport = f[2];
			let key = `${ip}|${sport}`;
			if (!used[key]) used[key] = {};
			let pick = null;
			// asking for one more good port than already used triggers a new probe batch when all are busy
			for (let round = 0; round < MAX_ROUNDS && pick == null && wan && !standby; round++) {
				let t = refresh_target(ip, sport, length(keys(used[key])) + 1 + round);
				for (let p in t.good)
					if (!used[key][p]) { pick = p; break; }
				keep_alive();
			}
			let tuple = `${ip} . ${cport} . ${sport}`;
			let cmds = [];
			if (pick != null) {
				used[key][pick] = true;
				// refresh the whitelist for this very tuple: the probe may have been a while ago
				if (fake_on()) fake_from(pick, ip, sport);
				// the probe left a router-originated conntrack entry with the very same tuple
				system(`conntrack -D -p udp --orig-port-src ${pick} --orig-dst ${ip} --orig-port-dst ${sport} >/dev/null 2>&1`);
				push(cmds, `add element ip fnport assign { ${tuple} : ${wan} . ${pick} }`);
				log(sprintf('flow %s:%d (pc:%d) -> wan port %d', ip, sport, cport, pick));
				stat('flows');
			}
			else if (standby) {
				log(sprintf('flow %s:%d (pc:%d) -> passing as is (standing by)', ip, sport, cport));
				stat('passed');
			}
			else {
				log(sprintf('flow %s:%d (pc:%d) -> no good port, passing as is', ip, sport, cport));
				stat('nogood');
			}
			push(cmds, `add element ip fnport assigned { ${tuple} }`);
			push(cmds, `delete element ip fnport pending { ${tuple} }`);
			nft(cmds);
			keep_alive();

			// Fortnite pairs the match port with the control port by suffix (15062 -> 9062):
			// probe it now so the match connection does not wait for its own probe
			if (pick != null && PAIR_FROM && sport >= PAIR_FROM[0] && sport <= PAIR_FROM[1]) {
				let mport = sport + PAIR_OFFSET;
				let mt = targets[`${ip}|${mport}`];
				if (!mt || time() - mt.ts > GOOD_TTL) {
					refresh_target(ip, mport, 1);
					keep_alive();
				}
			}
		}
	}
	socket.poll(100);
}
