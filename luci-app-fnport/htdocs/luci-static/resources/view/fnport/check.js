'use strict';
'require view';
'require fs';
'require poll';
'require ui';
'require dom';

var CHECK = '/usr/libexec/fnport-check';
var ISSUE_URL = 'https://github.com/YUNGSLXRD/fnport/issues/new?template=provider-report.yml';
var PASS = 26, FROZEN_MIN = 20, PKTS = 30, LOSSY = 1000;

function run(arg) {
	return fs.exec(CHECK, [ arg ]).then(function(res) {
		try {
			return JSON.parse(res.stdout || '{}');
		} catch (e) {
			return { error: res.stderr || String(e) };
		}
	});
}

// same thresholds as fnport-check
function verdictOf(r) {
	if (r >= LOSSY) return 'pass';
	return r >= PASS ? 'pass' : (r >= FROZEN_MIN ? 'frozen' : (r > 0 ? 'limited' : 'silent'));
}

// the most the line lost to the beacons without a freeze, in %; 0 = no such probe
function lossOf(st) {
	var loss = 0;
	(st.control || []).forEach(function(c) {
		(c.replies || []).forEach(function(r) {
			if (r >= LOSSY) loss = Math.max(loss, Math.round((PKTS - r % LOSSY) * 100 / PKTS));
		});
	});
	return loss;
}

function count(replies, what) {
	return (replies || []).filter(function(r) { return verdictOf(r) == what; }).length;
}

function cityName(c) {
	return { frankfurt: _('Frankfurt'), london: _('London'), paris: _('Paris') }[c] || _('Europe');
}

// AWS EU regions by prefix, same table as fnport-check: the report shows cities, not addresses
function cityOf(ip) {
	var o = ip.split('.').map(Number), x = o[0], y = o[1];
	if ((x == 3 && y >= 64 && y <= 79) || (x == 18 && y >= 153 && y <= 159) || (x == 35 && y >= 156 && y <= 159))
		return 'frankfurt';
	if ((x == 3 && y >= 8 && y <= 11) || (x == 18 && ((y >= 130 && y <= 135) || (y >= 168 && y <= 171))) ||
	    (x == 13 && y >= 40 && y <= 43) || (x == 35 && y >= 176 && y <= 179))
		return 'london';
	if ((x == 13 && y >= 36 && y <= 39) || (x == 15 && (y == 188 || y == 236 || y == 237)) || (x == 35 && (y == 180 || y == 181)))
		return 'paris';
	return null;
}

function maskAddresses(line) {
	return line.replace(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g, function(ip) {
		var c = cityOf(ip);
		return c ? 'aws-' + c : 'x.x.x.x';
	});
}

var LINE_RE = /^\w{3} (\w{3} +\d+ [\d:]+) \d{4} [\w.]+ fnport(?:\[\d+\])?: (.*)$/;

function logSummary(text) {
	var st = { flows: 0, nogood: 0, frozen: 0, good: 0, tested: 0, remaps: 0, fakeoff: 0, lines: [] };
	(text || '').trim().split(/\n/).forEach(function(l) {
		var lm = l.match(LINE_RE), m;
		if (!lm)
			return;
		var msg = lm[2];
		if ((m = msg.match(/^probe \S+ via \S+(?: port)?: (\d+) good, (\d+) frozen, (\d+) silent(?:, (\d+) limited)?/))) {
			st.good += +m[1];
			st.tested += +m[1] + +m[2] + +m[3] + +(m[4] || 0);
		}
		else if (/ remapped /.test(msg))
			st.remaps++;
		else if (/^flow .* -> wan port/.test(msg))
			st.flows++;
		else if (/no good port/.test(msg))
			st.nogood++;
		else if (/^frozen flow/.test(msg))
			st.frozen++;
		else if (/whitelist fake breaks flows/.test(msg))
			st.fakeoff++;
		st.lines.push(lm[1] + ' ' + maskAddresses(msg));
	});
	st.lines = st.lines.slice(-25);
	return st;
}

function stepText(st) {
	switch (st.step) {
	case 'control': return _('Checking for the freeze without the fake…');
	case 'ttl': return (st.fake_now && st.fake_now != st.fake)
		? _('Trying the spare fake %s with TTL %d…').format(st.fake_now, st.ttl_now)
		: _('Trying the fake with TTL %d…').format(st.ttl_now);
	case 'fake': return _('Comparing the fake on the same beacon…');
	default: return _('Looking up Epic\'s beacons…');
	}
}

function verdictText(st) {
	var loss = lossOf(st), v = verdictMain(st);
	// seen at SkyNet over Wi-Fi: 23 of 30 everywhere, with and without the fake
	return loss ? _('Some probes received packets past number 25 with up to %d%% missing replies. This proves those probes were not frozen; it does not establish where packets were lost.').format(loss) + ' ' + v : v;
}

function verdictMain(st) {
	switch (st.verdict) {
	case 'no_freeze':
		return _('No packet-count freeze was detected on the tested Epic beacons. This result alone does not establish how the game server or the fake will behave.');
	case 'fake_works':
		return st.recommended_fake
			? _('The ISP freezes game UDP. The first fake did not help, but the spare %s does. Recommended fake TTL: %d.').format(st.recommended_fake, st.recommended_ttl)
			: _('The ISP freezes game UDP, and the whitelist fake lifts the freeze. Recommended fake TTL: %d.').format(st.recommended_ttl);
	case 'fake_partial':
  return _('Some ports passed with the fake, but the replies are mixed. Keep the current fake and TTL; game connections still need port selection.');
 case 'fake_kills':
		return _('The ISP freezes game UDP, and the fake kills the whole flow once it gets far enough (from TTL %d). fnport can only look for passing ports without the fake here. Please send a report.').format(st.fake_kills_from);
	case 'fake_fails':
		return _('A packet-count freeze was detected, but the tried fakes and TTLs did not give a confirmed improvement. Limited or mixed replies remain inconclusive. Please send the report.');
	case 'freeze_no_fake':
		return _('The ISP freezes game UDP, but the fake file is missing, so it could not be tried.');
	case 'unclear':
		return _('No clear answer: no beacon froze, but some answered only part of the packets. The beacons limit replies when asked often, or the link loses packets. Try again in 15-30 minutes.');
	case 'no_reply':
		return _('Epic\'s beacons did not answer. UDP to them may be blocked, or a VPN on the router takes this traffic. Please send a report.');
	default:
		return _('Unknown result.');
	}
}

function repliesText(r) {
	return (r || []).map(function(x) { return x >= LOSSY ? _('%d (loss)').format(x % LOSSY) : String(x); }).join(', ');
}

function report(st, log, stats) {
	var ls = logSummary(log);
	var wan = { 'public': _('public'), lan: _('private: behind another router'), 'private': _('private: behind another router or ISP NAT') }[st.wan_kind] || st.wan_kind;
	var src = { dns: _('router DNS'), public_dns: _('public DNS'), builtin: _('built-in list') }[st.beacon_source] || st.beacon_source;
	var out = [
		'**fnport** %s, OpenWrt %s (%s)'.format(st.version, st.openwrt, st.target),
		'**%s**: %s'.format(_('ISP, city, connection type'), _('<fill in>')),
		'**%s**: %s'.format(_('Router WAN address'), wan),
		'**%s**: %s'.format(_('Beacons found via'), src),
		'**%s**: %s'.format(_('Without the fake (replies out of 30)'),
			(st.control || []).map(function(c) { return cityName(c.city) + ' ' + repliesText(c.replies); }).join('; '))
	];
	if (st.ttl)
		out.push('**%s** (%s): %s'.format(_('With the fake'), cityName(st.beacon),
			st.ttl.map(function(e) { return 'TTL %d: %s'.format(e.ttl, repliesText(e.replies)); }).join('; ')));
	(st.spares || []).forEach(function(sp) {
		out.push('**%s %s**: %s'.format(_('Spare fake'), sp.fake,
			(sp.ttl || []).map(function(e) { return 'TTL %d: %s'.format(e.ttl, repliesText(e.replies)); }).join('; ')));
	});
	if (st.fake_check) {
  out.push('**%s** (%s): %s'.format(_('Same-beacon control'),cityName(st.fake_check.city),repliesText(st.fake_check.control)));
  out.push('**%s**: TTL %d: %s (%s)'.format(_('Fake at the current TTL'),st.fake_check.ttl,repliesText(st.fake_check.replies),st.fake_check.verdict || 'unclear'));
 }
 if (st.kill_control) out.push('**%s**: %s'.format(_('Control after silent fake probes'),repliesText(st.kill_control)));
	var short = {
		no_freeze: _('no freeze'), fake_works: _('the fake works'), fake_kills: _('the fake kills flows'),
		fake_partial: _('mixed replies with the fake'), fake_fails: _('the fake does not help'), unclear: _('unclear'), no_reply: _('no reply'), freeze_no_fake: _('no fake file')
	}[st.verdict] || st.verdict;
	out.push('**%s**: %s'.format(_('Result'), short + ' (' + st.verdict + ')' +
		(st.recommended_ttl ? ', TTL %d (%s %d)'.format(st.recommended_ttl, _('tested TTL'), st.recommended_ttl) : '')));
	out.push('**%s**: TTL %d, %s'.format(_('Settings'), st.now_ttl,
		st.now_fake ? _('fake %s').format(st.fake) : _('fake off')));
	if (stats && stats.hours) {
		// a week of counters beats the few hours the system log keeps
		var w = {};
		Object.keys(stats.hours).forEach(function(h) {
			Object.keys(stats.hours[h]).forEach(function(k) { w[k] = (w[k] || 0) + stats.hours[h][k]; });
		});
		var n = stats.now || {};
		out.push('**%s**: %s'.format(_('Statistics, 7 days'),
			_('%d connections through a passing port, %d passed as is in standby, %d without a port, %d frozen anyway, %d remapped, fake turned off %d times, fake switched %d times, %d of %d probed ports passed')
				.format(w.flows || 0, w.passed || 0, w.nogood || 0, w.frozen || 0, w.remaps || 0, w.fakeoff || 0, w.fakeswitch || 0, w.good || 0, w.tested || 0)));
		out.push('**%s**: %s'.format(_('Mode'), (n.standby ? 'standby' : 'active') + (n.fake ? ', ' + n.fake : '') + (n.fake_off_until ? ', fake off' : '')));
	}
	else
		out.push('**%s**: %s'.format(_('fnport log'),
			_('%d connections through a passing port, %d without one, %d frozen anyway, %d remapped, fake turned off %d times, %d of %d probed ports passed')
				.format(ls.flows, ls.nogood, ls.frozen, ls.remaps, ls.fakeoff, ls.good, ls.tested)));
	out.push('', '<details><summary>%s</summary>'.format(_('Recent events (addresses hidden)')), '', '```');
	out = out.concat(ls.lines);
	out.push('```', '</details>');
	return out.join('\n');
}

function copyText(textarea) {
	textarea.select();
	try {
		if (document.execCommand('copy'))
			return ui.addNotification(null, E('p', _('Report copied.')), 'info');
	} catch (e) {}
	ui.addNotification(null, E('p', _('Select the text and copy it by hand.')), 'warning');
}

return view.extend({
	load: function() {
		return Promise.all([
			L.resolveDefault(run('status'), { state: 'none' }),
			L.resolveDefault(fs.exec_direct('/sbin/logread', [ '-e', 'fnport' ]), ''),
			L.resolveDefault(fs.read('/var/run/fnport-stats.json').then(JSON.parse), null)
		]);
	},

	handleStart: function(ev) {
		ev.target.disabled = true;
		return run('start').then(L.bind(function(res) {
			if (res.error == 'cooldown')
				ui.addNotification(null, E('p', _('Please wait %d more seconds before the next check: probing often gets the address punished.').format(res.wait)), 'warning');
			else if (res.error == 'running')
				ui.addNotification(null, E('p', _('A check is already running.')), 'info');
			else if (res.error)
				ui.addNotification(null, E('p', [ res.error ]), 'danger');
			return this.refresh();
		}, this));
	},

	handleApply: function(ev) {
		ev.target.disabled = true;
		return run('apply').then(L.bind(function(res) {
			if (res.applied)
				ui.addNotification(null, E('p', _('Fake TTL set to %d, fnport restarted.').format(res.applied)), 'info');
			else
				ui.addNotification(null, E('p', [ res.error || _('Nothing to apply.') ]), 'danger');
			return this.refresh();
		}, this));
	},

	refresh: function() {
		return this.load().then(L.bind(function(d) {
			dom.content(this.container, this.renderState(d[0], d[1], d[2]));
		}, this));
	},

	renderState: function(st, log, stats) {
		var running = this.running = (st.state == 'running');
		var nodes = [
			E('div', { 'class': 'cbi-page-actions', 'style': 'text-align:left' }, [
				E('button', {
					'class': 'cbi-button cbi-button-action',
					'disabled': running ? '' : null,
					'click': ui.createHandlerFn(this, 'handleStart')
				}, [ running ? _('Checking…') : _('Check my ISP') ])
			])
		];

		if (running) {
			nodes.push(E('p', {}, [ E('em', {}, [ stepText(st) ]) ]));
			return E('div', {}, nodes);
		}
		if (st.state == 'failed') {
			nodes.push(E('p', { 'style': 'color:red' }, [ _('The check stopped unexpectedly.') + (st.error ? ' ' + st.error : '') ]));
			return E('div', {}, nodes);
		}
		if (st.state != 'done')
			return E('div', {}, nodes);

		nodes.push(E('h3', {}, _('Result')));
		nodes.push(E('p', {}, [ E('strong', {}, [ verdictText(st) ]) ]));

		if (st.verdict == 'no_freeze' && st.fake_check && st.fake_check.verdict == 'kills')
			nodes.push(E('p', { 'style': 'color:#c60' }, [ _('At TTL %d the fake probes stopped replying, while both control probes on the same beacon passed. This check does not change your settings.').format(st.fake_check.ttl) ]));

		if (st.policy == 3 && st.recommended_ttl) {
			var selected = st.recommended_fake || st.fake;
   var steps = selected == st.fake ? st.ttl || [] : ((st.spares || []).filter(function(sp){return sp.fake == selected;})[0] || {}).ttl || [];
   var measuredCurrent = steps.some(function(e){return e.ttl == st.now_ttl && count(e.replies,'pass') >= 2;});
   if (st.now_fake && st.now_fake_name == selected && measuredCurrent)
				nodes.push(E('p', {}, [ _('Your current TTL %d passed the recorded probes with this fake.').format(st.now_ttl) ]));
			else
				nodes.push(E('p', {}, [
					E('button', {
						'class': 'cbi-button cbi-button-apply',
						'click': ui.createHandlerFn(this, 'handleApply')
					}, [ st.recommended_fake
						? _('Apply TTL %d and fake %s').format(st.recommended_ttl, st.recommended_fake)
						: _('Apply TTL %d').format(st.recommended_ttl) ]),
					' ',
					_('Now: TTL %d%s. Applying restarts fnport. Apply outside a match.').format(st.now_ttl, st.now_fake ? '' : _(', fake off'))
				]));
		}

		var rows = [ E('tr', { 'class': 'tr table-titles' }, [
			E('th', { 'class': 'th' }, _('Test')),
			E('th', { 'class': 'th' }, _('Replies out of 30 per port')),
			E('th', { 'class': 'th' }, _('Verdict'))
		]) ];
		var row = function(name, replies) {
			var v = count(replies, 'pass') ? _('passes') : (count(replies, 'frozen') ? _('frozen')
				: (count(replies, 'limited') ? _('few replies') : _('no reply')));
			rows.push(E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td' }, [ name ]),
				E('td', { 'class': 'td' }, [ repliesText(replies) ]),
				E('td', { 'class': 'td' }, [ v ])
			]));
		};
		(st.control || []).forEach(function(c) { row(_('%s, no fake').format(cityName(c.city)), c.replies); });
		(st.ttl || []).forEach(function(e) { row(_('%s, fake TTL %d').format(cityName(st.beacon), e.ttl), e.replies); });
		(st.spares || []).forEach(function(sp) {
			(sp.ttl || []).forEach(function(e) { row(_('%s, spare %s, TTL %d').format(cityName(st.beacon), sp.fake, e.ttl), e.replies); });
		});
		if (st.fake_check) {
   row(_('%s, no fake').format(cityName(st.fake_check.city)), st.fake_check.control);
   row(_('%s, fake TTL %d').format(cityName(st.fake_check.city),st.fake_check.ttl),st.fake_check.replies);
   nodes.push(E('p',{},st.fake_check.verdict == 'harmless' ? _('Both probes passed with and without the fake on the same beacon. This is not a guarantee for game servers.') : st.fake_check.verdict == 'kills' ? _('The control probes passed; the fake probes did not reply.') : _('The fake comparison is inconclusive. No setting change is recommended from it.')));
  }
		nodes.push(E('table', { 'class': 'table' }, rows));
		nodes.push(E('p', { 'class': 'cbi-section-descr' }, [
			_('More than 25 replies, or a tagged reply past packet 25: the probe was not frozen. 20-25 replies without a later packet suggest a freeze. Fewer replies can be rate limiting, filtering or loss. A beacon result is not a game-server guarantee.')
		]));

		var ta = E('textarea', { 'class': 'cbi-input-textarea', 'readonly': '', 'rows': 14, 'style': 'width:100%;font-family:monospace' }, [ report(st, log, stats) ]);
		nodes.push(E('h3', {}, _('Report for the developers')));
		nodes.push(E('p', { 'class': 'cbi-section-descr' }, [
			_('No addresses of your network inside: servers are shown as cities. Fill in your ISP and city and post it as an issue on GitHub; reports from different ISPs help tune the defaults.')
		]));
		nodes.push(ta);
		nodes.push(E('p', {}, [
			E('button', { 'class': 'cbi-button', 'click': function() { copyText(ta); } }, [ _('Copy report') ]),
			' ',
			E('a', { 'href': ISSUE_URL, 'target': '_blank', 'rel': 'noopener noreferrer' }, [ _('Open an issue on GitHub') ])
		]));
		return E('div', {}, nodes);
	},

	render: function(data) {
		this.container = E('div', {}, this.renderState(data[0], data[1], data[2]));

		poll.add(L.bind(function() {
			// only while a check runs; the log part of the report is refreshed with it
			if (this.running)
				return this.refresh();
		}, this), 2);

		return E('div', {}, [
			E('h2', {}, _('ISP check')),
			E('p', { 'class': 'cbi-map-descr' }, [
				_('Checks packet-count freezes on Epic\'s public beacons and compares whitelist fakes and measured TTLs. Slow retries can take several minutes. Run outside a match and avoid repeated checks.')
			]),
			this.container
		]);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
