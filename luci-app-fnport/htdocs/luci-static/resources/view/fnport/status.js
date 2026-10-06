'use strict';
'require view';
'require fs';
'require rpc';
'require poll';
'require ui';
'require dom';

var callServiceList = rpc.declare({
	object: 'service',
	method: 'list',
	params: [ 'name' ],
	expect: { '': {} }
});

function isRunning(res) {
	try {
		var inst = res.fnport.instances;
		return Object.keys(inst).some(function(k) { return inst[k].running; });
	} catch (e) {
		return false;
	}
}

// only lines logged under the fnport tag: `logread -e` matches the word anywhere in any line
var LINE_RE = /^\w{3} (\w{3} +\d+ [\d:]+) \d{4} [\w.]+ fnport(?:\[\d+\])?: (.*)$/;

function parseLog(text) {
	var st = { rows: [] };

	(text || '').trim().split(/\n/).forEach(function(l) {
		var lm = l.match(LINE_RE);
		if (lm)
			st.rows.push([ lm[1], lm[2] ]);
	});

	st.rows = st.rows.slice(-40).reverse();
	return st;
}

var RELEASES = 'https://api.github.com/repos/YUNGSLXRD/fnport/releases/latest';

function versionParts(v) {
	return String(v || '').replace(/^v/, '').replace(/-.*$/, '').split('.').map(Number);
}

function newer(a, b) {
	var x = versionParts(a), y = versionParts(b);
	for (var i = 0; i < 3; i++)
		if ((x[i] || 0) != (y[i] || 0))
			return (x[i] || 0) > (y[i] || 0);
	return false;
}

// what the user should do, from the service's own state and the last hours of statistics
function hints(running, stats) {
	var out = [], n = (stats && stats.now) || {};
	if (!running || !n.updated)
		return out;
	if (n.vpn)
		out.push(_('Device %s seems to use a VPN (%s): its game traffic may go past fnport. Turn the VPN off while playing.').format(n.vpn.device, n.vpn.kind));
	if (n.fake_off_until)
		out.push(_('The whitelist fake is off until %s: on this network it breaks connections. If connections freeze, run the ISP check.').format(clock(n.fake_off_until)));
	var recent = {}, now = Date.now() / 1000;
	Object.keys((stats && stats.hours) || {}).forEach(function(h) {
		if (+h > now - 3 * 3600)
			sumInto(recent, stats.hours[h]);
	});
	var conns = (recent.flows || 0) + (recent.passed || 0) + (recent.nogood || 0);
	if (conns >= 5 && ((recent.frozen || 0) + (recent.nogood || 0)) * 3 >= conns)
		out.push(_('Many connections froze or found no passing port in the last hours. Run the ISP check: the fake TTL may need a change.'));
	return out;
}

var COLS = [
	[ 'flows', _('Through a passing port') ],
	[ 'passed', _('Passed as is (standby)') ],
	[ 'nogood', _('No passing port') ],
	[ 'frozen', _('Frozen anyway') ],
	[ 'remaps', _('Moved to a new port') ]
];

function pad(n) {
	return (n < 10 ? '0' : '') + n;
}

function clock(ts) {
	var d = new Date(ts * 1000);
	return pad(d.getHours()) + ':' + pad(d.getMinutes());
}

function dayName(d) {
	return '%s.%s'.format(pad(d.getDate()), pad(d.getMonth() + 1));
}

function sumInto(acc, h) {
	Object.keys(h).forEach(function(k) { acc[k] = (acc[k] || 0) + h[k]; });
	return acc;
}

function statsTable(rows, firstTitle) {
	var head = [ E('th', { 'class': 'th' }, firstTitle) ].concat(COLS.map(function(c) {
		return E('th', { 'class': 'th' }, c[1]);
	})).concat([ E('th', { 'class': 'th' }, _('Probed ports passing')) ]);

	// seven columns do not fit a phone: let the table scroll instead of cutting it
	return E('div', { 'style': 'overflow-x:auto' }, E('table', { 'class': 'table' }, [ E('tr', { 'class': 'tr table-titles' }, head) ].concat(rows.map(function(r) {
		var v = r[1];
		return E('tr', { 'class': 'tr' }, [ E('td', { 'class': 'td' }, [ r[0] ]) ].concat(COLS.map(function(c) {
			return E('td', { 'class': 'td' }, [ String(v[c[0]] || 0) ]);
		})).concat([ E('td', { 'class': 'td' }, [
			v.tested ? '%d / %d (%d%%)'.format(v.good || 0, v.tested, Math.round(100 * (v.good || 0) / v.tested)) : '-'
		]) ]));
	}))));
}

function renderStats(stats) {
	var hours = (stats && stats.hours) || {};
	var keys = Object.keys(hours).map(Number).sort(function(a, b) { return a - b; });
	if (!keys.length)
		return [ E('p', {}, [ _('No connections yet.') ]) ];

	var days = {}, order = [];
	keys.forEach(function(h) {
		var d = new Date(h * 1000), k = dayName(d);
		if (!days[k]) { days[k] = {}; order.push(k); }
		sumInto(days[k], hours[h]);
	});

	var now = Date.now() / 1000;
	var recent = keys.filter(function(h) { return h > now - 24 * 3600; }).reverse().map(function(h) {
		return [ '%s %s-%s'.format(dayName(new Date(h * 1000)), clock(h), clock(h + 3600)), hours[h] ];
	});

	return [
		E('h3', {}, _('By day (last 7 days)')),
		statsTable(order.reverse().map(function(k) { return [ k, days[k] ]; }), _('Day')),
		E('h3', {}, _('Last 24 hours')),
		statsTable(recent, _('Hour'))
	];
}

function renderNow(running, stats) {
	var n = (stats && stats.now) || {};
	var rows = [
		[ _('Service'), running
			? E('span', { 'style': 'color:green' }, _('running'))
			: E('span', { 'style': 'color:red' }, _('not running')) ]
	];
	if (running && n.updated) {
		rows.push([ _('Mode'), n.standby
			? _('standing by: nothing freezes on this network, connections pass as they are')
			: _('active: probing ports for new connections') ]);
		rows.push([ _('Whitelist fake'), !n.fake ? _('off')
			: (n.fake_off_until ? _('%s, off until %s: it breaks connections on this network').format(n.fake, clock(n.fake_off_until))
				: (n.standby ? _('%s, not needed while standing by').format(n.fake) : n.fake)) ]);
		if (n.probe_off_until)
			rows.push([ _('Handshake probes'), _('paused until %s: the server limits replies to this address').format(clock(n.probe_off_until)) ]);
		rows.push([ _('Version'), '%s, %s %s'.format(n.version, _('started at'), clock(n.started)) ]);
	}
	return E('table', { 'class': 'table' }, rows.map(function(r) {
		return E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td left', 'width': '30%' }, [ r[0] ]),
			E('td', { 'class': 'td left' }, [ r[1] ])
		]);
	}));
}

return view.extend({
	load: function() {
		return Promise.all([
			L.resolveDefault(callServiceList('fnport'), {}),
			L.resolveDefault(fs.exec_direct('/sbin/logread', [ '-e', 'fnport' ]), ''),
			L.resolveDefault(fs.read('/var/run/fnport-stats.json').then(JSON.parse), null)
		]);
	},

	renderStatus: function(data) {
		var running = isRunning(data[0]);
		var st = parseLog(data[1]);
		var stats = data[2];

		var log = E('table', { 'class': 'table' }, [
			E('tr', { 'class': 'tr table-titles' }, [
				E('th', { 'class': 'th', 'width': '20%' }, _('Time')),
				E('th', { 'class': 'th' }, _('Event'))
			])
		].concat(st.rows.map(function(r) {
			return E('tr', { 'class': 'tr' }, [
				// arrays become text nodes; a plain string would be set as innerHTML
				E('td', { 'class': 'td' }, [ r[0] ]),
				E('td', { 'class': 'td' }, [ r[1] ])
			]);
		})));

		var tips = hints(running, stats);
		return E('div', {}, (tips.length ? [
			E('h3', {}, _('Hints')),
			E('ul', {}, tips.map(function(t) { return E('li', {}, [ t ]); }))
		] : []).concat([
			E('h3', {}, _('Now')),
			renderNow(running, stats)
		]).concat(renderStats(stats)).concat([
			E('h3', {}, _('Recent events')),
			log
		]));
	},

	// a newer release: offer the installer, the same one the README runs
	renderUpdate: function(stats) {
		var box = E('div', {}), cur = stats && stats.now && stats.now.version;
		if (!cur)
			return box;
		fetch(RELEASES).then(function(r) { return r.json(); }).then(function(rel) {
			if (!rel || !rel.tag_name || !newer(rel.tag_name, cur))
				return;
			var log = E('pre', { 'style': 'display:none;max-height:12em;overflow:auto' });
			var btn = E('button', { 'class': 'cbi-button cbi-button-apply' }, [ _('Update') ]);
			btn.addEventListener('click', function() {
				btn.disabled = true;
				fs.exec('/usr/libexec/fnport-update', [ 'start' ]).then(function() {
					log.style.display = '';
					var timer = window.setInterval(function() {
						fs.exec('/usr/libexec/fnport-update', [ 'status' ]).then(function(res) {
							var st = JSON.parse(res.stdout || '{}');
							log.textContent = st.log || '';
							if (!st.running && /exit \d+/.test(st.log || '')) {
								window.clearInterval(timer);
								if (/exit 0/.test(st.log))
									ui.addNotification(null, E('p', _('fnport updated. Reload the page to see the new version.')), 'info');
								else
									ui.addNotification(null, E('p', _('The update failed, see the log below.')), 'danger');
							}
						});
					}, 2000);
				});
			});
			dom.content(box, E('div', { 'class': 'alert-message notice' }, [
				E('p', {}, [ _('fnport %s is out (installed: %s).').format(rel.tag_name.replace(/^v/, ''), cur.replace(/-.*$/, '')), ' ',
					E('a', { 'href': rel.html_url, 'target': '_blank', 'rel': 'noopener noreferrer' }, [ _('What is new') ]) ]),
				btn, log
			]));
		}).catch(function() {});
		return box;
	},

	render: function(data) {
		var container = E('div', {}, this.renderStatus(data));

		poll.add(L.bind(function() {
			return this.load().then(L.bind(function(d) {
				dom.content(container, this.renderStatus(d));
			}, this));
		}, this), 5);

		return E('div', {}, [
			E('h2', {}, _('fnport status')),
			this.renderUpdate(data[2]),
			container
		]);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
