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
	var st = { flows: 0, nogood: 0, frozen: 0, probes: 0, good: 0, tested: 0, rows: [] };

	(text || '').trim().split(/\n/).forEach(function(l) {
		var lm = l.match(LINE_RE), m;
		if (!lm)
			return;
		var msg = lm[2];
		if ((m = msg.match(/^probe \S+ via \S+(?: port)?: (\d+) good, (\d+) frozen, (\d+) silent/))) {
			st.probes++;
			st.good += +m[1];
			st.tested += +m[1] + +m[2] + +m[3];
		}
		else if (/^flow .* -> wan port/.test(msg) && !/ remapped /.test(msg))
			st.flows++;
		else if (/no good port/.test(msg))
			st.nogood++;
		else if (/^frozen flow/.test(msg))
			st.frozen++;

		st.rows.push([ lm[1], msg ]);
	});

	st.rows = st.rows.slice(-40).reverse();
	return st;
}

return view.extend({
	load: function() {
		return Promise.all([
			L.resolveDefault(callServiceList('fnport'), {}),
			L.resolveDefault(fs.exec_direct('/sbin/logread', [ '-e', 'fnport' ]), '')
		]);
	},

	renderStatus: function(data) {
		var running = isRunning(data[0]);
		var st = parseLog(data[1]);
		var passRate = st.tested ? Math.round(100 * st.good / st.tested) : 0;

		var summary = E('table', { 'class': 'table' }, [
			E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td left', 'width': '40%' }, _('Service')),
				E('td', { 'class': 'td left' }, running
					? E('span', { 'style': 'color:green' }, _('running'))
					: E('span', { 'style': 'color:red' }, _('not running')))
			]),
			E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td left' }, _('Connections sent through a passing port')),
				E('td', { 'class': 'td left' }, String(st.flows))
			]),
			E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td left' }, _('Connections with no passing port found')),
				E('td', { 'class': 'td left' }, String(st.nogood))
			]),
			E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td left' }, _('Connections frozen anyway')),
				E('td', { 'class': 'td left' }, String(st.frozen))
			]),
			E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td left' }, _('Probed ports passing the DPI')),
				E('td', { 'class': 'td left' }, '%d / %d (%d%%)'.format(st.good, st.tested, passRate))
			])
		]);

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

		return E('div', {}, [
			E('h3', {}, _('Summary (since the system log was last cleared)')),
			summary,
			E('h3', {}, _('Recent events')),
			log
		]);
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
			container
		]);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
