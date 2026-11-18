'use strict';
'require view';
'require form';
'require fs';
'require uci';
'require ui';
'require poll';
'require dom';
'require network';
'require tools.widgets as widgets';

var CTL = '/usr/libexec/fnport-connectionsctl';

function callCtl(action) {
	return fs.exec(CTL, [ action ]).then(function(r) {
		try {
			return JSON.parse(r.stdout || '{}');
		} catch (e) {
			return { error: 'action_failed' };
		}
	});
}

var ERRORS = {
	insufficient_storage: _('At least 140 MB of free storage is required. Use external storage or extroot.'),
	unsupported_architecture: _('This router architecture is not supported.'),
	deps_install_failed: _('Could not install required OpenWrt network packages (kmod-tun, kmod-nft-tproxy, ip-full, ca-bundle).'),
	release_unreachable: _('Could not download release files from GitHub.'),
	core_download_failed: _('Could not download sing-box.'),
	helper_download_failed: _('Could not download connection components.'),
	helper_checksum_failed: _('The downloaded helper failed checksum verification.'),
	core_checksum_failed: _('The downloaded core failed checksum verification.'),
	warp_registration_failed: _('WARP registration failed. You can import a ready .conf file.'),
	warp_key_missing: _('Get a WARP key or import a .conf file first.'),
	warp_key_invalid: _('The saved WARP key could not be read.'),
	warp_no_usable_endpoint: _('No WARP endpoint passed the exit and download check.'),
	selected_connection_unreachable: _('The selected connection does not respond.'),
	tunnel_healthcheck_failed: _('The tunnel stopped responding and was restarted.'),
	subscription_fetch_failed: _('Could not load the subscription. Check the https:// link and connection.'),
	invalid_subscription_url: _('Enter a subscription link starting with https:// or http://.'),
	subscription_missing: _('Load the subscription servers first.'),
	core_exited: _('The connection core stopped.'),
	invalid_native_profile: _('Check the WireGuard / AmneziaWG configuration.'),
	invalid_profile: _('Check the connection link or configuration.'),
	core_profile_rejected: _('The core rejected this connection profile.'),
	select_devices: _('Select at least one device.'),
	select_services: _('Select at least one service.'),
	routing_priority_in_use: _('Another service uses the required routing priority.'),
	routing_table_in_use: _('Another service uses the required routing table.'),
	firewall_table_in_use: _('A connection instance is already using the firewall table.')
};

function errorText(code) {
	return ERRORS[code] || _('Connection error: %s').format(code || _('unknown'));
}

function flagEmoji(country) {
	if (!/^[A-Z]{2}$/.test(country || ''))
		return '';
	return String.fromCodePoint(127397 + country.charCodeAt(0), 127397 + country.charCodeAt(1)) + ' ';
}

function renderStatusBox(st) {
	var stateLabels = {
		connected: [ _('Connected'), 'green' ],
		starting: [ _('Starting'), '#c60' ],
		selecting_exit: [ _('Choosing a WARP exit'), '#c60' ],
		failed: [ _('Connection failed'), 'red' ],
		stopped: [ _('Stopped'), '' ]
	};
	var pair = stateLabels[st.state] || stateLabels.stopped;
	var stateSpan = pair[1]
		? E('strong', { 'style': 'color:' + pair[1] }, [ pair[0] ])
		: E('strong', {}, [ pair[0] ]);

	var rows = [
		[ _('Status'), stateSpan ]
	];

	if (st.node_name)
		rows.push([ _('Server'), st.node_name ]);

	if (st.colo || st.address) {
		var exitParts = [];
		if (st.colo)
			exitParts.push(flagEmoji(st.country) + st.colo);
		if (st.address)
			exitParts.push(st.address);
		if (st.rtt_ms > 0)
			exitParts.push(st.rtt_ms + ' ms');
		rows.push([ _('Exit'), exitParts.join(' · ') ]);
	}

	var nodes = [
		E('table', { 'class': 'table' }, rows.map(function(r) {
			return E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td left', 'width': '30%' }, [ r[0] ]),
				E('td', { 'class': 'td left' }, [ r[1] ])
			]);
		}))
	];

	if (st.error)
		nodes.push(E('div', { 'class': 'alert-message warning' }, [ E('p', {}, [ errorText(st.error) ]) ]));

	var a = st.action;
	if (a && a.state === 'running') {
		var runText = a.action === 'install'
			? _('Installing components…')
			: (a.action === 'subscription' ? _('Loading subscription…') : _('Registering a WARP key…'));
		nodes.push(E('div', { 'class': 'alert-message notice' }, [ E('p', {}, [ runText ]) ]));
	}
	else if (a && a.state === 'failed') {
		nodes.push(E('div', { 'class': 'alert-message warning' }, [ E('p', {}, [ errorText(a.error) ]) ]));
	}
	else if (a && a.state === 'done') {
		var doneText = a.action === 'install'
			? _('Components installed. You can enable the connection.')
			: (a.action === 'subscription' ? _('Subscription updated.') : _('The WARP key is saved.'));
		nodes.push(E('p', { 'class': 'cbi-section-descr' }, [ doneText ]));
	}

	return nodes;
}

return view.extend({
	load: function() {
		return Promise.all([
			uci.load('fnport_connections'),
			network.getHostHints(),
			L.resolveDefault(callCtl('status'), { state: 'stopped' })
		]);
	},

	runAction: function(kind) {
		return callCtl(kind).then(function(result) {
			if (result.error)
				ui.addNotification(null, E('p', {}, [ errorText(result.error) ]), 'warning');
		});
	},

	render: function(data) {
		var self = this;
		var hosts = data[1];
		var state = data[2];
		var m, s, o;

		var statusBox = E('div', { 'class': 'cbi-section' }, renderStatusBox(state));

		m = new form.Map('fnport_connections', _('Connections'),
			_('Route Epic services and Discord through WARP or your VPN on selected devices. Fortnite game UDP stays direct through fnport.'));

		s = m.section(form.NamedSection, 'main', 'connections');
		s.tab('general', _('General'));
		s.tab('advanced', _('Advanced'));

		o = s.taboption('general', form.Flag, 'enabled', _('Enable'));
		o.rmempty = false;

		var protoOpt = s.taboption('general', form.ListValue, 'protocol', _('Connection'));
		protoOpt.value('warp', 'WARP');
		protoOpt.value('amneziawg', _('AmneziaWG / WireGuard'));
		protoOpt.value('vpn', _('Subscription or VPN link'));

		var legacyLabels = {
			wireguard: 'WireGuard',
			vless: 'VLESS',
			hysteria2: 'Hysteria 2',
			shadowsocks: 'Shadowsocks',
			trojan: 'Trojan',
			socks: 'SOCKS5'
		};
		var savedProto = uci.get('fnport_connections', 'main', 'protocol');
		if (savedProto && legacyLabels[savedProto])
			protoOpt.value(savedProto, legacyLabels[savedProto]);
		protoOpt.default = 'warp';
		protoOpt.rmempty = false;

		var profileModes = [ 'amneziawg', 'vpn', 'wireguard', 'vless', 'hysteria2', 'shadowsocks', 'trojan', 'socks' ];

		var profileOpt = s.taboption('general', form.TextValue, 'profile', _('Connection profile'),
			_('Paste a subscription https:// link, a vless://, hy2://, ss://, trojan:// or socks5:// link, a WireGuard/AmneziaWG .conf, or a single sing-box JSON outbound.'));
		profileOpt.rows = 4;
		profileOpt.retain = true;
		profileModes.forEach(function(p) {
			profileOpt.depends('protocol', p);
		});

		var importBtn = s.taboption('general', form.Button, '_import', _('Import file'));
		importBtn.inputtitle = _('Choose .conf or .json');
		profileModes.forEach(function(p) {
			importBtn.depends('protocol', p);
		});
		importBtn.onclick = function() {
			var input = E('input', { type: 'file', accept: '.conf,.json,.txt', style: 'display:none' });
			input.addEventListener('change', function() {
				var file = input.files && input.files[0];
				if (!file) {
					input.remove();
					return;
				}
				if (file.size > 1048576) {
					input.remove();
					ui.addNotification(null, E('p', {}, [ _('The configuration file is too large.') ]), 'warning');
					return;
				}
				var reader = new FileReader();
				reader.onload = function() {
					var value = String(reader.result || '');
					uci.set('fnport_connections', 'main', 'profile', value);
					var field = document.getElementById(profileOpt.cbid('main'));
					if (field)
						field.value = value;
					input.remove();
					ui.addNotification(null, E('p', {}, [ _('File imported. Save and apply the settings.') ]), 'info');
				};
				reader.onerror = function() {
					input.remove();
					ui.addNotification(null, E('p', {}, [ _('Could not read the file.') ]), 'warning');
				};
				reader.readAsText(file);
			});
			document.body.appendChild(input);
			input.click();
		};

		var subBtn = s.taboption('general', form.Button, '_subscription', _('Subscription'),
			_('Loads servers from an https:// subscription link and saves them on the router.'));
		subBtn.depends('protocol', 'vpn');
		subBtn.inputtitle = state.subscription ? _('Update subscription') : _('Load servers');
		subBtn.onclick = function() {
			var field = document.getElementById(profileOpt.cbid('main'));
			var val = field ? field.value.trim() : (uci.get('fnport_connections', 'main', 'profile') || '').trim();
			if (!/^https?:\/\//i.test(val)) {
				ui.addNotification(null, E('p', {}, [ _('Enter a subscription link starting with https:// or http://.') ]), 'warning');
				return;
			}
			uci.set('fnport_connections', 'main', 'profile', val);
			uci.set('fnport_connections', 'main', 'protocol', 'vpn');
			return uci.save().then(function() {
				return self.runAction('subscription');
			});
		};

		var nodeOpt = s.taboption('general', form.ListValue, 'node', _('Subscription server'),
			_('Choose a server from your subscription, then save and apply.'));
		nodeOpt.depends('protocol', 'vpn');
		nodeOpt.optional = true;
		nodeOpt.placeholder = _('Automatic (first available)');
		if (state.subscription && Array.isArray(state.subscription.nodes)) {
			state.subscription.nodes.forEach(function(n) {
				nodeOpt.value(n.id, flagEmoji(n.country) + n.name + ' (' + n.badge + ')');
			});
			if (!uci.get('fnport_connections', 'main', 'node') && state.subscription.selected)
				nodeOpt.default = state.subscription.selected;
		}

		var keyBtn = s.taboption('general', form.Button, '_key', _('WARP key'),
			_('The key is stored on this router and reused when settings change.'));
		keyBtn.depends('protocol', 'warp');
		keyBtn.inputtitle = state.key_ready ? _('Refresh WARP key') : _('Get a key');
		keyBtn.onclick = function() {
			return self.runAction('register');
		};

		o = s.taboption('general', form.Flag, 'epic', _('Epic services'), _('Login, store and downloads.'));
		o.rmempty = false;
		o.default = '1';

		o = s.taboption('general', form.Flag, 'discord', _('Discord'), _('Messaging and voice. All supported protocols carry UDP for voice.'));
		o.rmempty = false;

		o = s.taboption('general', form.DynamicList, 'device', _('Devices'),
			_('Select a MAC address to cover both IPv4 and IPv6 DNS, or enter a local IPv4 address.'));
		o.datatype = 'or(macaddr,ip4addr)';
		hosts.getMACHints(false).forEach(function(hint) {
			var ip = hosts.getIPAddrByMACAddr(hint[0]);
			o.value(hint[0], '%h (%h)'.format(hint[1] || hint[0], ip || hint[0]));
		});

		var compBtn = s.taboption('general', form.Button, '_components', _('Components'),
			_('Downloads a separate sing-box core and the fnport helper. At least 140 MB of free storage is required.'));
		compBtn.inputtitle = state.installed ? _('Update components') : _('Install components');
		compBtn.onclick = function() {
			return self.runAction('install');
		};

		o = s.taboption('advanced', widgets.NetworkSelect, 'wan_interface', _('WAN interface'));
		o.nocreate = true;
		o.default = 'wan';

		o = s.taboption('advanced', widgets.NetworkSelect, 'lan_interface', _('Client networks'));
		o.nocreate = true;
		o.multiple = true;
		o.default = 'lan';

		o = s.taboption('advanced', form.ListValue, 'dns_mode', _('DNS transport'));
		o.value('https', 'DNS over HTTPS');
		o.value('tls', 'DNS over TLS');
		o.value('plain', _('Plain DNS'));
		o.default = 'https';

		o = s.taboption('advanced', form.ListValue, 'dns_provider', _('DNS provider'));
		o.value('cloudflare', 'Cloudflare · 1.1.1.1');
		o.value('google', 'Google · 8.8.8.8');
		o.value('quad9', 'Quad9 · 9.9.9.9');
		o.default = 'cloudflare';

		o = s.taboption('advanced', form.DynamicList, 'domain', _('Additional domains'));
		o.datatype = 'hostname';

		o = s.taboption('advanced', form.Value, 'fake_ttl', _('Fake TTL'));
		o.datatype = 'range(1,16)';
		o.default = '3';

		var pollBusy = false;
		var prevSubUpdated = state.subscription ? state.subscription.updated : 0;

		poll.add(function() {
			if (pollBusy)
				return;
			pollBusy = true;
			return callCtl('status').then(function(st) {
				pollBusy = false;
				dom.content(statusBox, renderStatusBox(st));

				var keyInput = document.querySelector('[data-name="_key"] button, #cbi-fnport_connections-main-_key input, #cbi-fnport_connections-main-_key button');
				if (keyInput)
					keyInput.value = keyInput.textContent = st.key_ready ? _('Refresh WARP key') : _('Get a key');

				var compInput = document.querySelector('[data-name="_components"] button, #cbi-fnport_connections-main-_components input, #cbi-fnport_connections-main-_components button');
				if (compInput)
					compInput.value = compInput.textContent = st.installed ? _('Update components') : _('Install components');

				if (st.subscription && st.subscription.updated && st.subscription.updated !== prevSubUpdated) {
					prevSubUpdated = st.subscription.updated;
					var selectEl = document.getElementById('widget.' + nodeOpt.cbid('main'));
					if (selectEl && selectEl.tagName === 'SELECT') {
						while (selectEl.options.length > 0)
							selectEl.remove(0);
						st.subscription.nodes.forEach(function(n) {
							var opt = document.createElement('option');
							opt.value = n.id;
							opt.textContent = flagEmoji(n.country) + n.name + ' (' + n.badge + ')';
							if (n.id === st.subscription.selected)
								opt.selected = true;
							selectEl.appendChild(opt);
						});
					}
				}
			}).catch(function() {
				pollBusy = false;
			});
		}, 3);

		return m.render().then(function(renderedForm) {
			return E('div', {}, [ statusBox, renderedForm ]);
		});
	}
});
