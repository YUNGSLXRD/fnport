'use strict';
'require view';
'require form';
'require network';
'require tools.widgets as widgets';

return view.extend({
	load: function() {
		return network.getHostHints();
	},

	render: function(hosts) {
		var m, s, o;

		m = new form.Map('fnport', _('fnport'),
			_('Some ISP DPI boxes freeze game UDP flows after 25 packets, and which flows get frozen depends on the source port. ' +
			  'fnport probes the game server from several source ports and sends each new game connection through one that passes. ' +
			  'No VPN: traffic goes directly to the server.'));

		s = m.section(form.NamedSection, 'main', 'fnport');

		s.tab('general', _('General'));
		s.tab('advanced', _('Advanced'));

		o = s.taboption('general', form.Flag, 'enabled', _('Enable'));
		o.rmempty = false;

		o = s.taboption('general', widgets.NetworkSelect, 'wan_interface', _('WAN interface'),
			_('Interface facing the ISP.'));
		o.nocreate = true;
		o.default = 'wan';

		o = s.taboption('general', form.DynamicList, 'device', _('Devices'),
			_('Game devices (PC, console): an address, or a subnet such as 192.168.56.0/24 (from /16). Give them static DHCP leases so the address does not change.'));
		o.datatype = 'ip4addr';
		hosts.getMACHints(false).forEach(function(hint) {
			var ip = hosts.getIPAddrByMACAddr(hint[0]);
			if (ip)
				o.value(ip, '%h (%h)'.format(ip, hint[1] || hint[0]));  // host names come from DHCP clients
		});

		o = s.taboption('advanced', form.DynamicList, 'port_range', _('Game server ports'),
			_('UDP ports of the game servers. Defaults are Fortnite: 9000-9999 (match) and 15000-15999 (control).'));
		o.datatype = 'portrange';
		o.default = [ '9000-9999', '15000-15999' ];

		o = s.taboption('advanced', form.Value, 'pair_from', _('Paired port range'),
			_('When a connection to this range is seen, the paired match port is probed in advance. Empty disables it.'));
		o.datatype = 'portrange';
		o.placeholder = '15000-15999';

		o = s.taboption('advanced', form.Value, 'pair_offset', _('Paired port offset'),
			_('Offset from the control port to the match port (Fortnite: 15062 → 9062 = -6000).'));
		o.datatype = 'integer';
		o.placeholder = '-6000';

		o = s.taboption('advanced', form.Value, 'qos_port', _('Fallback echo port'),
			_('Server UDP echo port used when the game port does not answer.'));
		o.datatype = 'port';
		o.placeholder = '22222';

		o = s.taboption('advanced', form.Value, 'probe_batch', _('Ports per probe round'),
			_('Probed in parallel. More may trigger the server\'s rate limit.'));
		o.datatype = 'range(1,12)';
		o.placeholder = '2';

		o = s.taboption('advanced', form.Value, 'max_rounds', _('Probe rounds'),
			_('Extra rounds when no port passes. Each round adds about 1.3 seconds to connecting.'));
		o.datatype = 'range(1,16)';
		o.placeholder = '8';

		o = s.taboption('advanced', form.Value, 'probe_budget', _('Probe budget per minute'),
			_('Upper limit of probe ports per minute for all servers together. Probing too much gets the address punished by the DPI.'));
		o.datatype = 'range(4,120)';
		o.placeholder = '24';

		o = s.taboption('advanced', form.Value, 'verdict_ttl', _('Reuse probe results (seconds)'),
			_('Results drift after 10-20 minutes, keep this short.'));
		o.datatype = 'range(10,900)';
		o.placeholder = '90';

		o = s.taboption('advanced', form.DynamicList, 'whitelist_fake', _('Whitelist fake'),
			_('Files with a fake QUIC Initial carrying a whitelisted SNI. One is sent before each probe and connection with a short TTL: the DPI stops freezing flows where it saw such a name. The first file is used; if it stops working, fnport switches to the next one. Empty disables the fake.'));
		o.placeholder = '/usr/share/fnport/quic_initial_vk_com.bin';
		o.validate = function(section_id, value) {
			// the service reads only its own directories, see fnportd.uc
			if (value == '' || /^\/(usr\/share|etc)\/fnport\/[A-Za-z0-9_-][A-Za-z0-9._-]*$/.test(value))
				return true;
			return _('Must be a file in /usr/share/fnport or /etc/fnport');
		};

		o = s.taboption('advanced', form.Flag, 'standby', _('Stand by where nothing freezes'),
			_('If probes pass without the fake, fnport stops probing and sending the fake: connections go as they are until a frozen one shows up. What it learns is kept per network.'));
		o.default = '1';
		o.rmempty = false;

		o = s.taboption('advanced', form.Value, 'fake_ttl', _('Fake TTL'),
			_('Hops from the router: the fake must pass the DPI and expire before reaching the server.'));
		o.datatype = 'range(1,16)';
		o.placeholder = '3';

		return m.render();
	}
});
