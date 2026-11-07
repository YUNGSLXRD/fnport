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

var CTL='/usr/libexec/fnport-connectionsctl';
function call(action){return fs.exec(CTL,[action]).then(function(r){try{return JSON.parse(r.stdout||'{}');}catch(e){return {error:'action_failed'};}});}
var errors={
 insufficient_storage:_('At least 140 MB of free storage is required. Use external storage or extroot.'),
 unsupported_architecture:_('This router architecture is not supported.'),
 release_unreachable:_('Could not download release files from GitHub.'),
 core_download_failed:_('Could not download sing-box.'),
 helper_download_failed:_('Could not download connection components.'),
 helper_checksum_failed:_('The downloaded helper failed checksum verification.'),
 core_checksum_failed:_('The downloaded core failed checksum verification.'),
 warp_registration_failed:_('WARP registration failed. You can import a ready .conf file.'),
 warp_key_missing:_('Get a WARP key or import a .conf file first.'),
 warp_key_invalid:_('The saved WARP key could not be read.'),
 warp_no_usable_endpoint:_('No WARP endpoint passed the exit and download check.'),
 selected_connection_unreachable:_('The selected connection does not respond.'),
 core_exited:_('The connection core stopped.'),
 invalid_native_profile:_('Check the AmneziaWG configuration.'),
 core_profile_rejected:_('The core rejected this connection profile.'),
 select_devices:_('Select at least one device.'),
 select_services:_('Select at least one service.'),
 routing_priority_in_use:_('Another service uses the required routing priority.'),
 routing_table_in_use:_('Another service uses the required routing table.'),
 firewall_table_in_use:_('A connection instance is already using the firewall table.')
};
function errorText(code){return errors[code]||_('Connection error: %s').format(code||_('unknown'));}
function flag(country){return /^[A-Z]{2}$/.test(country||'')?String.fromCodePoint(127397+country.charCodeAt(0),127397+country.charCodeAt(1))+' ':'';}
function statusContent(st){
 var labels={connected:_('Connected'),starting:_('Starting'),selecting_exit:_('Choosing a WARP exit'),failed:_('Connection failed'),stopped:_('Stopped')};
 var nodes=[E('strong',{},labels[st.state]||_('Stopped'))];
 if(st.colo)nodes.push(E('p',{},flag(st.country)+_('Exit: %s').format(st.colo)+(st.address?' · '+st.address:'')));
 if(st.error)nodes.push(E('p',{'class':'alert-message warning'},errorText(st.error)));
 var a=st.action;
 if(a&&a.state==='running')nodes.push(E('p',{},a.action==='install'?_('Installing components…'):_('Registering a WARP key…')));
 if(a&&a.state==='failed')nodes.push(E('p',{'class':'alert-message warning'},errorText(a.error)));
 if(a&&a.state==='done')nodes.push(E('p',{},a.action==='install'?_('Components installed. You can enable the connection.'):_('The WARP key is saved.')));
 return nodes;
}
return view.extend({
 load:function(){return Promise.all([uci.load('fnport_connections'),network.getHostHints(),L.resolveDefault(call('status'),{state:'stopped'})]);},
 action:function(kind){return call(kind).then(function(result){if(result.error)ui.addNotification(null,E('p',{},errorText(result.error)),'warning');});},
 render:function(data){
  var self=this,hosts=data[1],state=data[2],m,s,o;
  var status=E('div',{'class':'cbi-section'},statusContent(state));
  m=new form.Map('fnport_connections',_('Connections'),_('Route Epic services and Discord through WARP or your VPN on selected devices. Fortnite game UDP stays direct through fnport.'));
  s=m.section(form.NamedSection,'main','connections');
  s.tab('general',_('General'));s.tab('advanced',_('Advanced'));
  o=s.taboption('general',form.Flag,'enabled',_('Enable'));o.rmempty=false;
  o=s.taboption('general',form.ListValue,'protocol',_('Connection'));
  [['warp','WARP'],['amneziawg','AmneziaWG'],['vless','VLESS'],['shadowsocks','Shadowsocks'],['vmess','VMess'],['trojan','Trojan'],['hysteria2','Hysteria 2'],['hysteria','Hysteria'],['tuic','TUIC'],['anytls','AnyTLS'],['snell','Snell'],['wireguard','WireGuard'],['socks','SOCKS5'],['http','HTTP'],['ssh','SSH']].forEach(function(p){o.value(p[0],p[1]);});
  o.default='warp';o.rmempty=false;
  var protocols=['amneziawg','vless','shadowsocks','vmess','trojan','hysteria2','hysteria','tuic','anytls','snell','wireguard','socks','http','ssh'];
  var profile=s.taboption('general',form.TextValue,'profile',_('Connection profile'),_('Paste a VLESS link, a WireGuard/AmneziaWG .conf, or one sing-box outbound object.'));
  profile.rows=5;profile.retain=true;
  protocols.forEach(function(p){profile.depends('protocol',p);});
  o=s.taboption('general',form.Button,'_import',_('Import file'));
  o.inputtitle=_('Choose .conf or .json');
  o.onclick=function(){
   var input=E('input',{type:'file',accept:'.conf,.json,.txt',style:'display:none'});
   input.addEventListener('change',function(){
    var file=input.files&&input.files[0];if(!file){input.remove();return;}
    if(file.size>1048576){input.remove();return ui.addNotification(null,E('p',{},_('The configuration file is too large.')),'warning');}
    var reader=new FileReader();
    reader.onload=function(){
     var value=String(reader.result||'');
     uci.set('fnport_connections','main','profile',value);
     var field=document.getElementById(profile.cbid('main'));if(field)field.value=value;
     input.remove();ui.addNotification(null,E('p',{},_('File imported. Save and apply the settings.')),'info');
    };
    reader.onerror=function(){input.remove();ui.addNotification(null,E('p',{},_('Could not read the file.')),'warning');};
    reader.readAsText(file);
   });
   document.body.appendChild(input);input.click();
  };
  o=s.taboption('general',form.Button,'_key',_('WARP key'),_('The key is stored on this router and reused when settings change.'));
  o.depends('protocol','warp');o.inputtitle=state.key_ready?_('Use saved key'):_('Get a key');o.onclick=function(){return self.action('register');};
  o=s.taboption('general',form.Flag,'epic',_('Epic services'),_('Login, store and downloads.'));o.rmempty=false;o.default='1';
  o=s.taboption('general',form.Flag,'discord',_('Discord'),_('Messaging and voice. Your VPN must support UDP for voice.'));o.rmempty=false;
  o=s.taboption('general',form.DynamicList,'device',_('Devices'),_('Select a MAC address to cover both IPv4 and IPv6 DNS, or enter a local IPv4 address.'));
  o.datatype='or(macaddr,ip4addr)';
  hosts.getMACHints(false).forEach(function(hint){o.value(hint[0],'%h (%h)'.format(hint[1]||hint[0],hosts.getIPAddrByMACAddr(hint[0])||hint[0]));});
  o=s.taboption('general',form.Button,'_components',_('Components'),_('Downloads a separate sing-box core and the fnport helper. At least 140 MB of free storage is required.'));
  o.inputtitle=state.installed?_('Update components'):_('Install components');o.onclick=function(){return self.action('install');};
  o=s.taboption('advanced',widgets.NetworkSelect,'wan_interface',_('WAN interface'));o.nocreate=true;o.default='wan';
  o=s.taboption('advanced',widgets.NetworkSelect,'lan_interface',_('Client networks'));o.nocreate=true;o.multiple=true;o.default='lan';
  o=s.taboption('advanced',form.ListValue,'dns_mode',_('DNS transport'));o.value('https','DNS over HTTPS');o.value('tls','DNS over TLS');o.value('plain',_('Plain DNS'));o.default='https';
  o=s.taboption('advanced',form.ListValue,'dns_provider',_('DNS provider'));o.value('cloudflare','Cloudflare · 1.1.1.1');o.value('google','Google · 8.8.8.8');o.value('quad9','Quad9 · 9.9.9.9');o.default='cloudflare';
  o=s.taboption('advanced',form.DynamicList,'domain',_('Additional domains'));o.datatype='hostname';
  o=s.taboption('advanced',form.Value,'fake_ttl',_('Fake TTL'));o.datatype='range(1,16)';o.default='3';
  poll.add(function(){return call('status').then(function(st){dom.content(status,statusContent(st));});},3);
  return m.render().then(function(form){return E('div',{},[status,form]);});
 }
});
