import { cursor } from 'uci';
import { popen } from 'fs';

try {
 let uci=cursor();
 let get=(key,fallback)=>uci.get('fnport_connections','main',key) ?? fallback;
 let list=(v)=>type(v)=='array'?v:(v==null?[]:[v]);
 let device=(name)=>{
  if(!match(name,/^[A-Za-z0-9_.-]{1,15}$/)) die('invalid interface');
  let p=popen(`ubus call network.interface.${name} status 2>/dev/null`,'r');
  if(!p) die('interface unavailable');
  let status=json(p.read('all')||'null');p.close();
  if(!status?.up||!match(status.l3_device??'',/^[A-Za-z0-9_.@-]{1,15}$/)) die('interface unavailable');
  return status.l3_device;
 };
 let c={protocol:get('protocol','warp'),profile:get('profile',''),devices:list(get('device',null)),epic:get('epic','1')=='1',discord:get('discord','0')=='1',domains:list(get('domain',null)),dns_mode:get('dns_mode','https'),dns_provider:get('dns_provider','cloudflare'),wan:device(get('wan_interface','wan')),lan:map(list(get('lan_interface','lan')),device),fake_file:get('fake_file','/usr/share/fnport/quic_initial_vk_com.bin'),fake_ttl:+get('fake_ttl','3')};
 printf('%J\n',c);
}
catch(e){warn('Invalid connection configuration\n');exit(1);}
