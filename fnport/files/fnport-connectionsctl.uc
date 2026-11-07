#!/usr/bin/env ucode
import { readfile, access, writefile, mkdir, chmod, rmdir } from 'fs';
const RUN='/var/run/fnport-connections';
const ACTION='/usr/libexec/fnport-connections-action';
function state(path){try{return json(readfile(path)??'null');}catch(e){return null;}}
function alive(pid){return pid>1&&access(`/proc/${pid}/stat`);}
let cmd=ARGV[0];
if(cmd=='status'){
 let s=state(RUN+'/status.json')??{state:'stopped'};
 let a=state(RUN+'/action.json');
 let daemon=+(readfile(RUN+'/daemon.pid')??0);
 if(s.state in ['connected','starting','selecting_exit']&&!alive(daemon)){s.state='failed';s.error='helper_stopped';}
 let pid=+(readfile(RUN+'/action.pid')??0);
 if(a?.state=='running'&&!alive(pid)&&time()-(a.started??0)>10)a={state:'failed',error:'action_stopped'};
 // Only explicit public fields. Profiles and raw process output never reach the UI.
 printf('%J\n',{state:s.state,protocol:s.protocol,error:s.error,colo:s.colo,country:s.country,address:s.address,rtt_ms:s.rtt_ms,updated:s.updated,installed:access('/usr/libexec/fnport-connections-helper')&&access('/usr/lib/fnport-connections/sing-box'),key_ready:access('/etc/fnport/connections/warp.json'),action:a});
}
else if(cmd=='install'||cmd=='register'){
 mkdir(RUN,0700);chmod(RUN,0700);
 let pid=+(readfile(RUN+'/action.pid')??0);
 let previous=state(RUN+'/action.json');
 if(!alive(pid)&&time()-(previous?.started??0)>10)rmdir(RUN+'/action.lock');
 if(alive(pid)||!mkdir(RUN+'/action.lock',0700)){printf('%J\n',{error:'action_running'});exit(1);}
 writefile(RUN+'/action.json',sprintf('%J',{state:'running',action:cmd,started:time()}));
 system(['start-stop-daemon','-S','-b','-x',ACTION,'--',cmd]);
 printf('%J\n',{started:true});
}
else{printf('%J\n',{error:'invalid_command'});exit(2);}
