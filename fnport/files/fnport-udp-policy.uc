export function summarize_probes(ports,replies){
 let s={attempted:[],passing:[],frozen:0,limited:0,silent:0,socket_errors:0,counts:{}};
 for(let p in ports){
  let got=replies[p];
  if(got==null){s.socket_errors++;continue;}
  push(s.attempted,p);s.counts[got]=true;
  if(got>=26)push(s.passing,p);
  else if(got>=20)s.frozen++;
  else if(got>0)s.limited++;
  else s.silent++;
 }
 return s;
};
