import { summarize_probes } from '../fnport/files/fnport-udp-policy.uc';
let s=summarize_probes([20001,20002,20003,20004,20005,20006],{'20001':30,'20002':25,'20003':3,'20004':0,'20006':1023});
if(length(s.attempted)!=5||length(s.passing)!=2||s.frozen!=1||s.limited!=1||s.silent!=1||s.socket_errors!=1)die('Probe classification failed');
s=summarize_probes([20001,20002],{});
if(s.silent!=0||s.socket_errors!=2||length(s.attempted)!=0)die('Unbound sockets counted as silent');
printf('UDP policy: passed\n');
