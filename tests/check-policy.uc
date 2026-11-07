import { verdict, count, both_passed, all_silent, compare_fake, measured_ttl, select_ttl } from '../fnport/files/fnport-check-policy.uc';
function assert(value,reason){if(!value)die(reason);}
assert(!both_passed([]),'empty control accepted');
assert(!all_silent([]),'empty result treated as silent');
assert(compare_fake([30,30],[])=='unclear','empty fake result judged');
assert(compare_fake([2,0],[0,0])=='unclear','rate-limited baseline blamed on fake');
assert(compare_fake([30,0],[0,0])=='unclear','mixed baseline blamed on fake');
assert(compare_fake([30,30],[30,0])=='unclear','mixed fake result called harmless');
assert(compare_fake([30,30],[30,30])=='harmless','strong success rejected');
assert(compare_fake([30,30],[0,0])=='kills','strong loss of replies missed');
assert(verdict(1023)=='pass'&&!both_passed([1023,1030]),'late packets confused with full answers');
let report={ttl:[{ttl:3,replies:[30,30,30,30]}]};
assert(measured_ttl(report,3)&&!measured_ttl(report,4),'unmeasured TTL recommended');
report.recommended_fake='spare';report.spares=[{fake:'spare',ttl:[{ttl:2,replies:[30,30,30,30]}]}];
assert(measured_ttl(report,2)&&!measured_ttl(report,3),'fake provenance lost');
printf('check policy: passed\n');

let calls=[];
let mixed={};
let v=select_ttl(2,8,3,true,mixed,(ttl)=>{push(calls,ttl);if(ttl!=3)die('Mixed current TTL changed');return [30,25];});
assert(v=='fake_partial'&&mixed.recommended_ttl==null&&length(calls)==2,'Mixed recommendation');
let confirmed={};
v=select_ttl(2,3,3,true,confirmed,(ttl)=>ttl==3?[25,25]:[30,30]);
assert(v=='fake_works'&&confirmed.recommended_ttl==2&&measured_ttl(confirmed,2),'Confirmed candidate rejected');
assert(!measured_ttl({ttl:[{ttl:2,replies:[30,30]}]},2),'Single round applied');
printf('TTL selection: passed\n');
