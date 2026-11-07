// Pure policy shared by the checker and offline regression tests.
export function verdict(r) {
 if(r>=1000)return 'pass';
 return r>=26?'pass':(r>=20?'frozen':(r>0?'limited':'silent'));
};
export function count(replies,what){
 let n=0;for(let r in replies??[])if(verdict(r)==what)n++;return n;
};
export function raw(r){return r>=1000?r%1000:r;};
export function both_passed(replies){return length(replies??[])==2&&raw(replies[0])>=26&&raw(replies[1])>=26;};
export function both_answered(replies){return length(replies??[])==2&&raw(replies[0])>=20&&raw(replies[1])>=20;};
export function all_silent(replies){return length(replies??[])==2&&count(replies,'silent')==2;};
export function compare_fake(control,with_fake){
 if(!both_passed(control)||length(with_fake??[])!=2)return 'unclear';
 if(all_silent(with_fake))return 'kills';
 if(both_passed(with_fake))return 'harmless';
 return 'unclear';
};
export function full_series(replies){
 if(length(replies??[])!=4)return false;
 for(let n in replies)if(raw(n)<26)return false;
 return true;
};
export function measured_ttl(st,ttl){
 let steps=st.ttl??[];
 if(st.recommended_fake){
  let scans=filter(st.spares??[],s=>s.fake==st.recommended_fake);
  steps=scans[0]?.ttl??[];
 }
 return length(filter(steps,e=>e.ttl==ttl&&full_series(e.replies)))>0;
};

export function select_ttl(lo,hi,current,preserve,result,probe){
 result.ttl=[];delete result.recommended_ttl;delete result.works_from;delete result.partial_ttl;delete result.kill_control;
 let order=[];
 if(current>=1&&current<=16)push(order,current);
 for(let t=lo;t<=hi;t++)if(t!=current)push(order,t);
 let partial=0,previous=0,silent_run=0,attempted=0;
 for(let ttl in order){
  let first=probe(ttl),all=[...first];
  if(length(first)==2&&(ttl==current||count(first,'pass')>0))all=[...all,...probe(ttl)];
  push(result.ttl,{ttl,replies:all});attempted+=length(all);
  if(full_series(all)){result.works_from=ttl;result.recommended_ttl=ttl;return 'fake_works';}
  if(count(all,'pass')>0){
   if(!partial)partial=ttl;
   if(ttl==current&&preserve){result.partial_ttl=ttl;return 'fake_partial';}
  }
  let silent=length(all)>=2&&count(all,'silent')==length(all);
  silent_run=silent?(ttl==previous+1?silent_run+1:1):0;previous=ttl;
  if(silent_run>=2){
   result.kill_control=probe(0);
   if(partial){result.partial_ttl=partial;return 'fake_partial';}
   if(both_answered(result.kill_control)){result.fake_kills_from=ttl-1;return 'fake_kills';}
   return 'unclear';
  }
 }
 if(partial){result.partial_ttl=partial;return 'fake_partial';}
 return attempted?'fake_fails':'unclear';
};
