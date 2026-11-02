// PROTOTYPE ONLY. All synthetic traffic binds loopback; no public websocket.
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { mkdtempSync,mkdirSync,copyFileSync,rmSync,existsSync,writeFileSync,appendFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { hostname } from 'node:os';
import { WebSocketServer } from 'ws';
import { verifyEvent } from 'nostr-tools/pure';
if(hostname()!=='AI395')throw Error('AI395 required');
const out=process.env.EVIDENCE_DIR;if(!out)throw Error('EVIDENCE_DIR');mkdirSync(out,{recursive:true});
const privateRoot=mkdtempSync(out+'/private-state-');
const secret=randomBytes(32).toString('hex'), children=new Set(), fixtures=new Set(), results=[];
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const log=x=>{console.log(JSON.stringify(x));appendFileSync(out+'/progress.jsonl',JSON.stringify(x)+'\n');};
const sizes=(process.env.SIZES||'100,500,1000,2000,5000').split(',').map(Number);
const matches=(f,e)=>(!f.kinds||f.kinds.includes(e.kind))&&(!f.authors||f.authors.includes(e.pubkey))&&(!f['#p']||e.tags.some(t=>t[0]==='p'&&f['#p'].includes(t[1])))&&(!f.since||e.created_at>=f.since);
async function fixture(count,initial=[],cap=Infinity,reverse=false,hold=false){
 const servers=[],urls=[],histories=[],requests=[],publications=[];let held=null,released=false;
 for(let i=0;i<count;i++){
  const history=new Map(initial.map(e=>[e.id,e])),subs=new Map();histories.push(history);
  const server=new WebSocketServer({host:'127.0.0.1',port:0});await new Promise(r=>server.once('listening',r));servers.push(server);urls.push('ws://127.0.0.1:'+server.address().port);
  const publish=(event,socket)=>{history.set(event.id,event);publications.push({relay:i,id:event.id,kind:event.kind,ms:performance.now()});if(socket?.readyState===1)socket.send(JSON.stringify(['OK',event.id,true,'accepted']));for(const [s,ss]of subs)for(const [id,f]of ss)if(s.readyState===1&&matches(f,event))s.send(JSON.stringify(['EVENT',id,event]));};
  server.on('connection',socket=>{appendFileSync(out+'/relay-debug.jsonl',JSON.stringify({phase:'connection',relay:i})+'\n');subs.set(socket,new Map());socket.on('close',()=>subs.delete(socket));socket.on('message',raw=>{
   const f=JSON.parse(String(raw));appendFileSync(out+'/relay-debug.jsonl',JSON.stringify({phase:'frame',relay:i,type:f[0],kind:f[0]==='EVENT'?f[1].kind:null,filter:f[0]==='REQ'?f[2]:null})+'\n');
   if(f[0]==='REQ'){
    requests.push({relay:i,filter:f[2],ms:performance.now()});subs.get(socket).set(f[1],f[2]);
    // Release a signed new event at the FIRST receiver request, during start().
    // It is placed AFTER the old backlog for the unlimited ascending case.
    if(held&&!released&&f[2]['#p']?.includes(held.event.tags[0][1])){released=true;for(const h of histories)h.set(held.event.id,held.event);held.socket.send(JSON.stringify(['OK',held.event.id,true,'released at restart']));publications.push({id:held.event.id,kind:4741,restartRelease:true,ms:performance.now()});}
    let rows=[...history.values()].filter(e=>matches(f[2],e));
    if(reverse)rows.sort((a,b)=>b.created_at-a.created_at||b.id.localeCompare(a.id));
    rows=rows.slice(0,Math.min(cap,f[2].limit??Infinity));
    // Coalesce the burst in one TCP write, realistic fast local history response.
    socket._socket.cork();for(const e of rows)socket.send(JSON.stringify(['EVENT',f[1],e]));socket.send(JSON.stringify(['EOSE',f[1]]));socket._socket.uncork();
   }else if(f[0]==='EVENT'){
    const e=f[1];if(!verifyEvent(e))throw Error('invalid signature');
    if(hold&&!released&&e.kind===4741){held={event:e,socket};}else publish(e,socket);
   }else if(f[0]==='CLOSE')subs.get(socket).delete(f[1]);
  });});
 }
 const obj={urls,histories,requests,publications,held:()=>held,close:async()=>{for(const s of servers){for(const c of s.clients)c.terminate();await new Promise(r=>s.close(r));}fixtures.delete(obj);}};fixtures.add(obj);return obj;
}
function member(dir,role,peer,urls,options={}){
 mkdirSync(dir,{recursive:true,mode:0o700});
 const p=spawn(process.execPath,[new URL('long-history-member.mjs',import.meta.url).pathname],{env:{...process.env,STATE_DIR:dir,DEMO_STATE_KEY:secret,ROLE:role,PEER:peer,RELAYS:urls.join(','),...options},stdio:['pipe','pipe','pipe']});children.add(p);
 const events=[];let stderr='';p.stderr.on('data',x=>stderr+=x);createInterface({input:p.stdout}).on('line',line=>{try{const e=JSON.parse(line);events.push(e);if(!['message','stats'].includes(e.phase))appendFileSync(out+'/members.jsonl',JSON.stringify({role,dir:dir.split('/').slice(-2).join('/'),...e})+'\n');}catch{stderr+=line;}});
 const exit=new Promise(resolve=>p.on('exit',code=>{children.delete(p);resolve(code);}));
 return {p,events,exit,send:c=>p.stdin.write(JSON.stringify(c)+'\n'),wait:async(phase,predicate=()=>true,timeout=90000)=>{const end=Date.now()+timeout;for(;;){const e=events.find(e=>e.phase===phase&&predicate(e));if(e)return e;if(p.exitCode!==null)throw Error('child exit '+p.exitCode+' '+stderr);if(Date.now()>end)throw Error('timeout '+phase+' '+stderr);await sleep(10);}},stop:async()=>{p.stdin.write('{"op":"stop"}\n');const code=await exit;if(code!==0)throw Error('stop '+code+' '+stderr);}};
}
async function init(dir){const m=member(dir,'inviter','',[],{KEY_ONLY:'1'});const e=await m.wait('key');if(await m.exit!==0)throw Error('key');return e.key;}
function snapshot(source,dest){mkdirSync(dest,{recursive:true,mode:0o700});copyFileSync(source+'/state.aesgcm',dest+'/state.aesgcm');}
try{
 const gen=await fixture(1),ad=privateRoot+'/a',bd=privateRoot+'/b';const ak=await init(ad),bk=await init(bd);
 const a=member(ad,'inviter',bk,gen.urls,{CLOCK_OFFSET:'-3600000'}),b=member(bd,'invitee',ak,gen.urls,{CLOCK_OFFSET:'-3600000'});
 await Promise.all([a.wait('started'),b.wait('started')]);b.send({op:'pair'});await b.wait('waiting');a.send({op:'pair'});await Promise.all([a.wait('paired'),b.wait('paired')]);
 let previous=0;const datasets=[];
 for(const n of sizes){
  a.send({op:'bulk',from:previous+1,to:n});await a.wait('bulk-done',e=>e.n===n,600000);await sleep(100);
  const events=[...gen.histories[0].values()].filter(e=>[4741,4742].includes(e.kind));
  if(events.filter(e=>e.kind===4741).length!==n||events.filter(e=>e.kind===4742).length!==n)throw Error('history count '+n);
  const path=privateRoot+'/snapshot-'+n;snapshot(ad,path+'/a');snapshot(bd,path+'/b');datasets.push({n,path,events});previous=n;log({phase:'generated',n,events:events.length});
 }
 await a.stop();await b.stop();await gen.close();
 const policies=[{name:'all-oldest',cap:Infinity,reverse:false},{name:'all-newest',cap:Infinity,reverse:true},{name:'cap500-oldest',cap:500,reverse:false},{name:'cap500-newest',cap:500,reverse:true}];
 const jobs=[];for(const dataset of datasets)for(const count of [1,3])for(const policy of policies)if(process.env.BURST_ONLY!=='1'||policy.cap===Infinity)jobs.push({dataset,count,policy});
 if(process.env.BURST_ONLY!=='1')jobs.push({dataset:datasets.at(-1),count:3,policy:{name:'all-oldest-unobserved',cap:Infinity,reverse:false,observe:false}});
 let nextJob=0;
 await Promise.all(Array.from({length:Number(process.env.CONCURRENCY||4)},async()=>{while(nextJob<jobs.length){const {dataset,count,policy}=jobs[nextJob++];
  const name=`n${dataset.n}-r${count}-${policy.name}`;const dir=privateRoot+'/'+name;snapshot(dataset.path+'/a',dir+'/a');snapshot(dataset.path+'/b',dir+'/b');
  const f=await fixture(count,dataset.events,policy.cap,policy.reverse,true);let sender,receiver;
  try{
   sender=member(dir+'/a','inviter',bk,f.urls);await sender.wait('started');sender.send({op:'send',id:'new-'+name});
   const deadline=Date.now()+10000;while(!f.held()){if(Date.now()>deadline)throw Error('held timeout');await sleep(10);}
   receiver=member(dir+'/b','invitee',ak,f.urls,{MEASURE:'1',OBSERVE:policy.observe===false?'0':'1',BATCH_AT_EOSE:process.env.BURST_ONLY==='1'?'1':'0'});const started=await receiver.wait('started');
   await sleep(12500);receiver.send({op:'stats'});const stats=await receiver.wait('stats');
   const message=receiver.events.find(e=>e.phase==='message'&&e.id==='new-'+name)??null;
   const validatedSeq=new Set(stats.validated.map(x=>x.seq));
   const missing=stats.frames.filter(x=>!validatedSeq.has(x.seq));
   const newId=f.held().event.id;
   const row={name,n:dataset.n,relays:count,policy:policy.name,started,message,newId,frames:stats.frames.length,validated:stats.validated.length,droppedFrames:missing.length,droppedHistorical:missing.filter(x=>x.id!==newId).length,droppedNew:missing.filter(x=>x.id===newId).length,sessionFailures:stats.discards.filter(x=>x.code==='E_SDK_SESSION_FAILED').length,delivered:!!message,newCopies:stats.messages.filter(x=>x.id==='new-'+name).length,requests:stats.requests,cpu:stats.cpu,elapsedMs:stats.elapsedMs};
   if(policy.observe===false)Object.assign(row,{frames:stats.wire.length,validated:null,droppedFrames:null,droppedHistorical:null,droppedNew:null});
   writeFileSync(out+'/'+name+'.json',JSON.stringify({row,stats,dropped:missing,relayRequests:f.requests,publications:f.publications},null,2));results.push(row);log({phase:'case',...row});
  }finally{if(receiver)await receiver.stop();if(sender)await sender.stop();await f.close();rmSync(dir,{recursive:true,force:true});}
 }}));
 // Late application listener: fresh persisted session; one new message with no replay backlog.
 const dataset=datasets[0];
 for(const delay of (process.env.BURST_ONLY==='1'?[]:[1000,10000])){
  const dir=privateRoot+'/late-'+delay;snapshot(dataset.path+'/a',dir+'/a');snapshot(dataset.path+'/b',dir+'/b');const f=await fixture(1,[]);
  const sender=member(dir+'/a','inviter',bk,f.urls),receiver=member(dir+'/b','invitee',ak,f.urls,{MEASURE:'1',OBSERVE:'1',LISTENER_DELAY:String(delay)});
  try{await Promise.all([sender.wait('started'),receiver.wait('started')]);sender.send({op:'send',id:'late-'+delay});await sender.wait('sent');await sleep(delay+11500);receiver.send({op:'stats'});const stats=await receiver.wait('stats');const receipts=f.publications.filter(x=>x.kind===4742);const row={name:'late-'+delay,delay,stats,receipts};writeFileSync(out+'/late-'+delay+'.json',JSON.stringify(row,null,2));log({phase:'late',delay,decryptions:stats.decryptions,messages:stats.messages,receipts:receipts.length});}finally{await receiver.stop();await sender.stop();await f.close();rmSync(dir,{recursive:true,force:true});}
 }
 writeFileSync(out+'/summary.json',JSON.stringify({ok:true,results},null,2));
}catch(e){writeFileSync(out+'/failure.json',JSON.stringify({error:e.stack,results},null,2));process.exitCode=1;}
finally{
 for(const p of children)p.kill('SIGKILL');await Promise.all([...children].map(p=>new Promise(r=>p.once('exit',r))));for(const f of [...fixtures])await f.close();rmSync(privateRoot,{recursive:true,force:true});writeFileSync(out+'/cleanup.json',JSON.stringify({stateRemoved:!existsSync(privateRoot),childrenRemaining:children.size}));
}
