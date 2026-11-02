// PROTOTYPE ONLY. Real unchanged SDK; synthetic encrypted MLS state.
import { createInterface } from 'node:readline';
import { WebSocket } from 'ws';
import { createStyxClient, SDK_INTERFACE_VERSION } from '../../src/sdk/index.js';
import { stateFile, persistentSession } from './persistent-ports.mjs';
import { storage, clock } from './ports.mjs';
const parse = JSON.parse.bind(JSON), sleep = ms => new Promise(r => setTimeout(r,ms));
const log = (phase,data={}) => console.log(JSON.stringify({phase,...data}));
const start = performance.now(), cpu = process.cpuUsage();
const stats = {frames:[],validated:[],discards:[],opens:0,messages:[],wire:[],requests:[]};
let measuring=false, listener=false, own;
// Optional read-only observation: preserve all seven event keys and values.
// sig is read by receipts.validateEvent, never by catchUp.observe or transport.
// This counts each frame reaching validation, BEFORE deduplication.
if(process.env.OBSERVE==='1') JSON.parse = function(raw,...args) {
  const f=parse(raw,...args);
  if(measuring && Array.isArray(f) && f[0]==='EVENT' && f[2]?.tags?.some(t=>t[0]==='p'&&t[1]===own) && [4741,4742].includes(f[2].kind)) {
    const e=f[2], id=e.id, kind=e.kind, sig=e.sig;
    const item={seq:stats.frames.length,id,kind,ms:performance.now()-start}; stats.frames.push(item);
    let seen=false;
    Object.defineProperty(e,'sig',{enumerable:true,configurable:true,get(){if(!seen){seen=true;stats.validated.push({...item,ms:performance.now()-start});}return sig;}});
  }
  return f;
};
class Socket extends WebSocket {
  // Diagnostic only: forward a real socket's historical EVENT frames together
  // in one JavaScript turn at EOSE, to remove TCP segmentation as a throttle.
  emit(type,...args){
    if(type==='message'&&process.env.BATCH_AT_EOSE==='1'){
      const f=parse(String(args[0]));
      if(f[0]==='EVENT'&&[4741,4742].includes(f[2]?.kind)){(this.batch??=[]).push(args);return true;}
      if(f[0]==='EOSE'&&this.batch?.length){const batch=this.batch;this.batch=[];for(const frame of batch)super.emit('message',...frame);}
    }
    return super.emit(type,...args);
  }
  constructor(...args){super(...args); this.on('open',()=>log('socket-open'));this.on('error',error=>log('socket-error',{error:error.message})); this.on('message',raw=>{
    if(!measuring)return; const f=parse(String(raw));
    if(f[0]==='EVENT' && [4741,4742].includes(f[2]?.kind))stats.wire.push({id:f[2].id,kind:f[2].kind,ms:performance.now()-start});
  });}
  send(raw,...args){if(measuring){const f=parse(String(raw));if(f[0]==='REQ')stats.requests.push({filter:f[2],ms:performance.now()-start});}return super.send(raw,...args);}
}
globalThis.WebSocket=Socket;
const store=stateFile(process.env.STATE_DIR,process.env.DEMO_STATE_KEY);delete process.env.DEMO_STATE_KEY;
own=store.identity.getPublicKey();
if(process.env.KEY_ONLY==='1'){log('key',{key:own});store.identity.destroy();store.destroy();process.exit(0);}
const mls=await persistentSession(store),peer=process.env.PEER;
stats.decryptions=[];
const session={...mls.port,open(args){if(measuring)stats.opens++;const result=mls.port.open(args);if(measuring){const payload=parse(new TextDecoder().decode(result.plaintext));stats.decryptions.push({id:payload.id,ms:performance.now()-start,listener});}return result;}};
const need=r=>{if(!r.ok)throw Error(r.code);return r.value;};
let offset=Number(process.env.CLOCK_OFFSET||0);
const client=need(createStyxClient({interfaceVersion:SDK_INTERFACE_VERSION,relays:process.env.RELAYS.split(','),ports:{identity:store.identity,session,storage:storage()},clock:{...clock,now:()=>Date.now()+offset},delivery:{receiptMode:'RECIPIENT_RECEIPT',maxAttempts:1,deadlineMs:60000,perRelayTimeoutMs:12000}}));
const onEvent=e=>{
  if(e.kind==='MESSAGE_RECEIVED'){
    const payload=parse(new TextDecoder().decode(e.payload));
    if(payload.groupId)mls.bindGroup(e.sender,payload.groupId);
    if(measuring)stats.messages.push({id:payload.id,ms:performance.now()-start,listener});
    log('message',{id:payload.id,ms:performance.now()-start,cpu:process.cpuUsage(cpu),wireFrames:stats.wire.length,sessionFailures:stats.discards.filter(x=>x.code==='E_SDK_SESSION_FAILED').length});
  }else if(e.kind==='INBOUND_DISCARDED'&&measuring)stats.discards.push({code:e.code,ms:performance.now()-start});
};
// Late mode has no observer listener: successful decryption and the relay's
// signed receipt provide the independent evidence for the listener-free path.
const late=Number(process.env.LISTENER_DELAY||0);
if(!late){need(await client.onEvent(onEvent));listener=true;}
measuring=process.env.MEASURE==='1';
const startCall=performance.now();need(await client.start());
log('started',{startCallMs:startCall-start,startResolvedMs:performance.now()-start,key:own});
if(late)setTimeout(async()=>{need(await client.onEvent(onEvent));listener=true;log('listener-attached',{ms:performance.now()-start});},late);
try{
for await(const line of createInterface({input:process.stdin})){
 const c=parse(line);
 if(c.op==='clock'){offset=c.offset;log('clock-set');}
 else if(c.op==='pair'){
  if(process.env.ROLE==='invitee'){const kp=need(await client.publishKeyPackage());log('waiting');need(await client.acceptInvite({inviter:peer,keyPackageEventId:kp.keyPackageEventId}));}
  else need(await client.invite({invitee:peer}));log('paired');
 }else if(c.op==='send'){
  const sent=need(await client.send({recipient:peer,payload:new TextEncoder().encode(JSON.stringify({id:c.id,groupId:mls.groupId(peer)}))}));log('sent',{id:c.id,eventId:sent.eventId});
 }else if(c.op==='bulk'){
  for(let n=c.from;n<=c.to;n++){
   const sent=need(await client.send({recipient:peer,payload:new TextEncoder().encode(JSON.stringify({id:'history-'+n,groupId:mls.groupId(peer)}))}));
   for(;;){const d=need(await client.getDelivery({deliveryId:sent.deliveryId}));if(d.terminal){if(d.state!=='RECIPIENT_RECEIPT_RECEIVED')throw Error(d.state);break;}await sleep(1);}
   if(n%100===0)log('progress',{n});
  }log('bulk-done',{n:c.to});
 }else if(c.op==='stats'){
  log('stats',{...stats,elapsedMs:performance.now()-start,cpu:process.cpuUsage(cpu),listener});
 }else if(c.op==='stop'){need(await client.shutdown());store.save();log('stopped');break;}
}
}finally{await client.shutdown();store.identity.destroy();store.destroy();}
process.exit(0);
