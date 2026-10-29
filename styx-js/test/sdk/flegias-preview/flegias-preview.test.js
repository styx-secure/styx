// Flegias preview (synthetic data only)
import { generateSecretKey, createPreviewPorts } from '../../../examples/flegias-preview/ports.js';
import { runHandler } from '../../../examples/flegias-preview/handler.js';
import { runCaseReporter, runOutsideReporter } from '../../../examples/flegias-preview/reporter.js';
import { startLoopbackRelay } from './loopback-relay.js';
import { ClientState, DeliveryState } from '../../../src/sdk/index.js';
import { bytesToHex, hexToBytes, utf8Encode, bytesToBase64, base64ToBytes, randomBytes } from '../../../src/utils.js';
import { schnorr } from '@noble/curves/secp256k1';
import { describe, test, expect } from '@jest/globals';
import { WebSocket } from 'ws';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { AsyncLocalStorage } from 'node:async_hooks';
const LABEL = 'Flegias preview (synthetic data only)';
const equal = (a,b) => a.length === b.length && a.every((v,i) => v === b[i]);
const check = (truth, clause) => { expect(Boolean(truth)).toBe(true); if (!truth) throw new Error(clause); };
const parse = m => JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(m.bytes));
const frames = records => records.flatMap(r => r.messages.map(m => ({ ...m, frame: parse(m), record:r })));
const binaryValue = bytes => ({ bytes: bytes.slice(), literal:null });
const hexValue = hex => binaryValue(hexToBytes(hex));
const subscriptionValue = literal => ({ bytes:hexToBytes(literal.slice(1)), literal });
function forms(v) {
  const hex = bytesToHex(v.bytes); const b64 = bytesToBase64(v.bytes); const url = b64.replace(/\+/g,'-').replace(/\//g,'_');
  return [...new Set([hex,hex.toUpperCase(),b64,b64.replace(/=+$/,''),url,url.replace(/=+$/,''),...(v.literal ? [v.literal] : [])])];
}
function contains(haystack,needle) {
  outer: for (let i=0;i<=haystack.length-needle.length;i++) { for (let j=0;j<needle.length;j++) if(haystack[i+j]!==needle[j]) continue outer; return true; } return false;
}
function containsHex(haystack,needle) {
  // Fold ASCII A-F only, and only for the hex representation: raw/base64 stay exact.
  outer: for(let i=0;i<=haystack.length-needle.length;i++) {
    for(let j=0;j<needle.length;j++) {
      const byte=haystack[i+j],folded=byte>=65 && byte<=70 ? byte+32 : byte;
      if(folded!==needle[j]) continue outer;
    }
    return true;
  }
  return false;
}
function scan(inputs, forbidden) {
  if (!inputs.length || !forbidden.length) throw new Error('empty scan');
  const values = forbidden.map(v => ({ ...v, forms:forms(v), hex:utf8Encode(bytesToHex(v.bytes)), encoded:forms(v).map(utf8Encode) }));
  const seen = new Set(), seenText = new Set(); let found = false;
  const bytes = b => { for (const v of values) if (contains(b,v.bytes) || containsHex(b,v.hex) || v.encoded.some(f=>contains(b,f))) found=true; };
  const text = (s,decode=true) => {
    const cache=(decode?'1:':'0:')+s; if(seenText.has(cache)) return; seenText.add(cache);
    for (const v of values) if (v.forms.some(f => s.includes(f)) || s.toLowerCase().includes(bytesToHex(v.bytes))) found=true;
    for (const pattern of [/[A-Za-z0-9+/]+/g,/[A-Za-z0-9_-]+/g]) {
      for (const match of s.matchAll(pattern)) for(let offset=0;offset<4;offset++) {
        let normalized=match[0].slice(offset).replace(/-/g,'+').replace(/_/g,'/');
        if(normalized.length%4===1) normalized=normalized.slice(0,-1);
        normalized += '='.repeat((4-normalized.length%4)%4);
        bytes(base64ToBytes(normalized));
      }
    }
    // Captured text is scanned both on-wire and after recursive JSON decoding.
    if(decode) try { const value=JSON.parse(s); if(typeof value!=='string' || value!==s) walk(value); } catch(error) { if (!(error instanceof SyntaxError)) throw error; }
  };
  const walk = value => {
    if (typeof value === 'string') { text(value); return; }
    if (value instanceof Uint8Array) { bytes(value); return; }
    if(value===null || typeof value!=='object' || seen.has(value)) return;
    seen.add(value);
    const rendering=JSON.stringify(value,(_k,v)=>v instanceof Uint8Array?bytesToHex(v):v); if(rendering!==undefined) text(rendering,false);
    for(const [key,v] of Object.entries(value)) { text(key); walk(v); }
    if(Array.isArray(value) && value[0]==='EVENT' && typeof value[2]?.content==='string') {
      const content=value[2].content;
      if(/^[A-Za-z0-9+/]*={0,2}$/.test(content) && content.replace(/=+$/,'').length%4!==1) bytes(base64ToBytes(content));
    }
  };
  for(const input of inputs) walk(input);
  return found;
}
function plainRecords(records) { return records.map(r=>({role:r.role,url:r.url,owner:r.owner,upgrade:r.upgrade,closed:r.closed,closeCalls:r.closeCalls,messages:structuredClone(r.messages)})); }
function verifyCapture(sockets, connections, owners, signed) {
  if(!sockets.length || sockets.length!==connections.length) throw new Error('capture cardinality');
  const used=new Set();
  for(const s of sockets) {
    if(!s.owner || !owners.includes(s.owner) || s.role!==s.owner.role || !s.owner.urls.includes(s.url) || !s.url.endsWith('/'+s.owner.role) || !s.closed || !(s.closeCalls>0)) throw new Error('socket attribution/close');
    const c=connections.find((r,i)=>!used.has(i) && r.url===s.url);
    if(!c) throw new Error('missing relay pair'); used.add(connections.indexOf(c));
    if(c.role!==s.owner.role || !c.closed || !c.upgrade) throw new Error('relay attribution/close');
    for(const direction of ['in','out']) {
      const a=s.messages.filter(m=>m.direction===direction),b=c.messages.filter(m=>m.direction===direction);
      if(a.length!==b.length) throw new Error('stream cardinality');
      for(let i=0;i<a.length;i++) if(a[i].binary || b[i].binary || !equal(a[i].bytes,b[i].bytes)) throw new Error('stream mismatch');
    }
    const reqs=s.messages.filter(m=>m.direction==='out').map(parse).filter(f=>f[0]==='REQ');
    if(!reqs.length) throw new Error('missing REQ');
    for(const f of reqs) for(const filter of f.slice(2)) if(JSON.stringify(filter['#p'])!==JSON.stringify([s.owner.publicKey])) throw new Error('REQ ownership');
    if(reqs[0].slice(2).some(f=>Object.hasOwn(f,'since'))) throw new Error('initial cursor');
    const relayReqs=c.messages.filter(m=>m.direction==='out').map(parse).filter(f=>f[0]==='REQ');
    if(JSON.stringify(relayReqs[0])!==JSON.stringify(reqs[0])) throw new Error('relay first REQ');
    for(const f of s.messages.filter(m=>m.direction==='out').map(parse).filter(f=>f[0]==='EVENT')) {
      if(f[1].pubkey!==s.owner.publicKey || !signed.get(s.owner).includes(f[1].id)) throw new Error('unsigned/foreign publication');
    }
  }
  for(const owner of owners) {
    if(!sockets.some(s=>s.owner===owner)) throw new Error('missing owner sockets');
    for(const id of signed.get(owner)) {
      const sent=sockets.filter(s=>s.owner===owner).flatMap(s=>s.messages.filter(m=>m.direction==='out').map(parse)).some(f=>f[0]==='EVENT' && f[1].id===id);
      if(!sent) throw new Error('signed id not published');
      if(sockets.filter(s=>s.owner!==owner).flatMap(s=>s.messages.filter(m=>m.direction==='out').map(parse)).some(f=>f[0]==='EVENT' && f[1].id===id)) throw new Error('foreign signing owner');
    }
  }
}
function hygiene() {
  const dirs=[new URL('../../../examples/flegias-preview/',import.meta.url),new URL('./',import.meta.url)];
  const expected=[['README.md','handler.js','ports.js','reporter.js'],['flegias-preview.test.js','loopback-relay.js']];
  const texts=[];
  for(let i=0;i<dirs.length;i++) {
    check(JSON.stringify(readdirSync(fileURLToPath(dirs[i])).sort())===JSON.stringify(expected[i]),'A7 exact files');
    for(const name of expected[i]) texts.push(readFileSync(fileURLToPath(new URL(name,dirs[i])),'utf8'));
  }
  const forbidden=new RegExp(['anon','ym'].join(''),'i');
  for(const source of texts) { check(source.startsWith('// '+LABEL)||source.startsWith('# '+LABEL),'A7 initial label'); check(!forbidden.test(source),'A7 forbidden text'); }
  const imports = [
    ['handler.js',['SDK_INTERFACE_VERSION','createStyxClient','SdkEventKind','DeliveryState','utf8Encode']],
    ['ports.js',['schnorr','bytesToHex']],
    ['reporter.js',['SDK_INTERFACE_VERSION','createStyxClient','SdkEventKind','DeliveryState','utf8Encode','bytesToHex']],
    ['loopback-relay.js',['WebSocketServer','sha256','bytesToHex','utf8Encode']],
    ['flegias-preview.test.js',['generateSecretKey','createPreviewPorts','runHandler','runCaseReporter','runOutsideReporter','startLoopbackRelay','ClientState','DeliveryState','bytesToHex','hexToBytes','utf8Encode','bytesToBase64','base64ToBytes','randomBytes','schnorr','describe','test','expect','WebSocket','readFileSync','readdirSync','fileURLToPath','AsyncLocalStorage']]
  ];
  const names=['README.md','handler.js','ports.js','reporter.js','flegias-preview.test.js','loopback-relay.js'];
  for(const [name,expectedNames] of imports) {
    const src=texts[names.indexOf(name)]; const actual=[...src.matchAll(/^import \{([^}]+)\} from '([^']+)';$/gm)].flatMap(m=>m[1].split(',').map(v=>v.trim()));
    check(JSON.stringify(actual)===JSON.stringify(expectedNames),'A7 exact imported names');
    check(!/\bimport\s*\(|\brequire\s*\(/.test(src),'A7 no dynamic loading');
  }
  check(texts[0].includes('Styx is under active development and has **not** completed an independent security audit. Do not use current builds for sensitive, high-risk, or life-critical use.'),'A7 warning');
  check(texts[0].includes('C0.3 remains `NO-GO` for implementation alignment, demo, product, and sensitive use.'),'A7 NO-GO');
}
describe('Flegias preview (synthetic data only): integrated local fixture',()=>{
 test('Flegias preview (synthetic data only): two cases and all C-PREV A1–A9 controls',async()=>{
  check(typeof globalThis.crypto?.getRandomValues==='function','crypto prerequisite');
  const runDeadline=Date.now()+200000;
  // A stricter flow cutoff reserves shutdown/close/stop/custody inside the run.
  const flowDeadline=runDeadline-140000;
  function deadline(promise,ms=30000,due=flowDeadline) {
    return new Promise((resolve,reject)=>{
      let timer;
      Promise.resolve(promise).then(v=>{clearTimeout(timer);resolve(v);},e=>{clearTimeout(timer);reject(e);});
      const remaining=Math.min(ms,due-Date.now());
      if(remaining<=0) {reject(new Error('run deadline'));return;}
      timer=setTimeout(()=>reject(new Error('wait deadline')),remaining);
    });
  }
  const wait=async predicate => {
    const due=Math.min(Date.now()+30000,flowDeadline);
    while(Date.now()<due) {
      const value=await deadline(Promise.resolve().then(predicate),Math.max(1,due-Date.now()));
      if(value) return value;
      await new Promise(resolve=>setTimeout(resolve,10));
    }
    throw new Error('wait deadline');
  };
  await expect(deadline(new Promise(()=>{}),5)).rejects.toThrow('wait deadline');
  hygiene(); console.log(JSON.stringify({label:LABEL,checkpoint:'A7',status:'PASS'}));
  const als=new AsyncLocalStorage(),sockets=[],recorderFaults=[]; const original=globalThis.WebSocket;
  class RecorderSocket extends WebSocket {
    constructor(url,...args) {
      const owner=als.getStore(); super(url,...args);
      const r={owner,role:owner?.role,url:String(url),messages:[],closed:false,closeCalls:0,socket:this}; sockets.push(r); this.record=r;
      if(!owner) recorderFaults.push(new Error('missing socket owner'));
      this.on('message',(data,binary)=>r.messages.push({direction:'in',binary,bytes:new Uint8Array(data)}));
      this.on('close',()=>{r.closed=true;}); this.on('error',error=>recorderFaults.push(error));
    }
    send(data,...args) { this.record.messages.push({direction:'out',binary:typeof data!=='string',bytes:typeof data==='string'?utf8Encode(data):new Uint8Array(data)}); return super.send(data,...args); }
    close(...args) { this.record.closeCalls++; return super.close(...args); }
  }
  const drive=(owner,fn)=>als.run(owner,fn);
  function cleanupCase(c) {
    if(c.cleanup) return c.cleanup;
    // One promise owns every client/relay operation across both finally blocks.
    // The flow cutoff reserves 140s: shutdown30 + close40 + stop40 + custody30.
    c.cleanup=(async()=>{
      const errors=[],operations=[];
      const observe=fn=>{
        const record={settled:false};operations.push(record);
        record.promise=Promise.resolve().then(fn).then(value=>{record.settled=true;return {value};},error=>{record.settled=true;return {error};});
        return record;
      };
      const bounded=(promise,ms)=>new Promise((resolve,reject)=>{
        const remaining=Math.min(ms,runDeadline-Date.now());
        let timer;
        // Always observe an already-started operation, even at an expired deadline.
        Promise.resolve(promise).then(v=>{clearTimeout(timer);resolve(v);},e=>{clearTimeout(timer);reject(e);});
        if(remaining<=0) {reject(new Error('cleanup run deadline'));return;}
        timer=setTimeout(()=>reject(new Error('cleanup wait deadline')),remaining);
      });
      const clients=c.clients.map(e=>{
        if(!e.stopOperation) e.stopOperation=observe(()=>drive(e.owner,()=>e.run.shutdown()));
        return e;
      });
      try {
        const results=await bounded(Promise.all(clients.map(e=>e.stopOperation.promise)),30000);
        for(let i=0;i<clients.length;i++) {
          const result=results[i];if(result.error) {errors.push(result.error);continue;}
          clients[i].shutdown=true;
          try {check(result.value.clientState===ClientState.STOPPED && result.value.lost===0,'A6 stopped');}catch(error){errors.push(error);}
        }
      }catch(error){errors.push(error);}
      const owned=()=>sockets.filter(s=>s.owner?.case===c.k);
      try {
        if(c.clients.length) check(owned().length>0 && owned().every(s=>s.closeCalls>0),'A6 close before relay stop');
        const due=Math.min(Date.now()+40000,runDeadline);
        // No detached polling promise: expiration ends this loop itself.
        while(!owned().every(s=>s.closed) || !c.relays.every(r=>r.connections.every(x=>x.closed))) {
          const left=due-Date.now();if(left<=0) throw new Error('cleanup close deadline');
          await new Promise(resolve=>setTimeout(resolve,Math.min(10,left)));
        }
      }catch(error){errors.push(error);}
      finally {
        // Even a failed close assertion cannot bypass server stop.
        const stops=c.relays.map(r=>{
          if(!r.stopOperation) r.stopOperation=observe(()=>r.stop());
          return r.stopOperation.promise;
        });
        try {for(const result of await bounded(Promise.all(stops),40000)) if(result.error) errors.push(result.error);}
        catch(error){errors.push(error);}
      }
      // A timed-out phase is still a failure, never a successful shortened cleanup.
      // Retain observation of the SAME operations; never issue another shutdown/stop.
      try {await bounded(Promise.all(operations.map(o=>o.promise)),30000);}
      catch(error){errors.push(error);}
      c.sockets=owned();c.cleanupObserved=operations.every(o=>o.settled);
      if(!c.cleanupObserved) errors.push(new Error('cleanup operation still pending'));
      return errors;
    })();
    return c.cleanup;
  }
  async function cleanupRegression() {
    // Real host timers and the identical cleanup implementation used by both cases.
    // Flow timeout is an error already caught; cleanup must not reuse its deadline.
    let shutdownCalls=0,stopCalls=0,shutdownObserved=false,stopObserved=false;
    const owner={case:0},socket={owner,closeCalls:0,closed:false};sockets.push(socket);
    const connection={closed:false};
    const c={k:0,clients:[{owner,run:{shutdown:async()=>{
      shutdownCalls++;await new Promise(resolve=>setTimeout(resolve,5));
      shutdownObserved=true;socket.closeCalls++;socket.closed=true;connection.closed=true;
      return {clientState:ClientState.STOPPED,lost:0};
    }}}],relays:[{connections:[connection],stop:async()=>{
      stopCalls++;await new Promise(resolve=>setTimeout(resolve,5));stopObserved=true;
    }}]};
    let primary;try {await deadline(new Promise(()=>{}),30000,Date.now()-1);}catch(error){primary=error;}
    check(Boolean(primary),'F2 primary flow timeout');
    const first=cleanupCase(c);check(cleanupCase(c)===first,'F2 same cleanup promise');
    const errors=await first;await cleanupCase(c);
    check(errors.length===0 && shutdownCalls===1 && stopCalls===1 && shutdownObserved && stopObserved && c.cleanupObserved,'F2 observed single cleanup');
    check(primary.message==='run deadline','F2 primary preserved after cleanup');
    sockets.splice(sockets.indexOf(socket),1);
  }
  await cleanupRegression();
  const secretH=generateSecretKey(),secretR=generateSecretKey(),secretB=generateSecretKey(),token=randomBytes(16);
  const H=bytesToHex(schnorr.getPublicKey(secretH)),R=bytesToHex(schnorr.getPublicKey(secretR)),B=bytesToHex(schnorr.getPublicKey(secretB));
  const cases=[];const allClients=[],allRelays=[];let runError;
  globalThis.WebSocket=RecorderSocket;
  try {
    for(const k of [1,2]) {
      const secret=generateSecretKey(),C=bytesToHex(schnorr.getPublicKey(secret));
      const c={k,secret,C,relays:[],owners:[],clients:[],signed:new Map(),ports:new Map(),h1:[],h2:[],h4:[],sockets:[]}; cases.push(c);
      let primaryError;
      try {
        for(let n=0;n<2;n++) { const relay=await deadline(startLoopbackRelay()); c.relays.push(relay);allRelays.push(relay); }
        for(const [role,key,publicKey] of [['handler',secretH,H],['case-reporter',secret,C],['outside-reporter',secretR,R]]) {
          const owner={role,case:k,publicKey,urls:c.relays.map(r=>r.base+'/'+role)};c.owners.push(owner);c.signed.set(owner,[]); const calls=[];c.ports.set(owner,calls);
          const ports=createPreviewPorts({secretKey:key,recorder:(port,method,args)=>{
            calls.push({port,method,args}); if(port==='identity' && method==='sign') c.signed.get(owner).push(bytesToHex(args[0].digest));
            if(role==='handler') { c.h4.push(args); if(port==='session' && method==='open') { c.h1.push(args[0].sender);c.h2.push(args[0].ciphertext); } }
          }});
          let run;
          const shared={relays:owner.urls,ports,caseNumber:k,wait};
          if(role==='handler') run=drive(owner,()=>runHandler({...shared,sender:C,recorder:(type,value)=>{c.h4.push(value);if(type==='event' && value.kind==='MESSAGE_RECEIVED'){c.h1.push(value.sender);c.h2.push(value.payload);}}}));
          if(role==='case-reporter') run=drive(owner,()=>runCaseReporter({...shared,handler:H}));
          if(role==='outside-reporter') run=drive(owner,()=>runOutsideReporter({...shared,bystander:B,token}));
          const entry={run,owner,ports,shutdown:false};c.clients.push(entry);allClients.push(entry);
        }
        const starts=await deadline(Promise.all(c.clients.map(e=>drive(e.owner,()=>deadline(e.run.start())))));
        check(starts.every(s=>s.clientState===ClientState.RUNNING && s.connectedRelays===2),'A1 starts');
        const [handler,reporter,outside]=c.clients;
        c.outside=await drive(outside.owner,()=>deadline(outside.run.publish()));
        c.opening=await drive(reporter.owner,()=>deadline(reporter.run.open()));
        c.reply=await drive(handler.owner,()=>deadline(handler.run.completed()));
        await drive(reporter.owner,()=>deadline(reporter.run.receive()));
        check([c.outside,c.opening,c.reply].every(d=>d.state===DeliveryState.RELAY_ACCEPTED && d.terminal===true),'A1 accepted');
        check(handler.run.sends===1 && reporter.run.replies>0,'A1 single reply');
      } catch(error) { primaryError=error; }
      finally {
        const cleanupErrors=await cleanupCase(c);
        if(!primaryError && cleanupErrors.length) primaryError=cleanupErrors[0];
      }
      if(primaryError) throw primaryError;
      check(c.clients.every(e=>e.run.faults.length===0) && c.relays.every(r=>r.faults.length===0 && r.closed),'A1/A6 faults and closed');
    }
    check(recorderFaults.length===0,'A4 recorder faults');
    const publics=[H,R,B,...cases.map(c=>c.C)];check(new Set(publics).size===5,'A5 distinct keys');
    for(const c of cases) {
      const connections=c.relays.flatMap(r=>r.connections);const owners=c.owners;
      verifyCapture(c.sockets,connections,owners,c.signed);
      check(c.relays.every(r=>owners.every(o=>r.connections.some(x=>x.role===o.role))),'A4 roles on both relays');
      const s=plainRecords(c.sockets),r=plainRecords(connections);
      // Copies retain exact owner identity; only the four prescribed corruptions change.
      const copy=records=>records.map(x=>({...x,messages:structuredClone(x.messages)}));
      let m=copy(r);let target=m.find(x=>x.role==='handler');let index=target.messages.findIndex(x=>x.direction==='in');check(index>=0,'negative capture input');target.messages.splice(index,1);
      expect(()=>verifyCapture(s,m,owners,c.signed)).toThrow();
      m=copy(s);target=m.find(x=>x.role==='outside-reporter' && x.messages.some(v=>v.direction==='out' && parse(v)[0]==='EVENT'));check(Boolean(target),'outside publication input');index=target.messages.findIndex(v=>v.direction==='out' && parse(v)[0]==='EVENT');target.messages.splice(index,1);
      expect(()=>verifyCapture(m,r,owners,c.signed)).toThrow();
      m=copy(s);target=m.find(x=>x.owner.role==='handler');target.url=target.url.replace('/handler','/outside-reporter');
      expect(()=>verifyCapture(m,r,owners,c.signed)).toThrow();
      m=copy(s);const outside=s.find(x=>x.owner.role==='outside-reporter');const outsideEvent=outside.messages.find(v=>v.direction==='out' && parse(v)[0]==='EVENT');check(Boolean(outsideEvent),'outside negative fixture');
      m.push({...outside,owner:owners[0],role:'outside-reporter',messages:[...outside.messages.filter(v=>v.direction==='out' && parse(v)[0]==='REQ'),{direction:'in',binary:false,bytes:utf8Encode(JSON.stringify(['EVENT',outside.messages.map(parse).find(f=>f[0]==='REQ')[1],parse(outsideEvent)[1]]))}]});
      expect(()=>verifyCapture(m,r,owners,c.signed)).toThrow();
      const handlerRecords=[...c.sockets.filter(x=>x.owner.role==='handler'),...connections.filter(x=>x.role==='handler')];
      c.h3=frames(handlerRecords).filter(f=>f.direction==='in' && ['EVENT','OK'].includes(f.frame[0])).map(f=>new TextDecoder('utf-8',{fatal:true}).decode(f.bytes));
      c.h4.push(...frames(handlerRecords).filter(f=>f.direction==='in' && !['EVENT','OK'].includes(f.frame[0])).map(f=>new TextDecoder('utf-8',{fatal:true}).decode(f.bytes)));
      const openingIds=new Set(frames(c.sockets.filter(x=>x.owner.role==='case-reporter')).filter(f=>f.direction==='out' && f.frame[0]==='EVENT').map(f=>f.frame[1].id));
      const replyIds=new Set(c.signed.get(owners[0]));
      check(openingIds.size===1 && replyIds.size===1 && c.h1.length>0 && c.h1.every(x=>x===c.C),'A1/A3 identities');
      const payload=utf8Encode(`${LABEL}: synthetic case ${c.k} opening text.`);
      check(c.h2.length>0 && c.h2.every(x=>equal(x,payload)),'A1 payload');
      const hframes=c.h3.map(JSON.parse);check(hframes.some(f=>f[0]==='EVENT') && hframes.some(f=>f[0]==='OK'),'A3 nonempty frames');
      for(const f of hframes) {
        if(f[0]==='EVENT') check(openingIds.has(f[2].id) && f[2].pubkey===c.C && equal(base64ToBytes(f[2].content),payload),'A1 exact handler EVENT');
        if(f[0]==='OK') check(replyIds.has(f[1]) && f[2]===true && f[3]==='','A1 exact handler OK');
      }
      c.allEvents=frames([...c.sockets,...connections]).filter(f=>f.frame[0]==='EVENT').map(f=>f.frame[f.direction==='out'?1:2]);
      check(c.allEvents.every(e=>e.tags.every(t=>t[0]!=='r')),'A1 no receipt mode');
      check(c.clients[1].ports.identity.getPublicKey()===c.C,'A5 case identity port');
      check(allClients.filter(e=>e!==c.clients[1]).every(e=>e.ports.identity.getPublicKey()!==c.C),'A5 no other client key');
      c.reporterTraffic=connections.filter(x=>x.role==='case-reporter').flatMap(x=>x.messages.map(m=>new TextDecoder('utf-8',{fatal:true}).decode(m.bytes)));
      console.log(JSON.stringify({label:LABEL,case:c.k,checkpoint:'A1/A4/A5/A6',status:'PASS',sockets:c.sockets.length,relayConnections:connections.length,frames:connections.reduce((n,x)=>n+x.messages.length,0),handlerSends:c.clients[0].run.sends}));
    }
    for(const c of cases) {
      const other=cases.find(v=>v!==c);
      const forbidden=[hexValue(R),hexValue(B),hexValue(other.C),binaryValue(secretR),binaryValue(other.secret),binaryValue(token)];
      for(const source of cases) {
        const records=[...source.sockets,...source.relays.flatMap(r=>r.connections)];
        for(const {frame:f} of frames(records)) {
          if(f[0]!=='EVENT') continue;
          const event=f.length===2?f[1]:f[2];
          if(event.pubkey===R || source!==c) { forbidden.push(hexValue(event.id),hexValue(event.sig));for(const tag of event.tags) if(tag[0]==='n') forbidden.push(hexValue(tag[1])); }
        }
        for(const socket of source.sockets.filter(s=>s.owner.role!=='handler' && !(source===c && s.owner.role==='case-reporter'))) {
          const connection=source.relays.flatMap(r=>r.connections).filter(r=>r.url===socket.url)[source.sockets.filter(s=>s.url===socket.url).indexOf(socket)];
          forbidden.push(binaryValue(base64ToBytes(connection.upgrade)));
          for(const f of socket.messages.map(parse)) if(f[0]==='REQ') forbidden.push(subscriptionValue(f[1]));
          for(const f of connection.messages.map(parse)) if(f[0]==='REQ') forbidden.push(subscriptionValue(f[1]));
        }
      }
      const unique=[...new Map(forbidden.map(v=>[bytesToHex(v.bytes)+(v.literal||''),v])).values()];
      const covered=[...c.h1,...c.h2,...c.h3];const strength=[binaryValue(c.secret),binaryValue(secretB)];
      check(!scan(covered,unique),'A2 forbidden absence');
      check(!scan(c.h4,[...unique,...strength]) && !scan(covered,strength),'A9 strength');
      check(c.reporterTraffic.length>0 && !scan(c.reporterTraffic,unique),'A8 reporter traffic');
      check(c.clients[1].owner.urls.length===2 && c.clients[1].owner.urls.every((url,i)=>url===c.relays[i].base+'/case-reporter'),'A8 exact config');
      const subscription=unique.find(v=>v.literal);const v16=unique.find(v=>v.bytes.length===16 && !v.literal),v64=unique.find(v=>v.bytes.length===64);
      const replyOther=hexValue(other.signed.get(other.owners[0])[0]);
      check(Boolean(subscription && v16 && v64) && replyOther.bytes.length===32,'A3 kinds');
      const before=JSON.stringify(c.h3);let controls=0;
      const planted=[v16,replyOther,v64,subscription];
      const pristine=new Map();
      const control=(value,input)=>{
        const id=bytesToHex(value.bytes)+(value.literal||'');
        if(!pristine.has(id)) {check(!scan(covered,[value]),'A3 pristine absence');pristine.set(id,true);}
        check(scan([...covered,input],[value]),'A3 planted detection');controls++;
      };
      for(const value of planted) {
        const hex=bytesToHex(value.bytes),mixed=[...hex].map((ch,i)=>i%2?ch.toUpperCase():ch).join('');
        control(value,mixed);
        for(let prefix=0;prefix<=2;prefix++) for(let suffix=0;suffix<=2;suffix++) {
          const encoded=utf8Encode(mixed),input=new Uint8Array(prefix+encoded.length+suffix);
          input.fill(255);input.set(encoded,prefix);control(value,input);
        }
        for(const form of forms(value)) {
          control(value,form);control(value,utf8Encode(form));
          const escaped='["OK","id",true,"'+[...form].map(ch=>'\\u'+ch.charCodeAt(0).toString(16).padStart(4,'0')).join('')+'"]';control(value,escaped);
        }
        control(value,value.bytes);
        for(let prefix=0;prefix<=2;prefix++) for(let suffix=0;suffix<=2;suffix++) {
          const combined=new Uint8Array(prefix+value.bytes.length+suffix);combined.fill(255);combined.set(value.bytes,prefix);
          const standard=bytesToBase64(combined),url=standard.replace(/\+/g,'-').replace(/\//g,'_');
          for(const representation of [standard,standard.replace(/=+$/,''),url,url.replace(/=+$/,'')]) {
            // Insert into copies of actual captured frames, keeping originals untouched.
            const ok=JSON.parse(c.h3.find(t=>JSON.parse(t)[0]==='OK'));ok[3]=representation;control(value,JSON.stringify(ok));
            const event=JSON.parse(c.h3.find(t=>JSON.parse(t)[0]==='EVENT'));event[2].content=representation;control(value,JSON.stringify(event));
          }
        }
      }
      const outsideSocket=c.sockets.find(s=>s.owner.role==='outside-reporter');const outsideConn=c.relays.flatMap(r=>r.connections).find(r=>r.url===outsideSocket.url);
      const outsideSub=subscriptionValue(outsideSocket.messages.map(parse).find(f=>f[0]==='REQ')[1]);const upgrade=binaryValue(base64ToBytes(outsideConn.upgrade));
      for(const value of [replyOther,outsideSub,upgrade]) {const ok=JSON.parse(c.h3.find(t=>JSON.parse(t)[0]==='OK'));ok[3]=value.literal||bytesToBase64(value.bytes);control(value,JSON.stringify(ok));}
      check(JSON.stringify(c.h3)===before,'A3 originals unchanged');
      check(Date.now()<runDeadline,'run deadline includes all scans');
      console.log(JSON.stringify({label:LABEL,case:c.k,checkpoint:'A2/A3/A8/A9',status:'PASS',forbiddenValues:unique.length,negativeScanControls:controls,coveredInputs:covered.length,strengthInputs:c.h4.length}));
    }
  } catch(error) {runError=error;}
  finally {
    const cleanupErrors=[];
    for(const c of cases) cleanupErrors.push(...await cleanupCase(c));
    globalThis.WebSocket=original;
    if(!runError && cleanupErrors.length) runError=cleanupErrors[0];
  }
  if(runError) throw runError;
  check(globalThis.WebSocket===original && cases.every(c=>c.cleanupObserved) && allClients.every(e=>e.shutdown) && allRelays.every(r=>r.closed),'final cleanup');
  console.log(JSON.stringify({label:LABEL,checkpoint:'A1-A9',status:'PASS',cases:cases.length,clients:allClients.length,relays:allRelays.length,naturalExitRequired:true}));
 },300000);
});
