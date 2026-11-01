#!/usr/bin/env node
// Real ports, three local relay fixtures, two independent member processes.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { WebSocketServer } from 'ws';
import { verifyEvent } from 'nostr-tools/pure';
import { identity, session } from './ports.mjs';
const dir = process.env.EVIDENCE_DIR;
if (!dir) throw Error('EVIDENCE_DIR required');
mkdirSync(dir, { recursive: true });
const seeds = [randomBytes(32).toString('hex'), randomBytes(32).toString('hex')];
const ids = seeds.map(identity), keys = ids.map((id) => id.getPublicKey());
// Real encrypted gift wrap; tampering and a third party must fail.
const rumor = { pubkey: keys[0], created_at: Math.floor(Date.now()/1000), kind: 4744, tags: [], content: 'synthetic private welcome' };
const gift = ids[0].giftWrap({ rumor, recipient: keys[1] });
assert.equal(gift.kind, 1059); assert.ok(!gift.content.includes(rumor.content));
assert.deepEqual(ids[1].unwrapGift({ event: gift }), { rumor, sealSigner: keys[0] });
assert.throws(() => identity().unwrapGift({ event: gift }));
assert.throws(() => ids[1].unwrapGift({ event: { ...gift, content: gift.content + 'x' } }));
// Reject a KeyPackage whose credential differs from the Nostr peer key.
const a = await session(ids[0]), b = await session(ids[1]);
await assert.rejects(a.port.startSession({ peer: 'c'.repeat(64), keyPackage: b.port.createKeyPackage() }), /credential/);
const events = [], servers = [], urls = [];
const matches = (f,e) => (!f.kinds || f.kinds.includes(e.kind)) && (!f.authors || f.authors.includes(e.pubkey)) && (!f['#p'] || e.tags.some((t) => t[0] === 'p' && f['#p'].includes(t[1]))) && (!f.since || e.created_at >= f.since);
for (let i=0; i<3; i++) {
  const server = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await new Promise((resolve) => server.once('listening', resolve));
  servers.push(server); urls.push('ws://127.0.0.1:' + server.address().port);
  const subscriptions = new Map();
  server.on('connection', (socket) => {
    subscriptions.set(socket, new Map()); socket.on('close', () => subscriptions.delete(socket));
    socket.on('message', (raw) => {
      const f = JSON.parse(String(raw));
      if (f[0] === 'REQ') {
        subscriptions.get(socket).set(f[1], f[2]);
        for (const e of events) if (matches(f[2],e)) socket.send(JSON.stringify(['EVENT',f[1],e]));
        socket.send(JSON.stringify(['EOSE',f[1]]));
      } else if (f[0] === 'EVENT') {
        const e=f[1]; const valid=verifyEvent(e);
        socket.send(JSON.stringify(['OK',e.id,valid,valid?'fixture accepted':'bad signature']));
        if (!valid) return;
        if (!events.some((old)=>old.id===e.id)) events.push(e);
        for (const [s, subs] of subscriptions) for (const [sub,filter] of subs) if (s.readyState===1 && matches(filter,e)) s.send(JSON.stringify(['EVENT',sub,e]));
      } else if (f[0]==='CLOSE') subscriptions.get(socket).delete(f[1]);
    });
  });
}
const children=[];
function launch(i) {
  const role=i===0?'inviter':'invitee';
  const child=spawn(process.execPath,[new URL('member.mjs',import.meta.url).pathname],{env:{...process.env,DEMO_SEED:seeds[i],ROLE:role,PEER:keys[1-i],RELAYS:urls.join(','),OUT:dir+'/'+role+'-result.json'},stdio:['ignore','pipe','pipe']});
  children.push(child); let text=''; child.stdout.on('data',(d)=>{text+=d;}); child.stderr.on('data',(d)=>{text+=d;});
  const done=new Promise((resolve)=>child.on('exit',(code)=>{writeFileSync(dir+'/'+role+'.log',text);resolve(code);}));
  return {child,done,text:()=>text};
}
try {
  const invitee=launch(1);
  const deadline=Date.now()+60000;
  while(!invitee.text().includes('waiting-for-invite')) { if(Date.now()>deadline) throw Error('invitee timeout'); await new Promise((r)=>setTimeout(r,100)); }
  const inviter=launch(0);
  const codes=await Promise.all([inviter.done,invitee.done]);
  assert.deepEqual(codes,[0,0]);
  const results=['inviter','invitee'].map((r)=>JSON.parse(readFileSync(dir+'/'+r+'-result.json')));
  assert.equal(results[0].groupFingerprint,results[1].groupFingerprint);
  assert.ok(results.every((r)=>r.ok));
  assert.ok(results[0].deliveries[2].attempts>=2);
  assert.deepEqual(results[0].received.map((r)=>r.text).sort(),['synthetic reply 1','synthetic reply 2','synthetic reply 3']);
  const cleared=results[0].steps.find((s)=>s.phase==='stall-cleared');
  assert.ok(results[0].received.find((r)=>r.text==='synthetic reply 2').ms>=cleared.ms);
  const summary={ok:true,checks:['NIP-59 encrypted and authenticated','third-party unwrap rejected','tampered wrap rejected','wrong MLS credential rejected','two processes invite via SDK','equal MLS fingerprint','six recipient receipts','R1 excluded','retry after blackhole','reply during stall recovered exactly once'],kinds:[...new Set(events.map((e)=>e.kind))],results:results.map((r)=>({role:r.role,ok:r.ok,deliveries:r.deliveries.length,received:r.received.length}))};
  writeFileSync(dir+'/summary.json',JSON.stringify(summary,null,2)); console.log(JSON.stringify(summary));
} finally {
  for(const child of children) if(child.exitCode===null) child.kill();
  for(const server of servers) {for(const s of server.clients)s.terminate(); await new Promise((r)=>server.close(r));}
  ids.forEach((id)=>id.destroy());
}
