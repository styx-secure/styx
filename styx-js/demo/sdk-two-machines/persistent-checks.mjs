// PROTOTYPE tests: run only on AI395 under the test lock, nice 19/ionice idle.
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, statSync, rmSync, existsSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { stateFile, persistentSession, persistentOutbox } from './persistent-ports.mjs';
import { createStyxClient, SDK_INTERFACE_VERSION } from '../../src/sdk/index.js';
const root = mkdtempSync(process.env.TMPDIR + '/sdk-persistence-checks-');
const key = randomBytes(32).toString('hex'), checks = [];
const stores = [];
const open = (name) => { const s = stateFile(root+'/'+name,key); stores.push(s); return s; };
try {
  const a = open('a'), b = open('b'), pk = a.identity.getPublicKey();
  const out = persistentOutbox(a);
  const record = { deliveryId:'d1',recipient:b.identity.getPublicKey(),receiptMode:'RECIPIENT_RECEIPT',state:'IN_FLIGHT',attempts:1,createdAt:1000,deadlineAt:61000,lastCode:null,relayOutcomes:[],ciphertext:new Uint8Array([1,2,3]),event:null };
  assert.equal(out.port.put(record),true); assert.equal(out.port.update('missing',record),false);
  const reopened = open('a'); assert.equal(reopened.identity.getPublicKey(),pk);
  assert.deepEqual(reopened.data.outboxes[0].records.d1.ciphertext,record.ciphertext); checks.push('encrypted identity and typed-array outbox roundtrip');
  const raw = readFileSync(root+'/a/state.aesgcm');
  assert.equal(raw.includes(Buffer.from(a.data.seed)),false); checks.push('seed absent from encrypted file bytes');
  assert.throws(()=>stateFile(root+'/a',randomBytes(32).toString('hex'))); checks.push('wrong key rejected');
  const modified=Buffer.from(raw); modified[modified.length-1]^=1; writeFileSync(root+'/a/state.aesgcm',modified);
  assert.throws(()=>stateFile(root+'/a',key)); writeFileSync(root+'/a/state.aesgcm',raw); checks.push('tampered ciphertext rejected');
  assert.equal(statSync(root+'/a').mode & 0o777,0o700); assert.equal(statSync(root+'/a/state.aesgcm').mode & 0o777,0o600); checks.push('0700 directory and 0600 file');
  const made=createStyxClient({interfaceVersion:SDK_INTERFACE_VERSION,relays:['ws://127.0.0.1:1'],ports:{identity:{getPublicKey:a.identity.getPublicKey,sign:a.identity.sign},session:{seal:()=>{},open:()=>{}},storage:out.port}});
  assert.equal(made.ok,true); const started=await made.value.start(); assert.deepEqual(started,{ok:false,code:'E_SDK_STORAGE_NOT_EMPTY'}); await made.value.shutdown(); checks.push('real SDK rejects durable nonempty outbox');
  const newOut=persistentOutbox(reopened); assert.equal(newOut.recovered.length,1); assert.equal(newOut.recovered[0].retried,false); assert.equal(newOut.port.list().length,0); checks.push('pending archived and explicitly failed without retransmission');
  const ma=await persistentSession(a), mb=await persistentSession(b), peer=b.identity.getPublicKey();
  const kp=mb.port.createKeyPackage(), welcome=await ma.port.startSession({peer,keyPackage:kp});
  await mb.port.joinSession({peer:pk,...welcome}); mb.bindGroup(pk,ma.groupId(peer));
  const msg=ma.port.seal({recipient:peer,plaintext:new TextEncoder().encode('synthetic before restore')});
  mb.port.open({sender:pk,...msg});
  const ra=await persistentSession(open('a')),rb=await persistentSession(open('b'));
  assert.equal(ra.fingerprint(peer),rb.fingerprint(pk)); assert.equal(ra.fingerprint(peer),ma.fingerprint(peer));
  const next=ra.port.seal({recipient:peer,plaintext:new TextEncoder().encode('synthetic after restore')});
  assert.equal(new TextDecoder().decode(rb.port.open({sender:pk,...next}).plaintext),'synthetic after restore'); checks.push('MLS group ratchet and fingerprint restored via public engine methods');
  console.log(JSON.stringify({ok:true,checks}));
} finally {
  for(const s of stores){s.identity.destroy();s.destroy();} rmSync(root,{recursive:true});
  console.log(JSON.stringify({phase:'checks-cleanup',stateRemoved:!existsSync(root)}));
}
