#!/usr/bin/env node
// PROTOTYPE — DO NOT MERGE. Synthetic data, pre-audit.
import { writeFileSync } from 'node:fs';
import { WebSocket } from 'ws';
import { createStyxClient, SDK_INTERFACE_VERSION } from '../../src/sdk/index.js';
import { identity, session, storage, clock } from './ports.mjs';
const env = process.env;
const role = env.ROLE;
const id = identity(env.DEMO_SEED);
delete env.DEMO_SEED;
if (env.PUBLIC_KEY_ONLY === '1') { console.log(id.getPublicKey()); id.destroy(); process.exit(0); }
if (!['inviter', 'invitee'].includes(role) || !/^[0-9a-f]{64}$/.test(env.PEER ?? '')) throw Error('ROLE and PEER required');
const peer = env.PEER;
const relays = (env.RELAYS ?? 'wss://relay.nostr.net,wss://relay.primal.net,wss://offchain.pub').split(',');
const result = { role, self: id.getPublicKey(), peer, interfaceVersion: SDK_INTERFACE_VERSION, relays, steps: [], deliveries: [], received: [], states: [] };
const origin = Date.now();
function log(phase, data = {}) {
  const entry = { at: new Date().toISOString(), ms: Date.now() - origin, role, phase, ...data };
  result.steps.push(entry); console.log(JSON.stringify(entry));
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(predicate, ms = 180000) {
  const end = Date.now() + ms;
  while (!(await predicate())) { if (Date.now() > end) throw Error('phase timeout'); await sleep(100); }
}
// Caller-side transport faults only. TLS remains real. No SDK private API.
const faults = new Map(), live = new Set();
let holdReceipts = role === "invitee"; const heldReceipts = [];
class FaultSocket {
  static CONNECTING = 0; static OPEN = 1; static CLOSING = 2; static CLOSED = 3;
  constructor(url) {
    this.url = String(url); this.onopen = this.onmessage = this.onclose = this.onerror = null;
    if (faults.get(this.url) === 'down') {
      this.ws = null;
      setTimeout(() => { this.onerror?.({}); this.onclose?.({}); }, 1); return;
    }
    this.ws = new WebSocket(url); live.add(this);
    this.ws.onopen = (e) => this.onopen?.(e);
    this.ws.onmessage = (e) => {
      try { const m=JSON.parse(e.data); if(m[0]==='EVENT') log('sdk-wire-in', { relay:this.url,eventId:m[2].id,kind:m[2].kind,author:m[2].pubkey }); } catch {}
      if (!faults.has(this.url)) this.onmessage?.(e);
    };
    this.ws.onerror = (e) => this.onerror?.(e);
    this.ws.onclose = (e) => { live.delete(this); this.onclose?.(e); };
  }
  get readyState() { return this.ws?.readyState ?? 3; }
  send(data) {
    if (faults.has(this.url)) return;
    try {
      const m = JSON.parse(data);
      if (m[0] === 'REQ' && Number.isInteger(m[2]?.since)) log('catch-up-req', { relay: this.url, since: m[2].since });
      if (m[0] === 'EVENT') {
        if (m[1].kind === 4742 && holdReceipts) {
          heldReceipts.push({ socket: this, data });
          log('true-receipt-held', { relay: this.url, eventId: m[1].id, target: m[1].tags.find(t=>t[0]==='e')?.[1] });
          return;
        }
        log('wire-publish', { relay: this.url, kind: m[1].kind, eventId: m[1].id });
      }
    } catch { /* SDK owns validation */ }
    this.ws?.send(data);
  }
  close() { this.ws?.close(); }
}
globalThis.WebSocket = FaultSocket;
function fault(url, mode) {
  if (mode) faults.set(url, mode); else faults.delete(url);
  if (mode === 'down') for (const socket of live) if (socket.url === url) socket.close();
  log('fault', { relay: url, mode: mode ?? 'restored', scope: 'this process only' });
}
const mls = await session(id);
const made = createStyxClient({ interfaceVersion: SDK_INTERFACE_VERSION, relays,
  ...(relays.every((r) => r.startsWith('ws://127.0.0.1:')) ? {} : { publicRelayHosts: relays.map((r) => new URL(r).hostname) }),
  ports: { identity: id, session: mls.port, storage: storage() }, clock,
  delivery: { receiptMode: 'RECIPIENT_RECEIPT', maxAttempts: 5, deadlineMs: 180000, perRelayTimeoutMs: 12000 } });
function need(r) { if (!r.ok) throw Error(r.code); return r.value; }
const client = need(made);
const observers = relays.map(url => {
  const ws=new WebSocket(url);
  ws.on('error', error=>log('observer-error',{relay:url,error:error.message}));
  ws.on('open',()=>ws.send(JSON.stringify(['REQ','raw-'+role,{kinds:[4741,4742,1059],'#p':[id.getPublicKey()],since:Math.floor(Date.now()/1000)-5}])));
  ws.on('message',data=>{try {const m=JSON.parse(data); if(m[0]==='EVENT') log('raw-observed',{relay:url,eventId:m[2].id,kind:m[2].kind,author:m[2].pubkey,tags:m[2].tags});}catch{}});
  return ws;
});
let lastDelivery;
need(await client.onEvent((event) => {
  if (event.kind === 'MESSAGE_RECEIVED') {
    const text = new TextDecoder().decode(event.payload);
    result.received.push({ ms: Date.now() - origin, sender: event.sender, text });
    log('message-received', { sender: event.sender, text });
  } else if (event.kind === 'DELIVERY_STATE_CHANGED') {
    result.states.push({ ms: Date.now() - origin, deliveryId: event.deliveryId, state: event.state });
    log('delivery-state', { deliveryId: event.deliveryId, state: event.state });
  } else if (event.kind === 'INBOUND_DISCARDED') log('inbound-discarded', { code: event.code });
}));
async function send(text) {
  let lastSnapshotLog=0;
  const sent = need(await client.send({ recipient: peer, payload: new TextEncoder().encode(text) }));
  lastDelivery = sent.deliveryId;
  log('send', { text, deliveryId: lastDelivery });
  let snapshot;
  await until(async () => { snapshot = need(await client.getDelivery({ deliveryId: sent.deliveryId })); if(Date.now()-lastSnapshotLog>2000) { log('pending-snapshot', snapshot); lastSnapshotLog=Date.now(); } return snapshot.terminal; });
  result.deliveries.push({ text, ...snapshot });
  log('delivery-terminal', { text, ...snapshot });
  if (snapshot.state !== 'RECIPIENT_RECEIPT_RECEIVED') throw Error('delivery failed: ' + snapshot.state);
}
try {
  log('identity-ready', { publicKey: result.self, expectedPeer: peer });
  need(await client.start()); log('client-started');
  if (role === 'invitee') {
    const published = need(await client.publishKeyPackage());
    result.keyPackageEventId = published.keyPackageEventId;
    log('keypackage-published', published);
    log('waiting-for-invite');
    need(await client.acceptInvite({ inviter: peer, keyPackageEventId: published.keyPackageEventId }));
  } else {
    const invited = need(await client.invite({ invitee: peer }));
    result.keyPackageEventId = invited.keyPackageEventId;
    log('invite-published', invited);
  }
  result.groupFingerprint = mls.fingerprint(peer);
  log('mls-ready', { groupFingerprint: result.groupFingerprint });
  if (role === 'inviter') {
    await sleep(2000);
    await send('synthetic attacker target');
    await until(() => result.received.length === 1);
    await sleep(5000);
  } else {
    await until(() => result.received.length === 1);
    log('hold-window-start', { durationMs: 110000 });
    await sleep(110000);
    holdReceipts = false;
    log('true-receipt-release', { queued: heldReceipts.length });
    for (const item of heldReceipts) item.socket.send(item.data);
    await send('synthetic honest reply');
    await sleep(5000);
  }
  // Not a protocol guarantee: allow final inbound receipt publish to settle.
  await sleep(3000);
  need(await client.shutdown());
  result.ok = result.deliveries.length === 1 && result.deliveries.every((d) => d.state === 'RECIPIENT_RECEIPT_RECEIVED')
    && result.received.length === 1 && result.received.every((r) => r.sender === peer);
  log('result', { ok: result.ok });
} catch (error) {
  result.ok = false; result.error = error.message; log('failure', { error: error.message });
  await client.shutdown();
} finally {
  for (const ws of observers) ws.close();
  id.destroy();
  if (env.OUT) writeFileSync(env.OUT, JSON.stringify(result, null, 2));
}
process.exit(result.ok ? 0 : 1);
