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
    this.ws.onmessage = (e) => { if (!faults.has(this.url)) this.onmessage?.(e); };
    this.ws.onerror = (e) => this.onerror?.(e);
    this.ws.onclose = (e) => { live.delete(this); this.onclose?.(e); };
  }
  get readyState() { return this.ws?.readyState ?? 3; }
  send(data) {
    if (faults.has(this.url)) return;
    try {
      const m = JSON.parse(data);
      if (m[0] === 'REQ' && Number.isInteger(m[2]?.since)) log('catch-up-req', { relay: this.url, since: m[2].since });
      if (m[0] === 'EVENT') log('wire-publish', { relay: this.url, kind: m[1].kind, eventId: m[1].id });
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
  const sent = need(await client.send({ recipient: peer, payload: new TextEncoder().encode(text) }));
  lastDelivery = sent.deliveryId;
  log('send', { text, deliveryId: lastDelivery });
  let snapshot;
  await until(async () => { snapshot = need(await client.getDelivery({ deliveryId: sent.deliveryId })); return snapshot.terminal; });
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
    await send('synthetic message 1');
    await until(() => result.received.length >= 1);
    // Exclude R1 on this host; R1 itself remains online.
    fault(relays[0], 'down');
    await send('synthetic message 2');
    // Reply 2 is deliberately delayed by the other member, then sent while
    // this member drops both directions. Periodic SDK catch-up must recover it.
    for (const url of relays.slice(1)) fault(url, 'blackhole');
    const pending = send('synthetic message 3');
    await until(() => {
      const states = result.states.filter((s) => s.deliveryId === lastDelivery).map((s) => s.state);
      return states.includes('IN_FLIGHT') && states.slice(states.indexOf('IN_FLIGHT') + 1).includes('QUEUED');
    });
    for (const url of relays.slice(1)) fault(url, null);
    log('stall-cleared');
    await pending;
    await until(() => result.received.length >= 3);
  } else {
    for (let n = 1; n <= 3; n++) {
      await until(() => result.received.length >= n);
      if (n === 2) await sleep(2000);
      await send('synthetic reply ' + n);
    }
  }
  // Not a protocol guarantee: allow final inbound receipt publish to settle.
  await sleep(3000);
  need(await client.shutdown());
  result.ok = result.deliveries.length === 3 && result.deliveries.every((d) => d.state === 'RECIPIENT_RECEIPT_RECEIVED')
    && result.received.length === 3 && result.received.every((r) => r.sender === peer);
  log('result', { ok: result.ok });
} catch (error) {
  result.ok = false; result.error = error.message; log('failure', { error: error.message });
  await client.shutdown();
} finally {
  id.destroy();
  if (env.OUT) writeFileSync(env.OUT, JSON.stringify(result, null, 2));
}
process.exit(result.ok ? 0 : 1);
