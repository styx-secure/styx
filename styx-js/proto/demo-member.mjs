#!/usr/bin/env node
// PROTOTYPE demo (branch proto/sdk-demo-2026-10): one member of a two-member
// Styx exchange over PUBLIC Nostr relays, through the SDK only.
//
//   ROLE=invitee  node proto/demo-member.mjs   (start first; publishes a KeyPackage, waits for a Welcome)
//   ROLE=inviter  INVITEE=<hex> node proto/demo-member.mjs
//
// Env: ROLE, IDENTITY_FILE, IDENTITY_PASSPHRASE (>=12 chars), RELAYS (comma list),
//      INVITEE (inviter only), MESSAGES (default 3), OUT (JSON result path),
//      KEYPACKAGE_EVENT (optional, invitee: wait on an already published KP),
//      REPLY_AFTER_ALL=1 (invitee: reply only once all N messages arrived)
//      REPLY_DELAY_MS (invitee: wait this long before each reply; default 0)
//      SCENES=1 (inviter only): demo scenes -- message 1 normal; relay R1 dropped on
//      this host, message 2; this host's network stalls (R2, R3 black-holed), message 3
//      times out and is retried after the network returns. Faults are injected here, in
//      the demo, by wrapping the global WebSocket; the SDK is not changed for them.
// Nothing is copied between hosts: the only shared input is the invitee's public key.
// The identity secret stays in the identity port (proto/identity.js).
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { MlsEngine } from '../src/crypto/mls/mls-engine.js';
import { createStyxClient, SDK_INTERFACE_VERSION } from '../src/sdk/index.js';
import { createMlsSessionPort } from '../src/sdk/session/mls-port.js';
import { createInviteFlow } from '../src/sdk/session/invite.js';
import { createFileIdentity } from './identity.js';

const env = process.env;
const ROLE = env.ROLE;
const SCENES = env.SCENES === '1' && ROLE === 'inviter';

// ---- demo-side network fault injection (host level, outside the SDK) ----
const NativeWS = globalThis.WebSocket;
const faults = new Map();
const live = new Set();
class FaultWS {
  static CONNECTING = 0; static OPEN = 1; static CLOSING = 2; static CLOSED = 3;
  constructor(url) {
    this.url = url; this.host = new URL(url).host;
    this.onopen = this.onmessage = this.onclose = this.onerror = null;
    if ((faults.get(this.host) || 'ok') === 'down') {
      this._ws = null; this._state = 3;
      setTimeout(() => { this.onerror?.(new Error('injected: relay dropped')); this.onclose?.({}); }, 5);
      return;
    }
    const ws = new NativeWS(url); this._ws = ws; live.add(this);
    ws.onopen = (e) => this.onopen?.(e);
    ws.onmessage = (e) => { if ((faults.get(this.host) || 'ok') === 'ok') this.onmessage?.(e); };
    ws.onclose = (e) => { live.delete(this); this.onclose?.(e); };
    ws.onerror = (e) => this.onerror?.(e);
  }
  get readyState() { return this._ws ? this._ws.readyState : this._state; }
  send(d) {
    if ((faults.get(this.host) || 'ok') !== 'ok') return;
    // demo log only: show the SDK's catch-up re-requests (REQ with a `since` bound)
    try {
      const m = JSON.parse(d);
      if (m[0] === 'REQ' && Number.isInteger(m[2]?.since)) {
        log(`catch-up: REQ since=${new Date(m[2].since * 1000).toISOString().slice(11, 19)}Z on ${RN(this.url.replace(/\/$/, ''))}`);
      }
    } catch { /* not JSON */ }
    this._ws?.send(d);
  }
  close() { try { this._ws?.close(); } catch { /* ignore */ } }
}
if (SCENES) globalThis.WebSocket = FaultWS;
const setFault = (url, mode) => {
  const host = new URL(url).host; faults.set(host, mode);
  if (mode === 'down') for (const x of live) if (x.host === host) x.close();
};
const RELAYS = (env.RELAYS || 'wss://relay.damus.io,wss://relay.primal.net,wss://offchain.pub').split(',');
const N = Number(env.MESSAGES || 3);
const t0 = Date.now();
const ts = () => new Date().toISOString().slice(11, 22) + 'Z';
const log = (...a) => console.log(`[${ts()}] ${ROLE}`, ...a);
const RN = (url) => `R${RELAYS.indexOf(url) + 1} ${new URL(url).host}`;
const short = (h) => (h ? `${h.slice(0, 8)}…${h.slice(-4)}` : h);
const result = { role: ROLE, interfaceVersion: SDK_INTERFACE_VERSION, relays: RELAYS, steps: [], deliveries: [], received: [] };
const step = (name, detail = {}) => { result.steps.push({ t: Date.now() - t0, name, ...detail }); };
const save = () => env.OUT && writeFileSync(env.OUT, JSON.stringify(result, null, 2));

if (ROLE !== 'inviter' && ROLE !== 'invitee') { console.error('ROLE must be inviter or invitee'); process.exit(2); }
const identity = createFileIdentity({ path: env.IDENTITY_FILE, passphrase: env.IDENTITY_PASSPHRASE });
const me = identity.getPublicKey();
result.self = me;
log('identity (file, scrypt+AES-GCM):', short(me));

await MlsEngine.initWasm({ wasmBytes: readFileSync(new URL('../vendor/openmls-wasm/openmls_wasm_bg.wasm', import.meta.url)) });
const engine = await MlsEngine.create({ name: me });
const session = createMlsSessionPort({ engine, selfPublicKey: me });
const flow = createInviteFlow({
  relays: RELAYS, identity, mlsPort: session,
  onProgress: (s, d) => { step(s, d); log('invite:', s, JSON.stringify(d ?? {}).slice(0, 160)); },
});

/* ---- 1. MLS invitation over Nostr ---- */
let peer;
if (ROLE === 'invitee') {
  let kpId = env.KEYPACKAGE_EVENT;
  if (!kpId) kpId = (await flow.publishKeyPackage({ expiresInSec: 1800 })).eventId;
  result.keyPackageEventId = kpId;
  save();
  log('waiting for a gift-wrapped Welcome for KeyPackage', short(kpId));
  const j = await flow.awaitWelcome({ keyPackageEventId: kpId, timeoutMs: 300000 });
  peer = j.inviter;
  result.groupId = j.groupId;
} else {
  peer = env.INVITEE;
  const inv = await flow.invite({ invitee: peer, timeoutMs: 120000 });
  result.groupId = inv.groupId;
  result.keyPackageEventId = inv.keyPackageEventId;
}
result.peer = peer;
// fingerprint of an MLS exporter value (hash only; the exporter output itself is never logged)
const check = createHash('sha256').update(session.exportSecret(peer, 'styx-proto-demo-check', new TextEncoder().encode(result.groupId), 32)).digest('hex').slice(0, 16);
result.groupCheck = check;
log('MLS group joined; peer', short(peer), 'group fingerprint', check, '(same on both members = same MLS group and epoch)');
step('mls-ready', { groupCheck: check });
save();

/* ---- 2. SDK client ---- */
const store = new Map();
const storage = {
  put: (r) => { store.set(r.deliveryId, r); return true; }, get: (id) => store.get(id) ?? null,
  update: (id, r) => (store.has(id) ? (store.set(id, r), true) : false), remove: (id) => store.delete(id), list: () => [...store.values()],
};
const cr = createStyxClient({
  interfaceVersion: SDK_INTERFACE_VERSION, relays: RELAYS,
  ports: { storage, session, identity: { getPublicKey: identity.getPublicKey, sign: identity.sign } },
  delivery: { receiptMode: 'RECIPIENT_RECEIPT', maxAttempts: 5, deadlineMs: 180000, perRelayTimeoutMs: 12000 },
});
if (!cr.ok) { log('createStyxClient failed', cr.code); process.exit(1); }
const client = cr.value;
const sha = (b) => createHash('sha256').update(b).digest('hex').slice(0, 16);
const received = [];
await client.onEvent((e) => {
  if (e.kind === 'MESSAGE_RECEIVED') {
    const text = new TextDecoder().decode(e.payload);
    received.push({ sender: e.sender, text });
    result.received.push({ t: Date.now() - t0, sender: e.sender, sha: sha(e.payload), text });
    log('RECEIVED from', short(e.sender), JSON.stringify(text));
  } else if (e.kind === 'DELIVERY_STATE_CHANGED') {
    log('delivery', e.deliveryId, '->', e.state, e.lastCode ?? '');
    result.states = result.states || [];
    result.states.push({ t: Date.now() - t0, at: ts(), deliveryId: e.deliveryId, state: e.state, lastCode: e.lastCode });
  } else if (e.kind === 'INBOUND_DISCARDED') {
    log('inbound discarded', e.code);
    step('inbound-discarded', { code: e.code });
  } else {
    log('client', e.clientState);
  }
  save();
});
const st = await client.start();
log('client.start ->', JSON.stringify(st));
step('client-started', st.ok ? st.value : { code: st.code });
if (!st.ok) { save(); process.exit(1); }

/* ---- 3. exchange: inviter sends N, invitee replies to each ---- */
const waitFor = async (pred, ms) => { const t = Date.now(); while (!pred()) { if (Date.now() - t > ms) return false; await new Promise((r) => setTimeout(r, 200)); } return true; };
let lastSentId = null;
async function sendAndTrack(text, scene = null) {
  const payload = new TextEncoder().encode(text);
  const s = await client.send({ recipient: peer, payload });
  if (!s.ok) { log('send failed', s.code); result.deliveries.push({ text, code: s.code }); return; }
  const id = s.value.deliveryId;
  lastSentId = id;
  log('SENT', JSON.stringify(text), 'deliveryId', id);
  let snap;
  for (;;) {
    snap = (await client.getDelivery({ deliveryId: id })).value;
    if (snap?.terminal) break;
    await new Promise((r) => setTimeout(r, 300));
  }
  result.deliveries.push({ scene, text, sha: sha(payload), deliveryId: id, state: snap.state, attempts: snap.attempts, lastCode: snap.lastCode, relayOutcomes: snap.relayOutcomes.map((o) => o.outcome), ms: Date.now() - snap.createdAt });
  log('TERMINAL', id, snap.state, 'attempts', snap.attempts, 'relays', snap.relayOutcomes.map((o, i) => `R${i + 1}=${o.outcome}`).join(' '));
  save();
}

const TERMINAL_STATES = ['RELAY_ACCEPTED', 'RECIPIENT_RECEIPT_RECEIVED', 'FAILED_NOT_ACCEPTED', 'FAILED_NO_RECEIPT', 'CANCELLED', 'LOST_ON_SHUTDOWN'];
const scene = (n, text) => { log(`SCENE ${n}: ${text}`); step('scene', { n, text }); };
if (ROLE === 'inviter' && SCENES) {
  await new Promise((r) => setTimeout(r, 3000));
  scene(1, 'one message over three public relays');
  await sendAndTrack('synthetic test message 1', 1);
  scene(2, `relay ${RN(RELAYS[0])} dropped on this host -> the other relays carry it`);
  setFault(RELAYS[0], 'down');
  log('FAULT injected:', RN(RELAYS[0]), 'connection closed, reconnects refused');
  step('fault', { what: 'drop', relay: 0 });
  await new Promise((r) => setTimeout(r, 800));
  await sendAndTrack('synthetic test message 2', 2);
  scene(3, 'this host\'s network stalls (all relays black-holed) -> attempt times out -> retry');
  for (const u of RELAYS.slice(1)) setFault(u, 'blackhole');
  log('FAULT injected:', RELAYS.slice(1).map(RN).join(', '), 'black-holed (frames dropped both ways);', RN(RELAYS[0]), 'still dropped');
  step('fault', { what: 'stall', relays: [1, 2] });
  const p3 = sendAndTrack('synthetic test message 3', 3);
  // restore once attempt 1 has timed out (the item is back to QUEUED with attempts >= 1)
  for (;;) {
    await new Promise((r) => setTimeout(r, 250));
    const st3 = (result.states || []).filter((x) => x.deliveryId === lastSentId).map((x) => x.state);
    const i = st3.indexOf('IN_FLIGHT');
    if (lastSentId && i >= 0 && st3.slice(i + 1).some((x) => x === 'QUEUED' || TERMINAL_STATES.includes(x))) break;
  }
  for (const u of RELAYS.slice(1)) setFault(u, 'ok');
  log('FAULT cleared: attempt 1 got no acceptance;', RELAYS.slice(1).map(RN).join(', '), 'restored;', RN(RELAYS[0]), 'stays dropped');
  step('fault', { what: 'stall-cleared' });
  await p3;
  const okReplies = await waitFor(() => received.length >= N, 180000);
  log('replies received', received.length, okReplies ? '' : '(timeout)');
} else if (ROLE === 'inviter') {
  await new Promise((r) => setTimeout(r, 3000)); // let the invitee's client subscribe
  for (let i = 1; i <= N; i += 1) await sendAndTrack(`ciao ${i}/${N} dal mittente ${new Date().toISOString()}`);
  const okReplies = await waitFor(() => received.length >= N, 180000);
  log('replies received', received.length, okReplies ? '' : '(timeout)');
} else {
  let answered = 0;
  // reply to each message as it arrives, or (REPLY_AFTER_ALL=1) only once all N arrived
  const t1 = Date.now();
  const gate = () => env.REPLY_AFTER_ALL !== '1' || received.length >= N;
  while (answered < N && Date.now() - t1 < 300000) {
    if (received.length > answered && gate()) {
      const m = received[answered]; answered += 1;
      if (Number(env.REPLY_DELAY_MS) > 0) await new Promise((r) => setTimeout(r, Number(env.REPLY_DELAY_MS)));
      await sendAndTrack(`synthetic reply ${answered} to "${m.text.slice(0, 26)}"`);
    } else await new Promise((r) => setTimeout(r, 200));
  }
  const okAll = answered >= N;
  log('answered', answered, okAll ? '' : '(timeout)');
}

const sd = await client.shutdown();
log('client.shutdown ->', JSON.stringify(sd));
step('client-stopped', sd.ok ? sd.value : { code: sd.code });
await flow.close();
result.ok = result.deliveries.length === N && result.deliveries.every((d) => d.state === 'RECIPIENT_RECEIPT_RECEIVED') && result.received.length >= N
  && result.received.every((r) => r.sender === peer);
result.totalMs = Date.now() - t0;
save();
log('RESULT', result.ok ? 'PASS' : 'FAIL');
process.exit(result.ok ? 0 : 1);
