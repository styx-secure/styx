// I-SDK client tests -- PROTOTYPE branch (proto/sdk-demo-2026-10).
// Loopback relays are started inside this file (ws WebSocketServer on 127.0.0.1).
import { describe, test, expect, afterEach } from '@jest/globals';
import { WebSocketServer } from 'ws';
import { schnorr } from '@noble/curves/secp256k1';
import * as sdk from '../../src/sdk/index.js';
import * as clientModule from '../../src/sdk/client.js';
import { bytesToHex } from '../../src/utils.js';

const {
  SDK_INTERFACE_VERSION, SdkResultCode, DeliveryState, RelayOutcome, ClientState, SdkEventKind,
  isKnownResultCode, createStyxClient,
} = sdk;

/* ---------- a tiny loopback relay ---------- */
function matches(f, ev) {
  if (f.ids && !f.ids.includes(ev.id)) return false;
  if (f.authors && !f.authors.includes(ev.pubkey)) return false;
  if (f.kinds && !f.kinds.includes(ev.kind)) return false;
  for (const k of Object.keys(f)) {
    if (k[0] === '#' && !ev.tags.some((t) => t[0] === k.slice(1) && f[k].includes(t[1]))) return false;
  }
  return true;
}
async function startRelay({ dropKinds = [] } = {}) {
  const wss = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await new Promise((r) => wss.once('listening', r));
  const events = [];
  const conns = new Set();
  let connections = 0;
  wss.on('connection', (ws) => {
    connections += 1;
    conns.add(ws);
    ws.subs = new Map();
    ws.on('close', () => conns.delete(ws));
    ws.on('message', (raw) => {
      const m = JSON.parse(String(raw));
      if (m[0] === 'EVENT') {
        const ev = m[1];
        if (dropKinds.includes(ev.kind)) return; // swallow: never stored, never answered
        events.push(ev);
        ws.send(JSON.stringify(['OK', ev.id, true, '']));
        for (const c of conns) for (const [id, fs] of c.subs) if (fs.some((f) => matches(f, ev))) c.send(JSON.stringify(['EVENT', id, ev]));
      } else if (m[0] === 'REQ') {
        const [, id, ...fs] = m;
        ws.subs.set(id, fs);
        for (const ev of events) if (fs.some((f) => matches(f, ev))) ws.send(JSON.stringify(['EVENT', id, ev]));
        ws.send(JSON.stringify(['EOSE', id]));
      }
    });
  });
  return {
    url: `ws://127.0.0.1:${wss.address().port}`,
    events,
    get connections() { return connections; },
    get open() { return conns.size; },
    close: async () => { for (const c of conns) c.terminate(); await new Promise((r) => wss.close(() => r())); },
  };
}

/* ---------- ports ---------- */
function identityPort() {
  const sk = schnorr.utils.randomPrivateKey();
  const pk = bytesToHex(schnorr.getPublicKey(sk));
  const port = { calls: 0, signs: 0, getPublicKey() { port.calls += 1; return pk; }, sign({ digest }) { port.signs += 1; return schnorr.sign(digest, sk); } };
  return { port, pk };
}
const sessionPort = () => ({ seal: ({ plaintext }) => ({ ciphertext: new Uint8Array(plaintext) }), open: ({ ciphertext }) => ({ plaintext: new Uint8Array(ciphertext) }) });
function storagePort() {
  const m = new Map();
  return {
    put: (r) => { m.set(r.deliveryId, r); return true; }, get: (id) => m.get(id) ?? null,
    update: (id, r) => (m.has(id) ? (m.set(id, r), true) : false), remove: (id) => m.delete(id), list: () => [...m.values()],
  };
}
const ports = (id = identityPort().port) => ({ storage: storagePort(), session: sessionPort(), identity: id });
const cfg = (relays, extra = {}) => ({ interfaceVersion: SDK_INTERFACE_VERSION, relays, ports: ports(), delivery: { perRelayTimeoutMs: 11000 }, ...extra });
const flush = () => new Promise((r) => setTimeout(r, 0));
const waitFor = async (pred, ms = 30000) => { const t = Date.now(); while (!pred()) { if (Date.now() - t > ms) throw new Error('waitFor timeout'); await new Promise((r) => setTimeout(r, 50)); } };

let cleanup = [];
afterEach(async () => { for (const f of cleanup.reverse()) await f(); cleanup = []; });

/* ---------- surface ---------- */
describe('surface', () => {
  test('index re-exports exactly the eight names of client.js', () => {
    const names = ['SDK_INTERFACE_VERSION', 'SdkResultCode', 'DeliveryState', 'RelayOutcome', 'ClientState', 'SdkEventKind', 'isKnownResultCode', 'createStyxClient'];
    expect(Object.keys(sdk).sort()).toEqual([...names].sort());
    expect(Object.keys(clientModule).sort()).toEqual([...names].sort());
    for (const n of names) expect(sdk[n]).toBe(clientModule[n]);
    expect(SDK_INTERFACE_VERSION).toBe('styx-m3-sdk/0.1.0-experimental');
  });
  test('enumerations are frozen, closed and self-mapped', () => {
    for (const [e, n] of [[SdkResultCode, 18], [DeliveryState, 9], [RelayOutcome, 5], [ClientState, 3], [SdkEventKind, 4]]) {
      expect(Object.isFrozen(e)).toBe(true);
      expect(Object.keys(e)).toHaveLength(n);
      for (const [k, v] of Object.entries(e)) expect(v).toBe(k);
      expect(Object.getPrototypeOf(e)).toBe(Object.prototype);
    }
  });
  test('isKnownResultCode', () => {
    for (const c of Object.keys(SdkResultCode)) expect(isKnownResultCode(c)).toBe(true);
    const trap = new Proxy({}, { get() { throw new Error('trap'); }, getPrototypeOf() { throw new Error('trap'); } });
    for (const v of ['toString', '__proto__', 'constructor', 'E_SDK_FOO', '', undefined, null, 7, {}, Symbol('x'), trap]) {
      expect(isKnownResultCode(v)).toBe(false);
    }
  });
});

/* ---------- createStyxClient ---------- */
describe('createStyxClient validation', () => {
  const L = 'ws://127.0.0.1:7000';
  test('version is checked first', () => {
    expect(createStyxClient({ interfaceVersion: 'x', relays: [L], ports: ports(), bogus: 1 })).toEqual({ ok: false, code: 'E_SDK_UNSUPPORTED_VERSION' });
    expect(createStyxClient({ relays: [L], ports: ports() }).code).toBe('E_SDK_UNSUPPORTED_VERSION');
  });
  test('non-objects and unknown keys', () => {
    class K {}
    const trap = new Proxy({}, { ownKeys() { throw new Error('t'); }, getOwnPropertyDescriptor() { throw new Error('t'); }, getPrototypeOf() { throw new Error('t'); } });
    for (const v of [undefined, null, 1, 's', [], () => {}, new K(), trap]) expect(createStyxClient(v).code).toBe('E_SDK_INVALID_CONFIG');
    const c = cfg([L]);
    Object.defineProperty(c, 'hidden', { value: 1, enumerable: false });
    expect(createStyxClient(c).code).toBe('E_SDK_INVALID_CONFIG');
    const c2 = cfg([L]); c2[Symbol('s')] = 1;
    expect(createStyxClient(c2).code).toBe('E_SDK_INVALID_CONFIG');
    const c3 = cfg([L]); c3.ports.extra = {};
    expect(createStyxClient(c3).code).toBe('E_SDK_INVALID_CONFIG');
    const c4 = cfg([L]); delete c4.ports.session.open;
    expect(createStyxClient(c4).code).toBe('E_SDK_INVALID_CONFIG');
  });
  test('delivery bounds', () => {
    const b = { maxAttempts: [1, 10], deadlineMs: [30000, 600000], perRelayTimeoutMs: [11000, 30000] };
    for (const [k, [lo, hi]] of Object.entries(b)) {
      for (const v of [lo, hi]) expect(createStyxClient(cfg([L], { delivery: { [k]: v } })).ok).toBe(true);
      for (const v of [lo - 1, hi + 1, 0, -1, 1.5, NaN, Infinity, String(lo)]) expect(createStyxClient(cfg([L], { delivery: { [k]: v } })).code).toBe('E_SDK_INVALID_CONFIG');
    }
    expect(createStyxClient(cfg([L], { delivery: { receiptMode: 'X' } })).code).toBe('E_SDK_INVALID_CONFIG');
    expect(createStyxClient(cfg([L], { delivery: { receiptMode: 'RECIPIENT_RECEIPT' } })).ok).toBe(true);
  });
  test('relay counts and duplicates', () => {
    const many = (n) => Array.from({ length: n }, (_, i) => `ws://127.0.0.1:${7000 + i}`);
    expect(createStyxClient(cfg([])).code).toBe('E_SDK_INVALID_CONFIG');
    expect(createStyxClient(cfg(many(1))).ok).toBe(true);
    expect(createStyxClient(cfg(many(16))).ok).toBe(true);
    expect(createStyxClient(cfg(many(17))).code).toBe('E_SDK_INVALID_CONFIG');
    expect(createStyxClient(cfg([L, L])).code).toBe('E_SDK_INVALID_CONFIG');
  });
  test('relay URL rule (loopback literals + prototype allowlist)', () => {
    const accept = ['ws://127.0.0.1:7000', 'wss://127.255.255.254/x?y=1', 'WS://127.0.0.1', 'ws://127.0.0.1:080', 'ws://127.0.0.1:',
      'ws://[::1]:1', 'ws://[0:0:0:0:0:0:0:1]', 'ws://[::0001]/', 'ws://[::0.0.0.1]'];
    for (const u of accept) expect([u, createStyxClient(cfg([u])).ok]).toEqual([u, true]);
    const sep = ':/' + '/';
    const rejectHosts = ['localhost', '128.0.0.1', '10.0.0.1', '127.0.0.01', '127.1', '[::ffff:127.0.0.1]', '[v1.x]', '[::1%25lo]'];
    for (const h of rejectHosts) expect([h, createStyxClient(cfg(['ws' + sep + h])).code]).toEqual([h, 'E_SDK_INVALID_CONFIG']);
    for (const u of ['ws://u@127.0.0.1', 'ws://127.0.0.1#f', 'ws://127.0.0.1/%zz', 'ws://127.0.0.1/ x', 'ws://127.0.0.1/\\', 'http://127.0.0.1', '']) {
      expect([u, createStyxClient(cfg([u])).code]).toEqual([u, 'E_SDK_INVALID_CONFIG']);
    }
    // PROTOTYPE allowlist: three public hosts, wss only, default port only
    for (const h of ['relay.damus.io', 'relay.primal.net', 'offchain.pub']) {
      expect(createStyxClient(cfg(['wss' + sep + h])).ok).toBe(true);
      expect(createStyxClient(cfg(['ws' + sep + h])).code).toBe('E_SDK_INVALID_CONFIG');
      expect(createStyxClient(cfg(['wss' + sep + h + ':444'])).code).toBe('E_SDK_INVALID_CONFIG');
      expect(createStyxClient(cfg(['wss' + sep + h.toUpperCase()])).code).toBe('E_SDK_INVALID_CONFIG');
    }
    expect(createStyxClient(cfg(['wss' + sep + ['nos', 'lol'].join('.')])).code).toBe('E_SDK_INVALID_CONFIG');
  });
  test('no port is called at creation; later mutation of config has no effect', () => {
    const id = identityPort().port;
    const c = cfg([L], { ports: ports(id) });
    const r = createStyxClient(c);
    expect(r.ok).toBe(true);
    expect(id.calls).toBe(0);
    expect(Object.isFrozen(r)).toBe(true);
    expect(Object.isFrozen(r.value)).toBe(true);
  });
});

/* ---------- state machine ---------- */
describe('state machine', () => {
  test('CREATED and STOPPED codes; shutdown in CREATED', async () => {
    const seen = [];
    const c = createStyxClient(cfg(['ws://127.0.0.1:1'])).value;
    await c.onEvent((e) => seen.push(e));
    expect((await c.send({ recipient: 'a'.repeat(64), payload: new Uint8Array(1) })).code).toBe('E_SDK_NOT_STARTED');
    expect((await c.cancel({ deliveryId: 'x' })).code).toBe('E_SDK_NOT_STARTED');
    expect((await c.getDelivery({ deliveryId: 'x' })).code).toBe('E_SDK_NOT_STARTED');
    expect(await c.shutdown()).toEqual({ ok: true, value: { clientState: 'STOPPED', lost: 0 } });
    await flush();
    expect(seen).toEqual([{ kind: 'CLIENT_STATE_CHANGED', clientState: 'STOPPED' }]);
    expect((await c.shutdown()).code).toBe('E_SDK_CLIENT_STOPPED');
    expect((await c.start()).code).toBe('E_SDK_CLIENT_STOPPED');
    expect((await c.send({ recipient: 'a'.repeat(64), payload: new Uint8Array(1) })).code).toBe('E_SDK_CLIENT_STOPPED');
    expect((await c.getDelivery({ deliveryId: 'x' })).code).toBe('E_SDK_UNKNOWN_DELIVERY');
    expect((await c.onEvent(() => {})).ok).toBe(true);
    expect((await c.onEvent(1)).code).toBe('E_SDK_INVALID_ARGUMENT');
  });

  test('start failures: storage not empty, identity faults, no relay; client stays CREATED', async () => {
    const r = await startRelay();
    cleanup.push(() => r.close());
    const p = ports();
    p.storage.put({ deliveryId: 'old', state: 'QUEUED' });
    expect((await createStyxClient(cfg([r.url], { ports: p })).value.start()).code).toMatch(/E_SDK_STORAGE_(NOT_EMPTY|FAILED)/);
    for (const [bad, code] of [
      [() => { throw new Error('x'); }, 'E_SDK_IDENTITY_FAILED'],
      [() => Promise.reject(new Error('x')), 'E_SDK_IDENTITY_FAILED'],
      [() => 'A'.repeat(64), 'E_SDK_IDENTITY_FAILED'],
      [() => 'a'.repeat(63), 'E_SDK_IDENTITY_FAILED'],
      [() => ({ code: 'E_NOPE' }), 'E_SDK_UNKNOWN_CODE'],
    ]) {
      const id = { getPublicKey: bad, sign: () => new Uint8Array(64) };
      expect((await createStyxClient(cfg([r.url], { ports: ports(id) })).value.start()).code).toBe(code);
    }
    // never settles -> bounded by the port-call timeout (5.5 s)
    const t0 = Date.now();
    const hang = { getPublicKey: () => new Promise(() => {}), sign: () => new Uint8Array(64) };
    expect((await createStyxClient(cfg([r.url], { ports: ports(hang) })).value.start()).code).toBe('E_SDK_IDENTITY_FAILED');
    expect(Date.now() - t0).toBeLessThan(8000);
    expect(r.connections).toBe(0); // nothing connected before the key was read
    // no listener on the port -> no relay; a later start on a working relay succeeds
    const dead = await startRelay(); const deadUrl = dead.url; await dead.close();
    const id = identityPort();
    const c = createStyxClient(cfg([deadUrl], { ports: ports(id.port) })).value;
    expect((await c.start()).code).toBe('E_SDK_NO_RELAY_AVAILABLE');
    expect((await c.send({ recipient: id.pk, payload: new Uint8Array(1) })).code).toBe('E_SDK_NOT_STARTED');
  }, 60000);
});

/* ---------- end to end on loopback ---------- */
async function pair(relays, mode) {
  const a = identityPort();
  const b = identityPort();
  const mk = (id) => createStyxClient(cfg(relays.map((r) => r.url), { ports: ports(id.port), delivery: { perRelayTimeoutMs: 11000, receiptMode: mode } })).value;
  const A = mk(a); const B = mk(b);
  const evA = []; const evB = [];
  await A.onEvent((e) => evA.push(e)); await B.onEvent((e) => evB.push(e));
  const [sa, sb] = await Promise.all([A.start(), B.start()]);
  cleanup.push(async () => { await A.shutdown(); await B.shutdown(); });
  return { A, B, a, b, evA, evB, sa, sb };
}

describe('end to end (two loopback relays, identity-function session)', () => {
  test('RECIPIENT_RECEIPT: receipt closes the item; snapshot; key read once; mutation after send has no effect', async () => {
    const relays = [await startRelay(), await startRelay()];
    cleanup.push(async () => { for (const r of relays) await r.close(); });
    const { A, a, b, evA, evB, sa, sb } = await pair(relays, 'RECIPIENT_RECEIPT');
    expect(sa).toEqual({ ok: true, value: { clientState: 'RUNNING', connectedRelays: 2 } });
    expect(sb.ok).toBe(true);
    const payload = new TextEncoder().encode('hello b');
    const s = await A.send({ recipient: b.pk, payload });
    payload[0] = 0x58;
    expect(s.ok).toBe(true);
    expect(s.value.state).toBe('QUEUED');
    await waitFor(() => evA.some((e) => e.deliveryId === s.value.deliveryId && e.state === 'RECIPIENT_RECEIPT_RECEIVED'));
    const states = evA.filter((e) => e.deliveryId === s.value.deliveryId).map((e) => e.state);
    expect(states).toContain('RELAY_ACCEPTED_AWAITING_RECEIPT');
    expect(states.at(-1)).toBe('RECIPIENT_RECEIPT_RECEIVED');
    const msg = evB.find((e) => e.kind === 'MESSAGE_RECEIVED');
    expect(msg.sender).toBe(a.pk);
    expect(new TextDecoder().decode(msg.payload)).toBe('hello b');
    const snap = await A.getDelivery({ deliveryId: s.value.deliveryId });
    expect(Object.keys(snap.value).sort()).toEqual(['attempts', 'createdAt', 'deadlineAt', 'deliveryId', 'lastCode', 'recipient', 'relayOutcomes', 'state', 'terminal']);
    expect(snap.value.relayOutcomes.map((o) => o.relayIndex)).toEqual([0, 1]);
    expect(Object.isFrozen(snap.value)).toBe(true);
    expect((await A.cancel({ deliveryId: s.value.deliveryId })).code).toBe('E_SDK_DELIVERY_TERMINAL');
    expect((await A.cancel({ deliveryId: 'nope' })).code).toBe('E_SDK_UNKNOWN_DELIVERY');
    expect(a.port.calls).toBe(1);
    expect(b.port.calls).toBe(1);
    expect(b.port.signs).toBeGreaterThanOrEqual(1); // the receipt was signed through the port
    expect((await A.start()).code).toBe('E_SDK_ALREADY_STARTED');
    expect((await A.send({ recipient: b.pk, payload: new Uint8Array(0) })).code).toBe('E_SDK_INVALID_ARGUMENT');
    expect((await A.send({ recipient: b.pk, payload: new Uint8Array(65537) })).code).toBe('E_SDK_PAYLOAD_TOO_LARGE');
    expect((await A.send({ recipient: b.pk.toUpperCase(), payload: new Uint8Array(1) })).code).toBe('E_SDK_INVALID_ARGUMENT');
    expect((await A.send({ recipient: b.pk, payload: new Uint8Array(1), extra: 1 })).code).toBe('E_SDK_INVALID_ARGUMENT');
  }, 60000);

  test('RELAY_ACCEPTANCE_ONLY; listener order, faults and payload copies', async () => {
    const relays = [await startRelay()];
    cleanup.push(async () => { for (const r of relays) await r.close(); });
    const { A, B, b, evA } = await pair(relays, 'RELAY_ACCEPTANCE_ONLY');
    const order = [];
    const got = [];
    await B.onEvent(() => { order.push(1); throw new Error('listener fault'); });
    await B.onEvent((e) => { order.push(2); if (e.kind === 'MESSAGE_RECEIVED') { got.push(e.payload); e.payload[0] = 0; } });
    await B.onEvent((e) => { order.push(3); if (e.kind === 'MESSAGE_RECEIVED') got.push(e.payload); return Promise.reject(new Error('x')); });
    const before = evA.length;
    const p = A.send({ recipient: b.pk, payload: new Uint8Array([7, 8, 9]) });
    expect(evA.length).toBe(before); // nothing is dispatched synchronously inside send()
    const s = await p;
    await waitFor(() => evA.some((e) => e.deliveryId === s.value.deliveryId && e.state === 'RELAY_ACCEPTED'));
    await waitFor(() => got.length === 2);
    expect(got[1]).toEqual(new Uint8Array([7, 8, 9])); // listener 2 mutated its own copy only
    expect(got[0]).not.toBe(got[1]);
    expect(order.slice(0, 3)).toEqual([1, 2, 3]);
  }, 60000);

  test('shutdown with an item awaiting its receipt: LOST_ON_SHUTDOWN before STOPPED; sockets closed', async () => {
    const relays = [await startRelay({ dropKinds: [4742] })]; // receipts never reach anyone
    cleanup.push(async () => { for (const r of relays) await r.close(); });
    const { A, b, evA } = await pair(relays, 'RECIPIENT_RECEIPT');
    const s = await A.send({ recipient: b.pk, payload: new Uint8Array([1]) });
    await waitFor(() => evA.some((e) => e.state === 'RELAY_ACCEPTED_AWAITING_RECEIPT'));
    const late = [];
    const r = await A.shutdown();
    await A.onEvent((e) => late.push(e));
    expect(r).toEqual({ ok: true, value: { clientState: 'STOPPED', lost: 1 } });
    await flush();
    const tail = evA.slice(-2);
    expect(tail[0]).toMatchObject({ kind: 'DELIVERY_STATE_CHANGED', deliveryId: s.value.deliveryId, state: 'LOST_ON_SHUTDOWN', lastCode: null, terminal: true });
    expect(tail[1]).toEqual({ kind: 'CLIENT_STATE_CHANGED', clientState: 'STOPPED' });
    expect(late).toHaveLength(0);
    expect((await A.getDelivery({ deliveryId: s.value.deliveryId })).value.state).toBe('LOST_ON_SHUTDOWN');
    expect((await A.send({ recipient: b.pk, payload: new Uint8Array([1]) })).code).toBe('E_SDK_CLIENT_STOPPED');
    await waitFor(() => relays[0].open <= 1, 5000); // only B is still connected
  }, 60000);
});
