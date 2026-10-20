// PROTOTYPE tests: inbound catch-up after a stall or a reconnect (src/sdk/catch-up.js).
// Reproduces demo run1: a reply sent while the receiver's network is stalled
// is accepted by the relays, and is recovered once the network returns.
import { describe, test, expect, beforeAll, afterEach } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { MlsEngine } from '../../src/crypto/mls/mls-engine.js';
import { createMlsSessionPort } from '../../src/sdk/session/mls-port.js';
import { createStyxClient, SDK_INTERFACE_VERSION } from '../../src/sdk/index.js';
import { createCatchUp, CATCH_UP_MARGIN_SEC } from '../../src/sdk/catch-up.js';
import { createSeedIdentity } from '../../proto/identity.js';
import { startRelay } from './support/relay.js';

const wasmBytes = readFileSync(new URL('../../vendor/openmls-wasm/openmls_wasm_bg.wasm', import.meta.url));
const enc = (s) => new TextEncoder().encode(s);
const dec = (b) => new TextDecoder().decode(b);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ------------------------------------------------------------------ unit */

function fakeClock(startMs = 1_800_000_000_000) {
  let now = startMs;
  const timers = new Map();
  let next = 1;
  return {
    now: () => now,
    setTimer: (cb, ms) => { const h = next++; timers.set(h, { at: now + ms, cb }); return h; },
    clearTimer: (h) => { timers.delete(h); },
    advance(ms) {
      now += ms;
      for (const [h, t] of [...timers]) if (t.at <= now) { timers.delete(h); t.cb(); }
    },
    get pending() { return timers.size; },
  };
}

function fakePool() {
  const calls = [];
  return { calls, subscribe(id, f) { calls.push({ id, f }); } };
}

describe('catch-up (unit)', () => {
  test('first subscription has no since; after an event, re-requests carry since = lastSeen - margin', () => {
    const clock = fakeClock();
    const pools = {};
    const cu = createCatchUp({ clock, intervalMs: 1000, createPool: (u) => (pools[u] = fakePool()) });
    const p = cu.transport.create('ws://127.0.0.1:1');
    p.subscribe('s1', { kinds: [4741], '#p': ['aa'] });
    expect(pools['ws://127.0.0.1:1'].calls[0].f.since).toBeUndefined();
    cu.start();
    clock.advance(1000); // nothing seen yet: no re-request
    expect(pools['ws://127.0.0.1:1'].calls).toHaveLength(1);
    const t = Math.floor(clock.now() / 1000) - 5;
    cu.observe({ relay: 'ws://127.0.0.1:1', data: ['EVENT', 's1', { created_at: t }] });
    clock.advance(1000);
    const last = pools['ws://127.0.0.1:1'].calls.at(-1);
    expect(last).toEqual({ id: 's1', f: { kinds: [4741], '#p': ['aa'], since: t - CATCH_UP_MARGIN_SEC } });
    cu.stop();
    expect(clock.pending).toBe(0);
  });

  test('a replacement pool (reconnect) subscribes with since; created_at in the future is capped; relays are independent', () => {
    const clock = fakeClock();
    const pools = [];
    const cu = createCatchUp({ clock, createPool: () => { const x = fakePool(); pools.push(x); return x; } });
    cu.transport.create('ws://a').subscribe('s', { kinds: [1] });
    cu.transport.create('ws://b').subscribe('s', { kinds: [1] });
    const now = Math.floor(clock.now() / 1000);
    cu.observe({ relay: 'ws://a', data: ['EVENT', 's', { created_at: now + 100000 }] }); // lying relay
    cu.observe({ relay: 'ws://a', data: ['EVENT', 's', { created_at: 'x' }] }); // ignored
    cu.observe({ relay: 'ws://b', data: ['EOSE', 's'] }); // ignored
    expect(cu.inspect().since).toEqual({ 'ws://a': now - CATCH_UP_MARGIN_SEC, 'ws://b': null });
    cu.transport.create('ws://a').subscribe('s', { kinds: [1] }); // replacement pool for relay a
    expect(pools[2].calls[0].f).toEqual({ kinds: [1], since: now - CATCH_UP_MARGIN_SEC });
    cu.catchUpNow();
    expect(pools[1].calls).toHaveLength(1); // relay b: nothing seen, no re-request
  });
});

/* ----------------------------------------------------------- integration */

let relays = [];
const clients = [];
afterEach(async () => {
  for (const c of clients.splice(0)) await c.shutdown();
  for (const r of relays) await r.close();
  relays = [];
});
beforeAll(async () => { await MlsEngine.initWasm({ wasmBytes }); });

async function member(seed) {
  const identity = createSeedIdentity({ seed });
  const pk = identity.getPublicKey();
  const engine = await MlsEngine.create({ name: pk });
  return { identity, pk, port: createMlsSessionPort({ engine, selfPublicKey: pk }) };
}

function memStorage() {
  const s = new Map();
  return {
    put: (r) => { s.set(r.deliveryId, r); return true; }, get: (id) => s.get(id) ?? null,
    update: (id, r) => (s.has(id) ? (s.set(id, r), true) : false), remove: (id) => s.delete(id), list: () => [...s.values()],
  };
}

async function client(m, urls, opens) {
  const session = {
    seal: (a) => m.port.seal(a),
    open: (a) => { opens.push(a.sender); return m.port.open(a); },
  };
  const r = createStyxClient({
    interfaceVersion: SDK_INTERFACE_VERSION, relays: urls,
    ports: { storage: memStorage(), session, identity: { getPublicKey: m.identity.getPublicKey, sign: m.identity.sign } },
    delivery: { receiptMode: 'RECIPIENT_RECEIPT', maxAttempts: 5, deadlineMs: 60000, perRelayTimeoutMs: 11000 },
  });
  expect(r.ok).toBe(true);
  const c = r.value;
  const got = [];
  await c.onEvent((e) => { if (e.kind === 'MESSAGE_RECEIVED') got.push(dec(e.payload)); });
  const st = await c.start();
  expect(st.ok).toBe(true);
  clients.push(c);
  return { c, got };
}

async function waitTerminal(c, id, ms) {
  const t = Date.now();
  for (;;) {
    const s = (await c.getDelivery({ deliveryId: id })).value;
    if (s.terminal || Date.now() - t > ms) return s;
    await sleep(200);
  }
}

describe('catch-up (two clients, loopback relays)', () => {
  test('a reply sent while the receiver is stalled is recovered when the network returns, decrypted once', async () => {
    relays = [await startRelay(), await startRelay()];
    const urls = relays.map((r) => r.url);
    const alice = await member('alice-seed-catchup');
    const bob = await member('bob-seed-catchup');
    const st = alice.port.startSession(bob.pk, bob.port.keyPackageBytes());
    bob.port.joinSession(alice.pk, st.welcome, st.ratchetTree);
    const aliceOpens = [];
    const A = await client(alice, urls, aliceOpens);
    const B = await client(bob, urls, []);

    // 1. before the stall: Bob -> Alice, delivered with a receipt
    const s1 = await B.c.send({ recipient: alice.pk, payload: enc('reply 1 before the stall') });
    expect((await waitTerminal(B.c, s1.value.deliveryId, 30000)).state).toBe('RECIPIENT_RECEIPT_RECEIVED');
    expect(A.got).toEqual(['reply 1 before the stall']);

    // 2. Alice's network stalls on both relays (sockets stay open, frames dropped both ways)
    for (const r of relays) r.stall(alice.pk, true);
    const s2 = await B.c.send({ recipient: alice.pk, payload: enc('reply 2 during the stall') });
    expect(s2.ok).toBe(true);
    await sleep(3000);
    const mid = (await B.c.getDelivery({ deliveryId: s2.value.deliveryId })).value;
    expect(mid.state).toBe('RELAY_ACCEPTED_AWAITING_RECEIPT'); // relays have it
    expect(A.got).toEqual(['reply 1 before the stall']); // Alice does not
    expect(relays.every((r) => r.events.some((e) => e.kind === 4741 && e.tags.some((t) => t[0] === 'p' && t[1] === alice.pk)))).toBe(true);

    // 3. network back: the next catch-up round re-requests with since and recovers it
    const nReq = relays.map((r) => r.reqs.length);
    for (const r of relays) r.stall(alice.pk, false);
    const end = await waitTerminal(B.c, s2.value.deliveryId, 30000);
    expect(end.state).toBe('RECIPIENT_RECEIPT_RECEIVED');
    expect(A.got).toEqual(['reply 1 before the stall', 'reply 2 during the stall']);
    // the catch-up REQ carried a since bound
    const later = relays.flatMap((r, i) => r.reqs.slice(nReq[i])).filter((q) => q.owners.includes(alice.pk));
    expect(later.length).toBeGreaterThan(0);
    expect(later.every((q) => q.filters.every((f) => Number.isInteger(f.since)))).toBe(true);
    // replays (reply 1 again, from two relays) were dropped by id before the session port:
    // exactly one open() per distinct message
    expect(aliceOpens).toEqual([bob.pk, bob.pk]);
  }, 90000);
});
