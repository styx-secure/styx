// M3-RECEIVE-2: SDK clients over the reference receiver, the real MlsEngine
// and loopback relays started inside the test: invitation, restart of the
// invitee before any message (criterion 14), H17 with the port (criterion 13)
// and a transient engine fault (criterion 7).
import { describe, test, expect, beforeAll, afterAll, afterEach } from '@jest/globals';
import { WebSocket } from 'ws';
import { headerGroupId } from '../../reference/receive-state/index.js';
import {
  initWasm, tempRoot, removeTempRoots, party, relay, makeClient, counted, fastClock, until, sleep, text, untext,
} from './helpers.js';

import { jest } from '@jest/globals';
jest.setTimeout(30_000);
const cleanups = [];
let originalWebSocket;
beforeAll(async () => {
  originalWebSocket = globalThis.WebSocket;
  globalThis.WebSocket = WebSocket;
  await initWasm();
});
afterAll(() => {
  globalThis.WebSocket = originalWebSocket;
  removeTempRoots();
});
afterEach(async () => { for (const cleanup of cleanups.splice(0).reverse()) await cleanup(); });

async function relays(count, options = []) {
  const out = [];
  for (let i = 0; i < count; i += 1) {
    const r = await relay(options[i] ?? {});
    cleanups.push(() => r.close());
    out.push(r);
  }
  return out;
}

/** One SDK client run of `who` over `rs`; shut down at the end of the test. */
async function run(who, rs, { hooks, clock = fastClock(), onMessage, receiptMode } = {}) {
  const receiver = who.instance(hooks ? { hooks } : {});
  const ports = counted(receiver);
  const h = makeClient({ urls: rs.map((r) => r.url), keys: who.keys, ports, clock, receiptMode });
  cleanups.push(() => h.client.shutdown());
  const started = await h.start({ onMessage });
  expect(started.ok).toBe(true);
  return { ...h, receiver, calls: ports.calls };
}

async function invited(rs) {
  const root = tempRoot();
  const alice = party(root, 'alice');
  const bob = party(root, 'bob');
  const a = await run(alice, rs);
  const b = await run(bob, rs);
  const published = await b.client.publishKeyPackage();
  expect(published.ok).toBe(true);
  const accepting = b.client.acceptInvite({ inviter: alice.identity, keyPackageEventId: published.value.keyPackageEventId });
  const sent = await a.client.invite({ invitee: bob.identity });
  expect(sent.ok).toBe(true);
  expect(await accepting).toEqual({ ok: true, value: { inviter: alice.identity } });
  const bindings = b.receiver.inspect().bindings;
  await b.client.shutdown(); // one client owns one receive state: each test starts its own run of Bob
  return { alice, bob, a, bindings };
}

describe('invitation and restart with the reference receiver (criterion 14)', () => {
  test('the invitee restarts before any message: the first message is verified, delivered once, acknowledged', async () => {
    const rs = await relays(2);
    const { alice, bob, a, bindings } = await invited(rs);
    expect(bindings).toEqual([{ peer: alice.identity, groupId: null }]);
    let b2;
    const acked = [];
    b2 = await run(bob, rs, { onMessage: async (m) => { acked.push(await b2.client.acknowledgeMessage({ eventId: m.eventId })); } });
    expect(b2.receiver.inspect().bindings).toEqual([{ peer: alice.identity, groupId: null }]);
    const sent = await a.client.send({ recipient: bob.identity, payload: text('first') });
    expect(sent.ok).toBe(true);
    expect(await until(() => acked.length === 1)).toBe(true);
    expect(acked[0].ok).toBe(true);
    expect(b2.messages().map((m) => untext(m.payload))).toEqual(['first']);
    const stored = [...rs[0].events.values()].find((e) => e.kind === 4741);
    const groupId = headerGroupId(Uint8Array.from(Buffer.from(stored.content, 'base64')));
    expect(b2.receiver.inspect().bindings).toEqual([{ peer: alice.identity, groupId }]);
    expect(b2.calls.stage).toHaveLength(1);
    expect(b2.calls.open).toHaveLength(1);
    // Alice gets Bob's receipt; Bob's obligation is then done.
    expect(await until(() => a.events.some((e) => e.deliveryId === sent.value.deliveryId
      && e.state === 'RECIPIENT_RECEIPT_RECEIVED'))).toBe(true);
    expect(await until(() => b2.calls.receiptDone.length === 1)).toBe(true);
    await b2.client.shutdown();
    // A further restart loads the completed binding: Bob can now reply first.
    const b3 = await run(bob, rs);
    expect(b3.receiver.inspect().bindings).toEqual([{ peer: alice.identity, groupId }]);
    expect(b3.messages()).toEqual([]); // acknowledged: never delivered again
    const back = await b3.client.send({ recipient: alice.identity, payload: text('reply') });
    expect(back.ok).toBe(true);
    expect(await until(() => a.messages().length === 1)).toBe(true);
    expect(untext(a.messages()[0].payload)).toBe('reply');
    expect(b3.calls.open).toHaveLength(0); // the first message is not opened again after restart
  });

  test('an unacknowledged message is delivered again after restart, without opening it again', async () => {
    const rs = await relays(1);
    const { bob, a, alice } = await invited(rs);
    const b = await run(bob, rs);
    await a.client.send({ recipient: bob.identity, payload: text('keep') });
    expect(await until(() => b.messages().length === 1)).toBe(true);
    await b.client.shutdown();
    const b2 = await run(bob, rs);
    expect(await until(() => b2.messages().length === 1)).toBe(true);
    expect(b2.messages()[0]).toMatchObject({ sender: alice.identity, eventId: b.messages()[0].eventId });
    expect(untext(b2.messages()[0].payload)).toBe('keep');
    expect(b2.calls.open).toHaveLength(0);
    expect((await b2.client.acknowledgeMessage({ eventId: b2.messages()[0].eventId })).ok).toBe(true);
  });
});

describe('H17 with the port on the real engine (criterion 13) and transient faults (criterion 7)', () => {
  test('(a) a retry, then a copy from a second relay: retried and delivered exactly once, staged once', async () => {
    const rs = await relays(2, [{}, { delayMs: 300 }]);
    const { bob, a } = await invited(rs);
    let failures = 1;
    const b = await run(bob, rs, {
      clock: fastClock(1), // the periodic pass is 10 s away: only the copy can trigger the retry
      hooks: { beforeCandidate: () => { if (failures > 0) { failures -= 1; throw new Error('transient'); } } },
    });
    await a.client.send({ recipient: bob.identity, payload: text('h17-a') });
    expect(await until(() => b.messages().length === 1, 5_000)).toBe(true);
    expect(untext(b.messages()[0].payload)).toBe('h17-a');
    expect(b.calls.stage).toHaveLength(1);
    expect(b.calls.open).toHaveLength(2);
    expect(b.calls.commit).toHaveLength(1);
    await sleep(200);
    expect(b.messages()).toHaveLength(1);
  });

  test('(b) a retry without any copy is retried by the periodic pass after its budget renews', async () => {
    const rs = await relays(1);
    const { bob, a } = await invited(rs);
    let failures = 1;
    const b = await run(bob, rs, {
      clock: fastClock(50),
      hooks: { beforeCandidate: () => { if (failures > 0) { failures -= 1; throw new Error('transient'); } } },
    });
    await a.client.send({ recipient: bob.identity, payload: text('h17-b') });
    expect(await until(() => b.calls.open.length === 1)).toBe(true);
    expect(b.messages()).toHaveLength(0);
    expect(await until(() => b.messages().length === 1, 5_000)).toBe(true);
    expect(untext(b.messages()[0].payload)).toBe('h17-b');
    expect(b.calls.stage).toHaveLength(1);
    expect(b.calls.open).toHaveLength(2);
  });

  test('(d) many copies of a PENDING id after its in-run retry open nothing more before the next interval', async () => {
    const rs = await relays(4, [{}, { delayMs: 60 }, { delayMs: 120 }, { delayMs: 180 }]);
    const { bob, a } = await invited(rs);
    let failing = true;
    const b = await run(bob, rs, {
      clock: fastClock(5), // catch-up interval: 2 s of host time
      hooks: { beforeCandidate: () => { if (failing) throw new Error('still failing'); } },
    });
    await a.client.send({ recipient: bob.identity, payload: text('h17-d') });
    expect(await until(() => b.calls.open.length >= 1)).toBe(true);
    await sleep(600);
    expect(b.calls.open).toHaveLength(2); // the first attempt and one retry by the first copy
    expect(b.calls.stage).toHaveLength(1);
    failing = false;
    expect(await until(() => b.messages().length === 1, 8_000)).toBe(true);
    expect(b.calls.open).toHaveLength(3);
  });

  test('(c) a copy of a READY or acknowledged id is dropped without openCandidate', async () => {
    const rs = await relays(2);
    const { bob, a } = await invited(rs);
    const b = await run(bob, rs);
    await a.client.send({ recipient: bob.identity, payload: text('h17-c') });
    expect(await until(() => b.messages().length >= 1)).toBe(true);
    const id = b.messages()[0].eventId;
    rs[0].replay(id);
    rs[1].replay(id);
    await sleep(200);
    expect(b.calls.open).toHaveLength(1);
    expect((await b.client.acknowledgeMessage({ eventId: id })).ok).toBe(true);
    rs[0].replay(id);
    await sleep(200);
    expect(b.calls.open).toHaveLength(1);
    expect(b.calls.stage).toHaveLength(1);
  });

  test('criterion 7: an openCandidate that outlives the port-call timeout leaves the entry PENDING and MLS unchanged; a later trigger delivers it once', async () => {
    const rs = await relays(1);
    const { bob, a } = await invited(rs);
    let slow = true;
    const clock = fastClock(50);
    const b = await run(bob, rs, {
      clock,
      hooks: { beforeCandidate: async () => { if (slow) { slow = false; await sleep(6_500); } } },
    });
    await a.client.send({ recipient: bob.identity, payload: text('slow') });
    expect(await until(() => b.calls.open.length === 1)).toBe(true);
    // The SDK abandons the call after the port-call timeout (6 000 ms of host time).
    const got = await until(() => b.messages().length === 1, 20_000);
    if (!got) console.log('DEBUG', JSON.stringify({ open: b.calls.open.length, stage: b.calls.stage.length, commit: b.calls.commit, events: b.events.map((e) => [e.kind, e.code]), insp: { ...b.receiver.inspect(), engine: null } }));
    expect(got).toBe(true);
    expect(untext(b.messages()[0].payload)).toBe('slow');
    expect(b.calls.commit).toHaveLength(1);
    expect(b.calls.stage).toHaveLength(1);
    // The MLS state stayed consistent: the next message opens too.
    await a.client.send({ recipient: bob.identity, payload: text('next') });
    expect(await until(() => b.messages().length === 2)).toBe(true);
  }, 40_000);
});
