// M3-RECEIVE-1: the durable receive state of receive-state.js with deterministic
// fake ports (C-SDK section 8.5, C-DLV sections 5.4 and 7.4). A manual clock,
// an in-memory durable port with fault injection, a scripted session port, an
// injected delivery and frames counted as the client counts them.
import { describe, test, expect } from '@jest/globals';
import { bytesToHex, bytesToBase64, utf8Encode, utf8Decode } from '../../../src/utils.js';
import { SdkResultCode } from '../../../src/sdk/index.js';
import {
  createReceiveState, readReceiveLimits, RECEIVE_SCOPE, RECEIVE_SCHEMA, RETRY_INTERVAL_MS, REDELIVERY_INTERVAL_MS,
} from '../../../src/sdk/delivery/receive-state.js';

const OWN = 'a'.repeat(64);
const PEER = 'b'.repeat(64);
const STRANGER = 'c'.repeat(64);
const RELAYS = ['ws://127.0.0.1:1', 'ws://127.0.0.1:2'];
const BASE = 's' + '0'.repeat(32);
const TIMEOUT = Symbol('timeout');
const flush = async (turns = 30) => {
  for (let i = 0; i < turns; i += 1) await new Promise((resolve) => setImmediate(resolve));
};
const id = (n) => n.toString(16).padStart(64, '0');

function manualClock(start = 1700000000000) {
  let now = start;
  let next = 1;
  const timers = new Map();
  return {
    now: () => now,
    setTimer: (callback, delay) => { const handle = next++; timers.set(handle, { at: now + delay, callback }); return handle; },
    clearTimer: (handle) => { timers.delete(handle); },
    advance(ms) {
      const end = now + ms;
      for (;;) {
        let due = null;
        for (const [handle, timer] of timers) if (timer.at <= end && (due === null || timer.at < due[1].at)) due = [handle, timer];
        if (due === null) break;
        timers.delete(due[0]);
        now = due[1].at;
        due[1].callback();
      }
      now = end;
    },
    set(ms) { now = ms; },
    pending: () => timers.size,
  };
}

/** A minimal closed-slot inspection: an out-of-set own `code` is unknown. */
function scan(value) {
  if (value === null || typeof value !== 'object') return { unknown: false, malformed: false };
  if (Object.hasOwn(value, 'code') && !Object.hasOwn(SdkResultCode, value.code)) return { unknown: true, malformed: false };
  return { unknown: false, malformed: false };
}

async function call(holder, method, args) {
  try {
    const value = await holder[method](...args);
    if (value === TIMEOUT) return { settled: 'timeout' };
    return { settled: 'value', value };
  } catch {
    return { settled: 'error' };
  }
}

/** An in-memory durable port with revision checks, resolve and fault injection. */
function fakeStore(initial = {}) {
  const disk = {
    revision: 0, seen: [], pending: [], ready: [], acknowledged: [], receiptsDue: [], cursors: [],
    resolutions: new Map(), ...structuredClone(initial),
  };
  const calls = [];
  const faults = [];
  const bytes = () => 100 + disk.pending.reduce((n, e) => n + e.ciphertext.length, 0)
    + disk.ready.reduce((n, e) => n + e.payload.length, 0) + 32 * disk.seen.length;
  const ok = () => Object.freeze({ revision: disk.revision, storedBytes: bytes() });
  function fault(method) {
    const index = faults.findIndex((f) => f.method === method);
    if (index < 0) return null;
    const found = faults[index];
    if (!found.persistent) faults.splice(index, 1);
    return found;
  }
  function write(method, argument, apply) {
    calls.push({ method, argument });
    const injected = fault(method);
    if (injected?.kind === 'throw') throw new Error('injected');
    if (injected?.kind === 'timeout') return TIMEOUT;
    if (injected?.kind === 'code') return Object.freeze({ code: injected.code });
    if (argument.revision !== disk.revision) return Object.freeze({ code: 'E_SDK_RECEIVE_STATE_CONFLICT' });
    apply();
    disk.revision += 1;
    if (injected?.kind === 'throwAfterWrite') throw new Error('injected after write');
    if (injected?.kind === 'timeoutAfterWrite') return TIMEOUT;
    return ok();
  }
  const port = {
    load(argument) {
      calls.push({ method: 'load', argument });
      const injected = fault('load');
      if (injected?.kind === 'throw') throw new Error('injected');
      if (injected?.kind === 'code') return Object.freeze({ code: injected.code });
      if (injected?.kind === 'value') return injected.value;
      return {
        schema: RECEIVE_SCHEMA, identity: argument.identity, scope: argument.scope, revision: disk.revision,
        storedBytes: bytes(),
        cursors: disk.cursors.map((c) => ({ ...c })),
        pending: disk.pending.map((e) => ({ ...e, ciphertext: new Uint8Array(e.ciphertext) })),
        ready: disk.ready.map((e) => ({ ...e, payload: new Uint8Array(e.payload) })),
        acknowledged: [...disk.acknowledged],
        receiptsDue: disk.receiptsDue.map((e) => ({ ...e })),
        seen: [...disk.seen],
      };
    },
    stage(argument) {
      return write('stage', argument, () => {
        if (disk.seen.includes(argument.event.eventId)) return;
        disk.seen.push(argument.event.eventId);
        disk.pending.push({ ...argument.event, ciphertext: new Uint8Array(argument.event.ciphertext) });
      });
    },
    commit(argument) {
      const result = write('commit', argument, () => {
        disk.pending = disk.pending.filter((e) => e.eventId !== argument.eventId);
        if (argument.result.type === 'application') {
          disk.ready.push({ eventId: argument.eventId, sender: argument.result.sender,
            payload: new Uint8Array(argument.result.payload), receiptDue: argument.result.receiptDue });
          if (argument.result.receiptDue) disk.receiptsDue.push({ eventId: argument.eventId, sender: argument.result.sender });
        }
        disk.resolutions.set(argument.operationId, { result: argument.result, revision: disk.revision + 1 });
        disk.mls = argument.ticket;
      });
      return result;
    },
    ack(argument) {
      return write('ack', argument, () => {
        disk.ready = disk.ready.filter((e) => e.eventId !== argument.eventId);
        disk.acknowledged.push(argument.eventId);
      });
    },
    receiptDone(argument) {
      return write('receiptDone', argument, () => {
        disk.receiptsDue = disk.receiptsDue.filter((e) => e.eventId !== argument.eventId);
      });
    },
    commitCursor(argument) {
      return write('commitCursor', argument, () => {
        disk.cursors = disk.cursors.filter((c) => c.relay !== argument.relay);
        disk.cursors.push({ relay: argument.relay, syncedUntil: argument.syncedUntil });
      });
    },
    resolve(argument) {
      calls.push({ method: 'resolve', argument });
      const injected = fault('resolve');
      if (injected?.kind === 'throw') throw new Error('injected');
      if (injected?.kind === 'value') return injected.value;
      const found = disk.resolutions.get(argument.operationId);
      if (found !== undefined) {
        return { status: 'committed', revision: disk.revision, storedBytes: bytes(), result: found.result };
      }
      return { status: 'aborted', revision: disk.revision };
    },
  };
  return { port, disk, calls, faults, count: (method) => calls.filter((c) => c.method === method).length };
}

/** A scripted session port: the ciphertext is the UTF-8 label of the message. */
function fakeSession() {
  const script = new Map();
  const opens = [];
  const senders = new Set([PEER]);
  let generation = 0;
  return {
    opens, senders, script,
    session: {
      openCandidate({ sender, ciphertext }) {
        const label = utf8Decode(ciphertext);
        opens.push(label);
        const plan = script.get(label);
        const step = Array.isArray(plan) ? (plan.length > 1 ? plan.shift() : plan[0]) : plan ?? 'application';
        if (step === 'throw') throw new Error('injected');
        if (step === 'timeout') return TIMEOUT;
        generation += 1;
        if (step === 'application') {
          return { receiveOutcome: 'application', plaintext: utf8Encode(`plain:${label}`), ticket: { sender, generation } };
        }
        return { receiveOutcome: step, ticket: { sender, generation } };
      },
      isKnownSender({ sender }) {
        if (senders.has('throw')) throw new Error('injected');
        return senders.has(sender);
      },
    },
  };
}

function harness({ initial = {}, limits = undefined, audience = true, clock = manualClock() } = {}) {
  const store = fakeStore(initial);
  const sess = fakeSession();
  const events = [];
  const deliveries = [];
  const signed = [];
  const published = [];
  const state = { audience, connected: 2, acceptReceipts: true, delay: false, onDispatch: null };
  const identity = {
    sign: ({ digest }) => { signed.push(bytesToHex(digest)); return new Uint8Array(64).fill(7); },
  };
  const deliver = (message, wanted) => {
    if (!state.audience) return null;
    const later = state.delay ? new Promise((resolve) => setImmediate(resolve)) : Promise.resolve();
    return later.then(() => {
      if (!wanted()) return false;
      deliveries.push({ ...message, label: utf8Decode(message.payload) });
      if (state.onDispatch) state.onDispatch(message);
      return true;
    });
  };
  const receive = createReceiveState({
    port: store.port, session: sess.session, identity, clock, publicKey: OWN, relays: RELAYS,
    limits: readReceiveLimits(limits), subscriptionBase: BASE, call, scan,
    emit: (event) => events.push(event), deliver,
  });
  const seams = {
    connected: () => state.connected,
    publish: (receipt, onAccepted) => {
      if (state.connected === 0) return false;
      published.push(receipt);
      if (state.acceptReceipts) Promise.resolve().then(onAccepted);
      return true;
    },
    drain: (receipt) => published.push({ drained: receipt }),
  };
  let seq = 0;
  function frame(relayIndex, label, { sender = PEER, receipt = false, eventId = null } = {}) {
    seq += 1;
    const event = {
      id: eventId ?? bytesToHex(utf8Encode(label.padEnd(32, '.').slice(0, 32))),
      pubkey: sender,
      tags: receipt ? [['p', OWN], ['v', 'x'], ['n', '0'.repeat(32)], ['r', '1']] : [['p', OWN], ['v', 'x'], ['n', '0'.repeat(32)]],
      content: bytesToBase64(utf8Encode(label)),
    };
    const record = { relayIndex, relay: RELAYS[relayIndex], data: ['EVENT', `${BASE}.1`, event] };
    return { record, event };
  }
  /** Count, then admit, as the client and the inbound queue do. */
  async function arrive(relayIndex, label, options) {
    const { record, event } = frame(relayIndex, label, options);
    receive.countFrame(record);
    await receive.admit(event, record);
    await flush();
    return event;
  }
  async function start({ recover = true } = {}) {
    const code = await receive.load();
    if (code !== null) return code;
    receive.wake();
    if (recover) await receive.recover();
    for (let i = 0; i < RELAYS.length; i += 1) {
      receive.poolSubscriptionId(i);
      receive.issue(i);
    }
    receive.startRunning(seams);
    await flush();
    return null;
  }
  const eose = (relayIndex) => receive.observe({ relayIndex, relay: RELAYS[relayIndex], data: ['EOSE', `${BASE}.1`] });
  return { receive, store, sess, events, deliveries, signed, published, state, clock, frame, arrive, start, eose,
    kinds: () => events.map((e) => e.kind) };
}

describe('M3-RECEIVE-1 receive state: load', () => {
  test('a valid empty snapshot loads; config.receive limits are read closed', async () => {
    const h = harness();
    expect(await h.receive.load()).toBeNull();
    expect(h.store.calls[0]).toEqual({ method: 'load', argument: { identity: OWN, scope: RECEIVE_SCOPE } });
    expect(h.receive.isLoaded()).toBe(true);
    expect(readReceiveLimits(undefined)).toEqual({ maxPending: 4096, maxUnacknowledged: 4096, maxSeen: 1048576,
      maxStoredBytes: 268435456 });
    expect(readReceiveLimits({ maxPending: 65536 })).not.toBeNull();
    for (const bad of [{ maxPending: 65537 }, { maxPending: 0 }, { other: 1 }, null, [], { maxSeen: 1.5 }]) {
      expect(readReceiveLimits(bad)).toBeNull();
    }
  });

  test.each([
    ['identity', { kind: 'value', value: { schema: RECEIVE_SCHEMA, identity: PEER, scope: RECEIVE_SCOPE, revision: 0,
      storedBytes: 0, cursors: [], pending: [], ready: [], acknowledged: [], receiptsDue: [], seen: [] } },
    'E_SDK_RECEIVE_STATE_INCOMPATIBLE'],
    ['schema', { kind: 'value', value: { schema: 'other/v9', identity: OWN, scope: RECEIVE_SCOPE, revision: 0,
      storedBytes: 0, cursors: [], pending: [], ready: [], acknowledged: [], receiptsDue: [], seen: [] } },
    'E_SDK_RECEIVE_STATE_INCOMPATIBLE'],
    ['caller-detected inconsistency', { kind: 'code', code: 'E_SDK_RECEIVE_STATE_INCOMPATIBLE' },
      'E_SDK_RECEIVE_STATE_INCOMPATIBLE'],
    ['throw', { kind: 'throw' }, 'E_SDK_RECEIVE_STATE_FAILED'],
    ['refusal', { kind: 'code', code: 'E_SDK_RECEIVE_STATE_FAILED' }, 'E_SDK_RECEIVE_STATE_FAILED'],
    ['out-of-set code', { kind: 'value', value: { code: 'E_NOT_A_CODE' } }, 'E_SDK_UNKNOWN_CODE'],
    ['pending id outside seen', { kind: 'value', value: { schema: RECEIVE_SCHEMA, identity: OWN, scope: RECEIVE_SCOPE,
      revision: 0, storedBytes: 0, cursors: [], ready: [], acknowledged: [], receiptsDue: [], seen: [],
      pending: [{ eventId: id(1), sender: PEER, ciphertext: new Uint8Array([1]), receiptRequested: false }] } },
    'E_SDK_RECEIVE_STATE_FAILED'],
    ['receipt obligation of a rejected entry', { kind: 'value', value: { schema: RECEIVE_SCHEMA, identity: OWN,
      scope: RECEIVE_SCOPE, revision: 0, storedBytes: 0, cursors: [], pending: [], ready: [], acknowledged: [],
      receiptsDue: [{ eventId: id(1), sender: PEER }], seen: [id(1)] } }, 'E_SDK_RECEIVE_STATE_FAILED'],
    ['extra key', { kind: 'value', value: { schema: RECEIVE_SCHEMA, identity: OWN, scope: RECEIVE_SCOPE, revision: 0,
      storedBytes: 0, cursors: [], pending: [], ready: [], acknowledged: [], receiptsDue: [], seen: [], more: 1 } },
    'E_SDK_RECEIVE_STATE_FAILED'],
  ])('load %s fails with its code and nothing is reset', async (_name, fault, code) => {
    const h = harness();
    h.store.faults.push({ method: 'load', ...fault });
    expect(await h.receive.load()).toBe(code);
    expect(h.receive.isLoaded()).toBe(false);
    expect(h.store.calls.map((c) => c.method)).toEqual(['load']);
  });
});

describe('M3-RECEIVE-1 receive state: admission, open and commit', () => {
  test('stage -> openCandidate -> commit -> READY emitted with eventId; no second stage for a copy', async () => {
    const h = harness();
    await h.start();
    const event = await h.arrive(0, 'm1');
    expect(h.store.calls.map((c) => c.method)).toEqual(['load', 'stage', 'commit']);
    expect(h.store.calls[1].argument.event).toEqual({ eventId: event.id, sender: PEER,
      ciphertext: utf8Encode('m1'), receiptRequested: false });
    expect(h.store.calls[1].argument.operationId).toMatch(/^[0-9a-f]{32}$/);
    expect(h.store.calls[2].argument.result).toEqual({ type: 'application', sender: PEER,
      payload: utf8Encode('plain:m1'), receiptDue: false });
    expect(h.deliveries.map((d) => [d.eventId, d.label])).toEqual([[event.id, 'plain:m1']]);
    await h.arrive(1, 'm1');
    expect(h.store.count('stage')).toBe(1);
    expect(h.sess.opens).toEqual(['m1']);
    const ids = new Set(h.store.calls.filter((c) => c.argument?.operationId).map((c) => c.argument.operationId));
    expect(ids.size).toBe(h.store.calls.length - 1);
  });

  test('criterion 6: an unknown sender is not staged, opened or remembered; a later replay is admitted', async () => {
    const h = harness();
    await h.start();
    await h.arrive(0, 'early', { sender: STRANGER });
    expect(h.store.count('stage')).toBe(0);
    expect(h.sess.opens).toEqual([]);
    for (let i = 0; i < 200; i += 1) await h.arrive(0, `flood-${i}`, { sender: 'd'.repeat(64) });
    expect(h.store.calls.map((c) => c.method)).toEqual(['load']);
    h.sess.senders.add(STRANGER);
    await h.arrive(1, 'early', { sender: STRANGER });
    expect(h.deliveries.map((d) => d.label)).toEqual(['plain:early']);
  });

  test('a failed isKnownSender is not non-admission: nothing staged and the barrier fails', async () => {
    const h = harness();
    await h.start();
    h.sess.senders.add('throw');
    await h.arrive(0, 'x');
    h.eose(0);
    await flush();
    expect(h.store.count('stage')).toBe(0);
    expect(h.store.count('commitCursor')).toBe(0);
  });

  test('a committed rejection is REJECTED: tombstone, no payload, no receipt, never emitted', async () => {
    const h = harness();
    await h.start();
    h.sess.script.set('bad', 'reject');
    const event = await h.arrive(0, 'bad', { receipt: true });
    expect(h.store.calls.at(-1).argument.result).toEqual({ type: 'rejected' });
    expect(h.deliveries).toEqual([]);
    expect(h.kinds()).toEqual(['INBOUND_DISCARDED']);
    expect(h.store.disk.receiptsDue).toEqual([]);
    expect(await h.receive.acknowledge(event.id)).toBe('E_SDK_UNKNOWN_MESSAGE');
    await h.arrive(1, 'bad', { receipt: true });
    expect(h.sess.opens).toEqual(['bad']);
  });

  test('without an audience: open and commit still happen, nothing emitted, ack refused until invocation', async () => {
    const h = harness({ audience: false });
    await h.start();
    const event = await h.arrive(0, 'quiet', { receipt: true });
    expect(h.store.calls.map((c) => c.method)).toEqual(['load', 'stage', 'commit']);
    expect(h.deliveries).toEqual([]);
    expect(h.published).toEqual([]);
    expect(await h.receive.acknowledge(event.id)).toBe('E_SDK_UNKNOWN_MESSAGE');
    h.state.audience = true;
    h.receive.wake();
    await flush();
    expect(h.deliveries.map((d) => d.label)).toEqual(['plain:quiet']);
    expect(h.published).toHaveLength(1);
    expect(h.published[0].tags.slice(0, 2)).toEqual([['p', PEER], ['e', event.id]]);
    expect(await h.receive.acknowledge(event.id)).toBeNull();
    expect(await h.receive.acknowledge(event.id)).toBeNull();
    expect(h.store.count('ack')).toBe(1);
    expect(h.store.count('receiptDone')).toBe(1);
  });
});

describe('M3-RECEIVE-1 receive state: H17 retries (criterion 13)', () => {
  test('(a) a retry, then a copy from a second relay: retried at once, delivered once, no second stage', async () => {
    const h = harness();
    await h.start();
    h.sess.script.set('h17', ['retry', 'application']);
    await h.arrive(0, 'h17');
    expect(h.deliveries).toEqual([]);
    expect(h.store.disk.pending).toHaveLength(1);
    await h.arrive(1, 'h17');
    expect(h.sess.opens).toEqual(['h17', 'h17']);
    expect(h.deliveries.map((d) => d.label)).toEqual(['plain:h17']);
    expect(h.store.count('stage')).toBe(1);
  });

  test('(b) without any copy: retried by the first periodic pass; eligibility apart from a slow delivery', async () => {
    const h = harness();
    await h.start();
    h.sess.script.set('slow', ['retry', 'application']);
    await h.arrive(0, 'slow');
    expect(h.sess.opens).toEqual(['slow']);
    h.clock.advance(RETRY_INTERVAL_MS - 1);
    await flush();
    expect(h.sess.opens).toEqual(['slow']);
    h.clock.advance(1);
    await flush();
    expect(h.sess.opens).toEqual(['slow', 'slow']);
    expect(h.deliveries.map((d) => d.label)).toEqual(['plain:slow']);
  });

  test('(b) with a backlog of slow opens: every eligible entry is queued at the pass, delivery follows later', async () => {
    const h = harness();
    await h.start();
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    for (let i = 0; i < 5; i += 1) h.sess.script.set(`b${i}`, ['retry', 'application']);
    for (let i = 0; i < 5; i += 1) await h.arrive(0, `b${i}`);
    expect(h.sess.opens).toHaveLength(5);
    const original = h.sess.session.openCandidate;
    h.sess.session.openCandidate = async (argument) => { await gate; return original(argument); };
    h.clock.advance(RETRY_INTERVAL_MS);
    await flush();
    expect(h.deliveries).toEqual([]);
    release();
    await flush(80);
    expect(h.deliveries.map((d) => d.label)).toEqual(['plain:b0', 'plain:b1', 'plain:b2', 'plain:b3', 'plain:b4']);
  });

  test('(d) many copies after the first in-run retry: no further openCandidate before the budget renews', async () => {
    const h = harness();
    await h.start();
    h.sess.script.set('many', ['retry', 'retry', 'retry', 'application']);
    await h.arrive(0, 'many');
    await h.arrive(1, 'many');
    expect(h.sess.opens).toHaveLength(2);
    for (let i = 0; i < 20; i += 1) await h.arrive(i % 2, 'many');
    h.clock.advance(RETRY_INTERVAL_MS - 1);
    for (let i = 0; i < 20; i += 1) await h.arrive(i % 2, 'many');
    expect(h.sess.opens).toHaveLength(2);
    h.clock.advance(1);
    await flush();
    expect(h.sess.opens).toHaveLength(3);
    await h.arrive(0, 'many');
    expect(h.sess.opens).toHaveLength(3);
  });

  test('(c) a copy of a READY or acknowledged id is dropped without openCandidate', async () => {
    const h = harness();
    await h.start();
    const event = await h.arrive(0, 'done');
    await h.arrive(1, 'done');
    expect(await h.receive.acknowledge(event.id)).toBeNull();
    await h.arrive(1, 'done');
    expect(h.sess.opens).toEqual(['done']);
  });

  test('failed and timed-out openCandidate, malformed and out-of-set results are retry; the entry stays PENDING', async () => {
    const h = harness();
    await h.start();
    h.sess.script.set('f1', ['throw', 'timeout', 'application']);
    await h.arrive(0, 'f1');
    await h.arrive(1, 'f1');
    expect(h.store.disk.pending).toHaveLength(1);
    h.clock.advance(RETRY_INTERVAL_MS);
    await flush();
    expect(h.deliveries.map((d) => d.label)).toEqual(['plain:f1']);
    const original = h.sess.session.openCandidate;
    h.sess.session.openCandidate = () => ({ receiveOutcome: 'ACCEPTED', ticket: 1 });
    await h.arrive(0, 'f2');
    h.sess.session.openCandidate = () => ({ receiveOutcome: 'application', ticket: 1 });
    await h.arrive(1, 'f2');
    // An out-of-set receiveOutcome is an unknown closed value (one discard), then retry.
    expect(h.events).toEqual([{ kind: 'INBOUND_DISCARDED', code: 'E_SDK_UNKNOWN_CODE' }]);
    h.sess.session.openCandidate = () => ({ code: 'E_OUT_OF_SET' });
    h.clock.advance(RETRY_INTERVAL_MS);
    await flush();
    expect(h.events).toEqual([{ kind: 'INBOUND_DISCARDED', code: 'E_SDK_UNKNOWN_CODE' },
      { kind: 'INBOUND_DISCARDED', code: 'E_SDK_UNKNOWN_CODE' }]);
    expect(h.store.disk.pending).toHaveLength(1);
    h.sess.session.openCandidate = original;
    h.clock.advance(RETRY_INTERVAL_MS);
    await flush();
    expect(h.deliveries.map((d) => d.label)).toEqual(['plain:f1', 'plain:f2']);
    expect(h.store.count('stage')).toBe(2);
  });

  test('fairness: the open unit alternates between a backlog retry and a newly staged entry', async () => {
    const h = harness();
    await h.start();
    let release;
    let hold = new Promise((resolve) => { release = resolve; });
    const original = h.sess.session.openCandidate;
    h.sess.session.openCandidate = async (argument) => { await hold; return original(argument); };
    for (let i = 0; i < 3; i += 1) h.sess.script.set(`old${i}`, ['retry', 'application']);
    const arrivals = [];
    for (let i = 0; i < 3; i += 1) arrivals.push(h.arrive(0, `old${i}`));
    release();
    await Promise.all(arrivals);
    await flush();
    hold = new Promise((resolve) => { release = resolve; });
    h.clock.advance(RETRY_INTERVAL_MS);
    for (let i = 0; i < 3; i += 1) arrivals.push(h.arrive(1, `new${i}`));
    await flush();
    release();
    await Promise.all(arrivals);
    await flush(80);
    expect(h.sess.opens.slice(3)).toEqual(['old0', 'new0', 'old1', 'new1', 'old2', 'new2']);
  });
});

describe('M3-RECEIVE-1 receive state: commit failures and fail-stop', () => {
  test('capacity refusal keeps PENDING and the previous state, reports once, stops admission, deletes nothing', async () => {
    const h = harness();
    await h.start();
    h.store.faults.push({ method: 'commit', kind: 'code', code: 'E_SDK_RECEIVE_STATE_CAPACITY' });
    await h.arrive(0, 'cap');
    expect(h.kinds()).toEqual(['RECEIVE_STATE_CAPACITY']);
    expect(h.events[0]).toEqual({ kind: 'RECEIVE_STATE_CAPACITY', scope: RECEIVE_SCOPE });
    expect(h.store.disk.pending).toHaveLength(1);
    await h.arrive(0, 'cap2');
    expect(h.store.count('stage')).toBe(1);
    expect(h.kinds()).toEqual(['RECEIVE_STATE_CAPACITY']);
    h.clock.advance(RETRY_INTERVAL_MS);
    await flush();
    expect(h.deliveries.map((d) => d.label)).toEqual(['plain:cap']);
  });

  test.each(['E_SDK_RECEIVE_STATE_FAILED', 'E_SDK_RECEIVE_STATE_CONFLICT'])(
    'a definite commit failure %s freezes admission, cursors and provider mutations', async (code) => {
      const h = harness();
      await h.start();
      h.store.faults.push({ method: 'commit', kind: 'code', code });
      await h.arrive(0, 'x1');
      expect(h.events).toEqual([{ kind: 'RECEIVE_STATE_FAILED', code }]);
      expect(h.receive.blocked()).toBe(true);
      await h.arrive(0, 'x2');
      h.eose(0);
      h.clock.advance(RETRY_INTERVAL_MS * 3);
      await flush();
      expect(h.store.calls.map((c) => c.method)).toEqual(['load', 'stage', 'commit']);
      expect(h.store.disk.pending).toHaveLength(1);
      expect(h.events).toHaveLength(1);
    });

  test.each([
    ['committed', 'throwAfterWrite', null, ['plain:u1']],
    ['aborted', 'throw', null, []],
    ['failed resolve, then committed', 'timeoutAfterWrite', { kind: 'throw' }, ['plain:u1']],
  ])('an uncertain commit pauses until resolve answers: %s', async (_name, kind, resolveFault, delivered) => {
    const h = harness();
    await h.start();
    h.store.faults.push({ method: 'commit', kind });
    if (resolveFault !== null) h.store.faults.push({ method: 'resolve', ...resolveFault });
    await h.arrive(0, 'u1');
    expect(h.events[0]).toEqual({ kind: 'RECEIVE_STATE_FAILED', code: 'E_SDK_RECEIVE_STATE_FAILED' });
    const resolveCall = h.store.calls.find((c) => c.method === 'resolve');
    expect(resolveCall.argument).toEqual({ operationId: h.store.calls.find((c) => c.method === 'commit').argument.operationId });
    if (resolveFault !== null) {
      expect(h.receive.blocked()).toBe(true);
      await h.arrive(1, 'u2');
      expect(h.store.count('stage')).toBe(1);
      h.clock.advance(RETRY_INTERVAL_MS);
      await flush();
    }
    expect(h.receive.blocked()).toBe(false);
    expect(h.deliveries.map((d) => d.label)).toEqual(delivered);
    if (delivered.length === 0) {
      expect(h.store.disk.pending).toHaveLength(1);
      h.clock.advance(RETRY_INTERVAL_MS);
      await flush();
      expect(h.deliveries.map((d) => d.label)).toEqual(['plain:u1']);
    }
    expect(h.store.count('commit')).toBe(delivered.length === 0 ? 2 : 1);
  });

  test('a resolve that reports a different result is a failed resolve: the client stays paused', async () => {
    const h = harness();
    await h.start();
    h.store.faults.push({ method: 'commit', kind: 'timeout' });
    h.store.faults.push({ method: 'resolve', kind: 'value', persistent: true,
      value: { status: 'committed', revision: 1, storedBytes: 1, result: { type: 'rejected' } } });
    await h.arrive(0, 'odd');
    h.clock.advance(RETRY_INTERVAL_MS * 2);
    await flush();
    expect(h.receive.blocked()).toBe(true);
    expect(h.deliveries).toEqual([]);
    expect(h.store.count('resolve')).toBe(3);
  });

  test('a failed stage freezes; a failed ack freezes and reports; the 0.3.1 path is never used', async () => {
    const h = harness();
    await h.start();
    const event = await h.arrive(0, 'k1');
    h.store.faults.push({ method: 'ack', kind: 'throw' });
    expect(await h.receive.acknowledge(event.id)).toBe('E_SDK_RECEIVE_STATE_FAILED');
    expect(h.events).toEqual([{ kind: 'RECEIVE_STATE_FAILED', code: 'E_SDK_RECEIVE_STATE_FAILED' }]);
    expect(await h.receive.acknowledge(event.id)).toBe('E_SDK_RECEIVE_STATE_FAILED');
    await h.arrive(1, 'k2');
    expect(h.sess.opens).toEqual(['k1']);
    const g = harness();
    await g.start();
    g.store.faults.push({ method: 'stage', kind: 'timeout' });
    await g.arrive(0, 'k3');
    expect(g.receive.blocked()).toBe(true);
    expect(g.sess.opens).toEqual([]);
  });
});

describe('M3-RECEIVE-1 receive state: quotas', () => {
  test('pending quota reached: capacity once, nothing deleted, cursor blocked; ack of READY frees unacknowledged', async () => {
    const h = harness({ limits: { maxPending: 2, maxUnacknowledged: 2 } });
    await h.start();
    h.sess.script.set('p1', 'retry');
    h.sess.script.set('p2', 'retry');
    await h.arrive(0, 'p1');
    await h.arrive(0, 'p2');
    expect(h.kinds()).toEqual(['RECEIVE_STATE_CAPACITY']);
    await h.arrive(0, 'p3');
    expect(h.store.count('stage')).toBe(2);
    h.eose(0);
    await flush();
    expect(h.store.count('commitCursor')).toBe(0);
    expect(h.kinds()).toEqual(['RECEIVE_STATE_CAPACITY']);
  });

  test('maxStoredBytes reached through READY entries; an ack frees it and a later replay is admitted', async () => {
    // The fake store counts 100 + 32 per seen id + ciphertext and payload bytes.
    const h = harness({ limits: { maxStoredBytes: 150 } });
    await h.start();
    const first = await h.arrive(0, 'aaaaaaaaaaaaaaaaaaaa');
    await h.arrive(0, 'bbbb');
    expect(h.kinds()).toEqual(['RECEIVE_STATE_CAPACITY']);
    expect(h.store.count('stage')).toBe(1);
    expect(await h.receive.acknowledge(first.id)).toBeNull();
    await h.arrive(1, 'bbbb');
    expect(h.store.count('stage')).toBe(2);
    expect(h.deliveries.map((d) => d.label)).toEqual(['plain:aaaaaaaaaaaaaaaaaaaa', 'plain:bbbb']);
  });

  test('10 000 valid events from unknown keys leave durable state unchanged and are never opened', async () => {
    const h = harness();
    await h.start();
    for (let i = 0; i < 10000; i += 1) {
      const { record, event } = h.frame(i % 2, `u${i}`, { sender: 'e'.repeat(64) });
      h.receive.countFrame(record);
      await h.receive.admit(event, record);
    }
    expect(h.store.calls.map((c) => c.method)).toEqual(['load']);
    expect(h.sess.opens).toEqual([]);
  });
});

describe('M3-RECEIVE-1 receive state: cursors and barrier (criteria 4, 5, 8, 11)', () => {
  test('EOSE after every counted frame is staged commits the issue time; never from created_at', async () => {
    const h = harness();
    h.clock.set(1800000000500);
    await h.start();
    await h.arrive(0, 'c1');
    h.eose(0);
    await flush();
    expect(h.store.calls.filter((c) => c.method === 'commitCursor').map((c) => c.argument))
      .toEqual([expect.objectContaining({ relay: RELAYS[0], generation: 1, syncedUntil: 1800000000 })]);
    h.clock.advance(5000);
    expect(h.receive.issue(0)).toBe(1800000000 - 120);
  });

  test('slow stage: the EOSE waits for the stage; a failed stage blocks the cursor', async () => {
    const h = harness();
    await h.start();
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    const stage = h.store.port.stage;
    h.store.port.stage = async (argument) => { await gate; return stage(argument); };
    const { record, event } = h.frame(0, 'slow');
    h.receive.countFrame(record);
    const admitted = h.receive.admit(event, record);
    h.eose(0);
    await flush();
    expect(h.store.count('commitCursor')).toBe(0);
    release();
    await admitted;
    await flush();
    expect(h.store.count('commitCursor')).toBe(1);
  });

  test('cross-relay duplicate while the first stage is pending: one stage, both relays accounted', async () => {
    const h = harness();
    await h.start();
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    const stage = h.store.port.stage;
    h.store.port.stage = async (argument) => { await gate; return stage(argument); };
    const one = h.frame(0, 'dup');
    const two = h.frame(1, 'dup');
    h.receive.countFrame(one.record);
    h.receive.countFrame(two.record);
    const first = h.receive.admit(one.event, one.record);
    const second = h.receive.admit(two.event, two.record);
    h.eose(0);
    h.eose(1);
    release();
    await Promise.all([first, second]);
    await flush();
    expect(h.store.count('stage')).toBe(1);
    expect(h.store.count('commitCursor')).toBe(2);
  });

  test('queue drop in generation N, clean EOSE in N+1 without the id: no cursor passes it until accounted', async () => {
    const h = harness();
    await h.start();
    const lost = h.frame(0, 'lost');
    h.receive.countFrame(lost.record);
    h.receive.account(lost.record, 'dropped');
    h.eose(0);
    await flush();
    h.receive.issue(0);
    h.eose(0);
    await flush();
    expect(h.store.count('commitCursor')).toBe(0);
    await h.arrive(1, 'lost');
    h.receive.issue(0);
    h.eose(0);
    await flush();
    expect(h.store.calls.filter((c) => c.method === 'commitCursor').map((c) => c.argument.relay)).toEqual([RELAYS[0]]);
  });

  test('an unidentifiable drop blocks the relay for the run; the other relay still commits', async () => {
    const h = harness();
    await h.start();
    const garbage = { relayIndex: 0, relay: RELAYS[0], data: ['EVENT', `${BASE}.1`, { id: 'nope' }] };
    h.receive.countFrame(garbage);
    h.receive.account(garbage, 'dropped');
    h.eose(0);
    h.eose(1);
    await flush();
    expect(h.store.calls.filter((c) => c.method === 'commitCursor').map((c) => c.argument.relay)).toEqual([RELAYS[1]]);
  });

  test('late EOSE of an older pool or with another subscription id has no effect; pool replacement starts a new generation', async () => {
    const h = harness();
    await h.start();
    expect(h.receive.poolSubscriptionId(0)).toBe(`${BASE}.2`);
    h.receive.observe({ relayIndex: 0, relay: RELAYS[0], data: ['EOSE', `${BASE}.1`] });
    await flush();
    expect(h.store.count('commitCursor')).toBe(0);
    h.receive.issue(0);
    h.receive.observe({ relayIndex: 0, relay: RELAYS[0], data: ['EOSE', `${BASE}.2`] });
    await flush();
    expect(h.store.calls.find((c) => c.method === 'commitCursor').argument.generation).toBe(2);
  });

  test('re-requests on one pool: an EOSE commits at most the earliest outstanding issue time', async () => {
    const h = harness();
    h.clock.set(1800000000000);
    await h.start();
    h.clock.advance(10000);
    h.receive.issue(0);
    h.eose(0);
    await flush();
    expect(h.store.calls.find((c) => c.method === 'commitCursor').argument.syncedUntil).toBe(1800000000);
    h.eose(0);
    await flush();
    expect(h.store.count('commitCursor')).toBe(1);
  });

  test('criterion 8: future cursor loaded or committed is absent at every request, not reused, skew once per relay', async () => {
    const clock = manualClock(1800000000000);
    const h = harness({ clock, initial: { cursors: [{ relay: RELAYS[0], syncedUntil: 1900000000 },
      { relay: 'ws://127.0.0.1:9', syncedUntil: 1 }] } });
    await h.start();
    expect(h.events).toEqual([{ kind: 'RECEIVE_STATE_CLOCK_SKEW', scope: RECEIVE_SCOPE, relay: RELAYS[0] }]);
    clock.set(1950000000000);
    expect(h.receive.since(0)).toBeNull();
    expect(h.receive.issue(0)).toBeNull();
    h.eose(0);
    await flush();
    const committed = h.store.calls.find((c) => c.method === 'commitCursor').argument;
    expect(committed.syncedUntil).toBe(1800000000);
    expect(h.receive.issue(0)).toBe(1800000000 - 120);
    clock.set(1700000000000);
    expect(h.receive.issue(0)).toBeNull();
    expect(h.receive.issue(0)).toBeNull();
    h.eose(0);
    await flush();
    expect(h.store.calls.filter((c) => c.method === 'commitCursor').at(-1).argument.syncedUntil).toBe(1700000000);
    expect(h.kinds().filter((k) => k === 'RECEIVE_STATE_CLOCK_SKEW')).toHaveLength(1);
    expect(h.receive.issue(1)).toBeNull();
  });

  test('criterion 4 (Bob): cursor of a request issued at 09:55:00, restart at 10:10, first since is 09:53:00', async () => {
    const at = (h, m) => Date.UTC(2026, 10, 4, h, m) ;
    const clock = manualClock(at(9, 55));
    const h = harness({ clock });
    await h.start();
    h.eose(0);
    await flush();
    clock.set(at(10, 10));
    const restarted = harness({ clock, initial: { ...h.store.disk, resolutions: new Map() } });
    expect(await restarted.receive.load()).toBeNull();
    restarted.receive.poolSubscriptionId(0);
    expect(restarted.receive.issue(0)).toBe(at(9, 53) / 1000);
  });

  test('criterion 11: an invitation active blocks cursors of requests issued before it ended', async () => {
    const h = harness();
    await h.start();
    h.receive.invitationStarted();
    h.eose(0);
    await flush();
    h.receive.invitationEnded();
    // An EOSE after the end still covers the request issued before it: none.
    h.receive.issue(1);
    h.eose(1);
    await flush();
    expect(h.store.count('commitCursor')).toBe(0);
    // The next generation, issued after the end, replays from the pre-operation cursor and commits.
    expect(h.receive.issue(1)).toBeNull();
    h.eose(1);
    expect(h.receive.issue(0)).toBeNull();
    h.eose(0);
    await flush();
    expect(h.store.calls.filter((c) => c.method === 'commitCursor').map((c) => c.argument.relay)).toEqual([RELAYS[1], RELAYS[0]]);
  });
});

describe('M3-RECEIVE-1 receive state: redelivery, acknowledgement and receipts (criterion 10)', () => {
  test('a listener that throws and does not acknowledge receives the entry again by the 60 s pass', async () => {
    const h = harness();
    await h.start();
    await h.arrive(0, 'again');
    expect(h.deliveries).toHaveLength(1);
    h.clock.advance(REDELIVERY_INTERVAL_MS);
    await flush();
    expect(h.deliveries.map((d) => d.label)).toEqual(['plain:again', 'plain:again']);
  });

  test('an ack concurrent with an already scheduled redelivery: the dispatch sees it and delivers nothing', async () => {
    const h = harness();
    await h.start();
    const event = await h.arrive(0, 'scheduled');
    h.state.delay = true;
    h.receive.wake();
    expect(await h.receive.acknowledge(event.id)).toBeNull();
    await flush();
    expect(h.deliveries.map((d) => d.label)).toEqual(['plain:scheduled']);
    h.state.delay = false;
    h.clock.advance(REDELIVERY_INTERVAL_MS);
    h.receive.wake();
    await flush();
    expect(h.deliveries).toHaveLength(1);
  });

  test('an ack called inside the listener completes; the delivery in progress keeps its audience; none later', async () => {
    const h = harness();
    await h.start();
    const results = [];
    h.state.onDispatch = (message) => { results.push(h.receive.acknowledge(message.eventId)); };
    await h.arrive(0, 'inside');
    expect(await Promise.all(results)).toEqual([null]);
    expect(h.deliveries.map((d) => d.label)).toEqual(['plain:inside']);
    h.state.onDispatch = null;
    h.clock.advance(REDELIVERY_INTERVAL_MS);
    h.receive.wake();
    await flush();
    expect(h.deliveries).toHaveLength(1);
    expect(h.store.count('ack')).toBe(1);
  });

  test('receipt: deferred without a connected relay, published after a later connection, receiptDone after OK true', async () => {
    const h = harness();
    await h.start();
    h.state.connected = 0;
    const event = await h.arrive(0, 'rcpt', { receipt: true });
    expect(h.published).toEqual([]);
    expect(h.signed).toEqual([]);
    h.state.connected = 1;
    h.receive.relayConnected();
    await flush();
    expect(h.published).toHaveLength(1);
    expect(h.store.disk.receiptsDue).toEqual([]);
    h.receive.relayConnected();
    h.receive.wake();
    await flush();
    expect(h.published).toHaveLength(1);
    expect(event.id).toBe(h.published[0].tags[1][1]);
  });

  test('without OK true the obligation stays durable; after restart an acknowledged entry\'s receipt is published', async () => {
    const h = harness();
    await h.start();
    h.state.acceptReceipts = false;
    const event = await h.arrive(0, 'later', { receipt: true });
    expect(await h.receive.acknowledge(event.id)).toBeNull();
    expect(h.published).toHaveLength(1);
    expect(h.store.disk.receiptsDue).toEqual([{ eventId: event.id, sender: PEER }]);
    const restarted = harness({ initial: { ...h.store.disk, resolutions: new Map() } });
    await restarted.start();
    expect(restarted.published).toHaveLength(1);
    expect(restarted.deliveries).toEqual([]);
    expect(restarted.store.disk.receiptsDue).toEqual([]);
  });

  test('after restart a READY entry is redelivered and its receipt waits for the invocation', async () => {
    const h = harness({ audience: false });
    await h.start();
    const event = await h.arrive(0, 'kept', { receipt: true });
    const restarted = harness({ audience: false, initial: { ...h.store.disk, resolutions: new Map() } });
    await restarted.start();
    expect(restarted.published).toEqual([]);
    expect(await restarted.receive.acknowledge(event.id)).toBe('E_SDK_UNKNOWN_MESSAGE');
    restarted.state.audience = true;
    restarted.receive.wake();
    await flush();
    expect(restarted.deliveries.map((d) => d.eventId)).toEqual([event.id]);
    expect(restarted.published).toHaveLength(1);
    expect(await restarted.receive.acknowledge(event.id)).toBeNull();
  });

  test('recovery pass at start retries PENDING entries once, in stage order, before relays', async () => {
    const h = harness();
    await h.start();
    h.sess.script.set('r1', 'retry');
    h.sess.script.set('r2', 'retry');
    await h.arrive(0, 'r1');
    await h.arrive(0, 'r2');
    const restarted = harness({ initial: { ...h.store.disk, resolutions: new Map() } });
    expect(await restarted.receive.load()).toBeNull();
    await restarted.receive.recover();
    expect(restarted.sess.opens).toEqual(['r1', 'r2']);
    expect(restarted.deliveries.map((d) => d.label)).toEqual(['plain:r1', 'plain:r2']);
    expect(restarted.store.disk.pending).toEqual([]);
  });

  test('stop: no admission, candidate, pass or receipt starts; an open in flight is not committed', async () => {
    const h = harness();
    await h.start();
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    const original = h.sess.session.openCandidate;
    h.sess.session.openCandidate = async (argument) => { await gate; return original(argument); };
    const arrival = h.arrive(0, 'late');
    await flush();
    h.receive.stop();
    release();
    await arrival;
    await h.receive.settled();
    h.receive.dispose();
    expect(h.store.count('commit')).toBe(0);
    expect(h.store.disk.pending).toHaveLength(1);
    expect(h.clock.pending()).toBe(0);
  });
});

describe('M3-RECEIVE-1 receive state: closed edges', () => {
  test('resolve aborted may carry storedBytes; the client resumes and the entry is delivered later', async () => {
    const h = harness();
    await h.start();
    h.store.faults.push({ method: 'commit', kind: 'throw' });
    h.store.faults.push({ method: 'resolve', kind: 'value', value: { status: 'aborted', revision: 1, storedBytes: 200 } });
    await h.arrive(0, 'ab');
    expect(h.receive.blocked()).toBe(false);
    h.clock.advance(RETRY_INTERVAL_MS);
    await flush();
    expect(h.deliveries.map((d) => d.label)).toEqual(['plain:ab']);
  });

  test('an EVENT frame shorter than three elements is not counted and does not hold the cursor', async () => {
    const h = harness();
    await h.start();
    h.receive.countFrame({ relayIndex: 0, relay: RELAYS[0], data: ['EVENT', `${BASE}.1`] });
    h.eose(0);
    await flush();
    expect(h.store.count('commitCursor')).toBe(1);
  });

  test('an acknowledgement after stop writes nothing', async () => {
    const h = harness();
    await h.start();
    const event = await h.arrive(0, 'late-ack');
    h.receive.stop();
    expect(await h.receive.acknowledge(event.id)).toBe('E_SDK_CLIENT_STOPPED');
    expect(h.store.count('ack')).toBe(0);
  });
});

describe('M3-RECEIVE-1 receive state: review round 1', () => {
  test('a commitCursor queued behind another write is not written once an invitation started meanwhile', async () => {
    const h = harness();
    await h.start();
    const event = await h.arrive(0, 'hold');
    let release;
    const ack = h.store.port.ack;
    h.store.port.ack = async (argument) => { await new Promise((resolve) => { release = resolve; }); return ack(argument); };
    const acking = h.receive.acknowledge(event.id);
    await flush();
    h.eose(0);
    await flush();
    h.receive.invitationStarted();
    release();
    expect(await acking).toBeNull();
    await flush();
    expect(h.store.count('commitCursor')).toBe(0);
    h.receive.invitationEnded();
    h.receive.issue(0);
    h.eose(0);
    await flush();
    expect(h.store.count('commitCursor')).toBe(1);
  });

  test('a commitCursor queued behind another write is not written after a drop accounted meanwhile', async () => {
    const h = harness();
    await h.start();
    const event = await h.arrive(0, 'hold2');
    let release;
    const ack = h.store.port.ack;
    h.store.port.ack = async (argument) => { await new Promise((resolve) => { release = resolve; }); return ack(argument); };
    const acking = h.receive.acknowledge(event.id);
    await flush();
    h.eose(0);
    await flush();
    const lost = h.frame(0, 'lost-meanwhile');
    h.receive.countFrame(lost.record);
    h.receive.account(lost.record, 'dropped');
    release();
    await acking;
    await flush();
    expect(h.store.count('commitCursor')).toBe(0);
  });

  test('a capacity refusal is lifted by a later successful commit, also a rejection', async () => {
    const h = harness();
    await h.start();
    h.store.faults.push({ method: 'commit', kind: 'code', code: 'E_SDK_RECEIVE_STATE_CAPACITY' });
    h.sess.script.set('bad', 'reject');
    await h.arrive(0, 'bad');
    expect(h.kinds()).toEqual(['RECEIVE_STATE_CAPACITY']);
    h.clock.advance(RETRY_INTERVAL_MS);
    await flush();
    expect(h.store.disk.pending).toEqual([]);
    await h.arrive(0, 'after');
    expect(h.deliveries.map((d) => d.label)).toEqual(['plain:after']);
  });

  test('a commit queued behind another write does not start after stop; the entry stays PENDING', async () => {
    const h = harness();
    await h.start();
    const event = await h.arrive(0, 'first');
    // Hold the open of 'second' after its stage completed.
    let releaseOpen;
    const open = h.sess.session.openCandidate;
    h.sess.session.openCandidate = async (argument) => {
      await new Promise((resolve) => { releaseOpen = resolve; });
      return open(argument);
    };
    const second = h.frame(1, 'second');
    h.receive.countFrame(second.record);
    const admitted = h.receive.admit(second.event, second.record);
    await flush();
    expect(h.store.count('stage')).toBe(2);
    expect(typeof releaseOpen).toBe('function');
    // Hold an ack in the write chain, then let the open finish: its commit queues behind the ack.
    let releaseAck;
    const ack = h.store.port.ack;
    h.store.port.ack = async (argument) => { await new Promise((resolve) => { releaseAck = resolve; }); return ack(argument); };
    const acking = h.receive.acknowledge(event.id);
    await flush();
    releaseOpen();
    await flush();
    h.receive.stop();
    releaseAck();
    await acking;
    await admitted;
    await flush();
    expect(h.store.count('commit')).toBe(1);
    expect(h.store.disk.pending.map((e) => utf8Decode(e.ciphertext))).toEqual(['second']);
  });

  test('H17 13(b) with many slow messages: retried within one interval is separate from delivered', async () => {
    const h = harness();
    await h.start();
    for (let i = 0; i < 5; i += 1) h.sess.script.set(`s${i}`, ['retry', 'application']);
    for (let i = 0; i < 5; i += 1) await h.arrive(0, `s${i}`);
    h.state.audience = false;
    h.clock.advance(RETRY_INTERVAL_MS);
    await flush(80);
    // Every entry was retried and committed within the interval; nothing delivered yet.
    expect(h.sess.opens).toHaveLength(10);
    expect(h.store.count('commit')).toBe(5);
    expect(h.deliveries).toEqual([]);
    h.state.audience = true;
    h.receive.wake();
    await flush(80);
    expect(h.deliveries.map((d) => d.label)).toEqual(['plain:s0', 'plain:s1', 'plain:s2', 'plain:s3', 'plain:s4']);
  });

  test('a receiptDone that brings storedBytes below the limit re-arms the capacity event', async () => {
    const h = harness({ limits: { maxStoredBytes: 150 } });
    await h.start();
    const receiptDone = h.store.port.receiptDone;
    h.store.port.receiptDone = (argument) => {
      const value = receiptDone(argument);
      return value?.revision === undefined ? value : Object.freeze({ revision: value.revision, storedBytes: 0 });
    };
    await h.arrive(0, 'aaaaaaaaaaaaaaaaaaaa', { receipt: true });
    expect(h.kinds().filter((k) => k === 'RECEIVE_STATE_CAPACITY')).toHaveLength(1);
    expect(h.store.count('receiptDone')).toBe(1);
    await h.arrive(0, 'bbbbbbbbbbbbbbbbbbbb');
    expect(h.kinds().filter((k) => k === 'RECEIVE_STATE_CAPACITY')).toHaveLength(2);
  });
});
