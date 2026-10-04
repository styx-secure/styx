/**
 * I-QUEUE -- tests of the in-memory outbound queue of C-DLV section 4.
 *
 * Everything the module consumes is injected here: the clock and the random
 * port of C-SDK section 8.4, the storage, session and identity ports of
 * sections 8.1 to 8.3, the publication seam of C-DLV section 5.3 that card
 * I-RELAY implements, and the event sink of C-SDK section 7. The relay seam of
 * this file answers, times out and hangs on demand, so every timing below is
 * virtual and exactly reproducible.
 *
 * The five purpose items of the O-SCEN3 set each carry item-lifecycle
 * content, so one test per purpose item replays the timeline those records
 * state: `hungRelay` (`twoHungRelaysExhaustion`), `relayLoss`
 * (`relayLossAndReplacement`), `duplicateAndReordered`
 * (`outboundDuplicateAccepted`), `offlineRecipient` (its three timelines) and
 * `queueRestartLost` (`lostAtShutdownThenNewClient`, `nonEmptyStoreRefused`).
 * Beyond them the suite exercises port faults, unknown values, the timeout of
 * a port call, the deadline backstop of section 4.4, the continuations of
 * section 4.6 and the public-surface isolation of this card's contract, and it
 * ends with a generative property over a deterministic draw stream.
 *
 * No new dependency: this file imports the module under test, the test runner
 * and nothing else. The draw stream of the generative test is a small
 * deterministic generator defined inside the file.
 */
import { describe, expect, test } from '@jest/globals';

import { createOutbox } from '../../../src/sdk/delivery/outbox.js';

/* ------------------------------------------------------------------------- *
 * Fixtures and the injected harness.
 * ------------------------------------------------------------------------- */

/** A lowercase 64-hex public key, the form C-SDK section 8.3 fixes. */
const PUBKEY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
/** The recipient of every item below, in the same form. */
const RECIPIENT = 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210';
/** A different recipient, for the receipt checks of C-DLV section 7.3. */
const OTHER = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';

/** The delivery configuration of C-DLV section 3, at the values the records use. */
const DELIVERY = {
  maxAttempts: 5,
  deadlineMs: 120000,
  perRelayTimeoutMs: 12000,
  receiptMode: 'RELAY_ACCEPTANCE_ONLY',
};

const PAYLOAD = new Uint8Array([1, 2, 3, 4]);

/** Let every pending microtask and chained promise settle. */
async function flush(turns = 6) {
  for (let turn = 0; turn < turns; turn += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

/**
 * The injected clock port of C-SDK section 8.4: a virtual millisecond clock
 * that fires each armed timer at exactly its delay, exactly as every
 * precondition of the scenario records states.
 *
 * @param {number} [start]
 */
function makeClock(start = 0) {
  const state = {
    now: start,
    seq: 0,
    timers: new Map(),
    setCalls: [],
    clearCalls: [],
    nowCalls: 0,
    ignoreSetTimer: false,
  };
  const port = {
    now() {
      state.nowCalls += 1;
      if (state.nowThrows === true) throw new Error('clock.now');
      return state.now;
    },
    setTimer(callback, delayMs) {
      state.setCalls.push({ delayMs });
      if (state.ignoreSetTimer === true) return undefined;
      const handle = { timer: (state.seq += 1) };
      state.timers.set(handle.timer, { at: state.now + delayMs, callback });
      return handle;
    },
    clearTimer(handle) {
      state.clearCalls.push(handle);
      if (handle === null || handle === undefined) return;
      state.timers.delete(handle.timer);
    },
  };

  /** Fire every timer due within `ms` of virtual time, in order. */
  async function advance(ms) {
    const target = state.now + ms;
    for (;;) {
      let next = null;
      for (const [id, timer] of state.timers) {
        if (timer.at <= target && (next === null || timer.at < next.at)) next = { id, ...timer };
      }
      if (next === null) break;
      state.now = next.at;
      state.timers.delete(next.id);
      next.callback();
      await flush(3);
    }
    state.now = target;
    await flush(3);
  }

  /** Advance until `predicate()` holds, or throw after `steps` slices. */
  async function advanceUntil(predicate, { sliceMs = 100, steps = 2000 } = {}) {
    for (let step = 0; step < steps; step += 1) {
      if (await predicate()) return true;
      await advance(sliceMs);
    }
    return predicate();
  }

  return { port, state, advance, advanceUntil };
}

/** The storage port of C-SDK section 8.1, with per-call outcome controls. */
function makeStorage(overrides = {}) {
  const records = new Map();
  const calls = { put: [], update: [], remove: [], list: [] };
  const storage = {
    records,
    calls,
    putResult: true,
    updateResult: true,
    removeResult: true,
    listResult: () => [],
    async put(record) {
      calls.put.push(record);
      if (typeof storage.putResult === 'function') return storage.putResult(record);
      if (storage.putResult === true) records.set(record.deliveryId, record);
      return storage.putResult;
    },
    async update(deliveryId, record) {
      calls.update.push(record);
      if (typeof storage.updateResult === 'function') return storage.updateResult(deliveryId, record);
      if (storage.updateResult === true) records.set(deliveryId, record);
      return storage.updateResult;
    },
    async remove(deliveryId) {
      calls.remove.push(deliveryId);
      if (typeof storage.removeResult === 'function') return storage.removeResult(deliveryId);
      if (storage.removeResult === true) records.delete(deliveryId);
      return storage.removeResult;
    },
    async list() {
      calls.list.push(true);
      return typeof storage.listResult === 'function' ? storage.listResult() : storage.listResult;
    },
  };
  Object.assign(storage, overrides);
  return storage;
}

/** The session port of C-SDK section 8.2, sealing by copying the plaintext. */
function makeSession(overrides = {}) {
  const session = {
    sealCalls: [],
    seal: ({ plaintext }) => {
      session.sealCalls.push(plaintext);
      return { ciphertext: Uint8Array.from(plaintext) };
    },
  };
  Object.assign(session, overrides);
  return session;
}

/** The identity port of C-SDK section 8.3. */
function makeIdentity(overrides = {}) {
  const identity = {
    keyCalls: 0,
    signCalls: [],
    getPublicKey() {
      identity.keyCalls += 1;
      return PUBKEY;
    },
    sign({ digest }) {
      identity.signCalls.push(digest);
      return new Uint8Array(64).fill(digest[0]);
    },
  };
  Object.assign(identity, overrides);
  return identity;
}

/**
 * The publication seam of C-DLV section 5.3, in the shape card I-RELAY
 * returns: an attempt with its per-relay outcome array, the two listeners, the
 * two gates and `ignoreAcks`, and an attempt timeout armed on the injected
 * clock at `perRelayTimeoutMs`. A relay answers only through `answer()`; an
 * entry that is still PENDING when the attempt timeout elapses becomes
 * TIMED_OUT, and the attempt settles when every entry is non-PENDING.
 */
function makeRelaySet({ relayCount, clock, perRelayTimeoutMs }) {
  const attempts = [];
  function publish(event) {
    const outcomes = new Array(relayCount).fill('PENDING');
    const outcomeListeners = [];
    const settledListeners = [];
    let settled = false;
    let acksIgnored = false;
    const state = { events: [], publishCalls: 0 };
    const attempt = {
      outcomes,
      event,
      attempts: state,
      get acceptedIndex() {
        const index = outcomes.indexOf('ACCEPTED');
        return index === -1 ? null : index;
      },
      isSettled: () => settled,
      onOutcome(listener) {
        outcomeListeners.push(listener);
      },
      onSettled(listener) {
        settledListeners.push(listener);
      },
      ignoreAcks() {
        acksIgnored = true;
      },
      acceptGate: () => false,
      latePublishGate: () => false,
      announce() {
        if (settled) return;
        if (outcomes.every((outcome) => outcome !== 'PENDING')) {
          settled = true;
          for (const listener of settledListeners) listener();
        }
      },
      answer(relayIndex, outcome) {
        if (outcomes[relayIndex] !== 'PENDING') return false;
        if (acksIgnored && (outcome === 'ACCEPTED' || outcome === 'REJECTED')) return false;
        if (outcome === 'ACCEPTED' && attempt.acceptGate(relayIndex, attempt) !== true) return false;
        outcomes[relayIndex] = outcome;
        for (const listener of outcomeListeners) listener(relayIndex, outcome);
        attempt.announce();
        return true;
      },
      timeOut() {
        for (let index = 0; index < outcomes.length; index += 1) {
          if (outcomes[index] !== 'PENDING') continue;
          outcomes[index] = 'TIMED_OUT';
          for (const listener of outcomeListeners) listener(index, 'TIMED_OUT');
        }
        attempt.announce();
      },
      force(relayIndex, outcome) {
        outcomes[relayIndex] = outcome;
        for (const listener of outcomeListeners) listener(relayIndex, outcome);
        attempt.announce();
      },
      ignoreState() {
        return acksIgnored;
      },
    };
    state.publishCalls += 1;
    state.events.push(event);
    clock.port.setTimer(() => attempt.timeOut(), perRelayTimeoutMs);
    attempts.push(attempt);
    return attempt;
  }
  return { publish, attempts };
}

/**
 * Build one outbox over the injected harness.
 *
 * @param {object} [config]
 */
function makeHarness(config = {}) {
  const clock = makeClock(config.start ?? 0);
  const storage = config.storage ?? makeStorage();
  const session = config.session ?? makeSession();
  const identity = config.identity ?? makeIdentity();
  const relaySet = makeRelaySet({
    relayCount: config.relayCount ?? 2,
    clock,
    perRelayTimeoutMs: (config.delivery ?? DELIVERY).perRelayTimeoutMs,
  });
  const events = [];
  const draws = Array.isArray(config.randomValues) ? [...config.randomValues] : [];
  const random = {
    calls: 0,
    draws,
    nextUint32() {
      random.calls += 1;
      if (config.randomThrows === true) throw new Error('random');
      return draws.length === 0 ? 0 : draws.shift();
    },
  };
  const delivery = config.delivery ?? DELIVERY;
  const outbox = createOutbox({
    delivery,
    relayCount: config.relayCount ?? 2,
    storage,
    session,
    identity,
    clock: config.clockPort ?? clock.port,
    random: config.randomPort ?? random,
    publish: 'publish' in config ? config.publish : relaySet.publish,
    onEvent: (event) => {
      events.push({ at: clock.state.now, ...event });
    },
  });
  return { outbox, clock, storage, session, identity, relaySet, random, events, delivery };
}

/* ------------------------------------------------------------------------- *
 * The module and its public surface.
 * ------------------------------------------------------------------------- */

describe('the module and its public surface', () => {
  test('exports exactly one name, createOutbox, and nothing else', async () => {
    const module = await import('../../../src/sdk/delivery/outbox.js');
    expect(Object.keys(module)).toEqual(['createOutbox']);
    expect(typeof module.createOutbox).toBe('function');
  });

  test('the outbound message event of section 6.2: seven frozen fields, kind 4741, the tag order and the id the signature covers (C-DLV 6.2)', async () => {
    const { outbox, clock, relaySet, identity, session } = makeHarness({
      delivery: { ...DELIVERY, receiptMode: 'RECIPIENT_RECEIPT' },
    });
    clock.state.now = 12050;
    await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    const event = relaySet.attempts[0].event;
    expect(Object.isFrozen(event)).toBe(true);
    expect(Object.keys(event)).toEqual([
      'id',
      'pubkey',
      'created_at',
      'kind',
      'tags',
      'content',
      'sig',
    ]);
    expect(event.kind).toBe(4741);
    expect(event.pubkey).toBe(PUBKEY);
    expect(event.created_at).toBe(Math.floor(12050 / 1000));
    // The tag list and its order: the recipient, the version, the 32-hex nonce
    // and, in RECIPIENT_RECEIPT mode only, the receipt tag.
    expect(event.tags.map((tag) => tag[0])).toEqual(['p', 'v', 'n', 'r']);
    expect(event.tags[0]).toEqual(['p', RECIPIENT]);
    expect(event.tags[1][1]).toMatch(/^\S+$/);
    expect(event.tags[2][1]).toMatch(/^[0-9a-f]{32}$/);
    expect(event.tags[3]).toEqual(['r', '1']);
    // The sealed bytes are the session port's return and the content is their
    // base64; the signature is the identity port's 64-byte return.
    expect(session.sealCalls.length).toBe(1);
    expect(event.content).toBe(Buffer.from(PAYLOAD).toString('base64'));
    expect(identity.signCalls.length).toBe(1);
    expect(identity.signCalls[0]).toEqual(Uint8Array.from(Buffer.from(event.id, 'hex')));
    expect(identity.signCalls[0].length).toBe(32);
    // The seam double of this file signs by filling 64 bytes with the first
    // byte of the digest, so the event's `sig` is that value in hex.
    const signedByte = identity.signCalls[0][0].toString(16).padStart(2, '0');
    expect(event.sig).toBe(signedByte.repeat(64));
    // The id is a 64-hex value and no relay saw the event before the signature.
    expect(event.id).toMatch(/^[0-9a-f]{64}$/);
    await outbox.shutdown();
  });

  test('the object it returns carries exactly the six members of the contract, and is frozen', () => {
    const { outbox } = makeHarness();
    expect(Object.isFrozen(outbox)).toBe(true);
    expect(Object.keys(outbox).sort()).toEqual([
      'acceptReceipt',
      'cancel',
      'getDelivery',
      'inspectStore',
      'send',
      'shutdown',
    ]);
    for (const member of Object.values(outbox)) expect(typeof member).toBe('function');
  });

  test('an unsupported member or a non-plain argument object is E_SDK_INVALID_ARGUMENT', async () => {
    const { outbox } = makeHarness();
    for (const bad of [null, undefined, 0, 'd1', [], [{ deliveryId: 'd1' }]]) {
      const result = await outbox.getDelivery(bad);
      expect(result).toEqual({ ok: false, code: 'E_SDK_INVALID_ARGUMENT' });
    }
    const extra = await outbox.getDelivery({ deliveryId: 'd1', extra: 1 });
    expect(extra.code).toBe('E_SDK_INVALID_ARGUMENT');
    const send = await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD, extra: 1 });
    expect(send.code).toBe('E_SDK_INVALID_ARGUMENT');
    const cancel = await outbox.cancel({ deliveryId: 'd1', extra: 1 });
    expect(cancel.code).toBe('E_SDK_INVALID_ARGUMENT');
    await outbox.shutdown();
  });

  test('every envelope and snapshot is frozen, and a returned snapshot never changes', async () => {
    const { outbox, clock, relaySet } = makeHarness();
    clock.state.now = 1000;
    const admitted = await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    expect(Object.isFrozen(admitted)).toBe(true);
    expect(Object.isFrozen(admitted.value)).toBe(true);
    await flush();
    const first = await outbox.getDelivery({ deliveryId: 'd1' });
    expect(Object.isFrozen(first)).toBe(true);
    expect(Object.isFrozen(first.value)).toBe(true);
    expect(Object.isFrozen(first.value.relayOutcomes)).toBe(true);
    expect(Object.isFrozen(first.value.relayOutcomes[0])).toBe(true);
    expect(Object.keys(first.value).sort()).toEqual([
      'attempts',
      'createdAt',
      'deadlineAt',
      'deliveryId',
      'lastCode',
      'recipient',
      'relayOutcomes',
      'state',
      'terminal',
    ]);
    // The item moves on, and the snapshot already handed out is unchanged.
    relaySet.attempts[0].answer(1, 'ACCEPTED');
    await flush();
    const second = await outbox.getDelivery({ deliveryId: 'd1' });
    expect(first.value.state).toBe('IN_FLIGHT');
    expect(second.value.state).toBe('RELAY_ACCEPTED');
    expect(first.value.relayOutcomes.map((entry) => entry.outcome)).toEqual(['PENDING', 'PENDING']);
    // Neither the snapshot nor its array can be used to forge a state.
    expect(() => {
      first.value.state = 'CANCELLED';
    }).toThrow(TypeError);
    expect(() => {
      first.value.relayOutcomes.push({ relayIndex: 9, outcome: 'ACCEPTED' });
    }).toThrow(TypeError);
    await outbox.shutdown();
  });

  test('a callback receives the frozen public event of C-SDK section 7, never the internal record', async () => {
    const received = [];
    const clock = makeClock(0);
    const outbox = createOutbox({
      delivery: DELIVERY,
      relayCount: 1,
      storage: makeStorage(),
      session: makeSession(),
      identity: makeIdentity(),
      clock: clock.port,
      random: { nextUint32: () => 0 },
      publish: makeRelaySet({ relayCount: 1, clock, perRelayTimeoutMs: 12000 }).publish,
      onEvent: (event) => {
        received.push(event);
      },
    });
    clock.state.now = 1000;
    await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    expect(received.length).toBe(1);
    const event = received[0];
    expect(Object.isFrozen(event)).toBe(true);
    expect(Object.keys(event).sort()).toEqual([
      'deliveryId',
      'kind',
      'lastCode',
      'state',
      'terminal',
    ]);
    expect(event).toEqual({
      kind: 'DELIVERY_STATE_CHANGED',
      deliveryId: 'd1',
      state: 'IN_FLIGHT',
      terminal: false,
      lastCode: null,
    });
    expect(() => {
      event.state = 'CANCELLED';
    }).toThrow(TypeError);
    await outbox.shutdown();
  });

  test('a sink that throws changes nothing, and the transition is still recorded', async () => {
    const clock = makeClock(0);
    const storage = makeStorage();
    const outbox = createOutbox({
      delivery: DELIVERY,
      relayCount: 1,
      storage,
      session: makeSession(),
      identity: makeIdentity(),
      clock: clock.port,
      random: { nextUint32: () => 0 },
      publish: makeRelaySet({ relayCount: 1, clock, perRelayTimeoutMs: 12000 }).publish,
      onEvent: () => {
        throw new Error('listener');
      },
    });
    clock.state.now = 1000;
    const admitted = await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    expect(admitted.ok).toBe(true);
    await flush();
    const snapshot = await outbox.getDelivery({ deliveryId: 'd1' });
    expect(snapshot.value.state).toBe('IN_FLIGHT');
    expect(storage.calls.update.length).toBe(1);
    await outbox.shutdown();
  });
});

/* ------------------------------------------------------------------------- *
 * Admission (C-DLV section 4.2).
 * ------------------------------------------------------------------------- */

describe('admission (C-DLV section 4.2)', () => {
  test('step 1: argument validation, and no port is called for a refused argument', async () => {
    const { outbox, session, storage } = makeHarness();
    const bad = [
      { recipient: RECIPIENT.toUpperCase(), plaintext: PAYLOAD },
      { recipient: 'abcd', plaintext: PAYLOAD },
      { recipient: RECIPIENT, plaintext: [] },
      { recipient: RECIPIENT, plaintext: 'text' },
      { recipient: RECIPIENT, plaintext: new Uint8Array(0) },
      { recipient: 42, plaintext: PAYLOAD },
      { plaintext: PAYLOAD },
    ];
    for (const argument of bad) {
      const result = await outbox.send(argument);
      expect(result).toEqual({ ok: false, code: 'E_SDK_INVALID_ARGUMENT' });
    }
    expect(session.sealCalls.length).toBe(0);
    expect(storage.calls.put.length).toBe(0);
    await outbox.shutdown();
  });

  test('step 1: a payload above 65536 bytes is E_SDK_PAYLOAD_TOO_LARGE and is never sealed', async () => {
    const { outbox, session } = makeHarness();
    const tooLarge = await outbox.send({
      recipient: RECIPIENT,
      plaintext: new Uint8Array(65537),
    });
    expect(tooLarge).toEqual({ ok: false, code: 'E_SDK_PAYLOAD_TOO_LARGE' });
    expect(session.sealCalls.length).toBe(0);
    const exactly = await outbox.send({ recipient: RECIPIENT, plaintext: new Uint8Array(65536) });
    expect(exactly.code).toBe(undefined);
    await outbox.shutdown();
  });

  test('step 2: the bound is 256 non-terminal items, and concurrent sends cannot exceed it', async () => {
    const { outbox, clock, storage } = makeHarness();
    clock.state.now = 0;
    const admissions = [];
    for (let index = 0; index < 300; index += 1) {
      admissions.push(outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD }));
    }
    const results = await Promise.all(admissions);
    const accepted = results.filter((result) => result.ok);
    const refused = results.filter((result) => !result.ok);
    expect(accepted.length).toBe(256);
    expect(refused.length).toBe(44);
    for (const result of refused) expect(result.code).toBe('E_SDK_QUEUE_FULL');
    expect(new Set(accepted.map((result) => result.value.deliveryId)).size).toBe(256);
    expect(storage.calls.put.length).toBe(256);
    // A terminal item frees its slot: cancelling one admits one more.
    const cancel = await outbox.cancel({ deliveryId: 'd1' });
    expect(cancel.value.state).toBe('CANCELLED');
    const oneMore = await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    expect(oneMore.ok).toBe(true);
    await outbox.shutdown();
  });

  test('step 4 and 5: the delivery id is d1, d2, ... and a refused admission still consumes its number', async () => {
    const storage = makeStorage();
    storage.putResult = (record) => record.deliveryId !== 'd2';
    const { outbox, clock } = makeHarness({ storage });
    clock.state.now = 0;
    const first = await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    expect(first.value.deliveryId).toBe('d1');
    const refused = await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    expect(refused).toEqual({ ok: false, code: 'E_SDK_STORAGE_FAILED' });
    const third = await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    expect(third.value.deliveryId).toBe('d3');
    const unknown = await outbox.getDelivery({ deliveryId: 'd2' });
    expect(unknown).toEqual({ ok: false, code: 'E_SDK_UNKNOWN_DELIVERY' });
    await outbox.shutdown();
  });

  test('step 3: every seal fault is E_SDK_SESSION_FAILED, and the item is never admitted', async () => {
    const faults = [
      makeSession({ seal: () => { throw new Error('seal'); } }),
      makeSession({ seal: () => Promise.reject(new Error('seal')) }),
      makeSession({ seal: 42 }),
      makeSession({ seal: () => ({ ciphertext: new Uint8Array(0) }) }),
      makeSession({ seal: () => ({ ciphertext: 'deadbeef' }) }),
      makeSession({ seal: () => ({ ciphertext: new Uint8Array([1]), extra: 1 }) }),
      makeSession({ seal: () => undefined }),
    ];
    for (const session of faults) {
      const { outbox, clock, storage } = makeHarness({ session });
      clock.state.now = 0;
      const result = await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
      expect(result).toEqual({ ok: false, code: 'E_SDK_SESSION_FAILED' });
      expect(storage.calls.put.length).toBe(0);
      await outbox.shutdown();
    }
    const throwingGetter = {};
    Object.defineProperty(throwingGetter, 'seal', {
      get() {
        throw new Error('getter');
      },
    });
    const { outbox, clock } = makeHarness({ session: throwingGetter });
    clock.state.now = 0;
    expect(await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD })).toEqual({
      ok: false,
      code: 'E_SDK_SESSION_FAILED',
    });
    await outbox.shutdown();
  });

  test('step 5: a failed put whose remove succeeds leaves no item and emits no event', async () => {
    const storage = makeStorage();
    storage.putResult = false;
    const { outbox, clock, events } = makeHarness({ storage });
    clock.state.now = 0;
    const result = await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    expect(result).toEqual({ ok: false, code: 'E_SDK_STORAGE_FAILED' });
    expect(storage.calls.remove).toEqual(['d1']);
    expect(events.length).toBe(0);
    expect(await outbox.getDelivery({ deliveryId: 'd1' })).toEqual({
      ok: false,
      code: 'E_SDK_UNKNOWN_DELIVERY',
    });
    expect(clock.state.clearCalls.length).toBe(1);
    await outbox.shutdown();
  });

  test('step 5: a failed put whose remove also fails leaves the residual item, terminal and unpublished', async () => {
    const storage = makeStorage();
    storage.putResult = () => {
      throw new Error('put');
    };
    storage.removeResult = () => {
      throw new Error('remove');
    };
    const { outbox, clock, events, relaySet } = makeHarness({ storage });
    clock.state.now = 0;
    const result = await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    expect(result).toEqual({ ok: false, code: 'E_SDK_STORAGE_FAILED' });
    const snapshot = await outbox.getDelivery({ deliveryId: 'd1' });
    expect(snapshot.value.state).toBe('FAILED_NOT_ACCEPTED');
    expect(snapshot.value.terminal).toBe(true);
    expect(snapshot.value.lastCode).toBe('E_SDK_STORAGE_FAILED');
    expect(events.map((event) => event.state)).toEqual(['FAILED_NOT_ACCEPTED']);
    expect(relaySet.attempts.length).toBe(0);
    expect(storage.calls.update.length).toBe(0);
    await outbox.shutdown();
    // The residual item is kept in the in-memory view after the stop.
    const afterStop = await outbox.getDelivery({ deliveryId: 'd1' });
    expect(afterStop.value.state).toBe('FAILED_NOT_ACCEPTED');
  });

  test('step 4: an invalid clock reading is E_SDK_INTERNAL and arms no timer', async () => {
    for (const value of [Number.NaN, Number.POSITIVE_INFINITY, 'now', null, undefined]) {
      const clock = makeClock(0);
      clock.state.now = value;
      const storage = makeStorage();
      const outbox = createOutbox({
        delivery: DELIVERY,
        relayCount: 1,
        storage,
        session: makeSession(),
        identity: makeIdentity(),
        clock: clock.port,
        random: { nextUint32: () => 0 },
        publish: () => {
          throw new Error('never');
        },
        onEvent: () => {},
      });
      expect(await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD })).toEqual({
        ok: false,
        code: 'E_SDK_INTERNAL',
      });
      expect(storage.calls.put.length).toBe(0);
      expect(clock.state.setCalls.length).toBe(0);
      await outbox.shutdown();
    }
  });

  test('a clock whose now throws is E_SDK_INTERNAL, and a throwing getter on the clock port is too', async () => {
    const clock = makeClock(0);
    clock.port.now = () => {
      throw new Error('now');
    };
    const { outbox } = makeHarness({ clockPort: clock.port });
    expect(await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD })).toEqual({
      ok: false,
      code: 'E_SDK_INTERNAL',
    });
    await outbox.shutdown();

    const frozenClock = {};
    Object.defineProperty(frozenClock, 'now', {
      get() {
        throw new Error('getter');
      },
    });
    const second = makeHarness({ clockPort: frozenClock });
    expect(await second.outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD })).toEqual({
      ok: false,
      code: 'E_SDK_INTERNAL',
    });
    await second.outbox.shutdown();
  });
});

/* ------------------------------------------------------------------------- *
 * The O-SCEN3 timelines.
 * ------------------------------------------------------------------------- */

describe('the O-SCEN3 timelines', () => {
  test('hungRelay / twoHungRelaysExhaustion: five attempts, the four draws of the record, and the exhaustion', async () => {
    const { outbox, clock, events, random, storage } = makeHarness({
      randomValues: [4294967295, 2147483648, 4294967295, 0],
    });
    clock.state.now = 12000;
    const admitted = await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    expect(admitted).toEqual({ ok: true, value: { deliveryId: 'd1', state: 'QUEUED' } });
    expect(await outbox.getDelivery({ deliveryId: 'd1' })).toMatchObject({
      value: {
        createdAt: 12000,
        deadlineAt: 132000,
        // C-DLV section 4.3: the attempt start moved the item to IN_FLIGHT and
        // incremented its count before the first publication phase.
        attempts: 1,
        lastCode: null,
        state: 'IN_FLIGHT',
        relayOutcomes: [
          { relayIndex: 0, outcome: 'PENDING' },
          { relayIndex: 1, outcome: 'PENDING' },
        ],
      },
    });
    await flush();

    const terminal = () => outbox.getDelivery({ deliveryId: 'd1' }).then((snap) => snap.value.terminal);
    await clock.advanceUntil(terminal, { sliceMs: 100 });
    // The five attempts and the four retry delays of the record.
    const delays = clock.state.setCalls.map((call) => call.delayMs);
    expect(delays).toEqual([120000, 12000, 999, 12000, 1500, 12000, 3999, 12000, 4000, 12000]);
    expect(random.calls).toBe(4);
    expect(events).toEqual([
      { at: 12000, kind: 'DELIVERY_STATE_CHANGED', deliveryId: 'd1', state: 'IN_FLIGHT', terminal: false, lastCode: null },
      { at: 24000, kind: 'DELIVERY_STATE_CHANGED', deliveryId: 'd1', state: 'QUEUED', terminal: false, lastCode: null },
      { at: 24999, kind: 'DELIVERY_STATE_CHANGED', deliveryId: 'd1', state: 'IN_FLIGHT', terminal: false, lastCode: null },
      { at: 36999, kind: 'DELIVERY_STATE_CHANGED', deliveryId: 'd1', state: 'QUEUED', terminal: false, lastCode: null },
      { at: 38499, kind: 'DELIVERY_STATE_CHANGED', deliveryId: 'd1', state: 'IN_FLIGHT', terminal: false, lastCode: null },
      { at: 50499, kind: 'DELIVERY_STATE_CHANGED', deliveryId: 'd1', state: 'QUEUED', terminal: false, lastCode: null },
      { at: 54498, kind: 'DELIVERY_STATE_CHANGED', deliveryId: 'd1', state: 'IN_FLIGHT', terminal: false, lastCode: null },
      { at: 66498, kind: 'DELIVERY_STATE_CHANGED', deliveryId: 'd1', state: 'QUEUED', terminal: false, lastCode: null },
      { at: 70498, kind: 'DELIVERY_STATE_CHANGED', deliveryId: 'd1', state: 'IN_FLIGHT', terminal: false, lastCode: null },
      { at: 82498, kind: 'DELIVERY_STATE_CHANGED', deliveryId: 'd1', state: 'FAILED_NOT_ACCEPTED', terminal: true, lastCode: null },
    ]);
    expect(await outbox.getDelivery({ deliveryId: 'd1' })).toMatchObject({
      value: {
        state: 'FAILED_NOT_ACCEPTED',
        terminal: true,
        attempts: 5,
        lastCode: null,
        relayOutcomes: [
          { relayIndex: 0, outcome: 'TIMED_OUT' },
          { relayIndex: 1, outcome: 'TIMED_OUT' },
        ],
      },
    });
    // The whole publication kept one event and one signature.
    expect(storage.calls.put.length).toBe(1);
    const attemptsWithEvent = storage.calls.update.length;
    expect(attemptsWithEvent).toBe(10);
    const stop = await outbox.shutdown();
    expect(stop.value).toEqual({ clientState: 'STOPPED', lost: 0 });
  });

  test('hungRelay / hungRelayAlongsideNormal: the hung entry settles after the item left IN_FLIGHT', async () => {
    const { outbox, clock, relaySet, events } = makeHarness({
      delivery: { ...DELIVERY, receiptMode: 'RECIPIENT_RECEIPT' },
    });
    clock.state.now = 12000;
    await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    // The normal relay, configured second, answers at 12050.
    await clock.advance(50);
    expect(relaySet.attempts[0].answer(1, 'ACCEPTED')).toBe(true);
    await flush();
    const awaiting = await outbox.getDelivery({ deliveryId: 'd1' });
    expect(awaiting.value).toMatchObject({
      state: 'RELAY_ACCEPTED_AWAITING_RECEIPT',
      terminal: false,
      attempts: 1,
      lastCode: null,
    });
    // The attempt stays open and the hung relay settles at the attempt timeout.
    await clock.advance(24000 - clock.state.now);
    const settled = await outbox.getDelivery({ deliveryId: 'd1' });
    expect(settled.value.state).toBe('RELAY_ACCEPTED_AWAITING_RECEIPT');
    expect(settled.value.relayOutcomes).toEqual([
      { relayIndex: 0, outcome: 'TIMED_OUT' },
      { relayIndex: 1, outcome: 'ACCEPTED' },
    ]);
    expect(events.map((event) => event.state)).toEqual([
      'IN_FLIGHT',
      'RELAY_ACCEPTED_AWAITING_RECEIPT',
    ]);
    const stop = await outbox.shutdown();
    expect(stop.value).toEqual({ clientState: 'STOPPED', lost: 1 });
  });

  test('relayLoss / relayLossAndReplacement: a loss, a replacement, and the acceptance of the republished event', async () => {
    const { outbox, clock, relaySet, storage, random } = makeHarness({
      // The recorded draw of the ratified O-SCEN3 relayLoss record: the retry
      // delay is 500 + floor(u * 1000 / 2^33) = 999 ms.
      randomValues: [4294967295],
    });
    clock.state.now = 12000;
    await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    // Attempt 1: relay0 is lost, relay1 never answers.
    relaySet.attempts[0].answer(0, 'UNREACHABLE');
    await flush();
    expect((await outbox.getDelivery({ deliveryId: 'd1' })).value).toMatchObject({
      state: 'IN_FLIGHT',
      attempts: 1,
      relayOutcomes: [
        { relayIndex: 0, outcome: 'UNREACHABLE' },
        { relayIndex: 1, outcome: 'PENDING' },
      ],
    });
    await clock.advanceUntil(
      () => outbox.getDelivery({ deliveryId: 'd1' }).then((snap) => snap.value.attempts === 2),
      { sliceMs: 50 },
    );
    expect(relaySet.attempts.length).toBe(2);
    // The retry is armed at the recorded draw: delay(1, 4294967295) = 999 ms
    // after the attempt timeout at 24000, so the second attempt begins at 24999
    // (`advanceUntil` checks its predicate between 50 ms slices, hence 25000).
    expect(clock.state.setCalls.map((call) => call.delayMs)).toContain(999);
    expect(clock.state.now).toBe(25000);
    // The retransmission republishes exactly the signed bytes of attempt 1.
    expect(relaySet.attempts[1].event).toBe(relaySet.attempts[0].event);
    // Attempt 2: the replacement connection answers the republished event.
    expect(relaySet.attempts[1].answer(0, 'ACCEPTED')).toBe(true);
    await flush();
    const accepted = await outbox.getDelivery({ deliveryId: 'd1' });
    expect(accepted.value).toMatchObject({ state: 'RELAY_ACCEPTED', terminal: true, attempts: 2 });
    // The attempt timeout still settles relay1 although the item is terminal.
    await clock.advance(12000);
    const final = await outbox.getDelivery({ deliveryId: 'd1' });
    expect(final.value.relayOutcomes).toEqual([
      { relayIndex: 0, outcome: 'ACCEPTED' },
      { relayIndex: 1, outcome: 'TIMED_OUT' },
    ]);
    expect(final.value.lastCode).toBe(null);
    // One event, one signature and one put for the whole item.
    expect(storage.calls.put.length).toBe(1);
    expect(random.calls).toBe(1);
    const stop = await outbox.shutdown();
    expect(stop.value).toEqual({ clientState: 'STOPPED', lost: 0 });
  });

  test('duplicateAndReordered / outboundDuplicateAccepted: the identical bytes are republished and a duplicate: OK counts as ACCEPTED', async () => {
    const { outbox, clock, relaySet, session, identity, storage, events } = makeHarness({
      randomValues: [4294967295],
    });
    clock.state.now = 12000;
    await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    // Attempt 1: relay0 drops its socket after storing the event, relay1 never answers.
    relaySet.attempts[0].answer(0, 'UNREACHABLE');
    await clock.advanceUntil(
      () => outbox.getDelivery({ deliveryId: 'd1' }).then((snap) => snap.value.state === 'QUEUED'),
      { sliceMs: 50 },
    );
    expect(clock.state.now).toBe(24000);
    const retryDelay = clock.state.setCalls[clock.state.setCalls.length - 1].delayMs;
    expect(retryDelay).toBe(999);
    await clock.advance(999);
    expect(clock.state.now).toBe(24999);
    expect((await outbox.getDelivery({ deliveryId: 'd1' })).value.attempts).toBe(2);
    await flush();
    // The retransmission republishes exactly the signed bytes.
    expect(relaySet.attempts[1].event.id).toBe(relaySet.attempts[0].event.id);
    expect(relaySet.attempts[1].event).toBe(relaySet.attempts[0].event);
    expect(session.sealCalls.length).toBe(1);
    expect(identity.signCalls.length).toBe(1);
    expect(storage.calls.put.length).toBe(1);
    // The duplicate: answer of the stored event counts as ACCEPTED.
    expect(relaySet.attempts[1].answer(0, 'ACCEPTED')).toBe(true);
    await flush();
    await clock.advance(12000);
    expect(await outbox.getDelivery({ deliveryId: 'd1' })).toMatchObject({
      value: {
        state: 'RELAY_ACCEPTED',
        terminal: true,
        attempts: 2,
        createdAt: 12000,
        deadlineAt: 132000,
        lastCode: null,
        relayOutcomes: [
          { relayIndex: 0, outcome: 'ACCEPTED' },
          { relayIndex: 1, outcome: 'TIMED_OUT' },
        ],
      },
    });
    expect(events.map((event) => event.state)).toEqual([
      'IN_FLIGHT',
      'QUEUED',
      'IN_FLIGHT',
      'RELAY_ACCEPTED',
    ]);
    // No third attempt and no delay drawn after the acceptance.
    expect(relaySet.attempts.length).toBe(2);
    const stop = await outbox.shutdown();
    expect(stop.value.lost).toBe(0);
  });

  test('offlineRecipient: a receipt before the deadline, held or accepted, and the deadline after it', async () => {
    const { outbox, clock, relaySet, storage, events } = makeHarness({
      start: 0,
      delivery: { maxAttempts: 5, deadlineMs: 120000, perRelayTimeoutMs: 12000, receiptMode: 'RECIPIENT_RECEIPT' },
    });
    clock.state.now = 12000;
    await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    // A receipt that arrives while the item is still IN_FLIGHT is held.
    const eventId = relaySet.attempts[0].event.id;
    expect(typeof eventId).toBe('string');
    const held = await outbox.acceptReceipt({ eventId, recipient: RECIPIENT });
    expect(held).toEqual({ ok: true, value: { accepted: true, deliveryId: 'd1' } });
    expect((await outbox.getDelivery({ deliveryId: 'd1' })).value.state).toBe('IN_FLIGHT');
    expect(events.map((event) => event.state)).toEqual(['IN_FLIGHT']);
    // The acceptance of the publication then applies the held receipt at once.
    relaySet.attempts[0].answer(1, 'ACCEPTED');
    await flush();
    expect(await outbox.getDelivery({ deliveryId: 'd1' })).toMatchObject({
      value: { state: 'RECIPIENT_RECEIPT_RECEIVED', terminal: true, lastCode: null },
    });
    expect(events.map((event) => event.state)).toEqual([
      'IN_FLIGHT',
      'RELAY_ACCEPTED_AWAITING_RECEIPT',
      'RECIPIENT_RECEIPT_RECEIVED',
    ]);
    const stop = await outbox.shutdown();
    expect(stop.value).toEqual({ clientState: 'STOPPED', lost: 0 });
  });

  test('offlineRecipient: a second receipt for the same item is ignored, a receipt from another signer too', async () => {
    const { outbox, clock, relaySet, storage } = makeHarness({
      delivery: { maxAttempts: 5, deadlineMs: 120000, perRelayTimeoutMs: 12000, receiptMode: 'RECIPIENT_RECEIPT' },
    });
    clock.state.now = 0;
    await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    const eventId = relaySet.attempts[0].event.id;
    expect(await outbox.acceptReceipt({ eventId, recipient: OTHER })).toEqual({
      ok: true,
      value: { accepted: false, deliveryId: 'd1' },
    });
    expect(
      await outbox.acceptReceipt({
        eventId: '00'.repeat(32),
        recipient: RECIPIENT,
      }),
    ).toEqual({ ok: true, value: { accepted: false, deliveryId: null } });
    relaySet.attempts[0].answer(1, 'ACCEPTED');
    await flush();
    expect(await outbox.acceptReceipt({ eventId, recipient: RECIPIENT })).toEqual({
      ok: true,
      value: { accepted: true, deliveryId: 'd1' },
    });
    expect(await outbox.acceptReceipt({ eventId, recipient: RECIPIENT })).toEqual({
      ok: true,
      value: { accepted: false, deliveryId: null },
    });
    expect((await outbox.getDelivery({ deliveryId: 'd1' })).value.state).toBe(
      'RECIPIENT_RECEIPT_RECEIVED',
    );
    await outbox.shutdown();
  });

  test('offlineRecipient: a receipt at or after the deadline takes the deadline transition and is refused', async () => {
    const { outbox, clock, relaySet, storage, events } = makeHarness({
      delivery: { maxAttempts: 5, deadlineMs: 30000, perRelayTimeoutMs: 12000, receiptMode: 'RECIPIENT_RECEIPT' },
    });
    clock.state.now = 0;
    await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    relaySet.attempts[0].answer(0, 'ACCEPTED');
    await flush();
    const eventId = storage.records.get('d1').event.id;
    expect((await outbox.getDelivery({ deliveryId: 'd1' })).value.state).toBe(
      'RELAY_ACCEPTED_AWAITING_RECEIPT',
    );
    // Exactly at the deadline the receipt is refused and the item fails with
    // its deadline transition of section 4.4 and `lastCode: null`.
    clock.state.now = 30000;
    expect(await outbox.acceptReceipt({ eventId, recipient: RECIPIENT })).toEqual({
      ok: true,
      value: { accepted: false, deliveryId: 'd1' },
    });
    expect(await outbox.getDelivery({ deliveryId: 'd1' })).toMatchObject({
      value: { state: 'FAILED_NO_RECEIPT', terminal: true, lastCode: null },
    });
    expect(events[events.length - 1]).toMatchObject({
      state: 'FAILED_NO_RECEIPT',
      terminal: true,
      lastCode: null,
    });
    await outbox.shutdown();

    // One millisecond earlier the same receipt is accepted.
    const second = makeHarness({
      delivery: { maxAttempts: 5, deadlineMs: 30000, perRelayTimeoutMs: 12000, receiptMode: 'RECIPIENT_RECEIPT' },
    });
    second.clock.state.now = 0;
    await second.outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    second.relaySet.attempts[0].answer(0, 'ACCEPTED');
    await flush();
    const id = second.storage.records.get('d1').event.id;
    second.clock.state.now = 29999;
    expect(await second.outbox.acceptReceipt({ eventId: id, recipient: RECIPIENT })).toEqual({
      ok: true,
      value: { accepted: true, deliveryId: 'd1' },
    });
    expect((await second.outbox.getDelivery({ deliveryId: 'd1' })).value.state).toBe(
      'RECIPIENT_RECEIPT_RECEIVED',
    );
    await second.outbox.shutdown();
  });

  test('the deadline of section 4.4 ends an acceptance-only item in FAILED_NOT_ACCEPTED, and a later OK is refused', async () => {
    const { outbox, clock, relaySet, events } = makeHarness({
      delivery: { ...DELIVERY, deadlineMs: 30000, perRelayTimeoutMs: 12000 },
    });
    clock.state.now = 0;
    await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    await clock.advanceUntil(
      () => outbox.getDelivery({ deliveryId: 'd1' }).then((snap) => snap.value.terminal),
      { sliceMs: 100 },
    );
    expect(clock.state.now).toBe(30000);
    const snapshot = await outbox.getDelivery({ deliveryId: 'd1' });
    expect(snapshot.value).toMatchObject({
      state: 'FAILED_NOT_ACCEPTED',
      terminal: true,
      lastCode: null,
    });
    expect(snapshot.value.attempts).toBeLessThanOrEqual(5);
    expect(events[events.length - 1]).toMatchObject({ state: 'FAILED_NOT_ACCEPTED', terminal: true });
    // An OK frame after the deadline is refused by the acceptance gate, so no
    // success state is ever recorded at or after the deadline.
    const last = relaySet.attempts[relaySet.attempts.length - 1];
    expect(last.acceptGate(0, last)).toBe(false);
    expect(last.answer(0, 'ACCEPTED')).toBe(false);
    await flush();
    expect((await outbox.getDelivery({ deliveryId: 'd1' })).value.state).toBe('FAILED_NOT_ACCEPTED');
    await outbox.shutdown();
  });

  test('queueRestartLost / lostAtShutdownThenNewClient: the stop, the frozen outcomes and the retained snapshot', async () => {
    const { outbox, clock, storage, events, relaySet } = makeHarness();
    clock.state.now = 12000;
    await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    expect(events.map((event) => [event.at, event.deliveryId, event.state])).toEqual([
      [12000, 'd1', 'IN_FLIGHT'],
      [12000, 'd2', 'IN_FLIGHT'],
    ]);
    clock.state.now = 20000;
    const stop = await outbox.shutdown();
    expect(stop).toEqual({ ok: true, value: { clientState: 'STOPPED', lost: 2 } });
    expect(events.map((event) => [event.at, event.deliveryId, event.state])).toEqual([
      [12000, 'd1', 'IN_FLIGHT'],
      [12000, 'd2', 'IN_FLIGHT'],
      [20000, 'd1', 'LOST_ON_SHUTDOWN'],
      [20000, 'd2', 'LOST_ON_SHUTDOWN'],
    ]);
    for (const deliveryId of ['d1', 'd2']) {
      expect(await outbox.getDelivery({ deliveryId })).toMatchObject({
        value: {
          state: 'LOST_ON_SHUTDOWN',
          terminal: true,
          attempts: 1,
          createdAt: 12000,
          deadlineAt: 132000,
          lastCode: null,
          relayOutcomes: [
            { relayIndex: 0, outcome: 'PENDING' },
            { relayIndex: 1, outcome: 'PENDING' },
          ],
        },
      });
    }
    // Every handle this module held reached clearTimer exactly once.
    expect(clock.state.clearCalls.length).toBe(2);
    expect(new Set(clock.state.clearCalls.map((handle) => handle.timer)).size).toBe(2);
    // No attempt timeout, no retry and no acceptance is recorded afterwards.
    await clock.advance(16010);
    expect(clock.state.now).toBe(36010);
    expect(events.length).toBe(4);
    expect(relaySet.attempts.length).toBe(2);
    // C-DLV sections 4.6 step (1) and 5.3: the attempt timeout of each item
    // fires at 24000, 12010 ms before this read, and 36010 is the read the
    // ratified timeline fixes. The outcomes are frozen at their admission
    // values, so an entry in PENDING stays PENDING and the item never shows a
    // TIMED_OUT that the stopped client did not record.
    for (const deliveryId of ['d1', 'd2']) {
      expect((await outbox.getDelivery({ deliveryId })).value).toMatchObject({
        state: 'LOST_ON_SHUTDOWN',
        terminal: true,
        relayOutcomes: [
          { relayIndex: 0, outcome: 'PENDING' },
          { relayIndex: 1, outcome: 'PENDING' },
        ],
      });
    }
    // A stopped client serves no further state-changing call.
    expect(await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD })).toEqual({
      ok: false,
      code: 'E_SDK_CLIENT_STOPPED',
    });
    expect(await outbox.cancel({ deliveryId: 'd1' })).toEqual({
      ok: false,
      code: 'E_SDK_CLIENT_STOPPED',
    });
    expect(await outbox.shutdown()).toEqual({ ok: false, code: 'E_SDK_CLIENT_STOPPED' });
    // The writes of the step 4 are the two LOST_ON_SHUTDOWN records.
    const lostWrites = storage.calls.update.filter((record) => record.state === 'LOST_ON_SHUTDOWN');
    expect(lostWrites.length).toBe(2);
    expect(storage.calls.put.length).toBe(2);
  });

  test('queueRestartLost / nonEmptyStoreRefused: the storage checks of section 5.2 in their fixed order', async () => {
    const record = (overrides) => ({
      deliveryId: 'd1',
      recipient: RECIPIENT,
      receiptMode: 'RELAY_ACCEPTANCE_ONLY',
      state: 'LOST_ON_SHUTDOWN',
      attempts: 1,
      createdAt: 12000,
      deadlineAt: 132000,
      lastCode: null,
      relayOutcomes: [
        { relayIndex: 0, outcome: 'PENDING' },
        { relayIndex: 1, outcome: 'PENDING' },
      ],
      ciphertext: null,
      event: null,
      ...overrides,
    });

    const empty = makeHarness();
    expect(await empty.outbox.inspectStore()).toEqual({ ok: true, value: { empty: true } });
    await empty.outbox.shutdown();

    const nonEmpty = makeHarness();
    nonEmpty.storage.listResult = () => [record()];
    expect(await nonEmpty.outbox.inspectStore()).toEqual({
      ok: false,
      code: 'E_SDK_STORAGE_NOT_EMPTY',
    });
    await nonEmpty.outbox.shutdown();

    const twoRecords = makeHarness();
    twoRecords.storage.listResult = () => [record({ deliveryId: 'd1' }), record({ deliveryId: 'd2' })];
    expect(await twoRecords.outbox.inspectStore()).toEqual({
      ok: false,
      code: 'E_SDK_STORAGE_NOT_EMPTY',
    });
    await twoRecords.outbox.shutdown();

    // A closed slot outside its closed set is E_SDK_UNKNOWN_CODE, before the
    // shape check and before the emptiness rule.
    const unknownState = makeHarness();
    unknownState.storage.listResult = () => [record({ state: 'SOMETHING_ELSE' })];
    expect(await unknownState.outbox.inspectStore()).toEqual({
      ok: false,
      code: 'E_SDK_UNKNOWN_CODE',
    });
    await unknownState.outbox.shutdown();

    const unknownOutcome = makeHarness();
    unknownOutcome.storage.listResult = () => [
      record({ relayOutcomes: [{ relayIndex: 0, outcome: 'MAYBE' }] }),
    ];
    expect(await unknownOutcome.outbox.inspectStore()).toEqual({
      ok: false,
      code: 'E_SDK_UNKNOWN_CODE',
    });
    await unknownOutcome.outbox.shutdown();

    const unknownCode = makeHarness();
    unknownCode.storage.listResult = () => [record({ lastCode: 'E_SDK_SOMETHING' })];
    expect(await unknownCode.outbox.inspectStore()).toEqual({
      ok: false,
      code: 'E_SDK_UNKNOWN_CODE',
    });
    await unknownCode.outbox.shutdown();

    // A different shape, an element that is not a plain object, a non-array and
    // a fault are all E_SDK_STORAGE_FAILED. A stored record carries no `code`
    // slot (C-DLV section 6.4 has eleven fields), so one is a shape failure and
    // not the E_SDK_UNKNOWN_CODE of a closed slot.
    for (const listResult of [
      () => [record({ extra: 1 })],
      () => [record({ code: 'E_SDK_NOT_A_CODE' })],
      () => ['d1'],
      () => 'not-an-array',
      () => null,
      () => {
        throw new Error('list');
      },
    ]) {
      const harness = makeHarness();
      harness.storage.listResult = listResult;
      expect(await harness.outbox.inspectStore()).toEqual({
        ok: false,
        code: 'E_SDK_STORAGE_FAILED',
      });
      await harness.outbox.shutdown();
    }

    // A closed slot that is present but undefined is still outside its set.
    const undefinedState = makeHarness();
    undefinedState.storage.listResult = () => [record({ state: undefined })];
    expect(await undefinedState.outbox.inspectStore()).toEqual({
      ok: false,
      code: 'E_SDK_UNKNOWN_CODE',
    });
    await undefinedState.outbox.shutdown();
  });
});

/* ------------------------------------------------------------------------- *
 * Port faults, unknown values and the bounded calls of C-DLV section 4.5.
 * ------------------------------------------------------------------------- */

describe('port faults and unknown values (C-DLV section 4.5)', () => {
  test('an identity fault, a random fault and a clock fault at the attempt start fail the item with the code C-DLV fixes', async () => {
    // A signing fault: E_SDK_IDENTITY_FAILED, no attempt timeout and no publish.
    const signing = makeHarness({
      identity: makeIdentity({
        sign: () => {
          throw new Error('sign');
        },
      }),
    });
    signing.clock.state.now = 0;
    await signing.outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    expect(await signing.outbox.getDelivery({ deliveryId: 'd1' })).toMatchObject({
      value: {
        state: 'FAILED_NOT_ACCEPTED',
        lastCode: 'E_SDK_IDENTITY_FAILED',
        // C-DLV section 4.3: the attempt started (QUEUED -> IN_FLIGHT and the
        // count) before the first signature, and a failed signing is terminal.
        attempts: 1,
        relayOutcomes: [
          { relayIndex: 0, outcome: 'PENDING' },
          { relayIndex: 1, outcome: 'PENDING' },
        ],
      },
    });
    expect(signing.relaySet.attempts.length).toBe(0);
    await signing.outbox.shutdown();

    // A public key that is not a lowercase 64-hex string is E_SDK_IDENTITY_FAILED.
    const key = makeHarness({ identity: makeIdentity({ getPublicKey: () => 'ABCD' }) });
    key.clock.state.now = 0;
    await key.outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    expect((await key.outbox.getDelivery({ deliveryId: 'd1' })).value.lastCode).toBe(
      'E_SDK_IDENTITY_FAILED',
    );
    await key.outbox.shutdown();

    // A signature that is not 64 bytes is E_SDK_IDENTITY_FAILED.
    const short = makeHarness({ identity: makeIdentity({ sign: () => new Uint8Array(32) }) });
    short.clock.state.now = 0;
    await short.outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    expect((await short.outbox.getDelivery({ deliveryId: 'd1' })).value.lastCode).toBe(
      'E_SDK_IDENTITY_FAILED',
    );
    await short.outbox.shutdown();

    // A random fault reaches the retry decision of I-RETRY: E_SDK_INTERNAL.
    const randomFault = makeHarness({ randomThrows: true });
    randomFault.clock.state.now = 0;
    await randomFault.outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    await randomFault.clock.advanceUntil(
      () => randomFault.outbox.getDelivery({ deliveryId: 'd1' }).then((snap) => snap.value.terminal),
      { sliceMs: 100 },
    );
    expect(await randomFault.outbox.getDelivery({ deliveryId: 'd1' })).toMatchObject({
      value: { state: 'FAILED_NOT_ACCEPTED', lastCode: 'E_SDK_INTERNAL' },
    });
    await randomFault.outbox.shutdown();

    // A clock that throws at the attempt start is E_SDK_INTERNAL. The
    // admission reads the clock once at step 4; the attempt start is the next
    // reading, and it faults. No relay is published to and no attempt timeout
    // is armed, so no relay outcome of that attempt is set.
    const clockFault = makeHarness();
    clockFault.clock.state.now = 0;
    const realNow = clockFault.clock.port.now;
    let readings = 0;
    clockFault.clock.port.now = () => {
      readings += 1;
      if (readings > 1) throw new Error('now');
      return realNow();
    };
    const faulted = await clockFault.outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    expect(faulted.ok).toBe(true);
    await flush();
    expect(await clockFault.outbox.getDelivery({ deliveryId: 'd1' })).toMatchObject({
      value: {
        state: 'FAILED_NOT_ACCEPTED',
        lastCode: 'E_SDK_INTERNAL',
        relayOutcomes: [
          { relayIndex: 0, outcome: 'PENDING' },
          { relayIndex: 1, outcome: 'PENDING' },
        ],
      },
    });
    expect(clockFault.relaySet.attempts.length).toBe(0);
    await clockFault.outbox.shutdown();
  });

  test('an outcome outside the closed set of C-SDK section 6.3 is E_SDK_UNKNOWN_CODE', async () => {
    const { outbox, clock, relaySet } = makeHarness();
    clock.state.now = 0;
    await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    // The seam reports a name that is not an outcome of the closed set.
    relaySet.attempts[0].force(0, 'SOMETIME');
    await flush();
    const snapshot = await outbox.getDelivery({ deliveryId: 'd1' });
    expect(snapshot.value.state).toBe('FAILED_NOT_ACCEPTED');
    expect(snapshot.value.lastCode).toBe('E_SDK_UNKNOWN_CODE');
    await outbox.shutdown();
  });

  test('a closed slot outside its closed set in a port return is E_SDK_UNKNOWN_CODE and takes precedence', async () => {
    const session = makeSession({
      seal: () => ({ ciphertext: new Uint8Array([1]), code: 'E_SDK_NONSENSE' }),
    });
    const { outbox } = makeHarness({ session });
    expect(await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD })).toEqual({
      ok: false,
      code: 'E_SDK_UNKNOWN_CODE',
    });
    await outbox.shutdown();

    // A storage update that answers with an unknown code during a background
    // write moves the item with E_SDK_UNKNOWN_CODE, not with the storage code.
    const storage = makeStorage();
    storage.updateResult = () => ({ code: 'E_SDK_NONSENSE' });
    const second = makeHarness({ storage });
    second.clock.state.now = 0;
    await second.outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    await flush();
    expect(await second.outbox.getDelivery({ deliveryId: 'd1' })).toMatchObject({
      value: { state: 'FAILED_NOT_ACCEPTED', lastCode: 'E_SDK_UNKNOWN_CODE' },
    });
    await second.outbox.shutdown();
  });

  test('a storage write that fails during background processing fails the item with E_SDK_STORAGE_FAILED', async () => {
    const storage = makeStorage();
    storage.updateResult = () => false;
    const { outbox, clock } = makeHarness({ storage });
    clock.state.now = 0;
    await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    await flush();
    expect(await outbox.getDelivery({ deliveryId: 'd1' })).toMatchObject({
      value: { state: 'FAILED_NOT_ACCEPTED', lastCode: 'E_SDK_STORAGE_FAILED' },
    });
    await outbox.shutdown();
  });

  test('a publication seam that is absent, is not a function, throws or returns a malformed attempt is E_SDK_INTERNAL', async () => {
    for (const publish of [
      undefined,
      42,
      () => {
        throw new Error('publish');
      },
      () => ({ outcomes: [] }),
      () => ({ onOutcome: () => {}, onSettled: () => {}, outcomes: 'no' }),
      () => null,
    ]) {
      const { outbox, clock } = makeHarness({ publish });
      clock.state.now = 0;
      await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
      await flush();
      expect(await outbox.getDelivery({ deliveryId: 'd1' })).toMatchObject({
        value: { state: 'FAILED_NOT_ACCEPTED', lastCode: 'E_SDK_INTERNAL' },
      });
      await outbox.shutdown();
    }
  });

  test('a seal that never settles is bounded by the port-call timeout, floor(perRelayTimeoutMs / 2)', async () => {
    const session = makeSession({ seal: () => new Promise(() => {}) });
    const { outbox, clock } = makeHarness({
      session,
      delivery: { ...DELIVERY, perRelayTimeoutMs: 11000 },
    });
    clock.state.now = 0;
    const started = Date.now();
    expect(await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD })).toEqual({
      ok: false,
      code: 'E_SDK_SESSION_FAILED',
    });
    expect(Date.now() - started).toBeGreaterThanOrEqual(5000);
    expect(Date.now() - started).toBeLessThan(11000);
    await outbox.shutdown();
  }, 20000);

  test('the deadline backstop of section 4.4 holds when the clock port drops its timer', async () => {
    const { outbox, clock, events } = makeHarness({
      delivery: { maxAttempts: 5, deadlineMs: 30000, perRelayTimeoutMs: 12000, receiptMode: 'RELAY_ACCEPTANCE_ONLY' },
    });
    clock.state.now = 0;
    await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    // The clock port arms nothing from here on: only the host backstop can end
    // the item, and it does so within deadlineMs + 1000 ms of host time.
    clock.state.ignoreSetTimer = true;
    const started = Date.now();
    for (;;) {
      const snapshot = await outbox.getDelivery({ deliveryId: 'd1' });
      if (snapshot.value.terminal) break;
      if (Date.now() - started > 32000) break;
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    const elapsed = Date.now() - started;
    const snapshot = await outbox.getDelivery({ deliveryId: 'd1' });
    expect(snapshot.value.state).toBe('FAILED_NOT_ACCEPTED');
    expect(snapshot.value.terminal).toBe(true);
    expect(snapshot.value.lastCode).toBe(null);
    // The backstop is armed at deadlineMs + 1000 ms of host time, so the elapsed
    // host time is about 31000: the two bounds below are discriminating (a
    // backstop at deadlineMs itself would land near 30000) and tolerate the
    // millisecond rounding of a host timer and the polling granularity.
    expect(elapsed).toBeGreaterThanOrEqual(30900);
    expect(elapsed).toBeLessThan(31300);
    expect(events[events.length - 1].state).toBe('FAILED_NOT_ACCEPTED');
    await outbox.shutdown();
  }, 40000);
});

/* ------------------------------------------------------------------------- *
 * Cancel, retry, retention and shutdown continuations (C-DLV section 4.6).
 * ------------------------------------------------------------------------- */

describe('cancel, retry, retention and shutdown continuations (C-DLV section 4.6)', () => {
  test('cancel writes the item record in state CANCELLED and only then commits', async () => {
    const { outbox, clock, storage, relaySet, events } = makeHarness();
    clock.state.now = 0;
    await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    const cancel = await outbox.cancel({ deliveryId: 'd1' });
    expect(cancel).toEqual({ ok: true, value: { deliveryId: 'd1', state: 'CANCELLED' } });
    // The write carried the CANCELLED record, and it happened before the commit.
    const written = storage.calls.update[storage.calls.update.length - 1];
    expect(written.state).toBe('CANCELLED');
    expect(storage.records.get('d1').state).toBe('CANCELLED');
    expect(events[events.length - 1].state).toBe('CANCELLED');
    expect(relaySet.attempts[0].ignoreState()).toBe(true);
    // A terminal item refuses a second cancel.
    expect(await outbox.cancel({ deliveryId: 'd1' })).toEqual({
      ok: false,
      code: 'E_SDK_DELIVERY_TERMINAL',
    });
    expect(await outbox.cancel({ deliveryId: 'd99' })).toEqual({
      ok: false,
      code: 'E_SDK_UNKNOWN_DELIVERY',
    });
    await outbox.shutdown();
  });

  test('a cancel write that fails changes nothing and reports E_SDK_STORAGE_FAILED', async () => {
    const storage = makeStorage();
    const { outbox, clock, events, relaySet } = makeHarness({ storage });
    clock.state.now = 0;
    await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    storage.updateResult = (deliveryId, record) => record.state !== 'CANCELLED';
    const cancel = await outbox.cancel({ deliveryId: 'd1' });
    expect(cancel).toEqual({ ok: false, code: 'E_SDK_STORAGE_FAILED' });
    const snapshot = await outbox.getDelivery({ deliveryId: 'd1' });
    expect(snapshot.value.state).toBe('IN_FLIGHT');
    expect(events.map((event) => event.state)).toEqual(['IN_FLIGHT']);
    // No attempt started and no retry was armed by the failed cancel.
    expect(relaySet.attempts.length).toBe(1);
    await outbox.shutdown();
  });

  test('a retry that falls due while the cancel write is in progress waits for it', async () => {
    const storage = makeStorage();
    const { outbox, clock, relaySet } = makeHarness({ storage });
    clock.state.now = 0;
    await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    // The attempt times out and a retry is armed; the retry falls due while the
    // cancel write is held open.
    let release = null;
    storage.updateResult = (deliveryId, record) => {
      if (record.state !== 'CANCELLED') return true;
      return new Promise((resolve) => {
        release = () => resolve(false);
      });
    };
    await clock.advance(12000);
    const cancelling = outbox.cancel({ deliveryId: 'd1' });
    await flush();
    const attemptsBefore = relaySet.attempts.length;
    await clock.advance(5000);
    expect(relaySet.attempts.length).toBe(attemptsBefore);
    release();
    const cancel = await cancelling;
    expect(cancel).toEqual({ ok: false, code: 'E_SDK_STORAGE_FAILED' });
    await flush();
    // The deferred retry starts at once, from the state the item still has.
    expect(relaySet.attempts.length).toBe(attemptsBefore + 1);
    await outbox.shutdown();
  });

  test('two cancels for the same item resolve with the result of the one write in progress', async () => {
    const storage = makeStorage();
    const { outbox, clock } = makeHarness({ storage });
    clock.state.now = 0;
    await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    let release = null;
    let held = 0;
    storage.updateResult = (deliveryId, record) => {
      if (record.state !== 'CANCELLED' || held > 0) return true;
      held += 1;
      return new Promise((resolve) => {
        release = () => resolve(true);
      });
    };
    const first = outbox.cancel({ deliveryId: 'd1' });
    await flush();
    const second = outbox.cancel({ deliveryId: 'd1' });
    release();
    expect(await first).toEqual({ ok: true, value: { deliveryId: 'd1', state: 'CANCELLED' } });
    expect(await second).toEqual({ ok: true, value: { deliveryId: 'd1', state: 'CANCELLED' } });
    await outbox.shutdown();
  });

  test('a send before its put resolves E_SDK_CLIENT_STOPPED with no item, and a send past its put keeps its item as LOST_ON_SHUTDOWN', async () => {
    // The seal is held open, so the send is before its put when shutdown lands.
    let releaseSeal = null;
    const session = makeSession({
      seal: () =>
        new Promise((resolve) => {
          releaseSeal = () => resolve({ ciphertext: new Uint8Array([1, 2, 3]) });
        }),
    });
    const before = makeHarness({ storage: makeStorage(), session });
    before.clock.state.now = 0;
    const pending = before.outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    const stoppingBefore = before.outbox.shutdown();
    await flush();
    releaseSeal();
    expect(await pending).toEqual({ ok: false, code: 'E_SDK_CLIENT_STOPPED' });
    const stop = await stoppingBefore;
    expect(stop.value).toEqual({ clientState: 'STOPPED', lost: 0 });
    expect(before.storage.calls.put.length).toBe(0);
    expect(await before.outbox.getDelivery({ deliveryId: 'd1' })).toEqual({
      ok: false,
      code: 'E_SDK_UNKNOWN_DELIVERY',
    });
    expect(before.events.length).toBe(0);

    // The put is held open, so the send is past it when shutdown lands.
    const heldPut = makeStorage();
    let releasePut = null;
    heldPut.putResult = () =>
      new Promise((resolve) => {
        releasePut = () => resolve(true);
      });
    const after = makeHarness({ storage: heldPut });
    after.clock.state.now = 0;
    const admitted = after.outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    const stopping = after.outbox.shutdown();
    await flush();
    releasePut();
    expect(await admitted).toEqual({ ok: true, value: { deliveryId: 'd1', state: 'QUEUED' } });
    const stopAfter = await stopping;
    expect(stopAfter.value).toEqual({ clientState: 'STOPPED', lost: 1 });
    expect(await after.outbox.getDelivery({ deliveryId: 'd1' })).toMatchObject({
      value: { state: 'LOST_ON_SHUTDOWN', terminal: true },
    });
    expect(after.events.map((event) => event.state)).toEqual(['LOST_ON_SHUTDOWN']);
    // The item was never published.
    expect(after.relaySet.attempts.length).toBe(0);
  });

  test('a terminal item takes no further transition and its writes are ordered', async () => {
    const { outbox, clock, storage, relaySet } = makeHarness();
    clock.state.now = 0;
    await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    relaySet.attempts[0].answer(0, 'ACCEPTED');
    await flush();
    const writtenStates = storage.calls.update.map((record) => record.state);
    expect(writtenStates).toEqual(['IN_FLIGHT', 'RELAY_ACCEPTED']);
    // The attempt timeout settles the other entry without a second transition.
    await clock.advance(12000);
    const written = storage.calls.update.map((record) => record.state);
    expect(written).toEqual(['IN_FLIGHT', 'RELAY_ACCEPTED']);
    expect((await outbox.getDelivery({ deliveryId: 'd1' })).value.state).toBe('RELAY_ACCEPTED');
    await outbox.shutdown();
  });

  test('an acknowledgement that arrives once the item is terminal is recorded in relayOutcomes and moves no state (C-DLV 4.1, 4.6)', async () => {
    const { outbox, relaySet, events } = makeHarness({
      delivery: { ...DELIVERY, receiptMode: 'RELAY_ACCEPTANCE_ONLY' },
      relayCount: 2,
    });
    await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    expect(relaySet.attempts[0].answer(0, 'ACCEPTED')).toBe(true);
    await flush();
    expect((await outbox.getDelivery({ deliveryId: 'd1' })).value).toMatchObject({
      state: 'RELAY_ACCEPTED',
      relayOutcomes: [{ relayIndex: 0, outcome: 'ACCEPTED' }, { relayIndex: 1, outcome: 'PENDING' }],
    });
    // C-DLV sections 4.6 and 5.3: an `OK true` still acts on the outcomes of
    // its attempt after the item left IN_FLIGHT (`RELAY_ACCEPTED` is not one of
    // the three states that ignore it), so the acceptance gate admits it — it
    // refuses only a reading at or after the deadline while the item is still
    // IN_FLIGHT — and it changes the item's state only while the item is
    // IN_FLIGHT in that same attempt, so no state and no event.
    expect(relaySet.attempts[0].answer(1, 'ACCEPTED')).toBe(true);
    await flush();
    expect((await outbox.getDelivery({ deliveryId: 'd1' })).value).toMatchObject({
      state: 'RELAY_ACCEPTED',
      relayOutcomes: [{ relayIndex: 0, outcome: 'ACCEPTED' }, { relayIndex: 1, outcome: 'ACCEPTED' }],
    });
    expect(events.map((event) => event.state)).toEqual(['IN_FLIGHT', 'RELAY_ACCEPTED']);
    await outbox.shutdown();
  });

  test('the acceptance gate of section 4.6 admits a later relay once the item left IN_FLIGHT, also at or after the deadline, and refuses while it is still IN_FLIGHT', async () => {
    const { outbox, clock, relaySet } = makeHarness({
      delivery: { ...DELIVERY, deadlineMs: 30000, perRelayTimeoutMs: 12000, receiptMode: 'RECIPIENT_RECEIPT' },
      relayCount: 2,
    });
    clock.state.now = 0;
    await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    const attempt = relaySet.attempts[0];
    // Still IN_FLIGHT and before the deadline: the gate admits the answer.
    clock.state.now = 29999;
    expect(attempt.acceptGate(0, attempt)).toBe(true);
    expect(attempt.answer(0, 'ACCEPTED')).toBe(true);
    await flush();
    expect((await outbox.getDelivery({ deliveryId: 'd1' })).value.state).toBe(
      'RELAY_ACCEPTED_AWAITING_RECEIPT',
    );
    // The item has left IN_FLIGHT, so its only deadline condition does not
    // apply: the second relay's `OK true` keeps settling its own entry, even at
    // or after the deadline (C-DLV sections 4.6 and 5.3). The gate that refused
    // every state but IN_FLIGHT would drop this answer instead.
    clock.state.now = 30000;
    expect(attempt.acceptGate(1, attempt)).toBe(true);
    expect(attempt.answer(1, 'ACCEPTED')).toBe(true);
    await flush();
    expect((await outbox.getDelivery({ deliveryId: 'd1' })).value).toMatchObject({
      state: 'RELAY_ACCEPTED_AWAITING_RECEIPT',
      relayOutcomes: [{ relayIndex: 0, outcome: 'ACCEPTED' }, { relayIndex: 1, outcome: 'ACCEPTED' }],
    });
    await outbox.shutdown();
  });

  test('an OK frame that arrives after FAILED_NOT_ACCEPTED, CANCELLED or LOST_ON_SHUTDOWN is ignored (C-DLV 4.6)', async () => {
    const { outbox, clock, relaySet } = makeHarness({
      delivery: { ...DELIVERY, receiptMode: 'RELAY_ACCEPTANCE_ONLY', maxAttempts: 1 },
    });
    await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    // With maxAttempts 1, the attempt timeout settles both lanes and exhausts
    // the attempts: FAILED_NOT_ACCEPTED with lastCode null.
    await clock.advance(12000);
    expect((await outbox.getDelivery({ deliveryId: 'd1' })).value).toMatchObject({
      state: 'FAILED_NOT_ACCEPTED',
      relayOutcomes: [{ relayIndex: 0, outcome: 'TIMED_OUT' }, { relayIndex: 1, outcome: 'TIMED_OUT' }],
    });
    relaySet.attempts[0].force(1, 'ACCEPTED');
    await flush();
    expect((await outbox.getDelivery({ deliveryId: 'd1' })).value).toMatchObject({
      state: 'FAILED_NOT_ACCEPTED',
      relayOutcomes: [{ relayIndex: 0, outcome: 'TIMED_OUT' }, { relayIndex: 1, outcome: 'TIMED_OUT' }],
    });
    // C-DLV section 5.3: the settle window of this item admits only the attempt
    // timeout, so a supervision loss reported afterwards is not mirrored.
    relaySet.attempts[0].force(1, 'UNREACHABLE');
    await flush();
    expect((await outbox.getDelivery({ deliveryId: 'd1' })).value).toMatchObject({
      state: 'FAILED_NOT_ACCEPTED',
      relayOutcomes: [{ relayIndex: 0, outcome: 'TIMED_OUT' }, { relayIndex: 1, outcome: 'TIMED_OUT' }],
    });
    await outbox.shutdown();
  });

  test('the attempt timeout still settles a PENDING entry after the item left IN_FLIGHT (C-DLV 4.1, 5.3)', async () => {
    const { outbox, clock, relaySet, events } = makeHarness({
      delivery: { ...DELIVERY, receiptMode: 'RELAY_ACCEPTANCE_ONLY' },
      relayCount: 2,
    });
    await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    relaySet.attempts[0].answer(0, 'ACCEPTED');
    await flush();
    expect((await outbox.getDelivery({ deliveryId: 'd1' })).value).toMatchObject({
      state: 'RELAY_ACCEPTED',
      relayOutcomes: [{ relayIndex: 0, outcome: 'ACCEPTED' }, { relayIndex: 1, outcome: 'PENDING' }],
    });
    // The attempt timeout settles the lane that never answered, although the
    // item is no longer IN_FLIGHT, and emits no further event.
    await clock.advance(12000);
    expect((await outbox.getDelivery({ deliveryId: 'd1' })).value).toMatchObject({
      state: 'RELAY_ACCEPTED',
      relayOutcomes: [{ relayIndex: 0, outcome: 'ACCEPTED' }, { relayIndex: 1, outcome: 'TIMED_OUT' }],
    });
    expect(events.map((event) => event.state)).toEqual(['IN_FLIGHT', 'RELAY_ACCEPTED']);
    await outbox.shutdown();
  });

  test('an event signed at or after the deadline is never published: the deadline transition applies instead (C-DLV 4.4)', async () => {
    const clock = makeClock();
    const session = makeSession();
    // The signature completes at exactly deadlineAt.
    const identity = makeIdentity({
      sign() {
        clock.state.now = 30000;
        return new Uint8Array(64);
      },
    });
    const { outbox, relaySet, storage } = makeHarness({
      clockPort: clock.port,
      session,
      identity,
      delivery: { ...DELIVERY, deadlineMs: 30000 },
    });
    expect(await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD })).toEqual({
      ok: true,
      value: { deliveryId: 'd1', state: 'QUEUED' },
    });
    await flush();
    expect(relaySet.attempts.length).toBe(0);
    expect((await outbox.getDelivery({ deliveryId: 'd1' })).value).toMatchObject({
      state: 'FAILED_NOT_ACCEPTED',
      terminal: true,
      attempts: 1,
      lastCode: null,
    });
    // C-DLV section 4.3: the attempt moved the item to IN_FLIGHT before the
    // signature, so the IN_FLIGHT record precedes the deadline transition.
    expect(storage.calls.update.map((record) => record.state)).toEqual([
      'IN_FLIGHT',
      'FAILED_NOT_ACCEPTED',
    ]);
    await outbox.shutdown();
  });

  test('shutdown waits for every admission in progress before step (2) ends (C-DLV 4.6 step 2)', async () => {
    const gates = [];
    const session = makeSession({
      seal: () => new Promise((resolve) => {
        gates.push(() => resolve({ ciphertext: new Uint8Array([1, 2, 3]) }));
      }),
    });
    const { outbox, clock, relaySet } = makeHarness({ session: session });
    const first = outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    const second = outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    expect(gates.length).toBe(2);
    let resolved = false;
    const stopping = outbox.shutdown().then((result) => {
      resolved = true;
      return result;
    });
    await flush();
    expect(resolved).toBe(false);
    gates[0]();
    await flush();
    expect(resolved).toBe(false);
    gates[1]();
    expect(await first).toEqual({ ok: false, code: 'E_SDK_CLIENT_STOPPED' });
    expect(await second).toEqual({ ok: false, code: 'E_SDK_CLIENT_STOPPED' });
    expect(await stopping).toEqual({ ok: true, value: { clientState: 'STOPPED', lost: 0 } });
    expect(relaySet.attempts.length).toBe(0);
    void clock;
  });

  test('a put that fails after shutdown still takes the one remove, and the residual rule takes precedence over the stop (C-DLV 4.2, 4.6 step 2)', async () => {
    // A failed put whose remove succeeds: no item is left and nothing is kept.
    const storage = makeStorage();
    let releasePut = null;
    storage.putResult = () => new Promise((resolve) => {
      releasePut = () => resolve(false);
    });
    const first = makeHarness({ storage });
    const pending = first.outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    const stopping = first.outbox.shutdown();
    await flush();
    releasePut();
    expect(await pending).toEqual({ ok: false, code: 'E_SDK_STORAGE_FAILED' });
    expect(storage.calls.remove).toEqual(['d1']);
    expect(await stopping).toEqual({ ok: true, value: { clientState: 'STOPPED', lost: 0 } });
    expect(await first.outbox.getDelivery({ deliveryId: 'd1' })).toEqual({
      ok: false,
      code: 'E_SDK_UNKNOWN_DELIVERY',
    });
    expect(first.relaySet.attempts.length).toBe(0);

    // A failed put whose one remove returns false is a successful cleanup too.
    const third = makeStorage({ removeResult: false });
    let releaseThird = null;
    third.putResult = () => new Promise((resolve) => {
      releaseThird = () => resolve(false);
    });
    const cleaned = makeHarness({ storage: third });
    const pendingThird = cleaned.outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    releaseThird();
    expect(await pendingThird).toEqual({ ok: false, code: 'E_SDK_STORAGE_FAILED' });
    expect(third.calls.remove).toEqual(['d1']);
    expect(await cleaned.outbox.getDelivery({ deliveryId: 'd1' })).toEqual({
      ok: false,
      code: 'E_SDK_UNKNOWN_DELIVERY',
    });
    await cleaned.outbox.shutdown();

    // A `remove` return carrying an unknown closed slot is E_SDK_UNKNOWN_CODE
    // and takes precedence over the code of the failed `put` (C-DLV 4.5,
    // C-SDK 5.3), with the residual item too.
    const fourth = makeStorage({
      putResult: false,
      removeResult: () => ({ code: 'E_SDK_NOT_A_CODE' }),
    });
    const precedence = makeHarness({ storage: fourth });
    expect(await precedence.outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD })).toEqual({
      ok: false,
      code: 'E_SDK_UNKNOWN_CODE',
    });
    expect(precedence.events.map((event) => event.state)).toEqual(['FAILED_NOT_ACCEPTED']);
    expect((await precedence.outbox.getDelivery({ deliveryId: 'd1' })).value).toMatchObject({
      state: 'FAILED_NOT_ACCEPTED',
      lastCode: 'E_SDK_UNKNOWN_CODE',
      terminal: true,
    });
    expect(precedence.relaySet.attempts.length).toBe(0);
    await precedence.outbox.shutdown();

    // A failed put whose remove also fails: the residual item wins over the stop.
    const second = makeStorage();
    let releaseSecond = null;
    second.putResult = () => new Promise((resolve) => {
      releaseSecond = () => resolve(false);
    });
    second.removeResult = () => {
      throw new Error('remove');
    };
    const residual = makeHarness({ storage: second });
    const pendingSecond = residual.outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    const stoppingSecond = residual.outbox.shutdown();
    await flush();
    releaseSecond();
    expect(await pendingSecond).toEqual({ ok: false, code: 'E_SDK_STORAGE_FAILED' });
    // C-DLV section 4.2: the residual item is reported only as a
    // FAILED_NOT_ACCEPTED item, so it is not counted among the lost ones.
    expect(await stoppingSecond).toEqual({ ok: true, value: { clientState: 'STOPPED', lost: 0 } });
    expect(residual.events.map((event) => event.state)).toEqual(['FAILED_NOT_ACCEPTED']);
    await flush();
    expect((await residual.outbox.getDelivery({ deliveryId: 'd1' })).value).toMatchObject({
      state: 'FAILED_NOT_ACCEPTED',
      lastCode: 'E_SDK_STORAGE_FAILED',
      terminal: true,
    });
    expect(residual.relaySet.attempts.length).toBe(0);
  });

  test('a deadline that fires while put is pending only latches, and no event precedes admission (C-DLV 4.2)', async () => {
    const storage = makeStorage();
    let releasePut = null;
    storage.putResult = () => new Promise((resolve) => {
      releasePut = () => resolve(true);
    });
    const { outbox, clock, events } = makeHarness({ storage });
    const pending = outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    // The deadline callback runs while the item has not been admitted by `put`.
    await clock.advance(120000);
    expect(events).toEqual([]);
    releasePut();
    expect(await pending).toEqual({ ok: true, value: { deliveryId: 'd1', state: 'QUEUED' } });
    await flush();
    expect(events.map((event) => event.state)).toEqual(['FAILED_NOT_ACCEPTED']);
    expect((await outbox.getDelivery({ deliveryId: 'd1' })).value).toMatchObject({
      state: 'FAILED_NOT_ACCEPTED',
      attempts: 0,
      lastCode: null,
      terminal: true,
    });
    await outbox.shutdown();
  });

  test('a cancel whose update return carries an unknown code is E_SDK_UNKNOWN_CODE with the applicable failed state (C-SDK 5.3, C-DLV 4.5)', async () => {
    const storage = makeStorage();
    storage.updateResult = (deliveryId, record) =>
      record.state === 'CANCELLED' ? { code: 'E_SDK_NOT_A_CODE' } : true;
    const { outbox } = makeHarness({ storage });
    await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    expect(await outbox.cancel({ deliveryId: 'd1' })).toEqual({
      ok: false,
      code: 'E_SDK_UNKNOWN_CODE',
    });
    expect((await outbox.getDelivery({ deliveryId: 'd1' })).value).toMatchObject({
      state: 'FAILED_NOT_ACCEPTED',
      lastCode: 'E_SDK_UNKNOWN_CODE',
      terminal: true,
    });
    await outbox.shutdown();
  });

  test('an ordinary write not yet issued is dropped by shutdown, while a write in progress is awaited (C-DLV 4.6)', async () => {
    const storage = makeStorage();
    let releaseUpdate = null;
    let held = 0;
    storage.updateResult = (deliveryId, record) => {
      if (record.state !== 'IN_FLIGHT' || held > 0) return true;
      held += 1;
      return new Promise((resolve) => {
        releaseUpdate = () => resolve(true);
      });
    };
    const { outbox, clock } = makeHarness({
      storage,
      delivery: { ...DELIVERY, maxAttempts: 1 },
    });
    await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    // The attempt timeout exhausts the single attempt: the item becomes
    // FAILED_NOT_ACCEPTED and its record write queues behind the held one.
    await clock.advance(12000);
    expect((await outbox.getDelivery({ deliveryId: 'd1' })).value.state).toBe(
      'FAILED_NOT_ACCEPTED',
    );
    const stopping = outbox.shutdown();
    await flush();
    releaseUpdate();
    expect(await stopping).toEqual({ ok: true, value: { clientState: 'STOPPED', lost: 0 } });
    // The held write settled; the record of the transition that was only
    // queued when shutdown() was called was never issued.
    await flush();
    expect(storage.calls.update.map((record) => record.state)).toEqual(['IN_FLIGHT']);
    expect((await outbox.getDelivery({ deliveryId: 'd1' })).value.state).toBe(
      'FAILED_NOT_ACCEPTED',
    );
  });

  test('a clock fault at the acceptance gate fails the item with E_SDK_INTERNAL, not with the deadline transition (C-DLV 4.4, 4.5)', async () => {
    const { outbox, clock, relaySet } = makeHarness();
    await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    // The seam reports an acceptance although the clock port faults, so the
    // gate refuses it: the item takes its applicable failed state with
    // E_SDK_INTERNAL instead of the deadline transition.
    clock.state.nowThrows = true;
    relaySet.attempts[0].force(1, 'ACCEPTED');
    await flush();
    expect((await outbox.getDelivery({ deliveryId: 'd1' })).value).toMatchObject({
      state: 'FAILED_NOT_ACCEPTED',
      lastCode: 'E_SDK_INTERNAL',
      terminal: true,
    });
    // C-DLV section 5.3: the acceptance is checked before it is recorded, so the
    // entry stays PENDING and the item never shows a relay ACCEPTED it did not
    // record before its terminal state.
    expect((await outbox.getDelivery({ deliveryId: 'd1' })).value.relayOutcomes).toEqual([
      { relayIndex: 0, outcome: 'PENDING' },
      { relayIndex: 1, outcome: 'PENDING' },
    ]);
    clock.state.nowThrows = false;
    await outbox.shutdown();
  });

  test('an outcome reported after shutdown is dropped: the frozen relay outcomes never change (C-DLV 4.6 step 1, 5.3)', async () => {
    const { outbox, clock, relaySet } = makeHarness({
      delivery: { ...DELIVERY, receiptMode: 'RELAY_ACCEPTANCE_ONLY' },
      relayCount: 2,
    });
    await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    expect(relaySet.attempts[0].answer(0, 'ACCEPTED')).toBe(true);
    await flush();
    expect((await outbox.getDelivery({ deliveryId: 'd1' })).value).toMatchObject({
      state: 'RELAY_ACCEPTED',
      relayOutcomes: [
        { relayIndex: 0, outcome: 'ACCEPTED' },
        { relayIndex: 1, outcome: 'PENDING' },
      ],
    });
    expect((await outbox.shutdown()).ok).toBe(true);
    // The seam reports three outcomes after the stop: a rejection for the relay
    // still PENDING, a timeout for the attempt in progress and a rejection of
    // the relay that already accepted. C-DLV section 4.6 step (1) freezes every
    // relay outcome synchronously at the call, so none of them is mirrored and
    // the state does not move.
    relaySet.attempts[0].force(1, 'REJECTED');
    relaySet.attempts[0].force(0, 'REJECTED');
    relaySet.attempts[0].force(1, 'TIMED_OUT');
    await flush();
    await clock.advance(60000);
    expect((await outbox.getDelivery({ deliveryId: 'd1' })).value).toMatchObject({
      state: 'RELAY_ACCEPTED',
      terminal: true,
      relayOutcomes: [
        { relayIndex: 0, outcome: 'ACCEPTED' },
        { relayIndex: 1, outcome: 'PENDING' },
      ],
    });
  });

  test('a signature that carries an unknown closed slot is E_SDK_UNKNOWN_CODE although it is a Uint8Array (C-SDK 5.3, C-DLV 4.5)', async () => {
    const signed = new Uint8Array(64).fill(7);
    Object.defineProperty(signed, 'code', { value: 'E_SDK_NOT_A_CODE', enumerable: true });
    const { outbox, relaySet } = makeHarness({
      identity: {
        keyCalls: 0,
        signCalls: [],
        getPublicKey() {
          return PUBKEY;
        },
        sign({ digest }) {
          this.signCalls.push(digest);
          return signed;
        },
      },
    });
    await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    expect((await outbox.getDelivery({ deliveryId: 'd1' })).value).toMatchObject({
      state: 'FAILED_NOT_ACCEPTED',
      lastCode: 'E_SDK_UNKNOWN_CODE',
      terminal: true,
    });
    expect(relaySet.attempts.length).toBe(0);
    await outbox.shutdown();
  });

  test('shutdown drains a port call still in progress and the ordered write chain before the lost writes (C-DLV 4.6 step 4)', async () => {
    const storage = makeStorage();
    let releaseUpdate = null;
    let held = 0;
    storage.updateResult = (deliveryId, record) => {
      if (record.state !== 'RELAY_ACCEPTED_AWAITING_RECEIPT' || held > 0) return true;
      held += 1;
      return new Promise((resolve) => {
        releaseUpdate = () => resolve(true);
      });
    };
    const { outbox, relaySet } = makeHarness({
      storage,
      delivery: { ...DELIVERY, receiptMode: 'RECIPIENT_RECEIPT' },
    });
    await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    relaySet.attempts[0].answer(0, 'ACCEPTED');
    await flush();
    const stopping = outbox.shutdown();
    await flush();
    // The held write of the accepted item is still in progress, so no
    // LOST_ON_SHUTDOWN record has been written yet.
    expect(storage.calls.update.map((record) => record.state)).toEqual([
      'IN_FLIGHT',
      'RELAY_ACCEPTED_AWAITING_RECEIPT',
    ]);
    releaseUpdate();
    expect(await stopping).toEqual({ ok: true, value: { clientState: 'STOPPED', lost: 1 } });
    expect(storage.calls.update.map((record) => record.state)).toEqual([
      'IN_FLIGHT',
      'RELAY_ACCEPTED_AWAITING_RECEIPT',
      'LOST_ON_SHUTDOWN',
    ]);
    expect((await outbox.getDelivery({ deliveryId: 'd1' })).value.state).toBe('LOST_ON_SHUTDOWN');
  });
});

/* ------------------------------------------------------------------------- *
 * A generative property over a deterministic draw stream.
 * ------------------------------------------------------------------------- */

/** A small deterministic generator, so "fixed seed" means exactly that. */
function makeGenerator(seed) {
  let state = seed >>> 0;
  return {
    next() {
      state = (state * 1664525 + 1013904223) >>> 0;
      return state;
    },
    below(bound) {
      return this.next() % bound;
    },
  };
}

describe('generative invariants over a deterministic draw stream', () => {
  test('300 timelines: only transitions of the closed enumeration, in order, never after a terminal state', async () => {
    const STATES = [
      'QUEUED',
      'IN_FLIGHT',
      'RELAY_ACCEPTED_AWAITING_RECEIPT',
      'RELAY_ACCEPTED',
      'RECIPIENT_RECEIPT_RECEIVED',
      'FAILED_NOT_ACCEPTED',
      'FAILED_NO_RECEIPT',
      'CANCELLED',
      'LOST_ON_SHUTDOWN',
    ];
    const TERMINAL = [
      'RELAY_ACCEPTED',
      'RECIPIENT_RECEIPT_RECEIVED',
      'FAILED_NOT_ACCEPTED',
      'FAILED_NO_RECEIPT',
      'CANCELLED',
      'LOST_ON_SHUTDOWN',
    ];
    for (let seed = 1; seed <= 300; seed += 1) {
      const generator = makeGenerator(seed);
      const maxAttempts = 1 + generator.below(10);
      const deadlineMs = 30000 + generator.below(60000);
      const perRelayTimeoutMs = 11000 + generator.below(4000);
      const receiptMode = generator.below(2) === 0 ? 'RELAY_ACCEPTANCE_ONLY' : 'RECIPIENT_RECEIPT';
      const relayCount = 1 + generator.below(4);
      const draws = [];
      for (let index = 0; index < 12; index += 1) draws.push(generator.next());
      const harness = makeHarness({
        delivery: { maxAttempts, deadlineMs, perRelayTimeoutMs, receiptMode },
        relayCount,
        randomValues: draws,
      });
      harness.clock.state.now = generator.below(1000);
      const admitted = await harness.outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
      expect(admitted.value.deliveryId).toBe('d1');
      await flush();
      // A random script: relays answer, hang or are lost; a cancel or a
      // shutdown may land at a random instant.
      const script = generator.below(3);
      for (let round = 0; round < 6; round += 1) {
        const attempt = harness.relaySet.attempts[harness.relaySet.attempts.length - 1];
        if (attempt === undefined) break;
        for (let index = 0; index < relayCount; index += 1) {
          const choice = generator.below(4);
          if (choice === 0) attempt.answer(index, 'ACCEPTED');
          else if (choice === 1) attempt.answer(index, 'REJECTED');
          else if (choice === 2) attempt.answer(index, 'UNREACHABLE');
        }
        await flush();
        const slice = 1 + generator.below(perRelayTimeoutMs + 2000);
        await harness.clock.advance(slice);
        const snapshot = await harness.outbox.getDelivery({ deliveryId: 'd1' });
        if (snapshot.value.terminal) break;
      }
      if (script === 1) {
        await harness.outbox.cancel({ deliveryId: 'd1' });
      } else if (script === 2) {
        await harness.outbox.shutdown();
      }
      await harness.clock.advance(deadlineMs + 5000);
      const snapshot = await harness.outbox.getDelivery({ deliveryId: 'd1' });
      expect(snapshot.ok).toBe(true);
      expect(STATES).toContain(snapshot.value.state);
      expect(snapshot.value.attempts).toBeGreaterThanOrEqual(0);
      expect(snapshot.value.attempts).toBeLessThanOrEqual(maxAttempts);
      expect(snapshot.value.attempts).toBeLessThanOrEqual(10);
      // The event stream is the transition stream: one event per transition,
      // and no event after a terminal one.
      const eventStates = harness.events.map((event) => event.state);
      for (const state of eventStates) expect(STATES).toContain(state);
      const firstTerminal = eventStates.findIndex((state) => TERMINAL.includes(state));
      if (firstTerminal !== -1) {
        expect(eventStates.slice(firstTerminal + 1)).toEqual([]);
        expect(TERMINAL).toContain(snapshot.value.state);
      }
      for (const event of harness.events) {
        expect(event.kind).toBe('DELIVERY_STATE_CHANGED');
        expect(typeof event.deliveryId).toBe('string');
        expect(typeof event.terminal).toBe('boolean');
      }
      // Every relay outcome stays inside the closed set, and every state marked
      // terminal is a terminal state.
      for (const entry of snapshot.value.relayOutcomes) {
        expect(['PENDING', 'ACCEPTED', 'REJECTED', 'TIMED_OUT', 'UNREACHABLE']).toContain(
          entry.outcome,
        );
      }
      expect(snapshot.value.terminal).toBe(TERMINAL.includes(snapshot.value.state));
      // A failure code is a member of the set C-DLV section 4.5 fixes.
      expect([null, 'E_SDK_STORAGE_FAILED', 'E_SDK_IDENTITY_FAILED', 'E_SDK_INTERNAL', 'E_SDK_UNKNOWN_CODE']).toContain(
        snapshot.value.lastCode,
      );
      // No attempt started at or after the deadline.
      for (const event of harness.events) {
        if (event.state !== 'IN_FLIGHT') continue;
        expect(event.at).toBeLessThan(snapshot.value.deadlineAt);
      }
      // No timer of this module is left armed once the client stopped.
      await harness.outbox.shutdown();
    }
  }, 120000);
});
