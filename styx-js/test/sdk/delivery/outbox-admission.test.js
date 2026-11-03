/**
 * M3-OUTBOX-ROBUSTNESS -- regression tests of the outbound admission order of
 * C-DLV section 4.2: the record is stored before the payload is sealed, so a
 * storage failure never consumes a session seal, and a `put` that settles
 * only after its port-call timeout does not leave the record of a refused
 * admission in the store.
 *
 * Everything the module consumes is injected: a virtual clock port, a storage
 * port with per-call controls, a session port that models a sealing ratchet
 * (every seal consumes one generation, and an opener tolerates a bounded gap
 * of skipped generations), a signing identity port and the publication seam
 * of the I-QUEUE tests, which answers only on demand. Host time is only used for the port-call timeout.
 */
import { describe, expect, test } from '@jest/globals';

import { createOutbox } from '../../../src/sdk/delivery/outbox.js';

const PUBKEY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const RECIPIENT = 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210';
const PAYLOAD = new Uint8Array([1, 2, 3, 4]);

/** The minimum per-relay timeout, so the port-call timeout is 5 500 ms. */
const DELIVERY = {
  maxAttempts: 5,
  deadlineMs: 120000,
  perRelayTimeoutMs: 11000,
  receiptMode: 'RELAY_ACCEPTANCE_ONLY',
};
const PORT_CALL_TIMEOUT_MS = 5500;

/** The skipped-generation window of the modelled opener. */
const RATCHET_GAP = 1000;

async function flush(turns = 6) {
  for (let turn = 0; turn < turns; turn += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function makeClock(start = 0) {
  const state = { now: start, seq: 0, timers: new Map(), nowCalls: 0 };
  const port = {
    now() {
      state.nowCalls += 1;
      return state.now;
    },
    setTimer(callback, delayMs) {
      const handle = { timer: (state.seq += 1) };
      state.timers.set(handle.timer, { at: state.now + delayMs, callback });
      return handle;
    },
    clearTimer(handle) {
      if (handle === null || handle === undefined) return;
      state.timers.delete(handle.timer);
    },
  };
  return { port, state };
}

function makeStorage() {
  const records = new Map();
  const calls = { put: [], update: [], remove: [], list: [] };
  const storage = {
    records,
    calls,
    put: (record) => {
      calls.put.push(record);
      records.set(record.deliveryId, record);
      return true;
    },
    update: (deliveryId, record) => {
      calls.update.push(record);
      if (!records.has(deliveryId)) return false;
      records.set(deliveryId, record);
      return true;
    },
    remove: (deliveryId) => {
      calls.remove.push(deliveryId);
      return records.delete(deliveryId);
    },
    list: () => {
      calls.list.push(true);
      return [...records.values()];
    },
  };
  return storage;
}

/**
 * A session port that models a sealing ratchet: each seal consumes the next
 * generation and prefixes it to the ciphertext; `open` accepts a generation
 * at most RATCHET_GAP past the last opened one.
 */
function makeRatchetSession() {
  const session = {
    generation: 0,
    opened: -1,
    sealCalls: 0,
    seal: ({ plaintext }) => {
      session.sealCalls += 1;
      const generation = session.generation;
      session.generation += 1;
      const ciphertext = new Uint8Array(4 + plaintext.length);
      new DataView(ciphertext.buffer).setUint32(0, generation);
      ciphertext.set(plaintext, 4);
      return { ciphertext };
    },
    open: (ciphertext) => {
      const generation = new DataView(ciphertext.buffer, ciphertext.byteOffset).getUint32(0);
      if (generation <= session.opened || generation - session.opened > RATCHET_GAP) {
        throw new Error('generation outside the window');
      }
      session.opened = generation;
      return ciphertext.slice(4);
    },
  };
  return session;
}

function makeIdentity() {
  return {
    getPublicKey: () => PUBKEY,
    sign: ({ digest }) => new Uint8Array(64).fill(digest[0]),
  };
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

function makeHarness({ storage = makeStorage(), session = makeRatchetSession(), start = 0 } = {}) {
  const clock = makeClock(start);
  const relaySet = makeRelaySet({ relayCount: 1, clock, perRelayTimeoutMs: DELIVERY.perRelayTimeoutMs });
  const events = [];
  const outbox = createOutbox({
    delivery: DELIVERY,
    relayCount: 1,
    storage,
    session,
    identity: makeIdentity(),
    clock: clock.port,
    random: { nextUint32: () => 0 },
    publish: relaySet.publish,
    onEvent: (event) => events.push(event),
  });
  return { outbox, clock, storage, session, relaySet, events };
}

/** The base64 content of a published message event, decoded. */
function contentBytes(event) {
  return Uint8Array.from(Buffer.from(event.content, 'base64'));
}

describe('a storage failure at admission consumes no seal (C-DLV 4.2)', () => {
  test('a put that throws is never followed by a seal', async () => {
    const { outbox, storage, session, events } = makeHarness();
    storage.put = () => {
      throw new Error('synthetic storage failure');
    };
    expect(await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD })).toEqual({
      ok: false,
      code: 'E_SDK_STORAGE_FAILED',
    });
    expect(session.sealCalls).toBe(0);
    expect(events).toEqual([]);
    await outbox.shutdown();
  });

  test('a put that returns false, or a value with an unknown code, is never followed by a seal', async () => {
    for (const [returned, code] of [
      [false, 'E_SDK_STORAGE_FAILED'],
      [{ code: 'E_SDK_NOT_A_CODE' }, 'E_SDK_UNKNOWN_CODE'],
    ]) {
      const { outbox, storage, session } = makeHarness();
      storage.put = () => returned;
      expect(await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD })).toEqual({ ok: false, code });
      expect(storage.calls.remove).toEqual(['d1']);
      expect(session.sealCalls).toBe(0);
      await outbox.shutdown();
    }
  });

  test('after 1 024 failed puts the next message carries the next seal generation and still opens', async () => {
    const { outbox, storage, session, relaySet } = makeHarness();
    const put = storage.put;
    storage.put = () => {
      throw new Error('synthetic storage failure');
    };
    for (let index = 0; index < 1024; index += 1) {
      const result = await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
      expect(result.code).toBe('E_SDK_STORAGE_FAILED');
    }
    storage.put = put;
    const sent = await outbox.send({ recipient: RECIPIENT, plaintext: new Uint8Array([7]) });
    expect(sent).toEqual({ ok: true, value: { deliveryId: 'd1025', state: 'QUEUED' } });
    await flush();
    expect(session.sealCalls).toBe(1);
    expect(relaySet.attempts).toHaveLength(1);
    const opened = session.open(contentBytes(relaySet.attempts[0].event));
    expect([...opened]).toEqual([7]);
    await outbox.shutdown();
  }, 60000);

  test('a put that never settles is bounded by the port-call timeout and is never followed by a seal', async () => {
    const { outbox, storage, session } = makeHarness();
    storage.put = () => new Promise(() => {});
    const started = Date.now();
    expect(await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD })).toEqual({
      ok: false,
      code: 'E_SDK_STORAGE_FAILED',
    });
    expect(Date.now() - started).toBeGreaterThanOrEqual(PORT_CALL_TIMEOUT_MS - 50);
    expect(session.sealCalls).toBe(0);
    await outbox.shutdown();
  }, 30000);

  test('a seal fault after a successful put removes the stored record and leaves no item', async () => {
    const session = makeRatchetSession();
    session.seal = () => {
      session.sealCalls += 1;
      throw new Error('seal');
    };
    const { outbox, storage, events } = makeHarness({ session });
    expect(await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD })).toEqual({
      ok: false,
      code: 'E_SDK_SESSION_FAILED',
    });
    expect(storage.calls.put).toHaveLength(1);
    expect(storage.calls.remove).toEqual(['d1']);
    expect(storage.records.size).toBe(0);
    expect(events).toEqual([]);
    expect(await outbox.getDelivery({ deliveryId: 'd1' })).toEqual({
      ok: false,
      code: 'E_SDK_UNKNOWN_DELIVERY',
    });
    await outbox.shutdown();
  });

  test('the record handed to put holds no ciphertext; the first transition write carries the sealed bytes', async () => {
    const { outbox, storage } = makeHarness();
    await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    expect(storage.calls.put).toHaveLength(1);
    expect(storage.calls.put[0].ciphertext).toBe(null);
    expect(storage.calls.update[0].state).toBe('IN_FLIGHT');
    expect(storage.calls.update[0].ciphertext).toBeInstanceOf(Uint8Array);
    expect(storage.calls.update[0].ciphertext.length).toBe(4 + PAYLOAD.length);
    await outbox.shutdown();
  });

  test('the deadline is measured from the admission reading after put, so a slow put never shortens it', async () => {
    const storage = makeStorage();
    const put = storage.put;
    let releasePut = null;
    storage.put = (record) => new Promise((resolve) => {
      releasePut = () => resolve(put(record));
    });
    const { outbox, clock } = makeHarness({ storage });
    const pending = outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await flush();
    clock.state.now = 4000;
    releasePut();
    expect((await pending).ok).toBe(true);
    const snapshot = (await outbox.getDelivery({ deliveryId: 'd1' })).value;
    expect(snapshot.createdAt).toBe(4000);
    expect(snapshot.deadlineAt).toBe(4000 + DELIVERY.deadlineMs);
    await outbox.shutdown();
  });
});

describe('a put that settles after its timeout leaves no record (C-DLV 4.2)', () => {
  test('a late put that writes after the cleanup remove is removed again once it settles', async () => {
    const storage = makeStorage();
    const put = storage.put;
    let releasePut = null;
    storage.put = (record) => new Promise((resolve) => {
      releasePut = () => resolve(put(record));
    });
    const { outbox } = makeHarness({ storage });
    expect(await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD })).toEqual({
      ok: false,
      code: 'E_SDK_STORAGE_FAILED',
    });
    expect(storage.calls.remove).toEqual(['d1']);
    expect(storage.records.size).toBe(0);
    releasePut();
    await flush();
    expect(storage.records.size).toBe(0);
    expect(storage.calls.remove).toEqual(['d1', 'd1']);
    expect(await storage.list()).toEqual([]);
    await outbox.shutdown();
  }, 30000);

  test('a late put that settles while the cleanup remove is in progress is removed again only after that remove settled, even past its timeout', async () => {
    const storage = makeStorage();
    const put = storage.put;
    const remove = storage.remove;
    let releasePut = null;
    let releaseRemove = null;
    storage.put = (record) => new Promise((resolve) => {
      releasePut = () => resolve(put(record));
    });
    storage.remove = (deliveryId) => {
      const removed = remove(deliveryId);
      if (storage.calls.remove.length > 1) return removed;
      // The first cleanup removal runs at its call and answers late.
      return new Promise((resolve) => {
        releaseRemove = () => resolve(removed);
      });
    };
    const { outbox } = makeHarness({ storage });
    const pending = outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
    await sleep(PORT_CALL_TIMEOUT_MS + 200);
    expect(storage.calls.remove).toEqual(['d1']);
    // The late put writes while the cleanup removal is still in progress.
    releasePut();
    await flush();
    expect(storage.records.size).toBe(1);
    expect(storage.calls.remove).toEqual(['d1']);
    // The cleanup removal outlives its own port-call timeout: `send` resolves
    // within its bound, and the second removal still waits for it to settle.
    expect((await pending).code).toBe('E_SDK_STORAGE_FAILED');
    await flush();
    expect(storage.calls.remove).toEqual(['d1']);
    releaseRemove();
    await flush();
    expect(storage.calls.remove).toEqual(['d1', 'd1']);
    expect(storage.records.size).toBe(0);
    await outbox.shutdown();
  }, 30000);

  test('a late put that rejects after writing is removed again too, and changes no result or event', async () => {
    const storage = makeStorage();
    const put = storage.put;
    let releasePut = null;
    storage.put = (record) => new Promise((resolve, reject) => {
      releasePut = () => {
        put(record);
        reject(new Error('late failure after writing'));
      };
    });
    const { outbox, events } = makeHarness({ storage });
    expect((await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD })).code).toBe('E_SDK_STORAGE_FAILED');
    releasePut();
    await flush();
    expect(storage.records.size).toBe(0);
    expect(storage.calls.remove).toEqual(['d1', 'd1']);
    expect(events).toEqual([]);
    expect(await outbox.getDelivery({ deliveryId: 'd1' })).toEqual({
      ok: false,
      code: 'E_SDK_UNKNOWN_DELIVERY',
    });
    await outbox.shutdown();
  }, 30000);

  test('a put that settles within its timeout takes no second remove', async () => {
    const storage = makeStorage();
    storage.put = (record) => {
      storage.calls.put.push(record);
      return false;
    };
    const { outbox } = makeHarness({ storage });
    expect((await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD })).code).toBe('E_SDK_STORAGE_FAILED');
    await sleep(50);
    expect(storage.calls.remove).toEqual(['d1']);
    await outbox.shutdown();
  });

  test('a shutdown() re-entered from a clock reading of the admission never seals: from the pre-write reading nothing is stored, from the admission reading the stored item is LOST_ON_SHUTDOWN', async () => {
    for (const reentrantReading of [1, 2]) {
      const holder = {};
      const harness = makeHarness();
      const { outbox, clock, storage, session, events } = harness;
      const now = clock.port.now;
      let readings = 0;
      clock.port.now = () => {
        readings += 1;
        if (readings === reentrantReading) holder.stopping = outbox.shutdown();
        return now();
      };
      const result = await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD });
      const stop = await holder.stopping;
      expect(session.sealCalls).toBe(0);
      if (reentrantReading === 1) {
        expect(result).toEqual({ ok: false, code: 'E_SDK_CLIENT_STOPPED' });
        expect(storage.calls.put).toHaveLength(0);
        expect(stop).toEqual({ ok: true, value: { clientState: 'STOPPED', lost: 0 } });
        expect(events).toEqual([]);
      } else {
        expect(result).toEqual({ ok: true, value: { deliveryId: 'd1', state: 'QUEUED' } });
        expect(storage.calls.put).toHaveLength(1);
        expect(stop).toEqual({ ok: true, value: { clientState: 'STOPPED', lost: 1 } });
        expect(events.map((event) => event.state)).toEqual(['LOST_ON_SHUTDOWN']);
      }
    }
  });

  test('a late put that settles only after shutdown() was called takes no further port call', async () => {
    const storage = makeStorage();
    const put = storage.put;
    let releasePut = null;
    storage.put = (record) => new Promise((resolve) => {
      releasePut = () => resolve(put(record));
    });
    const { outbox } = makeHarness({ storage });
    expect((await outbox.send({ recipient: RECIPIENT, plaintext: PAYLOAD })).code).toBe('E_SDK_STORAGE_FAILED');
    expect(await outbox.shutdown()).toEqual({ ok: true, value: { clientState: 'STOPPED', lost: 0 } });
    releasePut();
    await flush();
    expect(storage.calls.remove).toEqual(['d1']);
  }, 30000);
});
