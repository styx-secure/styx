// styx-js/test/sdk/delivery/relay-pool.test.js
//
// Card I-RELAY unit tests. In-process only: no public relay, no remote relay,
// no network. The relay set is driven through an injected clock port and an
// in-process fake transport port whose pools hang, drop or error; a final group
// runs the unchanged `RelayPool` over an in-process fake WebSocket.
//
// The tests are generative over the relay count and the failure mix, and they
// assert the four properties of the card:
//   1. a hung relay never delays the others beyond its own timeout;
//   2. each relay's outcome is reported exactly once;
//   3. no unhandled rejection;
//   4. every subscription and timer is cleaned up on close.

import { describe, test, expect, beforeEach, afterEach } from '@jest/globals';

import { createRelaySet } from '../../../src/sdk/delivery/relay-pool.js';

const PER_RELAY_TIMEOUT_MS = 11000; // the C-DLV §3 minimum
const SUPERVISION_MS = 1000;
const RELAYPOOL_CONNECT_TIMEOUT_MS = 10000; // RelayPool's own fixed host timer
const SUBSCRIPTION_ID = 's'.padEnd(33, '0');
const FILTER = { kinds: [4741, 4742], '#p': ['0'.repeat(64)] };

// ---------------------------------------------------------------------------
// Process-level observations: the card asserts "no unhandled rejection" and
// "no timer left armed", so both are observed here instead of being assumed. A
// rejected promise or a leaked host backstop fails the suite.
// ---------------------------------------------------------------------------

const unhandledRejections = [];
const recordUnhandled = (reason) => unhandledRejections.push(reason);

/** Observe the host timers this module arms through `setTimeout`/`clearTimeout`. */
class HostTimerWatch {
  install() {
    this.realSet = globalThis.setTimeout;
    this.realClear = globalThis.clearTimeout;
    globalThis.setTimeout = (callback, delayMs, ...args) => {
      const handle = this.realSet(() => {
        this.live.delete(handle);
        callback(...args);
      }, delayMs);
      this.live.add(handle);
      this.armed.push(delayMs);
      return handle;
    };
    globalThis.clearTimeout = (handle) => {
      this.live.delete(handle);
      this.realClear(handle);
    };
  }

  uninstall() {
    globalThis.setTimeout = this.realSet;
    globalThis.clearTimeout = this.realClear;
  }
}

const host = new HostTimerWatch();
host.live = new Set();
host.armed = [];

/** Flush one real macrotask, so a queued unhandled rejection is reported. */
const settleProcess = () => new Promise((resolve) => host.realSet(resolve, 0));

beforeEach(() => {
  unhandledRejections.length = 0;
  host.live = new Set();
  host.armed = [];
  host.install();
  process.on('unhandledRejection', recordUnhandled);
});

afterEach(async () => {
  await settleProcess();
  host.uninstall();
  process.off('unhandledRejection', recordUnhandled);
  expect(unhandledRejections).toEqual([]);
});

// ---------------------------------------------------------------------------
// Injected clock port (C-SDK §8.4): manual, deterministic, no real time.
// ---------------------------------------------------------------------------

class ManualClock {
  constructor() {
    this.time = 0;
    this.nextId = 1;
    this.timers = new Map();
  }

  now() {
    return this.time;
  }

  setTimer(callback, delayMs) {
    const handle = this.nextId++;
    this.timers.set(handle, { at: this.time + delayMs, callback });
    return handle;
  }

  clearTimer(handle) {
    this.timers.delete(handle);
  }

  /** Fire every armed timer at or before `this.time + ms`, in order. */
  advance(ms) {
    const target = this.time + ms;
    for (;;) {
      let next = null;
      for (const [handle, timer] of this.timers) {
        if (timer.at > target) continue;
        if (next === null || timer.at < next.timer.at || (timer.at === next.timer.at && handle < next.handle)) {
          next = { handle, timer };
        }
      }
      if (next === null) break;
      this.timers.delete(next.handle);
      this.time = next.timer.at;
      next.timer.callback();
    }
    this.time = target;
  }

  get pending() {
    return [...this.timers.values()].map((timer) => timer.at - this.time);
  }
}

// ---------------------------------------------------------------------------
// In-process fake transport: one fake pool per relay.
// ---------------------------------------------------------------------------

class FakeEmitter {
  constructor() {
    this.listeners = new Map();
  }

  on(event, listener) {
    if (!this.listeners.has(event)) this.listeners.set(event, new Set());
    this.listeners.get(event).add(listener);
  }

  off(event, listener) {
    this.listeners.get(event)?.delete(listener);
  }

  emit(event, payload) {
    for (const listener of [...(this.listeners.get(event) ?? [])]) listener(payload);
  }

  count(event) {
    return this.listeners.get(event)?.size ?? 0;
  }
}

/**
 * A pool with the `RelayPool` surface this module uses.
 *
 * `spec.behaviour` is one of:
 *   `normal` - connects, publishes, answers as `spec.answer`;
 *   `hang`   - connects and accepts the event but never answers (C-DLV §10
 *              `neverAnswering`);
 *   `stall`  - the connection attempt settles with 0 on RelayPool's own
 *              10 000 ms timer (a refused connection or a stalled handshake);
 *   `drop`   - connects, publishes, then loses the connection;
 *   `error`  - the connection attempt rejects;
 *   `late`   - the connection attempt settles only when the test opens it.
 */
class FakePool {
  constructor(url, spec, harness) {
    this.url = url;
    this.spec = spec;
    this.harness = harness;
    this.messages = new FakeEmitter();
    this.connected = false;
    this.disposed = 0;
    this.autoReconnectCleared = 0;
    this.subscriptions = [];
    this.published = [];
    this.connectCalls = 0;
    this.pendingConnect = null;
    this.order = [];
  }

  disconnectAll() {
    this.autoReconnectCleared += 1;
    this.connected = false;
    this.order.push('disconnectAll');
    return Promise.resolve();
  }

  subscribe(subscriptionId, filter) {
    this.order.push('subscribe');
    this.subscriptions.push({ subscriptionId, filter });
  }

  connectAll() {
    this.connectCalls += 1;
    this.order.push('connectAll');
    const settleWithoutConnection = () => new Promise((resolve) => {
      this.harness.clock.setTimer(() => resolve(0), RELAYPOOL_CONNECT_TIMEOUT_MS);
    });
    if (this.spec.behaviour === 'error') return Promise.reject(new Error('connection refused'));
    if (this.spec.behaviour === 'stall') return settleWithoutConnection();
    if (this.spec.behaviour === 'late') {
      // A connection attempt that is still in progress when the clock's
      // connection phase ends (C-DLV §5.2, the `clockAheadOfHost` case): only
      // the test opens it, so no host-timer bound applies to it.
      return new Promise((resolve) => {
        this.pendingConnect = () => {
          this.pendingConnect = null;
          resolve(1);
        };
      });
    }
    if (this.spec.behaviour === 'eagerLate') {
      // Reports the relay connected while the attempt is still in progress: the
      // phase must not count it (C-DLV §5.2, "never joins the completed phase").
      this.connected = true;
      return new Promise((resolve) => {
        this.pendingConnect = () => {
          this.pendingConnect = null;
          resolve(1);
        };
      });
    }
    this.connected = true;
    return Promise.resolve(1);
  }

  /** A `late` pool's connection opens after the phase already ended. */
  openLate() {
    if (!this.pendingConnect) return;
    this.connected = true;
    this.pendingConnect();
  }

  healthCheck() {
    return [{ url: this.url, isConnected: this.connected }];
  }

  publish(event) {
    if (this.spec.behaviour === 'error' || this.spec.behaviour === 'stall') return 0;
    if (!this.connected) return 0;
    this.published.push(event);
    if (this.spec.behaviour === 'drop') this.connected = false;
    if (this.spec.behaviour === 'hang' || this.spec.answer === 'silent') return 1;
    if (this.spec.answer === 'ok-true') {
      this.messages.emit('message', { relay: this.url, data: ['OK', event.id, true, 'saved'] });
    } else if (this.spec.answer === 'ok-false') {
      this.messages.emit('message', { relay: this.url, data: ['OK', event.id, false, 'blocked'] });
    }
    return 1;
  }

  dispose() {
    this.disposed += 1;
    this.connected = false;
    return Promise.resolve();
  }
}

function makeHarness(specs, options = {}) {
  const clock = new ManualClock();
  const draws = [...(options.draws ?? [])];
  const created = [];
  // Loopback literals only: no test in this file reaches a public or remote relay.
  const relays = specs.map((_, index) => `ws://127.0.0.1:${21000 + index}/`);
  const transport = {
    create: (url) => {
      if (options.beforeCreate) options.beforeCreate(url);
      const pool = new FakePool(url, specs[relays.indexOf(url)], { clock });
      created.push(pool);
      return pool;
    },
  };
  const common = {
    relays,
    clock,
    random: { nextUint32: () => (draws.length ? draws.shift() : 0) },
    perRelayTimeoutMs: PER_RELAY_TIMEOUT_MS,
    subscriptionId: SUBSCRIPTION_ID,
    filter: FILTER,
    transport,
  };
  return {
    relays,
    clock,
    created,
    specs,
    draws,
    make: (overrides = {}) => createRelaySet({ ...common, ...overrides }),
  };
}

const EVENT = { id: 'e'.repeat(64), kind: 4741 };

/** Start the set and end its connection phase. */
async function startSet(set, clock) {
  const promise = set.start();
  clock.advance(PER_RELAY_TIMEOUT_MS);
  return promise;
}

/** Open every `late` connection that is still pending. */
function releaseLate(h) {
  for (const pool of h.created) pool.openLate();
}

/** Advance the clock exactly to the next relay supervision tick. */
function toNextSupervisionTick(h) {
  const next = (Math.floor(h.clock.time / SUPERVISION_MS) + 1) * SUPERVISION_MS;
  h.clock.advance(next - h.clock.time);
}

/** The supervision read itself, without waiting for its clock tick. */
const nextTick = (set) => set.supervise();

/** Milliseconds from now until the clock creates the next pool. */
function msUntilNextPool(h, limit = 40000) {
  const before = h.created.length;
  for (let elapsed = 0; elapsed <= limit; elapsed += 1) {
    if (h.created.length > before) return elapsed;
    h.clock.advance(1);
  }
  return -1;
}

/** Let the settle handlers of the pools the clock just connected run. */
async function flush() {
  await Promise.resolve();
  await Promise.resolve();
}

// ---------------------------------------------------------------------------
// 1. Connection phase
// ---------------------------------------------------------------------------

describe('createRelaySet — connection phase', () => {
  test('prepares one pool per relay and subscribes before it connects', async () => {
    const h = makeHarness([{ behaviour: 'normal', answer: 'silent' }, { behaviour: 'normal', answer: 'silent' }]);
    const set = h.make();
    await startSet(set, h.clock);
    expect(h.created).toHaveLength(2);
    for (const pool of h.created) {
      expect(pool.autoReconnectCleared).toBe(1);
      expect(pool.subscriptions).toEqual([{ subscriptionId: SUBSCRIPTION_ID, filter: FILTER }]);
      // disconnectAll, then subscribe, then connect (C-DLV §5.1).
      expect(pool.order).toEqual(['disconnectAll', 'subscribe', 'connectAll']);
    }
    await set.dispose();
  });

  test('the phase ends on the clock port even when every attempt settled earlier', async () => {
    const h = makeHarness([{ behaviour: 'normal', answer: 'silent' }]);
    const set = h.make();
    let resolved = false;
    const promise = set.start().then((value) => {
      resolved = true;
      return value;
    });
    await flush();
    expect(resolved).toBe(false);
    h.clock.advance(PER_RELAY_TIMEOUT_MS - 1);
    await flush();
    expect(resolved).toBe(false);
    h.clock.advance(1);
    await expect(promise).resolves.toEqual({ connectedRelays: 1 });
    await set.dispose();
  });

  test('a failed start disposes every pool, clears every timer and starts from scratch', async () => {
    const h = makeHarness([{ behaviour: 'stall', answer: 'silent' }, { behaviour: 'error', answer: 'silent' }]);
    const set = h.make();
    await expect(startSet(set, h.clock)).resolves.toEqual({ connectedRelays: 0 });
    expect(h.created.every((pool) => pool.disposed === 1)).toBe(true);
    expect(h.clock.pending).toEqual([]);
    expect(set.running).toBe(false);
    await set.dispose();
  });

  test('a start over one connected relay and one stall relay succeeds', async () => {
    const h = makeHarness([{ behaviour: 'normal', answer: 'silent' }, { behaviour: 'stall', answer: 'silent' }]);
    const set = h.make();
    await expect(startSet(set, h.clock)).resolves.toEqual({ connectedRelays: 1 });
    expect(set.connectedRelays).toBe(1);
    await set.dispose();
  });

  test('a second start prepares no second pool per relay', async () => {
    const h = makeHarness([{ behaviour: 'normal', answer: 'silent' }, { behaviour: 'normal', answer: 'silent' }]);
    const set = h.make();
    await expect(startSet(set, h.clock)).resolves.toEqual({ connectedRelays: 2 });
    expect(h.created).toHaveLength(2);
    // At most one current pool per relay (C-DLV §5.1).
    await expect(set.start()).resolves.toEqual({ connectedRelays: 2 });
    expect(h.created).toHaveLength(2);
    await set.dispose();
    expect(h.created.every((pool) => pool.disposed === 1)).toBe(true);
  });

  test('a second start during the phase joins the phase in progress', async () => {
    const h = makeHarness([{ behaviour: 'normal', answer: 'silent' }]);
    const set = h.make();
    const first = set.start();
    const second = set.start();
    h.clock.advance(PER_RELAY_TIMEOUT_MS);
    await expect(first).resolves.toEqual({ connectedRelays: 1 });
    await expect(second).resolves.toEqual({ connectedRelays: 1 });
    expect(h.created).toHaveLength(1);
    await set.dispose();
  });

  test('the phase host backstop is armed with the same delay and cleared by the clock', async () => {
    const h = makeHarness([{ behaviour: 'normal', answer: 'silent' }]);
    const set = h.make();
    await startSet(set, h.clock);
    expect(host.armed).toContain(PER_RELAY_TIMEOUT_MS);
    // The clock port ended the phase first: its twin never stays armed.
    expect(host.live.size).toBe(0);
    await set.dispose();
    expect(host.live.size).toBe(0);
  });

  test('dispose during the phase clears its timers, waits for the start and closes the pool', async () => {
    const h = makeHarness([{ behaviour: 'late', answer: 'silent' }]);
    const set = h.make();
    const starting = set.start();
    await flush();
    expect(h.created).toHaveLength(1);
    expect(h.clock.pending).toContain(PER_RELAY_TIMEOUT_MS);
    const closing = set.dispose();
    await flush();
    await flush(); // the interrupted start counts its relays before the attempt settles
    releaseLate(h); // its connection attempt settles, as RelayPool's own timer would
    await expect(starting).resolves.toEqual({ connectedRelays: 0 });
    await expect(closing).resolves.toBeUndefined();
    expect(set.stopped).toBe(true);
    expect(h.created[0].disposed).toBe(1);
    expect(h.clock.pending).toEqual([]);
    expect(host.live.size).toBe(0);
  });
  test('a clock that refuses to arm the phase still disposes every pool', async () => {
    const h = makeHarness([{ behaviour: 'stall', answer: 'silent' }]);
    let faults = 1;
    const real = h.clock.setTimer.bind(h.clock);
    h.clock.setTimer = (callback, delayMs) => {
      if (faults > 0) {
        faults -= 1;
        throw new Error('clock fault');
      }
      return real(callback, delayMs);
    };
    // The phase keeps its bound on the host backstop instead.
    const set = h.make({ perRelayTimeoutMs: 30 });
    const starting = set.start();
    h.clock.advance(RELAYPOOL_CONNECT_TIMEOUT_MS); // the stalled attempt settles
    await expect(starting).resolves.toEqual({ connectedRelays: 0 });
    expect(h.created.every((pool) => pool.disposed === 1)).toBe(true);
    expect(host.live.size).toBe(0);
    await set.dispose();
    expect(h.clock.pending).toEqual([]);
  });

  test('the attempt host backstop times out a hung relay when the clock never fires', async () => {
    const h = makeHarness([{ behaviour: 'hang', answer: 'silent' }]);
    const armed = [];
    h.clock.setTimer = (callback, delayMs) => {
      armed.push(delayMs);
      return -1; // armed, never fired
    };
    h.clock.clearTimer = () => {};
    const set = h.make({ perRelayTimeoutMs: 30 });
    await expect(set.start()).resolves.toEqual({ connectedRelays: 1 });
    const attempt = set.publish(EVENT);
    expect(attempt.outcomes).toEqual(['PENDING']);
    expect(armed.filter((delay) => delay === 30).length).toBeGreaterThanOrEqual(2);
    // Real time only: the host backstop is what ends the attempt.
    await new Promise((resolve) => host.realSet(resolve, 60));
    expect(attempt.outcomes).toEqual(['TIMED_OUT']);
    expect(host.live.size).toBe(0);
    await set.dispose();
  });

  test('the host backstop ends the phase when the clock port never fires', async () => {
    const h = makeHarness([{ behaviour: 'normal', answer: 'silent' }]);
    const armed = [];
    h.clock.setTimer = (callback, delayMs) => {
      armed.push(delayMs);
      return -1; // armed, never fired
    };
    h.clock.clearTimer = () => {};
    const set = h.make({ perRelayTimeoutMs: 30 });
    await expect(set.start()).resolves.toEqual({ connectedRelays: 1 });
    expect(armed).toContain(30);
    // The backstop fired and was cleared: no host timer stays armed.
    expect(host.live.size).toBe(0);
    await set.dispose();
  });

  test('a later start after a failed start prepares fresh pools', async () => {
    const spec = { behaviour: 'stall', answer: 'silent' };
    const h = makeHarness([spec]);
    const set = h.make();
    const first = set.start();
    h.clock.advance(PER_RELAY_TIMEOUT_MS); // the phase ends with nothing connected
    h.clock.advance(RELAYPOOL_CONNECT_TIMEOUT_MS); // the stalled attempt settles
    await expect(first).resolves.toEqual({ connectedRelays: 0 });
    expect(h.created).toHaveLength(1);
    const failed = h.created[0];
    expect(failed.disposed).toBe(1);
    expect(set.running).toBe(false);
    // The next start does not reuse the pool the failed one disposed.
    spec.behaviour = 'normal';
    await expect(startSet(set, h.clock)).resolves.toEqual({ connectedRelays: 1 });
    expect(h.created).toHaveLength(2);
    expect(h.created[1]).not.toBe(failed);
    expect(failed.disposed).toBe(1);
    expect(set.running).toBe(true);
    expect(host.live.size).toBe(0);
    await set.dispose();
    expect(h.created.every((pool) => pool.disposed === 1)).toBe(true);
  });

  test('a refused phase timer keeps the phase bounded on the host backstop', async () => {
    const h = makeHarness([{ behaviour: 'normal', answer: 'silent' }]);
    h.clock.setTimer = () => {
      throw new Error('clock fault');
    };
    const set = h.make({ perRelayTimeoutMs: 30 });
    let settled = false;
    const starting = set.start().then((result) => {
      settled = true;
      return result;
    });
    await new Promise((resolve) => host.realSet(resolve, 20));
    // The phase is still open: it did not end at the instant the clock refused.
    expect(settled).toBe(false);
    await expect(starting).resolves.toEqual({ connectedRelays: 1 });
    // The phase's own backstop was cleared when it fired; the only host timer
    // left is the supervision fallback, and the close clears that too.
    await set.dispose();
    expect(host.live.size).toBe(0);
  });

  test('a clock port that returns a null timer handle is still tracked', async () => {
    const h = makeHarness([{ behaviour: 'normal', answer: 'silent' }], { draws: [0] });
    let cleared = 0;
    const realSet = h.clock.setTimer.bind(h.clock);
    const realClear = h.clock.clearTimer.bind(h.clock);
    // A legal opaque handle (C-SDK §8.4): the module must not mistake it for
    // "no timer armed".
    h.clock.setTimer = (callback, delayMs) => {
      realSet(callback, delayMs);
      return null;
    };
    h.clock.clearTimer = (handle) => {
      cleared += 1;
      realClear(handle);
    };
    const set = h.make();
    await startSet(set, h.clock);
    expect(cleared).toBeGreaterThan(0);
    expect(h.clock.pending).toContain(SUPERVISION_MS);
    // One loss: the replacement timer is armed with the port's null handle and
    // is still tracked, so a second read arms no second replacement.
    h.created[0].connected = false;
    set.supervise();
    expect(h.created[0].disposed).toBe(1);
    expect(h.clock.pending.filter((delay) => delay === 500)).toHaveLength(1);
    set.supervise();
    expect(h.clock.pending.filter((delay) => delay === 500)).toHaveLength(1);
    h.clock.advance(500);
    await flush();
    expect(h.created).toHaveLength(2);
    expect(h.created.filter((pool) => pool.disposed === 0 && pool.connected)).toHaveLength(1);
    await set.dispose();
    expect(h.created.every((pool) => pool.disposed === 1)).toBe(true);
  });

  test('a connection still in progress at the phase end never counts', async () => {
    const h = makeHarness([{ behaviour: 'eagerLate', answer: 'silent' }]);
    const set = h.make();
    let settled = false;
    const starting = set.start().then((result) => {
      settled = true;
      return result;
    });
    h.clock.advance(PER_RELAY_TIMEOUT_MS); // the phase ends with the attempt open
    await flush();
    // The pool already reports the relay connected, but its attempt has not
    // settled: the phase counts nothing, and the failed start waits for it.
    expect(h.created[0].connected).toBe(true);
    expect(settled).toBe(false);
    h.created[0].openLate(); // the attempt settles connected, still outside the phase
    await flush();
    await expect(starting).resolves.toEqual({ connectedRelays: 0 });
    expect(set.running).toBe(false);
    await flush();
    // The late connection is disposed once settled (C-DLV §5.2).
    expect(h.created[0].disposed).toBe(1);
    expect(set.connectedRelays).toBe(0);
    await set.dispose();
  });

  test('a frame from a retired pool never settles the current attempt', async () => {
    const h = makeHarness([
      { behaviour: 'normal', answer: 'silent' },
      { behaviour: 'stall', answer: 'silent' },
    ]);
    const set = h.make();
    const starting = set.start();
    const retired = h.created[1];
    // The handler the module registered on that pool, kept so that the frame can
    // still be delivered after the listener was removed.
    const staleHandler = [...retired.messages.listeners.get('message')][0];
    h.clock.advance(PER_RELAY_TIMEOUT_MS);
    await expect(starting).resolves.toEqual({ connectedRelays: 1 });
    // The stalled relay is not connected: its pool is retired, with the attempt
    // below live, and its replacement is prepared after the delay.
    expect(retired.disposed).toBe(1);
    const attempt = set.publish(EVENT);
    expect(attempt.outcomes).toEqual(['PENDING', 'PENDING']);
    h.clock.advance(500);
    await flush();
    expect(h.created).toHaveLength(3);
    // A frame the retired pool had already queued arrives after the removal: it
    // is not a frame of the relay's current pool and settles nothing (C-DLV §5.3).
    staleHandler({ relay: h.relays[1], data: ['OK', EVENT.id, true, 'saved'] });
    expect(attempt.outcomes).toEqual(['PENDING', 'PENDING']);
    h.clock.advance(PER_RELAY_TIMEOUT_MS);
    expect(attempt.outcomes).toEqual(['TIMED_OUT', 'TIMED_OUT']);
    await set.dispose();
  });

  test('a relay with no current pool receives no publication', async () => {
    let refuse = false;
    const h = makeHarness([{ behaviour: 'normal', answer: 'silent' }], {
      draws: [0],
      beforeCreate: () => {
        if (refuse) throw new Error('factory fault');
      },
    });
    const set = h.make();
    await startSet(set, h.clock);
    h.created[0].connected = false;
    set.supervise(); // the lost relay is retired at once
    expect(h.created[0].disposed).toBe(1);
    refuse = true; // its replacement cannot be prepared
    h.clock.advance(500);
    await flush();
    expect(h.created).toHaveLength(1);
    const attempt = set.publish(EVENT);
    // No pool, so nothing is published and the relay stays PENDING until its
    // own attempt timeout (C-DLV §5.3).
    expect(attempt.outcomes).toEqual(['PENDING']);
    h.clock.advance(PER_RELAY_TIMEOUT_MS);
    expect(attempt.outcomes).toEqual(['TIMED_OUT']);
    await set.dispose();
  });

  test('the connectedRelays getter does not count a connection still in progress', async () => {
    const h = makeHarness([
      { behaviour: 'normal', answer: 'silent' },
      { behaviour: 'eagerLate', answer: 'silent' },
    ]);
    const set = h.make();
    const starting = set.start();
    h.clock.advance(PER_RELAY_TIMEOUT_MS);
    await expect(starting).resolves.toEqual({ connectedRelays: 1 });
    // The second pool reports connected while its attempt is still open.
    expect(h.created[1].connected).toBe(true);
    expect(set.connectedRelays).toBe(1);
    h.created[1].openLate();
    await flush();
    expect(set.connectedRelays).toBe(2);
    await set.dispose();
  });

  test('a close after a successful start waits for a connection attempt', async () => {
    const h = makeHarness([
      { behaviour: 'normal', answer: 'silent' },
      { behaviour: 'late', answer: 'silent' },
    ]);
    const set = h.make();
    await startSet(set, h.clock);
    const late = h.created[1];
    const closing = set.dispose();
    await flush();
    // The close waits for the attempt: the pool is still open (C-DLV §5.5).
    expect(set.stopped).toBe(true);
    expect(late.disposed).toBe(0);
    late.openLate();
    await expect(closing).resolves.toBeUndefined();
    expect(late.disposed).toBe(1);
    expect(h.created.every((pool) => pool.disposed === 1)).toBe(true);
  });

  test('EOSE and CLOSED of another subscription are not forwarded', async () => {
    const h = makeHarness([{ behaviour: 'normal', answer: 'silent' }]);
    const set = h.make();
    await startSet(set, h.clock);
    const frames = [];
    set.onFrame((frame) => frames.push(frame));
    h.created[0].messages.emit('message', { relay: h.relays[0], data: ['EOSE', SUBSCRIPTION_ID] });
    h.created[0].messages.emit('message', { relay: h.relays[0], data: ['CLOSED', 'another-subscription'] });
    expect(frames).toHaveLength(1);
    expect(frames[0].data).toEqual(['EOSE', SUBSCRIPTION_ID]);
    await set.dispose();
  });

  test('a clock that refuses the replacement timer counts the loss once', async () => {
    const h = makeHarness([{ behaviour: 'normal', answer: 'silent' }], { draws: [0] });
    const set = h.make();
    await startSet(set, h.clock);
    // The fault is installed after the phase, so the call it refuses is the
    // replacement arming that this test is about.
    let faults = 1;
    const realSet = h.clock.setTimer.bind(h.clock);
    h.clock.setTimer = (callback, delayMs) => {
      if (faults > 0) {
        faults -= 1;
        throw new Error('clock fault');
      }
      return realSet(callback, delayMs);
    };
    h.created[0].connected = false;
    // The first read retires the relay and its arming is refused; the next read
    // picks the relay up again with the same delay, not a longer one (C-DLV §5.2).
    set.supervise();
    set.supervise();
    expect(h.clock.pending.filter((delay) => delay === 500)).toHaveLength(1);
    h.clock.advance(500);
    await flush();
    expect(h.created).toHaveLength(2);
    await set.dispose();
  });
});

// ---------------------------------------------------------------------------
// 2. Publish and per-relay outcomes
// ---------------------------------------------------------------------------

describe('createRelaySet — publish and per-relay outcomes', () => {
  test('publishes one attempt to every relay and settles each relay once', async () => {
    const h = makeHarness([
      { behaviour: 'normal', answer: 'ok-true' },
      { behaviour: 'normal', answer: 'ok-false' },
      { behaviour: 'normal', answer: 'silent' },
    ]);
    const set = h.make();
    await startSet(set, h.clock);
    const attempt = set.publish(EVENT);
    const settled = [];
    attempt.onOutcome((index, outcome) => settled.push([index, outcome]));

    expect(attempt.outcomes).toEqual(['ACCEPTED', 'REJECTED', 'PENDING']);
    expect(attempt.acceptedIndex).toBe(0);
    // The attempt timeout carries its own host backstop of the same delay.
    expect(host.armed.filter((delay) => delay === PER_RELAY_TIMEOUT_MS).length).toBeGreaterThanOrEqual(2);
    expect(h.created[0].published).toEqual([EVENT]);
    expect(h.created[1].published).toEqual([EVENT]);
    expect(h.created[2].published).toEqual([EVENT]);

    h.clock.advance(PER_RELAY_TIMEOUT_MS);
    expect(attempt.outcomes).toEqual(['ACCEPTED', 'REJECTED', 'TIMED_OUT']);
    expect(settled).toEqual([[0, 'ACCEPTED'], [1, 'REJECTED'], [2, 'TIMED_OUT']]);
    expect(attempt.isSettled()).toBe(true);
    await set.dispose();
  });

  test('a listener registered after the publication still hears each relay once', async () => {
    const h = makeHarness([{ behaviour: 'normal', answer: 'ok-true' }, { behaviour: 'normal', answer: 'silent' }]);
    const set = h.make();
    await startSet(set, h.clock);
    const attempt = set.publish(EVENT);
    const seen = [];
    const unsubscribe = attempt.onOutcome((index, outcome) => seen.push([index, outcome]));
    expect(seen).toEqual([[0, 'ACCEPTED']]);
    h.clock.advance(PER_RELAY_TIMEOUT_MS);
    expect(seen).toEqual([[0, 'ACCEPTED'], [1, 'TIMED_OUT']]);
    unsubscribe();
    h.clock.advance(PER_RELAY_TIMEOUT_MS);
    expect(seen).toHaveLength(2);
    await set.dispose();
  });

  test('reports onSettled exactly once', async () => {
    const h = makeHarness([{ behaviour: 'normal', answer: 'ok-true' }, { behaviour: 'normal', answer: 'silent' }]);
    const set = h.make();
    await startSet(set, h.clock);
    const attempt = set.publish(EVENT);
    let settledCalls = 0;
    attempt.onSettled(() => {
      settledCalls += 1;
    });
    expect(settledCalls).toBe(0);
    h.clock.advance(PER_RELAY_TIMEOUT_MS);
    expect(settledCalls).toBe(1);
    h.clock.advance(PER_RELAY_TIMEOUT_MS);
    expect(settledCalls).toBe(1);
    await set.dispose();
  });

  test('an OK frame that arrives after its relay settled is ignored', async () => {
    const h = makeHarness([{ behaviour: 'normal', answer: 'silent' }]);
    const set = h.make();
    await startSet(set, h.clock);
    const attempt = set.publish(EVENT);
    h.clock.advance(PER_RELAY_TIMEOUT_MS);
    expect(attempt.outcomes).toEqual(['TIMED_OUT']);
    h.created[0].messages.emit('message', { relay: h.relays[0], data: ['OK', EVENT.id, true, 'late'] });
    expect(attempt.outcomes).toEqual(['TIMED_OUT']);
    await set.dispose();
  });

  test('ignoreAcks keeps PENDING -> TIMED_OUT and ignores later OK frames', async () => {
    const h = makeHarness([{ behaviour: 'normal', answer: 'silent' }]);
    const set = h.make();
    await startSet(set, h.clock);
    const attempt = set.publish(EVENT);
    attempt.ignoreAcks();
    h.created[0].messages.emit('message', { relay: h.relays[0], data: ['OK', EVENT.id, true, 'late'] });
    expect(attempt.outcomes).toEqual(['PENDING']);
    h.clock.advance(PER_RELAY_TIMEOUT_MS);
    expect(attempt.outcomes).toEqual(['TIMED_OUT']);
    await set.dispose();
  });

  test('a relay whose publish returned 0 stays PENDING and times out', async () => {
    const h = makeHarness([{ behaviour: 'normal', answer: 'ok-true' }, { behaviour: 'stall', answer: 'silent' }]);
    const set = h.make();
    await expect(startSet(set, h.clock)).resolves.toEqual({ connectedRelays: 1 });
    const attempt = set.publish(EVENT);
    expect(attempt.outcomes).toEqual(['ACCEPTED', 'PENDING']);
    expect(h.created[1].published).toEqual([]);
    h.clock.advance(PER_RELAY_TIMEOUT_MS);
    expect(attempt.outcomes).toEqual(['ACCEPTED', 'TIMED_OUT']);
    await set.dispose();
  });

  test('an accept gate that refuses keeps the relay PENDING', async () => {
    const h = makeHarness([{ behaviour: 'normal', answer: 'silent' }]);
    const set = h.make();
    await startSet(set, h.clock);
    const attempt = set.publish(EVENT);
    const pool = h.created[0];
    attempt.acceptGate = () => false;
    pool.messages.emit('message', { relay: h.relays[0], data: ['OK', EVENT.id, true, 'saved'] });
    expect(attempt.outcomes).toEqual(['PENDING']);
    attempt.acceptGate = () => true;
    pool.messages.emit('message', { relay: h.relays[0], data: ['OK', EVENT.id, true, 'saved'] });
    expect(attempt.outcomes).toEqual(['ACCEPTED']);
    await set.dispose();
  });

  test('a sticky acceptance is never reset or republished', async () => {
    const h = makeHarness([{ behaviour: 'normal', answer: 'silent' }]);
    const set = h.make();
    await startSet(set, h.clock);
    const second = set.publish(EVENT, { accepted: [0] });
    expect(second.outcomes).toEqual(['ACCEPTED']);
    expect(h.created[0].published).toEqual([]);
    await set.dispose();
  });

  test('frames of another subscription and unknown kinds are not forwarded', async () => {
    const h = makeHarness([{ behaviour: 'normal', answer: 'silent' }]);
    const set = h.make();
    await startSet(set, h.clock);
    const frames = [];
    set.onFrame((frame) => frames.push(frame));
    const pool = h.created[0];
    pool.messages.emit('message', { relay: h.relays[0], data: ['EVENT', 'other-sub', { id: 'x' }] });
    pool.messages.emit('message', { relay: h.relays[0], data: ['FUTURE', SUBSCRIPTION_ID] });
    pool.messages.emit('message', { relay: h.relays[0], data: 'not-an-array' });
    pool.messages.emit('message', { relay: h.relays[0], data: ['EVENT', SUBSCRIPTION_ID, { id: 'y' }] });
    pool.messages.emit('message', { relay: h.relays[0], data: ['EOSE', SUBSCRIPTION_ID] });
    expect(frames.map((frame) => frame.data[0])).toEqual(['EVENT', 'EOSE']);
    await set.dispose();
  });

  test('a gate that throws refuses and never escapes into the pool emitter', async () => {
    const h = makeHarness([{ behaviour: 'normal', answer: 'silent' }]);
    const set = h.make();
    await startSet(set, h.clock);
    const attempt = set.publish(EVENT);
    const pool = h.created[0];
    attempt.acceptGate = () => { throw new Error('gate fault'); };
    // The frame must be read as refused, not as an exception out of `emit`.
    expect(() => pool.messages.emit('message', { relay: h.relays[0], data: ['OK', EVENT.id, true, 'saved'] })).not.toThrow();
    expect(attempt.outcomes).toEqual(['PENDING']);
    attempt.acceptGate = () => true;
    pool.messages.emit('message', { relay: h.relays[0], data: ['OK', EVENT.id, true, 'saved'] });
    expect(attempt.outcomes).toEqual(['ACCEPTED']);
    await set.dispose();
  });

  test('a throwing late-publish gate refuses and supervision keeps running', async () => {
    const h = makeHarness([{ behaviour: 'normal', answer: 'silent' }, { behaviour: 'late', answer: 'ok-true' }]);
    const set = h.make();
    await startSet(set, h.clock);
    const attempt = set.publish(EVENT);
    // The late relay was not connected when the attempt was published.
    expect(h.created[1].published).toEqual([]);
    attempt.latePublishGate = () => { throw new Error('gate fault'); };
    releaseLate(h);
    await flush();
    expect(h.created[1].published).toEqual([]);
    expect(attempt.outcomes).toEqual(['PENDING', 'PENDING']);
    // The fault never stops supervision: the next read is armed and it sees a loss.
    h.created[1].connected = false;
    toNextSupervisionTick(h);
    expect(h.clock.pending).toContain(SUPERVISION_MS);
    expect(h.created[1].disposed).toBe(1);
    await set.dispose();
  });

  test('onSettled reaches a listener registered after the attempt settled', async () => {
    const h = makeHarness([{ behaviour: 'normal', answer: 'ok-true' }, { behaviour: 'normal', answer: 'ok-true' }]);
    const set = h.make();
    await startSet(set, h.clock);
    // Every relay is sticky-ACCEPTED, so the attempt is settled when it returns.
    const attempt = set.publish(EVENT, { accepted: [0, 1] });
    expect(attempt.isSettled()).toBe(true);
    let settled = 0;
    attempt.onSettled(() => { settled += 1; });
    expect(settled).toBe(1);
    h.clock.advance(PER_RELAY_TIMEOUT_MS * 2);
    expect(settled).toBe(1);
    await set.dispose();
  });

  test('a connected relay written to once is not written to again in the same attempt', async () => {
    const h = makeHarness([{ behaviour: 'normal', answer: 'silent' }]);
    const set = h.make();
    await startSet(set, h.clock);
    // A connected relay whose publication returned 0 anyway: the module still
    // called `publish` on it once for this attempt (C-DLV §5.3).
    h.created[0].publish = () => 0;
    const attempt = set.publish(EVENT);
    expect(attempt.outcomes).toEqual(['PENDING']);
    expect(h.created[0].published).toEqual([]);
    let writes = 0;
    h.created[0].publish = () => { writes += 1; return 0; };
    toNextSupervisionTick(h);
    toNextSupervisionTick(h);
    expect(writes).toBe(0);
    expect(attempt.outcomes).toEqual(['PENDING']);
    h.clock.advance(PER_RELAY_TIMEOUT_MS);
    expect(attempt.outcomes).toEqual(['TIMED_OUT']);
    await set.dispose();
  });

  test('a connection lost between two reads still gets its late-open publication', async () => {
    const h = makeHarness([{ behaviour: 'normal', answer: 'ok-true' }]);
    const set = h.make();
    await startSet(set, h.clock);
    // The connection was lost since the last read: the write returns 0 while
    // the module's cached "connected" is still true.
    h.created[0].connected = false;
    const attempt = set.publish(EVENT);
    expect(attempt.outcomes).toEqual(['PENDING']);
    expect(h.created[0].disposed).toBe(1); // that same publication retires it
    // Its replacement opens inside the same attempt, so the relay is written
    // to once and accepted instead of ending TIMED_OUT with no frame sent.
    h.clock.advance(500);
    await flush();
    expect(h.created).toHaveLength(2);
    expect(h.created[1].published).toEqual([EVENT]);
    expect(attempt.outcomes).toEqual(['ACCEPTED']);
    await set.dispose();
  });

  test('a duplicate: acceptance still sets ACCEPTED', async () => {
    const h = makeHarness([{ behaviour: 'normal', answer: 'silent' }]);
    const set = h.make();
    await startSet(set, h.clock);
    const attempt = set.publish(EVENT);
    h.created[0].messages.emit('message', {
      relay: h.relays[0],
      data: ['OK', EVENT.id, true, 'duplicate: has already been saved'],
    });
    expect(attempt.outcomes).toEqual(['ACCEPTED']);
    await set.dispose();
  });

  test('a second onSettled listener registered inside an outcome callback fires once', async () => {
    const h = makeHarness([{ behaviour: 'normal', answer: 'silent' }]);
    const set = h.make();
    await startSet(set, h.clock);
    const attempt = set.publish(EVENT);
    let settled = 0;
    attempt.onOutcome(() => { attempt.onSettled(() => { settled += 1; }); });
    h.created[0].messages.emit('message', { relay: h.relays[0], data: ['OK', EVENT.id, true, 'saved'] });
    expect(attempt.outcomes).toEqual(['ACCEPTED']);
    expect(settled).toBe(1);
    await set.dispose();
  });

  test('a listener registered after a partial settlement hears each relay once', async () => {
    const h = makeHarness([{ behaviour: 'normal', answer: 'ok-true' }, { behaviour: 'drop', answer: 'silent' }]);
    const set = h.make();
    await startSet(set, h.clock);
    const attempt = set.publish(EVENT);
    // Relay 0 is ACCEPTED, relay 1 lost its connection and is still PENDING.
    expect(attempt.outcomes).toEqual(['ACCEPTED', 'PENDING']);
    const reports = [0, 0];
    attempt.onOutcome((index) => {
      reports[index] += 1;
      // A supervision read inside the replay settles relay 1; it must not be
      // reported a second time by the replay loop of the same registration.
      set.supervise();
    });
    expect(reports).toEqual([1, 1]);
    await set.dispose();
  });

  test('a factory fault during a replacement keeps the relay on its replacement path', async () => {
    let refuse = false;
    const h = makeHarness([{ behaviour: 'normal', answer: 'ok-true' }], {
      draws: [0, 0, 0],
      beforeCreate: () => {
        if (refuse) throw new Error('factory fault');
      },
    });
    const set = h.make();
    await startSet(set, h.clock);
    // The connection is lost, so this publication returns 0 and the attempt
    // stays PENDING while the replacement is scheduled after delay(1, 0).
    h.created[0].connected = false;
    const attempt = set.publish(EVENT);
    expect(attempt.outcomes).toEqual(['PENDING']);
    expect(h.created[0].disposed).toBe(1);
    // The factory refuses the replacement: the relay must keep its replacement
    // path instead of being left with no pool and no armed timer.
    refuse = true;
    h.clock.advance(500);
    expect(h.created).toHaveLength(1);
    refuse = false;
    const delay = msUntilNextPool(h);
    expect(delay).toBe(1000); // delay(2, 0)
    await flush();
    expect(h.created).toHaveLength(2);
    expect(attempt.outcomes).toEqual(['ACCEPTED']);
    await set.dispose();
  });

  test('ignoreAcks keeps a lost relay PENDING until the attempt timeout', async () => {
    const h = makeHarness([{ behaviour: 'drop', answer: 'silent' }]);
    const set = h.make();
    await startSet(set, h.clock);
    const attempt = set.publish(EVENT);
    attempt.ignoreAcks();
    // A lost connection after an acceptance was waived: the only remaining
    // change is PENDING -> TIMED_OUT at the attempt timeout (C-DLV §5.3).
    nextTick(set);
    expect(attempt.outcomes).toEqual(['PENDING']);
    h.clock.advance(PER_RELAY_TIMEOUT_MS);
    expect(attempt.outcomes).toEqual(['TIMED_OUT']);
    await set.dispose();
  });

  test('a NOTICE frame of the client is forwarded unchanged', async () => {
    const h = makeHarness([{ behaviour: 'normal', answer: 'silent' }]);
    const set = h.make();
    await startSet(set, h.clock);
    const frames = [];
    set.onFrame((frame) => frames.push(frame));
    h.created[0].messages.emit('message', { relay: h.relays[0], data: ['NOTICE', 'rate limited'] });
    expect(frames.map((frame) => frame.data)).toEqual([['NOTICE', 'rate limited']]);
    await set.dispose();
  });

  test('a replacement pool still gets its late-open publication after a refused write', async () => {
    const h = makeHarness([{ behaviour: 'normal', answer: 'ok-true' }], { draws: [0] });
    const set = h.make();
    await startSet(set, h.clock);
    const first = h.created[0];
    // The pool reports connected but refuses the write: nothing is sent, and
    // the refusal does not outlive the pool it describes.
    first.publish = () => 0;
    const attempt = set.publish(EVENT);
    expect(attempt.outcomes).toEqual(['PENDING']);
    expect(first.published).toEqual([]);
    // The connection is then lost and the replacement opens inside the attempt.
    first.connected = false;
    toNextSupervisionTick(h);
    const delay = msUntilNextPool(h);
    expect(delay).toBe(500); // delay(1, 0)
    await flush();
    expect(h.created).toHaveLength(2);
    expect(h.created[1].published).toEqual([EVENT]);
    expect(attempt.outcomes).toEqual(['ACCEPTED']);
    await set.dispose();
  });
});

// ---------------------------------------------------------------------------
// 3. Supervision, loss and replacement
// ---------------------------------------------------------------------------

describe('createRelaySet — supervision, loss and replacement', () => {
  test('a relay that drops after publishing is UNREACHABLE and is retired at once', async () => {
    const h = makeHarness([{ behaviour: 'drop', answer: 'silent' }], { draws: [0] });
    const set = h.make();
    await startSet(set, h.clock);
    const first = h.created[0];
    const attempt = set.publish(EVENT);
    expect(first.published).toEqual([EVENT]);
    expect(first.connected).toBe(false);
    expect(attempt.outcomes).toEqual(['PENDING']);

    // The next supervision interval is the read that sees the loss.
    h.clock.advance(SUPERVISION_MS);
    expect(attempt.outcomes).toEqual(['UNREACHABLE']);
    expect(first.disposed).toBe(1);
    // Its replacement pool is prepared only after delay(k, u) (C-DLV §5.2).
    expect(h.created).toHaveLength(1);
    h.clock.advance(499); // delay(1, 0) = 500 ms
    expect(h.created).toHaveLength(1);
    h.clock.advance(1);
    expect(h.created).toHaveLength(2);
    expect(h.created[1].connectCalls).toBe(1);
    await set.dispose();
  });

  test('the reconnection delay follows the injected draw', async () => {
    // delay(1, u) = floor(1000 / 2) + floor(u * 1000 / 2^33); an invalid draw
    // uses the largest delay of the step, base(1) - 1 = 999 ms (C-DLV §5.2).
    const cases = [[0, 500], [2147483648, 750], [4294967295, 999], [-1, 999]];
    for (const [draw, expected] of cases) {
      const h = makeHarness([{ behaviour: 'drop', answer: 'silent' }], { draws: [draw] });
      const set = h.make();
      await startSet(set, h.clock);
      set.publish(EVENT);
      toNextSupervisionTick(h);
      expect(h.created).toHaveLength(1);
      expect(msUntilNextPool(h)).toBe(expected);
      expect(h.created).toHaveLength(2);
      const closing = set.dispose();
      h.clock.advance(RELAYPOOL_CONNECT_TIMEOUT_MS);
      await closing;
    }
  });

  test('an injected schedule replaces the private default one', async () => {
    const injected = [];
    const h = makeHarness([{ behaviour: 'drop', answer: 'silent' }], { draws: [123] });
    const set = h.make({
      reconnectDelay: (k, u) => {
        injected.push([k, u]);
        return 250;
      },
    });
    await startSet(set, h.clock);
    set.publish(EVENT);
    toNextSupervisionTick(h);
    expect(msUntilNextPool(h)).toBe(250);
    expect(injected).toEqual([[1, 123]]);
    const closing = set.dispose();
    h.clock.advance(RELAYPOOL_CONNECT_TIMEOUT_MS);
    await closing;
  });

  test('a successful reconnection resets the consecutive-loss counter', async () => {
    const h = makeHarness([{ behaviour: 'drop', answer: 'silent' }], { draws: [0, 0] });
    const set = h.make();
    await startSet(set, h.clock);
    set.publish(EVENT);
    toNextSupervisionTick(h);
    h.clock.advance(500); // delay(1, 0)
    expect(h.created).toHaveLength(2);
    await flush();

    // The replacement connected, so the next loss is again the first one and
    // uses delay(1, u) - not delay(2, u).
    set.publish(EVENT);
    toNextSupervisionTick(h);
    expect(h.created).toHaveLength(2);
    h.clock.advance(499);
    expect(h.created).toHaveLength(2);
    h.clock.advance(1);
    expect(h.created).toHaveLength(3);
    await flush();
    await set.dispose();
  });

  test('an invalid random draw uses the largest delay of the step', async () => {
    const h = makeHarness([{ behaviour: 'drop', answer: 'silent' }], { draws: [-1] });
    const set = h.make();
    await startSet(set, h.clock);
    set.publish(EVENT);
    toNextSupervisionTick(h);
    expect(h.created).toHaveLength(1);
    h.clock.advance(999 - 1); // base(1) - 1
    expect(h.created).toHaveLength(1);
    h.clock.advance(1);
    expect(h.created).toHaveLength(2);
    await set.dispose();
  });

  test('a relay that settles without a connection at the phase end takes the replacement path', async () => {
    const h = makeHarness([{ behaviour: 'normal', answer: 'silent' }, { behaviour: 'stall', answer: 'silent' }], { draws: [0] });
    const set = h.make();
    await expect(startSet(set, h.clock)).resolves.toEqual({ connectedRelays: 1 });
    expect(h.created[1].disposed).toBe(1);
    h.clock.advance(500); // delay(1, 0)
    expect(h.created).toHaveLength(3);
    const closing = set.dispose();
    h.clock.advance(RELAYPOOL_CONNECT_TIMEOUT_MS);
    await closing;
  });

  test('a late connection after a successful start is published on once', async () => {
    const h = makeHarness([{ behaviour: 'normal', answer: 'silent' }, { behaviour: 'late', answer: 'ok-true' }]);
    const set = h.make();
    await expect(startSet(set, h.clock)).resolves.toEqual({ connectedRelays: 1 });
    const attempt = set.publish(EVENT);
    expect(attempt.outcomes).toEqual(['PENDING', 'PENDING']);
    const late = h.created[1];
    expect(late.published).toEqual([]);

    late.openLate();
    // The connection that had not settled when the phase ended now joins: the
    // publication of this attempt follows it (C-DLV §5.2, §5.3).
    await flush();
    expect(late.published).toEqual([EVENT]);
    expect(attempt.outcomes).toEqual(['PENDING', 'ACCEPTED']);

    // Published once: a later supervision read does not publish again.
    set.supervise();
    expect(late.published).toEqual([EVENT]);
    await set.dispose();
  });

  test('a late opening with a refusing gate publishes nothing', async () => {
    const h = makeHarness([{ behaviour: 'normal', answer: 'silent' }, { behaviour: 'late', answer: 'ok-true' }]);
    const set = h.make();
    await startSet(set, h.clock);
    const attempt = set.publish(EVENT);
    attempt.latePublishGate = () => false;
    h.created[1].openLate();
    // The connection that had not settled when the phase ended now joins, but the
    // gate refuses this attempt's late publication.
    await flush();
    expect(h.created[1].published).toEqual([]);
    expect(attempt.outcomes).toEqual(['PENDING', 'PENDING']);
    const closing = set.dispose();
    h.clock.advance(RELAYPOOL_CONNECT_TIMEOUT_MS);
    await closing;
  });
});

// ---------------------------------------------------------------------------
// 4. Closing
// ---------------------------------------------------------------------------

describe('createRelaySet — closing', () => {
  test('dispose closes every pool, clears every timer and removes every listener', async () => {
    const h = makeHarness([
      { behaviour: 'hang', answer: 'silent' },
      { behaviour: 'stall', answer: 'silent' },
      { behaviour: 'late', answer: 'silent' },
    ], { draws: [3] });
    const set = h.make();
    await expect(startSet(set, h.clock)).resolves.toEqual({ connectedRelays: 1 });
    const attempt = set.publish(EVENT);
    expect(attempt.outcomes).toEqual(['PENDING', 'PENDING', 'PENDING']);

    releaseLate(h);
    const closing = set.dispose();
    h.clock.advance(RELAYPOOL_CONNECT_TIMEOUT_MS * 2);
    await closing;

    expect(set.stopped).toBe(true);
    expect(set.running).toBe(false);
    expect(h.created.every((pool) => pool.disposed === 1)).toBe(true);
    expect(h.created.every((pool) => pool.messages.count('message') === 0)).toBe(true);
    expect(h.clock.pending).toEqual([]);
    // Outcomes freeze at their current value: no PENDING -> TIMED_OUT after stop.
    h.clock.advance(PER_RELAY_TIMEOUT_MS * 4);
    expect(attempt.outcomes).toEqual(['PENDING', 'PENDING', 'PENDING']);
    const created = h.created.length;
    h.clock.advance(PER_RELAY_TIMEOUT_MS * 4);
    expect(h.created).toHaveLength(created);
  });

  test('dispose is idempotent and stops reconnection', async () => {
    const h = makeHarness([{ behaviour: 'drop', answer: 'silent' }], { draws: [0] });
    const set = h.make();
    await startSet(set, h.clock);
    set.publish(EVENT);
    const closing = set.dispose();
    h.clock.advance(RELAYPOOL_CONNECT_TIMEOUT_MS);
    await closing;
    const created = h.created.length;
    h.clock.advance(PER_RELAY_TIMEOUT_MS * 4);
    expect(h.created).toHaveLength(created);
    await set.dispose();
    expect(h.clock.pending).toEqual([]);
  });

  test('a close clears the reconnection timer and the supervision timer', async () => {
    const h = makeHarness([
      { behaviour: 'normal', answer: 'silent' },
      { behaviour: 'drop', answer: 'silent' },
    ], { draws: [0] });
    const set = h.make();
    await startSet(set, h.clock);
    const attempt = set.publish(EVENT);
    expect(attempt.outcomes).toEqual(['PENDING', 'PENDING']);
    // The next read retires the dropped relay and arms its reconnection timer, and
    // re-arms the supervision timer.
    h.clock.advance(SUPERVISION_MS);
    await flush();
    expect(h.clock.pending).toEqual(expect.arrayContaining([500]));
    expect(h.clock.pending).toEqual(expect.arrayContaining([SUPERVISION_MS]));
    await set.dispose();
    // Read the clock straight after the close, with no advance in between: an
    // advance would fire a timer the module had forgotten to clear, whose callback
    // returns on `stopped` and hides the leak.
    expect(h.clock.pending.filter((delay) => [500, SUPERVISION_MS].includes(delay))).toEqual([]);
  });

  test('a late OK never changes a settled outcome', async () => {
    const h = makeHarness([
      { behaviour: 'normal', answer: 'ok-true' },
      { behaviour: 'normal', answer: 'ok-false' },
    ]);
    const set = h.make();
    await startSet(set, h.clock);
    const attempt = set.publish(EVENT);
    expect(attempt.outcomes).toEqual(['ACCEPTED', 'REJECTED']);
    // Frames that would contradict an already settled outcome arrive afterwards.
    h.created[0].messages.emit('message', { relay: h.relays[0], data: ['OK', EVENT.id, false, 'blocked'] });
    h.created[1].messages.emit('message', { relay: h.relays[1], data: ['OK', EVENT.id, true, 'saved'] });
    expect(attempt.outcomes).toEqual(['ACCEPTED', 'REJECTED']);
    await set.dispose();
  });

  test('a close clears the attempt clock timer', async () => {
    const h = makeHarness([{ behaviour: 'normal', answer: 'silent' }]);
    const set = h.make();
    await startSet(set, h.clock);
    set.publish(EVENT);
    // The live attempt and the supervision read are the only timers this clock
    // holds, so what remains after the close is exactly what the module leaked.
    expect(h.clock.pending).toEqual(expect.arrayContaining([PER_RELAY_TIMEOUT_MS]));
    await set.dispose();
    expect(h.clock.pending).toEqual([]);
  });

  test('dispose after a failed start leaves no timer and no open pool', async () => {
    const h = makeHarness([{ behaviour: 'stall', answer: 'silent' }]);
    const set = h.make();
    await startSet(set, h.clock);
    const closing = set.dispose();
    h.clock.advance(RELAYPOOL_CONNECT_TIMEOUT_MS);
    await closing;
    expect(h.clock.pending).toEqual([]);
    expect(h.created.every((pool) => pool.disposed === 1)).toBe(true);
  });

  test('a second dispose waits for the close in progress and closes nothing twice', async () => {
    const h = makeHarness([{ behaviour: 'stall', answer: 'silent' }]);
    const set = h.make();
    const starting = set.start();
    const first = set.dispose();
    const second = set.dispose();
    h.clock.advance(RELAYPOOL_CONNECT_TIMEOUT_MS);
    await expect(second).resolves.toBeUndefined();
    // When the second caller is told "closed", the pools are already closed.
    expect(h.created[0].disposed).toBe(1);
    await expect(first).resolves.toBeUndefined();
    await expect(starting).resolves.toEqual({ connectedRelays: 0 });
    expect(h.created[0].disposed).toBe(1);
    expect(h.clock.pending).toEqual([]);
    expect(host.live.size).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// 5. The O-SCEN3 scenarios cited by this card
// ---------------------------------------------------------------------------

describe('createRelaySet — O-SCEN3 scenarios', () => {
  test('hungRelayAlongsideNormal: the normal relay is accepted without waiting for the hung one', async () => {
    // docs/architecture/m3/scenarios/hung-relay.md, timeline `hungRelayAlongsideNormal`.
    const h = makeHarness([{ behaviour: 'normal', answer: 'ok-true' }, { behaviour: 'hang', answer: 'silent' }]);
    const set = h.make();
    await expect(startSet(set, h.clock)).resolves.toEqual({ connectedRelays: 2 });
    const settledAt = [];
    const attempt = set.publish(EVENT);
    attempt.onOutcome((index, outcome) => settledAt.push([index, outcome, h.clock.time]));

    // The normal relay settles at the publication instant, the hung one only at
    // its own per-relay timeout; the acceptance never waits for the hung relay.
    expect(attempt.outcomes).toEqual(['ACCEPTED', 'PENDING']);
    expect(settledAt).toEqual([[0, 'ACCEPTED', PER_RELAY_TIMEOUT_MS]]);

    h.clock.advance(PER_RELAY_TIMEOUT_MS);
    expect(attempt.outcomes).toEqual(['ACCEPTED', 'TIMED_OUT']);
    expect(settledAt).toEqual([
      [0, 'ACCEPTED', PER_RELAY_TIMEOUT_MS],
      [1, 'TIMED_OUT', 2 * PER_RELAY_TIMEOUT_MS],
    ]);
    await set.dispose();
  });

  test('twoHungRelaysExhaustion: two never-answering relays time out on their own timeout', async () => {
    // docs/architecture/m3/scenarios/hung-relay.md, timeline `twoHungRelaysExhaustion`.
    const h = makeHarness([{ behaviour: 'hang', answer: 'silent' }, { behaviour: 'hang', answer: 'silent' }]);
    const set = h.make();
    await expect(startSet(set, h.clock)).resolves.toEqual({ connectedRelays: 2 });
    const attempt = set.publish(EVENT);
    expect(attempt.outcomes).toEqual(['PENDING', 'PENDING']);
    // Nothing settles before the per-relay timeout, and nothing after it.
    h.clock.advance(PER_RELAY_TIMEOUT_MS - 1);
    expect(attempt.outcomes).toEqual(['PENDING', 'PENDING']);
    h.clock.advance(1);
    expect(attempt.outcomes).toEqual(['TIMED_OUT', 'TIMED_OUT']);
    h.clock.advance(PER_RELAY_TIMEOUT_MS);
    expect(attempt.outcomes).toEqual(['TIMED_OUT', 'TIMED_OUT']);
    await set.dispose();
  });

  test('relayLossAndReplacement: the lost relay is retired and replaced', async () => {
    // docs/architecture/m3/scenarios/relay-loss.md, timeline `relayLossAndReplacement`.
    const h = makeHarness([
      { behaviour: 'normal', answer: 'ok-true' },
      { behaviour: 'drop', answer: 'silent' },
    ], { draws: [0] });
    const set = h.make();
    await expect(startSet(set, h.clock)).resolves.toEqual({ connectedRelays: 2 });
    const attempt = set.publish(EVENT);
    expect(attempt.outcomes).toEqual(['ACCEPTED', 'PENDING']);

    h.clock.advance(SUPERVISION_MS);
    expect(attempt.outcomes).toEqual(['ACCEPTED', 'UNREACHABLE']);
    expect(h.created[1].disposed).toBe(1);

    h.clock.advance(499);
    // The replacement is prepared after the delay, not before it (C-DLV §5.2).
    expect(h.created).toHaveLength(2);
    h.clock.advance(1); // delay(1, 0)
    expect(h.created).toHaveLength(3);
    // Let the replacement's connectAll() settle first: a publication on it could
    // only happen after that handler, so asserting before it would be vacuous.
    await flush();
    // The replacement connection exists but nothing was published on it in this
    // attempt (C-DLV §5.3).
    expect(h.created[2].published).toEqual([]);
    expect(h.created[2].subscriptions).toHaveLength(1);
    h.clock.advance(PER_RELAY_TIMEOUT_MS);
    // The attempt is unchanged by the replacement connection.
    expect(attempt.outcomes).toEqual(['ACCEPTED', 'UNREACHABLE']);
    await set.dispose();
  });
});

// ---------------------------------------------------------------------------
// 6. Generative properties over the relay count and the failure mix
// ---------------------------------------------------------------------------

describe('createRelaySet — generative', () => {
  const behaviours = ['normal', 'hang', 'stall', 'drop', 'error'];
  const answers = ['ok-true', 'ok-false', 'silent'];

  /**
   * A deterministic scenario stream defined inside this file, so that the suite
   * imports nothing beyond the module under test and `@jest/globals` (the
   * C-SDK §9 import table lists no property-testing package). The same seed
   * reproduces the same scenarios; a different seed does not have to.
   */
  const scenarios = (seed) => {
    let state = seed >>> 0;
    const draw = () => {
      state ^= state << 13; state >>>= 0;
      state ^= state >>> 17;
      state ^= state << 5; state >>>= 0;
      return state;
    };
    const out = [];
    // Every behaviour x answer x relay count is present; the remaining relays
    // of a scenario are drawn from the same cross.
    for (const behaviour of behaviours) {
      for (const answer of answers) {
        for (let relayCount = 1; relayCount <= 6; relayCount += 1) {
          const specs = [];
          for (let j = 0; j < relayCount; j += 1) {
            specs.push(j === 0
              ? { behaviour, answer }
              : { behaviour: behaviours[draw() % behaviours.length], answer: answers[draw() % answers.length] });
          }
          out.push(specs);
        }
      }
    }
    return out;
  };

  test('the scenario stream is deterministic for a seed and covers the whole cross', () => {
    const stream = scenarios(7);
    expect(stream).toEqual(scenarios(7));
    expect(stream).not.toEqual(scenarios(8));
    const counts = new Set();
    const seen = new Set();
    for (const specs of stream) {
      counts.add(specs.length);
      seen.add(`${specs[0].behaviour}/${specs[0].answer}`);
    }
    expect([...counts].sort((a, b) => a - b)).toEqual([1, 2, 3, 4, 5, 6]);
    expect(seen.size).toBe(behaviours.length * answers.length);
    expect(seen.has('normal/ok-true')).toBe(true);
    expect(seen.has('error/ok-false')).toBe(true);
  });

  test('each relay outcome is reported exactly once, whatever the mix', async () => {
    for (const specs of scenarios(20261003)) {
      const h = makeHarness(specs, { draws: [0, 0, 0, 0, 0, 0] });
      const set = h.make();
      await startSet(set, h.clock);
      const attempt = set.publish(EVENT);
      // A relay that answers settles at the publication instant; a relay that
      // never answers stays PENDING and delays no other relay's outcome
      // (C-DLV §5.3), over the whole deterministic stream.
      specs.forEach((spec, index) => {
        const answered = spec.answer !== 'silent';
        if (spec.behaviour === 'normal') {
          expect(answered ? ['ACCEPTED', 'REJECTED'] : ['PENDING']).toContain(attempt.outcomes[index]);
          return;
        }
        if (spec.behaviour === 'drop') {
          // It accepted the event and then lost the connection, so its outcome
          // at this instant depends on whether a read already saw the loss
          // (C-DLV §5.3): an acceptance of a relay that is no longer connected
          // becomes UNREACHABLE.
          expect(['ACCEPTED', 'REJECTED', 'UNREACHABLE', 'PENDING']).toContain(attempt.outcomes[index]);
          return;
        }
        // A relay that never answered and is still connected stays PENDING.
        expect(attempt.outcomes[index]).toBe('PENDING');
      });
      const reported = attempt.outcomes.map(() => 0);
      let settled = 0;
      attempt.onOutcome((index) => {
        reported[index] += 1;
      });
      attempt.onSettled(() => {
        settled += 1;
      });
      // A listener registered after some relays already settled still hears
      // each of them exactly once, over the whole deterministic stream.
      const lateReports = attempt.outcomes.map(() => 0);
      attempt.onOutcome((index) => {
        lateReports[index] += 1;
      });
      h.clock.advance(PER_RELAY_TIMEOUT_MS);
      set.supervise();
      h.clock.advance(PER_RELAY_TIMEOUT_MS);
      const closing = set.dispose();
      h.clock.advance(RELAYPOOL_CONNECT_TIMEOUT_MS * 3);
      await closing;

      expect(reported.every((count) => count === 1)).toBe(true);
      expect(lateReports.every((count) => count === 1)).toBe(true);
      expect(settled).toBe(1);
      expect(attempt.outcomes.every((outcome) => ['ACCEPTED', 'REJECTED', 'TIMED_OUT', 'UNREACHABLE'].includes(outcome))).toBe(true);
      expect(h.clock.pending).toEqual([]);
      expect(host.live.size).toBe(0);
      expect(h.created.every((pool) => pool.disposed === 1)).toBe(true);
      // No pool is connected twice and none is ever reconnected through
      // `RelayPool`'s own reconnect path.
      expect(h.created.every((pool) => pool.connectCalls === 1)).toBe(true);
    }
  });

  test('no hung relay delays another relay beyond its own timeout', async () => {
    for (let normalCount = 1; normalCount <= 4; normalCount += 1) {
      for (let hungCount = 1; hungCount <= 4; hungCount += 1) {
        const specs = [
          ...Array.from({ length: normalCount }, () => ({ behaviour: 'normal', answer: 'ok-true' })),
          ...Array.from({ length: hungCount }, () => ({ behaviour: 'hang', answer: 'silent' })),
        ];
        const h = makeHarness(specs);
        const set = h.make();
        await startSet(set, h.clock);
        expect(set.connectedRelays).toBe(normalCount + hungCount);

        const attempt = set.publish(EVENT);
        // Every normal relay is accepted at the publication instant, before any
        // hung relay has consumed its per-relay timeout.
        expect(attempt.outcomes.slice(0, normalCount).every((outcome) => outcome === 'ACCEPTED')).toBe(true);
        expect(attempt.outcomes.slice(normalCount).every((outcome) => outcome === 'PENDING')).toBe(true);

        // The hung relay is still PENDING one millisecond before its own timeout.
        h.clock.advance(PER_RELAY_TIMEOUT_MS - 1);
        expect(attempt.outcomes.slice(normalCount).every((outcome) => outcome === 'PENDING')).toBe(true);
        h.clock.advance(1);
        expect(attempt.outcomes.slice(0, normalCount).every((outcome) => outcome === 'ACCEPTED')).toBe(true);
        expect(attempt.outcomes.slice(normalCount).every((outcome) => outcome === 'TIMED_OUT')).toBe(true);
        // Nothing changes again after the hung relays' own timeout.
        h.clock.advance(PER_RELAY_TIMEOUT_MS * 3);
        expect(attempt.outcomes.slice(0, normalCount).every((outcome) => outcome === 'ACCEPTED')).toBe(true);
        expect(attempt.outcomes.slice(normalCount).every((outcome) => outcome === 'TIMED_OUT')).toBe(true);
        await set.dispose();
      }
    }
  });

  test('every subscription and timer is cleaned up on close', async () => {
    for (const specs of scenarios(424242)) {
      const h = makeHarness(specs, { draws: [7, 7, 7] });
      const set = h.make();
      await startSet(set, h.clock);
      set.publish(EVENT);
      h.clock.advance(SUPERVISION_MS);
      const closing = set.dispose();
      h.clock.advance(RELAYPOOL_CONNECT_TIMEOUT_MS * 3);
      await closing;

      expect(h.clock.pending).toEqual([]);
      expect(host.live.size).toBe(0);
      expect(set.stopped).toBe(true);
      expect(h.created.every((pool) => pool.disposed === 1)).toBe(true);
      expect(h.created.every((pool) => pool.messages.count('message') === 0)).toBe(true);
      for (const pool of h.created) {
        expect(pool.subscriptions.length).toBeGreaterThanOrEqual(1);
        expect(pool.subscriptions.every((entry) => entry.subscriptionId === SUBSCRIPTION_ID)).toBe(true);
      }
      const created = h.created.length;
      h.clock.advance(PER_RELAY_TIMEOUT_MS * 4);
      expect(h.created).toHaveLength(created);
    }
  });
});

// ---------------------------------------------------------------------------
// 7. The unchanged RelayPool over an in-process fake WebSocket
// ---------------------------------------------------------------------------

class FakeWebSocket {
  constructor(url) {
    this.url = url;
    this.readyState = 0; // CONNECTING
    this.sent = [];
    this.onopen = null;
    this.onclose = null;
    this.onerror = null;
    this.onmessage = null;
    FakeWebSocket.instances.push(this);
    queueMicrotask(() => {
      if (this.readyState !== 0) return;
      this.readyState = FakeWebSocket.OPEN;
      this.onopen?.();
    });
  }

  send(data) {
    this.sent.push(data);
  }

  close() {
    this.readyState = 3; // CLOSED
    this.onclose?.();
  }

  /** Deliver one decoded frame to the pool. */
  deliver(frame) {
    this.onmessage?.({ data: JSON.stringify(frame) });
  }
}
FakeWebSocket.OPEN = 1;
FakeWebSocket.instances = [];

describe('createRelaySet — the unchanged RelayPool over a fake WebSocket', () => {
  let originalWebSocket;

  beforeEach(() => {
    originalWebSocket = globalThis.WebSocket;
    globalThis.WebSocket = FakeWebSocket;
    FakeWebSocket.instances = [];
  });

  afterEach(() => {
    globalThis.WebSocket = originalWebSocket;
  });

  const relaySet = (clock, relays) => createRelaySet({
    relays,
    clock,
    random: { nextUint32: () => 0 },
    perRelayTimeoutMs: PER_RELAY_TIMEOUT_MS,
    subscriptionId: SUBSCRIPTION_ID,
    filter: FILTER,
  });

  test('the default transport is one RelayPool per relay and the REQ is sent on open', async () => {
    const clock = new ManualClock();
    const set = relaySet(clock, ['ws://127.0.0.1:21201/', 'ws://127.0.0.1:21202/']);
    const promise = set.start();
    // Host time: the fake sockets open and every `connectAll()` settles, so the
    // phase ends with the connections already joined (C-DLV §5.2).
    await flush();
    expect(FakeWebSocket.instances).toHaveLength(2);
    clock.advance(PER_RELAY_TIMEOUT_MS);
    await expect(promise).resolves.toEqual({ connectedRelays: 2 });
    for (const socket of FakeWebSocket.instances) {
      expect(socket.sent).toEqual([JSON.stringify(['REQ', SUBSCRIPTION_ID, FILTER])]);
    }
    await set.dispose();
    expect(FakeWebSocket.instances.every((socket) => socket.readyState === 3)).toBe(true);
  });

  test('an OK frame from one relay settles that relay only', async () => {
    const clock = new ManualClock();
    const set = relaySet(clock, ['ws://127.0.0.1:21203/', 'ws://127.0.0.1:21204/']);
    const promise = set.start();
    // Host time: the fake sockets open and every `connectAll()` settles, so the
    // phase ends with the connections already joined (C-DLV §5.2).
    await flush();
    clock.advance(PER_RELAY_TIMEOUT_MS);
    await promise;

    const attempt = set.publish(EVENT);
    expect(attempt.outcomes).toEqual(['PENDING', 'PENDING']);
    expect(FakeWebSocket.instances[0].sent[1]).toBe(JSON.stringify(['EVENT', EVENT]));
    FakeWebSocket.instances[1].deliver(['OK', EVENT.id, true, 'saved']);
    expect(attempt.outcomes).toEqual(['PENDING', 'ACCEPTED']);
    clock.advance(PER_RELAY_TIMEOUT_MS);
    expect(attempt.outcomes).toEqual(['TIMED_OUT', 'ACCEPTED']);
    await set.dispose();
  });

  test('one RelayPool per relay, addressed by its own URL', async () => {
    const clock = new ManualClock();
    const relays = ['ws://127.0.0.1:21211/', 'ws://127.0.0.1:21212/', 'ws://127.0.0.1:21213/'];
    const set = relaySet(clock, relays);
    const promise = set.start();
    await flush();
    await flush();
    // The default transport is the unchanged RelayPool, one per relay, and each
    // instance was constructed with that relay's own URL (C-DLV §5.1).
    expect(FakeWebSocket.instances.map((socket) => socket.url)).toEqual(relays);
    clock.advance(PER_RELAY_TIMEOUT_MS);
    await expect(promise).resolves.toEqual({ connectedRelays: 3 });
    for (const socket of FakeWebSocket.instances) {
      expect(socket.sent).toEqual([JSON.stringify(['REQ', SUBSCRIPTION_ID, FILTER])]);
    }
    await set.dispose();
    expect(FakeWebSocket.instances.every((socket) => socket.readyState === 3)).toBe(true);
  });

  test('an unexpected frame does not settle a relay', async () => {
    const clock = new ManualClock();
    const set = relaySet(clock, ['ws://127.0.0.1:21205/']);
    const promise = set.start();
    // Host time: the fake sockets open and every `connectAll()` settles, so the
    // phase ends with the connections already joined (C-DLV §5.2).
    await flush();
    clock.advance(PER_RELAY_TIMEOUT_MS);
    await promise;
    const attempt = set.publish(EVENT);
    FakeWebSocket.instances[0].deliver(['OK', 'f'.repeat(64), true, 'other event']);
    FakeWebSocket.instances[0].deliver('not-a-frame');
    expect(attempt.outcomes).toEqual(['PENDING']);
    clock.advance(PER_RELAY_TIMEOUT_MS);
    expect(attempt.outcomes).toEqual(['TIMED_OUT']);
    await set.dispose();
  });
});
