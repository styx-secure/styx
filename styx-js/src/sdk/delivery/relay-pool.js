// styx-js/src/sdk/delivery/relay-pool.js
//
// M3 early lane, card I-RELAY: parallel multi-relay publish and subscribe with
// per-relay timeouts. SDK-internal module: it is not part of the public surface
// of `styx-js/src/sdk/index.js`.
//
// It implements C-DLV §5.1 to §5.5 (`docs/architecture/m3/delivery-layer.md`):
// at most one current `RelayPool` per configured relay, one subscription per
// relay registered before the connection opens, parallel publication of an
// attempt, one outcome per relay and per attempt, per-relay timeouts, relay
// supervision, retirement and replacement after a loss, and closing.
//
// A relay that hangs never delays another relay's outcome, the acceptance of an
// item or the settlement of another relay: every publication and every outcome
// is per relay and no step of one relay awaits another.
//
// Imports are exactly the C-DLV §9 subset for this card: the unchanged
// `RelayPool` export of `styx-js/src/transport/nostr-transport.js`, and the
// runtime globals `setTimeout` and `clearTimeout`. No relay URL literal and no
// default relay list appears here: `options.relays` is caller configuration.

import { RelayPool } from '../../transport/nostr-transport.js';

// Closed per-relay outcome set, C-SDK §6.3 / C-DLV §5.3. These are the values
// of the interface enumeration, not a second definition of it.
const PENDING = 'PENDING';
const ACCEPTED = 'ACCEPTED';
const REJECTED = 'REJECTED';
const TIMED_OUT = 'TIMED_OUT';
const UNREACHABLE = 'UNREACHABLE';

// C-DLV §3 fixed value: relay supervision interval.
const RELAY_SUPERVISION_MS = 1000;
// C-DLV §3: backoff base and cap, used by the reconnect delay of §5.2.
const BACKOFF_BASE_MS = 1000;
const BACKOFF_CAP_MS = 30000;
// 2^33, the divisor of the jitter term of C-DLV §4.3.
const JITTER_DIVISOR = 8589934592;
// Two to the thirty-two, the exclusive upper bound of `random.nextUint32()`.
const UINT32_LIMIT = 4294967296;

/**
 * This module's own "no timer is armed" marker. A timer handle is an opaque
 * value of the injected clock (C-SDK §8.4), so the module cannot use `null` as
 * its sentinel: a port that returns `null` for a live handle would look like an
 * unarmed timer and its timer would never be cleared.
 */
const NOT_ARMED = Symbol('relay-pool: no timer armed');

/**
 * The pure `delay(k, u)` schedule of C-DLV §4.3, used by §5.2 for the
 * reconnection of one relay after its k-th consecutive loss.
 *
 * I-RETRY owns this schedule in C-DLV §9, but that module does not exist at
 * this card's base, so the card carries the identical formula as the private
 * default and a caller may inject I-RETRY's own implementation with
 * `options.reconnectDelay`. The schedule is not exported here: I-RETRY owns it
 * and this module owns only when and with which `k` it is applied.
 *
 * @param {number} k - consecutive failures of one relay, 1-based
 * @param {number} u - one `random.nextUint32()` value
 * @returns {number} milliseconds
 */
function reconnectDelay(k, u) {
  const base = Math.min(BACKOFF_BASE_MS * Math.pow(2, k - 1), BACKOFF_CAP_MS);
  return Math.floor(base / 2) + Math.floor((u * base) / JITTER_DIVISOR);
}

/** The largest delay of one backoff step, `base(k) - 1` ms (C-DLV §5.2). */
function largestDelayOfStep(k) {
  const base = Math.min(BACKOFF_BASE_MS * Math.pow(2, k - 1), BACKOFF_CAP_MS);
  return base - 1;
}

function isUint32(value) {
  return Number.isInteger(value) && value >= 0 && value < UINT32_LIMIT;
}

/** One relay's supervision state. */
function relayState(url, index) {
  return {
    index,
    url,
    pool: null,
    // True while the current pool's `connectAll()` promise has not settled.
    connecting: false,
    // True when the current pool's `healthCheck()` reports it connected.
    connected: false,
    // The current connection attempt's promise, kept so that closing can wait.
    settle: null,
    // Consecutive failed or lost connections of this relay (C-DLV §5.2).
    losses: 0,
    // Armed reconnection timer handle on the clock port (C-SDK §8.4).
    reconnectHandle: NOT_ARMED,
  };
}

/**
 * One publication attempt over every configured relay.
 *
 * `outcomes` is a live array in `options.relays` order, one entry per relay,
 * each settling to `PENDING` -> one of `ACCEPTED`, `REJECTED`, `TIMED_OUT` or
 * `UNREACHABLE`, exactly once (C-DLV §5.3). `onOutcome` reports each relay's
 * settlement exactly once; `onSettled` fires once when no entry is `PENDING`.
 */
function attemptState(event, index, relayCount) {
  const listeners = new Set();
  const settledListeners = new Set();
  const state = {
    index,
    event,
    outcomes: new Array(relayCount).fill(PENDING),
    publishedOnce: new Array(relayCount).fill(false),
    // The pool this attempt has already called `publish` on while it was
    // connected, per relay, so §5.3's "calls `publish(event)` on it once" holds
    // per pool: a replacement is a new pool and keeps its late-open
    // publication, while the same pool is never written to twice.
    calledPool: new Array(relayCount).fill(null),
    acceptedIndex: -1,
    // Set by dispose(): no outcome may change after the freeze (C-DLV §5.3).
    frozen: false,
    // Set by the caller after FAILED_NOT_ACCEPTED / CANCELLED: OK frames for
    // this attempt are then ignored and only PENDING -> TIMED_OUT remains.
    acksIgnored: false,
    // Caller-supplied predicates; see the module documentation below.
    acceptGate: null,
    latePublishGate: null,
    clockHandle: NOT_ARMED,
    hostHandle: NOT_ARMED,
  };

  const report = (relayIndex, outcome) => {
    if (state.outcomes[relayIndex] !== PENDING) return;
    state.outcomes[relayIndex] = outcome;
    if (outcome === ACCEPTED && state.acceptedIndex < 0) {
      state.acceptedIndex = relayIndex;
    }
    const snapshot = [...listeners];
    for (const listener of snapshot) {
      try {
        listener(relayIndex, outcome);
      } catch {
        // A listener fault never breaks another relay's outcome.
      }
    }
    if (state.isSettled()) {
      notifySettled();
    }
  };

  state.isSettled = () => state.outcomes.every((outcome) => outcome !== PENDING);

  /** Settle one relay unless it is frozen, already settled or acknowledgements
   * are ignored (after `ignoreAcks` only PENDING -> TIMED_OUT remains). */
  state.settle = (relayIndex, outcome) => {
    if (state.frozen) return;
    if (state.acksIgnored && outcome !== TIMED_OUT) return;
    report(relayIndex, outcome);
  };

  /**
   * Fire every settled listener that has not fired yet. The listener is
   * dropped as it is called, so `onSettled` fires exactly once per attempt
   * even when a listener registers while the last outcome is being reported.
   */
  const notifySettled = () => {
    for (const listener of [...settledListeners]) {
      settledListeners.delete(listener);
      try {
        listener();
      } catch {
        // A listener fault never breaks another listener.
      }
    }
  };

  state.onOutcome = (listener) => {
    // The already-settled entries are snapshotted before the listener joins the
    // live set, so a settlement that the replayed callbacks trigger cannot
    // report the same relay to this listener twice.
    const settled = [];
    for (let index = 0; index < state.outcomes.length; index += 1) {
      if (state.outcomes[index] !== PENDING) settled.push([index, state.outcomes[index]]);
    }
    const already = listeners.has(listener);
    listeners.add(listener);
    // A listener registered after some relays settled still receives each of
    // those relays' outcomes once, so "exactly once per relay" holds for every
    // listener and not only for one registered before the publication. The same
    // function registered twice is one listener and is not replayed twice.
    if (!already) {
      for (const [index, outcome] of settled) {
        try {
          listener(index, outcome);
        } catch {
          // as above
        }
      }
    }
    return () => listeners.delete(listener);
  };

  state.onSettled = (listener) => {
    settledListeners.add(listener);
    // A listener registered after the attempt settled still receives it once:
    // every relay can be sticky-`ACCEPTED` before `publish` even returns.
    if (state.isSettled()) notifySettled();
    return () => settledListeners.delete(listener);
  };

  /** Ignore further acknowledgements, keeping PENDING -> TIMED_OUT. */
  state.ignoreAcks = () => {
    state.acksIgnored = true;
  };

  return state;
}

/**
 * The public face of one attempt: exactly the members the card contract lists
 * (Issue #426, Observable outcome) and nothing else. The module keeps its own
 * record, which holds the timers, the settlement and the per-pool bookkeeping, so
 * a caller cannot forge a settlement, reach a live `RelayPool` through
 * `calledPool`, or disarm a timeout by overwriting a handle.
 *
 * The facade is frozen, has a null prototype and non-configurable members, so
 * it cannot be extended or redefined; only the two gates are assignable, as
 * accessor pairs. `outcomes` and `publishedOnce` are read-only live views of
 * the record's arrays: they always read the current values, and every write,
 * definition, deletion, extension prevention or prototype change through them
 * is refused (a TypeError in strict code), so a caller cannot forge an outcome.
 *
 * The Proxy handler and every property descriptor below have a null prototype:
 * a trap or a descriptor field is looked up through the prototype chain, so an
 * inherited `Object.prototype.get` would otherwise become a `get` trap that is
 * handed the record's own array.
 */
const READ_ONLY_VIEW = Object.freeze({
  __proto__: null,
  set: () => false,
  defineProperty: () => false,
  deleteProperty: () => false,
  preventExtensions: () => false,
  setPrototypeOf: () => false,
});
const readOnlyView = (array) => new Proxy(array, READ_ONLY_VIEW);

const publicAttempts = new WeakMap();
function publicAttempt(record) {
  const cached = publicAttempts.get(record);
  if (cached) return cached;
  const value = (v) => ({ __proto__: null, value: v, enumerable: true, writable: false, configurable: false });
  const facade = Object.create(null, {
    __proto__: null,
    index: value(record.index),
    event: value(record.event),
    outcomes: value(readOnlyView(record.outcomes)),
    publishedOnce: value(readOnlyView(record.publishedOnce)),
    acceptedIndex: {
      __proto__: null,
      get: () => record.acceptedIndex,
      enumerable: true,
      configurable: false,
    },
    isSettled: value(record.isSettled),
    onOutcome: value(record.onOutcome),
    onSettled: value(record.onSettled),
    ignoreAcks: value(record.ignoreAcks),
    acceptGate: {
      __proto__: null,
      get: () => record.acceptGate,
      set: (gate) => { record.acceptGate = gate; },
      enumerable: true,
      configurable: false,
    },
    latePublishGate: {
      __proto__: null,
      get: () => record.latePublishGate,
      set: (gate) => { record.latePublishGate = gate; },
      enumerable: true,
      configurable: false,
    },
  });
  Object.freeze(facade);
  publicAttempts.set(record, facade);
  return facade;
}

/**
 * Create the relay set of one client.
 *
 * @param {object} options
 * @param {string[]} options.relays - 1 to 16 relay URLs, caller configuration.
 *   No default list and no fallback relay exists.
 * @param {object} options.clock - the injected clock port `{ now, setTimer,
 *   clearTimer }` (C-SDK §8.4). Every delivery timer of this module is armed
 *   with it, and the attempt timeout and the connection phase also carry a host
 *   `setTimeout` backstop of the same delay (C-DLV §4.5).
 * @param {object} options.random - the injected randomness port
 *   `{ nextUint32 }`, used only for reconnection delays.
 * @param {number} options.perRelayTimeoutMs - per relay, per attempt.
 * @param {string} options.subscriptionId - one per client (C-DLV §5.4).
 * @param {object} options.filter - the subscription filter (C-DLV §5.4).
 * @param {object} [options.transport] - in-process transport port
 *   `{ create(url) -> pool }`. The default creates the unchanged `RelayPool`
 *   with a one-element URL list (C-DLV §5.1). The port exists so that unit
 *   tests run against an in-process fake; the product path uses `RelayPool`.
 * @param {Function} [options.reconnectDelay] - the pure `delay(k, u)` schedule
 *   (C-DLV §4.3). Defaults to the private schedule of this module, which
 *   `I-RETRY` owns once it exists; the module exports it to no caller.
 * @returns {object} the relay set handle, documented below.
 */
export function createRelaySet(options) {
  const {
    relays,
    clock,
    random,
    perRelayTimeoutMs,
    subscriptionId,
    filter,
    transport,
    reconnectDelay: delayOf = reconnectDelay,
  } = options;

  if (!Array.isArray(relays) || relays.length === 0) {
    throw new TypeError('createRelaySet: `relays` must be a non-empty array');
  }
  if (!clock || typeof clock.now !== 'function' || typeof clock.setTimer !== 'function' || typeof clock.clearTimer !== 'function') {
    throw new TypeError('createRelaySet: `clock` must expose now, setTimer and clearTimer');
  }
  if (!random || typeof random.nextUint32 !== 'function') {
    throw new TypeError('createRelaySet: `random` must expose nextUint32');
  }
  if (!Number.isInteger(perRelayTimeoutMs) || perRelayTimeoutMs <= 0) {
    throw new TypeError('createRelaySet: `perRelayTimeoutMs` must be a positive integer');
  }

  // A transport port keeps its own `this`: `create` is called as a method of the
  // object that carries it, so a class-based port works too (C-SDK §8.4).
  const createPool = transport && typeof transport.create === 'function'
    ? (url) => transport.create(url)
    : (url) => new RelayPool([url]);

  const states = relays.map((url, index) => relayState(url, index));
  const frameListeners = new Set();
  // Live attempts by event id: an OK frame settles the relay of the item's
  // latest attempt that published that event id (C-DLV §5.3).
  const attemptsByEventId = new Map();
  const liveAttempts = new Set();

  let stopped = false;
  let running = false;
  let supervisionHandle = NOT_ARMED;
  let supervisionOnHost = false;
  let supervising = false;
  let attemptCounter = 0;
  // The connection phase's own end, so a close during the phase clears its two
  // timers instead of leaving them armed (§5.5).
  let phaseEnd = null;
  // One `start()` and one `dispose()` at a time: a second call of either gets
  // the promise of the call in progress (§5.1, §5.5).
  let startPromise = null;
  let startedResult = null;
  let disposePromise = null;

  // --- Timers -------------------------------------------------------------

  const armClock = (callback, delayMs) => clock.setTimer(callback, delayMs);
  const clearClock = (handle) => {
    if (handle === NOT_ARMED) return;
    try {
      clock.clearTimer(handle);
    } catch {
      // An injected clock that refuses to clear changes nothing here.
    }
  };
  const armHost = (callback, delayMs) => setTimeout(callback, delayMs);
  const clearHost = (handle) => {
    if (handle === NOT_ARMED) return;
    clearTimeout(handle);
  };

  // --- Pools --------------------------------------------------------------

  const detachPool = (state) => {
    const pool = state.pool;
    state.pool = null;
    state.connected = false;
    state.connecting = false;
    state.settle = null;
    if (!pool) return null;
    if (state.frameHandler && typeof pool.messages?.off === 'function') {
      try {
        pool.messages.off('message', state.frameHandler);
      } catch {
        // A pool that cannot detach is still disposed below.
      }
    }
    state.frameHandler = null;
    return pool;
  };

  /**
   * `UNREACHABLE` for the live attempts that published on this relay and whose
   * connection is now gone: §5.3 sets it for a relay on which `publish` returned
   * `1` in this attempt and whose connection was then lost, both at a supervision
   * read and when the loss is what the relay's own `connectAll()` observed.
   */
  const settleLostConnection = (state) => {
    for (const attempt of liveAttempts) {
      if (attempt.outcomes[state.index] !== PENDING) continue;
      if (attempt.publishedOnce[state.index] && !state.connected && !state.connecting) {
        attempt.settle(state.index, UNREACHABLE);
      }
    }
  };

  /** Retire the relay's current pool (C-DLV §5.1, §5.2). */
  const retire = (state) => {
    const pool = detachPool(state);
    if (!pool) return;
    try {
      const disposed = pool.dispose();
      if (disposed && typeof disposed.catch === 'function') disposed.catch(() => {});
    } catch {
      // A throwing dispose never breaks another relay.
    }
  };

  /** Prepare one pool: disconnectAll, subscribe, then attach one listener. */
  const prepare = (state) => {
    let pool;
    try {
      pool = createPool(state.url);
    } catch {
      // A transport factory that refuses leaves the relay without a pool; the
      // replacement path picks it up on the next supervision read.
      state.pool = null;
      state.connected = false;
      state.connecting = false;
      return null;
    }
    state.pool = pool;
    state.connected = false;
    state.connecting = false;
    state.frameHandler = (message) => {
      if (stopped) return;
      // A frame of a pool that is no longer this relay's current pool never
      // settles the relay: a callback a retired pool had already queued can run
      // after its listener was removed (C-DLV §5.3, "from that relay's current
      // pool").
      if (state.pool !== pool) return;
      onPoolFrame(state.index, message);
    };
    try {
      const detached = pool.disconnectAll();
      if (detached && typeof detached.catch === 'function') detached.catch(() => {});
    } catch {
      // as above
    }
    try {
      pool.subscribe(subscriptionId, filter);
    } catch {
      // A pool that refuses the subscription simply never delivers frames.
    }
    try {
      pool.messages?.on?.('message', state.frameHandler);
    } catch {
      // as above
    }
    return pool;
  };

  /** Read the relay's current connection state through `healthCheck()`. */
  const readsConnected = (state) => {
    if (!state.pool) return false;
    try {
      const health = state.pool.healthCheck();
      return Array.isArray(health) && !!health[0] && health[0].isConnected === true;
    } catch {
      return false;
    }
  };

  /**
   * Connect one relay's current pool. The attempt is in progress until its
   * `connectAll()` promise settles; a resolution with 0 and a rejection are
   * alike a failed connection (C-DLV §5.2).
   */
  const connect = (state) => {
    const pool = state.pool;
    if (!pool) return;
    state.connecting = true;
    let promise;
    try {
      promise = pool.connectAll();
    } catch (error) {
      promise = Promise.reject(error);
    }
    const settle = Promise.resolve(promise).then(
      () => {
        if (state.pool !== pool) return;
        state.connecting = false;
        state.settle = null;
        state.connected = readsConnected(state);
        if (stopped) return;
        if (state.connected) {
          state.losses = 0;
          onRelayConnected(state.index);
        } else {
          settleLostConnection(state);
          retireAndScheduleReplacement(state);
        }
      },
      () => {
        if (state.pool !== pool) return;
        state.connecting = false;
        state.settle = null;
        state.connected = false;
        if (stopped) return;
        settleLostConnection(state);
        retireAndScheduleReplacement(state);
      },
    );
    // A fault inside either handler never becomes an unhandled rejection and
    // never rejects the promise the close waits on.
    state.settle = settle.catch(() => {});
  };

  /**
   * Retire a relay's pool after a failed or lost connection and arm its
   * replacement connection after `delay(k, u)` (C-DLV §5.1, §5.2).
   */
  const retireAndScheduleReplacement = (state) => {
    // A replacement connection belongs to a started client: during the
    // connection phase and after the close nothing is scheduled here.
    if (stopped || !running) return;
    if (state.reconnectHandle !== NOT_ARMED) return;
    retire(state);
    const k = state.losses + 1;
    let draw;
    try {
      draw = random.nextUint32();
    } catch {
      draw = NaN;
    }
    // An invalid random value is E_SDK_INTERNAL for this reconnection delay and
    // has no surface: the largest delay of the step is used (C-DLV §5.2).
    let delayMs;
    try {
      delayMs = isUint32(draw) ? delayOf(k, draw) : largestDelayOfStep(k);
    } catch {
      // A caller-supplied schedule that throws never takes another relay down.
      delayMs = largestDelayOfStep(k);
    }
    const reconnect = () => {
      state.reconnectHandle = NOT_ARMED;
      if (stopped) return;
      // A factory that refuses leaves the relay without a pool: it keeps its
      // replacement path instead of being left with no pool and no timer.
      // At most one current pool per relay (C-DLV §5.1): a pool that is still
      // current is retired, not overwritten, so a stray second replacement can
      // never leave a connected pool behind.
      if (state.pool !== null) retire(state);
      if (prepare(state) === null) {
        retireAndScheduleReplacement(state);
        return;
      }
      connect(state);
    };
    try {
      state.reconnectHandle = armClock(reconnect, delayMs);
      // The k-th consecutive failure is counted only once its delay is armed: a
      // clock port that refuses the timer leaves the counter unchanged, so the
      // retry of that same failure uses the same delay and one loss is never
      // counted as two (C-DLV §5.2).
      state.losses = k;
    } catch {
      // A clock port that refuses to arm a timer changes nothing here.
      state.reconnectHandle = NOT_ARMED;
    }
  };

  // --- Frames -------------------------------------------------------------

  /**
   * Read one caller-supplied gate. Both gates default to allowing and a gate
   * that throws is read as refusing, so an ill-behaved client can fail the
   * recording of an acceptance but never make this module record one it
   * refused, and a gate fault never escapes into a pool's emitter. The gate
   * receives the attempt's public facade, never the module's own record.
   */
  const gateAllows = (gate, relayIndex, attempt) => {
    if (typeof gate !== 'function') return true;
    try {
      return gate(relayIndex, publicAttempt(attempt)) !== false;
    } catch {
      return false;
    }
  };

  const emitFrame = (record) => {
    for (const listener of [...frameListeners]) {
      try {
        listener(record);
      } catch {
        // A listener fault never changes an outcome.
      }
    }
  };

  /**
   * Handle one decoded frame of one relay's current pool.
   * An `OK` frame settles the relay's outcome of the item's latest attempt;
   * every other frame of the client's subscription is forwarded unchanged to
   * the inbound handler (C-DLV §5.3, §5.4).
   */
  const onPoolFrame = (relayIndex, message) => {
    const data = message && message.data;
    if (!Array.isArray(data) || data.length === 0) return;
    const kind = data[0];
    // C-DLV §5.4: a frame that is not one of the five known kinds, or, for an
    // EVENT, EOSE or CLOSED frame, names another subscription, is ignored.
    if (kind !== 'EVENT' && kind !== 'OK' && kind !== 'EOSE' && kind !== 'NOTICE' && kind !== 'CLOSED') return;
    if (kind !== 'OK' && kind !== 'NOTICE' && data[1] !== subscriptionId) return;
    if (kind === 'OK') {
      const eventId = data[1];
      const attempt = attemptsByEventId.get(eventId);
      if (!attempt) return;
      if (attempt.frozen || attempt.acksIgnored) return;
      if (relayIndex >= attempt.outcomes.length) return;
      if (attempt.outcomes[relayIndex] !== PENDING) return;
      if (data[2] === true) {
        if (!gateAllows(attempt.acceptGate, relayIndex, attempt)) return;
        attempt.settle(relayIndex, ACCEPTED);
      } else if (data[2] === false) {
        attempt.settle(relayIndex, REJECTED);
      }
      return;
    }
    emitFrame({ relayIndex, relay: states[relayIndex].url, data });
  };

  // --- Publication --------------------------------------------------------

  const publishTo = (state, attempt) => {
    if (!state.pool) return false;
    let sent;
    try {
      sent = state.pool.publish(attempt.event);
    } catch {
      sent = 0;
    }
    if (sent === 1) {
      attempt.publishedOnce[state.index] = true;
      attempt.calledPool[state.index] = state.pool;
      return true;
    }
    // C-DLV §5.3 calls `publish(event)` on a relay once per pool that has an
    // open connection at this instant; a relay with no open connection keeps
    // the late-open publication of §5.3. The read is live, because the cached
    // flag can be up to one supervision interval old.
    if (readsConnected(state)) attempt.calledPool[state.index] = state.pool;
    return false;
  };

  /** Publish once on a relay whose connection opened during an attempt. */
  const publishLateOpen = (state, attempt) => {
    // A replacement connection belongs to a running client: after the close
    // nothing is written on it (C-DLV §5.3).
    if (!running) return;
    if (attempt.frozen || attempt.acksIgnored) return;
    if (attempt.outcomes[state.index] !== PENDING) return;
    if (attempt.calledPool[state.index] === state.pool) return;
    if (!state.connected) return;
    if (!gateAllows(attempt.latePublishGate, state.index, attempt)) return;
    // C-DLV §5.2 reads `healthCheck()` whenever `publish` returns 0.
    if (!publishTo(state, attempt)) superviseOnce();
  };

  /** A relay's connection opened: publish on it once for a live attempt. */
  const onRelayConnected = (relayIndex) => {
    const state = states[relayIndex];
    for (const attempt of liveAttempts) {
      publishLateOpen(state, attempt);
    }
  };

  // --- Supervision --------------------------------------------------------

  /**
   * One supervision pass (C-DLV §5.2, §5.3): read every current pool's
   * `healthCheck()`, retire and replace a pool that is not connected and has no
   * connection attempt in progress, mark `UNREACHABLE` the relays that lost the
   * connection after a publication of an attempt, and publish on a relay whose
   * connection opened during a live attempt.
   */
  const superviseOnce = () => {
    if (stopped || !running) return;
    // One read at a time: a replayed listener or a publication may reach this
    // function while a pass is already running.
    if (supervising) return;
    supervising = true;
    try {
      for (const state of states) {
        state.connected = readsConnected(state);
      }
      // An outcome settles before the pools below are retired: the loss a relay
      // showed at this read is what makes its attempt outcome `UNREACHABLE`.
      for (const attempt of liveAttempts) {
        for (const state of states) {
          const index = state.index;
          if (attempt.outcomes[index] !== PENDING) continue;
          if (attempt.publishedOnce[index] && !state.connected && !state.connecting) {
            attempt.settle(index, UNREACHABLE);
            continue;
          }
          if (state.connected) publishLateOpen(state, attempt);
        }
      }
      for (const state of states) {
        if (state.connected) continue;
        // A relay whose current pool is gone and whose replacement timer is not
        // armed — only reachable when an injected port refused — is picked up
        // again here, so no relay is ever left with no pool and no timer.
        const orphan = state.pool === null && state.reconnectHandle === NOT_ARMED;
        if (orphan || (state.pool && !state.connecting)) {
          retireAndScheduleReplacement(state);
        }
      }
    } finally {
      supervising = false;
    }
  };

  const armSupervision = () => {
    if (stopped || supervisionHandle !== NOT_ARMED) return;
    const read = () => {
      supervisionHandle = NOT_ARMED;
      supervisionOnHost = false;
      if (stopped) return;
      // A fault of an injected port never stops supervision: the next read is
      // armed whatever this pass did (C-DLV §5.2).
      try {
        superviseOnce();
      } catch {
        // as above
      }
      armSupervision();
    };
    try {
      supervisionHandle = armClock(read, RELAY_SUPERVISION_MS);
      supervisionOnHost = false;
    } catch {
      // A clock port that refuses the read keeps supervision alive on the host
      // backstop of the same delay (C-DLV §4.5): one refused arming never ends
      // supervision for good.
      try {
        supervisionHandle = armHost(read, RELAY_SUPERVISION_MS);
        supervisionOnHost = true;
      } catch {
        supervisionHandle = NOT_ARMED;
        supervisionOnHost = false;
      }
    }
  };

  const clearSupervision = () => {
    if (supervisionOnHost) clearHost(supervisionHandle);
    else clearClock(supervisionHandle);
    supervisionHandle = NOT_ARMED;
    supervisionOnHost = false;
  };

  // --- Lifecycle ----------------------------------------------------------

  const countConnected = () => {
    let count = 0;
    for (const state of states) {
      // A pool counts as connected when its `healthCheck()` reports the relay
      // connected, but a connection attempt still in progress at the phase end
      // never joins the completed phase: it does not count in `connectedRelays`
      // and does not change the result of `start()` (C-DLV §5.2). It becomes
      // the relay's connection when its attempt settles connected.
      const connected = !state.connecting && readsConnected(state);
      state.connected = connected;
      if (connected) count += 1;
    }
    return count;
  };

  /** Wait until every connection attempt of every current pool has settled. */
  const waitForConnectionAttempts = async () => {
    const pending = states.map((state) => state.settle).filter((p) => p && typeof p.then === 'function');
    await Promise.all(pending);
  };

  const disposePools = async () => {
    const disposals = states.map((state) => {
      const pool = detachPool(state);
      if (!pool) return Promise.resolve();
      try {
        return Promise.resolve(pool.dispose()).catch(() => {});
      } catch {
        return Promise.resolve();
      }
    });
    await Promise.all(disposals);
  };

  /** The connection phase of `start()`: `perRelayTimeoutMs` on the clock, with a host backstop. */
  const runConnectionPhase = () => new Promise((resolve) => {
    let done = false;
    let hostHandle = NOT_ARMED;
    let clockHandle = NOT_ARMED;
    const end = () => {
      if (done) return;
      done = true;
      clearHost(hostHandle);
      clearClock(clockHandle);
      phaseEnd = null;
      resolve();
    };
    phaseEnd = end;
    let clockArmed = false;
    try {
      clockHandle = armClock(end, perRelayTimeoutMs);
      clockArmed = true;
    } catch {
      // The clock port refused the phase timer: the host backstop of the same
      // delay keeps the phase bound (C-DLV §4.5).
      clockHandle = NOT_ARMED;
    }
    try {
      hostHandle = armHost(end, perRelayTimeoutMs);
    } catch {
      hostHandle = NOT_ARMED;
      // Neither timer could be armed: the phase ends at once, so the start path
      // below still disposes every pool and leaves no timer armed.
      if (!clockArmed) end();
    }
  });

  /**
   * `start()`: prepare one pool per relay, connect them all in parallel and end
   * the connection phase `perRelayTimeoutMs` after it begins, on the clock port
   * with a host backstop (C-DLV §5.2). Resolves with the number of relays
   * connected at the phase end; the caller maps 0 to `E_SDK_NO_RELAY_AVAILABLE`.
   */
  const runStart = async () => {
    for (const state of states) prepare(state);
    const phase = runConnectionPhase();
    for (const state of states) connect(state);
    await phase;
    const connectedRelays = countConnected();
    if (stopped || connectedRelays === 0) {
      // A failed start, or one a close interrupted, waits for the connection
      // attempts, disposes every pool and clears every timer, so a later start
      // begins from scratch and a closed set reports no relay.
      await waitForConnectionAttempts();
      await disposePools();
      running = false;
      return { connectedRelays: 0 };
    }
    running = !stopped;
    // A relay whose connection attempt settled without a connection at the
    // phase end takes the replacement path (C-DLV §5.2).
    for (const state of states) {
      if (!state.connected && !state.connecting) retireAndScheduleReplacement(state);
    }
    armSupervision();
    return { connectedRelays };
  };

  const start = async () => {
    if (stopped) return { connectedRelays: 0 };
    // At most one current pool per relay: a second `start()` while this set is
    // already started returns what the first one returned, and a second
    // `start()` during the phase returns the phase's own promise (C-DLV §5.1).
    if (startPromise) return startPromise;
    if (running) return startedResult ?? { connectedRelays: countConnected() };
    startPromise = runStart().catch(() => ({ connectedRelays: 0 }));
    try {
      startedResult = await startPromise;
      return startedResult;
    } finally {
      startPromise = null;
    }
  };

  /** Publish one attempt to every relay in parallel (C-DLV §5.3). */
  const publish = (event, publishOptions = {}) => {
    const attempt = attemptState(event, ++attemptCounter, states.length);
    const accepted = Array.isArray(publishOptions.accepted) ? publishOptions.accepted : [];
    for (const state of states) {
      const index = state.index;
      if (accepted.includes(index)) {
        // `ACCEPTED` is sticky for an item (C-DLV §5.3), also on an attempt made
        // after the close.
        attempt.outcomes[index] = ACCEPTED;
        if (attempt.acceptedIndex < 0) attempt.acceptedIndex = index;
        attempt.publishedOnce[index] = true;
      } else {
        attempt.outcomes[index] = PENDING;
      }
    }
    if (stopped) {
      attempt.frozen = true;
      return publicAttempt(attempt);
    }
    const onTimeout = () => {
      const clockHandle = attempt.clockHandle;
      const hostHandle = attempt.hostHandle;
      attempt.clockHandle = NOT_ARMED;
      attempt.hostHandle = NOT_ARMED;
      // Whichever of the two timers fired, the twin is cleared here: a timer
      // this module armed is never left armed (C-DLV §5.2, §5.5).
      clearHost(hostHandle);
      clearClock(clockHandle);
      if (attempt.frozen) return;
      for (const state of states) {
        if (attempt.outcomes[state.index] === PENDING) {
          attempt.settle(state.index, TIMED_OUT);
        }
      }
      attempt.frozen = true;
      liveAttempts.delete(attempt);
      if (attempt.event && attemptsByEventId.get(attempt.event.id) === attempt) {
        attemptsByEventId.delete(attempt.event.id);
      }
    };
    // The attempt timeout is armed before the attempt becomes live, so a clock
    // port that refuses the clock timer still leaves the host backstop of the
    // same delay (C-DLV §4.5) rather than an attempt with no timeout at all.
    try {
      attempt.clockHandle = armClock(onTimeout, perRelayTimeoutMs);
    } catch {
      attempt.clockHandle = NOT_ARMED;
    }
    try {
      attempt.hostHandle = armHost(onTimeout, perRelayTimeoutMs);
    } catch {
      attempt.hostHandle = NOT_ARMED;
    }
    liveAttempts.add(attempt);
    if (event && typeof event.id === 'string') attemptsByEventId.set(event.id, attempt);

    let anyZero = false;
    for (const state of states) {
      if (attempt.outcomes[state.index] === ACCEPTED) continue;
      const sent = publishTo(state, attempt);
      if (!sent) anyZero = true;
    }
    // C-DLV §5.2 reads `healthCheck()` whenever `publish` returns 0.
    if (anyZero) superviseOnce();
    return publicAttempt(attempt);
  };

  /**
   * Orderly close (C-DLV §5.3, §5.5): synchronously stop supervision and
   * reconnection, clear every timer and freeze every relay outcome at its
   * current value, then wait for every connection attempt to settle and
   * `dispose()` every current pool. Never rejects.
   */
  const runDispose = async () => {
    stopped = true;
    running = false;
    clearSupervision();
    for (const state of states) {
      clearClock(state.reconnectHandle);
      state.reconnectHandle = NOT_ARMED;
    }
    for (const attempt of liveAttempts) {
      clearClock(attempt.clockHandle);
      clearHost(attempt.hostHandle);
      attempt.clockHandle = NOT_ARMED;
      attempt.hostHandle = NOT_ARMED;
      attempt.frozen = true;
    }
    liveAttempts.clear();
    attemptsByEventId.clear();
    // A close that interrupts a `start()` waits for that `start()` first
    // (C-DLV §5.5): the phase is ended here so that the wait terminates, and
    // the phase's own two timers are cleared with it.
    const inflight = startPromise;
    if (phaseEnd) phaseEnd();
    if (inflight) {
      try {
        await inflight;
      } catch {
        // `start()` never rejects; this is only belt and braces.
      }
    }
    await waitForConnectionAttempts();
    await disposePools();
    frameListeners.clear();
  };

  const dispose = async () => {
    // One close: a second caller waits for the same close instead of being
    // told "closed" while the pools are still open (C-DLV §5.5).
    if (disposePromise) return disposePromise;
    disposePromise = runDispose();
    return disposePromise;
  };

  return {
    /** Relay count of the caller's configuration. */
    get relayCount() {
      return states.length;
    },
    /** Relays whose current pool reports connected, a connection still in progress not counting. */
    get connectedRelays() {
      return states.filter((state) => !state.connecting && readsConnected(state)).length;
    },
    get stopped() {
      return stopped;
    },
    get running() {
      return running;
    },
    start,
    publish,
    supervise: superviseOnce,
    dispose,
    /** Subscribe to the inbound frames of every current pool. */
    onFrame: (listener) => {
      frameListeners.add(listener);
      return () => frameListeners.delete(listener);
    },
  };
}
