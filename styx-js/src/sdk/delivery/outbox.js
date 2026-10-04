/**
 * I-QUEUE -- in-memory outbound queue of the M3 early-lane delivery layer
 * (C-DLV section 4), behind the storage port of C-SDK section 8.1, with the
 * retransmission schedule of I-RETRY, plus the outbound message event of
 * C-DLV section 6.2, the item record of section 6.4 and the retention of
 * section 4.6.
 *
 * This module is SDK-internal (C-DLV section 9). It owns the item: admission
 * (section 4.2), attempts and retransmission (section 4.3), the deadline
 * (section 4.4), timers, faults and unknown values (section 4.5), and
 * retention, continuations, cancel and shutdown (section 4.6). It owns no
 * relay: one attempt is handed to the caller's publication seam, which is the
 * per-relay publication of section 5.3 that card I-RELAY implements, and this
 * module mirrors the per-relay outcomes that seam reports. It adds no bound,
 * no state, no ordering rule and no code of its own: every value below is the
 * one C-DLV fixes.
 *
 * Nothing a caller supplies escapes as an exception. Every read of an
 * injected port happens inside a guarded path, so a port that is absent, is
 * not a function, throws when read or throws when called, and a value that
 * does not settle within its port-call timeout, are all mapped to the code
 * C-DLV fixes for them (`E_SDK_INTERNAL`, `E_SDK_STORAGE_FAILED`,
 * `E_SDK_SESSION_FAILED`, `E_SDK_IDENTITY_FAILED` or `E_SDK_UNKNOWN_CODE`),
 * never rethrown. A port return is validated, and a closed slot of a return
 * (`code`, `state`, `outcome`, `lastCode`, `receiptMode`) outside the closed
 * sets of C-SDK is `E_SDK_UNKNOWN_CODE`, which takes precedence.
 *
 * The public objects this module returns and the callback payloads it hands
 * out are frozen and carry exactly the members this card's contract lists. A
 * callback receives the frozen public event, never the internal record, and a
 * snapshot is a fresh frozen copy, so no caller can forge a state or watch an
 * internal array change.
 */

import { sha256 } from '@noble/hashes/sha256';

import { bytesToBase64, bytesToHex, hexToBytes, randomBytes, utf8Encode } from '../../utils.js';
import { planRetry } from './retry.js';

/* ------------------------------------------------------------------------- *
 * Fixed values and closed sets, all from C-DLV section 3, C-SDK section 5.2,
 * C-SDK section 6.1 and C-SDK section 6.3. They are carried, not invented.
 * ------------------------------------------------------------------------- */

/** C-DLV section 3: the queue bound, 256 non-terminal items per client. */
const QUEUE_BOUND_NON_TERMINAL = 256;

/** C-DLV section 3: the payload maximum, 65 536 bytes. */
const PAYLOAD_MAX_BYTES = 65536;

/** C-DLV section 3: the terminal processing slack, 1 000 ms. */
const TERMINAL_PROCESSING_SLACK_MS = 1000;

/** C-DLV section 6.2: the number of `n` tag redraws after a repeated event id. */
const MAX_EVENT_ID_REDRAWS = 3;

/** C-DLV section 6.1: the message event kind. */
const EVENT_KIND_MESSAGE = 4741;

/** C-DLV section 6.2: the interface version string of the `v` tag. */
const INTERFACE_VERSION = 'styx-m3-sdk/0.1.0-experimental';

/** C-SDK section 7: the only event kind this module emits. */
const EVENT_KIND_DELIVERY_STATE_CHANGED = 'DELIVERY_STATE_CHANGED';

/** C-SDK section 4.1: the two receipt modes. */
const RECEIPT_MODE_ACCEPTANCE_ONLY = 'RELAY_ACCEPTANCE_ONLY';
const RECEIPT_MODE_RECIPIENT_RECEIPT = 'RECIPIENT_RECEIPT';

/** C-SDK section 6.1: the closed delivery-state enumeration. */
const STATE_QUEUED = 'QUEUED';
const STATE_IN_FLIGHT = 'IN_FLIGHT';
const STATE_AWAITING_RECEIPT = 'RELAY_ACCEPTED_AWAITING_RECEIPT';
const STATE_RELAY_ACCEPTED = 'RELAY_ACCEPTED';
const STATE_RECEIPT_RECEIVED = 'RECIPIENT_RECEIPT_RECEIVED';
const STATE_FAILED_NOT_ACCEPTED = 'FAILED_NOT_ACCEPTED';
const STATE_FAILED_NO_RECEIPT = 'FAILED_NO_RECEIPT';
const STATE_CANCELLED = 'CANCELLED';
const STATE_LOST_ON_SHUTDOWN = 'LOST_ON_SHUTDOWN';

/** C-DLV section 4.1: every state of the closed enumeration of C-SDK section 6.1. */
const DELIVERY_STATES = new Set([
  STATE_QUEUED,
  STATE_IN_FLIGHT,
  STATE_AWAITING_RECEIPT,
  STATE_RELAY_ACCEPTED,
  STATE_RECEIPT_RECEIVED,
  STATE_FAILED_NOT_ACCEPTED,
  STATE_FAILED_NO_RECEIPT,
  STATE_CANCELLED,
  STATE_LOST_ON_SHUTDOWN,
]);

/** C-SDK section 6.1: the terminal states. */
const TERMINAL_STATES = new Set([
  STATE_RELAY_ACCEPTED,
  STATE_RECEIPT_RECEIVED,
  STATE_FAILED_NOT_ACCEPTED,
  STATE_FAILED_NO_RECEIPT,
  STATE_CANCELLED,
  STATE_LOST_ON_SHUTDOWN,
]);

/** C-SDK section 6.3: the closed per-relay outcome enumeration. */
const RELAY_OUTCOMES = new Set(['PENDING', 'ACCEPTED', 'REJECTED', 'TIMED_OUT', 'UNREACHABLE']);

const OUTCOME_PENDING = 'PENDING';
const OUTCOME_ACCEPTED = 'ACCEPTED';

/** C-DLV section 6.4: the exact field names of the item record. */
const RECORD_FIELDS = Object.freeze([
  'deliveryId',
  'recipient',
  'receiptMode',
  'state',
  'attempts',
  'createdAt',
  'deadlineAt',
  'lastCode',
  'relayOutcomes',
  'ciphertext',
  'event',
]);

/** C-SDK section 5.2: the closed result-code set. */
const SdkResultCode = Object.freeze({
  E_SDK_UNSUPPORTED_VERSION: 'E_SDK_UNSUPPORTED_VERSION',
  E_SDK_INVALID_CONFIG: 'E_SDK_INVALID_CONFIG',
  E_SDK_INVALID_ARGUMENT: 'E_SDK_INVALID_ARGUMENT',
  E_SDK_PAYLOAD_TOO_LARGE: 'E_SDK_PAYLOAD_TOO_LARGE',
  E_SDK_NOT_STARTED: 'E_SDK_NOT_STARTED',
  E_SDK_ALREADY_STARTED: 'E_SDK_ALREADY_STARTED',
  E_SDK_CLIENT_STOPPED: 'E_SDK_CLIENT_STOPPED',
  E_SDK_STORAGE_NOT_EMPTY: 'E_SDK_STORAGE_NOT_EMPTY',
  E_SDK_NO_RELAY_AVAILABLE: 'E_SDK_NO_RELAY_AVAILABLE',
  E_SDK_QUEUE_FULL: 'E_SDK_QUEUE_FULL',
  E_SDK_UNKNOWN_DELIVERY: 'E_SDK_UNKNOWN_DELIVERY',
  E_SDK_DELIVERY_TERMINAL: 'E_SDK_DELIVERY_TERMINAL',
  E_SDK_STORAGE_FAILED: 'E_SDK_STORAGE_FAILED',
  E_SDK_SESSION_FAILED: 'E_SDK_SESSION_FAILED',
  E_SDK_IDENTITY_FAILED: 'E_SDK_IDENTITY_FAILED',
  E_SDK_INBOUND_INVALID: 'E_SDK_INBOUND_INVALID',
  E_SDK_INTERNAL: 'E_SDK_INTERNAL',
  E_SDK_UNKNOWN_CODE: 'E_SDK_UNKNOWN_CODE',
});
const RESULT_CODES = new Set(Object.values(SdkResultCode));

/** C-DLV section 4.5: the `lastCode` values, the `null` of exhaustion and deadline included. */
const LAST_CODES = new Set([
  null,
  SdkResultCode.E_SDK_STORAGE_FAILED,
  SdkResultCode.E_SDK_IDENTITY_FAILED,
  SdkResultCode.E_SDK_INTERNAL,
  SdkResultCode.E_SDK_UNKNOWN_CODE,
]);

/** C-SDK section 4.1: the closed receipt-mode set. */
const RECEIPT_MODES = new Set([RECEIPT_MODE_ACCEPTANCE_ONLY, RECEIPT_MODE_RECIPIENT_RECEIPT]);

/* ------------------------------------------------------------------------- *
 * Small pure helpers.
 * ------------------------------------------------------------------------- */

/**
 * A plain object is one whose prototype is `Object.prototype` or `null`, as
 * C-DLV section 5.2 and C-SDK section 8 read every structure they receive.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
function isPlainObject(value) {
  if (value === null || typeof value !== 'object') return false;
  let proto;
  try {
    proto = Object.getPrototypeOf(value);
  } catch {
    return false;
  }
  return proto === Object.prototype || proto === null;
}

/**
 * The lowercase hexadecimal form of a fixed length: the form C-SDK section 8.3
 * gives a public key and C-DLV section 6.1 an event id.
 *
 * @param {unknown} value
 * @param {number} length
 * @returns {boolean}
 */
function isLowerHexOfLength(value, length) {
  return typeof value === 'string' && value.length === length && /^[0-9a-f]+$/.test(value);
}

/**
 * A clock reading of C-SDK section 8.4 is a finite number of milliseconds;
 * C-DLV section 6.1 states that the clock domain is not narrowed.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
function isValidClockValue(value) {
  return typeof value === 'number' && Number.isFinite(value);
}

/**
 * A promise-like return of a synchronous port method is an invalid value
 * (C-SDK section 8.4).
 *
 * @param {unknown} value
 * @returns {boolean}
 */
function isThenable(value) {
  if (value === null) return false;
  const type = typeof value;
  if (type !== 'object' && type !== 'function') return false;
  return typeof value.then === 'function';
}

/**
 * The first closed slot of a value that carries a name outside the closed sets
 * of C-SDK: `code` (section 5.2), `state` (section 6.1), `outcome` (section
 * 6.3), `lastCode` (C-DLV section 4.5) and `receiptMode` (section 4.1). C-DLV
 * section 4.5 and section 5.2 make such a value `E_SDK_UNKNOWN_CODE`, and it
 * takes precedence over every other code.
 *
 * Every property read is guarded: a getter that throws is reported as a
 * violation of the slot it guards, never allowed to escape.
 *
 * @param {unknown} value
 * @param {number} [depth]
 * @returns {string|null} the offending slot name, or null
 */
function closedSlotViolation(value, depth = 0) {
  if (!isPlainObject(value) || depth > 2) return null;
  const slots = [
    ['code', RESULT_CODES],
    ['state', DELIVERY_STATES],
    ['outcome', RELAY_OUTCOMES],
    ['lastCode', LAST_CODES],
    ['receiptMode', RECEIPT_MODES],
  ];
  for (const [name, allowed] of slots) {
    let present;
    try {
      present = Object.prototype.hasOwnProperty.call(value, name);
    } catch {
      return name;
    }
    if (!present) continue;
    let slot;
    try {
      slot = value[name];
    } catch {
      return name;
    }
    if (name === 'code' && slot === undefined) continue;
    if (!allowed.has(slot)) return name;
  }
  let outcomes;
  try {
    outcomes = value.relayOutcomes;
  } catch {
    return 'outcome';
  }
  if (Array.isArray(outcomes)) {
    for (const entry of outcomes) {
      if (!isPlainObject(entry)) continue;
      let outcome;
      try {
        outcome = entry.outcome;
      } catch {
        return 'outcome';
      }
      if (!RELAY_OUTCOMES.has(outcome)) return 'outcome';
    }
  }
  return null;
}

/** Compare two key lists as sets. @param {string[]} actual @param {readonly string[]} expected */
function sameKeySet(actual, expected) {
  if (actual.length !== expected.length) return false;
  const set = new Set(actual);
  if (set.size !== expected.length) return false;
  return expected.every((key) => set.has(key));
}

/* ------------------------------------------------------------------------- *
 * Host timers. Every host timer is armed and cleared through these, so none
 * can outlive the client, and a host that refuses one is reported rather than
 * rethrown (C-DLV section 4.5: an internal fault).
 * ------------------------------------------------------------------------- */

/**
 * @param {() => void} callback
 * @param {number} delayMs
 * @returns {{ ok: boolean, handle?: unknown }}
 */
function armHostTimer(callback, delayMs) {
  try {
    return { ok: true, handle: setTimeout(callback, delayMs) };
  } catch {
    return { ok: false };
  }
}

/** @param {unknown} handle */
function clearHostTimer(handle) {
  if (handle === null || handle === undefined) return;
  try {
    clearTimeout(handle);
  } catch {
    /* nothing is claimed about a host timer that cannot be cleared */
  }
}

/** @param {() => void} callback @returns {boolean} */
function armMicrotask(callback) {
  try {
    queueMicrotask(callback);
    return true;
  } catch {
    return false;
  }
}

/* ------------------------------------------------------------------------- *
 * Port calls (C-SDK section 8: bounded by the port-call timeout, which C-DLV
 * section 3 fixes at floor(perRelayTimeoutMs / 2) and enforces with the host's
 * own setTimeout, never with the clock port).
 * ------------------------------------------------------------------------- */

/**
 * Await a value with a host-time bound. A value that has not settled when the
 * bound elapses is a timeout; a rejection is a fault.
 *
 * @param {unknown} value
 * @param {number} timeoutMs
 * @returns {Promise<{ settled: boolean, rejected?: boolean, value?: unknown, error?: unknown }>}
 */
function settleWithin(value, timeoutMs) {
  return new Promise((resolve) => {
    let done = false;
    let handle = null;
    const finish = (result) => {
      if (done) return;
      done = true;
      clearHostTimer(handle);
      resolve(result);
    };
    const armed = armHostTimer(() => finish({ settled: false }), timeoutMs);
    if (!armed.ok) {
      // The call cannot be bounded at all, so it is a host fault: refusing it
      // is the safe side and C-DLV section 4.5 maps it to E_SDK_INTERNAL.
      finish({ settled: false });
      return;
    }
    handle = armed.handle;
    let promise;
    try {
      promise = Promise.resolve(value);
    } catch (error) {
      finish({ settled: true, rejected: true, error });
      return;
    }
    promise.then(
      (settled) => finish({ settled: true, value: settled }),
      (error) => finish({ settled: true, rejected: true, error }),
    );
  });
}

/**
 * Read and call one method of an injected port, bounded by the port-call
 * timeout. The property read and the call both happen here, inside the guarded
 * path of the caller, so a port that is absent, a method that is not a
 * function, a getter that throws and a method that throws are all reported the
 * same way (C-SDK section 8.4, C-DLV section 4.5) and never escape.
 *
 * @param {unknown} port
 * @param {string} name
 * @param {unknown[]} args
 * @param {number} timeoutMs
 * @returns {Promise<{ ok: true, value: unknown } | { ok: false, reason: string }>}
 */
async function callPort(port, name, args, timeoutMs) {
  let method;
  try {
    method = port === null || port === undefined ? undefined : port[name];
  } catch {
    return { ok: false, reason: 'read' };
  }
  if (typeof method !== 'function') return { ok: false, reason: 'type' };
  let returned;
  try {
    returned = method.apply(port, args);
  } catch {
    return { ok: false, reason: 'thrown' };
  }
  const settled = await settleWithin(returned, timeoutMs);
  if (!settled.settled) return { ok: false, reason: 'timeout' };
  if (settled.rejected) return { ok: false, reason: 'thrown' };
  return { ok: true, value: settled.value };
}

/**
 * Read and call one method of an injected port synchronously, validating that
 * it returned synchronously (C-SDK section 8.4).
 *
 * @param {unknown} port
 * @param {string} name
 * @param {unknown[]} [args]
 * @returns {{ ok: true, value: unknown } | { ok: false }}
 */
function callSyncPort(port, name, args = []) {
  let method;
  try {
    method = port === null || port === undefined ? undefined : port[name];
  } catch {
    return { ok: false };
  }
  if (typeof method !== 'function') return { ok: false };
  let value;
  try {
    value = method.apply(port, args);
  } catch {
    return { ok: false };
  }
  let thenable;
  try {
    thenable = isThenable(value);
  } catch {
    return { ok: false };
  }
  if (thenable) return { ok: false };
  return { ok: true, value };
}

/* ------------------------------------------------------------------------- *
 * The outbox.
 * ------------------------------------------------------------------------- */

/**
 * Build the outbox of one client.
 *
 * `options` is exactly: `delivery` -- the effective `{ maxAttempts,
 * deadlineMs, perRelayTimeoutMs, receiptMode }` of the client, already inside
 * the C-DLV section 3 bounds; `relayCount` -- the number of configured relays,
 * which fixes the length and the order of every `relayOutcomes`; `storage`,
 * `session` and `identity` -- the ports of C-SDK sections 8.1 to 8.3; `clock`
 * and `random` -- the ports of C-SDK section 8.4; `publish` -- the publication
 * seam of C-DLV section 5.3, called once per attempt with the signed event and
 * returning the attempt of card I-RELAY; `onEvent` -- the sink that receives
 * the frozen `DELIVERY_STATE_CHANGED` event of C-SDK section 7 after every
 * recorded transition, and whose faults C-SDK section 7 ignores.
 *
 * This function never throws, for any `options`: a fault while reading them is
 * remembered as an internal fault and every method then answers
 * `E_SDK_INTERNAL`.
 *
 * @param {object} options
 * @returns {{ send: Function, cancel: Function, getDelivery: Function,
 *            acceptReceipt: Function, inspectStore: Function, shutdown: Function }}
 */
export function createOutbox(options) {
  /* --- options, read once, guarded ------------------------------------- */
  let read = null;
  try {
    const source = options === null || options === undefined ? {} : options;
    read = {
      delivery: source.delivery,
      relayCount: source.relayCount,
      storage: source.storage,
      session: source.session,
      identity: source.identity,
      clock: source.clock,
      random: source.random,
      publish: source.publish,
      onEvent: source.onEvent,
    };
  } catch {
    read = null;
  }
  const creationFault = read === null || read.delivery === null || read.delivery === undefined;

  /** The effective delivery configuration of C-SDK section 4.1. */
  const delivery = (() => {
    if (creationFault) return Object.create(null);
    try {
      return read.delivery;
    } catch {
      return Object.create(null);
    }
  })();

  const items = new Map();
  const lostItems = new Set();
  const assignedEventIds = new Set();
  const admissionWaiters = [];
  let admissionsInProgress = 0;
  let deliveryCounter = 0;
  let stopped = false;
  let cachedPublicKey = null;

  const failure = (code) => Object.freeze({ ok: false, code });

  /* --- guarded reads of the configuration ------------------------------ */

  /**
   * Read one numeric configuration value. C-DLV section 3 bounds it and the
   * client validated it; a malformed one here is an internal fault, because
   * C-DLV gives it no code of its own and this module invents none.
   *
   * @param {string} name
   * @returns {{ ok: boolean, value?: number }}
   */
  function readNumber(name) {
    if (creationFault) return { ok: false };
    let value;
    try {
      value = delivery[name];
    } catch {
      return { ok: false };
    }
    if (!Number.isSafeInteger(value) || value < 1) return { ok: false };
    return { ok: true, value };
  }

  /**
   * Read the receipt mode. A name outside the closed set of C-SDK section 4.1
   * is `E_SDK_UNKNOWN_CODE`; a malformed read is an internal fault.
   *
   * @returns {{ ok: true, value: string } | { ok: false, code: string }}
   */
  function readReceiptMode() {
    if (creationFault) return { ok: false, code: SdkResultCode.E_SDK_INTERNAL };
    let value;
    try {
      value = delivery.receiptMode;
    } catch {
      return { ok: false, code: SdkResultCode.E_SDK_INTERNAL };
    }
    if (!RECEIPT_MODES.has(value)) {
      return { ok: false, code: SdkResultCode.E_SDK_UNKNOWN_CODE };
    }
    return { ok: true, value };
  }

  /** @returns {{ ok: boolean, value?: number }} the port-call timeout. */
  function readPortCallTimeout() {
    const perRelay = readNumber('perRelayTimeoutMs');
    if (!perRelay.ok) return { ok: false };
    return { ok: true, value: Math.floor(perRelay.value / 2) };
  }

  /** @returns {{ ok: boolean, value?: number }} the configured relay count. */
  function readRelayCount() {
    if (creationFault) return { ok: false };
    let value;
    try {
      value = read.relayCount;
    } catch {
      return { ok: false };
    }
    if (!Number.isSafeInteger(value) || value < 0) return { ok: false };
    return { ok: true, value };
  }

  /* --- frozen public shapes -------------------------------------------- */

  /**
   * The per-relay outcome array of a snapshot (C-SDK section 6.2), frozen and
   * rebuilt on every read, so no caller holds a live internal array.
   *
   * @param {object} item
   * @returns {ReadonlyArray<object>}
   */
  function frozenOutcomes(item) {
    return Object.freeze(
      item.outcomes.map((outcome, relayIndex) => Object.freeze({ relayIndex, outcome })),
    );
  }

  /**
   * The delivery snapshot of C-SDK section 6.2: a fresh frozen copy that a
   * later transition never changes.
   *
   * @param {object} item
   * @returns {object}
   */
  function buildSnapshot(item) {
    return Object.freeze({
      deliveryId: item.deliveryId,
      recipient: item.recipient,
      state: item.state,
      terminal: TERMINAL_STATES.has(item.state),
      attempts: item.attempts,
      createdAt: item.createdAt,
      deadlineAt: item.deadlineAt,
      lastCode: item.lastCode,
      relayOutcomes: frozenOutcomes(item),
    });
  }

  /**
   * The item record of C-DLV section 6.4: a frozen plain object with exactly
   * its eleven fields, handed to the storage port, which stores and returns it
   * without interpretation.
   *
   * @param {object} item
   * @returns {object}
   */
  function buildRecord(item) {
    return Object.freeze({
      deliveryId: item.deliveryId,
      recipient: item.recipient,
      receiptMode: item.receiptMode,
      state: item.state,
      attempts: item.attempts,
      createdAt: item.createdAt,
      deadlineAt: item.deadlineAt,
      lastCode: item.lastCode,
      relayOutcomes: frozenOutcomes(item),
      ciphertext: item.ciphertext === null ? null : item.ciphertext.slice(),
      event: item.event,
    });
  }

  /**
   * Deliver one frozen `DELIVERY_STATE_CHANGED` event of C-SDK section 7 to
   * the caller's sink. The payload is the frozen public view, never the
   * internal record, and a sink that is absent, is not a function or throws
   * changes nothing (C-SDK section 7).
   *
   * @param {object} item
   */
  function emitTransition(item) {
    let sink;
    try {
      sink = read === null ? undefined : read.onEvent;
    } catch {
      return;
    }
    if (typeof sink !== 'function') return;
    const event = Object.freeze({
      kind: EVENT_KIND_DELIVERY_STATE_CHANGED,
      deliveryId: item.deliveryId,
      state: item.state,
      terminal: TERMINAL_STATES.has(item.state),
      lastCode: item.lastCode,
    });
    try {
      sink(event);
    } catch {
      /* a listener fault never changes delivery or state (C-SDK section 7) */
    }
  }

  /* --- timers ---------------------------------------------------------- */

  /**
   * Arm one clock-port timer. C-SDK section 8.4 defines
   * `setTimer(callback, delayMs)`, returning an opaque handle.
   *
   * @param {() => void} callback
   * @param {number} delayMs
   * @returns {{ ok: boolean, handle?: unknown }}
   */
  function clockSetTimer(callback, delayMs) {
    const armed = callSyncPort(read.clock, 'setTimer', [callback, delayMs]);
    if (!armed.ok) return { ok: false };
    return { ok: true, handle: armed.value };
  }

  /** @param {unknown} handle */
  function clockClearTimer(handle) {
    if (handle === null || handle === undefined) return;
    callSyncPort(read.clock, 'clearTimer', [handle]);
  }

  /**
   * Fire a delivery timer exactly once. The handle that fired is spent and is
   * not passed to `clearTimer` again; only its sibling is cleared, so each
   * handle reaches the clock port a single time.
   *
   * @param {object} record
   * @param {boolean} byClock
   */
  function runTimer(record, byClock) {
    if (record.fired === true) return;
    record.fired = true;
    if (byClock) clearHostTimer(record.hostHandle);
    else clockClearTimer(record.clockHandle);
    record.callback();
  }

  /**
   * Clear one named timer of an item, both handles (C-DLV section 4.6).
   *
   * @param {object} item
   * @param {string} slot
   */
  function clearItemTimer(item, slot) {
    const record = item.timers[slot];
    if (record === null || record === undefined) return;
    delete item.timers[slot];
    if (record.fired === true) return;
    record.fired = true;
    clearHostTimer(record.hostHandle);
    clockClearTimer(record.clockHandle);
  }

  /** Clear every timer an item holds. @param {object} item */
  function clearItemTimers(item) {
    clearItemTimer(item, 'deadline');
    clearItemTimer(item, 'retry');
  }

  /**
   * Arm the deadline timer of C-DLV section 4.4 and its host `setTimeout`
   * backstop, in the same synchronous step as the clock reading that set
   * `createdAt`.
   *
   * @param {object} item
   * @param {number} deadlineMs
   * @returns {boolean}
   */
  function armDeadline(item, deadlineMs) {
    const record = {
      slot: 'deadline',
      clockHandle: null,
      hostHandle: null,
      fired: false,
      callback: null,
    };
    record.callback = () => {
      clearItemTimer(item, 'deadline');
      item.deadlineFired = true;
      if (stopped) return;
      if (TERMINAL_STATES.has(item.state)) return;
      applyDeadline(item);
    };
    const armed = clockSetTimer(() => runTimer(record, true), deadlineMs);
    if (!armed.ok) return false;
    record.clockHandle = armed.handle;
    item.timers.deadline = record;
    const host = armHostTimer(
      () => runTimer(record, false),
      deadlineMs + TERMINAL_PROCESSING_SLACK_MS,
    );
    if (!host.ok) {
      clearItemTimer(item, 'deadline');
      return false;
    }
    record.hostHandle = host.handle;
    return true;
  }

  /**
   * Arm the retry timer of C-DLV section 4.3: the next attempt starts after
   * the decision's delay, measured on the clock port.
   *
   * @param {object} item
   * @param {number} delayMs
   * @returns {boolean}
   */
  function armRetry(item, delayMs) {
    const record = {
      slot: 'retry',
      clockHandle: null,
      hostHandle: null,
      fired: false,
      callback: null,
    };
    record.callback = () => {
      clearItemTimer(item, 'retry');
      if (stopped) return;
      if (item.cancelInProgress) {
        // A retry that falls due while a cancel write is in progress waits for
        // it (C-DLV section 4.6).
        item.retryDeferred = true;
        return;
      }
      if (item.state !== STATE_QUEUED) return;
      startAttempt(item);
    };
    const armed = clockSetTimer(() => runTimer(record, true), delayMs);
    if (!armed.ok) return false;
    record.clockHandle = armed.handle;
    item.timers.retry = record;
    return true;
  }

  /* --- storage --------------------------------------------------------- */

  /**
   * Issue the storage write of a recorded transition, in the order the
   * transitions were recorded (C-DLV section 6.4 and section 4.6). The record
   * is built at the instant of the transition, so a later transition never
   * rewrites it.
   *
   * @param {object} item
   * @param {object} record
   */
  function writeRecord(item, record) {
    const portCall = readPortCallTimeout();
    if (!portCall.ok) {
      backgroundStorageFailure(item, record.state);
      return;
    }
    const write = async () => {
      const result = await callPort(read.storage, 'update', [item.deliveryId, record], portCall.value);
      if (result.ok) {
        const violation = closedSlotViolation(result.value);
        if (violation !== null) {
          applyTerminalFromFault(item, SdkResultCode.E_SDK_UNKNOWN_CODE);
          return;
        }
        if (result.value === true) return;
      }
      backgroundStorageFailure(item, record.state);
    };
    item.writes = item.writes.then(write, write);
  }

  /**
   * C-DLV section 4.5: a storage write that fails during background processing
   * does not undo the recorded transition; the item keeps the state it had
   * when the write was issued, and if it is still non-terminal it moves at
   * once to its applicable terminal failed state with
   * `lastCode: 'E_SDK_STORAGE_FAILED'`.
   *
   * @param {object} item
   * @param {string} stateAtWrite
   */
  function backgroundStorageFailure(item, stateAtWrite) {
    if (TERMINAL_STATES.has(stateAtWrite)) return;
    if (TERMINAL_STATES.has(item.state)) return;
    applyTerminalFromFault(item, SdkResultCode.E_SDK_STORAGE_FAILED);
  }

  /* --- transitions ----------------------------------------------------- */

  /**
   * Record one transition of C-SDK section 6.1 on an item: set the state, emit
   * the frozen event and write the record. Only the transitions C-DLV fixes
   * are ever passed here; an illegal one is refused rather than recorded, and
   * after an orderly `shutdown()` no further transition is recorded (section
   * 4.6).
   *
   * @param {object} item
   * @param {string} to
   * @param {string|null} lastCode
   * @returns {boolean}
   */
  function recordTransition(item, to, lastCode) {
    if (stopped) return false;
    if (!DELIVERY_STATES.has(to)) return false;
    if (TERMINAL_STATES.has(item.state)) return false;
    item.state = to;
    item.lastCode = lastCode === undefined ? null : lastCode;
    if (TERMINAL_STATES.has(to)) {
      item.ciphertext = null;
      item.event = null;
      const attempt = item.attempt;
      item.attempt = null;
      if (attempt !== null && attempt !== undefined && (to === STATE_FAILED_NOT_ACCEPTED || to === STATE_CANCELLED)) {
        try {
          if (typeof attempt.ignoreAcks === 'function') attempt.ignoreAcks();
        } catch {
          /* a fault of the seam is reported nowhere; the item is terminal */
        }
      }
      clearItemTimers(item);
    }
    emitTransition(item);
    writeRecord(item, buildRecord(item));
    return true;
  }

  /**
   * The applicable terminal failed state of C-DLV section 4.5:
   * `FAILED_NOT_ACCEPTED` from `QUEUED` or `IN_FLIGHT`, `FAILED_NO_RECEIPT`
   * from `RELAY_ACCEPTED_AWAITING_RECEIPT`.
   *
   * @param {object} item
   * @returns {string|null}
   */
  function applicableFailedState(item) {
    if (item.state === STATE_QUEUED || item.state === STATE_IN_FLIGHT) return STATE_FAILED_NOT_ACCEPTED;
    if (item.state === STATE_AWAITING_RECEIPT) return STATE_FAILED_NO_RECEIPT;
    return null;
  }

  /**
   * Move a non-terminal item to its applicable terminal failed state for an
   * internal fault, an invalid clock or random value, a malformed port return
   * or a storage write that failed (C-DLV section 4.5).
   *
   * @param {object} item
   * @param {string} code
   */
  function applyTerminalFromFault(item, code) {
    const to = applicableFailedState(item);
    if (to === null) return;
    recordTransition(item, to, code);
  }

  /**
   * Apply the deadline transition of C-DLV section 4.4 to a non-terminal item:
   * `FAILED_NOT_ACCEPTED` from `QUEUED` or `IN_FLIGHT`, `FAILED_NO_RECEIPT`
   * from `RELAY_ACCEPTED_AWAITING_RECEIPT`, both with `lastCode: null`.
   *
   * @param {object} item
   */
  function applyDeadline(item) {
    if (TERMINAL_STATES.has(item.state)) return;
    const to = item.state === STATE_AWAITING_RECEIPT ? STATE_FAILED_NO_RECEIPT : STATE_FAILED_NOT_ACCEPTED;
    recordTransition(item, to, null);
  }

  /* --- admission (C-DLV section 4.2) ------------------------------------ */

  /**
   * The number of non-terminal items plus the admissions still in progress,
   * which is what the queue bound of C-DLV section 4.2 step 2 counts.
   *
   * @returns {number}
   */
  function occupancy() {
    let count = 0;
    for (const item of items.values()) {
      if (!TERMINAL_STATES.has(item.state)) count += 1;
    }
    return count + admissionsInProgress;
  }

  /** Release one admission reservation. */
  function releaseAdmission() {
    admissionsInProgress -= 1;
    while (admissionWaiters.length > 0) {
      const waiter = admissionWaiters.shift();
      waiter();
    }
  }

  /** @returns {Promise<void>} resolves once no admission is in progress. */
  function admissionsSettled() {
    if (admissionsInProgress === 0) return Promise.resolve();
    return new Promise((resolve) => {
      admissionWaiters.push(resolve);
    });
  }

  /**
   * The identity port's public key, read once for the client's lifetime
   * (C-SDK section 8.3).
   *
   * @returns {Promise<{ ok: true, value: string } | { ok: false, code: string }>}
   */
  async function identityPublicKey() {
    if (cachedPublicKey !== null) return { ok: true, value: cachedPublicKey };
    const portCall = readPortCallTimeout();
    if (!portCall.ok) return { ok: false, code: SdkResultCode.E_SDK_INTERNAL };
    const result = await callPort(read.identity, 'getPublicKey', [], portCall.value);
    if (!result.ok) return { ok: false, code: SdkResultCode.E_SDK_IDENTITY_FAILED };
    const violation = closedSlotViolation(result.value);
    if (violation !== null) return { ok: false, code: SdkResultCode.E_SDK_UNKNOWN_CODE };
    if (!isLowerHexOfLength(result.value, 64)) {
      return { ok: false, code: SdkResultCode.E_SDK_IDENTITY_FAILED };
    }
    cachedPublicKey = result.value;
    return { ok: true, value: cachedPublicKey };
  }

  /**
   * Build and sign the outbound message event of C-DLV section 6.2.
   *
   * @param {object} item
   * @returns {Promise<{ ok: true, value: object } | { ok: false, code: string }>}
   */
  async function buildMessageEvent(item) {
    const portCall = readPortCallTimeout();
    if (!portCall.ok) return { ok: false, code: SdkResultCode.E_SDK_INTERNAL };
    if (item.ciphertext === null) return { ok: false, code: SdkResultCode.E_SDK_INTERNAL };
    const key = await identityPublicKey();
    if (!key.ok) return { ok: false, code: key.code };

    const reading = callSyncPort(read.clock, 'now');
    if (!reading.ok) return { ok: false, code: SdkResultCode.E_SDK_INTERNAL };
    if (!isValidClockValue(reading.value)) return { ok: false, code: SdkResultCode.E_SDK_INTERNAL };
    const createdAtSeconds = Math.floor(reading.value / 1000);
    // C-DLV section 6.1: a negative `created_at`, or one that is not a safe
    // integer, means the structure cannot be built and the item moves to
    // FAILED_NOT_ACCEPTED with E_SDK_INTERNAL. The clock domain is not
    // narrowed; only a non-finite reading is an invalid value.
    if (createdAtSeconds < 0 || !Number.isSafeInteger(createdAtSeconds)) {
      return { ok: false, code: SdkResultCode.E_SDK_INTERNAL };
    }

    let content;
    try {
      content = bytesToBase64(item.ciphertext);
    } catch {
      return { ok: false, code: SdkResultCode.E_SDK_INTERNAL };
    }
    const extraTags = item.receiptMode === RECEIPT_MODE_RECIPIENT_RECEIPT ? [['r', '1']] : [];

    let eventId = null;
    let tags = null;
    for (let redraw = 0; redraw <= MAX_EVENT_ID_REDRAWS; redraw += 1) {
      let nonce;
      try {
        nonce = bytesToHex(randomBytes(16));
      } catch {
        return { ok: false, code: SdkResultCode.E_SDK_INTERNAL };
      }
      tags = [['p', item.recipient], ['v', INTERFACE_VERSION], ['n', nonce], ...extraTags];
      let serialized;
      try {
        serialized = JSON.stringify([
          0,
          key.value,
          createdAtSeconds,
          EVENT_KIND_MESSAGE,
          tags,
          content,
        ]);
      } catch {
        return { ok: false, code: SdkResultCode.E_SDK_INTERNAL };
      }
      try {
        eventId = bytesToHex(sha256(utf8Encode(serialized)));
      } catch {
        return { ok: false, code: SdkResultCode.E_SDK_INTERNAL };
      }
      if (!assignedEventIds.has(eventId)) break;
      eventId = null;
    }
    if (eventId === null) return { ok: false, code: SdkResultCode.E_SDK_INTERNAL };

    let digest;
    try {
      digest = hexToBytes(eventId);
    } catch {
      return { ok: false, code: SdkResultCode.E_SDK_INTERNAL };
    }
    const signed = await callPort(read.identity, 'sign', [{ digest }], portCall.value);
    if (!signed.ok) return { ok: false, code: SdkResultCode.E_SDK_IDENTITY_FAILED };
    const violation = closedSlotViolation(signed.value);
    if (violation !== null) return { ok: false, code: SdkResultCode.E_SDK_UNKNOWN_CODE };
    if (!(signed.value instanceof Uint8Array) || signed.value.length !== 64) {
      return { ok: false, code: SdkResultCode.E_SDK_IDENTITY_FAILED };
    }
    let signature;
    try {
      signature = bytesToHex(signed.value);
    } catch {
      return { ok: false, code: SdkResultCode.E_SDK_INTERNAL };
    }
    assignedEventIds.add(eventId);
    return {
      ok: true,
      value: Object.freeze({
        id: eventId,
        pubkey: key.value,
        created_at: createdAtSeconds,
        kind: EVENT_KIND_MESSAGE,
        tags: Object.freeze(tags.map((tag) => Object.freeze(tag))),
        content,
        sig: signature,
      }),
    };
  }

  /**
   * `send` of C-DLV section 4.2.
   *
   * @param {unknown} argument
   * @returns {Promise<object>}
   */
  async function send(argument) {
    try {
      return await admit(argument);
    } catch {
      return failure(SdkResultCode.E_SDK_INTERNAL);
    }
  }

  /**
   * The body of `send`: the five steps of C-DLV section 4.2.
   *
   * @param {unknown} argument
   * @returns {Promise<object>}
   */
  async function admit(argument) {
    if (stopped) return failure(SdkResultCode.E_SDK_CLIENT_STOPPED);

    // Step 1: argument validation.
    let recipient = null;
    let plaintext = null;
    try {
      if (!isPlainObject(argument)) return failure(SdkResultCode.E_SDK_INVALID_ARGUMENT);
      const keys = Object.keys(argument);
      if (!sameKeySet(keys, ['recipient', 'plaintext'])) {
        return failure(SdkResultCode.E_SDK_INVALID_ARGUMENT);
      }
      recipient = argument.recipient;
      plaintext = argument.plaintext;
    } catch {
      return failure(SdkResultCode.E_SDK_INVALID_ARGUMENT);
    }
    if (!isLowerHexOfLength(recipient, 64)) return failure(SdkResultCode.E_SDK_INVALID_ARGUMENT);
    if (!(plaintext instanceof Uint8Array) || plaintext.length === 0) {
      return failure(SdkResultCode.E_SDK_INVALID_ARGUMENT);
    }
    if (plaintext.length > PAYLOAD_MAX_BYTES) return failure(SdkResultCode.E_SDK_PAYLOAD_TOO_LARGE);

    // Step 2: the queue bound, counting non-terminal items and admissions in
    // progress, so concurrent `send` calls cannot exceed it.
    if (occupancy() >= QUEUE_BOUND_NON_TERMINAL) return failure(SdkResultCode.E_SDK_QUEUE_FULL);
    admissionsInProgress += 1;
    try {
      const mode = readReceiptMode();
      if (!mode.ok) return failure(mode.code);
      const relayCount = readRelayCount();
      if (!relayCount.ok) return failure(SdkResultCode.E_SDK_INTERNAL);
      const deadlineMs = readNumber('deadlineMs');
      if (!deadlineMs.ok) return failure(SdkResultCode.E_SDK_INTERNAL);
      const portCall = readPortCallTimeout();
      if (!portCall.ok) return failure(SdkResultCode.E_SDK_INTERNAL);

      // Step 3: session.seal, bounded by the port-call timeout.
      const sealed = await callPort(read.session, 'seal', [{ recipient, plaintext }], portCall.value);
      if (stopped) return failure(SdkResultCode.E_SDK_CLIENT_STOPPED);
      if (!sealed.ok) return failure(SdkResultCode.E_SDK_SESSION_FAILED);
      let violation = closedSlotViolation(sealed.value);
      if (violation !== null) return failure(SdkResultCode.E_SDK_UNKNOWN_CODE);
      if (!isPlainObject(sealed.value) || Object.keys(sealed.value).length !== 1) {
        return failure(SdkResultCode.E_SDK_SESSION_FAILED);
      }
      let ciphertext = null;
      try {
        ciphertext = sealed.value.ciphertext;
      } catch {
        return failure(SdkResultCode.E_SDK_SESSION_FAILED);
      }
      if (!(ciphertext instanceof Uint8Array) || ciphertext.length === 0) {
        return failure(SdkResultCode.E_SDK_SESSION_FAILED);
      }

      // Step 4: the clock reading, and in the same synchronous step the
      // deadline timer of section 4.4 and its host backstop.
      const reading = callSyncPort(read.clock, 'now');
      if (!reading.ok || !isValidClockValue(reading.value)) {
        return failure(SdkResultCode.E_SDK_INTERNAL);
      }
      const item = {
        deliveryId: null,
        recipient,
        receiptMode: mode.value,
        state: STATE_QUEUED,
        attempts: 0,
        createdAt: reading.value,
        deadlineAt: reading.value + deadlineMs.value,
        lastCode: null,
        outcomes: new Array(relayCount.value).fill(OUTCOME_PENDING),
        ciphertext: ciphertext.slice(),
        event: null,
        attempt: null,
        lastAttempt: null,
        receipt: null,
        deadlineFired: false,
        cancelInProgress: false,
        cancelPromise: null,
        retryDeferred: false,
        writes: Promise.resolve(),
        timers: { deadline: null, retry: null },
      };
      if (!armDeadline(item, deadlineMs.value)) {
        clearItemTimers(item);
        return failure(SdkResultCode.E_SDK_INTERNAL);
      }

      // Step 5: storage.put with the record of section 6.4.
      deliveryCounter += 1;
      item.deliveryId = `d${deliveryCounter}`;
      const put = await callPort(read.storage, 'put', [buildRecord(item)], portCall.value);
      if (stopped) {
        // A `send` past `put` completes it; an item it admits takes
        // QUEUED -> LOST_ON_SHUTDOWN at once (C-DLV section 4.6).
        if (put.ok && put.value === true) {
          items.set(item.deliveryId, item);
          takeLostOnShutdown(item);
          return Object.freeze({
            ok: true,
            value: Object.freeze({ deliveryId: item.deliveryId, state: STATE_QUEUED }),
          });
        }
        return failure(SdkResultCode.E_SDK_CLIENT_STOPPED);
      }
      if (put.ok) {
        violation = closedSlotViolation(put.value);
        if (violation !== null) {
          clearItemTimers(item);
          return failure(SdkResultCode.E_SDK_UNKNOWN_CODE);
        }
        if (put.value === true) {
          items.set(item.deliveryId, item);
          finishAdmission(item);
          return Object.freeze({
            ok: true,
            value: Object.freeze({ deliveryId: item.deliveryId, state: STATE_QUEUED }),
          });
        }
      }
      const putCode =
        put.ok && closedSlotViolation(put.value) !== null
          ? SdkResultCode.E_SDK_UNKNOWN_CODE
          : SdkResultCode.E_SDK_STORAGE_FAILED;

      // A failed `put`: the SDK calls `remove` once. A `remove` that undoes the
      // failed admission succeeds when it returns `true` or `false`.
      const removed = await callPort(read.storage, 'remove', [item.deliveryId], portCall.value);
      const cleaned = removed.ok && (removed.value === true || removed.value === false);
      if (!cleaned) {
        // The residual-item rule of C-DLV section 4.2 and C-SDK section 5.2:
        // the item is recorded in the in-memory view directly as
        // FAILED_NOT_ACCEPTED with lastCode E_SDK_STORAGE_FAILED, one terminal
        // event, and it is never published.
        clearItemTimers(item);
        item.state = STATE_FAILED_NOT_ACCEPTED;
        item.lastCode = SdkResultCode.E_SDK_STORAGE_FAILED;
        item.ciphertext = null;
        item.event = null;
        items.set(item.deliveryId, item);
        emitTransition(item);
      } else {
        clearItemTimers(item);
      }
      return failure(putCode);
    } finally {
      releaseAdmission();
    }
  }

  /**
   * C-DLV section 4.2, after a successful `put`: the shutdown and deadline
   * precedence, and otherwise the first attempt scheduled with
   * `queueMicrotask`.
   *
   * @param {object} item
   */
  function finishAdmission(item) {
    if (stopped) {
      takeLostOnShutdown(item);
      return;
    }
    if (item.deadlineFired === true) {
      recordTransition(item, STATE_FAILED_NOT_ACCEPTED, null);
      return;
    }
    if (!armMicrotask(() => startAttempt(item))) {
      applyTerminalFromFault(item, SdkResultCode.E_SDK_INTERNAL);
    }
  }

  /* --- attempts and retransmission (C-DLV section 4.3) ------------------ */

  /**
   * Start one attempt: the deadline check of section 4.4 before the attempt,
   * the transition to `IN_FLIGHT`, the attempt counter, the first-attempt
   * event and signature, and the publication through the seam of section 5.3.
   *
   * @param {object} item
   */
  async function startAttempt(item) {
    try {
      if (stopped) return;
      if (item.state !== STATE_QUEUED) return;

      const maxAttempts = readNumber('maxAttempts');
      if (!maxAttempts.ok) {
        applyTerminalFromFault(item, SdkResultCode.E_SDK_INTERNAL);
        return;
      }
      if (item.attempts >= maxAttempts.value) {
        recordTransition(item, STATE_FAILED_NOT_ACCEPTED, null);
        return;
      }

      // C-DLV section 4.4: the attempt start reads the clock immediately
      // before the attempt, so that a signature completed after the deadline
      // is never published.
      let reading = callSyncPort(read.clock, 'now');
      if (!reading.ok || !isValidClockValue(reading.value)) {
        applyTerminalFromFault(item, SdkResultCode.E_SDK_INTERNAL);
        return;
      }
      if (reading.value >= item.deadlineAt) {
        applyDeadline(item);
        return;
      }

      if (item.event === null) {
        const built = await buildMessageEvent(item);
        if (stopped) return;
        if (item.state !== STATE_QUEUED) return;
        if (!built.ok) {
          // No relay was published to and no attempt timeout was armed, so no
          // relay outcome of this attempt is set (C-DLV section 4.3).
          const to = applicableFailedState(item);
          if (to !== null) recordTransition(item, to, built.code);
          return;
        }
        item.event = built.value;
      }

      item.attempts += 1;
      if (!recordTransition(item, STATE_IN_FLIGHT, null)) return;
      await publishAttempt(item);
    } catch {
      applyTerminalFromFault(item, SdkResultCode.E_SDK_INTERNAL);
    }
  }

  /**
   * Publish one attempt through the injected seam and mirror its per-relay
   * outcomes (C-DLV section 5.3). The two gates are the whole of the boundary
   * with the relay set: they answer whether the item is still `IN_FLIGHT` in
   * this same attempt with an unexpired deadline, which is exactly the
   * condition section 5.3 conditions a late publication on and section 4.4
   * conditions an acceptance on.
   *
   * @param {object} item
   */
  async function publishAttempt(item) {
    for (let index = 0; index < item.outcomes.length; index += 1) {
      // C-DLV section 5.3: an entry is set back to PENDING for a new attempt
      // unless it is already ACCEPTED for this item.
      if (item.outcomes[index] !== OUTCOME_ACCEPTED) item.outcomes[index] = OUTCOME_PENDING;
    }

    let publish;
    try {
      publish = read === null ? undefined : read.publish;
    } catch {
      applyTerminalFromFault(item, SdkResultCode.E_SDK_INTERNAL);
      return;
    }
    if (typeof publish !== 'function') {
      applyTerminalFromFault(item, SdkResultCode.E_SDK_INTERNAL);
      return;
    }
    let attempt;
    try {
      attempt = publish(item.event);
    } catch {
      applyTerminalFromFault(item, SdkResultCode.E_SDK_INTERNAL);
      return;
    }
    if (attempt === null || typeof attempt !== 'object') {
      applyTerminalFromFault(item, SdkResultCode.E_SDK_INTERNAL);
      return;
    }
    if (typeof attempt.onOutcome !== 'function' || typeof attempt.onSettled !== 'function') {
      applyTerminalFromFault(item, SdkResultCode.E_SDK_INTERNAL);
      return;
    }
    let live;
    try {
      live = attempt.outcomes;
    } catch {
      live = undefined;
    }
    if (!Array.isArray(live)) {
      // C-DLV section 5.3 pairs `outcomes` with the configured relays in `j`
      // order; an attempt of the seam without that array is malformed.
      applyTerminalFromFault(item, SdkResultCode.E_SDK_INTERNAL);
      return;
    }
    item.attempt = attempt;
    item.lastAttempt = attempt;
    try {
      attempt.acceptGate = () => isPublishable(item, attempt);
    } catch {
      applyTerminalFromFault(item, SdkResultCode.E_SDK_INTERNAL);
      return;
    }
    try {
      attempt.latePublishGate = () => isPublishable(item, attempt);
    } catch {
      /* the late publication gate is a narrowing only; the item keeps its
         acceptGate, and no acceptance can be recorded through it anyway */
    }
    try {
      attempt.onOutcome((relayIndex, outcome) => {
        onRelayOutcome(item, attempt, relayIndex, outcome);
      });
    } catch {
      applyTerminalFromFault(item, SdkResultCode.E_SDK_INTERNAL);
      return;
    }
    try {
      attempt.onSettled(() => {
        onAttemptSettled(item, attempt);
      });
    } catch {
      applyTerminalFromFault(item, SdkResultCode.E_SDK_INTERNAL);
      return;
    }
    // The attempt may already carry outcomes at this instant; an outcome of a
    // lane module outside the closed set of C-SDK section 6.3 is an unknown
    // value (C-DLV section 4.5).
    for (let index = 0; index < live.length; index += 1) {
      let outcome;
      try {
        outcome = live[index];
      } catch {
        outcome = undefined;
      }
      if (outcome === OUTCOME_PENDING || outcome === undefined) continue;
      onRelayOutcome(item, attempt, index, outcome);
    }
  }

  /**
   * The condition of C-DLV section 5.3 for a publication and of section 4.4
   * for an acceptance: the item is still `IN_FLIGHT` in this same attempt and
   * its deadline has not passed. At an orderly `shutdown()` every non-terminal
   * item is terminal synchronously at the call (section 4.6), so the client's
   * `RUNNING` condition of section 5.3 is subsumed. A clock fault refuses.
   *
   * @param {object} item
   * @param {object} attempt
   * @returns {boolean}
   */
  function isPublishable(item, attempt) {
    if (stopped) return false;
    if (item.state !== STATE_IN_FLIGHT) return false;
    if (item.attempt !== attempt) return false;
    const reading = callSyncPort(read.clock, 'now');
    if (!reading.ok || !isValidClockValue(reading.value)) return false;
    return reading.value < item.deadlineAt;
  }

  /**
   * One per-relay outcome of the latest attempt (C-DLV section 5.3). A
   * per-relay outcome never changes the item's state except the first
   * `ACCEPTED` of an item in `IN_FLIGHT`.
   *
   * @param {object} item
   * @param {object} attempt
   * @param {number} relayIndex
   * @param {string} outcome
   */
  function onRelayOutcome(item, attempt, relayIndex, outcome) {
    // The outcome of the latest attempt for a relay is mirrored even after the
    // item became terminal, because a PENDING entry settles at the attempt
    // timeout although the attempt is over (C-DLV section 5.3); an outcome of
    // any earlier attempt is not.
    if (attempt !== item.attempt && attempt !== item.lastAttempt) return;
    if (!RELAY_OUTCOMES.has(outcome)) {
      applyTerminalFromFault(item, SdkResultCode.E_SDK_UNKNOWN_CODE);
      return;
    }
    if (Number.isInteger(relayIndex) && relayIndex >= 0 && relayIndex < item.outcomes.length) {
      item.outcomes[relayIndex] = outcome;
    }
    if (outcome !== OUTCOME_ACCEPTED) return;
    if (item.attempt !== attempt) return;
    if (item.state !== STATE_IN_FLIGHT) return;
    if (!isPublishable(item, attempt)) {
      // The deadline check before a success (C-DLV section 4.4): at or after
      // the deadline the deadline transition applies instead.
      if (!stopped && !TERMINAL_STATES.has(item.state)) applyDeadline(item);
      return;
    }
    if (item.receiptMode === RECEIPT_MODE_RECIPIENT_RECEIPT) {
      recordTransition(item, STATE_AWAITING_RECEIPT, null);
      if (item.receipt !== null && !TERMINAL_STATES.has(item.state)) {
        // A held receipt (C-DLV section 7.3): the item moves at once, two
        // transitions with two events.
        recordTransition(item, STATE_RECEIPT_RECEIVED, null);
      }
      return;
    }
    recordTransition(item, STATE_RELAY_ACCEPTED, null);
  }

  /**
   * The end of a publication phase without an acceptance: the retry-or-fail
   * decision of C-DLV section 4.3, taken by I-RETRY over the item's attempt
   * count, the effective maximum, the deadline and the two ports.
   *
   * @param {object} item
   * @param {object} attempt
   */
  function onAttemptSettled(item, attempt) {
    if (stopped) return;
    if (item.attempt !== attempt) return;
    if (item.state !== STATE_IN_FLIGHT) return;
    item.attempt = null;
    decideRetry(item);
  }

  /**
   * The retry decision and arming of C-DLV section 4.3.
   *
   * @param {object} item
   */
  function decideRetry(item) {
    const maxAttempts = readNumber('maxAttempts');
    if (!maxAttempts.ok) {
      applyTerminalFromFault(item, SdkResultCode.E_SDK_INTERNAL);
      return;
    }
    let decision;
    try {
      decision = planRetry({
        attempts: item.attempts,
        maxAttempts: maxAttempts.value,
        clock: read.clock,
        deadlineAt: item.deadlineAt,
        random: read.random,
      });
    } catch {
      applyTerminalFromFault(item, SdkResultCode.E_SDK_INTERNAL);
      return;
    }
    if (decision === null || typeof decision !== 'object') {
      applyTerminalFromFault(item, SdkResultCode.E_SDK_INTERNAL);
      return;
    }
    const violation = closedSlotViolation(decision);
    if (violation !== null) {
      applyTerminalFromFault(item, SdkResultCode.E_SDK_UNKNOWN_CODE);
      return;
    }
    if (decision.action === 'FAIL') {
      const code = decision.lastCode === undefined ? null : decision.lastCode;
      recordTransition(item, STATE_FAILED_NOT_ACCEPTED, code);
      return;
    }
    if (
      decision.action !== 'RETRY' ||
      !Number.isSafeInteger(decision.delayMs) ||
      decision.delayMs < 0
    ) {
      applyTerminalFromFault(item, SdkResultCode.E_SDK_INTERNAL);
      return;
    }
    if (!recordTransition(item, STATE_QUEUED, null)) return;
    if (!armRetry(item, decision.delayMs)) {
      applyTerminalFromFault(item, SdkResultCode.E_SDK_INTERNAL);
    }
  }

  /* --- cancel (C-DLV section 4.6) --------------------------------------- */

  /**
   * `cancel` of C-DLV section 4.6 and C-SDK section 4.2.
   *
   * @param {unknown} argument
   * @returns {Promise<object>}
   */
  async function cancel(argument) {
    try {
      return await runCancel(argument);
    } catch {
      return failure(SdkResultCode.E_SDK_INTERNAL);
    }
  }

  /**
   * The body of `cancel`.
   *
   * @param {unknown} argument
   * @returns {Promise<object>}
   */
  async function runCancel(argument) {
    if (stopped) return failure(SdkResultCode.E_SDK_CLIENT_STOPPED);
    let deliveryId = null;
    try {
      if (!isPlainObject(argument)) return failure(SdkResultCode.E_SDK_INVALID_ARGUMENT);
      if (!sameKeySet(Object.keys(argument), ['deliveryId'])) {
        return failure(SdkResultCode.E_SDK_INVALID_ARGUMENT);
      }
      deliveryId = argument.deliveryId;
    } catch {
      return failure(SdkResultCode.E_SDK_INVALID_ARGUMENT);
    }
    if (typeof deliveryId !== 'string') return failure(SdkResultCode.E_SDK_INVALID_ARGUMENT);
    const item = items.get(deliveryId);
    if (item === undefined) return failure(SdkResultCode.E_SDK_UNKNOWN_DELIVERY);
    if (TERMINAL_STATES.has(item.state)) return failure(SdkResultCode.E_SDK_DELIVERY_TERMINAL);
    if (item.cancelInProgress && item.cancelPromise !== null) return item.cancelPromise;

    const portCall = readPortCallTimeout();
    if (!portCall.ok) return failure(SdkResultCode.E_SDK_INTERNAL);

    item.cancelInProgress = true;
    item.cancelPromise = (async () => {
      // From the call on, no new attempt of the item starts: `cancel` writes
      // the item's record in state CANCELLED and only then commits, and a
      // retry that falls due while the write is in progress waits for it.
      const written = Object.freeze({ ...buildRecord(item), state: STATE_CANCELLED });
      const result = await callPort(
        read.storage,
        'update',
        [item.deliveryId, written],
        portCall.value,
      );
      item.cancelInProgress = false;
      if (stopped) return failure(SdkResultCode.E_SDK_CLIENT_STOPPED);
      const committed = result.ok && result.value === true;
      if (!committed) {
        // The failed cancel changes nothing. A retry that fell due meanwhile
        // starts at once, unless the deadline rule of section 4.3 applies.
        item.retryDeferred = false;
        if (item.state === STATE_QUEUED) startAttempt(item);
        return failure(SdkResultCode.E_SDK_STORAGE_FAILED);
      }
      if (TERMINAL_STATES.has(item.state)) {
        // The item became terminal meanwhile: the actual terminal record is
        // written (a failure of that write is ignored) and the cancel reports
        // the terminal item.
        writeRecord(item, buildRecord(item));
        return failure(SdkResultCode.E_SDK_DELIVERY_TERMINAL);
      }
      if (!recordTransition(item, STATE_CANCELLED, null)) {
        return failure(SdkResultCode.E_SDK_DELIVERY_TERMINAL);
      }
      return Object.freeze({
        ok: true,
        value: Object.freeze({ deliveryId: item.deliveryId, state: STATE_CANCELLED }),
      });
    })();
    return item.cancelPromise;
  }

  /* --- getDelivery (C-SDK section 6.2) ---------------------------------- */

  /**
   * `getDelivery`: a fresh frozen snapshot from the in-memory view, which is
   * authoritative (C-DLV section 4.6).
   *
   * @param {unknown} argument
   * @returns {Promise<object>}
   */
  async function getDelivery(argument) {
    try {
      if (!isPlainObject(argument)) return failure(SdkResultCode.E_SDK_INVALID_ARGUMENT);
      if (!sameKeySet(Object.keys(argument), ['deliveryId'])) {
        return failure(SdkResultCode.E_SDK_INVALID_ARGUMENT);
      }
      const deliveryId = argument.deliveryId;
      if (typeof deliveryId !== 'string') return failure(SdkResultCode.E_SDK_INVALID_ARGUMENT);
      const item = items.get(deliveryId);
      if (item === undefined) return failure(SdkResultCode.E_SDK_UNKNOWN_DELIVERY);
      return Object.freeze({ ok: true, value: buildSnapshot(item) });
    } catch {
      return failure(SdkResultCode.E_SDK_INTERNAL);
    }
  }

  /* --- receipts (C-DLV section 7.3, item side) -------------------------- */

  /**
   * Apply the item-side conditions of C-DLV section 7.3 to a receipt the
   * inbound layer of card I-ACK already validated: a kind-4742 event accepted
   * as the receipt of an outbound item only when its event id is the id of a
   * non-terminal item of this client in `RECIPIENT_RECEIPT` mode, its signer
   * equals that item's recipient, the item has not already taken a receipt and
   * the clock reading is before the item's deadline; otherwise the deadline
   * transition of section 4.4 applies at once and the receipt is ignored
   * without an event.
   *
   * @param {unknown} argument `{ eventId, recipient }`
   * @returns {Promise<object>}
   */
  async function acceptReceipt(argument) {
    const refused = (deliveryId) =>
      Object.freeze({ ok: true, value: Object.freeze({ accepted: false, deliveryId }) });
    try {
      if (!isPlainObject(argument)) return failure(SdkResultCode.E_SDK_INVALID_ARGUMENT);
      if (!sameKeySet(Object.keys(argument), ['eventId', 'recipient'])) {
        return failure(SdkResultCode.E_SDK_INVALID_ARGUMENT);
      }
      const eventId = argument.eventId;
      const recipient = argument.recipient;
      if (typeof eventId !== 'string') return failure(SdkResultCode.E_SDK_INVALID_ARGUMENT);
      if (!isLowerHexOfLength(recipient, 64)) return failure(SdkResultCode.E_SDK_INVALID_ARGUMENT);

      let target = null;
      for (const item of items.values()) {
        if (TERMINAL_STATES.has(item.state)) continue;
        if (item.receiptMode !== RECEIPT_MODE_RECIPIENT_RECEIPT) continue;
        if (item.event === null || item.event.id !== eventId) continue;
        target = item;
        break;
      }
      if (target === null) return refused(null);
      if (target.recipient !== recipient) return refused(target.deliveryId);
      if (target.receipt !== null) return refused(target.deliveryId);

      const reading = callSyncPort(read.clock, 'now');
      if (!reading.ok || !isValidClockValue(reading.value)) {
        applyTerminalFromFault(target, SdkResultCode.E_SDK_INTERNAL);
        return refused(target.deliveryId);
      }
      if (reading.value >= target.deadlineAt) {
        if (!TERMINAL_STATES.has(target.state)) applyDeadline(target);
        return refused(target.deliveryId);
      }
      if (target.state === STATE_AWAITING_RECEIPT) {
        target.receipt = Object.freeze({ eventId });
        if (!recordTransition(target, STATE_RECEIPT_RECEIVED, null)) return refused(target.deliveryId);
        return Object.freeze({
          ok: true,
          value: Object.freeze({ accepted: true, deliveryId: target.deliveryId }),
        });
      }
      // An item still in QUEUED or IN_FLIGHT: the receipt is held on the item
      // and causes no transition; it is discarded if the item becomes terminal
      // without an acceptance.
      target.receipt = Object.freeze({ eventId });
      return Object.freeze({
        ok: true,
        value: Object.freeze({ accepted: true, deliveryId: target.deliveryId }),
      });
    } catch {
      return failure(SdkResultCode.E_SDK_INTERNAL);
    }
  }

  /* --- the storage check of C-DLV section 5.2 --------------------------- */

  /**
   * Run the storage checks of C-DLV section 5.2 on the storage port, in the
   * order that section fixes, so that `start()` can decide whether the port
   * holds no item. `start()` itself belongs to the client; the record of
   * section 6.4 and its closed slots belong to this module.
   *
   * @returns {Promise<object>}
   */
  async function inspectStore() {
    try {
      const portCall = readPortCallTimeout();
      if (!portCall.ok) return failure(SdkResultCode.E_SDK_INTERNAL);
      const listed = await callPort(read.storage, 'list', [], portCall.value);
      if (!listed.ok) return failure(SdkResultCode.E_SDK_STORAGE_FAILED);
      if (!Array.isArray(listed.value)) return failure(SdkResultCode.E_SDK_STORAGE_FAILED);
      // The closed-slot check runs before the shape check and before the
      // emptiness rule: a value outside a closed set that any element carries
      // is E_SDK_UNKNOWN_CODE, whatever else the element holds.
      for (const element of listed.value) {
        if (!isPlainObject(element)) continue;
        if (closedSlotViolation(element) !== null) {
          return failure(SdkResultCode.E_SDK_UNKNOWN_CODE);
        }
      }
      for (const element of listed.value) {
        let keys;
        try {
          keys = Object.keys(element);
        } catch {
          return failure(SdkResultCode.E_SDK_STORAGE_FAILED);
        }
        if (!isPlainObject(element) || !sameKeySet(keys, RECORD_FIELDS)) {
          return failure(SdkResultCode.E_SDK_STORAGE_FAILED);
        }
      }
      if (listed.value.length > 0) return failure(SdkResultCode.E_SDK_STORAGE_NOT_EMPTY);
      return Object.freeze({ ok: true, value: Object.freeze({ empty: true }) });
    } catch {
      return failure(SdkResultCode.E_SDK_INTERNAL);
    }
  }

  /* --- shutdown (C-DLV section 4.6) ------------------------------------ */

  /**
   * Take one admitted item to `LOST_ON_SHUTDOWN` at the call of `shutdown()`,
   * without emitting: the events of an orderly stop are delivered in step (3)
   * of C-DLV section 4.6, and their writes are issued in step (4).
   *
   * @param {object} item
   */
  function takeLostOnShutdown(item) {
    if (TERMINAL_STATES.has(item.state)) return;
    item.state = STATE_LOST_ON_SHUTDOWN;
    item.lastCode = null;
    item.ciphertext = null;
    item.event = null;
    item.attempt = null;
    lostItems.add(item);
  }

  /**
   * The item-side part of the orderly stop of C-DLV section 4.6: step (1) is
   * synchronous at the call, then the wait of step (2), the delivery of the
   * `LOST_ON_SHUTDOWN` events of step (3) and the storage writes and timer
   * clears of step (4).
   *
   * @returns {Promise<object>}
   */
  async function shutdown() {
    if (stopped) return failure(SdkResultCode.E_SDK_CLIENT_STOPPED);
    try {
      // Step (1): synchronous at the call. Admission stops, and every admitted
      // non-terminal item is LOST_ON_SHUTDOWN in the in-memory view, so no
      // item's terminal state waits for the steps below and every timer
      // callback that runs afterwards does nothing.
      stopped = true;
      for (const item of items.values()) takeLostOnShutdown(item);

      // Step (2): wait until every `send` already in progress has resolved.
      await admissionsSettled();

      // Step (3): deliver the LOST_ON_SHUTDOWN events.
      for (const item of lostItems) emitTransition(item);

      // Step (4): issue the storage writes of the LOST_ON_SHUTDOWN records in
      // parallel (failures ignored, each bounded by the port-call timeout) and
      // clear every timer this module armed.
      const portCall = readPortCallTimeout();
      const writes = [];
      if (portCall.ok) {
        for (const item of lostItems) {
          writes.push(
            callPort(read.storage, 'update', [item.deliveryId, buildRecord(item)], portCall.value),
          );
        }
      }
      for (const item of items.values()) clearItemTimers(item);
      await Promise.all(writes.map((write) => write.catch(() => undefined)));

      // Step (5), the item side: release the ports this module held.
      try {
        read.storage = null;
        read.session = null;
        read.identity = null;
        read.clock = null;
        read.random = null;
        read.publish = null;
      } catch {
        /* the retained snapshots need no port */
      }
      return Object.freeze({
        ok: true,
        value: Object.freeze({ clientState: 'STOPPED', lost: lostItems.size }),
      });
    } catch {
      return failure(SdkResultCode.E_SDK_INTERNAL);
    }
  }

  return Object.freeze({
    send,
    cancel,
    getDelivery,
    acceptReceipt,
    inspectStore,
    shutdown,
  });
}
