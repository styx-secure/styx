/**
 * M3-RECEIVE-1 -- crash-safe reception behind the optional caller-injected
 * `ports.receiveState` (C-SDK sections 4.1, 7, 8.5; C-DLV sections 5.4, 7.4).
 *
 * This module is SDK-internal. It exists only when the caller configures the
 * port; without it the client keeps the 0.3.1 inbound path of `receipts.js`.
 * It owns, for kind 4741 only: the durable seen set and the PENDING, READY,
 * acknowledged and REJECTED entries mirrored from the port; admission
 * (`isKnownSender`, quotas); the single open unit (`openCandidate`, `commit`,
 * `resolve`); the in-run retry budget and periodic pass; emission and
 * redelivery of READY entries until acknowledgement; durable receipt
 * obligations; durable catch-up cursors with their barrier and clock-skew
 * rule; and the fail-stop states. Kind 4742 keeps its existing path.
 *
 * Every call into caller code goes through the client's boundary (`call`,
 * bounded by the port-call timeout on the host timer, never throwing) or is a
 * guarded synchronous clock read. Nothing here throws to its caller.
 */

import { sha256 } from '@noble/hashes/sha256';
import { base64ToBytes, bytesToHex, hexToBytes, randomBytes, utf8Encode } from '../../utils.js';
import { SDK_WIRE_VERSION } from '../wire-version.js';

/** C-SDK section 8.5: the scope literal of the receive state. */
export const RECEIVE_SCOPE = 'styx-m3-delivery/4741/wire-0.3.0';
/** C-SDK section 8.5: the only snapshot schema this version reads. */
export const RECEIVE_SCHEMA = 'styx-m3-receive-state/v1';
/** C-SDK section 4.1: the receive quotas, defaults and maxima. */
export const RECEIVE_LIMITS = Object.freeze({
  maxPending: Object.freeze({ default: 4096, max: 65536 }),
  maxUnacknowledged: Object.freeze({ default: 4096, max: 65536 }),
  maxSeen: Object.freeze({ default: 1048576, max: 16777216 }),
  maxStoredBytes: Object.freeze({ default: 268435456, max: 4294967296 }),
});
/** C-SDK section 8.5: the seven methods of the port, all or none. */
export const RECEIVE_PORT_METHODS = Object.freeze(['load', 'stage', 'commit', 'ack', 'receiptDone', 'commitCursor', 'resolve']);
/** C-SDK section 8.2: the session methods the port requires. */
export const RECEIVE_SESSION_METHODS = Object.freeze(['openCandidate', 'isKnownSender']);
/** C-DLV section 3: periodic retry pass and per-entry retry budget (the catch-up interval). */
export const RETRY_INTERVAL_MS = 10000;
/** C-DLV section 3: redelivery pass of unacknowledged READY entries. */
export const REDELIVERY_INTERVAL_MS = 60000;
/** C-DLV section 3: catch-up margin in seconds. */
const MARGIN_SECONDS = 120;
/**
 * C-DLV sections 3 and 5.4: at most 4 096 distinct failed event ids are kept
 * per relay; one more clears them and blocks the relay's cursor commits for
 * the rest of the client run, as a failure whose event cannot be identified.
 */
const FAILED_IDS_BOUND = 4096;

const HEX64 = /^[0-9a-f]{64}$/;
const HEX32 = /^[0-9a-f]{32}$/;
const RECEIPT_KIND = 4742;
const OUTCOMES = new Set(['application', 'retry', 'reject']);
const FAILED = 'E_SDK_RECEIVE_STATE_FAILED';
const INCOMPATIBLE = 'E_SDK_RECEIVE_STATE_INCOMPATIBLE';
const CONFLICT = 'E_SDK_RECEIVE_STATE_CONFLICT';
const CAPACITY = 'E_SDK_RECEIVE_STATE_CAPACITY';
const UNKNOWN = 'E_SDK_UNKNOWN_CODE';
const WRITE_CODES = new Set([FAILED, CONFLICT]);
const COMMIT_CODES = new Set([FAILED, CONFLICT, CAPACITY]);
const LOAD_CODES = new Set([FAILED, INCOMPATIBLE]);
const RESOLVE_CODES = new Set([FAILED]);
/** Barrier outcomes that account a counted frame without a failure. */
const ACCOUNTED = new Set(['staged', 'seen', 'notAdmitted', 'invalid', 'receipt']);
/** Accounted outcomes that also clear a known failed id (validated events only). */
const CLEARING = new Set(['staged', 'seen', 'notAdmitted']);

const hasOwn = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
const isCount = (value) => Number.isSafeInteger(value) && value >= 0;

/** The `length` and tag getters of typed arrays, read once from the intrinsic. */
const typedArrayProto = Reflect.getPrototypeOf(Uint8Array.prototype);
const typedLength = Reflect.getOwnPropertyDescriptor(typedArrayProto, 'length').get;
const typedTag = Reflect.getOwnPropertyDescriptor(typedArrayProto, Symbol.toStringTag).get;

/**
 * A fresh copy of a genuine `Uint8Array` (brand-checked, no property of the
 * value read), or `null`. Never throws.
 *
 * @param {unknown} value
 * @returns {Uint8Array | null}
 */
function copyBytes(value) {
  try {
    if (Reflect.apply(typedTag, value, []) !== 'Uint8Array') return null;
    const length = Reflect.apply(typedLength, value, []);
    const copy = new Uint8Array(value);
    return copy.length === length ? copy : null;
  } catch {
    return null;
  }
}

/**
 * The own data properties of a plain object whose own keys are exactly the
 * required ones plus any of the optional ones, or `null`. Never throws.
 *
 * @param {unknown} value
 * @param {readonly string[]} required
 * @param {readonly string[]} [optional]
 * @returns {Record<string, unknown> | null}
 */
function closed(value, required, optional = []) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
    const prototype = Reflect.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return null;
    const allowed = new Set([...required, ...optional]);
    const fields = Object.create(null);
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== 'string' || !allowed.has(key)) return null;
      const descriptor = Reflect.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !hasOwn(descriptor, 'value')) return null;
      fields[key] = descriptor.value;
    }
    for (const key of required) if (!hasOwn(fields, key)) return null;
    return fields;
  } catch {
    return null;
  }
}

/**
 * The elements of a genuine array, each an own data property, or `null`.
 * Never throws.
 *
 * @param {unknown} value
 * @returns {unknown[] | null}
 */
function elements(value) {
  try {
    if (!Array.isArray(value)) return null;
    const length = Reflect.getOwnPropertyDescriptor(value, 'length');
    if (length === undefined || !isCount(length.value)) return null;
    if (Reflect.ownKeys(value).length !== length.value + 1) return null;
    const out = [];
    for (let index = 0; index < length.value; index += 1) {
      const descriptor = Reflect.getOwnPropertyDescriptor(value, String(index));
      if (descriptor === undefined || !hasOwn(descriptor, 'value')) return null;
      out.push(descriptor.value);
    }
    return out;
  } catch {
    return null;
  }
}

/**
 * Read the optional `config.receive` closed object (C-SDK section 4.1).
 * Returns the effective limits, or `null` when invalid. Never throws.
 *
 * @param {unknown} value `undefined` when absent
 * @returns {Readonly<Record<string, number>> | null}
 */
export function readReceiveLimits(value) {
  const limits = {};
  for (const [name, bound] of Object.entries(RECEIVE_LIMITS)) limits[name] = bound.default;
  if (value === undefined) return Object.freeze(limits);
  const fields = closed(value, [], Object.keys(RECEIVE_LIMITS));
  if (fields === null) return null;
  for (const name of Object.keys(fields)) {
    const number = fields[name];
    if (!Number.isSafeInteger(number) || number < 1 || number > RECEIVE_LIMITS[name].max) return null;
    limits[name] = number;
  }
  return Object.freeze(limits);
}

/** C-DLV section 6.1: the event id of a structure. */
function eventIdOf(pubkey, createdAt, kind, tags, content) {
  return bytesToHex(sha256(utf8Encode(JSON.stringify([0, pubkey, createdAt, kind, tags, content]))));
}

/**
 * Build the durable receive state of one client run.
 *
 * `options`: `port` (the caller's receive-state port), `session` and
 * `identity` (the caller's ports), `clock` (the effective clock port),
 * `publicKey`, `relays` (the configured relay strings), `limits`
 * (`readReceiveLimits`), `subscriptionBase` (the client's subscription id),
 * `call(holder, method, args)` (the client's bounded boundary call, resolving
 * `{ settled, value }`), `scan(value)` (the client's closed-slot inspection),
 * `emit(event)` (the client's checked event sink) and `deliver(message,
 * wanted)` (the client's reserved MESSAGE_RECEIVED dispatch: `null` without
 * an audience, else a promise of whether a listener was invoked).
 *
 * @param {object} options
 * @returns {object}
 */
export function createReceiveState(options) {
  const {
    port, session, identity, clock, publicKey, relays, limits, subscriptionBase, call, scan, emit, deliver,
  } = options;

  /** 'normal', 'paused' (an uncertain commit awaits `resolve`) or 'frozen'. */
  let mode = 'normal';
  let stopped = false;
  let running = false;
  let loaded = false;
  let revision = 0;
  let storedBytes = 0;
  const seen = new Set();
  const acknowledged = new Set();
  /** PENDING entries in stage order. */
  const pending = new Map();
  /** READY entries in commit order. */
  const ready = new Map();
  /** Durable receipt obligations, in load then commit order. */
  const receiptsDue = new Map();
  /** Durable cursors by relay index: `{ syncedUntil, skewed }`. */
  const cursors = new Map();
  const usedOperationIds = new Set();
  let capacityReported = false;
  let portCapacity = false;
  let paused = null;

  /* --- small helpers ---------------------------------------------------- */

  function nowMs() {
    try {
      const value = clock.now();
      if (value !== null && typeof value === 'object') Promise.resolve(value).catch(() => {});
      return typeof value === 'number' && Number.isFinite(value) ? value : null;
    } catch {
      return null;
    }
  }

  function nowSeconds() {
    const value = nowMs();
    if (value === null || value < 0) return null;
    const seconds = Math.floor(value / 1000);
    return Number.isSafeInteger(seconds) ? seconds : null;
  }

  function newOperationId() {
    for (;;) {
      const id = bytesToHex(randomBytes(16));
      if (HEX32.test(id) && !usedOperationIds.has(id)) {
        usedOperationIds.add(id);
        return id;
      }
    }
  }

  function safeEmit(event) {
    try {
      emit(Object.freeze(event));
    } catch {
      // The sink never throws; a fault changes nothing here.
    }
  }

  /** Enter a failed condition, reported once per entry from `normal`. */
  function failState(next, code) {
    if (mode === 'frozen') return;
    const report = mode === 'normal';
    mode = next;
    if (report && !stopped) safeEmit({ kind: 'RECEIVE_STATE_FAILED', code });
  }

  /* --- the write chain ---------------------------------------------------- */

  let chain = Promise.resolve();
  /** Run `task` after every write already queued; one port write at a time. */
  function serialized(task) {
    const run = chain.then(task, task);
    chain = run.then(() => undefined, () => undefined);
    return run;
  }

  /**
   * One port call of a write method: `{ status: 'ok', revision, storedBytes }`,
   * `{ status: 'code', code }` for a defined refusal, or
   * `{ status: 'uncertain', code }` for a throw, rejection, timeout or a
   * malformed or out-of-set value (the write may or may not have happened).
   */
  async function portWrite(name, fields, codes) {
    const operationId = newOperationId();
    const argument = Object.freeze({ operationId, revision, ...fields });
    const called = await call(port, name, [argument]);
    if (called.settled !== 'value') return { status: 'uncertain', code: FAILED, operationId };
    const value = called.value;
    const inspected = scan(value);
    if (inspected.unknown) return { status: 'uncertain', code: UNKNOWN, operationId };
    if (inspected.malformed) return { status: 'uncertain', code: FAILED, operationId };
    const done = closed(value, ['revision', 'storedBytes']);
    if (done !== null && isCount(done.revision) && isCount(done.storedBytes)) {
      return { status: 'ok', revision: done.revision, storedBytes: done.storedBytes, operationId };
    }
    const refused = closed(value, ['code']);
    if (refused !== null && codes.has(refused.code)) return { status: 'code', code: refused.code, operationId };
    return { status: 'uncertain', code: FAILED, operationId };
  }

  function adopt(result) {
    revision = result.revision;
    storedBytes = result.storedBytes;
  }

  /**
   * A non-commit write: blocked unless `normal`; any failure, definite or
   * uncertain, freezes the client (C-SDK section 8.5, fail-stop).
   *
   * @returns {Promise<boolean>} whether the write succeeded
   */
  function plainWrite(name, fields) {
    return serialized(async () => {
      if (mode !== 'normal') return false;
      const result = await portWrite(name, fields, WRITE_CODES);
      if (result.status === 'ok') {
        adopt(result);
        // The adopted `storedBytes` may cross a limit or drop below it.
        if (quotaReached()) reportCapacity(); else recheckCapacity();
        return true;
      }
      failState('frozen', result.code);
      return false;
    });
  }

  /* --- quotas and capacity ---------------------------------------------- */

  function quotaReached() {
    return pending.size >= limits.maxPending || ready.size >= limits.maxUnacknowledged
      || seen.size >= limits.maxSeen || storedBytes >= limits.maxStoredBytes || portCapacity;
  }

  function reportCapacity() {
    if (capacityReported || stopped) return;
    capacityReported = true;
    safeEmit({ kind: 'RECEIVE_STATE_CAPACITY', scope: RECEIVE_SCOPE });
  }

  function recheckCapacity() {
    if (capacityReported && !quotaReached()) capacityReported = false;
  }

  /* --- load (C-SDK section 8.5) ------------------------------------------ */

  /**
   * `load` once, before any relay connection. Resolves `null` on success or
   * the failure code of `start()`.
   *
   * @returns {Promise<string | null>}
   */
  async function load() {
    const called = await call(port, 'load', [Object.freeze({ identity: publicKey, scope: RECEIVE_SCOPE })]);
    if (called.settled !== 'value') return FAILED;
    const value = called.value;
    const inspected = scan(value);
    if (inspected.unknown) return UNKNOWN;
    if (inspected.malformed) return FAILED;
    const refused = closed(value, ['code']);
    if (refused !== null) return LOAD_CODES.has(refused.code) ? refused.code : FAILED;
    const snapshot = closed(value, ['schema', 'identity', 'scope', 'revision', 'storedBytes', 'cursors', 'pending',
      'ready', 'acknowledged', 'receiptsDue', 'seen']);
    if (snapshot === null) return FAILED;
    if (snapshot.schema !== RECEIVE_SCHEMA || snapshot.identity !== publicKey || snapshot.scope !== RECEIVE_SCOPE) {
      return INCOMPATIBLE;
    }
    if (!isCount(snapshot.revision) || !isCount(snapshot.storedBytes)) return FAILED;
    const lists = {};
    for (const name of ['cursors', 'pending', 'ready', 'acknowledged', 'receiptsDue', 'seen']) {
      lists[name] = elements(snapshot[name]);
      if (lists[name] === null) return FAILED;
    }
    const loadedSeen = new Set();
    for (const id of lists.seen) {
      if (typeof id !== 'string' || !HEX64.test(id) || loadedSeen.has(id)) return FAILED;
      loadedSeen.add(id);
    }
    const loadedAcknowledged = new Set();
    for (const id of lists.acknowledged) {
      if (typeof id !== 'string' || !loadedSeen.has(id) || loadedAcknowledged.has(id)) return FAILED;
      loadedAcknowledged.add(id);
    }
    const loadedPending = new Map();
    for (const record of lists.pending) {
      const fields = closed(record, ['eventId', 'sender', 'ciphertext', 'receiptRequested']);
      if (fields === null || typeof fields.eventId !== 'string' || !loadedSeen.has(fields.eventId)) return FAILED;
      if (loadedPending.has(fields.eventId) || loadedAcknowledged.has(fields.eventId)) return FAILED;
      if (typeof fields.sender !== 'string' || !HEX64.test(fields.sender)) return FAILED;
      if (typeof fields.receiptRequested !== 'boolean') return FAILED;
      const ciphertext = copyBytes(fields.ciphertext);
      if (ciphertext === null || ciphertext.length === 0) return FAILED;
      loadedPending.set(fields.eventId, pendingEntry(fields.eventId, fields.sender, ciphertext, fields.receiptRequested));
    }
    const loadedReady = new Map();
    for (const record of lists.ready) {
      const fields = closed(record, ['eventId', 'sender', 'payload', 'receiptDue']);
      if (fields === null || typeof fields.eventId !== 'string' || !loadedSeen.has(fields.eventId)) return FAILED;
      if (loadedReady.has(fields.eventId) || loadedPending.has(fields.eventId)
        || loadedAcknowledged.has(fields.eventId)) return FAILED;
      if (typeof fields.sender !== 'string' || !HEX64.test(fields.sender)) return FAILED;
      if (typeof fields.receiptDue !== 'boolean') return FAILED;
      const payload = copyBytes(fields.payload);
      if (payload === null) return FAILED;
      loadedReady.set(fields.eventId, readyEntry(fields.eventId, fields.sender, payload, fields.receiptDue));
    }
    const loadedReceipts = new Map();
    for (const record of lists.receiptsDue) {
      const fields = closed(record, ['eventId', 'sender']);
      if (fields === null || typeof fields.eventId !== 'string' || loadedReceipts.has(fields.eventId)) return FAILED;
      if (typeof fields.sender !== 'string' || !HEX64.test(fields.sender)) return FAILED;
      const entry = loadedReady.get(fields.eventId);
      if (entry !== undefined) {
        if (!entry.receiptDue || entry.sender !== fields.sender) return FAILED;
      } else if (!loadedAcknowledged.has(fields.eventId)) {
        return FAILED;
      }
      loadedReceipts.set(fields.eventId, { eventId: fields.eventId, sender: fields.sender, attempted: false, job: null });
    }
    const loadedCursors = new Map();
    const relayIndex = new Map(relays.map((relay, index) => [relay, index]));
    const relayStrings = new Set();
    for (const record of lists.cursors) {
      const fields = closed(record, ['relay', 'syncedUntil']);
      if (fields === null || typeof fields.relay !== 'string' || relayStrings.has(fields.relay)) return FAILED;
      if (!isCount(fields.syncedUntil)) return FAILED;
      relayStrings.add(fields.relay);
      // A relay no longer configured is ignored (C-DLV section 5.4).
      if (relayIndex.has(fields.relay)) {
        loadedCursors.set(relayIndex.get(fields.relay), { syncedUntil: fields.syncedUntil, skewed: false });
      }
    }
    revision = snapshot.revision;
    storedBytes = snapshot.storedBytes;
    for (const id of loadedSeen) seen.add(id);
    for (const id of loadedAcknowledged) acknowledged.add(id);
    for (const [id, entry] of loadedPending) pending.set(id, entry);
    for (const [id, entry] of loadedReady) ready.set(id, entry);
    for (const [id, entry] of loadedReceipts) receiptsDue.set(id, entry);
    for (const [index, cursor] of loadedCursors) cursors.set(index, cursor);
    loaded = true;
    if (quotaReached()) reportCapacity();
    return null;
  }

  function pendingEntry(eventId, sender, ciphertext, receiptRequested) {
    return {
      eventId, sender, ciphertext, receiptRequested, relays: new Set(), budgetAt: null, queued: false,
    };
  }

  function readyEntry(eventId, sender, payload, receiptDue) {
    return { eventId, sender, payload, receiptDue, invoked: false, delivery: null, acking: null };
  }

  /* --- the frame barrier and cursors (C-DLV section 5.4) ----------------- */

  const relayStates = relays.map(() => ({
    counted: new Map(), nextSeq: 1, failedIds: new Set(), blocked: false, outstanding: [], poolSeq: 0,
    poolSubscriptionId: null, pendingCommits: [], skewReported: false,
  }));
  /** frame object -> { relay, seq, eventId } */
  const counted = new WeakMap();
  let issueCounter = 0;
  let invitationsActive = 0;
  let lastInvitationEndSeq = 0;

  const relayAt = (index) => (Number.isInteger(index) && index >= 0 && index < relayStates.length
    ? relayStates[index] : null);

  function readRelayIndex(frame) {
    try {
      const descriptor = Reflect.getOwnPropertyDescriptor(frame, 'relayIndex');
      return descriptor !== undefined && hasOwn(descriptor, 'value') ? descriptor.value : null;
    } catch {
      return null;
    }
  }

  /** Count one inbound `EVENT` frame before the volatile queue. */
  function countFrame(frame) {
    if (stopped || frame === null || typeof frame !== 'object') return;
    const index = readRelayIndex(frame);
    const relay = relayAt(index);
    if (relay === null) return;
    let eventId = null;
    try {
      const data = frame.data;
      // The inbound queue ignores an `EVENT` frame shorter than three
      // elements without accounting it (C-DLV section 7.1), so it is not counted.
      if (!Array.isArray(data) || data.length < 3 || data[0] !== 'EVENT') return;
      const event = data[2];
      if (event !== null && typeof event === 'object' && typeof event.id === 'string' && HEX64.test(event.id)) {
        eventId = event.id;
      }
    } catch {
      eventId = null;
    }
    const seq = relay.nextSeq;
    relay.nextSeq += 1;
    relay.counted.set(seq, eventId);
    counted.set(frame, { relay, seq, eventId });
  }

  /** Block the relay's cursor commits for the rest of the run; no id is kept. */
  function blockRelay(relay) {
    relay.blocked = true;
    relay.failedIds.clear();
  }

  /** Record a barrier failure tied to `eventId` (C-DLV section 5.4). */
  function addFailedId(relay, eventId) {
    if (relay.blocked) return;
    relay.failedIds.add(eventId);
    if (relay.failedIds.size > FAILED_IDS_BOUND) blockRelay(relay);
  }

  function clearFailedId(eventId) {
    for (const relay of relayStates) {
      if (relay.failedIds.delete(eventId)) checkPendingCommits(relay);
    }
  }

  /**
   * Account one counted frame: `staged`, `seen`, `notAdmitted`, `invalid` or
   * `receipt`, or any other outcome (`dropped`, `failed`) as a barrier failure.
   * `eventId` is the validated id, when there is one.
   */
  function account(frame, outcome, eventId = null) {
    if (frame === null || typeof frame !== 'object') return;
    const record = counted.get(frame);
    if (record === undefined) return;
    counted.delete(frame);
    const { relay, seq } = record;
    relay.counted.delete(seq);
    if (!ACCOUNTED.has(outcome)) {
      const id = eventId !== null ? eventId : record.eventId;
      if (id !== null) addFailedId(relay, id); else blockRelay(relay);
    } else if (CLEARING.has(outcome) && eventId !== null) {
      clearFailedId(eventId);
    }
    checkPendingCommits(relay);
  }

  /** Mark a barrier failure on the relays that delivered `entry`. */
  function failRelaysOf(entry) {
    for (const relay of entry.relays) addFailedId(relay, entry.eventId);
  }

  /** A new pool of relay `index` is prepared: its own subscription id. */
  function poolSubscriptionId(index) {
    const relay = relayAt(index);
    if (relay === null) return subscriptionBase;
    relay.poolSeq += 1;
    relay.outstanding = [];
    relay.poolSubscriptionId = `${subscriptionBase}.${relay.poolSeq}`;
    return relay.poolSubscriptionId;
  }

  /**
   * The `since` of a request about to be issued to relay `index` (C-DLV
   * section 5.4): absent without a cursor, for a skewed cursor, or when the
   * clock reading is invalid; a future cursor is skewed from then on.
   */
  function sinceAt(index, now) {
    const cursor = cursors.get(index);
    if (cursor === undefined || cursor.skewed || now === null) return null;
    if (cursor.syncedUntil > now) {
      cursor.skewed = true;
      const relay = relayAt(index);
      if (relay !== null && !relay.skewReported && !stopped) {
        relay.skewReported = true;
        safeEmit({ kind: 'RECEIVE_STATE_CLOCK_SKEW', scope: RECEIVE_SCOPE, relay: relays[index] });
      }
      return null;
    }
    return Math.max(0, cursor.syncedUntil - MARGIN_SECONDS);
  }

  /** The issue notice of a request on relay `index`; returns its `since`. */
  function issue(index) {
    const relay = relayAt(index);
    if (relay === null || stopped) return null;
    const now = nowSeconds();
    issueCounter += 1;
    // Only the earliest outstanding request of the pool is kept (the first of
    // equal issue times): it is the only one an EOSE can commit, so memory
    // stays constant while a relay withholds EOSE (C-DLV section 5.4).
    if (now !== null && (relay.outstanding.length === 0 || now < relay.outstanding[0].issuedAt)) {
      relay.outstanding = [{ issuedAt: now, issueSeq: issueCounter, poolSeq: relay.poolSeq }];
    }
    return sinceAt(index, now);
  }

  /** The `since` of a periodic re-request about to be issued (no record). */
  function since(index) {
    if (relayAt(index) === null || stopped) return null;
    return sinceAt(index, nowSeconds());
  }

  /** An `EOSE` frame of the current pool's subscription. */
  function observe(frame) {
    if (stopped || frame === null || typeof frame !== 'object') return;
    const index = readRelayIndex(frame);
    const relay = relayAt(index);
    if (relay === null) return;
    let data;
    try {
      data = frame.data;
      if (!Array.isArray(data) || data[0] !== 'EOSE' || data[1] !== relay.poolSubscriptionId) return;
    } catch {
      return;
    }
    if (relay.outstanding.length === 0) return;
    // The earliest outstanding request on this pool, the only one kept: a late
    // EOSE of an older request can only commit that older request's issue time.
    const earliest = relay.outstanding[0];
    relay.outstanding = [];
    relay.pendingCommits.push({ index, generation: earliest, mark: relay.nextSeq - 1 });
    checkPendingCommits(relay);
  }

  function checkPendingCommits(relay) {
    while (relay.pendingCommits.length > 0) {
      const first = relay.pendingCommits[0];
      let waiting = false;
      for (const seq of relay.counted.keys()) {
        if (seq <= first.mark) {
          waiting = true;
          break;
        }
      }
      if (waiting) return;
      relay.pendingCommits.shift();
      evaluateCommit(relay, first);
    }
  }

  function evaluateCommit(relay, pendingCommit) {
    if (stopped || mode !== 'normal' || relay.blocked || relay.failedIds.size > 0) return;
    if (invitationsActive > 0 || pendingCommit.generation.issueSeq <= lastInvitationEndSeq) return;
    const { index, generation } = pendingCommit;
    const target = generation.issuedAt;
    const current = cursors.get(index);
    if (current !== undefined && !current.skewed && target <= current.syncedUntil) return;
    serialized(async () => {
      // Re-checked when the write actually starts: a barrier failure or an
      // invitation that began while the write waited in the chain prevents it.
      if (stopped || mode !== 'normal' || relay.blocked || relay.failedIds.size > 0) return;
      if (invitationsActive > 0 || generation.issueSeq <= lastInvitationEndSeq) return;
      const latest = cursors.get(index);
      if (latest !== undefined && !latest.skewed && target <= latest.syncedUntil) return;
      const result = await portWrite('commitCursor', {
        relay: relays[index], generation: generation.poolSeq, syncedUntil: target,
      }, WRITE_CODES);
      if (result.status === 'ok') {
        adopt(result);
        cursors.set(index, { syncedUntil: target, skewed: false });
        return;
      }
      failState('frozen', result.code);
    });
  }

  function invitationStarted() {
    invitationsActive += 1;
  }

  function invitationEnded() {
    if (invitationsActive > 0) invitationsActive -= 1;
    lastInvitationEndSeq = issueCounter;
  }

  /* --- admission (C-SDK section 7, C-DLV section 7.4) -------------------- */

  /**
   * One validated kind-4741 event of the inbound queue, in arrival order.
   * Resolves once it is staged, dropped or refused; never rejects.
   *
   * @param {{ id: string, pubkey: string, tags: string[][], content: string }} event
   * @param {object} frame the counted frame
   */
  async function admit(event, frame) {
    const eventId = event.id;
    if (stopped) {
      account(frame, 'dropped', eventId);
      return;
    }
    if (seen.has(eventId)) {
      const entry = pending.get(eventId);
      if (entry !== undefined) {
        const record = counted.get(frame);
        if (record !== undefined) entry.relays.add(record.relay);
        copyArrived(entry);
      }
      account(frame, 'seen', eventId);
      return;
    }
    let ciphertext = null;
    try {
      ciphertext = base64ToBytes(event.content);
    } catch {
      ciphertext = null;
    }
    if (!(ciphertext instanceof Uint8Array) || ciphertext.length === 0) {
      safeEmit({ kind: 'INBOUND_DISCARDED', code: 'E_SDK_INBOUND_INVALID' });
      account(frame, 'invalid', null);
      return;
    }
    if (mode !== 'normal') {
      account(frame, 'failed', eventId);
      return;
    }
    const known = await call(session, 'isKnownSender', [Object.freeze({ sender: event.pubkey })]);
    if (stopped) {
      account(frame, 'dropped', eventId);
      return;
    }
    if (known.settled !== 'value' || typeof known.value !== 'boolean') {
      if (known.settled === 'value' && scan(known.value).unknown) {
        safeEmit({ kind: 'INBOUND_DISCARDED', code: UNKNOWN });
      }
      account(frame, 'failed', eventId);
      return;
    }
    if (known.value === false) {
      // Not admitted: not staged, opened, emitted, receipted or remembered.
      account(frame, 'notAdmitted', eventId);
      return;
    }
    if (quotaReached()) {
      reportCapacity();
      account(frame, 'failed', eventId);
      return;
    }
    const receiptRequested = event.tags.length === 4;
    const staged = await serialized(async () => {
      if (mode !== 'normal' || stopped) return 'blocked';
      if (seen.has(eventId)) return 'seen';
      const result = await portWrite('stage', {
        event: Object.freeze({ eventId, sender: event.pubkey, ciphertext: new Uint8Array(ciphertext), receiptRequested }),
      }, WRITE_CODES);
      if (result.status === 'ok') {
        adopt(result);
        seen.add(eventId);
        const entry = pendingEntry(eventId, event.pubkey, ciphertext, receiptRequested);
        const record = counted.get(frame);
        if (record !== undefined) entry.relays.add(record.relay);
        pending.set(eventId, entry);
        return 'staged';
      }
      failState('frozen', result.code);
      return 'blocked';
    });
    if (staged === 'staged') {
      account(frame, 'staged', eventId);
      const entry = pending.get(eventId);
      if (entry !== undefined) enqueue(entry, 'fresh');
      if (quotaReached()) reportCapacity();
    } else if (staged === 'seen') {
      account(frame, 'seen', eventId);
    } else {
      account(frame, 'failed', eventId);
    }
  }

  /* --- the open unit and the retry budget (C-DLV section 7.4) ------------ */

  const freshQueue = [];
  const retryQueue = [];
  let unit = null;
  let lastPick = 'retry';
  let unitIdle = Promise.resolve();
  let releaseUnitIdle = null;

  /**
   * The in-run retry budget (C-DLV section 7.4): one retry per entry per
   * catch-up interval across copies and the periodic pass. It is available
   * from the entry's first attempt in this run (at staging or in the recovery
   * pass, which consume none) and, once a retry starts, renews
   * RETRY_INTERVAL_MS after that start on the clock port.
   */
  function eligible(entry) {
    if (entry.budgetAt === null) return true;
    const now = nowMs();
    return now !== null && now >= entry.budgetAt;
  }

  function enqueue(entry, which) {
    if (entry.queued || (unit !== null && unit.eventId === entry.eventId)) return;
    entry.queued = true;
    (which === 'fresh' ? freshQueue : retryQueue).push(entry.eventId);
    pump();
  }

  function copyArrived(entry) {
    if (entry.queued || (unit !== null && unit.eventId === entry.eventId)) return;
    if (eligible(entry)) enqueue(entry, 'retry');
  }

  function nextEntry() {
    const order = lastPick === 'fresh' ? [retryQueue, freshQueue] : [freshQueue, retryQueue];
    for (const queue of order) {
      while (queue.length > 0) {
        const id = queue.shift();
        const entry = pending.get(id);
        if (entry === undefined) continue;
        entry.queued = false;
        lastPick = queue === freshQueue ? 'fresh' : 'retry';
        if (queue === retryQueue) {
          const now = nowMs();
          entry.budgetAt = now === null ? Number.POSITIVE_INFINITY : now + RETRY_INTERVAL_MS;
        }
        return entry;
      }
    }
    return null;
  }

  function pump() {
    if (unit !== null || stopped || mode !== 'normal') return;
    const entry = nextEntry();
    if (entry === null) return;
    unit = entry;
    unitIdle = new Promise((resolve) => { releaseUnitIdle = resolve; });
    openOne(entry).catch(() => undefined).then(() => {
      unit = null;
      const release = releaseUnitIdle;
      releaseUnitIdle = null;
      if (release !== null) release();
      if (!stopped) Promise.resolve().then(pump);
    });
  }

  /**
   * Whether an `openCandidate` result carries a `receiveOutcome` outside its
   * closed set: any own data value other than the three outcome strings, of
   * any type (C-SDK section 5.3), not only an unknown string.
   */
  function outcomeOutOfSet(value) {
    try {
      if (value === null || typeof value !== 'object') return false;
      const descriptor = Reflect.getOwnPropertyDescriptor(value, 'receiveOutcome');
      return descriptor !== undefined && hasOwn(descriptor, 'value') && !OUTCOMES.has(descriptor.value);
    } catch {
      return false;
    }
  }

  /** The closed `openCandidate` result, or `null` for a malformed one. */
  function readCandidate(value) {
    const fields = closed(value, ['receiveOutcome', 'ticket'], ['plaintext']);
    if (fields === null || !OUTCOMES.has(fields.receiveOutcome)) return null;
    if (fields.receiveOutcome === 'application') {
      if (!hasOwn(fields, 'plaintext')) return null;
      const plaintext = copyBytes(fields.plaintext);
      return plaintext === null ? null : { outcome: 'application', plaintext, ticket: fields.ticket };
    }
    if (hasOwn(fields, 'plaintext')) return null;
    return { outcome: fields.receiveOutcome, ticket: fields.ticket };
  }

  async function openOne(entry) {
    const called = await call(session, 'openCandidate', [Object.freeze({
      sender: entry.sender, ciphertext: new Uint8Array(entry.ciphertext),
    })]);
    // Shutdown starts no commit for a candidate still being prepared.
    if (stopped) return;
    let candidate = null;
    if (called.settled === 'value') {
      if (scan(called.value).unknown || outcomeOutOfSet(called.value)) {
        safeEmit({ kind: 'INBOUND_DISCARDED', code: UNKNOWN });
      } else {
        candidate = readCandidate(called.value);
      }
    }
    if (candidate === null || candidate.outcome === 'retry') return;
    const result = candidate.outcome === 'application'
      ? Object.freeze({ type: 'application', sender: entry.sender, payload: candidate.plaintext,
        receiptDue: entry.receiptRequested })
      : Object.freeze({ type: 'rejected' });
    await serialized(() => commitEntry(entry, candidate.ticket, result));
  }

  async function commitEntry(entry, ticket, result) {
    // Shutdown starts no commit that was only queued behind another write.
    if (stopped || mode !== 'normal') return;
    const written = await portWrite('commit', { eventId: entry.eventId, ticket, result }, COMMIT_CODES);
    if (written.status === 'ok') {
      adopt(written);
      applyCommit(entry, result);
      return;
    }
    if (written.status === 'code' && written.code === CAPACITY) {
      // Nothing was written: the entry stays PENDING and admission stops.
      portCapacity = true;
      reportCapacity();
      failRelaysOf(entry);
      return;
    }
    if (written.status === 'code') {
      failState('frozen', written.code);
      failRelaysOf(entry);
      return;
    }
    failState('paused', written.code);
    failRelaysOf(entry);
    paused = { operationId: written.operationId, entry, result };
    await resolvePaused();
  }

  function applyCommit(entry, result) {
    pending.delete(entry.eventId);
    if (result.type === 'application') {
      const view = readyEntry(entry.eventId, entry.sender, new Uint8Array(result.payload), result.receiptDue);
      ready.set(entry.eventId, view);
      if (result.receiptDue) {
        receiptsDue.set(entry.eventId, { eventId: entry.eventId, sender: entry.sender, attempted: false, job: null });
      }
      scheduleDelivery(view);
    } else {
      safeEmit({ kind: 'INBOUND_DISCARDED', code: 'E_SDK_SESSION_FAILED' });
    }
    clearFailedId(entry.eventId);
    // A capacity refusal of the port holds until a later write succeeds.
    portCapacity = false;
    if (quotaReached()) reportCapacity(); else recheckCapacity();
  }

  /** `resolve` of the paused commit; runs inside the write chain. */
  async function resolvePaused() {
    if (paused === null || mode !== 'paused') return;
    const { operationId, entry, result } = paused;
    const called = await call(port, 'resolve', [Object.freeze({ operationId })]);
    if (paused === null || mode !== 'paused') return;
    if (called.settled !== 'value' || scan(called.value).unknown || scan(called.value).malformed) return;
    const value = called.value;
    const committed = closed(value, ['status', 'revision', 'storedBytes', 'result']);
    if (committed !== null && committed.status === 'committed' && isCount(committed.revision)
      && isCount(committed.storedBytes) && sameResult(committed.result, result)) {
      paused = null;
      mode = 'normal';
      adopt(committed);
      applyCommit(entry, result);
      return;
    }
    const aborted = closed(value, ['status', 'revision'], ['storedBytes']);
    if (aborted !== null && aborted.status === 'aborted' && isCount(aborted.revision)
      && (aborted.storedBytes === undefined || isCount(aborted.storedBytes))) {
      paused = null;
      mode = 'normal';
      revision = aborted.revision;
      if (aborted.storedBytes !== undefined) storedBytes = aborted.storedBytes;
      clearFailedId(entry.eventId);
      return;
    }
    const refused = closed(value, ['code']);
    if (refused !== null && RESOLVE_CODES.has(refused.code)) return;
    // Anything else is a failed resolve: the client stays paused.
  }

  function sameResult(value, sent) {
    if (sent.type === 'rejected') {
      const fields = closed(value, ['type']);
      return fields !== null && fields.type === 'rejected';
    }
    const fields = closed(value, ['type', 'sender', 'payload', 'receiptDue']);
    if (fields === null || fields.type !== 'application' || fields.sender !== sent.sender
      || fields.receiptDue !== sent.receiptDue) return false;
    const payload = copyBytes(fields.payload);
    if (payload === null || payload.length !== sent.payload.length) return false;
    for (let index = 0; index < payload.length; index += 1) if (payload[index] !== sent.payload[index]) return false;
    return true;
  }

  /**
   * The recovery pass of `start()`: every loaded PENDING entry is retried once
   * in stage order before the first relay connection. Resolves `null`, or
   * `E_SDK_RECEIVE_STATE_FAILED` when the state is not `normal` afterwards.
   */
  async function recover() {
    for (const entry of pending.values()) enqueue(entry, 'fresh');
    for (;;) {
      await unitIdle;
      if (stopped) return null;
      if (unit === null && (freshQueue.length === 0 || mode !== 'normal')) break;
      await Promise.resolve();
    }
    return mode === 'normal' ? null : FAILED;
  }

  /** The periodic pass (every RETRY_INTERVAL_MS while running). */
  function periodicPass() {
    if (stopped) return;
    if (mode === 'paused') serialized(resolvePaused);
    if (mode !== 'normal') return;
    for (const entry of pending.values()) {
      if (!entry.queued && !(unit !== null && unit.eventId === entry.eventId) && eligible(entry)) {
        entry.queued = true;
        retryQueue.push(entry.eventId);
      }
    }
    pump();
  }

  /* --- emission and redelivery (C-SDK section 7) -------------------------- */

  function scheduleDelivery(entry) {
    if (stopped || entry.delivery !== null || !ready.has(entry.eventId)) return;
    let delivery = null;
    try {
      // Read once when the dispatch runs: an entry acknowledged meanwhile is
      // not dispatched; otherwise its reserved listeners are invoked now, so
      // the entry is acknowledgeable from inside them (C-SDK section 4.2).
      delivery = deliver(
        Object.freeze({ eventId: entry.eventId, sender: entry.sender, payload: entry.payload }),
        () => {
          if (ready.get(entry.eventId) !== entry) return false;
          entry.invoked = true;
          return true;
        },
      );
    } catch {
      delivery = null;
    }
    if (delivery === null || delivery === undefined || typeof delivery.then !== 'function') return;
    entry.delivery = delivery;
    delivery.then((invoked) => {
      entry.delivery = null;
      if (invoked === true) {
        entry.invoked = true;
        pumpReceipts();
      }
    }, () => {
      entry.delivery = null;
    });
  }

  /** Redeliver every unacknowledged READY entry, in commit order. */
  function redeliverAll() {
    if (stopped) return;
    for (const entry of ready.values()) scheduleDelivery(entry);
  }

  /* --- acknowledgement (C-SDK section 4.2) -------------------------------- */

  /**
   * @param {string} eventId
   * @returns {Promise<string | null>} `null` on success, else the code
   */
  async function acknowledge(eventId) {
    if (stopped) return 'E_SDK_CLIENT_STOPPED';
    if (acknowledged.has(eventId)) return null;
    const entry = ready.get(eventId);
    if (entry === undefined || !entry.invoked) return 'E_SDK_UNKNOWN_MESSAGE';
    if (mode !== 'normal') return FAILED;
    if (entry.acking !== null) return entry.acking;
    entry.acking = (async () => {
      const done = await plainWrite('ack', { eventId });
      if (!done) {
        entry.acking = null;
        return acknowledged.has(eventId) ? null : FAILED;
      }
      ready.delete(eventId);
      acknowledged.add(eventId);
      entry.payload = new Uint8Array(0);
      portCapacity = false;
      recheckCapacity();
      pumpReceipts();
      return null;
    })();
    return entry.acking;
  }

  /* --- receipt obligations (C-DLV section 7.4) --------------------------- */

  let relaySeams = null;
  let receiptJob = null;
  let waitingForRelay = false;

  function receiptEligible(obligation) {
    if (obligation.attempted || obligation.job !== null) return false;
    if (acknowledged.has(obligation.eventId)) return true;
    const entry = ready.get(obligation.eventId);
    return entry !== undefined && entry.invoked;
  }

  function pumpReceipts() {
    if (!running || stopped || mode !== 'normal' || relaySeams === null || receiptJob !== null || waitingForRelay) return;
    for (const obligation of receiptsDue.values()) {
      if (!receiptEligible(obligation)) continue;
      let connected = 0;
      try {
        connected = relaySeams.connected();
      } catch {
        connected = 0;
      }
      if (!(connected > 0)) {
        // Deferred, not consumed: a later connection wakes it.
        waitingForRelay = true;
        return;
      }
      obligation.job = runReceipt(obligation);
      receiptJob = obligation.job;
      receiptJob.then(() => {
        obligation.job = null;
        receiptJob = null;
        if (!stopped) Promise.resolve().then(pumpReceipts);
      });
      return;
    }
  }

  async function runReceipt(obligation) {
    const now = nowMs();
    if (now === null || now < 0) {
      obligation.attempted = true;
      return;
    }
    const createdAt = Math.floor(now / 1000);
    if (!Number.isSafeInteger(createdAt)) {
      obligation.attempted = true;
      return;
    }
    let nonce;
    try {
      nonce = bytesToHex(randomBytes(16));
    } catch {
      obligation.attempted = true;
      return;
    }
    const tags = Object.freeze([
      Object.freeze(['p', obligation.sender]),
      Object.freeze(['e', obligation.eventId]),
      Object.freeze(['v', SDK_WIRE_VERSION]),
      Object.freeze(['n', nonce]),
    ]);
    let id;
    try {
      id = eventIdOf(publicKey, createdAt, RECEIPT_KIND, tags, '');
    } catch {
      obligation.attempted = true;
      return;
    }
    const signed = await call(identity, 'sign', [Object.freeze({ digest: hexToBytes(id) })]);
    obligation.attempted = true;
    if (signed.settled !== 'value') return;
    if (scan(signed.value).unknown) {
      if (!stopped) safeEmit({ kind: 'INBOUND_DISCARDED', code: UNKNOWN });
      return;
    }
    const signature = copyBytes(signed.value);
    if (signature === null || signature.length !== 64) return;
    const receipt = Object.freeze({
      id, pubkey: publicKey, created_at: createdAt, kind: RECEIPT_KIND, tags, content: '', sig: bytesToHex(signature),
    });
    if (stopped) {
      // The shutdown drain: S6 publication without waiting for OK.
      try {
        relaySeams.drain(receipt);
      } catch {
        // Best effort.
      }
      return;
    }
    let published = false;
    try {
      published = relaySeams.publish(receipt, () => receiptAccepted(obligation));
    } catch {
      published = false;
    }
    if (published !== true) {
      // No connected pool took it: the attempt is deferred, not consumed.
      obligation.attempted = false;
      waitingForRelay = true;
    }
  }

  function receiptAccepted(obligation) {
    if (stopped || obligation.done) return;
    obligation.done = true;
    plainWrite('receiptDone', { eventId: obligation.eventId }).then((done) => {
      if (done) receiptsDue.delete(obligation.eventId);
      else obligation.done = false;
    });
  }

  function relayConnected() {
    if (!waitingForRelay) return;
    waitingForRelay = false;
    pumpReceipts();
  }

  /* --- lifecycle ---------------------------------------------------------- */

  const timers = { retry: null, redelivery: null };

  function arm(name, delay, action) {
    try {
      const handle = clock.setTimer(() => {
        if (stopped) return;
        timers[name] = null;
        try {
          action();
        } catch {
          // A pass fault never stops the next one.
        }
        arm(name, delay, action);
      }, delay);
      if (handle !== null && typeof handle === 'object') Promise.resolve(handle).catch(() => {});
      timers[name] = { handle };
    } catch {
      timers[name] = null;
    }
  }

  /**
   * The client is RUNNING: attach the relay seams, arm the periodic passes and
   * start the receipt obligations whose invocation is proven.
   *
   * @param {{ connected: () => number, publish: Function, drain: Function }} seams
   */
  function startRunning(seams) {
    if (stopped || running) return;
    running = true;
    relaySeams = seams;
    arm('retry', RETRY_INTERVAL_MS, periodicPass);
    arm('redelivery', REDELIVERY_INTERVAL_MS, redeliverAll);
    pumpReceipts();
    pump();
  }

  /** Shutdown step (1): synchronous; no admission, candidate, pass or receipt starts. */
  function stop() {
    stopped = true;
  }

  /** Shutdown step (4): clear the two pass timers. */
  function dispose() {
    stopped = true;
    for (const name of Object.keys(timers)) {
      const timer = timers[name];
      timers[name] = null;
      if (timer === null) continue;
      try {
        const cleared = clock.clearTimer(timer.handle);
        if (cleared !== null && typeof cleared === 'object') Promise.resolve(cleared).catch(() => {});
      } catch {
        // Best effort.
      }
    }
  }

  /** Resolves once the open unit, the write chain and the receipt job settled. */
  function settled() {
    return Promise.all([unitIdle, chain, receiptJob === null ? undefined : receiptJob]).then(() => undefined,
      () => undefined);
  }

  return Object.freeze({
    load,
    recover,
    admit,
    countFrame,
    account,
    poolSubscriptionId,
    issue,
    since,
    observe,
    invitationStarted,
    invitationEnded,
    acknowledge,
    wake: redeliverAll,
    relayConnected,
    startRunning,
    stop,
    dispose,
    settled,
    isLoaded: () => loaded,
    isConfigured: () => true,
    blocked: () => mode !== 'normal',
  });
}
