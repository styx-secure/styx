// M2 legacy-session invalidation marker. Internal-only: no barrel export.
//
// This module owns the *encoding and physical evidence* of the abstract one-way
// cutover/invalidation marker of the owner-ratified C-REC contract (C-REC §6 and the
// §13 `/marker` record, `/marker/encodingOwner` = `L-MARK`). It publishes the closed
// marker vocabulary verbatim — the four states, the five transitions, the derived
// `legacyEligibleByState` fact, the opaque-binding rule, the two owners and the closed
// flags — and gives those facts a canonical encoding of its own.
//
// The marker is NOT a C-FMT record kind and is NOT a legacy locator. C-REC §6: "The
// abstract marker is not an M2 record kind, not a legacy-byte mutation, and not obtained
// by re-reading or reclassifying storage." C-FMT `/recordKinds` contains no marker or
// invalidation kind. The marker therefore uses its own canonical encoding here and is
// never written as, or read back by, a re-classified legacy locator or a C-FMT record.
//
// The marker is one-way. `reverseAfterConfirmation` is false, no transition leads from
// `NEW_SESSION_CONFIRMED` or `LEGACY_INVALIDATED` to a legacy-eligible state, and every
// event that would return there is refused with `MARKER_TRANSITION_FORBIDDEN`. Invalidation
// never deletes, moves, overwrites, compacts or proves erasure of any byte.
//
// It never reads or writes a stored value, never opens a store, never acquires a lock
// (the lock is an injected boolean), never imports, decrypts, translates, copies, selects,
// decodes as M2 or falls back to legacy, and creates no session (that is `L-REEST`).
//
// Totality: every input is untrusted. Members are read from their own property descriptors,
// so no accessor is ever invoked; the marker bytes are copied through the `%TypedArray%`
// internal slot, never through a caller-controlled `length`, `buffer`, `Symbol.species` or
// own `constructor`. Every failure path leaves through `M2LegacyInvalidationError` with one
// of the three closed decode codes, or through a closed `REJECT` decision — never a foreign
// exception.

const TE = new TextEncoder();

const SCHEMA = 'styx-m2-legacy-invalidation/v1';
const MARKER_MAGIC = 'STYXMARK1';
const MAGIC_BYTES = TE.encode('STYXMARK1');
const MARKER_VERSION = 1;
const MAGIC_LENGTH = 9;
const BINDING_TOKEN_BYTES = 32;
const MARKER_LENGTH = MAGIC_LENGTH + 2 + 1 + BINDING_TOKEN_BYTES;

const ABSENT = 'ABSENT';
const PENDING = 'PENDING_NEW_SESSION';
const CONFIRMED = 'NEW_SESSION_CONFIRMED';
const INVALIDATED = 'LEGACY_INVALIDATED';

const STATES = Object.freeze([ABSENT, PENDING, CONFIRMED, INVALIDATED]);

/** The four ratified `state -> u8` codes, in C-REC `/marker/states` order. */
const STATE_CODES = Object.freeze({ [ABSENT]: 0, [PENDING]: 1, [CONFIRMED]: 2, [INVALIDATED]: 3 });
const STATE_BY_CODE = Object.freeze([ABSENT, PENDING, CONFIRMED, INVALIDATED]);

// C-REC §13 `/marker/transitions`, transcribed verbatim and frozen. The event strings are
// the ratified `/marker/transitions[*].event` values.
const EVENT_START = 'USER_CONFIRMED_START';
const EVENT_CANCEL = 'USER_CANCEL_BEFORE_CONFIRMATION';
const EVENT_CONFIRM = 'DISTINCT_POST_START_C_FMT_COMMITTED_AUTHORITY_RESTORED_ACTIVE';
const EVENT_COMMIT = 'ATOMIC_MARKER_COMMIT';
const EVENT_REPEAT = 'REPEAT_MARKER_COMPLETION';

const EVENTS = Object.freeze([EVENT_START, EVENT_CANCEL, EVENT_CONFIRM, EVENT_COMMIT, EVENT_REPEAT]);

const IMMUTABLE = (list) => Object.freeze(list);
const TRANSITIONS = Object.freeze([
  Object.freeze({
    id: 'START', from: ABSENT, event: EVENT_START, to: PENDING,
    allowedRestoreResults: IMMUTABLE(['LEGACY_ONLY']), requiresLock: true, idempotent: false,
  }),
  Object.freeze({
    id: 'CANCEL', from: PENDING, event: EVENT_CANCEL, to: ABSENT,
    allowedRestoreResults: IMMUTABLE(['LEGACY_ONLY']), requiresLock: true, idempotent: false,
  }),
  Object.freeze({
    id: 'CONFIRM', from: PENDING, event: EVENT_CONFIRM, to: CONFIRMED,
    allowedRestoreResults: IMMUTABLE(['RESTORED_ACTIVE']), requiresLock: true, idempotent: false,
  }),
  Object.freeze({
    id: 'COMMIT_MARKER', from: CONFIRMED, event: EVENT_COMMIT, to: INVALIDATED,
    allowedRestoreResults: IMMUTABLE(['RESTORED_ACTIVE']), requiresLock: true, idempotent: true,
  }),
  Object.freeze({
    id: 'REPEAT_COMPLETION', from: INVALIDATED, event: EVENT_REPEAT, to: INVALIDATED,
    allowedRestoreResults: IMMUTABLE(['RESTORED_ACTIVE']), requiresLock: true, idempotent: true,
  }),
]);

/** C-REC `/marker/legacyEligibleByState`, transcribed verbatim. */
const LEGACY_ELIGIBLE_BY_STATE = Object.freeze({
  [ABSENT]: true, [PENDING]: true, [CONFIRMED]: false, [INVALIDATED]: false,
});

const DISPOSITIONS = Object.freeze(['MARKER_TRANSITION', 'LOCK_RETRY', 'REJECT']);
const REJECT_CODES = Object.freeze([
  'MARKER_TRANSITION_FORBIDDEN', 'TOKEN_MISMATCH', 'CONFIRMATION_PRECONDITION_FAILED',
  'RESTORE_PRECONDITION_FAILED', 'LOCKED_ELSEWHERE',
]);
const DECODE_FAILURE_CODES = Object.freeze([
  'INCOMPATIBLE_FORMAT', 'UNSUPPORTED_VERSION', 'MARKER_ENCODING_INVALID',
]);

export const M2_LEGACY_INVALIDATION = Object.freeze({
  SCHEMA,
  MARKER_MAGIC,
  MARKER_VERSION,
  MARKER_LENGTH,
  BINDING_TOKEN_BYTES,
  STATES,
  STATE_CODES,
  EVENTS,
  TRANSITIONS,
  LEGACY_ELIGIBLE_BY_STATE,
  BINDING: 'OPAQUE_START_AUTHORITY_CONFIRMATION_TOKEN_EQUALITY',
  ENCODING_OWNER: 'L-MARK',
  NEW_SESSION_OWNER: 'L-REEST',
  COMPLETE_RESTORE_RESULT_REQUIRED: true,
  TIME_OR_FRESHNESS_COMPARISON: false,
  CLEANUP_EFFECT: false,
  REVERSE_AFTER_CONFIRMATION: false,
  REAL_CONFIRMATION_BLOCKED_UNTIL_OWNERS_RATIFIED: true,
  DISPOSITIONS,
  REJECT_CODES,
  DECODE_FAILURE_CODES,
  // C-REC `/legacy/*`: the inventory is abstract, preserved and non-authoritative.
  PHYSICAL_INVENTORY_OWNER: 'L-INV',
  IMPORT: false,
  DECRYPT: false,
  TRANSLATE: false,
  FALLBACK: false,
  SELECTED_AUTHORITY: false,
  PRESERVE_BYTES: true,
  CLEANUP: 'DEFERRED',
  // `/precedence/lockedDisposition`.
  LOCKED_DISPOSITION: 'LOCK_RETRY',
  // The exact C-REC state names of the two states after which no reverse transition exists.
  CONFIRMED_STATES: IMMUTABLE([CONFIRMED, INVALIDATED]),
});

export class M2LegacyInvalidationError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'M2LegacyInvalidationError';
    this.code = DECODE_FAILURE_CODES.includes(code) ? code : 'MARKER_ENCODING_INVALID';
  }
}

const fail = (code, message) => { throw new M2LegacyInvalidationError(code, message); };

// A foreign exception must never escape and must never choose the code: every `fail(...)`
// sits outside a guarded block, so whatever a caller's trap or getter threw is discarded
// here and the block's own closed code is raised instead.
const mapFailure = (code, message) => fail(code, message);

// The `%TypedArray%` brand check reads the internal slot, so a proxy, a forged
// `Uint8Array.prototype` object or another view type is refused.
const TYPED_ARRAY_PROTO = Object.getPrototypeOf(Uint8Array.prototype);
const TYPED_ARRAY_TAG = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTO, Symbol.toStringTag).get;
const TYPED_ARRAY_LENGTH = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTO, 'length').get;

function isByteSequence(value) {
  try {
    return ArrayBuffer.isView(value) && TYPED_ARRAY_TAG.call(value) === 'Uint8Array';
  } catch {
    return false;
  }
}

// One snapshot per value, and it is the only bytes any later step reads. `new Uint8Array(len)`
// plus `set` consult neither `Symbol.species` nor an own `constructor`/`length`, so a caller
// cannot redirect, shorten or alias the copy. A detached view throws in `set`.
function snapshot(value, name) {
  if (!isByteSequence(value)) fail('INCOMPATIBLE_FORMAT', `${name} must be a Uint8Array`);
  let copy = null;
  try {
    copy = new Uint8Array(TYPED_ARRAY_LENGTH.call(value));
    Uint8Array.prototype.set.call(copy, value);
  } catch {
    mapFailure('INCOMPATIBLE_FORMAT', `${name} could not be read as a byte sequence`);
  }
  return copy;
}

function isPlainObject(value) {
  try {
    return value !== null && typeof value === 'object' && !Array.isArray(value)
      && !ArrayBuffer.isView(value) && Object.getPrototypeOf(value) === Object.prototype;
  } catch {
    return false;
  }
}

// Read exactly the allowed own enumerable data members of a plain object, without ever
// invoking an accessor. `allowed` bounds the member set; `required` must all be present.
// Returns the present values or throws a closed decode code.
function readClosed(value, allowed, required, name) {
  if (!isPlainObject(value)) fail('INCOMPATIBLE_FORMAT', `${name} must be a plain object`);
  let own = null;
  try {
    own = Reflect.ownKeys(value);
  } catch {
    mapFailure('INCOMPATIBLE_FORMAT', `${name} could not be inspected`);
  }
  for (const key of own) {
    if (typeof key !== 'string' || !allowed.includes(key)) {
      fail('INCOMPATIBLE_FORMAT', `${name} has an unknown, missing or symbol property`);
    }
  }
  const out = {};
  for (const key of allowed) {
    let d = null;
    try {
      d = Object.getOwnPropertyDescriptor(value, key);
    } catch {
      mapFailure('INCOMPATIBLE_FORMAT', `${name}.${key} could not be inspected`);
    }
    if (d === undefined) continue;
    if (!d.enumerable || !Object.hasOwn(d, 'value')) {
      fail('INCOMPATIBLE_FORMAT', `${name}.${key} must be enumerable data`);
    }
    out[key] = d.value;
  }
  for (const key of required) {
    if (!Object.hasOwn(out, key)) fail('INCOMPATIBLE_FORMAT', `${name} is missing ${key}`);
  }
  return out;
}

function descriptorValue(record, key) {
  if (!isPlainObject(record)) return undefined;
  let d = null;
  try {
    d = Object.getOwnPropertyDescriptor(record, key);
  } catch {
    return undefined;
  }
  if (!d || !d.enumerable || !Object.hasOwn(d, 'value')) return undefined;
  return d.value;
}

const isZeroToken = (bytes) => {
  for (let i = 0; i < bytes.length; i += 1) if (bytes[i] !== 0) return false;
  return true;
};

// Plain byte equality of the two opaque tokens. No time, counter, digest or freshness
// comparison exists in this module; the loop does not early-exit.
function tokensEqual(left, right) {
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let i = 0; i < left.length; i += 1) diff |= left[i] ^ right[i];
  return diff === 0;
}

/** The exact `state` of a closed state name, or a closed refusal. */
function stateOf(value) {
  if (typeof value !== 'string' || !Object.hasOwn(STATE_CODES, value)) {
    fail('INCOMPATIBLE_FORMAT', 'marker state is not a ratified state name');
  }
  return value;
}

/** Total and deterministic over the four states; an unknown state fails closed. */
export function legacyEligible(state) {
  return LEGACY_ELIGIBLE_BY_STATE[stateOf(state)];
}

/**
 * Canonical encoding of a `{ state, bindingToken }` marker. `bindingToken` is the opaque
 * start-authority token: `ABSENT` requires it to be all-zero, every other state requires a
 * nonzero token. Returns a fresh `Uint8Array(43)`; the caller's memory is never written and
 * never aliased.
 */
export function encodeMarker(marker) {
  const members = ['state', 'bindingToken'];
  const m = readClosed(marker, members, members, 'marker');
  const state = stateOf(m.state);
  const token = snapshot(m.bindingToken, 'marker.bindingToken');
  if (token.length !== BINDING_TOKEN_BYTES) fail('MARKER_ENCODING_INVALID', 'binding token is not 32 bytes');
  const zero = isZeroToken(token);
  if (state === ABSENT && !zero) fail('MARKER_ENCODING_INVALID', 'an ABSENT marker carries no start token');
  if (state !== ABSENT && zero) fail('MARKER_ENCODING_INVALID', 'a started marker carries a start token');
  const out = new Uint8Array(MARKER_LENGTH);
  out.set(MAGIC_BYTES, 0);
  out[MAGIC_LENGTH] = 0;
  out[MAGIC_LENGTH + 1] = MARKER_VERSION;
  out[MAGIC_LENGTH + 2] = STATE_CODES[state];
  out.set(token, MAGIC_LENGTH + 3);
  return out;
}

// The internal decode that keeps the start token. `readMarker` below is the value-free
// public view; this one never escapes the module.
function readMarkerInternal(bytes) {
  const b = snapshot(bytes, 'marker');
  if (b.length < MAGIC_LENGTH + 2) fail('MARKER_ENCODING_INVALID', 'marker is shorter than its header');
  for (let i = 0; i < MAGIC_LENGTH; i += 1) {
    if (b[i] !== MAGIC_BYTES[i]) fail('MARKER_ENCODING_INVALID', 'marker magic is not canonical');
  }
  const version = b[MAGIC_LENGTH] * 256 + b[MAGIC_LENGTH + 1];
  if (version !== MARKER_VERSION) fail('UNSUPPORTED_VERSION', 'unknown marker version');
  if (b.length !== MARKER_LENGTH) fail('MARKER_ENCODING_INVALID', 'marker length is not canonical');
  const code = b[MAGIC_LENGTH + 2];
  if (code >= STATE_BY_CODE.length) fail('MARKER_ENCODING_INVALID', 'unknown marker state code');
  const state = STATE_BY_CODE[code];
  const token = b.slice(MAGIC_LENGTH + 3);
  const zero = isZeroToken(token);
  if (state === ABSENT && !zero) fail('MARKER_ENCODING_INVALID', 'an ABSENT marker carries no start token');
  if (state !== ABSENT && zero) fail('MARKER_ENCODING_INVALID', 'a started marker carries a start token');
  return { state, token };
}

/**
 * Decode the module's own canonical encoding. Returns exactly
 * `{ schema, version, state, legacyEligible }` and never the binding token, any byte of it,
 * its digest or a context identifier, so no `markerBinding` diagnostic is produced (C-REC §9).
 */
export function readMarker(bytes) {
  const { state } = readMarkerInternal(bytes);
  return Object.freeze({
    schema: SCHEMA, version: MARKER_VERSION, state, legacyEligible: LEGACY_ELIGIBLE_BY_STATE[state],
  });
}

const C_REST_RESULTS = Object.freeze([
  'NO_M2_STATE', 'LEGACY_ONLY', 'RESTORED_ACTIVE', 'RESTORED_EMPTY', 'RESTORED_RECONCILIATION_REQUIRED',
]);

function transitionFor(state, event) {
  for (const t of TRANSITIONS) if (t.from === state && t.event === event) return t;
  return null;
}

function settle(state, disposition, stateAfter, reject, firstFailingPhase) {
  return Object.freeze({
    disposition,
    accepted: disposition === 'MARKER_TRANSITION',
    stateBefore: state,
    stateAfter,
    legacyEligible: LEGACY_ELIGIBLE_BY_STATE[stateAfter],
    reject,
    firstFailingPhase,
  });
}

// `/precedence/lockedDisposition` is `LOCK_RETRY`; a non-holder learns nothing else.
const lockRetry = (state) => settle(state, 'LOCK_RETRY', state, 'LOCKED_ELSEWHERE', 'LOCK');

// The four states and five transitions are closed, so any other pair is forbidden.
const forbidden = (state) => settle(state, 'REJECT', state, 'MARKER_TRANSITION_FORBIDDEN', 'MARKER_GATE');

function decide(state, startToken, event, lockHeld, restoreResult, committed, authorityToken) {
  const settled = (disposition, stateAfter, reject, firstFailingPhase) => settle(
    state, disposition, stateAfter, reject, firstFailingPhase,
  );

  // 1. LOCK.
  if (lockHeld !== true) return lockRetry(state);

  // 2. MARKER_GATE — the (state, event) pair must be one of the five ratified transitions.
  const transition = transitionFor(state, event);
  if (transition === null) return forbidden(state);

  // 3. MARKER_GATE — the raised restore precondition.
  if (typeof restoreResult !== 'string' || !transition.allowedRestoreResults.includes(restoreResult)) {
    return settled('REJECT', state, transition.id === 'CONFIRM'
      ? 'CONFIRMATION_PRECONDITION_FAILED' : 'RESTORE_PRECONDITION_FAILED', 'MARKER_GATE');
  }

  if (transition.id === 'CONFIRM') {
    // 4. MARKER_GATE — a C-FMT COMMITTED authority is required.
    if (committed !== true) return settled('REJECT', state, 'CONFIRMATION_PRECONDITION_FAILED', 'MARKER_GATE');
    // 5. MARKER_GATE — opaque token equality: the authority must be a *distinct* post-start one.
    if (!isByteSequence(authorityToken)) {
      return settled('REJECT', state, 'TOKEN_MISMATCH', 'MARKER_GATE');
    }
    const token = snapshot(authorityToken, 'authorityToken');
    if (token.length !== BINDING_TOKEN_BYTES || tokensEqual(token, startToken)) {
      return settled('REJECT', state, 'TOKEN_MISMATCH', 'MARKER_GATE');
    }
  }

  return settled('MARKER_TRANSITION', transition.to, null, 'NONE');
}

/**
 * Apply one event to one encoded marker. `input` carries exactly the members
 * `marker`, `event`, `lockHeld` and `restoreResult`, plus `committed` and `authorityToken` for the
 * `CONFIRM` event only; `marker`, `event` and `lockHeld` are always required, `restoreResult` is
 * required for every reachable (state, event) pair. Returns exactly one frozen decision record;
 * throws only `M2LegacyInvalidationError`, and only when the input record itself is malformed.
 */
export function applyMarkerTransition(input) {
  if (!isPlainObject(input)) fail('INCOMPATIBLE_FORMAT', 'transition input must be a plain object');
  const event = descriptorValue(input, 'event');
  if (typeof event !== 'string') fail('INCOMPATIBLE_FORMAT', 'transition event must be a string');
  const confirm = event === EVENT_CONFIRM;
  const allowed = confirm
    ? ['marker', 'event', 'lockHeld', 'restoreResult', 'committed', 'authorityToken']
    : ['marker', 'event', 'lockHeld', 'restoreResult'];
  const required = confirm ? allowed : ['marker', 'event', 'lockHeld'];
  const v = readClosed(input, allowed, required, 'transition input');
  if (typeof v.lockHeld !== 'boolean') fail('INCOMPATIBLE_FORMAT', 'lockHeld must be a boolean');
  if (Object.hasOwn(v, 'restoreResult')
      && (typeof v.restoreResult !== 'string' || !C_REST_RESULTS.includes(v.restoreResult))) {
    fail('INCOMPATIBLE_FORMAT', 'restoreResult is not a closed C-REST result');
  }
  if (confirm && typeof v.committed !== 'boolean') {
    fail('INCOMPATIBLE_FORMAT', 'committed must be a boolean');
  }
  const marker = readMarkerInternal(v.marker);
  if (v.lockHeld !== true) return lockRetry(marker.state);
  if (transitionFor(marker.state, event) === null) return forbidden(marker.state);
  if (!Object.hasOwn(v, 'restoreResult')) {
    fail('INCOMPATIBLE_FORMAT', 'restoreResult is required for a reachable transition');
  }
  return decide(marker.state, marker.token, event, v.lockHeld, v.restoreResult,
    v.committed, v.authorityToken);
}

