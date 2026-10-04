// M2 session re-establishment for a browser whose only stored session is legacy.
// (card L-REEST of #317 G-SCOPE; `/marker/newSessionOwner` = `L-REEST` of the ratified C-REC.)
//
// This module is the consent-gated, value-free decision surface of the visible re-establishment
// flow of C-REC §6. It owns new-session creation *sequencing* and the consent surface; it owns no
// encoding (that is `L-MARK`), no physical inventory (that is `L-INV`), no adapter decision (that is
// `I-JOIN`) and no restore classification (that is `I-REST`). It composes their merged public exports
// unchanged:
//
//   L-MARK  styx-js/src/storage/m2/legacy-session-invalidation.js  (applyMarkerTransition, readMarker,
//           encodeMarker, M2_LEGACY_INVALIDATION)
//   L-INV   styx-js/src/storage/m2/legacy-session-inventory.js     (inventoryLegacySessions)
//   I-JOIN  styx-js/src/crypto/mls/m2/adapter.js                   (invokeAdapter, M2_ADAPTER)
//   I-REST  styx-js/src/storage/m2/session-restore.js              (classifyRestore)
//
// C-REC §6, carried verbatim: "`NO_M2_STATE` shows creation without asserting prior absence,
// deletion, freshness or rollback protection. `LEGACY_ONLY` shows visible re-establishment guidance,
// never conversion." "Confirmation requires a distinct post-start authority created by a C-FMT
// COMMITTED operation and later returned by C-REST as `RESTORED_ACTIVE`; EMPTY, reconciliation, failure
// or candidate evidence cannot confirm. Binding uses opaque token equality, never time." "After
// confirmation no reverse transition exists. Repeated marker completion is idempotent." "invalidation
// never deletes, moves, overwrites, compacts or proves erasure of bytes. Cleanup remains deferred."
//
// It never imports, decrypts, translates, copies, selects, decodes as M2 or falls back to legacy; it
// never reads or writes a stored value, opens a store, acquires a lock (the lock is an injected
// boolean), persists a marker or touches the DOM. A state change is returned as fresh marker bytes the
// caller may persist; until `L-MARK` and `L-REEST` are owner-ratified the module is imported by nothing
// and `/marker/realConfirmationBlockedUntilOwnersRatified` stays true.
//
// Totality: every input is untrusted. Members are read from their own property descriptors (no
// accessor is ever invoked); bytes are copied through the `%TypedArray%` internal slot. A non-holder of
// the one-writer lock is told only `LOCKED_ELSEWHERE` / `LOCK_RETRY` and nothing else is read. Every
// failure leaves as a closed `REJECT` record or as `M2ReestablishmentError` with a closed code — never a
// foreign exception.

import {
  M2_LEGACY_INVALIDATION,
  applyMarkerTransition,
  encodeMarker,
  readMarker,
} from '../../../../../src/storage/m2/legacy-session-invalidation.js';
import { inventoryLegacySessions } from '../../../../../src/storage/m2/legacy-session-inventory.js';
import { M2_ADAPTER, invokeAdapter } from '../../../../../src/crypto/mls/m2/adapter.js';
import { classifyRestore } from '../../../../../src/storage/m2/session-restore.js';

const SCHEMA = 'styx-m2-session-reestablishment/v1';

const MARKER = M2_LEGACY_INVALIDATION;
const [ABSENT, PENDING, CONFIRMED, INVALIDATED] = MARKER.STATES;
const [EVENT_START, EVENT_CANCEL, EVENT_CONFIRM, EVENT_COMMIT, EVENT_REPEAT] = MARKER.EVENTS;
/** Offset of the `stateCode:u8` byte in the ratified L-MARK layout `MAGIC || u16be(version) || stateCode || token`. */
const STATE_OFFSET = MARKER.MARKER_MAGIC.length + 2;

/** The eighteen C-REST results, in the C-REC `/restoreResults` order. */
const RESTORE_RESULTS = Object.freeze([
  'NO_M2_STATE', 'LEGACY_ONLY', 'RESTORED_EMPTY', 'RESTORED_ACTIVE', 'RESTORED_RECONCILIATION_REQUIRED',
  'LOCKED_ELSEWHERE', 'WRAPPER_AUTH_FAILED', 'INCOMPATIBLE_BUILD', 'INCOMPATIBLE_FORMAT',
  'UNSUPPORTED_VERSION', 'SELECTOR_INVALID', 'AUTHENTICATION_FAILED', 'MANIFEST_INVALID',
  'RECORD_SET_INCOMPLETE', 'RECORD_INVALID', 'REFERENCE_INCONSISTENT', 'PARTIAL_GENERATION',
  'INTERNAL_VALIDATION_FAILED',
]);

/** The C-REST results the merged L-MARK accepts as `restoreResult` (inventory and success results). */
const MARKER_RESTORE_RESULTS = Object.freeze([
  'NO_M2_STATE', 'LEGACY_ONLY', 'RESTORED_ACTIVE', 'RESTORED_EMPTY', 'RESTORED_RECONCILIATION_REQUIRED',
]);

/**
 * The (result, legacyPresent) pairs absent from C-REC `/reachableConditionRows` (32 rows over the 18
 * results): these four, and no other, reject `UNREACHABLE_CONDITION_PAIR`.
 */
const UNREACHABLE_PAIRS = Object.freeze([
  'NO_M2_STATE:true', 'LEGACY_ONLY:false', 'LOCKED_ELSEWHERE:true', 'INCOMPATIBLE_BUILD:true',
]);

/**
 * The two C-REC `/dispatchRows` this card owns, transcribed verbatim, plus the one `legacyPresent`
 * value C-REC `/reachableConditionRows` pairs with each of them.
 */
const OWNED_DISPATCH_ROWS = Object.freeze({
  NO_M2_STATE: Object.freeze({
    result: 'NO_M2_STATE', disposition: 'SHOW_CREATE', authority: 'NONE', resetEligible: false,
    legacyCondition: 'UNAVAILABLE', byteAction: 'PRESERVE', legacyPresent: false,
  }),
  LEGACY_ONLY: Object.freeze({
    result: 'LEGACY_ONLY', disposition: 'SHOW_REESTABLISHMENT', authority: 'NONE', resetEligible: false,
    legacyCondition: 'REQUIRED', byteAction: 'PRESERVE', legacyPresent: true,
  }),
});

/**
 * User-visible wording (it-IT, the app's language). C-REC §9: the wording distinguishes new-session
 * re-establishment from restored authority, compatible-build handoff and destructive reset. Neither text
 * offers or claims conversion, import, recovery of the old session, deletion, prior absence, freshness
 * or rollback protection.
 */
const COPY = Object.freeze({
  SHOW_REESTABLISHMENT: Object.freeze({
    title: 'Nuova sessione su questo browser',
    body: 'Su questo browser è presente soltanto una sessione di un formato precedente. '
      + 'Quella sessione resta intatta su questo dispositivo e non viene letta né trasferita. '
      + 'Puoi avviare una nuova sessione: i contatti andranno abbinati di nuovo.',
    accept: 'Avvia una nuova sessione',
    decline: 'Non ora',
  }),
  SHOW_CREATE: Object.freeze({
    title: 'Crea una sessione',
    body: 'Su questo browser non è stata trovata una sessione utilizzabile. Puoi crearne una nuova.',
    accept: 'Crea una sessione',
    decline: 'Non ora',
  }),
});

const STEPS = Object.freeze(['START', 'CANCEL', 'CREATE_SESSION', 'CONFIRM', 'COMPLETE']);
const DISPOSITIONS = Object.freeze(['MARKER_TRANSITION', 'SESSION_OPERATION', 'LOCK_RETRY', 'REJECT']);
const REJECT_CODES = Object.freeze([
  // L-MARK's closed decision codes, passed through unchanged.
  'MARKER_TRANSITION_FORBIDDEN', 'TOKEN_MISMATCH', 'CONFIRMATION_PRECONDITION_FAILED',
  'RESTORE_PRECONDITION_FAILED', 'LOCKED_ELSEWHERE',
  // This card's own gates.
  'CONSENT_REQUIRED', 'RESTORE_EVIDENCE_INCONSISTENT', 'MARKER_NOT_PENDING',
]);
const PHASES = Object.freeze(['NONE', 'LOCK', 'CONSENT_GATE', 'RESTORE_GATE', 'MARKER_GATE']);
const GUIDANCE_DISPOSITIONS = Object.freeze(['SHOW_CREATE', 'SHOW_REESTABLISHMENT', 'REJECT']);
const GUIDANCE_REJECT_CODES = Object.freeze([
  'MISSING_DISPATCH_INPUT', 'UNKNOWN_RESULT', 'NOT_REESTABLISHMENT_RESULT', 'UNREACHABLE_CONDITION_PAIR',
]);
const RESUME = Object.freeze({
  [ABSENT]: 'GUIDANCE', [PENDING]: 'CONFIRM_OR_CANCEL', [CONFIRMED]: 'MARKER_COMPLETION_ONLY', [INVALIDATED]: 'NONE',
});
/** C-REC `ACTION` fixtures this card refuses, with their ratified reject codes. */
const LEGACY_ACTION_REJECTS = Object.freeze({
  LEGACY_FALLBACK: 'LEGACY_FALLBACK_FORBIDDEN',
  LEGACY_IMPORT: 'LEGACY_IMPORT_FORBIDDEN',
  DELETE_LEGACY: 'CLEANUP_DEFERRED',
});
const ERROR_CODES = Object.freeze(['INVALID_INPUT', 'MARKER_INVALID', 'INVENTORY_INVALID']);
/** C-REC `/diagnostics/allowed`, verbatim: the only members a diagnostics record may carry. */
const DIAGNOSTIC_FIELDS = Object.freeze([
  'restoreResult', 'condition', 'recoveryDisposition', 'stageCode', 'reasonCode', 'boundedCount',
]);
/** The closed consent record: the user saw exactly this guidance and accepted it. */
const CONSENT_PROMPT = 'SHOW_REESTABLISHMENT';
const SESSION_OPERATIONS = Object.freeze(['CREATE', 'JOIN_WELCOME']);
const SESSION_SUCCESS = Object.freeze({ CREATE: 'CREATED', JOIN_WELCOME: 'JOINED' });

export const M2_REESTABLISHMENT = Object.freeze({
  SCHEMA,
  OWNER: 'L-REEST',
  ENCODING_OWNER: MARKER.ENCODING_OWNER,
  PHYSICAL_INVENTORY_OWNER: 'L-INV',
  STEPS,
  DISPOSITIONS,
  REJECT_CODES,
  PHASES,
  GUIDANCE_DISPOSITIONS,
  GUIDANCE_REJECT_CODES,
  OWNED_DISPATCH_ROWS,
  RESTORE_RESULTS,
  COPY,
  CONSENT_PROMPT,
  SESSION_OPERATIONS,
  RESUME,
  LEGACY_ACTION_REJECTS,
  ERROR_CODES,
  DIAGNOSTIC_FIELDS,
  VISIBLE_CONSENT_REQUIRED: true,
  BINDING: MARKER.BINDING,
  TIME_OR_FRESHNESS_COMPARISON: false,
  REVERSE_AFTER_CONFIRMATION: false,
  REAL_CONFIRMATION_BLOCKED_UNTIL_OWNERS_RATIFIED: true,
  PERSISTS_MARKER: false,
  IMPORT: false,
  DECRYPT: false,
  TRANSLATE: false,
  COPY_LEGACY: false,
  SELECT_LEGACY: false,
  DECODE_LEGACY_AS_M2: false,
  FALLBACK: false,
  PRESERVE_BYTES: true,
  CLEANUP: 'DEFERRED',
});

export class M2ReestablishmentError extends Error {
  constructor(code) {
    super(`M2 re-establishment input rejected: ${ERROR_CODES.includes(code) ? code : 'INVALID_INPUT'}`);
    this.name = 'M2ReestablishmentError';
    this.code = ERROR_CODES.includes(code) ? code : 'INVALID_INPUT';
  }
}

const fail = (code) => { throw new M2ReestablishmentError(code); };

// ------------------------------------------------------------------------------------------------
// Untrusted-input helpers.
// ------------------------------------------------------------------------------------------------

const TYPED_ARRAY_PROTO = Object.getPrototypeOf(Uint8Array.prototype);
const TYPED_ARRAY_TAG = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTO, Symbol.toStringTag).get;
const TYPED_ARRAY_LENGTH = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTO, 'length').get;

function isPlainObject(value) {
  try {
    return value !== null && typeof value === 'object' && !Array.isArray(value)
      && !ArrayBuffer.isView(value) && Object.getPrototypeOf(value) === Object.prototype;
  } catch {
    return false;
  }
}

/**
 * Read exactly `members` (all required) from a plain object without invoking an accessor. Any other
 * own key, a symbol key, a missing member or an accessor member is `INVALID_INPUT`.
 */
function readClosed(value, members) {
  if (!isPlainObject(value)) fail('INVALID_INPUT');
  let own = null;
  try {
    own = Reflect.ownKeys(value);
  } catch {
    own = null;
  }
  if (own === null) fail('INVALID_INPUT');
  if (own.length !== members.length || own.some((k) => typeof k !== 'string' || !members.includes(k))) {
    fail('INVALID_INPUT');
  }
  const out = {};
  for (const key of members) {
    let d;
    try {
      d = Object.getOwnPropertyDescriptor(value, key);
    } catch {
      d = undefined;
    }
    if (!d || !d.enumerable || !Object.hasOwn(d, 'value')) fail('INVALID_INPUT');
    out[key] = d.value;
  }
  return out;
}

/** One own data member, or `undefined` for a missing or accessor member; never invokes a getter. */
function dataMember(record, key) {
  if (!isPlainObject(record)) return undefined;
  let d;
  try {
    d = Object.getOwnPropertyDescriptor(record, key);
  } catch {
    return undefined;
  }
  if (!d || !d.enumerable || !Object.hasOwn(d, 'value')) return undefined;
  return d.value;
}

/** A fresh copy of a `Uint8Array` through the internal slot, or `null`. Never aliases caller memory. */
function snapshotBytes(value) {
  try {
    if (!ArrayBuffer.isView(value) || TYPED_ARRAY_TAG.call(value) !== 'Uint8Array') return null;
    const copy = new Uint8Array(TYPED_ARRAY_LENGTH.call(value));
    Uint8Array.prototype.set.call(copy, value);
    return copy;
  } catch {
    return null;
  }
}

/** Bounds of the passive snapshot of a caller-supplied adapter input (depth and members per level). */
const SNAPSHOT_MAX_DEPTH = 6;
const SNAPSHOT_MAX_MEMBERS = 64;
const SNAPSHOT_REFUSED = Symbol('refused');

/**
 * A passive, frozen deep copy of a caller-supplied adapter input, or `SNAPSHOT_REFUSED`.
 *
 * Only plain objects, plain arrays, `Uint8Array`s (copied through the internal slot) and primitives
 * are copied. Every member is read through its own data descriptor and every array element by index
 * through its own data descriptor: no getter, no `Symbol.iterator`, no `toJSON` and no species is ever
 * invoked, so the copy cannot change between two readers. A symbol key, an accessor, a hole, a
 * non-enumerable member, a function or any other object kind refuses the whole input. The same frozen
 * copy is handed to every merged reader, so the merged adapter and the merged classifier see identical
 * values.
 */
function passiveSnapshot(value, depth = 0) {
  if (value === null || typeof value !== 'object') {
    return typeof value === 'function' || typeof value === 'symbol' ? SNAPSHOT_REFUSED : value;
  }
  if (depth >= SNAPSHOT_MAX_DEPTH) return SNAPSHOT_REFUSED;
  if (ArrayBuffer.isView(value)) {
    const bytes = snapshotBytes(value);
    return bytes === null ? SNAPSHOT_REFUSED : bytes;
  }
  let isArray;
  let proto;
  let own;
  try {
    isArray = Array.isArray(value);
    proto = Object.getPrototypeOf(value);
    own = Reflect.ownKeys(value);
  } catch {
    return SNAPSHOT_REFUSED;
  }
  if (isArray ? proto !== Array.prototype : proto !== Object.prototype) return SNAPSHOT_REFUSED;
  if (own.length > SNAPSHOT_MAX_MEMBERS + (isArray ? 1 : 0)) return SNAPSHOT_REFUSED;
  const descriptors = new Map();
  for (const key of own) {
    if (typeof key !== 'string') return SNAPSHOT_REFUSED;
    let d;
    try {
      d = Object.getOwnPropertyDescriptor(value, key);
    } catch {
      return SNAPSHOT_REFUSED;
    }
    if (d === undefined || !Object.hasOwn(d, 'value')) return SNAPSHOT_REFUSED;
    descriptors.set(key, d);
  }
  if (isArray) {
    const lengthD = descriptors.get('length');
    if (lengthD === undefined || typeof lengthD.value !== 'number') return SNAPSHOT_REFUSED;
    const length = lengthD.value;
    if (own.length !== length + 1) return SNAPSHOT_REFUSED;
    const out = [];
    for (let i = 0; i < length; i += 1) {
      const d = descriptors.get(String(i));
      if (d === undefined || !d.enumerable) return SNAPSHOT_REFUSED;
      const v = passiveSnapshot(d.value, depth + 1);
      if (v === SNAPSHOT_REFUSED) return SNAPSHOT_REFUSED;
      out.push(v);
    }
    return Object.freeze(out);
  }
  const out = {};
  for (const [key, d] of descriptors) {
    if (!d.enumerable) return SNAPSHOT_REFUSED;
    const v = passiveSnapshot(d.value, depth + 1);
    if (v === SNAPSHOT_REFUSED) return SNAPSHOT_REFUSED;
    // Define, never assign: an own `__proto__` member stays an own data member (r2 DeepSeek LOW-3).
    Object.defineProperty(out, key, { value: v, enumerable: true, writable: true, configurable: true });
  }
  return Object.freeze(out);
}

// ------------------------------------------------------------------------------------------------
// Records.
// ------------------------------------------------------------------------------------------------

function diagnostics({ restoreResult = null, condition = null, recoveryDisposition = null, stageCode = null,
  reasonCode = null, boundedCount = null }) {
  return Object.freeze({ restoreResult, condition, recoveryDisposition, stageCode, reasonCode, boundedCount });
}

function stepRecord(step, fields) {
  const record = {
    step,
    disposition: fields.disposition,
    accepted: fields.accepted,
    stateBefore: fields.stateBefore ?? null,
    stateAfter: fields.stateAfter ?? null,
    legacyEligible: fields.stateAfter == null ? null : MARKER.LEGACY_ELIGIBLE_BY_STATE[fields.stateAfter],
    reject: fields.reject ?? null,
    firstFailingPhase: fields.firstFailingPhase,
    committed: fields.committed ?? null,
    adapterResult: fields.adapterResult ?? null,
    marker: fields.marker ?? null,
    diagnostics: diagnostics({
      restoreResult: fields.restoreResult ?? null,
      condition: fields.condition ?? null,
      recoveryDisposition: fields.disposition,
      stageCode: fields.firstFailingPhase,
      reasonCode: fields.reject ?? 'NONE',
    }),
  };
  return Object.freeze(record);
}

/** C-REC §8: a non-holder receives only `LOCKED_ELSEWHERE` / `LOCK_RETRY`; nothing else is read. */
function lockRetry(step) {
  // The merged L-MARK lock gate runs before any decode; asking it keeps the two records identical.
  const decision = applyMarkerTransition({ lockHeld: false });
  return stepRecord(step, {
    disposition: decision.disposition,
    accepted: false,
    reject: decision.reject,
    firstFailingPhase: decision.firstFailingPhase,
  });
}

/** Read `lockHeld` first. Returns `true` when held; throws `INVALID_INPUT` when it is not a boolean. */
function lockHeldOf(input) {
  if (!isPlainObject(input)) fail('INVALID_INPUT');
  const lockHeld = dataMember(input, 'lockHeld');
  if (typeof lockHeld !== 'boolean') fail('INVALID_INPUT');
  return lockHeld;
}

/** Snapshot and decode a marker through the merged L-MARK reader. */
function markerOf(value) {
  const bytes = snapshotBytes(value);
  if (bytes === null) fail('MARKER_INVALID');
  let state;
  try {
    ({ state } = readMarker(bytes));
  } catch {
    fail('MARKER_INVALID');
  }
  return { bytes, state };
}

/** Whether a consent record is exactly the visible acceptance of the re-establishment guidance. */
function consentGiven(consent) {
  if (!isPlainObject(consent)) return false;
  let own;
  try {
    own = Reflect.ownKeys(consent);
  } catch {
    return false;
  }
  if (own.length !== 2) return false;
  return dataMember(consent, 'prompt') === CONSENT_PROMPT && dataMember(consent, 'accepted') === true;
}

/** One closed C-API result's code: the success code, or the error code. `null` when malformed. */
function resultCode(result) {
  const kind = dataMember(result, 'kind');
  if (kind === 'SUCCESS' || kind === 'NO_CHANGE') return dataMember(result, 'successCode') ?? null;
  if (kind === 'REJECTED') return dataMember(dataMember(result, 'error'), 'code') ?? null;
  return null;
}

/**
 * Run one restore through the merged adapter and the merged C-REST classifier and require that they
 * agree. Both read the same passive frozen snapshot of the caller's input (`passiveSnapshot`), so no
 * caller code runs and the two readers cannot be shown different evidence. Returns
 * `{ restoreResult, condition, adapterResult }`, or `{ inconsistent: true }`.
 */
function restoreEvidence(restore) {
  const snapshot = passiveSnapshot(restore);
  if (snapshot === SNAPSHOT_REFUSED || !isPlainObject(snapshot)) fail('INVALID_INPUT');
  const request = dataMember(snapshot, 'request');
  if (dataMember(request, 'operation') !== 'RESTORE') fail('INVALID_INPUT');
  let adapterResult;
  try {
    adapterResult = invokeAdapter(snapshot);
  } catch {
    fail('INVALID_INPUT');
  }
  const observation = dataMember(dataMember(snapshot, 'observation'), 'restoreObservation');
  let classified = null;
  try {
    classified = classifyRestore(observation);
  } catch {
    classified = null;
  }
  const restoreResult = classified === null ? null : classified.result;
  if (!RESTORE_RESULTS.includes(restoreResult)
      || M2_ADAPTER.RESTORE_DISPOSITIONS[restoreResult] !== resultCode(adapterResult)) {
    return { inconsistent: true, restoreResult: null, condition: null, adapterResult };
  }
  return { inconsistent: false, restoreResult, condition: classified.condition ?? null, adapterResult };
}

/** The fresh marker bytes after an accepted transition. Never aliases the caller's bytes. */
function nextMarker(bytes, stateAfter, startToken) {
  let out;
  try {
    if (stateAfter === ABSENT) {
      out = encodeMarker({ state: ABSENT, bindingToken: new Uint8Array(MARKER.BINDING_TOKEN_BYTES) });
    } else if (startToken !== null) {
      out = encodeMarker({ state: stateAfter, bindingToken: startToken });
    } else {
      // The stored start token is kept byte-for-byte; only the ratified state byte changes.
      out = new Uint8Array(bytes);
      out[STATE_OFFSET] = MARKER.STATE_CODES[stateAfter];
    }
    if (readMarker(out).state !== stateAfter) out = null;
  } catch {
    // An L-MARK refusal (`M2LegacyInvalidationError`) or anything else: no marker bytes are produced.
    out = null;
  }
  if (out === null) fail('MARKER_INVALID');
  return out;
}

/** Apply one L-MARK event after this card's own gates passed. */
function markerStep(step, marker, event, evidence, extra, startToken) {
  const input = { marker: marker.bytes, event, lockHeld: true, restoreResult: evidence.restoreResult, ...extra };
  let decision;
  try {
    decision = applyMarkerTransition(input);
  } catch {
    fail('MARKER_INVALID');
  }
  const accepted = decision.accepted === true;
  return stepRecord(step, {
    disposition: decision.disposition,
    accepted,
    stateBefore: decision.stateBefore,
    stateAfter: decision.stateAfter,
    reject: decision.reject,
    firstFailingPhase: decision.firstFailingPhase,
    committed: Object.hasOwn(extra, 'committed') ? extra.committed : null,
    marker: accepted ? nextMarker(marker.bytes, decision.stateAfter, startToken) : null,
    restoreResult: evidence.restoreResult,
    condition: evidence.condition,
  });
}

function gateReject(step, marker, reject, phase, evidence = {}) {
  return stepRecord(step, {
    disposition: 'REJECT',
    accepted: false,
    stateBefore: marker.state,
    stateAfter: marker.state,
    reject,
    firstFailingPhase: phase,
    restoreResult: evidence.restoreResult ?? null,
    condition: evidence.condition ?? null,
  });
}

/**
 * The restore gate: the two evidence sources must agree, and the C-REST result must be one the marker
 * can consume at all. A failure result never reaches the marker; it cannot confirm or start anything.
 */
function restoreGate(step, marker, evidence, failureCode) {
  if (evidence.inconsistent) return gateReject(step, marker, 'RESTORE_EVIDENCE_INCONSISTENT', 'RESTORE_GATE');
  if (!MARKER_RESTORE_RESULTS.includes(evidence.restoreResult)) {
    return gateReject(step, marker, failureCode, 'RESTORE_GATE', evidence);
  }
  return null;
}

// ------------------------------------------------------------------------------------------------
// Public surface.
// ------------------------------------------------------------------------------------------------

/**
 * C-REC dispatch for the two inventory results this card owns. `input` is exactly the C-REC
 * `DISPATCH` fixture input `{ result, legacyPresent }`. Returns one frozen record; never throws.
 */
export function guidanceFor(input) {
  let own = null;
  try {
    own = isPlainObject(input) ? Reflect.ownKeys(input) : null;
  } catch {
    own = null;
  }
  const closed = own !== null && own.length === 2 && own.every((k) => k === 'result' || k === 'legacyPresent');
  const result = closed ? dataMember(input, 'result') : undefined;
  const legacyPresent = closed ? dataMember(input, 'legacyPresent') : undefined;
  const reject = (code) => Object.freeze({
    disposition: 'REJECT',
    authority: 'NONE',
    resetEligible: false,
    byteAction: 'PRESERVE',
    markerState: 'UNCHANGED',
    reject: code,
    firstFailingPhase: 'C_REST_CLASSIFIED',
    consentRequired: false,
    copy: null,
    diagnostics: diagnostics({
      restoreResult: typeof result === 'string' && RESTORE_RESULTS.includes(result) ? result : null,
      recoveryDisposition: 'REJECT', stageCode: 'C_REST_CLASSIFIED', reasonCode: code,
    }),
  });
  if (typeof result !== 'string' || typeof legacyPresent !== 'boolean') return reject('MISSING_DISPATCH_INPUT');
  if (!RESTORE_RESULTS.includes(result)) return reject('UNKNOWN_RESULT');
  // C-REC /reachableConditionRows: these four (result, legacyPresent) pairs are unreachable; the
  // pair check precedes the owned-row check (C-REC NEG-NO-M2-LEGACY, NEG-LOCKED-LEGACY, NEG-BUILD-LEGACY).
  if (UNREACHABLE_PAIRS.includes(`${result}:${legacyPresent}`)) return reject('UNREACHABLE_CONDITION_PAIR');
  const row = Object.hasOwn(OWNED_DISPATCH_ROWS, result) ? OWNED_DISPATCH_ROWS[result] : null;
  if (row === null) return reject('NOT_REESTABLISHMENT_RESULT');
  if (legacyPresent !== row.legacyPresent) return reject('UNREACHABLE_CONDITION_PAIR');
  return Object.freeze({
    disposition: row.disposition,
    authority: row.authority,
    resetEligible: row.resetEligible,
    byteAction: row.byteAction,
    markerState: 'UNCHANGED',
    reject: null,
    firstFailingPhase: 'NONE',
    consentRequired: row.disposition === CONSENT_PROMPT,
    copy: COPY[row.disposition],
    diagnostics: diagnostics({
      restoreResult: result,
      condition: legacyPresent ? 'LEGACY_PRESENT' : null,
      recoveryDisposition: row.disposition,
      stageCode: 'NONE',
      reasonCode: 'NONE',
    }),
  });
}

/**
 * The abstract C-REC `/legacy/input` of an already-enumerated key space, through the merged L-INV
 * inventory: `{ legacyPresent, boundedCount }`, value-free. No key, byte or locator is returned.
 */
export function legacyPresenceOf(keys) {
  let inventory;
  try {
    inventory = inventoryLegacySessions({ keys });
  } catch {
    fail('INVENTORY_INVALID');
  }
  return Object.freeze({ legacyPresent: inventory.legacyPresent, boundedCount: inventory.legacyCount });
}

/**
 * Crash-resume view of a persisted marker (C-REC `MARKER-CRASH-*` boundaries). Read-only: it changes no
 * state and needs no lock. Returns `{ markerState, legacyEligibility, legacyAuthority, resume }`.
 */
export function resumeFor(marker) {
  const { state } = markerOf(marker);
  const legacyEligibility = MARKER.LEGACY_ELIGIBLE_BY_STATE[state];
  return Object.freeze({
    markerState: state,
    legacyEligibility,
    legacyAuthority: legacyEligibility ? 'UNCHANGED' : 'INELIGIBLE',
    resume: RESUME[state],
  });
}

/** The ratified refusal of a legacy action (C-REC `ACTION` fixtures `NEG-FALLBACK`, `NEG-IMPORT`, `NEG-CLEANUP`). */
export function legacyActionDecision(input) {
  const { action } = readClosed(input, ['action']);
  if (typeof action !== 'string' || !Object.hasOwn(LEGACY_ACTION_REJECTS, action)) fail('INVALID_INPUT');
  return Object.freeze({
    disposition: 'REJECT',
    reject: LEGACY_ACTION_REJECTS[action],
    firstFailingPhase: 'ACTION_GATE',
    authorityIdentity: 'UNCHANGED',
    markerState: 'UNCHANGED',
  });
}

/**
 * `START`: the user saw the `SHOW_REESTABLISHMENT` guidance and accepted it. `input` is exactly
 * `{ lockHeld, marker, consent, restore, startToken }`; `restore` is the closed adapter input of one
 * `RESTORE` (`{ request, snapshot, observation }`) and `startToken` is the fresh opaque 32-byte
 * start-authority token the caller generated. Precedence: lock, input, consent, restore evidence, then
 * the merged L-MARK gates.
 */
export function startReestablishment(input) {
  if (!lockHeldOf(input)) return lockRetry('START');
  const v = readClosed(input, ['lockHeld', 'marker', 'consent', 'restore', 'startToken']);
  if (v.lockHeld !== true) return lockRetry('START');
  const marker = markerOf(v.marker);
  const startToken = snapshotBytes(v.startToken);
  if (startToken === null || startToken.length !== MARKER.BINDING_TOKEN_BYTES || startToken.every((b) => b === 0)) {
    fail('INVALID_INPUT');
  }
  if (!consentGiven(v.consent)) return gateReject('START', marker, 'CONSENT_REQUIRED', 'CONSENT_GATE');
  const evidence = restoreEvidence(v.restore);
  const refused = restoreGate('START', marker, evidence, 'RESTORE_PRECONDITION_FAILED');
  if (refused) return refused;
  return markerStep('START', marker, EVENT_START, evidence, {}, startToken);
}

/** `CANCEL` before confirmation. `input` is exactly `{ lockHeld, marker, restore }`. Preserves every byte. */
export function cancelReestablishment(input) {
  if (!lockHeldOf(input)) return lockRetry('CANCEL');
  const v = readClosed(input, ['lockHeld', 'marker', 'restore']);
  if (v.lockHeld !== true) return lockRetry('CANCEL');
  const marker = markerOf(v.marker);
  const evidence = restoreEvidence(v.restore);
  const refused = restoreGate('CANCEL', marker, evidence, 'RESTORE_PRECONDITION_FAILED');
  if (refused) return refused;
  return markerStep('CANCEL', marker, EVENT_CANCEL, evidence, {}, null);
}

/**
 * The distinct post-start authority: one consented `CREATE` (or `JOIN_WELCOME`) through the merged
 * adapter, allowed only while the marker is `PENDING_NEW_SESSION`. `input` is exactly
 * `{ lockHeld, marker, consent, operation }`, `operation` being the closed adapter input. The marker is
 * not changed; `committed` is true only for a `SUCCESS` with `commitOutcome` `COMMITTED`.
 */
export function createNewSession(input) {
  if (!lockHeldOf(input)) return lockRetry('CREATE_SESSION');
  const v = readClosed(input, ['lockHeld', 'marker', 'consent', 'operation']);
  if (v.lockHeld !== true) return lockRetry('CREATE_SESSION');
  const marker = markerOf(v.marker);
  if (!consentGiven(v.consent)) return gateReject('CREATE_SESSION', marker, 'CONSENT_REQUIRED', 'CONSENT_GATE');
  if (marker.state !== PENDING) return gateReject('CREATE_SESSION', marker, 'MARKER_NOT_PENDING', 'MARKER_GATE');
  const snapshot = passiveSnapshot(v.operation);
  if (snapshot === SNAPSHOT_REFUSED) fail('INVALID_INPUT');
  const operation = dataMember(dataMember(snapshot, 'request'), 'operation');
  if (!SESSION_OPERATIONS.includes(operation)) fail('INVALID_INPUT');
  let adapterResult;
  try {
    adapterResult = invokeAdapter(snapshot);
  } catch {
    fail('INVALID_INPUT');
  }
  const committed = isCommittedSession(adapterResult);
  return stepRecord('CREATE_SESSION', {
    disposition: 'SESSION_OPERATION',
    accepted: committed,
    stateBefore: marker.state,
    stateAfter: marker.state,
    firstFailingPhase: 'NONE',
    committed,
    adapterResult,
  });
}

/**
 * The exact own-key set of a committed new-session C-API result (`/response/commonRequired`, then
 * `successCode`, `commitOutcome`, and the `/response/outputBySuccessCode` member when there is one).
 */
const COMMITTED_SESSION_KEYS = Object.freeze({
  CREATE: Object.freeze(['api', 'requestId', 'operation', 'kind', 'stateBefore', 'stateAfter', 'successCode',
    'commitOutcome', 'output']),
  JOIN_WELCOME: Object.freeze(['api', 'requestId', 'operation', 'kind', 'stateBefore', 'stateAfter', 'successCode',
    'commitOutcome']),
});

/**
 * A C-FMT `COMMITTED` new-session result of the merged adapter, read without invoking an accessor.
 *
 * The whole closed record is checked, not only the four deciding members: a plain object with exactly
 * the C-API key set of the operation, `api` the adapter's, a non-empty `requestId`, `kind` `SUCCESS`, the
 * operation's success code, `commitOutcome` `COMMITTED`, the session transition `EMPTY` -> `ACTIVE`,
 * and for `CREATE` an `output` that is exactly `{ embeddedTreeWelcome }` with non-empty bytes.
 */
function isCommittedSession(result) {
  const operation = dataMember(result, 'operation');
  if (!SESSION_OPERATIONS.includes(operation)) return false;
  const keys = COMMITTED_SESSION_KEYS[operation];
  let own;
  try {
    own = Reflect.ownKeys(result);
  } catch {
    return false;
  }
  if (own.length !== keys.length || !own.every((k) => typeof k === 'string' && keys.includes(k))) return false;
  const requestId = dataMember(result, 'requestId');
  if (dataMember(result, 'api') !== M2_ADAPTER.API
      || typeof requestId !== 'string' || requestId.length === 0
      || dataMember(result, 'kind') !== 'SUCCESS'
      || dataMember(result, 'successCode') !== SESSION_SUCCESS[operation]
      || dataMember(result, 'commitOutcome') !== 'COMMITTED'
      || dataMember(result, 'stateBefore') !== 'EMPTY'
      || dataMember(result, 'stateAfter') !== 'ACTIVE') {
    return false;
  }
  if (operation !== 'CREATE') return true;
  const output = dataMember(result, 'output');
  let outputKeys;
  try {
    outputKeys = isPlainObject(output) ? Reflect.ownKeys(output) : null;
  } catch {
    outputKeys = null;
  }
  if (outputKeys === null || outputKeys.length !== 1 || outputKeys[0] !== 'embeddedTreeWelcome') return false;
  const welcome = snapshotBytes(dataMember(output, 'embeddedTreeWelcome'));
  return welcome !== null && welcome.length > 0;
}

/**
 * `CONFIRM`: the committed post-start session was later restored as `RESTORED_ACTIVE`, and the presented
 * opaque token is the marker's own start token. `input` is exactly
 * `{ lockHeld, marker, createResult, authorityToken, restore }`; `createResult` is the adapter result of
 * `createNewSession`. Legacy eligibility becomes false.
 */
export function confirmReestablishment(input) {
  if (!lockHeldOf(input)) return lockRetry('CONFIRM');
  const v = readClosed(input, ['lockHeld', 'marker', 'createResult', 'authorityToken', 'restore']);
  if (v.lockHeld !== true) return lockRetry('CONFIRM');
  const marker = markerOf(v.marker);
  const evidence = restoreEvidence(v.restore);
  const refused = restoreGate('CONFIRM', marker, evidence, 'CONFIRMATION_PRECONDITION_FAILED');
  if (refused) return refused;
  const extra = { committed: isCommittedSession(v.createResult), authorityToken: v.authorityToken };
  return markerStep('CONFIRM', marker, EVENT_CONFIRM, evidence, extra, null);
}

/**
 * Marker completion: `COMMIT_MARKER` from `NEW_SESSION_CONFIRMED`, the idempotent `REPEAT_COMPLETION`
 * from `LEGACY_INVALIDATED`; any other state is refused by the merged L-MARK table. `input` is exactly
 * `{ lockHeld, marker, restore }`.
 */
export function completeReestablishment(input) {
  if (!lockHeldOf(input)) return lockRetry('COMPLETE');
  const v = readClosed(input, ['lockHeld', 'marker', 'restore']);
  if (v.lockHeld !== true) return lockRetry('COMPLETE');
  const marker = markerOf(v.marker);
  const evidence = restoreEvidence(v.restore);
  const refused = restoreGate('COMPLETE', marker, evidence, 'RESTORE_PRECONDITION_FAILED');
  if (refused) return refused;
  const event = marker.state === INVALIDATED ? EVENT_REPEAT : EVENT_COMMIT;
  return markerStep('COMPLETE', marker, event, evidence, {}, null);
}
