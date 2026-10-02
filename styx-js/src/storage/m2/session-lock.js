// session-lock.js — one-worker/one-writer Web Lock policy for the M2 browser profile
// (card I-LOCK of #317 G-SCOPE; see the card contract Issue for this repository).
//
// The M2 adapter is invoked only from the single context that owns the dedicated M2
// worker. The C-API `singleWriter` rule places that exclusion *outside* the adapter:
// "I-LOCK prevents a second active context before it invokes this API;
// session-active-elsewhere is therefore an outer UI/controller result, not an adapter
// result". This module is that outer policy expressed as a closed, side-effect-free
// decision core. It decides, from observed lock facts alone, whether a context may act,
// and it yields the exact second-tab outcomes: exactly one context may be ACTIVE and
// every other context is SESSION_ACTIVE_ELSEWHERE.
//
// It is a pure data-only module: no imports, no effects, no `navigator.locks`, no
// `Worker`, no `postMessage`, no storage, no clock and no randomness. It acquires
// nothing and reads nothing; it only classifies an observation that the caller makes.
// Whether a real browser Web Lock exists, is exclusive, survives a crash or is
// reachable from a second tab is NOT claimed here and cannot be claimed by a Node test.
//
// Ratified inputs copied verbatim (see the contract Issue this card published; SHAs are
// re-checked against the ratified bytes before publication, never re-derived here):
//   C-API   docs/architecture/m2/adapter-contract.md  sha256 b77d39fb…05ad9 (#319 5886838783)
//           /rules/singleWriter — the second-active-context rule transcribed above.
//   C-MUT   docs/architecture/m2/mutation-table.md    sha256 6c2c045c…eb3060 (#324 5890545934)
//           "The D13/C-API `singleWriter` precondition is one worker and one writer per
//           browser profile, enforced outside the adapter by I-LOCK."
//   C-REC   docs/architecture/m2/recovery-and-coexistence.md  sha256 5b0d2fbd…94f87 (#335 5909885218)
//           §8, /precedence, /faultPhaseOrder, /faultPrecedence, /restoreResults,
//           /dispositionEnum, /fixtures (NEG-NO-LOCK), /marker/transitions.
//   C-REST  docs/architecture/m2/restore-compatibility.md (reached through O-SCEN)
//           /phaseRules/0 — phase LOCK: "Acquire the one-writer Web Lock; read no M2 or
//           legacy bytes before success."  /prose/19 — "Before reading any stored M2 or
//           legacy byte, the one-writer Web Lock MUST be held and one complete
//           `buildMatrix` row MUST match."
//   O-SCEN  docs/architecture/m2/scenarios/clause-scenarios.md sha256 6c19a01c…4d37ae (#337 5912195865)
//           the blind scenario set whose lock clauses are transcribed in LOCK_SCENARIOS.
//   SCOPE-M2 (owner proposal ratified into D13/D7): "one worker and one writer per
//           browser profile under Web Lock; second tab is read-disabled/session-active
//           elsewhere; mutations serialized internally"; "lock terminates or wipes the
//           owning worker according to the ratified lifecycle; fresh worker starts locked
//           and must reauthenticate before restore".

/** Freeze a value tree in place (descriptors only; typed arrays are left alone). */
function freezeData(value) {
  if (value === null || typeof value !== 'object') return value;
  if (ArrayBuffer.isView(value)) return value;
  for (const descriptor of Object.values(Object.getOwnPropertyDescriptors(value))) {
    if (Object.hasOwn(descriptor, 'value')) freezeData(descriptor.value);
  }
  return Object.freeze(value);
}

// ---------------------------------------------------------------------------------------------
// Closed sets, transcribed from the ratified bytes.
// ---------------------------------------------------------------------------------------------

/**
 * C-REC `/faultPhaseOrder[0]` — the LOCK phase precedes every other recovery phase.
 * A lock fault can therefore never be shadowed by a later, more specific fault.
 */
export const LOCK_PHASE = 'LOCK';

/** C-REC `/faultPrecedence[0]` — the closed LOCK-phase fault name. */
export const LOCK_FAULTS = Object.freeze(['lockUnavailable']);

/** C-REC `/faultPrecedence[0].result` — the only result a LOCK-phase fault produces. */
export const LOCK_RESULTS = Object.freeze(['LOCKED_ELSEWHERE']);

/** C-REC `/dispositionEnum[7]` and `/precedence/lockedDisposition` — the locked disposition. */
export const LOCK_DISPOSITIONS = Object.freeze(['LOCK_RETRY']);

/**
 * C-API `/rules/singleWriter` names the second-tab outcome and places it outside the
 * adapter: "session-active-elsewhere is therefore an outer UI/controller result, not an
 * adapter result". SCOPE-M2 D13 restates it as "read-disabled/session-active elsewhere".
 */
export const OUTER_RESULTS = Object.freeze(['SESSION_ACTIVE_ELSEWHERE']);

/** The C-API term exactly as ratified, in its ratified spelling. */
export const SESSION_ACTIVE_ELSEWHERE = 'SESSION_ACTIVE_ELSEWHERE';

/** C-MUT D13 precondition — one worker and one writer per browser profile. */
export const CONTEXT_ROLES = Object.freeze(['WORKER', 'WRITER']);

/** The two closed second-tab outcomes this card must yield exactly. */
export const CONTEXT_OUTCOMES = Object.freeze(['ACTIVE', SESSION_ACTIVE_ELSEWHERE]);

/**
 * The closed observation of lock ownership, from the point of view of one context.
 *  - HELD_BY_SELF   — this context holds the one Web Lock.
 *  - HELD_BY_OTHER  — another context holds it (second tab: session active elsewhere).
 *  - FREE           — no context holds it; acquisition is still required before any read.
 *  - UNAVAILABLE    — the lock could not be observed/acquired (C-REC `lockUnavailable`).
 */
export const OWNERSHIP = Object.freeze(['HELD_BY_SELF', 'HELD_BY_OTHER', 'FREE', 'UNAVAILABLE']);

/** The closed action vocabulary a context may intend. */
export const ACTIONS = Object.freeze(['ACQUIRE', 'READ', 'STATE_CHANGE']);

/** C-API `/errorCodeEnum` members this module is allowed to reject with. No new vocabulary. */
export const LOCK_ERROR_CODES = Object.freeze(['UNKNOWN_FIELD', 'INVALID_REQUEST', 'UNKNOWN_VALUE']);

/**
 * The closed first-failing-phase values this module can name. C-REC `/faultPhaseOrder[0]`
 * is LOCK, so a lock rejection always fails first at LOCK; an authorized observation has
 * failed nowhere. (C-REC also records `C_REST_CLASSIFIED` for the dispatch of an already
 * classified `LOCKED_ELSEWHERE` result, which is downstream of this module and is not
 * produced here.)
 */
export const FIRST_FAILING_PHASES = Object.freeze(['NONE', LOCK_PHASE]);

/** C-REC marker states reachable through the lock gate (a lock fault changes no marker). */
export const MARKER_STATES = Object.freeze(['UNCHANGED']);

/**
 * The ratified lock clauses this card transcribes, with their owner-visible keys and the
 * SHA-256 of the canonical clause content recorded in O-SCEN. These are the anchors the
 * scenario-mapping test below cites; they are not re-derived from the documents at runtime.
 */
export const LOCK_CLAUSES = Object.freeze({
  SINGLE_WRITER: Object.freeze({
    key: 'CL-CAPI-b02195b48fbc',
    path: '/rules/singleWriter',
    clauseSha256: 'bd5b8b8356c0c60e04ed40241930e3c136d26ba6c5d93e0b1c269f4e7d81f115',
    content: 'I-LOCK prevents a second active context before it invokes this API; '
      + 'session-active-elsewhere is therefore an outer UI/controller result, not an adapter result',
  }),
  REST_PHASE_LOCK: Object.freeze({
    key: 'CL-CREST-bb9bf966faca',
    path: '/phaseRules/0',
    clauseSha256: 'ebe3cbb6ed4cdd42001a028b0b7c41b6bd08cfb69a4d389103dad0a5839b1ffa',
    content: 'Acquire the one-writer Web Lock; read no M2 or legacy bytes before success.',
  }),
  REST_PROSE_19: Object.freeze({
    key: 'PROSE-CREST-19-7b3a0709a784',
    path: '/prose/19',
    clauseSha256: '9c4a27bfed3e189e09bc8eb444938fbe669007715364b47f326bd047d026c89b',
    content: 'Before reading any stored M2 or legacy byte, the one-writer Web Lock MUST be '
      + 'held and one complete `buildMatrix` row MUST match.',
  }),
  REC_REQUIRES_LOCK: Object.freeze({
    key: 'CL-CREC-75e30e3c094e',
    path: '/precedence/lockedDisposition',
    clauseSha256: '89fb9dae2b011c6943b81a32ab9e74f654080f61587d784adc299da452827893',
    content: 'LOCK_RETRY',
  }),
  REC_FAULT_PRECEDENCE: Object.freeze({
    key: 'CL-CREC-07ea4cb3e02d',
    path: '/faultPrecedence/0',
    clauseSha256: '2ea8afd00482766b96f24d364ffec2cabfb0caab307bf8ab6c45ccb91a356d52',
    content: '{"fault":"lockUnavailable","phase":"LOCK","result":"LOCKED_ELSEWHERE"}',
  }),
  REST_FAULT_PRECEDENCE: Object.freeze({
    key: 'CL-CREST-f29f714b4f0e',
    path: '/faultPrecedence/0',
    clauseSha256: '2ea8afd00482766b96f24d364ffec2cabfb0caab307bf8ab6c45ccb91a356d52',
    content: '{"fault":"lockUnavailable","phase":"LOCK","result":"LOCKED_ELSEWHERE"}',
  }),
  REC_NEG_NO_LOCK: Object.freeze({
    key: 'CL-CREC-207db887bd1c',
    path: '/fixtures/56',
    clauseSha256: '7f51788a637285f57a20e0c83229b0aecfe084ad81552d39fd86b127bbbede0a',
    content: '{"expected":{"agreement":{"authorityIdentity":"NONE","disposition":"LOCK_RETRY",'
      + '"firstFailingPhase":"LOCK","markerState":"UNCHANGED"},"reject":"LOCKED_ELSEWHERE"},'
      + '"id":"NEG-NO-LOCK","input":{"event":"USER_CONFIRMED_START","lockHeld":false,'
      + '"state":"ABSENT"},"kind":"MARKER"}',
  }),
  REC_MARKER_TRANSITIONS: Object.freeze({
    key: 'CL-CREC-7d3c371b9cb1',
    path: '/marker/transitions',
    clauseSha256: 'eb3c0cd8d0f8a62c6adfa413b3644317cf1cbf9ee4568921a44a1c46cc4f411d',
    content: 'every marker transition carries "requiresLock": true',
  }),
});

/**
 * The O-SCEN blind scenario rows this card owns, transcribed from the ratified scenario
 * set with the clause key each row cites. The mapping test below either binds a row to a
 * named test or records why it is unmapped; it never silently drops one.
 */
export const LOCK_SCENARIOS = Object.freeze([
  Object.freeze({ id: 'OSC-7e009f23be2707b5', kind: 'POSITIVE', clause: LOCK_CLAUSES.SINGLE_WRITER.key }),
  Object.freeze({ id: 'OSC-847305bb3c22662a', kind: 'POSITIVE', clause: LOCK_CLAUSES.REST_PROSE_19.key }),
  Object.freeze({ id: 'OSC-968ce5454a763f57', kind: 'POSITIVE', clause: LOCK_CLAUSES.REST_PHASE_LOCK.key }),
  Object.freeze({ id: 'OSC-54b26121e663f399', kind: 'PRECEDENCE', clause: LOCK_CLAUSES.REC_REQUIRES_LOCK.key }),
  Object.freeze({ id: 'OSC-398767b7cf0d54b3', kind: 'PAIR', clause: LOCK_CLAUSES.REC_FAULT_PRECEDENCE.key }),
  Object.freeze({ id: 'OSC-28721c8bb3dd0d1c', kind: 'PAIR', clause: LOCK_CLAUSES.REC_FAULT_PRECEDENCE.key }),
  Object.freeze({ id: 'OSC-5856153389554186', kind: 'POSITIVE', clause: LOCK_CLAUSES.REC_NEG_NO_LOCK.key }),
  Object.freeze({ id: 'OSC-0c458c1dd534931c', kind: 'POSITIVE', clause: LOCK_CLAUSES.REC_MARKER_TRANSITIONS.key }),
]);

/**
 * The closed plan for a lock rejection, in the exact shape of a C-REC `agreement`
 * (`/fixtures/56` NEG-NO-LOCK): authority NONE, disposition LOCK_RETRY, first failing
 * phase LOCK, marker unchanged.
 */
const LOCK_REJECTION = freezeData({
  result: 'LOCKED_ELSEWHERE',
  disposition: 'LOCK_RETRY',
  authority: 'NONE',
  firstFailingPhase: LOCK_PHASE,
  markerState: 'UNCHANGED',
  authorized: false,
});

/** The closed plan for an authorized lock observation. */
const LOCK_AUTHORIZATION = freezeData({
  result: null,
  disposition: null,
  authority: 'SELF',
  firstFailingPhase: 'NONE',
  markerState: 'UNCHANGED',
  authorized: true,
});

const KNOWN_OWNERSHIP = new Set(OWNERSHIP);
const KNOWN_ACTIONS = new Set(ACTIONS);
const KNOWN_ROLES = new Set(CONTEXT_ROLES);
const KNOWN_ERROR_CODES = new Set(LOCK_ERROR_CODES);

// ---------------------------------------------------------------------------------------------
// Closed-shape inspection, using the C-API error vocabulary only.
// ---------------------------------------------------------------------------------------------

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  if (ArrayBuffer.isView(value)) return false;
  try {
    return Object.getPrototypeOf(value) === Object.prototype;
  } catch {
    return false;
  }
}

/**
 * Accept a value only when it is a plain object whose own enumerable data keys are exactly
 * the allowed set. Returns `{ error, values }` where `error` is a C-API error code or null.
 */
function closedObject(value, allowed) {
  if (!isPlainObject(value)) return { error: 'INVALID_REQUEST', values: null };
  let keys;
  let descriptors;
  try {
    keys = Reflect.ownKeys(value);
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    return { error: 'INVALID_REQUEST', values: null };
  }
  if (keys.some((key) => typeof key !== 'string')) return { error: 'UNKNOWN_FIELD', values: null };
  for (const key of keys) {
    if (!allowed.includes(key)) return { error: 'UNKNOWN_FIELD', values: null };
    const descriptor = descriptors[key];
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) {
      return { error: 'INVALID_REQUEST', values: null };
    }
  }
  for (const key of allowed) {
    if (!Object.hasOwn(descriptors, key)) return { error: 'INVALID_REQUEST', values: null };
  }
  const values = {};
  for (const key of keys) values[key] = descriptors[key].value;
  return { error: null, values };
}

/** Reject a valid-shaped observation whose member carries an unknown enum value. */
function invalidObservation(code) {
  constraintErrorUnknown(code);
  return freezeData({
    accepted: false,
    error: code,
    result: null,
    disposition: null,
    authority: 'NONE',
    firstFailingPhase: 'NONE',
    markerState: 'UNCHANGED',
    authorized: false,
  });
}

/** Thrown only for a programming error inside this module (an unknown code word). */
class ConstraintError extends Error {}

function constraintErrorUnknown(code) {
  if (!KNOWN_ERROR_CODES.has(code)) {
    throw new ConstraintError(`unknown lock rejection code: ${String(code)}`);
  }
}

// ---------------------------------------------------------------------------------------------
// Gate: may this context act?
// ---------------------------------------------------------------------------------------------

/** True when the action may not proceed without the one-writer Web Lock. */
export function actionRequiresLock(action) {
  if (!KNOWN_ACTIONS.has(action)) throw new TypeError('unknown action');
  // C-REC `/precedence/requiresOneWriterLockForStateChange` covers STATE_CHANGE; C-REST
  // `/phaseRules/0` and `/prose/19` cover READ. Only ACQUIRE itself precedes the lock.
  return action === 'STATE_CHANGE' || action === 'READ';
}

/**
 * Evaluate one closed lock observation.
 *
 * Input record (closed): `{ contextId, role, ownership, action }`.
 * Output: a frozen envelope carrying the closed outcome, a C-API error code for a
 * malformed observation, and the exact C-REC agreement fields for a well-formed one.
 */
export function evaluateLockAction(input) {
  const shape = closedObject(input, ['contextId', 'role', 'ownership', 'action']);
  if (shape.error) return invalidObservation(shape.error);
  const { contextId, role, ownership, action } = shape.values;
  if (typeof contextId !== 'string' || contextId.length === 0) return invalidObservation('INVALID_REQUEST');
  if (!KNOWN_ROLES.has(role)) return invalidObservation('UNKNOWN_VALUE');
  if (!KNOWN_OWNERSHIP.has(ownership)) return invalidObservation('UNKNOWN_VALUE');
  if (!KNOWN_ACTIONS.has(action)) return invalidObservation('UNKNOWN_VALUE');

  const plan = resolvePlan(ownership, action);
  return freezeData({
    accepted: true,
    error: null,
    contextId,
    role,
    action,
    result: plan.result,
    disposition: plan.disposition,
    authority: plan.authority,
    firstFailingPhase: plan.firstFailingPhase,
    markerState: plan.markerState,
    authorized: plan.authorized,
  });
}

function resolvePlan(ownership, action) {
  if (ownership === 'UNAVAILABLE') return LOCK_REJECTION;
  if (ownership === 'HELD_BY_OTHER') return LOCK_REJECTION;
  if (ownership === 'HELD_BY_SELF') return LOCK_AUTHORIZATION;
  // FREE: only the acquisition attempt itself may proceed; every gated action must wait.
  return action === 'ACQUIRE' ? LOCK_AUTHORIZATION : LOCK_REJECTION;
}

// ---------------------------------------------------------------------------------------------
// The second-tab matrix.
// ---------------------------------------------------------------------------------------------

/**
 * Evaluate the second-tab matrix over the contexts observable for one browser profile.
 *
 * Input: an array (any order) of closed context records
 * `{ contextId, role, ownership, intent }` where `intent` is the action the context wants.
 *
 * Output: a frozen matrix. Exactly one context may be ACTIVE — the single holder of the
 * one Web Lock — and every other context is SESSION_ACTIVE_ELSEWHERE with its action
 * gated to LOCKED_ELSEWHERE/LOCK_RETRY. If two contexts both claim the lock, the facts are
 * contradictory and no context becomes active (C-REC: ambiguous facts choose the safer
 * non-authorizing disposition; enumeration order cannot affect the result).
 */
export function evaluateSecondTabMatrix(contexts) {
  if (!Array.isArray(contexts)) {
    return freezeData({ accepted: false, error: 'INVALID_REQUEST', contexts: [], activeContextIds: [], ambiguous: false });
  }
  const seen = new Set();
  const observations = [];
  for (const entry of contexts) {
    const shape = closedObject(entry, ['contextId', 'role', 'ownership', 'intent']);
    if (shape.error) {
      return freezeData({ accepted: false, error: shape.error, contexts: [], activeContextIds: [], ambiguous: false });
    }
    const { contextId, role, ownership, intent } = shape.values;
    if (typeof contextId !== 'string' || contextId.length === 0) {
      return freezeData({ accepted: false, error: 'INVALID_REQUEST', contexts: [], activeContextIds: [], ambiguous: false });
    }
    if (seen.has(contextId)) {
      return freezeData({ accepted: false, error: 'UNKNOWN_VALUE', contexts: [], activeContextIds: [], ambiguous: false });
    }
    seen.add(contextId);
    if (!KNOWN_ROLES.has(role)) {
      return freezeData({ accepted: false, error: 'UNKNOWN_VALUE', contexts: [], activeContextIds: [], ambiguous: false });
    }
    if (!KNOWN_OWNERSHIP.has(ownership)) {
      return freezeData({ accepted: false, error: 'UNKNOWN_VALUE', contexts: [], activeContextIds: [], ambiguous: false });
    }
    if (!KNOWN_ACTIONS.has(intent)) {
      return freezeData({ accepted: false, error: 'UNKNOWN_VALUE', contexts: [], activeContextIds: [], ambiguous: false });
    }
    observations.push({ contextId, role, ownership, intent });
  }

  const claimants = observations.filter((o) => o.ownership === 'HELD_BY_SELF');
  const ambiguous = claimants.length > 1;
  const activeContextIds = ambiguous ? [] : claimants.map((o) => o.contextId);

  const rows = observations.map((o) => {
    const isActive = activeContextIds.includes(o.contextId);
    const gate = evaluateLockAction({
      contextId: o.contextId, role: o.role, ownership: o.ownership, action: o.intent,
    });
    return freezeData({
      contextId: o.contextId,
      role: o.role,
      ownership: o.ownership,
      intent: o.intent,
      outcome: isActive ? 'ACTIVE' : SESSION_ACTIVE_ELSEWHERE,
      result: gate.result,
      disposition: gate.disposition,
      firstFailingPhase: gate.firstFailingPhase,
      markerState: gate.markerState,
      authorized: isActive,
    });
  });

  return freezeData({
    accepted: true,
    error: null,
    contexts: rows,
    activeContextIds,
    ambiguous,
    singleWriter: activeContextIds.length <= 1,
  });
}

/** The context ids that are ACTIVE in a matrix. Never more than one. */
export function activeContextIds(matrix) {
  if (!matrix || !Array.isArray(matrix.activeContextIds)) throw new TypeError('not a matrix');
  return matrix.activeContextIds.slice();
}

/**
 * Fail-closed guard: true when the matrix would let more than one context act, which is the
 * exact condition the one-worker/one-writer rule forbids. Always false for a matrix built by
 * `evaluateSecondTabMatrix`; callers that hand-build a matrix can assert it.
 */
export function anySecondContextSilentlyActive(matrix) {
  if (!matrix || !Array.isArray(matrix.contexts)) throw new TypeError('not a matrix');
  const active = matrix.contexts.filter((row) => row.outcome === 'ACTIVE'
    || (row.outcome !== SESSION_ACTIVE_ELSEWHERE && row.authorized === true));
  return active.length > 1;
}

// ---------------------------------------------------------------------------------------------
// Frozen bundle + debug string guard.
// ---------------------------------------------------------------------------------------------

export const M2_LOCK = freezeData({
  LOCK_PHASE,
  LOCK_FAULTS,
  LOCK_RESULTS,
  LOCK_DISPOSITIONS,
  OUTER_RESULTS,
  SESSION_ACTIVE_ELSEWHERE,
  CONTEXT_ROLES,
  CONTEXT_OUTCOMES,
  OWNERSHIP,
  ACTIONS,
  LOCK_ERROR_CODES,
  FIRST_FAILING_PHASES,
  MARKER_STATES,
  LOCK_CLAUSES,
  LOCK_SCENARIOS,
});

// A closed data-only module exposes no behaviour beyond its frozen data and pure functions.

export default M2_LOCK;
