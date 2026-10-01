// M2 atomic mutation/result transaction over an injected storage port.
// Internal-only: no barrel export.
//
// This module executes one C-MUT vault-owned logical mutation as a single atomic transaction. It
// forms and validates the closed `MutationEnvelope`, binds it to the selected C-MUT row, drives an
// ordered and inspectable step plan against an injected storage port, changes authority only through
// one atomic selector replacement, and classifies the stored state afterwards as exactly the complete
// old generation or exactly the complete new generation - never a mixture. It reuses
// `./session-codec.js` and `./session-root.js` unchanged and adds no IndexedDB, worker, browser, UI,
// transport, vault, password, migration, restore or public-package behaviour.
//
// The storage port is injected because C-MUT and C-FMT both leave the physical storage design to a
// later card. The real IndexedDB adapter arrives in B-CHR. The port owns the in-memory hold lifecycle:
// a successful terminal clearing step (RELEASE_ESCROW or CLEAR_CANDIDATE) is the event after which
// `readMemoryHold()` reports no hold.
import { M2_KIND, decodePlaintext, encodePlaintext } from './session-codec.js';
import {
  validateAuthority, computeKeyedRoot, ciphertextDigest, manifestEntry, encodeManifest,
  manifestKeyDigest,
} from './session-root.js';

/** The three C-MUT logical commit outcomes. */
export const M2_OUTCOME = Object.freeze({ COMMITTED: 1, NOT_COMMITTED: 2, INDETERMINATE: 3 });
const OUTCOME_NAME = Object.freeze(['', 'COMMITTED', 'NOT_COMMITTED', 'INDETERMINATE']);

const SCENARIOS = Object.freeze([
  'CAPI-S001', 'CAPI-S006', 'CAPI-S009', 'CAPI-S010', 'CAPI-S014', 'CAPI-S016', 'CAPI-S017',
]);

const BOUNDARIES = Object.freeze([
  'BEFORE_STAGING',
  'AFTER_CANDIDATE_COMPUTATION',
  'AFTER_LOCAL_STAGING',
  'BEFORE_RS_REQUEST',
  'DURING_RS_WORK',
  'AFTER_DURABLE_COMMIT_BEFORE_RESPONSE',
  'AFTER_NOT_COMMITTED',
  'AFTER_INDETERMINATE',
  'DURING_RECONCILIATION',
  'AFTER_AUTHORITY_SELECTION_BEFORE_OUTPUT_RESPONSE',
  'DURING_ESCROW_OUTPUT_RESPONSE',
  'AFTER_OUTPUT_RESPONSE_LOSS',
]);

const STEP_KINDS = Object.freeze([
  'VALIDATE_ENVELOPE', 'COMPUTE_CANDIDATE', 'STAGE_LOCAL', 'OPEN_RS_REQUEST', 'STAGE_DATA',
  'STAGE_MANIFEST', 'STAGE_EVIDENCE', 'STAGE_ESCROW', 'REPLACE_SELECTOR', 'CONFIRM_AUTHORITY',
  'WRITE_HOLD', 'CLEAR_CANDIDATE', 'RELEASE_ESCROW', 'REPORT_RESULT',
]);

// Steps that create no durable byte: `apply` is never called for them.
const MEMORY_ONLY = Object.freeze(new Set([
  'VALIDATE_ENVELOPE', 'COMPUTE_CANDIDATE', 'STAGE_LOCAL', 'OPEN_RS_REQUEST', 'CONFIRM_AUTHORITY',
  'REPORT_RESULT',
]));

const STORAGE_METHODS = Object.freeze(['apply', 'readSelector', 'readGeneration', 'readMemoryHold']);

const OPERATIONS = Object.freeze([
  'CREATE', 'RESTORE', 'JOIN_WELCOME', 'PROTECT_APPLICATION', 'OPEN_APPLICATION', 'SELF_UPDATE',
  'APPLY_PEER_UPDATE', 'RECONCILE_INDETERMINATE',
]);

const SUCCESS_CODES = Object.freeze([
  'CREATED', 'RESTORED', 'JOINED', 'APPLICATION_PROTECTED', 'APPLICATION_OPENED', 'SELF_UPDATED',
  'PEER_UPDATE_APPLIED', 'CANDIDATE_SELECTED', 'RECONCILED_COMMITTED', 'DUPLICATE_IGNORED',
]);

const OUTPUT_KINDS = Object.freeze([
  'NONE', 'EMBEDDED_TREE_WELCOME', 'PROTECTED_APPLICATION_BYTES', 'APPLICATION_BYTES',
  'PROTECTED_COMMIT_BYTES', 'SELECTED_CANDIDATE_REF',
]);

const COMPONENTS = Object.freeze([
  'SESSION_TRANSITION', 'BINDING_METADATA', 'REPLAY_RETENTION_STATE', 'AUTHENTICATED_MANIFEST_UPDATE',
  'COMMIT_RESULT_EVIDENCE', 'KEY_PACKAGE_CONSUMPTION', 'OUTPUT_ESCROW', 'SELECTION_METADATA',
  'RETAINED_PARENT_REFERENCE', 'LOSING_CANDIDATE_EVIDENCE',
]);

const DISPOSITIONS = Object.freeze([
  'CHANGED', 'UNCHANGED', 'CHANGED_OR_UNCHANGED_BY_SELECTED_CANDIDATE', 'CREATED', 'CONSUMED', 'HELD',
  'ESTABLISHED', 'INVALIDATED', 'RETAINED_NON_AUTHORITATIVE',
  'INVALIDATE_PRIOR_AND_RETAIN_CURRENT_NON_AUTHORITATIVE', 'TERMINATED',
]);

const API_STATE_CODE = Object.freeze({ EMPTY: 1, ACTIVE: 2 });
const SELECTOR_STATE = Object.freeze({ EMPTY: 1, ACTIVE: 2, RECONCILIATION_REQUIRED: 3 });
const DATA_KIND_COUNT = 15;

// The C-MUT rows whose committed selection the unratified F-WASM feasibility evidence demonstrated
// only through matching-durable-COMMITTED readback reconciliation after INDETERMINATE.
const AUTOMATIC_ROWS = Object.freeze(['CAPI-S006']);

export const M2_TXN = Object.freeze({
  ROW_COUNT: 7,
  BOUNDARY_COUNT: 12,
  COMPONENT_COUNT: 10,
  STORAGE_METHODS,
  SCENARIOS,
  BOUNDARIES,
  AUTOMATIC_ROWS,
});

const CODE = Object.freeze({
  MALFORMED_INPUT: 'MALFORMED_INPUT',
  UNSUPPORTED_VALUE: 'UNSUPPORTED_VALUE',
  CONTEXT_MISMATCH: 'CONTEXT_MISMATCH',
  INVALID_ENVELOPE: 'INVALID_ENVELOPE',
  DUPLICATE_OPERATION_IDENTITY: 'DUPLICATE_OPERATION_IDENTITY',
  STALE_PARENT: 'STALE_PARENT',
  NONTERMINAL_NOT_COMMITTED: 'NONTERMINAL_NOT_COMMITTED',
  BLIND_RETRY: 'BLIND_RETRY',
  REFERENCE_MISMATCH: 'REFERENCE_MISMATCH',
  EVIDENCE_MISMATCH: 'EVIDENCE_MISMATCH',
  PARTIAL_APPLICATION: 'PARTIAL_APPLICATION',
  NO_RECONCILIATION_PENDING: 'NO_RECONCILIATION_PENDING',
  HOLD_UNAVAILABLE: 'HOLD_UNAVAILABLE',
});

/** The only error class this module exports. */
export class M2TxnError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'M2TxnError';
    this.code = code;
  }
}

const fail = (code, message) => { throw new M2TxnError(code, message); };
const malformed = (m) => fail(CODE.MALFORMED_INPUT, m);
const unsupported = (m) => fail(CODE.UNSUPPORTED_VALUE, m);
const mismatch = (m) => fail(CODE.CONTEXT_MISMATCH, m);
const partial = (m) => fail(CODE.PARTIAL_APPLICATION, m);

function strictObject(value, keys, name = 'value') {
  if (value === null || typeof value !== 'object' || Array.isArray(value)
      || Object.getPrototypeOf(value) !== Object.prototype) malformed(`${name} must be a plain object`);
  const own = Reflect.ownKeys(value);
  if (own.length !== keys.length || own.some((k) => typeof k !== 'string' || !keys.includes(k))) {
    malformed(`${name} has an unknown, missing, or symbol property`);
  }
  const out = {};
  for (const key of keys) {
    const d = Object.getOwnPropertyDescriptor(value, key);
    if (!d || !d.enumerable || !Object.hasOwn(d, 'value')) malformed(`${name}.${key} must be enumerable data`);
    out[key] = d.value;
  }
  return out;
}
function bytes(value, length, name) {
  if (!(value instanceof Uint8Array) || (length !== null && value.length !== length)) {
    malformed(`${name} has wrong byte width`);
  }
  // Uint8Array.prototype.slice, never value.slice(): Buffer overrides slice() to return a view.
  return Uint8Array.prototype.slice.call(value);
}
function nonzero(value, name) {
  const out = bytes(value, 32, name);
  if (out.every((b) => b === 0)) malformed(`${name} must be nonzero`);
  return out;
}
function safeInt(value, max, name) {
  if (!Number.isSafeInteger(value) || value < 0 || value > max) malformed(`${name} is out of range`);
  return value;
}
function u64(value, name) {
  if (typeof value !== 'bigint' || value < 0n || value > ((1n << 64n) - 1n)) malformed(`${name} is out of range`);
  return value;
}
function text(value, allowed, name) {
  if (typeof value !== 'string' || !allowed.includes(value)) unsupported(`${name} is not a defined value`);
  return value;
}
function outcomeValue(value) {
  if (value !== M2_OUTCOME.COMMITTED && value !== M2_OUTCOME.NOT_COMMITTED
      && value !== M2_OUTCOME.INDETERMINATE) unsupported('outcome is not a defined C-MUT commit outcome');
  return value;
}
const equal = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
const deepEqual = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const freezeDeep = (o) => (Array.isArray(o)
  ? Object.freeze(o.map(freezeDeep))
  : (o !== null && typeof o === 'object' && Object.getPrototypeOf(o) === Object.prototype
    ? Object.freeze(Object.fromEntries(Object.entries(o).map(([k, v]) => [k, freezeDeep(v)])))
    : o));

const ROWS = Object.freeze([
  {
    scenario: 'CAPI-S001', operation: 'CREATE', stateBefore: 'EMPTY', stateAfterCommitted: 'ACTIVE',
    successCode: 'CREATED', outputKind: 'EMBEDDED_TREE_WELCOME', selectionEffect: 'NOT_APPLICABLE', retainedParentEffect: 'NOT_APPLICABLE',
    components: [
      { id: 'SESSION_TRANSITION', disposition: 'CHANGED', fact: 'FOUNDER_STATE' },
      { id: 'BINDING_METADATA', disposition: 'CHANGED', fact: 'INITIAL_EXACT_BINDING_AND_PROFILE' },
      { id: 'REPLAY_RETENTION_STATE', disposition: 'CHANGED', fact: 'INITIAL_BASELINE' },
      { id: 'AUTHENTICATED_MANIFEST_UPDATE', disposition: 'CHANGED', fact: 'FOUNDER_MANIFEST' },
      { id: 'COMMIT_RESULT_EVIDENCE', disposition: 'CREATED', fact: 'BOUND_TO_OPERATION_IDENTITY' },
      { id: 'OUTPUT_ESCROW', disposition: 'HELD', fact: 'EMBEDDED_TREE_WELCOME' },
    ],
  },
  {
    scenario: 'CAPI-S006', operation: 'JOIN_WELCOME', stateBefore: 'EMPTY', stateAfterCommitted: 'ACTIVE',
    successCode: 'JOINED', outputKind: 'NONE', selectionEffect: 'NOT_APPLICABLE', retainedParentEffect: 'NOT_APPLICABLE',
    components: [
      { id: 'SESSION_TRANSITION', disposition: 'CHANGED', fact: 'JOINED_STATE' },
      { id: 'BINDING_METADATA', disposition: 'CHANGED', fact: 'JOINED_EXACT_BINDING_AND_PROFILE' },
      { id: 'REPLAY_RETENTION_STATE', disposition: 'CHANGED', fact: 'JOINED_BASELINE' },
      { id: 'AUTHENTICATED_MANIFEST_UPDATE', disposition: 'CHANGED', fact: 'JOINED_MANIFEST' },
      { id: 'COMMIT_RESULT_EVIDENCE', disposition: 'CREATED', fact: 'BOUND_TO_OPERATION_IDENTITY' },
      { id: 'KEY_PACKAGE_CONSUMPTION', disposition: 'CONSUMED', fact: 'MATCHING_LOCAL_ONE_SHOT_REFERENCE' },
    ],
  },
  {
    scenario: 'CAPI-S009', operation: 'PROTECT_APPLICATION', stateBefore: 'ACTIVE', stateAfterCommitted: 'ACTIVE',
    successCode: 'APPLICATION_PROTECTED', outputKind: 'PROTECTED_APPLICATION_BYTES', selectionEffect: 'PRESERVE', retainedParentEffect: 'PRESERVE',
    components: [
      { id: 'SESSION_TRANSITION', disposition: 'CHANGED', fact: 'SENDER_RATCHET_ADVANCEMENT' },
      { id: 'BINDING_METADATA', disposition: 'UNCHANGED', fact: 'EXACT_BINDING_AND_PROFILE' },
      { id: 'REPLAY_RETENTION_STATE', disposition: 'CHANGED', fact: 'SENDER_RATCHET_RETENTION' },
      { id: 'AUTHENTICATED_MANIFEST_UPDATE', disposition: 'CHANGED', fact: 'RATCHET_STATE_MANIFEST' },
      { id: 'COMMIT_RESULT_EVIDENCE', disposition: 'CREATED', fact: 'BOUND_TO_OPERATION_IDENTITY' },
      { id: 'OUTPUT_ESCROW', disposition: 'HELD', fact: 'PROTECTED_APPLICATION_BYTES' },
      { id: 'SELECTION_METADATA', disposition: 'UNCHANGED', fact: 'EPOCH_PRESERVING_ELIGIBILITY' },
      { id: 'RETAINED_PARENT_REFERENCE', disposition: 'UNCHANGED', fact: 'PRESERVED_IF_PRESENT' },
    ],
  },
  {
    scenario: 'CAPI-S010', operation: 'OPEN_APPLICATION', stateBefore: 'ACTIVE', stateAfterCommitted: 'ACTIVE',
    successCode: 'APPLICATION_OPENED', outputKind: 'APPLICATION_BYTES', selectionEffect: 'PRESERVE', retainedParentEffect: 'PRESERVE',
    components: [
      { id: 'SESSION_TRANSITION', disposition: 'CHANGED', fact: 'RECEIVER_RATCHET_ADVANCEMENT' },
      { id: 'BINDING_METADATA', disposition: 'UNCHANGED', fact: 'EXACT_BINDING_AND_PROFILE' },
      { id: 'REPLAY_RETENTION_STATE', disposition: 'CHANGED', fact: 'REPLAY_ACCEPTANCE_AND_RECEIVER_RETENTION' },
      { id: 'AUTHENTICATED_MANIFEST_UPDATE', disposition: 'CHANGED', fact: 'RATCHET_AND_REPLAY_MANIFEST' },
      { id: 'COMMIT_RESULT_EVIDENCE', disposition: 'CREATED', fact: 'BOUND_TO_OPERATION_IDENTITY' },
      { id: 'OUTPUT_ESCROW', disposition: 'HELD', fact: 'APPLICATION_BYTES' },
      { id: 'SELECTION_METADATA', disposition: 'UNCHANGED', fact: 'EPOCH_PRESERVING_ELIGIBILITY' },
      { id: 'RETAINED_PARENT_REFERENCE', disposition: 'UNCHANGED', fact: 'PRESERVED_IF_PRESENT' },
    ],
  },
  {
    scenario: 'CAPI-S014', operation: 'SELF_UPDATE', stateBefore: 'ACTIVE', stateAfterCommitted: 'ACTIVE',
    successCode: 'SELF_UPDATED', outputKind: 'PROTECTED_COMMIT_BYTES', selectionEffect: 'ESTABLISH', retainedParentEffect: 'ESTABLISH_FOR_CAPI_S017_ONLY',
    components: [
      { id: 'SESSION_TRANSITION', disposition: 'CHANGED', fact: 'LOCAL_UPDATE_STATE' },
      { id: 'BINDING_METADATA', disposition: 'UNCHANGED', fact: 'EXACT_BINDING_AND_PROFILE' },
      { id: 'REPLAY_RETENTION_STATE', disposition: 'CHANGED', fact: 'EPOCH_WINDOW_ADVANCEMENT' },
      { id: 'AUTHENTICATED_MANIFEST_UPDATE', disposition: 'CHANGED', fact: 'LOCAL_UPDATE_MANIFEST' },
      { id: 'COMMIT_RESULT_EVIDENCE', disposition: 'CREATED', fact: 'BOUND_TO_OPERATION_IDENTITY' },
      { id: 'OUTPUT_ESCROW', disposition: 'HELD', fact: 'PROTECTED_COMMIT_BYTES' },
      { id: 'SELECTION_METADATA', disposition: 'ESTABLISHED', fact: 'IMMEDIATELY_PRECEDING_LOCAL_UPDATE_ELIGIBILITY' },
      { id: 'RETAINED_PARENT_REFERENCE', disposition: 'ESTABLISHED', fact: 'PARENT_REQUIRED_BY_CAPI_S017' },
    ],
  },
  {
    scenario: 'CAPI-S016', operation: 'APPLY_PEER_UPDATE', stateBefore: 'ACTIVE', stateAfterCommitted: 'ACTIVE',
    successCode: 'PEER_UPDATE_APPLIED', outputKind: 'NONE', selectionEffect: 'INVALIDATE', retainedParentEffect: 'INVALIDATE_SELECTION_ROLE',
    components: [
      { id: 'SESSION_TRANSITION', disposition: 'CHANGED', fact: 'PEER_UPDATE_STATE' },
      { id: 'BINDING_METADATA', disposition: 'UNCHANGED', fact: 'EXACT_BINDING_AND_PROFILE' },
      { id: 'REPLAY_RETENTION_STATE', disposition: 'CHANGED', fact: 'EPOCH_WINDOW_ADVANCEMENT' },
      { id: 'AUTHENTICATED_MANIFEST_UPDATE', disposition: 'CHANGED', fact: 'PEER_UPDATE_MANIFEST' },
      { id: 'COMMIT_RESULT_EVIDENCE', disposition: 'CREATED', fact: 'BOUND_TO_OPERATION_IDENTITY' },
      { id: 'SELECTION_METADATA', disposition: 'INVALIDATED', fact: 'ANY_CAPI_S014_ELIGIBILITY' },
      { id: 'RETAINED_PARENT_REFERENCE', disposition: 'INVALIDATED', fact: 'NO_LONGER_SELECTION_AUTHORIZING' },
      { id: 'LOSING_CANDIDATE_EVIDENCE', disposition: 'INVALIDATED', fact: 'ANY_RETAINED_LOSER_EVIDENCE' },
    ],
  },
  {
    scenario: 'CAPI-S017', operation: 'APPLY_PEER_UPDATE', stateBefore: 'ACTIVE', stateAfterCommitted: 'ACTIVE',
    successCode: 'CANDIDATE_SELECTED', outputKind: 'SELECTED_CANDIDATE_REF', selectionEffect: 'TERMINATE', retainedParentEffect: 'TERMINATE_SELECTION_ROLE',
    components: [
      { id: 'SESSION_TRANSITION', disposition: 'CHANGED_OR_UNCHANGED_BY_SELECTED_CANDIDATE', fact: 'CURRENT_WINNER_UNCHANGED_INCOMING_WINNER_CHANGED' },
      { id: 'BINDING_METADATA', disposition: 'UNCHANGED', fact: 'EXACT_BINDING_AND_PROFILE' },
      { id: 'REPLAY_RETENTION_STATE', disposition: 'CHANGED', fact: 'SELECTED_EPOCH_WINDOW' },
      { id: 'AUTHENTICATED_MANIFEST_UPDATE', disposition: 'CHANGED', fact: 'SELECTED_STATE_MANIFEST' },
      { id: 'COMMIT_RESULT_EVIDENCE', disposition: 'CREATED', fact: 'BOUND_TO_OPERATION_IDENTITY' },
      { id: 'OUTPUT_ESCROW', disposition: 'HELD', fact: 'SELECTED_CANDIDATE_REF' },
      { id: 'SELECTION_METADATA', disposition: 'TERMINATED', fact: 'NO_FURTHER_SELECTION_FROM_OLD_PARENT' },
      { id: 'RETAINED_PARENT_REFERENCE', disposition: 'TERMINATED', fact: 'NO_LONGER_SELECTION_AUTHORIZING' },
      { id: 'LOSING_CANDIDATE_EVIDENCE', disposition: 'RETAINED_NON_AUTHORITATIVE', fact: 'BOUNDED_VALID_LOSER' },
    ],
  },
]);

const ROW_BY_SCENARIO = new Map(ROWS.map((row) => [row.scenario, row]));

/** The closed C-MUT mutation row for one scenario. */
export function mutationRow(scenario) {
  if (typeof scenario !== 'string' || !ROW_BY_SCENARIO.has(scenario)) {
    unsupported('unknown C-MUT mutation row');
  }
  return freezeDeep(ROW_BY_SCENARIO.get(scenario));
}

const ENVELOPE_KEYS = Object.freeze([
  'operationIdentity', 'operation', 'scenario', 'originalApiState', 'originalAuthority',
  'bindingProfileIdentity', 'candidate', 'componentSet', 'heldOutput', 'expectedSuccess',
  'reconciliationIdentity',
]);

function componentEntries(value, name) {
  if (!Array.isArray(value)) malformed(`${name} must be an array`);
  return value.map((entry, i) => {
    const c = strictObject(entry, ['id', 'disposition', 'fact'], `${name}[${i}]`);
    text(c.id, COMPONENTS, `${name}[${i}].id`);
    text(c.disposition, DISPOSITIONS, `${name}[${i}].disposition`);
    if (typeof c.fact !== 'string' || c.fact.length === 0) {
      unsupported(`${name}[${i}].fact must be a value-free nonempty string`);
    }
    return { id: c.id, disposition: c.disposition, fact: c.fact };
  });
}

/**
 * Form and validate the closed C-MUT `MutationEnvelope`, bound to its selected row.
 * An application-originated operation identity, a reusable identity, an identity equal to the C-API
 * request id, a row-binding mismatch or a `NONE` held output carrying bytes fails closed before any
 * RS request.
 */
export function buildMutationEnvelope(input) {
  const s = strictObject(input, ENVELOPE_KEYS, 'mutation envelope');
  const identity = strictObject(s.operationIdentity,
    ['value', 'assignedBy', 'fresh', 'reusable', 'apRequestIdEqual'], 'operationIdentity');
  if (identity.assignedBy !== 'SS_RS' || identity.fresh !== true || identity.reusable !== false
      || identity.apRequestIdEqual !== false) {
    fail(CODE.INVALID_ENVELOPE,
      'operation identity must be fresh, non-reusable, not the C-API request id, and assigned by SS_RS');
  }
  const operation = text(s.operation, OPERATIONS, 'operation');
  const scenario = text(s.scenario, SCENARIOS, 'scenario');
  const originalApiState = text(s.originalApiState, Object.keys(API_STATE_CODE), 'originalApiState');
  const originalAuthority = strictObject(s.originalAuthority, ['digest', 'reference'], 'originalAuthority');
  const bindingProfileIdentity = strictObject(s.bindingProfileIdentity, ['bindingRef', 'profile'], 'bindingProfileIdentity');
  const candidate = strictObject(s.candidate, ['digest', 'reference'], 'candidate');
  const componentSet = strictObject(s.componentSet, ['digest', 'reference', 'entries'], 'componentSet');
  const heldOutput = strictObject(s.heldOutput, ['kind', 'digest', 'reference'], 'heldOutput');
  const expectedSuccess = strictObject(s.expectedSuccess, ['code', 'stateAfter'], 'expectedSuccess');
  const reconciliationIdentity = strictObject(s.reconciliationIdentity, ['reference', 'owner'], 'reconciliationIdentity');

  const heldOutputKind = text(heldOutput.kind, OUTPUT_KINDS, 'heldOutput.kind');
  let heldOutputDigest = null;
  let heldOutputReference = null;
  if (heldOutputKind === 'NONE') {
    if (heldOutput.digest !== null || heldOutput.reference !== null) {
      fail(CODE.INVALID_ENVELOPE, 'a NONE held output requires a null digest and a null reference');
    }
  } else {
    heldOutputDigest = bytes(heldOutput.digest, 32, 'heldOutput.digest');
    heldOutputReference = bytes(heldOutput.reference, 32, 'heldOutput.reference');
  }
  if (reconciliationIdentity.owner !== 'SS_RS') {
    fail(CODE.INVALID_ENVELOPE, 'reconciliation identity must be owned by SS_RS');
  }

  const envelope = freezeDeep({
    operationIdentity: { value: nonzero(identity.value, 'operationIdentity.value'), assignedBy: 'SS_RS', fresh: true, reusable: false, apRequestIdEqual: false },
    operation,
    scenario,
    originalApiState,
    originalAuthority: {
      digest: bytes(originalAuthority.digest, 32, 'originalAuthority.digest'),
      reference: bytes(originalAuthority.reference, 32, 'originalAuthority.reference'),
    },
    bindingProfileIdentity: {
      bindingRef: bytes(bindingProfileIdentity.bindingRef, 32, 'bindingProfileIdentity.bindingRef'),
      profile: bytes(bindingProfileIdentity.profile, 32, 'bindingProfileIdentity.profile'),
    },
    candidate: {
      digest: bytes(candidate.digest, 32, 'candidate.digest'),
      reference: bytes(candidate.reference, 32, 'candidate.reference'),
    },
    componentSet: {
      digest: bytes(componentSet.digest, 32, 'componentSet.digest'),
      reference: bytes(componentSet.reference, 32, 'componentSet.reference'),
      entries: componentEntries(componentSet.entries, 'componentSet.entries'),
    },
    heldOutput: { kind: heldOutputKind, digest: heldOutputDigest, reference: heldOutputReference },
    expectedSuccess: {
      code: text(expectedSuccess.code, SUCCESS_CODES, 'expectedSuccess.code'),
      stateAfter: text(expectedSuccess.stateAfter, Object.keys(API_STATE_CODE), 'expectedSuccess.stateAfter'),
    },
    reconciliationIdentity: {
      reference: nonzero(reconciliationIdentity.reference, 'reconciliationIdentity.reference'),
      owner: 'SS_RS',
    },
  });

  const row = ROW_BY_SCENARIO.get(scenario);
  const bound = envelope.operation === row.operation
    && envelope.originalApiState === row.stateBefore
    && envelope.heldOutput.kind === row.outputKind
    && envelope.expectedSuccess.code === row.successCode
    && envelope.expectedSuccess.stateAfter === row.stateAfterCommitted
    && deepEqual(envelope.componentSet.entries, row.components);
  if (!bound) fail(CODE.INVALID_ENVELOPE, 'the envelope is not bound to its selected C-MUT row');
  return envelope;
}

const EVIDENCE_KEYS = Object.freeze([
  'operationIdentity', 'originalAuthorityDigest', 'originalAuthorityReference', 'candidateDigest',
  'candidateReference', 'mutationSetDigest', 'mutationSetReference', 'expectedOriginalState',
  'bindingRef', 'profile', 'outcome', 'authenticatedByRS', 'terminal',
]);

function evidenceFacts(evidence, name) {
  const e = strictObject(evidence, EVIDENCE_KEYS, name);
  if (e.authenticatedByRS !== true) fail(CODE.EVIDENCE_MISMATCH, `${name} must be authenticated by RS`);
  if (typeof e.terminal !== 'boolean') malformed(`${name}.terminal must be boolean`);
  const outcome = outcomeValue(e.outcome);
  const terminal = e.terminal;
  if (outcome === M2_OUTCOME.NOT_COMMITTED && terminal !== true) {
    fail(CODE.NONTERMINAL_NOT_COMMITTED,
      'a NOT_COMMITTED result is accepted only from terminal evidence that the request can no longer commit');
  }
  return {
    operationIdentity: bytes(e.operationIdentity, 32, `${name}.operationIdentity`),
    originalAuthorityDigest: bytes(e.originalAuthorityDigest, 32, `${name}.originalAuthorityDigest`),
    originalAuthorityReference: bytes(e.originalAuthorityReference, 32, `${name}.originalAuthorityReference`),
    candidateDigest: bytes(e.candidateDigest, 32, `${name}.candidateDigest`),
    candidateReference: bytes(e.candidateReference, 32, `${name}.candidateReference`),
    mutationSetDigest: bytes(e.mutationSetDigest, 32, `${name}.mutationSetDigest`),
    mutationSetReference: bytes(e.mutationSetReference, 32, `${name}.mutationSetReference`),
    expectedOriginalState: safeInt(e.expectedOriginalState, 255, `${name}.expectedOriginalState`),
    bindingRef: bytes(e.bindingRef, 32, `${name}.bindingRef`),
    profile: bytes(e.profile, 32, `${name}.profile`),
    outcome,
    authenticatedByRS: true,
    terminal,
  };
}

/**
 * Accept commit-result evidence only when every identity field matches the held envelope.
 * Unknown, stale, cross-binding, cross-profile, duplicate, conflicting or mismatched evidence fails
 * closed and selects nothing.
 */
export function validateCommitResultEvidence(input) {
  const s = strictObject(input, ['evidence', 'envelope'], 'commit result evidence');
  const e = evidenceFacts(s.evidence, 'commit result evidence');
  const envelope = buildMutationEnvelope(s.envelope);
  for (const [field, want] of [
    ['operationIdentity', envelope.operationIdentity.value],
    ['originalAuthorityDigest', envelope.originalAuthority.digest],
    ['originalAuthorityReference', envelope.originalAuthority.reference],
    ['candidateDigest', envelope.candidate.digest],
    ['candidateReference', envelope.candidate.reference],
    ['mutationSetDigest', envelope.componentSet.digest],
    ['mutationSetReference', envelope.componentSet.reference],
    ['bindingRef', envelope.bindingProfileIdentity.bindingRef],
    ['profile', envelope.bindingProfileIdentity.profile],
  ]) {
    if (!equal(e[field], want)) fail(CODE.EVIDENCE_MISMATCH, `evidence ${field} does not match the envelope`);
  }
  if (e.expectedOriginalState !== API_STATE_CODE[envelope.originalApiState]) {
    fail(CODE.EVIDENCE_MISMATCH, 'evidence expected original state does not match the envelope');
  }
  return freezeDeep(e);
}

// ---------------------------------------------------------------------------------------------
// The injected storage port.
// ---------------------------------------------------------------------------------------------

function storagePort(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    malformed('storage port must be a plain object');
  }
  for (const name of STORAGE_METHODS) {
    const d = Object.getOwnPropertyDescriptor(value, name);
    if (!d || !Object.hasOwn(d, 'value') || typeof d.value !== 'function') {
      malformed(`storage port must provide ${name}()`);
    }
  }
  return value;
}

const PLAN_KEYS = Object.freeze([
  'generation', 'parentGeneration', 'records', 'manifestKey', 'manifestBytes', 'manifestCipherDigest',
  'keyedRoot', 'sessionBindingDigest', 'selectorBytes', 'holdSelectorBytes', 'parentSelectorBytes',
  'resultEvidence', 'escrow', 'mutationHold',
]);

const CANDIDATE_KEYS = Object.freeze([
  'generation', 'records', 'manifestKey', 'manifestBytes', 'manifestCipherDigest', 'keyedRoot',
  'sessionBindingDigest', 'escrow', 'resultEvidence', 'selectorBytes', 'holdSelectorBytes',
  'parentSelectorBytes', 'parentGeneration', 'parentKeyedRoot',
]);

function recordFacts(value, name) {
  const r = strictObject(value, ['recordKey', 'recordKind', 'plaintext', 'ciphertext', 'tag'], name);
  const recordKind = safeInt(r.recordKind, 65535, `${name}.recordKind`);
  if (recordKind < 1 || recordKind > DATA_KIND_COUNT) unsupported(`${name}.recordKind is not a data record kind`);
  return {
    recordKey: bytes(r.recordKey, null, `${name}.recordKey`),
    recordKind,
    plaintext: bytes(r.plaintext, null, `${name}.plaintext`),
    ciphertext: bytes(r.ciphertext, null, `${name}.ciphertext`),
    tag: bytes(r.tag, 16, `${name}.tag`),
  };
}

function manifestFromRecords(records) {
  const entries = records.map((r) => manifestEntry({
    recordKey: r.recordKey,
    recordKind: r.recordKind,
    ciphertextDigest: ciphertextDigest({
      recordKey: r.recordKey, recordKind: r.recordKind, ciphertext: r.ciphertext, tag: r.tag,
    }),
  }));
  return encodeManifest(entries);
}

function selectorFacts(selectorBytes) {
  let decoded;
  try { decoded = decodePlaintext(M2_KIND.GENERATION_SELECTOR, selectorBytes); } catch (e) {
    mismatch(`stored selector is not canonical: ${e.message}`);
  }
  if (decoded.presence !== 1) unsupported('stored selector is a tombstone');
  return decoded;
}

// The minimal session-root-shaped hold facts: the four fields the merged authority rule consumes.
const HOLD_KEYS = Object.freeze(['presence', 'resultStatus', 'parentGeneration', 'parentKeyedRoot']);

function holdFacts(value, name = 'hold') {
  if (value === null || value === undefined) return null;
  if (typeof value !== 'object' || Array.isArray(value)) malformed(`${name} must be null or a plain object`);
  const presence = Object.getOwnPropertyDescriptor(value, 'presence');
  if (!presence || !Object.hasOwn(presence, 'value')) malformed(`${name} must be a plain value`);
  if (presence.value === 0) return Object.freeze({ presence: 0 });
  if (presence.value !== 1) unsupported(`${name} has an invalid presence`);
  const h = strictObject(value, HOLD_KEYS, name);
  const resultStatus = safeInt(h.resultStatus, 255, `${name}.resultStatus`);
  if (resultStatus !== M2_OUTCOME.COMMITTED && resultStatus !== M2_OUTCOME.NOT_COMMITTED
      && resultStatus !== M2_OUTCOME.INDETERMINATE) {
    unsupported(`${name}.resultStatus is not a defined commit outcome`);
  }
  return Object.freeze({
    presence: 1,
    resultStatus,
    parentGeneration: u64(h.parentGeneration, `${name}.parentGeneration`),
    parentKeyedRoot: bytes(h.parentKeyedRoot, 32, `${name}.parentKeyedRoot`),
  });
}

// The complete kind-13 record: every field of the held mutation envelope.
const HOLD_RECORD_KEYS = Object.freeze([
  'presence', 'operationIdentity', 'operation', 'scenario', 'originalApiState',
  'originalAuthorityDigest', 'originalAuthorityReference', 'bindingRef', 'profileDigest',
  'candidateDigest', 'candidateReference', 'componentSetDigest', 'componentSetReference',
  'heldOutputKind', 'heldOutputDigest', 'heldOutputReference', 'expectedSuccessCode',
  'expectedStateAfter', 'reconciliationReference', 'resultStatus', 'parentGeneration', 'parentKeyedRoot',
]);

function holdRecordFacts(value, name = 'hold') {
  if (value === null || value === undefined) return null;
  if (typeof value !== 'object' || Array.isArray(value)) malformed(`${name} must be null or a plain object`);
  const presence = Object.getOwnPropertyDescriptor(value, 'presence');
  if (!presence || !Object.hasOwn(presence, 'value')) malformed(`${name} must be a plain value`);
  if (presence.value === 0) return Object.freeze({ presence: 0 });
  if (presence.value !== 1) unsupported(`${name} has an invalid presence`);
  const h = strictObject(value, HOLD_RECORD_KEYS, name);
  const operationIndex = safeInt(h.operation, 255, `${name}.operation`);
  const scenarioIndex = safeInt(h.scenario, 65535, `${name}.scenario`);
  if (operationIndex < 1 || operationIndex > OPERATIONS.length) unsupported(`${name}.operation is not a defined operation`);
  if (scenarioIndex < 1 || scenarioIndex > SCENARIOS.length) unsupported(`${name}.scenario is not a defined mutation row`);
  const originalApiState = safeInt(h.originalApiState, 255, `${name}.originalApiState`);
  const heldOutputKind = safeInt(h.heldOutputKind, 255, `${name}.heldOutputKind`);
  const expectedSuccessCode = safeInt(h.expectedSuccessCode, 255, `${name}.expectedSuccessCode`);
  const expectedStateAfter = safeInt(h.expectedStateAfter, 255, `${name}.expectedStateAfter`);
  if (originalApiState !== API_STATE_CODE.EMPTY && originalApiState !== API_STATE_CODE.ACTIVE) {
    unsupported(`${name}.originalApiState is not a defined original state`);
  }
  if (heldOutputKind < 1 || heldOutputKind > OUTPUT_KINDS.length) unsupported(`${name}.heldOutputKind is not a defined output kind`);
  if (expectedSuccessCode < 1 || expectedSuccessCode > SUCCESS_CODES.length) unsupported(`${name}.expectedSuccessCode is not a defined success code`);
  if (expectedStateAfter !== API_STATE_CODE.EMPTY && expectedStateAfter !== API_STATE_CODE.ACTIVE) {
    unsupported(`${name}.expectedStateAfter is not a defined state`);
  }
  const resultStatus = safeInt(h.resultStatus, 255, `${name}.resultStatus`);
  if (resultStatus !== M2_OUTCOME.COMMITTED && resultStatus !== M2_OUTCOME.NOT_COMMITTED
      && resultStatus !== M2_OUTCOME.INDETERMINATE) {
    unsupported(`${name}.resultStatus is not a defined commit outcome`);
  }
  const nullable = (v, field) => (v === null || v === undefined ? null : bytes(v, 32, `${name}.${field}`));
  return Object.freeze({
    presence: 1,
    operationIdentity: bytes(h.operationIdentity, 32, `${name}.operationIdentity`),
    operation: operationIndex,
    scenario: scenarioIndex,
    originalApiState,
    originalAuthorityDigest: bytes(h.originalAuthorityDigest, 32, `${name}.originalAuthorityDigest`),
    originalAuthorityReference: bytes(h.originalAuthorityReference, 32, `${name}.originalAuthorityReference`),
    bindingRef: bytes(h.bindingRef, 32, `${name}.bindingRef`),
    profileDigest: bytes(h.profileDigest, 32, `${name}.profileDigest`),
    candidateDigest: bytes(h.candidateDigest, 32, `${name}.candidateDigest`),
    candidateReference: bytes(h.candidateReference, 32, `${name}.candidateReference`),
    componentSetDigest: bytes(h.componentSetDigest, 32, `${name}.componentSetDigest`),
    componentSetReference: bytes(h.componentSetReference, 32, `${name}.componentSetReference`),
    heldOutputKind,
    heldOutputDigest: nullable(h.heldOutputDigest, 'heldOutputDigest'),
    heldOutputReference: nullable(h.heldOutputReference, 'heldOutputReference'),
    expectedSuccessCode,
    expectedStateAfter,
    reconciliationReference: bytes(h.reconciliationReference, 32, `${name}.reconciliationReference`),
    resultStatus,
    parentGeneration: u64(h.parentGeneration, `${name}.parentGeneration`),
    parentKeyedRoot: bytes(h.parentKeyedRoot, 32, `${name}.parentKeyedRoot`),
  });
}

function buildHold(envelope, candidate) {
  return freezeDeep({
    presence: 1,
    operationIdentity: envelope.operationIdentity.value,
    operation: OPERATIONS.indexOf(envelope.operation) + 1,
    scenario: SCENARIOS.indexOf(envelope.scenario) + 1,
    originalApiState: API_STATE_CODE[envelope.originalApiState],
    originalAuthorityDigest: envelope.originalAuthority.digest,
    originalAuthorityReference: envelope.originalAuthority.reference,
    bindingRef: envelope.bindingProfileIdentity.bindingRef,
    profileDigest: envelope.bindingProfileIdentity.profile,
    candidateDigest: envelope.candidate.digest,
    candidateReference: envelope.candidate.reference,
    componentSetDigest: envelope.componentSet.digest,
    componentSetReference: envelope.componentSet.reference,
    heldOutputKind: OUTPUT_KINDS.indexOf(envelope.heldOutput.kind) + 1,
    heldOutputDigest: envelope.heldOutput.digest,
    heldOutputReference: envelope.heldOutput.reference,
    expectedSuccessCode: SUCCESS_CODES.indexOf(envelope.expectedSuccess.code) + 1,
    expectedStateAfter: API_STATE_CODE[envelope.expectedSuccess.stateAfter],
    reconciliationReference: envelope.reconciliationIdentity.reference,
    resultStatus: M2_OUTCOME.INDETERMINATE,
    parentGeneration: candidate.parentGeneration,
    parentKeyedRoot: candidate.parentKeyedRoot,
  });
}

// Reconstruct the closed envelope from a complete kind-13 hold record: the hold is the envelope.
function envelopeFromHold(hold) {
  return buildMutationEnvelope({
    operationIdentity: { value: hold.operationIdentity, assignedBy: 'SS_RS', fresh: true, reusable: false, apRequestIdEqual: false },
    operation: OPERATIONS[hold.operation - 1],
    scenario: SCENARIOS[hold.scenario - 1],
    originalApiState: hold.originalApiState === API_STATE_CODE.ACTIVE ? 'ACTIVE' : 'EMPTY',
    originalAuthority: { digest: hold.originalAuthorityDigest, reference: hold.originalAuthorityReference },
    bindingProfileIdentity: { bindingRef: hold.bindingRef, profile: hold.profileDigest },
    candidate: { digest: hold.candidateDigest, reference: hold.candidateReference },
    componentSet: {
      digest: hold.componentSetDigest,
      reference: hold.componentSetReference,
      entries: ROW_BY_SCENARIO.get(SCENARIOS[hold.scenario - 1]).components.map((c) => ({ ...c })),
    },
    heldOutput: {
      kind: OUTPUT_KINDS[hold.heldOutputKind - 1],
      digest: hold.heldOutputDigest,
      reference: hold.heldOutputReference,
    },
    expectedSuccess: {
      code: SUCCESS_CODES[hold.expectedSuccessCode - 1],
      stateAfter: hold.expectedStateAfter === API_STATE_CODE.ACTIVE ? 'ACTIVE' : 'EMPTY',
    },
    reconciliationIdentity: { reference: hold.reconciliationReference, owner: 'SS_RS' },
  });
}

function candidateFacts(value, manifestRootKey) {
  const c = strictObject(value, CANDIDATE_KEYS, 'candidate');
  const generation = u64(c.generation, 'candidate.generation');
  if (generation === 0n) malformed('candidate.generation is zero');
  if (!Array.isArray(c.records) || c.records.length !== DATA_KIND_COUNT) {
    unsupported(`candidate must stage exactly ${DATA_KIND_COUNT} data records`);
  }
  const records = c.records.map((r, i) => recordFacts(r, `candidate.records[${i}]`));
  if (new Set(records.map((r) => r.recordKind)).size !== DATA_KIND_COUNT) {
    unsupported('candidate stages a duplicate data record kind');
  }
  const manifestBytes = bytes(c.manifestBytes, null, 'candidate.manifestBytes');
  const manifestKey = bytes(c.manifestKey, null, 'candidate.manifestKey');
  const manifestCipherDigest = bytes(c.manifestCipherDigest, 32, 'candidate.manifestCipherDigest');
  const keyedRoot = bytes(c.keyedRoot, 32, 'candidate.keyedRoot');
  const parentGeneration = u64(c.parentGeneration, 'candidate.parentGeneration');
  if (parentGeneration === 0n) malformed('candidate.parentGeneration is zero');
  const parentKeyedRoot = bytes(c.parentKeyedRoot, 32, 'candidate.parentKeyedRoot');
  const parentSelectorBytes = bytes(c.parentSelectorBytes, null, 'candidate.parentSelectorBytes');
  const selectorBytes = bytes(c.selectorBytes, null, 'candidate.selectorBytes');
  const holdSelectorBytes = bytes(c.holdSelectorBytes, null, 'candidate.holdSelectorBytes');
  const sessionBindingDigest = c.sessionBindingDigest === null || c.sessionBindingDigest === undefined
    ? null : bytes(c.sessionBindingDigest, 32, 'candidate.sessionBindingDigest');
  let escrow = null;
  if (c.escrow !== null && c.escrow !== undefined) {
    const e = strictObject(c.escrow, ['kind', 'digest', 'reference', 'output'], 'candidate.escrow');
    const kind = text(e.kind, OUTPUT_KINDS, 'candidate.escrow.kind');
    if (kind === 'NONE') unsupported('a NONE escrow is expressed as a null escrow');
    escrow = {
      kind,
      digest: bytes(e.digest, 32, 'candidate.escrow.digest'),
      reference: bytes(e.reference, 32, 'candidate.escrow.reference'),
      output: e.output === null || e.output === undefined ? null : bytes(e.output, null, 'candidate.escrow.output'),
    };
  }
  let rebuilt;
  try { rebuilt = manifestFromRecords(records); } catch (e) {
    mismatch(`candidate records do not form a complete manifest: ${e.message}`);
  }
  if (!equal(rebuilt, manifestBytes)) mismatch('candidate records do not reproduce the candidate manifest bytes');
  if (!equal(computeKeyedRoot({ manifestRootKey, manifestKey, generation, manifestBytes }), keyedRoot)) {
    mismatch('candidate keyed root does not reproduce from its own manifest');
  }

  return freezeDeep({
    generation, records, manifestKey, manifestBytes, manifestCipherDigest, keyedRoot,
    sessionBindingDigest, escrow,
    resultEvidence: evidenceFacts(c.resultEvidence, 'candidate.resultEvidence'),
    selectorBytes, holdSelectorBytes, parentSelectorBytes, parentGeneration, parentKeyedRoot,
  });
}

/**
 * The deterministic ordered step plan for a row and outcome. Inspectable without executing anything.
 * `phase` is `ORIGINAL` (the default) or `RECONCILIATION`.
 */
export function mutationSteps(input) {
  const s = strictObject(input, ['envelope', 'candidate', 'outcome', 'phase'], 'step plan input');
  const envelope = buildMutationEnvelope(s.envelope);
  const outcome = outcomeValue(s.outcome);
  const phase = s.phase === undefined ? 'ORIGINAL' : s.phase;
  if (phase !== 'ORIGINAL' && phase !== 'RECONCILIATION') unsupported('phase is not ORIGINAL or RECONCILIATION');
  const plan = strictObject(s.candidate, PLAN_KEYS, 'candidate plan');
  const generation = u64(plan.generation, 'candidate.generation');
  const parentGeneration = u64(plan.parentGeneration, 'candidate.parentGeneration');
  const row = ROW_BY_SCENARIO.get(envelope.scenario);
  const optionalBytes = (v, name) => (v === null || v === undefined ? null : bytes(v, null, name));
  const selectorBytes = optionalBytes(plan.selectorBytes, 'candidate.selectorBytes');
  const holdSelectorBytes = optionalBytes(plan.holdSelectorBytes, 'candidate.holdSelectorBytes');
  const parentSelectorBytes = optionalBytes(plan.parentSelectorBytes, 'candidate.parentSelectorBytes');
  const requireBytes = (value, name) => {
    if (value === null) malformed(`${name} is required for this step plan`);
    return value;
  };
  const records = Array.isArray(plan.records) ? plan.records : [];
  const hasOutput = row.outputKind !== 'NONE';

  const raw = [];
  const push = (boundary, kind, payload) => raw.push({ boundary, kind, payload: freezeDeep(payload) });

  if (phase === 'ORIGINAL') {
    push('BEFORE_STAGING', 'VALIDATE_ENVELOPE', { scenario: envelope.scenario });
    push('AFTER_CANDIDATE_COMPUTATION', 'COMPUTE_CANDIDATE', { generation });
    push('AFTER_LOCAL_STAGING', 'STAGE_LOCAL', { generation });
    push('BEFORE_RS_REQUEST', 'OPEN_RS_REQUEST', { candidateReference: envelope.candidate.reference });
    for (const record of records) {
      push('DURING_RS_WORK', 'STAGE_DATA', {
        generation,
        recordKey: record.recordKey,
        recordKind: record.recordKind,
        plaintext: record.plaintext,
        ciphertext: record.ciphertext,
        tag: record.tag,
      });
    }
    push('DURING_RS_WORK', 'STAGE_MANIFEST', {
      generation,
      manifestKey: plan.manifestKey,
      manifestBytes: plan.manifestBytes,
      manifestCipherDigest: plan.manifestCipherDigest,
      keyedRoot: plan.keyedRoot,
      sessionBindingDigest: plan.sessionBindingDigest,
    });
    push('DURING_RS_WORK', 'STAGE_EVIDENCE', { generation, evidence: plan.resultEvidence });
    if (hasOutput) push('DURING_RS_WORK', 'STAGE_ESCROW', { generation, escrow: plan.escrow });
    if (outcome === M2_OUTCOME.COMMITTED) {
      push('AFTER_DURABLE_COMMIT_BEFORE_RESPONSE', 'REPLACE_SELECTOR', {
        selectorBytes: requireBytes(selectorBytes, 'candidate.selectorBytes'),
        resolveHoldGeneration: generation,
      });
      push('AFTER_AUTHORITY_SELECTION_BEFORE_OUTPUT_RESPONSE', 'CONFIRM_AUTHORITY', { generation });
      if (hasOutput) {
        push('DURING_ESCROW_OUTPUT_RESPONSE', 'RELEASE_ESCROW',
          { generation, operationIdentity: envelope.operationIdentity.value });
      }
      push('AFTER_OUTPUT_RESPONSE_LOSS', 'REPORT_RESULT', { commitOutcome: OUTCOME_NAME[outcome] });
    } else if (outcome === M2_OUTCOME.NOT_COMMITTED) {
      push('DURING_RS_WORK', 'CLEAR_CANDIDATE', { generation });
      push('AFTER_NOT_COMMITTED', 'REPORT_RESULT', { commitOutcome: OUTCOME_NAME[outcome] });
    } else {
      push('DURING_RS_WORK', 'WRITE_HOLD',
        { generation, hold: plan.mutationHold === undefined ? null : plan.mutationHold });
      push('AFTER_INDETERMINATE', 'REPLACE_SELECTOR', {
        selectorBytes: requireBytes(holdSelectorBytes, 'candidate.holdSelectorBytes'),
        resolveHoldGeneration: null,
      });
      push('AFTER_INDETERMINATE', 'REPORT_RESULT', { commitOutcome: OUTCOME_NAME[outcome] });
    }
  } else if (outcome === M2_OUTCOME.COMMITTED) {
    push('DURING_RECONCILIATION', 'REPLACE_SELECTOR', {
      selectorBytes: requireBytes(selectorBytes, 'candidate.selectorBytes'),
      resolveHoldGeneration: generation,
    });
    // Every row ends the reconciliation with the local emission call: it is the step that releases
    // the retained response hold. A row with no escrow releases nothing but still resolves the hold.
    push('DURING_ESCROW_OUTPUT_RESPONSE', 'RELEASE_ESCROW',
      { generation, operationIdentity: envelope.operationIdentity.value });
    push('AFTER_OUTPUT_RESPONSE_LOSS', 'REPORT_RESULT', { commitOutcome: OUTCOME_NAME[outcome] });
  } else if (outcome === M2_OUTCOME.NOT_COMMITTED) {
    // The stored selector must stop naming the candidate before the candidate's bytes are discarded:
    // deleting a generation the selector still names would expose a mixture to any reader. Restoring
    // the parent selector first is still one atomic authority change, and it names the old authority.
    push('DURING_RECONCILIATION', 'REPLACE_SELECTOR', {
      selectorBytes: requireBytes(parentSelectorBytes, 'candidate.parentSelectorBytes'),
      resolveHoldGeneration: null,
    });
    push('DURING_RECONCILIATION', 'CLEAR_CANDIDATE', { generation });
    push('AFTER_NOT_COMMITTED', 'REPORT_RESULT', { commitOutcome: OUTCOME_NAME[outcome] });
  } else {
    push('DURING_RECONCILIATION', 'CONFIRM_AUTHORITY', { generation: parentGeneration });
    push('AFTER_INDETERMINATE', 'REPORT_RESULT', { commitOutcome: OUTCOME_NAME[outcome] });
  }

  return Object.freeze(raw.map((step, index) => freezeDeep({
    index, boundary: step.boundary, kind: step.kind, payload: step.payload,
  })));
}

function planCandidate(envelope, candidate, outcome) {
  return freezeDeep({
    generation: candidate.generation,
    parentGeneration: candidate.parentGeneration,
    records: candidate.records,
    manifestKey: candidate.manifestKey,
    manifestBytes: candidate.manifestBytes,
    manifestCipherDigest: candidate.manifestCipherDigest,
    keyedRoot: candidate.keyedRoot,
    sessionBindingDigest: candidate.sessionBindingDigest,
    selectorBytes: candidate.selectorBytes,
    holdSelectorBytes: candidate.holdSelectorBytes,
    parentSelectorBytes: candidate.parentSelectorBytes,
    resultEvidence: candidate.resultEvidence,
    escrow: candidate.escrow,
    mutationHold: outcome === M2_OUTCOME.INDETERMINATE ? buildHold(envelope, candidate) : null,
  });
}

function resultFor(envelope, candidate, outcome, row) {
  const committed = outcome === M2_OUTCOME.COMMITTED;
  const indeterminate = outcome === M2_OUTCOME.INDETERMINATE;
  return freezeDeep({
    commitOutcome: OUTCOME_NAME[outcome],
    resultKind: committed ? 'SUCCESS' : OUTCOME_NAME[outcome],
    state: committed ? row.stateAfterCommitted : (indeterminate ? 'RECONCILIATION_REQUIRED' : row.stateBefore),
    originalStateBefore: envelope.originalApiState,
    generation: committed ? candidate.generation : candidate.parentGeneration,
    keyedRoot: committed ? candidate.keyedRoot : candidate.parentKeyedRoot,
    reconciliationRef: indeterminate ? envelope.reconciliationIdentity.reference : null,
    output: committed && candidate.escrow !== null ? candidate.escrow.output : null,
    holds: indeterminate ? 1 : 0,
  });
}

// After any fault the stored state must be exactly the complete old or exactly the complete new
// generation. When the authority did not move, SS retains exactly one immutable hold as internal
// reconciliation evidence. The module never guesses an outcome from SS memory.
async function establishRecoveryEvidence(storage, manifestRootKey, envelope, candidate) {
  let classification;
  try {
    classification = await classifyAuthority({
      storage,
      manifestRootKey,
      oldGeneration: candidate.parentGeneration,
      newGeneration: candidate.generation,
    });
  } catch {
    return; // A mixture: leave the bytes untouched; the caller re-reads and fails closed.
  }
  if (classification.authority === 'COMPLETE_NEW') return;
  try {
    await storage.apply(freezeDeep({
      index: -1,
      boundary: 'AFTER_INDETERMINATE',
      kind: 'WRITE_HOLD',
      payload: { generation: candidate.generation, hold: buildHold(envelope, candidate) },
    }));
  } catch { /* the hold is best-effort here; the caller re-reads storage and fails closed */ }
}

/**
 * Execute one C-MUT logical mutation as a single atomic transaction.
 * The result is returned only when the complete plan succeeded. Any fault propagates, and storage is
 * left holding exactly the complete old or exactly the complete new generation.
 */
export async function runMutation(input) {
  const s = strictObject(input, ['storage', 'manifestRootKey', 'envelope', 'candidate', 'outcome'], 'mutation input');
  const storage = storagePort(s.storage);
  const manifestRootKey = bytes(s.manifestRootKey, 32, 'manifestRootKey');
  const envelope = buildMutationEnvelope(s.envelope);
  const candidate = candidateFacts(s.candidate, manifestRootKey);
  const outcome = outcomeValue(s.outcome);
  const row = ROW_BY_SCENARIO.get(envelope.scenario);

  const authenticated = validateCommitResultEvidence({ evidence: candidate.resultEvidence, envelope });
  if (authenticated.outcome !== outcome) {
    fail(CODE.EVIDENCE_MISMATCH, 'authenticated commit-result evidence does not carry the requested outcome');
  }

  const memoryHold = holdRecordFacts(await storage.readMemoryHold());
  if (memoryHold !== null) {
    fail(CODE.BLIND_RETRY,
      'a mutation request arrived while an unresolved immutable hold exists; the API state is '
      + 'RECONCILIATION_REQUIRED and blind retry is forbidden');
  }

  const storedSelector = await storage.readSelector();
  if (storedSelector !== null && storedSelector !== undefined) {
    const current = selectorFacts(storedSelector);
    // The durable selector is authority, not the live memory hold: after an SS restart the hold may be
    // gone while the stored selector still demands reconciliation, and a blind retry stays forbidden.
    if (current.state === SELECTOR_STATE.RECONCILIATION_REQUIRED) {
      fail(CODE.BLIND_RETRY,
        'the stored selector is in RECONCILIATION_REQUIRED; the unresolved mutation must be reconciled '
        + 'before a new request is accepted');
    }
    if (current.generation !== candidate.parentGeneration && envelope.scenario !== 'CAPI-S017') {
      fail(CODE.STALE_PARENT,
        'the stored selector names a physical generation that is not the candidate parent');
    }
  }

  let steps;
  try {
    steps = mutationSteps({ envelope, candidate: planCandidate(envelope, candidate, outcome), outcome, phase: 'ORIGINAL' });
  } catch (e) {
    malformed(`the step plan could not be formed: ${e.message}`);
  }

  try {
    for (const step of steps) {
      if (MEMORY_ONLY.has(step.kind)) continue;
      await storage.apply(step);
    }
  } catch (cause) {
    await establishRecoveryEvidence(storage, manifestRootKey, envelope, candidate);
    throw cause;
  }
  return resultFor(envelope, candidate, outcome, row);
}

function generationFactsFromStorage(value, generation, manifestRootKey) {
  if (value === null || value === undefined) {
    partial(`the selector names generation ${generation}, which is not stored`);
  }
  if (typeof value !== 'object' || Array.isArray(value)) partial('a stored generation must be a plain object');
  const stored = Array.isArray(value.records) ? value.records : [];
  if (stored.length !== DATA_KIND_COUNT) {
    partial(`generation ${generation} does not store exactly ${DATA_KIND_COUNT} complete data records`);
  }
  let records;
  try { records = stored.map((r, i) => recordFacts(r, `generation ${generation}.records[${i}]`)); } catch (e) {
    partial(`generation ${generation} stores a malformed data record: ${e.message}`);
  }
  const manifestBytes = bytes(value.manifestBytes, null, 'stored manifestBytes');
  let rebuilt;
  try { rebuilt = manifestFromRecords(records); } catch (e) {
    partial(`generation ${generation} records do not form a complete manifest: ${e.message}`);
  }
  if (!equal(rebuilt, manifestBytes)) {
    partial(`generation ${generation} records do not reproduce its stored manifest bytes`);
  }
  const manifestKey = bytes(value.manifestKey, null, 'stored manifestKey');
  const root = computeKeyedRoot({ manifestRootKey, manifestKey, generation, manifestBytes });
  const declaredRoot = bytes(value.keyedRoot, 32, 'stored keyedRoot');
  if (!equal(root, declaredRoot)) {
    partial(`generation ${generation} declares a keyed root that its own manifest does not produce`);
  }
  return {
    generation,
    manifestKey,
    manifestBytes,
    manifestCipherDigest: bytes(value.manifestCipherDigest, 32, 'stored manifestCipherDigest'),
    keyedRoot: root,
    mutationHold: holdFacts(value.mutationHold, 'stored mutationHold'),
    sessionBindingDigest: value.sessionBindingDigest === null || value.sessionBindingDigest === undefined
      ? null : bytes(value.sessionBindingDigest, 32, 'stored sessionBindingDigest'),
    escrow: value.escrow === null || value.escrow === undefined ? null : value.escrow,
    resultEvidence: value.resultEvidence === null || value.resultEvidence === undefined ? null : value.resultEvidence,
  };
}

function authorityTuple(facts) {
  return {
    generation: facts.generation,
    manifestKey: facts.manifestKey,
    manifestBytes: facts.manifestBytes,
    manifestCipherDigest: facts.manifestCipherDigest,
    keyedRoot: facts.keyedRoot,
    mutationHold: facts.mutationHold,
    sessionBindingDigest: facts.sessionBindingDigest,
  };
}

/**
 * The acceptance oracle. Read the stored selector and the generation it names, recompute the keyed
 * root from the literal stored manifest bytes, and report exactly `EMPTY`, `COMPLETE_OLD` or
 * `COMPLETE_NEW`. A mixture, a partial generation or an inconsistent selector fails closed as
 * `PARTIAL_APPLICATION` and is never reported as a complete authority.
 */
export async function classifyAuthority(input) {
  const s = strictObject(input, ['storage', 'manifestRootKey', 'oldGeneration', 'newGeneration'], 'readback input');
  const storage = storagePort(s.storage);
  const manifestRootKey = bytes(s.manifestRootKey, 32, 'manifestRootKey');
  const oldGeneration = s.oldGeneration === null || s.oldGeneration === undefined
    ? null : u64(s.oldGeneration, 'oldGeneration');
  const newGeneration = s.newGeneration === null || s.newGeneration === undefined
    ? null : u64(s.newGeneration, 'newGeneration');
  const storedSelector = await storage.readSelector();
  if (storedSelector === null || storedSelector === undefined) {
    if (oldGeneration !== null) partial('no stored selector exists although an old authority was expected');
    return freezeDeep({ authority: 'EMPTY', generation: null, keyedRoot: null, state: 1, held: false });
  }
  const selector = selectorFacts(storedSelector);
  const selected = generationFactsFromStorage(
    await storage.readGeneration(selector.generation), selector.generation, manifestRootKey,
  );
  let candidate = null;
  if (selector.candidateGeneration !== selector.generation) {
    candidate = generationFactsFromStorage(
      await storage.readGeneration(selector.candidateGeneration), selector.candidateGeneration, manifestRootKey,
    );
  }
  try {
    validateAuthority({
      selector: storedSelector,
      manifestRootKey,
      selected: authorityTuple(selected),
      candidate: candidate === null ? null : authorityTuple(candidate),
    });
  } catch (e) {
    partial(`the stored selector is not consistent with the generation it names: ${e.message}`);
  }
  if (selector.generation === newGeneration && selected.resultEvidence === null) {
    partial('the new authority names a generation that carries no committed result evidence');
  }
  const authority = newGeneration !== null && selector.generation === newGeneration ? 'COMPLETE_NEW'
    : (oldGeneration !== null && selector.generation === oldGeneration ? 'COMPLETE_OLD' : null);
  if (authority === null) {
    partial(`the stored selector names generation ${selector.generation}, which is neither the expected old nor the expected new authority`);
  }
  return freezeDeep({
    authority,
    generation: selector.generation,
    keyedRoot: selected.keyedRoot,
    state: selector.state,
    held: selector.state === SELECTOR_STATE.RECONCILIATION_REQUIRED,
  });
}

function sameTupleSelector(facts, state) {
  const digest = manifestKeyDigest(facts.manifestKey);
  return {
    presence: 1,
    generation: facts.generation,
    manifestKeyDigest: digest,
    manifestCipherDigest: facts.manifestCipherDigest,
    keyedRoot: facts.keyedRoot,
    state,
    candidateGeneration: facts.generation,
    candidateManifestKey: facts.manifestKey,
    candidateManifestKeyDigest: digest,
    candidateManifestCipherDigest: facts.manifestCipherDigest,
    candidateKeyedRoot: facts.keyedRoot,
  };
}

/**
 * Reconcile one unresolved hold from authenticated evidence. The module selects an already-staged
 * candidate once, never replays the transition, never regenerates a security-sensitive byte, and
 * never guesses. A reference or evidence mismatch rejects without mutation and leaves the hold
 * logically unchanged.
 */
export async function reconcileIndeterminate(input) {
  const s = strictObject(input, ['storage', 'manifestRootKey', 'hold', 'evidence', 'reference'], 'reconciliation input');
  const storage = storagePort(s.storage);
  const manifestRootKey = bytes(s.manifestRootKey, 32, 'manifestRootKey');
  const reference = nonzero(s.reference, 'reference');
  const held = holdRecordFacts(await storage.readMemoryHold());
  if (held === null) {
    // Without a hold only the durable selector can say whether anything is pending.
    const durable = await storage.readSelector();
    if (durable !== null && durable !== undefined
      && selectorFacts(durable).state === SELECTOR_STATE.RECONCILIATION_REQUIRED) {
      fail(CODE.HOLD_UNAVAILABLE,
        'the stored selector is in RECONCILIATION_REQUIRED although no hold is available to this '
        + 'profile; the unresolved mutation cannot be reconciled from here');
    }
    fail(CODE.NO_RECONCILIATION_PENDING, 'no reconciliation is pending for this profile');
  }
  const supplied = holdRecordFacts(s.hold);
  if (supplied === null || supplied.presence !== 1) malformed('the supplied hold must be present');
  if (!equal(supplied.reconciliationReference, reference)) {
    fail(CODE.REFERENCE_MISMATCH, 'the supplied reconciliation reference is not the held reference');
  }
  for (const field of ['operationIdentity', 'originalAuthorityDigest', 'originalAuthorityReference',
    'candidateDigest', 'candidateReference', 'componentSetDigest', 'componentSetReference',
    'bindingRef', 'profileDigest', 'parentGeneration', 'parentKeyedRoot', 'heldOutputKind',
    'expectedSuccessCode', 'expectedStateAfter', 'reconciliationReference']) {
    const a = supplied[field];
    const b = held[field];
    const same = (a instanceof Uint8Array || b instanceof Uint8Array) ? equal(a, b) : a === b;
    if (!same) fail(CODE.EVIDENCE_MISMATCH, `the supplied hold ${field} does not match the held envelope`);
  }
  const evidence = evidenceFacts(s.evidence, 'reconciliation evidence');
  for (const field of ['operationIdentity', 'originalAuthorityDigest', 'originalAuthorityReference',
    'candidateDigest', 'candidateReference', 'bindingRef']) {
    if (!equal(evidence[field], held[field])) {
      fail(CODE.EVIDENCE_MISMATCH, `reconciliation evidence ${field} does not match the held envelope`);
    }
  }
  // The held envelope names the component set; the evidence names the mutation set it was formed over.
  if (!equal(evidence.mutationSetDigest, held.componentSetDigest)) {
    fail(CODE.EVIDENCE_MISMATCH, 'reconciliation evidence mutation-set digest does not match the held envelope');
  }
  if (!equal(evidence.mutationSetReference, held.componentSetReference)) {
    fail(CODE.EVIDENCE_MISMATCH, 'reconciliation evidence mutation-set reference does not match the held envelope');
  }
  if (!equal(evidence.profile, held.profileDigest)) {
    fail(CODE.EVIDENCE_MISMATCH, 'reconciliation evidence profile does not match the held envelope');
  }
  if (evidence.expectedOriginalState !== held.originalApiState) {
    fail(CODE.EVIDENCE_MISMATCH, 'reconciliation evidence expected original state does not match the held envelope');
  }
  const reconciliationEnvelope = envelopeFromHold(held);
  const row = ROW_BY_SCENARIO.get(reconciliationEnvelope.scenario);

  if (evidence.outcome === M2_OUTCOME.INDETERMINATE) {
    return freezeDeep({
      reconciliation: 'INDETERMINATE', resultKind: 'INDETERMINATE', state: 'RECONCILIATION_REQUIRED',
      authority: 'COMPLETE_OLD', output: null, holds: 1,
    });
  }

  const storedSelector = await storage.readSelector();
  if (storedSelector === null || storedSelector === undefined) {
    partial('no stored selector exists although one hold is pending');
  }
  const selector = selectorFacts(storedSelector);
  // The generation this reconciliation may clear or select is the candidate the STORED hold selector
  // binds, never whatever candidateGeneration some other selector state happens to carry. A selector
  // that names its own generation as candidate, or that is not in RECONCILIATION_REQUIRED, is not a
  // pending hold: reconciling from it would delete or re-select the live authority.
  if (selector.generation !== held.parentGeneration
    || selector.candidateGeneration === selector.generation
    || selector.state !== SELECTOR_STATE.RECONCILIATION_REQUIRED) {
    fail(CODE.NO_RECONCILIATION_PENDING,
      'the stored selector does not bind an unresolved candidate to the held parent generation; the '
      + 'hold is not reconcilable from this stored state');
  }

  if (evidence.outcome === M2_OUTCOME.NOT_COMMITTED) {
    const parent = generationFactsFromStorage(
      await storage.readGeneration(held.parentGeneration), held.parentGeneration, manifestRootKey,
    );
    const parentSelectorBytes = encodePlaintext(M2_KIND.GENERATION_SELECTOR, sameTupleSelector(parent, held.originalApiState));
    const steps = mutationSteps({
      envelope: reconciliationEnvelope,
      candidate: {
        generation: selector.candidateGeneration, parentGeneration: held.parentGeneration, records: [],
        manifestKey: null, manifestBytes: null, manifestCipherDigest: null, selectorBytes: null,
        holdSelectorBytes: null, parentSelectorBytes, resultEvidence: null, escrow: null,
        keyedRoot: null, sessionBindingDigest: null, mutationHold: null,
      },
      outcome: M2_OUTCOME.NOT_COMMITTED, phase: 'RECONCILIATION',
    });
    for (const step of steps) {
      if (MEMORY_ONLY.has(step.kind)) continue;
      await storage.apply(step);
    }
    return freezeDeep({
      reconciliation: 'NOT_COMMITTED', resultKind: 'NOT_COMMITTED',
      state: held.originalApiState === API_STATE_CODE.EMPTY ? 'EMPTY' : 'ACTIVE',
      authority: 'COMPLETE_OLD', output: null, holds: 0,
    });
  }

  const candidate = generationFactsFromStorage(
    await storage.readGeneration(selector.candidateGeneration), selector.candidateGeneration, manifestRootKey,
  );
  const selectorBytes = encodePlaintext(M2_KIND.GENERATION_SELECTOR,
    sameTupleSelector(candidate, SELECTOR_STATE.ACTIVE));
  const escrow = candidate.escrow === null || candidate.escrow === undefined ? null : candidate.escrow;
  const steps = mutationSteps({
    envelope: reconciliationEnvelope,
    candidate: {
      generation: selector.candidateGeneration, parentGeneration: held.parentGeneration, records: [],
      manifestKey: null, manifestBytes: null, manifestCipherDigest: null, selectorBytes,
      holdSelectorBytes: null, parentSelectorBytes: null, resultEvidence: null, escrow,
      keyedRoot: null, sessionBindingDigest: null, mutationHold: null,
    },
    outcome: M2_OUTCOME.COMMITTED, phase: 'RECONCILIATION',
  });
  for (const step of steps) {
    if (MEMORY_ONLY.has(step.kind)) continue;
    await storage.apply(step);
  }
  return freezeDeep({
    reconciliation: 'RECONCILED_COMMITTED', resultKind: 'SUCCESS',
    state: row.stateAfterCommitted, authority: 'COMPLETE_NEW',
    output: escrow === null ? null : escrow.output, holds: 0,
  });
}
