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
import { sha256 } from '@noble/hashes/sha256';
import { M2_KIND, M2_SCOPE, decodePlaintext, encodePlaintext, decodeRecordKey } from './session-codec.js';
import {
  validateAuthority, computeKeyedRoot, ciphertextDigest, manifestEntry, encodeManifest,
  manifestKeyDigest, encodeManifestKey,
} from './session-root.js';

const TE = new TextEncoder();

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

const STORAGE_METHODS = Object.freeze(['apply', 'readSelector', 'readGeneration', 'readMemoryHold', 'readGenerationNumbers']);

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
  // F2: the typed code a storage port throws when the stored selector envelope is not byte-identical
  // to the `expectedSelectorBytes` of a REPLACE_SELECTOR; I-TXN rethrows it unchanged.
  SELECTOR_PRECONDITION_FAILED: 'SELECTOR_PRECONDITION_FAILED',
  // I-RESTART: the two exact error codes of `loadBoundHold`. An authenticated contradiction (fail
  // closed, never the routine `CAPI-S024` continuation) and an unavailable readback.
  BOUND_HOLD_INVALID: 'BOUND_HOLD_INVALID',
  READBACK_UNAVAILABLE: 'READBACK_UNAVAILABLE',
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
  SELECTOR_PRECONDITION_FAILED: 'SELECTOR_PRECONDITION_FAILED',
  // I-RESTART: the loader's two codes, single-sourced from the exported constant surface.
  BOUND_HOLD_INVALID: M2_TXN.BOUND_HOLD_INVALID,
  READBACK_UNAVAILABLE: M2_TXN.READBACK_UNAVAILABLE,
});

const isPreconditionFailure = (e) => e !== null && typeof e === 'object'
  && e.code === CODE.SELECTOR_PRECONDITION_FAILED;

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
  'resultEvidence', 'escrow', 'mutationHold', 'expectedSelectorBytes',
]);
const INSPECTION_PLAN_KEYS = Object.freeze(PLAN_KEYS.filter((k) => k !== 'expectedSelectorBytes'));

// F2/F3: `readSelector()` returns null (no stored selector) or `{ plaintext, envelope }`: the
// AEAD-verified, canonically re-encoded selector plaintext and, opaquely, the exact stored C-FMT
// envelope bytes (nonce, ciphertext and tag) that every later REPLACE_SELECTOR of the same request
// carries as `expectedSelectorBytes`. The envelope is never interpreted here, only compared by the port.
async function readStoredSelector(storage) {
  return storedSelectorValue(await storage.readSelector());
}
const envelopeOf = (stored) => (stored === null ? null : stored.envelope);

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
  // A conformant port stores the complete C-FMT kind-13 record in the candidate generation; its
  // authority facts are the same four fields, so the complete record is projected onto them.
  if (isCompleteHold(value)) {
    const record = holdRecordFacts(value, name);
    return Object.freeze({
      presence: 1,
      resultStatus: record.resultStatus,
      parentGeneration: record.parentGeneration,
      parentKeyedRoot: record.parentKeyedRoot,
    });
  }
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
// Rule-only hold locator (C-FMT draft retainedHoldLookup): the SS memory copy of a hold carries,
// beside the unchanged v2 kind-13 fields, the authenticated record key under which that kind-13
// record is stored. No plaintext field is added; the locator is derived from that key.
const HOLD_MEMORY_KEYS = Object.freeze([...HOLD_RECORD_KEYS, 'recordKey']);
const HOLD_COMPARE = HOLD_RECORD_KEYS.filter((k) => k !== 'presence');
const isCompleteHold = (value) => {
  const n = Reflect.ownKeys(value).length;
  return n === HOLD_RECORD_KEYS.length || n === HOLD_MEMORY_KEYS.length;
};

// Derive the candidate generation and its exact kind-16 manifest key from the canonical kind-13
// record key of the hold: same writeGeneration, scope, localContextId and secureSessionIdentity,
// record kind 16 and empty objectId. Anything else is not a hold locator.
function holdLocatorFromKey(recordKey, name) {
  let decoded;
  try { decoded = decodeRecordKey(recordKey); } catch (e) {
    malformed(`${name}.recordKey is not a canonical record key: ${e.message}`);
  }
  if (decoded.recordKind !== M2_KIND.MUTATION_HOLD) mismatch(`${name}.recordKey is not a kind-13 MUTATION_HOLD key`);
  return {
    holdRecordKey: Uint8Array.prototype.slice.call(recordKey),
    candidateGeneration: decoded.writeGeneration,
    candidateManifestKey: encodeManifestKey({
      localContextId: decoded.localContextId,
      scope: decoded.scope,
      secureSessionIdentity: decoded.secureSessionIdentity,
      writeGeneration: decoded.writeGeneration,
    }),
  };
}

function holdRecordKeyOf(records) {
  if (!Array.isArray(records)) return null;
  const r = records.find((x) => x !== null && typeof x === 'object' && x.recordKind === M2_KIND.MUTATION_HOLD);
  return r === undefined ? null : r.recordKey;
}

function holdRecordFacts(value, name = 'hold') {
  if (value === null || value === undefined) return null;
  if (typeof value !== 'object' || Array.isArray(value)) malformed(`${name} must be null or a plain object`);
  const presence = Object.getOwnPropertyDescriptor(value, 'presence');
  if (!presence || !Object.hasOwn(presence, 'value')) malformed(`${name} must be a plain value`);
  if (presence.value === 0) return Object.freeze({ presence: 0 });
  if (presence.value !== 1) unsupported(`${name} has an invalid presence`);
  const withKey = Reflect.ownKeys(value).length === HOLD_MEMORY_KEYS.length;
  const h = strictObject(value, withKey ? HOLD_MEMORY_KEYS : HOLD_RECORD_KEYS, name);
  const locator = withKey
    ? holdLocatorFromKey(bytes(h.recordKey, null, `${name}.recordKey`), name)
    : { holdRecordKey: null, candidateGeneration: null, candidateManifestKey: null };
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
    ...locator,
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
  const withExpected = s.candidate !== null && typeof s.candidate === 'object'
    && Object.hasOwn(s.candidate, 'expectedSelectorBytes');
  const plan = strictObject(s.candidate, withExpected ? PLAN_KEYS : INSPECTION_PLAN_KEYS, 'candidate plan');
  const generation = u64(plan.generation, 'candidate.generation');
  const parentGeneration = u64(plan.parentGeneration, 'candidate.parentGeneration');
  const row = ROW_BY_SCENARIO.get(envelope.scenario);
  const optionalBytes = (v, name) => (v === null || v === undefined ? null : bytes(v, null, name));
  const selectorBytes = optionalBytes(plan.selectorBytes, 'candidate.selectorBytes');
  const holdSelectorBytes = optionalBytes(plan.holdSelectorBytes, 'candidate.holdSelectorBytes');
  const parentSelectorBytes = optionalBytes(plan.parentSelectorBytes, 'candidate.parentSelectorBytes');
  // F2: the stored selector envelope the request read when it was planned; null means no selector.
  const expectedSelectorBytes = withExpected
    ? optionalBytes(plan.expectedSelectorBytes, 'candidate.expectedSelectorBytes') : null;
  // The CAS member of every REPLACE_SELECTOR payload this module executes; absent only from a plan
  // formed for inspection without it.
  const cas = withExpected ? { expectedSelectorBytes } : {};
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
        resolveHoldGeneration: null,
        ...cas,
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
      push('DURING_RS_WORK', 'WRITE_HOLD', {
        generation,
        hold: plan.mutationHold === undefined ? null : plan.mutationHold,
        holdRecordKey: holdRecordKeyOf(records),
      });
      push('AFTER_INDETERMINATE', 'REPLACE_SELECTOR', {
        selectorBytes: requireBytes(holdSelectorBytes, 'candidate.holdSelectorBytes'),
        resolveHoldGeneration: null,
        ...cas,
      });
      push('AFTER_INDETERMINATE', 'REPORT_RESULT', { commitOutcome: OUTCOME_NAME[outcome] });
    }
  } else if (outcome === M2_OUTCOME.COMMITTED) {
    push('DURING_RECONCILIATION', 'REPLACE_SELECTOR', {
      selectorBytes: requireBytes(selectorBytes, 'candidate.selectorBytes'),
      resolveHoldGeneration: null,
      ...cas,
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
      ...cas,
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

function planCandidate(envelope, candidate, outcome, expectedSelectorBytes) {
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
    expectedSelectorBytes,
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
// generation (C-MUT /crashBoundaries). When the authority did not move, the outcome of the fault is
// one of exactly two closed states, never an unbound in-memory hold that no path can reconcile:
// - OLD_PLUS_ONE_IMMUTABLE_HOLD: the candidate is completely staged, so SS writes the one immutable
//   hold and performs the single selector replacement that binds the retained candidate and sets
//   RECONCILIATION_REQUIRED (C-FMT §6/§7, the INDETERMINATE plan), which reconciliation then resolves;
// - COMPLETE_OLD with no hold: the request is terminal NOT_COMMITTED (which retains no hold or escrow,
//   C-MUT §5), and the unbound candidate is discarded best-effort. A candidate that is not completely
//   staged can never be bound (C-FMT partial generation rejects); it is left as non-authoritative
//   debris and never discarded without terminal evidence (C-FMT generationCommit.unboundCandidate).
// Every write here is best-effort: the caller rethrows the original fault and storage is re-read,
// except a refused compare-and-set on the bind, which is rethrown unchanged in its place (F2).
// The module never guesses an outcome from SS memory and never reports a result.
async function establishRecoveryEvidence(storage, manifestRootKey, envelope, candidate, outcome, row, expectedSelectorBytes) {
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
  if (classification.authority !== 'COMPLETE_OLD' || classification.held) return;

  const discard = async () => {
    try {
      await storage.apply(freezeDeep({
        index: -1, boundary: 'DURING_RS_WORK', kind: 'CLEAR_CANDIDATE', payload: { generation: candidate.generation },
      }));
    } catch { /* best-effort: an unbound candidate is never authority */ }
  };
  if (outcome === M2_OUTCOME.NOT_COMMITTED) { await discard(); return; }

  const hold = buildHold(envelope, candidate);
  let bindable = false;
  try {
    const parent = generationFactsFromStorage(
      await storage.readGeneration(candidate.parentGeneration), candidate.parentGeneration, manifestRootKey,
    );
    const staged = generationFactsFromStorage(
      await storage.readGeneration(candidate.generation), candidate.generation, manifestRootKey,
    );
    const complete = staged.resultEvidence !== null
      && (row.outputKind === 'NONE' || staged.escrow !== null)
      && equal(staged.keyedRoot, candidate.keyedRoot)
      && equal(staged.manifestCipherDigest, candidate.manifestCipherDigest)
      && equal(parent.keyedRoot, candidate.parentKeyedRoot);
    if (complete) {
      // The bind is checked as a pure decision before any byte is written: the hold selector the
      // candidate supplies must validate against the stored parent and the candidate-with-hold.
      validateAuthority({
        selector: candidate.holdSelectorBytes,
        manifestRootKey,
        selected: authorityTuple(parent),
        candidate: authorityTuple({ ...staged, mutationHold: holdFacts(hold) }),
      });
      const held = selectorFacts(candidate.holdSelectorBytes);
      bindable = held.state === SELECTOR_STATE.RECONCILIATION_REQUIRED
        && held.generation === candidate.parentGeneration
        && held.candidateGeneration === candidate.generation;
    }
  } catch {
    bindable = false;
  }
  // Not bindable: the staged candidate stays as preserved, non-authoritative debris (C-FMT
  // unboundCandidate); only terminal NOT_COMMITTED evidence authorizes a discard.
  if (!bindable) return;

  try {
    // The one immutable hold for this envelope: rewriting it is idempotent (same bytes), and it makes
    // the candidate generation's MUTATION_HOLD present before the selector binds it.
    await storage.apply(freezeDeep({
      index: -1,
      boundary: 'DURING_RS_WORK',
      kind: 'WRITE_HOLD',
      payload: { generation: candidate.generation, hold, holdRecordKey: holdRecordKeyOf(candidate.records) },
    }));
    await storage.apply(freezeDeep({
      index: -1,
      boundary: 'AFTER_INDETERMINATE',
      kind: 'REPLACE_SELECTOR',
      // F2: the envelope this request read when it was planned, never re-read here.
      payload: { selectorBytes: candidate.holdSelectorBytes, resolveHoldGeneration: null, expectedSelectorBytes },
    }));
  } catch (e) {
    // F2: a refused compare-and-set on the binding selector is rethrown unchanged; it replaces the
    // original fault as the typed signal that the stored selector changed under this request.
    if (isPreconditionFailure(e)) throw e;
    // Otherwise the bind did not land. Nothing is discarded without terminal evidence: the candidate,
    // its hold and escrow stay preserved. A hold retained in SS memory with its record key stays
    // reconcilable through the rule-only retainedHoldLookup; without it the candidate is debris.
  }
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
  // KIND13-RESOLVE change 1 (C-FMT historicalHoldRule, row F8), ORIGINAL path: before any write, a
  // canonical present kind-13 record the candidate stages must satisfy the record-derived conjuncts
  // against the candidate's own authenticated COMMIT_RESULT. The selection never tombstones it, so a
  // record that is not this mutation's own hold would otherwise become selected authority.
  const candidateHoldProblem = presentHoldProblem(
    candidate.records, candidate.resultEvidence, candidate.generation, candidate.manifestKey);
  if (candidateHoldProblem !== null) fail(CODE.EVIDENCE_MISMATCH, candidateHoldProblem);
  // Amended F3 (row T1): WRITE_HOLD must agree with the staged kind-13 envelope. A candidate eligible for
  // an uncertain outcome whose kind-13 record is a canonical plaintext must stage exactly the present hold
  // this request writes (all 21 fields), never a tombstone or another hold. A non-canonical (filler)
  // plaintext keeps the #457 behaviour (B-CHR item 12).
  if (outcome === M2_OUTCOME.INDETERMINATE) {
    const staged = canonicalHoldRecord(candidate.records);
    if (staged !== undefined && !sameHold(staged, buildHold(envelope, candidate))) {
      fail(CODE.EVIDENCE_MISMATCH,
        'the candidate\'s staged kind-13 record is not the present hold this INDETERMINATE request writes');
    }
  }

  const memoryHold = holdRecordFacts(await storage.readMemoryHold());
  if (memoryHold !== null) {
    fail(CODE.BLIND_RETRY,
      'a mutation request arrived while an unresolved immutable hold exists; the API state is '
      + 'RECONCILIATION_REQUIRED and blind retry is forbidden');
  }

  // A candidate may only describe a change of authority from the stored one, and the selector bytes it
  // asks the port to install must be the selftuple selector for the generation it names. Without this
  // the module would report a commit the storage contradicts, or clear a generation that is the live
  // authority, from a candidate no caller should be able to form.
  if (candidate.generation === candidate.parentGeneration) {
    fail(CODE.CONTEXT_MISMATCH, 'the candidate generation must differ from the generation it replaces');
  }
  const plannedSelector = selectorFacts(candidate.selectorBytes);
  if (plannedSelector.generation !== candidate.generation
    || plannedSelector.candidateGeneration !== candidate.generation
    || !equal(plannedSelector.manifestCipherDigest, candidate.manifestCipherDigest)
    || !equal(plannedSelector.keyedRoot, candidate.keyedRoot)
    || (candidate.manifestKey !== null
      && !equal(plannedSelector.manifestKeyDigest, manifestKeyDigest(candidate.manifestKey)))) {
    fail(CODE.CONTEXT_MISMATCH,
      'the selector the candidate would install does not name the candidate generation as its own authority');
  }

  const stored = await readStoredSelector(storage);
  if (stored !== null) {
    const current = selectorFacts(stored.plaintext);
    // The durable selector is authority, not the live memory hold: after an SS restart the hold may be
    // gone while the stored selector still demands reconciliation, and a blind retry stays forbidden.
    if (current.state === SELECTOR_STATE.RECONCILIATION_REQUIRED) {
      fail(CODE.BLIND_RETRY,
        'the stored selector is in RECONCILIATION_REQUIRED; the unresolved mutation must be reconciled '
        + 'before a new request is accepted');
    }
    if (current.generation !== candidate.parentGeneration) {
      fail(CODE.STALE_PARENT,
        'the stored selector names a physical generation that is not the candidate parent');
    }
    // KIND13-RESOLVE change 2: the stored selected parent is read through the trusted reader before any
    // write; a present hold that is not that generation's own historical hold is PARTIAL_APPLICATION.
    generationFactsFromStorage(await storage.readGeneration(current.generation), current.generation, manifestRootKey);
  }
  // Rule-only hold locator, debris rule: an unbound candidate generation left by a crash is preserved,
  // non-authoritative debris and its generation number is never reused. A candidate that would stage
  // over any stored generation is refused before any byte is written.
  // The port's number-only inventory lists every generation number with any stored artifact (complete
  // or partially staged) under this locator context; it chooses only a number and never authority.
  let present;
  try {
    present = Array.from(await storage.readGenerationNumbers(), (n) => u64(n, 'present generation number'));
  } catch (e) {
    fail(CODE.STALE_PARENT, `the generation-number inventory could not be read: ${e.message}`);
  }
  if (present.some((n) => n >= candidate.generation)) {
    fail(CODE.STALE_PARENT,
      'the candidate generation number does not exceed every generation number present under the locator '
      + 'context; generation numbers are never reused');
  }

  let steps;
  try {
    steps = mutationSteps({
      envelope, candidate: planCandidate(envelope, candidate, outcome, envelopeOf(stored)), outcome, phase: 'ORIGINAL',
    });
  } catch (e) {
    malformed(`the step plan could not be formed: ${e.message}`);
  }

  try {
    for (const step of steps) {
      if (MEMORY_ONLY.has(step.kind)) continue;
      await storage.apply(step);
    }
  } catch (cause) {
    // F2: a refused compare-and-set wrote nothing: the stored selector changed under this request, so
    // no hold is written from this request's view and the caller must classify by readback.
    if (!isPreconditionFailure(cause)) {
      await establishRecoveryEvidence(storage, manifestRootKey, envelope, candidate, outcome, row, envelopeOf(stored));
    }
    throw cause;
  }
  return resultFor(envelope, candidate, outcome, row);
}

// ---------------------------------------------------------------------------------------------
// I-RESTART: the bound-hold loader and the restart readback rules.
//
// After an SS restart the memory hold is gone while the durable selector still demands
// reconciliation. The complete kind-13 record of the bound candidate is durable authority for that
// mutation (C-FMT §6/§7, C-REST §6/§7); `loadBoundHold` authenticates the whole locator chain down
// to that record and returns it read-only, and `reconcileIndeterminate` uses the same rules - with
// the per-record-kind compatibility of Change 5 - when it has no memory hold left.
//
// Two exact codes, and nothing else, come out of `loadBoundHold`: `BOUND_HOLD_INVALID` for every
// authenticated contradiction on returned data (never the routine `CAPI-S024` continuation) and
// `READBACK_UNAVAILABLE` for a readback the port could not perform. Only the awaited port call is
// classified by code: a throw whose own string `code` is one of the four verification codes of the
// port error obligation is an authenticated refusal, anything else means no readback happened.
// ---------------------------------------------------------------------------------------------

const BINDING_DIGEST_LABEL = 'STYX-M2-BINDING-DIGEST-V1';
const CANONICAL_BINDING_LENGTH = 389;
const CANDIDATE_REF_MAX_UNITS = 256;
const READBACK_VERIFICATION_CODES = Object.freeze(new Set([
  'AUTHENTICATION_FAILED', CODE.MALFORMED_INPUT, CODE.UNSUPPORTED_VALUE, CODE.CONTEXT_MISMATCH,
]));

const be32 = (n) => Uint8Array.of((n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
function concatBytes(...parts) {
  const length = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(length);
  let at = 0;
  for (const part of parts) { out.set(part, at); at += part.length; }
  return out;
}
// The candidate binding leg of C-FMT `sessionDomain`, exactly as `session-codec.js::encodeAad`
// computes it (ASCII label, the be32 length prefix, then the 389 canonical binding bytes).
const bindingDigestOf = (canonicalBinding) => sha256(concatBytes(
  TE.encode(BINDING_DIGEST_LABEL), be32(CANONICAL_BINDING_LENGTH), canonicalBinding,
));
const sameBytesOrNull = (a, b) => (a === null || b === null ? a === b : equal(a, b));

function storedSelectorValue(value) {
  if (value === null || value === undefined) return null;
  const s = strictObject(value, ['plaintext', 'envelope'], 'stored selector');
  return Object.freeze({
    plaintext: bytes(s.plaintext, null, 'stored selector.plaintext'),
    envelope: bytes(s.envelope, null, 'stored selector.envelope'),
  });
}

// The selector binds a candidate distinct from the generation it names.
const selectorBindsCandidate = (selector) => selector.candidateGeneration !== selector.generation
  || !equal(selector.candidateManifestKeyDigest, selector.manifestKeyDigest)
  || !equal(selector.candidateManifestCipherDigest, selector.manifestCipherDigest)
  || !equal(selector.candidateKeyedRoot, selector.keyedRoot);

// Change 1(h): every data record of a generation is stored under its own canonical key, in the
// generation and the manifest-key locator context the generation declares.
function checkRecordKeyLocators(facts, locator, refuse) {
  for (let i = 0; i < facts.records.length; i += 1) {
    const record = facts.records[i];
    let decoded;
    try { decoded = decodeRecordKey(record.recordKey); } catch (e) {
      refuse(`generation ${facts.generation} stores record ${i} under a non-canonical key: ${e.message}`);
    }
    if (decoded.recordKind !== record.recordKind) {
      refuse(`generation ${facts.generation} stores record ${i} under the key of kind ${decoded.recordKind}`);
    }
    if (decoded.writeGeneration !== facts.generation) {
      refuse(`generation ${facts.generation} stores record ${i} under the key of generation ${decoded.writeGeneration}`);
    }
    if (decoded.scope !== locator.scope || !equal(decoded.localContextId, locator.localContextId)
        || !sameBytesOrNull(decoded.secureSessionIdentity, locator.secureSessionIdentity)) {
      refuse(`generation ${facts.generation} stores record ${i} outside its manifest-key locator context`);
    }
  }
}

// Change 1(e)-1(f), on the manifest keys the port returned, before 1(g) reads the generations: the
// selected generation's manifest key is in the locator context of the candidate locator, and the
// candidate's stored manifest key is the stored selector locator byte for byte. A manifest key that
// is not a byte array or does not decode is left to the base reader of 1(g), which refuses it with
// its own class. No port call is made here.
function checkStoredLocators(selectedRaw, candidateRaw, locator, candidateManifestKey, refuse) {
  const keyOf = (raw) => (raw !== null && typeof raw === 'object' ? raw.manifestKey : undefined);
  const selectedKey = keyOf(selectedRaw);
  const candidateKey = keyOf(candidateRaw);
  if (selectedKey instanceof Uint8Array) {
    let selectedLocator = null;
    try { selectedLocator = decodeRecordKey(selectedKey); } catch { selectedLocator = null; }
    if (selectedLocator !== null && !equal(selectedLocator.localContextId, locator.localContextId)) {
      refuse('the candidate manifest key is in another locator context than the selected generation');
    }
  }
  if (candidateKey instanceof Uint8Array && !equal(candidateKey, candidateManifestKey)) {
    refuse('the located candidate manifest key is not the stored selector locator');
  }
}

// Change 1(k), the candidate binding leg: the candidate is stored in the SESSION scope, its
// BINDING_PROFILE decodes canonically present, and the profile hashes to the session binding digest
// the trusted reader projects for the located manifest (F3).
function checkCandidateBindingDigest(candidate, locator, strict, refuse) {
  if (locator.scope !== M2_SCOPE.SESSION) refuse('the candidate manifest key is not in the session scope');
  const record = candidate.records.find((r) => r.recordKind === M2_KIND.BINDING_PROFILE);
  const decoded = record === undefined
    ? undefined : optionalCanonicalPlaintext(record.plaintext, M2_KIND.BINDING_PROFILE);
  if (decoded === undefined || decoded.presence !== 1) {
    if (strict) refuse('the candidate stores no canonical present BINDING_PROFILE record');
    return;
  }
  if (candidate.sessionBindingDigest === null) refuse('the candidate declares no session binding digest');
  if (!equal(bindingDigestOf(decoded.canonicalBinding), candidate.sessionBindingDigest)) {
    refuse('the candidate binding profile does not hash to its declared session binding digest');
  }
}

// A record plaintext decoded canonically for its kind, or `undefined` when it does not decode (a
// filler plaintext, B-CHR item 12). Callers decide whether that is a refusal.
function optionalCanonicalPlaintext(plaintext, kind) {
  try {
    return decodePlaintext(kind, plaintext);
  } catch {
    return undefined;
  }
}

// The kind-13 hold of a list of records: the canonical present MUTATION_HOLD plaintext, the complete
// `mutationHold` projection when no canonical plaintext exists, or `null` when there is no hold.
function candidateHoldRecord(candidate, strict) {
  const record = candidate.records.find((r) => r.recordKind === M2_KIND.MUTATION_HOLD);
  if (record !== undefined) {
    const decoded = optionalCanonicalPlaintext(record.plaintext, M2_KIND.MUTATION_HOLD);
    if (decoded !== undefined) {
      if (decoded.presence !== 1) return null; // a canonical tombstone holds nothing
      return holdRecordFacts(decoded, 'authenticated candidate hold');
    }
  }
  return strict ? null : candidate.holdRecord;
}

// The kind-8 normalization (closed, used by both paths): a canonical present COMMIT_RESULT plaintext
// minus `presence`, with `profileDigest` renamed `profile`, must pass `evidenceFacts` and equal the
// same generation's `resultEvidence` projection member by member, bytes compared by value.
const RESULT_RECORD_FIELDS = Object.freeze([
  'operationIdentity', 'originalAuthorityDigest', 'originalAuthorityReference', 'candidateDigest',
  'candidateReference', 'mutationSetDigest', 'mutationSetReference', 'expectedOriginalState',
  'bindingRef', 'profile', 'outcome', 'authenticatedByRS', 'terminal',
]);

function normalizedResultRecord(decoded) {
  return evidenceFacts({
    operationIdentity: decoded.operationIdentity,
    originalAuthorityDigest: decoded.originalAuthorityDigest,
    originalAuthorityReference: decoded.originalAuthorityReference,
    candidateDigest: decoded.candidateDigest,
    candidateReference: decoded.candidateReference,
    mutationSetDigest: decoded.mutationSetDigest,
    mutationSetReference: decoded.mutationSetReference,
    expectedOriginalState: decoded.expectedOriginalState,
    bindingRef: decoded.bindingRef,
    profile: decoded.profileDigest,
    outcome: decoded.outcome,
    authenticatedByRS: decoded.authenticatedByRS,
    terminal: decoded.terminal,
  }, 'authenticated commit result');
}

const sameEvidence = (a, b) => RESULT_RECORD_FIELDS.every((k) => (
  (a[k] instanceof Uint8Array || b[k] instanceof Uint8Array) ? equal(a[k], b[k]) : a[k] === b[k]));

// A validation failure of returned data (a projection or a record that does not pass
// `evidenceFacts`) contradicts the rule being checked: it goes through that rule's refusal, so the
// reconcile path keeps the class Change 5 names for it. Only pure validators run inside; no port
// call is made here, so no port read error is re-classified.
function validatedOrRefused(validate, refuse, message) {
  try {
    return validate();
  } catch (e) {
    return refuse(`${message}: ${e instanceof Error ? e.message : 'refused'}`);
  }
}

// Change 2(g): the candidate COMMIT_RESULT. The record-plaintext leg is checked only where a
// canonical plaintext exists and is skipped otherwise (Change 5); the outcome set and the
// association with the hold are projection checks and always apply.
function checkCandidateResult(candidate, hold, strict, refuse) {
  const projection = validatedOrRefused(
    () => evidenceFacts(candidate.resultEvidence, 'candidate result evidence'), refuse,
    'the candidate result evidence projection is not commit-result evidence');
  const record = candidate.records.find((r) => r.recordKind === M2_KIND.COMMIT_RESULT);
  const decoded = record === undefined ? undefined : optionalCanonicalPlaintext(record.plaintext, M2_KIND.COMMIT_RESULT);
  if (decoded === undefined || decoded.presence !== 1) {
    if (strict) refuse('the candidate stores no canonical present COMMIT_RESULT record');
  } else {
    const normalized = validatedOrRefused(() => normalizedResultRecord(decoded), refuse,
      'the candidate COMMIT_RESULT record fails the kind-8 normalization');
    if (!sameEvidence(normalized, projection)) {
      refuse('the candidate COMMIT_RESULT record differs from its stored evidence projection');
    }
  }
  if (projection.outcome !== M2_OUTCOME.COMMITTED && projection.outcome !== M2_OUTCOME.INDETERMINATE) {
    refuse('the candidate commit result is neither committed nor indeterminate');
  }
  if (!storedResultMatchesHold(projection, hold)) {
    refuse('the candidate commit result does not identify the held mutation');
  }
}

// Change 2(h)-2(i): the candidate component set, compared with the held component-set identity.
function checkComponentSet(records, hold, strict, refuse) {
  const record = records.find((r) => r.recordKind === M2_KIND.COMPONENT_SET);
  const decoded = record === undefined ? undefined : optionalCanonicalPlaintext(record.plaintext, M2_KIND.COMPONENT_SET);
  if (decoded === undefined || decoded.presence !== 1) {
    if (strict) refuse('the candidate stores no canonical present COMPONENT_SET record');
    return;
  }
  if (!equal(decoded.mutationSetDigest, hold.componentSetDigest)) {
    refuse('the candidate component set digest is not the held component-set digest');
  }
  if (!equal(decoded.mutationSetReference, hold.componentSetReference)) {
    refuse('the candidate component set reference is not the held component-set reference');
  }
}

// Change 2(j): the stored escrow is the held output; a row with an output requires output bytes.
function requireEscrowMatchesHold(escrow, hold, refuse) {
  if (!storedEscrowMatchesHold(escrow, hold)) refuse('the candidate escrow is not the held output of this mutation');
  const kind = OUTPUT_KINDS[hold.heldOutputKind - 1];
  if (kind !== 'NONE'
      && !(escrow !== null && typeof escrow === 'object' && escrow.output instanceof Uint8Array)) {
    refuse('the candidate escrow carries no output bytes for a row with an output');
  }
}

// Change 2(k)-2(m): the OUTPUT_ESCROW record against the hold and the stored projection.
function checkEscrowRecord(candidate, hold, strict, refuse) {
  const record = candidate.records.find((r) => r.recordKind === M2_KIND.OUTPUT_ESCROW);
  const decoded = record === undefined ? undefined : optionalCanonicalPlaintext(record.plaintext, M2_KIND.OUTPUT_ESCROW);
  if (decoded === undefined || decoded.presence !== 1) {
    if (strict) refuse('the candidate stores no canonical present OUTPUT_ESCROW record');
    return;
  }
  for (const [recordField, heldField] of [
    ['operationIdentity', 'operationIdentity'], ['candidateDigest', 'candidateDigest'],
    ['candidateReference', 'candidateReference'], ['mutationSetDigest', 'componentSetDigest'],
    ['mutationSetReference', 'componentSetReference'],
  ]) {
    if (!equal(decoded[recordField], hold[heldField])) {
      refuse(`the candidate OUTPUT_ESCROW ${recordField} is not the held envelope's`);
    }
  }
  if (decoded.outputKind !== hold.heldOutputKind) {
    refuse('the candidate OUTPUT_ESCROW kind is not the held output kind');
  }
  const escrow = candidate.escrow;
  if (escrow === null || typeof escrow !== 'object' || !(escrow.output instanceof Uint8Array)) {
    refuse('the candidate escrow projection carries no output bytes to compare with the record');
  }
  if (!equal(decoded.output, escrow.output)) {
    refuse('the candidate OUTPUT_ESCROW bytes are not the escrow projection bytes');
  }
}

// Change 1(j): the selected generation's kind-13 record is a canonical tombstone or historical
// evidence of the mutation that produced it, associated with that generation's own commit result.
function checkSelectedGeneration(selected, selector, strict, refuse) {
  const record = selected.records.find((r) => r.recordKind === M2_KIND.MUTATION_HOLD);
  const decoded = record === undefined ? undefined : optionalCanonicalPlaintext(record.plaintext, M2_KIND.MUTATION_HOLD);
  if (decoded === undefined) {
    if (strict) refuse('the selected generation stores no canonical MUTATION_HOLD record');
    return;
  }
  if (decoded.presence === 0) return; // a tombstone: nothing is held in the selected generation
  const held = holdRecordFacts(decoded, 'selected historical hold');
  let key;
  try { key = decodeRecordKey(record.recordKey); } catch (e) {
    refuse(`the selected historical hold is stored under a non-canonical key: ${e.message}`);
  }
  if (key.recordKind !== M2_KIND.MUTATION_HOLD || key.writeGeneration !== selected.generation) {
    refuse('the selected historical hold is not stored under its own generation key');
  }
  const derived = encodeManifestKey({
    localContextId: key.localContextId, scope: key.scope,
    secureSessionIdentity: key.secureSessionIdentity, writeGeneration: key.writeGeneration,
  });
  if (!equal(derived, selected.manifestKey)) {
    refuse('the selected historical hold record key does not derive its generation manifest key');
  }
  if (!(held.parentGeneration < selected.generation)) {
    refuse('the selected historical hold does not name an earlier parent');
  }
  const resultRecord = selected.records.find((r) => r.recordKind === M2_KIND.COMMIT_RESULT);
  const resultPlaintext = resultRecord === undefined
    ? undefined : optionalCanonicalPlaintext(resultRecord.plaintext, M2_KIND.COMMIT_RESULT);
  const projection = validatedOrRefused(
    () => evidenceFacts(selected.resultEvidence, 'selected result evidence'), refuse,
    'the selected result evidence projection is not commit-result evidence');
  if (resultPlaintext === undefined || resultPlaintext.presence !== 1) {
    if (strict) {
      refuse('the selected generation stores no canonical present COMMIT_RESULT record beside its historical hold');
    }
  } else {
    const normalized = validatedOrRefused(() => normalizedResultRecord(resultPlaintext), refuse,
      'the selected COMMIT_RESULT record fails the kind-8 normalization');
    if (!sameEvidence(normalized, projection)) {
      refuse('the selected COMMIT_RESULT record differs from its stored evidence projection');
    }
  }
  if (!storedResultMatchesHold(projection, held)) {
    refuse('the selected historical hold is not identified by its generation commit result');
  }
}

// Exactly the 22 members of `HOLD_RECORD_KEYS`, each byte array a fresh copy: no locator member.
function boundHoldCopy(record) {
  const out = {};
  for (const key of HOLD_RECORD_KEYS) {
    const value = record[key];
    out[key] = value instanceof Uint8Array ? Uint8Array.prototype.slice.call(value) : value;
  }
  return Object.freeze(out);
}

// Change 3: the CAPI-S017 escrow carries the reference string; the staging producer owns the
// UTF-8 encoding and the loader decodes it back with the exact reversible form.
function selectedCandidateRefOf(hold, escrow) {
  if (OUTPUT_KINDS[hold.heldOutputKind - 1] !== 'SELECTED_CANDIDATE_REF') return null;
  if (escrow === null || typeof escrow !== 'object' || !(escrow.output instanceof Uint8Array)) {
    mismatch('the candidate escrow of a CAPI-S017 row carries no reference bytes');
  }
  let ref;
  try {
    ref = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(escrow.output);
  } catch (e) {
    mismatch(`the staged candidate reference is not well-formed UTF-8: ${e.message}`);
  }
  if (ref.length === 0) mismatch('the staged candidate reference is empty');
  if (ref.length > CANDIDATE_REF_MAX_UNITS) {
    mismatch(`the staged candidate reference is ${ref.length} UTF-16 units, over the ${CANDIDATE_REF_MAX_UNITS} bound`);
  }
  return ref;
}

const loadBoundHoldInvalid = (message) => fail(CODE.BOUND_HOLD_INVALID, message);

// One awaited port call. The port error obligation makes a verification failure carry its own
// string `code`; anything else - a wrapped, inherited, non-string or absent code - means the
// readback was not performed.
async function awaitedReadback(call, label) {
  let value;
  try {
    value = await call();
  } catch (error) {
    const descriptor = error !== null && typeof error === 'object'
      ? Object.getOwnPropertyDescriptor(error, 'code') : undefined;
    const code = descriptor === undefined ? undefined : descriptor.value;
    if (typeof code === 'string' && READBACK_VERIFICATION_CODES.has(code)) {
      loadBoundHoldInvalid(`the ${label} readback refused the stored bytes with ${code}`);
    }
    fail(CODE.READBACK_UNAVAILABLE,
      `the ${label} readback was not performed; the bound hold cannot be loaded from here`);
  }
  return value;
}

/**
 * Load the hold of the candidate a `RECONCILIATION_REQUIRED` selector binds, from durable bytes
 * alone, and return `{ hold, facts }` read-only. Never calls `apply` or `readMemoryHold`, never
 * writes or caches the hold, and never returns `CAPI-S024`: an authenticated contradiction is
 * `BOUND_HOLD_INVALID` and an unperformed readback is `READBACK_UNAVAILABLE`.
 */
export async function loadBoundHold(input) {
  const s = strictObject(input, ['storage', 'manifestRootKey'], 'bound hold input');
  const storage = storagePort(s.storage);
  const manifestRootKey = bytes(s.manifestRootKey, 32, 'manifestRootKey');
  let stored;
  try {
    stored = await readBoundHold(storage, manifestRootKey);
  } catch (error) {
    if (error instanceof M2TxnError
        && (error.code === CODE.BOUND_HOLD_INVALID || error.code === CODE.READBACK_UNAVAILABLE)) throw error;
    fail(CODE.BOUND_HOLD_INVALID,
      `the stored bytes of this profile are not a bound hold: ${error instanceof Error ? error.message : 'refused'}`);
  }
  return stored;
}

async function readBoundHold(storage, manifestRootKey) {
  // Change 1(a): the authenticated selector is in RECONCILIATION_REQUIRED and binds a candidate
  // distinct from the generation it names.
  const selectorValue = await awaitedReadback(() => storage.readSelector(), 'stored selector');
  const stored = storedSelectorValue(selectorValue);
  if (stored === null) loadBoundHoldInvalid('no stored selector exists; no reconciliation is pending');
  const selectorBytes = stored.plaintext;
  const selector = selectorFacts(selectorBytes);
  if (selector.state !== SELECTOR_STATE.RECONCILIATION_REQUIRED) {
    loadBoundHoldInvalid('the stored selector is not in RECONCILIATION_REQUIRED');
  }
  if (!selectorBindsCandidate(selector)) {
    loadBoundHoldInvalid('the stored selector names no candidate distinct from the selected generation');
  }
  // Change 1(b)-1(c): the locator is a canonical kind-16 key with an empty objectId for exactly the
  // candidate generation, and its literal digest is the stored candidate manifest key digest.
  let locator;
  try { locator = decodeRecordKey(selector.candidateManifestKey); } catch (e) {
    loadBoundHoldInvalid(`the candidate manifest key is not a canonical record key: ${e.message}`);
  }
  if (locator.recordKind !== M2_KIND.MANIFEST || locator.objectId.length !== 0) {
    loadBoundHoldInvalid('the candidate manifest key is not a canonical kind-16 manifest key');
  }
  if (locator.writeGeneration !== selector.candidateGeneration) {
    loadBoundHoldInvalid('the candidate manifest key does not derive the bound candidate generation');
  }
  if (!equal(manifestKeyDigest(selector.candidateManifestKey), selector.candidateManifestKeyDigest)) {
    loadBoundHoldInvalid('the candidate manifest key digest is not the literal digest of the stored locator');
  }
  // Change 1(d): one point lookup per named generation, in order; a named generation that is not
  // stored fails.
  const selectedRaw = await awaitedReadback(
    () => storage.readGeneration(selector.generation), `generation ${selector.generation}`);
  const candidateRaw = await awaitedReadback(
    () => storage.readGeneration(selector.candidateGeneration), `generation ${selector.candidateGeneration}`);
  if (selectedRaw === null || selectedRaw === undefined) {
    loadBoundHoldInvalid(`the selected generation ${selector.generation} is not stored`);
  }
  if (candidateRaw === null || candidateRaw === undefined) {
    loadBoundHoldInvalid(`the candidate generation ${selector.candidateGeneration} is not stored`);
  }
  // Change 1(e)-1(f): one locator context, and the located candidate key is the stored locator.
  checkStoredLocators(selectedRaw, candidateRaw, locator, selector.candidateManifestKey, loadBoundHoldInvalid);
  // Change 1(g): both generations pass the base generation-facts reader.
  const selected = generationFactsFromStorage(selectedRaw, selector.generation, manifestRootKey);
  const candidate = generationFactsFromStorage(candidateRaw, selector.candidateGeneration, manifestRootKey);
  // The same 1(e)-1(f) on the keys 1(g) accepted (equal by construction to the keys checked above).
  const selectedLocator = decodeRecordKey(selected.manifestKey);
  if (!equal(selectedLocator.localContextId, locator.localContextId)) {
    loadBoundHoldInvalid('the candidate manifest key is in another locator context than the selected generation');
  }
  if (!equal(candidate.manifestKey, selector.candidateManifestKey)) {
    loadBoundHoldInvalid('the located candidate manifest key is not the stored selector locator');
  }
  // Change 1(h): every record key of both generations.
  checkRecordKeyLocators(selected, selectedLocator, loadBoundHoldInvalid);
  checkRecordKeyLocators(candidate, locator, loadBoundHoldInvalid);
  // Change 1(i): the selector and both generations are one consistent authority.
  try {
    validateAuthority({
      selector: selectorBytes, manifestRootKey,
      selected: authorityTuple(selected), candidate: authorityTuple(candidate),
    });
  } catch (e) {
    loadBoundHoldInvalid(`the stored selector is not consistent with the generations it binds: ${e.message}`);
  }
  // Change 1(j)-1(k).
  checkSelectedGeneration(selected, selector, true, loadBoundHoldInvalid);
  checkCandidateBindingDigest(candidate, locator, true, loadBoundHoldInvalid);
  // Change 2(a): the candidate kind-13 record is a canonical present MUTATION_HOLD - the hold.
  const record = candidateHoldRecord(candidate, true);
  if (record === null) {
    loadBoundHoldInvalid('the candidate stores no canonical present MUTATION_HOLD record');
  }
  const hold = boundHoldCopy(record);
  if (hold.resultStatus !== M2_OUTCOME.INDETERMINATE) {
    loadBoundHoldInvalid('the held mutation is not INDETERMINATE');
  }
  if (hold.parentGeneration !== selector.generation) {
    loadBoundHoldInvalid('the held mutation does not name the selected generation as its physical parent');
  }
  if (!equal(hold.parentKeyedRoot, selector.keyedRoot)) {
    loadBoundHoldInvalid('the held mutation parent root is not the selected authority root');
  }
  // Change 2(e): the hold rebuilds the closed, row-bound envelope.
  try {
    envelopeFromHold(hold);
  } catch (e) {
    loadBoundHoldInvalid(`the held mutation does not rebuild its mutation envelope: ${e.message}`);
  }
  // Change 2(f), R3: a NONE-output row is refused by the loader.
  if (OUTPUT_KINDS[hold.heldOutputKind - 1] === 'NONE') {
    loadBoundHoldInvalid('the held mutation has no output; the bound-hold loader refuses this row');
  }
  checkCandidateResult(candidate, hold, true, loadBoundHoldInvalid);
  checkComponentSet(candidate.records, hold, true, loadBoundHoldInvalid);
  requireEscrowMatchesHold(candidate.escrow, hold, loadBoundHoldInvalid);
  checkEscrowRecord(candidate, hold, true, loadBoundHoldInvalid);
  const selectedCandidateRef = selectedCandidateRefOf(hold, candidate.escrow);
  return Object.freeze({
    hold,
    facts: Object.freeze({
      scenario: SCENARIOS[hold.scenario - 1],
      operation: OPERATIONS[hold.operation - 1],
      originalStateBefore: hold.originalApiState === API_STATE_CODE.ACTIVE ? 'ACTIVE' : 'EMPTY',
      expectedStateAfter: hold.expectedStateAfter === API_STATE_CODE.ACTIVE ? 'ACTIVE' : 'EMPTY',
      expectedSuccessCode: SUCCESS_CODES[hold.expectedSuccessCode - 1],
      outputKind: OUTPUT_KINDS[hold.heldOutputKind - 1],
      operationIdentity: Uint8Array.prototype.slice.call(hold.operationIdentity),
      reconciliationReference: Uint8Array.prototype.slice.call(hold.reconciliationReference),
      selectedCandidateRef,
    }),
  });
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
  sidecarHoldMatchesRecord(records, value.mutationHold, generation);
  presentHoldBelongsToGeneration(records, value.resultEvidence, generation, manifestKey);
  return {
    generation,
    records,
    manifestKey,
    manifestBytes,
    manifestCipherDigest: bytes(value.manifestCipherDigest, 32, 'stored manifestCipherDigest'),
    keyedRoot: root,
    mutationHold: holdFacts(value.mutationHold, 'stored mutationHold'),
    sessionBindingDigest: value.sessionBindingDigest === null || value.sessionBindingDigest === undefined
      ? null : bytes(value.sessionBindingDigest, 32, 'stored sessionBindingDigest'),
    escrow: value.escrow === null || value.escrow === undefined ? null : value.escrow,
    resultEvidence: value.resultEvidence === null || value.resultEvidence === undefined ? null : value.resultEvidence,
    // The complete kind-13 record when the port stores it (C-FMT /recordKinds[13]); otherwise null.
    holdRecord: durableHoldRecord(value.mutationHold),
  };
}

// F3: no sidecar is authoritative. When the generation's kind-13 record plaintext is a canonical
// MUTATION_HOLD plaintext (the authenticated record of its kind, as the trusted reader returns it), the
// `mutationHold` projection the port returns beside it must state the same thing: the same presence,
// and for a complete projection the same 21 fields. A projection that differs is refused fail-closed,
// before any authority, hold or escrow decision reads it. A record plaintext that is not a canonical
// kind-13 plaintext gives this module no authenticated view to compare (B-CHR item 12 owns that).
function sidecarHoldMatchesRecord(records, sidecar, generation) {
  const record = records.find((r) => r.recordKind === M2_KIND.MUTATION_HOLD);
  if (record === undefined) return;
  let authenticated;
  try { authenticated = decodePlaintext(M2_KIND.MUTATION_HOLD, record.plaintext); } catch { return; }
  const refuse = () => partial(
    `generation ${generation} returns a mutationHold projection that differs from its authenticated kind-13 record`);
  const presence = sidecar === null || sidecar === undefined || typeof sidecar !== 'object' ? null
    : Object.getOwnPropertyDescriptor(sidecar, 'presence')?.value;
  if (authenticated.presence !== 1) {
    if (presence !== 0) refuse();
    return;
  }
  if (presence !== 1) refuse();
  let projected;
  try {
    projected = isCompleteHold(sidecar) ? holdRecordFacts(sidecar, 'stored mutationHold') : holdFacts(sidecar, 'stored mutationHold');
  } catch { refuse(); }
  const truth = holdRecordFacts(authenticated, 'authenticated mutationHold');
  const keys = isCompleteHold(sidecar) ? HOLD_COMPARE : ['resultStatus', 'parentGeneration', 'parentKeyedRoot'];
  for (const k of keys) {
    const a = projected[k];
    const b = truth[k];
    if (!((a instanceof Uint8Array || b instanceof Uint8Array) ? equal(a, b) : a === b)) refuse();
  }
}

// KIND13-RESOLVE change 2 (C-FMT historicalHoldRule, row F8): the record-derived conjuncts of a canonical
// present kind-13 record in a stored generation. It must be stored under a canonical kind-13 record key
// whose writeGeneration is that generation and from which holdLocatorRule derives that generation's own
// manifest key; its parentGeneration must be strictly lower; and it must be the hold of that generation's
// own mutation (storedResultMatchesHold against its own COMMIT_RESULT). Derived from the authenticated
// record, never from the mutationHold projection. A non-canonical (filler) plaintext is outside the rule
// (B-CHR item 12). The manifest binding-digest leg stays with the trusted reader (row B4). Returns the
// problem, or null for a tombstone, a non-canonical plaintext or valid historical evidence.
function presentHoldProblem(records, resultEvidence, generation, manifestKey) {
  const record = records.find((r) => r.recordKind === M2_KIND.MUTATION_HOLD);
  if (record === undefined) return null;
  let authenticated;
  try { authenticated = decodePlaintext(M2_KIND.MUTATION_HOLD, record.plaintext); } catch { return null; }
  if (authenticated.presence !== 1) return null;
  let key;
  try { key = decodeRecordKey(record.recordKey); } catch { return `generation ${generation} stores its kind-13 record under a non-canonical key`; }
  if (key.recordKind !== M2_KIND.MUTATION_HOLD) return `generation ${generation} stores its kind-13 record under a non-kind-13 key`;
  if (key.writeGeneration !== generation) return `generation ${generation} stores a present hold whose record key derives generation ${key.writeGeneration}`;
  const derived = encodeManifestKey({
    localContextId: key.localContextId, scope: key.scope,
    secureSessionIdentity: key.secureSessionIdentity, writeGeneration: key.writeGeneration,
  });
  if (manifestKey === null || !equal(derived, manifestKey)) {
    return `generation ${generation} stores a present hold whose record key does not derive its manifest key`;
  }
  const held = holdRecordFacts(authenticated, 'authenticated mutationHold');
  if (!(held.parentGeneration < generation)) return `generation ${generation} stores a present hold that does not name an earlier parent`;
  if (resultEvidence === null || resultEvidence === undefined || !storedResultMatchesHold(resultEvidence, held)) {
    return `generation ${generation} stores a present hold that its own commit result does not identify`;
  }
  return null;
}

function presentHoldBelongsToGeneration(records, resultEvidence, generation, manifestKey) {
  const problem = presentHoldProblem(records, resultEvidence, generation, manifestKey);
  if (problem !== null) partial(problem);
}

// The record-derived kind-13 hold of a list of records (C-FMT /recordKinds[13]), or null.
function recordDerivedHold(records) {
  const record = records.find((r) => r.recordKind === M2_KIND.MUTATION_HOLD);
  if (record === undefined) return null;
  let authenticated;
  try { authenticated = decodePlaintext(M2_KIND.MUTATION_HOLD, record.plaintext); } catch { return null; }
  if (authenticated.presence !== 1) return null;
  return holdRecordFacts(authenticated, 'authenticated mutationHold');
}

// The canonical kind-13 record of a list of records: the record-derived present hold, null for a
// canonical tombstone, or undefined when there is no canonical kind-13 plaintext (filler, B-CHR item 12).
function canonicalHoldRecord(records) {
  const record = records.find((r) => r.recordKind === M2_KIND.MUTATION_HOLD);
  if (record === undefined) return undefined;
  let authenticated;
  try { authenticated = decodePlaintext(M2_KIND.MUTATION_HOLD, record.plaintext); } catch { return undefined; }
  if (authenticated.presence !== 1) return null;
  return holdRecordFacts(authenticated, 'authenticated mutationHold');
}

// The complete C-FMT kind-13 MUTATION_HOLD record a stored generation carries, or null when the port
// stores only the four authority facts or a tombstone. A malformed complete record fails closed.
function durableHoldRecord(value) {
  if (value === null || value === undefined || typeof value !== 'object' || Array.isArray(value)) return null;
  if (Reflect.ownKeys(value).length !== HOLD_RECORD_KEYS.length) return null;
  const record = holdRecordFacts(value, 'stored mutationHold');
  return record !== null && record.presence === 1 ? record : null;
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
  const stored = await readStoredSelector(storage);
  const storedSelector = stored === null ? null : stored.plaintext;
  if (storedSelector === null) {
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

// After SS memory loss: the held envelope is the complete kind-13 record stored in the candidate
// generation a RECONCILIATION_REQUIRED selector binds. The selected and candidate generations must
// validate as one consistent authority (C-FMT §6) and the record must be the unresolved INDETERMINATE
// hold whose parent is the selector's physical authority. Anything else yields null (fail closed).
// Change 5: with no memory hold the durable selector decides whether anything is pending, and the
// same Changes 1-2 authenticate the bound candidate, with the per-record-kind compatibility of the
// reconcile path: a record whose plaintext decodes canonically for its kind is checked, a record
// that does not decode is skipped, and a canonical record that contradicts is never skipped. The
// projection checks (storedResultMatchesHold, the outcome set, all of 2(j)) always apply, and 2(f)
// does not apply here. Failures apply nothing, are never the loader's codes and never CAPI-S024.
async function durableHeldEnvelope(storage, manifestRootKey, selectorBytes) {
  const partialRefuse = (message) => partial(message);
  const evidenceRefuse = (message) => fail(CODE.EVIDENCE_MISMATCH, message);
  const selector = selectorFacts(selectorBytes);
  if (selector.state !== SELECTOR_STATE.RECONCILIATION_REQUIRED || !selectorBindsCandidate(selector)) {
    fail(CODE.NO_RECONCILIATION_PENDING,
      'the stored selector is not in RECONCILIATION_REQUIRED with a separate candidate');
  }
  // Change 1(b)-1(c): the bound locator.
  let locator;
  try { locator = decodeRecordKey(selector.candidateManifestKey); } catch (e) {
    partial(`the candidate manifest key is not a canonical record key: ${e.message}`);
  }
  if (locator.recordKind !== M2_KIND.MANIFEST || locator.objectId.length !== 0) {
    partial('the candidate manifest key is not a canonical kind-16 manifest key');
  }
  if (locator.writeGeneration !== selector.candidateGeneration) {
    partial('the candidate manifest key does not derive the bound candidate generation');
  }
  if (!equal(manifestKeyDigest(selector.candidateManifestKey), selector.candidateManifestKeyDigest)) {
    partial('the candidate manifest key digest is not the literal digest of the stored locator');
  }
  // Change 1(d): one point lookup per named generation, in order; a named generation that is not
  // stored fails before the next lookup, as at the base.
  const selectedRaw = await storage.readGeneration(selector.generation);
  if (selectedRaw === null || selectedRaw === undefined) {
    partial(`the selector names generation ${selector.generation}, which is not stored`);
  }
  const candidateRaw = await storage.readGeneration(selector.candidateGeneration);
  if (candidateRaw === null || candidateRaw === undefined) {
    partial(`the selector names generation ${selector.candidateGeneration}, which is not stored`);
  }
  // Change 1(g), then 1(e)-1(f): on the reconcile path Change 5 keeps the base behaviour, so the base
  // reader runs first and keeps its class (a candidate in another context is CONTEXT_MISMATCH there);
  // the loader alone runs 1(e)-1(f) before 1(g) (checkStoredLocators).
  const selected = generationFactsFromStorage(selectedRaw, selector.generation, manifestRootKey);
  const candidate = generationFactsFromStorage(candidateRaw, selector.candidateGeneration, manifestRootKey);
  // Change 1(e)-1(f) on the keys 1(g) accepted, then 1(h).
  const selectedLocator = decodeRecordKey(selected.manifestKey);
  if (!equal(selectedLocator.localContextId, locator.localContextId)) {
    partial('the candidate manifest key is in another locator context than the selected generation');
  }
  if (!equal(candidate.manifestKey, selector.candidateManifestKey)) {
    partial('the located candidate manifest key is not the stored selector locator');
  }
  checkRecordKeyLocators(selected, selectedLocator, partialRefuse);
  checkRecordKeyLocators(candidate, locator, partialRefuse);
  // Change 1(i).
  try {
    validateAuthority({
      selector: selectorBytes, manifestRootKey, selected: authorityTuple(selected), candidate: authorityTuple(candidate),
    });
  } catch (e) {
    partial(`the stored selector is not consistent with the generations it binds: ${e.message}`);
  }
  // Change 1(j)-1(k).
  checkSelectedGeneration(selected, selector, false, partialRefuse);
  checkCandidateBindingDigest(candidate, locator, false, partialRefuse);
  // Change 2(a)-2(d): the hold, and the four hold facts the durable selector must confirm.
  const record = candidateHoldRecord(candidate, false);
  if (record === null || record.resultStatus !== M2_OUTCOME.INDETERMINATE
    || record.parentGeneration !== selector.generation || !equal(record.parentKeyedRoot, selector.keyedRoot)) {
    return null;
  }
  // Change 2(e): the held mutation rebuilds the closed, row-bound envelope (2(f) does not apply here).
  try {
    envelopeFromHold(record);
  } catch (e) {
    if (e instanceof M2TxnError && e.code === CODE.INVALID_ENVELOPE) throw e;
    evidenceRefuse(`the held mutation does not rebuild its mutation envelope: ${e.message}`);
  }
  // Change 2(g)-2(j) and 2(k)-2(m).
  checkCandidateResult(candidate, record, false, evidenceRefuse);
  checkComponentSet(candidate.records, record, false, evidenceRefuse);
  requireEscrowMatchesHold(candidate.escrow, record, evidenceRefuse);
  checkEscrowRecord(candidate, record, false, evidenceRefuse);
  return record;
}

// The stored COMMIT_RESULT of the generation a reconciliation acts on must identify the held mutation
// (C-FMT /generationCommit/originalAuthorityMatch, C-MUT /escrow sameMutationAsCandidate): the same
// operation, original authority, candidate, mutation set, binding and profile. Physical selector
// consistency alone does not establish that relationship.
const RESULT_HOLD_PAIRS = Object.freeze([
  ['operationIdentity', 'operationIdentity'], ['originalAuthorityDigest', 'originalAuthorityDigest'],
  ['originalAuthorityReference', 'originalAuthorityReference'], ['candidateDigest', 'candidateDigest'],
  ['candidateReference', 'candidateReference'], ['mutationSetDigest', 'componentSetDigest'],
  ['mutationSetReference', 'componentSetReference'], ['bindingRef', 'bindingRef'], ['profile', 'profileDigest'],
]);

function storedResultMatchesHold(resultEvidence, held) {
  let stored;
  try { stored = evidenceFacts(resultEvidence, 'stored result evidence'); } catch { return false; }
  return RESULT_HOLD_PAIRS.every(([e, h]) => equal(stored[e], held[h]))
    && stored.expectedOriginalState === held.originalApiState;
}

// The stored escrow released by a reconciliation must be the held output (C-FMT §9: a mismatched
// result/escrow association rejects): a row with no output stores none; otherwise its kind, digest and
// reference equal the held envelope's held output.
function storedEscrowMatchesHold(escrow, held) {
  const kind = OUTPUT_KINDS[held.heldOutputKind - 1];
  if (kind === 'NONE') return escrow === null;
  if (escrow === null || typeof escrow !== 'object' || Array.isArray(escrow)) return false;
  try {
    return escrow.kind === kind
      && equal(bytes(escrow.digest, 32, 'stored escrow.digest'), held.heldOutputDigest)
      && equal(bytes(escrow.reference, 32, 'stored escrow.reference'), held.heldOutputReference)
      && (escrow.output === null || escrow.output === undefined || escrow.output instanceof Uint8Array);
  } catch {
    return false;
  }
}

// CAPI-S020/S022 repeat: the committed candidate is already the authority and only the local emission
// call is outstanding. The stored generation must be the held mutation's committed candidate, proven
// by its own stored result evidence; only RELEASE_ESCROW is applied, with the same escrow bytes.
async function repeatCommittedEmission(storage, manifestRootKey, held, evidence, selector, envelope, row, storedSelector, expectedSelectorBytes) {
  const notPending = () => fail(CODE.NO_RECONCILIATION_PENDING,
    'the stored selector does not bind an unresolved candidate to the held parent generation; the '
    + 'hold is not reconcilable from this stored state');
  const selected = generationFactsFromStorage(
    await storage.readGeneration(selector.generation), selector.generation, manifestRootKey,
  );
  try {
    validateAuthority({ selector: storedSelector, manifestRootKey, selected: authorityTuple(selected), candidate: null });
  } catch (e) {
    partial(`the stored selector is not consistent with the generation it names: ${e.message}`);
  }
  // KIND13-RESOLVE change 3 (rows M1, M2, R1): the committed candidate keeps its own present hold as
  // historical evidence; the repeat proceeds only when it is the held hold, compared record-derived.
  if (selected.mutationHold !== null && selected.mutationHold.presence !== 0) {
    const recordHold = recordDerivedHold(selected.records);
    if (!sameHold(recordHold !== null ? recordHold : selected.holdRecord, held)) notPending();
  }
  if (!storedResultMatchesHold(selected.resultEvidence, held)) notPending();
  if (evidence.outcome !== M2_OUTCOME.COMMITTED) {
    fail(CODE.EVIDENCE_MISMATCH,
      'the held mutation is already the committed authority; non-COMMITTED evidence contradicts it and '
      + 'the hold is left unchanged');
  }
  const escrow = selected.escrow === null || selected.escrow === undefined ? null : selected.escrow;
  if (!storedEscrowMatchesHold(escrow, held)) {
    fail(CODE.EVIDENCE_MISMATCH,
      'the stored escrow is not the held output of this mutation; nothing is emitted and the hold is '
      + 'left unchanged');
  }
  const steps = mutationSteps({
    envelope,
    candidate: {
      generation: selector.generation, parentGeneration: held.parentGeneration, records: [],
      manifestKey: null, manifestBytes: null, manifestCipherDigest: null, selectorBytes: storedSelector,
      holdSelectorBytes: null, parentSelectorBytes: null, resultEvidence: null, escrow,
      keyedRoot: null, sessionBindingDigest: null, mutationHold: null, expectedSelectorBytes,
    },
    outcome: M2_OUTCOME.COMMITTED, phase: 'RECONCILIATION',
  });
  for (const step of steps) {
    if (step.kind !== 'RELEASE_ESCROW') continue; // the selection already happened exactly once
    await storage.apply(step);
  }
  return freezeDeep({
    reconciliation: 'RECONCILED_COMMITTED', resultKind: 'SUCCESS',
    state: row.stateAfterCommitted, authority: 'COMPLETE_NEW',
    output: escrow === null ? null : escrow.output, holds: 0,
  });
}

function sameHold(a, b) {
  return a !== null && b !== null && a.presence === 1 && b.presence === 1 && HOLD_COMPARE.every((k) => (
    (a[k] instanceof Uint8Array || b[k] instanceof Uint8Array) ? equal(a[k], b[k]) : a[k] === b[k]));
}

// Rule-only retainedHoldLookup (C-FMT draft): the SS memory retains one unresolved hold together with
// the authenticated record key of its stored kind-13 record, but the binding selector replacement did
// not land. The candidate generation and exact manifest key are DERIVED from that record key; one
// point lookup follows. No scan, no inference, and the lookup confers no authority. Every check fails
// closed with the hold unchanged.
async function retainedHoldTarget(storage, manifestRootKey, storedSelector, selector, held) {
  const notPending = (why) => fail(CODE.NO_RECONCILIATION_PENDING, `the retained hold cannot locate its candidate: ${why}`);
  if (held.holdRecordKey === null) notPending('the retained hold carries no stored record key');
  if (held.resultStatus !== M2_OUTCOME.INDETERMINATE) notPending('the retained hold is not INDETERMINATE');
  if (held.candidateGeneration === selector.generation) notPending('the hold names the selected authority');
  const parent = generationFactsFromStorage(
    await storage.readGeneration(selector.generation), selector.generation, manifestRootKey,
  );
  try {
    validateAuthority({ selector: storedSelector, manifestRootKey, selected: authorityTuple(parent), candidate: null });
  } catch (e) {
    partial(`the stored selector is not consistent with the generation it names: ${e.message}`);
  }
  // KIND13-RESOLVE change 4: a parent whose selected hold is historical evidence is not refused here;
  // both layers of change 2 (generationFactsFromStorage, validateAuthority) validated it above.
  if (!equal(held.parentKeyedRoot, selector.keyedRoot)) notPending('the hold parent root is not the selected root');
  const stored = await storage.readGeneration(held.candidateGeneration);
  if (stored === null || stored === undefined) notPending('no generation is stored at the derived locator');
  const located = generationFactsFromStorage(stored, held.candidateGeneration, manifestRootKey);
  if (!equal(located.manifestKey, held.candidateManifestKey)) notPending('the located manifest key is not the derived locator');
  const holdRecord = located.records.find((r) => r.recordKind === M2_KIND.MUTATION_HOLD);
  if (holdRecord === undefined || !equal(holdRecord.recordKey, held.holdRecordKey)) {
    notPending('the located generation does not store the hold under the retained record key');
  }
  if (!sameHold(located.holdRecord, held)) notPending('the located stored hold is not the retained hold');
  if (!storedResultMatchesHold(located.resultEvidence, held)) notPending('the located commit result does not identify the held mutation');
  return held.candidateGeneration;
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
  let held = holdRecordFacts(await storage.readMemoryHold());
  let durableHold = false;
  if (held === null) {
    // Without a memory hold only the durable selector can say whether anything is pending. After an
    // SS memory loss the held envelope is the complete kind-13 record stored in the candidate
    // generation the RECONCILIATION_REQUIRED selector binds (C-FMT §6, /recordKinds[13]); authenticated
    // RS evidence then terminally classifies the profile (C-MUT §8). A port that does not persist the
    // complete record cannot be reconciled from here and fails closed.
    const durableStored = await readStoredSelector(storage);
    const durable = durableStored === null ? null : durableStored.plaintext;
    if (durable !== null && selectorFacts(durable).state === SELECTOR_STATE.RECONCILIATION_REQUIRED) {
      held = await durableHeldEnvelope(storage, manifestRootKey, durable);
      if (held === null) {
        fail(CODE.HOLD_UNAVAILABLE,
          'the stored selector is in RECONCILIATION_REQUIRED although no hold is available to this '
          + 'profile; the unresolved mutation cannot be reconciled from here');
      }
      durableHold = true;
    } else {
      fail(CODE.NO_RECONCILIATION_PENDING, 'no reconciliation is pending for this profile');
    }
  }
  const supplied = durableHold && (s.hold === null || s.hold === undefined) ? held : holdRecordFacts(s.hold);
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

  // F2: the one selector read this reconciliation plans from; its envelope guards every write below.
  const stored = await readStoredSelector(storage);
  const storedSelector = stored === null ? null : stored.plaintext;
  const expectedSelectorBytes = envelopeOf(stored);
  const selector = storedSelector === null ? null : selectorFacts(storedSelector);
  // CAPI-S020/S022 repeat after an interrupted local emission (C-MUT §5/§6, /crashBoundaries
  // DURING_ESCROW_OUTPUT_RESPONSE POST_INDETERMINATE): the selector already names the committed
  // candidate as authority, but the hold is still retained because the local emission call did not
  // return success. Matching COMMITTED evidence repeats only that emission with the same escrow bytes;
  // nothing is re-selected, re-staged or regenerated. Any other evidence, INDETERMINATE included,
  // contradicts the committed authority and is EVIDENCE_MISMATCH with the hold unchanged.
  if (!durableHold && selector !== null
    && selector.state !== SELECTOR_STATE.RECONCILIATION_REQUIRED
    && selector.candidateGeneration === selector.generation
    && selector.generation !== held.parentGeneration) {
    return repeatCommittedEmission(storage, manifestRootKey, held, evidence, selector, reconciliationEnvelope, row,
      storedSelector, expectedSelectorBytes);
  }

  if (selector === null) {
    partial('no stored selector exists although one hold is pending');
  }
  // The generation this reconciliation may clear or select is the candidate the STORED hold selector
  // binds, never whatever candidateGeneration some other selector state happens to carry. A selector
  // that names its own generation as candidate, or that is not in RECONCILIATION_REQUIRED, is not a
  // pending hold: reconciling from it would delete or re-select the live authority.
  // Rule-only retainedHoldLookup: when the SS memory retains the hold but the binding selector
  // replacement did not land, the selector names the parent and binds nothing; the candidate is then
  // the one derived from the retained hold's stored record key, located by one point lookup.
  let target = selector.candidateGeneration;
  if (!durableHold && selector.generation === held.parentGeneration
    && selector.candidateGeneration === selector.generation
    && selector.state !== SELECTOR_STATE.RECONCILIATION_REQUIRED) {
    target = await retainedHoldTarget(storage, manifestRootKey, storedSelector, selector, held);
  } else if (selector.generation !== held.parentGeneration
    || selector.candidateGeneration === selector.generation
    || selector.state !== SELECTOR_STATE.RECONCILIATION_REQUIRED) {
    fail(CODE.NO_RECONCILIATION_PENDING,
      'the stored selector does not bind an unresolved candidate to the held parent generation; the '
      + 'hold is not reconcilable from this stored state');
  } else if (held.holdRecordKey !== null && (held.candidateGeneration !== selector.candidateGeneration
    || !equal(held.candidateManifestKey, selector.candidateManifestKey))) {
    // holdLocatorRule: a bound selector must coincide with the locator derived from the retained key.
    fail(CODE.EVIDENCE_MISMATCH,
      'the retained hold record key does not derive the candidate the stored selector binds; the hold is '
      + 'left unchanged');
  }

  // Before any decision, for every outcome and whether the hold is durable or retained in SS memory:
  // the bound candidate is read through the trusted reader (F3: its mutationHold projection must match
  // its authenticated kind-13 record), and its stored COMMIT_RESULT must identify the held mutation
  // (C-FMT /generationCommit/originalAuthorityMatch) before evidence selects or discards it.
  {
    const bound = generationFactsFromStorage(
      await storage.readGeneration(target), target, manifestRootKey,
    );
    if (!storedResultMatchesHold(bound.resultEvidence, held)) {
      fail(CODE.EVIDENCE_MISMATCH,
        'the bound candidate\'s stored commit result does not identify the held mutation; nothing is '
        + 'selected or discarded and the hold is left unchanged');
    }
    // KIND13-RESOLVE change 1 (rows F3, T1): the candidate's real stored hold, never an imagined one.
    // A canonical kind-13 record in the bound candidate must be exactly the held hold.
    const staged = canonicalHoldRecord(bound.records);
    if (staged !== undefined && !sameHold(staged, held)) {
      fail(CODE.EVIDENCE_MISMATCH,
        'the bound candidate\'s stored kind-13 record is not the held hold; nothing is selected or '
        + 'discarded and the hold is left unchanged');
    }
    // KIND13-RESOLVE change 2 (rows F1, F4, F8): the selected parent the bound selector names is read
    // through the trusted reader and the stored selector must validate as one consistent authority with
    // the bound candidate before evidence selects or discards anything. The retained lookup validates
    // its parent in retainedHoldTarget; the durable hold was validated in durableHeldEnvelope.
    if (target === selector.candidateGeneration && selector.candidateGeneration !== selector.generation) {
      const parent = generationFactsFromStorage(
        await storage.readGeneration(selector.generation), selector.generation, manifestRootKey,
      );
      try {
        validateAuthority({
          selector: storedSelector, manifestRootKey, selected: authorityTuple(parent), candidate: authorityTuple(bound),
        });
      } catch (e) {
        partial(`the stored selector is not consistent with the generations it binds: ${e.message}`);
      }
    }
  }

  // A continued INDETERMINATE applies nothing; it answers only after the bound candidate, its F3
  // projection and its stored result were checked above, so a contradiction is refused here too.
  if (evidence.outcome === M2_OUTCOME.INDETERMINATE) {
    return freezeDeep({
      reconciliation: 'INDETERMINATE', resultKind: 'INDETERMINATE', state: 'RECONCILIATION_REQUIRED',
      authority: 'COMPLETE_OLD', output: null, holds: 1,
    });
  }

  if (evidence.outcome === M2_OUTCOME.NOT_COMMITTED) {
    const parent = generationFactsFromStorage(
      await storage.readGeneration(held.parentGeneration), held.parentGeneration, manifestRootKey,
    );
    const parentSelectorBytes = encodePlaintext(M2_KIND.GENERATION_SELECTOR, sameTupleSelector(parent, held.originalApiState));
    const steps = mutationSteps({
      envelope: reconciliationEnvelope,
      candidate: {
        generation: target, parentGeneration: held.parentGeneration, records: [],
        manifestKey: null, manifestBytes: null, manifestCipherDigest: null, selectorBytes: null,
        holdSelectorBytes: null, parentSelectorBytes, resultEvidence: null, escrow: null,
        keyedRoot: null, sessionBindingDigest: null, mutationHold: null, expectedSelectorBytes,
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
    await storage.readGeneration(target), target, manifestRootKey,
  );
  const selectorBytes = encodePlaintext(M2_KIND.GENERATION_SELECTOR,
    sameTupleSelector(candidate, SELECTOR_STATE.ACTIVE));
  // The located or bound candidate must validate as the complete prospective authority, with its real
  // stored hold (KIND13-RESOLVE change 1: never an imagined tombstone; the present hold becomes
  // historical evidence once selected), before the selector is replaced or any escrow is emitted.
  try {
    validateAuthority({
      selector: selectorBytes,
      manifestRootKey,
      selected: authorityTuple(candidate),
      candidate: null,
    });
  } catch (e) {
    partial(`the candidate does not validate as the complete prospective authority: ${e.message}`);
  }
  if (candidate.resultEvidence === null) partial('the candidate carries no committed result evidence');
  const escrow = candidate.escrow === null || candidate.escrow === undefined ? null : candidate.escrow;
  if (!storedEscrowMatchesHold(escrow, held)) {
    fail(CODE.EVIDENCE_MISMATCH,
      'the bound candidate\'s stored escrow is not the held output of this mutation; nothing is selected '
      + 'and the hold is left unchanged');
  }
  const steps = mutationSteps({
    envelope: reconciliationEnvelope,
    candidate: {
      generation: target, parentGeneration: held.parentGeneration, records: [],
      manifestKey: null, manifestBytes: null, manifestCipherDigest: null, selectorBytes,
      holdSelectorBytes: null, parentSelectorBytes: null, resultEvidence: null, escrow,
      keyedRoot: null, sessionBindingDigest: null, mutationHold: null, expectedSelectorBytes,
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
