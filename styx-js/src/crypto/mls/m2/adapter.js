// adapter.js — M2 new-profile create / restore / Welcome integration adapter
// (card I-JOIN of #317 G-SCOPE; contract Issue #402).
//
// This is the semantic integration boundary of the M2 session adapter API: it accepts exactly the
// closed C-API request record for the three onboarding and re-establishment operations this card
// integrates (`CREATE`, `RESTORE`, `JOIN_WELCOME`), reads the owning-layer facts from an INJECTED
// closed observation, takes the decision with the merged I-SM decision core and, for `RESTORE`, with
// the merged I-REST classifier, releases output only on a `COMMITTED` tri-state, and emits exactly one
// closed C-API result record of the five ratified kinds.
//
// It performs no I/O, no cryptography, no storage call, no lock acquisition, no worker call and no
// transport action: the request, the current snapshot and the owning-layer observation are injected.
//
// Ratified inputs copied verbatim (see contract Issue #402 "Frozen shared interfaces"):
//   C-API  docs/architecture/m2/adapter-contract.md  sha256 b77d39fb…05ad9  (#319 5886838783)
//   C-REST docs/architecture/m2/restore-compatibility.md sha256 853dbc41…766b6 (#332 5900545454)
//   C-BIND docs/architecture/m2/binding-v0.md        sha256 2ee9b022…1d4a42 (#323 5890060894)
//   C-MUT  docs/architecture/m2/mutation-table.md    sha256 6c2c045c…eb3060 (#324 5890545934)
//   C-FMT  docs/architecture/m2/storage-format.md    sha256 b57df3a8…32812  (#327 5898801523)
//   C-REC  docs/architecture/m2/recovery-and-coexistence.md sha256 5b0d2fbd…94f87 (#335 5909885218)
//   O-SCEN docs/architecture/m2/scenarios/clause-scenarios.md sha256 6c19a01c…4d37ae (#337 5912195865)

import { transitionAdapter } from './state-machine.js';
import { classifyRestore } from '../../../storage/m2/session-restore.js';

/** The exact `adapterApi` constant of C-API §2. */
const API = 'styx-m2-session-adapter/v1';

/** The eight C-API `/operationEnum` members, in ratified order. */
const OPERATIONS = Object.freeze([
  'CREATE', 'RESTORE', 'JOIN_WELCOME', 'PROTECT_APPLICATION', 'OPEN_APPLICATION',
  'SELF_UPDATE', 'APPLY_PEER_UPDATE', 'RECONCILE_INDETERMINATE',
]);

/**
 * The three operations this card integrates. The other five remain valid C-API operations; this
 * module's closed dispatch refuses them with `UNSUPPORTED_OPERATION` (contract Issue #402,
 * "Open owner questions" item 1).
 */
const INTEGRATED_OPERATIONS = Object.freeze(['CREATE', 'RESTORE', 'JOIN_WELCOME']);

/** The three C-API `/stateEnum` members. */
const STATES = Object.freeze(['EMPTY', 'ACTIVE', 'RECONCILIATION_REQUIRED']);

/** The five C-API `/resultKindEnum` members. */
const RESULT_KINDS = Object.freeze(['SUCCESS', 'NO_CHANGE', 'NOT_COMMITTED', 'INDETERMINATE', 'REJECTED']);

/** The three C-API `/commitOutcomeEnum` members. */
const COMMIT_OUTCOMES = Object.freeze(['COMMITTED', 'NOT_COMMITTED', 'INDETERMINATE']);

/** The ten C-API `/successCodeEnum` members, in ratified order. */
const SUCCESS_CODES = Object.freeze([
  'CREATED', 'RESTORED', 'JOINED', 'APPLICATION_PROTECTED', 'APPLICATION_OPENED',
  'SELF_UPDATED', 'PEER_UPDATE_APPLIED', 'CANDIDATE_SELECTED', 'RECONCILED_COMMITTED',
  'DUPLICATE_IGNORED',
]);

/** The twenty-five C-API `/errorCodeEnum` members, in ratified order. */
const ERROR_CODES = Object.freeze([
  'UNKNOWN_FIELD', 'INVALID_REQUEST', 'UNKNOWN_VALUE', 'UNSUPPORTED_API_VERSION',
  'UNSUPPORTED_PROFILE', 'BINDING_MISMATCH', 'UNSUPPORTED_OPERATION',
  'SESSION_ALREADY_EXISTS', 'NO_ACTIVE_SESSION', 'NO_STORED_SESSION',
  'STORED_SESSION_INCOMPATIBLE', 'RECONCILIATION_REQUIRED', 'NO_RECONCILIATION_PENDING',
  'RECONCILIATION_REFERENCE_MISMATCH', 'UNSUPPORTED_ONBOARDING',
  'WELCOME_NO_MATCHING_KEY_PACKAGE', 'UNSUPPORTED_UPDATE_FORM', 'UNSUPPORTED_COMMIT_SHAPE',
  'KEY_PACKAGE_ALREADY_CONSUMED', 'AUTHENTICATION_FAILED', 'AUTHENTICATED_STATE_INCONSISTENT',
  'EPOCH_OUTSIDE_RETAINED_WINDOW', 'FUTURE_EPOCH', 'VALUE_OUT_OF_RANGE', 'FAIL_CLOSED_INTERNAL',
]);

/** C-API `/codeToResultKind`, transposed verbatim. */
const CODE_TO_KIND = Object.freeze({
  CREATED: 'SUCCESS', RESTORED: 'SUCCESS', JOINED: 'SUCCESS',
  APPLICATION_PROTECTED: 'SUCCESS', APPLICATION_OPENED: 'SUCCESS',
  SELF_UPDATED: 'SUCCESS', PEER_UPDATE_APPLIED: 'SUCCESS',
  CANDIDATE_SELECTED: 'SUCCESS', RECONCILED_COMMITTED: 'SUCCESS',
  DUPLICATE_IGNORED: 'NO_CHANGE',
  UNKNOWN_FIELD: 'REJECTED', INVALID_REQUEST: 'REJECTED', UNKNOWN_VALUE: 'REJECTED',
  UNSUPPORTED_API_VERSION: 'REJECTED', UNSUPPORTED_PROFILE: 'REJECTED',
  BINDING_MISMATCH: 'REJECTED', UNSUPPORTED_OPERATION: 'REJECTED',
  SESSION_ALREADY_EXISTS: 'REJECTED', NO_ACTIVE_SESSION: 'REJECTED',
  NO_STORED_SESSION: 'REJECTED', STORED_SESSION_INCOMPATIBLE: 'REJECTED',
  RECONCILIATION_REQUIRED: 'REJECTED', NO_RECONCILIATION_PENDING: 'REJECTED',
  RECONCILIATION_REFERENCE_MISMATCH: 'REJECTED', UNSUPPORTED_ONBOARDING: 'REJECTED',
  WELCOME_NO_MATCHING_KEY_PACKAGE: 'REJECTED', UNSUPPORTED_UPDATE_FORM: 'REJECTED',
  UNSUPPORTED_COMMIT_SHAPE: 'REJECTED', KEY_PACKAGE_ALREADY_CONSUMED: 'REJECTED',
  AUTHENTICATION_FAILED: 'REJECTED', AUTHENTICATED_STATE_INCONSISTENT: 'REJECTED',
  EPOCH_OUTSIDE_RETAINED_WINDOW: 'REJECTED', FUTURE_EPOCH: 'REJECTED',
  VALUE_OUT_OF_RANGE: 'REJECTED', FAIL_CLOSED_INTERNAL: 'REJECTED',
  NOT_COMMITTED: 'NOT_COMMITTED', INDETERMINATE: 'INDETERMINATE',
});

/** C-API `/precedenceLevels`, transposed: the level of each closed error code. */
const ERROR_LEVEL = Object.freeze({
  UNKNOWN_FIELD: 1, INVALID_REQUEST: 1, UNKNOWN_VALUE: 1,
  UNSUPPORTED_API_VERSION: 2,
  UNSUPPORTED_PROFILE: 3, BINDING_MISMATCH: 3,
  UNSUPPORTED_OPERATION: 4,
  SESSION_ALREADY_EXISTS: 5, NO_ACTIVE_SESSION: 5, NO_STORED_SESSION: 5,
  RECONCILIATION_REQUIRED: 5, NO_RECONCILIATION_PENDING: 5,
  RECONCILIATION_REFERENCE_MISMATCH: 5,
  VALUE_OUT_OF_RANGE: 6,
  EPOCH_OUTSIDE_RETAINED_WINDOW: 7, FUTURE_EPOCH: 7,
  AUTHENTICATION_FAILED: 8, AUTHENTICATED_STATE_INCONSISTENT: 8,
  STORED_SESSION_INCOMPATIBLE: 9, UNSUPPORTED_ONBOARDING: 9,
  WELCOME_NO_MATCHING_KEY_PACKAGE: 9, UNSUPPORTED_UPDATE_FORM: 9,
  UNSUPPORTED_COMMIT_SHAPE: 9, KEY_PACKAGE_ALREADY_CONSUMED: 9,
  FAIL_CLOSED_INTERNAL: 10,
});

/** C-API `/errorDefinitions` `errorOrder`: the within-level tie-break, in ratified order. */
const ERROR_RANK = Object.freeze(ERROR_CODES.reduce((table, code, index) => {
  table[code] = index;
  return table;
}, {}));

/** C-API `/profile`, transcribed exactly (13 closed fields). */
const PROFILE = Object.freeze({
  adapterApi: 'styx-m2-session-adapter/v1',
  bindingVersion: 'm2-opaque-binding/v0',
  logicalAdapter: 'session',
  physicalStore: 'mls',
  stage: 'test-profile',
  topology: 'two-member-direct',
  openMlsRevision: '09e92777dba0528d3d29e2e5e681b7e91637c7be',
  wasmArtifactPath: 'styx-js/vendor/openmls-wasm/openmls_wasm_bg.wasm',
  wasmArtifactSha256: 'fef05368f143de044274f8804d2ba195a1f886bc528651e98bd9c393fde4650e',
  ciphersuiteIanaId: '0x0001',
  ciphersuiteName: 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519',
  ss0DecisionsSha256: '235bcb86f9dd25e3c3cb56ed3a0b4820214821cf78ea881547c824db831eba07',
  pastEpochWindow: 5,
});
const PROFILE_KEYS = Object.freeze(Object.keys(PROFILE));

/** C-API `/request/commonRequired`; `/request/commonOptional` is empty. */
const REQUEST_FIELDS = Object.freeze(['api', 'operation', 'requestId', 'profile', 'bindingRef', 'input']);

/** C-API `/request/inputByOperation`, transcribed exactly. */
const INPUT_BY_OPERATION = Object.freeze({
  CREATE: Object.freeze(['peerFramedKeyPackage']),
  RESTORE: Object.freeze([]),
  JOIN_WELCOME: Object.freeze(['embeddedTreeWelcome']),
});

/** The opaque-byte members of `/request/inputByOperation`. */
const INPUT_BYTES = Object.freeze(['peerFramedKeyPackage', 'embeddedTreeWelcome']);

/** C-API `/response/commonRequired`, transcribed exactly. */
const RESULT_COMMON = Object.freeze(['api', 'requestId', 'operation', 'kind', 'stateBefore', 'stateAfter']);

/** C-API `/response/outputBySuccessCode`, transcribed exactly. */
const OUTPUT_BY_SUCCESS_CODE = Object.freeze({
  CREATED: Object.freeze(['embeddedTreeWelcome']),
  RESTORED: Object.freeze([]),
  JOINED: Object.freeze([]),
  APPLICATION_PROTECTED: Object.freeze(['protectedApplicationBytes']),
  APPLICATION_OPENED: Object.freeze(['applicationBytes']),
  SELF_UPDATED: Object.freeze(['protectedCommitBytes']),
  PEER_UPDATE_APPLIED: Object.freeze([]),
  CANDIDATE_SELECTED: Object.freeze(['selectedCandidateRef']),
  RECONCILED_COMMITTED: Object.freeze(['originalSuccessCode', 'originalOutput']),
  DUPLICATE_IGNORED: Object.freeze([]),
});

/** The C-REST-owning rule of the I-SM decision rows this card consumes: the `RS_TRI_STATE` rows. */
const TRI_STATE_ROWS = Object.freeze(['CAPI-S001', 'CAPI-S006']);

/**
 * The closed C-REST outcome to C-API disposition mapping of the contract (issue #402). The first
 * column is the complete C-REST `resultSets` union; no other outcome can be classified.
 */
const RESTORE_DISPOSITIONS = Object.freeze({
  NO_M2_STATE: 'NO_STORED_SESSION',
  LEGACY_ONLY: 'STORED_SESSION_INCOMPATIBLE',
  RESTORED_ACTIVE: 'RESTORED',
  RESTORED_EMPTY: 'AUTHENTICATED_STATE_INCONSISTENT',
  RESTORED_RECONCILIATION_REQUIRED: 'AUTHENTICATED_STATE_INCONSISTENT',
  LOCKED_ELSEWHERE: 'FAIL_CLOSED_INTERNAL',
  INCOMPATIBLE_BUILD: 'STORED_SESSION_INCOMPATIBLE',
  INCOMPATIBLE_FORMAT: 'STORED_SESSION_INCOMPATIBLE',
  UNSUPPORTED_VERSION: 'STORED_SESSION_INCOMPATIBLE',
  WRAPPER_AUTH_FAILED: 'AUTHENTICATION_FAILED',
  AUTHENTICATION_FAILED: 'AUTHENTICATION_FAILED',
  SELECTOR_INVALID: 'AUTHENTICATED_STATE_INCONSISTENT',
  MANIFEST_INVALID: 'AUTHENTICATED_STATE_INCONSISTENT',
  RECORD_SET_INCOMPLETE: 'AUTHENTICATED_STATE_INCONSISTENT',
  RECORD_INVALID: 'AUTHENTICATED_STATE_INCONSISTENT',
  REFERENCE_INCONSISTENT: 'AUTHENTICATED_STATE_INCONSISTENT',
  PARTIAL_GENERATION: 'AUTHENTICATED_STATE_INCONSISTENT',
  INTERNAL_VALIDATION_FAILED: 'FAIL_CLOSED_INTERNAL',
});

/**
 * The I-SM decision facts that stand for each C-REST outcome: the classifier's outcome name is not
 * an I-SM fact, so the mapping is explicit and closed. `RESTORED_ACTIVE` is the only C-REST success
 * C-API fixes; the two remaining authenticated successes fail closed.
 */
const RESTORE_FACTS = Object.freeze({
  NO_M2_STATE: 'NO_STORED_SESSION',
  LEGACY_ONLY: 'STORED_SESSION_INCOMPATIBLE',
  RESTORED_ACTIVE: 'RESTORED',
  RESTORED_EMPTY: 'AUTHENTICATED_RECORD_INCONSISTENT',
  RESTORED_RECONCILIATION_REQUIRED: 'AUTHENTICATED_RECORD_INCONSISTENT',
  INCOMPATIBLE_BUILD: 'STORED_SESSION_INCOMPATIBLE',
  INCOMPATIBLE_FORMAT: 'STORED_SESSION_INCOMPATIBLE',
  UNSUPPORTED_VERSION: 'STORED_SESSION_INCOMPATIBLE',
  WRAPPER_AUTH_FAILED: 'AUTHENTICATION_FAILED',
  AUTHENTICATION_FAILED: 'AUTHENTICATION_FAILED',
  SELECTOR_INVALID: 'MULTIPLE_OR_MIXED_NONLEGACY_CANDIDATES',
  MANIFEST_INVALID: 'AUTHENTICATED_RECORD_INCONSISTENT',
  RECORD_SET_INCOMPLETE: 'AUTHENTICATED_RECORD_INCONSISTENT',
  RECORD_INVALID: 'AUTHENTICATED_RECORD_INCONSISTENT',
  REFERENCE_INCONSISTENT: 'AUTHENTICATED_RECORD_INCONSISTENT',
  PARTIAL_GENERATION: 'AUTHENTICATED_RECORD_INCONSISTENT',
});

/** The C-REST outcomes this card cannot route through a ratified I-SM decision row. */
const UNROUTABLE_OUTCOMES = Object.freeze(['LOCKED_ELSEWHERE', 'INTERNAL_VALIDATION_FAILED']);

/**
 * The bounds this card selects for the adapter boundary. C-API §4 leaves the bounded-byte limits to a
 * later selection; this is that selection for this boundary only. Over-limit values reject, never
 * truncate.
 */
const BOUNDS = Object.freeze({
  MAX_REQUEST_ID_CHARS: 128,
  MAX_BINDING_REF_BYTES: 4096,
  MAX_OPAQUE_BYTES: 1048576,
});

/** The closed observation member sets, one per integrated operation. */
const OBSERVATION_KEYS = Object.freeze({
  CREATE: Object.freeze(['onboarding', 'commitOutcome', 'operationIdentity', 'stagedOutput']),
  JOIN_WELCOME: Object.freeze(['keyPackage', 'commitOutcome', 'operationIdentity']),
  RESTORE: Object.freeze(['restoreObservation']),
});

const ONBOARDING_VALUES = Object.freeze(['SUPPORTED', 'UNSUPPORTED_ONBOARDING']);
const KEY_PACKAGE_VALUES = Object.freeze([
  'MATCHED', 'KEY_PACKAGE_ALREADY_CONSUMED', 'WELCOME_NO_MATCHING_KEY_PACKAGE', 'UNSUPPORTED_ONBOARDING',
]);
/** The closed `JOIN_WELCOME` fact mapping onto the I-SM decision facts. */
const JOIN_FACTS = Object.freeze({
  MATCHED: 'SUPPORTED',
  KEY_PACKAGE_ALREADY_CONSUMED: 'KEY_PACKAGE_ALREADY_CONSUMED',
  WELCOME_NO_MATCHING_KEY_PACKAGE: 'WELCOME_NO_MATCHING_KEY_PACKAGE',
  UNSUPPORTED_ONBOARDING: 'UNSUPPORTED_ONBOARDING',
});
/** The closed C-REST observation member set, as `readObservation` fixes it. */
const RESTORE_OBSERVATION_KEYS = Object.freeze(['faults', 'inventory', 'legacy', 'vector', 'selectorState']);

const TYPED_ARRAY_PROTOTYPE = Object.getPrototypeOf(Uint8Array.prototype);
const TYPED_ARRAY_TAG = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, Symbol.toStringTag).get;

/**
 * The only error this module throws. It carries a C-API error code and nothing else: no free text, no
 * field name, no value, no path and no offending input. It is thrown exactly when a closed C-API
 * result record cannot be shaped at all, because the request does not carry a readable `requestId`
 * and `operation`, or one of the three input members is unreadable.
 */
export class M2AdapterError extends Error {
  constructor(code) {
    const closed = typeof code === 'string' && ERROR_CODES.includes(code);
    const useCode = closed ? code : 'FAIL_CLOSED_INTERNAL';
    super(useCode);
    this.name = 'M2AdapterError';
    this.code = useCode;
  }
}

function freezeData(value) {
  if (value === null || typeof value !== 'object') return value;
  if (ArrayBuffer.isView(value)) return value;
  for (const descriptor of Object.values(Object.getOwnPropertyDescriptors(value))) {
    if (Object.hasOwn(descriptor, 'value')) freezeData(descriptor.value);
  }
  return Object.freeze(value);
}

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) || ArrayBuffer.isView(value)) return false;
  try {
    return Object.getPrototypeOf(value) === Object.prototype;
  } catch {
    return false;
  }
}

function isUint8Array(value) {
  try {
    return ArrayBuffer.isView(value)
      && TYPED_ARRAY_TAG.call(value) === 'Uint8Array'
      && Object.getPrototypeOf(value) === Uint8Array.prototype;
  } catch {
    return false;
  }
}

/**
 * Read a closed record: every own key must be an allowed member, every allowed member must be present,
 * every member must be a plain own data property. Returns `{ error, values }` with a C-API error code.
 */
function readClosed(value, allowed) {
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
  for (const key of allowed) values[key] = descriptors[key].value;
  return { error: null, values };
}

function levelOf(code) {
  return Object.hasOwn(ERROR_LEVEL, code) ? ERROR_LEVEL[code] : 10;
}

function rankOf(code) {
  return Object.hasOwn(ERROR_RANK, code) ? ERROR_RANK[code] : ERROR_CODES.length;
}

/** Pick the highest-precedence candidate: lowest level first, then the ratified within-level order. */
function worst(candidates) {
  return [...candidates].sort((left, right) => levelOf(left) - levelOf(right) || rankOf(left) - rankOf(right))[0];
}

function resultRecord(requestId, operation, kind, stateBefore, stateAfter, extra) {
  return freezeData({
    api: API,
    requestId,
    operation,
    kind,
    stateBefore,
    stateAfter,
    ...extra,
  });
}

function rejected(requestId, operation, stateBefore, stateAfter, code) {
  return resultRecord(requestId, operation, 'REJECTED', stateBefore, stateAfter, { error: freezeData({ code }) });
}

/**
 * Validate the closed C-API request alone. Returns a frozen `{ ok, code }` record: `code` is the
 * exact C-API error code of the first applicable P01 to P04 defect, or `null` when the request itself
 * is admissible (the state gate, the bounds and the owning-layer decision are not decided here).
 */
export function validateAdapterRequest(request) {
  const shape = readClosed(request, REQUEST_FIELDS);
  if (shape.error) return freezeData({ ok: false, code: shape.error });
  const code = requestLevelCode(shape.values);
  return freezeData({ ok: code === null, code });
}

/** Read one own data-property string member, or `null` when it is absent or not a string. */
function readMemberString(record, key) {
  if (!isPlainObject(record)) return null;
  let descriptor;
  try {
    descriptor = Object.getOwnPropertyDescriptor(record, key);
  } catch {
    return null;
  }
  if (!descriptor || !Object.hasOwn(descriptor, 'value') || typeof descriptor.value !== 'string') return null;
  return descriptor.value;
}

/** The P01 to P04 error code of a request, or `null`. */
function requestLevelCode(value) {
  const candidates = [];
  if (typeof value.api !== 'string') candidates.push('INVALID_REQUEST');
  else if (value.api !== API) candidates.push('UNSUPPORTED_API_VERSION');

  const profileShape = readClosed(value.profile, PROFILE_KEYS);
  if (profileShape.error === 'INVALID_REQUEST') candidates.push('UNSUPPORTED_PROFILE');
  else if (profileShape.error === 'UNKNOWN_FIELD') candidates.push('UNSUPPORTED_PROFILE');
  else if (profileShape.values.adapterApi !== value.api) candidates.push('UNSUPPORTED_API_VERSION');
  else {
    for (const key of PROFILE_KEYS) {
      if (profileShape.values[key] !== PROFILE[key]) {
        candidates.push('UNSUPPORTED_PROFILE');
        break;
      }
    }
  }

  if (typeof value.bindingRef !== 'string' && !isUint8Array(value.bindingRef)) candidates.push('BINDING_MISMATCH');
  else if (isUint8Array(value.bindingRef)) {
    if (value.bindingRef.byteLength === 0) candidates.push('BINDING_MISMATCH');
  } else if (value.bindingRef.length === 0) candidates.push('BINDING_MISMATCH');

  if (typeof value.operation !== 'string' || !OPERATIONS.includes(value.operation)) {
    candidates.push('UNSUPPORTED_OPERATION');
  } else if (!INTEGRATED_OPERATIONS.includes(value.operation)) {
    candidates.push('UNSUPPORTED_OPERATION');
  } else {
    const inputShape = readClosed(value.input, INPUT_BY_OPERATION[value.operation]);
    if (inputShape.error) candidates.push(inputShape.error);
    else {
      for (const key of INPUT_BY_OPERATION[value.operation]) {
        if (INPUT_BYTES.includes(key) && !isUint8Array(inputShape.values[key])) {
          candidates.push('INVALID_REQUEST');
          break;
        }
      }
    }
  }

  if (typeof value.requestId !== 'string' || value.requestId.length === 0) candidates.push('INVALID_REQUEST');
  return candidates.length === 0 ? null : worst(candidates);
}

/** The P06 bound codes of a request and its observation, or an empty list. */
function boundCodes(value, observation) {
  const candidates = [];
  if (typeof value.requestId === 'string' && value.requestId.length > BOUNDS.MAX_REQUEST_ID_CHARS) {
    candidates.push('VALUE_OUT_OF_RANGE');
  }
  if (isUint8Array(value.bindingRef) && value.bindingRef.byteLength > BOUNDS.MAX_BINDING_REF_BYTES) {
    candidates.push('BINDING_MISMATCH');
  }
  const inputShape = isPlainObject(value.input) && typeof value.operation === 'string'
    ? readClosed(value.input, INPUT_BY_OPERATION[value.operation] ?? [])
    : { error: 'INVALID_REQUEST', values: null };
  if (inputShape.error === null) {
    for (const key of INPUT_BY_OPERATION[value.operation] ?? []) {
      if (INPUT_BYTES.includes(key) && isUint8Array(inputShape.values[key])
        && inputShape.values[key].byteLength > BOUNDS.MAX_OPAQUE_BYTES) {
        candidates.push('VALUE_OUT_OF_RANGE');
      }
    }
  }
  if (isPlainObject(observation) && isUint8Array(observation.stagedOutput?.embeddedTreeWelcome)
    && observation.stagedOutput.embeddedTreeWelcome.byteLength > BOUNDS.MAX_OPAQUE_BYTES) {
    candidates.push('VALUE_OUT_OF_RANGE');
  }
  return candidates;
}

/** Read the M2 snapshot state. Throws when the snapshot is unreadable at all. */
function snapshotStateOf(snapshot) {
  if (!isPlainObject(snapshot)) throw new M2AdapterError('FAIL_CLOSED_INTERNAL');
  let descriptor;
  try {
    descriptor = Object.getOwnPropertyDescriptor(snapshot, 'state');
  } catch {
    throw new M2AdapterError('FAIL_CLOSED_INTERNAL');
  }
  if (!descriptor || !Object.hasOwn(descriptor, 'value') || !STATES.includes(descriptor.value)) {
    throw new M2AdapterError('FAIL_CLOSED_INTERNAL');
  }
  return descriptor.value;
}

/**
 * The owning-layer decision for one integrated operation. Returns `{ facts, commitOutcome,
 * operationIdentity, stagedOutput }` or `{ error }` with a C-API error code, or `{ unroutable: code }`
 * for an outcome this card cannot route through a ratified decision row.
 */
function deriveDecision(operation, observation) {
  const shape = readClosed(observation, OBSERVATION_KEYS[operation]);
  if (shape.error) return { error: shape.error };
  const value = shape.values;

  if (operation === 'RESTORE') {
    const restoreShape = readClosed(value.restoreObservation, RESTORE_OBSERVATION_KEYS);
    if (restoreShape.error) return { error: 'FAIL_CLOSED_INTERNAL' };
    let outcome;
    try {
      outcome = classifyRestore(value.restoreObservation);
    } catch {
      return { error: 'FAIL_CLOSED_INTERNAL' };
    }
    if (outcome === null || typeof outcome !== 'object' || !Object.hasOwn(RESTORE_DISPOSITIONS, outcome.result)) {
      return { error: 'FAIL_CLOSED_INTERNAL' };
    }
    const code = RESTORE_DISPOSITIONS[outcome.result];
    if (UNROUTABLE_OUTCOMES.includes(outcome.result)) return { unroutable: code, facts: RESTORE_FACTS.NO_M2_STATE };
    return { facts: RESTORE_FACTS[outcome.result], commitOutcome: null, operationIdentity: null };
  }

  const factKey = operation === 'CREATE' ? 'onboarding' : 'keyPackage';
  const allowed = operation === 'CREATE' ? ONBOARDING_VALUES : KEY_PACKAGE_VALUES;
  if (typeof value[factKey] !== 'string') return { error: 'INVALID_REQUEST' };
  if (!allowed.includes(value[factKey])) return { error: 'UNKNOWN_VALUE' };
  const reached = operation === 'CREATE'
    ? value.onboarding === 'SUPPORTED'
    : value.keyPackage === 'MATCHED';

  if (!reached) {
    if (value.commitOutcome !== null || value.operationIdentity !== null) return { error: 'INVALID_REQUEST' };
    if (operation === 'CREATE' && value.stagedOutput !== null) return { error: 'INVALID_REQUEST' };
    return { facts: operation === 'CREATE' ? value.onboarding : JOIN_FACTS[value.keyPackage], commitOutcome: null, operationIdentity: null };
  }

  if (typeof value.commitOutcome !== 'string') return { error: 'INVALID_REQUEST' };
  if (!COMMIT_OUTCOMES.includes(value.commitOutcome)) return { error: 'UNKNOWN_VALUE' };
  if (typeof value.operationIdentity !== 'string' || value.operationIdentity.length === 0) {
    return { error: 'INVALID_REQUEST' };
  }
  let stagedOutput = null;
  if (operation === 'CREATE') {
    const staged = readClosed(value.stagedOutput, ['embeddedTreeWelcome']);
    if (staged.error) return { error: staged.error };
    if (!isUint8Array(staged.values.embeddedTreeWelcome)) return { error: 'INVALID_REQUEST' };
    stagedOutput = staged.values;
  }
  return {
    facts: operation === 'CREATE' ? value.onboarding : JOIN_FACTS[value.keyPackage],
    commitOutcome: value.commitOutcome,
    operationIdentity: value.operationIdentity,
    stagedOutput,
  };
}

/**
 * The state-gate rejection of the current state for one operation, or `null` when the state row
 * allows the operation. Used for the outcomes that have no ratified I-SM decision row.
 */
function stateGateResult(snapshot, operation) {
  const probe = { operation, applicableErrors: [], facts: 'NO_STORED_SESSION' };
  let decision;
  try {
    decision = transitionAdapter(snapshot, probe);
  } catch {
    return null;
  }
  return typeof decision.result.scenario === 'string' && decision.result.scenario.startsWith('CAPI-G')
    ? decision
    : null;
}

function shapeDecision(decision, requestId, operation, stagedOutput) {
  const result = decision.result;
  const kind = result.kind;
  const base = [requestId, operation, kind, result.stateBefore, result.stateAfter];
  if (kind === 'REJECTED') return rejected(...base, result.code);
  if (kind === 'NOT_COMMITTED') {
    return resultRecord(...base, { commitOutcome: 'NOT_COMMITTED' });
  }
  if (kind === 'INDETERMINATE') {
    return resultRecord(...base, {
      commitOutcome: 'INDETERMINATE',
      reconciliationRef: result.reconciliationRef,
      originalStateBefore: result.originalStateBefore,
    });
  }
  const extra = { successCode: result.code };
  if (TRI_STATE_ROWS.includes(result.scenario)) extra.commitOutcome = 'COMMITTED';
  if (kind === 'SUCCESS' && Object.hasOwn(OUTPUT_BY_SUCCESS_CODE, result.code)
    && OUTPUT_BY_SUCCESS_CODE[result.code].length > 0) {
    const output = {};
    for (const member of OUTPUT_BY_SUCCESS_CODE[result.code]) {
      if (member === 'embeddedTreeWelcome' && stagedOutput !== null
        && isUint8Array(stagedOutput.embeddedTreeWelcome)) {
        output.embeddedTreeWelcome = new Uint8Array(stagedOutput.embeddedTreeWelcome);
      }
    }
    if (Object.keys(output).length > 0) extra.output = output;
  }
  return resultRecord(...base, extra);
}

/**
 * The integration entry point. `input` is a closed record with exactly `request`, `snapshot` and
 * `observation`; returns exactly one closed C-API result record, or throws `M2AdapterError` when no
 * closed result record can be shaped.
 */
export function invokeAdapter(input) {
  const outer = readClosed(input, ['request', 'snapshot', 'observation']);
  if (outer.error) throw new M2AdapterError(outer.error === 'UNKNOWN_FIELD' ? 'UNKNOWN_FIELD' : 'FAIL_CLOSED_INTERNAL');
  const { request, snapshot, observation } = outer.values;
  const requestShape = readClosed(request, REQUEST_FIELDS);
  const requestId = readMemberString(request, 'requestId');
  const operation = readMemberString(request, 'operation');
  if (requestId === null || requestId.length === 0 || operation === null) {
    throw new M2AdapterError(requestShape.error ?? 'INVALID_REQUEST');
  }
  const stateBefore = snapshotStateOf(snapshot);
  if (requestShape.error) return rejected(requestId, operation, stateBefore, stateBefore, requestShape.error);

  const levelCode = requestLevelCode(requestShape.values);
  if (levelCode !== null) return rejected(requestId, operation, stateBefore, stateBefore, levelCode);

  const derived = INTEGRATED_OPERATIONS.includes(operation)
    ? deriveDecision(operation, observation)
    : { error: 'UNSUPPORTED_OPERATION' };
  const bounds = boundCodes(requestShape.values, observation);
  const candidates = [...bounds];

  let decision = null;
  if (Object.hasOwn(derived, 'error')) {
    candidates.push(derived.error);
  } else if (Object.hasOwn(derived, 'unroutable')) {
    const gate = stateGateResult(snapshot, operation);
    const gateLevel = gate === null ? 10 : levelOf(gate.result.code);
    if (gate !== null && gateLevel < 10) decision = gate;
    else candidates.push(derived.unroutable);
  } else {
    const event = { operation, applicableErrors: [], facts: derived.facts };
    if (derived.commitOutcome !== null) {
      event.commitOutcome = derived.commitOutcome;
      event.operationIdentity = derived.operationIdentity;
    }
    try {
      decision = transitionAdapter(snapshot, event);
    } catch {
      candidates.push('FAIL_CLOSED_INTERNAL');
    }
    if (decision !== null && decision.result.kind === 'REJECTED') candidates.push(decision.result.code);
  }

  if (candidates.length > 0 && (decision === null || levelOf(worst(candidates)) < levelOf(decision.result.code))) {
    const code = worst(candidates);
    if (decision === null || levelOf(code) < levelOf(decision.result.code)
      || (levelOf(code) === levelOf(decision.result.code) && rankOf(code) < rankOf(decision.result.code))) {
      return rejected(requestId, operation, stateBefore, stateBefore, code);
    }
  }
  if (decision === null) return rejected(requestId, operation, stateBefore, stateBefore, 'FAIL_CLOSED_INTERNAL');
  if (decision.result.kind === 'REJECTED') {
    return rejected(requestId, operation, decision.result.stateBefore, decision.result.stateAfter, decision.result.code);
  }
  return shapeDecision(decision, requestId, operation, derived.stagedOutput ?? null);
}

/** Frozen metadata: exactly the closed members the contract names. */
export const M2_ADAPTER = Object.freeze({
  API,
  OPERATIONS,
  INTEGRATED_OPERATIONS,
  STATES,
  RESULT_KINDS,
  COMMIT_OUTCOMES,
  SUCCESS_CODES,
  ERROR_CODES,
  CODE_TO_KIND,
  PROFILE,
  OUTPUT_BY_SUCCESS_CODE,
  INPUT_BY_OPERATION,
  RESTORE_DISPOSITIONS,
  BOUNDS,
});
