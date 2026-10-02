// adapter.js — M2 session adapter integration: onboarding/re-establishment, opaque application
// messages and the C-RET replay/retention window.
// (card I-JOIN of #317 G-SCOPE, contract Issue #407; extended by card I-MSG, contract Issue #411.)
//
// This is the semantic integration boundary of the M2 session adapter API. It accepts exactly the
// closed C-API request record for the five operations it integrates (`CREATE`, `RESTORE`,
// `JOIN_WELCOME`, `PROTECT_APPLICATION`, `OPEN_APPLICATION`), reads the owning-layer facts from an
// INJECTED closed observation, applies the C-RET current-plus-five-past-epoch replay/retention window
// to the declared framing epoch of `OPEN_APPLICATION` before any key-dependent work, takes the
// decision with the merged I-SM decision core and, for `RESTORE`, with the merged I-REST classifier,
// releases output only on a `COMMITTED` tri-state, and emits exactly one closed C-API result record of
// the five ratified kinds.
//
// It performs no I/O, no cryptography, no storage call, no lock acquisition, no worker call and no
// transport action: the request, the current snapshot and the owning-layer observation are injected.
//
// Ratified inputs copied verbatim (see contract Issues #402 and #411 "Frozen shared interfaces"):
//   C-API  docs/architecture/m2/adapter-contract.md  sha256 b77d39fb…05ad9  (#319 5886838783)
//   C-RET  docs/security/m2-retention-and-disposal-limits.md sha256 eb051194…b31a2 (#328 5893776065)
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
 * The five operations this module integrates. The other three remain valid C-API operations; this
 * module's closed dispatch refuses them with `UNSUPPORTED_OPERATION` (contract Issues #402 and #411,
 * "Open owner questions").
 */
const INTEGRATED_OPERATIONS = Object.freeze([
  'CREATE', 'RESTORE', 'JOIN_WELCOME', 'PROTECT_APPLICATION', 'OPEN_APPLICATION',
]);

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

/**
 * C-API `/withinLevelErrorOrder`, transcribed exactly: level `P01` to `P10`, each with its ratified
 * within-level order. Both the level and the within-level rank of every error code derive from it.
 */
const WITHIN_LEVEL_ERROR_ORDER = Object.freeze([
  Object.freeze(['UNKNOWN_FIELD', 'INVALID_REQUEST', 'UNKNOWN_VALUE']),
  Object.freeze(['UNSUPPORTED_API_VERSION']),
  Object.freeze(['UNSUPPORTED_PROFILE', 'BINDING_MISMATCH']),
  Object.freeze(['UNSUPPORTED_OPERATION']),
  Object.freeze([
    'RECONCILIATION_REQUIRED', 'SESSION_ALREADY_EXISTS', 'NO_ACTIVE_SESSION', 'NO_STORED_SESSION',
    'NO_RECONCILIATION_PENDING', 'RECONCILIATION_REFERENCE_MISMATCH',
  ]),
  Object.freeze(['VALUE_OUT_OF_RANGE']),
  Object.freeze(['EPOCH_OUTSIDE_RETAINED_WINDOW', 'FUTURE_EPOCH']),
  Object.freeze(['AUTHENTICATION_FAILED', 'AUTHENTICATED_STATE_INCONSISTENT']),
  Object.freeze([
    'STORED_SESSION_INCOMPATIBLE', 'UNSUPPORTED_ONBOARDING', 'WELCOME_NO_MATCHING_KEY_PACKAGE',
    'UNSUPPORTED_UPDATE_FORM', 'UNSUPPORTED_COMMIT_SHAPE', 'KEY_PACKAGE_ALREADY_CONSUMED',
  ]),
  Object.freeze(['FAIL_CLOSED_INTERNAL']),
]);

/** C-API `/errorPrecedenceLevel`: the level (1 to 10) of each closed error code. */
const ERROR_LEVEL = Object.freeze(Object.fromEntries(
  WITHIN_LEVEL_ERROR_ORDER.flatMap((codes, index) => codes.map((code) => [code, index + 1])),
));

/** The ratified within-level tie-break: the position of each code in `/withinLevelErrorOrder`. */
const ERROR_RANK = Object.freeze(Object.fromEntries(
  WITHIN_LEVEL_ERROR_ORDER.flat().map((code, index) => [code, index]),
));

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

/**
 * C-API `/request/inputByOperation`, transcribed exactly for all eight operations, so that a
 * malformed `input` is a P01 defect even for an operation this card does not integrate.
 */
const INPUT_BY_OPERATION = Object.freeze({
  CREATE: Object.freeze(['peerFramedKeyPackage']),
  RESTORE: Object.freeze([]),
  JOIN_WELCOME: Object.freeze(['embeddedTreeWelcome']),
  PROTECT_APPLICATION: Object.freeze(['applicationBytes']),
  OPEN_APPLICATION: Object.freeze(['protectedApplicationMessage']),
  SELF_UPDATE: Object.freeze([]),
  APPLY_PEER_UPDATE: Object.freeze(['protectedCommitBytes']),
  RECONCILE_INDETERMINATE: Object.freeze(['reconciliationRef']),
});

/** The `AP_OPAQUE_BYTES` members of `/request/inputByOperation`. */
const INPUT_BYTES = Object.freeze([
  'peerFramedKeyPackage', 'embeddedTreeWelcome', 'applicationBytes', 'protectedApplicationMessage',
  'protectedCommitBytes',
]);

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

/**
 * The single opaque-bytes output member each success code that carries one releases, so the plan
 * component held in the mutation and the released output member cannot drift apart. A success code
 * absent here (or with an empty member list) releases no opaque-bytes output.
 */
const OUTPUT_MEMBER_BY_SUCCESS_CODE = Object.freeze({
  CREATED: 'embeddedTreeWelcome',
  APPLICATION_PROTECTED: 'protectedApplicationBytes',
  APPLICATION_OPENED: 'applicationBytes',
});

/** The C-API-owning rule of the I-SM decision rows this module consumes: the `RS_TRI_STATE` rows. */
const TRI_STATE_ROWS = Object.freeze(['CAPI-S001', 'CAPI-S006', 'CAPI-S009', 'CAPI-S010']);

/**
 * The C-MUT-owning rule of the I-SM decision rows this module consumes whose complete logical mutation
 * holds an `OUTPUT_ESCROW` component (`HELD`): the rows that must carry staged output to succeed.
 * `CAPI-S006` holds no output (its output kind is `NONE`), so it is deliberately absent here.
 */
const STAGED_OUTPUT_ROWS = Object.freeze(['CAPI-S001', 'CAPI-S009', 'CAPI-S010']);

/**
 * The closed C-REST outcome to C-API disposition mapping of the contract. The first column is the
 * complete C-REST `resultSets` union; no other outcome can be classified. `MANIFEST_INVALID` is the
 * C-REST `MANIFEST_ROOT` failure (manifest or keyed-root mismatch) and therefore C-API CAPI-S005
 * "authentication or keyed-root validation fails" -> `AUTHENTICATION_FAILED`.
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
  MANIFEST_INVALID: 'AUTHENTICATION_FAILED',
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
  MANIFEST_INVALID: 'AUTHENTICATION_FAILED',
  RECORD_SET_INCOMPLETE: 'AUTHENTICATED_RECORD_INCONSISTENT',
  RECORD_INVALID: 'AUTHENTICATED_RECORD_INCONSISTENT',
  REFERENCE_INCONSISTENT: 'AUTHENTICATED_RECORD_INCONSISTENT',
  PARTIAL_GENERATION: 'AUTHENTICATED_RECORD_INCONSISTENT',
});

/**
 * The bounds this module selects for the adapter boundary. C-API §4 leaves the bounded-byte limits to
 * a later selection; this is that selection for this boundary only. Over-limit values reject, never
 * truncate. `MAX_FRAMING_EPOCH` bounds the structural epoch count of a declared framing epoch and of
 * the authoritative current epoch (`CAPI-E014`, `VALUE_OUT_OF_RANGE` at `P06`).
 */
const BOUNDS = Object.freeze({
  MAX_REQUEST_ID_CHARS: 128,
  MAX_BINDING_REF_BYTES: 4096,
  MAX_OPAQUE_BYTES: 1048576,
  MAX_FRAMING_EPOCH: 2147483647,
});

/**
 * The ratified C-RET replay/retention window this module applies, transcribed from the C-RET §12
 * normative `epochRule` of `docs/security/m2-retention-and-disposal-limits.md`
 * (sha256 `eb051194620d795fc047cae367e4cd8e6c26c568fddae5a2986cdbc7549b31a2`, #328 comment
 * `5893776065`). `PAST_EPOCHS_ONCE_AVAILABLE` is byte-equal to the C-API `profile.pastEpochWindow`.
 * The window is never reduced and never extended here, and this module disposes no material.
 */
const RETENTION = Object.freeze({
  CURRENT_EPOCHS: 1,
  MAXIMUM_PAST_EPOCHS: 5,
  PAST_EPOCHS_ONCE_AVAILABLE: 5,
});

/** The closed observation member sets, one per integrated operation. */
const OBSERVATION_KEYS = Object.freeze({
  CREATE: Object.freeze(['onboarding', 'commitOutcome', 'operationIdentity', 'stagedOutput']),
  JOIN_WELCOME: Object.freeze(['keyPackage', 'commitOutcome', 'operationIdentity']),
  RESTORE: Object.freeze(['restoreObservation']),
  PROTECT_APPLICATION: Object.freeze(['commitOutcome', 'operationIdentity', 'stagedOutput']),
  OPEN_APPLICATION: Object.freeze([
    'currentEpoch', 'framingEpoch', 'authentication', 'replayIdentity', 'commitOutcome',
    'operationIdentity', 'stagedOutput',
  ]),
});

/** The closed key-dependent authentication verdicts of an in-window `OPEN_APPLICATION` framing. */
const AUTHENTICATION_VALUES = Object.freeze(['AUTHENTICATED', 'AUTHENTICATION_FAILED']);

/** The closed replay verdicts of an authenticated in-window `OPEN_APPLICATION` identity. */
const REPLAY_IDENTITY_VALUES = Object.freeze(['UNSEEN', 'DUPLICATE']);

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
/** The intrinsic `byteLength` getter: an own `byteLength` property on a byte array is never read. */
const TYPED_ARRAY_BYTE_LENGTH = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, 'byteLength').get;

/**
 * The only error this module throws. It carries a C-API error code and nothing else: no free text, no
 * field name, no value, no path and no offending input. It is thrown exactly when a closed C-API
 * result record cannot be shaped at all, because the request does not carry a readable `requestId`
 * and `operation`, the snapshot carries no readable state, or one of the three input members is
 * unreadable. Any other internal exception is converted to it with `FAIL_CLOSED_INTERNAL`.
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

/** The intrinsic byte length of a value `isUint8Array` accepted, or `-1` when it cannot be read. */
function byteLengthOf(bytes) {
  try {
    return TYPED_ARRAY_BYTE_LENGTH.call(bytes);
  } catch {
    return -1;
  }
}

/**
 * Read a closed record: every own key must be an allowed member, every allowed member must be present,
 * every member must be a plain own data property. No accessor is ever invoked: members are read from
 * their property descriptors. Returns `{ error, values }` with a C-API error code.
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

/** Whether `code` preempts the code of `decision` under the C-API total precedence. */
function preempts(code, decision) {
  if (decision === null) return true;
  const other = decision.result.code;
  return levelOf(code) < levelOf(other) || (levelOf(code) === levelOf(other) && rankOf(code) < rankOf(other));
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

function rejected(requestId, operation, stateBefore, code) {
  return resultRecord(requestId, operation, 'REJECTED', stateBefore, stateBefore, { error: freezeData({ code }) });
}

/** The P01 to P04 error code of a closed request record, or `null`. */
function requestLevelCode(value) {
  const candidates = [];
  if (typeof value.api !== 'string') candidates.push('INVALID_REQUEST');
  else if (value.api !== API) candidates.push('UNSUPPORTED_API_VERSION');

  const profileShape = readClosed(value.profile, PROFILE_KEYS);
  if (profileShape.error) candidates.push('UNSUPPORTED_PROFILE');
  else if (profileShape.values.adapterApi !== value.api) candidates.push('UNSUPPORTED_API_VERSION');
  else if (PROFILE_KEYS.some((key) => profileShape.values[key] !== PROFILE[key])) candidates.push('UNSUPPORTED_PROFILE');

  if (!isUint8Array(value.bindingRef)) {
    // C-API §4: the binding reference is opaque AP bytes; anything that is not a `Uint8Array` is
    // malformed framing at P01, while an empty or over-bound reference is `BINDING_MISMATCH` at P03.
    candidates.push('INVALID_REQUEST');
  } else {
    const length = byteLengthOf(value.bindingRef);
    if (length < 0) candidates.push('INVALID_REQUEST');
    else if (length === 0 || length > BOUNDS.MAX_BINDING_REF_BYTES) candidates.push('BINDING_MISMATCH');
  }

  if (typeof value.operation !== 'string' || !OPERATIONS.includes(value.operation)) {
    candidates.push('UNSUPPORTED_OPERATION');
  } else {
    if (!INTEGRATED_OPERATIONS.includes(value.operation)) candidates.push('UNSUPPORTED_OPERATION');
    // C-API `/request/inputByOperation` closes `input` for every operation of `operationEnum`, so a
    // malformed `input` is a P01 defect that preempts the P04 refusal of a non-integrated operation.
    const inputShape = readClosed(value.input, INPUT_BY_OPERATION[value.operation]);
    if (inputShape.error) candidates.push(inputShape.error);
    else if (INPUT_BY_OPERATION[value.operation].some((key) => INPUT_BYTES.includes(key)
      && (!isUint8Array(inputShape.values[key]) || byteLengthOf(inputShape.values[key]) < 0))) {
      candidates.push('INVALID_REQUEST');
    }
  }

  if (typeof value.requestId !== 'string' || value.requestId.length === 0) candidates.push('INVALID_REQUEST');
  return candidates.length === 0 ? null : worst(candidates);
}

/** The P06 bound codes of an admissible request (no P01 to P04 defect), or an empty list. */
function requestBoundCodes(value) {
  const candidates = [];
  if (value.requestId.length > BOUNDS.MAX_REQUEST_ID_CHARS) candidates.push('VALUE_OUT_OF_RANGE');
  const inputShape = readClosed(value.input, INPUT_BY_OPERATION[value.operation]);
  for (const key of INPUT_BY_OPERATION[value.operation]) {
    if (INPUT_BYTES.includes(key) && byteLengthOf(inputShape.values[key]) > BOUNDS.MAX_OPAQUE_BYTES) {
      candidates.push('VALUE_OUT_OF_RANGE');
    }
  }
  return candidates;
}

function validateRequestRecord(request) {
  const shape = readClosed(request, REQUEST_FIELDS);
  if (shape.error) return { code: shape.error, values: null };
  const levelCode = requestLevelCode(shape.values);
  return { code: levelCode, values: shape.values };
}

/**
 * Validate the closed C-API request alone — the pre-commit request gate. Returns a frozen
 * `{ ok, code }` record: `code` is the exact C-API error code of the highest-precedence request-level
 * defect (P01 to P04, and the P06 bounds of the request), or `null` when the request itself is
 * admissible. The state gate and the owning-layer decision are not decided here.
 */
export function validateAdapterRequest(request) {
  try {
    const checked = validateRequestRecord(request);
    if (checked.code !== null) return freezeData({ ok: false, code: checked.code });
    const bounds = requestBoundCodes(checked.values);
    const code = bounds.length === 0 ? null : worst(bounds);
    return freezeData({ ok: code === null, code });
  } catch {
    return freezeData({ ok: false, code: 'FAIL_CLOSED_INTERNAL' });
  }
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

/** Read the M2 snapshot state. Throws when the snapshot carries no readable C-API state at all. */
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
 * The P01 code of a snapshot that is not a closed I-SM snapshot (exactly `state` and `held`, with a
 * valid hold), or `null`. The check is the merged I-SM core's own: an invalid snapshot is the one for
 * which `transitionAdapter` returns no next snapshot.
 */
function snapshotShapeCode(snapshot) {
  let decision;
  try {
    decision = transitionAdapter(snapshot, { operation: 'RESTORE', applicableErrors: [], facts: 'NO_STORED_SESSION' });
  } catch {
    return 'FAIL_CLOSED_INTERNAL';
  }
  return decision.snapshot === null ? decision.result.code : null;
}

/** Read an opaque byte member of a closed staged-output record, or `null` when the record is `null`. */
function readStagedBytes(stagedOutput, member) {
  if (stagedOutput === null) return { error: null, staged: null };
  const stagedShape = readClosed(stagedOutput, [member]);
  if (stagedShape.error) return { error: stagedShape.error, staged: null };
  const bytes = stagedShape.values[member];
  if (!isUint8Array(bytes)) return { error: 'INVALID_REQUEST', staged: null };
  const length = byteLengthOf(bytes);
  if (length < 0) return { error: 'INVALID_REQUEST', staged: null };
  return { error: null, staged: { bytes, length } };
}

/** Read the closed RS tri-state and the identity of the staged mutation, or an error code. */
function readCommitTrio(value) {
  if (typeof value.commitOutcome !== 'string') return { error: 'INVALID_REQUEST' };
  if (!COMMIT_OUTCOMES.includes(value.commitOutcome)) return { error: 'UNKNOWN_VALUE' };
  if (typeof value.operationIdentity !== 'string' || value.operationIdentity.length === 0) {
    return { error: 'INVALID_REQUEST' };
  }
  return { error: null };
}

/** Whether an observation member the closed table requires to be absent is exactly `null`. */
function mustBeNull(value) {
  return value === null;
}

/**
 * Read the closed `PROTECT_APPLICATION` observation: the RS tri-state, the identity of the staged
 * mutation and the staged protected bytes. Every member is always present; `commitOutcome` is never
 * `null`, because an admissible `PROTECT_APPLICATION` in `ACTIVE` always requests one RS outcome.
 */
function readProtectObservation(value) {
  const trio = readCommitTrio(value);
  if (trio.error) return { error: trio.error };
  const staged = readStagedBytes(value.stagedOutput, 'protectedApplicationBytes');
  if (staged.error) return { error: staged.error };
  return {
    error: null,
    facts: 'SUPPORTED',
    applicableErrors: [],
    commitOutcome: value.commitOutcome,
    operationIdentity: value.operationIdentity,
    staged: staged.staged,
  };
}

/**
 * Read the closed `OPEN_APPLICATION` observation and classify the declared framing epoch against the
 * authoritative current epoch, structurally and without trusting content, at `P07`. Only distance `0`
 * through `RETENTION.PAST_EPOCHS_ONCE_AVAILABLE` continues to authentication and replay. The return
 * carries the derived I-SM fact, the applicable authenticated errors and, when a commit request is
 * reachable, the RS tri-state and the staged plaintext.
 */
function readOpenObservation(value) {
  for (const epoch of [value.currentEpoch, value.framingEpoch]) {
    if (typeof epoch !== 'number' || !Number.isSafeInteger(epoch) || epoch < 0) {
      return { error: 'INVALID_REQUEST' };
    }
  }
  // `P06` is a structural bound on the epoch count; it is decided before the `P07` window rejection.
  // The bound is reported with the strength of a `P07` window rejection (`FUTURE`), so that only
  // `P01` to `P05` can preempt it and the core still yields the `P05` state gate in a state that
  // refuses the operation.
  if (value.currentEpoch > BOUNDS.MAX_FRAMING_EPOCH || value.framingEpoch > BOUNDS.MAX_FRAMING_EPOCH) {
    return {
      error: null,
      bounds: ['VALUE_OUT_OF_RANGE'],
      facts: 'FUTURE',
      applicableErrors: [],
      commitOutcome: null,
      operationIdentity: null,
      staged: null,
    };
  }
  const distance = value.currentEpoch - value.framingEpoch;
  if (distance < 0 || distance > RETENTION.PAST_EPOCHS_ONCE_AVAILABLE) {
    // The window decides before any key-dependent work: authentication, replay lookup and the RS
    // tri-state are unreachable and must be exactly `null`.
    const nulls = [value.authentication, value.replayIdentity, value.commitOutcome,
      value.operationIdentity, value.stagedOutput];
    if (!nulls.every(mustBeNull)) return { error: 'INVALID_REQUEST' };
    return {
      error: null,
      facts: distance < 0 ? 'FUTURE' : 'PAST_OUTSIDE_WINDOW',
      applicableErrors: [],
      commitOutcome: null,
      operationIdentity: null,
      staged: null,
    };
  }
  if (typeof value.authentication !== 'string') return { error: 'INVALID_REQUEST' };
  if (!AUTHENTICATION_VALUES.includes(value.authentication)) return { error: 'UNKNOWN_VALUE' };
  if (value.authentication === 'AUTHENTICATION_FAILED') {
    if (![value.replayIdentity, value.commitOutcome, value.operationIdentity, value.stagedOutput].every(mustBeNull)) {
      return { error: 'INVALID_REQUEST' };
    }
    return {
      error: null,
      facts: 'UNSEEN_IN_WINDOW',
      applicableErrors: ['AUTHENTICATION_FAILED'],
      commitOutcome: null,
      operationIdentity: null,
      staged: null,
    };
  }
  if (typeof value.replayIdentity !== 'string') return { error: 'INVALID_REQUEST' };
  if (!REPLAY_IDENTITY_VALUES.includes(value.replayIdentity)) return { error: 'UNKNOWN_VALUE' };
  if (value.replayIdentity === 'DUPLICATE') {
    if (![value.commitOutcome, value.operationIdentity, value.stagedOutput].every(mustBeNull)) {
      return { error: 'INVALID_REQUEST' };
    }
    return {
      error: null,
      facts: 'DUPLICATE_IN_WINDOW',
      applicableErrors: [],
      commitOutcome: null,
      operationIdentity: null,
      staged: null,
    };
  }
  const trio = readCommitTrio(value);
  if (trio.error) return { error: trio.error };
  const staged = readStagedBytes(value.stagedOutput, 'applicationBytes');
  if (staged.error) return { error: staged.error };
  return {
    error: null,
    facts: 'UNSEEN_IN_WINDOW',
    applicableErrors: [],
    commitOutcome: value.commitOutcome,
    operationIdentity: value.operationIdentity,
    staged: staged.staged,
  };
}

/**
 * Read the closed observation of one integrated operation, at P01: an unknown member is
 * `UNKNOWN_FIELD`, a missing, accessor or out-of-type member is `INVALID_REQUEST`, an out-of-set value
 * is `UNKNOWN_VALUE`. No accessor is invoked. Returns `{ error }`, or the decoded observation, or the
 * `P06` structural bound codes the observation establishes.
 */
function readObservation(operation, observation) {
  const shape = readClosed(observation, OBSERVATION_KEYS[operation]);
  if (shape.error) return { error: shape.error };
  const value = shape.values;

  if (operation === 'RESTORE') {
    const inner = readClosed(value.restoreObservation, RESTORE_OBSERVATION_KEYS);
    if (inner.error) return { error: inner.error };
    return { error: null, restoreObservation: inner.values };
  }

  if (operation === 'PROTECT_APPLICATION') return readProtectObservation(value);
  if (operation === 'OPEN_APPLICATION') return readOpenObservation(value);

  const factKey = operation === 'CREATE' ? 'onboarding' : 'keyPackage';
  const allowed = operation === 'CREATE' ? ONBOARDING_VALUES : KEY_PACKAGE_VALUES;
  if (typeof value[factKey] !== 'string') return { error: 'INVALID_REQUEST' };
  if (!allowed.includes(value[factKey])) return { error: 'UNKNOWN_VALUE' };
  const facts = operation === 'CREATE' ? value.onboarding : JOIN_FACTS[value.keyPackage];
  const reached = facts === 'SUPPORTED';

  if (!reached) {
    if (value.commitOutcome !== null || value.operationIdentity !== null) return { error: 'INVALID_REQUEST' };
    if (operation === 'CREATE' && value.stagedOutput !== null) return { error: 'INVALID_REQUEST' };
    return { error: null, facts, commitOutcome: null, operationIdentity: null, staged: null };
  }

  if (typeof value.commitOutcome !== 'string') return { error: 'INVALID_REQUEST' };
  if (!COMMIT_OUTCOMES.includes(value.commitOutcome)) return { error: 'UNKNOWN_VALUE' };
  if (typeof value.operationIdentity !== 'string' || value.operationIdentity.length === 0) {
    return { error: 'INVALID_REQUEST' };
  }
  let staged = null;
  if (operation === 'CREATE' && value.stagedOutput !== null) {
    const stagedShape = readClosed(value.stagedOutput, ['embeddedTreeWelcome']);
    if (stagedShape.error) return { error: stagedShape.error };
    const bytes = stagedShape.values.embeddedTreeWelcome;
    if (!isUint8Array(bytes)) return { error: 'INVALID_REQUEST' };
    const length = byteLengthOf(bytes);
    if (length < 0) return { error: 'INVALID_REQUEST' };
    staged = { bytes, length };
  }
  return { error: null, facts, commitOutcome: value.commitOutcome, operationIdentity: value.operationIdentity, staged };
}

/** Run the merged I-SM core; an exception or a malformed return is `null` (an internal failure). */
function decide(snapshot, event) {
  try {
    const decision = transitionAdapter(snapshot, event);
    if (decision === null || typeof decision !== 'object' || decision.result === null
      || typeof decision.result !== 'object') {
      return null;
    }
    return decision;
  } catch {
    return null;
  }
}

/**
 * The owning-layer `RESTORE` decision: classify the closed C-REST observation with the merged I-REST
 * classifier and map its outcome. Returns `{ decision, code }`: an I-SM decision, and/or the C-API
 * code of an outcome that cannot be routed through a ratified decision row.
 */
function decideRestore(snapshot, restoreObservation) {
  let outcome;
  try {
    outcome = classifyRestore({ ...restoreObservation });
  } catch {
    return { decision: null, code: 'FAIL_CLOSED_INTERNAL' };
  }
  if (outcome === null || typeof outcome !== 'object' || !Object.isFrozen(outcome)
    || typeof outcome.result !== 'string' || !Object.hasOwn(RESTORE_DISPOSITIONS, outcome.result)) {
    return { decision: null, code: 'FAIL_CLOSED_INTERNAL' };
  }
  if (Object.hasOwn(RESTORE_FACTS, outcome.result)) {
    const decision = decide(snapshot, { operation: 'RESTORE', applicableErrors: [], facts: RESTORE_FACTS[outcome.result] });
    return decision === null ? { decision: null, code: 'FAIL_CLOSED_INTERNAL' } : { decision, code: null };
  }
  // `LOCKED_ELSEWHERE` and `INTERNAL_VALIDATION_FAILED` have no ratified decision row: only the P05
  // state gate of the current state can preempt their P10 disposition.
  const gate = decide(snapshot, { operation: 'RESTORE', applicableErrors: [], facts: 'NO_STORED_SESSION' });
  const isGate = gate !== null && typeof gate.result.scenario === 'string' && gate.result.scenario.startsWith('CAPI-G');
  return { decision: isGate ? gate : null, code: RESTORE_DISPOSITIONS[outcome.result] };
}

function shapeDecision(decision, requestId, operation, staged) {
  const result = decision.result;
  const kind = result.kind;
  const base = [requestId, operation, kind, result.stateBefore, result.stateAfter];
  if (kind === 'NOT_COMMITTED') return resultRecord(...base, { commitOutcome: 'NOT_COMMITTED' });
  if (kind === 'INDETERMINATE') {
    return resultRecord(...base, {
      commitOutcome: 'INDETERMINATE',
      reconciliationRef: result.reconciliationRef,
      originalStateBefore: result.originalStateBefore,
    });
  }
  const extra = { successCode: result.code };
  if (TRI_STATE_ROWS.includes(result.scenario)) extra.commitOutcome = 'COMMITTED';
  // C-API `/rules/payloadRelease` and `/response/outputBySuccessCode`: the plaintext is released only
  // on `SUCCESS`, only after `COMMITTED`, and only through the output member of the success code.
  if (kind === 'SUCCESS' && staged !== null) {
    const member = OUTPUT_MEMBER_BY_SUCCESS_CODE[result.code];
    if (member !== undefined) extra.output = { [member]: new Uint8Array(staged.bytes) };
  }
  return resultRecord(...base, extra);
}

function transitionResult(result, snapshot) {
  return freezeData({ result, snapshot });
}

function rejectedTransition(requestId, operation, stateBefore, code) {
  return transitionResult(rejected(requestId, operation, stateBefore, code), null);
}

function decisionTransition(decision, requestId, operation, staged) {
  if (decision.result.kind === 'REJECTED') {
    return rejectedTransition(requestId, operation, decision.result.stateBefore, decision.result.code);
  }
  return transitionResult(shapeDecision(decision, requestId, operation, staged), decision.snapshot);
}

function run(input) {
  const outer = readClosed(input, ['request', 'snapshot', 'observation']);
  if (outer.error) throw new M2AdapterError(outer.error === 'UNKNOWN_FIELD' ? 'UNKNOWN_FIELD' : 'FAIL_CLOSED_INTERNAL');
  const { request, snapshot, observation } = outer.values;
  const requestId = readMemberString(request, 'requestId');
  const operation = readMemberString(request, 'operation');
  if (requestId === null || requestId.length === 0 || operation === null) {
    const shape = readClosed(request, REQUEST_FIELDS);
    throw new M2AdapterError(shape.error ?? 'INVALID_REQUEST');
  }
  const stateBefore = snapshotStateOf(snapshot);

  // P01 to P04: the request, the snapshot and the observation are all checked before any level is
  // chosen, so a P01 defect of any of the three preempts every P02 to P04 defect.
  const checked = validateRequestRecord(request);
  const framing = [];
  if (checked.code !== null) framing.push(checked.code);
  const snapshotCode = snapshotShapeCode(snapshot);
  if (snapshotCode !== null) framing.push(snapshotCode);
  const observed = INTEGRATED_OPERATIONS.includes(operation) ? readObservation(operation, observation) : { error: null };
  if (observed.error) framing.push(observed.error);
  if (framing.length > 0) return rejectedTransition(requestId, operation, stateBefore, worst(framing));

  // P06: the request bounds and the structural epoch bound, decidable before any commit request
  // (see `validateAdapterRequest` and `readOpenObservation`).
  const bounds = [...requestBoundCodes(checked.values), ...(observed.bounds ?? [])];

  if (operation === 'RESTORE') {
    const restore = decideRestore(snapshot, observed.restoreObservation);
    const candidates = [...bounds];
    if (restore.code !== null) candidates.push(restore.code);
    if (restore.decision !== null && restore.decision.result.kind === 'REJECTED') candidates.push(restore.decision.result.code);
    if (candidates.length > 0) {
      const code = worst(candidates);
      if (preempts(code, restore.decision)) return rejectedTransition(requestId, operation, stateBefore, code);
    }
    if (restore.decision === null) return rejectedTransition(requestId, operation, stateBefore, 'FAIL_CLOSED_INTERNAL');
    return decisionTransition(restore.decision, requestId, operation, null);
  }

  // CREATE, JOIN_WELCOME, PROTECT_APPLICATION and OPEN_APPLICATION: one I-SM decision over the
  // operation, the authenticated facts and the applicable errors derived from the observation.
  const event = { operation, applicableErrors: [...(observed.applicableErrors ?? [])], facts: observed.facts };
  if (observed.commitOutcome !== null) {
    event.commitOutcome = observed.commitOutcome;
    event.operationIdentity = observed.operationIdentity;
  }
  const decision = decide(snapshot, event);
  if (decision === null) {
    return rejectedTransition(requestId, operation, stateBefore, worst([...bounds, 'FAIL_CLOSED_INTERNAL']));
  }
  if (decision.result.kind === 'REJECTED' || observed.commitOutcome === null) {
    // No RS commit request was made: every applicable error preempts by the C-API total precedence.
    const candidates = [...bounds];
    if (decision.result.kind === 'REJECTED') candidates.push(decision.result.code);
    if (candidates.length > 0) {
      const code = worst(candidates);
      if (preempts(code, decision)) return rejectedTransition(requestId, operation, stateBefore, code);
    }
    return decisionTransition(decision, requestId, operation, null);
  }

  // A commit request reached RS and RS answered with `observed.commitOutcome`. C-API
  // `/rules/internalFailureBoundary`: FAIL_CLOSED_INTERNAL applies only before any RS commit request;
  // after it the adapter never emits REJECTED. A defect this layer detects only now (a request bound,
  // a `CREATE` staged Welcome that is absent, empty or over the bound, or a staged opaque message of a
  // `PROTECT_APPLICATION` or of an in-window unseen `OPEN_APPLICATION` that is absent, empty or over
  // the bound) is therefore an internal failure after the request: `NOT_COMMITTED` stays
  // `NOT_COMMITTED` (RS proves absence), while `COMMITTED` and `INDETERMINATE` retain the held mutation
  // and enter `RECONCILIATION_REQUIRED` through the merged I-SM `INDETERMINATE` row, with no output and
  // no blind retry. The held mutation is the complete C-MUT logical mutation, which includes the
  // `REPLAY_RETENTION_STATE` component of the C-RET window.
  const commitTriStateRow = STAGED_OUTPUT_ROWS.includes(decision.result.scenario);
  const stagedDefect = commitTriStateRow
    && (observed.staged === null || observed.staged.length === 0 || observed.staged.length > BOUNDS.MAX_OPAQUE_BYTES);
  const defect = bounds.length > 0 || stagedDefect;
  if (!defect || observed.commitOutcome === 'NOT_COMMITTED') {
    return decisionTransition(decision, requestId, operation, defect ? null : observed.staged);
  }
  const held = decide(snapshot, { ...event, commitOutcome: 'INDETERMINATE' });
  if (held === null || held.result.kind !== 'INDETERMINATE') {
    throw new M2AdapterError('FAIL_CLOSED_INTERNAL');
  }
  return decisionTransition(held, requestId, operation, null);
}

/**
 * The integration entry point with the next snapshot. `input` is a closed record with exactly
 * `request`, `snapshot` and `observation`. Returns a frozen `{ result, snapshot }`: `result` is exactly
 * one closed C-API result record, and `snapshot` is the next I-SM snapshot the caller must hold — the
 * `ACTIVE` snapshot after `SUCCESS`, the unchanged state after `NOT_COMMITTED`, the
 * `RECONCILIATION_REQUIRED` snapshot carrying the held mutation after `INDETERMINATE` — or `null` after
 * `REJECTED`, whose state is unchanged. Throws only `M2AdapterError`, and only when no closed result
 * record can be shaped.
 */
export function invokeAdapterTransition(input) {
  try {
    return run(input);
  } catch (error) {
    if (error instanceof M2AdapterError) throw error;
    throw new M2AdapterError('FAIL_CLOSED_INTERNAL');
  }
}

/**
 * The integration entry point. Returns exactly one closed C-API result record — the `result` member of
 * `invokeAdapterTransition(input)` — or throws `M2AdapterError` when no closed result record can be
 * shaped.
 */
export function invokeAdapter(input) {
  return invokeAdapterTransition(input).result;
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
  RETENTION,
  OBSERVATION_KEYS,
});
