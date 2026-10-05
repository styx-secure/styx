// adapter.js — M2 session adapter integration: onboarding/re-establishment, opaque application
// messages and the C-RET replay/retention window, staged self-update and reconciliation.
// (cards I-JOIN, I-MSG and I-UPD of #317 G-SCOPE; contract Issues #402/#407, #411, and the I-UPD
// contract of record, revision R2, which supersedes #412 and #415 in exactly the clauses it records.)
//
// This is the semantic integration boundary of the M2 session adapter API. It accepts exactly the
// closed C-API request record for the seven operations it integrates (`CREATE`, `RESTORE`,
// `JOIN_WELCOME`, `PROTECT_APPLICATION`, `OPEN_APPLICATION`, `SELF_UPDATE`,
// `RECONCILE_INDETERMINATE`), reads the owning-layer facts from an INJECTED closed observation,
// applies the C-RET current-plus-five-past-epoch replay/retention window to the declared framing epoch
// of `OPEN_APPLICATION` before any key-dependent work, takes the decision with the merged I-SM decision
// core and, for `RESTORE`, with the merged I-REST classifier, releases output only on a `COMMITTED`
// tri-state (and, for reconciliation, only on an RS proof of commit), and emits exactly one closed
// C-API result record of the five ratified kinds.
//
// I-UPD adds the staged self-update and commit path and the reconciliation path. C-API
// `/rules/rsTriState` and `/rules/internalFailureBoundary` govern both: a supported proposal-free
// `SELF_UPDATE` whose RS outcome is `COMMITTED` releases the staged protected Commit exactly once,
// `NOT_COMMITTED` releases nothing and leaves the state unchanged, and an ambiguous outcome retains
// exactly one immutable held mutation in the `RECONCILIATION_REQUIRED` snapshot with no output and no
// blind retry; `RECONCILE_INDETERMINATE` is then the only operation C-API admits in that state.
//
// It performs no I/O, no cryptography, no storage call, no lock acquisition, no worker call and no
// transport action: the request, the current snapshot and the owning-layer observation are injected.
//
// Ratified inputs copied verbatim (see contract Issues #402 and #411 and the I-UPD contract of record
// "Frozen shared interfaces", unchanged from #412 beyond the clauses its revisions record):
//   C-API  docs/architecture/m2/adapter-contract.md  sha256 b77d39fb…05ad9  (#319 5886838783)
//   C-RET  docs/security/m2-retention-and-disposal-limits.md sha256 eb051194…b31a2 (#328 5893776065)
//   C-REST docs/architecture/m2/restore-compatibility.md sha256 853dbc41…766b6 (#332 5900545454)
//   C-BIND docs/architecture/m2/binding-v0.md        sha256 2ee9b022…1d4a42 (#323 5890060894)
//   C-MUT  docs/architecture/m2/mutation-table.md    sha256 6c2c045c…eb3060 (#324 5890545934)
//   C-FMT  docs/architecture/m2/storage-format.md    sha256 b57df3a8…32812  (#327 5898801523)
//   C-REC  docs/architecture/m2/recovery-and-coexistence.md sha256 5b0d2fbd…94f87 (#335 5909885218)
//   O-SCEN docs/architecture/m2/scenarios/clause-scenarios.md sha256 6c19a01c…4d37ae (#337 5912195865)

import { MUTATION_PLANS, transitionAdapter } from './state-machine.js';
import { classifyRestore } from '../../../storage/m2/session-restore.js';

/** The exact `adapterApi` constant of C-API §2. */
const API = 'styx-m2-session-adapter/v1';

/** The eight C-API `/operationEnum` members, in ratified order. */
const OPERATIONS = Object.freeze([
  'CREATE', 'RESTORE', 'JOIN_WELCOME', 'PROTECT_APPLICATION', 'OPEN_APPLICATION',
  'SELF_UPDATE', 'APPLY_PEER_UPDATE', 'RECONCILE_INDETERMINATE',
]);

/**
 * The seven operations this module integrates. The other one remains a valid C-API operation; this
 * module's closed dispatch refuses them with `UNSUPPORTED_OPERATION` (contract Issues #402 and #411
 * and the I-UPD contract of record, "Open owner questions" item 1). `APPLY_PEER_UPDATE` is owned by
 * I-FORK.
 */
const INTEGRATED_OPERATIONS = Object.freeze([
  'CREATE', 'RESTORE', 'JOIN_WELCOME', 'PROTECT_APPLICATION', 'OPEN_APPLICATION', 'SELF_UPDATE',
  'RECONCILE_INDETERMINATE',
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
 * The decision rows the C-MUT section 4 mutation plans drive: the `RS_TRI_STATE` rows this module
 * consumes (I-JOIN `CAPI-S001`/`CAPI-S006`, I-MSG `CAPI-S009`/`CAPI-S010`, I-UPD `CAPI-S014`).
 */
const TRI_STATE_ROWS = Object.freeze(['CAPI-S001', 'CAPI-S006', 'CAPI-S009', 'CAPI-S010', 'CAPI-S014']);

/**
 * The C-MUT-owning rule of the I-SM decision rows I-MSG's single decision path consumes whose complete
 * logical mutation holds an `OUTPUT_ESCROW` component (`HELD`): the rows that must carry staged output
 * to succeed. `CAPI-S006` holds no output (its output kind is `NONE`), so it is deliberately absent here.
 * `CAPI-S014` (`SELF_UPDATE`) is decided by the I-UPD path, whose staged escrow is checked against
 * `STAGED_OUTPUT_BY_CODE`.
 */
const STAGED_OUTPUT_ROWS = Object.freeze(['CAPI-S001', 'CAPI-S009', 'CAPI-S010']);

/**
 * The closed `SELF_UPDATE` observation values of `/request/inputByOperation`'s owning layer, and their
 * mapping onto the merged I-SM decision facts (C-API `/request/derivedByOperation` `SELF_UPDATE`:
 * `proposalFree`, `committerIdentity`, `protectedCommitBytes`).
 */
const UPDATE_FORMS = Object.freeze(['SUPPORTED', 'UNSUPPORTED_UPDATE_FORM']);
const UPDATE_FACTS = Object.freeze({
  SUPPORTED: 'SUPPORTED',
  UNSUPPORTED_UPDATE_FORM: 'UNSUPPORTED_UPDATE_FORM',
});

/**
 * C-API `/response/outputBySuccessCode` fixes, for each success code that releases bytes, the one
 * `output` member that carries them. This is the closed stage/release binding: a staged or held output
 * of another shape is never released, and no output is released under a code that fixes none.
 */
const STAGED_OUTPUT_BY_CODE = Object.freeze({
  CREATED: 'embeddedTreeWelcome',
  SELF_UPDATED: 'protectedCommitBytes',
});

/**
 * The five C-MUT escrow kinds of the merged I-TXN mutation rows, mapped onto the C-API `output` member
 * that carries them. `SELECTED_CANDIDATE_REF` is an opaque reference and not bytes. The I-MSG success
 * codes `APPLICATION_PROTECTED` and `APPLICATION_OPENED` release through the same map: their decision
 * names `PROTECTED_APPLICATION_BYTES` and `APPLICATION_BYTES`.
 */
const OUTPUT_MEMBER_BY_KIND = Object.freeze({
  EMBEDDED_TREE_WELCOME: 'embeddedTreeWelcome',
  PROTECTED_APPLICATION_BYTES: 'protectedApplicationBytes',
  APPLICATION_BYTES: 'applicationBytes',
  PROTECTED_COMMIT_BYTES: 'protectedCommitBytes',
  SELECTED_CANDIDATE_REF: 'selectedCandidateRef',
});
const REFERENCE_OUTPUT_MEMBERS = Object.freeze(['selectedCandidateRef']);
const OUTPUT_MEMBERS = Object.freeze(Object.values(OUTPUT_MEMBER_BY_KIND));

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
  MAX_RECONCILIATION_REF_CHARS: 256,
  // An RS tri-state proof's operation identity is echoed back inside the reconciliation reference the
  // merged I-SM issues (`I-SM-HOLD:<operationIdentity>`), so an identity longer than the reference bound
  // minus that prefix would make this module issue a reference it then refuses, locking the hold out of
  // every reconciliation. The bound is derived from the reference bound, never independent of it.
  MAX_OPERATION_IDENTITY_CHARS: 256 - 'I-SM-HOLD:'.length,
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
  PROTECT_APPLICATION: Object.freeze(['commitOutcome', 'operationIdentity', 'stagedOutput', 'internalFailure']),
  OPEN_APPLICATION: Object.freeze([
    'currentEpoch', 'framingEpoch', 'authentication', 'replayIdentity', 'commitOutcome',
    'operationIdentity', 'stagedOutput', 'internalFailure',
  ]),
  SELF_UPDATE: Object.freeze(['updateForm', 'commitOutcome', 'operationIdentity', 'stagedOutput', 'slotContext']),
  RECONCILE_INDETERMINATE: Object.freeze(['commitOutcome', 'responseEmission', 'heldOutput', 'slotContext']),
});

/**
 * C-BIND §4: `bindingRef` denotes exactly the 32 `localContextId` bytes of a local binding slot. The two
 * session-bound operations of this slice compare it at P03 with the authoritative slot context the SS
 * reports in the observation member `slotContext` (C-BIND `/comparisonRules/active` and
 * `/comparisonRules/reconciliationRequired`, C-API `CAPI-E006`).
 */
const BINDING_CONTEXT_BYTES = 32;
const SLOT_BOUND_OPERATIONS = Object.freeze(['SELF_UPDATE', 'RECONCILE_INDETERMINATE']);

/**
 * The operations whose observed RS `operationIdentity` is bounded at P06 by
 * `MAX_OPERATION_IDENTITY_CHARS` (contract R2 step 5, C-API `CAPI-E014`, C-MUT §3). The I-MSG operations
 * are not in this set: R2 keeps their integrated behaviour unchanged.
 */
const IDENTITY_BOUND_OPERATIONS = Object.freeze(['CREATE', 'JOIN_WELCOME', 'SELF_UPDATE']);

/** The two closed `responseEmission` values of the merged I-SM reconciliation rows. */
const RESPONSE_EMISSIONS = Object.freeze(['SUCCEEDED', 'INTERRUPTED']);

/**
 * The closed key-dependent authentication verdicts of an in-window `OPEN_APPLICATION` framing. The two
 * verdicts are the two `P08` rows of the C-API error set: `CAPI-E017` `AUTHENTICATION_FAILED` and
 * `CAPI-E018` `AUTHENTICATED_STATE_INCONSISTENT`.
 */
const AUTHENTICATION_VALUES = Object.freeze(['AUTHENTICATED', 'AUTHENTICATION_FAILED', 'AUTHENTICATED_STATE_INCONSISTENT']);

/** The closed verdict of an unclassified internal failure strictly before any RS commit request. */
const INTERNAL_FAILURE_VALUES = Object.freeze(['FAIL_CLOSED_INTERNAL']);

/**
 * The one observation member whose absence is equivalent to `null`, per operation: `internalFailure`
 * reports a failure of the owning layer that produced no verdict at all, so a caller that observed none
 * simply omits it. Every other member of a closed observation set is mandatory. The two I-UPD
 * operations read their observation with their own closed reader and are not listed here.
 */
const OPTIONAL_OBSERVATION_MEMBERS = Object.freeze({
  CREATE: Object.freeze([]),
  JOIN_WELCOME: Object.freeze([]),
  RESTORE: Object.freeze([]),
  PROTECT_APPLICATION: Object.freeze(['internalFailure']),
  OPEN_APPLICATION: Object.freeze(['internalFailure']),
});

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
 * Read one own property descriptor, or `null` when reading it raises. A hostile record can carry a proxy
 * trap that throws while its own member is being inspected (review finding p13a): the throw is a defect
 * of the record being read, never an error this module propagates, so every own-descriptor read goes
 * through this helper.
 */
function readOwnDescriptor(record, key) {
  try {
    return Object.getOwnPropertyDescriptor(record, key);
  } catch {
    return null;
  }
}

/**
 * Read a closed record: every own key must be an allowed member, every allowed member must be present,
 * every member must be a plain own data property. No accessor is ever invoked: members are read from
 * their property descriptors. Returns `{ error, values }` with a C-API error code.
 */
function readClosed(value, allowed, optional = []) {
  if (!isPlainObject(value)) return { error: 'INVALID_REQUEST', values: null };
  let keys;
  try {
    keys = Reflect.ownKeys(value);
  } catch {
    return { error: 'INVALID_REQUEST', values: null };
  }
  // C-API `/withinLevelErrorOrder` P01: UNKNOWN_FIELD preempts INVALID_REQUEST. Membership is decided
  // from the key list alone, so the answer never depends on member order or on a descriptor read that
  // fails. Each descriptor is then read exactly once, key by key: a read that throws is a shape defect of
  // that member only, and every other readable data member is still returned, as `partial`, so a caller
  // can let a nested record's own P01 defect compete in the same precedence. Nothing is read again.
  const unknown = keys.some((key) => typeof key !== 'string' || !allowed.includes(key));
  // Null-prototype maps: an own `__proto__` member is kept as a member, never taken as a prototype.
  const descriptors = Object.create(null);
  let unreadable = false;
  // The allowed members that are not a readable own data property: absent, accessor, non-enumerable, or
  // whose descriptor read threw. Reported with the error so a caller can tell which members failed.
  const bad = [];
  for (const key of keys) {
    if (typeof key !== 'string') continue;
    try {
      descriptors[key] = Reflect.getOwnPropertyDescriptor(value, key);
    } catch {
      unreadable = true;
      if (allowed.includes(key)) bad.push(key);
    }
  }
  const partial = Object.create(null);
  for (const key of Object.keys(descriptors)) {
    const descriptor = descriptors[key];
    if (descriptor && Object.hasOwn(descriptor, 'value')) partial[key] = descriptor.value;
  }
  for (const key of allowed) {
    if (bad.includes(key)) continue;
    const descriptor = Object.hasOwn(descriptors, key) ? descriptors[key] : undefined;
    // An absent optional member (I-MSG `internalFailure`) is equivalent to `null`, never a bad member.
    if (descriptor === undefined && optional.includes(key)) continue;
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) bad.push(key);
  }
  if (unknown) return { error: 'UNKNOWN_FIELD', values: null, partial, bad };
  if (unreadable) return { error: 'INVALID_REQUEST', values: null, partial, bad };
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) {
      return { error: 'INVALID_REQUEST', values: null, partial, bad };
    }
  }
  for (const key of allowed) {
    if (!Object.hasOwn(descriptors, key) && !optional.includes(key)) {
      return { error: 'INVALID_REQUEST', values: null, partial, bad };
    }
  }
  const values = {};
  for (const key of allowed) values[key] = Object.hasOwn(descriptors, key) ? descriptors[key].value : null;
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
function requestLevelCode(value, inputShape = null) {
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
    const shape = inputShape ?? readClosed(value.input, INPUT_BY_OPERATION[value.operation]);
    if (shape.error) candidates.push(shape.error);
    else if (INPUT_BY_OPERATION[value.operation].some((key) => INPUT_BYTES.includes(key)
      && (!isUint8Array(shape.values[key]) || byteLengthOf(shape.values[key]) < 0))) {
      candidates.push('INVALID_REQUEST');
    } else if (value.operation === 'RECONCILE_INDETERMINATE'
      && (typeof shape.values.reconciliationRef !== 'string'
        || shape.values.reconciliationRef.length === 0)) {
      // C-API `/request/inputByOperation` closes the reconcile input to one opaque
      // `reconciliationRef`; a missing, empty or non-string value is malformed framing at P01.
      candidates.push('INVALID_REQUEST');
    }
  }

  if (typeof value.requestId !== 'string' || value.requestId.length === 0) candidates.push('INVALID_REQUEST');
  return candidates.length === 0 ? null : worst(candidates);
}

/** The P06 bound codes of an admissible request (no P01 to P04 defect), or an empty list. */
function requestBoundCodes(value, inputShape = null) {
  const candidates = [];
  if (value.requestId.length > BOUNDS.MAX_REQUEST_ID_CHARS) candidates.push('VALUE_OUT_OF_RANGE');
  const shape = inputShape ?? readClosed(value.input, INPUT_BY_OPERATION[value.operation]);
  for (const key of INPUT_BY_OPERATION[value.operation]) {
    if (INPUT_BYTES.includes(key) && byteLengthOf(shape.values[key]) > BOUNDS.MAX_OPAQUE_BYTES) {
      candidates.push('VALUE_OUT_OF_RANGE');
    }
  }
  if (shape.error === null && value.operation === 'RECONCILE_INDETERMINATE'
    && typeof shape.values.reconciliationRef === 'string'
    && shape.values.reconciliationRef.length > BOUNDS.MAX_RECONCILIATION_REF_CHARS) {
    candidates.push('VALUE_OUT_OF_RANGE');
  }
  return candidates;
}

function validateRequestRecord(request, inputShape = null, decoded = null) {
  const shape = decoded ?? readClosed(request, REQUEST_FIELDS);
  if (shape.error) {
    // A malformed request record still lets the P01 defect of a readable `input` compete: C-API
    // `/withinLevelErrorOrder/P01` orders UNKNOWN_FIELD first whichever record carries it.
    const nested = inputShape && inputShape.error ? [inputShape.error] : [];
    return { code: worst([shape.error, ...nested]), values: null };
  }
  const levelCode = requestLevelCode(shape.values, inputShape);
  return { code: levelCode, values: shape.values };
}

/**
 * The decoded `input` of a request, read from the request's own decoded record and never through a
 * property get. When the request record itself is malformed, the input is still decoded from the readable
 * members (`partial`) so its P01 defect can compete; an unreadable or absent input contributes nothing.
 */
function decodeRequestInput(requestShape, operation) {
  if (typeof operation !== 'string' || !Object.hasOwn(INPUT_BY_OPERATION, operation)) return null;
  if (requestShape.error === null) return readClosed(requestShape.values.input, INPUT_BY_OPERATION[operation]);
  if (requestShape.partial && Object.hasOwn(requestShape.partial, 'input')) {
    return readClosed(requestShape.partial.input, INPUT_BY_OPERATION[operation]);
  }
  return null;
}

/**
 * Validate the closed C-API request alone — the pre-commit request gate. Returns a frozen
 * `{ ok, code }` record: `code` is the exact C-API error code of the highest-precedence request-level
 * defect (P01 to P04, and the P06 bounds of the request), or `null` when the request itself is
 * admissible. The state gate and the owning-layer decision are not decided here.
 */
export function validateAdapterRequest(request) {
  try {
    const decoded = readClosed(request, REQUEST_FIELDS);
    // One decoded record is used for every step below: the request is never read a second time, so a
    // Proxy cannot answer one record to the input check and another to the request check (cycle 5e review).
    const operation = decoded.error === null ? decoded.values.operation
      : (decoded.partial && typeof decoded.partial.operation === 'string' ? decoded.partial.operation : null);
    const decodedInput = decodeRequestInput(decoded, operation);
    const checked = validateRequestRecord(request, decodedInput, decoded);
    if (checked.code !== null) return freezeData({ ok: false, code: checked.code });
    const bounds = requestBoundCodes(checked.values, decodedInput);
    const code = bounds.length === 0 ? null : worst(bounds);
    return freezeData({ ok: code === null, code });
  } catch {
    return freezeData({ ok: false, code: 'FAIL_CLOSED_INTERNAL' });
  }
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
 * The closed member sets of an I-SM snapshot and of its hold, as the merged I-SM core defines them
 * (`state-machine.js`, not exported there and not modified by this card). They are used only to put
 * UNKNOWN_FIELD ahead of descriptor-shape defects; every other snapshot check stays the core's own.
 */
const SNAPSHOT_KEYS = Object.freeze(['state', 'held']);
const SNAPSHOT_HOLD_KEYS = Object.freeze(['originalStateBefore', 'scenario', 'mutationPlanIdentity', 'operationIdentity',
  'expectedSuccessCode', 'expectedStateAfter', 'outputKind', 'reconciliationRef', 'selectedCandidateRef', 'terminalEvidenceStatus']);

/**
 * The P01 code of a snapshot that is not a closed I-SM snapshot (exactly `state` and `held`, with a
 * valid hold), or `null`. The check is the merged I-SM core's own: an invalid snapshot is the one for
 * which `transitionAdapter` returns no next snapshot.
 */
function snapshotShapeCode(snapshot) {
  // C-API `/withinLevelErrorOrder/P01`: an unknown member of the snapshot, or of a plain hold inside
  // it, is UNKNOWN_FIELD whatever the member order, ahead of any descriptor-shape defect the merged
  // core would meet first while walking the members in order. The snapshot here is always the
  // adapter's own data copy (`snapshotOnce`), so these reads run no caller code.
  if (isPlainObject(snapshot)) {
    const keys = Reflect.ownKeys(snapshot);
    if (keys.some((key) => typeof key !== 'string' || !SNAPSHOT_KEYS.includes(key))) return 'UNKNOWN_FIELD';
    const held = Object.getOwnPropertyDescriptor(snapshot, 'held');
    if (held && Object.hasOwn(held, 'value') && isPlainObject(held.value)
      && Reflect.ownKeys(held.value).some((key) => typeof key !== 'string' || !SNAPSHOT_HOLD_KEYS.includes(key))) {
      return 'UNKNOWN_FIELD';
    }
  }
  let decision;
  try {
    decision = transitionAdapter(snapshot, { operation: 'RESTORE', applicableErrors: [], facts: 'NO_STORED_SESSION' });
  } catch {
    return 'FAIL_CLOSED_INTERNAL';
  }
  if (decision.snapshot !== null) return null;
  const coreCode = decision.result.code;
  // The core stops at the first hold value it rejects, and its out-of-set checks (`originalStateBefore`,
  // `scenario`: UNKNOWN_VALUE) come before its malformed-value checks (INVALID_REQUEST). P01 orders
  // INVALID_REQUEST first, so a hold that also carries a malformed value the out-of-set member cannot
  // explain answers INVALID_REQUEST: an identity that is not a non-empty string, a reference that is not
  // the one the identity fixes, or a terminal-evidence status outside its two values (cycle 5e review).
  if (coreCode === 'UNKNOWN_VALUE' && heldHasMalformedValue(snapshot)) return 'INVALID_REQUEST';
  return coreCode;
}

/** Whether a plain hold of data members carries a scenario-independent INVALID_REQUEST value. */
function heldHasMalformedValue(snapshot) {
  if (!isPlainObject(snapshot)) return false;
  const held = Object.getOwnPropertyDescriptor(snapshot, 'held');
  if (!held || !Object.hasOwn(held, 'value') || !isPlainObject(held.value)) return false;
  const values = Object.create(null);
  for (const key of SNAPSHOT_HOLD_KEYS) {
    const descriptor = Object.getOwnPropertyDescriptor(held.value, key);
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) return false;
    values[key] = descriptor.value;
  }
  // Checks that do not depend on the out-of-set member (C-API `/withinLevelErrorOrder/P01`, cycle 5f
  // review): the identity and the reference it fixes, the terminal-evidence status, and the plan identity
  // that must name the scenario.
  if (typeof values.operationIdentity !== 'string' || values.operationIdentity.length === 0) return true;
  if (values.reconciliationRef !== `I-SM-HOLD:${values.operationIdentity}`) return true;
  if (!['PENDING', 'COMMITTED'].includes(values.terminalEvidenceStatus)) return true;
  if (values.mutationPlanIdentity !== values.scenario) return true;
  // With a scenario in the closed set its plan is known, so every plan-fixed member is decidable whatever
  // `originalStateBefore` carries; the plan's own state is the out-of-set member's defect and is left to it.
  if (typeof values.scenario !== 'string' || !Object.hasOwn(MUTATION_PLANS, values.scenario)) return false;
  const plan = MUTATION_PLANS[values.scenario];
  if (values.expectedSuccessCode !== plan.successCode || values.expectedStateAfter !== plan.stateAfterCommitted
    || values.outputKind !== plan.outputKind) return true;
  if (values.scenario === 'CAPI-S017') {
    return typeof values.selectedCandidateRef !== 'string' || values.selectedCandidateRef.length === 0;
  }
  return values.selectedCandidateRef !== null;
}

/**
 * Read a staged output of the one member the releasing success code fixes. The member must be a
 * readable `Uint8Array`; anything else — an unknown member, a missing one, an accessor, a wrong type —
 * is a closed observation defect.
 */
function readStagedOutput(value, member) {
  const shape = readClosed(value, [member]);
  if (shape.error) return { error: shape.error, staged: null };
  const bytes = shape.values[member];
  if (!isUint8Array(bytes)) return { error: 'INVALID_REQUEST', staged: null };
  const length = byteLengthOf(bytes);
  if (length < 0) return { error: 'INVALID_REQUEST', staged: null };
  return { error: null, staged: { member, bytes, length } };
}

/**
 * Read the held escrow of a reconciliation: a closed record carrying exactly the one C-API `output`
 * member of the held C-MUT escrow kind, or a non-empty opaque reference for `SELECTED_CANDIDATE_REF`.
 */
function readHeldOutput(value) {
  if (!isPlainObject(value)) return { error: 'INVALID_REQUEST', heldOutput: null };
  let keys;
  try {
    keys = Reflect.ownKeys(value);
  } catch {
    return { error: 'INVALID_REQUEST', heldOutput: null };
  }
  if (keys.length !== 1) return { error: keys.length === 0 ? 'INVALID_REQUEST' : 'UNKNOWN_FIELD', heldOutput: null };
  const member = keys[0];
  if (typeof member !== 'string' || !OUTPUT_MEMBERS.includes(member)) {
    return { error: 'UNKNOWN_FIELD', heldOutput: null };
  }
  const descriptor = readOwnDescriptor(value, member);
  if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) {
    return { error: 'INVALID_REQUEST', heldOutput: null };
  }
  if (REFERENCE_OUTPUT_MEMBERS.includes(member)) {
    if (typeof descriptor.value !== 'string' || descriptor.value.length === 0) {
      return { error: 'INVALID_REQUEST', heldOutput: null };
    }
    return { error: null, heldOutput: { member, ref: descriptor.value } };
  }
  if (!isUint8Array(descriptor.value)) return { error: 'INVALID_REQUEST', heldOutput: null };
  const length = byteLengthOf(descriptor.value);
  if (length < 0) return { error: 'INVALID_REQUEST', heldOutput: null };
  return { error: null, heldOutput: { member, bytes: descriptor.value, length } };
}

/**
 * The authoritative slot context of a session-bound operation (C-BIND §4): exactly 32 nonzero
 * `localContextId` bytes, copied once. Returns the copy, or `null` for anything else.
 */
function readSlotContext(value) {
  if (!isUint8Array(value) || byteLengthOf(value) !== BINDING_CONTEXT_BYTES) return null;
  const copy = new Uint8Array(value);
  if (copy.length !== BINDING_CONTEXT_BYTES || copy.every((byte) => byte === 0)) return null;
  return copy;
}

/**
 * C-BIND `/comparisonRules`: byte equality of the request `bindingRef` with the authoritative slot
 * context, over all 32 bytes. Wrong length, unknown reference, byte mismatch and cross-context use are all
 * a mismatch; a partial match never authorizes.
 */
function bindingRefMatches(bindingRef, slotContext) {
  if (!isUint8Array(bindingRef) || byteLengthOf(bindingRef) !== BINDING_CONTEXT_BYTES) return false;
  const copy = new Uint8Array(bindingRef);
  if (copy.length !== BINDING_CONTEXT_BYTES) return false;
  let difference = 0;
  for (let index = 0; index < BINDING_CONTEXT_BYTES; index += 1) difference |= copy[index] ^ slotContext[index];
  return difference === 0;
}

/**
 * The P01 defects of the readable nested records of a malformed observation (`partial`), for the C-API
 * `/withinLevelErrorOrder/P01` competition against the outer defect. Only `UNKNOWN_FIELD` can outrank
 * the outer record's own defect, so only a nested unknown member is reported; a nested record is read
 * from the value the outer descriptor read already holds, never again from the caller.
 */
function nestedObservationDefects(operation, partial) {
  if (!partial) return [];
  const defects = [];
  const unknownIn = (value, allowed) => {
    if (!isPlainObject(value)) return false;
    let keys;
    try {
      keys = Reflect.ownKeys(value);
    } catch {
      return false;
    }
    return keys.some((key) => typeof key !== 'string' || !allowed.includes(key));
  };
  if ((operation === 'CREATE' || operation === 'SELF_UPDATE') && Object.hasOwn(partial, 'stagedOutput')) {
    const member = operation === 'CREATE' ? STAGED_OUTPUT_BY_CODE.CREATED : STAGED_OUTPUT_BY_CODE.SELF_UPDATED;
    if (unknownIn(partial.stagedOutput, [member])) defects.push('UNKNOWN_FIELD');
  }
  if (operation === 'RECONCILE_INDETERMINATE' && Object.hasOwn(partial, 'heldOutput')) {
    // The same closure `readHeldOutput` enforces: a plain record with more than one member, or with a
    // member outside the output set, is `UNKNOWN_FIELD` (cycle 5g review).
    const held = partial.heldOutput;
    if (isPlainObject(held)) {
      let keys = null;
      try {
        keys = Reflect.ownKeys(held);
      } catch {
        keys = null;
      }
      if (keys !== null && (keys.length > 1
        || keys.some((key) => typeof key !== 'string' || !OUTPUT_MEMBERS.includes(key)))) {
        defects.push('UNKNOWN_FIELD');
      }
    }
  }
  if (operation === 'RESTORE' && Object.hasOwn(partial, 'restoreObservation')) {
    if (unknownIn(partial.restoreObservation, RESTORE_OBSERVATION_KEYS)) defects.push('UNKNOWN_FIELD');
  }
  return defects;
}

/**
 * The post-request evidence members of an observation (C-API `/rules/rsTriState`,
 * `/rules/internalFailureBoundary`; C-MUT §§3, 6). Once the commit request may have reached RS, an RS
 * outcome, emission fact or escrow the owning layer cannot state is evidence that failed, not a malformed
 * request: it is read as absent (`ABSENT_MEMBER`) and decided by the same ambiguity and retention rules as
 * an absent or unknown value (cycle 5i review). Every other member keeps the closed-record P01 rejection.
 */
const EVIDENCE_MEMBERS = Object.freeze({
  SELF_UPDATE: Object.freeze(['commitOutcome', 'stagedOutput']),
  RECONCILE_INDETERMINATE: Object.freeze(['commitOutcome', 'responseEmission', 'heldOutput']),
});
const ABSENT_MEMBER = Object.freeze({ absent: true });

/** Read an opaque byte member of a closed staged-output record, or `null` when the record is `null`. */
function readStagedBytes(stagedOutput, member) {
  if (stagedOutput === null) return { error: null, staged: null };
  const stagedShape = readClosed(stagedOutput, [member]);
  if (stagedShape.error) return { error: stagedShape.error, staged: null };
  const bytes = stagedShape.values[member];
  if (!isUint8Array(bytes)) return { error: 'INVALID_REQUEST', staged: null };
  const length = byteLengthOf(bytes);
  if (length < 0) return { error: 'INVALID_REQUEST', staged: null };
  return { error: null, staged: { member, bytes, length } };
}

/**
 * Read the closed RS tri-state and the identity of the staged mutation.
 *
 * Two forms are admissible at `P01`. Either an RS commit request was made, and `commitOutcome` and
 * `operationIdentity` carry the closed tri-state and the mutation identity; or no RS commit request was
 * made, and both are exactly `null`, which is the honest report of a call the `P05` state gate rejects
 * before any commit request exists (`CAPI-G004`, `CAPI-G020`). Defects are collected, not
 * short-circuited, so the ratified `/withinLevelErrorOrder` decides between them.
 */
function readCommitTrio(value) {
  const absent = value.commitOutcome === null && value.operationIdentity === null;
  const candidates = [];
  if (!absent && value.commitOutcome === null) candidates.push('INVALID_REQUEST');
  if (value.commitOutcome !== null) {
    if (typeof value.commitOutcome !== 'string') candidates.push('INVALID_REQUEST');
    else if (!COMMIT_OUTCOMES.includes(value.commitOutcome)) candidates.push('UNKNOWN_VALUE');
  }
  if (value.operationIdentity !== null
    && (typeof value.operationIdentity !== 'string' || value.operationIdentity.length === 0)) {
    candidates.push('INVALID_REQUEST');
  }
  if (candidates.length > 0) return { error: worst(candidates), absent };
  return { error: null, absent };
}

/** Whether an observation member the closed table requires to be absent is exactly `null`. */
function mustBeNull(value) {
  return value === null;
}

/**
 * Read the closed `PROTECT_APPLICATION` observation.
 *
 * Two forms are admissible at `P01`: an RS commit request was made (`commitOutcome` and
 * `operationIdentity` present, `stagedOutput` carrying the staged protected bytes or `null` when RS
 * reports no staged mutation), or no RS commit request was made (all three exactly `null`), which is the
 * only honest report of a call the `P05` state gate rejects before any commit request (`CAPI-G004`,
 * `CAPI-G020`) and is answered by the gate. Every defect of every member is collected and ranked by the
 * ratified `/withinLevelErrorOrder`, so an unknown member preempts a wrong type, which preempts an
 * out-of-set value, whatever the member order of the record.
 */
function readProtectObservation(value) {
  const trio = readCommitTrio(value);
  const staged = readStagedBytes(value.stagedOutput, 'protectedApplicationBytes');
  if (trio.error || staged.error) {
    const codes = [trio.error, staged.error].filter((code) => code !== null && code !== undefined);
    return { error: worst(codes) };
  }
  if (trio.absent && staged.staged === null) {
    if (value.internalFailure !== null && !INTERNAL_FAILURE_VALUES.includes(value.internalFailure)) {
      return { error: 'UNKNOWN_VALUE' };
    }
    if (value.internalFailure !== null) {
      return {
        error: null,
        facts: 'SUPPORTED',
        applicableErrors: [],
        extraCodes: ['FAIL_CLOSED_INTERNAL'],
        noCommitRequest: true,
        commitOutcome: null,
        operationIdentity: null,
        staged: null,
      };
    }
    return {
      error: null,
      facts: 'SUPPORTED',
      applicableErrors: [],
      extraCodes: [],
      noCommitRequest: true,
      commitOutcome: null,
      operationIdentity: null,
      staged: null,
    };
  }
  const candidates = [];
  if (trio.absent && staged.staged !== null) {
    // A staged record with no commit outcome is inconsistent: the RS tri-state is what produced it.
    candidates.push('INVALID_REQUEST');
  }
  if (value.internalFailure !== null && !trio.absent) {
    // `FAIL_CLOSED_INTERNAL` is decided strictly before any RS commit request (`CAPI-E025`).
    candidates.push('INVALID_REQUEST');
  }
  if (candidates.length > 0) return { error: worst(candidates) };
  return {
    error: null,
    facts: 'SUPPORTED',
    applicableErrors: [],
    extraCodes: [],
    noCommitRequest: false,
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
  // The honest form of a call the `P05` state gate rejects (`CAPI-G005`, `CAPI-G021`): there is no
  // active session, so there is no authoritative epoch, no authentication verdict, no replay lookup and
  // no RS commit request to report, and every one of those members is exactly `null`. The gate, not
  // this reader, produces the ratified code.
  if (value.currentEpoch === null && value.framingEpoch === null) {
    const others = [value.authentication, value.replayIdentity, value.commitOutcome,
      value.operationIdentity, value.stagedOutput];
    if (!others.every(mustBeNull)) return { error: 'INVALID_REQUEST' };
    return {
      error: null,
      facts: 'SUPPORTED',
      applicableErrors: [],
      extraCodes: value.internalFailure === null ? [] : ['FAIL_CLOSED_INTERNAL'],
      noCommitRequest: true,
      commitOutcome: null,
      operationIdentity: null,
      staged: null,
    };
  }
  // `P01`: every member is checked structurally and by value, and every defect is collected rather than
  // short-circuited, so the ratified `/withinLevelErrorOrder` (`UNKNOWN_FIELD`, then `INVALID_REQUEST`,
  // then `UNKNOWN_VALUE`) decides between them wherever they occur in the record. A member that is
  // exactly `null` claims that the owning layer never reached it, which is admissible: the region that
  // decides reachability (the `P06` bound, the `P07` window) either confirms the claim or rejects the
  // record. The epoch bound of `P06` and the window of `P07` are chosen only after no `P01` defect
  // remains, and a `P01` defect of any member preempts them.
  const candidates = [];
  for (const epoch of [value.currentEpoch, value.framingEpoch]) {
    if (typeof epoch !== 'number' || !Number.isSafeInteger(epoch) || epoch < 0) {
      candidates.push('INVALID_REQUEST');
    }
  }
  if (value.authentication !== null) {
    if (typeof value.authentication !== 'string') candidates.push('INVALID_REQUEST');
    else if (!AUTHENTICATION_VALUES.includes(value.authentication)) candidates.push('UNKNOWN_VALUE');
  }
  if (value.replayIdentity !== null) {
    if (typeof value.replayIdentity !== 'string') candidates.push('INVALID_REQUEST');
    else if (!REPLAY_IDENTITY_VALUES.includes(value.replayIdentity)) candidates.push('UNKNOWN_VALUE');
  }
  if (value.commitOutcome !== null) {
    if (typeof value.commitOutcome !== 'string') candidates.push('INVALID_REQUEST');
    else if (!COMMIT_OUTCOMES.includes(value.commitOutcome)) candidates.push('UNKNOWN_VALUE');
  }
  if (value.operationIdentity !== null
    && (typeof value.operationIdentity !== 'string' || value.operationIdentity.length === 0)) {
    candidates.push('INVALID_REQUEST');
  }
  if (value.internalFailure !== null && !INTERNAL_FAILURE_VALUES.includes(value.internalFailure)) {
    candidates.push('UNKNOWN_VALUE');
  }
  if (value.internalFailure !== null
    && ![value.commitOutcome, value.operationIdentity, value.stagedOutput].every(mustBeNull)) {
    // `FAIL_CLOSED_INTERNAL` is decided strictly before any RS commit request (`CAPI-E025`).
    candidates.push('INVALID_REQUEST');
  }
  const staged = readStagedBytes(value.stagedOutput, 'applicationBytes');
  if (staged.error) candidates.push(staged.error);
  if (candidates.length > 0) return { error: worst(candidates) };
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
    // tri-state are unreachable and must be exactly `null`. An unclassified internal failure strictly
    // before any commit request is not key-dependent, so it stays reportable at `P10`, where the
    // window rejection of `P07` preempts it.
    const nulls = [value.authentication, value.replayIdentity, value.commitOutcome,
      value.operationIdentity, value.stagedOutput];
    if (!nulls.every(mustBeNull)) return { error: 'INVALID_REQUEST' };
    return {
      error: null,
      facts: distance < 0 ? 'FUTURE' : 'PAST_OUTSIDE_WINDOW',
      applicableErrors: [],
      extraCodes: value.internalFailure === null ? [] : ['FAIL_CLOSED_INTERNAL'],
      commitOutcome: null,
      operationIdentity: null,
      staged: null,
    };
  }
  if (value.authentication !== 'AUTHENTICATED') {
    if (value.authentication === 'AUTHENTICATION_FAILED' || value.authentication === 'AUTHENTICATED_STATE_INCONSISTENT') {
      if (![value.replayIdentity, value.commitOutcome, value.operationIdentity, value.stagedOutput].every(mustBeNull)) {
        return { error: 'INVALID_REQUEST' };
      }
      return {
        error: null,
        facts: 'UNSEEN_IN_WINDOW',
        applicableErrors: [value.authentication],
        extraCodes: value.internalFailure === null ? [] : ['FAIL_CLOSED_INTERNAL'],
        commitOutcome: null,
        operationIdentity: null,
        staged: null,
      };
    }
    // In the window an `OPEN_APPLICATION` carries an authentication verdict: an absent one claims a
    // classification the owning layer must have made, so it fail-closes at `P01`.
    return { error: 'INVALID_REQUEST' };
  }
  if (value.replayIdentity === 'DUPLICATE') {
    if (![value.commitOutcome, value.operationIdentity, value.stagedOutput].every(mustBeNull)) {
      return { error: 'INVALID_REQUEST' };
    }
    return {
      error: null,
      facts: 'DUPLICATE_IN_WINDOW',
      applicableErrors: [],
      extraCodes: [],
      commitOutcome: null,
      operationIdentity: null,
      staged: null,
    };
  }
  if (value.replayIdentity !== 'UNSEEN') {
    // An authenticated, in-window identity is either already accepted or not: nothing else routes.
    return { error: 'INVALID_REQUEST' };
  }
  if (value.commitOutcome === null || value.operationIdentity === null) {
    // An authenticated, in-window, unseen identity always requests exactly one RS outcome.
    return { error: 'INVALID_REQUEST' };
  }
  return {
    error: null,
    facts: 'UNSEEN_IN_WINDOW',
    applicableErrors: [],
    extraCodes: [],
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
function readObservation(operation, observation, decoded = null) {
  const shape = decoded !== null ? { error: null, values: decoded }
    : readClosed(observation, OBSERVATION_KEYS[operation], OPTIONAL_OBSERVATION_MEMBERS[operation] ?? []);
  let value = shape.values;
  if (shape.error) {
    const evidence = Object.hasOwn(EVIDENCE_MEMBERS, operation) ? EVIDENCE_MEMBERS[operation] : null;
    // C-API `/withinLevelErrorOrder/P01`: a readable nested record's own P01 defect competes first, before
    // any failed evidence member is read as absent (cycle 5j review).
    const nested = nestedObservationDefects(operation, shape.partial);
    if (shape.error === 'INVALID_REQUEST' && nested.length === 0 && evidence !== null
      && Array.isArray(shape.bad) && shape.bad.length > 0
      && shape.bad.every((key) => evidence.includes(key))) {
      // Only post-request evidence members failed: every other member was read once, as a plain data
      // member, into `partial`; the failed ones are read as absent and decided below.
      value = {};
      const byValue = {};
      let readable = false;
      for (const key of OBSERVATION_KEYS[operation]) {
        const failed = shape.bad.includes(key);
        value[key] = failed ? ABSENT_MEMBER : shape.partial[key];
        // A readable non-enumerable data member's own value is checked exactly as an enumerable one would
        // be, so its P01 defect still competes; the member is then still decided as absent and its value
        // is never released (cycle 5k review).
        if (failed && Object.hasOwn(shape.partial, key)) readable = true;
        byValue[key] = failed && !Object.hasOwn(shape.partial, key) ? ABSENT_MEMBER : shape.partial[key];
      }
      if (readable) {
        const checked = readObservation(operation, null, byValue);
        if (checked.error) return { error: checked.error };
      }
    } else {
      // C-API `/withinLevelErrorOrder/P01`: a malformed observation still lets the P01 defect of a readable
      // nested record (the staged or held escrow, the restore facts) compete, so an unknown member there
      // preempts a malformed member of the outer record whatever the order (cycle 5f review).
      return { error: worst([shape.error, ...nested]) };
    }
  }

  if (operation === 'RESTORE') {
    const inner = readClosed(value.restoreObservation, RESTORE_OBSERVATION_KEYS);
    if (inner.error) return { error: inner.error };
    return { error: null, restoreObservation: inner.values };
  }

  if (operation === 'PROTECT_APPLICATION') return readProtectObservation(value);
  if (operation === 'OPEN_APPLICATION') return readOpenObservation(value);

  // C-BIND §4 and `/comparisonRules`: the authoritative slot context the SS resolves for the request — the
  // active slot in `ACTIVE`, the original slot in `RECONCILIATION_REQUIRED`, the empty slot in `EMPTY` —
  // is an SS fact of exactly the 32 `localContextId` bytes. It is copied once, here, so the P03
  // comparison reads the bytes this read validated and nothing a caller can change afterwards.
  let slotContext = null;
  const slotDefects = [];
  if (SLOT_BOUND_OPERATIONS.includes(operation)) {
    slotContext = readSlotContext(value.slotContext);
    if (slotContext === null) slotDefects.push('INVALID_REQUEST');
  }

  if (operation === 'RECONCILE_INDETERMINATE') {
    // C-API `/request/derivedByOperation` `RECONCILE_INDETERMINATE`: the RS commit/readback outcome and
    // the held SS original state are owning-layer facts. The merged I-SM core additionally fixes the
    // emitted-response fact of the committed reconciliation rows, so the observation closes it as
    // `null` unless the outcome is `COMMITTED`, in which case it must be one of the two values.
    // Every P01 defect the observation carries is collected before one is returned: the ratified
    // `/withinLevelErrorOrder` is total over the defects a request carries, not over the order in which
    // this layer happens to read its members (`CAPI-EP001`-`CAPI-EP003`).
    const defects = [...slotDefects];
    // C-API `/rules/rsTriState`: `INDETERMINATE` "includes every absent, failed or unknown RS outcome",
    // and a reconciliation is only ever asked after the original commit request. An absent or unknown RS
    // readback is therefore the still-ambiguous outcome (`CAPI-S024`), never a malformed or out-of-set
    // request (probe p14; cycle 5e review), and `/rules/internalFailureBoundary` then keeps a committed
    // hold instead of rejecting.
    const commitOutcome = COMMIT_OUTCOMES.includes(value.commitOutcome) ? value.commitOutcome : 'INDETERMINATE';
    const committed = commitOutcome === 'COMMITTED';
    // The emission fact of a `COMMITTED` readback is reported apart (`emissionError`), like the held
    // escrow: an emission fact the SS cannot state is a failed emission, and C-API
    // `/rules/internalFailureBoundary` with C-MUT §6 then retains the hold with the `COMMITTED` proof
    // instead of rejecting (cycle 5h review). `run` adds it back to the P01 framing for every readback that
    // does not name the hold.
    let emissionError = null;
    if (value.responseEmission === ABSENT_MEMBER) {
      // A failed emission member is decided by the retention rule: it retains a hold RS has proved
      // `COMMITTED` (now or earlier) and stays the P01 rejection for any other hold (cycle 5k review).
      emissionError = 'INVALID_REQUEST';
    } else if (value.responseEmission === null) {
      if (committed) emissionError = 'INVALID_REQUEST';
    } else if (typeof value.responseEmission !== 'string') {
      if (committed) emissionError = 'INVALID_REQUEST';
      else defects.push('INVALID_REQUEST');
    } else if (!RESPONSE_EMISSIONS.includes(value.responseEmission)) {
      if (committed) emissionError = 'UNKNOWN_VALUE';
      else defects.push('UNKNOWN_VALUE');
    } else if (!committed) {
      defects.push('INVALID_REQUEST');
    }
    // The held escrow's own defect is reported apart (`heldOutputError`): for a hold RS has already proved
    // `COMMITTED` an escrow the SS cannot hand over retains the hold instead of rejecting (C-API
    // `/rules/internalFailureBoundary`, cycle 5f review); for every other hold `run` adds it back to the
    // P01 framing, exactly where it was.
    let heldOutput = null;
    let heldOutputError = null;
    if (value.heldOutput === ABSENT_MEMBER) {
      heldOutputError = 'INVALID_REQUEST';
    } else if (value.heldOutput !== null) {
      const held = readHeldOutput(value.heldOutput);
      if (held.error) heldOutputError = held.error;
      else heldOutput = held.heldOutput;
    }
    if (defects.length > 0) {
      return { error: worst([...defects, ...[heldOutputError, emissionError].filter((code) => code !== null)]) };
    }
    return {
      error: null,
      facts: 'RECONCILE_HELD',
      commitOutcome,
      responseEmission: emissionError === null ? value.responseEmission : null,
      heldOutput,
      heldOutputError,
      emissionError,
      slotContext,
    };
  }

  const selfUpdate = operation === 'SELF_UPDATE';
  const factKey = selfUpdate ? 'updateForm' : (operation === 'CREATE' ? 'onboarding' : 'keyPackage');
  const allowed = selfUpdate ? UPDATE_FORMS : (operation === 'CREATE' ? ONBOARDING_VALUES : KEY_PACKAGE_VALUES);
  const defects = [...slotDefects];
  const factKnown = typeof value[factKey] === 'string' && allowed.includes(value[factKey]);
  if (typeof value[factKey] !== 'string') defects.push('INVALID_REQUEST');
  else if (!allowed.includes(value[factKey])) defects.push('UNKNOWN_VALUE');
  const facts = factKnown
    ? (selfUpdate ? UPDATE_FACTS[value.updateForm]
      : (operation === 'CREATE' ? value.onboarding : JOIN_FACTS[value.keyPackage]))
    : null;
  const reached = facts === 'SUPPORTED';

  if (reached) {
    // C-MUT §3 and §5, C-API `/rules/rsTriState`: an SS_RS operation identity exists only for a mutation
    // whose commit request is issued, and once it may have reached RS "an absent/failed/unknown outcome
    // is INDETERMINATE, never REJECTED". A supported `SELF_UPDATE` that carries its identity but no RS
    // outcome is therefore the ambiguous outcome and is held (probe p14); so is one carrying an unknown
    // outcome (cycle 5e review). With no identity, no request was ever made and the missing or unknown
    // proof stays the P01 defect below. `CREATE` and `JOIN_WELCOME` keep the merged I-JOIN closure unchanged.
    const requestIssued = selfUpdate && typeof value.operationIdentity === 'string' && value.operationIdentity.length > 0;
    const commitOutcome = requestIssued && !COMMIT_OUTCOMES.includes(value.commitOutcome)
      ? 'INDETERMINATE' : value.commitOutcome;
    if (typeof commitOutcome !== 'string') defects.push('INVALID_REQUEST');
    else if (!COMMIT_OUTCOMES.includes(commitOutcome)) defects.push('UNKNOWN_VALUE');
    if (typeof value.operationIdentity !== 'string' || value.operationIdentity.length === 0) {
      defects.push('INVALID_REQUEST');
    }
    let staged = null;
    if (selfUpdate && requestIssued && value.stagedOutput === ABSENT_MEMBER && commitOutcome !== 'COMMITTED') {
      // A failed escrow member of an issued update that RS has not proved committed is the absent escrow:
      // the ambiguous outcome is still held and nothing is released (cycle 5j review).
      staged = null;
    } else if ((operation === 'CREATE' || operation === 'SELF_UPDATE') && value.stagedOutput !== null) {
      const member = operation === 'CREATE' ? STAGED_OUTPUT_BY_CODE.CREATED : STAGED_OUTPUT_BY_CODE.SELF_UPDATED;
      const stagedShape = value.stagedOutput === ABSENT_MEMBER ? { error: 'INVALID_REQUEST' }
        : readStagedOutput(value.stagedOutput, member);
      if (stagedShape.error) {
        // C-API `/rules/internalFailureBoundary`: after COMMITTED the adapter emits success or retains
        // reconciliation evidence and never emits REJECTED. A `SELF_UPDATE` escrow the owning layer cannot
        // hand over after a commit report is therefore held, exactly as an absent, empty or over-bound one
        // is; before a commit proof the same defect stays the P01 rejection the closure fixes. `CREATE`
        // keeps the merged I-JOIN behaviour unchanged.
        if (!(selfUpdate && commitOutcome === 'COMMITTED')) defects.push(stagedShape.error);
      } else {
        staged = stagedShape.staged;
      }
    }
    if (defects.length > 0) return { error: worst(defects) };
    return { error: null, facts, commitOutcome, operationIdentity: value.operationIdentity, staged, slotContext };
  }

  // A form the owning layer does not support (or a form outside the closed set) carries no commit proof
  // and no identity, and nothing is ever applied for it: a staged output supplied with it is read through
  // the same closed member check and then dropped, never released (contract Issue #415: rejects
  // `UNSUPPORTED_UPDATE_FORM` and releases nothing even when a staged output is supplied). `CREATE` keeps
  // the merged I-JOIN closure unchanged, which is `INVALID_REQUEST` for that member.
  if (value.commitOutcome !== null || value.operationIdentity !== null) defects.push('INVALID_REQUEST');
  if (operation === 'CREATE' && value.stagedOutput !== null) defects.push('INVALID_REQUEST');
  if (selfUpdate && value.stagedOutput !== null) {
    const unsupportedStaged = value.stagedOutput === ABSENT_MEMBER ? { error: 'INVALID_REQUEST' }
      : readStagedOutput(value.stagedOutput, STAGED_OUTPUT_BY_CODE.SELF_UPDATED);
    if (unsupportedStaged.error) defects.push(unsupportedStaged.error);
  }
  if (defects.length > 0) return { error: worst(defects) };
  return { error: null, facts, commitOutcome: null, operationIdentity: null, staged: null, slotContext };
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

/**
 * The hold's own C-MUT facts, read exactly once from the snapshot's own descriptors. The hold decides
 * which escrow a reconciliation may release, so it is read the way the merged I-SM core reads it —
 * through property descriptors, never by plain property access, which a proxy snapshot can answer
 * differently for the same member (review finding p13b). Returns the decoded facts and the C-API code of
 * a hold this layer cannot read, never a value the caller can change between two reads.
 */
function readHeldFacts(snapshot) {
  const unreadable = {
    error: 'INVALID_REQUEST', outputKind: null, expectedSuccessCode: null, selectedCandidateRef: null,
    terminalEvidenceStatus: null, reconciliationRef: null, originalStateBefore: null,
  };
  if (snapshot === null || typeof snapshot !== 'object') return unreadable;
  const descriptor = readOwnDescriptor(snapshot, 'held');
  if (!descriptor || !Object.hasOwn(descriptor, 'value')) return unreadable;
  const held = descriptor.value;
  if (held === null) return { ...unreadable, error: null };
  if (!isPlainObject(held)) return unreadable;
  let descriptors;
  try {
    descriptors = Object.getOwnPropertyDescriptors(held);
  } catch {
    return unreadable;
  }
  const member = (key) => (descriptors[key] && Object.hasOwn(descriptors[key], 'value') ? descriptors[key].value : null);
  // `copy` is the single data-only read of every held member. A caller that needs the hold itself (the
  // committed-hold path) uses this copy, so a snapshot cannot answer one hold to the guard and another
  // to the decision (review finding: double-read of `held`).
  const copy = Object.fromEntries(Object.keys(descriptors).map((key) => [key, member(key)]));
  return {
    error: null,
    copy,
    outputKind: member('outputKind'),
    expectedSuccessCode: member('expectedSuccessCode'),
    selectedCandidateRef: member('selectedCandidateRef'),
    terminalEvidenceStatus: member('terminalEvidenceStatus'),
    reconciliationRef: member('reconciliationRef'),
    originalStateBefore: member('originalStateBefore'),
  };
}

/** The one C-API output member the hold's decoded C-MUT escrow kind fixes, or `null` for `NONE`. */
function heldOutputMemberOf(heldFacts) {
  if (heldFacts.error !== null || typeof heldFacts.outputKind !== 'string') return null;
  return OUTPUT_MEMBER_BY_KIND[heldFacts.outputKind] ?? null;
}

/**
 * P01 closure of the held escrow against the hold the reconciliation resolves: the injected held output
 * must be exactly the escrow the held mutation's C-MUT output kind fixes — present, and of that one
 * member, when the kind names one; absent when the kind is `NONE` or nothing is held. The rule is
 * independent of the outcome: the held mutation is what the SS reports as held, and the readback of a
 * committed, a terminal or a still ambiguous hold is read against the same hold.
 */
function heldOutputShapeCode(heldFacts, heldOutput) {
  const expected = heldOutputMemberOf(heldFacts);
  if (expected === null) return heldOutput === null ? null : 'INVALID_REQUEST';
  if (heldOutput === null || heldOutput.member !== expected) return 'INVALID_REQUEST';
  // Cross-check the two ratified transcriptions: wherever `/response/outputBySuccessCode` fixes a single
  // released member for the held row, it must be the member the hold's C-MUT escrow kind names. They
  // disagree only for escrow kinds the success table leaves empty (`JOINED` releases the welcome, not a
  // success output), so the guard fires exactly where both speak and stays silent where only one does.
  const byCode = heldFacts.error === null ? OUTPUT_BY_SUCCESS_CODE[heldFacts.expectedSuccessCode] : undefined;
  if (Array.isArray(byCode) && byCode.length === 1 && byCode[0] !== expected) return 'INVALID_REQUEST';
  if (REFERENCE_OUTPUT_MEMBERS.includes(expected)) {
    // The hold fixes the winner: releasing whatever reference the observation hands over would report an
    // escrow the held mutation does not own.
    const fixed = heldFacts.selectedCandidateRef;
    return typeof fixed === 'string' && heldOutput.ref === fixed ? null : 'INVALID_REQUEST';
  }
  // The released escrow is bounded exactly like the staged one, or a hold created for an escrow the direct
  // path refused could be cleared in two calls by presenting an empty or over-bound one. The length is
  // re-measured here, after the merged core has read the snapshot: a resizable backing buffer the caller
  // grows between the observation read and this decision must not be able to widen what is released
  // (review finding p13c).
  const length = byteLengthOf(heldOutput.bytes);
  return length > 0 && length <= BOUNDS.MAX_OPAQUE_BYTES && length === heldOutput.length ? null : 'INVALID_REQUEST';
}

/** The closed C-API `output` record of one released staged or held escrow, or `null` when it cannot be copied. */
function releasedOutput(output) {
  if (REFERENCE_OUTPUT_MEMBERS.includes(output.member)) return { [output.member]: output.ref };
  // The copy is the moment the escrow leaves this module, so the bound is re-checked here against the
  // buffer's own intrinsic length: the length the observation read validated is not the length a
  // resizable buffer necessarily has when the copy is taken (review finding p13c). A length that changed,
  // emptied or grew past the bound releases nothing.
  const length = byteLengthOf(output.bytes);
  if (length !== output.length || length <= 0 || length > BOUNDS.MAX_OPAQUE_BYTES) return null;
  const copy = new Uint8Array(output.bytes);
  if (copy.length !== length) return null;
  return { [output.member]: copy };
}

function shapeDecision(decision, requestId, operation, staged, heldOutput = null) {
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
  if (kind === 'SUCCESS') {
    // C-API `/response/outputBySuccessCode` fixes the one member a releasing success code carries, and
    // the decision itself names the escrow kind it releases (`/rules/payloadRelease`). `CREATED`,
    // `APPLICATION_PROTECTED`, `APPLICATION_OPENED` and `SELF_UPDATED` release the staged escrow of the
    // mutation just applied, only after `COMMITTED`; `RECONCILED_COMMITTED` returns the escrow of the
    // mutation that was already committed, under its original success code.
    // Nothing else is ever released, and a released member is never the caller's own buffer.
    const expectedMember = typeof result.outputKind === 'string' ? OUTPUT_MEMBER_BY_KIND[result.outputKind] : null;
    if (result.code === 'RECONCILED_COMMITTED') {
      // `originalOutput` is the closed output object of the original success code under C-API
      // `/response/outputBySuccessCode`; a code whose member list is empty (`JOINED`,
      // `PEER_UPDATE_APPLIED`) carries the empty closed object `{}`, never `null` (owner act on #317,
      // binding interpretation of the ratified C-API "All objects are closed maps").
      if (expectedMember !== null && (heldOutput === null || heldOutput.member !== expectedMember)) return null;
      const released = expectedMember === null ? {} : releasedOutput(heldOutput);
      if (expectedMember !== null && released === null) return null;
      extra.output = freezeData({
        originalSuccessCode: result.originalSuccessCode,
        originalOutput: released,
      });
    } else if (expectedMember !== null) {
      if (staged === null || staged.member !== expectedMember) return null;
      const released = releasedOutput(staged);
      if (released === null) return null;
      extra.output = freezeData(released);
    }
  }
  return resultRecord(...base, extra);
}

function transitionResult(result, snapshot) {
  return freezeData({ result, snapshot });
}

function rejectedTransition(requestId, operation, stateBefore, code) {
  return transitionResult(rejected(requestId, operation, stateBefore, code), null);
}

function decisionTransition(decision, requestId, operation, staged, heldOutput = null) {
  if (decision.result.kind === 'REJECTED') {
    return rejectedTransition(requestId, operation, decision.result.stateBefore, decision.result.code);
  }
  const shaped = shapeDecision(decision, requestId, operation, staged, heldOutput);
  // A decision that names an escrow it cannot release is an inconsistent injected observation: refuse it
  // fail-closed at P01 rather than emit a result that silently released nothing (review finding M3).
  if (shaped === null) {
    return rejectedTransition(requestId, operation, decision.result.stateBefore, 'INVALID_REQUEST');
  }
  return transitionResult(shaped, decision.snapshot);
}

/**
 * The one read of the caller's snapshot (review findings p13b and the cycle-5 hold substitutions). The
 * snapshot and the `held` inside it are each read through their own property descriptors exactly once
 * into ordinary objects carrying the same descriptors, and every later step (state, shape, hold facts,
 * decision, successor) sees only that copy. The caller's objects are never read again:
 * - accessor descriptors are copied as descriptors and never invoked, so the merged core rejects them
 *   exactly as before;
 * - an own `__proto__` member is kept as a member (the descriptor maps have no prototype), so it is still
 *   rejected as unknown;
 * - a snapshot or `held` that is an object but not a plain one is replaced by a fixed non-plain stand-in,
 *   which keeps its rejection without a second prototype read;
 * - a copy whose reads threw is marked `failed`, and the call then fails closed on that alone.
 */
const NON_PLAIN = Object.freeze([]);

function snapshotOnce(snapshot) {
  const descriptorsOf = (value) => {
    const descriptors = Object.create(null);
    try {
      for (const key of Reflect.ownKeys(value)) {
        const descriptor = Reflect.getOwnPropertyDescriptor(value, key);
        if (descriptor !== undefined) descriptors[key] = descriptor;
      }
    } catch {
      return { descriptors, failed: true };
    }
    return { descriptors, failed: false };
  };
  if (snapshot === null || typeof snapshot !== 'object') return { snapshot, failed: false };
  if (!isPlainObject(snapshot)) return { snapshot: NON_PLAIN, failed: false };
  const outer = descriptorsOf(snapshot);
  let failed = outer.failed;
  const held = outer.descriptors.held;
  if (held && Object.hasOwn(held, 'value') && held.value !== null && typeof held.value === 'object') {
    if (isPlainObject(held.value)) {
      const inner = descriptorsOf(held.value);
      failed = failed || inner.failed;
      outer.descriptors.held = { ...held, value: Object.defineProperties({}, inner.descriptors) };
    } else {
      outer.descriptors.held = { ...held, value: NON_PLAIN };
    }
  }
  return { snapshot: Object.defineProperties({}, outer.descriptors), failed };
}

function run(input) {
  const outer = readClosed(input, ['request', 'snapshot', 'observation']);
  if (outer.error) throw new M2AdapterError(outer.error === 'UNKNOWN_FIELD' ? 'UNKNOWN_FIELD' : 'FAIL_CLOSED_INTERNAL');
  const { request, observation } = outer.values;
  const copied = snapshotOnce(outer.values.snapshot);
  const { snapshot } = copied;
  // The request is decoded exactly once, through its descriptors, and `requestId`, `operation`, `input`,
  // the bounds, the observation set and the dispatch are all taken from that one decoded record (or from
  // its readable members when it is malformed). A Proxy therefore cannot validate one operation and
  // dispatch another (cycle 5f review).
  const requestShape = readClosed(request, REQUEST_FIELDS);
  const requestMembers = requestShape.error === null ? requestShape.values : (requestShape.partial ?? {});
  const requestId = typeof requestMembers.requestId === 'string' ? requestMembers.requestId : null;
  const operation = typeof requestMembers.operation === 'string' ? requestMembers.operation : null;
  if (requestId === null || requestId.length === 0 || operation === null) {
    throw new M2AdapterError(requestShape.error ?? 'INVALID_REQUEST');
  }
  const stateBefore = snapshotStateOf(snapshot);

  // P01 to P04: the request, the snapshot and the observation are all checked before any level is
  // chosen, so a P01 defect of any of the three preempts every P02 to P04 defect.
  // The `input` record is decoded exactly once per call and the decoded members are reused below: a proxy
  // or accessor-bearing `input` cannot present one value to validation and another to the event (F14).
  // `input` is taken from the decoded request, never through a property get, so an accessor `input` is
  // never invoked and stays a P01 defect.
  const decodedInput = Object.hasOwn(INPUT_BY_OPERATION, operation)
    ? decodeRequestInput(requestShape, operation) : { error: null, values: {} };
  const checked = validateRequestRecord(request, decodedInput, requestShape);
  const framing = [];
  if (checked.code !== null) framing.push(checked.code);
  const snapshotCode = copied.failed ? 'FAIL_CLOSED_INTERNAL' : snapshotShapeCode(snapshot);
  if (snapshotCode !== null) framing.push(snapshotCode);
  const observed = INTEGRATED_OPERATIONS.includes(operation) ? readObservation(operation, observation) : { error: null };
  if (observed.error) framing.push(observed.error);
  // The hold is read once, from the adapter's own snapshot copy, and these facts serve every later step.
  // A reconciliation that names a hold RS has proved `COMMITTED` — recorded earlier in the hold, or
  // reported by this very readback — keeps its escrow defect out of the framing: that defect retains the
  // hold below, with the `COMMITTED` proof, instead of rejecting it (C-API `/rules/internalFailureBoundary`,
  // C-MUT §6, cycle 5f/5g reviews). For every other hold it stays a P01 defect.
  const heldFacts = operation === 'RECONCILE_INDETERMINATE' ? readHeldFacts(snapshot) : null;
  const echoedRef = decodedInput && decodedInput.error === null ? decodedInput.values.reconciliationRef : undefined;
  const escrowOfCommittedHold = heldFacts !== null && heldFacts.error === null
    && (heldFacts.terminalEvidenceStatus === 'COMMITTED' || (!observed.error && observed.commitOutcome === 'COMMITTED'))
    && typeof echoedRef === 'string' && echoedRef === heldFacts.reconciliationRef;
  if (!observed.error && !escrowOfCommittedHold) {
    if (observed.heldOutputError) framing.push(observed.heldOutputError);
    if (observed.emissionError) framing.push(observed.emissionError);
  }
  // P03 binding (C-BIND §4 and `/comparisonRules/active` / `/comparisonRules/reconciliationRequired`,
  // C-API `CAPI-E006`): the request `bindingRef` of a session-bound operation must byte-equal the
  // authoritative slot context the SS resolved for it — the active slot, or the original slot of a held
  // mutation. Wrong length, unknown reference, byte mismatch and cross-context use are all
  // `BINDING_MISMATCH`, at P03, ahead of every state gate and decision, with the state unchanged.
  if (checked.code === null && !observed.error && SLOT_BOUND_OPERATIONS.includes(operation)
    && !bindingRefMatches(checked.values.bindingRef, observed.slotContext)) {
    framing.push('BINDING_MISMATCH');
  }
  if (framing.length > 0) return rejectedTransition(requestId, operation, stateBefore, worst(framing));

  // An honest caller that made no RS commit request because the state gate rejects the operation before
  // any commit request exists (`CAPI-G004`, `CAPI-G005`, `CAPI-G020`, `CAPI-G021`): the merged I-SM state
  // gate supplies the ratified code, which is `P05` and therefore preempts every bound. In a state that
  // does not gate the operation, no `ACTIVE`-session operation can have been called without issuing its
  // commit request, so the observation is impossible and the call fails closed at `P01` instead of
  // succeeding without proof of the commit.
  if (observed.noCommitRequest === true) {
    const codes = [...(observed.extraCodes ?? [])];
    // The `P05` state gate of the C-API state matrix, for the two states that refuse an active-session
    // operation before any commit request exists: `EMPTY` (`CAPI-G004`, `CAPI-G005`, error `CAPI-E009`)
    // and `RECONCILIATION_REQUIRED` (`CAPI-G020`, `CAPI-G021`, error `CAPI-E011`). The merged I-SM core
    // returns exactly these codes for both states, and reading them from the state here is what makes the
    // rows reachable for a caller that honestly reports that no commit request was made. In a state that
    // does not gate the operation, no active-session operation can have been called without issuing its
    // commit request, so the call fails closed: `FAIL_CLOSED_INTERNAL` (`CAPI-E025`) when the owning layer
    // reported an unclassified failure strictly before the commit request, `INVALID_REQUEST` otherwise.
    if (stateBefore === 'EMPTY') codes.push('NO_ACTIVE_SESSION');
    if (stateBefore === 'RECONCILIATION_REQUIRED') codes.push('RECONCILIATION_REQUIRED');
    return rejectedTransition(requestId, operation, stateBefore,
      codes.length > 0 ? worst(codes) : 'INVALID_REQUEST');
  }

  // P06: the request bounds, decidable before any commit request (see `validateAdapterRequest`), the
  // structural epoch bound of `OPEN_APPLICATION` (see `readOpenObservation`), plus the one bound that only
  // the injected observation can carry: the operation identity the merged core echoes inside the
  // reconciliation reference it issues (`I-SM-HOLD:<operationIdentity>`). C-MUT §3 makes the identity an
  // SS_RS fact whose defects are detected "strictly before an RS request": no request is sent and "no
  // commit-result evidence exists". An identity past the bound is therefore never a commit the module
  // must hold — holding it would mint a reference this module then refuses and lock the hold out of every
  // reconciliation (probe p06). It rejects at P06, whatever outcome is reported, behind the P05 state
  // gates and ahead of the P09 and P10 decision rows, and nothing is held.
  const bounds = [
    ...requestBoundCodes(checked.values, decodedInput), ...(observed.bounds ?? []), ...(observed.extraCodes ?? []),
  ];
  // Contract R2 step 5 scopes this bound to `CREATE`, `JOIN_WELCOME` and `SELF_UPDATE`; the I-MSG
  // operations keep their integrated behaviour unchanged (final review, confirmed on AI395).
  const identityOverBound = IDENTITY_BOUND_OPERATIONS.includes(operation)
    && typeof observed.operationIdentity === 'string'
    && observed.operationIdentity.length > BOUNDS.MAX_OPERATION_IDENTITY_CHARS;

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

  if (operation === 'RECONCILE_INDETERMINATE') {
    // C-MUT §5 and C-API fix reconciliation as the resolution of one already issued mutation: no new
    // commit request is made, so every applicable error preempts the decision by the C-API total
    // precedence, exactly as for RESTORE. The AP-echoed reference travels in the request; the RS
    // outcome and the held escrow travel in the injected observation.
    const event = {
      operation,
      applicableErrors: [],
      facts: observed.facts,
      reconciliationRef: decodedInput.error === null ? decodedInput.values.reconciliationRef ?? null : null,
    };
    // The RS proof belongs to the held mutation. With none held it is forwarded to no one: the ratified
    // answer is then the state gate (`CAPI-G008`/`CAPI-G016` `NO_RECONCILIATION_PENDING`, C-MUT
    // `/reconciliation/afterHoldClearedRepeat`), which an AP repeating the reconcile after the hold was
    // cleared reaches with durable RS evidence. Forwarding a proof the state cannot own would make the
    // merged core refuse the emission at P01, ahead of the P05 gate, and answer a well-formed repeat with
    // `INVALID_REQUEST` instead of the ratified code.
    if (snapshot !== null && snapshot.state === 'RECONCILIATION_REQUIRED') {
      event.commitOutcome = observed.commitOutcome;
      if (observed.responseEmission !== null) event.responseEmission = observed.responseEmission;
    } else {
      // With no hold the RS proof is forwarded to no one — the emission stays out of the injected outcome,
      // which is what makes the merged core select its no-emission row — while the outcome member itself is
      // still carried, because the tri-state has no absent value and a null member is refused as unknown.
      event.commitOutcome = observed.commitOutcome;
    }
    // C-API `/rules/internalFailureBoundary` and `/rules/rsTriState` `COMMITTED`, C-MUT §6: once RS has
    // proved this hold `COMMITTED` (an earlier interrupted emission recorded `terminalEvidenceStatus`
    // `COMMITTED`, or this readback reports it), the adapter "emits success or retains reconciliation
    // evidence but never emits REJECTED", and mismatched later RS evidence "fails closed and leaves the
    // hold unchanged". A later readback that is absent, unknown or `NOT_COMMITTED` therefore cannot select
    // or discard anything: it is the still-pending `CAPI-S024` answer, with the committed hold returned
    // exactly as it was and no output (probe p16); a `COMMITTED` readback whose escrow cannot be handed over
    // retains the hold with the `COMMITTED` proof recorded. The reference must still match; a mismatch
    // keeps its own `CAPI-S028` row.
    const committedHold = snapshot !== null && snapshot.state === 'RECONCILIATION_REQUIRED'
      && escrowOfCommittedHold && (observed.commitOutcome !== 'COMMITTED' || observed.emissionError !== null
        || observed.heldOutputError !== null || heldOutputShapeCode(heldFacts, observed.heldOutput) !== null);
    if (committedHold) {
      // The guard above, the re-decision below and the hold returned are all the one descriptor read
      // `readHeldFacts` took; the merged core re-validates that copy in full (review findings p13b and
      // the cycle-5 double-read of `held`). An escrow the SS cannot hand over, or one that is not the held
      // mutation's, never rejects a hold RS has proved committed: it is retained unchanged, exactly as a
      // non-committed readback is, and only a later `COMMITTED` readback with the escrow releases it
      // (cycle 5f review).
      const heldCopy = heldFacts.copy;
      const pending = decide(
        { state: 'RECONCILIATION_REQUIRED', held: { ...heldCopy, terminalEvidenceStatus: 'PENDING' } },
        {
          operation: event.operation, applicableErrors: [], facts: event.facts,
          reconciliationRef: event.reconciliationRef, commitOutcome: 'INDETERMINATE',
        },
      );
      if (pending === null || pending.result.kind !== 'INDETERMINATE' || pending.snapshot === null) {
        return rejectedTransition(requestId, operation, stateBefore, worst([...bounds, 'FAIL_CLOSED_INTERNAL']));
      }
      if (bounds.length > 0) {
        const code = worst(bounds);
        if (preempts(code, pending)) return rejectedTransition(requestId, operation, stateBefore, code);
      }
      const retained = { ...pending, snapshot: { state: pending.snapshot.state, held: { ...pending.snapshot.held, terminalEvidenceStatus: 'COMMITTED' } } };
      return decisionTransition(retained, requestId, operation, null);
    }
    const decision = decide(snapshot, event);
    if (decision === null) {
      return rejectedTransition(requestId, operation, stateBefore, worst([...bounds, 'FAIL_CLOSED_INTERNAL']));
    }
    const candidates = [...bounds];
    // The hold is decoded once, through descriptors, and the same decoded facts close the injected held
    // escrow: a snapshot that answers `held` differently to a property access than to a descriptor read
    // cannot pick the escrow this reconciliation releases (review finding p13b).
    if (heldFacts.error !== null) candidates.push(heldFacts.error);
    const heldShape = heldFacts.error === null ? heldOutputShapeCode(heldFacts, observed.heldOutput) : null;
    if (heldShape !== null) candidates.push(heldShape);
    if (decision.result.kind === 'REJECTED') candidates.push(decision.result.code);
    if (candidates.length > 0) {
      const code = worst(candidates);
      if (preempts(code, decision)) return rejectedTransition(requestId, operation, stateBefore, code);
    }
    return decisionTransition(decision, requestId, operation, null, observed.heldOutput);
  }

  // CREATE, JOIN_WELCOME, PROTECT_APPLICATION, OPEN_APPLICATION and SELF_UPDATE: one I-SM decision over
  // the operation, the authenticated facts and the applicable errors derived from the observation.
  const event = { operation, applicableErrors: [...(observed.applicableErrors ?? [])], facts: observed.facts };
  if (observed.commitOutcome !== null) {
    event.commitOutcome = observed.commitOutcome;
    event.operationIdentity = observed.operationIdentity;
  }
  const decision = decide(snapshot, event);
  if (decision === null) {
    return rejectedTransition(requestId, operation, stateBefore, worst([...bounds, 'FAIL_CLOSED_INTERNAL']));
  }
  if (decision.result.kind === 'REJECTED' || observed.commitOutcome === null || identityOverBound) {
    // No RS commit request was made: every applicable error preempts by the C-API total precedence. An
    // operation identity past its bound is C-API `CAPI-E014` ("a structural byte/count bound is exceeded
    // before stateful processing", P06, REJECTED, UNCHANGED): with it, no commit request is ever issued.
    const candidates = [...bounds];
    if (identityOverBound) candidates.push('VALUE_OUT_OF_RANGE');
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
  // a `CREATE` staged Welcome, a `SELF_UPDATE` staged Commit, or a staged opaque message of a
  // `PROTECT_APPLICATION` or of an in-window unseen `OPEN_APPLICATION`, that is absent, empty or over the
  // bound) is therefore an internal failure after the request: `NOT_COMMITTED` stays `NOT_COMMITTED` (RS
  // proves absence), while `COMMITTED` and `INDETERMINATE` retain the held mutation and enter
  // `RECONCILIATION_REQUIRED` through the merged I-SM `INDETERMINATE` row, with no output and no blind
  // retry. The held mutation is the complete C-MUT logical mutation, which includes the
  // `REPLAY_RETENTION_STATE` component of the C-RET window.
  //
  // The escrow is re-measured here, at the point this layer decides whether to release it: a resizable
  // backing buffer can be grown by a trap that fires while the merged core reads the snapshot, after the
  // length the observation read recorded. A length that changed, emptied or grew past the bound is
  // released by nothing, exactly like an absent or over-bound one (review finding p13c).
  const escrowLength = observed.staged === null ? -1 : byteLengthOf(observed.staged.bytes);
  const stagedRow = STAGED_OUTPUT_ROWS.includes(decision.result.scenario) || operation === 'SELF_UPDATE';
  const stagedDefect = stagedRow
    && (observed.staged === null || escrowLength <= 0 || escrowLength > BOUNDS.MAX_OPAQUE_BYTES
      || escrowLength !== observed.staged.length);
  const defect = bounds.length > 0 || stagedDefect;
  if (!defect || observed.commitOutcome === 'NOT_COMMITTED') {
    return decisionTransition(decision, requestId, operation, defect ? null : observed.staged);
  }
  const held = decide(snapshot, { ...event, commitOutcome: 'INDETERMINATE' });
  if (held === null || held.result.kind !== 'INDETERMINATE' || held.snapshot === null) {
    throw new M2AdapterError('FAIL_CLOSED_INTERNAL');
  }
  if (observed.commitOutcome === 'COMMITTED') {
    // C-MUT §§5-6 and C-API `/rules/internalFailureBoundary`: RS has already proved this mutation
    // committed, so the retained hold keeps that proof (`terminalEvidenceStatus` `COMMITTED`) exactly as
    // an interrupted emission does. A later readback that is not `COMMITTED` can then never clear or
    // reject it; only a `COMMITTED` reconciliation releases its escrow (cycle 5f review).
    const retained = {
      ...held,
      snapshot: { state: held.snapshot.state, held: { ...held.snapshot.held, terminalEvidenceStatus: 'COMMITTED' } },
    };
    return decisionTransition(retained, requestId, operation, null);
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
    // A hostile input can throw an `M2AdapterError` of its own — a proxy trap handing back an instance
    // whose `code` was overwritten after construction. The thrown error is therefore rebuilt from its
    // code and never passed through as it arrived: `M2AdapterError` closes every code it does not
    // recognise to `FAIL_CLOSED_INTERNAL`, and its message is the code, never text chosen by the caller
    // (review finding p13a).
    throw new M2AdapterError(error instanceof M2AdapterError ? error.code : 'FAIL_CLOSED_INTERNAL');
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
  UPDATE_FORMS,
  STAGED_OUTPUT_BY_CODE,
  OUTPUT_MEMBER_BY_KIND,
  BOUNDS,
  RETENTION,
  OBSERVATION_KEYS,
});
