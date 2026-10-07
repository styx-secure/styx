// worker-protocol.js — closed, bounded message grammar of the M2 worker boundary
// (card I-WORK of #317 G-SCOPE; contract Issue #369).
//
// Everything that crosses between the application context (AP) and the dedicated
// M2 worker that owns SS/RS is untrusted input. This module is a pure validator
// and codec: it accepts exactly the closed C-API request record and exactly one of
// the five closed C-API result kinds, enforces every bound of the contract, and
// gives opaque values no representation at all. It performs no state transition,
// no durable write, no cryptographic operation and no transport action.
//
// Ratified inputs copied verbatim (see contract Issue #369 "Frozen shared interfaces"):
//   C-API  docs/architecture/m2/adapter-contract.md  sha256 b77d39fb…05ad9  (#319 5886838783)
//   C-BIND docs/architecture/m2/binding-v0.md        sha256 2ee9b022…1d4a42 (#323 5890060894)
//   C-MUT  docs/architecture/m2/mutation-table.md    sha256 6c2c045c…eb3060 (#324 5890545934)
//   C-REC  docs/architecture/m2/recovery-and-coexistence.md  sha256 ab11271c…7149 (owner act #327 6035801582)
//   O-SCEN docs/architecture/m2/scenarios/clause-scenarios.md sha256 75d84350…16532 (owner act #327 6035801582)

import { STATES as ADAPTER_STATES, OPERATIONS as ADAPTER_OPERATIONS } from './state-machine.js';

/** The eight C-API `/operationEnum` members (I-SM's closed operation set). */
const OPERATIONS = Object.freeze([
  'CREATE', 'RESTORE', 'JOIN_WELCOME', 'PROTECT_APPLICATION', 'OPEN_APPLICATION',
  'SELF_UPDATE', 'APPLY_PEER_UPDATE', 'RECONCILE_INDETERMINATE',
]);

/** The three C-API `/stateEnum` members. */
const STATES = Object.freeze(['EMPTY', 'ACTIVE', 'RECONCILIATION_REQUIRED']);

/** The five C-API `/resultKindEnum` members. */
const RESULT_KINDS = Object.freeze([
  'SUCCESS', 'NO_CHANGE', 'NOT_COMMITTED', 'INDETERMINATE', 'REJECTED',
]);

/** The three C-API `/commitOutcomeEnum` members. */
const COMMIT_OUTCOMES = Object.freeze(['COMMITTED', 'NOT_COMMITTED', 'INDETERMINATE']);

/** The ten C-API `/successCodeEnum` members, in ratified order. */
const SUCCESS_CODES = Object.freeze([
  'CREATED', 'RESTORED', 'JOINED', 'APPLICATION_PROTECTED', 'APPLICATION_OPENED',
  'SELF_UPDATED', 'PEER_UPDATE_APPLIED', 'CANDIDATE_SELECTED', 'RECONCILED_COMMITTED',
  'DUPLICATE_IGNORED',
]);

/** The 25 C-API `/errorCodeEnum` members, in ratified order. */
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

/**
 * C-API `/response/outputBySuccessCode/RECONCILED_COMMITTED` carries the *held*
 * original success code. The contract requires it to be a member of
 * `/successCodeEnum` other than `RECONCILED_COMMITTED` itself: a reconciliation
 * result cannot describe a previous reconciliation.
 *
 * Owner observation, recorded and not enforced: of the enum members only the seven
 * `RS_TRI_STATE` decision-row dispositions can physically be held — CAPI-S001
 * `CREATED`, S006 `JOINED`, S009 `APPLICATION_PROTECTED`, S010 `APPLICATION_OPENED`,
 * S014 `SELF_UPDATED`, S016 `PEER_UPDATE_APPLIED`, S017 `CANDIDATE_SELECTED`
 * (C-API `/decisionRows`). `RESTORED` persists nothing and `DUPLICATE_IGNORED` is
 * not a mutation disposition, so both are grammatically permitted here but cannot
 * arise from a real row. Whether the grammar should be narrowed to the seven is an
 * owner decision, not a silent choice of this module.
 */
const ORIGINAL_SUCCESS_CODE_SET = new Set(
  SUCCESS_CODES.filter((code) => code !== 'RECONCILED_COMMITTED'),
);

/** The ten C-API `/response/errorShape` `detailTagEnum` members. */
const DETAIL_TAGS = Object.freeze([
  'FIELD', 'PROFILE', 'BINDING', 'STATE', 'AUTH', 'EPOCH', 'ONBOARDING', 'UPDATE', 'COMMIT',
  'INTERNAL',
]);

/** The C-API `/request/inputByOperation` assignment, transcribed exactly. */
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

/** C-API `/request/inputByOperation` members whose wire value is opaque bytes. */
const INPUT_BYTES = Object.freeze([
  'peerFramedKeyPackage', 'embeddedTreeWelcome', 'applicationBytes',
  'protectedApplicationMessage', 'protectedCommitBytes',
]);

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

/** C-API `/response/outputBySuccessCode` members whose wire value is opaque bytes. */
const OUTPUT_BYTES = Object.freeze([
  'embeddedTreeWelcome', 'protectedApplicationBytes', 'applicationBytes',
  'protectedCommitBytes',
]);

/** C-API `/response/byKind` `allowedCodes`, transcribed exactly. */
const ALLOWED_CODES = Object.freeze({
  SUCCESS: Object.freeze([
    'CREATED', 'RESTORED', 'JOINED', 'APPLICATION_PROTECTED', 'APPLICATION_OPENED',
    'SELF_UPDATED', 'PEER_UPDATE_APPLIED', 'CANDIDATE_SELECTED', 'RECONCILED_COMMITTED',
  ]),
  NO_CHANGE: Object.freeze(['DUPLICATE_IGNORED']),
});

/** C-API `/response/commonRequired`, transcribed exactly. */
const RESULT_COMMON = Object.freeze([
  'api', 'requestId', 'operation', 'kind', 'stateBefore', 'stateAfter',
]);

/** C-API `/request/commonRequired`; `/request/commonOptional` is empty. */
const REQUEST_FIELDS = Object.freeze([
  'api', 'operation', 'requestId', 'profile', 'bindingRef', 'input',
]);

/** C-API `/response/byKind`, transcribed exactly: allowed and required members. */
const RESULT_ALLOWED_BY_KIND = Object.freeze({
  SUCCESS: Object.freeze(['successCode', 'output', 'commitOutcome']),
  NO_CHANGE: Object.freeze(['successCode']),
  NOT_COMMITTED: Object.freeze(['commitOutcome']),
  INDETERMINATE: Object.freeze(['commitOutcome', 'reconciliationRef', 'originalStateBefore']),
  REJECTED: Object.freeze(['error']),
});

const RESULT_REQUIRED = Object.freeze({
  SUCCESS: Object.freeze(['successCode']),
  NO_CHANGE: Object.freeze(['successCode']),
  NOT_COMMITTED: Object.freeze(['commitOutcome']),
  INDETERMINATE: Object.freeze(['commitOutcome', 'reconciliationRef', 'originalStateBefore']),
  REJECTED: Object.freeze(['error']),
});

const RESULT_ALLOWED = Object.freeze(Object.fromEntries(
  RESULT_KINDS.map((kind) => [kind, Object.freeze(
    RESULT_COMMON.concat(RESULT_ALLOWED_BY_KIND[kind]),
  )]),
));

/** Union of every kind's allowed members, used to read the envelope before the kind is known. */
const RESULT_UNION = Object.freeze(Array.from(new Set(
  RESULT_KINDS.flatMap((kind) => RESULT_ALLOWED[kind]),
)));

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

/**
 * C-API `/codeToResultKind`, transposed verbatim. Every success code, every error
 * code and the two remaining commit outcomes appear exactly once, so a result's
 * `kind` can never disagree with its `successCode` or its `error.code`.
 */
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
 * The bounds this card selects for the worker boundary (contract Issue #369
 * "Bounds"). C-API §4 leaves the bounded-byte limits to a later selection; this is
 * that selection for the worker boundary only. Over-limit values reject, never
 * truncate.
 */
const BOUNDS = Object.freeze({
  MAX_MESSAGE_BYTES: 4194304,
  MAX_DEPTH: 16,
  MAX_NODES: 65536,
  MAX_ARRAY_LENGTH: 16384,
  MAX_STRING_CHARS: 65536,
  MAX_REQUEST_ID_CHARS: 128,
  MAX_BINDING_REF_BYTES: 4096,
  MAX_OPAQUE_BYTES: 1048576,
  MAX_TOTAL_OPAQUE_BYTES: 3145728,
  MAX_BINARY_LEAVES: 64,
});

const PROTOCOL_VERSION = 1;
const API = 'styx-m2-session-adapter/v1';
const BYTES_KEY = '$bytes';

const WIRE_ERROR_CODES = Object.freeze([
  'UNKNOWN_FIELD', 'INVALID_REQUEST', 'UNKNOWN_VALUE', 'UNSUPPORTED_API_VERSION',
  'UNSUPPORTED_PROFILE', 'UNSUPPORTED_OPERATION', 'VALUE_OUT_OF_RANGE', 'FAIL_CLOSED_INTERNAL',
]);

/**
 * The only error this module throws. It carries a C-API error code and a C-API
 * `detailTag` and nothing else: no free text, no field name, no value, no path and
 * no positional detail of the rejected input.
 */
export class M2WorkerError extends Error {
  constructor(code, detailTag = 'FIELD') {
    if (!WIRE_ERROR_CODES.includes(code)) throw new TypeError('unknown M2 worker error code');
    if (!DETAIL_TAGS.includes(detailTag)) throw new TypeError('unknown M2 worker detail tag');
    super(code);
    this.name = 'M2WorkerError';
    this.code = code;
    this.detailTag = detailTag;
    this.valueFree = true;
  }
}

/**
 * Every error this module raises is registered here at construction. A caller can
 * forge an object that passes `instanceof M2WorkerError` (a plain
 * `Object.create(M2WorkerError.prototype)`), so shape alone cannot decide whether an
 * escaping exception is ours: membership of this WeakSet can. A forged error is never
 * rethrown and never lets its open `code`/free text out.
 */
const OWN_ERRORS = new WeakSet();

const fail = (code, detailTag) => {
  const error = new M2WorkerError(code, detailTag);
  OWN_ERRORS.add(error);
  throw error;
};

/** True only for errors this module itself constructed. */
const isOwnError = (error) => typeof error === 'object' && error !== null && OWN_ERRORS.has(error);

// --- closed-set membership -------------------------------------------------

const setOf = (values) => new Set(values);
const OPERATION_SET = setOf(OPERATIONS);
const STATE_SET = setOf(STATES);
const RESULT_KIND_SET = setOf(RESULT_KINDS);
const COMMIT_OUTCOME_SET = setOf(COMMIT_OUTCOMES);
const SUCCESS_CODE_SET = setOf(SUCCESS_CODES);
const ERROR_CODE_SET = setOf(ERROR_CODES);
const DETAIL_TAG_SET = setOf(DETAIL_TAGS);
const PROFILE_KEYS = Object.freeze(Object.keys(PROFILE));
const PROFILE_KEY_SET = setOf(PROFILE_KEYS);

/** Fail closed at load time if the merged adapter tables have drifted from C-API. */
function assertNoAdapterDrift() {
  const same = (left, right) => left.length === right.length
    && left.every((value, index) => value === right[index]);
  if (!same(ADAPTER_STATES, STATES) || !same(ADAPTER_OPERATIONS, OPERATIONS)) {
    throw new Error('I-WORK: merged adapter tables disagree with the ratified C-API enums');
  }
}
assertNoAdapterDrift();

// --- wire value grammar ----------------------------------------------------

const UINT8_PROTOTYPE = Uint8Array.prototype;
const TYPED_ARRAY_PROTOTYPE = Object.getPrototypeOf(Uint8Array.prototype);
const TYPED_TAG = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, Symbol.toStringTag).get;
const BYTE_LENGTH_GETTER = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, 'byteLength').get;
const OBJECT_PROTOTYPE = Object.prototype;
// The contract names four own keys a closed plain object may not carry: the two
// wasm-bindgen handle fields, the `$$` marker and `Symbol.toStringTag`. Symbol keys are
// refused outright by the key-type check, so only the three string keys are listed.
const FORBIDDEN_OWN_KEYS = Object.freeze(['__wbg_ptr', 'ptr', '$$']);
const BUFFER_GETTER = Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, 'buffer').get;
const OWN_INDEX = /^(0|[1-9][0-9]*)$/;

/**
 * Run one intrinsic inspection of an untrusted value. A revoked proxy or a proxy
 * whose trap throws raises a raw engine exception, and the contract permits only
 * `M2WorkerError` to escape, so every other exception becomes `INVALID_REQUEST`.
 * No free text from the rejected input is ever carried out.
 */
function inspect(thunk) {
  try {
    return thunk();
  } catch (error) {
    if (isOwnError(error)) throw error;
    fail('INVALID_REQUEST', 'FIELD');
  }
}

/**
 * Define one own enumerable data property without going through a setter. A decoded
 * document can carry a member literally named `__proto__`; assigning it would invoke
 * the `Object.prototype.__proto__` setter and silently drop the member before the
 * closed-object check ever sees it.
 */
const defineMember = (target, key, value) => Object.defineProperty(target, key, {
  value, writable: true, enumerable: true, configurable: true,
});

const isUint8 = (value) => {
  try {
    return ArrayBuffer.isView(value)
      && TYPED_TAG.call(value) === 'Uint8Array'
      && Object.getPrototypeOf(value) === UINT8_PROTOTYPE;
  } catch {
    return false;
  }
};

const byteLengthOf = (value) => {
  try {
    return BYTE_LENGTH_GETTER.call(value);
  } catch {
    return -1;
  }
};

const isArrayBuffer = (value) => {
  if (typeof ArrayBuffer === 'undefined') return false;
  try {
    if (!(value instanceof ArrayBuffer)) return false;
    return Object.getPrototypeOf(value) === ArrayBuffer.prototype;
  } catch {
    return false;
  }
};

const ARRAY_BUFFER_BYTE_LENGTH_GETTER = typeof ArrayBuffer === 'undefined'
  ? null
  : Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'byteLength').get;

/** Brand-checked byte length of a raw buffer, or -1 when it is not one. */
const arrayBufferByteLength = (value) => {
  if (ARRAY_BUFFER_BYTE_LENGTH_GETTER === null) return -1;
  try {
    return ARRAY_BUFFER_BYTE_LENGTH_GETTER.call(value);
  } catch {
    return -1;
  }
};

/**
 * Brand check for `SharedArrayBuffer`. `instanceof` walks the prototype chain of an
 * untrusted value, so a caller can re-prototype a shared buffer
 * (`Object.setPrototypeOf(sab, ArrayBuffer.prototype)`) or forge one and defeat it.
 * Calling the intrinsic `SharedArrayBuffer.prototype.byteLength` getter succeeds only
 * for a real shared buffer (the internal slot is not forgeable and is realm-public).
 */
const SHARED_BYTE_LENGTH_GETTER = typeof SharedArrayBuffer === 'undefined'
  ? null
  : Object.getOwnPropertyDescriptor(SharedArrayBuffer.prototype, 'byteLength').get;

const isSharedBuffer = (value) => {
  if (SHARED_BYTE_LENGTH_GETTER === null) return false;
  try {
    SHARED_BYTE_LENGTH_GETTER.call(value);
    return true;
  } catch {
    return false;
  }
};

/**
 * A view is shared-backed only when its *intrinsic* buffer is a `SharedArrayBuffer`,
 * and sharedness is decided by brand check, never by `instanceof`. `value.buffer` is an
 * ordinary property that a caller can shadow with an own data property, so the
 * intrinsic getter is used instead.
 */
const isSharedBacked = (value) => {
  try {
    if (isUint8(value)) return isSharedBuffer(BUFFER_GETTER.call(value));
    return isSharedBuffer(value);
  } catch {
    return false;
  }
};

const isOpaqueObject = (value) => {
  if (typeof CryptoKey !== 'undefined') {
    try {
      if (value instanceof CryptoKey) return 'cryptokey';
    } catch { /* ignore */ }
  }
  if (typeof WebAssembly !== 'undefined') {
    for (const name of ['Module', 'Instance', 'Memory', 'Table', 'Global']) {
      const ctor = WebAssembly[name];
      if (typeof ctor === 'function') {
        try {
          if (value instanceof ctor) return `wasm-${name.toLowerCase()}`;
        } catch { /* ignore */ }
      }
    }
  }
  return null;
};

const isLoneSurrogateFree = (text) => {
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = text.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }
  return true;
};

// C0 (U+0000–U+001F), DEL (U+007F) and the C1 block (U+0080–U+009F) are all Unicode
// category Cc, and the contract forbids every control character in a carried string.
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;

const newBudget = () => ({ nodes: 0, binaries: 0, opaqueBytes: 0 });

const spendNode = (budget) => {
  budget.nodes += 1;
  if (budget.nodes > BOUNDS.MAX_NODES) fail('VALUE_OUT_OF_RANGE', 'FIELD');
};

/**
 * Deep validation of one wire value against the closed grammar. Accepts null,
 * booleans, finite numbers, bounded strings without lone surrogates, closed plain
 * objects, bounded arrays and bounded binary leaves; rejects accessors, symbol
 * keys, exotic prototypes, opaque handles, shared buffers and cycles.
 */
function validateWireValue(value, budget, depth, seen) {
  if (depth > BOUNDS.MAX_DEPTH) fail('VALUE_OUT_OF_RANGE', 'FIELD');
  spendNode(budget);

  if (value === null) return null;
  const type = typeof value;
  if (type === 'boolean') return value;
  if (type === 'number') {
    if (!Number.isFinite(value)) fail('UNKNOWN_VALUE', 'FIELD');
    return value;
  }
  if (type === 'string') {
    if (value.length > BOUNDS.MAX_STRING_CHARS) fail('VALUE_OUT_OF_RANGE', 'FIELD');
    if (!isLoneSurrogateFree(value)) fail('INVALID_REQUEST', 'FIELD');
    return value;
  }
  if (type === 'function' || type === 'symbol' || type === 'bigint' || type === 'undefined') {
    fail('INVALID_REQUEST', 'FIELD');
  }
  if (inspect(() => value instanceof Promise)) fail('INVALID_REQUEST', 'FIELD');
  if (isOpaqueObject(value) !== null) fail('INVALID_REQUEST', 'FIELD');

  if (isUint8(value) || isArrayBuffer(value)) {
    if (isSharedBacked(value)) fail('INVALID_REQUEST', 'FIELD');
    const expected = isUint8(value) ? byteLengthOf(value) : 0;
    // A typed array or a buffer can carry only own integer-indexed properties, and
    // those are non-configurable, so they can neither be deleted nor shadowed. Any
    // other own member — `__wbg_ptr`, an attached function or `WebAssembly` object,
    // a symbol key — raises the count, so the count alone proves there is none.
    const own = inspect(() => Reflect.ownKeys(value));
    if (own.length !== expected) fail('INVALID_REQUEST', 'FIELD');
    for (const key of own) {
      if (typeof key !== 'string') fail('INVALID_REQUEST', 'FIELD');
    }
    const length = isUint8(value) ? byteLengthOf(value) : value.byteLength;
    if (length < 0) fail('INVALID_REQUEST', 'FIELD');
    if (length > BOUNDS.MAX_OPAQUE_BYTES) fail('VALUE_OUT_OF_RANGE', 'FIELD');
    budget.binaries += 1;
    budget.opaqueBytes += length;
    if (budget.binaries > BOUNDS.MAX_BINARY_LEAVES) fail('VALUE_OUT_OF_RANGE', 'FIELD');
    if (budget.opaqueBytes > BOUNDS.MAX_TOTAL_OPAQUE_BYTES) fail('VALUE_OUT_OF_RANGE', 'FIELD');
    return value;
  }
  if (type !== 'object') fail('INVALID_REQUEST', 'FIELD');

  if (ArrayBuffer.isView(value)) fail('INVALID_REQUEST', 'FIELD');
  if (seen.has(value)) fail('INVALID_REQUEST', 'FIELD');
  seen.add(value);
  try {
    if (inspect(() => Array.isArray(value))) {
      const arrayLength = inspect(() => value.length);
      if (arrayLength > BOUNDS.MAX_ARRAY_LENGTH) fail('VALUE_OUT_OF_RANGE', 'FIELD');
      const output = [];
      for (let index = 0; index < arrayLength; index += 1) {
        const descriptor = inspect(() => Object.getOwnPropertyDescriptor(value, String(index)));
        if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) {
          fail('INVALID_REQUEST', 'FIELD');
        }
        output.push(validateWireValue(descriptor.value, budget, depth + 1, seen));
      }
      const own = inspect(() => Reflect.ownKeys(value));
      if (own.length !== arrayLength + 1) fail('UNKNOWN_FIELD', 'FIELD');
      for (const key of own) {
        if (typeof key !== 'string') fail('INVALID_REQUEST', 'FIELD');
        if (key === 'length') continue;
        if (!OWN_INDEX.test(key) || Number(key) >= arrayLength) {
          fail('UNKNOWN_FIELD', 'FIELD');
        }
      }
      return output;
    }
    if (inspect(() => Object.getPrototypeOf(value)) !== OBJECT_PROTOTYPE) {
      fail('INVALID_REQUEST', 'FIELD');
    }
    const keys = inspect(() => Reflect.ownKeys(value));
    const descriptors = inspect(() => Object.getOwnPropertyDescriptors(value));
    const output = {};
    for (const key of keys) {
      if (typeof key !== 'string') fail('INVALID_REQUEST', 'FIELD');
      if (FORBIDDEN_OWN_KEYS.includes(key)) fail('INVALID_REQUEST', 'FIELD');
      const descriptor = descriptors[key];
      if (!Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) {
        fail('INVALID_REQUEST', 'FIELD');
      }
      defineMember(output, key, validateWireValue(descriptor.value, budget, depth + 1, seen));
    }
    return output;
  } finally {
    seen.delete(value);
  }
}

/**
 * Bounds-only pass. It walks the caller's value looking *only* for bound violations,
 * so an over-limit value is `VALUE_OUT_OF_RANGE` even when it sits under a member the
 * closed-object grammar refuses for a different reason. Kind violations — a function,
 * a promise, an opaque handle, an exotic prototype, a cycle, an accessor — are left to
 * the grammar and to the full sweep that runs after it, so a foreign member holding
 * one of those still reports `UNKNOWN_FIELD` rather than `INVALID_REQUEST`.
 *
 * The walk is trap-safe: any engine error raised by an untrusted value stops that
 * branch and is left to the full sweep, which reports it as `INVALID_REQUEST`.
 */
function sweepBounds(value, budget, depth, seen) {
  if (depth > BOUNDS.MAX_DEPTH) fail('VALUE_OUT_OF_RANGE', 'FIELD');
  spendNode(budget);
  if (typeof value !== 'object' || value === null) {
    if (typeof value === 'string' && value.length > BOUNDS.MAX_STRING_CHARS) {
      fail('VALUE_OUT_OF_RANGE', 'FIELD');
    }
    return;
  }
  try {
    if (isUint8(value) || isArrayBuffer(value)) {
      if (isSharedBacked(value)) return; // the full sweep reports the shared buffer
      const length = isUint8(value) ? byteLengthOf(value) : arrayBufferByteLength(value);
      if (length < 0) return;
      if (length > BOUNDS.MAX_OPAQUE_BYTES) fail('VALUE_OUT_OF_RANGE', 'FIELD');
      budget.binaries += 1;
      budget.opaqueBytes += length;
      if (budget.binaries > BOUNDS.MAX_BINARY_LEAVES) fail('VALUE_OUT_OF_RANGE', 'FIELD');
      if (budget.opaqueBytes > BOUNDS.MAX_TOTAL_OPAQUE_BYTES) fail('VALUE_OUT_OF_RANGE', 'FIELD');
      return;
    }
    if (ArrayBuffer.isView(value)) return;
    if (Object.getPrototypeOf(value) !== OBJECT_PROTOTYPE && !Array.isArray(value)) return;
    if (seen.has(value)) return;
    seen.add(value);
    if (Array.isArray(value)) {
      const arrayLength = value.length;
      if (arrayLength > BOUNDS.MAX_ARRAY_LENGTH) fail('VALUE_OUT_OF_RANGE', 'FIELD');
      for (let index = 0; index < arrayLength; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (descriptor && Object.hasOwn(descriptor, 'value')) {
          sweepBounds(descriptor.value, budget, depth + 1, seen);
        }
      }
      return;
    }
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== 'string') continue;
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor && Object.hasOwn(descriptor, 'value')) {
        sweepBounds(descriptor.value, budget, depth + 1, seen);
      }
    }
  } catch (error) {
    if (isOwnError(error)) throw error;
  }
}

const wireCheck = (value, boundsOnly = false) => {
  const budget = newBudget();
  const seen = new Set();
  if (boundsOnly) return sweepBounds(value, budget, 0, seen);
  return validateWireValue(value, budget, 0, seen);
};

/**
 * Read a closed plain object: only the allowed keys, only data properties, and
 * every required key present. `onUnknown` selects the code a foreign key raises so
 * a closed profile tuple reports `UNSUPPORTED_PROFILE` rather than `UNKNOWN_FIELD`.
 */
function readClosed(value, allowed, required, onUnknown = 'UNKNOWN_FIELD', onMissing = 'INVALID_REQUEST') {
  const tag = (code) => (code === 'UNSUPPORTED_PROFILE' ? 'PROFILE' : 'FIELD');
  if (value === null || typeof value !== 'object'
      || inspect(() => Array.isArray(value)) || ArrayBuffer.isView(value)) {
    fail('INVALID_REQUEST', 'FIELD');
  }
  if (inspect(() => Object.getPrototypeOf(value)) !== OBJECT_PROTOTYPE) {
    fail('INVALID_REQUEST', 'FIELD');
  }
  const keys = inspect(() => Reflect.ownKeys(value));
  const descriptors = inspect(() => Object.getOwnPropertyDescriptors(value));
  const values = {};
  for (const key of keys) {
    if (typeof key !== 'string') fail('INVALID_REQUEST', 'FIELD');
    if (FORBIDDEN_OWN_KEYS.includes(key)) fail('INVALID_REQUEST', 'FIELD');
    const descriptor = descriptors[key];
    if (!Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) {
      fail('INVALID_REQUEST', 'FIELD');
    }
    if (!allowed.includes(key)) fail(onUnknown, tag(onUnknown));
    defineMember(values, key, descriptor.value);
  }
  for (const key of required) {
    if (!Object.hasOwn(descriptors, key)) fail(onMissing, tag(onMissing));
  }
  return { values, keys };
}

function boundedString(value, maxChars, code = 'INVALID_REQUEST', tag = 'FIELD') {
  if (typeof value !== 'string' || value.length === 0) fail(code, tag);
  if (value.length > maxChars) fail('VALUE_OUT_OF_RANGE', tag);
  if (!isLoneSurrogateFree(value)) fail(code, tag);
  return value;
}

function opaqueBytes(value, maxBytes, tag = 'BINDING') {
  if (!isUint8(value)) fail('VALUE_OUT_OF_RANGE', tag);
  if (isSharedBacked(value)) fail('INVALID_REQUEST', tag);
  const length = byteLengthOf(value);
  if (length < 1 || length > maxBytes) fail('VALUE_OUT_OF_RANGE', tag);
  // A view whose own members are not exactly its indices carries something other than
  // bytes — typically a wasm-bindgen handle such as `__wbg_ptr`. The wire sweep rejects
  // it; the field-level copy must agree with the sweep rather than silently accepting a
  // decoy the sweep would refuse. A `Uint8Array` has no own `length` (it lives on the
  // prototype), so its own keys are exactly the byte indices.
  const own = inspect(() => Reflect.ownKeys(value));
  if (own.length !== length) fail('INVALID_REQUEST', tag);
  for (const key of own) {
    if (typeof key !== 'string' || !OWN_INDEX.test(key) || Number(key) >= length) {
      fail('INVALID_REQUEST', tag);
    }
  }
  const copy = new Uint8Array(length);
  copy.set(value);
  return copy;
}

function checkApi(value) {
  if (value !== API) fail('UNSUPPORTED_API_VERSION', 'PROFILE');
  return API;
}

function checkOperation(value) {
  if (typeof value !== 'string' || !OPERATION_SET.has(value)) fail('UNSUPPORTED_OPERATION', 'STATE');
  return value;
}

function checkRequestId(value) {
  if (typeof value !== 'string' || value.length === 0
      || CONTROL.test(value) || !isLoneSurrogateFree(value)) {
    fail('INVALID_REQUEST', 'FIELD');
  }
  // The bounds table is normative: an over-limit value is VALUE_OUT_OF_RANGE, never
  // truncated and never folded into the malformed-value code.
  if (value.length > BOUNDS.MAX_REQUEST_ID_CHARS) fail('VALUE_OUT_OF_RANGE', 'FIELD');
  return value;
}

function checkProfile(value) {
  const { values, keys } = readClosed(value, PROFILE_KEYS, PROFILE_KEYS,
    'UNSUPPORTED_PROFILE', 'UNSUPPORTED_PROFILE');
  if (keys.length !== PROFILE_KEYS.length) fail('UNSUPPORTED_PROFILE', 'PROFILE');
  for (const key of PROFILE_KEYS) {
    if (values[key] !== PROFILE[key]) fail('UNSUPPORTED_PROFILE', 'PROFILE');
  }
  return values;
}

// --- requests --------------------------------------------------------------

/** Validate exactly the closed C-API `/request` record for its operation. */
function validateRequestTotal(input) {
  const { values } = readClosed(input, REQUEST_FIELDS, REQUEST_FIELDS);
  checkApi(values.api);
  const operation = checkOperation(values.operation);
  const requestId = checkRequestId(values.requestId);
  const profile = checkProfile(values.profile);
  const bindingRef = opaqueBytes(values.bindingRef, BOUNDS.MAX_BINDING_REF_BYTES, 'BINDING');
  const assigned = INPUT_BY_OPERATION[operation];
  const { values: rawInput } = readClosed(values.input, assigned, assigned);
  const requestInput = {};
  for (const key of assigned) {
    requestInput[key] = INPUT_BYTES.includes(key)
      ? opaqueBytes(rawInput[key], BOUNDS.MAX_OPAQUE_BYTES, 'FIELD')
      : boundedString(rawInput[key], BOUNDS.MAX_STRING_CHARS, 'UNKNOWN_VALUE', 'FIELD');
  }
  return freezeDeep({
    api: API, operation, requestId, profile, bindingRef, input: requestInput,
  });
}

// --- results ---------------------------------------------------------------

function checkCommitOutcome(value, expected) {
  if (typeof value !== 'string' || !COMMIT_OUTCOME_SET.has(value)) fail('UNKNOWN_VALUE', 'STATE');
  if (value !== expected) fail('UNKNOWN_VALUE', 'STATE');
  return value;
}

function checkSuccessCode(value, kind) {
  if (typeof value !== 'string' || !SUCCESS_CODE_SET.has(value)) fail('UNKNOWN_VALUE', 'STATE');
  if (!ALLOWED_CODES[kind].includes(value)) fail('UNKNOWN_VALUE', 'STATE');
  if (CODE_TO_KIND[value] !== kind) fail('UNKNOWN_VALUE', 'STATE');
  return value;
}

function checkOutput(value, successCode, depth) {
  if (depth > BOUNDS.MAX_DEPTH) fail('VALUE_OUT_OF_RANGE', 'FIELD');
  const assigned = OUTPUT_BY_SUCCESS_CODE[successCode];
  const { values } = readClosed(value, assigned, assigned);
  const output = {};
  for (const key of assigned) {
    if (key === 'originalOutput') {
      const original = values.originalSuccessCode;
      if (typeof original !== 'string' || !ORIGINAL_SUCCESS_CODE_SET.has(original)) {
        fail('UNKNOWN_VALUE', 'STATE');
      }
      output.originalSuccessCode = original;
      output.originalOutput = checkOutput(values.originalOutput, original, depth + 1);
    } else if (OUTPUT_BYTES.includes(key)) {
      output[key] = opaqueBytes(values[key], BOUNDS.MAX_OPAQUE_BYTES, 'FIELD');
    } else {
      output[key] = boundedString(values[key], BOUNDS.MAX_STRING_CHARS, 'UNKNOWN_VALUE', 'FIELD');
    }
  }
  return output;
}

function checkErrorShape(value) {
  const { values, keys } = readClosed(value, ['code', 'detailTag'], ['code']);
  if (typeof values.code !== 'string' || !ERROR_CODE_SET.has(values.code)) {
    fail('UNKNOWN_VALUE', 'STATE');
  }
  if (CODE_TO_KIND[values.code] !== 'REJECTED') fail('UNKNOWN_VALUE', 'STATE');
  const error = { code: values.code };
  if (keys.includes('detailTag')) {
    if (typeof values.detailTag !== 'string' || !DETAIL_TAG_SET.has(values.detailTag)) {
      fail('UNKNOWN_VALUE', 'STATE');
    }
    error.detailTag = values.detailTag;
  }
  return error;
}

/** Validate exactly `{code}` plus an optional C-API `detailTag`. */
function validateErrorTotal(value) {
  return freezeDeep(checkErrorShape(value));
}

/** Validate one closed result of any of the five C-API kinds. */
function validateResultTotal(input) {
  const { values, keys } = readClosed(input, RESULT_UNION, RESULT_COMMON);
  checkApi(values.api);
  const requestId = checkRequestId(values.requestId);
  const operation = checkOperation(values.operation);
  if (typeof values.kind !== 'string' || !RESULT_KIND_SET.has(values.kind)) {
    fail('UNKNOWN_VALUE', 'STATE');
  }
  const kind = values.kind;
  for (const key of RESULT_REQUIRED[kind]) {
    if (!keys.includes(key)) fail('INVALID_REQUEST', 'FIELD');
  }
  for (const key of keys) {
    if (!RESULT_COMMON.includes(key) && !RESULT_ALLOWED_BY_KIND[kind].includes(key)) {
      fail('UNKNOWN_FIELD', 'FIELD');
    }
  }
  if (typeof values.stateBefore !== 'string' || !STATE_SET.has(values.stateBefore)) {
    fail('UNKNOWN_VALUE', 'STATE');
  }
  if (typeof values.stateAfter !== 'string' || !STATE_SET.has(values.stateAfter)) {
    fail('UNKNOWN_VALUE', 'STATE');
  }
  const result = {
    api: API,
    requestId,
    operation,
    kind,
    stateBefore: values.stateBefore,
    stateAfter: values.stateAfter,
  };
  if (kind === 'SUCCESS') {
    const successCode = checkSuccessCode(values.successCode, kind);
    result.successCode = successCode;
    if (keys.includes('commitOutcome')) {
      result.commitOutcome = checkCommitOutcome(values.commitOutcome, 'COMMITTED');
    }
    if (keys.includes('output')) result.output = checkOutput(values.output, successCode, 0);
  } else if (kind === 'NO_CHANGE') {
    result.successCode = checkSuccessCode(values.successCode, kind);
  } else if (kind === 'NOT_COMMITTED') {
    result.commitOutcome = checkCommitOutcome(values.commitOutcome, 'NOT_COMMITTED');
  } else if (kind === 'INDETERMINATE') {
    result.commitOutcome = checkCommitOutcome(values.commitOutcome, 'INDETERMINATE');
    result.reconciliationRef = boundedString(values.reconciliationRef, BOUNDS.MAX_STRING_CHARS,
      'UNKNOWN_VALUE', 'FIELD');
    if (values.originalStateBefore !== 'EMPTY' && values.originalStateBefore !== 'ACTIVE') {
      fail('UNKNOWN_VALUE', 'STATE');
    }
    result.originalStateBefore = values.originalStateBefore;
  } else {
    result.error = checkErrorShape(values.error);
  }
  return freezeDeep(result);
}

// --- classification and dispatch -------------------------------------------

const hasOwn = (value, key) => value !== null && typeof value === 'object'
  && inspect(() => Object.getPrototypeOf(value)) === OBJECT_PROTOTYPE && Object.hasOwn(value, key);

/** Deterministic, total discriminator over the closed grammar. */
export function classifyWorkerMessage(value) {
  try {
    return classify(value);
  } catch {
    return null;
  }
}

function classify(value) {
  if (value === null || typeof value !== 'object'
      || inspect(() => Array.isArray(value)) || ArrayBuffer.isView(value)) {
    return null;
  }
  if (inspect(() => Object.getPrototypeOf(value)) !== OBJECT_PROTOTYPE) return null;
  if (inspect(() => hasOwn(value, 'input'))) return 'REQUEST';
  const kind = inspect(() => Object.getOwnPropertyDescriptor(value, 'kind'));
  if (!kind || !Object.hasOwn(kind, 'value') || kind.enumerable !== true) return null;
  return typeof kind.value === 'string' && RESULT_KIND_SET.has(kind.value) ? kind.value : null;
}

/** Validate a message of either family by classification. */
function validateMessageTotal(value) {
  const kind = classifyWorkerMessage(value);
  if (kind === null) fail('INVALID_REQUEST', 'FIELD');
  return kind === 'REQUEST' ? validateWorkerRequest(value) : validateWorkerResult(value);
}

/**
 * Validate the called kind and sweep every reachable leaf for wire safety.
 *
 * The caller's value is swept twice: a bounds-only pass *before* the grammar, then the
 * full wire sweep *after* it. The bounds pass makes every numeric bound observable — an
 * over-limit value is `VALUE_OUT_OF_RANGE` even under a member the grammar would refuse
 * for another reason, which is what the acceptance criteria's per-bound named
 * rejections require. The full sweep then decides everything the bounds pass left to
 * the grammar: opaque handles, exotic prototypes, cycles, accessors and shared buffers.
 * Both sweeps run over the *caller's* value, never over the validator's output: the
 * output is rebuilt only from fresh plain objects, strings and fresh `Uint8Array`
 * copies, so a sweep of it could never reject anything.
 */
function assertSafeTotal(value) {
  wireCheck(value, true);
  const message = validateWorkerMessage(value);
  wireCheck(value);
  const bytes = encodeWire(message);
  if (bytes.length > BOUNDS.MAX_MESSAGE_BYTES) fail('VALUE_OUT_OF_RANGE', 'FIELD');
  return message;
}

// --- freezing --------------------------------------------------------------

function freezeDeep(value) {
  if (value === null || typeof value !== 'object') return value;
  if (isUint8(value)) {
    const copy = new Uint8Array(byteLengthOf(value));
    copy.set(value);
    return copy;
  }
  if (Array.isArray(value)) {
    value.forEach((entry) => freezeDeep(entry));
    return Object.freeze(value);
  }
  for (const key of Object.keys(value)) freezeDeep(value[key]);
  return Object.freeze(value);
}

// --- wire encoding ---------------------------------------------------------

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function base64Encode(bytes) {
  let output = '';
  for (let index = 0; index < bytes.length; index += 3) {
    const a = bytes[index];
    const b = index + 1 < bytes.length ? bytes[index + 1] : 0;
    const c = index + 2 < bytes.length ? bytes[index + 2] : 0;
    output += B64[a >> 2];
    output += B64[((a & 3) << 4) | (b >> 4)];
    output += index + 1 < bytes.length ? B64[((b & 15) << 2) | (c >> 6)] : '=';
    output += index + 2 < bytes.length ? B64[c & 63] : '=';
  }
  return output;
}

function base64Decode(text) {
  if (text.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) {
    fail('UNKNOWN_VALUE', 'FIELD');
  }
  const clean = text.replace(/=+$/, '');
  const output = new Uint8Array((clean.length * 3) >> 2);
  let accumulator = 0;
  let bits = 0;
  let offset = 0;
  for (const character of clean) {
    const value = B64.indexOf(character);
    if (value < 0) fail('UNKNOWN_VALUE', 'FIELD');
    accumulator = (accumulator << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      output[offset] = (accumulator >> bits) & 0xff;
      offset += 1;
    }
  }
  return offset === output.length ? output : output.subarray(0, offset);
}

function toJsonValue(value) {
  if (isUint8(value)) return { [BYTES_KEY]: base64Encode(value) };
  if (inspect(() => Array.isArray(value))) return value.map(toJsonValue);
  if (value !== null && typeof value === 'object') {
    const output = {};
    for (const key of Object.keys(value)) defineMember(output, key, toJsonValue(value[key]));
    return output;
  }
  return value;
}

/**
 * Restore the binary leaves of a parsed document and rebuild every object as a
 * plain object with own enumerable data properties.
 *
 * Depth is bounded *before* the recursion descends, so a deeply nested document
 * cannot exhaust the stack: `MAX_DEPTH` is `VALUE_OUT_OF_RANGE`/`FIELD` here, the
 * same code the deep wire-value grammar raises.
 */
const fromJsonValue = (value, depth = 0) => {
  if (depth > BOUNDS.MAX_DEPTH) fail('VALUE_OUT_OF_RANGE', 'FIELD');
  if (inspect(() => Array.isArray(value))) return value.map((entry) => fromJsonValue(entry, depth + 1));
  if (value !== null && typeof value === 'object') {
    const keys = inspect(() => Reflect.ownKeys(value));
    for (const key of keys) if (typeof key !== 'string') fail('INVALID_REQUEST', 'FIELD');
    if (keys.includes(BYTES_KEY)) {
      // The reserved key owns the whole object: it is a binary leaf and its value
      // must be a base64 string. A member named `$bytes` beside any other member is
      // not a leaf at all and is a message field the grammar does not allow.
      if (keys.length !== 1) fail('UNKNOWN_FIELD', 'FIELD');
      if (typeof value[BYTES_KEY] !== 'string') fail('INVALID_REQUEST', 'FIELD');
      return base64Decode(value[BYTES_KEY]);
    }
    const output = {};
    for (const key of keys) defineMember(output, key, fromJsonValue(value[key], depth + 1));
    return output;
  }
  return value;
};

function encodeWire(message) {
  if (typeof TextEncoder === 'undefined') throw new Error('TextEncoder unavailable');
  return new TextEncoder().encode(JSON.stringify(toJsonValue(message)));
}

/** Make a validated message wire-safe and return its canonical encoding. */
function toWireTotal(message) {
  const safe = assertWireSafe(message);
  const bytes = encodeWire(safe);
  if (bytes.length > BOUNDS.MAX_MESSAGE_BYTES) fail('VALUE_OUT_OF_RANGE', 'FIELD');
  return bytes;
}

/** Decode and validate a canonical message; bounded before it is parsed. */
function fromWireTotal(bytes) {
  if (!isUint8(bytes)) fail('INVALID_REQUEST', 'FIELD');
  const length = byteLengthOf(bytes);
  if (length > BOUNDS.MAX_MESSAGE_BYTES) fail('VALUE_OUT_OF_RANGE', 'FIELD');
  if (typeof TextDecoder === 'undefined') throw new Error('TextDecoder unavailable');
  let text;
  try {
    // `ignoreBOM: true` keeps a leading U+FEFF in the decoded text instead of
    // silently stripping it, so a byte-order-marked document is not a valid one.
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    fail('INVALID_REQUEST', 'FIELD');
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    fail('INVALID_REQUEST', 'FIELD');
  }
  return assertWireSafe(fromJsonValue(parsed));
}

// --- public surface ---------------------------------------------------------

/**
 * Make totality a property of the exported surface rather than of each inspection
 * site. The contract permits only `M2WorkerError` to escape, but a raw engine
 * exception can still be raised anywhere an untrusted value reaches an intrinsic:
 * a revoked proxy, a proxy trap that throws, or a class with a hostile
 * `Symbol.hasInstance` reached through `instanceof`. The wrapper maps anything that is
 * not an error this module constructed to `INVALID_REQUEST`/`FIELD`, and rethrows our
 * own errors unchanged, so no forged error and no engine text can escape.
 */
const total = (implementation) => {
  const wrapped = function totalValidator(value) {
    try {
      return implementation(value);
    } catch (error) {
      if (isOwnError(error)) throw error;
      fail('INVALID_REQUEST', 'FIELD');
    }
  };
  Object.defineProperty(wrapped, 'name', { value: implementation.name, configurable: true });
  return wrapped;
};

export const validateWorkerRequest = total(validateRequestTotal);
export const validateWorkerResult = total(validateResultTotal);
export const validateWorkerError = total(validateErrorTotal);
export const validateWorkerMessage = total(validateMessageTotal);
export const assertWireSafe = total(assertSafeTotal);
export const toWireBytes = total(toWireTotal);
export const fromWireBytes = total(fromWireTotal);

/** Frozen metadata: exactly the closed members the contract names. */
export const M2_WORKER = Object.freeze({
  PROTOCOL_VERSION,
  API,
  MESSAGE_KINDS: Object.freeze(['REQUEST'].concat(RESULT_KINDS)),
  RESULT_KINDS,
  SUCCESS_CODES,
  ERROR_CODES,
  DETAIL_TAGS,
  COMMIT_OUTCOMES,
  STATES,
  OPERATIONS,
  CODE_TO_KIND,
  PROFILE,
  OUTPUT_BY_SUCCESS_CODE,
  BOUNDS,
});
