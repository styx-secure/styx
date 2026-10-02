// M2 fail-closed restore/version decision over an injected observation record.
// Internal-only: no barrel export.
//
// This module is the executable form of the ratified C-REST contract
// (`docs/architecture/m2/restore-compatibility.md`, SHA-256
// 853dbc41778d86ff42432d5cc0bc75d8c51ac32606daae9240271c1ce78766b6). It carries the closed
// restore vocabulary - fourteen ordered phases, two inventory outcomes, three authenticated
// successes, thirteen failures, one condition, twenty-six fault-precedence rows and twenty
// negative classes - and it classifies one restore observation fail-closed.
//
// The observation is an injected record because C-REST leaves the physical storage design to a
// later card (B-CHR). This module therefore executes no storage, no crypto, no browser and no
// worker call: it decides, from the facts it is handed, exactly the closed outcome C-REST
// mandates, and it refuses to accept a fact, a version, a pin, a build row or an observation
// member that is not in a closed allowlist.
//
// Fail-closed rule of the module: anything unknown, missing, duplicate, reordered, extra,
// overlapping or out of type resolves to `INTERNAL_VALIDATION_FAILED` at `CLASSIFY` - never to a
// success, never to an empty result, never to legacy-only and never to a repair path.
//
// `M2_RESTORE.VERSIONS` is a closed allowlist of equality, never a range: equality of the eight
// C-FMT versions and equality of a complete `buildMatrix` row. There is no semver rule, no
// minimum, no downgrade and no partial recognition.
//
// The fresh-worker fixture matrix of §12 is executable here as
// `runFreshWorkerFixtureMatrix()`: the seven positive fixtures and the sixty-five negative
// fixtures of C-REST are classified through `classifyRestore` and return their exact typed
// outcomes (`result`) at their exact `firstPhase`.

/** The only exported error class. `result` is a closed failure; `stage` a closed phase. */
export class M2RestoreError extends Error {
  constructor(result, stage) {
    if (!FAILURE_RESULTS.includes(result) || !PHASES.includes(stage)) {
      throw new Error('M2RestoreError requires a closed result and a closed stage');
    }
    super('M2_RESTORE_REJECTED');
    this.name = 'M2RestoreError';
    this.result = result;
    this.stage = stage;
  }
}

/** The fourteen C-REST phases, in exactly the normative `phaseOrder`. */
export const PHASES = Object.freeze([
  'LOCK',
  'BUILD_ELIGIBILITY',
  'INVENTORY',
  'WRAPPER_AUTH',
  'KEY_DERIVATION',
  'SELECTOR_HEADER',
  'SELECTOR_AUTH',
  'AUTHENTICATED_COMPATIBILITY',
  'MANIFEST_ROOT',
  'RECORD_SET',
  'RECORD_DECODE',
  'REFERENCES',
  'CLASSIFY',
  'EXPOSE',
]);

/** §10 `resultSets.inventory`: the two unauthenticated inventory outcomes. */
export const INVENTORY_RESULTS = Object.freeze(['NO_M2_STATE', 'LEGACY_ONLY']);

/** §10 `resultSets.success`: the three authenticated successes. */
export const SUCCESS_RESULTS = Object.freeze([
  'RESTORED_EMPTY',
  'RESTORED_ACTIVE',
  'RESTORED_RECONCILIATION_REQUIRED',
]);

/** §10 `resultSets.failure`: exactly thirteen closed failures. */
export const FAILURE_RESULTS = Object.freeze([
  'LOCKED_ELSEWHERE',
  'WRAPPER_AUTH_FAILED',
  'INCOMPATIBLE_BUILD',
  'INCOMPATIBLE_FORMAT',
  'UNSUPPORTED_VERSION',
  'SELECTOR_INVALID',
  'AUTHENTICATION_FAILED',
  'MANIFEST_INVALID',
  'RECORD_SET_INCOMPLETE',
  'RECORD_INVALID',
  'REFERENCE_INCONSISTENT',
  'PARTIAL_GENERATION',
  'INTERNAL_VALIDATION_FAILED',
]);

/** §10 `resultSets.condition`: a condition attached to the applicable M2 result. */
export const CONDITIONS = Object.freeze(['LEGACY_PRESENT']);

/** `failureDefault`: every unresolved case resolves here. */
export const FAILURE_DEFAULT = 'INTERNAL_VALIDATION_FAILED';

/** `successBySelectorState`: the only mapping from authenticated selector state to success. */
export const SUCCESS_BY_SELECTOR_STATE = Object.freeze({
  EMPTY: 'RESTORED_EMPTY',
  ACTIVE: 'RESTORED_ACTIVE',
  RECONCILIATION_REQUIRED: 'RESTORED_RECONCILIATION_REQUIRED',
});

/** `faultPrecedence`: phase order first, then the unique row for a fault. */
export const FAULT_PRECEDENCE = Object.freeze([
  { fault: 'lockUnavailable', phase: 'LOCK', result: 'LOCKED_ELSEWHERE' },
  { fault: 'buildNotListed', phase: 'BUILD_ELIGIBILITY', result: 'INCOMPATIBLE_BUILD' },
  { fault: 'inventoryAmbiguous', phase: 'INVENTORY', result: 'INTERNAL_VALIDATION_FAILED' },
  { fault: 'multipleSelectorCandidates', phase: 'INVENTORY', result: 'SELECTOR_INVALID' },
  { fault: 'orphanGeneration', phase: 'INVENTORY', result: 'PARTIAL_GENERATION' },
  { fault: 'wrapperWrongOrInvalid', phase: 'WRAPPER_AUTH', result: 'WRAPPER_AUTH_FAILED' },
  { fault: 'keyDerivationFailed', phase: 'KEY_DERIVATION', result: 'INTERNAL_VALIDATION_FAILED' },
  { fault: 'selectorHeaderVersionUnknown', phase: 'SELECTOR_HEADER', result: 'UNSUPPORTED_VERSION' },
  { fault: 'selectorHeaderStructureIncompatible', phase: 'SELECTOR_HEADER', result: 'INCOMPATIBLE_FORMAT' },
  { fault: 'selectorMalformedOrMultiple', phase: 'SELECTOR_AUTH', result: 'SELECTOR_INVALID' },
  { fault: 'selectorAuthenticationFailed', phase: 'SELECTOR_AUTH', result: 'AUTHENTICATION_FAILED' },
  { fault: 'authenticatedVersionUnknownOrMixed', phase: 'AUTHENTICATED_COMPATIBILITY', result: 'UNSUPPORTED_VERSION' },
  { fault: 'authenticatedProfileIncompatible', phase: 'AUTHENTICATED_COMPATIBILITY', result: 'INCOMPATIBLE_FORMAT' },
  { fault: 'manifestOrRootMismatch', phase: 'MANIFEST_ROOT', result: 'MANIFEST_INVALID' },
  { fault: 'recordMissingExtraDuplicateReordered', phase: 'RECORD_SET', result: 'RECORD_SET_INCOMPLETE' },
  { fault: 'partialSelectedOrCandidateGeneration', phase: 'RECORD_SET', result: 'PARTIAL_GENERATION' },
  { fault: 'recordAuthenticationFailed', phase: 'RECORD_DECODE', result: 'AUTHENTICATION_FAILED' },
  { fault: 'recordCanonicalKeyKindVersionGenerationInvalid', phase: 'RECORD_DECODE', result: 'RECORD_INVALID' },
  { fault: 'candidateManifestKeyScopeSessionSubstitution', phase: 'RECORD_DECODE', result: 'RECORD_INVALID' },
  { fault: 'referenceOrLifecycleInconsistent', phase: 'REFERENCES', result: 'REFERENCE_INCONSISTENT' },
  { fault: 'candidateManifestKeyMismatch', phase: 'REFERENCES', result: 'REFERENCE_INCONSISTENT' },
  { fault: 'candidateParentMismatch', phase: 'REFERENCES', result: 'REFERENCE_INCONSISTENT' },
  { fault: 'candidateEqualsSelectedDuringReconciliation', phase: 'REFERENCES', result: 'REFERENCE_INCONSISTENT' },
  { fault: 'candidateFieldsDifferWithoutReconciliation', phase: 'REFERENCES', result: 'REFERENCE_INCONSISTENT' },
  { fault: 'unexpectedValidatorCondition', phase: 'CLASSIFY', result: 'INTERNAL_VALIDATION_FAILED' },
  { fault: 'unexpectedExposeCondition', phase: 'EXPOSE', result: 'INTERNAL_VALIDATION_FAILED' },
]);

/** `negativeClassMap`: every C-REST negative class and its unique fault/phase/result. */
export const NEGATIVE_CLASSES = Object.freeze([
  { negativeClass: 'UNKNOWN_MISSING_DUPLICATE_REORDERED_JSON_FIELD', fault: 'unexpectedValidatorCondition', phase: 'CLASSIFY', result: 'INTERNAL_VALIDATION_FAILED' },
  { negativeClass: 'UNKNOWN_MISSING_DUPLICATE_REORDERED_PLAINTEXT_FIELD', fault: 'recordCanonicalKeyKindVersionGenerationInvalid', phase: 'RECORD_DECODE', result: 'RECORD_INVALID' },
  { negativeClass: 'UNKNOWN_KIND_VERSION_ALGORITHM_LABEL', fault: 'authenticatedVersionUnknownOrMixed', phase: 'AUTHENTICATED_COMPATIBILITY', result: 'UNSUPPORTED_VERSION' },
  { negativeClass: 'NONCANONICAL_LENGTH_ENDIAN', fault: 'selectorHeaderStructureIncompatible', phase: 'SELECTOR_HEADER', result: 'INCOMPATIBLE_FORMAT' },
  { negativeClass: 'TRUNCATION_TRAILING_SIZE_OVERFLOW', fault: 'selectorHeaderStructureIncompatible', phase: 'SELECTOR_HEADER', result: 'INCOMPATIBLE_FORMAT' },
  { negativeClass: 'NONCE_REUSE', fault: 'recordAuthenticationFailed', phase: 'RECORD_DECODE', result: 'AUTHENTICATION_FAILED' },
  { negativeClass: 'AAD_CONTEXT_SESSION_PROFILE_KIND_VERSION_GENERATION_SUBSTITUTION', fault: 'recordAuthenticationFailed', phase: 'RECORD_DECODE', result: 'AUTHENTICATION_FAILED' },
  { negativeClass: 'KEY_OR_LABEL_COLLISION', fault: 'authenticatedProfileIncompatible', phase: 'AUTHENTICATED_COMPATIBILITY', result: 'INCOMPATIBLE_FORMAT' },
  { negativeClass: 'CROSS_DOMAIN_COPY', fault: 'recordAuthenticationFailed', phase: 'RECORD_DECODE', result: 'AUTHENTICATION_FAILED' },
  { negativeClass: 'MANIFEST_OMISSION_ADDITION_DUPLICATE_REORDER', fault: 'manifestOrRootMismatch', phase: 'MANIFEST_ROOT', result: 'MANIFEST_INVALID' },
  { negativeClass: 'ROOT_OR_SELECTOR_MISMATCH', fault: 'manifestOrRootMismatch', phase: 'MANIFEST_ROOT', result: 'MANIFEST_INVALID' },
  { negativeClass: 'HISTORICAL_SUBSET_UNDER_CURRENT_ROOT', fault: 'manifestOrRootMismatch', phase: 'MANIFEST_ROOT', result: 'MANIFEST_INVALID' },
  { negativeClass: 'PARTIAL_GENERATION', fault: 'partialSelectedOrCandidateGeneration', phase: 'RECORD_SET', result: 'PARTIAL_GENERATION' },
  { negativeClass: 'FORGED_RESULT_ESCROW_ASSOCIATION', fault: 'referenceOrLifecycleInconsistent', phase: 'REFERENCES', result: 'REFERENCE_INCONSISTENT' },
  { negativeClass: 'CANDIDATE_FIELDS_DIFFER_WITHOUT_RECONCILIATION_REQUIRED', fault: 'candidateFieldsDifferWithoutReconciliation', phase: 'REFERENCES', result: 'REFERENCE_INCONSISTENT' },
  { negativeClass: 'RECONCILIATION_REQUIRED_CANDIDATE_MISSING_OR_MISMATCHED', fault: 'candidateManifestKeyMismatch', phase: 'REFERENCES', result: 'REFERENCE_INCONSISTENT' },
  { negativeClass: 'RECONCILIATION_REQUIRED_CANDIDATE_EQUALS_SELECTED', fault: 'candidateEqualsSelectedDuringReconciliation', phase: 'REFERENCES', result: 'REFERENCE_INCONSISTENT' },
  { negativeClass: 'CANDIDATE_MANIFEST_KEY_MISMATCH', fault: 'candidateManifestKeyMismatch', phase: 'REFERENCES', result: 'REFERENCE_INCONSISTENT' },
  { negativeClass: 'CANDIDATE_PARENT_MISMATCH', fault: 'candidateParentMismatch', phase: 'REFERENCES', result: 'REFERENCE_INCONSISTENT' },
  { negativeClass: 'CANDIDATE_MANIFEST_KEY_SCOPE_SESSION_SUBSTITUTION', fault: 'candidateManifestKeyScopeSessionSubstitution', phase: 'RECORD_DECODE', result: 'RECORD_INVALID' },
]);

/** `diagnostics`: the five allowlisted diagnostic members and the ten forbidden ones. */
export const DIAGNOSTIC_ALLOWED = Object.freeze([
  'stageCode', 'reasonCode', 'm2LocatorCount', 'm2ArtifactCount', 'legacyPresent',
]);
export const DIAGNOSTIC_FORBIDDEN = Object.freeze([
  'raw keys', 'nonces', 'plaintext', 'binding bytes', 'context identifiers',
  'session identifiers', 'package references', 'digests', 'record keys', 'escrow content',
]);

/** §3 `buildMatrix` + `unsupportedRuntimeClasses`: the closed build eligibility allowlist. */
export const BUILD_MATRIX = Object.freeze([
  Object.freeze({
    readerProfile: 'CFMT_EXACT_B57DF3A8',
    cFmtDocumentSha256: 'b57df3a8f5dac9cc9f11702fe55d9badf9f98683e3dd7ac03aa81b8fa7932812',
    versions: Object.freeze({
      format: 1, envelope: 1, recordKey: 1, plaintext: 1,
      manifest: 1, keySchedule: 1, upstreamBinding: 0, upstreamMutationTable: 1,
    }),
    openMlsRevision: '09e92777dba0528d3d29e2e5e681b7e91637c7be',
    wasmArtifactPath: 'styx-js/vendor/openmls-wasm/openmls_wasm_bg.wasm',
    wasmArtifactSha256: 'fef05368f143de044274f8804d2ba195a1f886bc528651e98bd9c393fde4650e',
    ss0Ciphersuite: Object.freeze({ ianaId: '0x0001', name: 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519' }),
    ss0GateADecisionsSha256: '235bcb86f9dd25e3c3cb56ed3a0b4820214821cf78ea881547c824db831eba07',
    buildId: 'M2_WEB_CHROMIUM_STANDARD',
    runtimeClass: 'BROWSER_STANDARD_NON_PRIVATE_NON_EVICTED',
    browserClass: 'CHROMIUM',
  }),
  Object.freeze({
    readerProfile: 'CFMT_EXACT_B57DF3A8',
    cFmtDocumentSha256: 'b57df3a8f5dac9cc9f11702fe55d9badf9f98683e3dd7ac03aa81b8fa7932812',
    versions: Object.freeze({
      format: 1, envelope: 1, recordKey: 1, plaintext: 1,
      manifest: 1, keySchedule: 1, upstreamBinding: 0, upstreamMutationTable: 1,
    }),
    openMlsRevision: '09e92777dba0528d3d29e2e5e681b7e91637c7be',
    wasmArtifactPath: 'styx-js/vendor/openmls-wasm/openmls_wasm_bg.wasm',
    wasmArtifactSha256: 'fef05368f143de044274f8804d2ba195a1f886bc528651e98bd9c393fde4650e',
    ss0Ciphersuite: Object.freeze({ ianaId: '0x0001', name: 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519' }),
    ss0GateADecisionsSha256: '235bcb86f9dd25e3c3cb56ed3a0b4820214821cf78ea881547c824db831eba07',
    buildId: 'M2_WEB_FIREFOX_STANDARD',
    runtimeClass: 'BROWSER_STANDARD_NON_PRIVATE_NON_EVICTED',
    browserClass: 'FIREFOX',
  }),
]);

export const UNSUPPORTED_RUNTIME_CLASSES = Object.freeze([
  'MOBILE', 'NATIVE_NON_BROWSER', 'PRIVATE_BROWSING', 'EVICTED_OR_PARTIAL_PROFILE',
]);

/** §2 `compatibilityRegistry.versions`: the closed equality allowlist - never a range. */
export const VERSIONS = Object.freeze({
  format: 1,
  envelope: 1,
  recordKey: 1,
  plaintext: 1,
  manifest: 1,
  keySchedule: 1,
  upstreamBinding: 0,
  upstreamMutationTable: 1,
});

export const ALGORITHMS = Object.freeze({
  recordAead: 'AES-256-GCM',
  nonceBytes: 12,
  tagBytes: 16,
  hash: 'SHA-256',
  mac: 'HMAC-SHA-256',
  kdf: 'HKDF-SHA-256',
  integerEndian: 'big',
});

/** `compatibilityRegistry.valueRegistries`: the closed value sets of the readable profile. */
export const VALUE_REGISTRIES = Object.freeze({
  slotState: Object.freeze({ EMPTY: 1, ISSUANCE_HELD: 2, BOUND: 3, RECONCILIATION_REQUIRED: 4 }),
  keyPackageLifecycle: Object.freeze({ UNCONSUMED: 1, RESERVED: 2, CONSUMED: 3, INVALID: 4 }),
  commitOutcome: Object.freeze({ COMMITTED: 1, NOT_COMMITTED: 2, INDETERMINATE: 3 }),
  apiState: Object.freeze({ EMPTY: 1, ACTIVE: 2, RECONCILIATION_REQUIRED: 3 }),
  selectorState: Object.freeze({ EMPTY: 1, ACTIVE: 2, RECONCILIATION_REQUIRED: 3 }),
  operation: Object.freeze({
    CREATE: 1, RESTORE: 2, JOIN_WELCOME: 3, PROTECT_APPLICATION: 4, OPEN_APPLICATION: 5,
    SELF_UPDATE: 6, APPLY_PEER_UPDATE: 7, RECONCILE_INDETERMINATE: 8,
  }),
  outputKind: Object.freeze({
    NONE: 1, EMBEDDED_TREE_WELCOME: 2, PROTECTED_APPLICATION_BYTES: 3, APPLICATION_BYTES: 4,
    PROTECTED_COMMIT_BYTES: 5, SELECTED_CANDIDATE_REF: 6,
  }),
  bool: Object.freeze({ false: 0, true: 1 }),
});

export const READER_PROFILE = 'CFMT_EXACT_B57DF3A8';
export const CORRUPTION_ACTION = 'PRESERVE_AND_STOP_LOGICAL_READ_DISABLE_ONLY';

/** §9 `automaticActions`: every automatic action is forbidden, and the module honours it. */
export const AUTOMATIC_ACTIONS = Object.freeze({
  rewrite: false,
  normalize: false,
  regenerate: false,
  fallback: false,
  repair: false,
  clearHold: false,
  consumeKeyPackage: false,
  discardEscrow: false,
  automaticReset: false,
});

/** §9 `exposure`: nothing is exposed before EXPOSE, and never these four. */
export const EXPOSURE = Object.freeze({
  beforeEXPOSE: Object.freeze([]),
  atEXPOSE: Object.freeze(['SELECTED_AUTHORITY']),
  never: Object.freeze([
    'UNSELECTED_CANDIDATE_AS_AUTHORITY', 'LEGACY_AS_AUTHORITY', 'PARTIAL_PLAINTEXT',
    'ESCROW_OUTPUT_FROM_RESTORE',
  ]),
});

/** §11 `freshness`: authentication proves consistency, not freshness. */
export const FRESHNESS = Object.freeze({
  authenticatedConsistency: true,
  freshnessClaim: false,
  coherentWholeProfileRollbackDetection: false,
});

/** Closed observation vocabulary. Anything outside these sets is unknown and rejects. */
const LOCK_VALUES = Object.freeze(['HELD', 'UNAVAILABLE']);
const INVENTORY_VALUES = Object.freeze(['NONE', 'LEGACY_ONLY', 'M2']);
const SELECTOR_STATE_VALUES = Object.freeze(['EMPTY', 'ACTIVE', 'RECONCILIATION_REQUIRED']);
const OBSERVATION_KEYS = Object.freeze(['faults', 'inventory', 'legacy', 'vector', 'selectorState']);

const hasOwn = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
const isPlainObject = (value) => value !== null && typeof value === 'object'
  && Object.getPrototypeOf(value) === Object.prototype;
const isString = (value) => typeof value === 'string';
const isBoolean = (value) => typeof value === 'boolean';

const freezeDeep = (value) => {
  if (ArrayBuffer.isView(value)) {
    return value;
  }
  if (Array.isArray(value)) {
    value.forEach(freezeDeep);
  } else if (isPlainObject(value)) {
    Object.values(value).forEach(freezeDeep);
  }
  return Object.freeze(value);
};

const faultRow = (fault) => FAULT_PRECEDENCE.find((row) => row.fault === fault) ?? null;
const faultRank = (fault) => FAULT_PRECEDENCE.findIndex((row) => row.fault === fault);

/** The frozen metadata surface of this module. */
export const M2_RESTORE = Object.freeze({
  READER_PROFILE,
  PHASES,
  INVENTORY_RESULTS,
  SUCCESS_RESULTS,
  FAILURE_RESULTS,
  CONDITIONS,
  FAILURE_DEFAULT,
  SUCCESS_BY_SELECTOR_STATE,
  FAULT_PRECEDENCE,
  NEGATIVE_CLASSES,
  DIAGNOSTIC_ALLOWED,
  DIAGNOSTIC_FORBIDDEN,
  BUILD_MATRIX,
  UNSUPPORTED_RUNTIME_CLASSES,
  VERSIONS,
  ALGORITHMS,
  VALUE_REGISTRIES,
  CORRUPTION_ACTION,
  AUTOMATIC_ACTIONS,
  EXPOSURE,
  FRESHNESS,
});

// --------------------------------------------------------------------------------------------
// Closed registry self-check. The module refuses to expose an inconsistent vocabulary: C-REST
// states the sets are disjoint and total, and every negative class and fixture names a row that
// must exist. A drift here is a rejection, not a warning.
// --------------------------------------------------------------------------------------------
const assertClosedVocabulary = () => {
  const results = new Set([...INVENTORY_RESULTS, ...SUCCESS_RESULTS, ...FAILURE_RESULTS]);
  if (results.size !== INVENTORY_RESULTS.length + SUCCESS_RESULTS.length + FAILURE_RESULTS.length) {
    throw new M2RestoreError(FAILURE_DEFAULT, 'CLASSIFY');
  }
  if (SUCCESS_RESULTS.length !== 3 || FAILURE_RESULTS.length !== 13) {
    throw new M2RestoreError(FAILURE_DEFAULT, 'CLASSIFY');
  }
  if (PHASES.length !== 14 || FAULT_PRECEDENCE.length !== 26 || NEGATIVE_CLASSES.length !== 20) {
    throw new M2RestoreError(FAILURE_DEFAULT, 'CLASSIFY');
  }
  for (const row of FAULT_PRECEDENCE) {
    if (!PHASES.includes(row.phase) || !FAILURE_RESULTS.includes(row.result)) {
      throw new M2RestoreError(FAILURE_DEFAULT, 'CLASSIFY');
    }
  }
  for (const row of NEGATIVE_CLASSES) {
    const precedence = faultRow(row.fault);
    if (precedence === null) {
      throw new M2RestoreError(FAILURE_DEFAULT, 'CLASSIFY');
    }
    if (precedence.phase !== row.phase || precedence.result !== row.result) {
      throw new M2RestoreError(FAILURE_DEFAULT, 'CLASSIFY');
    }
  }
  for (const state of Object.keys(SUCCESS_BY_SELECTOR_STATE)) {
    if (!SELECTOR_STATE_VALUES.includes(state) || !SUCCESS_RESULTS.includes(SUCCESS_BY_SELECTOR_STATE[state])) {
      throw new M2RestoreError(FAILURE_DEFAULT, 'CLASSIFY');
    }
  }
  if (Object.keys(SUCCESS_BY_SELECTOR_STATE).length !== SELECTOR_STATE_VALUES.length) {
    throw new M2RestoreError(FAILURE_DEFAULT, 'CLASSIFY');
  }
};

assertClosedVocabulary();

// --------------------------------------------------------------------------------------------
// Version and pin checks. Equality, never a range. Unknown, future, missing, mixed or downgraded
// versions are UNSUPPORTED_VERSION; any other authenticated profile mismatch is
// INCOMPATIBLE_FORMAT; a store on an ineligible build is INCOMPATIBLE_BUILD.
// --------------------------------------------------------------------------------------------

/**
 * `checkVersions(observed)`: exact equality against the closed eight-version allowlist.
 * Returns `null` when the eight versions are exactly the C-FMT versions, otherwise the closed
 * failure `UNSUPPORTED_VERSION`. A missing, extra, duplicate or non-integer member rejects.
 */
export function checkVersions(observed) {
  if (!isPlainObject(observed)) {
    return 'UNSUPPORTED_VERSION';
  }
  const keys = Object.keys(observed);
  if (keys.length !== Object.keys(VERSIONS).length) {
    return 'UNSUPPORTED_VERSION';
  }
  for (const [name, expected] of Object.entries(VERSIONS)) {
    if (!hasOwn(observed, name) || observed[name] !== expected) {
      return 'UNSUPPORTED_VERSION';
    }
  }
  return null;
}

/**
 * `checkBuildEligibility(build)`: one complete `buildMatrix` row must match by equality. A
 * partial row, an extra member, a missing member, an unlisted runtime class or any drifted pin
 * is not eligible. Returns `true` only for an exact row match.
 */
export function checkBuildEligibility(build) {
  if (!isPlainObject(build)) {
    return false;
  }
  const keys = Object.keys(build).sort().join(',');
  const required = [
    'browserClass', 'buildId', 'cFmtDocumentSha256', 'openMlsRevision', 'readerProfile',
    'runtimeClass', 'ss0Ciphersuite', 'ss0GateADecisionsSha256', 'versions', 'wasmArtifactPath',
    'wasmArtifactSha256',
  ].join(',');
  if (keys !== required) {
    return false;
  }
  for (const row of BUILD_MATRIX) {
    if (build.ss0Ciphersuite !== undefined && (!isPlainObject(build.ss0Ciphersuite)
      || Object.keys(build.ss0Ciphersuite).sort().join(',') !== 'ianaId,name')) {
      return false;
    }
    if (build.readerProfile !== row.readerProfile
      || build.cFmtDocumentSha256 !== row.cFmtDocumentSha256
      || build.openMlsRevision !== row.openMlsRevision
      || build.wasmArtifactPath !== row.wasmArtifactPath
      || build.wasmArtifactSha256 !== row.wasmArtifactSha256
      || build.ss0GateADecisionsSha256 !== row.ss0GateADecisionsSha256
      || build.buildId !== row.buildId
      || build.runtimeClass !== row.runtimeClass
      || build.browserClass !== row.browserClass) {
      continue;
    }
    if (!isPlainObject(build.ss0Ciphersuite)) {
      continue;
    }
    if (build.ss0Ciphersuite.ianaId !== row.ss0Ciphersuite.ianaId
      || build.ss0Ciphersuite.name !== row.ss0Ciphersuite.name) {
      continue;
    }
    if (checkVersions(build.versions) !== null) {
      continue;
    }
    return true;
  }
  return false;
}

// --------------------------------------------------------------------------------------------
// Authenticated compatibility. §4: authenticated version compatibility precedes other profile,
// manifest and record checks; §2: version mismatch is UNSUPPORTED_VERSION, any other profile
// mismatch is INCOMPATIBLE_FORMAT.
// --------------------------------------------------------------------------------------------
export function checkAuthenticatedCompatibility(authenticated) {
  if (!isPlainObject(authenticated) || !isPlainObject(authenticated.versions)) {
    return 'UNSUPPORTED_VERSION';
  }
  if (checkVersions(authenticated.versions) !== null) {
    return 'UNSUPPORTED_VERSION';
  }
  if (!isPlainObject(authenticated.profile)) {
    return 'INCOMPATIBLE_FORMAT';
  }
  const profile = authenticated.profile;
  if (profile.readerProfile !== READER_PROFILE) {
    return 'INCOMPATIBLE_FORMAT';
  }
  if (profile.algorithms !== undefined && isPlainObject(profile.algorithms)) {
    for (const [name, expected] of Object.entries(ALGORITHMS)) {
      if (profile.algorithms[name] !== expected) {
        return 'INCOMPATIBLE_FORMAT';
      }
    }
  }
  return null;
}

// --------------------------------------------------------------------------------------------
// §7 reconciliation candidate and physical parent. The candidate binding digest MUST be checked
// against the candidate generation's own BINDING_PROFILE (I-ROOT ratification 5933193607,
// assigned to this card by the I-WORK ratification 5944375194).
// --------------------------------------------------------------------------------------------

/** Closed candidate facts. `b128eq` compares two 32-byte Uint8Arrays by value. */
const byteEqual = (a, b) => {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
};

/**
 * `validateReconciliationCandidate(facts)`: the complete §7 and `candidateRules` conjunction for
 * a located candidate. Every mismatch is `REFERENCE_INCONSISTENT` except a canonical-key shape or
 * scope/substitution fault, which is `RECORD_INVALID` at `RECORD_DECODE`. The candidate is never
 * authority and this function never selects, retries, releases or repairs anything.
 */
export function validateReconciliationCandidate(facts) {
  if (!isPlainObject(facts) || !isPlainObject(facts.locator) || !isPlainObject(facts.candidate)) {
    throw new M2RestoreError(FAILURE_DEFAULT, 'CLASSIFY');
  }
  const { locator, candidate } = facts;

  // Canonical-kind shape of the candidate manifest key: kind 16, empty object ID.
  if (locator.recordKind !== 16 || locator.objectIdLength !== 0) {
    throw new M2RestoreError('RECORD_INVALID', 'RECORD_DECODE');
  }
  // Scope/session substitution is a decode-time fault, never a reference fault.
  if (locator.scope !== 'CONTEXT_PRESESSION' || locator.secureSessionIdentity !== null) {
    throw new M2RestoreError('RECORD_INVALID', 'RECORD_DECODE');
  }
  // Generation and context of the locator equal the candidate generation and locator context.
  if (locator.generation !== facts.candidateGeneration
    || !byteEqual(locator.localContextId, facts.localContextId)) {
    throw new M2RestoreError('REFERENCE_INCONSISTENT', 'REFERENCES');
  }
  if (!byteEqual(locator.sha256, facts.candidateManifestKeyDigest)) {
    throw new M2RestoreError('REFERENCE_INCONSISTENT', 'REFERENCES');
  }
  // The located candidate manifest's own digests and keyed root must match the selector tuple.
  if (!byteEqual(candidate.manifestCiphertextDigest, facts.manifestCiphertextDigest)) {
    throw new M2RestoreError('REFERENCE_INCONSISTENT', 'REFERENCES');
  }
  if (!byteEqual(candidate.keyedRoot, facts.keyedRoot)) {
    throw new M2RestoreError('REFERENCE_INCONSISTENT', 'REFERENCES');
  }
  // I-ROOT obligation: the candidate binding digest equals that generation's own BINDING_PROFILE.
  if (!byteEqual(candidate.manifestBindingDigest, candidate.bindingProfileDigest)) {
    throw new M2RestoreError('REFERENCE_INCONSISTENT', 'REFERENCES');
  }
  if (!isPlainObject(facts.candidateBindingProfile)
    || !byteEqual(candidate.bindingProfileDigest, facts.candidateBindingProfile.bindingProfileDigest)
    || facts.candidateBindingProfile.generation !== facts.candidateGeneration) {
    throw new M2RestoreError('REFERENCE_INCONSISTENT', 'REFERENCES');
  }
  // A candidate equal to the selected generation is never RECONCILIATION_REQUIRED.
  if (facts.selectorState === 'RECONCILIATION_REQUIRED' && facts.candidateEqualsSelected === true) {
    throw new M2RestoreError('REFERENCE_INCONSISTENT', 'REFERENCES');
  }
  // Candidate fields differing without RECONCILIATION_REQUIRED reject.
  if (facts.candidateEqualsSelected !== true && facts.selectorState !== 'RECONCILIATION_REQUIRED') {
    throw new M2RestoreError('REFERENCE_INCONSISTENT', 'REFERENCES');
  }
  // Unresolved hold: the physical parent is the selector's selected generation and keyed root.
  if (facts.candidate.resultStatus === 'INDETERMINATE') {
    if (facts.selectorState !== 'RECONCILIATION_REQUIRED'
      || candidate.parentGeneration !== facts.selectedGeneration
      || !byteEqual(candidate.parentKeyedRoot, facts.selectedKeyedRoot)) {
      throw new M2RestoreError('REFERENCE_INCONSISTENT', 'REFERENCES');
    }
    // The logical identifiers must match each other, and are never compared to the parent.
    if (!byteEqual(candidate.originalAuthorityDigest, candidate.originalAuthorityReference)) {
      throw new M2RestoreError('REFERENCE_INCONSISTENT', 'REFERENCES');
    }
  }
  return freezeDeep({
    candidateGeneration: facts.candidateGeneration,
    candidateManifestKeyDigest: facts.candidateManifestKeyDigest,
    bindingProfileVerified: true,
    authority: false,
  });
}

// --------------------------------------------------------------------------------------------
// The classifier.
// --------------------------------------------------------------------------------------------

const rejection = (result, stage, diagnostics) => freezeDeep({
  result,
  stage,
  legacyPresent: diagnostics.legacyPresent,
  exposed: false,
  diagnostics,
});

const diagnosticsFor = (observation) => {
  const inventory = observation.inventory;
  return {
    stageCode: null,
    reasonCode: null,
    m2LocatorCount: observation.inventory === 'M2' ? 1 : 0,
    m2ArtifactCount: observation.inventory === 'M2' ? 1 : 0,
    legacyPresent: observation.legacy === true,
  };
};

const validateObservation = (observation) => {
  if (!isPlainObject(observation)) {
    return false;
  }
  const keys = Object.keys(observation);
  if (keys.length !== OBSERVATION_KEYS.length) {
    return false;
  }
  for (const key of OBSERVATION_KEYS) {
    if (!hasOwn(observation, key)) {
      return false;
    }
  }
  if (!Array.isArray(observation.faults) || !observation.faults.every(isString)) {
    return false;
  }
  if (!INVENTORY_VALUES.includes(observation.inventory)) {
    return false;
  }
  if (!isBoolean(observation.legacy)) {
    return false;
  }
  if (observation.vector !== null && !isString(observation.vector)) {
    return false;
  }
  if (!SELECTOR_STATE_VALUES.includes(observation.selectorState)) {
    return false;
  }
  return true;
};

/**
 * `classifyRestore(observation)`: the total, deterministic and fail-closed restore decision.
 *
 * The observation is a closed record with exactly the five members `faults`, `inventory`,
 * `legacy`, `vector` and `selectorState`. The classification follows C-REST exactly:
 *
 * 1. a malformed or non-closed observation is `INTERNAL_VALIDATION_FAILED` at `CLASSIFY`;
 * 2. a non-empty fault set resolves by `faultPrecedence` order - phase order first, then the
 *    unique row for the fault - so physical enumeration order is irrelevant;
 * 3. otherwise `NONE` inventory is `NO_M2_STATE` and `LEGACY_ONLY` is `LEGACY_ONLY`, both at
 *    `INVENTORY`, unauthenticated and exposing nothing;
 * 4. otherwise the authenticated selector state maps through `successBySelectorState`;
 * 5. only a success exposes selected authority, and only at `EXPOSE`.
 */
export function classifyRestore(observation) {
  if (!validateObservation(observation)) {
    return rejection(FAILURE_DEFAULT, 'CLASSIFY', {
      stageCode: 'CLASSIFY',
      reasonCode: FAILURE_DEFAULT,
      m2LocatorCount: 0,
      m2ArtifactCount: 0,
      legacyPresent: false,
    });
  }
  const diagnostics = diagnosticsFor(observation);

  if (observation.faults.length > 0) {
    let chosen = null;
    for (const fault of observation.faults) {
      const rank = faultRank(fault);
      if (rank < 0) {
        return rejection(FAILURE_DEFAULT, 'CLASSIFY', {
          ...diagnostics, stageCode: 'CLASSIFY', reasonCode: FAILURE_DEFAULT,
        });
      }
      if (chosen === null || rank < chosen.rank) {
        chosen = { rank, row: FAULT_PRECEDENCE[rank] };
      }
    }
    return rejection(chosen.row.result, chosen.row.phase, {
      ...diagnostics, stageCode: chosen.row.phase, reasonCode: chosen.row.result,
    });
  }

  if (observation.inventory === 'NONE') {
    if (observation.legacy === true) {
      return rejection(FAILURE_DEFAULT, 'CLASSIFY', {
        ...diagnostics, stageCode: 'CLASSIFY', reasonCode: FAILURE_DEFAULT,
      });
    }
    return rejection('NO_M2_STATE', 'INVENTORY', {
      ...diagnostics, stageCode: 'INVENTORY', reasonCode: 'NO_M2_STATE',
    });
  }

  if (observation.inventory === 'LEGACY_ONLY') {
    if (observation.legacy !== true) {
      return rejection(FAILURE_DEFAULT, 'CLASSIFY', {
        ...diagnostics, stageCode: 'CLASSIFY', reasonCode: FAILURE_DEFAULT,
      });
    }
    return rejection('LEGACY_ONLY', 'INVENTORY', {
      ...diagnostics, stageCode: 'INVENTORY', reasonCode: 'LEGACY_ONLY',
    });
  }

  const result = SUCCESS_BY_SELECTOR_STATE[observation.selectorState];
  if (result === undefined) {
    return rejection(FAILURE_DEFAULT, 'CLASSIFY', {
      ...diagnostics, stageCode: 'CLASSIFY', reasonCode: FAILURE_DEFAULT,
    });
  }
  return freezeDeep({
    result,
    stage: 'EXPOSE',
    legacyPresent: observation.legacy === true,
    exposed: true,
    diagnostics: { ...diagnostics, stageCode: 'EXPOSE', reasonCode: result },
  });
}

// --------------------------------------------------------------------------------------------
// §12 fresh-worker fixture matrix.
// --------------------------------------------------------------------------------------------

const fixture = (id, inventory, vector, legacy, selectorState, faults, result, firstPhase) => ({
  id, inventory, vector, legacy, selectorState, faults, result, firstPhase,
});

const CLEAN = {
  inventory: 'M2', vector: 'FMT-KAT-ACTIVE', legacy: false,
  selectorState: 'ACTIVE', faults: [],
};

/** The 7 positive and 65 negative C-REST fixtures, as executable rows. */
export const FRESH_WORKER_FIXTURES = Object.freeze([
  fixture('POS-NO-M2', 'NONE', null, false, 'EMPTY', [], 'NO_M2_STATE', 'INVENTORY'),
  fixture('POS-LEGACY-ONLY', 'LEGACY_ONLY', null, true, 'EMPTY', [], 'LEGACY_ONLY', 'INVENTORY'),
  fixture('POS-EMPTY', 'M2', 'FMT-KAT-EMPTY', false, 'EMPTY', [], 'RESTORED_EMPTY', 'EXPOSE'),
  fixture('POS-ACTIVE', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', [], 'RESTORED_ACTIVE', 'EXPOSE'),
  fixture('POS-HOLD', 'M2', 'FMT-KAT-HOLD', false, 'RECONCILIATION_REQUIRED', [], 'RESTORED_RECONCILIATION_REQUIRED', 'EXPOSE'),
  fixture('POS-EMPTY-HOLD', 'M2', 'FMT-KAT-EMPTY-HOLD', false, 'RECONCILIATION_REQUIRED', [], 'RESTORED_RECONCILIATION_REQUIRED', 'EXPOSE'),
  fixture('POS-M2-LEGACY-PRESENT', 'M2', 'FMT-KAT-ACTIVE', true, 'ACTIVE', [], 'RESTORED_ACTIVE', 'EXPOSE'),
  fixture('NEG-LOCKUNAVAILABLE', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['lockUnavailable'], 'LOCKED_ELSEWHERE', 'LOCK'),
  fixture('NEG-BUILDNOTLISTED', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['buildNotListed'], 'INCOMPATIBLE_BUILD', 'BUILD_ELIGIBILITY'),
  fixture('NEG-INVENTORYAMBIGUOUS', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['inventoryAmbiguous'], 'INTERNAL_VALIDATION_FAILED', 'INVENTORY'),
  fixture('NEG-WRAPPERWRONGORINVALID', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['wrapperWrongOrInvalid'], 'WRAPPER_AUTH_FAILED', 'WRAPPER_AUTH'),
  fixture('NEG-SELECTORHEADERVERSIONUNKNOWN', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['selectorHeaderVersionUnknown'], 'UNSUPPORTED_VERSION', 'SELECTOR_HEADER'),
  fixture('NEG-SELECTORHEADERSTRUCTUREINCOMPATIBLE', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['selectorHeaderStructureIncompatible'], 'INCOMPATIBLE_FORMAT', 'SELECTOR_HEADER'),
  fixture('NEG-SELECTORMALFORMEDORMULTIPLE', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['selectorMalformedOrMultiple'], 'SELECTOR_INVALID', 'SELECTOR_AUTH'),
  fixture('NEG-SELECTORAUTHENTICATIONFAILED', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['selectorAuthenticationFailed'], 'AUTHENTICATION_FAILED', 'SELECTOR_AUTH'),
  fixture('NEG-AUTHENTICATEDVERSIONUNKNOWNORMIXED', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['authenticatedVersionUnknownOrMixed'], 'UNSUPPORTED_VERSION', 'AUTHENTICATED_COMPATIBILITY'),
  fixture('NEG-AUTHENTICATEDPROFILEINCOMPATIBLE', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['authenticatedProfileIncompatible'], 'INCOMPATIBLE_FORMAT', 'AUTHENTICATED_COMPATIBILITY'),
  fixture('NEG-MANIFESTORROOTMISMATCH', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['manifestOrRootMismatch'], 'MANIFEST_INVALID', 'MANIFEST_ROOT'),
  fixture('NEG-RECORDMISSINGEXTRADUPLICATEREORDERED', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['recordMissingExtraDuplicateReordered'], 'RECORD_SET_INCOMPLETE', 'RECORD_SET'),
  fixture('NEG-PARTIALSELECTEDORCANDIDATEGENERATION', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['partialSelectedOrCandidateGeneration'], 'PARTIAL_GENERATION', 'RECORD_SET'),
  fixture('NEG-RECORDAUTHENTICATIONFAILED', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['recordAuthenticationFailed'], 'AUTHENTICATION_FAILED', 'RECORD_DECODE'),
  fixture('NEG-RECORDCANONICALKEYKINDVERSIONGENERATIONINVALID', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['recordCanonicalKeyKindVersionGenerationInvalid'], 'RECORD_INVALID', 'RECORD_DECODE'),
  fixture('NEG-REFERENCEORLIFECYCLEINCONSISTENT', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['referenceOrLifecycleInconsistent'], 'REFERENCE_INCONSISTENT', 'REFERENCES'),
  fixture('NEG-UNEXPECTEDVALIDATORCONDITION', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['unexpectedValidatorCondition'], 'INTERNAL_VALIDATION_FAILED', 'CLASSIFY'),
  fixture('NEG-UNKNOWN-MIXED-VERSIONS', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['authenticatedVersionUnknownOrMixed'], 'UNSUPPORTED_VERSION', 'AUTHENTICATED_COMPATIBILITY'),
  fixture('NEG-INELIGIBLE-BUILD', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['buildNotListed'], 'INCOMPATIBLE_BUILD', 'BUILD_ELIGIBILITY'),
  fixture('NEG-MALFORMED-SELECTOR', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['selectorMalformedOrMultiple'], 'SELECTOR_INVALID', 'SELECTOR_AUTH'),
  fixture('NEG-SELECTOR-MANIFEST-ROOT-MISMATCH', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['manifestOrRootMismatch'], 'MANIFEST_INVALID', 'MANIFEST_ROOT'),
  fixture('NEG-MISSING-RECORD', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['recordMissingExtraDuplicateReordered'], 'RECORD_SET_INCOMPLETE', 'RECORD_SET'),
  fixture('NEG-EXTRA-RECORD', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['recordMissingExtraDuplicateReordered'], 'RECORD_SET_INCOMPLETE', 'RECORD_SET'),
  fixture('NEG-DUPLICATE-RECORD', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['recordMissingExtraDuplicateReordered'], 'RECORD_SET_INCOMPLETE', 'RECORD_SET'),
  fixture('NEG-REORDERED-RECORD', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['recordMissingExtraDuplicateReordered'], 'RECORD_SET_INCOMPLETE', 'RECORD_SET'),
  fixture('NEG-RECORD-KEY-SUBSTITUTION', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['recordCanonicalKeyKindVersionGenerationInvalid'], 'RECORD_INVALID', 'RECORD_DECODE'),
  fixture('NEG-RECORD-KIND-SUBSTITUTION', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['recordCanonicalKeyKindVersionGenerationInvalid'], 'RECORD_INVALID', 'RECORD_DECODE'),
  fixture('NEG-SELECTED-GENERATION-SUBSTITUTION', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['recordCanonicalKeyKindVersionGenerationInvalid'], 'RECORD_INVALID', 'RECORD_DECODE'),
  fixture('NEG-BAD-TOMBSTONE', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['recordCanonicalKeyKindVersionGenerationInvalid'], 'RECORD_INVALID', 'RECORD_DECODE'),
  fixture('NEG-PARTIAL-CANDIDATE', 'M2', 'FMT-KAT-HOLD', false, 'RECONCILIATION_REQUIRED', ['partialSelectedOrCandidateGeneration'], 'PARTIAL_GENERATION', 'RECORD_SET'),
  fixture('NEG-FORGED-RESULT-ESCROW-HOLD', 'M2', 'FMT-KAT-HOLD', false, 'RECONCILIATION_REQUIRED', ['referenceOrLifecycleInconsistent'], 'REFERENCE_INCONSISTENT', 'REFERENCES'),
  fixture('NEG-INVALID-LIFECYCLE-PAIR', 'M2', 'FMT-KAT-HOLD', false, 'RECONCILIATION_REQUIRED', ['referenceOrLifecycleInconsistent'], 'REFERENCE_INCONSISTENT', 'REFERENCES'),
  fixture('NEG-AMBIGUOUS-INVENTORY', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['inventoryAmbiguous'], 'INTERNAL_VALIDATION_FAILED', 'INVENTORY'),
  fixture('NEG-LEGACY-SHAPED-AT-M2-LOCATOR', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['selectorHeaderStructureIncompatible'], 'INCOMPATIBLE_FORMAT', 'SELECTOR_HEADER'),
  fixture('NEG-LEGACY-CIPHERSUITE-AT-M2-LOCATOR', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['authenticatedProfileIncompatible'], 'INCOMPATIBLE_FORMAT', 'AUTHENTICATED_COMPATIBILITY'),
  fixture('NEG-M2-LEGACY-PRESENT-INVALID', 'M2', 'FMT-KAT-ACTIVE', true, 'ACTIVE', ['manifestOrRootMismatch'], 'MANIFEST_INVALID', 'MANIFEST_ROOT'),
  fixture('NEG-CONCRETE-MULTIPLE-SELECTOR-CANDIDATES', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['multipleSelectorCandidates'], 'SELECTOR_INVALID', 'INVENTORY'),
  fixture('NEG-CONCRETE-ORPHAN-GENERATION', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['orphanGeneration'], 'PARTIAL_GENERATION', 'INVENTORY'),
  fixture('NEG-CONCRETE-KEY-DERIVATION-FAILED', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['keyDerivationFailed'], 'INTERNAL_VALIDATION_FAILED', 'KEY_DERIVATION'),
  fixture('NEG-CONCRETE-CANDIDATE-MANIFEST-KEY-SCOPE-SESSION-SUBSTITUTION', 'M2', 'FMT-KAT-HOLD', false, 'RECONCILIATION_REQUIRED', ['candidateManifestKeyScopeSessionSubstitution'], 'RECORD_INVALID', 'RECORD_DECODE'),
  fixture('NEG-CONCRETE-CANDIDATE-MANIFEST-KEY-MISMATCH', 'M2', 'FMT-KAT-HOLD', false, 'RECONCILIATION_REQUIRED', ['candidateManifestKeyMismatch'], 'REFERENCE_INCONSISTENT', 'REFERENCES'),
  fixture('NEG-CONCRETE-CANDIDATE-PARENT-MISMATCH', 'M2', 'FMT-KAT-HOLD', false, 'RECONCILIATION_REQUIRED', ['candidateParentMismatch'], 'REFERENCE_INCONSISTENT', 'REFERENCES'),
  fixture('NEG-CONCRETE-CANDIDATE-EQUALS-SELECTED-DURING-RECONCILIATION', 'M2', 'FMT-KAT-HOLD', false, 'RECONCILIATION_REQUIRED', ['candidateEqualsSelectedDuringReconciliation'], 'REFERENCE_INCONSISTENT', 'REFERENCES'),
  fixture('NEG-CONCRETE-CANDIDATE-FIELDS-DIFFER-WITHOUT-RECONCILIATION', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['candidateFieldsDifferWithoutReconciliation'], 'REFERENCE_INCONSISTENT', 'REFERENCES'),
  fixture('NEG-CONCRETE-UNEXPECTED-EXPOSE-CONDITION', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['unexpectedExposeCondition'], 'INTERNAL_VALIDATION_FAILED', 'EXPOSE'),
  fixture('NEG-CFMT-UNKNOWN_MISSING_DUPLICATE_REORDERED_JSON_FIELD', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['unexpectedValidatorCondition'], 'INTERNAL_VALIDATION_FAILED', 'CLASSIFY'),
  fixture('NEG-CFMT-UNKNOWN_MISSING_DUPLICATE_REORDERED_PLAINTEXT_FIELD', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['recordCanonicalKeyKindVersionGenerationInvalid'], 'RECORD_INVALID', 'RECORD_DECODE'),
  fixture('NEG-CFMT-UNKNOWN_KIND_VERSION_ALGORITHM_LABEL', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['authenticatedVersionUnknownOrMixed'], 'UNSUPPORTED_VERSION', 'AUTHENTICATED_COMPATIBILITY'),
  fixture('NEG-CFMT-NONCANONICAL_LENGTH_ENDIAN', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['selectorHeaderStructureIncompatible'], 'INCOMPATIBLE_FORMAT', 'SELECTOR_HEADER'),
  fixture('NEG-CFMT-TRUNCATION_TRAILING_SIZE_OVERFLOW', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['selectorHeaderStructureIncompatible'], 'INCOMPATIBLE_FORMAT', 'SELECTOR_HEADER'),
  fixture('NEG-CFMT-NONCE_REUSE', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['recordAuthenticationFailed'], 'AUTHENTICATION_FAILED', 'RECORD_DECODE'),
  fixture('NEG-CFMT-AAD_CONTEXT_SESSION_PROFILE_KIND_VERSION_GENERATION_SUBSTITUTION', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['recordAuthenticationFailed'], 'AUTHENTICATION_FAILED', 'RECORD_DECODE'),
  fixture('NEG-CFMT-KEY_OR_LABEL_COLLISION', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['authenticatedProfileIncompatible'], 'INCOMPATIBLE_FORMAT', 'AUTHENTICATED_COMPATIBILITY'),
  fixture('NEG-CFMT-CROSS_DOMAIN_COPY', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['recordAuthenticationFailed'], 'AUTHENTICATION_FAILED', 'RECORD_DECODE'),
  fixture('NEG-CFMT-MANIFEST_OMISSION_ADDITION_DUPLICATE_REORDER', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['manifestOrRootMismatch'], 'MANIFEST_INVALID', 'MANIFEST_ROOT'),
  fixture('NEG-CFMT-ROOT_OR_SELECTOR_MISMATCH', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['manifestOrRootMismatch'], 'MANIFEST_INVALID', 'MANIFEST_ROOT'),
  fixture('NEG-CFMT-HISTORICAL_SUBSET_UNDER_CURRENT_ROOT', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['manifestOrRootMismatch'], 'MANIFEST_INVALID', 'MANIFEST_ROOT'),
  fixture('NEG-CFMT-PARTIAL_GENERATION', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['partialSelectedOrCandidateGeneration'], 'PARTIAL_GENERATION', 'RECORD_SET'),
  fixture('NEG-CFMT-FORGED_RESULT_ESCROW_ASSOCIATION', 'M2', 'FMT-KAT-HOLD', false, 'RECONCILIATION_REQUIRED', ['referenceOrLifecycleInconsistent'], 'REFERENCE_INCONSISTENT', 'REFERENCES'),
  fixture('NEG-CFMT-CANDIDATE_FIELDS_DIFFER_WITHOUT_RECONCILIATION_REQUIRED', 'M2', 'FMT-KAT-ACTIVE', false, 'ACTIVE', ['candidateFieldsDifferWithoutReconciliation'], 'REFERENCE_INCONSISTENT', 'REFERENCES'),
  fixture('NEG-CFMT-RECONCILIATION_REQUIRED_CANDIDATE_MISSING_OR_MISMATCHED', 'M2', 'FMT-KAT-HOLD', false, 'RECONCILIATION_REQUIRED', ['candidateManifestKeyMismatch'], 'REFERENCE_INCONSISTENT', 'REFERENCES'),
  fixture('NEG-CFMT-RECONCILIATION_REQUIRED_CANDIDATE_EQUALS_SELECTED', 'M2', 'FMT-KAT-HOLD', false, 'RECONCILIATION_REQUIRED', ['candidateEqualsSelectedDuringReconciliation'], 'REFERENCE_INCONSISTENT', 'REFERENCES'),
  fixture('NEG-CFMT-CANDIDATE_MANIFEST_KEY_MISMATCH', 'M2', 'FMT-KAT-HOLD', false, 'RECONCILIATION_REQUIRED', ['candidateManifestKeyMismatch'], 'REFERENCE_INCONSISTENT', 'REFERENCES'),
  fixture('NEG-CFMT-CANDIDATE_PARENT_MISMATCH', 'M2', 'FMT-KAT-HOLD', false, 'RECONCILIATION_REQUIRED', ['candidateParentMismatch'], 'REFERENCE_INCONSISTENT', 'REFERENCES'),
  fixture('NEG-CFMT-CANDIDATE_MANIFEST_KEY_SCOPE_SESSION_SUBSTITUTION', 'M2', 'FMT-KAT-HOLD', false, 'RECONCILIATION_REQUIRED', ['candidateManifestKeyScopeSessionSubstitution'], 'RECORD_INVALID', 'RECORD_DECODE'),
]);

/**
 * `runFreshWorkerFixtureMatrix()`: classify every C-REST fixture through the real classifier on
 * a fresh worker observation and return one frozen row per fixture with the typed outcome.
 */
export function runFreshWorkerFixtureMatrix() {
  return freezeDeep(FRESH_WORKER_FIXTURES.map((row) => {
    const observation = {
      faults: row.faults.slice(),
      inventory: row.inventory,
      legacy: row.legacy,
      vector: row.vector,
      selectorState: row.selectorState,
    };
    const outcome = classifyRestore(observation);
    return {
      id: row.id,
      expectedResult: row.result,
      expectedPhase: row.firstPhase,
      result: outcome.result,
      stage: outcome.stage,
      legacyPresent: outcome.legacyPresent,
      exposed: outcome.exposed,
      ok: outcome.result === row.result && outcome.stage === row.firstPhase,
    };
  }));
}

export { CLEAN as CLEAN_OBSERVATION };
