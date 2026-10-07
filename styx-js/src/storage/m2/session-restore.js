// M2 fail-closed restore/version decision over an injected observation record.
// Internal-only: no barrel export.
//
// This module is the executable form of the ratified C-REST contract
// (`docs/architecture/m2/restore-compatibility.md` at commit bc3b01f2411615c40a177a913de11dba72c4a8eb,
// SHA-256 ccbdd3ceb94c0c32c081757bbf6f0d19a84b5c45933f94115c58500e70854c9f): the ordered
// fourteen-phase restore decision, the closed result vocabulary, the twenty-six fault-precedence rows,
// the seventy-seven fixtures, the eight-version allowlist, the two build-matrix rows and the §7
// reconciliation-candidate rules. It performs no I/O, storage, worker, browser, crypto, lock, network,
// migration, retention, recovery or UI behaviour, and it exposes no restore implementation.
//
// Two properties are load-bearing and are enforced structurally rather than by convention:
//
// 1. **Closure.** Every accepted input is checked against an exact member set with `Reflect.ownKeys`,
//    so an extra enumerable member, an extra non-enumerable member, a symbol-keyed member and an
//    accessor member all reject. Every accepted value is drawn from a closed set, and every rejection
//    is a C-REST failure code at a C-REST phase.
// 2. **Totality.** `classifyRestore` never throws and never returns a value outside the closed sets: an
//    unexpected input resolves to `INTERNAL_VALIDATION_FAILED` at `CLASSIFY`, the C-REST failure
//    default. The exported registries are deep-frozen so the decision table cannot be edited through
//    the module's own surface.
//
// The observation is the card's own closed record of fresh-worker evidence: `faults`, `inventory`,
// `legacy`, `vector` and `selectorState`. It carries no caller-supplied result, no caller-supplied
// count and no caller-supplied verdict, so nothing here echoes authority back to the caller.

// The observation is the card's own closed record of fresh-worker evidence.

// ------------------------------------------------------------------------------------------------
// Closed vocabulary, exactly the ratified C-REST record.
// ------------------------------------------------------------------------------------------------

//
// §4/§9/§10 closed sets. The phases are the `phaseOrder`; the inventory set is the card's fresh-worker
// store classification (`NONE` and `LEGACY_ONLY` are the two C-REST inventory results, and `M2` names a
// store whose fixed locator and generation artifacts are present); the successes, failures and the
// single condition are `resultSets`; the selector states are `successBySelectorState`; the failure
// default is `failureDefault`.
//

/**
 * The fourteen C-REST phases, in `phaseOrder`.
 */
export const PHASES = deepFreeze([
  'LOCK', 'BUILD_ELIGIBILITY', 'INVENTORY', 'WRAPPER_AUTH', 'KEY_DERIVATION', 'SELECTOR_HEADER',
  'SELECTOR_AUTH', 'AUTHENTICATED_COMPATIBILITY', 'MANIFEST_ROOT', 'RECORD_SET', 'RECORD_DECODE',
  'REFERENCES', 'CLASSIFY', 'EXPOSE',
]);

/**
 * The observed store classification. `NONE` and `LEGACY_ONLY` are C-REST inventory results; `M2` names
 * a store whose fixed locator and generation artifacts are present.
 */
const OBSERVED_INVENTORY = deepFreeze(['NONE', 'LEGACY_ONLY', 'M2']);

/**
 * The two C-REST inventory results (results, not store classifications).
 */
export const INVENTORY_RESULTS = deepFreeze(['NO_M2_STATE', 'LEGACY_ONLY']);

/**
 * The three C-REST successes.
 */
export const SUCCESS_RESULTS = deepFreeze([
  'RESTORED_EMPTY', 'RESTORED_ACTIVE', 'RESTORED_RECONCILIATION_REQUIRED',
]);

/**
 * The thirteen C-REST failures.
 */
export const FAILURE_RESULTS = deepFreeze([
  'LOCKED_ELSEWHERE', 'WRAPPER_AUTH_FAILED', 'INCOMPATIBLE_BUILD', 'INCOMPATIBLE_FORMAT',
  'UNSUPPORTED_VERSION', 'SELECTOR_INVALID', 'AUTHENTICATION_FAILED', 'MANIFEST_INVALID',
  'RECORD_SET_INCOMPLETE', 'RECORD_INVALID', 'REFERENCE_INCONSISTENT', 'PARTIAL_GENERATION',
  'INTERNAL_VALIDATION_FAILED',
]);

/**
 * The single C-REST condition. A condition is never itself a result.
 */
export const CONDITIONS = deepFreeze(['LEGACY_PRESENT']);

/**
 * The C-REST failure default.
 */
export const FAILURE_DEFAULT = 'INTERNAL_VALIDATION_FAILED';

/**
 * The authenticated selector state maps to exactly one success.
 */
export const SUCCESS_BY_SELECTOR_STATE = deepFreeze({
  EMPTY: 'RESTORED_EMPTY',
  ACTIVE: 'RESTORED_ACTIVE',
  RECONCILIATION_REQUIRED: 'RESTORED_RECONCILIATION_REQUIRED',
});

/**
 * The twenty-six `faultPrecedence` rows, in the record's order (phase order first).
 */
export const FAULT_PRECEDENCE = deepFreeze([
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
  {
    fault: 'authenticatedVersionUnknownOrMixed',
    phase: 'AUTHENTICATED_COMPATIBILITY',
    result: 'UNSUPPORTED_VERSION',
  },
  {
    fault: 'authenticatedProfileIncompatible',
    phase: 'AUTHENTICATED_COMPATIBILITY',
    result: 'INCOMPATIBLE_FORMAT',
  },
  { fault: 'manifestOrRootMismatch', phase: 'MANIFEST_ROOT', result: 'MANIFEST_INVALID' },
  {
    fault: 'recordMissingExtraDuplicateReordered',
    phase: 'RECORD_SET',
    result: 'RECORD_SET_INCOMPLETE',
  },
  { fault: 'partialSelectedOrCandidateGeneration', phase: 'RECORD_SET', result: 'PARTIAL_GENERATION' },
  { fault: 'recordAuthenticationFailed', phase: 'RECORD_DECODE', result: 'AUTHENTICATION_FAILED' },
  {
    fault: 'recordCanonicalKeyKindVersionGenerationInvalid',
    phase: 'RECORD_DECODE',
    result: 'RECORD_INVALID',
  },
  {
    fault: 'candidateManifestKeyScopeSessionSubstitution',
    phase: 'RECORD_DECODE',
    result: 'RECORD_INVALID',
  },
  { fault: 'referenceOrLifecycleInconsistent', phase: 'REFERENCES', result: 'REFERENCE_INCONSISTENT' },
  { fault: 'candidateManifestKeyMismatch', phase: 'REFERENCES', result: 'REFERENCE_INCONSISTENT' },
  { fault: 'candidateParentMismatch', phase: 'REFERENCES', result: 'REFERENCE_INCONSISTENT' },
  {
    fault: 'candidateEqualsSelectedDuringReconciliation',
    phase: 'REFERENCES',
    result: 'REFERENCE_INCONSISTENT',
  },
  {
    fault: 'candidateFieldsDifferWithoutReconciliation',
    phase: 'REFERENCES',
    result: 'REFERENCE_INCONSISTENT',
  },
  { fault: 'unexpectedValidatorCondition', phase: 'CLASSIFY', result: 'INTERNAL_VALIDATION_FAILED' },
  { fault: 'unexpectedExposeCondition', phase: 'EXPOSE', result: 'INTERNAL_VALIDATION_FAILED' },
]);

const FAULT_RANK = new Map(FAULT_PRECEDENCE.map((row, index) => [row.fault, index]));
const FAULT_ROW = new Map(FAULT_PRECEDENCE.map((row) => [row.fault, row]));
const phaseIndexOf = (phase) => PHASES.indexOf(phase);
const INVENTORY_PHASE_INDEX = phaseIndexOf('INVENTORY');

/**
 * The twenty-five `negativeClassMap` rows, in the record's order.
 */
export const NEGATIVE_CLASSES = deepFreeze([
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
  { negativeClass: 'HOLD_LOCATOR_DERIVATION_MISMATCH', fault: 'candidateManifestKeyMismatch', phase: 'REFERENCES', result: 'REFERENCE_INCONSISTENT' },
  { negativeClass: 'HOLD_LOCATOR_SCOPE_SESSION_SUBSTITUTION', fault: 'candidateManifestKeyScopeSessionSubstitution', phase: 'RECORD_DECODE', result: 'RECORD_INVALID' },
  { negativeClass: 'HOLD_LOCATOR_ON_NON_CANDIDATE_HOLD', fault: 'referenceOrLifecycleInconsistent', phase: 'REFERENCES', result: 'REFERENCE_INCONSISTENT' },
  { negativeClass: 'HOLD_LOCATOR_GENERATION_MISMATCH', fault: 'candidateManifestKeyMismatch', phase: 'REFERENCES', result: 'REFERENCE_INCONSISTENT' },
  { negativeClass: 'UNBOUND_CANDIDATE_GENERATION_REUSE', fault: 'referenceOrLifecycleInconsistent', phase: 'REFERENCES', result: 'REFERENCE_INCONSISTENT' },
]);

/**
 * §9 `diagnostics.allowed`.
 */
export const DIAGNOSTIC_ALLOWED = deepFreeze([
  'stageCode', 'reasonCode', 'm2LocatorCount', 'm2ArtifactCount', 'legacyPresent',
]);

/**
 * §9 `diagnostics.forbidden`.
 */
export const DIAGNOSTIC_FORBIDDEN = deepFreeze([
  'raw keys', 'nonces', 'plaintext', 'binding bytes', 'context identifiers', 'session identifiers',
  'package references', 'digests', 'record keys', 'escrow content',
]);

/**
 * §3 `buildMatrix`: both rows are complete; no flag or partial row widens the matrix.
 */
export const BUILD_MATRIX = deepFreeze([
  {
    readerProfile: 'CFMT_EXACT_9DACE4A0',
    cFmtDocumentSha256: '9dace4a0182c5694857cc1e8efb59257f3e4b276e8c62846d2d329626e8c963b',
    versions: {
      format: 1, envelope: 1, recordKey: 1, plaintext: 1, manifest: 1, keySchedule: 1,
      upstreamBinding: 0, upstreamMutationTable: 1,
    },
    openMlsRevision: '09e92777dba0528d3d29e2e5e681b7e91637c7be',
    wasmArtifactPath: 'styx-js/vendor/openmls-wasm/openmls_wasm_bg.wasm',
    wasmArtifactSha256: 'fef05368f143de044274f8804d2ba195a1f886bc528651e98bd9c393fde4650e',
    ss0Ciphersuite: { ianaId: '0x0001', name: 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519' },
    ss0GateADecisionsSha256: '235bcb86f9dd25e3c3cb56ed3a0b4820214821cf78ea881547c824db831eba07',
    buildId: 'M2_WEB_CHROMIUM_STANDARD',
    runtimeClass: 'BROWSER_STANDARD_NON_PRIVATE_NON_EVICTED',
    browserClass: 'CHROMIUM',
  },
  {
    readerProfile: 'CFMT_EXACT_9DACE4A0',
    cFmtDocumentSha256: '9dace4a0182c5694857cc1e8efb59257f3e4b276e8c62846d2d329626e8c963b',
    versions: {
      format: 1, envelope: 1, recordKey: 1, plaintext: 1, manifest: 1, keySchedule: 1,
      upstreamBinding: 0, upstreamMutationTable: 1,
    },
    openMlsRevision: '09e92777dba0528d3d29e2e5e681b7e91637c7be',
    wasmArtifactPath: 'styx-js/vendor/openmls-wasm/openmls_wasm_bg.wasm',
    wasmArtifactSha256: 'fef05368f143de044274f8804d2ba195a1f886bc528651e98bd9c393fde4650e',
    ss0Ciphersuite: { ianaId: '0x0001', name: 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519' },
    ss0GateADecisionsSha256: '235bcb86f9dd25e3c3cb56ed3a0b4820214821cf78ea881547c824db831eba07',
    buildId: 'M2_WEB_FIREFOX_STANDARD',
    runtimeClass: 'BROWSER_STANDARD_NON_PRIVATE_NON_EVICTED',
    browserClass: 'FIREFOX',
  },
]);

/**
 * §2 `unsupportedRuntimeClasses`.
 */
export const UNSUPPORTED_RUNTIME_CLASSES = deepFreeze([
  'MOBILE', 'NATIVE_NON_BROWSER', 'PRIVATE_BROWSING', 'EVICTED_OR_PARTIAL_PROFILE',
]);

/**
 * §2 `versions`, the closed eight-member allowlist.
 */
export const VERSIONS = deepFreeze({
  format: 1, envelope: 1, recordKey: 1, plaintext: 1, manifest: 1, keySchedule: 1,
  upstreamBinding: 0, upstreamMutationTable: 1,
});

/**
 * §2 `algorithms`.
 */
export const ALGORITHMS = deepFreeze({
  recordAead: 'AES-256-GCM', nonceBytes: 12, tagBytes: 16, hash: 'SHA-256', mac: 'HMAC-SHA-256',
  kdf: 'HKDF-SHA-256', integerEndian: 'big',
});

const VERSION_KEYS = Object.freeze(Object.keys(VERSIONS));
const ALGORITHM_KEYS = Object.freeze(Object.keys(ALGORITHMS));
const BUILD_ROW_KEYS = Object.freeze(Object.keys(BUILD_MATRIX[0]));

/**
 * §3 `readerProfile`.
 */
export const READER_PROFILE = 'CFMT_EXACT_9DACE4A0';

/**
 * §9 `corruptionAction`.
 */
export const CORRUPTION_ACTION = 'PRESERVE_AND_STOP_LOGICAL_READ_DISABLE_ONLY';

/**
 * §9 `automaticActions`: every one is `false`.
 */
export const AUTOMATIC_ACTIONS = deepFreeze({
  rewrite: false, normalize: false, regenerate: false, fallback: false, repair: false, clearHold: false,
  consumeKeyPackage: false, discardEscrow: false, automaticReset: false,
});

/**
 * §9 `exposure`.
 */
export const EXPOSURE = deepFreeze({
  beforeEXPOSE: [],
  atEXPOSE: ['SELECTED_AUTHORITY'],
  never: [
    'UNSELECTED_CANDIDATE_AS_AUTHORITY', 'LEGACY_AS_AUTHORITY', 'PARTIAL_PLAINTEXT',
    'ESCROW_OUTPUT_FROM_RESTORE',
  ],
});

/**
 * §11 `freshness`.
 */
export const FRESHNESS = deepFreeze({
  authenticatedConsistency: true,
  freshnessClaim: false,
  coherentWholeProfileRollbackDetection: false,
  statement: 'A coherent replay of a complete same-key browser profile, including wrapper, selector, '
    + 'and anchors, can restore successfully and may be undetectable.',
});

/**
 * The vector values carried by the ratified fixtures, and the slot state each one names in the
 * record's `compatibilityRegistry.vectorIdentities`. A vector always describes exactly one state, so
 * a store whose vector and authenticated selector state disagree is contradictory evidence.
 */
const VECTOR_STATES = deepFreeze({
  'FMT-KAT-EMPTY': 'EMPTY',
  'FMT-KAT-ACTIVE': 'ACTIVE',
  'FMT-KAT-HOLD': 'RECONCILIATION_REQUIRED',
  'FMT-KAT-EMPTY-HOLD': 'RECONCILIATION_REQUIRED',
});

const VECTOR_ALLOWLIST = deepFreeze(Object.keys(VECTOR_STATES));

const OBSERVATION_KEYS = deepFreeze(['faults', 'inventory', 'legacy', 'vector', 'selectorState']);
const SELECTOR_STATES = Object.freeze(Object.keys(SUCCESS_BY_SELECTOR_STATE));
const RECORD_SCOPES = deepFreeze(['CONTEXT_PRESESSION', 'SESSION']);
const RESULT_STATUSES = deepFreeze(['COMMITTED', 'NOT_COMMITTED', 'INDETERMINATE']);

const C_REST_FIXTURES = deepFreeze(Object.assign(Object.create(null), {
  positive: [
    { "id": "POS-NO-M2", "inventory": "NONE", "vector": null, "legacy": false, "result": "NO_M2_STATE", "firstPhase": "INVENTORY", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [] },
    { "id": "POS-LEGACY-ONLY", "inventory": "LEGACY_ONLY", "vector": null, "legacy": true, "result": "LEGACY_ONLY", "firstPhase": "INVENTORY", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "legacy", "kind": "LEGACY_ENVELOPE" }] },
    { "id": "POS-EMPTY", "inventory": "M2", "vector": "FMT-KAT-EMPTY", "legacy": false, "result": "RESTORED_EMPTY", "firstPhase": "EXPOSE", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "POS-ACTIVE", "inventory": "M2", "vector": "FMT-KAT-ACTIVE", "legacy": false, "result": "RESTORED_ACTIVE", "firstPhase": "EXPOSE", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "POS-HOLD", "inventory": "M2", "vector": "FMT-KAT-HOLD", "legacy": false, "result": "RESTORED_RECONCILIATION_REQUIRED", "firstPhase": "EXPOSE", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "POS-EMPTY-HOLD", "inventory": "M2", "vector": "FMT-KAT-EMPTY-HOLD", "legacy": false, "result": "RESTORED_RECONCILIATION_REQUIRED", "firstPhase": "EXPOSE", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "POS-M2-LEGACY-PRESENT", "inventory": "M2", "vector": "FMT-KAT-ACTIVE", "legacy": true, "condition": "LEGACY_PRESENT", "result": "RESTORED_ACTIVE", "firstPhase": "EXPOSE", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }, { "id": "legacy", "kind": "LEGACY_ENVELOPE" }] },
  ],
  negative: [
    { "id": "NEG-LOCKUNAVAILABLE", "faults": ["lockUnavailable"], "result": "LOCKED_ELSEWHERE", "firstPhase": "LOCK", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-BUILDNOTLISTED", "faults": ["buildNotListed"], "result": "INCOMPATIBLE_BUILD", "firstPhase": "BUILD_ELIGIBILITY", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-INVENTORYAMBIGUOUS", "faults": ["inventoryAmbiguous"], "result": "INTERNAL_VALIDATION_FAILED", "firstPhase": "INVENTORY", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-WRAPPERWRONGORINVALID", "faults": ["wrapperWrongOrInvalid"], "result": "WRAPPER_AUTH_FAILED", "firstPhase": "WRAPPER_AUTH", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-SELECTORHEADERVERSIONUNKNOWN", "faults": ["selectorHeaderVersionUnknown"], "result": "UNSUPPORTED_VERSION", "firstPhase": "SELECTOR_HEADER", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-SELECTORHEADERSTRUCTUREINCOMPATIBLE", "faults": ["selectorHeaderStructureIncompatible"], "result": "INCOMPATIBLE_FORMAT", "firstPhase": "SELECTOR_HEADER", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-SELECTORMALFORMEDORMULTIPLE", "faults": ["selectorMalformedOrMultiple"], "result": "SELECTOR_INVALID", "firstPhase": "SELECTOR_AUTH", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-SELECTORAUTHENTICATIONFAILED", "faults": ["selectorAuthenticationFailed"], "result": "AUTHENTICATION_FAILED", "firstPhase": "SELECTOR_AUTH", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-AUTHENTICATEDVERSIONUNKNOWNORMIXED", "faults": ["authenticatedVersionUnknownOrMixed"], "result": "UNSUPPORTED_VERSION", "firstPhase": "AUTHENTICATED_COMPATIBILITY", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-AUTHENTICATEDPROFILEINCOMPATIBLE", "faults": ["authenticatedProfileIncompatible"], "result": "INCOMPATIBLE_FORMAT", "firstPhase": "AUTHENTICATED_COMPATIBILITY", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-MANIFESTORROOTMISMATCH", "faults": ["manifestOrRootMismatch"], "result": "MANIFEST_INVALID", "firstPhase": "MANIFEST_ROOT", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-RECORDMISSINGEXTRADUPLICATEREORDERED", "faults": ["recordMissingExtraDuplicateReordered"], "result": "RECORD_SET_INCOMPLETE", "firstPhase": "RECORD_SET", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-PARTIALSELECTEDORCANDIDATEGENERATION", "faults": ["partialSelectedOrCandidateGeneration"], "result": "PARTIAL_GENERATION", "firstPhase": "RECORD_SET", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-RECORDAUTHENTICATIONFAILED", "faults": ["recordAuthenticationFailed"], "result": "AUTHENTICATION_FAILED", "firstPhase": "RECORD_DECODE", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-RECORDCANONICALKEYKINDVERSIONGENERATIONINVALID", "faults": ["recordCanonicalKeyKindVersionGenerationInvalid"], "result": "RECORD_INVALID", "firstPhase": "RECORD_DECODE", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-REFERENCEORLIFECYCLEINCONSISTENT", "faults": ["referenceOrLifecycleInconsistent"], "result": "REFERENCE_INCONSISTENT", "firstPhase": "REFERENCES", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-UNEXPECTEDVALIDATORCONDITION", "faults": ["unexpectedValidatorCondition"], "result": "INTERNAL_VALIDATION_FAILED", "firstPhase": "CLASSIFY", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-UNKNOWN-MIXED-VERSIONS", "faults": ["authenticatedVersionUnknownOrMixed"], "result": "UNSUPPORTED_VERSION", "firstPhase": "AUTHENTICATED_COMPATIBILITY", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-INELIGIBLE-BUILD", "faults": ["buildNotListed"], "result": "INCOMPATIBLE_BUILD", "firstPhase": "BUILD_ELIGIBILITY", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-MALFORMED-SELECTOR", "faults": ["selectorMalformedOrMultiple"], "result": "SELECTOR_INVALID", "firstPhase": "SELECTOR_AUTH", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-SELECTOR-MANIFEST-ROOT-MISMATCH", "faults": ["manifestOrRootMismatch"], "result": "MANIFEST_INVALID", "firstPhase": "MANIFEST_ROOT", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-MISSING-RECORD", "faults": ["recordMissingExtraDuplicateReordered"], "result": "RECORD_SET_INCOMPLETE", "firstPhase": "RECORD_SET", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-EXTRA-RECORD", "faults": ["recordMissingExtraDuplicateReordered"], "result": "RECORD_SET_INCOMPLETE", "firstPhase": "RECORD_SET", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-DUPLICATE-RECORD", "faults": ["recordMissingExtraDuplicateReordered"], "result": "RECORD_SET_INCOMPLETE", "firstPhase": "RECORD_SET", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-REORDERED-RECORD", "faults": ["recordMissingExtraDuplicateReordered"], "result": "RECORD_SET_INCOMPLETE", "firstPhase": "RECORD_SET", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-RECORD-KEY-SUBSTITUTION", "faults": ["recordCanonicalKeyKindVersionGenerationInvalid"], "result": "RECORD_INVALID", "firstPhase": "RECORD_DECODE", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-RECORD-KIND-SUBSTITUTION", "faults": ["recordCanonicalKeyKindVersionGenerationInvalid"], "result": "RECORD_INVALID", "firstPhase": "RECORD_DECODE", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-SELECTED-GENERATION-SUBSTITUTION", "faults": ["recordCanonicalKeyKindVersionGenerationInvalid"], "result": "RECORD_INVALID", "firstPhase": "RECORD_DECODE", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-BAD-TOMBSTONE", "faults": ["recordCanonicalKeyKindVersionGenerationInvalid"], "result": "RECORD_INVALID", "firstPhase": "RECORD_DECODE", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-PARTIAL-CANDIDATE", "faults": ["partialSelectedOrCandidateGeneration"], "result": "PARTIAL_GENERATION", "firstPhase": "RECORD_SET", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-FORGED-RESULT-ESCROW-HOLD", "faults": ["referenceOrLifecycleInconsistent"], "result": "REFERENCE_INCONSISTENT", "firstPhase": "REFERENCES", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-INVALID-LIFECYCLE-PAIR", "faults": ["referenceOrLifecycleInconsistent"], "result": "REFERENCE_INCONSISTENT", "firstPhase": "REFERENCES", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-AMBIGUOUS-INVENTORY", "faults": ["inventoryAmbiguous"], "result": "INTERNAL_VALIDATION_FAILED", "firstPhase": "INVENTORY", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-LEGACY-SHAPED-AT-M2-LOCATOR", "faults": ["selectorHeaderStructureIncompatible"], "result": "INCOMPATIBLE_FORMAT", "firstPhase": "SELECTOR_HEADER", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-LEGACY-CIPHERSUITE-AT-M2-LOCATOR", "faults": ["authenticatedProfileIncompatible"], "result": "INCOMPATIBLE_FORMAT", "firstPhase": "AUTHENTICATED_COMPATIBILITY", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-M2-LEGACY-PRESENT-INVALID", "inventory": "M2", "vector": "FMT-KAT-ACTIVE", "legacy": true, "faults": ["manifestOrRootMismatch"], "condition": "LEGACY_PRESENT", "result": "MANIFEST_INVALID", "firstPhase": "MANIFEST_ROOT", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }, { "id": "legacy", "kind": "LEGACY_ENVELOPE" }] },
    { "id": "NEG-CONCRETE-MULTIPLE-SELECTOR-CANDIDATES", "inventory": "M2", "vector": "FMT-KAT-ACTIVE", "legacy": false, "faults": ["multipleSelectorCandidates"], "result": "SELECTOR_INVALID", "firstPhase": "INVENTORY", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-CONCRETE-ORPHAN-GENERATION", "inventory": "M2", "vector": "FMT-KAT-ACTIVE", "legacy": false, "faults": ["orphanGeneration"], "result": "PARTIAL_GENERATION", "firstPhase": "INVENTORY", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-CONCRETE-KEY-DERIVATION-FAILED", "inventory": "M2", "vector": "FMT-KAT-ACTIVE", "legacy": false, "faults": ["keyDerivationFailed"], "result": "INTERNAL_VALIDATION_FAILED", "firstPhase": "KEY_DERIVATION", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-CONCRETE-CANDIDATE-MANIFEST-KEY-SCOPE-SESSION-SUBSTITUTION", "inventory": "M2", "vector": "FMT-KAT-ACTIVE", "legacy": false, "faults": ["candidateManifestKeyScopeSessionSubstitution"], "result": "RECORD_INVALID", "firstPhase": "RECORD_DECODE", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-CONCRETE-CANDIDATE-MANIFEST-KEY-MISMATCH", "inventory": "M2", "vector": "FMT-KAT-ACTIVE", "legacy": false, "faults": ["candidateManifestKeyMismatch"], "result": "REFERENCE_INCONSISTENT", "firstPhase": "REFERENCES", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-CONCRETE-CANDIDATE-PARENT-MISMATCH", "inventory": "M2", "vector": "FMT-KAT-ACTIVE", "legacy": false, "faults": ["candidateParentMismatch"], "result": "REFERENCE_INCONSISTENT", "firstPhase": "REFERENCES", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-CONCRETE-CANDIDATE-EQUALS-SELECTED-DURING-RECONCILIATION", "inventory": "M2", "vector": "FMT-KAT-ACTIVE", "legacy": false, "faults": ["candidateEqualsSelectedDuringReconciliation"], "result": "REFERENCE_INCONSISTENT", "firstPhase": "REFERENCES", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-CONCRETE-CANDIDATE-FIELDS-DIFFER-WITHOUT-RECONCILIATION", "inventory": "M2", "vector": "FMT-KAT-ACTIVE", "legacy": false, "faults": ["candidateFieldsDifferWithoutReconciliation"], "result": "REFERENCE_INCONSISTENT", "firstPhase": "REFERENCES", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-CONCRETE-UNEXPECTED-EXPOSE-CONDITION", "inventory": "M2", "vector": "FMT-KAT-ACTIVE", "legacy": false, "faults": ["unexpectedExposeCondition"], "result": "INTERNAL_VALIDATION_FAILED", "firstPhase": "EXPOSE", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-CFMT-UNKNOWN_MISSING_DUPLICATE_REORDERED_JSON_FIELD", "inventory": "M2", "vector": "FMT-KAT-ACTIVE", "legacy": false, "faults": ["unexpectedValidatorCondition"], "negativeClass": "UNKNOWN_MISSING_DUPLICATE_REORDERED_JSON_FIELD", "result": "INTERNAL_VALIDATION_FAILED", "firstPhase": "CLASSIFY", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-CFMT-UNKNOWN_MISSING_DUPLICATE_REORDERED_PLAINTEXT_FIELD", "inventory": "M2", "vector": "FMT-KAT-ACTIVE", "legacy": false, "faults": ["recordCanonicalKeyKindVersionGenerationInvalid"], "negativeClass": "UNKNOWN_MISSING_DUPLICATE_REORDERED_PLAINTEXT_FIELD", "result": "RECORD_INVALID", "firstPhase": "RECORD_DECODE", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-CFMT-UNKNOWN_KIND_VERSION_ALGORITHM_LABEL", "inventory": "M2", "vector": "FMT-KAT-ACTIVE", "legacy": false, "faults": ["authenticatedVersionUnknownOrMixed"], "negativeClass": "UNKNOWN_KIND_VERSION_ALGORITHM_LABEL", "result": "UNSUPPORTED_VERSION", "firstPhase": "AUTHENTICATED_COMPATIBILITY", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-CFMT-NONCANONICAL_LENGTH_ENDIAN", "inventory": "M2", "vector": "FMT-KAT-ACTIVE", "legacy": false, "faults": ["selectorHeaderStructureIncompatible"], "negativeClass": "NONCANONICAL_LENGTH_ENDIAN", "result": "INCOMPATIBLE_FORMAT", "firstPhase": "SELECTOR_HEADER", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-CFMT-TRUNCATION_TRAILING_SIZE_OVERFLOW", "inventory": "M2", "vector": "FMT-KAT-ACTIVE", "legacy": false, "faults": ["selectorHeaderStructureIncompatible"], "negativeClass": "TRUNCATION_TRAILING_SIZE_OVERFLOW", "result": "INCOMPATIBLE_FORMAT", "firstPhase": "SELECTOR_HEADER", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-CFMT-NONCE_REUSE", "inventory": "M2", "vector": "FMT-KAT-ACTIVE", "legacy": false, "faults": ["recordAuthenticationFailed"], "negativeClass": "NONCE_REUSE", "result": "AUTHENTICATION_FAILED", "firstPhase": "RECORD_DECODE", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-CFMT-AAD_CONTEXT_SESSION_PROFILE_KIND_VERSION_GENERATION_SUBSTITUTION", "inventory": "M2", "vector": "FMT-KAT-ACTIVE", "legacy": false, "faults": ["recordAuthenticationFailed"], "negativeClass": "AAD_CONTEXT_SESSION_PROFILE_KIND_VERSION_GENERATION_SUBSTITUTION", "result": "AUTHENTICATION_FAILED", "firstPhase": "RECORD_DECODE", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-CFMT-KEY_OR_LABEL_COLLISION", "inventory": "M2", "vector": "FMT-KAT-ACTIVE", "legacy": false, "faults": ["authenticatedProfileIncompatible"], "negativeClass": "KEY_OR_LABEL_COLLISION", "result": "INCOMPATIBLE_FORMAT", "firstPhase": "AUTHENTICATED_COMPATIBILITY", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-CFMT-CROSS_DOMAIN_COPY", "inventory": "M2", "vector": "FMT-KAT-ACTIVE", "legacy": false, "faults": ["recordAuthenticationFailed"], "negativeClass": "CROSS_DOMAIN_COPY", "result": "AUTHENTICATION_FAILED", "firstPhase": "RECORD_DECODE", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-CFMT-MANIFEST_OMISSION_ADDITION_DUPLICATE_REORDER", "inventory": "M2", "vector": "FMT-KAT-ACTIVE", "legacy": false, "faults": ["manifestOrRootMismatch"], "negativeClass": "MANIFEST_OMISSION_ADDITION_DUPLICATE_REORDER", "result": "MANIFEST_INVALID", "firstPhase": "MANIFEST_ROOT", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-CFMT-ROOT_OR_SELECTOR_MISMATCH", "inventory": "M2", "vector": "FMT-KAT-ACTIVE", "legacy": false, "faults": ["manifestOrRootMismatch"], "negativeClass": "ROOT_OR_SELECTOR_MISMATCH", "result": "MANIFEST_INVALID", "firstPhase": "MANIFEST_ROOT", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-CFMT-HISTORICAL_SUBSET_UNDER_CURRENT_ROOT", "inventory": "M2", "vector": "FMT-KAT-ACTIVE", "legacy": false, "faults": ["manifestOrRootMismatch"], "negativeClass": "HISTORICAL_SUBSET_UNDER_CURRENT_ROOT", "result": "MANIFEST_INVALID", "firstPhase": "MANIFEST_ROOT", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-CFMT-PARTIAL_GENERATION", "inventory": "M2", "vector": "FMT-KAT-ACTIVE", "legacy": false, "faults": ["partialSelectedOrCandidateGeneration"], "negativeClass": "PARTIAL_GENERATION", "result": "PARTIAL_GENERATION", "firstPhase": "RECORD_SET", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-CFMT-FORGED_RESULT_ESCROW_ASSOCIATION", "inventory": "M2", "vector": "FMT-KAT-ACTIVE", "legacy": false, "faults": ["referenceOrLifecycleInconsistent"], "negativeClass": "FORGED_RESULT_ESCROW_ASSOCIATION", "result": "REFERENCE_INCONSISTENT", "firstPhase": "REFERENCES", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-CFMT-CANDIDATE_FIELDS_DIFFER_WITHOUT_RECONCILIATION_REQUIRED", "inventory": "M2", "vector": "FMT-KAT-ACTIVE", "legacy": false, "faults": ["candidateFieldsDifferWithoutReconciliation"], "negativeClass": "CANDIDATE_FIELDS_DIFFER_WITHOUT_RECONCILIATION_REQUIRED", "result": "REFERENCE_INCONSISTENT", "firstPhase": "REFERENCES", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-CFMT-RECONCILIATION_REQUIRED_CANDIDATE_MISSING_OR_MISMATCHED", "inventory": "M2", "vector": "FMT-KAT-ACTIVE", "legacy": false, "faults": ["candidateManifestKeyMismatch"], "negativeClass": "RECONCILIATION_REQUIRED_CANDIDATE_MISSING_OR_MISMATCHED", "result": "REFERENCE_INCONSISTENT", "firstPhase": "REFERENCES", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-CFMT-RECONCILIATION_REQUIRED_CANDIDATE_EQUALS_SELECTED", "inventory": "M2", "vector": "FMT-KAT-ACTIVE", "legacy": false, "faults": ["candidateEqualsSelectedDuringReconciliation"], "negativeClass": "RECONCILIATION_REQUIRED_CANDIDATE_EQUALS_SELECTED", "result": "REFERENCE_INCONSISTENT", "firstPhase": "REFERENCES", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-CFMT-CANDIDATE_MANIFEST_KEY_MISMATCH", "inventory": "M2", "vector": "FMT-KAT-ACTIVE", "legacy": false, "faults": ["candidateManifestKeyMismatch"], "negativeClass": "CANDIDATE_MANIFEST_KEY_MISMATCH", "result": "REFERENCE_INCONSISTENT", "firstPhase": "REFERENCES", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-CFMT-CANDIDATE_PARENT_MISMATCH", "inventory": "M2", "vector": "FMT-KAT-ACTIVE", "legacy": false, "faults": ["candidateParentMismatch"], "negativeClass": "CANDIDATE_PARENT_MISMATCH", "result": "REFERENCE_INCONSISTENT", "firstPhase": "REFERENCES", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-CFMT-CANDIDATE_MANIFEST_KEY_SCOPE_SESSION_SUBSTITUTION", "inventory": "M2", "vector": "FMT-KAT-ACTIVE", "legacy": false, "faults": ["candidateManifestKeyScopeSessionSubstitution"], "negativeClass": "CANDIDATE_MANIFEST_KEY_SCOPE_SESSION_SUBSTITUTION", "result": "RECORD_INVALID", "firstPhase": "RECORD_DECODE", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-CFMT-HOLD_LOCATOR_DERIVATION_MISMATCH", "inventory": "M2", "vector": "FMT-KAT-ACTIVE", "legacy": false, "faults": ["candidateManifestKeyMismatch"], "negativeClass": "HOLD_LOCATOR_DERIVATION_MISMATCH", "result": "REFERENCE_INCONSISTENT", "firstPhase": "REFERENCES", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-CFMT-HOLD_LOCATOR_SCOPE_SESSION_SUBSTITUTION", "inventory": "M2", "vector": "FMT-KAT-ACTIVE", "legacy": false, "faults": ["candidateManifestKeyScopeSessionSubstitution"], "negativeClass": "HOLD_LOCATOR_SCOPE_SESSION_SUBSTITUTION", "result": "RECORD_INVALID", "firstPhase": "RECORD_DECODE", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-CFMT-HOLD_LOCATOR_ON_NON_CANDIDATE_HOLD", "inventory": "M2", "vector": "FMT-KAT-ACTIVE", "legacy": false, "faults": ["referenceOrLifecycleInconsistent"], "negativeClass": "HOLD_LOCATOR_ON_NON_CANDIDATE_HOLD", "result": "REFERENCE_INCONSISTENT", "firstPhase": "REFERENCES", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-CFMT-HOLD_LOCATOR_GENERATION_MISMATCH", "inventory": "M2", "vector": "FMT-KAT-ACTIVE", "legacy": false, "faults": ["candidateManifestKeyMismatch"], "negativeClass": "HOLD_LOCATOR_GENERATION_MISMATCH", "result": "REFERENCE_INCONSISTENT", "firstPhase": "REFERENCES", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
    { "id": "NEG-CFMT-UNBOUND_CANDIDATE_GENERATION_REUSE", "inventory": "M2", "vector": "FMT-KAT-ACTIVE", "legacy": false, "faults": ["referenceOrLifecycleInconsistent"], "negativeClass": "UNBOUND_CANDIDATE_GENERATION_REUSE", "result": "REFERENCE_INCONSISTENT", "firstPhase": "REFERENCES", "gates": { "AUTHENTICATED_COMPATIBILITY": "PASS", "BUILD_ELIGIBILITY": "PASS", "CLASSIFY": "PASS", "INVENTORY": "PASS", "KEY_DERIVATION": "PASS", "LOCK": "PASS", "MANIFEST_ROOT": "PASS", "RECORD_DECODE": "PASS", "RECORD_SET": "PASS", "REFERENCES": "PASS", "SELECTOR_AUTH": "PASS", "SELECTOR_HEADER": "PASS", "WRAPPER_AUTH": "PASS" }, "artifacts": [{ "id": "fixed-selector", "kind": "GENERATION_SELECTOR" }, { "id": "selected-manifest", "kind": "MANIFEST" }, { "id": "selected-record-set", "kind": "DATA_RECORD_SET" }] },
  ],
}));

const VALUE_REGISTRIES = deepFreeze(Object.assign(Object.create(null), {
  "apiState": { "ACTIVE": 2, "EMPTY": 1, "RECONCILIATION_REQUIRED": 3 },
  "bool": { "false": 0, "true": 1 },
  "commitOutcome": { "COMMITTED": 1, "INDETERMINATE": 3, "NOT_COMMITTED": 2 },
  "fieldTags": "For each recordKinds entry, orderedFields is numbered consecutively from tag 1; no other tag is valid.",
  "keyPackageLifecycle": { "CONSUMED": 3, "INVALID": 4, "RESERVED": 2, "UNCONSUMED": 1 },
  "operation": { "APPLY_PEER_UPDATE": 7, "CREATE": 1, "JOIN_WELCOME": 3, "OPEN_APPLICATION": 5, "PROTECT_APPLICATION": 4, "RECONCILE_INDETERMINATE": 8, "RESTORE": 2, "SELF_UPDATE": 6 },
  "outputKind": { "APPLICATION_BYTES": 4, "EMBEDDED_TREE_WELCOME": 2, "NONE": 1, "PROTECTED_APPLICATION_BYTES": 3, "PROTECTED_COMMIT_BYTES": 5, "SELECTED_CANDIDATE_REF": 6 },
  "scenario": { "CAPI-S001": 1, "CAPI-S006": 2, "CAPI-S009": 3, "CAPI-S010": 4, "CAPI-S014": 5, "CAPI-S016": 6, "CAPI-S017": 7 },
  "selectorState": { "ACTIVE": 2, "EMPTY": 1, "RECONCILIATION_REQUIRED": 3 },
  "slotState": { "BOUND": 3, "EMPTY": 1, "ISSUANCE_HELD": 2, "RECONCILIATION_REQUIRED": 4 },
  "successCode": { "APPLICATION_OPENED": 5, "APPLICATION_PROTECTED": 4, "CANDIDATE_SELECTED": 8, "CREATED": 1, "DUPLICATE_IGNORED": 10, "JOINED": 3, "PEER_UPDATE_APPLIED": 7, "RECONCILED_COMMITTED": 9, "RESTORED": 2, "SELF_UPDATED": 6 },
}));

// ------------------------------------------------------------------------------------------------
// Structural helpers. Every accepted value is checked structurally; nothing is coerced.
// ------------------------------------------------------------------------------------------------

/**
 * Deep-freeze a closed value. Typed arrays are left alone (an array buffer view with elements cannot
 * be frozen), so no caller-visible byte array is ever echoed back from this module.
 */
function deepFreeze(value) {
  if (ArrayBuffer.isView(value)) {
    return value;
  }
  if (Array.isArray(value)) {
    value.forEach(deepFreeze);
  } else if (value !== null && typeof value === 'object') {
    Object.values(value).forEach(deepFreeze);
  }
  return Object.freeze(value);
}

const hasOwn = (value, key) => Object.prototype.hasOwnProperty.call(value, key);

const isPlainObject = (value) => {
  if (value === null || typeof value !== 'object') {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
};

/**
 * True only for a plain object with exactly the expected own members, no symbol-keyed member, no
 * accessor member and no extra member. This is the closure check every accepted record passes.
 */
function hasExactMembers(value, expected) {
  if (!isPlainObject(value)) {
    return false;
  }
  const own = Reflect.ownKeys(value);
  if (own.length !== expected.length) {
    return false;
  }
  for (const key of own) {
    if (typeof key !== 'string' || !expected.includes(key)) {
      return false;
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !hasOwn(descriptor, 'value')) {
      return false;
    }
  }
  return true;
}

/** Read one already-validated data member without re-triggering a getter. */
const memberOf = (value, key) => Object.getOwnPropertyDescriptor(value, key).value;

const isBytes = (value, length) => value instanceof Uint8Array && value.byteLength === length;

const isNonZeroBytes = (value, length) => {
  if (!isBytes(value, length)) {
    return false;
  }
  for (let index = 0; index < value.byteLength; index += 1) {
    if (value[index] !== 0) {
      return true;
    }
  }
  return false;
};

const isGeneration = (value) => typeof value === 'bigint' && value >= 1n;

const isVersionNumber = (value) => Number.isInteger(value) && Object.is(value, Math.trunc(value))
  && !Object.is(value, -0);

const bytesEqual = (left, right) => {
  if (left instanceof Uint8Array && right instanceof Uint8Array) {
    if (left.byteLength !== right.byteLength) {
      return false;
    }
    for (let index = 0; index < left.byteLength; index += 1) {
      if (left[index] !== right[index]) {
        return false;
      }
    }
    return true;
  }
  return false;
};

const frozenBytes32 = (value) => value;

// ------------------------------------------------------------------------------------------------
// The closed error class. It carries one C-REST failure code and one C-REST phase, and nothing else:
// no free text, no path, no value and no offending input. An out-of-set argument is discarded and the
// error itself is the closed failure default at CLASSIFY.
// ------------------------------------------------------------------------------------------------

const ERROR_FALLBACK_RESULT = 'INTERNAL_VALIDATION_FAILED';
const ERROR_FALLBACK_STAGE = 'CLASSIFY';

export class M2RestoreError extends Error {
  constructor(result, stage) {
    const closed = typeof result === 'string' && FAILURE_RESULTS.includes(result)
      && typeof stage === 'string' && PHASES.includes(stage);
    const useResult = closed ? result : ERROR_FALLBACK_RESULT;
    const useStage = closed ? stage : ERROR_FALLBACK_STAGE;
    super(`${useResult}@${useStage}`);
    this.name = 'M2RestoreError';
    this.result = useResult;
    this.stage = useStage;
  }
}

const fail = (result, stage) => {
  throw new M2RestoreError(result, stage);
};

// ------------------------------------------------------------------------------------------------
// §2/§3: version equality and build eligibility.
// ------------------------------------------------------------------------------------------------

/**
 * The eight observed versions must equal the ratified allowlist exactly. A missing, extra, mixed,
 * non-integer, unknown or drifted version set is `UNSUPPORTED_VERSION` - never a partial match.
 */
export function checkVersions(observed) {
  if (!hasExactMembers(observed, VERSION_KEYS)) {
    return 'UNSUPPORTED_VERSION';
  }
  for (const key of VERSION_KEYS) {
    const value = memberOf(observed, key);
    if (!isVersionNumber(value) || value !== VERSIONS[key]) {
      return 'UNSUPPORTED_VERSION';
    }
  }
  return null;
}

/**
 * One complete `buildMatrix` row, by equality of every member. A partial row, an extra member, an
 * unlisted runtime or browser class, a wrong ciphersuite or a drifted version set is ineligible.
 */
export function checkBuildEligibility(build) {
  if (!hasExactMembers(build, BUILD_ROW_KEYS)) {
    return false;
  }
  const ciphersuite = memberOf(build, 'ss0Ciphersuite');
  if (!hasExactMembers(ciphersuite, ['ianaId', 'name'])) {
    return false;
  }
  for (const row of BUILD_MATRIX) {
    let matches = true;
    for (const key of BUILD_ROW_KEYS) {
      const value = memberOf(build, key);
      if (key === 'ss0Ciphersuite') {
        matches = matches && memberOf(value, 'ianaId') === row.ss0Ciphersuite.ianaId
          && memberOf(value, 'name') === row.ss0Ciphersuite.name;
      } else if (key === 'versions') {
        matches = matches && hasExactMembers(value, VERSION_KEYS)
          && VERSION_KEYS.every((versionKey) => memberOf(value, versionKey) === row.versions[versionKey]);
      } else {
        matches = matches && value === row[key];
      }
    }
    if (matches) {
      return true;
    }
  }
  return false;
}

// ------------------------------------------------------------------------------------------------
// §4: the authenticated compatibility conjunction.
// ------------------------------------------------------------------------------------------------

/**
 * Apply the entire `compatibilityRegistry` conjunction to authenticated values. A version mismatch
 * precedes every other profile mismatch; any other authenticated mismatch is `INCOMPATIBLE_FORMAT`.
 * A structurally invalid input is `INTERNAL_VALIDATION_FAILED`.
 */
export function checkAuthenticatedCompatibility(authenticated) {
  if (!hasExactMembers(authenticated, ['versions', 'profile'])) {
    return 'INTERNAL_VALIDATION_FAILED';
  }
  const versions = memberOf(authenticated, 'versions');
  // C-REST §2: unknown, future, missing, mixed or downgraded versions are UNSUPPORTED_VERSION, so a
  // version set that is not the exact closed eight-member set is an unsupported version, never an
  // internal validator failure. §2's only INTERNAL_VALIDATION_FAILED case is a malformed argument.
  if (!hasExactMembers(versions, VERSION_KEYS)) {
    return 'UNSUPPORTED_VERSION';
  }
  for (const key of VERSION_KEYS) {
    const value = memberOf(versions, key);
    if (!isVersionNumber(value)) {
      return 'UNSUPPORTED_VERSION';
    }
    if (value !== VERSIONS[key]) {
      return 'UNSUPPORTED_VERSION';
    }
  }
  const profile = memberOf(authenticated, 'profile');
  if (!hasExactMembers(profile, ['readerProfile', 'algorithms'])) {
    return 'INCOMPATIBLE_FORMAT';
  }
  if (memberOf(profile, 'readerProfile') !== READER_PROFILE) {
    return 'INCOMPATIBLE_FORMAT';
  }
  const algorithms = memberOf(profile, 'algorithms');
  if (!hasExactMembers(algorithms, ALGORITHM_KEYS)) {
    return 'INCOMPATIBLE_FORMAT';
  }
  for (const key of ALGORITHM_KEYS) {
    if (memberOf(algorithms, key) !== ALGORITHMS[key]) {
      return 'INCOMPATIBLE_FORMAT';
    }
  }
  return null;
}

// ------------------------------------------------------------------------------------------------
// §7: the reconciliation candidate and its physical parent.
// ------------------------------------------------------------------------------------------------

const LOCATOR_KIND = 16;
const LOCATOR_KEYS = deepFreeze([
  'recordKind', 'objectIdLength', 'scope', 'secureSessionIdentity', 'generation', 'localContextId',
  'sha256',
]);
const CANDIDATE_KEYS = deepFreeze([
  'manifestCiphertextDigest', 'keyedRoot', 'manifestBindingDigest', 'bindingProfileDigest',
  'parentGeneration', 'parentKeyedRoot', 'originalAuthorityDigest', 'originalAuthorityReference',
  'resultStatus',
]);
const CANDIDATE_FACT_KEYS = deepFreeze([
  'localContextId', 'candidateGeneration', 'candidateManifestKeyDigest', 'manifestCiphertextDigest',
  'keyedRoot', 'selectedGeneration', 'selectedKeyedRoot', 'selectorState', 'locator', 'candidate',
  'candidateBindingProfile', 'commitResult',
]);
const COMMIT_RESULT_KEYS = deepFreeze(['originalAuthorityDigest', 'originalAuthorityReference']);

const invalidFacts = () => fail('INTERNAL_VALIDATION_FAILED', 'CLASSIFY');
const recordInvalid = () => fail('RECORD_INVALID', 'RECORD_DECODE');
const inconsistent = () => fail('REFERENCE_INCONSISTENT', 'REFERENCES');

const locatorKeyValid = (locator) => {
  if (!hasExactMembers(locator, LOCATOR_KEYS)) {
    return false;
  }
  const scope = memberOf(locator, 'scope');
  const sessionIdentity = memberOf(locator, 'secureSessionIdentity');
  const preSession = scope === 'CONTEXT_PRESESSION' || scope === 1;
  const session = scope === 'SESSION' || scope === 2;
  if (!preSession && !session) {
    return false;
  }
  if (preSession && sessionIdentity !== null) {
    return false;
  }
  if (session && !isNonZeroBytes(sessionIdentity, 32)) {
    return false;
  }
  if (memberOf(locator, 'recordKind') !== LOCATOR_KIND) {
    return false;
  }
  if (memberOf(locator, 'objectIdLength') !== 0) {
    return false;
  }
  return isGeneration(memberOf(locator, 'generation'))
    && isBytes(memberOf(locator, 'localContextId'), 32)
    && isBytes(memberOf(locator, 'sha256'), 32);
};

/**
 * The three carried equalities of a canonical kind-16 locator. A canonical locator that disagrees with
 * the candidate it locates is `candidateManifestKeyMismatch`, a `REFERENCES` fault, and not a
 * `RECORD_DECODE` fault: only a non-canonical key or a scope/session substitution is `RECORD_INVALID`.
 */
const locatorMatchesFacts = (locator, facts) => memberOf(locator, 'generation') === memberOf(facts, 'candidateGeneration')
  && bytesEqual(memberOf(locator, 'localContextId'), memberOf(facts, 'localContextId'))
  && bytesEqual(memberOf(locator, 'sha256'), memberOf(facts, 'candidateManifestKeyDigest'));

const candidateShapeValid = (candidate, profile) => {
  if (!hasExactMembers(candidate, CANDIDATE_KEYS) || !hasExactMembers(profile, ['generation', 'bindingProfileDigest'])) {
    return false;
  }
  if (!isGeneration(memberOf(profile, 'generation'))) {
    return false;
  }
  if (!isBytes(memberOf(profile, 'bindingProfileDigest'), 32)
    || !isBytes(memberOf(candidate, 'manifestBindingDigest'), 32)) {
    return false;
  }
  if (!isBytes(memberOf(candidate, 'manifestCiphertextDigest'), 32)
    || !isBytes(memberOf(candidate, 'keyedRoot'), 32)
    || !isBytes(memberOf(candidate, 'bindingProfileDigest'), 32)
    || !isBytes(memberOf(candidate, 'parentKeyedRoot'), 32)
    || !isBytes(memberOf(candidate, 'originalAuthorityDigest'), 32)
    || !isBytes(memberOf(candidate, 'originalAuthorityReference'), 32)) {
    return false;
  }
  if (!isGeneration(memberOf(candidate, 'parentGeneration'))) {
    return false;
  }
  return RESULT_STATUSES.includes(memberOf(candidate, 'resultStatus'));
};

/**
 * Validate one C-REST §7 reconciliation candidate against the closed candidate grammar and return the
 * frozen facts the classifier may use. A candidate is never authority: a candidate equal to the
 * selected generation during reconciliation rejects, and candidate fields that differ without
 * `RECONCILIATION_REQUIRED` reject. The located candidate manifest binding digest must equal that
 * candidate generation's own `BINDING_PROFILE`, and the candidate hold's logical original-authority
 * digest and reference must each equal the same field of the candidate `COMMIT_RESULT`. The scope of
 * the kind-16 manifest key is not restricted by §7: the record-key grammar admits both
 * `CONTEXT_PRESESSION` and `SESSION`, and an ACTIVE-parent hold carries a session generation.
 */
export function validateReconciliationCandidate(facts) {
  if (!hasExactMembers(facts, CANDIDATE_FACT_KEYS)) {
    return invalidFacts();
  }
  for (const key of ['localContextId', 'candidateManifestKeyDigest', 'manifestCiphertextDigest', 'keyedRoot', 'selectedKeyedRoot']) {
    if (!isBytes(memberOf(facts, key), 32)) {
      return invalidFacts();
    }
  }
  if (!isNonZeroBytes(memberOf(facts, 'localContextId'), 32)) {
    return invalidFacts();
  }
  if (!isGeneration(memberOf(facts, 'candidateGeneration')) || !isGeneration(memberOf(facts, 'selectedGeneration'))) {
    return invalidFacts();
  }
  const selectorState = memberOf(facts, 'selectorState');
  if (typeof selectorState !== 'string' || !SELECTOR_STATES.includes(selectorState)) {
    return invalidFacts();
  }
  const candidateEqualsSelected = memberOf(facts, 'candidateGeneration') === memberOf(facts, 'selectedGeneration')
    && bytesEqual(memberOf(facts, 'keyedRoot'), memberOf(facts, 'selectedKeyedRoot'));
  const generationEquals = memberOf(facts, 'candidateGeneration') === memberOf(facts, 'selectedGeneration');
  const rootEquals = bytesEqual(memberOf(facts, 'keyedRoot'), memberOf(facts, 'selectedKeyedRoot'));
  if (generationEquals !== rootEquals) {
    // Neither the selected tuple nor a distinct one: an "other combination", which rejects.
    return inconsistent();
  }
  if (candidateEqualsSelected && selectorState === 'RECONCILIATION_REQUIRED') {
    // A candidate that is physically the selected generation is not a separate candidate.
    return inconsistent();
  }
  if (!candidateEqualsSelected && selectorState !== 'RECONCILIATION_REQUIRED') {
    return inconsistent();
  }
  const locator = memberOf(facts, 'locator');
  if (!locatorKeyValid(locator)) {
    return recordInvalid();
  }
  if (!locatorMatchesFacts(locator, facts)) {
    return inconsistent();
  }
  const candidate = memberOf(facts, 'candidate');
  const profile = memberOf(facts, 'candidateBindingProfile');
  const commitResult = memberOf(facts, 'commitResult');
  if (!candidateShapeValid(candidate, profile) || !hasExactMembers(commitResult, COMMIT_RESULT_KEYS)) {
    return invalidFacts();
  }
  if (!isBytes(memberOf(commitResult, 'originalAuthorityDigest'), 32)
    || !isBytes(memberOf(commitResult, 'originalAuthorityReference'), 32)) {
    return invalidFacts();
  }
  // The located candidate manifest binding digest must match that candidate generation's own profile,
  // which the candidate repeats in its manifest binding digest and in its own binding profile digest.
  if (memberOf(profile, 'generation') !== memberOf(facts, 'candidateGeneration')
    || !bytesEqual(memberOf(candidate, 'manifestBindingDigest'), memberOf(profile, 'bindingProfileDigest'))
    || !bytesEqual(memberOf(candidate, 'bindingProfileDigest'), memberOf(profile, 'bindingProfileDigest'))
    || !bytesEqual(memberOf(candidate, 'bindingProfileDigest'), memberOf(candidate, 'manifestBindingDigest'))) {
    return inconsistent();
  }
  if (!bytesEqual(memberOf(candidate, 'manifestCiphertextDigest'), memberOf(facts, 'manifestCiphertextDigest'))
    || !bytesEqual(memberOf(candidate, 'keyedRoot'), memberOf(facts, 'keyedRoot'))) {
    return inconsistent();
  }
  // The hold's logical original authority must equal the candidate COMMIT_RESULT's same fields.
  if (!bytesEqual(memberOf(candidate, 'originalAuthorityDigest'), memberOf(commitResult, 'originalAuthorityDigest'))
    || !bytesEqual(memberOf(candidate, 'originalAuthorityReference'), memberOf(commitResult, 'originalAuthorityReference'))) {
    return inconsistent();
  }
  // An unresolved candidate hold must name the selector's physical parent.
  if (memberOf(candidate, 'resultStatus') === 'INDETERMINATE') {
    if (memberOf(candidate, 'parentGeneration') !== memberOf(facts, 'selectedGeneration')
      || !bytesEqual(memberOf(candidate, 'parentKeyedRoot'), memberOf(facts, 'selectedKeyedRoot'))) {
      return inconsistent();
    }
  }
  return deepFreeze({
    candidateGeneration: memberOf(facts, 'candidateGeneration'),
    bindingProfileVerified: true,
    candidateEqualsSelected,
    authority: 'CANDIDATE_NOT_AUTHORITY',
  });
}

// ------------------------------------------------------------------------------------------------
// §4/§5/§10: the ordered, total, fail-closed decision.
// ------------------------------------------------------------------------------------------------

const invalidObservation = () => fail(FAILURE_DEFAULT, 'CLASSIFY');

/**
 * Validate the closed five-member observation and return its members, or throw the fail-closed default.
 * An extra enumerable, non-enumerable or symbol-keyed member, a missing member, an accessor member, a
 * non-plain object, an out-of-type value, an out-of-set value, a duplicate fault, a vector that
 * contradicts the inventory and a fault that contradicts the inventory all reject here.
 */
function readObservation(observation) {
  if (!hasExactMembers(observation, OBSERVATION_KEYS)) {
    return invalidObservation();
  }
  const faults = memberOf(observation, 'faults');
  if (!Array.isArray(faults)) {
    return invalidObservation();
  }
  const snapshot = [];
  const seen = new Set();
  for (const fault of faults) {
    if (typeof fault !== 'string' || !FAULT_RANK.has(fault)) {
      return invalidObservation();
    }
    if (seen.has(fault)) {
      return invalidObservation();
    }
    seen.add(fault);
    snapshot.push(fault);
  }
  Object.freeze(snapshot);
  const inventory = memberOf(observation, 'inventory');
  if (typeof inventory !== 'string' || !OBSERVED_INVENTORY.includes(inventory)) {
    return invalidObservation();
  }
  const legacy = memberOf(observation, 'legacy');
  if (typeof legacy !== 'boolean') {
    return invalidObservation();
  }
  const vector = memberOf(observation, 'vector');
  if (vector !== null && (typeof vector !== 'string' || !VECTOR_ALLOWLIST.includes(vector))) {
    return invalidObservation();
  }
  const selectorState = memberOf(observation, 'selectorState');
  if (typeof selectorState !== 'string' || !hasOwn(SUCCESS_BY_SELECTOR_STATE, selectorState)) {
    return invalidObservation();
  }
  if (inventory === 'NONE' && (legacy !== false || vector !== null)) {
    return invalidObservation();
  }
  if (inventory === 'LEGACY_ONLY' && (legacy !== true || vector !== null)) {
    return invalidObservation();
  }
  if (inventory === 'M2' && vector === null) {
    return invalidObservation();
  }
  if (vector !== null && VECTOR_STATES[vector] !== selectorState) {
    return invalidObservation();
  }
  if (snapshot.some((fault) => phaseIndexOf(FAULT_ROW.get(fault).phase) > INVENTORY_PHASE_INDEX)
    && inventory !== 'M2') {
    return invalidObservation();
  }
  return { faults: snapshot, inventory, legacy, vector, selectorState };
}

const reasonFor = (result) => (FAILURE_RESULTS.includes(result) || INVENTORY_RESULTS.includes(result)
  ? result
  : result);

function outcomeFor(result, stage, members, exposed) {
  const legacyPresent = result === 'NO_M2_STATE' ? false : members.legacy;
  const seenM2 = members.inventory === 'M2';
  return deepFreeze({
    result,
    stage,
    condition: seenM2 && members.legacy ? 'LEGACY_PRESENT' : null,
    exposed,
    diagnostics: deepFreeze({
      stageCode: stage,
      reasonCode: reasonFor(result),
      m2LocatorCount: seenM2 ? null : 0,
      m2ArtifactCount: seenM2 ? null : 0,
      legacyPresent,
    }),
  });
}

/**
 * The total, deterministic, fail-closed restore decision. It never throws and never returns a value
 * outside the closed vocabulary: every rejection is a C-REST failure code at a C-REST phase, and
 * anything unexpected is `INTERNAL_VALIDATION_FAILED` at `CLASSIFY`. Only a success exposes selected
 * authority, and only at `EXPOSE`.
 */
export function classifyRestore(observation) {
  let members;
  try {
    members = readObservation(observation);
  } catch (error) {
    if (error instanceof M2RestoreError) {
      return outcomeFor(error.result, error.stage, {
        inventory: 'NONE', legacy: false, vector: null,
      }, false);
    }
    return outcomeFor(FAILURE_DEFAULT, 'CLASSIFY', { inventory: 'NONE', legacy: false, vector: null }, false);
  }
  if (members.faults.length > 0) {
    let chosen = null;
    for (const fault of members.faults) {
      const row = FAULT_ROW.get(fault);
      if (row !== undefined && (chosen === null || FAULT_RANK.get(fault) < FAULT_RANK.get(chosen.fault))) {
        chosen = row;
      }
    }
    if (chosen === null) {
      return outcomeFor(FAILURE_DEFAULT, 'CLASSIFY', members, false);
    }
    return outcomeFor(chosen.result, chosen.phase, members, false);
  }
  if (members.inventory === 'NONE') {
    return outcomeFor('NO_M2_STATE', 'INVENTORY', members, false);
  }
  if (members.inventory === 'LEGACY_ONLY') {
    return outcomeFor('LEGACY_ONLY', 'INVENTORY', members, false);
  }
  const result = SUCCESS_BY_SELECTOR_STATE[members.selectorState];
  return outcomeFor(result, 'EXPOSE', members, true);
}

// ------------------------------------------------------------------------------------------------
// §12: the fresh-worker fixture matrix.
// ------------------------------------------------------------------------------------------------

/**
 * The seventy-seven ratified fixtures, verbatim: seven positive rows and seventy negative rows.
 */
export const FRESH_WORKER_FIXTURES = deepFreeze({
  positive: C_REST_FIXTURES.positive,
  negative: C_REST_FIXTURES.negative,
});

/**
 * The store context a `gates`-only negative fixture is exercised under. Thirty-five negative rows
 * carry no store members of their own, so the matrix supplies the ACTIVE store vector the record uses
 * for every other negative row. The row itself is copied verbatim and is not modified.
 */
const NEGATIVE_CONTEXT = deepFreeze({ inventory: 'M2', vector: 'FMT-KAT-ACTIVE', legacy: false });

const SELECTOR_STATE_OF_SUCCESS = deepFreeze({
  RESTORED_EMPTY: 'EMPTY',
  RESTORED_ACTIVE: 'ACTIVE',
  RESTORED_RECONCILIATION_REQUIRED: 'RECONCILIATION_REQUIRED',
});

function observationForFixture(row, fallback) {
  const inventory = hasOwn(row, 'inventory') ? row.inventory : fallback.inventory;
  const vector = hasOwn(row, 'vector') ? row.vector : fallback.vector;
  const legacy = hasOwn(row, 'legacy') ? row.legacy : fallback.legacy;
  const faults = hasOwn(row, 'faults') ? row.faults : [];
  // The authenticated selector state is read from the store vector, never from the row's expected
  // result: feeding the expectation back in as input would make the matrix tautological.
  const selectorState = vector === null
    ? (faults.length > 0 ? 'ACTIVE' : SELECTOR_STATE_OF_SUCCESS[row.result] ?? 'ACTIVE')
    : VECTOR_STATES[vector];
  return { faults, inventory, legacy, vector, selectorState };
}

/**
 * Execute every ratified fixture against the real classifier and return the frozen result rows. Each
 * row carries the fixture id, the record's expected result and first phase, and the classifier's
 * actual outcome; nothing is asserted here, so the caller can prove the matrix independently.
 */
export function runFreshWorkerFixtureMatrix() {
  const rows = [];
  for (const row of C_REST_FIXTURES.positive) {
    rows.push(deepFreeze({
      id: row.id,
      kind: 'positive',
      expected: deepFreeze({ result: row.result, firstPhase: row.firstPhase }),
      actual: classifyRestore(observationForFixture(row, NEGATIVE_CONTEXT)),
    }));
  }
  for (const row of C_REST_FIXTURES.negative) {
    rows.push(deepFreeze({
      id: row.id,
      kind: 'negative',
      expected: deepFreeze({ result: row.result, firstPhase: row.firstPhase }),
      actual: classifyRestore(observationForFixture(row, NEGATIVE_CONTEXT)),
    }));
  }
  return deepFreeze(rows);
}

// ------------------------------------------------------------------------------------------------
// The closed module surface: exactly the thirty names the contract fixes.
// ------------------------------------------------------------------------------------------------

/**
 * The frozen C-REST metadata. Every member is a closed registry, and every registry is deep-frozen so
 * the decision table cannot be edited through the module surface.
 */
export const M2_RESTORE = deepFreeze({
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
  READER_PROFILE,
  CORRUPTION_ACTION,
  AUTOMATIC_ACTIONS,
  EXPOSURE,
  FRESHNESS,
});

export { VALUE_REGISTRIES };
