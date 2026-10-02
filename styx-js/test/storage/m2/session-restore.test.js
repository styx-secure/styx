import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import {
  ALGORITHMS, AUTOMATIC_ACTIONS, BUILD_MATRIX, CONDITIONS, CORRUPTION_ACTION,
  DIAGNOSTIC_ALLOWED, DIAGNOSTIC_FORBIDDEN, EXPOSURE, FAILURE_DEFAULT, FAILURE_RESULTS,
  FAULT_PRECEDENCE, FRESHNESS, FRESH_WORKER_FIXTURES, INVENTORY_RESULTS, M2_RESTORE,
  M2RestoreError, NEGATIVE_CLASSES, PHASES, READER_PROFILE, SUCCESS_BY_SELECTOR_STATE,
  SUCCESS_RESULTS, UNSUPPORTED_RUNTIME_CLASSES, VALUE_REGISTRIES, VERSIONS,
  checkAuthenticatedCompatibility, checkBuildEligibility, checkVersions, classifyRestore,
  runFreshWorkerFixtureMatrix, validateReconciliationCandidate,
} from '../../../src/storage/m2/session-restore.js';

// ---------------------------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------------------------
const ACTIVE_OBSERVATION = Object.freeze({
  faults: [], inventory: 'M2', legacy: false, vector: 'FMT-KAT-ACTIVE', selectorState: 'ACTIVE',
});
const HOLD_OBSERVATION = Object.freeze({
  faults: [], inventory: 'M2', legacy: false, vector: 'FMT-KAT-HOLD', selectorState: 'RECONCILIATION_REQUIRED',
});
const cleanObservation = (overrides = {}) => ({ ...ACTIVE_OBSERVATION, ...overrides });
const bytes = (seed) => Uint8Array.from({ length: 32 }, (_, i) => (seed + i) & 0xff);
const clone = (value) => JSON.parse(JSON.stringify(value));
const rowNamed = (name) => BUILD_MATRIX.find((row) => row.buildId === name);
const goodBuild = () => {
  const row = clone(rowNamed('M2_WEB_CHROMIUM_STANDARD'));
  return row;
};

const goodCandidateFacts = () => {
  const bindingProfileDigest = bytes(0x90);
  return {
    localContextId: bytes(0x11),
    candidateGeneration: 7n,
    candidateManifestKeyDigest: bytes(0x21),
    manifestCiphertextDigest: bytes(0x31),
    keyedRoot: bytes(0x41),
    selectedGeneration: 6n,
    selectedKeyedRoot: bytes(0x51),
    selectorState: 'RECONCILIATION_REQUIRED',
    candidateEqualsSelected: false,
    locator: {
      recordKind: 16,
      objectIdLength: 0,
      scope: 'CONTEXT_PRESESSION',
      secureSessionIdentity: null,
      generation: 7n,
      localContextId: bytes(0x11),
      sha256: bytes(0x21),
    },
    candidate: {
      manifestCiphertextDigest: bytes(0x31),
      keyedRoot: bytes(0x41),
      manifestBindingDigest: bytes(0x90),
      bindingProfileDigest,
      parentGeneration: 6n,
      parentKeyedRoot: bytes(0x51),
      originalAuthorityDigest: bytes(0x61),
      originalAuthorityReference: bytes(0x61),
      resultStatus: 'INDETERMINATE',
    },
    candidateBindingProfile: { generation: 7n, bindingProfileDigest },
  };
};

const expectRejection = (thunk, result, stage) => {
  let thrown = null;
  try {
    thunk();
  } catch (error) {
    thrown = error;
  }
  expect(thrown).toBeInstanceOf(M2RestoreError);
  expect(thrown.result).toBe(result);
  expect(thrown.stage).toBe(stage);
};

// ---------------------------------------------------------------------------------------------
describe('closed vocabulary', () => {
  test('the phase, result and fault sets are exactly the C-REST closed sets', () => {
    expect(PHASES).toHaveLength(14);
    expect(PHASES[0]).toBe('LOCK');
    expect(PHASES[13]).toBe('EXPOSE');
    expect(INVENTORY_RESULTS).toEqual(['NO_M2_STATE', 'LEGACY_ONLY']);
    expect(SUCCESS_RESULTS).toHaveLength(3);
    expect(FAILURE_RESULTS).toHaveLength(13);
    expect(CONDITIONS).toEqual(['LEGACY_PRESENT']);
    expect(FAILURE_DEFAULT).toBe('INTERNAL_VALIDATION_FAILED');
    expect(FAULT_PRECEDENCE).toHaveLength(26);
    expect(NEGATIVE_CLASSES).toHaveLength(20);
  });

  test('inventory, success and failure sets are disjoint and total', () => {
    const all = [...INVENTORY_RESULTS, ...SUCCESS_RESULTS, ...FAILURE_RESULTS];
    expect(new Set(all).size).toBe(all.length);
    expect(FAILURE_DEFAULT).toBe(FAILURE_RESULTS[FAILURE_RESULTS.length - 1]);
  });

  test('successBySelectorState is total over the three selector states', () => {
    expect(Object.keys(SUCCESS_BY_SELECTOR_STATE).sort())
      .toEqual(['ACTIVE', 'EMPTY', 'RECONCILIATION_REQUIRED']);
    expect(SUCCESS_BY_SELECTOR_STATE.EMPTY).toBe('RESTORED_EMPTY');
    expect(SUCCESS_BY_SELECTOR_STATE.ACTIVE).toBe('RESTORED_ACTIVE');
    expect(SUCCESS_BY_SELECTOR_STATE.RECONCILIATION_REQUIRED).toBe('RESTORED_RECONCILIATION_REQUIRED');
  });

  test('every negative class names an existing faultPrecedence row with the same phase and result', () => {
    for (const row of NEGATIVE_CLASSES) {
      const precedence = FAULT_PRECEDENCE.find((candidate) => candidate.fault === row.fault);
      expect(precedence).toBeDefined();
      expect(precedence.phase).toBe(row.phase);
      expect(precedence.result).toBe(row.result);
    }
  });

  test('faultPrecedence is ordered by phase and every phase is reachable', () => {
    const seen = FAULT_PRECEDENCE.map((row) => PHASES.indexOf(row.phase));
    for (let i = 1; i < seen.length; i += 1) {
      expect(seen[i]).toBeGreaterThanOrEqual(seen[i - 1]);
    }
  });

  test('the metadata surface is frozen, and the automatic-action prohibition is honoured', () => {
    expect(Object.isFrozen(M2_RESTORE)).toBe(true);
    expect(Object.isFrozen(FAULT_PRECEDENCE)).toBe(true);
    expect(Object.isFrozen(BUILD_MATRIX)).toBe(true);
    expect(Object.values(AUTOMATIC_ACTIONS).every((value) => value === false)).toBe(true);
    expect(CORRUPTION_ACTION).toBe('PRESERVE_AND_STOP_LOGICAL_READ_DISABLE_ONLY');
    expect(EXPOSURE.beforeEXPOSE).toEqual([]);
    expect(EXPOSURE.atEXPOSE).toEqual(['SELECTED_AUTHORITY']);
    expect(EXPOSURE.never).toHaveLength(4);
    expect(FRESHNESS.freshnessClaim).toBe(false);
    expect(FRESHNESS.coherentWholeProfileRollbackDetection).toBe(false);
  });
});

// ---------------------------------------------------------------------------------------------
describe('fresh-worker fixture matrix (C-REST 12)', () => {
  test('the matrix carries exactly seven positive and sixty-five negative fixtures', () => {
    expect(FRESH_WORKER_FIXTURES).toHaveLength(72);
    expect(FRESH_WORKER_FIXTURES.filter((row) => row.id.startsWith('POS-'))).toHaveLength(7);
    expect(FRESH_WORKER_FIXTURES.filter((row) => row.id.startsWith('NEG-'))).toHaveLength(65);
  });

  test('every fixture returns its exact typed outcome at its exact first phase', () => {
    const rows = runFreshWorkerFixtureMatrix();
    const mismatched = rows.filter((row) => row.ok !== true || row.result !== row.expectedResult
      || row.stage !== row.expectedPhase);
    expect(mismatched).toEqual([]);
    expect(rows).toHaveLength(72);
  });

  test('every fixture result is a closed value and every rejection exposes nothing', () => {
    const closed = new Set([...INVENTORY_RESULTS, ...SUCCESS_RESULTS, ...FAILURE_RESULTS]);
    for (const row of runFreshWorkerFixtureMatrix()) {
      expect(closed.has(row.result)).toBe(true);
      expect(PHASES).toContain(row.stage);
      if (row.result.startsWith('RESTORED_')) {
        expect(row.exposed).toBe(true);
      } else {
        expect(row.exposed).toBe(false);
      }
    }
  });

  test('a negative fixture never resolves to a success or to an empty result', () => {
    for (const row of FRESH_WORKER_FIXTURES.filter((item) => item.id.startsWith('NEG-'))) {
      expect(SUCCESS_RESULTS).not.toContain(row.result);
      expect(INVENTORY_RESULTS).not.toContain(row.result);
    }
  });

  test('the four positive successes carry the LEGACY_PRESENT condition only when legacy is present', () => {
    const rows = runFreshWorkerFixtureMatrix();
    for (const row of rows) {
      const source = FRESH_WORKER_FIXTURES.find((item) => item.id === row.id);
      expect(row.legacyPresent).toBe(source.legacy === true);
    }
    expect(rows.find((row) => row.id === 'POS-M2-LEGACY-PRESENT').result).toBe('RESTORED_ACTIVE');
    expect(rows.find((row) => row.id === 'POS-M2-LEGACY-PRESENT').legacyPresent).toBe(true);
  });
});

// ---------------------------------------------------------------------------------------------
describe('positive classification', () => {
  test('absence of every M2 locator and artifact is NO_M2_STATE at INVENTORY', () => {
    const outcome = classifyRestore(cleanObservation({ inventory: 'NONE', vector: null }));
    expect(outcome.result).toBe('NO_M2_STATE');
    expect(outcome.stage).toBe('INVENTORY');
    expect(outcome.exposed).toBe(false);
  });

  test('legacy-only requires observed legacy presence and reports LEGACY_ONLY', () => {
    const outcome = classifyRestore(cleanObservation({ inventory: 'LEGACY_ONLY', legacy: true, vector: null }));
    expect(outcome.result).toBe('LEGACY_ONLY');
    expect(outcome.stage).toBe('INVENTORY');
    expect(outcome.exposed).toBe(false);
  });

  test('the three authenticated selector states map to the three successes at EXPOSE', () => {
    const empt = classifyRestore(cleanObservation({ vector: 'FMT-KAT-EMPTY', selectorState: 'EMPTY' }));
    expect(empt.result).toBe('RESTORED_EMPTY');
    expect(empt.stage).toBe('EXPOSE');
    expect(empt.exposed).toBe(true);
    const active = classifyRestore(ACTIVE_OBSERVATION);
    expect(active.result).toBe('RESTORED_ACTIVE');
    const hold = classifyRestore(HOLD_OBSERVATION);
    expect(hold.result).toBe('RESTORED_RECONCILIATION_REQUIRED');
    expect(hold.exposed).toBe(true);
  });

  test('valid M2 plus legacy keeps the M2 result and only attaches LEGACY_PRESENT', () => {
    const outcome = classifyRestore(cleanObservation({ legacy: true }));
    expect(outcome.result).toBe('RESTORED_ACTIVE');
    expect(outcome.legacyPresent).toBe(true);
  });

  test('a success exposes selected authority only, at EXPOSE', () => {
    const outcome = classifyRestore(ACTIVE_OBSERVATION);
    expect(outcome.stage).toBe('EXPOSE');
    expect(outcome.exposed).toBe(true);
    for (const rejection of FAULT_PRECEDENCE.map((row) => classifyRestore(cleanObservation({ faults: [row.fault] })))) {
      expect(rejection.exposed).toBe(false);
    }
  });
});

// ---------------------------------------------------------------------------------------------
describe('failure precedence and fail-closed faults', () => {
  test('every faultPrecedence row classifies to its exact result and phase', () => {
    for (const row of FAULT_PRECEDENCE) {
      const outcome = classifyRestore(cleanObservation({ faults: [row.fault] }));
      expect(outcome.result).toBe(row.result);
      expect(outcome.stage).toBe(row.phase);
      expect(outcome.exposed).toBe(false);
    }
  });

  test('a fault set resolves by phase order regardless of the order it is given in', () => {
    const faults = [
      'unexpectedValidatorCondition',
      'lockUnavailable',
      'selectorAuthenticationFailed',
      'buildNotListed',
    ];
    const expected = classifyRestore(cleanObservation({ faults: ['lockUnavailable'] }));
    for (const permutation of [
      faults,
      [...faults].reverse(),
      [faults[2], faults[0], faults[3], faults[1]],
      [faults[1], faults[3], faults[2], faults[0]],
    ]) {
      const outcome = classifyRestore(cleanObservation({ faults: permutation }));
      expect(outcome.result).toBe(expected.result);
      expect(outcome.stage).toBe(expected.stage);
    }
  });

  test('a later-phase fault is never promoted above an earlier-phase fault', () => {
    const outcome = classifyRestore(cleanObservation({ faults: ['manifestOrRootMismatch', 'lockUnavailable'] }));
    expect(outcome.result).toBe('LOCKED_ELSEWHERE');
    expect(outcome.stage).toBe('LOCK');
  });

  test('an unknown fault name resolves fail-closed, never to a success', () => {
    const outcome = classifyRestore(cleanObservation({ faults: ['noSuchFault'] }));
    expect(outcome.result).toBe('INTERNAL_VALIDATION_FAILED');
    expect(outcome.stage).toBe('CLASSIFY');
    expect(outcome.exposed).toBe(false);
  });

  test('a duplicated fault is idempotent and a repeated classification is byte-identical', () => {
    const first = classifyRestore(cleanObservation({ faults: ['manifestOrRootMismatch', 'manifestOrRootMismatch'] }));
    const second = classifyRestore(cleanObservation({ faults: ['manifestOrRootMismatch'] }));
    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
  });
});

// ---------------------------------------------------------------------------------------------
describe('fail-closed observation validation', () => {
  const bad = (value) => classifyRestore(value).result;

  test('a non-object observation is INTERNAL_VALIDATION_FAILED at CLASSIFY', () => {
    for (const value of [null, undefined, 0, 1n, 'M2', true, [], () => {}]) {
      expect(bad(value)).toBe('INTERNAL_VALIDATION_FAILED');
    }
    expect(classifyRestore(null).stage).toBe('CLASSIFY');
  });

  test('an unknown, missing, extra or overlapping member rejects', () => {
    expect(bad(cleanObservation({ extra: 1 }))).toBe('INTERNAL_VALIDATION_FAILED');
    const missing = cleanObservation();
    delete missing.vector;
    expect(bad(missing)).toBe('INTERNAL_VALIDATION_FAILED');
    expect(bad(cleanObservation({ faults: undefined }))).toBe('INTERNAL_VALIDATION_FAILED');
  });

  test('a non-closed prototype or a non-plain object rejects', () => {
    class Observation {}
    const instance = new Observation();
    Object.assign(instance, ACTIVE_OBSERVATION);
    expect(bad(instance)).toBe('INTERNAL_VALIDATION_FAILED');
    expect(bad(new Map(Object.entries(ACTIVE_OBSERVATION)))).toBe('INTERNAL_VALIDATION_FAILED');
    expect(bad(Object.assign(Object.create(null), ACTIVE_OBSERVATION))).toBe('INTERNAL_VALIDATION_FAILED');
  });

  test('an out-of-type or out-of-set member rejects', () => {
    expect(bad(cleanObservation({ faults: 'lockUnavailable' }))).toBe('INTERNAL_VALIDATION_FAILED');
    expect(bad(cleanObservation({ faults: [1] }))).toBe('INTERNAL_VALIDATION_FAILED');
    expect(bad(cleanObservation({ inventory: 'M1' }))).toBe('INTERNAL_VALIDATION_FAILED');
    expect(bad(cleanObservation({ selectorState: 'UNKNOWN' }))).toBe('INTERNAL_VALIDATION_FAILED');
    expect(bad(cleanObservation({ legacy: 'true' }))).toBe('INTERNAL_VALIDATION_FAILED');
    expect(bad(cleanObservation({ vector: 7 }))).toBe('INTERNAL_VALIDATION_FAILED');
  });

  test('impossible positive combinations fail closed instead of returning a result', () => {
    expect(bad(cleanObservation({ inventory: 'NONE', legacy: true }))).toBe('INTERNAL_VALIDATION_FAILED');
    expect(bad(cleanObservation({ inventory: 'LEGACY_ONLY', legacy: false }))).toBe('INTERNAL_VALIDATION_FAILED');
  });

  test('classification mutates nothing and returns a frozen value', () => {
    const observation = cleanObservation({ faults: ['selectorAuthenticationFailed'] });
    const before = JSON.stringify(observation);
    const outcome = classifyRestore(observation);
    expect(JSON.stringify(observation)).toBe(before);
    expect(Object.isFrozen(outcome)).toBe(true);
    expect(Object.isFrozen(outcome.diagnostics)).toBe(true);
    expect(() => { outcome.result = 'RESTORED_ACTIVE'; }).toThrow();
  });

  test('diagnostics carry only allowlisted members, never a forbidden token', () => {
    const outcome = classifyRestore(cleanObservation({ faults: ['recordAuthenticationFailed'] }));
    expect(Object.keys(outcome.diagnostics).sort()).toEqual([...DIAGNOSTIC_ALLOWED].sort());
    const serialized = JSON.stringify(outcome);
    for (const forbidden of DIAGNOSTIC_FORBIDDEN) {
      expect(serialized).not.toContain(forbidden);
    }
    expect(outcome.diagnostics.stageCode).toBe('RECORD_DECODE');
    expect(outcome.diagnostics.reasonCode).toBe('AUTHENTICATION_FAILED');
  });
});

// ---------------------------------------------------------------------------------------------
describe('version and pin drift (closed allowlist)', () => {
  test('the exact eight C-FMT versions are accepted', () => {
    expect(checkVersions({ ...VERSIONS })).toBeNull();
    expect(Object.keys(VERSIONS)).toHaveLength(8);
  });

  test('every single-version drift is UNSUPPORTED_VERSION - never a range or a downgrade', () => {
    for (const name of Object.keys(VERSIONS)) {
      const forward = { ...VERSIONS, [name]: VERSIONS[name] + 1 };
      const backward = { ...VERSIONS, [name]: VERSIONS[name] - 1 };
      expect(checkVersions(forward)).toBe('UNSUPPORTED_VERSION');
      expect(checkVersions(backward)).toBe('UNSUPPORTED_VERSION');
    }
  });

  test('a missing, extra, reordered, non-integer or mixed version set rejects', () => {
    const missing = { ...VERSIONS };
    delete missing.manifest;
    expect(checkVersions(missing)).toBe('UNSUPPORTED_VERSION');
    expect(checkVersions({ ...VERSIONS, futureVersion: 1 })).toBe('UNSUPPORTED_VERSION');
    expect(checkVersions({ ...VERSIONS, format: '1' })).toBe('UNSUPPORTED_VERSION');
    expect(checkVersions({ format: 1 })).toBe('UNSUPPORTED_VERSION');
    expect(checkVersions(null)).toBe('UNSUPPORTED_VERSION');
    expect(checkVersions({ ...VERSIONS, format: 2, envelope: 2 })).toBe('UNSUPPORTED_VERSION');
  });

  test('an unknown key version is REJECT', () => {
    expect(checkVersions({ ...VERSIONS, keyVersion: 2 })).toBe('UNSUPPORTED_VERSION');
  });
});

// ---------------------------------------------------------------------------------------------
describe('build eligibility (one complete buildMatrix row)', () => {
  test('both listed rows are eligible', () => {
    for (const row of BUILD_MATRIX) {
      expect(checkBuildEligibility(clone(row))).toBe(true);
    }
  });

  test('every single-field drift of a complete row is ineligible', () => {
    const fields = [
      'readerProfile', 'cFmtDocumentSha256', 'openMlsRevision', 'wasmArtifactPath',
      'wasmArtifactSha256', 'ss0GateADecisionsSha256', 'buildId', 'runtimeClass', 'browserClass',
    ];
    for (const field of fields) {
      const built = goodBuild();
      built[field] = `${built[field]}-drift`;
      expect(checkBuildEligibility(built)).toBe(false);
    }
    const ciphersuite = goodBuild();
    ciphersuite.ss0Ciphersuite.name = 'MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519';
    expect(checkBuildEligibility(ciphersuite)).toBe(false);
    const version = goodBuild();
    version.versions.format = 2;
    expect(checkBuildEligibility(version)).toBe(false);
  });

  test('a partial, extra, non-object or unlisted row is ineligible', () => {
    const partial = goodBuild();
    delete partial.wasmArtifactSha256;
    expect(checkBuildEligibility(partial)).toBe(false);
    expect(checkBuildEligibility({ ...goodBuild(), extra: 1 })).toBe(false);
    expect(checkBuildEligibility(null)).toBe(false);
    expect(checkBuildEligibility('M2_WEB_CHROMIUM_STANDARD')).toBe(false);
    expect(checkBuildEligibility({})).toBe(false);
  });

  test('an unlisted runtime class or browser class is ineligible although it looks close', () => {
    const mobile = goodBuild();
    mobile.runtimeClass = 'MOBILE';
    expect(checkBuildEligibility(mobile)).toBe(false);
    const privateBrowsing = goodBuild();
    privateBrowsing.runtimeClass = 'PRIVATE_BROWSING';
    expect(checkBuildEligibility(privateBrowsing)).toBe(false);
    const safari = goodBuild();
    safari.browserClass = 'SAFARI';
    expect(checkBuildEligibility(safari)).toBe(false);
    expect(UNSUPPORTED_RUNTIME_CLASSES).toEqual([
      'MOBILE', 'NATIVE_NON_BROWSER', 'PRIVATE_BROWSING', 'EVICTED_OR_PARTIAL_PROFILE',
    ]);
  });

  test('the unlisted build is INCOMPATIBLE_BUILD at BUILD_ELIGIBILITY', () => {
    const outcome = classifyRestore(cleanObservation({ faults: ['buildNotListed'] }));
    expect(outcome.result).toBe('INCOMPATIBLE_BUILD');
    expect(outcome.stage).toBe('BUILD_ELIGIBILITY');
  });
});

// ---------------------------------------------------------------------------------------------
describe('authenticated compatibility', () => {
  const base = () => ({
    versions: { ...VERSIONS },
    profile: { readerProfile: READER_PROFILE, algorithms: { ...ALGORITHMS } },
  });

  test('the exact conjunction is accepted', () => {
    expect(checkAuthenticatedCompatibility(base())).toBeNull();
  });

  test('version mismatch precedes other profile mismatch and is UNSUPPORTED_VERSION', () => {
    const value = base();
    value.versions.format = 2;
    value.profile.readerProfile = 'CFMT_OTHER';
    expect(checkAuthenticatedCompatibility(value)).toBe('UNSUPPORTED_VERSION');
  });

  test('a non-version profile mismatch is INCOMPATIBLE_FORMAT', () => {
    const drifted = base();
    drifted.profile.readerProfile = 'CFMT_EXACT_OTHER';
    expect(checkAuthenticatedCompatibility(drifted)).toBe('INCOMPATIBLE_FORMAT');
    const algorithm = base();
    algorithm.profile.algorithms.recordAead = 'AES-128-GCM';
    expect(checkAuthenticatedCompatibility(algorithm)).toBe('INCOMPATIBLE_FORMAT');
    const label = base();
    label.profile.algorithms.kdf = 'HKDF-SHA-512';
    expect(checkAuthenticatedCompatibility(label)).toBe('INCOMPATIBLE_FORMAT');
    expect(checkAuthenticatedCompatibility(null)).toBe('UNSUPPORTED_VERSION');
  });

  test('the two compatibility faults classify at AUTHENTICATED_COMPATIBILITY', () => {
    expect(classifyRestore(cleanObservation({ faults: ['authenticatedVersionUnknownOrMixed'] })).result)
      .toBe('UNSUPPORTED_VERSION');
    expect(classifyRestore(cleanObservation({ faults: ['authenticatedProfileIncompatible'] })).result)
      .toBe('INCOMPATIBLE_FORMAT');
    expect(classifyRestore(cleanObservation({ faults: ['authenticatedProfileIncompatible'] })).stage)
      .toBe('AUTHENTICATED_COMPATIBILITY');
  });
});

// ---------------------------------------------------------------------------------------------
describe('reconciliation candidate and physical parent (I-ROOT obligation)', () => {
  test('a complete, physically consistent candidate validates and is never authority', () => {
    const verified = validateReconciliationCandidate(goodCandidateFacts());
    expect(verified.bindingProfileVerified).toBe(true);
    expect(verified.authority).toBe(false);
    expect(Object.isFrozen(verified)).toBe(true);
  });

  test('the candidate binding digest must equal the candidate generation own BINDING_PROFILE', () => {
    const facts = goodCandidateFacts();
    facts.candidate.manifestBindingDigest = bytes(0x91);
    expectRejection(() => validateReconciliationCandidate(facts), 'REFERENCE_INCONSISTENT', 'REFERENCES');
    const otherGeneration = goodCandidateFacts();
    otherGeneration.candidateBindingProfile.generation = 8n;
    expectRejection(() => validateReconciliationCandidate(otherGeneration), 'REFERENCE_INCONSISTENT', 'REFERENCES');
    const absentProfile = goodCandidateFacts();
    absentProfile.candidateBindingProfile = null;
    expectRejection(() => validateReconciliationCandidate(absentProfile), 'REFERENCE_INCONSISTENT', 'REFERENCES');
  });

  test('the locator must be the canonical kind-16 key with empty object ID and pre-session scope', () => {
    const kind = goodCandidateFacts();
    kind.locator.recordKind = 17;
    expectRejection(() => validateReconciliationCandidate(kind), 'RECORD_INVALID', 'RECORD_DECODE');
    const objectId = goodCandidateFacts();
    objectId.locator.objectIdLength = 16;
    expectRejection(() => validateReconciliationCandidate(objectId), 'RECORD_INVALID', 'RECORD_DECODE');
    const session = goodCandidateFacts();
    session.locator.scope = 'SESSION';
    session.locator.secureSessionIdentity = bytes(0x71);
    expectRejection(() => validateReconciliationCandidate(session), 'RECORD_INVALID', 'RECORD_DECODE');
  });

  test('a locator generation, context or key digest that differs from the candidate rejects', () => {
    const generation = goodCandidateFacts();
    generation.locator.generation = 8n;
    expectRejection(() => validateReconciliationCandidate(generation), 'REFERENCE_INCONSISTENT', 'REFERENCES');
    const context = goodCandidateFacts();
    context.locator.localContextId = bytes(0x12);
    expectRejection(() => validateReconciliationCandidate(context), 'REFERENCE_INCONSISTENT', 'REFERENCES');
    const digest = goodCandidateFacts();
    digest.locator.sha256 = bytes(0x22);
    expectRejection(() => validateReconciliationCandidate(digest), 'REFERENCE_INCONSISTENT', 'REFERENCES');
  });

  test('the candidate manifest digests and keyed root must match the selector tuple', () => {
    const digest = goodCandidateFacts();
    digest.candidate.manifestCiphertextDigest = bytes(0x32);
    expectRejection(() => validateReconciliationCandidate(digest), 'REFERENCE_INCONSISTENT', 'REFERENCES');
    const root = goodCandidateFacts();
    root.candidate.keyedRoot = bytes(0x42);
    expectRejection(() => validateReconciliationCandidate(root), 'REFERENCE_INCONSISTENT', 'REFERENCES');
  });

  test('an unresolved hold must name the selector generation and keyed root as physical parent', () => {
    const parent = goodCandidateFacts();
    parent.candidate.parentGeneration = 5n;
    expectRejection(() => validateReconciliationCandidate(parent), 'REFERENCE_INCONSISTENT', 'REFERENCES');
    const parentRoot = goodCandidateFacts();
    parentRoot.candidate.parentKeyedRoot = bytes(0x52);
    expectRejection(() => validateReconciliationCandidate(parentRoot), 'REFERENCE_INCONSISTENT', 'REFERENCES');
  });

  test('logical original-authority identifiers must match each other, never the parent', () => {
    const mismatch = goodCandidateFacts();
    mismatch.candidate.originalAuthorityReference = bytes(0x62);
    expectRejection(() => validateReconciliationCandidate(mismatch), 'REFERENCE_INCONSISTENT', 'REFERENCES');
    const parentEqual = goodCandidateFacts();
    parentEqual.candidate.originalAuthorityDigest = bytes(0x51);
    parentEqual.candidate.originalAuthorityReference = bytes(0x51);
    expect(() => validateReconciliationCandidate(parentEqual)).not.toThrow();
  });

  test('a candidate equal to the selected generation during reconciliation rejects', () => {
    const facts = goodCandidateFacts();
    facts.candidateEqualsSelected = true;
    expectRejection(() => validateReconciliationCandidate(facts), 'REFERENCE_INCONSISTENT', 'REFERENCES');
  });

  test('candidate fields differing without RECONCILIATION_REQUIRED reject', () => {
    const facts = goodCandidateFacts();
    facts.selectorState = 'ACTIVE';
    facts.candidateEqualsSelected = false;
    expectRejection(() => validateReconciliationCandidate(facts), 'REFERENCE_INCONSISTENT', 'REFERENCES');
  });

  test('a malformed candidate fact set fails closed', () => {
    expectRejection(() => validateReconciliationCandidate(null), 'INTERNAL_VALIDATION_FAILED', 'CLASSIFY');
    expectRejection(() => validateReconciliationCandidate({}), 'INTERNAL_VALIDATION_FAILED', 'CLASSIFY');
    const facts = goodCandidateFacts();
    facts.locator = null;
    expectRejection(() => validateReconciliationCandidate(facts), 'INTERNAL_VALIDATION_FAILED', 'CLASSIFY');
  });

  test('the five candidate faults classify to their exact C-REST rows', () => {
    const rows = [
      ['candidateManifestKeyScopeSessionSubstitution', 'RECORD_INVALID', 'RECORD_DECODE'],
      ['candidateManifestKeyMismatch', 'REFERENCE_INCONSISTENT', 'REFERENCES'],
      ['candidateParentMismatch', 'REFERENCE_INCONSISTENT', 'REFERENCES'],
      ['candidateEqualsSelectedDuringReconciliation', 'REFERENCE_INCONSISTENT', 'REFERENCES'],
      ['candidateFieldsDifferWithoutReconciliation', 'REFERENCE_INCONSISTENT', 'REFERENCES'],
    ];
    for (const [fault, result, phase] of rows) {
      const outcome = classifyRestore(cleanObservation({ faults: [fault] }));
      expect(outcome.result).toBe(result);
      expect(outcome.stage).toBe(phase);
    }
  });
});

// ---------------------------------------------------------------------------------------------
describe('value registries and non-claims', () => {
  test('the copied C-FMT value sets are exactly the closed sets', () => {
    expect(VALUE_REGISTRIES.commitOutcome).toEqual({ COMMITTED: 1, NOT_COMMITTED: 2, INDETERMINATE: 3 });
    expect(VALUE_REGISTRIES.selectorState).toEqual({ EMPTY: 1, ACTIVE: 2, RECONCILIATION_REQUIRED: 3 });
    expect(Object.keys(VALUE_REGISTRIES.operation)).toHaveLength(8);
    expect(Object.keys(VALUE_REGISTRIES.keyPackageLifecycle)).toEqual(
      ['UNCONSUMED', 'RESERVED', 'CONSUMED', 'INVALID'],
    );
  });

  test('the diagnostics member names are the five allowlisted names', () => {
    expect([...DIAGNOSTIC_ALLOWED]).toEqual(
      ['stageCode', 'reasonCode', 'm2LocatorCount', 'm2ArtifactCount', 'legacyPresent'],
    );
    expect(DIAGNOSTIC_FORBIDDEN).toHaveLength(10);
  });
});

// ---------------------------------------------------------------------------------------------
describe('property tests (seeded, reproducible)', () => {
  const resultSet = new Set([...INVENTORY_RESULTS, ...SUCCESS_RESULTS, ...FAILURE_RESULTS]);
  const faultNames = FAULT_PRECEDENCE.map((row) => row.fault);
  const observationArbitrary = fc.record({
    faults: fc.array(fc.constantFrom(...faultNames), { maxLength: 5 }),
    inventory: fc.constantFrom('NONE', 'LEGACY_ONLY', 'M2'),
    legacy: fc.boolean(),
    vector: fc.constantFrom(null, 'FMT-KAT-EMPTY', 'FMT-KAT-ACTIVE', 'FMT-KAT-HOLD', 'FMT-KAT-EMPTY-HOLD'),
    selectorState: fc.constantFrom('EMPTY', 'ACTIVE', 'RECONCILIATION_REQUIRED'),
  });

  test('any observation classifies to a closed result or the fail-closed default, never throwing', () => {
    fc.assert(fc.property(observationArbitrary, (observation) => {
      const outcome = classifyRestore(observation);
      expect(resultSet.has(outcome.result)).toBe(true);
      expect(PHASES).toContain(outcome.stage);
      expect(Object.isFrozen(outcome)).toBe(true);
      if (outcome.exposed === true) {
        expect(SUCCESS_RESULTS).toContain(outcome.result);
        expect(outcome.stage).toBe('EXPOSE');
      }
    }), { numRuns: 400, seed: 20261002 });
  });

  test('a mutated observation never yields a success that the fault set forbids', () => {
    fc.assert(fc.property(
      observationArbitrary,
      fc.string({ maxLength: 8 }),
      (observation, junk) => {
        const mutated = { ...observation, version: junk };
        const outcome = classifyRestore(mutated);
        expect(outcome.result).toBe(FAILURE_DEFAULT);
        expect(outcome.stage).toBe('CLASSIFY');
      },
    ), { numRuns: 200, seed: 20261003 });
  });

  test('the same seed replays to identical outcomes', () => {
    const run = () => {
      const outcomes = [];
      fc.assert(fc.property(observationArbitrary, (observation) => {
        outcomes.push(JSON.stringify(classifyRestore(observation)));
      }), { numRuns: 60, seed: 20261004 });
      return outcomes;
    };
    expect(run()).toEqual(run());
  });
});
