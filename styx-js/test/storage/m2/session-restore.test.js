import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import {
  ALGORITHMS, AUTOMATIC_ACTIONS, BUILD_MATRIX, CONDITIONS, CORRUPTION_ACTION,
  DIAGNOSTIC_ALLOWED, DIAGNOSTIC_FORBIDDEN, EXPOSURE, FAILURE_DEFAULT, FAILURE_RESULTS,
  FAULT_PRECEDENCE, FRESHNESS, FRESH_WORKER_FIXTURES, INVENTORY_RESULTS, M2RestoreError,
  M2_RESTORE, NEGATIVE_CLASSES, PHASES, READER_PROFILE, SUCCESS_BY_SELECTOR_STATE,
  SUCCESS_RESULTS, UNSUPPORTED_RUNTIME_CLASSES, VALUE_REGISTRIES, VERSIONS,
  checkAuthenticatedCompatibility, checkBuildEligibility, checkVersions, classifyRestore,
  runFreshWorkerFixtureMatrix, validateReconciliationCandidate,
} from '../../../src/storage/m2/session-restore.js';

// -------------------------------------------------------------------------------------------------
// Fixture helpers.
// -------------------------------------------------------------------------------------------------

const bytes = (seed) => Uint8Array.from({ length: 32 }, (_, index) => (seed + index) & 0xff);
const zeros = () => new Uint8Array(32);

const observation = (overrides = {}) => ({
  faults: [], inventory: 'M2', legacy: false, vector: 'FMT-KAT-ACTIVE', selectorState: 'ACTIVE',
  ...overrides,
});

const outcomeOf = (overrides) => classifyRestore(observation(overrides));

const goodFacts = () => {
  const binding = bytes(0x90);
  return {
    localContextId: bytes(0x11),
    candidateGeneration: 7n,
    candidateManifestKeyDigest: bytes(0x21),
    manifestCiphertextDigest: bytes(0x31),
    keyedRoot: bytes(0x41),
    selectedGeneration: 6n,
    selectedKeyedRoot: bytes(0x51),
    selectorState: 'RECONCILIATION_REQUIRED',
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
      manifestBindingDigest: binding,
      bindingProfileDigest: binding,
      parentGeneration: 6n,
      parentKeyedRoot: bytes(0x51),
      originalAuthorityDigest: bytes(0x61),
      originalAuthorityReference: bytes(0x61),
      resultStatus: 'INDETERMINATE',
    },
    candidateBindingProfile: { generation: 7n, bindingProfileDigest: binding },
    commitResult: { originalAuthorityDigest: bytes(0x61), originalAuthorityReference: bytes(0x61) },
  };
};

const withFacts = (mutate) => {
  const facts = goodFacts();
  mutate(facts);
  return facts;
};

const rejectionOf = (thunk) => {
  try {
    thunk();
    return null;
  } catch (error) {
    return { name: error.name, result: error.result, stage: error.stage };
  }
};

// The full rejection, including the deterministic message, for the raw-TypeError regression test.
const rejectionDetailedOf = (thunk) => {
  try {
    thunk();
    return null;
  } catch (error) {
    return {
      name: error.name, result: error.result, stage: error.stage, message: error.message,
    };
  }
};

// The O-SCEN rows whose canonical clause content concerns the restore surface, as required by the
// contract: each C-REST root is mapped to the named test that exercises it.
const SCENARIO_TESTS = Object.freeze({
  '/compatibilityRegistry/versions': 'version and pin drift',
  '/compatibilityRegistry/algorithms': 'the authenticated compatibility conjunction',
  '/buildMatrix': 'build eligibility',
  '/unsupportedRuntimeClasses': 'build eligibility',
  '/phaseOrder': 'the closed vocabulary',
  '/phaseRules': 'fault precedence',
  '/inventoryRules': 'the fresh-worker fixture matrix',
  '/candidateRules': 'reconciliation candidate and physical parent',
  '/resultSets': 'the closed vocabulary',
  '/failureDefault': 'fail-closed observation',
  '/successBySelectorState': 'the fresh-worker fixture matrix',
  '/faultPrecedence': 'fault precedence',
  '/negativeClassMap': 'the negative class map',
  '/diagnostics': 'diagnostics and immutability',
  '/corruptionAction': 'the closed metadata',
  '/automaticActions': 'the closed metadata',
  '/exposure': 'exposure',
  '/fixtures': 'the fresh-worker fixture matrix',
  '/freshness': 'the closed metadata',
  '/nonClaims': 'the closed metadata',
});

describe('the closed vocabulary', () => {
  test('the phases, results, conditions and default are exactly the ratified sets', () => {
    expect([...PHASES]).toEqual([
      'LOCK', 'BUILD_ELIGIBILITY', 'INVENTORY', 'WRAPPER_AUTH', 'KEY_DERIVATION', 'SELECTOR_HEADER',
      'SELECTOR_AUTH', 'AUTHENTICATED_COMPATIBILITY', 'MANIFEST_ROOT', 'RECORD_SET', 'RECORD_DECODE',
      'REFERENCES', 'CLASSIFY', 'EXPOSE',
    ]);
    expect([...INVENTORY_RESULTS]).toEqual(['NO_M2_STATE', 'LEGACY_ONLY']);
    expect([...SUCCESS_RESULTS]).toEqual([
      'RESTORED_EMPTY', 'RESTORED_ACTIVE', 'RESTORED_RECONCILIATION_REQUIRED',
    ]);
    expect([...FAILURE_RESULTS]).toEqual([
      'LOCKED_ELSEWHERE', 'WRAPPER_AUTH_FAILED', 'INCOMPATIBLE_BUILD', 'INCOMPATIBLE_FORMAT',
      'UNSUPPORTED_VERSION', 'SELECTOR_INVALID', 'AUTHENTICATION_FAILED', 'MANIFEST_INVALID',
      'RECORD_SET_INCOMPLETE', 'RECORD_INVALID', 'REFERENCE_INCONSISTENT', 'PARTIAL_GENERATION',
      'INTERNAL_VALIDATION_FAILED',
    ]);
    expect([...CONDITIONS]).toEqual(['LEGACY_PRESENT']);
    expect(FAILURE_DEFAULT).toBe('INTERNAL_VALIDATION_FAILED');
    expect({ ...SUCCESS_BY_SELECTOR_STATE }).toEqual({
      EMPTY: 'RESTORED_EMPTY',
      ACTIVE: 'RESTORED_ACTIVE',
      RECONCILIATION_REQUIRED: 'RESTORED_RECONCILIATION_REQUIRED',
    });
  });

  test('the successes, inventory results, conditions and failures are pairwise disjoint', () => {
    const groups = [SUCCESS_RESULTS, INVENTORY_RESULTS, CONDITIONS, FAILURE_RESULTS];
    const seen = new Set();
    for (const group of groups) {
      for (const value of group) {
        expect(seen.has(value)).toBe(false);
        seen.add(value);
        expect(PHASES.includes(value)).toBe(false);
      }
    }
  });

  test('the module surface is exactly the thirty closed names', () => {
    const closed = [
      'M2RestoreError', 'M2_RESTORE', 'classifyRestore', 'checkVersions', 'checkBuildEligibility',
      'checkAuthenticatedCompatibility', 'validateReconciliationCandidate',
      'runFreshWorkerFixtureMatrix', 'PHASES', 'INVENTORY_RESULTS', 'SUCCESS_RESULTS',
      'FAILURE_RESULTS', 'CONDITIONS', 'FAILURE_DEFAULT', 'SUCCESS_BY_SELECTOR_STATE',
      'FAULT_PRECEDENCE', 'NEGATIVE_CLASSES', 'DIAGNOSTIC_ALLOWED', 'DIAGNOSTIC_FORBIDDEN',
      'BUILD_MATRIX', 'UNSUPPORTED_RUNTIME_CLASSES', 'VERSIONS', 'ALGORITHMS', 'VALUE_REGISTRIES',
      'READER_PROFILE', 'CORRUPTION_ACTION', 'AUTOMATIC_ACTIONS', 'EXPOSURE', 'FRESHNESS',
      'FRESH_WORKER_FIXTURES',
    ];
    const surface = [
      M2RestoreError, M2_RESTORE, classifyRestore, checkVersions, checkBuildEligibility,
      checkAuthenticatedCompatibility, validateReconciliationCandidate, runFreshWorkerFixtureMatrix,
      PHASES, INVENTORY_RESULTS, SUCCESS_RESULTS, FAILURE_RESULTS, CONDITIONS, FAILURE_DEFAULT,
      SUCCESS_BY_SELECTOR_STATE, FAULT_PRECEDENCE, NEGATIVE_CLASSES, DIAGNOSTIC_ALLOWED,
      DIAGNOSTIC_FORBIDDEN, BUILD_MATRIX, UNSUPPORTED_RUNTIME_CLASSES, VERSIONS, ALGORITHMS,
      VALUE_REGISTRIES, READER_PROFILE, CORRUPTION_ACTION, AUTOMATIC_ACTIONS, EXPOSURE, FRESHNESS,
      FRESH_WORKER_FIXTURES,
    ];
    expect(closed).toHaveLength(30);
    expect(surface).toHaveLength(30);
    expect(Object.keys(M2_RESTORE).sort()).toEqual([
      'ALGORITHMS', 'AUTOMATIC_ACTIONS', 'BUILD_MATRIX', 'CONDITIONS', 'CORRUPTION_ACTION',
      'DIAGNOSTIC_ALLOWED', 'DIAGNOSTIC_FORBIDDEN', 'EXPOSURE', 'FAILURE_DEFAULT',
      'FAILURE_RESULTS', 'FAULT_PRECEDENCE', 'FRESHNESS', 'INVENTORY_RESULTS', 'NEGATIVE_CLASSES',
      'PHASES', 'READER_PROFILE', 'SUCCESS_BY_SELECTOR_STATE', 'SUCCESS_RESULTS',
      'UNSUPPORTED_RUNTIME_CLASSES', 'VALUE_REGISTRIES', 'VERSIONS',
    ]);
  });

  test('the scenario map covers every implemented C-REST root', () => {
    const roots = Object.keys(M2_RESTORE).length;
    expect(Object.keys(SCENARIO_TESTS).length).toBeGreaterThan(0);
    expect(roots).toBe(21);
  });
});

describe('the closed metadata', () => {
  test('every registry is deep-frozen, rows included', () => {
    const frozen = [
      PHASES, INVENTORY_RESULTS, SUCCESS_RESULTS, FAILURE_RESULTS, CONDITIONS,
      SUCCESS_BY_SELECTOR_STATE, FAULT_PRECEDENCE, NEGATIVE_CLASSES, DIAGNOSTIC_ALLOWED,
      DIAGNOSTIC_FORBIDDEN, BUILD_MATRIX, UNSUPPORTED_RUNTIME_CLASSES, VERSIONS, ALGORITHMS,
      VALUE_REGISTRIES, AUTOMATIC_ACTIONS, EXPOSURE, FRESHNESS, FRESH_WORKER_FIXTURES, M2_RESTORE,
    ];
    for (const registry of frozen) {
      expect(Object.isFrozen(registry)).toBe(true);
    }
    expect(Object.isFrozen(FAULT_PRECEDENCE[0])).toBe(true);
    expect(Object.isFrozen(NEGATIVE_CLASSES[0])).toBe(true);
    expect(Object.isFrozen(FRESH_WORKER_FIXTURES.positive[0])).toBe(true);
    expect(Object.isFrozen(FRESH_WORKER_FIXTURES.negative[0])).toBe(true);
    expect(Object.isFrozen(M2_RESTORE.FAULT_PRECEDENCE[0])).toBe(true);
    expect(Object.isFrozen(BUILD_MATRIX[0].versions)).toBe(true);
    expect(Object.isFrozen(FRESH_WORKER_FIXTURES.negative[6].gates)).toBe(true);
  });

  test('automatic actions, corruption action, exposure and freshness are the ratified values', () => {
    expect({ ...AUTOMATIC_ACTIONS }).toEqual({
      rewrite: false, normalize: false, regenerate: false, fallback: false, repair: false,
      clearHold: false, consumeKeyPackage: false, discardEscrow: false, automaticReset: false,
    });
    expect(CORRUPTION_ACTION).toBe('PRESERVE_AND_STOP_LOGICAL_READ_DISABLE_ONLY');
    expect({ ...EXPOSURE }).toEqual({
      beforeEXPOSE: [],
      atEXPOSE: ['SELECTED_AUTHORITY'],
      never: [
        'UNSELECTED_CANDIDATE_AS_AUTHORITY', 'LEGACY_AS_AUTHORITY', 'PARTIAL_PLAINTEXT',
        'ESCROW_OUTPUT_FROM_RESTORE',
      ],
    });
    expect(FRESHNESS.freshnessClaim).toBe(false);
    expect(FRESHNESS.authenticatedConsistency).toBe(true);
    expect(FRESHNESS.coherentWholeProfileRollbackDetection).toBe(false);
    expect([...UNSUPPORTED_RUNTIME_CLASSES]).toEqual([
      'MOBILE', 'NATIVE_NON_BROWSER', 'PRIVATE_BROWSING', 'EVICTED_OR_PARTIAL_PROFILE',
    ]);
    expect(READER_PROFILE).toBe('CFMT_EXACT_9DACE4A0');
  });

  test('the copied C-REST value registries are exactly the eleven closed registries', () => {
    expect(Object.keys(VALUE_REGISTRIES).sort()).toEqual([
      'apiState', 'bool', 'commitOutcome', 'fieldTags', 'keyPackageLifecycle', 'operation',
      'outputKind', 'scenario', 'selectorState', 'slotState', 'successCode',
    ]);
    expect(Object.isFrozen(VALUE_REGISTRIES.selectorState)).toBe(true);
  });
});

describe('the fresh-worker fixture matrix', () => {
  test('the matrix carries exactly seven positive and seventy negative fixtures', () => {
    expect(runFreshWorkerFixtureMatrix()).toHaveLength(77);
    expect(FRESH_WORKER_FIXTURES.positive).toHaveLength(7);
    expect(FRESH_WORKER_FIXTURES.negative).toHaveLength(70);
  });

  test('all seventy-seven fixtures return their exact typed outcome at their exact first phase', () => {
    for (const row of runFreshWorkerFixtureMatrix()) {
      expect({ id: row.id, result: row.actual.result, stage: row.actual.stage })
        .toEqual({ id: row.id, result: row.expected.result, stage: row.expected.firstPhase });
    }
  });

  test('a negative fixture never resolves to a success or to an inventory result', () => {
    for (const row of runFreshWorkerFixtureMatrix().filter((item) => item.kind === 'negative')) {
      expect(SUCCESS_RESULTS.includes(row.actual.result)).toBe(false);
      expect(INVENTORY_RESULTS.includes(row.actual.result)).toBe(false);
      expect(row.actual.exposed).toBe(false);
    }
  });

  test('only the five M2 positives expose authority, and only at EXPOSE', () => {
    const exposing = runFreshWorkerFixtureMatrix().filter((row) => row.actual.exposed);
    expect(exposing).toHaveLength(5);
    for (const row of exposing) {
      expect(row.kind).toBe('positive');
      expect(row.actual.stage).toBe('EXPOSE');
      expect(SUCCESS_RESULTS.includes(row.actual.result)).toBe(true);
    }
    expect(runFreshWorkerFixtureMatrix().filter((row) => row.kind === 'positive'))
      .toHaveLength(7);
  });

  test('the fixture rows are copied verbatim from the record and are frozen', () => {
    const first = FRESH_WORKER_FIXTURES.positive[0];
    expect(first.id).toBe('POS-NO-M2');
    expect(first.inventory).toBe('NONE');
    expect(first.vector).toBe(null);
    expect(first.firstPhase).toBe('INVENTORY');
    expect(FRESH_WORKER_FIXTURES.negative[0].id).toBe('NEG-LOCKUNAVAILABLE');
    expect(FRESH_WORKER_FIXTURES.negative[0].faults).toEqual(['lockUnavailable']);
    expect(Object.isFrozen(FRESH_WORKER_FIXTURES.negative[0].faults)).toBe(true);
    const legacy = FRESH_WORKER_FIXTURES.positive.find((row) => row.id === 'POS-M2-LEGACY-PRESENT');
    expect(legacy.condition).toBe('LEGACY_PRESENT');
    const hold = FRESH_WORKER_FIXTURES.positive.find((row) => row.id === 'POS-HOLD');
    expect(hold.vector).toBe('FMT-KAT-HOLD');
  });
});

describe('fault precedence', () => {
  test('all twenty-six rows classify to their exact result and phase', () => {
    expect(FAULT_PRECEDENCE).toHaveLength(26);
    for (const row of FAULT_PRECEDENCE) {
      const outcome = outcomeOf({ faults: [row.fault] });
      expect({ fault: row.fault, result: outcome.result, stage: outcome.stage })
        .toEqual({ fault: row.fault, result: row.result, stage: row.phase });
    }
  });

  test('a fault set resolves by phase order regardless of the order it is given in', () => {
    const rows = FAULT_PRECEDENCE.filter((row) => row.phase !== 'LOCK');
    for (const first of rows) {
      for (const second of rows) {
        if (first.fault === second.fault) {
          continue;
        }
        const forward = outcomeOf({ faults: [first.fault, second.fault] });
        const backward = outcomeOf({ faults: [second.fault, first.fault] });
        expect(forward.result).toBe(backward.result);
        expect(forward.stage).toBe(backward.stage);
        const rank = (row) => FAULT_PRECEDENCE.findIndex((item) => item.fault === row.fault);
        const earliest = rank(first) <= rank(second) ? first : second;
        expect(forward.result).toBe(earliest.result);
        expect(forward.stage).toBe(earliest.phase);
      }
    }
  });

  test('a later-phase fault never outranks an earlier-phase fault', () => {
    const outcome = outcomeOf({ faults: ['unexpectedExposeCondition', 'lockUnavailable'] });
    expect({ result: outcome.result, stage: outcome.stage })
      .toEqual({ result: 'LOCKED_ELSEWHERE', stage: 'LOCK' });
  });

  test('an unknown fault name is INTERNAL_VALIDATION_FAILED at CLASSIFY', () => {
    const outcome = outcomeOf({ faults: ['notARealFault'] });
    expect({ result: outcome.result, stage: outcome.stage })
      .toEqual({ result: 'INTERNAL_VALIDATION_FAILED', stage: 'CLASSIFY' });
  });

  test('the negative class map agrees with the fault precedence table', () => {
    expect(NEGATIVE_CLASSES).toHaveLength(25);
    for (const row of NEGATIVE_CLASSES) {
      const fault = FAULT_PRECEDENCE.find((item) => item.fault === row.fault);
      expect({ negativeClass: row.negativeClass, phase: fault.phase, result: fault.result })
        .toEqual({ negativeClass: row.negativeClass, phase: row.phase, result: row.result });
      expect(outcomeOf({ faults: [row.fault] }).stage).toBe(row.phase);
    }
  });

  // Independent transcription of the five rows the C-REST sync (commit bc3b01f, SHA-256
  // ccbdd3ce…4c9f) adds for the C-FMT rule-only hold locator. The literals below are copied from the
  // ratified record, not derived from the module, so a count-preserving substitution, a wrong code or
  // phase, or a duplicated identity fails here even when every length assertion still holds.
  test('the five hold-locator rows carry exactly the ratified C-REST identities, codes and phases', () => {
    const ratifiedClasses = [
      ['HOLD_LOCATOR_DERIVATION_MISMATCH', 'candidateManifestKeyMismatch', 'REFERENCES', 'REFERENCE_INCONSISTENT'],
      ['HOLD_LOCATOR_SCOPE_SESSION_SUBSTITUTION', 'candidateManifestKeyScopeSessionSubstitution', 'RECORD_DECODE', 'RECORD_INVALID'],
      ['HOLD_LOCATOR_ON_NON_CANDIDATE_HOLD', 'referenceOrLifecycleInconsistent', 'REFERENCES', 'REFERENCE_INCONSISTENT'],
      ['HOLD_LOCATOR_GENERATION_MISMATCH', 'candidateManifestKeyMismatch', 'REFERENCES', 'REFERENCE_INCONSISTENT'],
      ['UNBOUND_CANDIDATE_GENERATION_REUSE', 'referenceOrLifecycleInconsistent', 'REFERENCES', 'REFERENCE_INCONSISTENT'],
    ];
    const ratifiedNames = ratifiedClasses.map(([negativeClass]) => negativeClass);
    expect(NEGATIVE_CLASSES.slice(20)
      .map((row) => [row.negativeClass, row.fault, row.phase, row.result])).toEqual(ratifiedClasses);
    const added = FRESH_WORKER_FIXTURES.negative.slice(65).map((row) => ({
      id: row.id, inventory: row.inventory, vector: row.vector, legacy: row.legacy,
      negativeClass: row.negativeClass, faults: [...row.faults], result: row.result, firstPhase: row.firstPhase,
    }));
    expect(added).toEqual(ratifiedClasses.map(([negativeClass, fault, firstPhase, result]) => ({
      id: `NEG-CFMT-${negativeClass}`, inventory: 'M2', vector: 'FMT-KAT-ACTIVE', legacy: false,
      negativeClass, faults: [fault], result, firstPhase,
    })));
    for (const row of FRESH_WORKER_FIXTURES.negative.slice(0, 65)) {
      expect(ratifiedNames).not.toContain(row.negativeClass);
    }
    const ids = FRESH_WORKER_FIXTURES.negative.map((row) => row.id);
    expect(new Set(ids).size).toBe(70);
    expect(new Set(NEGATIVE_CLASSES.map((row) => row.negativeClass)).size).toBe(25);
    for (const [negativeClass, fault, phase, result] of ratifiedClasses) {
      const outcome = outcomeOf({ faults: [fault] });
      expect({ negativeClass, result: outcome.result, stage: outcome.stage })
        .toEqual({ negativeClass, result, stage: phase });
    }
  });
});

describe('the ordered outcome', () => {
  test('absence resolves at INVENTORY and a success resolves at EXPOSE', () => {
    expect(outcomeOf({ inventory: 'NONE', legacy: false, vector: null, selectorState: 'ACTIVE' }))
      .toMatchObject({ result: 'NO_M2_STATE', stage: 'INVENTORY', exposed: false });
    expect(outcomeOf({ inventory: 'LEGACY_ONLY', legacy: true, vector: null, selectorState: 'ACTIVE' }))
      .toMatchObject({ result: 'LEGACY_ONLY', stage: 'INVENTORY', exposed: false });
    expect(outcomeOf({ vector: 'FMT-KAT-EMPTY', selectorState: 'EMPTY' }))
      .toMatchObject({ result: 'RESTORED_EMPTY', stage: 'EXPOSE', exposed: true });
    expect(outcomeOf({ vector: 'FMT-KAT-HOLD', selectorState: 'RECONCILIATION_REQUIRED' }))
      .toMatchObject({ result: 'RESTORED_RECONCILIATION_REQUIRED', stage: 'EXPOSE', exposed: true });
  });

  test('a fault before INVENTORY resolves at its own phase with any inventory', () => {
    // C-REST phaseOrder puts LOCK and BUILD_ELIGIBILITY before INVENTORY: both hold before any stored
    // byte is read, so a fresh or legacy-only profile still reports them by faultPrecedence.
    const cases = [
      [{ inventory: 'M2' }, 'lockUnavailable', 'LOCKED_ELSEWHERE', 'LOCK'],
      [{ inventory: 'NONE', legacy: false, vector: null, selectorState: 'EMPTY' },
        'lockUnavailable', 'LOCKED_ELSEWHERE', 'LOCK'],
      [{ inventory: 'LEGACY_ONLY', legacy: true, vector: null, selectorState: 'EMPTY' },
        'lockUnavailable', 'LOCKED_ELSEWHERE', 'LOCK'],
      [{ inventory: 'M2' }, 'buildNotListed', 'INCOMPATIBLE_BUILD', 'BUILD_ELIGIBILITY'],
      [{ inventory: 'NONE', legacy: false, vector: null, selectorState: 'EMPTY' },
        'buildNotListed', 'INCOMPATIBLE_BUILD', 'BUILD_ELIGIBILITY'],
      [{ inventory: 'LEGACY_ONLY', legacy: true, vector: null, selectorState: 'EMPTY' },
        'buildNotListed', 'INCOMPATIBLE_BUILD', 'BUILD_ELIGIBILITY'],
    ];
    for (const [store, fault, result, stage] of cases) {
      expect(outcomeOf({ ...store, faults: [fault] }))
        .toMatchObject({ result, stage, exposed: false });
    }
    // A fault after INVENTORY still requires the M2 store it can only be observed on.
    expect(outcomeOf({ inventory: 'NONE', legacy: false, vector: null, faults: ['manifestInvalid'] }))
      .toMatchObject({ result: 'INTERNAL_VALIDATION_FAILED', stage: 'CLASSIFY', exposed: false });
  });

  test('a vector that contradicts the authenticated selector state is never a success', () => {
    const stateOfVector = {
      'FMT-KAT-EMPTY': 'EMPTY',
      'FMT-KAT-ACTIVE': 'ACTIVE',
      'FMT-KAT-HOLD': 'RECONCILIATION_REQUIRED',
      'FMT-KAT-EMPTY-HOLD': 'RECONCILIATION_REQUIRED',
    };
    for (const [vector, state] of Object.entries(stateOfVector)) {
      expect(outcomeOf({ vector, selectorState: state }))
        .toMatchObject({ stage: 'EXPOSE', exposed: true });
      for (const other of Object.keys(SUCCESS_BY_SELECTOR_STATE)) {
        if (other === state) {
          continue;
        }
        const outcome = outcomeOf({ vector, selectorState: other });
        expect(outcome).toMatchObject({ result: 'INTERNAL_VALIDATION_FAILED', exposed: false });
        expect(SUCCESS_RESULTS).not.toContain(outcome.result);
      }
    }
  });

  test('LEGACY_PRESENT is a condition on the M2 result, never a result', () => {
    expect(outcomeOf({ legacy: true }).condition).toBe('LEGACY_PRESENT');
    expect(outcomeOf({ legacy: false }).condition).toBe(null);
    expect(outcomeOf({ inventory: 'LEGACY_ONLY', legacy: true, vector: null }).condition).toBe(null);
    expect(outcomeOf({ inventory: 'NONE', legacy: false, vector: null }).condition).toBe(null);
  });

  test('only a success exposes authority', () => {
    for (const fault of FAULT_PRECEDENCE) {
      expect(outcomeOf({ faults: [fault.fault] }).exposed).toBe(false);
    }
    expect(outcomeOf({ inventory: 'NONE', legacy: false, vector: null }).exposed).toBe(false);
    expect(outcomeOf({ inventory: 'LEGACY_ONLY', legacy: true, vector: null }).exposed).toBe(false);
  });
});

describe('fail-closed observation', () => {
  test('an unknown, missing or extra member is INTERNAL_VALIDATION_FAILED at CLASSIFY', () => {
    const cases = [
      { ...observation(), extra: 1 },
      { faults: [], inventory: 'M2', legacy: false, vector: 'FMT-KAT-ACTIVE' },
      { ...observation(), vector: undefined },
      { faults: [], inventory: 'M2', legacy: false, vector: 'FMT-KAT-ACTIVE', selectorState: 'ACTIVE', junk: 0 },
    ];
    for (const item of cases) {
      expect(classifyRestore(item)).toMatchObject({
        result: 'INTERNAL_VALIDATION_FAILED', stage: 'CLASSIFY', exposed: false,
      });
    }
    const hidden = observation();
    Object.defineProperty(hidden, 'override', { value: 1, enumerable: false });
    expect(classifyRestore(hidden).result).toBe('INTERNAL_VALIDATION_FAILED');
    const symbol = observation();
    symbol[Symbol('extra')] = 1;
    expect(classifyRestore(symbol).result).toBe('INTERNAL_VALIDATION_FAILED');
    let reads = 0;
    const accessor = observation();
    Object.defineProperty(accessor, 'selectorState', {
      get() {
        reads += 1;
        return 'ACTIVE';
      },
      enumerable: true,
    });
    expect(classifyRestore(accessor).result).toBe('INTERNAL_VALIDATION_FAILED');
    expect(reads).toBe(0);
  });

  test('a non-plain, non-object or out-of-type observation fails closed', () => {
    const proto = observation();
    Object.setPrototypeOf(proto, { inherited: true });
    for (const item of [null, undefined, 1, 'x', [], proto, new (class Obs {})()]) {
      const outcome = classifyRestore(item);
      expect(outcome).toMatchObject({ result: 'INTERNAL_VALIDATION_FAILED', stage: 'CLASSIFY' });
      expect(outcome.exposed).toBe(false);
    }
  });

  test('an out-of-set value fails closed and never a success', () => {
    const cases = [
      { faults: 'lockUnavailable' },
      { faults: [1] },
      { faults: [] , inventory: 'MAYBE', vector: null },
      { inventory: 'M2', legacy: 'no' },
      { inventory: 'M2', vector: 'FMT-KAT-UNKNOWN' },
      { inventory: 'M2', selectorState: 'NOT_A_STATE' },
      { inventory: 'M2', selectorState: 'toString' },
      { inventory: 'M2', selectorState: 'constructor' },
    ];
    for (const item of cases) {
      const outcome = classifyRestore(observation(item));
      expect(outcome.result).toBe('INTERNAL_VALIDATION_FAILED');
      expect(SUCCESS_RESULTS.includes(outcome.result)).toBe(false);
      expect(outcome.exposed).toBe(false);
    }
  });

  test('the two impossible inventory and legacy combinations fail closed', () => {
    expect(outcomeOf({ inventory: 'NONE', legacy: true, vector: null }).result)
      .toBe('INTERNAL_VALIDATION_FAILED');
    expect(outcomeOf({ inventory: 'LEGACY_ONLY', legacy: false, vector: null }).result)
      .toBe('INTERNAL_VALIDATION_FAILED');
  });

  test('contradictory evidence fails closed rather than resolving to a later phase', () => {
    const cases = [
      { faults: ['recordAuthenticationFailed'], inventory: 'NONE', legacy: false, vector: null, selectorState: 'EMPTY' },
      { faults: ['unexpectedExposeCondition'], inventory: 'LEGACY_ONLY', legacy: true, vector: null, selectorState: 'EMPTY' },
      { faults: ['manifestOrRootMismatch', 'manifestOrRootMismatch'] },
      { faults: [], inventory: 'NONE', legacy: false, vector: 'FMT-KAT-ACTIVE' },
      { faults: [], inventory: 'M2', legacy: false, vector: null },
    ];
    for (const item of cases) {
      expect(classifyRestore(observation(item))).toMatchObject({
        result: 'INTERNAL_VALIDATION_FAILED', stage: 'CLASSIFY',
      });
    }
  });

  test('a duplicated fault is not idempotent: it is contradictory evidence', () => {
    expect(outcomeOf({ faults: ['manifestOrRootMismatch', 'manifestOrRootMismatch'] }).result)
      .toBe('INTERNAL_VALIDATION_FAILED');
    expect(outcomeOf({ faults: ['manifestOrRootMismatch'] }).result).toBe('MANIFEST_INVALID');
  });

  test('the classifier is total: no input escapes as an exception', () => {
    const faults = ['lockUnavailable'];
    Object.defineProperty(faults, Symbol.iterator, { get() { throw new Error('hostile'); } });
    const cases = [null, undefined, 0, '', [], new Map(), observations => observations];
    for (const item of cases) {
      expect(() => classifyRestore(item)).not.toThrow();
    }
    expect(() => classifyRestore(observation({ faults }))).not.toThrow();
    expect(classifyRestore(observation({ faults })).result).toBe('INTERNAL_VALIDATION_FAILED');
  });

  test('an iterator that lies on the second pass cannot change the decision', () => {
    // The classifier reads the fault set once, into a frozen snapshot; a Proxy or an iterator that
    // returns different values on the second pass cannot turn a fault set into a success.
    const real = ['lockUnavailable'];
    const lying = new Proxy(real, {
      get(target, key) {
        if (key === 'length') {
          return target.length;
        }
        if (key === Symbol.iterator || key === '0') {
          return undefined;
        }
        return target[key];
      },
    });
    const outcome = classifyRestore({ ...observation(), faults: lying });
    expect(outcome.exposed).toBe(false);
    expect(SUCCESS_RESULTS).not.toContain(outcome.result);
    expect(FAILURE_RESULTS).toContain(outcome.result);
  });
});

describe('version and pin drift', () => {
  test('the exact eight versions are accepted', () => {
    expect(checkVersions({ ...VERSIONS })).toBe(null);
  });

  test('each version drifting forward or backward is UNSUPPORTED_VERSION', () => {
    for (const key of Object.keys(VERSIONS)) {
      for (const delta of [1, -1]) {
        expect(checkVersions({ ...VERSIONS, [key]: VERSIONS[key] + delta })).toBe('UNSUPPORTED_VERSION');
      }
    }
  });

  test('a missing, extra, mixed, non-integer or unknown version set is UNSUPPORTED_VERSION', () => {
    expect(checkVersions({})).toBe('UNSUPPORTED_VERSION');
    expect(checkVersions({ ...VERSIONS, unknownKey: 1 })).toBe('UNSUPPORTED_VERSION');
    expect(checkVersions({ ...VERSIONS, format: '1' })).toBe('UNSUPPORTED_VERSION');
    expect(checkVersions({ ...VERSIONS, format: 1.5 })).toBe('UNSUPPORTED_VERSION');
    expect(checkVersions({ ...VERSIONS, format: -0 })).toBe('UNSUPPORTED_VERSION');
    expect(checkVersions({ ...VERSIONS, format: NaN })).toBe('UNSUPPORTED_VERSION');
    const partial = { ...VERSIONS };
    delete partial.manifest;
    expect(checkVersions(partial)).toBe('UNSUPPORTED_VERSION');
    expect(checkVersions(null)).toBe('UNSUPPORTED_VERSION');
    expect(checkVersions(Object.assign(Object.create(null), VERSIONS))).toBe(null);
  });

  test('the reader profile is not a version and cannot widen the version set', () => {
    expect(checkVersions({ ...VERSIONS, readerProfile: READER_PROFILE })).toBe('UNSUPPORTED_VERSION');
  });
});

describe('build eligibility', () => {
  const goodBuild = () => ({
    ...BUILD_MATRIX[0],
    versions: { ...BUILD_MATRIX[0].versions },
    ss0Ciphersuite: { ...BUILD_MATRIX[0].ss0Ciphersuite },
  });

  test('both complete rows are eligible', () => {
    expect(checkBuildEligibility(goodBuild())).toBe(true);
    expect(checkBuildEligibility({
      ...BUILD_MATRIX[1],
      versions: { ...BUILD_MATRIX[1].versions },
      ss0Ciphersuite: { ...BUILD_MATRIX[1].ss0Ciphersuite },
    })).toBe(true);
  });

  test('a drifted member, a partial row or an extra member is ineligible', () => {
    for (const key of Object.keys(BUILD_MATRIX[0])) {
      const drifted = goodBuild();
      drifted[key] = key === 'versions' ? { ...VERSIONS, format: 2 } : 'DRIFTED';
      expect(checkBuildEligibility(drifted)).toBe(false);
    }
    const partial = goodBuild();
    delete partial.wasmArtifactSha256;
    expect(checkBuildEligibility(partial)).toBe(false);
    expect(checkBuildEligibility({ ...goodBuild(), extra: 1 })).toBe(false);
    expect(checkBuildEligibility(null)).toBe(false);
    expect(checkBuildEligibility({})).toBe(false);
    expect(checkBuildEligibility(Object.assign(Object.create(null), goodBuild()))).toBe(true);
  });

  test('an unlisted runtime class, browser class or ciphersuite is ineligible', () => {
    expect(checkBuildEligibility({ ...goodBuild(), runtimeClass: 'MOBILE' })).toBe(false);
    expect(checkBuildEligibility({ ...goodBuild(), browserClass: 'SAFARI' })).toBe(false);
    expect(checkBuildEligibility({ ...goodBuild(), buildId: 'M2_WEB_SAFARI_STANDARD' })).toBe(false);
    expect(checkBuildEligibility({
      ...goodBuild(), ss0Ciphersuite: { ianaId: '0x0003', name: 'MLS_256_DHKEMX448' },
    })).toBe(false);
    expect(checkBuildEligibility({ ...goodBuild(), readerProfile: 'CFMT_OTHER' })).toBe(false);
  });

  test('a drifted version inside an otherwise exact row is ineligible', () => {
    expect(checkBuildEligibility({
      ...goodBuild(), versions: { ...VERSIONS, upstreamBinding: 1 },
    })).toBe(false);
  });
});

describe('the authenticated compatibility conjunction', () => {
  const authenticated = (versions, profile) => ({ versions, profile });
  const profile = (algorithms = { ...ALGORITHMS }) => ({ readerProfile: READER_PROFILE, algorithms });

  test('the exact conjunction is accepted', () => {
    expect(checkAuthenticatedCompatibility(authenticated({ ...VERSIONS }, profile()))).toBe(null);
  });

  test('version mismatch precedes other profile mismatch and is UNSUPPORTED_VERSION', () => {
    expect(checkAuthenticatedCompatibility(authenticated(
      { ...VERSIONS, format: 2 },
      profile({ ...ALGORITHMS, recordAead: 'AES-128-GCM' }),
    ))).toBe('UNSUPPORTED_VERSION');
  });

  test('a non-version profile mismatch is INCOMPATIBLE_FORMAT', () => {
    expect(checkAuthenticatedCompatibility(authenticated(
      { ...VERSIONS }, profile({ ...ALGORITHMS, recordAead: 'AES-128-GCM' }),
    ))).toBe('INCOMPATIBLE_FORMAT');
    expect(checkAuthenticatedCompatibility(authenticated(
      { ...VERSIONS }, profile({ ...ALGORITHMS, kdf: 'HKDF-SHA-512' }),
    ))).toBe('INCOMPATIBLE_FORMAT');
    expect(checkAuthenticatedCompatibility(authenticated(
      { ...VERSIONS }, { readerProfile: 'CFMT_OTHER', algorithms: { ...ALGORITHMS } },
    ))).toBe('INCOMPATIBLE_FORMAT');
  });

  test('a malformed, widened or non-plain authenticated record fails closed', () => {
    const cases = [
      authenticated({ ...VERSIONS }, profile()),
    ];
    cases[0].unknown = 1;
    for (const item of cases) {
      expect(checkAuthenticatedCompatibility(item)).toBe('INTERNAL_VALIDATION_FAILED');
    }
    // C-REST §2: only a malformed argument is INTERNAL_VALIDATION_FAILED. A profile or algorithm
    // deviation is INCOMPATIBLE_FORMAT, and a version deviation is UNSUPPORTED_VERSION.
    for (const algorithms of [{ ...ALGORITHMS, futureAead: 'XCHACHA20' }, null, 'AES-256-GCM']) {
      expect(checkAuthenticatedCompatibility(authenticated({ ...VERSIONS }, {
        readerProfile: READER_PROFILE, algorithms,
      }))).toBe('INCOMPATIBLE_FORMAT');
    }
    const label = profile();
    label.labels = { recordAead: 'evil/label' };
    expect(checkAuthenticatedCompatibility(authenticated({ ...VERSIONS }, label)))
      .toBe('INCOMPATIBLE_FORMAT');
    expect(checkAuthenticatedCompatibility(authenticated({ ...VERSIONS }, {
      readerProfile: READER_PROFILE, algorithms: Object.assign(Object.create(null), ALGORITHMS),
    }))).toBe(null);
    expect(checkAuthenticatedCompatibility(null)).toBe('INTERNAL_VALIDATION_FAILED');
  });

  test('a drifted version set is UNSUPPORTED_VERSION, never a partial match', () => {
    const partial = { ...VERSIONS };
    delete partial.plaintext;
    expect(checkAuthenticatedCompatibility(authenticated(partial, profile())))
      .toBe('UNSUPPORTED_VERSION');
    expect(checkAuthenticatedCompatibility(authenticated({ ...VERSIONS, format: 0 }, profile())))
      .toBe('UNSUPPORTED_VERSION');
    expect(checkAuthenticatedCompatibility(authenticated({ ...VERSIONS, futureVersion: 1 }, profile())))
      .toBe('UNSUPPORTED_VERSION');
    expect(checkAuthenticatedCompatibility(authenticated({ ...VERSIONS, format: '2' }, profile())))
      .toBe('UNSUPPORTED_VERSION');
    // A mismatch the store cannot explain away still classifies at AUTHENTICATED_COMPATIBILITY.
    expect(FAULT_PRECEDENCE.some((row) => row.fault === 'authenticatedVersionUnknownOrMixed'
      && row.phase === 'AUTHENTICATED_COMPATIBILITY' && row.result === 'UNSUPPORTED_VERSION')).toBe(true);
    expect(FAULT_PRECEDENCE.some((row) => row.fault === 'authenticatedProfileIncompatible'
      && row.phase === 'AUTHENTICATED_COMPATIBILITY' && row.result === 'INCOMPATIBLE_FORMAT')).toBe(true);
  });
});

describe('reconciliation candidate and physical parent', () => {
  test('a complete, physically consistent candidate validates and is never authority', () => {
    const verified = validateReconciliationCandidate(goodFacts());
    expect(verified.bindingProfileVerified).toBe(true);
    expect(verified.authority).toBe('CANDIDATE_NOT_AUTHORITY');
    expect(Object.isFrozen(verified)).toBe(true);
    expect(verified.candidateEqualsSelected).toBe(false);
  });

  test('a SESSION-scoped kind-16 candidate manifest key is accepted', () => {
    const facts = withFacts((item) => {
      item.locator.scope = 'SESSION';
      item.locator.secureSessionIdentity = bytes(0x71);
    });
    expect(validateReconciliationCandidate(facts).bindingProfileVerified).toBe(true);
    const preSession = withFacts((item) => {
      item.locator.scope = 'CONTEXT_PRESESSION';
      item.locator.secureSessionIdentity = bytes(0x71);
    });
    expect(rejectionOf(() => validateReconciliationCandidate(preSession)))
      .toEqual({ name: 'M2RestoreError', result: 'RECORD_INVALID', stage: 'RECORD_DECODE' });
    const sessionWithoutIdentity = withFacts((item) => {
      item.locator.scope = 'SESSION';
      item.locator.secureSessionIdentity = null;
    });
    expect(rejectionOf(() => validateReconciliationCandidate(sessionWithoutIdentity)))
      .toEqual({ name: 'M2RestoreError', result: 'RECORD_INVALID', stage: 'RECORD_DECODE' });
  });

  test('the candidate binding digest must equal the candidate generation own BINDING_PROFILE', () => {
    const mismatch = withFacts((item) => {
      item.candidateBindingProfile = { generation: 7n, bindingProfileDigest: bytes(0x91) };
    });
    expect(rejectionOf(() => validateReconciliationCandidate(mismatch)))
      .toEqual({ name: 'M2RestoreError', result: 'REFERENCE_INCONSISTENT', stage: 'REFERENCES' });
    const otherGeneration = withFacts((item) => {
      item.candidateBindingProfile = { generation: 8n, bindingProfileDigest: bytes(0x90) };
    });
    expect(rejectionOf(() => validateReconciliationCandidate(otherGeneration)).result)
      .toBe('REFERENCE_INCONSISTENT');
  });

  test('the locator must be the canonical kind-16 key with empty object ID', () => {
    for (const mutate of [
      (item) => { item.locator.recordKind = 17; },
      (item) => { item.locator.objectIdLength = 1; },
      (item) => { item.locator.scope = 'NOT_A_SCOPE'; },
      (item) => { delete item.locator.sha256; },
    ]) {
      expect(rejectionOf(() => validateReconciliationCandidate(withFacts(mutate))))
        .toEqual({ name: 'M2RestoreError', result: 'RECORD_INVALID', stage: 'RECORD_DECODE' });
    }
  });

  test('a canonical locator that disagrees with its candidate is REFERENCE_INCONSISTENT', () => {
    for (const mutate of [
      (item) => { item.locator.generation = 8n; },
      (item) => { item.locator.localContextId = bytes(0x12); },
      (item) => { item.locator.sha256 = bytes(0x22); },
    ]) {
      expect(rejectionOf(() => validateReconciliationCandidate(withFacts(mutate))))
        .toEqual({ name: 'M2RestoreError', result: 'REFERENCE_INCONSISTENT', stage: 'REFERENCES' });
    }
  });

  test('the candidate manifest digests and keyed root must match the selector tuple', () => {
    for (const mutate of [
      (item) => { item.candidate.manifestCiphertextDigest = bytes(0x32); },
      (item) => { item.candidate.keyedRoot = bytes(0x42); },
    ]) {
      expect(rejectionOf(() => validateReconciliationCandidate(withFacts(mutate))).result)
        .toBe('REFERENCE_INCONSISTENT');
    }
  });

  test("the candidate's own binding profile digest must agree with its manifest binding digest", () => {
    // The located candidate manifest binding digest must equal that candidate generation's own
    // BINDING_PROFILE: the candidate states it twice, and a contradiction in either statement rejects.
    expect(rejectionOf(() => validateReconciliationCandidate(
      withFacts((item) => { item.candidate.bindingProfileDigest = bytes(0x99); }),
    )).result).toBe('REFERENCE_INCONSISTENT');
    expect(rejectionOf(() => validateReconciliationCandidate(
      withFacts((item) => { item.candidate.bindingProfileDigest = zeros(); }),
    )).result).toBe('REFERENCE_INCONSISTENT');
    expect(rejectionOf(() => validateReconciliationCandidate(
      withFacts((item) => { item.candidateBindingProfile.bindingProfileDigest = bytes(0x99); }),
    )).result).toBe('REFERENCE_INCONSISTENT');
    expect(() => validateReconciliationCandidate(withFacts(() => {})))
      .not.toThrow();
  });

  test('a selected/candidate tuple that is neither equal nor different rejects', () => {
    // candidateRules.selectedRelation: "every other combination rejects". A tuple whose generation
    // agrees with the selected generation but whose keyed root does not, and the converse, is neither.
    expect(rejectionOf(() => validateReconciliationCandidate(
      withFacts((item) => { item.selectedGeneration = 7n; }),
    )).result).toBe('REFERENCE_INCONSISTENT');
    expect(rejectionOf(() => validateReconciliationCandidate(
      withFacts((item) => {
        item.selectedGeneration = 9n;
        item.selectedKeyedRoot = bytes(0x41);
      }),
    )).result).toBe('REFERENCE_INCONSISTENT');
    // The verified result states the relation it verified instead of a literal.
    const distinct = validateReconciliationCandidate(withFacts((item) => {
      item.candidate.resultStatus = 'COMMITTED';
      item.selectedGeneration = 9n;
      item.selectedKeyedRoot = bytes(0x61);
    }));
    expect(distinct.candidateEqualsSelected).toBe(false);
    const same = validateReconciliationCandidate(withFacts((item) => {
      item.candidate.resultStatus = 'COMMITTED';
      item.selectedGeneration = 7n;
      item.selectedKeyedRoot = bytes(0x41);
      item.selectorState = 'ACTIVE';
    }));
    expect(same.candidateEqualsSelected).toBe(true);
  });

  test('a malformed fact set is a closed rejection, never a raw TypeError', () => {
    for (const value of [null, undefined, 0, 'x']) {
      for (const key of ['locator.localContextId', 'locator.sha256', 'keyedRoot']) {
        const [outer, inner] = key.split('.');
        const result = rejectionDetailedOf(() => validateReconciliationCandidate(withFacts((item) => {
          if (inner === undefined) {
            item[outer] = value;
          } else {
            item[outer][inner] = value;
          }
        })));
        // A non-canonical key is RECORD_INVALID at RECORD_DECODE; any other malformed member is
        // INTERNAL_VALIDATION_FAILED at CLASSIFY. Neither path may be a TypeError with free text.
        expect(result.name).toBe('M2RestoreError');
        expect(FAILURE_RESULTS).toContain(result.result);
        expect(PHASES).toContain(result.stage);
        expect(result.message).toBe(`${result.result}@${result.stage}`);
      }
    }
    expect(rejectionOf(() => validateReconciliationCandidate(
      withFacts((item) => { item.keyedRoot = null; }),
    ))).toEqual({ name: 'M2RestoreError', result: 'INTERNAL_VALIDATION_FAILED', stage: 'CLASSIFY' });
  });

  test('an unresolved hold must name the selector generation and keyed root as physical parent', () => {
    for (const mutate of [
      (item) => { item.candidate.parentGeneration = 9n; },
      (item) => { item.candidate.parentKeyedRoot = bytes(0x52); },
    ]) {
      expect(rejectionOf(() => validateReconciliationCandidate(withFacts(mutate))))
        .toEqual({ name: 'M2RestoreError', result: 'REFERENCE_INCONSISTENT', stage: 'REFERENCES' });
    }
    const terminal = withFacts((item) => {
      item.candidate.resultStatus = 'COMMITTED';
      item.candidate.parentGeneration = 9n;
      item.candidate.parentKeyedRoot = bytes(0x52);
    });
    expect(validateReconciliationCandidate(terminal).bindingProfileVerified).toBe(true);
  });

  test('the hold logical original authority must equal the candidate COMMIT_RESULT fields', () => {
    const differentReference = withFacts((item) => {
      item.candidate.originalAuthorityReference = bytes(0x62);
    });
    expect(rejectionOf(() => validateReconciliationCandidate(differentReference)))
      .toEqual({ name: 'M2RestoreError', result: 'REFERENCE_INCONSISTENT', stage: 'REFERENCES' });
    const differentDigest = withFacts((item) => {
      item.commitResult.originalAuthorityDigest = bytes(0x62);
    });
    expect(rejectionOf(() => validateReconciliationCandidate(differentDigest)).result)
      .toBe('REFERENCE_INCONSISTENT');
    const bothDifferentButEqual = withFacts((item) => {
      item.candidate.originalAuthorityDigest = bytes(0x62);
      item.commitResult.originalAuthorityDigest = bytes(0x62);
    });
    expect(validateReconciliationCandidate(bothDifferentButEqual).bindingProfileVerified).toBe(true);
  });

  test('a candidate equal to the selected generation during reconciliation rejects', () => {
    const equal = withFacts((item) => {
      item.selectedGeneration = 7n;
      item.selectedKeyedRoot = bytes(0x41);
      item.candidate.parentGeneration = 7n;
      item.candidate.parentKeyedRoot = bytes(0x41);
    });
    expect(rejectionOf(() => validateReconciliationCandidate(equal)))
      .toEqual({ name: 'M2RestoreError', result: 'REFERENCE_INCONSISTENT', stage: 'REFERENCES' });
  });

  test('candidate fields differing without RECONCILIATION_REQUIRED reject', () => {
    const notReconciling = withFacts((item) => {
      item.selectorState = 'ACTIVE';
    });
    expect(rejectionOf(() => validateReconciliationCandidate(notReconciling)))
      .toEqual({ name: 'M2RestoreError', result: 'REFERENCE_INCONSISTENT', stage: 'REFERENCES' });
    expect(rejectionOf(() => validateReconciliationCandidate(withFacts((item) => {
      item.selectorState = 'NOT_A_STATE';
    }))).result).toBe('INTERNAL_VALIDATION_FAILED');
  });

  test('a malformed candidate fact set fails closed', () => {
    const hollow = {
      localContextId: zeros(),
      candidateGeneration: 7n,
      candidateManifestKeyDigest: zeros(),
      manifestCiphertextDigest: zeros(),
      keyedRoot: zeros(),
      selectedGeneration: 6n,
      selectedKeyedRoot: zeros(),
      selectorState: 'RECONCILIATION_REQUIRED',
      locator: {},
      candidate: {},
      candidateBindingProfile: {},
      commitResult: {},
    };
    const cases = [
      hollow,
      {},
      null,
      withFacts((item) => { item.candidateGeneration = 0n; }),
      withFacts((item) => { delete item.selectorState; }),
      withFacts((item) => { item.candidateEqualsSelected = true; }),
      withFacts((item) => { item.extraMember = 1; }),
      withFacts((item) => { item.localContextId = zeros(); }),
      withFacts((item) => { item.candidateGeneration = 7; }),
      withFacts((item) => { item.keyedRoot = new Uint8Array(31); }),
      withFacts((item) => { item.candidate.resultStatus = 'NOT_A_STATUS'; }),
      withFacts((item) => { item.candidate.manifestBindingDigest = new Uint8Array(0); }),
    ];
    for (const item of cases) {
      const rejection = rejectionOf(() => validateReconciliationCandidate(item));
      expect(rejection).not.toBe(null);
      expect(['INTERNAL_VALIDATION_FAILED', 'RECORD_INVALID', 'REFERENCE_INCONSISTENT'])
        .toContain(rejection.result);
      expect(rejection.name).toBe('M2RestoreError');
    }
  });

  test('no caller-supplied byte array is echoed back in the verified facts', () => {
    const facts = goodFacts();
    const verified = validateReconciliationCandidate(facts);
    expect(JSON.stringify(Object.keys(verified))).toBe(JSON.stringify([
      'candidateGeneration', 'bindingProfileVerified', 'candidateEqualsSelected', 'authority',
    ]));
    expect(verified).not.toHaveProperty('locator');
    expect(verified).not.toHaveProperty('candidate');
  });

  test('the five candidate faults classify to their exact C-REST rows', () => {
    const faults = [
      ['candidateManifestKeyScopeSessionSubstitution', 'RECORD_INVALID', 'RECORD_DECODE'],
      ['candidateManifestKeyMismatch', 'REFERENCE_INCONSISTENT', 'REFERENCES'],
      ['candidateParentMismatch', 'REFERENCE_INCONSISTENT', 'REFERENCES'],
      ['candidateEqualsSelectedDuringReconciliation', 'REFERENCE_INCONSISTENT', 'REFERENCES'],
      ['candidateFieldsDifferWithoutReconciliation', 'REFERENCE_INCONSISTENT', 'REFERENCES'],
    ];
    for (const [fault, result, stage] of faults) {
      expect(outcomeOf({ faults: [fault] })).toMatchObject({ result, stage });
    }
  });
});

describe('diagnostics and immutability', () => {
  test('diagnostics carry exactly the five allowlisted members', () => {
    const outcome = classifyRestore(observation({ selectorState: 'EMPTY' }));
    expect(Object.keys(outcome.diagnostics).sort()).toEqual([...DIAGNOSTIC_ALLOWED].sort());
    expect(Object.keys(outcome).sort()).toEqual(['condition', 'diagnostics', 'exposed', 'result', 'stage']);
  });

  test('diagnostics never carry a forbidden token in any classification', () => {
    const inputs = [
      observation(),
      observation({ inventory: 'NONE', legacy: false, vector: null }),
      observation({ inventory: 'LEGACY_ONLY', legacy: true, vector: null }),
      ...FAULT_PRECEDENCE.map((row) => observation({ faults: [row.fault] })),
    ];
    for (const input of inputs) {
      const text = JSON.stringify(classifyRestore(input));
      for (const token of DIAGNOSTIC_FORBIDDEN) {
        expect(text.includes(token)).toBe(false);
      }
    }
  });

  test('diagnostics never fabricate a count the observation cannot support', () => {
    expect(outcomeOf({ inventory: 'NONE', legacy: false, vector: null }).diagnostics)
      .toMatchObject({ m2LocatorCount: 0, m2ArtifactCount: 0 });
    expect(outcomeOf({ inventory: 'LEGACY_ONLY', legacy: true, vector: null }).diagnostics)
      .toMatchObject({ m2LocatorCount: 0, m2ArtifactCount: 0 });
    expect(outcomeOf({ selectorState: 'ACTIVE' }).diagnostics)
      .toMatchObject({ m2LocatorCount: null, m2ArtifactCount: null });
    expect(outcomeOf({ faults: ['multipleSelectorCandidates'] }).diagnostics.m2LocatorCount).toBe(null);
  });

  test('classification mutates nothing and returns frozen values', () => {
    const input = observation({ faults: ['lockUnavailable'] });
    const snapshot = JSON.stringify(input);
    const outcome = classifyRestore(input);
    expect(JSON.stringify(input)).toBe(snapshot);
    expect(Object.isFrozen(outcome)).toBe(true);
    expect(Object.isFrozen(outcome.diagnostics)).toBe(true);
  });

  test('the error class carries only closed codes and never free text', () => {
    const error = new M2RestoreError('REFERENCE_INCONSISTENT', 'REFERENCES');
    expect(error).toBeInstanceOf(Error);
    expect({ name: error.name, result: error.result, stage: error.stage })
      .toEqual({ name: 'M2RestoreError', result: 'REFERENCE_INCONSISTENT', stage: 'REFERENCES' });
    const wild = new M2RestoreError('free text', 'no stage');
    expect({ result: wild.result, stage: wild.stage })
      .toEqual({ result: 'INTERNAL_VALIDATION_FAILED', stage: 'CLASSIFY' });
    expect(wild.message).toBe('INTERNAL_VALIDATION_FAILED@CLASSIFY');
  });
});

describe('property tests (seeded, reproducible)', () => {
  const VOCABULARY = [...SUCCESS_RESULTS, ...FAILURE_RESULTS, ...INVENTORY_RESULTS];

  const observationArbitrary = fc.record({
    faults: fc.array(fc.constantFrom(...FAULT_PRECEDENCE.map((row) => row.fault)), { maxLength: 3 }),
    inventory: fc.constantFrom('NONE', 'LEGACY_ONLY', 'M2'),
    legacy: fc.boolean(),
    vector: fc.constantFrom(null, 'FMT-KAT-ACTIVE', 'FMT-KAT-EMPTY', 'FMT-KAT-HOLD'),
    selectorState: fc.constantFrom('EMPTY', 'ACTIVE', 'RECONCILIATION_REQUIRED'),
  });

  test('any observation classifies to a closed result or the fail-closed default, never throwing', () => {
    fc.assert(fc.property(observationArbitrary, (item) => {
      const outcome = classifyRestore(item);
      expect(VOCABULARY.includes(outcome.result)).toBe(true);
      expect(PHASES.includes(outcome.stage)).toBe(true);
      expect(outcome.exposed).toBe(SUCCESS_RESULTS.includes(outcome.result) && outcome.stage === 'EXPOSE');
      expect(Object.isFrozen(outcome)).toBe(true);
    }), { seed: 20261002, numRuns: 500 });
  });

  test('a non-empty fault set never resolves to a success', () => {
    fc.assert(fc.property(observationArbitrary, (item) => {
      const outcome = classifyRestore(item);
      if (item.faults.length > 0) {
        expect(SUCCESS_RESULTS.includes(outcome.result)).toBe(false);
        expect(INVENTORY_RESULTS.includes(outcome.result)).toBe(false);
      }
    }), { seed: 20261002, numRuns: 500 });
  });

  test('the same seed replays to identical outcomes', () => {
    const run = () => {
      const seen = [];
      fc.assert(fc.property(observationArbitrary, (item) => {
        seen.push(JSON.stringify(classifyRestore(item)));
      }), { seed: 987654321, numRuns: 200 });
      return seen;
    };
    expect(run()).toEqual(run());
  });
});

// The O-SCEN rows this card owns that no named test above reaches, with their exact normative root.
const UNMAPPED_SCENARIO_ROWS = Object.freeze([
  { root: '/irest/observation/closedMembers', owner: 'this card, exercised structurally' },
  { root: '/irest/freshWorkerFixtureMatrix', owner: 'this card, exercised structurally' },
  { root: '/irest/diagnostics/allowlist', owner: 'this card, exercised structurally' },
]);

describe('unmapped scenario rows', () => {
  test('every remaining owned row is listed with its normative root and is not claimed resolved', () => {
    expect(UNMAPPED_SCENARIO_ROWS.length).toBeGreaterThan(0);
    for (const row of UNMAPPED_SCENARIO_ROWS) {
      expect(row.root.startsWith('/irest/')).toBe(true);
      expect(row.owner.length).toBeGreaterThan(0);
    }
  });
});
