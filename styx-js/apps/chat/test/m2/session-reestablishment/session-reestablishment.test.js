// session-reestablishment.test.js — L-REEST conformance tests (card L-REEST of #317 G-SCOPE).
//
// The tests drive only the module's public surface, over the real merged L-MARK, L-INV, I-JOIN adapter
// and I-REST classifier: nothing is mocked. The C-REC §13 rows this card owns are transcribed verbatim
// below and replayed: the `SHOW_REESTABLISHMENT` / `SHOW_CREATE` dispatch rows and their reachable
// condition pairs, the dispatch negatives, the thirteen `MARKER` fixtures, the three `MARKER-CRASH-*`
// boundaries and the three legacy `ACTION` refusals.

import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import * as reest from '../../../src/m2/session-reestablishment/session-reestablishment.js';
import {
  M2_REESTABLISHMENT,
  M2ReestablishmentError,
  cancelReestablishment,
  completeReestablishment,
  confirmReestablishment,
  createNewSession,
  guidanceFor,
  legacyActionDecision,
  legacyPresenceOf,
  resumeFor,
  startReestablishment,
} from '../../../src/m2/session-reestablishment/session-reestablishment.js';
import {
  M2_LEGACY_INVALIDATION,
  encodeMarker,
  readMarker,
} from '../../../../../src/storage/m2/legacy-session-invalidation.js';
import { M2_ADAPTER } from '../../../../../src/crypto/mls/m2/adapter.js';
import { createAdapterSnapshot } from '../../../../../src/crypto/mls/m2/state-machine.js';
import { encodeRecordKey, encodeSelectorKey } from '../../../../../src/storage/m2/session-codec.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const MODULE_PATH = resolve(HERE, '../../../src/m2/session-reestablishment/session-reestablishment.js');

const [ABSENT, PENDING, CONFIRMED, INVALIDATED] = M2_LEGACY_INVALIDATION.STATES;
const EV = {
  START: 'USER_CONFIRMED_START',
  CANCEL: 'USER_CANCEL_BEFORE_CONFIRMATION',
  CONFIRM: 'DISTINCT_POST_START_C_FMT_COMMITTED_AUTHORITY_RESTORED_ACTIVE',
  COMMIT: 'ATOMIC_MARKER_COMMIT',
  REPEAT: 'REPEAT_MARKER_COMPLETION',
};

// ------------------------------------------------------------------------------------------------
// C-REC §13 rows, transcribed verbatim (C-REC sha256 ab11271c…7149, #327 comment 6035801582).
// ------------------------------------------------------------------------------------------------

const CREC_OWNED_DISPATCH_ROWS = [
  { result: 'NO_M2_STATE', disposition: 'SHOW_CREATE', authority: 'NONE', resetEligible: false, legacyCondition: 'UNAVAILABLE', byteAction: 'PRESERVE' },
  { result: 'LEGACY_ONLY', disposition: 'SHOW_REESTABLISHMENT', authority: 'NONE', resetEligible: false, legacyCondition: 'REQUIRED', byteAction: 'PRESERVE' },
];
const CREC_OWNED_REACHABLE_ROWS = [
  { result: 'NO_M2_STATE', legacyPresent: false, disposition: 'SHOW_CREATE', authority: 'NONE', resetEligible: false },
  { result: 'LEGACY_ONLY', legacyPresent: true, disposition: 'SHOW_REESTABLISHMENT', authority: 'NONE', resetEligible: false },
];
const CREC_DISPATCH_FIXTURES = [
  { id: 'DISPATCH-NO_M2_STATE-NOLEGACY', input: { result: 'NO_M2_STATE', legacyPresent: false }, expected: { disposition: 'SHOW_CREATE', authority: 'NONE', resetEligible: false, agreement: { disposition: 'SHOW_CREATE', authorityIdentity: 'NONE', markerState: 'UNCHANGED', firstFailingPhase: 'NONE' } } },
  { id: 'DISPATCH-LEGACY_ONLY-LEGACY', input: { result: 'LEGACY_ONLY', legacyPresent: true }, expected: { disposition: 'SHOW_REESTABLISHMENT', authority: 'NONE', resetEligible: false, agreement: { disposition: 'SHOW_REESTABLISHMENT', authorityIdentity: 'NONE', markerState: 'UNCHANGED', firstFailingPhase: 'NONE' } } },
  { id: 'NEG-UNKNOWN-RESULT', input: { result: 'UNKNOWN', legacyPresent: false }, expected: { reject: 'UNKNOWN_RESULT', agreement: { disposition: 'REJECT', authorityIdentity: 'NONE', markerState: 'UNCHANGED', firstFailingPhase: 'C_REST_CLASSIFIED' } } },
  { id: 'NEG-INCOMPLETE-DISPATCH', input: { result: 'RESTORED_ACTIVE' }, expected: { reject: 'MISSING_DISPATCH_INPUT', agreement: { disposition: 'REJECT', authorityIdentity: 'NONE', markerState: 'UNCHANGED', firstFailingPhase: 'C_REST_CLASSIFIED' } } },
  { id: 'NEG-NO-M2-LEGACY', input: { result: 'NO_M2_STATE', legacyPresent: true }, expected: { reject: 'UNREACHABLE_CONDITION_PAIR', agreement: { disposition: 'REJECT', authorityIdentity: 'NONE', markerState: 'UNCHANGED', firstFailingPhase: 'C_REST_CLASSIFIED' } } },
  { id: 'NEG-LOCKED-LEGACY', input: { result: 'LOCKED_ELSEWHERE', legacyPresent: true }, expected: { reject: 'UNREACHABLE_CONDITION_PAIR', agreement: { disposition: 'REJECT', authorityIdentity: 'NONE', markerState: 'UNCHANGED', firstFailingPhase: 'C_REST_CLASSIFIED' } } },
  { id: 'NEG-BUILD-LEGACY', input: { result: 'INCOMPATIBLE_BUILD', legacyPresent: true }, expected: { reject: 'UNREACHABLE_CONDITION_PAIR', agreement: { disposition: 'REJECT', authorityIdentity: 'NONE', markerState: 'UNCHANGED', firstFailingPhase: 'C_REST_CLASSIFIED' } } },
];
/** C-REC `/reachableConditionRows` as `result:legacyPresent` pairs, verbatim and in order (32 rows). */
const CREC_REACHABLE_PAIRS = [
  'NO_M2_STATE:false', 'LEGACY_ONLY:true', 'RESTORED_EMPTY:false', 'RESTORED_EMPTY:true', 'RESTORED_ACTIVE:false',
  'RESTORED_ACTIVE:true', 'RESTORED_RECONCILIATION_REQUIRED:false', 'RESTORED_RECONCILIATION_REQUIRED:true',
  'LOCKED_ELSEWHERE:false', 'WRAPPER_AUTH_FAILED:false', 'WRAPPER_AUTH_FAILED:true', 'INCOMPATIBLE_BUILD:false',
  'INCOMPATIBLE_FORMAT:false', 'INCOMPATIBLE_FORMAT:true', 'UNSUPPORTED_VERSION:false', 'UNSUPPORTED_VERSION:true',
  'SELECTOR_INVALID:false', 'SELECTOR_INVALID:true', 'AUTHENTICATION_FAILED:false', 'AUTHENTICATION_FAILED:true',
  'MANIFEST_INVALID:false', 'MANIFEST_INVALID:true', 'RECORD_SET_INCOMPLETE:false', 'RECORD_SET_INCOMPLETE:true',
  'RECORD_INVALID:false', 'RECORD_INVALID:true', 'REFERENCE_INCONSISTENT:false', 'REFERENCE_INCONSISTENT:true',
  'PARTIAL_GENERATION:false', 'PARTIAL_GENERATION:true', 'INTERNAL_VALIDATION_FAILED:false',
  'INTERNAL_VALIDATION_FAILED:true',
];
const CREC_MARKER_FIXTURES = [
  { id: 'MARKER-START', input: { committed: false, distinct: false, event: EV.START, lockHeld: true, restoreResult: 'LEGACY_ONLY', state: ABSENT }, expected: { accepted: true, state: PENDING, agreement: { disposition: 'MARKER_TRANSITION', firstFailingPhase: 'NONE', markerState: PENDING } } },
  { id: 'MARKER-CANCEL', input: { committed: false, distinct: false, event: EV.CANCEL, lockHeld: true, restoreResult: 'LEGACY_ONLY', state: PENDING }, expected: { accepted: true, state: ABSENT, agreement: { disposition: 'MARKER_TRANSITION', firstFailingPhase: 'NONE', markerState: ABSENT } } },
  { id: 'MARKER-CONFIRM', input: { committed: true, distinct: true, event: EV.CONFIRM, lockHeld: true, restoreResult: 'RESTORED_ACTIVE', state: PENDING }, expected: { accepted: true, state: CONFIRMED, agreement: { disposition: 'MARKER_TRANSITION', firstFailingPhase: 'NONE', markerState: CONFIRMED } } },
  { id: 'MARKER-COMMIT_MARKER', input: { committed: false, distinct: false, event: EV.COMMIT, lockHeld: true, restoreResult: 'RESTORED_ACTIVE', state: CONFIRMED }, expected: { accepted: true, state: INVALIDATED, agreement: { disposition: 'MARKER_TRANSITION', firstFailingPhase: 'NONE', markerState: INVALIDATED } } },
  { id: 'MARKER-REPEAT_COMPLETION', input: { committed: false, distinct: false, event: EV.REPEAT, lockHeld: true, restoreResult: 'RESTORED_ACTIVE', state: INVALIDATED }, expected: { accepted: true, state: INVALIDATED, agreement: { disposition: 'MARKER_TRANSITION', firstFailingPhase: 'NONE', markerState: INVALIDATED } } },
  { id: 'NEG-MARKER-REVERSE', input: { event: EV.CANCEL, lockHeld: true, state: INVALIDATED }, expected: { reject: 'MARKER_TRANSITION_FORBIDDEN', agreement: { disposition: 'REJECT', firstFailingPhase: 'MARKER_GATE', markerState: INVALIDATED } } },
  { id: 'NEG-STALE-TOKEN', input: { committed: true, distinct: false, event: EV.CONFIRM, lockHeld: true, restoreResult: 'RESTORED_ACTIVE', state: PENDING }, expected: { reject: 'TOKEN_MISMATCH', agreement: { disposition: 'REJECT', firstFailingPhase: 'MARKER_GATE', markerState: PENDING } } },
  { id: 'NEG-CROSS-SESSION-TOKEN', input: { committed: true, distinct: false, event: EV.CONFIRM, lockHeld: true, restoreResult: 'RESTORED_ACTIVE', state: PENDING }, expected: { reject: 'TOKEN_MISMATCH', agreement: { disposition: 'REJECT', firstFailingPhase: 'MARKER_GATE', markerState: PENDING } } },
  { id: 'NEG-EMPTY-CONFIRM', input: { committed: true, distinct: true, event: EV.CONFIRM, lockHeld: true, restoreResult: 'RESTORED_EMPTY', state: PENDING }, expected: { reject: 'CONFIRMATION_PRECONDITION_FAILED', agreement: { disposition: 'REJECT', firstFailingPhase: 'MARKER_GATE', markerState: PENDING } } },
  { id: 'NEG-RECONCILIATION-CONFIRM', input: { committed: true, distinct: true, event: EV.CONFIRM, lockHeld: true, restoreResult: 'RESTORED_RECONCILIATION_REQUIRED', state: PENDING }, expected: { reject: 'CONFIRMATION_PRECONDITION_FAILED', agreement: { disposition: 'REJECT', firstFailingPhase: 'MARKER_GATE', markerState: PENDING } } },
  { id: 'NEG-NO-LOCK', input: { event: EV.START, lockHeld: false, state: ABSENT }, expected: { reject: 'LOCKED_ELSEWHERE', agreement: { disposition: 'LOCK_RETRY', firstFailingPhase: 'LOCK', markerState: 'UNCHANGED' } } },
  { id: 'NEG-NO-M2-MARKER-START', input: { event: EV.START, lockHeld: true, restoreResult: 'NO_M2_STATE', state: ABSENT }, expected: { reject: 'RESTORE_PRECONDITION_FAILED', agreement: { disposition: 'REJECT', firstFailingPhase: 'MARKER_GATE', markerState: ABSENT } } },
  { id: 'NEG-RECONCILIATION-MARKER-COMMIT', input: { event: EV.COMMIT, lockHeld: true, restoreResult: 'RESTORED_RECONCILIATION_REQUIRED', state: CONFIRMED }, expected: { reject: 'RESTORE_PRECONDITION_FAILED', agreement: { disposition: 'REJECT', firstFailingPhase: 'MARKER_GATE', markerState: CONFIRMED } } },
];
const CREC_CRASH_FIXTURES = [
  { id: 'MARKER-CRASH-BEFORE-CONFIRMATION', state: PENDING, expected: { legacyAuthority: 'UNCHANGED', markerState: PENDING } },
  { id: 'MARKER-CRASH-AFTER-CONFIRMATION', state: CONFIRMED, expected: { legacyEligibility: false, markerState: CONFIRMED, resume: 'MARKER_COMPLETION_ONLY' } },
  { id: 'MARKER-CRASH-AFTER-COMMIT', state: INVALIDATED, expected: { legacyEligibility: false, markerState: INVALIDATED } },
];
const CREC_ACTION_FIXTURES = [
  { id: 'NEG-FALLBACK', input: { action: 'LEGACY_FALLBACK' }, reject: 'LEGACY_FALLBACK_FORBIDDEN' },
  { id: 'NEG-IMPORT', input: { action: 'LEGACY_IMPORT' }, reject: 'LEGACY_IMPORT_FORBIDDEN' },
  { id: 'NEG-CLEANUP', input: { action: 'DELETE_LEGACY' }, reject: 'CLEANUP_DEFERRED' },
];
const CREC_LEGACY = {
  input: 'ABSTRACT_LEGACY_PRESENT_AND_BOUNDED_VALUE_FREE_COUNT', import: false, decrypt: false, translate: false,
  fallback: false, selectedAuthority: false, preserveBytes: true, physicalInventoryOwner: 'L-INV', cleanup: 'DEFERRED',
};
const CREC_DEPENDENCY_COVERAGE_6 = {
  criterion: 'INVALIDATION_AND_REESTABLISHMENT', ownership: 'C_REC_OWNED', cMut: [],
  cFmt: ['mutationRows', 'generationCommit.outcomes.COMMITTED'],
  cRest: ['resultSets.success', 'successBySelectorState', 'inventoryRules.legacyDomain', 'guidance.legacy'],
};
const CREC_DIAGNOSTICS_ALLOWED = ['restoreResult', 'condition', 'recoveryDisposition', 'stageCode', 'reasonCode', 'boundedCount'];
const CREC_RESTORE_RESULTS = [
  'NO_M2_STATE', 'LEGACY_ONLY', 'RESTORED_EMPTY', 'RESTORED_ACTIVE', 'RESTORED_RECONCILIATION_REQUIRED',
  'LOCKED_ELSEWHERE', 'WRAPPER_AUTH_FAILED', 'INCOMPATIBLE_BUILD', 'INCOMPATIBLE_FORMAT', 'UNSUPPORTED_VERSION',
  'SELECTOR_INVALID', 'AUTHENTICATION_FAILED', 'MANIFEST_INVALID', 'RECORD_SET_INCOMPLETE', 'RECORD_INVALID',
  'REFERENCE_INCONSISTENT', 'PARTIAL_GENERATION', 'INTERNAL_VALIDATION_FAILED',
];

// ------------------------------------------------------------------------------------------------
// Builders over the real merged modules.
// ------------------------------------------------------------------------------------------------

const token = (seed) => {
  const t = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) t[i] = (seed * 31 + i * 7 + 1) & 0xff || 1;
  return t;
};
const START_TOKEN = token(3);
const ZERO = new Uint8Array(32);
const marker = (state, bindingToken = START_TOKEN) => encodeMarker({ state, bindingToken: state === ABSENT ? ZERO : bindingToken });

const request = (operation, input) => ({
  api: M2_ADAPTER.API, operation, requestId: 'req-reest', profile: { ...M2_ADAPTER.PROFILE },
  bindingRef: new Uint8Array([0xa1, 0xa2]), input,
});

/** The closed adapter input of one `RESTORE` whose C-REST result is `result`. */
const RESTORE_OBSERVATIONS = {
  NO_M2_STATE: { faults: [], inventory: 'NONE', legacy: false, vector: null, selectorState: 'EMPTY' },
  LEGACY_ONLY: { faults: [], inventory: 'LEGACY_ONLY', legacy: true, vector: null, selectorState: 'EMPTY' },
  RESTORED_ACTIVE: { faults: [], inventory: 'M2', legacy: true, vector: 'FMT-KAT-ACTIVE', selectorState: 'ACTIVE' },
  RESTORED_EMPTY: { faults: [], inventory: 'M2', legacy: true, vector: 'FMT-KAT-EMPTY', selectorState: 'EMPTY' },
  RESTORED_RECONCILIATION_REQUIRED: { faults: [], inventory: 'M2', legacy: true, vector: 'FMT-KAT-HOLD', selectorState: 'RECONCILIATION_REQUIRED' },
  LOCKED_ELSEWHERE: { faults: ['lockUnavailable'], inventory: 'M2', legacy: true, vector: 'FMT-KAT-ACTIVE', selectorState: 'ACTIVE' },
};
const restore = (result) => ({
  request: request('RESTORE', {}),
  snapshot: createAdapterSnapshot('EMPTY'),
  observation: { restoreObservation: { ...RESTORE_OBSERVATIONS[result], faults: [...RESTORE_OBSERVATIONS[result].faults] } },
});
const createOp = (commitOutcome = 'COMMITTED') => ({
  request: request('CREATE', { peerFramedKeyPackage: new Uint8Array([0x01]) }),
  snapshot: createAdapterSnapshot('EMPTY'),
  observation: {
    onboarding: 'SUPPORTED', commitOutcome, operationIdentity: 'op-reest-1',
    stagedOutput: { embeddedTreeWelcome: new Uint8Array([0x11, 0x22]) },
  },
});
const CONSENT = () => ({ prompt: 'SHOW_REESTABLISHMENT', accepted: true });

/** The `CREATE_SESSION` adapter result of one consented session creation, from a PENDING marker. */
const committedCreate = (commitOutcome = 'COMMITTED') => createNewSession({
  lockHeld: true, marker: marker(PENDING), consent: CONSENT(), operation: createOp(commitOutcome),
}).adapterResult;

const ending = (fn) => {
  try {
    fn();
    return 'ok';
  } catch (error) {
    return error instanceof M2ReestablishmentError ? `M2ReestablishmentError:${error.code}` : `foreign:${error?.constructor?.name}`;
  }
};
const hex = (b) => Buffer.from(b).toString('hex');
const STEP_RECORD_KEYS = ['step', 'disposition', 'accepted', 'stateBefore', 'stateAfter', 'legacyEligible', 'reject',
  'firstFailingPhase', 'committed', 'adapterResult', 'marker', 'diagnostics'].join(',');

/** Replay one C-REC `MARKER` fixture through the public step function its event belongs to. */
function replayMarkerFixture(row) {
  const i = row.input;
  const m = marker(i.state);
  const restoreResult = i.restoreResult ?? (i.state === ABSENT || i.state === PENDING ? 'LEGACY_ONLY' : 'RESTORED_ACTIVE');
  switch (i.event) {
    case EV.START:
      return startReestablishment({ lockHeld: i.lockHeld, marker: m, consent: CONSENT(), restore: restore(restoreResult), startToken: START_TOKEN });
    case EV.CANCEL:
      return cancelReestablishment({ lockHeld: i.lockHeld, marker: m, restore: restore(restoreResult) });
    case EV.CONFIRM: {
      // `distinct: false` is a presented token that is not the marker's own start token: the stale row
      // presents an earlier token of this browser, the cross-session row another session's token.
      const presented = i.distinct ? START_TOKEN : (row.id === 'NEG-STALE-TOKEN' ? token(1) : token(200));
      return confirmReestablishment({
        lockHeld: i.lockHeld, marker: m, createResult: committedCreate(i.committed ? 'COMMITTED' : 'NOT_COMMITTED'),
        authorityToken: presented, restore: restore(restoreResult),
      });
    }
    default:
      return completeReestablishment({ lockHeld: i.lockHeld, marker: m, restore: restore(restoreResult) });
  }
}

// ------------------------------------------------------------------------------------------------

describe('L-REEST module surface', () => {
  test('exactly the eleven named exports exist and nothing else', () => {
    expect(Object.keys(reest).sort()).toEqual([
      'M2ReestablishmentError', 'M2_REESTABLISHMENT', 'cancelReestablishment', 'completeReestablishment',
      'confirmReestablishment', 'createNewSession', 'guidanceFor', 'legacyActionDecision', 'legacyPresenceOf',
      'resumeFor', 'startReestablishment',
    ].sort());
  });

  test('the metadata is frozen, has the exact key set and publishes the C-REC facts verbatim', () => {
    expect(Object.isFrozen(M2_REESTABLISHMENT)).toBe(true);
    expect(Object.keys(M2_REESTABLISHMENT).sort()).toEqual([
      'SCHEMA', 'OWNER', 'ENCODING_OWNER', 'PHYSICAL_INVENTORY_OWNER', 'STEPS', 'DISPOSITIONS', 'REJECT_CODES',
      'PHASES', 'GUIDANCE_DISPOSITIONS', 'GUIDANCE_REJECT_CODES', 'OWNED_DISPATCH_ROWS', 'RESTORE_RESULTS', 'COPY',
      'CONSENT_PROMPT', 'SESSION_OPERATIONS', 'RESUME', 'LEGACY_ACTION_REJECTS', 'ERROR_CODES', 'DIAGNOSTIC_FIELDS',
      'VISIBLE_CONSENT_REQUIRED', 'BINDING', 'TIME_OR_FRESHNESS_COMPARISON', 'REVERSE_AFTER_CONFIRMATION',
      'REAL_CONFIRMATION_BLOCKED_UNTIL_OWNERS_RATIFIED', 'PERSISTS_MARKER', 'IMPORT', 'DECRYPT', 'TRANSLATE',
      'COPY_LEGACY', 'SELECT_LEGACY', 'DECODE_LEGACY_AS_M2', 'FALLBACK', 'PRESERVE_BYTES', 'CLEANUP',
    ].sort());
    const M = M2_REESTABLISHMENT;
    expect(M.SCHEMA).toBe('styx-m2-session-reestablishment/v1');
    expect(M.OWNER).toBe('L-REEST');
    expect(M.OWNER).toBe(M2_LEGACY_INVALIDATION.NEW_SESSION_OWNER);
    expect(M.ENCODING_OWNER).toBe('L-MARK');
    expect(M.PHYSICAL_INVENTORY_OWNER).toBe('L-INV');
    expect(M.BINDING).toBe('OPAQUE_START_AUTHORITY_CONFIRMATION_TOKEN_EQUALITY');
    expect(M.VISIBLE_CONSENT_REQUIRED).toBe(true);
    expect(M.TIME_OR_FRESHNESS_COMPARISON).toBe(false);
    expect(M.REVERSE_AFTER_CONFIRMATION).toBe(false);
    expect(M.REAL_CONFIRMATION_BLOCKED_UNTIL_OWNERS_RATIFIED).toBe(true);
    expect(M.PERSISTS_MARKER).toBe(false);
    for (const flag of ['IMPORT', 'DECRYPT', 'TRANSLATE', 'COPY_LEGACY', 'SELECT_LEGACY', 'DECODE_LEGACY_AS_M2', 'FALLBACK']) {
      expect(`${flag}:${M[flag]}`).toBe(`${flag}:false`);
    }
    expect(M.PRESERVE_BYTES).toBe(true);
    expect(M.CLEANUP).toBe('DEFERRED');
    expect([...M.RESTORE_RESULTS]).toEqual(CREC_RESTORE_RESULTS);
    expect([...M.DIAGNOSTIC_FIELDS]).toEqual(CREC_DIAGNOSTICS_ALLOWED);
    expect([...M.STEPS]).toEqual(['START', 'CANCEL', 'CREATE_SESSION', 'CONFIRM', 'COMPLETE']);
    expect([...M.DISPOSITIONS]).toEqual(['MARKER_TRANSITION', 'SESSION_OPERATION', 'LOCK_RETRY', 'REJECT']);
    expect([...M.ERROR_CODES]).toEqual(['INVALID_INPUT', 'MARKER_INVALID', 'INVENTORY_INVALID']);
    expect({ ...M.RESUME }).toEqual({
      [ABSENT]: 'GUIDANCE', [PENDING]: 'CONFIRM_OR_CANCEL', [CONFIRMED]: 'MARKER_COMPLETION_ONLY', [INVALIDATED]: 'NONE',
    });
  });

  test('the module imports exactly the four merged modules and no browser or storage surface', () => {
    const source = readFileSync(MODULE_PATH, 'utf8');
    const specifiers = [...source.matchAll(/^import\s+(?:[^'"]*?from\s+)?'([^']+)';$/gms)].map((m) => m[1]);
    expect(specifiers).toEqual([
      '../../../../../src/storage/m2/legacy-session-invalidation.js',
      '../../../../../src/storage/m2/legacy-session-inventory.js',
      '../../../../../src/crypto/mls/m2/adapter.js',
      '../../../../../src/storage/m2/session-restore.js',
    ]);
    const code = source.replace(/^\s*\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '');
    for (const forbidden of ['indexedDB', 'localStorage', 'sessionStorage', 'navigator', 'document', 'window',
      'Worker', 'postMessage', 'fetch(', 'Date', 'performance', 'setTimeout', 'Math.random', 'crypto.', 'require(', 'import(']) {
      expect(`${forbidden}:${code.includes(forbidden)}`).toBe(`${forbidden}:false`);
    }
  });
});

describe('C-REC SHOW_REESTABLISHMENT / SHOW_CREATE dispatch rows', () => {
  test('the owned dispatch rows equal the C-REC /dispatchRows bytes and pair with the reachable rows', () => {
    for (const row of CREC_OWNED_DISPATCH_ROWS) {
      const owned = M2_REESTABLISHMENT.OWNED_DISPATCH_ROWS[row.result];
      const { legacyPresent, ...dispatch } = owned;
      expect(dispatch).toEqual(row);
      const reachable = CREC_OWNED_REACHABLE_ROWS.find((r) => r.result === row.result);
      expect(legacyPresent).toBe(reachable.legacyPresent);
      expect(reachable.disposition).toBe(row.disposition);
    }
    expect(Object.keys(M2_REESTABLISHMENT.OWNED_DISPATCH_ROWS).sort()).toEqual(['LEGACY_ONLY', 'NO_M2_STATE']);
  });

  for (const row of CREC_DISPATCH_FIXTURES) {
    test(`${row.id} replays verbatim`, () => {
      const g = guidanceFor(row.input);
      expect(g.disposition).toBe(row.expected.agreement.disposition);
      expect(g.firstFailingPhase).toBe(row.expected.agreement.firstFailingPhase);
      expect(g.markerState).toBe(row.expected.agreement.markerState);
      expect(g.authority).toBe(row.expected.agreement.authorityIdentity);
      if (row.expected.reject) {
        expect(g.reject).toBe(row.expected.reject);
        expect(g.copy).toBeNull();
        expect(g.consentRequired).toBe(false);
      } else {
        expect(g.reject).toBeNull();
        expect(g.disposition).toBe(row.expected.disposition);
        expect(g.authority).toBe(row.expected.authority);
        expect(g.resetEligible).toBe(row.expected.resetEligible);
        expect(g.byteAction).toBe('PRESERVE');
      }
    });
  }

  test('LEGACY_ONLY shows visible re-establishment guidance that requires consent and never converts', () => {
    const g = guidanceFor({ result: 'LEGACY_ONLY', legacyPresent: true });
    expect(g.consentRequired).toBe(true);
    expect(g.copy).toBe(M2_REESTABLISHMENT.COPY.SHOW_REESTABLISHMENT);
    expect(g.copy.accept.length).toBeGreaterThan(0);
    expect(g.copy.decline.length).toBeGreaterThan(0);
    const text = Object.values(g.copy).join(' ').toLowerCase();
    for (const word of ['convert', 'conver', 'import', 'migra', 'recuper', 'ripristin', 'trasferit']) {
      if (word === 'trasferit') {
        expect(text).toContain('né trasferita'); // stated only as a negation
      } else {
        expect(`${word}:${text.includes(word)}`).toBe(`${word}:false`);
      }
    }
    expect(text).toContain('resta intatta');
  });

  test('NO_M2_STATE shows creation without asserting prior absence, deletion, freshness or rollback', () => {
    const g = guidanceFor({ result: 'NO_M2_STATE', legacyPresent: false });
    expect(g.consentRequired).toBe(false);
    expect(g.copy).toBe(M2_REESTABLISHMENT.COPY.SHOW_CREATE);
    const text = Object.values(g.copy).join(' ').toLowerCase();
    for (const word of ['mai ', 'nessuna sessione', 'eliminat', 'cancellat', 'aggiornat', 'rollback', 'recente', 'sicur', 'legacy', 'precedente']) {
      expect(`${word}:${text.includes(word)}`).toBe(`${word}:false`);
    }
  });

  test('the two texts are distinct from each other (C-REC §9 user-visible distinctions)', () => {
    const { SHOW_CREATE, SHOW_REESTABLISHMENT } = M2_REESTABLISHMENT.COPY;
    expect(SHOW_CREATE.title).not.toBe(SHOW_REESTABLISHMENT.title);
    expect(SHOW_CREATE.accept).not.toBe(SHOW_REESTABLISHMENT.accept);
    expect(SHOW_REESTABLISHMENT.body.toLowerCase()).toContain('nuova sessione');
  });

  test('every other C-REST result is not a re-establishment result, and malformed inputs reject closed', () => {
    // C-REC /reachableConditionRows decide reachability for every result: an unreachable pair is
    // UNREACHABLE_CONDITION_PAIR; any other reachable result outside the two owned rows is
    // NOT_REESTABLISHMENT_RESULT (r2 DeepSeek LOW-1: NEG-LOCKED-LEGACY, NEG-BUILD-LEGACY).
    expect(CREC_REACHABLE_PAIRS).toHaveLength(32);
    let unreachable = 0;
    for (const result of CREC_RESTORE_RESULTS) {
      for (const legacyPresent of [false, true]) {
        const g = guidanceFor({ result, legacyPresent });
        const pair = `${result}:${legacyPresent}`;
        let want = 'NOT_REESTABLISHMENT_RESULT';
        if (!CREC_REACHABLE_PAIRS.includes(pair)) {
          want = 'UNREACHABLE_CONDITION_PAIR';
          unreachable += 1;
        } else if (pair === 'NO_M2_STATE:false' || pair === 'LEGACY_ONLY:true') {
          want = null;
        }
        expect(`${pair}:${g.reject}`).toBe(`${pair}:${want}`);
      }
    }
    expect(unreachable).toBe(4);
    expect(guidanceFor({ result: 'LEGACY_ONLY', legacyPresent: false }).reject).toBe('UNREACHABLE_CONDITION_PAIR');
    expect(guidanceFor(null).reject).toBe('MISSING_DISPATCH_INPUT');
    expect(guidanceFor({ legacyPresent: true }).reject).toBe('MISSING_DISPATCH_INPUT');
    expect(guidanceFor({ result: 'LEGACY_ONLY', legacyPresent: 'yes' }).reject).toBe('MISSING_DISPATCH_INPUT');
    expect(guidanceFor({ result: 'toString', legacyPresent: true }).reject).toBe('UNKNOWN_RESULT');
    let read = 0;
    const accessor = { get result() { read += 1; return 'LEGACY_ONLY'; }, legacyPresent: true };
    expect(guidanceFor(accessor).reject).toBe('MISSING_DISPATCH_INPUT');
    expect(read).toBe(0);
    // The input is exactly { result, legacyPresent }: an extra or symbol member, or another prototype,
    // rejects closed and never reaches an owned row (r1 GPT-6.1 Sol M2, Muse N1).
    const closedInputs = [
      { result: 'LEGACY_ONLY', legacyPresent: true, extra: 1 },
      { result: 'LEGACY_ONLY', legacyPresent: true, [Symbol('s')]: 1 },
      Object.assign(Object.create(null), { result: 'LEGACY_ONLY', legacyPresent: true }),
      Object.defineProperty({ result: 'LEGACY_ONLY', legacyPresent: true }, 'other', { get() { read += 1; return 1; }, enumerable: false }),
    ];
    for (const [i, input] of closedInputs.entries()) {
      const g = guidanceFor(input);
      expect(`${i}:${g.disposition}:${g.reject}:${g.copy}`).toBe(`${i}:REJECT:MISSING_DISPATCH_INPUT:null`);
    }
    expect(read).toBe(0);
  });

  test('the guidance diagnostics carry only the six allowlisted value-free fields', () => {
    for (const row of CREC_DISPATCH_FIXTURES) {
      const g = guidanceFor(row.input);
      expect(Object.keys(g.diagnostics)).toEqual(CREC_DIAGNOSTICS_ALLOWED);
    }
  });
});

describe('legacy presence comes from the merged L-INV inventory', () => {
  const selector = () => encodeSelectorKey({ localContextId: new Uint8Array(32).fill(7) });
  const legacyKey = (s) => new TextEncoder().encode(`styx-mls:legacy-session:${s}`);

  test('a legacy-only key space reports legacyPresent and a bounded count, and pairs with SHOW_REESTABLISHMENT', () => {
    const keys = [legacyKey('a'), legacyKey('b'), legacyKey('c')];
    const before = keys.map(hex);
    const presence = legacyPresenceOf(keys);
    expect(presence).toEqual({ legacyPresent: true, boundedCount: 3 });
    expect(Object.isFrozen(presence)).toBe(true);
    expect(keys.map(hex)).toEqual(before);
    expect(guidanceFor({ result: 'LEGACY_ONLY', legacyPresent: presence.legacyPresent }).disposition).toBe('SHOW_REESTABLISHMENT');
  });

  test('an empty key space pairs with SHOW_CREATE, and an M2 key space is not legacy-only', () => {
    expect(legacyPresenceOf([])).toEqual({ legacyPresent: false, boundedCount: 0 });
    expect(guidanceFor({ result: 'NO_M2_STATE', legacyPresent: false }).disposition).toBe('SHOW_CREATE');
    const withM2 = legacyPresenceOf([selector(), legacyKey('x')]);
    expect(withM2).toEqual({ legacyPresent: true, boundedCount: 1 });
  });

  test('a malformed key space is INVENTORY_INVALID, never a foreign exception', () => {
    expect(ending(() => legacyPresenceOf('nope'))).toBe('M2ReestablishmentError:INVENTORY_INVALID');
    expect(ending(() => legacyPresenceOf([1, 2]))).toBe('M2ReestablishmentError:INVENTORY_INVALID');
    expect(ending(() => legacyPresenceOf(new Proxy([], { getOwnPropertyDescriptor() { throw new Error('trap'); } }))))
      .toBe('M2ReestablishmentError:INVENTORY_INVALID');
    const record = encodeRecordKey({ scope: 1, localContextId: new Uint8Array(32).fill(7), secureSessionIdentity: null, writeGeneration: 1n, recordKind: 1 });
    expect(legacyPresenceOf([selector(), record])).toEqual({ legacyPresent: false, boundedCount: 0 });
  });
});

describe('C-REC MARKER fixtures replay through the public steps', () => {
  test('C-REC has thirteen MARKER rows and all thirteen are transcribed', () => {
    expect(CREC_MARKER_FIXTURES).toHaveLength(13);
    expect(new Set(CREC_MARKER_FIXTURES.map((r) => r.id)).size).toBe(13);
  });

  for (const row of CREC_MARKER_FIXTURES) {
    test(`${row.id}`, () => {
      const d = replayMarkerFixture(row);
      expect(d.disposition).toBe(row.expected.agreement.disposition);
      expect(d.firstFailingPhase).toBe(row.expected.agreement.firstFailingPhase);
      if (row.expected.accepted) {
        expect(d.accepted).toBe(true);
        expect(d.reject).toBeNull();
        expect(d.stateAfter).toBe(row.expected.state);
        expect(readMarker(d.marker).state).toBe(row.expected.state);
        expect(d.legacyEligible).toBe(M2_LEGACY_INVALIDATION.LEGACY_ELIGIBLE_BY_STATE[row.expected.state]);
      } else {
        expect(d.accepted).toBe(false);
        expect(d.reject).toBe(row.expected.reject);
        expect(d.marker).toBeNull();
        if (row.expected.agreement.markerState === 'UNCHANGED') {
          expect(d.stateBefore).toBeNull();
          expect(d.stateAfter).toBeNull();
          expect(d.legacyEligible).toBeNull();
        } else {
          expect(d.stateAfter).toBe(row.expected.agreement.markerState);
        }
      }
    });
  }
});

describe('the consented end-to-end re-establishment', () => {
  test('guidance, consent, START, CREATE, RESTORED_ACTIVE, CONFIRM, COMMIT and REPEAT, and never a legacy byte', () => {
    const legacyKeys = [new TextEncoder().encode('styx-mls:legacy-session:only')];
    const legacyBefore = legacyKeys.map(hex);
    const presence = legacyPresenceOf(legacyKeys);
    const guidance = guidanceFor({ result: 'LEGACY_ONLY', legacyPresent: presence.legacyPresent });
    expect(guidance.disposition).toBe('SHOW_REESTABLISHMENT');

    let m = marker(ABSENT);
    expect(resumeFor(m).resume).toBe('GUIDANCE');

    const started = startReestablishment({ lockHeld: true, marker: m, consent: CONSENT(), restore: restore('LEGACY_ONLY'), startToken: START_TOKEN });
    expect([started.accepted, started.stateAfter, started.legacyEligible]).toEqual([true, PENDING, true]);
    m = started.marker;

    const created = createNewSession({ lockHeld: true, marker: m, consent: CONSENT(), operation: createOp() });
    expect([created.disposition, created.committed, created.stateAfter]).toEqual(['SESSION_OPERATION', true, PENDING]);
    expect(created.adapterResult.successCode).toBe('CREATED');
    expect(created.marker).toBeNull();

    const confirmed = confirmReestablishment({ lockHeld: true, marker: m, createResult: created.adapterResult, authorityToken: START_TOKEN, restore: restore('RESTORED_ACTIVE') });
    expect([confirmed.accepted, confirmed.stateAfter, confirmed.legacyEligible]).toEqual([true, CONFIRMED, false]);
    m = confirmed.marker;
    expect(resumeFor(m).resume).toBe('MARKER_COMPLETION_ONLY');

    const committed = completeReestablishment({ lockHeld: true, marker: m, restore: restore('RESTORED_ACTIVE') });
    expect([committed.accepted, committed.stateAfter, committed.legacyEligible]).toEqual([true, INVALIDATED, false]);
    m = committed.marker;

    const repeated = completeReestablishment({ lockHeld: true, marker: m, restore: restore('RESTORED_ACTIVE') });
    expect([repeated.accepted, repeated.stateAfter]).toEqual([true, INVALIDATED]);
    expect(hex(repeated.marker)).toBe(hex(m)); // repeated completion is idempotent, byte for byte

    expect(legacyKeys.map(hex)).toEqual(legacyBefore); // invalidation never touches a legacy byte
  });

  test('the start token is the one stored in the marker, and CONFIRM binds to it by byte equality', () => {
    const started = startReestablishment({ lockHeld: true, marker: marker(ABSENT), consent: CONSENT(), restore: restore('LEGACY_ONLY'), startToken: token(42) });
    expect(hex(started.marker)).toBe(hex(encodeMarker({ state: PENDING, bindingToken: token(42) })));
    const create = committedCreate();
    const confirmWith = (t) => confirmReestablishment({ lockHeld: true, marker: started.marker, createResult: create, authorityToken: t, restore: restore('RESTORED_ACTIVE') });
    expect(confirmWith(token(42)).accepted).toBe(true);
    expect(confirmWith(START_TOKEN).reject).toBe('TOKEN_MISMATCH');
    const lastByte = token(42); lastByte[31] ^= 1;
    expect(confirmWith(lastByte).reject).toBe('TOKEN_MISMATCH');
    const midByte = token(42); midByte[16] ^= 0x80;
    expect(confirmWith(midByte).reject).toBe('TOKEN_MISMATCH');
    expect(confirmWith(token(42).subarray(0, 31)).reject).toBe('TOKEN_MISMATCH');
    expect(confirmWith('a'.repeat(32)).reject).toBe('TOKEN_MISMATCH');
  });

  test('CONFIRM keeps the stored start token byte-for-byte and changes only the state byte', () => {
    const pending = marker(PENDING, token(9));
    const out = confirmReestablishment({ lockHeld: true, marker: pending, createResult: committedCreate(), authorityToken: token(9), restore: restore('RESTORED_ACTIVE') }).marker;
    expect(hex(out)).toBe(hex(encodeMarker({ state: CONFIRMED, bindingToken: token(9) })));
    const diff = [...out].map((b, i) => (b === pending[i] ? null : i)).filter((i) => i !== null);
    expect(diff).toEqual([11]);
  });

  test('CANCEL before confirmation returns to ABSENT with an all-zero token and preserves legacy eligibility', () => {
    const d = cancelReestablishment({ lockHeld: true, marker: marker(PENDING), restore: restore('LEGACY_ONLY') });
    expect([d.accepted, d.stateAfter, d.legacyEligible]).toEqual([true, ABSENT, true]);
    expect(hex(d.marker)).toBe(hex(marker(ABSENT)));
  });
});

describe('visible consent is required', () => {
  const bad = [
    ['no consent', null],
    ['declined', { prompt: 'SHOW_REESTABLISHMENT', accepted: false }],
    ['wrong prompt', { prompt: 'SHOW_CREATE', accepted: true }],
    ['truthy, not true', { prompt: 'SHOW_REESTABLISHMENT', accepted: 1 }],
    ['extra member', { prompt: 'SHOW_REESTABLISHMENT', accepted: true, silent: true }],
    ['accessor', { prompt: 'SHOW_REESTABLISHMENT', get accepted() { return true; } }],
    ['array', ['SHOW_REESTABLISHMENT', true]],
    // r4 GPT-6.1 Sol H4: two keys, but not `prompt` and `accepted`; a trap synthesizes the missing `prompt`.
    ['key set without prompt', new Proxy({ accepted: true, extra: true }, {
      getOwnPropertyDescriptor(target, key) {
        if (key === 'prompt') return { value: 'SHOW_REESTABLISHMENT', enumerable: true, configurable: true, writable: true };
        return Reflect.getOwnPropertyDescriptor(target, key);
      },
    })],
  ];
  for (const [name, consent] of bad) {
    test(`START refuses ${name} with CONSENT_REQUIRED and changes nothing`, () => {
      const m = marker(ABSENT);
      const before = hex(m);
      const d = startReestablishment({ lockHeld: true, marker: m, consent, restore: restore('LEGACY_ONLY'), startToken: START_TOKEN });
      expect([d.disposition, d.reject, d.firstFailingPhase, d.stateAfter]).toEqual(['REJECT', 'CONSENT_REQUIRED', 'CONSENT_GATE', ABSENT]);
      expect(d.marker).toBeNull();
      expect(hex(m)).toBe(before);
    });
    test(`CREATE_SESSION refuses ${name} with CONSENT_REQUIRED and never reaches the adapter`, () => {
      // The operation input is a Proxy that counts every inspection, traps included: the passive copy
      // and the merged adapter both inspect it, so reaching either before the consent gate would count
      // (r3 GPT-6.1 Sol M3: plain getters are never invoked by either, so they cannot show this).
      let operationReads = 0;
      const count = (fn) => (...args) => {
        operationReads += 1;
        return fn(...args);
      };
      const watched = new Proxy(createOp(), {
        get: count(Reflect.get),
        getPrototypeOf: count(Reflect.getPrototypeOf),
        ownKeys: count(Reflect.ownKeys),
        getOwnPropertyDescriptor: count(Reflect.getOwnPropertyDescriptor),
        has: count(Reflect.has),
      });
      const d = createNewSession({ lockHeld: true, marker: marker(PENDING), consent, operation: watched });
      expect([d.disposition, d.reject, d.firstFailingPhase]).toEqual(['REJECT', 'CONSENT_REQUIRED', 'CONSENT_GATE']);
      expect(d.adapterResult).toBeNull();
      expect(operationReads).toBe(0);
    });
  }

  test('consent is checked before the restore evidence', () => {
    const d = startReestablishment({ lockHeld: true, marker: marker(ABSENT), consent: null, restore: restore('NO_M2_STATE'), startToken: START_TOKEN });
    expect(d.reject).toBe('CONSENT_REQUIRED');
  });
});

describe('the one-writer lock', () => {
  const steps = {
    START: (lockHeld) => startReestablishment({ lockHeld, marker: marker(ABSENT), consent: CONSENT(), restore: restore('LEGACY_ONLY'), startToken: START_TOKEN }),
    CANCEL: (lockHeld) => cancelReestablishment({ lockHeld, marker: marker(PENDING), restore: restore('LEGACY_ONLY') }),
    CREATE_SESSION: (lockHeld) => createNewSession({ lockHeld, marker: marker(PENDING), consent: CONSENT(), operation: createOp() }),
    CONFIRM: (lockHeld) => confirmReestablishment({ lockHeld, marker: marker(PENDING), createResult: committedCreate(), authorityToken: START_TOKEN, restore: restore('RESTORED_ACTIVE') }),
    COMPLETE: (lockHeld) => completeReestablishment({ lockHeld, marker: marker(CONFIRMED), restore: restore('RESTORED_ACTIVE') }),
  };
  for (const [step, run] of Object.entries(steps)) {
    test(`${step} without the lock is LOCK_RETRY / LOCKED_ELSEWHERE and discloses nothing`, () => {
      const d = run(false);
      expect(d.step).toBe(step);
      expect([d.disposition, d.reject, d.firstFailingPhase, d.accepted]).toEqual(['LOCK_RETRY', 'LOCKED_ELSEWHERE', 'LOCK', false]);
      expect([d.stateBefore, d.stateAfter, d.legacyEligible, d.marker, d.adapterResult, d.committed]).toEqual([null, null, null, null, null, null]);
      expect(run(true).disposition).not.toBe('LOCK_RETRY');
    });
  }

  test('the lock gate runs before any other member is read', () => {
    let reads = 0;
    const input = { lockHeld: false };
    for (const key of ['marker', 'consent', 'restore', 'startToken']) {
      Object.defineProperty(input, key, { enumerable: true, get() { reads += 1; return null; } });
    }
    expect(startReestablishment(input).disposition).toBe('LOCK_RETRY');
    expect(completeReestablishment(new Proxy({ lockHeld: false, marker: 1, restore: 2 }, {
      ownKeys() { reads += 1; return []; },
    })).disposition).toBe('LOCK_RETRY');
    expect(reads).toBe(0);
  });

  const inputs = {
    START: () => ({ marker: marker(ABSENT), consent: CONSENT(), restore: restore('LEGACY_ONLY'), startToken: START_TOKEN }),
    CANCEL: () => ({ marker: marker(PENDING), restore: restore('LEGACY_ONLY') }),
    CREATE_SESSION: () => ({ marker: marker(PENDING), consent: CONSENT(), operation: createOp() }),
    CONFIRM: () => ({ marker: marker(PENDING), createResult: committedCreate(), authorityToken: START_TOKEN, restore: restore('RESTORED_ACTIVE') }),
    COMPLETE: () => ({ marker: marker(CONFIRMED), restore: restore('RESTORED_ACTIVE') }),
  };
  const fns = {
    START: startReestablishment, CANCEL: cancelReestablishment, CREATE_SESSION: createNewSession,
    CONFIRM: confirmReestablishment, COMPLETE: completeReestablishment,
  };
  for (const step of Object.keys(inputs)) {
    test(`${step}: a lock flag that reads true and then false is LOCK_RETRY, never accepted`, () => {
      // r3 GPT-6.1 Sol H3: the flag flips between the lock gate and the closed read; the closed copy decides.
      const real = { lockHeld: true, ...inputs[step]() };
      const reads = [];
      const flipping = new Proxy(real, {
        ownKeys(target) {
          target.lockHeld = false;
          return Reflect.ownKeys(target);
        },
        getOwnPropertyDescriptor(target, key) {
          const d = Reflect.getOwnPropertyDescriptor(target, key);
          if (key === 'lockHeld') reads.push(d.value);
          return d;
        },
      });
      const d = fns[step](flipping);
      expect(reads).toEqual([true, false]);
      expect([d.step, d.disposition, d.reject, d.firstFailingPhase, d.accepted])
        .toEqual([step, 'LOCK_RETRY', 'LOCKED_ELSEWHERE', 'LOCK', false]);
      expect([d.stateBefore, d.stateAfter, d.legacyEligible, d.marker, d.adapterResult, d.committed])
        .toEqual([null, null, null, null, null, null]);
      // Control: the same input with a stable true flag is accepted.
      expect(fns[step]({ lockHeld: true, ...inputs[step]() }).accepted).toBe(true);
    });

    test(`${step}: an inherited lockHeld accessor cannot turn the captured false into true`, () => {
      // r4 GPT-6.1 Sol H3-R: a trap installs Object.prototype.lockHeld between the two lock reads; the
      // closed copy defines its members, so the inherited setter and getter are never used.
      const previous = Object.getOwnPropertyDescriptor(Object.prototype, 'lockHeld');
      const real = { lockHeld: true, ...inputs[step]() };
      const reads = [];
      let inherited = 0;
      const flipping = new Proxy(real, {
        ownKeys(target) {
          target.lockHeld = false;
          Object.defineProperty(Object.prototype, 'lockHeld', {
            configurable: true,
            get() { inherited += 1; return true; },
            set() { inherited += 1; },
          });
          return Reflect.ownKeys(target);
        },
        getOwnPropertyDescriptor(target, key) {
          const d = Reflect.getOwnPropertyDescriptor(target, key);
          if (key === 'lockHeld') reads.push(d.value);
          return d;
        },
      });
      let d;
      try {
        d = fns[step](flipping);
      } finally {
        if (previous) Object.defineProperty(Object.prototype, 'lockHeld', previous);
        else delete Object.prototype.lockHeld;
      }
      expect(reads).toEqual([true, false]);
      expect(inherited).toBe(0);
      expect([d.step, d.disposition, d.reject, d.firstFailingPhase, d.accepted])
        .toEqual([step, 'LOCK_RETRY', 'LOCKED_ELSEWHERE', 'LOCK', false]);
      expect([d.stateBefore, d.stateAfter, d.legacyEligible, d.marker, d.adapterResult, d.committed])
        .toEqual([null, null, null, null, null, null]);
    });

    test(`${step}: a captured false lock is LOCK_RETRY before any later member is inspected`, () => {
      // r4 GPT-6.1 Sol M4: a later descriptor that fails cannot preempt the lock refusal.
      const real = { lockHeld: true, ...inputs[step]() };
      const reads = [];
      const later = [];
      const flipping = new Proxy(real, {
        ownKeys(target) {
          target.lockHeld = false;
          return Reflect.ownKeys(target);
        },
        getOwnPropertyDescriptor(target, key) {
          if (key !== 'lockHeld') {
            later.push(key);
            throw new Error('later member inspected');
          }
          const d = Reflect.getOwnPropertyDescriptor(target, key);
          reads.push(d.value);
          return d;
        },
      });
      const d = fns[step](flipping);
      expect(reads).toEqual([true, false]);
      expect(later).toEqual([]);
      expect([d.step, d.disposition, d.reject, d.firstFailingPhase, d.accepted])
        .toEqual([step, 'LOCK_RETRY', 'LOCKED_ELSEWHERE', 'LOCK', false]);
    });
  }

  test('a non-boolean lockHeld is INVALID_INPUT', () => {
    for (const lockHeld of [undefined, 1, 'true', null]) {
      expect(ending(() => cancelReestablishment({ lockHeld, marker: marker(PENDING), restore: restore('LEGACY_ONLY') })))
        .toBe('M2ReestablishmentError:INVALID_INPUT');
    }
  });
});

describe('confirmation requires a distinct COMMITTED post-start authority later restored as RESTORED_ACTIVE', () => {
  const confirm = (overrides) => confirmReestablishment({
    lockHeld: true, marker: marker(PENDING), createResult: committedCreate(), authorityToken: START_TOKEN,
    restore: restore('RESTORED_ACTIVE'), ...overrides,
  });

  test('EMPTY and reconciliation evidence cannot confirm', () => {
    expect(confirm({ restore: restore('RESTORED_EMPTY') }).reject).toBe('CONFIRMATION_PRECONDITION_FAILED');
    expect(confirm({ restore: restore('RESTORED_RECONCILIATION_REQUIRED') }).reject).toBe('CONFIRMATION_PRECONDITION_FAILED');
  });

  test('failure and inventory evidence cannot confirm, and a failure never reaches the marker', () => {
    for (const r of ['LOCKED_ELSEWHERE', 'LEGACY_ONLY', 'NO_M2_STATE']) {
      const d = confirm({ restore: restore(r) });
      expect(`${r}:${d.reject}`).toBe(`${r}:CONFIRMATION_PRECONDITION_FAILED`);
      expect(d.stateAfter).toBe(PENDING);
    }
    expect(confirm({ restore: restore('LOCKED_ELSEWHERE') }).firstFailingPhase).toBe('RESTORE_GATE');
  });

  test('a NOT_COMMITTED or INDETERMINATE creation cannot confirm', () => {
    expect(confirm({ createResult: committedCreate('NOT_COMMITTED') }).reject).toBe('CONFIRMATION_PRECONDITION_FAILED');
    const indeterminate = committedCreate('INDETERMINATE');
    expect(indeterminate.kind).toBe('INDETERMINATE');
    expect(confirm({ createResult: indeterminate }).reject).toBe('CONFIRMATION_PRECONDITION_FAILED');
  });

  test('candidate or forged evidence cannot confirm: only a SUCCESS CREATED/JOINED COMMITTED adapter record counts', () => {
    const good = committedCreate();
    const forged = [
      { ...good, kind: 'NO_CHANGE' },
      { ...good, successCode: 'CANDIDATE_SELECTED' },
      { ...good, successCode: 'RECONCILED_COMMITTED' },
      { ...good, operation: 'RESTORE', successCode: 'RESTORED' },
      { ...good, commitOutcome: 'INDETERMINATE' },
      { kind: 'SUCCESS', successCode: 'CREATED', commitOutcome: 'COMMITTED' },
      Object.defineProperty({ ...good }, 'commitOutcome', { get() { return 'COMMITTED'; }, enumerable: true }),
      null,
    ];
    for (const createResult of forged) {
      expect(confirm({ createResult }).reject).toBe('CONFIRMATION_PRECONDITION_FAILED');
    }
    expect(confirm({ createResult: good }).accepted).toBe(true);
  });

  test('the creation result must be the complete closed C-API record, not only its four deciding members', () => {
    const good = committedCreate();
    const without = (key) => {
      const copy = { ...good };
      delete copy[key];
      return copy;
    };
    const forged = [
      // r1 GPT-6.1 Sol H1: the four deciding members alone, with no adapter call behind them.
      { operation: 'CREATE', kind: 'SUCCESS', successCode: 'CREATED', commitOutcome: 'COMMITTED' },
      ...['api', 'requestId', 'operation', 'kind', 'stateBefore', 'stateAfter', 'successCode', 'commitOutcome', 'output']
        .map(without),
      { ...good, extra: 1 },
      Object.assign({ ...good }, { [Symbol('s')]: 1 }),
      Object.defineProperty({ ...good }, 'api', { get() { return M2_ADAPTER.API; }, enumerable: true }),
      { ...good, api: 'styx-m2-session-adapter/v0' },
      { ...good, requestId: '' },
      { ...good, requestId: 7 },
      { ...good, stateBefore: 'ACTIVE' },
      { ...good, stateAfter: 'EMPTY' },
      { ...good, stateAfter: 'RECONCILIATION_REQUIRED' },
      { ...good, output: {} },
      { ...good, output: { embeddedTreeWelcome: new Uint8Array(0) } },
      { ...good, output: { embeddedTreeWelcome: [1, 2] } },
      { ...good, output: { embeddedTreeWelcome: new Uint8Array([1]), extra: 1 } },
      { ...good, operation: 'JOIN_WELCOME', successCode: 'JOINED' },
      Object.setPrototypeOf({ ...good }, null),
    ];
    for (const [i, createResult] of forged.entries()) {
      const d = confirm({ createResult });
      expect(`${i}:${d.reject}:${d.stateAfter}`).toBe(`${i}:CONFIRMATION_PRECONDITION_FAILED:${PENDING}`);
    }
    expect(confirm({ createResult: { ...good } }).accepted).toBe(true);
  });

  test('the binding is checked before the restore precondition, which is checked before committed', () => {
    expect(confirm({ authorityToken: token(77), restore: restore('RESTORED_EMPTY'), createResult: null }).reject).toBe('TOKEN_MISMATCH');
    expect(confirm({ restore: restore('RESTORED_EMPTY'), createResult: null }).reject).toBe('CONFIRMATION_PRECONDITION_FAILED');
  });

  test('a session can be created only while the marker is PENDING_NEW_SESSION', () => {
    for (const state of [ABSENT, CONFIRMED, INVALIDATED]) {
      const d = createNewSession({ lockHeld: true, marker: marker(state), consent: CONSENT(), operation: createOp() });
      expect(`${state}:${d.reject}:${d.adapterResult}`).toBe(`${state}:MARKER_NOT_PENDING:null`);
    }
  });

  test('createNewSession accepts only CREATE or JOIN_WELCOME adapter inputs', () => {
    const restoreOp = restore('RESTORED_ACTIVE');
    expect(ending(() => createNewSession({ lockHeld: true, marker: marker(PENDING), consent: CONSENT(), operation: restoreOp })))
      .toBe('M2ReestablishmentError:INVALID_INPUT');
    const join = {
      request: request('JOIN_WELCOME', { embeddedTreeWelcome: new Uint8Array([0x02]) }),
      snapshot: createAdapterSnapshot('EMPTY'),
      observation: { keyPackage: 'MATCHED', commitOutcome: 'COMMITTED', operationIdentity: 'op-join' },
    };
    const d = createNewSession({ lockHeld: true, marker: marker(PENDING), consent: CONSENT(), operation: join });
    expect([d.disposition, d.adapterResult.successCode, d.committed]).toEqual(['SESSION_OPERATION', 'JOINED', true]);
    expect(confirmReestablishment({ lockHeld: true, marker: marker(PENDING), createResult: d.adapterResult, authorityToken: START_TOKEN, restore: restore('RESTORED_ACTIVE') }).accepted).toBe(true);
  });

  test('a rejected session creation is reported closed and not committed', () => {
    const op = createOp();
    op.snapshot = createAdapterSnapshot('ACTIVE');
    const d = createNewSession({ lockHeld: true, marker: marker(PENDING), consent: CONSENT(), operation: op });
    expect([d.disposition, d.accepted, d.committed, d.adapterResult.kind]).toEqual(['SESSION_OPERATION', false, false, 'REJECTED']);
  });
});

describe('restore evidence is double-checked', () => {
  test('a RESTORE observation the adapter and the classifier disagree on is RESTORE_EVIDENCE_INCONSISTENT', () => {
    // The adapter rejects a non-EMPTY snapshot restore; the classifier alone would say RESTORED_ACTIVE.
    const r = restore('RESTORED_ACTIVE');
    r.snapshot = createAdapterSnapshot('ACTIVE');
    const d = confirmReestablishment({ lockHeld: true, marker: marker(PENDING), createResult: committedCreate(), authorityToken: START_TOKEN, restore: r });
    expect([d.reject, d.firstFailingPhase]).toEqual(['RESTORE_EVIDENCE_INCONSISTENT', 'RESTORE_GATE']);
  });

  test('a non-RESTORE adapter input is INVALID_INPUT', () => {
    expect(ending(() => completeReestablishment({ lockHeld: true, marker: marker(CONFIRMED), restore: createOp() })))
      .toBe('M2ReestablishmentError:INVALID_INPUT');
  });

  test('no caller code runs while the restore evidence is read, so the two readers cannot be split', () => {
    // r1 GPT-6.1 Sol H2: an accessor fault that empties the array after its first read.
    let getterCalls = 0;
    const faults = [];
    Object.defineProperty(faults, '0', {
      enumerable: true, configurable: true,
      get() { getterCalls += 1; faults.length = 0; return 'buildNotListed'; },
    });
    const r = restore('LEGACY_ONLY');
    r.observation.restoreObservation.faults = faults;
    const start = (restoreInput) => startReestablishment({
      lockHeld: true, marker: marker(ABSENT), consent: CONSENT(), restore: restoreInput, startToken: START_TOKEN,
    });
    expect(ending(() => start(r))).toBe('M2ReestablishmentError:INVALID_INPUT');
    expect(getterCalls).toBe(0);

    // A custom iterator (symbol key), a hole and a subclassed array are refused too.
    let iteratorCalls = 0;
    const iterated = ['lockUnavailable'];
    iterated[Symbol.iterator] = function* it() { iteratorCalls += 1; yield* []; };
    class Faults extends Array {}
    const hostile = [
      iterated,
      [, 'lockUnavailable'],
      Faults.from(['lockUnavailable']),
    ];
    for (const [i, bad] of hostile.entries()) {
      const input = restore('LEGACY_ONLY');
      input.observation.restoreObservation.faults = bad;
      expect(`${i}:${ending(() => start(input))}`).toBe(`${i}:M2ReestablishmentError:INVALID_INPUT`);
    }
    expect(iteratorCalls).toBe(0);

    // The passive copy is what both merged readers saw: a plain faults array still decides.
    const control = restore('LEGACY_ONLY');
    control.observation.restoreObservation.faults = ['buildNotListed'];
    const refused = start(control);
    expect([refused.accepted, refused.diagnostics.restoreResult]).toEqual([false, 'INCOMPATIBLE_BUILD']);
  });

  test('the session operation input is read passively as well: its accessors never run', () => {
    let reads = 0;
    const op = createOp();
    Object.defineProperty(op.observation, 'commitOutcome', { enumerable: true, get() { reads += 1; return 'COMMITTED'; } });
    expect(ending(() => createNewSession({ lockHeld: true, marker: marker(PENDING), consent: CONSENT(), operation: op })))
      .toBe('M2ReestablishmentError:INVALID_INPUT');
    expect(reads).toBe(0);
  });

  test('START from a NO_M2_STATE restore is refused (NEG-NO-M2-MARKER-START) and from M2 failures at the restore gate', () => {
    expect(startReestablishment({ lockHeld: true, marker: marker(ABSENT), consent: CONSENT(), restore: restore('NO_M2_STATE'), startToken: START_TOKEN }).reject)
      .toBe('RESTORE_PRECONDITION_FAILED');
    const locked = startReestablishment({ lockHeld: true, marker: marker(ABSENT), consent: CONSENT(), restore: restore('LOCKED_ELSEWHERE'), startToken: START_TOKEN });
    expect([locked.reject, locked.firstFailingPhase]).toEqual(['RESTORE_PRECONDITION_FAILED', 'RESTORE_GATE']);
  });
});

describe('one-way: no reverse transition after confirmation, completion is idempotent', () => {
  test('from NEW_SESSION_CONFIRMED and LEGACY_INVALIDATED, START and CANCEL are MARKER_TRANSITION_FORBIDDEN', () => {
    for (const state of [CONFIRMED, INVALIDATED]) {
      const m = marker(state);
      const s = startReestablishment({ lockHeld: true, marker: m, consent: CONSENT(), restore: restore('LEGACY_ONLY'), startToken: START_TOKEN });
      const c = cancelReestablishment({ lockHeld: true, marker: m, restore: restore('LEGACY_ONLY') });
      expect([s.reject, c.reject]).toEqual(['MARKER_TRANSITION_FORBIDDEN', 'MARKER_TRANSITION_FORBIDDEN']);
      expect([s.legacyEligible, c.legacyEligible]).toEqual([false, false]);
      expect([s.marker, c.marker]).toEqual([null, null]);
    }
  });

  test('a second START from PENDING is forbidden, and so is a second CONFIRM', () => {
    expect(startReestablishment({ lockHeld: true, marker: marker(PENDING), consent: CONSENT(), restore: restore('LEGACY_ONLY'), startToken: START_TOKEN }).reject)
      .toBe('MARKER_TRANSITION_FORBIDDEN');
    expect(confirmReestablishment({ lockHeld: true, marker: marker(CONFIRMED), createResult: committedCreate(), authorityToken: START_TOKEN, restore: restore('RESTORED_ACTIVE') }).reject)
      .toBe('MARKER_TRANSITION_FORBIDDEN');
  });

  test('completion from ABSENT or PENDING is forbidden', () => {
    for (const state of [ABSENT, PENDING]) {
      expect(completeReestablishment({ lockHeld: true, marker: marker(state), restore: restore('RESTORED_ACTIVE') }).reject)
        .toBe('MARKER_TRANSITION_FORBIDDEN');
    }
  });

  test('a seeded walk over every step never returns to a legacy-eligible state after confirmation', () => {
    const stepRunners = [
      (m) => startReestablishment({ lockHeld: true, marker: m, consent: CONSENT(), restore: restore('LEGACY_ONLY'), startToken: START_TOKEN }),
      (m) => cancelReestablishment({ lockHeld: true, marker: m, restore: restore('LEGACY_ONLY') }),
      (m) => confirmReestablishment({ lockHeld: true, marker: m, createResult: committedCreate(), authorityToken: START_TOKEN, restore: restore('RESTORED_ACTIVE') }),
      (m) => completeReestablishment({ lockHeld: true, marker: m, restore: restore('RESTORED_ACTIVE') }),
    ];
    fc.assert(fc.property(fc.array(fc.integer({ min: 0, max: 3 }), { maxLength: 12 }), (walk) => {
      let m = marker(ABSENT);
      let confirmedOnce = false;
      for (const i of walk) {
        const d = stepRunners[i](m);
        if (d.accepted) m = d.marker;
        const state = readMarker(m).state;
        if (state === CONFIRMED || state === INVALIDATED) confirmedOnce = true;
        if (confirmedOnce && readMarker(m).legacyEligible) return false;
        if (!M2_LEGACY_INVALIDATION.STATES.includes(d.stateAfter)) return false;
      }
      return true;
    }), { seed: 0x5eed, numRuns: 300 });
  });
});

describe('C-REC MARKER-CRASH-* boundaries', () => {
  for (const row of CREC_CRASH_FIXTURES) {
    test(`${row.id}`, () => {
      const r = resumeFor(marker(row.state));
      expect(r.markerState).toBe(row.expected.markerState);
      if (Object.hasOwn(row.expected, 'legacyEligibility')) expect(r.legacyEligibility).toBe(row.expected.legacyEligibility);
      if (Object.hasOwn(row.expected, 'legacyAuthority')) expect(r.legacyAuthority).toBe(row.expected.legacyAuthority);
      if (Object.hasOwn(row.expected, 'resume')) expect(r.resume).toBe(row.expected.resume);
    });
  }

  test('after a crash past confirmation the only accepted continuation is marker completion', () => {
    const m = marker(CONFIRMED);
    expect(completeReestablishment({ lockHeld: true, marker: m, restore: restore('RESTORED_ACTIVE') }).accepted).toBe(true);
    expect(cancelReestablishment({ lockHeld: true, marker: m, restore: restore('LEGACY_ONLY') }).accepted).toBe(false);
    expect(startReestablishment({ lockHeld: true, marker: m, consent: CONSENT(), restore: restore('LEGACY_ONLY'), startToken: START_TOKEN }).accepted).toBe(false);
    expect(createNewSession({ lockHeld: true, marker: m, consent: CONSENT(), operation: createOp() }).reject).toBe('MARKER_NOT_PENDING');
  });

  test('resumeFor is read-only and rejects a non-marker as MARKER_INVALID', () => {
    const m = marker(PENDING);
    const before = hex(m);
    resumeFor(m);
    expect(hex(m)).toBe(before);
    expect(ending(() => resumeFor(new Uint8Array(44)))).toBe('M2ReestablishmentError:MARKER_INVALID');
    expect(ending(() => resumeFor('marker'))).toBe('M2ReestablishmentError:MARKER_INVALID');
  });
});

describe('legacy actions are refused (C-REC ACTION fixtures)', () => {
  for (const row of CREC_ACTION_FIXTURES) {
    test(`${row.id}`, () => {
      const d = legacyActionDecision(row.input);
      expect([d.disposition, d.reject, d.firstFailingPhase, d.authorityIdentity, d.markerState])
        .toEqual(['REJECT', row.reject, 'ACTION_GATE', 'UNCHANGED', 'UNCHANGED']);
    });
  }
  test('an unknown or malformed action is INVALID_INPUT', () => {
    for (const input of [{ action: 'RESET' }, { action: 'toString' }, {}, null, { action: 'LEGACY_IMPORT', extra: 1 }]) {
      expect(ending(() => legacyActionDecision(input))).toBe('M2ReestablishmentError:INVALID_INPUT');
    }
  });
});

describe('totality: malformed input writes nothing and throws only M2ReestablishmentError', () => {
  test('missing, extra, accessor and symbol members are INVALID_INPUT', () => {
    const base = () => ({ lockHeld: true, marker: marker(PENDING), restore: restore('LEGACY_ONLY') });
    const cases = [
      (() => { const v = base(); delete v.restore; return v; })(),
      { ...base(), extra: 1 },
      { ...base(), [Symbol('s')]: 1 },
      Object.defineProperty(base(), 'restore', { enumerable: true, get() { throw new Error('getter'); } }),
      Object.create(base()),
    ];
    for (const input of cases) {
      expect(ending(() => cancelReestablishment(input))).toMatch(/^(M2ReestablishmentError:INVALID_INPUT)$/);
    }
  });

  test('a malformed marker is MARKER_INVALID, and the caller bytes stay byte-identical', () => {
    const bad = marker(PENDING);
    bad[0] ^= 0xff;
    const before = hex(bad);
    expect(ending(() => cancelReestablishment({ lockHeld: true, marker: bad, restore: restore('LEGACY_ONLY') })))
      .toBe('M2ReestablishmentError:MARKER_INVALID');
    expect(hex(bad)).toBe(before);
    expect(ending(() => cancelReestablishment({ lockHeld: true, marker: [...marker(PENDING)], restore: restore('LEGACY_ONLY') })))
      .toBe('M2ReestablishmentError:MARKER_INVALID');
  });

  test('a malformed start token is INVALID_INPUT', () => {
    for (const startToken of [ZERO, new Uint8Array(31).fill(1), 'x'.repeat(32), null]) {
      expect(ending(() => startReestablishment({ lockHeld: true, marker: marker(ABSENT), consent: CONSENT(), restore: restore('LEGACY_ONLY'), startToken })))
        .toBe('M2ReestablishmentError:INVALID_INPUT');
    }
  });

  test('a proxied marker is refused as MARKER_INVALID without any trap writing to it', () => {
    const traps = [];
    const watched = new Proxy(marker(PENDING), {
      set() { traps.push('set'); return false; },
      defineProperty() { traps.push('defineProperty'); return false; },
      deleteProperty() { traps.push('deleteProperty'); return false; },
    });
    expect(ending(() => cancelReestablishment({ lockHeld: true, marker: watched, restore: restore('LEGACY_ONLY') })))
      .toBe('M2ReestablishmentError:MARKER_INVALID');
    expect(traps).toEqual([]);
  });

  test('every accepted step leaves the caller marker byte-identical', () => {
    const inputs = [
      [marker(ABSENT), (m) => startReestablishment({ lockHeld: true, marker: m, consent: CONSENT(), restore: restore('LEGACY_ONLY'), startToken: START_TOKEN })],
      [marker(PENDING), (m) => cancelReestablishment({ lockHeld: true, marker: m, restore: restore('LEGACY_ONLY') })],
      [marker(PENDING), (m) => confirmReestablishment({ lockHeld: true, marker: m, createResult: committedCreate(), authorityToken: START_TOKEN, restore: restore('RESTORED_ACTIVE') })],
      [marker(CONFIRMED), (m) => completeReestablishment({ lockHeld: true, marker: m, restore: restore('RESTORED_ACTIVE') })],
    ];
    for (const [m, run] of inputs) {
      const before = hex(m);
      expect(run(m).accepted).toBe(true);
      expect(hex(m)).toBe(before);
    }
  });

  test('a returned marker is a fresh buffer', () => {
    const m = marker(INVALIDATED);
    const d = completeReestablishment({ lockHeld: true, marker: m, restore: restore('RESTORED_ACTIVE') });
    expect(d.marker).not.toBe(m);
    expect(d.marker.buffer).not.toBe(m.buffer);
    d.marker[0] ^= 1;
    expect(readMarker(m).state).toBe(INVALIDATED);
  });

  test('every step record is frozen, value-free and carries only the six allowlisted diagnostics', () => {
    const records = [
      startReestablishment({ lockHeld: true, marker: marker(ABSENT), consent: CONSENT(), restore: restore('LEGACY_ONLY'), startToken: START_TOKEN }),
      confirmReestablishment({ lockHeld: true, marker: marker(PENDING), createResult: committedCreate(), authorityToken: token(5), restore: restore('RESTORED_ACTIVE') }),
      cancelReestablishment({ lockHeld: false }),
    ];
    for (const r of records) {
      expect(Object.isFrozen(r)).toBe(true);
      expect(Object.keys(r.diagnostics)).toEqual(CREC_DIAGNOSTICS_ALLOWED);
      const text = JSON.stringify({ ...r, marker: null });
      expect(text).not.toContain(hex(START_TOKEN));
      expect(text).not.toContain(hex(token(5)));
      // A token carried as a typed array would serialize as indexed decimals, not hex: walk the record
      // and require that the only byte arrays are the marker and the adapter's own output member.
      const bytesAt = [];
      const walk = (v, path) => {
        if (v instanceof Uint8Array) bytesAt.push(path);
        else if (v !== null && typeof v === 'object') for (const [k, x] of Object.entries(v)) walk(x, `${path}.${k}`);
      };
      walk(r, '');
      expect(bytesAt.every((p) => p === '.marker' || p === '.adapterResult.output.embeddedTreeWelcome')).toBe(true);
      // The marker carries the start token by design (L-MARK encoding); it must be the 44-byte marker.
      if (r.marker !== null) expect(r.marker.length).toBe(M2_LEGACY_INVALIDATION.MARKER_LENGTH);
    }
  });

  test('seeded property: arbitrary inputs end in a closed record or M2ReestablishmentError, never a foreign exception', () => {
    const hostileRestore = () => {
      const r = restore('LEGACY_ONLY');
      Object.defineProperty(r.observation.restoreObservation.faults, '0', {
        enumerable: true, configurable: true, get() { throw new Error('getter ran'); },
      });
      return r;
    };
    const anyValue = fc.oneof(
      fc.constant(null), fc.boolean(), fc.string(), fc.integer(), fc.uint8Array({ maxLength: 50 }),
      fc.constantFrom(marker(ABSENT), marker(PENDING), marker(CONFIRMED), marker(INVALIDATED), START_TOKEN),
      fc.constantFrom(restore('LEGACY_ONLY'), restore('RESTORED_ACTIVE'), CONSENT(), createOp()),
      fc.constant(null).map(hostileRestore),
    );
    const fns = [startReestablishment, cancelReestablishment, createNewSession, confirmReestablishment, completeReestablishment];
    const keys = ['lockHeld', 'marker', 'consent', 'restore', 'startToken', 'operation', 'createResult', 'authorityToken'];
    const run = (seed) => {
      const outcomes = [];
      fc.assert(fc.property(fc.integer({ min: 0, max: 4 }), fc.dictionary(fc.constantFrom(...keys), anyValue), (f, input) => {
        let record;
        const e = ending(() => { record = fns[f](input); });
        outcomes.push(e);
        if (e !== 'ok') return e.startsWith('M2ReestablishmentError:');
        // A non-throwing return must be a closed, frozen step record of this step.
        return Object.isFrozen(record)
          && Object.keys(record).join(',') === STEP_RECORD_KEYS
          && record.step === M2_REESTABLISHMENT.STEPS[f]
          && M2_REESTABLISHMENT.DISPOSITIONS.includes(record.disposition)
          && typeof record.accepted === 'boolean'
          && Object.keys(record.diagnostics).join(',') === CREC_DIAGNOSTICS_ALLOWED.join(',');
      }), { seed, numRuns: 400 });
      return outcomes;
    };
    expect(run(17)).toEqual(run(17));
  });
});

// ------------------------------------------------------------------------------------------------
// O-SCEN clause rows owned by this card (#337, ratification #327 comment 6035801582; reconciliation list OPEN).
// Each row is pinned by a named test that drives the public surface; the other /marker/* rows are
// L-MARK's and are consumed, not re-owned.
// ------------------------------------------------------------------------------------------------

describe('O-SCEN clause rows owned by L-REEST', () => {
  test('OSC-a218f4baff492e91 /marker/newSessionOwner: this module is the L-MARK-named new-session owner', () => {
    expect(M2_LEGACY_INVALIDATION.NEW_SESSION_OWNER).toBe('L-REEST');
    expect(M2_REESTABLISHMENT.OWNER).toBe(M2_LEGACY_INVALIDATION.NEW_SESSION_OWNER);
    const created = createNewSession({ lockHeld: true, marker: marker(PENDING), consent: CONSENT(), operation: createOp() });
    expect([created.disposition, created.committed]).toEqual(['SESSION_OPERATION', true]);
  });

  test('OSC-1fdd425852367fdb /dispatchRows/0 and OSC-719ddcd6363d42ef /reachableConditionRows/0: NO_M2_STATE → SHOW_CREATE', () => {
    const g = guidanceFor({ result: 'NO_M2_STATE', legacyPresent: false });
    expect([g.disposition, g.authority, g.resetEligible, g.byteAction, g.consentRequired])
      .toEqual(['SHOW_CREATE', 'NONE', false, 'PRESERVE', false]);
    expect(guidanceFor({ result: 'NO_M2_STATE', legacyPresent: true }).reject).toBe('UNREACHABLE_CONDITION_PAIR');
  });

  test('OSC-1fbb862cd5ad6ca7 /dispatchRows/1 and OSC-8036125ff8f2e0e1 /reachableConditionRows/1: LEGACY_ONLY → SHOW_REESTABLISHMENT', () => {
    const g = guidanceFor({ result: 'LEGACY_ONLY', legacyPresent: true });
    expect([g.disposition, g.authority, g.resetEligible, g.byteAction, g.consentRequired])
      .toEqual(['SHOW_REESTABLISHMENT', 'NONE', false, 'PRESERVE', true]);
    expect(guidanceFor({ result: 'LEGACY_ONLY', legacyPresent: false }).reject).toBe('UNREACHABLE_CONDITION_PAIR');
  });

  test('OSC-f26591afa72098b3 /dependencyCoverage/6 INVALIDATION_AND_REESTABLISHMENT: only a C-FMT COMMITTED creation later RESTORED_ACTIVE confirms', () => {
    expect(CREC_DEPENDENCY_COVERAGE_6.criterion).toBe('INVALIDATION_AND_REESTABLISHMENT');
    const confirmWith = (commitOutcome, result) => confirmReestablishment({
      lockHeld: true, marker: marker(PENDING), createResult: committedCreate(commitOutcome), authorityToken: START_TOKEN, restore: restore(result),
    });
    expect(confirmWith('COMMITTED', 'RESTORED_ACTIVE').accepted).toBe(true);
    for (const [outcome, result] of [['NOT_COMMITTED', 'RESTORED_ACTIVE'], ['INDETERMINATE', 'RESTORED_ACTIVE'],
      ['COMMITTED', 'RESTORED_EMPTY'], ['COMMITTED', 'RESTORED_RECONCILIATION_REQUIRED']]) {
      expect(`${outcome}/${result}:${confirmWith(outcome, result).accepted}`).toBe(`${outcome}/${result}:false`);
    }
  });

  test('OSC-2f4ed692514c3076 /legacy/input: only legacyPresent and a bounded value-free count are read', () => {
    expect(CREC_LEGACY.input).toBe('ABSTRACT_LEGACY_PRESENT_AND_BOUNDED_VALUE_FREE_COUNT');
    const presence = legacyPresenceOf([new TextEncoder().encode('styx-mls:legacy-session:x')]);
    expect(Object.keys(presence).sort()).toEqual(['boundedCount', 'legacyPresent']);
    expect(presence).toEqual({ legacyPresent: true, boundedCount: 1 });
  });

  test('OSC-dab163edd0c9b3d0 /legacy/import and OSC-d1b2e537b3cb3796 /legacy/fallback are refused', () => {
    expect([CREC_LEGACY.import, CREC_LEGACY.fallback]).toEqual([false, false]);
    expect([M2_REESTABLISHMENT.IMPORT, M2_REESTABLISHMENT.FALLBACK]).toEqual([false, false]);
    expect(legacyActionDecision({ action: 'LEGACY_IMPORT' }).reject).toBe('LEGACY_IMPORT_FORBIDDEN');
    expect(legacyActionDecision({ action: 'LEGACY_FALLBACK' }).reject).toBe('LEGACY_FALLBACK_FORBIDDEN');
  });

  test('OSC-d808b3c93b140daa /legacy/decrypt and OSC-ba4e42b9406ab4e8 /legacy/translate: no legacy byte is decrypted, translated or decoded', () => {
    expect([CREC_LEGACY.decrypt, CREC_LEGACY.translate]).toEqual([false, false]);
    expect([M2_REESTABLISHMENT.DECRYPT, M2_REESTABLISHMENT.TRANSLATE, M2_REESTABLISHMENT.DECODE_LEGACY_AS_M2]).toEqual([false, false, false]);
    const code = readFileSync(MODULE_PATH, 'utf8').replace(/^\s*\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '');
    for (const forbidden of ['decrypt', 'subtle', 'TextDecoder', 'legacy-session:']) {
      expect(`${forbidden}:${code.includes(forbidden)}`).toBe(`${forbidden}:false`);
    }
  });

  test('OSC-49c8f1a0bec40ec4 /legacy/selectedAuthority: legacy never becomes selected authority', () => {
    expect(CREC_LEGACY.selectedAuthority).toBe(false);
    expect(M2_REESTABLISHMENT.SELECT_LEGACY).toBe(false);
    for (const row of CREC_OWNED_REACHABLE_ROWS) {
      expect(guidanceFor({ result: row.result, legacyPresent: row.legacyPresent }).authority).toBe('NONE');
    }
  });

  test('OSC-52b1ec77a8479eca /legacy/preserveBytes: the whole flow leaves legacy bytes byte-identical', () => {
    expect(CREC_LEGACY.preserveBytes).toBe(true);
    expect(M2_REESTABLISHMENT.PRESERVE_BYTES).toBe(true);
    const keys = [new TextEncoder().encode('styx-mls:legacy-session:keep')];
    const before = keys.map(hex);
    legacyPresenceOf(keys);
    let m = startReestablishment({ lockHeld: true, marker: marker(ABSENT), consent: CONSENT(), restore: restore('LEGACY_ONLY'), startToken: START_TOKEN }).marker;
    m = confirmReestablishment({ lockHeld: true, marker: m, createResult: committedCreate(), authorityToken: START_TOKEN, restore: restore('RESTORED_ACTIVE') }).marker;
    completeReestablishment({ lockHeld: true, marker: m, restore: restore('RESTORED_ACTIVE') });
    expect(keys.map(hex)).toEqual(before);
  });

  test('OSC-ec87e495fed379ab /legacy/physicalInventoryOwner: physical inventory is L-INV', () => {
    expect(CREC_LEGACY.physicalInventoryOwner).toBe('L-INV');
    expect(M2_REESTABLISHMENT.PHYSICAL_INVENTORY_OWNER).toBe('L-INV');
    expect(ending(() => legacyPresenceOf('not-a-key-list'))).toBe('M2ReestablishmentError:INVENTORY_INVALID');
  });

  test('OSC-fdce598205538566 /legacy/cleanup: cleanup is DEFERRED and DELETE_LEGACY is refused', () => {
    expect(CREC_LEGACY.cleanup).toBe('DEFERRED');
    expect(M2_REESTABLISHMENT.CLEANUP).toBe('DEFERRED');
    expect(legacyActionDecision({ action: 'DELETE_LEGACY' }).reject).toBe('CLEANUP_DEFERRED');
  });
});
