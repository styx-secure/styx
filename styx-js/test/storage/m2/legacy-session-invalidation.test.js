import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import {
  M2_LEGACY_INVALIDATION, M2LegacyInvalidationError,
  applyMarkerTransition, encodeMarker, legacyEligible, readMarker,
} from '../../../src/storage/m2/legacy-session-invalidation.js';
import * as invalidationModule from '../../../src/storage/m2/legacy-session-invalidation.js';

// The ratified C-REC vocabulary asserted below is copied verbatim from
// `docs/architecture/m2/recovery-and-coexistence.md` §13 `/marker` and `/fixtures`
// (commit c755c2c2eafd0d58f74577c1adaa8031011ec7a7, SHA-256
// 5b0d2fbd685a198e7e6e6bb10cb7740680086d27690c3cc622915e68beb94f87, #335 comment 5909885218).

const ABSENT = 'ABSENT';
const PENDING = 'PENDING_NEW_SESSION';
const CONFIRMED = 'NEW_SESSION_CONFIRMED';
const INVALIDATED = 'LEGACY_INVALIDATED';
const EVENT_START = 'USER_CONFIRMED_START';
const EVENT_CANCEL = 'USER_CANCEL_BEFORE_CONFIRMATION';
const EVENT_CONFIRM = 'DISTINCT_POST_START_C_FMT_COMMITTED_AUTHORITY_RESTORED_ACTIVE';
const EVENT_COMMIT = 'ATOMIC_MARKER_COMMIT';
const EVENT_REPEAT = 'REPEAT_MARKER_COMPLETION';
const ZERO = new Uint8Array(32);
const TOKEN = new Uint8Array(32).fill(0x5a);
const OTHER = new Uint8Array(32).fill(0xa5);
const hex = (b) => Array.from(b, (v) => v.toString(16).padStart(2, '0')).join('');
const marker = (state, bindingToken) => encodeMarker({ state, bindingToken });

const errorOf = (fn) => {
  try {
    fn();
  } catch (error) {
    return error;
  }
  throw new Error('expected the call to throw');
};

describe('legacy-session-invalidation: closed vocabulary', () => {
  test('publishes the C-REC §13 /marker record verbatim and frozen', () => {
    expect(M2_LEGACY_INVALIDATION.SCHEMA).toBe('styx-m2-legacy-invalidation/v1');
    expect(M2_LEGACY_INVALIDATION.STATES).toEqual([ABSENT, PENDING, CONFIRMED, INVALIDATED]);
    expect(M2_LEGACY_INVALIDATION.EVENTS).toEqual([EVENT_START, EVENT_CANCEL, EVENT_CONFIRM, EVENT_COMMIT, EVENT_REPEAT]);
    expect(M2_LEGACY_INVALIDATION.TRANSITIONS).toEqual([
      {
        id: 'START', from: ABSENT, event: EVENT_START, to: PENDING,
        allowedRestoreResults: ['LEGACY_ONLY'], requiresLock: true, idempotent: false,
      },
      {
        id: 'CANCEL', from: PENDING, event: EVENT_CANCEL, to: ABSENT,
        allowedRestoreResults: ['LEGACY_ONLY'], requiresLock: true, idempotent: false,
      },
      {
        id: 'CONFIRM', from: PENDING, event: EVENT_CONFIRM, to: CONFIRMED,
        allowedRestoreResults: ['RESTORED_ACTIVE'], requiresLock: true, idempotent: false,
      },
      {
        id: 'COMMIT_MARKER', from: CONFIRMED, event: EVENT_COMMIT, to: INVALIDATED,
        allowedRestoreResults: ['RESTORED_ACTIVE'], requiresLock: true, idempotent: true,
      },
      {
        id: 'REPEAT_COMPLETION', from: INVALIDATED, event: EVENT_REPEAT, to: INVALIDATED,
        allowedRestoreResults: ['RESTORED_ACTIVE'], requiresLock: true, idempotent: true,
      },
    ]);
    expect(M2_LEGACY_INVALIDATION.LEGACY_ELIGIBLE_BY_STATE).toEqual({
      ABSENT: true, LEGACY_INVALIDATED: false, NEW_SESSION_CONFIRMED: false, PENDING_NEW_SESSION: true,
    });
    expect(M2_LEGACY_INVALIDATION.BINDING).toBe('OPAQUE_START_AUTHORITY_CONFIRMATION_TOKEN_EQUALITY');
    expect(M2_LEGACY_INVALIDATION.ENCODING_OWNER).toBe('L-MARK');
    expect(M2_LEGACY_INVALIDATION.NEW_SESSION_OWNER).toBe('L-REEST');
    expect(M2_LEGACY_INVALIDATION.COMPLETE_RESTORE_RESULT_REQUIRED).toBe(true);
    expect(M2_LEGACY_INVALIDATION.TIME_OR_FRESHNESS_COMPARISON).toBe(false);
    expect(M2_LEGACY_INVALIDATION.CLEANUP_EFFECT).toBe(false);
    expect(M2_LEGACY_INVALIDATION.REVERSE_AFTER_CONFIRMATION).toBe(false);
    expect(M2_LEGACY_INVALIDATION.REAL_CONFIRMATION_BLOCKED_UNTIL_OWNERS_RATIFIED).toBe(true);
    expect(M2_LEGACY_INVALIDATION.MARKER_MAGIC).toBe('STYXMARK1');
    expect(M2_LEGACY_INVALIDATION.MARKER_VERSION).toBe(1);
    expect(M2_LEGACY_INVALIDATION.MARKER_LENGTH).toBe(44);
    expect(M2_LEGACY_INVALIDATION.BINDING_TOKEN_BYTES).toBe(32);
    expect(M2_LEGACY_INVALIDATION.STATE_CODES).toEqual({
      ABSENT: 0, PENDING_NEW_SESSION: 1, NEW_SESSION_CONFIRMED: 2, LEGACY_INVALIDATED: 3,
    });
    expect(M2_LEGACY_INVALIDATION.DISPOSITIONS).toEqual(['MARKER_TRANSITION', 'LOCK_RETRY', 'REJECT']);
    expect([...M2_LEGACY_INVALIDATION.REJECT_CODES].sort()).toEqual([
      'CONFIRMATION_PRECONDITION_FAILED', 'LOCKED_ELSEWHERE', 'MARKER_TRANSITION_FORBIDDEN',
      'RESTORE_PRECONDITION_FAILED', 'TOKEN_MISMATCH',
    ]);
    expect([...M2_LEGACY_INVALIDATION.DECODE_FAILURE_CODES].sort()).toEqual([
      'INCOMPATIBLE_FORMAT', 'MARKER_ENCODING_INVALID', 'UNSUPPORTED_VERSION',
    ]);
    expect(Object.isFrozen(M2_LEGACY_INVALIDATION)).toBe(true);
    expect(Object.isFrozen(M2_LEGACY_INVALIDATION.TRANSITIONS)).toBe(true);
    expect(M2_LEGACY_INVALIDATION.TRANSITIONS.every(Object.isFrozen)).toBe(true);
    expect(Object.isFrozen(M2_LEGACY_INVALIDATION.TRANSITIONS[0].allowedRestoreResults)).toBe(true);
  });

  test('carries the C-REC /legacy facts and performs no import, decrypt, translate or fallback', () => {
    expect(M2_LEGACY_INVALIDATION.PHYSICAL_INVENTORY_OWNER).toBe('L-INV');
    expect(M2_LEGACY_INVALIDATION.IMPORT).toBe(false);
    expect(M2_LEGACY_INVALIDATION.DECRYPT).toBe(false);
    expect(M2_LEGACY_INVALIDATION.TRANSLATE).toBe(false);
    expect(M2_LEGACY_INVALIDATION.FALLBACK).toBe(false);
    expect(M2_LEGACY_INVALIDATION.SELECTED_AUTHORITY).toBe(false);
    expect(M2_LEGACY_INVALIDATION.PRESERVE_BYTES).toBe(true);
    expect(M2_LEGACY_INVALIDATION.CLEANUP).toBe('DEFERRED');
    expect(M2_LEGACY_INVALIDATION.LOCKED_DISPOSITION).toBe('LOCK_RETRY');
  });

  test('the module surface is closed: no re-establishment, reset, cleanup or authority API', () => {
    expect(Object.keys(invalidationModule).sort()).toEqual([
      'M2LegacyInvalidationError', 'M2_LEGACY_INVALIDATION',
      'applyMarkerTransition', 'encodeMarker', 'legacyEligible', 'readMarker',
    ]);
    for (const forbidden of [
      'createSession', 'reestablish', 'reset', 'cleanup', 'importLegacy', 'decrypt', 'translate',
      'fallback', 'selectAuthority', 'invokeAdapter', 'acquireLock', 'reconcile', 'commit',
    ]) {
      expect(Object.hasOwn(invalidationModule, forbidden)).toBe(false);
    }
  });

  test('the marker is not a C-FMT record kind and not a legacy locator', () => {
    expect(M2_LEGACY_INVALIDATION.MARKER_MAGIC).not.toBe('STYXKEY1');
    expect(M2_LEGACY_INVALIDATION.MARKER_MAGIC).not.toBe('STYXSEL1');
    expect(M2_LEGACY_INVALIDATION.TIME_OR_FRESHNESS_COMPARISON).toBe(false);
    // No timestamp, counter, epoch or freshness fact exists on the module at all.
    const timeLike = Object.keys(M2_LEGACY_INVALIDATION)
      .filter((k) => k !== 'TIME_OR_FRESHNESS_COMPARISON')
      .filter((k) => /TIMESTAMP|COUNTER|EPOCH|FRESHNESS|CLOCK/.test(k));
    expect(timeLike).toEqual([]);
  });
});

describe('legacy-session-invalidation: canonical encoding', () => {
  test('the ABSENT encoding is the exact 44-byte known vector', () => {
    const bytes = marker(ABSENT, ZERO);
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.length).toBe(44);
    expect(hex(bytes)).toBe('535459584d41524b31' + '0001' + '00' + '00'.repeat(32));
    expect(String.fromCharCode(...bytes.slice(0, 9))).toBe('STYXMARK1');
    expect(bytes[9]).toBe(0);
    expect(bytes[10]).toBe(1);
    expect(bytes[11]).toBe(0);
  });

  test('each state encodes its ratified code and round-trips through readMarker', () => {
    const cases = [
      [ABSENT, ZERO, 0, true],
      [PENDING, TOKEN, 1, true],
      [CONFIRMED, TOKEN, 2, false],
      [INVALIDATED, TOKEN, 3, false],
    ];
    for (const [state, token, code, eligible] of cases) {
      const bytes = marker(state, token);
      expect(bytes[11]).toBe(code);
      const read = readMarker(bytes);
      expect(read).toEqual({
        schema: 'styx-m2-legacy-invalidation/v1', version: 1, state, legacyEligible: eligible,
      });
      expect(Object.isFrozen(read)).toBe(true);
      expect(legacyEligible(state)).toBe(eligible);
    }
  });

  test('readMarker is value-free: four closed keys, no byte of the binding, no alias', () => {
    const bytes = marker(CONFIRMED, TOKEN);
    const read = readMarker(bytes);
    expect(Object.keys(read).sort()).toEqual(['legacyEligible', 'schema', 'state', 'version']);
    expect(Object.values(read).some((v) => ArrayBuffer.isView(v))).toBe(false);
    const serialized = JSON.stringify(read);
    expect(serialized).not.toContain(hex(TOKEN));
    expect(serialized).not.toContain('5a');
    // Mutating the caller's bytes after the call changes nothing the module returned.
    bytes[43] = 0x00;
    expect(read).toEqual({
      schema: 'styx-m2-legacy-invalidation/v1', version: 1, state: CONFIRMED, legacyEligible: false,
    });
  });

  test('encodeMarker never aliases or writes the caller memory', () => {
    const token = new Uint8Array(32).fill(0x11);
    const bytes = marker(PENDING, token);
    expect(bytes).not.toBe(token);
    token.fill(0x22);
    expect(bytes[12]).toBe(0x11);
    expect(hex(bytes.slice(12))).toBe('11'.repeat(32));
  });

  test('canonical rejections are closed and total', () => {
    const cases = [
      [Uint8Array.of(1, 2, 3), 'MARKER_ENCODING_INVALID'], // shorter than header
      [Uint8Array.from(marker(PENDING, TOKEN), (v, i) => (i === 0 ? 0x00 : v)), 'MARKER_ENCODING_INVALID'], // magic
      [Uint8Array.from(marker(PENDING, TOKEN), (v, i) => (i === 10 ? 0x02 : v)), 'UNSUPPORTED_VERSION'],
      [marker(PENDING, TOKEN).slice(0, 43), 'MARKER_ENCODING_INVALID'], // short length
      [new Uint8Array([...marker(PENDING, TOKEN), 0x00]), 'MARKER_ENCODING_INVALID'], // trailing byte
      [Uint8Array.from(marker(PENDING, TOKEN), (v, i) => (i === 11 ? 0x09 : v)), 'MARKER_ENCODING_INVALID'], // state code
      [Uint8Array.from(marker(ABSENT, ZERO), (v, i) => (i >= 12 ? 0x11 : v)), 'MARKER_ENCODING_INVALID'], // ABSENT with a start token
      [Uint8Array.from(marker(CONFIRMED, TOKEN), (v, i) => (i >= 12 ? 0x00 : v)), 'MARKER_ENCODING_INVALID'], // started with an absent token
      ['STYXMARK1', 'INCOMPATIBLE_FORMAT'],
      [null, 'INCOMPATIBLE_FORMAT'],
      [43, 'INCOMPATIBLE_FORMAT'],
    ];
    for (const [input, code] of cases) {
      const error = errorOf(() => readMarker(input));
      expect(error).toBeInstanceOf(M2LegacyInvalidationError);
      expect(error.code).toBe(code);
      expect([...M2_LEGACY_INVALIDATION.DECODE_FAILURE_CODES]).toContain(error.code);
    }
  });

  test('encodeMarker rejects a non-canonical marker record with a closed code', () => {
    const cases = [
      [{ state: PENDING, bindingToken: TOKEN, extra: 1 }, 'INCOMPATIBLE_FORMAT'],
      [{ state: PENDING }, 'INCOMPATIBLE_FORMAT'],
      [{ state: 'NOT_A_STATE', bindingToken: TOKEN }, 'INCOMPATIBLE_FORMAT'],
      [{ state: PENDING, bindingToken: ZERO }, 'MARKER_ENCODING_INVALID'],
      [{ state: ABSENT, bindingToken: TOKEN }, 'MARKER_ENCODING_INVALID'],
      [{ state: PENDING, bindingToken: new Uint8Array(31) }, 'MARKER_ENCODING_INVALID'],
      [{ state: PENDING, bindingToken: 'not bytes' }, 'INCOMPATIBLE_FORMAT'],
      [null, 'INCOMPATIBLE_FORMAT'],
      [[], 'INCOMPATIBLE_FORMAT'],
    ];
    for (const [input, code] of cases) {
      const error = errorOf(() => encodeMarker(input));
      expect(error.code).toBe(code);
    }
  });

  test('a hostile marker proxy and an accessor-bearing marker are refused', () => {
    const hostile = new Proxy({}, {
      get() { throw new Error('trap'); },
      getOwnPropertyDescriptor() { throw new Error('trap'); },
    });
    expect(errorOf(() => readMarker(hostile)).code).toBe('INCOMPATIBLE_FORMAT');
    const accessor = { state: PENDING };
    Object.defineProperty(accessor, 'bindingToken', { get() { throw new Error('never'); }, enumerable: true });
    expect(errorOf(() => encodeMarker(accessor)).code).toBe('INCOMPATIBLE_FORMAT');
  });

  test('legacyEligible is total over the four states and fails closed otherwise', () => {
    expect([ABSENT, PENDING, CONFIRMED, INVALIDATED].map(legacyEligible)).toEqual([true, true, false, false]);
    for (const bad of ['', 'new_session_confirmed', null, undefined, 0, {}]) {
      expect(errorOf(() => legacyEligible(bad)).code).toBe('INCOMPATIBLE_FORMAT');
    }
  });
});

// C-REC §13 `/fixtures`, kind MARKER, verbatim: thirteen rows plus the three
// MARKER-CRASH-* BOUNDARY rows. Each row is replayed through the public surface.
describe('legacy-session-invalidation: C-REC §13 MARKER fixtures', () => {
  const MARKER_FIXTURES = [
    {
      id: 'MARKER-START',
      input: { state: ABSENT, event: EVENT_START, lockHeld: true, restoreResult: 'LEGACY_ONLY' },
      expected: { state: PENDING, accepted: true, reject: null, disposition: 'MARKER_TRANSITION' },
    },
    {
      id: 'MARKER-CANCEL',
      input: { state: PENDING, event: EVENT_CANCEL, lockHeld: true, restoreResult: 'LEGACY_ONLY' },
      expected: { state: ABSENT, accepted: true, reject: null, disposition: 'MARKER_TRANSITION' },
    },
    {
      id: 'MARKER-CONFIRM',
      input: {
        state: PENDING, event: EVENT_CONFIRM, lockHeld: true, restoreResult: 'RESTORED_ACTIVE',
        committed: true, authorityToken: OTHER,
      },
      expected: { state: CONFIRMED, accepted: true, reject: null, disposition: 'MARKER_TRANSITION' },
    },
    {
      id: 'MARKER-COMMIT_MARKER',
      input: { state: CONFIRMED, event: EVENT_COMMIT, lockHeld: true, restoreResult: 'RESTORED_ACTIVE' },
      expected: { state: INVALIDATED, accepted: true, reject: null, disposition: 'MARKER_TRANSITION' },
    },
    {
      id: 'MARKER-REPEAT_COMPLETION',
      input: { state: INVALIDATED, event: EVENT_REPEAT, lockHeld: true, restoreResult: 'RESTORED_ACTIVE' },
      expected: { state: INVALIDATED, accepted: true, reject: null, disposition: 'MARKER_TRANSITION' },
    },
    {
      id: 'NEG-MARKER-REVERSE',
      input: { state: INVALIDATED, event: EVENT_CANCEL, lockHeld: true, restoreResult: 'LEGACY_ONLY' },
      expected: { state: INVALIDATED, accepted: false, reject: 'MARKER_TRANSITION_FORBIDDEN', disposition: 'REJECT' },
    },
    {
      id: 'NEG-STALE-TOKEN',
      input: {
        state: PENDING, event: EVENT_CONFIRM, lockHeld: true, restoreResult: 'RESTORED_ACTIVE',
        committed: true, authorityToken: TOKEN, // equal to the start token: not distinct
      },
      expected: { state: PENDING, accepted: false, reject: 'TOKEN_MISMATCH', disposition: 'REJECT' },
    },
    {
      id: 'NEG-CROSS-SESSION-TOKEN',
      input: {
        state: PENDING, event: EVENT_CONFIRM, lockHeld: true, restoreResult: 'RESTORED_ACTIVE',
        committed: true, authorityToken: TOKEN, // a cross-session replay of the start token
      },
      expected: { state: PENDING, accepted: false, reject: 'TOKEN_MISMATCH', disposition: 'REJECT' },
    },
    {
      id: 'NEG-EMPTY-CONFIRM',
      input: {
        state: PENDING, event: EVENT_CONFIRM, lockHeld: true, restoreResult: 'RESTORED_EMPTY',
        committed: true, authorityToken: OTHER,
      },
      expected: { state: PENDING, accepted: false, reject: 'CONFIRMATION_PRECONDITION_FAILED', disposition: 'REJECT' },
    },
    {
      id: 'NEG-RECONCILIATION-CONFIRM',
      input: {
        state: PENDING, event: EVENT_CONFIRM, lockHeld: true,
        restoreResult: 'RESTORED_RECONCILIATION_REQUIRED', committed: true, authorityToken: OTHER,
      },
      expected: { state: PENDING, accepted: false, reject: 'CONFIRMATION_PRECONDITION_FAILED', disposition: 'REJECT' },
    },
    {
      id: 'NEG-NO-LOCK',
      input: { state: ABSENT, event: EVENT_START, lockHeld: false, restoreResult: 'LEGACY_ONLY' },
      expected: { state: ABSENT, accepted: false, reject: 'LOCKED_ELSEWHERE', disposition: 'LOCK_RETRY' },
    },
    {
      id: 'NEG-NO-M2-MARKER-START',
      input: { state: ABSENT, event: EVENT_START, lockHeld: true, restoreResult: 'NO_M2_STATE' },
      expected: { state: ABSENT, accepted: false, reject: 'RESTORE_PRECONDITION_FAILED', disposition: 'REJECT' },
    },
    {
      id: 'NEG-RECONCILIATION-MARKER-COMMIT',
      input: {
        state: CONFIRMED, event: EVENT_COMMIT, lockHeld: true, restoreResult: 'RESTORED_RECONCILIATION_REQUIRED',
      },
      expected: { state: CONFIRMED, accepted: false, reject: 'RESTORE_PRECONDITION_FAILED', disposition: 'REJECT' },
    },
  ];

  test.each(MARKER_FIXTURES.map((f) => [f.id, f]))('%s', (id, fixture) => {
    const { state, ...members } = fixture.input;
    const token = state === ABSENT ? ZERO : TOKEN;
    const decision = applyMarkerTransition({ marker: marker(state, token), ...members });
    expect(decision.stateAfter).toBe(fixture.expected.state);
    expect(decision.accepted).toBe(fixture.expected.accepted);
    expect(decision.reject).toBe(fixture.expected.reject);
    expect(decision.disposition).toBe(fixture.expected.disposition);
    expect(decision.stateBefore).toBe(state);
    expect(decision.legacyEligible).toBe(M2_LEGACY_INVALIDATION.LEGACY_ELIGIBLE_BY_STATE[fixture.expected.state]);
    expect(decision.firstFailingPhase).toBe(
      fixture.expected.disposition === 'LOCK_RETRY' ? 'LOCK'
        : (fixture.expected.disposition === 'REJECT' ? 'MARKER_GATE' : 'NONE'),
    );
    expect(Object.isFrozen(decision)).toBe(true);
    if (fixture.expected.disposition === 'MARKER_TRANSITION') {
      // An accepted transition is exactly what the persisted marker becomes.
      expect(readMarker(marker(decision.stateAfter, decision.stateAfter === ABSENT ? ZERO : TOKEN)).state)
        .toBe(fixture.expected.state);
    }
  });

  test('the fixture set is complete: thirteen MARKER rows, all replayed above', () => {
    expect(MARKER_FIXTURES).toHaveLength(13);
    expect(new Set(MARKER_FIXTURES.map((f) => f.id)).size).toBe(13);
    for (const f of MARKER_FIXTURES) {
      expect(['MARKER_TRANSITION', 'LOCK_RETRY', 'REJECT']).toContain(f.expected.disposition);
      if (f.expected.reject !== null) {
        expect([...M2_LEGACY_INVALIDATION.REJECT_CODES]).toContain(f.expected.reject);
      }
    }
  });

  test('MARKER-CRASH-BEFORE-CONFIRMATION: PENDING still allows only the start path', () => {
    const decision = applyMarkerTransition({
      marker: marker(PENDING, TOKEN), event: EVENT_START, lockHeld: true, restoreResult: 'LEGACY_ONLY',
    });
    expect(decision.reject).toBe('MARKER_TRANSITION_FORBIDDEN');
    expect(readMarker(marker(PENDING, TOKEN)).state).toBe(PENDING);
  });

  test('MARKER-CRASH-AFTER-CONFIRMATION: legacy eligibility is false, resume is completion only', () => {
    const persisted = marker(CONFIRMED, TOKEN);
    expect(readMarker(persisted).legacyEligible).toBe(false);
    // Only the completion pair is accepted from CONFIRMED.
    const accepted = applyMarkerTransition({
      marker: persisted, event: EVENT_COMMIT, lockHeld: true, restoreResult: 'RESTORED_ACTIVE',
    });
    expect(accepted.stateAfter).toBe(INVALIDATED);
    for (const event of [EVENT_START, EVENT_CANCEL, EVENT_CONFIRM, EVENT_REPEAT]) {
      const input = event === EVENT_CONFIRM
        ? { marker: persisted, event, lockHeld: true, restoreResult: 'RESTORED_ACTIVE', committed: true, authorityToken: OTHER }
        : { marker: persisted, event, lockHeld: true, restoreResult: 'LEGACY_ONLY' };
      expect(applyMarkerTransition(input).reject).toBe('MARKER_TRANSITION_FORBIDDEN');
    }
  });

  test('MARKER-CRASH-AFTER-COMMIT: legacy eligibility stays false and completion is idempotent', () => {
    const persisted = marker(INVALIDATED, TOKEN);
    expect(readMarker(persisted).legacyEligible).toBe(false);
    const again = applyMarkerTransition({
      marker: persisted, event: EVENT_REPEAT, lockHeld: true, restoreResult: 'RESTORED_ACTIVE',
    });
    expect(again.stateAfter).toBe(INVALIDATED);
    expect(again.legacyEligible).toBe(false);
  });
});

describe('legacy-session-invalidation: one-way cutover (the card exit criterion)', () => {
  test('an old build cannot silently resume stale authority in the fixture', () => {
    // A legacy-only key space (the fixture the C-REC recovery surface starts from) plus a
    // marker that has passed confirmation.
    for (const state of [CONFIRMED, INVALIDATED]) {
      const persisted = marker(state, TOKEN);
      const read = readMarker(persisted);
      expect(read.legacyEligible).toBe(false);
      expect(legacyEligible(state)).toBe(false);
      // Every event that would return to a legacy-eligible state is refused.
      for (const [event, extra] of [
        [EVENT_START, {}], [EVENT_CANCEL, {}],
      ]) {
        const decision = applyMarkerTransition({
          marker: persisted, event, lockHeld: true, restoreResult: 'LEGACY_ONLY', ...extra,
        });
        expect(decision.disposition).toBe('REJECT');
        expect(decision.reject).toBe('MARKER_TRANSITION_FORBIDDEN');
        expect(decision.legacyEligible).toBe(false);
        expect(decision.stateAfter).toBe(state);
      }
      // The only accepted event from these states is the completion pair.
      const completion = state === CONFIRMED ? EVENT_COMMIT : EVENT_REPEAT;
      const accepted = applyMarkerTransition({
        marker: persisted, event: completion, lockHeld: true, restoreResult: 'RESTORED_ACTIVE',
      });
      expect(accepted.accepted).toBe(true);
      expect(accepted.legacyEligible).toBe(false);
    }
  });

  test('the transition table is exhaustive: no accepted pair reaches a legacy-eligible state', () => {
    for (const state of [CONFIRMED, INVALIDATED]) {
      for (const event of M2_LEGACY_INVALIDATION.EVENTS) {
        const transition = M2_LEGACY_INVALIDATION.TRANSITIONS.find((t) => t.from === state && t.event === event);
        if (transition !== undefined) {
          expect(M2_LEGACY_INVALIDATION.LEGACY_ELIGIBLE_BY_STATE[transition.to]).toBe(false);
        }
      }
    }
    // And the only entry into the two confirmed states is CONFIRM from PENDING.
    const entries = M2_LEGACY_INVALIDATION.TRANSITIONS.filter((t) => [CONFIRMED, INVALIDATED].includes(t.to));
    expect(entries.some((t) => t.from === ABSENT)).toBe(false);
    expect(entries.some((t) => t.from === PENDING && t.id !== 'CONFIRM')).toBe(false);
  });

  test('REPEAT_COMPLETION is the idempotent closure and every other transition is not idempotent', () => {
    expect(M2_LEGACY_INVALIDATION.TRANSITIONS.filter((t) => t.idempotent).map((t) => t.id)).toEqual(['COMMIT_MARKER', 'REPEAT_COMPLETION']);
    expect(M2_LEGACY_INVALIDATION.REVERSE_AFTER_CONFIRMATION).toBe(false);
    expect(M2_LEGACY_INVALIDATION.CLEANUP_EFFECT).toBe(false);
    expect(M2_LEGACY_INVALIDATION.REAL_CONFIRMATION_BLOCKED_UNTIL_OWNERS_RATIFIED).toBe(true);
  });
});

describe('legacy-session-invalidation: totality and hostile input', () => {
  test('every malformed transition input rejects with a closed code or decision', () => {
    const good = { marker: marker(PENDING, TOKEN), event: EVENT_CANCEL, lockHeld: true, restoreResult: 'LEGACY_ONLY' };
    const cases = [
      [null, 'INCOMPATIBLE_FORMAT'],
      [[], 'INCOMPATIBLE_FORMAT'],
      ['x', 'INCOMPATIBLE_FORMAT'],
      [{ ...good, extra: 1 }, 'INCOMPATIBLE_FORMAT'],
      [{ marker: good.marker, event: EVENT_CANCEL, lockHeld: true }, 'INCOMPATIBLE_FORMAT'],
      [{ ...good, event: 7 }, 'INCOMPATIBLE_FORMAT'],
      [{ ...good, lockHeld: 'yes' }, 'INCOMPATIBLE_FORMAT'],
      [{ ...good, restoreResult: 'NOT_A_RESULT' }, 'INCOMPATIBLE_FORMAT'],
      [{ ...good, marker: 'not bytes' }, 'INCOMPATIBLE_FORMAT'],
      [{ ...good, marker: new Uint8Array(44) }, 'MARKER_ENCODING_INVALID'],
    ];
    for (const [input, code] of cases) {
      const error = errorOf(() => applyMarkerTransition(input));
      expect(error).toBeInstanceOf(M2LegacyInvalidationError);
      expect(error.code).toBe(code);
    }
  });

  test('an unknown event and a CONFIRM without its members never throw a foreign exception', () => {
    const unknown = applyMarkerTransition({
      marker: marker(PENDING, TOKEN), event: 'NOT_AN_EVENT', lockHeld: true, restoreResult: 'LEGACY_ONLY',
    });
    expect(unknown.disposition).toBe('REJECT');
    expect(unknown.reject).toBe('MARKER_TRANSITION_FORBIDDEN');
    expect(errorOf(() => applyMarkerTransition({
      marker: marker(PENDING, TOKEN), event: EVENT_CONFIRM, lockHeld: true, restoreResult: 'RESTORED_ACTIVE',
    })).code).toBe('INCOMPATIBLE_FORMAT');
  });

  test('a transition never writes the caller marker: the bytes are identical afterwards', () => {
    const bytes = marker(PENDING, TOKEN);
    const before = Uint8Array.from(bytes);
    for (const event of M2_LEGACY_INVALIDATION.EVENTS) {
      const input = event === EVENT_CONFIRM
        ? { marker: bytes, event, lockHeld: true, restoreResult: 'RESTORED_ACTIVE', committed: true, authorityToken: OTHER }
        : { marker: bytes, event, lockHeld: true, restoreResult: 'LEGACY_ONLY' };
      try {
        applyMarkerTransition(input);
      } catch (error) {
        expect(error).toBeInstanceOf(M2LegacyInvalidationError);
      }
    }
    expect(hex(bytes)).toBe(hex(before));
  });

  test('the module never writes through a proxy that records every mutating trap', () => {
    const traps = [];
    const target = { buffer: new ArrayBuffer(8), state: 0 };
    const proxy = new Proxy(target, {
      set(t, p, v) { traps.push(['set', p]); return Reflect.set(t, p, v); },
      deleteProperty(t, p) { traps.push(['delete', p]); return Reflect.deleteProperty(t, p); },
      defineProperty(t, p, d) { traps.push(['define', p]); return Reflect.defineProperty(t, p, d); },
    });
    expect(errorOf(() => readMarker(proxy)).code).toBe('INCOMPATIBLE_FORMAT');
    expect(traps).toEqual([]);
  });

  test('a spent transition decision grants no authority and no byte', () => {
    const decision = applyMarkerTransition({
      marker: marker(PENDING, TOKEN), event: EVENT_CONFIRM, lockHeld: true,
      restoreResult: 'RESTORED_ACTIVE', committed: true, authorityToken: OTHER,
    });
    expect(Object.keys(decision).sort()).toEqual([
      'accepted', 'disposition', 'firstFailingPhase', 'legacyEligible', 'reject', 'stateAfter', 'stateBefore',
    ]);
    expect(JSON.stringify(decision)).not.toContain(hex(OTHER));
    expect(JSON.stringify(decision)).not.toContain(hex(TOKEN));
  });
});

describe('legacy-session-invalidation: seeded properties', () => {
  const tokens = fc.uint8Array({ minLength: 32, maxLength: 32 });

  test('an arbitrary byte sequence decodes to a marker or a closed rejection', () => {
    fc.assert(fc.property(fc.uint8Array({ maxLength: 64 }), (bytes) => {
      try {
        const read = readMarker(bytes);
        expect([...M2_LEGACY_INVALIDATION.STATES]).toContain(read.state);
        expect(typeof read.legacyEligible).toBe('boolean');
      } catch (error) {
        expect(error).toBeInstanceOf(M2LegacyInvalidationError);
        expect([...M2_LEGACY_INVALIDATION.DECODE_FAILURE_CODES]).toContain(error.code);
      }
    }), { seed: 20261002, numRuns: 200 });
  });

  test('an arbitrary transition yields an accepted transition or a closed REJECT', () => {
    fc.assert(fc.property(
      fc.constantFrom(...M2_LEGACY_INVALIDATION.STATES),
      fc.constantFrom(...M2_LEGACY_INVALIDATION.EVENTS, 'NOT_AN_EVENT'),
      fc.constantFrom('LEGACY_ONLY', 'RESTORED_ACTIVE', 'RESTORED_EMPTY', 'NO_M2_STATE'),
      fc.boolean(), tokens, tokens,
      (state, event, restoreResult, lockHeld, start, authority) => {
        const startToken = state === ABSENT ? ZERO : start;
        const input = event === EVENT_CONFIRM
          ? { marker: marker(state, startToken), event, lockHeld, restoreResult, committed: true, authorityToken: authority }
          : { marker: marker(state, startToken), event, lockHeld, restoreResult };
        const decision = applyMarkerTransition(input);
        expect([...M2_LEGACY_INVALIDATION.DISPOSITIONS]).toContain(decision.disposition);
        expect([...M2_LEGACY_INVALIDATION.STATES]).toContain(decision.stateAfter);
        expect(decision.legacyEligible).toBe(M2_LEGACY_INVALIDATION.LEGACY_ELIGIBLE_BY_STATE[decision.stateAfter]);
        if (decision.disposition !== 'MARKER_TRANSITION') {
          expect([...M2_LEGACY_INVALIDATION.REJECT_CODES]).toContain(decision.reject);
        }
      },
    ), { seed: 20261003, numRuns: 300 });
  });

  test('legacyEligible agrees with LEGACY_ELIGIBLE_BY_STATE and replays identically', () => {
    fc.assert(fc.property(tokens, fc.constantFrom(...M2_LEGACY_INVALIDATION.STATES), (t, state) => {
      const token = state === ABSENT ? ZERO : t;
      expect(readMarker(marker(state, token)).legacyEligible)
        .toBe(M2_LEGACY_INVALIDATION.LEGACY_ELIGIBLE_BY_STATE[state]);
      expect(hex(marker(state, token))).toBe(hex(marker(state, token)));
      expect(legacyEligible(state)).toBe(M2_LEGACY_INVALIDATION.LEGACY_ELIGIBLE_BY_STATE[state]);
    }), { seed: 20261004, numRuns: 200 });
  });
});

// O-SCEN /marker scenarios (#337, ratification 5912195865). Eleven rows, all mapped.
describe('legacy-session-invalidation: O-SCEN /marker scenario mapping', () => {
  test('OSC-0617f4a2e92bc67a /marker/states', () => {
    expect(M2_LEGACY_INVALIDATION.STATES).toEqual([ABSENT, PENDING, CONFIRMED, INVALIDATED]);
  });

  test('OSC-0c458c1dd534931c /marker/transitions', () => {
    expect(M2_LEGACY_INVALIDATION.TRANSITIONS.map((t) => t.id)).toEqual([
      'START', 'CANCEL', 'CONFIRM', 'COMMIT_MARKER', 'REPEAT_COMPLETION',
    ]);
    expect(M2_LEGACY_INVALIDATION.TRANSITIONS.every((t) => t.requiresLock === true)).toBe(true);
  });

  test('OSC-0e3dca21f11c1ac9 /marker/completeRestoreResultRequired', () => {
    expect(M2_LEGACY_INVALIDATION.COMPLETE_RESTORE_RESULT_REQUIRED).toBe(true);
    expect(errorOf(() => applyMarkerTransition({
      marker: marker(ABSENT, ZERO), event: EVENT_START, lockHeld: true, restoreResult: 'NOT_A_RESULT',
    })).code).toBe('INCOMPATIBLE_FORMAT');
  });

  test('OSC-4680c61e241ca128 /marker/legacyEligibleByState', () => {
    expect(M2_LEGACY_INVALIDATION.LEGACY_ELIGIBLE_BY_STATE).toEqual({
      ABSENT: true, LEGACY_INVALIDATED: false, NEW_SESSION_CONFIRMED: false, PENDING_NEW_SESSION: true,
    });
  });

  test('OSC-4c3c094cf46d0bcc /marker/binding', () => {
    expect(M2_LEGACY_INVALIDATION.BINDING).toBe('OPAQUE_START_AUTHORITY_CONFIRMATION_TOKEN_EQUALITY');
  });

  test('OSC-6ca21590b4a144b9 /marker/encodingOwner', () => {
    expect(M2_LEGACY_INVALIDATION.ENCODING_OWNER).toBe('L-MARK');
  });

  test('OSC-a218f4baff492e91 /marker/newSessionOwner', () => {
    expect(M2_LEGACY_INVALIDATION.NEW_SESSION_OWNER).toBe('L-REEST');
    expect(Object.hasOwn(invalidationModule, 'createSession')).toBe(false);
  });

  test('OSC-176c10e0e39b4da5 /marker/timeOrFreshnessComparison', () => {
    expect(M2_LEGACY_INVALIDATION.TIME_OR_FRESHNESS_COMPARISON).toBe(false);
  });

  test('OSC-9fa14e5d931541c9 /marker/cleanupEffect', () => {
    expect(M2_LEGACY_INVALIDATION.CLEANUP_EFFECT).toBe(false);
  });

  test('OSC-08a2b725d2fa29e3 /marker/reverseAfterConfirmation', () => {
    expect(M2_LEGACY_INVALIDATION.REVERSE_AFTER_CONFIRMATION).toBe(false);
    expect(applyMarkerTransition({
      marker: marker(CONFIRMED, TOKEN), event: EVENT_CANCEL, lockHeld: true, restoreResult: 'LEGACY_ONLY',
    }).reject).toBe('MARKER_TRANSITION_FORBIDDEN');
  });

  test('OSC-a3f5176794a7cad3 /marker/realConfirmationBlockedUntilOwnersRatified', () => {
    expect(M2_LEGACY_INVALIDATION.REAL_CONFIRMATION_BLOCKED_UNTIL_OWNERS_RATIFIED).toBe(true);
  });
});
