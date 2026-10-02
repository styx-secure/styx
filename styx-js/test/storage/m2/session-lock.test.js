import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import M2_LOCK, {
  ACTIONS, CONTEXT_OUTCOMES, CONTEXT_ROLES, FIRST_FAILING_PHASES, LOCK_CLAUSES,
  LOCK_DISPOSITIONS, LOCK_ERROR_CODES, LOCK_FAULTS, LOCK_PHASE, LOCK_RESULTS,
  LOCK_SCENARIOS, MARKER_STATES, OUTER_RESULTS, OWNERSHIP, SESSION_ACTIVE_ELSEWHERE,
  actionRequiresLock, activeContextIds, anySecondContextSilentlyActive,
  evaluateLockAction, evaluateSecondTabMatrix,
} from '../../../src/storage/m2/session-lock.js';

// ---------------------------------------------------------------------------------------------
// Fixtures and helpers.
// ---------------------------------------------------------------------------------------------

const ctx = (contextId, role, ownership, intent) => ({ contextId, role, ownership, intent });

/** Build a lock observation by name. */
const obs = (contextId, role, ownership, action) => ({ contextId, role, ownership, action });

/** The exact C-REC /fixtures/56 NEG-NO-LOCK agreement, as a matrix row or gate must carry it. */
const NEG_NO_LOCK = Object.freeze({
  result: 'LOCKED_ELSEWHERE',
  disposition: 'LOCK_RETRY',
  authority: 'NONE',
  firstFailingPhase: 'LOCK',
  markerState: 'UNCHANGED',
  authorized: false,
});
const agreementOf = (row) => ({
  result: row.result,
  disposition: row.disposition,
  authority: row.authority,
  firstFailingPhase: row.firstFailingPhase,
  markerState: row.markerState,
  authorized: row.authorized,
});

const sha256 = (text) => createHash('sha256').update(text, 'utf8').digest('hex');

const EXPECTED_CLAUSE_SHA = {
  SINGLE_WRITER: 'bd5b8b8356c0c60e04ed40241930e3c136d26ba6c5d93e0b1c269f4e7d81f115',
  REST_PHASE_LOCK: 'ebe3cbb6ed4cdd42001a028b0b7c41b6bd08cfb69a4d389103dad0a5839b1ffa',
  REST_PROSE_19: '9c4a27bfed3e189e09bc8eb444938fbe669007715364b47f326bd047d026c89b',
  REC_REQUIRES_LOCK: '89fb9dae2b011c6943b81a32ab9e74f654080f61587d784adc299da452827893',
  REC_DISPOSITION_LOCK_RETRY: '89fb9dae2b011c6943b81a32ab9e74f654080f61587d784adc299da452827893',
  REC_REQUIRES_LOCK_FOR_STATE_CHANGE: 'b5bea41b6c623f7c09f1bf24dcae58ebab3c0cdd90ad966bc43a45b44867e12b',
  REC_AMBIGUOUS_FACTS: '5f73f2562834ac35edc6bbdfadda70ffad8debcbb4e1f67cf456caf7bdeb6cc1',
  REC_ENUMERATION_ORDER: 'fcbcf165908dd18a9e49f7ff27810176db8e9f63b4352213741664245224f8aa',
  REC_FAULT_PRECEDENCE: '2ea8afd00482766b96f24d364ffec2cabfb0caab307bf8ab6c45ccb91a356d52',
  REST_FAULT_PRECEDENCE: '2ea8afd00482766b96f24d364ffec2cabfb0caab307bf8ab6c45ccb91a356d52',
  REC_NEG_NO_LOCK: '7f51788a637285f57a20e0c83229b0aecfe084ad81552d39fd86b127bbbede0a',
  REC_RESET_NO_LOCK: 'accdc51e23385e5a76d7927678ed85f9e6d0ea292d130ee58b8ff81ad17c4087',
  REC_MARKER_TRANSITIONS: 'eb3c0cd8d0f8a62c6adfa413b3644317cf1cbf9ee4568921a44a1c46cc4f411d',
};

/** Canonical JSON: sorted keys, compact separators (the O-SCEN canonical clause rule). */
const canonical = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(value);
};

// ---------------------------------------------------------------------------------------------
// Closed sets.
// ---------------------------------------------------------------------------------------------

describe('M2_LOCK closed sets', () => {
  test('every exported set is frozen and carries exactly its ratified members', () => {
    expect(Object.isFrozen(M2_LOCK)).toBe(true);
    expect(LOCK_PHASE).toBe('LOCK');
    expect([...LOCK_FAULTS]).toEqual(['lockUnavailable']);
    expect([...LOCK_RESULTS]).toEqual(['LOCKED_ELSEWHERE']);
    expect([...LOCK_DISPOSITIONS]).toEqual(['LOCK_RETRY']);
    expect([...OUTER_RESULTS]).toEqual([SESSION_ACTIVE_ELSEWHERE]);
    expect(SESSION_ACTIVE_ELSEWHERE).toBe('SESSION_ACTIVE_ELSEWHERE');
    expect([...CONTEXT_ROLES]).toEqual(['WORKER', 'WRITER']);
    expect([...CONTEXT_OUTCOMES]).toEqual(['ACTIVE', SESSION_ACTIVE_ELSEWHERE]);
    expect([...OWNERSHIP]).toEqual(['HELD_BY_SELF', 'HELD_BY_OTHER', 'FREE', 'UNAVAILABLE']);
    expect([...ACTIONS]).toEqual(['ACQUIRE', 'READ', 'STATE_CHANGE']);
    expect([...LOCK_ERROR_CODES]).toEqual(['UNKNOWN_FIELD', 'INVALID_REQUEST', 'UNKNOWN_VALUE']);
    expect([...FIRST_FAILING_PHASES]).toEqual(['NONE', 'LOCK']);
    expect([...MARKER_STATES]).toEqual(['UNCHANGED']);
  });

  test('every closed set is frozen so a caller cannot widen it', () => {
    for (const set of [LOCK_FAULTS, LOCK_RESULTS, LOCK_DISPOSITIONS, OUTER_RESULTS, CONTEXT_ROLES,
      CONTEXT_OUTCOMES, OWNERSHIP, ACTIONS, LOCK_ERROR_CODES, FIRST_FAILING_PHASES, MARKER_STATES]) {
      expect(Object.isFrozen(set)).toBe(true);
    }
  });

  test('no new error vocabulary is introduced: every rejection code is a C-API errorCodeEnum member', () => {
    for (const code of LOCK_ERROR_CODES) {
      expect(['UNKNOWN_FIELD', 'INVALID_REQUEST', 'UNKNOWN_VALUE']).toContain(code);
    }
  });

  test('the ratified lock clauses and their canonical SHA-256 are transcribed exactly', () => {
    expect(Object.keys(LOCK_CLAUSES).sort()).toEqual(Object.keys(EXPECTED_CLAUSE_SHA).sort());
    for (const [name, sha] of Object.entries(EXPECTED_CLAUSE_SHA)) {
      expect(LOCK_CLAUSES[name].clauseSha256).toBe(sha);
      expect(LOCK_CLAUSES[name].key).toMatch(/^(CL|PROSE)-[A-Z]+(-[0-9]+)?-[0-9a-f]+$/);
      expect(LOCK_CLAUSES[name].content.length).toBeGreaterThan(0);
      expect(Object.isFrozen(LOCK_CLAUSES[name])).toBe(true);
    }
    expect(LOCK_CLAUSES.SINGLE_WRITER.key).toBe('CL-CAPI-b02195b48fbc');
    expect(LOCK_CLAUSES.SINGLE_WRITER.path).toBe('/rules/singleWriter');
    expect(LOCK_CLAUSES.REST_PHASE_LOCK.path).toBe('/phaseRules/0');
    expect(LOCK_CLAUSES.REST_PROSE_19.path).toBe('/prose/19');
  });

  test('the ratified C-API singleWriter sentence is carried verbatim', () => {
    expect(JSON.parse(LOCK_CLAUSES.SINGLE_WRITER.content)).toBe(
      'I-LOCK prevents a second active context before it invokes this API; '
      + 'session-active-elsewhere is therefore an outer UI/controller result, not an adapter result',
    );
  });

  test('the ratified C-REST LOCK-phase rule is carried verbatim', () => {
    expect(JSON.parse(LOCK_CLAUSES.REST_PHASE_LOCK.content)).toEqual({
      phase: 'LOCK',
      rule: 'Acquire the one-writer Web Lock; read no M2 or legacy bytes before success.',
    });
  });

  test('every carried clause content is the canonical content its clauseSha256 covers', () => {
    for (const [name, clause] of Object.entries(LOCK_CLAUSES)) {
      expect([name, sha256(clause.content)]).toEqual([name, clause.clauseSha256]);
      expect([name, canonical(JSON.parse(clause.content))]).toEqual([name, clause.content]);
    }
  });

  test('every ratified C-REC marker transition requires the lock', () => {
    const transitions = JSON.parse(LOCK_CLAUSES.REC_MARKER_TRANSITIONS.content);
    expect(transitions.map((t) => t.id)).toEqual(['START', 'CANCEL', 'CONFIRM', 'COMMIT_MARKER', 'REPEAT_COMPLETION']);
    for (const t of transitions) expect(t.requiresLock).toBe(true);
  });

  test('the ratified C-REC precedence and disposition clauses the matrix relies on are carried', () => {
    expect(JSON.parse(LOCK_CLAUSES.REC_AMBIGUOUS_FACTS.content)).toBe('SAFER_DISPOSITION_NO_AUTHORITY');
    expect(JSON.parse(LOCK_CLAUSES.REC_ENUMERATION_ORDER.content)).toBe(false);
    expect(JSON.parse(LOCK_CLAUSES.REC_REQUIRES_LOCK_FOR_STATE_CHANGE.content)).toBe(true);
    expect(JSON.parse(LOCK_CLAUSES.REC_DISPOSITION_LOCK_RETRY.content)).toBe(LOCK_DISPOSITIONS[0]);
    expect(JSON.parse(LOCK_CLAUSES.REC_REQUIRES_LOCK.content)).toBe(LOCK_DISPOSITIONS[0]);
  });

  test('NEG-NO-LOCK and RESET-NO-LOCK carry the same lock agreement the gate emits', () => {
    for (const clause of [LOCK_CLAUSES.REC_NEG_NO_LOCK, LOCK_CLAUSES.REC_RESET_NO_LOCK]) {
      const { expected } = JSON.parse(clause.content);
      expect(expected.reject).toBe(NEG_NO_LOCK.result);
      expect(expected.agreement).toEqual({
        authorityIdentity: NEG_NO_LOCK.authority,
        disposition: NEG_NO_LOCK.disposition,
        firstFailingPhase: NEG_NO_LOCK.firstFailingPhase,
        markerState: NEG_NO_LOCK.markerState,
      });
    }
  });
});

// ---------------------------------------------------------------------------------------------
// actionRequiresLock.
// ---------------------------------------------------------------------------------------------

describe('actionRequiresLock', () => {
  test('STATE_CHANGE requires the lock (C-REC requiresOneWriterLockForStateChange)', () => {
    expect(actionRequiresLock('STATE_CHANGE')).toBe(true);
  });

  test('READ requires the lock (C-REST /phaseRules/0, /prose/19)', () => {
    expect(actionRequiresLock('READ')).toBe(true);
  });

  test('only ACQUIRE itself precedes the lock', () => {
    expect(actionRequiresLock('ACQUIRE')).toBe(false);
  });

  test('an unknown action throws rather than silently permitting', () => {
    expect(() => actionRequiresLock('DELETE')).toThrow(TypeError);
    expect(() => actionRequiresLock('')).toThrow(TypeError);
    expect(() => actionRequiresLock(null)).toThrow(TypeError);
    expect(() => actionRequiresLock(undefined)).toThrow(TypeError);
  });
});

// ---------------------------------------------------------------------------------------------
// evaluateLockAction — the holder.
// ---------------------------------------------------------------------------------------------

describe('evaluateLockAction — the holder is authorized', () => {
  for (const role of CONTEXT_ROLES) {
    for (const action of ACTIONS) {
      test(`HELD_BY_SELF/${role}/${action} is authorized with no result`, () => {
        const out = evaluateLockAction(obs('tabA', role, 'HELD_BY_SELF', action));
        expect(out.accepted).toBe(true);
        expect(out.error).toBeNull();
        expect(out.authorized).toBe(true);
        expect(out.result).toBeNull();
        expect(out.disposition).toBeNull();
        expect(out.authority).toBe('SELF');
        expect(out.firstFailingPhase).toBe('NONE');
        expect(out.markerState).toBe('UNCHANGED');
      });
    }
  }

  test('the holder envelope echoes the observation it classified', () => {
    const out = evaluateLockAction(obs('tabA', 'WRITER', 'HELD_BY_SELF', 'STATE_CHANGE'));
    expect(out.contextId).toBe('tabA');
    expect(out.role).toBe('WRITER');
    expect(out.action).toBe('STATE_CHANGE');
  });
});

// ---------------------------------------------------------------------------------------------
// evaluateLockAction — every non-holder is closed out.
// ---------------------------------------------------------------------------------------------

describe('evaluateLockAction — a non-holder never proceeds', () => {
  test('HELD_BY_OTHER yields LOCKED_ELSEWHERE with disposition LOCK_RETRY', () => {
    for (const role of CONTEXT_ROLES) {
      for (const action of ACTIONS) {
        const out = evaluateLockAction(obs('tabB', role, 'HELD_BY_OTHER', action));
        expect(out.accepted).toBe(true);
        expect(out.authorized).toBe(false);
        expect(out.result).toBe('LOCKED_ELSEWHERE');
        expect(out.disposition).toBe('LOCK_RETRY');
        expect(out.authority).toBe('NONE');
        expect(out.firstFailingPhase).toBe('LOCK');
        expect(out.markerState).toBe('UNCHANGED');
      }
    }
  });

  test('UNAVAILABLE (C-REC lockUnavailable) yields LOCKED_ELSEWHERE at the LOCK phase', () => {
    for (const role of CONTEXT_ROLES) {
      for (const action of ACTIONS) {
        const out = evaluateLockAction(obs('tabB', role, 'UNAVAILABLE', action));
        expect(out.authorized).toBe(false);
        expect(out.result).toBe('LOCKED_ELSEWHERE');
        expect(out.disposition).toBe('LOCK_RETRY');
        expect(out.firstFailingPhase).toBe('LOCK');
      }
    }
  });

  test('FREE permits only the acquisition attempt itself', () => {
    const acquire = evaluateLockAction(obs('tabA', 'WORKER', 'FREE', 'ACQUIRE'));
    expect(acquire.authorized).toBe(true);
    expect(acquire.result).toBeNull();
    for (const action of ['READ', 'STATE_CHANGE']) {
      const gated = evaluateLockAction(obs('tabA', 'WORKER', 'FREE', action));
      expect(gated.authorized).toBe(false);
      expect(gated.result).toBe('LOCKED_ELSEWHERE');
      expect(gated.disposition).toBe('LOCK_RETRY');
      expect(gated.firstFailingPhase).toBe('LOCK');
    }
  });

  test('the rejection envelope reproduces the C-REC /fixtures/56 NEG-NO-LOCK agreement', () => {
    // input {event USER_CONFIRMED_START, lockHeld false, state ABSENT} => reject LOCKED_ELSEWHERE
    const out = evaluateLockAction(obs('tabB', 'WRITER', 'HELD_BY_OTHER', 'STATE_CHANGE'));
    expect({
      result: out.result, disposition: out.disposition, authority: out.authority,
      firstFailingPhase: out.firstFailingPhase, markerState: out.markerState,
    }).toEqual({
      result: 'LOCKED_ELSEWHERE', disposition: 'LOCK_RETRY', authority: 'NONE',
      firstFailingPhase: 'LOCK', markerState: 'UNCHANGED',
    });
  });
});

// ---------------------------------------------------------------------------------------------
// evaluateLockAction — malformed observations.
// ---------------------------------------------------------------------------------------------

describe('evaluateLockAction — malformed observations reject with C-API codes', () => {
  const BAD = [
    [null, 'INVALID_REQUEST'],
    [undefined, 'INVALID_REQUEST'],
    [42, 'INVALID_REQUEST'],
    ['tabA', 'INVALID_REQUEST'],
    [[], 'INVALID_REQUEST'],
    [new Map(), 'INVALID_REQUEST'],
    [new Uint8Array(3), 'INVALID_REQUEST'],
    [{ contextId: 'a', role: 'WORKER', ownership: 'FREE' }, 'INVALID_REQUEST'],
    [{ contextId: 'a', role: 'WORKER', action: 'READ' }, 'INVALID_REQUEST'],
    [{ role: 'WORKER', ownership: 'FREE', action: 'READ' }, 'INVALID_REQUEST'],
    [{ contextId: 'a', role: 'WORKER', ownership: 'FREE', action: 'READ', extra: 1 }, 'UNKNOWN_FIELD'],
    // `__proto__: null` makes the value a null-prototype object, which this module never
    // treats as a closed plain record: it is rejected before any field is read.
    [{ contextId: 'a', role: 'WORKER', ownership: 'FREE', action: 'READ', __proto__: null }, 'INVALID_REQUEST'],
  ];
  for (const [value, code] of BAD) {
    test(`rejects ${JSON.stringify(value)} as ${code}`, () => {
      const out = evaluateLockAction(value);
      expect(out.accepted).toBe(false);
      expect(out.error).toBe(code);
      expect(out.authorized).toBe(false);
      expect(out.authority).toBe('NONE');
    });
  }

  test('rejects an empty context id', () => {
    const out = evaluateLockAction(obs('', 'WORKER', 'FREE', 'READ'));
    expect(out.accepted).toBe(false);
    expect(out.error).toBe('INVALID_REQUEST');
  });

  test('rejects unknown enum values with UNKNOWN_VALUE', () => {
    expect(evaluateLockAction(obs('a', 'READER', 'FREE', 'READ')).error).toBe('UNKNOWN_VALUE');
    expect(evaluateLockAction(obs('a', 'WORKER', 'MAYBE', 'READ')).error).toBe('UNKNOWN_VALUE');
    expect(evaluateLockAction(obs('a', 'WORKER', 'FREE', 'DELETE')).error).toBe('UNKNOWN_VALUE');
  });

  test('rejects a symbol-keyed observation as UNKNOWN_FIELD', () => {
    const value = obs('a', 'WORKER', 'FREE', 'READ');
    value[Symbol('x')] = 1;
    expect(evaluateLockAction(value).error).toBe('UNKNOWN_FIELD');
  });

  test('rejects an accessor member rather than executing it', () => {
    const value = obs('a', 'WORKER', 'FREE', 'READ');
    let executed = false;
    Object.defineProperty(value, 'action', { get() { executed = true; return 'READ'; }, enumerable: true });
    const out = evaluateLockAction(value);
    expect(out.accepted).toBe(false);
    expect(out.error).toBe('INVALID_REQUEST');
    expect(executed).toBe(false);
  });

  test('rejects a Proxy whose descriptor reports a value its target does not hold', () => {
    const lying = (field) => new Proxy(
      { contextId: 'tabB', role: 'WRITER', ownership: 'HELD_BY_OTHER', [field]: 'STATE_CHANGE' },
      {
        getOwnPropertyDescriptor(target, key) {
          const d = Reflect.getOwnPropertyDescriptor(target, key);
          return key === 'ownership' && d ? { ...d, value: 'HELD_BY_SELF' } : d;
        },
      },
    );
    const single = evaluateLockAction(lying('action'));
    expect(single.accepted).toBe(false);
    expect(single.error).toBe('INVALID_REQUEST');
    expect(single.authorized).toBe(false);
    const matrix = evaluateSecondTabMatrix([lying('intent')]);
    expect(matrix.accepted).toBe(false);
    expect(matrix.error).toBe('INVALID_REQUEST');
    expect(matrix.activeContextIds).toEqual([]);
  });

  test('rejects a Proxy whose trap throws, and a revoked Proxy, with INVALID_REQUEST', () => {
    const throwing = new Proxy(obs('a', 'WORKER', 'FREE', 'READ'), { ownKeys() { throw new Error('trap'); } });
    expect(evaluateLockAction(throwing).error).toBe('INVALID_REQUEST');
    const { proxy, revoke } = Proxy.revocable(obs('a', 'WORKER', 'FREE', 'READ'), {});
    revoke();
    expect(evaluateLockAction(proxy).error).toBe('INVALID_REQUEST');
  });
});

// ---------------------------------------------------------------------------------------------
// evaluateSecondTabMatrix — the exact second-tab outcomes.
// ---------------------------------------------------------------------------------------------

describe('evaluateSecondTabMatrix — exact disabled/active outcomes', () => {
  test('one holder and one second tab: exactly ACTIVE and SESSION_ACTIVE_ELSEWHERE', () => {
    const matrix = evaluateSecondTabMatrix([
      ctx('tabA', 'WRITER', 'HELD_BY_SELF', 'STATE_CHANGE'),
      ctx('tabB', 'WRITER', 'HELD_BY_OTHER', 'STATE_CHANGE'),
    ]);
    expect(matrix.accepted).toBe(true);
    expect(matrix.ambiguous).toBe(false);
    expect(matrix.singleWriter).toBe(true);
    expect(matrix.activeContextIds).toEqual(['tabA']);
    expect(matrix.contexts.map((r) => [r.contextId, r.outcome, r.result, r.disposition])).toEqual([
      ['tabA', 'ACTIVE', null, null],
      ['tabB', SESSION_ACTIVE_ELSEWHERE, 'LOCKED_ELSEWHERE', 'LOCK_RETRY'],
    ]);
  });

  test('a second tab that only reads is still SESSION_ACTIVE_ELSEWHERE, never ACTIVE', () => {
    const matrix = evaluateSecondTabMatrix([
      ctx('tabA', 'WRITER', 'HELD_BY_SELF', 'STATE_CHANGE'),
      ctx('tabB', 'WORKER', 'HELD_BY_OTHER', 'READ'),
    ]);
    const tabB = matrix.contexts.find((r) => r.contextId === 'tabB');
    expect(tabB.outcome).toBe(SESSION_ACTIVE_ELSEWHERE);
    expect(tabB.authorized).toBe(false);
    expect(tabB.result).toBe('LOCKED_ELSEWHERE');
  });

  test('a fresh worker with a free lock starts locked and may only acquire', () => {
    const matrix = evaluateSecondTabMatrix([ctx('fresh', 'WORKER', 'FREE', 'ACQUIRE')]);
    expect(matrix.activeContextIds).toEqual([]);
    expect(matrix.ambiguous).toBe(false);
    const row = matrix.contexts[0];
    expect(row.outcome).toBe(SESSION_ACTIVE_ELSEWHERE);
    expect(row.authorized).toBe(false);
    expect(row.result).toBeNull();
    expect(row.authority).toBe('NONE');
    expect(row.firstFailingPhase).toBe('NONE');
  });

  test('a free lock gates READ and STATE_CHANGE in the matrix with the NEG-NO-LOCK agreement', () => {
    const matrix = evaluateSecondTabMatrix([
      ctx('fresh', 'WORKER', 'FREE', 'READ'),
      ctx('other', 'WRITER', 'FREE', 'STATE_CHANGE'),
    ]);
    for (const row of matrix.contexts) expect(agreementOf(row)).toEqual(NEG_NO_LOCK);
  });

  test('a single holder is ACTIVE and is the only active context', () => {
    const matrix = evaluateSecondTabMatrix([ctx('tabA', 'WRITER', 'HELD_BY_SELF', 'STATE_CHANGE')]);
    expect(matrix.activeContextIds).toEqual(['tabA']);
    expect(matrix.contexts[0].outcome).toBe('ACTIVE');
    expect(matrix.contexts[0].authorized).toBe(true);
  });

  test('an empty profile has no active context', () => {
    const matrix = evaluateSecondTabMatrix([]);
    expect(matrix.accepted).toBe(true);
    expect(matrix.activeContextIds).toEqual([]);
    expect(matrix.contexts).toEqual([]);
    expect(matrix.singleWriter).toBe(true);
  });

  test('outcomes are independent of the input order', () => {
    const forward = evaluateSecondTabMatrix([
      ctx('tabA', 'WRITER', 'HELD_BY_SELF', 'STATE_CHANGE'),
      ctx('tabB', 'WORKER', 'HELD_BY_OTHER', 'READ'),
      ctx('tabC', 'WRITER', 'FREE', 'STATE_CHANGE'),
    ]);
    const reversed = evaluateSecondTabMatrix([
      ctx('tabC', 'WRITER', 'FREE', 'STATE_CHANGE'),
      ctx('tabB', 'WORKER', 'HELD_BY_OTHER', 'READ'),
      ctx('tabA', 'WRITER', 'HELD_BY_SELF', 'STATE_CHANGE'),
    ]);
    const outcomeMap = (m) => Object.fromEntries(m.contexts.map((r) => [r.contextId, [r.outcome, r.result, r.disposition]]));
    expect(outcomeMap(forward)).toEqual(outcomeMap(reversed));
    expect(forward.activeContextIds).toEqual(reversed.activeContextIds);
  });
});

describe('evaluateSecondTabMatrix — contradictory and degenerate inputs', () => {
  test('two claimants of the one lock contradict: no context is active', () => {
    const matrix = evaluateSecondTabMatrix([
      ctx('tabA', 'WRITER', 'HELD_BY_SELF', 'STATE_CHANGE'),
      ctx('tabB', 'WRITER', 'HELD_BY_SELF', 'STATE_CHANGE'),
    ]);
    expect(matrix.accepted).toBe(true);
    expect(matrix.ambiguous).toBe(true);
    expect(matrix.activeContextIds).toEqual([]);
    expect(matrix.singleWriter).toBe(true);
    for (const row of matrix.contexts) expect(row.outcome).toBe(SESSION_ACTIVE_ELSEWHERE);
    expect(anySecondContextSilentlyActive(matrix)).toBe(false);
  });

  test('two claimants: every non-active READ/STATE_CHANGE row carries exactly NEG-NO-LOCK', () => {
    for (const [intentA, intentB] of [['STATE_CHANGE', 'READ'], ['READ', 'READ'], ['STATE_CHANGE', 'STATE_CHANGE']]) {
      const input = [
        ctx('tabA', 'WRITER', 'HELD_BY_SELF', intentA),
        ctx('tabB', 'WORKER', 'HELD_BY_SELF', intentB),
      ];
      for (const order of [input, input.slice().reverse()]) {
        const matrix = evaluateSecondTabMatrix(order);
        expect(matrix.ambiguous).toBe(true);
        expect(matrix.activeContextIds).toEqual([]);
        for (const row of matrix.contexts) {
          expect(row.outcome).toBe(SESSION_ACTIVE_ELSEWHERE);
          expect(agreementOf(row)).toEqual(NEG_NO_LOCK);
        }
      }
    }
  });

  test('a claimant beside a context observing the lock FREE is contradictory: no context is active', () => {
    const input = [
      ctx('tabA', 'WRITER', 'HELD_BY_SELF', 'STATE_CHANGE'),
      ctx('tabB', 'WRITER', 'FREE', 'ACQUIRE'),
    ];
    for (const order of [input, input.slice().reverse()]) {
      const matrix = evaluateSecondTabMatrix(order);
      expect(matrix.ambiguous).toBe(true);
      expect(matrix.activeContextIds).toEqual([]);
      for (const row of matrix.contexts) {
        expect(row.outcome).toBe(SESSION_ACTIVE_ELSEWHERE);
        expect(agreementOf(row)).toEqual(NEG_NO_LOCK);
      }
    }
  });

  test('a claimant beside a context that cannot observe the lock (UNAVAILABLE) is not made active', () => {
    const matrix = evaluateSecondTabMatrix([
      ctx('tabA', 'WRITER', 'HELD_BY_SELF', 'READ'),
      ctx('tabB', 'WORKER', 'UNAVAILABLE', 'READ'),
    ]);
    expect(matrix.ambiguous).toBe(true);
    expect(matrix.activeContextIds).toEqual([]);
    for (const row of matrix.contexts) expect(agreementOf(row)).toEqual(NEG_NO_LOCK);
  });

  test('every matrix row carries an authority field', () => {
    const matrix = evaluateSecondTabMatrix([
      ctx('tabA', 'WRITER', 'HELD_BY_SELF', 'STATE_CHANGE'),
      ctx('tabB', 'WORKER', 'HELD_BY_OTHER', 'READ'),
    ]);
    expect(matrix.contexts.map((r) => r.authority)).toEqual(['SELF', 'NONE']);
  });

  test('a duplicate context id rejects', () => {
    const matrix = evaluateSecondTabMatrix([
      ctx('tabA', 'WRITER', 'HELD_BY_SELF', 'STATE_CHANGE'),
      ctx('tabA', 'WORKER', 'FREE', 'READ'),
    ]);
    expect(matrix.accepted).toBe(false);
    expect(matrix.error).toBe('UNKNOWN_VALUE');
    expect(matrix.activeContextIds).toEqual([]);
  });

  test('a malformed context record rejects the whole matrix', () => {
    for (const bad of [null, 1, 'tabA', [], {}, { contextId: 'a', role: 'READER', ownership: 'FREE', intent: 'READ' },
      { contextId: 'a', role: 'WORKER', ownership: 'FREE', intent: 'DELETE' },
      { contextId: '', role: 'WORKER', ownership: 'FREE', intent: 'READ' }]) {
      const matrix = evaluateSecondTabMatrix([bad]);
      expect(matrix.accepted).toBe(false);
      expect(['INVALID_REQUEST', 'UNKNOWN_FIELD', 'UNKNOWN_VALUE']).toContain(matrix.error);
      expect(matrix.activeContextIds).toEqual([]);
    }
  });

  test('a non-array input rejects', () => {
    const { proxy, revoke } = Proxy.revocable([], {});
    revoke();
    for (const value of [null, undefined, {}, 'tabA', 7, proxy]) {
      expect(evaluateSecondTabMatrix(value).accepted).toBe(false);
    }
  });
});

// ---------------------------------------------------------------------------------------------
// The fail-closed guard.
// ---------------------------------------------------------------------------------------------

describe('anySecondContextSilentlyActive', () => {
  test('is false for every matrix this module can build', () => {
    const matrices = [
      [],
      [ctx('a', 'WRITER', 'HELD_BY_SELF', 'STATE_CHANGE')],
      [ctx('a', 'WRITER', 'HELD_BY_SELF', 'STATE_CHANGE'), ctx('b', 'WORKER', 'HELD_BY_OTHER', 'READ')],
      [ctx('a', 'WRITER', 'HELD_BY_SELF', 'STATE_CHANGE'), ctx('b', 'WRITER', 'HELD_BY_SELF', 'READ')],
      [ctx('a', 'WORKER', 'FREE', 'ACQUIRE'), ctx('b', 'WORKER', 'FREE', 'ACQUIRE')],
      [ctx('a', 'WORKER', 'UNAVAILABLE', 'STATE_CHANGE'), ctx('b', 'WORKER', 'HELD_BY_OTHER', 'READ')],
    ];
    for (const input of matrices) {
      expect(anySecondContextSilentlyActive(evaluateSecondTabMatrix(input))).toBe(false);
    }
  });

  test('detects a hand-built matrix that would activate two contexts', () => {
    const cheating = {
      accepted: true,
      contexts: [
        { contextId: 'a', outcome: 'ACTIVE', authorized: true },
        { contextId: 'b', outcome: 'ACTIVE', authorized: true },
      ],
    };
    expect(anySecondContextSilentlyActive(cheating)).toBe(true);
  });

  test('a matrix row that is neither ACTIVE nor SESSION_ACTIVE_ELSEWHERE but authorized is caught', () => {
    const cheating = {
      accepted: true,
      contexts: [
        { contextId: 'a', outcome: 'ACTIVE', authorized: true },
        { contextId: 'b', outcome: 'SOMETHING_ELSE', authorized: true },
      ],
    };
    expect(anySecondContextSilentlyActive(cheating)).toBe(true);
  });

  test('an authorized row labelled SESSION_ACTIVE_ELSEWHERE beside the holder is caught', () => {
    expect(anySecondContextSilentlyActive({
      accepted: true,
      activeContextIds: ['a'],
      contexts: [
        { contextId: 'a', outcome: 'ACTIVE', authorized: true },
        { contextId: 'b', outcome: SESSION_ACTIVE_ELSEWHERE, authorized: true },
      ],
    })).toBe(true);
  });

  test('activeContextIds naming two contexts is caught even with no rows', () => {
    expect(anySecondContextSilentlyActive({ accepted: true, activeContextIds: ['a', 'b'], contexts: [] })).toBe(true);
    expect(anySecondContextSilentlyActive({
      accepted: true,
      activeContextIds: ['b'],
      contexts: [{ contextId: 'a', outcome: 'ACTIVE', authorized: true }],
    })).toBe(true);
  });

  test('a malformed activeContextIds fails closed', () => {
    expect(anySecondContextSilentlyActive({ accepted: true, activeContextIds: 'a', contexts: [] })).toBe(true);
  });

  test('one holder consistently named by its row and activeContextIds is not flagged', () => {
    expect(anySecondContextSilentlyActive({
      accepted: true,
      activeContextIds: ['a'],
      contexts: [
        { contextId: 'a', outcome: 'ACTIVE', authorized: true },
        { contextId: 'b', outcome: SESSION_ACTIVE_ELSEWHERE, authorized: false },
      ],
    })).toBe(false);
  });

  test('throws on a value that is not a matrix', () => {
    expect(() => anySecondContextSilentlyActive(null)).toThrow(TypeError);
    expect(() => anySecondContextSilentlyActive({})).toThrow(TypeError);
  });
});

describe('activeContextIds', () => {
  test('returns a copy and never more than one id', () => {
    const matrix = evaluateSecondTabMatrix([ctx('a', 'WRITER', 'HELD_BY_SELF', 'STATE_CHANGE')]);
    const ids = activeContextIds(matrix);
    ids.push('intruder');
    expect(activeContextIds(matrix)).toEqual(['a']);
  });

  test('throws on a value that is not a matrix', () => {
    expect(() => activeContextIds(null)).toThrow(TypeError);
    expect(() => activeContextIds({})).toThrow(TypeError);
  });
});

// ---------------------------------------------------------------------------------------------
// Determinism and closedness.
// ---------------------------------------------------------------------------------------------

describe('determinism and closedness', () => {
  test('the same observation serialises identically twice', () => {
    const value = obs('tabA', 'WRITER', 'HELD_BY_OTHER', 'STATE_CHANGE');
    expect(JSON.stringify(evaluateLockAction(value))).toBe(JSON.stringify(evaluateLockAction(value)));
  });

  test('the same matrix serialises identically twice', () => {
    const input = [ctx('a', 'WRITER', 'HELD_BY_SELF', 'STATE_CHANGE'), ctx('b', 'WORKER', 'FREE', 'READ')];
    expect(JSON.stringify(evaluateSecondTabMatrix(input))).toBe(JSON.stringify(evaluateSecondTabMatrix(input)));
  });

  test('results are frozen so a caller cannot rewrite an outcome', () => {
    const out = evaluateLockAction(obs('a', 'WRITER', 'HELD_BY_OTHER', 'READ'));
    expect(Object.isFrozen(out)).toBe(true);
    expect(() => { out.authorized = true; }).toThrow(TypeError);
  });

  test('matrix rows are frozen', () => {
    const matrix = evaluateSecondTabMatrix([ctx('a', 'WRITER', 'HELD_BY_SELF', 'STATE_CHANGE')]);
    expect(Object.isFrozen(matrix)).toBe(true);
    expect(Object.isFrozen(matrix.contexts)).toBe(true);
    expect(Object.isFrozen(matrix.contexts[0])).toBe(true);
  });
});

// ---------------------------------------------------------------------------------------------
// Property sweep: no input can produce a silently active second context.
// ---------------------------------------------------------------------------------------------

describe('property sweep (seed 20261002)', () => {
  const arbCtx = (id) => fc.record({
    contextId: fc.constant(id),
    role: fc.constantFrom(...CONTEXT_ROLES),
    ownership: fc.constantFrom(...OWNERSHIP),
    intent: fc.constantFrom(...ACTIONS),
  });
  const arbMatrix = fc.tuple(arbCtx('c0'), arbCtx('c1'), arbCtx('c2')).map(([a, b, c]) => [a, b, c]);

  test('any three-context matrix yields at most one ACTIVE context', () => {
    fc.assert(fc.property(arbMatrix, (input) => {
      const matrix = evaluateSecondTabMatrix(input);
      expect(matrix.accepted).toBe(true);
      return matrix.activeContextIds.length <= 1;
    }), { seed: 20261002, numRuns: 200 });
  });

  test('no context other than the unique holder is ever authorized', () => {
    fc.assert(fc.property(arbMatrix, (input) => {
      const matrix = evaluateSecondTabMatrix(input);
      const holders = input.filter((c) => c.ownership === 'HELD_BY_SELF');
      for (const row of matrix.contexts) {
        const isUniqueHolder = holders.length === 1 && holders[0].contextId === row.contextId;
        if (row.authorized) expect(isUniqueHolder).toBe(true);
      }
      return true;
    }), { seed: 20261002, numRuns: 200 });
  });

  test('every rejection is exactly LOCKED_ELSEWHERE / LOCK_RETRY at the LOCK phase', () => {
    fc.assert(fc.property(arbMatrix, (input) => {
      const matrix = evaluateSecondTabMatrix(input);
      for (const row of matrix.contexts) {
        if (row.authorized) continue;
        // The only non-authorized row that is not a lock rejection is the acquisition attempt
        // itself (intent ACQUIRE); a READ or STATE_CHANGE row is never skipped, whatever
        // ownership it reported — including a HELD_BY_SELF claimant in a contradictory matrix.
        if (row.intent === 'ACQUIRE' && row.result === null) continue;
        expect(agreementOf(row)).toEqual(NEG_NO_LOCK);
      }
      return true;
    }), { seed: 20261002, numRuns: 200 });
  });

  test('every non-ACTIVE READ/STATE_CHANGE row carries NEG-NO-LOCK, over every 1..3-context matrix', () => {
    // Exhaustive, not sampled: every ownership x intent combination for one to three contexts
    // (12^1 + 12^2 + 12^3 = 1884 matrices), so no contradictory combination is skipped.
    const cells = [];
    for (const ownership of OWNERSHIP) for (const intent of ACTIONS) cells.push([ownership, intent]);
    let checkedRows = 0;
    let contradictoryGated = 0;
    const visit = (prefix, depth) => {
      if (prefix.length > 0) {
        const input = prefix.map(([ownership, intent], i) => ctx(`c${i}`, i % 2 ? 'WORKER' : 'WRITER', ownership, intent));
        const matrix = evaluateSecondTabMatrix(input);
        expect(matrix.accepted).toBe(true);
        const claimants = input.filter((c) => c.ownership === 'HELD_BY_SELF');
        const consistent = claimants.length === 1 && input.every((c) => c.ownership === 'HELD_BY_SELF'
          || c.ownership === 'HELD_BY_OTHER');
        expect(matrix.activeContextIds).toEqual(consistent ? [claimants[0].contextId] : []);
        expect(matrix.ambiguous).toBe(claimants.length > 1 || (claimants.length === 1 && !consistent));
        for (const row of matrix.contexts) {
          checkedRows += 1;
          expect(Object.hasOwn(row, 'authority')).toBe(true);
          if (row.outcome === 'ACTIVE') {
            expect(row.authorized).toBe(true);
            expect(row.authority).toBe('SELF');
            continue;
          }
          expect(row.outcome).toBe(SESSION_ACTIVE_ELSEWHERE);
          expect(row.authorized).toBe(false);
          if (row.intent === 'READ' || row.intent === 'STATE_CHANGE') {
            expect(agreementOf(row)).toEqual(NEG_NO_LOCK);
            if (row.ownership === 'HELD_BY_SELF') contradictoryGated += 1;
          } else if (row.ownership === 'FREE' && !matrix.ambiguous) {
            expect(agreementOf(row)).toEqual({ ...NEG_NO_LOCK, result: null, disposition: null, firstFailingPhase: 'NONE' });
          } else {
            expect(agreementOf(row)).toEqual(NEG_NO_LOCK);
          }
        }
      }
      if (depth === 0) return;
      for (const cell of cells) visit([...prefix, cell], depth - 1);
    };
    visit([], 3);
    expect(checkedRows).toBe(12 + 2 * 144 + 3 * 1728);
    expect(contradictoryGated).toBeGreaterThan(0);
  });

  test('the matrix depends only on the multiset of observations, never on their order', () => {
    fc.assert(fc.property(arbMatrix, fc.nat(5), (input, k) => {
      const perms = [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]];
      const permuted = perms[k].map((i) => input[i]);
      const a = evaluateSecondTabMatrix(input);
      const b = evaluateSecondTabMatrix(permuted);
      const byId = (m) => Object.fromEntries(m.contexts.map((r) => [r.contextId, JSON.stringify(r)]));
      expect(byId(a)).toEqual(byId(b));
      expect(a.activeContextIds).toEqual(b.activeContextIds);
      expect(a.ambiguous).toBe(b.ambiguous);
      return true;
    }), { seed: 20261002, numRuns: 200 });
  });

  test('any mutated observation is either accepted-and-closed or rejected with a C-API code', () => {
    const valid = obs('tabA', 'WRITER', 'HELD_BY_OTHER', 'STATE_CHANGE');
    fc.assert(fc.property(fc.object({ depth: 2 }), (patch) => {
      const candidate = { ...valid, ...patch };
      const out = evaluateLockAction(candidate);
      if (out.accepted) {
        if (out.authorized) {
          expect(out.authority).toBe('SELF');
        } else {
          expect(out.result).toBe('LOCKED_ELSEWHERE');
          expect(out.disposition).toBe('LOCK_RETRY');
        }
      } else {
        expect(LOCK_ERROR_CODES).toContain(out.error);
      }
      return true;
    }), { seed: 20261002, numRuns: 200 });
  });
});

// ---------------------------------------------------------------------------------------------
// The scenario mapping this card owns, cross-checked against the ratified O-SCEN set.
// ---------------------------------------------------------------------------------------------

const MAPPING = [
  { item: 'clause:CL-CAPI-b02195b48fbc', disposition: 'MAPPED', scenarios: ['OSC-7e009f23be2707b5'], tests: ['one holder and one second tab: exactly ACTIVE and SESSION_ACTIVE_ELSEWHERE', 'a second tab that only reads is still SESSION_ACTIVE_ELSEWHERE, never ACTIVE'] },
  { item: 'clause:CL-CREST-bb9bf966faca', disposition: 'MAPPED', scenarios: ['OSC-968ce5454a763f57'], tests: ['FREE permits only the acquisition attempt itself', 'READ requires the lock (C-REST /phaseRules/0, /prose/19)', 'the ratified C-REST LOCK-phase rule is carried verbatim'] },
  { item: 'clause:PROSE-CREST-19-7b3a0709a784', disposition: 'MAPPED', scenarios: ['OSC-847305bb3c22662a'], tests: ['FREE permits only the acquisition attempt itself', 'a free lock gates READ and STATE_CHANGE in the matrix with the NEG-NO-LOCK agreement'] },
  { item: 'clause:CL-CREC-75e30e3c094e', disposition: 'MAPPED', scenarios: ['OSC-54b26121e663f399'], tests: ['HELD_BY_OTHER yields LOCKED_ELSEWHERE with disposition LOCK_RETRY'] },
  { item: 'clause:CL-CREC-6a5601422fde', disposition: 'MAPPED', scenarios: ['OSC-8683e98159d91cfa'], tests: ['the ratified C-REC precedence and disposition clauses the matrix relies on are carried', 'HELD_BY_OTHER yields LOCKED_ELSEWHERE with disposition LOCK_RETRY'] },
  { item: 'clause:CL-CREC-f0b168585993', disposition: 'MAPPED', scenarios: ['OSC-0f9e9c754c5d5946'], tests: ['STATE_CHANGE requires the lock (C-REC requiresOneWriterLockForStateChange)', 'the ratified C-REC precedence and disposition clauses the matrix relies on are carried'] },
  { item: 'clause:CL-CREC-b778a6264679', disposition: 'MAPPED', scenarios: ['OSC-da53590e29e58465'], tests: ['two claimants: every non-active READ/STATE_CHANGE row carries exactly NEG-NO-LOCK', 'a claimant beside a context observing the lock FREE is contradictory: no context is active', 'a claimant beside a context that cannot observe the lock (UNAVAILABLE) is not made active'] },
  { item: 'clause:CL-CREC-3002d7e0cddb', disposition: 'MAPPED', scenarios: ['OSC-c0cffa17b8b81768'], tests: ['outcomes are independent of the input order', 'the matrix depends only on the multiset of observations, never on their order'] },
  { item: 'clause:CL-CREC-07ea4cb3e02d', disposition: 'MAPPED', scenarios: ['OSC-398767b7cf0d54b3'], tests: ['UNAVAILABLE (C-REC lockUnavailable) yields LOCKED_ELSEWHERE at the LOCK phase'] },
  { item: 'clause:CL-CREST-f29f714b4f0e', disposition: 'MAPPED', scenarios: ['OSC-28721c8bb3dd0d1c'], tests: ['UNAVAILABLE (C-REC lockUnavailable) yields LOCKED_ELSEWHERE at the LOCK phase'] },
  { item: 'clause:CL-CREC-207db887bd1c', disposition: 'MAPPED', scenarios: ['OSC-5856153389554186'], tests: ['the rejection envelope reproduces the C-REC /fixtures/56 NEG-NO-LOCK agreement', 'NEG-NO-LOCK and RESET-NO-LOCK carry the same lock agreement the gate emits'] },
  { item: 'clause:CL-CREC-d365f4775117', disposition: 'MAPPED', scenarios: ['OSC-ae3bda700eed1be3'], tests: ['NEG-NO-LOCK and RESET-NO-LOCK carry the same lock agreement the gate emits'] },
  { item: 'clause:CL-CREC-7d3c371b9cb1', disposition: 'MAPPED', scenarios: ['OSC-0c458c1dd534931c'], tests: ['every ratified C-REC marker transition requires the lock', 'every carried clause content is the canonical content its clauseSha256 covers'] },
  { item: 'outcome:ACTIVE', disposition: 'MAPPED', scenarios: ['OSC-7e009f23be2707b5'], tests: ['a single holder is ACTIVE and is the only active context'] },
  { item: 'outcome:SESSION_ACTIVE_ELSEWHERE', disposition: 'MAPPED', scenarios: ['OSC-7e009f23be2707b5'], tests: ['a second tab that only reads is still SESSION_ACTIVE_ELSEWHERE, never ACTIVE'] },
  { item: 'rejection:LOCKED_ELSEWHERE', disposition: 'MAPPED', scenarios: ['OSC-5856153389554186'], tests: ['HELD_BY_OTHER yields LOCKED_ELSEWHERE with disposition LOCK_RETRY', 'every non-ACTIVE READ/STATE_CHANGE row carries NEG-NO-LOCK, over every 1..3-context matrix'] },
  { item: 'rejection:LOCK_RETRY', disposition: 'MAPPED', scenarios: ['OSC-54b26121e663f399', 'OSC-8683e98159d91cfa'], tests: ['HELD_BY_OTHER yields LOCKED_ELSEWHERE with disposition LOCK_RETRY'] },
  { item: 'fault:lockUnavailable', disposition: 'MAPPED', scenarios: ['OSC-398767b7cf0d54b3', 'OSC-28721c8bb3dd0d1c'], tests: ['UNAVAILABLE (C-REC lockUnavailable) yields LOCKED_ELSEWHERE at the LOCK phase'] },
  { item: 'role:WORKER', disposition: 'MAPPED', scenarios: ['OSC-7e009f23be2707b5'], tests: ['one holder and one second tab: exactly ACTIVE and SESSION_ACTIVE_ELSEWHERE'] },
  { item: 'role:WRITER', disposition: 'MAPPED', scenarios: ['OSC-7e009f23be2707b5'], tests: ['one holder and one second tab: exactly ACTIVE and SESSION_ACTIVE_ELSEWHERE'] },
  { item: 'owner:SCOPE-M2-D13-read-disabled', disposition: 'UNMAPPED', reason: 'O-SCEN is blind to the owner proposal SCOPE-M2 D13: it names a UI read-disabled presentation, and no ratified O-SCEN row asserts a UI or presentation outcome. The policy exposes the outcome name; the presentation is out of scope for this module.' },
  { item: 'owner:SCOPE-M2-D7-fresh-worker-starts-locked', disposition: 'UNMAPPED', reason: 'SCOPE-M2 D7 binds "fresh worker starts locked and must reauthenticate before restore" to the worker lifecycle (I-REST/I-JOIN), not to a lock-policy observation; no O-SCEN row names it and this card models no worker startup.' },
  { item: 'owner:C-REC-crash-release', disposition: 'UNMAPPED', reason: 'Whether lock release takes part in crash recovery (the I-TXN ratification 5938316207 MEDIUM) is owned by I-REST; no O-SCEN lock row asserts a release-after-crash outcome and this module exposes no release API.' },
  { item: 'owner:browser-web-lock-reality', disposition: 'UNMAPPED', reason: 'O-SCEN rows are abstract and claim no browser behaviour; whether navigator.locks is exclusive, survives a crash or is reachable across tabs is unobservable in Node and is deliberately not claimed.' },
];

/** Every test() and describe() title in this file, read from its own source bytes. */
const OWN_TITLES = (() => {
  const source = readFileSync(new URL(import.meta.url), 'utf8');
  const titles = [];
  for (const m of source.matchAll(/\b(?:test|describe)\(\s*(['`])((?:(?!\1).)*)\1/g)) titles.push(m[2]);
  return titles;
})();

describe('scenario mapping against O-SCEN', () => {
  test('every owned item appears exactly once and every disposition is closed', () => {
    const ids = MAPPING.map((m) => m.item);
    expect(new Set(ids).size).toBe(ids.length);
    for (const entry of MAPPING) {
      expect(['MAPPED', 'UNMAPPED']).toContain(entry.disposition);
      if (entry.disposition === 'MAPPED') {
        expect(entry.scenarios.length).toBeGreaterThan(0);
        for (const id of entry.scenarios) expect(id).toMatch(/^OSC-[0-9a-f]{16}$/);
        expect(entry.tests.length).toBeGreaterThan(0);
      } else {
        expect(typeof entry.reason).toBe('string');
        expect(entry.reason.length).toBeGreaterThan(0);
      }
    }
  });

  test('every test name a MAPPED item cites is the exact title of a test in this file', () => {
    expect(OWN_TITLES.length).toBeGreaterThan(50);
    const titles = new Set(OWN_TITLES);
    const dangling = MAPPING.flatMap((m) => m.tests || []).filter((name) => !titles.has(name));
    expect(dangling).toEqual([]);
  });

  test('the owned clause set is exactly the transcribed LOCK_CLAUSES anchors', () => {
    const owned = MAPPING.filter((m) => m.item.startsWith('clause:')).map((m) => m.item.slice(7));
    expect(owned.sort()).toEqual(Object.values(LOCK_CLAUSES).map((c) => c.key).sort());
  });

  test('every MAPPED scenario id is a ratified lock scenario this card transcribed', () => {
    const known = new Set(LOCK_SCENARIOS.map((s) => s.id));
    for (const entry of MAPPING) {
      if (entry.disposition !== 'MAPPED') continue;
      for (const id of entry.scenarios) expect(known.has(id)).toBe(true);
    }
  });

  test('each clause item cites exactly the scenario row whose clause is that key', () => {
    for (const entry of MAPPING.filter((m) => m.item.startsWith('clause:'))) {
      const key = entry.item.slice(7);
      expect([key, entry.scenarios]).toEqual([key, LOCK_SCENARIOS.filter((s) => s.clause === key).map((s) => s.id)]);
    }
  });

  test('the transcribed O-SCEN lock scenario set is exactly the thirteen rows this card owns', () => {
    expect(LOCK_SCENARIOS.map((s) => [s.id, s.clause]).sort()).toEqual([
      ['OSC-0c458c1dd534931c', 'CL-CREC-7d3c371b9cb1'],
      ['OSC-0f9e9c754c5d5946', 'CL-CREC-f0b168585993'],
      ['OSC-28721c8bb3dd0d1c', 'CL-CREST-f29f714b4f0e'],
      ['OSC-398767b7cf0d54b3', 'CL-CREC-07ea4cb3e02d'],
      ['OSC-54b26121e663f399', 'CL-CREC-75e30e3c094e'],
      ['OSC-5856153389554186', 'CL-CREC-207db887bd1c'],
      ['OSC-7e009f23be2707b5', 'CL-CAPI-b02195b48fbc'],
      ['OSC-847305bb3c22662a', 'PROSE-CREST-19-7b3a0709a784'],
      ['OSC-8683e98159d91cfa', 'CL-CREC-6a5601422fde'],
      ['OSC-968ce5454a763f57', 'CL-CREST-bb9bf966faca'],
      ['OSC-ae3bda700eed1be3', 'CL-CREC-d365f4775117'],
      ['OSC-c0cffa17b8b81768', 'CL-CREC-3002d7e0cddb'],
      ['OSC-da53590e29e58465', 'CL-CREC-b778a6264679'],
    ].sort());
  });

  test('every lock scenario row is cited by at least one mapping item, and the unmapped list is explicit', () => {
    const cited = new Set(MAPPING.flatMap((m) => m.scenarios || []));
    for (const scenario of LOCK_SCENARIOS) expect(cited.has(scenario.id)).toBe(true);
    expect(MAPPING.filter((m) => m.disposition === 'UNMAPPED').length).toBe(4);
    expect(MAPPING.length).toBe(24);
  });
});
