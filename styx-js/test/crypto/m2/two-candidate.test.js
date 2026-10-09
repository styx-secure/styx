// two-candidate.test.js — I-FORK conformance tests for the bounded two-candidate case of the M2 session
// adapter (card I-FORK of #317 G-SCOPE).
//
// The tests drive the real `invokeAdapter` / `invokeAdapterTransition` over the injected request, snapshot
// and owning-layer observation. Nothing is mocked: the decision is taken by the merged I-SM decision core
// (C-API `/rules/candidateSelector`, decision rows CAPI-S016 to CAPI-S019), and the hold a reconciliation
// resolves is produced by that same core. Scope is only the bounded two-candidate case of Exact-pin
// Phase B; every other candidate shape fails closed with UNSUPPORTED_COMMIT_SHAPE before any mutation.

import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import {
  M2_ADAPTER,
  M2AdapterError,
  invokeAdapter,
  invokeAdapterTransition,
  validateAdapterRequest,
} from '../../../src/crypto/mls/m2/adapter.js';
import { createAdapterSnapshot } from '../../../src/crypto/mls/m2/state-machine.js';
import { fromWireBytes, toWireBytes, validateWorkerResult } from '../../../src/crypto/mls/m2/worker-protocol.js';

// The ratified O-SCEN rows citing each C-API clause this card implements (registry sha256 0e05f023…abba0,
// O-SCEN markdown sha256 75d84350…16532; derived by the card's gen_mapping.py with the I-UPD rule).
const OSCEN_SCENARIOS = Object.freeze({
  '/rules/candidateSelector': ['OSC-0885ca4fd15bf91b'],
  'CAPI-S016': ['OSC-43bc2f410abce99b'],
  'CAPI-S017': ['OSC-850b3351c75edb32'],
  'CAPI-S018': ['OSC-3dbc018c5e9fa76d'],
  'CAPI-S019': ['OSC-0df5460505e0acc8'],
  'CAPI-G007': ['OSC-04cc18f5934cb614'],
  'CAPI-G015': ['OSC-03d9a9914b0aa6c4'],
  'CAPI-G023': ['OSC-f89aee5d6c2a5235'],
  '/rules/peerMaterial': ['OSC-991188c596bfbc0f'],
});

const PROFILE = M2_ADAPTER.PROFILE;
const API = M2_ADAPTER.API;
const RESULT_COMMON_MEMBERS = ['api', 'requestId', 'operation', 'kind', 'stateBefore', 'stateAfter'];

// C-BIND §4: the authoritative slot context the SS resolves, and the request `bindingRef` naming it.
const SLOT = new Uint8Array(32).fill(0xa1);
const OTHER_SLOT = new Uint8Array(32).fill(0xb2);
const COMMIT = new Uint8Array([0xc0, 0xff, 0xee]);

let counter = 0;
const request = (operation, input, overrides = {}) => ({
  api: API,
  operation,
  requestId: `req-ifork-${++counter}`,
  profile: { ...PROFILE },
  bindingRef: SLOT.slice(),
  input,
  ...overrides,
});
const applyRequest = (overrides = {}) => request('APPLY_PEER_UPDATE', { protectedCommitBytes: COMMIT.slice() }, overrides);

const empty = () => createAdapterSnapshot('EMPTY');
const active = () => createAdapterSnapshot('ACTIVE');

const id = (first, fill = 0x00) => {
  const value = new Uint8Array(32).fill(fill);
  value[0] = first;
  return value;
};
const LOW = id(0x01);
const HIGH = id(0xfe);
const candidate = (committerId, ref) => ({ committerId, ref });
const eligible = (current, incoming) => ({ kind: 'ELIGIBLE_TWO_CANDIDATE', current, incoming });

const observation = ({
  authentication = 'AUTHENTICATED',
  candidate: classification = { kind: 'CURRENT_PARENT' },
  commitOutcome = 'COMMITTED',
  operationIdentity = 'op-fork-1',
  slotContext = SLOT.slice(),
} = {}) => ({ authentication, candidate: classification, commitOutcome, operationIdentity, slotContext });

// A rejecting classification (CAPI-S018/S019) carries no RS request.
const rejectingObservation = (classification) => observation({ candidate: classification, commitOutcome: null, operationIdentity: null });
const noRequestObservation = () => ({
  authentication: null, candidate: null, commitOutcome: null, operationIdentity: null, slotContext: SLOT.slice(),
});

const code = (result) => (result.error === undefined ? undefined : result.error.code);
const assertEnvelope = (result, kind, extra) => {
  expect(Object.isFrozen(result)).toBe(true);
  const keys = Object.keys(result);
  for (const member of RESULT_COMMON_MEMBERS) expect(keys).toContain(member);
  expect(result.kind).toBe(kind);
  expect(keys.filter((key) => !RESULT_COMMON_MEMBERS.includes(key)).sort()).toEqual([...extra].sort());
};
const transition = (snapshot, obs, req = applyRequest()) => invokeAdapterTransition({ request: req, snapshot, observation: obs });
const apply = (snapshot, obs, req) => transition(snapshot, obs, req).result;

describe('I-FORK module surface', () => {
  test('APPLY_PEER_UPDATE is integrated; the operation set is the full C-API operation set', () => {
    expect([...M2_ADAPTER.INTEGRATED_OPERATIONS]).toEqual([...M2_ADAPTER.OPERATIONS]);
    expect(M2_ADAPTER.INTEGRATED_OPERATIONS).toContain('APPLY_PEER_UPDATE');
    expect(Object.isFrozen(M2_ADAPTER.INTEGRATED_OPERATIONS)).toBe(true);
    expect([...M2_ADAPTER.OBSERVATION_KEYS.APPLY_PEER_UPDATE])
      .toEqual(['authentication', 'candidate', 'commitOutcome', 'operationIdentity', 'slotContext']);
    expect(M2_ADAPTER.BOUNDS.MAX_CANDIDATE_REF_CHARS).toBe(256);
    expect([...M2_ADAPTER.OUTPUT_BY_SUCCESS_CODE.CANDIDATE_SELECTED]).toEqual(['selectedCandidateRef']);
    expect([...M2_ADAPTER.OUTPUT_BY_SUCCESS_CODE.PEER_UPDATE_APPLIED]).toEqual([]);
  });

  test('the request gate admits a well-formed APPLY_PEER_UPDATE and still closes its input', () => {
    expect(validateAdapterRequest(applyRequest())).toEqual({ ok: true, code: null });
    expect(validateAdapterRequest(request('APPLY_PEER_UPDATE', {})).code).toBe('INVALID_REQUEST');
    expect(validateAdapterRequest(request('APPLY_PEER_UPDATE', { protectedCommitBytes: COMMIT, extra: 1 })).code).toBe('UNKNOWN_FIELD');
    expect(validateAdapterRequest(request('APPLY_PEER_UPDATE', { protectedCommitBytes: 'bytes' })).code).toBe('INVALID_REQUEST');
    expect(validateAdapterRequest(request('APPLY_PEER_UPDATE', { protectedCommitBytes: new Uint8Array(1048577) })).code)
      .toBe('VALUE_OUT_OF_RANGE');
  });

  test('every O-SCEN row id this card maps is a well-formed ratified id', () => {
    for (const ids of Object.values(OSCEN_SCENARIOS)) {
      for (const scenario of ids) expect(scenario).toMatch(/^OSC-[0-9a-f]{16}$/);
    }
  });
});

describe('CAPI-S016 current-parent peer update (OSC-43bc2f410abce99b)', () => {
  test('COMMITTED applies the update: SUCCESS PEER_UPDATE_APPLIED, no output, ACTIVE', () => {
    const { result, snapshot } = transition(active(), observation());
    assertEnvelope(result, 'SUCCESS', ['successCode', 'commitOutcome']);
    expect(result.successCode).toBe('PEER_UPDATE_APPLIED');
    expect(result.commitOutcome).toBe('COMMITTED');
    expect(result.stateAfter).toBe('ACTIVE');
    expect(snapshot).toEqual({ state: 'ACTIVE', held: null });
  });

  test('NOT_COMMITTED applies nothing and keeps ACTIVE', () => {
    const { result, snapshot } = transition(active(), observation({ commitOutcome: 'NOT_COMMITTED' }));
    assertEnvelope(result, 'NOT_COMMITTED', ['commitOutcome']);
    expect(snapshot).toEqual({ state: 'ACTIVE', held: null });
  });

  test('INDETERMINATE holds the mutation: RECONCILIATION_REQUIRED snapshot with the S016 hold', () => {
    const { result, snapshot } = transition(active(), observation({ commitOutcome: 'INDETERMINATE', operationIdentity: 'op-s016' }));
    assertEnvelope(result, 'INDETERMINATE', ['commitOutcome', 'reconciliationRef', 'originalStateBefore']);
    expect(result.reconciliationRef).toBe('I-SM-HOLD:op-s016');
    expect(snapshot.state).toBe('RECONCILIATION_REQUIRED');
    expect(snapshot.held.scenario).toBe('CAPI-S016');
    expect(snapshot.held.outputKind).toBe('NONE');
    expect(snapshot.held.selectedCandidateRef).toBeNull();
  });

  test('an absent, unknown or wrongly typed RS outcome after an issued request is INDETERMINATE, never REJECTED', () => {
    for (const commitOutcome of [null, 'MAYBE', 7]) {
      const result = apply(active(), observation({ commitOutcome }));
      expect([commitOutcome, result.kind]).toEqual([commitOutcome, 'INDETERMINATE']);
    }
  });

  test('a supported shape without an operation identity is malformed (no commit request can exist without it)', () => {
    expect(code(apply(active(), observation({ operationIdentity: null })))).toBe('INVALID_REQUEST');
    expect(code(apply(active(), observation({ operationIdentity: '' })))).toBe('INVALID_REQUEST');
  });
});

describe('CAPI-S017 bounded two-candidate selection (OSC-850b3351c75edb32, OSC-0885ca4fd15bf91b)', () => {
  test('the lower raw committer identity wins and only its reference is released after COMMITTED', () => {
    const { result, snapshot } = transition(active(), observation({
      candidate: eligible(candidate(HIGH, 'cand:local'), candidate(LOW, 'cand:peer')),
    }));
    assertEnvelope(result, 'SUCCESS', ['successCode', 'commitOutcome', 'output']);
    expect(result.successCode).toBe('CANDIDATE_SELECTED');
    expect(result.commitOutcome).toBe('COMMITTED');
    expect(result.output).toEqual({ selectedCandidateRef: 'cand:peer' });
    expect(Object.isFrozen(result.output)).toBe(true);
    expect(snapshot).toEqual({ state: 'ACTIVE', held: null });
  });

  test('the selection is order invariant (current/incoming swapped selects the same reference)', () => {
    const one = apply(active(), observation({ candidate: eligible(candidate(LOW, 'a'), candidate(HIGH, 'b')) }));
    const two = apply(active(), observation({ candidate: eligible(candidate(HIGH, 'b'), candidate(LOW, 'a')) }));
    expect(one.output).toEqual({ selectedCandidateRef: 'a' });
    expect(two.output).toEqual({ selectedCandidateRef: 'a' });
  });

  test('comparison is unsigned and lexicographic over all 32 bytes, not numeric on the first byte only', () => {
    const left = id(0x10, 0x00);
    const right = id(0x10, 0x00);
    right[31] = 0x01;
    expect(apply(active(), observation({ candidate: eligible(candidate(right, 'r'), candidate(left, 'l')) })).output)
      .toEqual({ selectedCandidateRef: 'l' });
    // 0x80 is greater than 0x7f unsigned (it would be negative as a signed byte).
    expect(apply(active(), observation({ candidate: eligible(candidate(id(0x80), 'neg'), candidate(id(0x7f), 'pos')) })).output)
      .toEqual({ selectedCandidateRef: 'pos' });
  });

  test('NOT_COMMITTED releases nothing and keeps ACTIVE', () => {
    const { result, snapshot } = transition(active(), observation({
      candidate: eligible(candidate(LOW, 'a'), candidate(HIGH, 'b')), commitOutcome: 'NOT_COMMITTED',
    }));
    assertEnvelope(result, 'NOT_COMMITTED', ['commitOutcome']);
    expect(snapshot).toEqual({ state: 'ACTIVE', held: null });
  });

  test('INDETERMINATE holds the selected reference, and the COMMITTED reconciliation releases exactly it', () => {
    const { result, snapshot } = transition(active(), observation({
      candidate: eligible(candidate(HIGH, 'cand:hi'), candidate(LOW, 'cand:lo')),
      commitOutcome: 'INDETERMINATE', operationIdentity: 'op-s017',
    }));
    expect(result.kind).toBe('INDETERMINATE');
    expect(result).not.toHaveProperty('output');
    expect(snapshot.state).toBe('RECONCILIATION_REQUIRED');
    expect(snapshot.held.scenario).toBe('CAPI-S017');
    expect(snapshot.held.outputKind).toBe('SELECTED_CANDIDATE_REF');
    expect(snapshot.held.selectedCandidateRef).toBe('cand:lo');

    const reconcile = (heldOutput, commitOutcome = 'COMMITTED') => invokeAdapterTransition({
      request: request('RECONCILE_INDETERMINATE', { reconciliationRef: 'I-SM-HOLD:op-s017' }),
      snapshot,
      observation: {
        slotContext: SLOT.slice(), commitOutcome, responseEmission: commitOutcome === 'COMMITTED' ? 'SUCCEEDED' : null, heldOutput,
      },
    });
    // An escrow that is not the held winner never releases anything; RS has proved the hold COMMITTED, so
    // it is retained unchanged with that proof, never rejected (C-API `/rules/internalFailureBoundary`).
    const forged = reconcile({ selectedCandidateRef: 'cand:hi' });
    expect(forged.result.kind).toBe('INDETERMINATE');
    expect(forged.result).not.toHaveProperty('output');
    expect(forged.snapshot.state).toBe('RECONCILIATION_REQUIRED');
    expect(forged.snapshot.held.selectedCandidateRef).toBe('cand:lo');
    expect(forged.snapshot.held.terminalEvidenceStatus).toBe('COMMITTED');
    const done = reconcile({ selectedCandidateRef: 'cand:lo' });
    expect(done.result.successCode).toBe('RECONCILED_COMMITTED');
    expect(done.result.output).toEqual({ originalSuccessCode: 'CANDIDATE_SELECTED', originalOutput: { selectedCandidateRef: 'cand:lo' } });
    expect(done.snapshot).toEqual({ state: 'ACTIVE', held: null });
    const discarded = reconcile({ selectedCandidateRef: 'cand:lo' }, 'NOT_COMMITTED');
    expect(discarded.result.kind).toBe('NOT_COMMITTED');
    expect(discarded.snapshot).toEqual({ state: 'ACTIVE', held: null });
  });

  test('the released reference is the core-selected copy: mutating the caller identities afterwards changes nothing', () => {
    const lo = LOW.slice();
    const hi = HIGH.slice();
    const obs = observation({ candidate: eligible(candidate(hi, 'h'), candidate(lo, 'l')) });
    const result = apply(active(), obs);
    lo.fill(0xff);
    expect(result.output).toEqual({ selectedCandidateRef: 'l' });
  });

  test('an over-bound candidate reference is refused up front (P06) and nothing is held, whatever the outcome', () => {
    const long = 'r'.repeat(M2_ADAPTER.BOUNDS.MAX_CANDIDATE_REF_CHARS + 1);
    for (const commitOutcome of ['COMMITTED', 'INDETERMINATE', 'NOT_COMMITTED']) {
      const { result, snapshot } = transition(active(), observation({
        candidate: eligible(candidate(LOW, long), candidate(HIGH, 'b')), commitOutcome,
      }));
      expect([commitOutcome, code(result)]).toEqual([commitOutcome, 'VALUE_OUT_OF_RANGE']);
      expect(snapshot).toBeNull();
    }
    const atBound = 'r'.repeat(M2_ADAPTER.BOUNDS.MAX_CANDIDATE_REF_CHARS);
    expect(apply(active(), observation({ candidate: eligible(candidate(LOW, atBound), candidate(HIGH, 'b')) })).output)
      .toEqual({ selectedCandidateRef: atBound });
  });

  test('an over-bound operation identity is refused up front (P06) and nothing is held (I-UPD p06)', () => {
    const operationIdentity = 'i'.repeat(M2_ADAPTER.BOUNDS.MAX_OPERATION_IDENTITY_CHARS + 1);
    for (const classification of [{ kind: 'CURRENT_PARENT' }, eligible(candidate(LOW, 'a'), candidate(HIGH, 'b'))]) {
      const { result, snapshot } = transition(active(), observation({ candidate: classification, commitOutcome: 'INDETERMINATE', operationIdentity }));
      expect(code(result)).toBe('VALUE_OUT_OF_RANGE');
      expect(snapshot).toBeNull();
    }
  });
});

describe('Other shapes fail closed before mutation (CAPI-S018 OSC-3dbc018c5e9fa76d, CAPI-S019 OSC-0df5460505e0acc8)', () => {
  const cases = [
    ['proposal-bearing or unselected form', { kind: 'UNSUPPORTED_UPDATE_FORM' }, 'UNSUPPORTED_UPDATE_FORM'],
    ['unrelated parent / peer-predecessor / count / witness / priority / digest', { kind: 'UNSUPPORTED_TOPOLOGY', reason: 'PEER_PREDECESSOR' }, 'UNSUPPORTED_COMMIT_SHAPE'],
    ['equal committer identities', eligible(candidate(LOW, 'a'), candidate(LOW.slice(), 'b')), 'UNSUPPORTED_COMMIT_SHAPE'],
    ['re-presented candidate (same reference)', eligible(candidate(LOW, 'same'), candidate(HIGH, 'same')), 'UNSUPPORTED_COMMIT_SHAPE'],
    ['committer identity outside the 32-byte profile', eligible(candidate(new Uint8Array(31), 'a'), candidate(HIGH, 'b')), 'UNSUPPORTED_COMMIT_SHAPE'],
    ['committer identity of 33 bytes', eligible(candidate(LOW, 'a'), candidate(new Uint8Array(33).fill(9), 'b')), 'UNSUPPORTED_COMMIT_SHAPE'],
  ];
  test.each(cases)('%s -> %s, state unchanged, no snapshot', (_label, classification, expected) => {
    const { result, snapshot } = transition(active(), rejectingObservation(classification));
    assertEnvelope(result, 'REJECTED', ['error']);
    expect(code(result)).toBe(expected);
    expect(result.stateAfter).toBe('ACTIVE');
    expect(snapshot).toBeNull();
  });

  test.each(cases)('%s carrying an RS request is malformed (a refused shape never reaches RS)', (_label, classification) => {
    expect(code(apply(active(), observation({ candidate: classification })))).toBe('INVALID_REQUEST');
    expect(code(apply(active(), observation({ candidate: classification, commitOutcome: null })))).toBe('INVALID_REQUEST');
  });
});

describe('State gates CAPI-G007 / CAPI-G015 / CAPI-G023', () => {
  test('EMPTY refuses with NO_ACTIVE_SESSION (honest no-request form and full form)', () => {
    expect(code(apply(empty(), noRequestObservation()))).toBe('NO_ACTIVE_SESSION');
    expect(code(apply(empty(), observation()))).toBe('NO_ACTIVE_SESSION');
  });

  test('RECONCILIATION_REQUIRED refuses with RECONCILIATION_REQUIRED and keeps the hold', () => {
    const held = transition(active(), observation({ commitOutcome: 'INDETERMINATE', operationIdentity: 'op-g023' })).snapshot;
    const { result, snapshot } = transition(held, noRequestObservation());
    expect(code(result)).toBe('RECONCILIATION_REQUIRED');
    expect(result.stateAfter).toBe('RECONCILIATION_REQUIRED');
    expect(snapshot).toBeNull();
    expect(code(apply(held, observation()))).toBe('RECONCILIATION_REQUIRED');
  });

  test('ACTIVE allows; the honest no-request form is impossible there and fails closed', () => {
    expect(code(apply(active(), noRequestObservation()))).toBe('INVALID_REQUEST');
  });
});

describe('Authentication (P08), binding (P03) and precedence', () => {
  test.each(['AUTHENTICATION_FAILED', 'AUTHENTICATED_STATE_INCONSISTENT'])('%s rejects at P08 before any candidate or RS request', (verdict) => {
    const obs = { ...noRequestObservation(), authentication: verdict };
    const { result, snapshot } = transition(active(), obs);
    expect(code(result)).toBe(verdict);
    expect(snapshot).toBeNull();
    expect(code(apply(active(), { ...obs, candidate: { kind: 'CURRENT_PARENT' } }))).toBe('INVALID_REQUEST');
    expect(code(apply(active(), { ...obs, commitOutcome: 'COMMITTED', operationIdentity: 'x' }))).toBe('INVALID_REQUEST');
    // The P05 gate preempts the P08 verdict.
    expect(code(apply(empty(), obs))).toBe('NO_ACTIVE_SESSION');
  });

  test('P08 preempts the P09 shape refusal; P03 binding preempts everything after it', () => {
    expect(code(apply(active(), observation({ slotContext: OTHER_SLOT.slice() })))).toBe('BINDING_MISMATCH');
    expect(code(apply(empty(), observation({ slotContext: OTHER_SLOT.slice() })))).toBe('BINDING_MISMATCH');
    expect(code(apply(active(), observation(), applyRequest({ bindingRef: OTHER_SLOT.slice() })))).toBe('BINDING_MISMATCH');
    expect(code(apply(active(), observation({ slotContext: new Uint8Array(32) })))).toBe('INVALID_REQUEST');
  });

  test('the request-level P01-P04 errors preempt the observation', () => {
    expect(code(apply(active(), observation(), applyRequest({ api: 'styx-m2-session-adapter/v2' })))).toBe('UNSUPPORTED_API_VERSION');
    expect(code(apply(active(), observation(), applyRequest({ profile: { ...PROFILE, topology: 'group' } })))).toBe('UNSUPPORTED_PROFILE');
    for (const commitOutcome of ['COMMITTED', 'INDETERMINATE']) {
      const { result, snapshot } = transition(active(), observation({ commitOutcome }),
        request('APPLY_PEER_UPDATE', { protectedCommitBytes: new Uint8Array(1048577) }));
      expect([commitOutcome, code(result)]).toEqual([commitOutcome, 'VALUE_OUT_OF_RANGE']);
      expect(snapshot).toBeNull();
    }
  });
});

describe('Closed observation (P01): no accessor is invoked, inner records are not collapsed', () => {
  test('unknown, missing and mistyped members', () => {
    expect(code(apply(active(), { ...observation(), extra: 1 }))).toBe('UNKNOWN_FIELD');
    const missing = observation();
    delete missing.candidate;
    expect(code(apply(active(), missing))).toBe('INVALID_REQUEST');
    expect(code(apply(active(), observation({ authentication: 'MAYBE' })))).toBe('UNKNOWN_VALUE');
    expect(code(apply(active(), observation({ authentication: 1 })))).toBe('INVALID_REQUEST');
    expect(code(apply(active(), observation({ candidate: { kind: 'THREE_CANDIDATES' } })))).toBe('UNKNOWN_VALUE');
    expect(code(apply(active(), observation({ candidate: { kind: 'CURRENT_PARENT', reason: 'x' } })))).toBe('UNKNOWN_FIELD');
    expect(code(apply(active(), observation({ candidate: { kind: 'CURRENT_PARENT', witness: 1 } })))).toBe('UNKNOWN_FIELD');
    expect(code(apply(active(), rejectingObservation({ kind: 'UNSUPPORTED_TOPOLOGY' })))).toBe('INVALID_REQUEST');
    expect(code(apply(active(), rejectingObservation({ kind: 'UNSUPPORTED_TOPOLOGY', reason: '' })))).toBe('INVALID_REQUEST');
    expect(code(apply(active(), observation({ candidate: { kind: 'ELIGIBLE_TWO_CANDIDATE', current: candidate(LOW, 'a') } }))))
      .toBe('INVALID_REQUEST');
  });

  test('a malformed inner candidate is a P01 defect, and an unknown inner member outranks it', () => {
    const bad = [
      [eligible({ committerId: LOW, ref: 'a', extra: 1 }, candidate(HIGH, 'b')), 'UNKNOWN_FIELD'],
      [eligible({ committerId: LOW }, candidate(HIGH, 'b')), 'INVALID_REQUEST'],
      [eligible(candidate([...LOW], 'a'), candidate(HIGH, 'b')), 'INVALID_REQUEST'],
      [eligible(candidate(LOW, ''), candidate(HIGH, 'b')), 'INVALID_REQUEST'],
      [eligible(candidate(LOW, 7), candidate(HIGH, 'b')), 'INVALID_REQUEST'],
      [eligible(null, candidate(HIGH, 'b')), 'INVALID_REQUEST'],
    ];
    for (const [classification, expected] of bad) {
      expect(code(apply(active(), observation({ candidate: classification })))).toBe(expected);
    }
    // An unknown member of the candidate record competes with a malformed outer member at P01.
    expect(code(apply(active(), { ...observation({ candidate: { kind: 'CURRENT_PARENT', x: 1 } }), authentication: 3 }))).toBe('UNKNOWN_FIELD');
  });

  test('accessors are never invoked on the observation, the classification or a candidate', () => {
    let reads = 0;
    const getter = { enumerable: true, get() { reads += 1; return 'AUTHENTICATED'; } };
    const obs = observation();
    Object.defineProperty(obs, 'authentication', getter);
    expect(code(apply(active(), obs))).toBe('INVALID_REQUEST');

    const classification = { kind: 'ELIGIBLE_TWO_CANDIDATE', incoming: candidate(HIGH, 'b') };
    Object.defineProperty(classification, 'current', { enumerable: true, get() { reads += 1; return candidate(LOW, 'a'); } });
    expect(code(apply(active(), observation({ candidate: classification })))).toBe('INVALID_REQUEST');

    const inner = { committerId: LOW };
    Object.defineProperty(inner, 'ref', { enumerable: true, get() { reads += 1; return 'a'; } });
    expect(code(apply(active(), observation({ candidate: eligible(inner, candidate(HIGH, 'b')) })))).toBe('INVALID_REQUEST');
    expect(reads).toBe(0);
  });

  test('a proxy cannot answer one candidate to validation and another to the decision', () => {
    let calls = 0;
    const target = candidate(HIGH, 'first');
    const proxy = new Proxy(target, {
      getOwnPropertyDescriptor(object, key) {
        calls += 1;
        const descriptor = Reflect.getOwnPropertyDescriptor(object, key);
        if (key === 'ref' && calls > 4) return { ...descriptor, value: 'swapped' };
        return descriptor;
      },
    });
    const result = apply(active(), observation({ candidate: eligible(proxy, candidate(LOW.slice().fill(0xff), 'other')) }));
    expect(result.kind).toBe('SUCCESS');
    expect(['first', 'other']).toContain(result.output.selectedCandidateRef);
  });

  test('a throwing proxy trap fails closed at P01 and never escapes as a foreign error', () => {
    const hostile = new Proxy({}, { ownKeys() { throw new Error('boom'); } });
    expect(code(apply(active(), observation({ candidate: hostile })))).toBe('INVALID_REQUEST');
    expect(code(apply(active(), observation({ candidate: eligible(hostile, candidate(HIGH, 'b')) })))).toBe('INVALID_REQUEST');
  });

  test('an unshapeable call still throws only M2AdapterError', () => {
    expect(() => invokeAdapter({ request: { operation: 'APPLY_PEER_UPDATE' }, snapshot: active(), observation: observation() }))
      .toThrow(M2AdapterError);
  });
});

describe('Purity and the seeded property sweep', () => {
  test('inputs are not mutated and results are deeply frozen', () => {
    const obs = observation({ candidate: eligible(candidate(LOW, 'a'), candidate(HIGH, 'b')) });
    const before = JSON.stringify(obs, (_key, value) => (value instanceof Uint8Array ? [...value] : value));
    const { result, snapshot } = transition(active(), obs);
    expect(JSON.stringify(obs, (_key, value) => (value instanceof Uint8Array ? [...value] : value))).toBe(before);
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(snapshot)).toBe(true);
  });

  test('for any two distinct 32-byte identities the unsigned-lexicographic lower one wins, in either order', () => {
    const identity = fc.uint8Array({ minLength: 32, maxLength: 32 });
    fc.assert(fc.property(identity, identity, (left, right) => {
      const order = Buffer.compare(Buffer.from(left), Buffer.from(right));
      const one = apply(active(), observation({ candidate: eligible(candidate(left, 'L'), candidate(right, 'R')) }));
      const two = apply(active(), observation({ candidate: eligible(candidate(right, 'R'), candidate(left, 'L')) }));
      if (order === 0) {
        return one.kind === 'REJECTED' && one.error.code === 'INVALID_REQUEST' && two.kind === 'REJECTED';
      }
      const winner = order < 0 ? 'L' : 'R';
      return one.output.selectedCandidateRef === winner && two.output.selectedCandidateRef === winner;
    }), { seed: 0x1f04c, numRuns: 400 });
  });

  test('for any outcome, no SUCCESS ever appears without COMMITTED and INDETERMINATE always holds', () => {
    const outcome = fc.constantFrom('COMMITTED', 'NOT_COMMITTED', 'INDETERMINATE', null, 'X');
    const shape = fc.constantFrom('current', 'eligible');
    fc.assert(fc.property(outcome, shape, (commitOutcome, which) => {
      const classification = which === 'current' ? { kind: 'CURRENT_PARENT' } : eligible(candidate(LOW, 'a'), candidate(HIGH, 'b'));
      const { result, snapshot } = transition(active(), observation({ candidate: classification, commitOutcome }));
      if (result.kind === 'SUCCESS') return commitOutcome === 'COMMITTED' && snapshot.state === 'ACTIVE';
      if (result.kind === 'INDETERMINATE') return snapshot.state === 'RECONCILIATION_REQUIRED' && snapshot.held !== null;
      return result.kind === 'NOT_COMMITTED' && commitOutcome === 'NOT_COMMITTED';
    }), { seed: 0x1f04d, numRuns: 200 });
  });
});

// Owner decision A (2026-10-05) condition 4 and U1 (#445): a reconciled `PEER_UPDATE_APPLIED` hold produced
// by this module's own APPLY_PEER_UPDATE path reconciles to `originalOutput` `{}` (never `null`), and that
// exact result, like a reconciled `CANDIDATE_SELECTED`, crosses the I-WORK worker boundary unchanged.
describe('Reconciled APPLY_PEER_UPDATE results cross the worker boundary (U1 `{}` rule)', () => {
  const reconcileHeld = (snapshot, reference, heldOutput) => invokeAdapter({
    request: request('RECONCILE_INDETERMINATE', { reconciliationRef: reference }),
    snapshot,
    observation: { slotContext: SLOT.slice(), commitOutcome: 'COMMITTED', responseEmission: 'SUCCEEDED', heldOutput },
  });
  const crossesWire = (result) => {
    const validated = validateWorkerResult(result);
    const decoded = fromWireBytes(toWireBytes(result));
    for (const copy of [validated, decoded]) {
      expect(copy.kind).toBe('SUCCESS');
      expect(copy.successCode).toBe('RECONCILED_COMMITTED');
      expect(copy.output.originalSuccessCode).toBe(result.output.originalSuccessCode);
      expect({ ...copy.output.originalOutput }).toEqual({ ...result.output.originalOutput });
    }
  };

  test('CAPI-S016: invokeAdapter -> hold -> RECONCILED_COMMITTED with originalOutput {} -> toWireBytes -> validateWorkerResult', () => {
    const { result: first, snapshot } = transition(active(), observation({ commitOutcome: 'INDETERMINATE', operationIdentity: 'op-wire-s016' }));
    expect(first.kind).toBe('INDETERMINATE');
    expect(snapshot.held.scenario).toBe('CAPI-S016');
    const result = reconcileHeld(snapshot, first.reconciliationRef, null);
    assertEnvelope(result, 'SUCCESS', ['successCode', 'output']);
    expect(result.output.originalSuccessCode).toBe('PEER_UPDATE_APPLIED');
    expect(result.output.originalOutput).not.toBeNull();
    expect(Object.getPrototypeOf(result.output.originalOutput)).toBe(Object.prototype);
    expect(Object.keys(result.output.originalOutput)).toEqual([]);
    expect(Object.isFrozen(result.output.originalOutput)).toBe(true);
    crossesWire(result);
  });

  test('CAPI-S017: the reconciled CANDIDATE_SELECTED reference crosses the worker boundary unchanged', () => {
    const { result: first, snapshot } = transition(active(), observation({
      candidate: eligible(candidate(HIGH, 'cand:hi'), candidate(LOW, 'cand:lo')),
      commitOutcome: 'INDETERMINATE', operationIdentity: 'op-wire-s017',
    }));
    const result = reconcileHeld(snapshot, first.reconciliationRef, { selectedCandidateRef: 'cand:lo' });
    expect(result.output).toEqual({ originalSuccessCode: 'CANDIDATE_SELECTED', originalOutput: { selectedCandidateRef: 'cand:lo' } });
    crossesWire(result);
  });

  test('the direct APPLY_PEER_UPDATE successes cross the worker boundary too', () => {
    const applied = apply(active(), observation());
    expect(validateWorkerResult(applied).successCode).toBe('PEER_UPDATE_APPLIED');
    expect(fromWireBytes(toWireBytes(applied)).successCode).toBe('PEER_UPDATE_APPLIED');
    const selected = apply(active(), observation({ candidate: eligible(candidate(LOW, 'a'), candidate(HIGH, 'b')) }));
    expect(fromWireBytes(toWireBytes(selected)).output).toEqual({ selectedCandidateRef: 'a' });
  });
});

// I-FORK review r1 (Sol R1-R4, DeepSeek F1-F2), each confirmed on AI395 at a39f3e5 before the fix.
describe('I-FORK review r1 regressions', () => {
  const bound = M2_ADAPTER.BOUNDS.MAX_CANDIDATE_REF_CHARS;

  test('R1: the candidate subtree is read once; a descriptor that changes on re-read cannot swap the held winner', () => {
    let reads = 0;
    const current = new Proxy({ committerId: LOW.slice(), ref: 'validated' }, {
      getOwnPropertyDescriptor(target, key) {
        const descriptor = Reflect.getOwnPropertyDescriptor(target, key);
        if (key !== 'ref') return descriptor;
        reads += 1;
        return { ...descriptor, value: reads === 1 ? 'validated' : 'swapped' };
      },
    });
    const obs = observation({ candidate: eligible(current, candidate(HIGH, 'other')) });
    Object.defineProperty(obs, 'commitOutcome', { enumerable: false });
    const { result, snapshot } = transition(active(), obs);
    expect(reads).toBe(1);
    expect(result.kind).toBe('INDETERMINATE');
    expect(snapshot.held.selectedCandidateRef).toBe('validated');
    const reconcile = (ref) => invokeAdapter({
      request: request('RECONCILE_INDETERMINATE', { reconciliationRef: result.reconciliationRef }),
      snapshot,
      observation: { slotContext: SLOT.slice(), commitOutcome: 'COMMITTED', responseEmission: 'SUCCEEDED', heldOutput: { selectedCandidateRef: ref } },
    });
    expect(reconcile('swapped').kind).not.toBe('SUCCESS');
    expect(reconcile('validated').output.originalOutput).toEqual({ selectedCandidateRef: 'validated' });
  });

  test('R2: a listed key whose descriptor is hidden is still an unknown member, never dropped', () => {
    const hidden = new Proxy({ committerId: LOW.slice(), ref: 'lo', extra: 1 }, {
      getOwnPropertyDescriptor: (target, key) => (key === 'extra' ? undefined : Reflect.getOwnPropertyDescriptor(target, key)),
    });
    const { result, snapshot } = transition(active(), observation({ candidate: eligible(hidden, candidate(HIGH, 'hi')) }));
    expect(code(result)).toBe('UNKNOWN_FIELD');
    expect(result.stateAfter).toBe('ACTIVE');
    expect(snapshot).toBeNull();
  });

  test('R3/F1: an unknown nested candidate member is UNKNOWN_FIELD whatever else is malformed (P01)', () => {
    const make = () => observation({
      candidate: eligible({ committerId: LOW.slice(), ref: 'lo', extra: 1 }, candidate(HIGH, 'hi')),
    });
    const noAuth = make();
    delete noAuth.authentication;
    const noIncoming = make();
    delete noIncoming.candidate.incoming;
    const accessor = make();
    Object.defineProperty(accessor, 'slotContext', { enumerable: true, configurable: true, get: () => SLOT.slice() });
    for (const obs of [make(), noAuth, noIncoming, accessor]) expect(code(apply(active(), obs))).toBe('UNKNOWN_FIELD');
  });

  test('R4: a detached identity is CAPI-S019 and a revoked classification proxy is INVALID_REQUEST, never a throw', () => {
    const identity = new Uint8Array(32);
    structuredClone(identity.buffer, { transfer: [identity.buffer] });
    const detached = apply(active(), rejectingObservation(eligible(candidate(identity, 'd'), candidate(HIGH, 'o'))));
    expect(detached.kind).toBe('REJECTED');
    expect(code(detached)).toBe('UNSUPPORTED_COMMIT_SHAPE');
    const revoked = Proxy.revocable({}, {});
    revoked.revoke();
    const proxy = apply(active(), rejectingObservation(revoked.proxy));
    expect(proxy.kind).toBe('REJECTED');
    expect(code(proxy)).toBe('INVALID_REQUEST');
  });

  test('F2: a hold whose selected reference is over MAX_CANDIDATE_REF_CHARS never releases it', () => {
    const longRef = 'r'.repeat(bound + 1);
    const opIdentity = 'op-ifork-f2';
    const held = {
      originalStateBefore: 'ACTIVE', scenario: 'CAPI-S017', mutationPlanIdentity: 'CAPI-S017', operationIdentity: opIdentity,
      expectedSuccessCode: 'CANDIDATE_SELECTED', expectedStateAfter: 'ACTIVE', outputKind: 'SELECTED_CANDIDATE_REF',
      reconciliationRef: `I-SM-HOLD:${opIdentity}`, selectedCandidateRef: longRef, terminalEvidenceStatus: 'PENDING',
    };
    const result = invokeAdapter({
      request: request('RECONCILE_INDETERMINATE', { reconciliationRef: `I-SM-HOLD:${opIdentity}` }),
      snapshot: { state: 'RECONCILIATION_REQUIRED', held },
      observation: { slotContext: SLOT.slice(), commitOutcome: 'COMMITTED', responseEmission: 'SUCCEEDED', heldOutput: { selectedCandidateRef: longRef } },
    });
    expect(result.kind).not.toBe('SUCCESS');
    expect(Object.hasOwn(result, 'output')).toBe(false);
  });
});
