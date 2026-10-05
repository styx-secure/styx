// u1-reconcile-wire.test.js — M2 U1 regression: a RECONCILED_COMMITTED result whose original success
// code carries no output member crosses the worker boundary.
//
// Owner act on #317 (2026-10-05, U1 decision A): `originalOutput` is the closed output object for
// `originalSuccessCode` under C-API `/response/outputBySuccessCode`; an empty member list is the empty
// closed object `{}`, never `null`. The tests drive the real `invokeAdapter` over a hold produced by the
// merged I-SM core, then pass the exact result through the I-WORK codec (`toWireBytes`, `fromWireBytes`,
// `validateWorkerResult`). Nothing is mocked.

import { describe, expect, test } from '@jest/globals';
import { M2_ADAPTER, invokeAdapter, invokeAdapterTransition } from '../../../src/crypto/mls/m2/adapter.js';
import {
  MUTATION_PLANS,
  createAdapterSnapshot,
  transitionAdapter,
} from '../../../src/crypto/mls/m2/state-machine.js';
import { fromWireBytes, toWireBytes, validateWorkerResult } from '../../../src/crypto/mls/m2/worker-protocol.js';

const SLOT = new Uint8Array(32).fill(0xa1);
const EMPTY_OUTPUT_CODES = Object.entries(M2_ADAPTER.OUTPUT_BY_SUCCESS_CODE)
  .filter(([, members]) => members.length === 0)
  .map(([successCode]) => successCode)
  .sort();

const holdOf = (operation, state, facts, operationIdentity) => transitionAdapter(createAdapterSnapshot(state), {
  operation,
  applicableErrors: [],
  facts,
  commitOutcome: 'INDETERMINATE',
  operationIdentity,
}).snapshot;

const reconcile = (snapshot, requestId) => invokeAdapter({
  request: {
    api: M2_ADAPTER.API,
    operation: 'RECONCILE_INDETERMINATE',
    requestId,
    profile: { ...M2_ADAPTER.PROFILE },
    bindingRef: SLOT.slice(),
    input: { reconciliationRef: snapshot.held.reconciliationRef },
  },
  snapshot,
  observation: { slotContext: SLOT.slice(), commitOutcome: 'COMMITTED', responseEmission: 'SUCCEEDED', heldOutput: null },
});

const expectWireRoundTrip = (result, originalSuccessCode) => {
  expect(result.kind).toBe('SUCCESS');
  expect(result.successCode).toBe('RECONCILED_COMMITTED');
  expect(Object.keys(result.output)).toEqual(['originalSuccessCode', 'originalOutput']);
  expect(result.output.originalSuccessCode).toBe(originalSuccessCode);
  expect(Object.getPrototypeOf(result.output.originalOutput)).toBe(Object.prototype);
  expect(Object.keys(result.output.originalOutput)).toEqual([]);
  expect(Object.isFrozen(result.output.originalOutput)).toBe(true);
  const validated = validateWorkerResult(result);
  expect(validated.output.originalSuccessCode).toBe(originalSuccessCode);
  expect(Object.keys(validated.output.originalOutput)).toEqual([]);
  const decoded = fromWireBytes(toWireBytes(result));
  expect(decoded.kind).toBe('SUCCESS');
  expect(decoded.successCode).toBe('RECONCILED_COMMITTED');
  expect(decoded.output.originalSuccessCode).toBe(originalSuccessCode);
  expect(Object.keys(decoded.output.originalOutput)).toEqual([]);
};

// Every RS_TRI_STATE mutation plan whose original success code lists no output member. A plan missing
// here fails the coverage test below.
// - CAPI-S006 (JOIN_WELCOME) is integrated: its hold comes from the adapter itself.
// - CAPI-S016 (APPLY_PEER_UPDATE) is not integrated at this base (I-FORK), so its hold comes from the
//   merged core only. RECONCILE_INDETERMINATE is integrated and resolves it.
const HELD_EMPTY_OUTPUT = ['CAPI-S006', 'CAPI-S016'];

describe('U1: RECONCILED_COMMITTED with an empty original output crosses the worker boundary', () => {
  test('the empty-output success codes are exactly the four C-API lists', () => {
    expect(EMPTY_OUTPUT_CODES).toEqual(['DUPLICATE_IGNORED', 'JOINED', 'PEER_UPDATE_APPLIED', 'RESTORED']);
  });

  test('every holdable plan with an empty output list is covered, and no other', () => {
    const holdable = Object.values(MUTATION_PLANS)
      .filter((plan) => EMPTY_OUTPUT_CODES.includes(plan.successCode))
      .map((plan) => plan.scenario)
      .sort();
    expect(holdable).toEqual(HELD_EMPTY_OUTPUT);
    for (const scenario of holdable) expect(MUTATION_PLANS[scenario].outputKind).toBe('NONE');
  });

  test('a committed JOIN_WELCOME (CAPI-S006) reconciles to originalOutput {} and round-trips the wire', () => {
    // The whole integrated path: JOIN_WELCOME through the adapter ends INDETERMINATE with the hold, and
    // RECONCILE_INDETERMINATE through the adapter resolves it COMMITTED.
    expect(M2_ADAPTER.INTEGRATED_OPERATIONS).toContain('JOIN_WELCOME');
    const join = invokeAdapterTransition({
      request: {
        api: M2_ADAPTER.API,
        operation: 'JOIN_WELCOME',
        requestId: 'u1-join',
        profile: { ...M2_ADAPTER.PROFILE },
        bindingRef: SLOT.slice(),
        input: { embeddedTreeWelcome: new Uint8Array([0x02]) },
      },
      snapshot: createAdapterSnapshot('EMPTY'),
      observation: { keyPackage: 'MATCHED', commitOutcome: 'INDETERMINATE', operationIdentity: 'u1-join-1' },
    });
    expect(join.result.kind).toBe('INDETERMINATE');
    expect(join.result.reconciliationRef).toBe('I-SM-HOLD:u1-join-1');
    const held = join.snapshot;
    expect(held.state).toBe('RECONCILIATION_REQUIRED');
    expect(held.held.scenario).toBe('CAPI-S006');
    expectWireRoundTrip(reconcile(held, 'u1-r-join'), 'JOINED');
  });

  test('a committed APPLY_PEER_UPDATE hold (CAPI-S016) reconciles to originalOutput {} and round-trips the wire', () => {
    const held = holdOf('APPLY_PEER_UPDATE', 'ACTIVE', { kind: 'CURRENT_PARENT' }, 'u1-peer-1');
    expect(held.state).toBe('RECONCILIATION_REQUIRED');
    expect(held.held.scenario).toBe('CAPI-S016');
    expectWireRoundTrip(reconcile(held, 'u1-r-peer'), 'PEER_UPDATE_APPLIED');
  });

  test('RESTORED and DUPLICATE_IGNORED are never held mutations', () => {
    for (const plan of Object.values(MUTATION_PLANS)) {
      expect(['RESTORED', 'DUPLICATE_IGNORED']).not.toContain(plan.successCode);
    }
    // The merged core produces no hold for either row, whatever commit outcome the owning layer reports.
    const restored = holdOf('RESTORE', 'EMPTY', 'RESTORED', 'u1-restore-1');
    expect(restored.state).not.toBe('RECONCILIATION_REQUIRED');
    expect(restored.held).toBe(null);
    const duplicate = holdOf('OPEN_APPLICATION', 'ACTIVE', 'DUPLICATE_IN_WINDOW', 'u1-dup-1');
    expect(duplicate.state).not.toBe('RECONCILIATION_REQUIRED');
    expect(duplicate.held).toBe(null);
  });

  test('a forged hold naming RESTORED or DUPLICATE_IGNORED never reconciles to a success', () => {
    const forged = [
      { scenario: 'CAPI-S003', originalStateBefore: 'EMPTY', expectedSuccessCode: 'RESTORED', expectedStateAfter: 'ACTIVE' },
      { scenario: 'CAPI-S011', originalStateBefore: 'ACTIVE', expectedSuccessCode: 'DUPLICATE_IGNORED', expectedStateAfter: 'ACTIVE' },
    ];
    for (const [index, fields] of forged.entries()) {
      const operationIdentity = `u1-forged-${index}`;
      const snapshot = {
        state: 'RECONCILIATION_REQUIRED',
        held: {
          ...fields,
          mutationPlanIdentity: fields.scenario,
          operationIdentity,
          outputKind: 'NONE',
          reconciliationRef: `I-SM-HOLD:${operationIdentity}`,
          selectedCandidateRef: null,
          terminalEvidenceStatus: 'PENDING',
        },
      };
      const result = reconcile(snapshot, `u1-r-forged-${index}`);
      expect(result.kind).toBe('REJECTED');
      expect(result.error.code).toBe('UNKNOWN_VALUE');
      expect(result.output).toBeUndefined();
    }
  });
});
