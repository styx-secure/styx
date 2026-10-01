// worker-protocol.test.js — I-WORK conformance tests for the closed M2 worker
// message grammar (contract Issue #369).
//
// Positive and negative grammar coverage for every message kind, a seeded
// property sweep, and the boundary proof that no CryptoKey, WebAssembly handle,
// wasm-bindgen pointer, function, symbol or shared buffer has any representation.

import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import {
  M2_WORKER,
  M2WorkerError,
  assertWireSafe,
  classifyWorkerMessage,
  fromWireBytes,
  toWireBytes,
  validateWorkerError,
  validateWorkerMessage,
  validateWorkerRequest,
  validateWorkerResult,
} from '../../../src/crypto/mls/m2/worker-protocol.js';
import { OPERATIONS, STATES } from '../../../src/crypto/mls/m2/state-machine.js';
import { encodeBindingV0 } from '../../../src/crypto/m2-binding-v0.js';

const B = M2_WORKER.BOUNDS;
const SEED = 20261001;
const ANALYTIC = { numRuns: 300, seed: SEED };

const bytes = (fill, length = 8) => Uint8Array.from({ length }, () => fill);

const request = (operation, input = {}, overrides = {}) => ({
  api: M2_WORKER.API,
  operation,
  requestId: 'req-0001',
  profile: M2_WORKER.PROFILE,
  bindingRef: bytes(0x5b, 32),
  input,
  ...overrides,
});

const INPUT_FOR = {
  CREATE: { peerFramedKeyPackage: bytes(1) },
  RESTORE: {},
  JOIN_WELCOME: { embeddedTreeWelcome: bytes(2) },
  PROTECT_APPLICATION: { applicationBytes: bytes(3) },
  OPEN_APPLICATION: { protectedApplicationMessage: bytes(4) },
  SELF_UPDATE: {},
  APPLY_PEER_UPDATE: { protectedCommitBytes: bytes(5) },
  RECONCILE_INDETERMINATE: { reconciliationRef: 'INDETERMINATE:req-0001' },
};

const result = (kind, extra = {}, overrides = {}) => ({
  api: M2_WORKER.API,
  requestId: 'req-0001',
  operation: 'CREATE',
  kind,
  stateBefore: 'EMPTY',
  stateAfter: 'ACTIVE',
  ...extra,
  ...overrides,
});

const SUCCESS_RESULT = result('SUCCESS', { successCode: 'CREATED', output: { embeddedTreeWelcome: bytes(7) } });
const NO_CHANGE_RESULT = result('NO_CHANGE', { successCode: 'DUPLICATE_IGNORED' });
const NOT_COMMITTED_RESULT = result('NOT_COMMITTED', { commitOutcome: 'NOT_COMMITTED' });
const INDETERMINATE_RESULT = result('INDETERMINATE', {
  commitOutcome: 'INDETERMINATE',
  reconciliationRef: 'INDETERMINATE:req-0001',
  originalStateBefore: 'EMPTY',
});
const REJECTED_RESULT = result('REJECTED', { error: { code: 'AUTHENTICATION_FAILED', detailTag: 'AUTH' } });

const RESULTS = [
  ['SUCCESS', SUCCESS_RESULT],
  ['NO_CHANGE', NO_CHANGE_RESULT],
  ['NOT_COMMITTED', NOT_COMMITTED_RESULT],
  ['INDETERMINATE', INDETERMINATE_RESULT],
  ['REJECTED', REJECTED_RESULT],
];

const thrown = (fn) => {
  try {
    fn();
  } catch (error) {
    return error;
  }
  return null;
};

const expectRejection = (fn, code, detailTag) => {
  const error = thrown(fn);
  expect(error).toBeInstanceOf(M2WorkerError);
  expect(error.code).toBe(code);
  if (detailTag !== undefined) expect(error.detailTag).toBe(detailTag);
  expect(M2_WORKER.ERROR_CODES).toContain(error.code);
  expect(M2_WORKER.DETAIL_TAGS).toContain(error.detailTag);
  expect(error.valueFree).toBe(true);
  return error;
};

/** Values that must have no representation anywhere on this boundary. */
const opaqueValues = () => {
  const values = [
    ['function', () => 1],
    ['async-function', async () => 1],
    ['promise', Promise.resolve(1)],
    ['symbol', Symbol('key')],
    ['bigint', 1n],
    ['undefined', undefined],
    ['date', new Date(0)],
    ['map', new Map([['k', 'v']])],
    ['set', new Set([1])],
    ['weakmap', new WeakMap()],
    ['regexp', /key/],
    ['error', new Error('key material')],
    ['dataview', new DataView(new ArrayBuffer(8))],
    ['float32-view', new Float32Array(2)],
    ['array-buffer', new ArrayBuffer(8)],
    ['class-instance', new (class Handle { constructor() { this.k = 1; } })()],
    ['null-prototype', Object.create(null)],
    ['wasm-handle', { __wbg_ptr: 12345 }],
    ['ptr-handle', { ptr: 7 }],
  ];
  if (typeof WebAssembly !== 'undefined' && typeof WebAssembly.Module === 'function') {
    try {
      values.push(['wasm-module', new WebAssembly.Module(Uint8Array.of(0, 97, 115, 109, 1, 0, 0, 0))]);
    } catch { /* platform refused the empty module */ }
  }
  if (typeof SharedArrayBuffer !== 'undefined') {
    values.push(['shared-buffer', new SharedArrayBuffer(8)]);
    values.push(['shared-view', new Uint8Array(new SharedArrayBuffer(8))]);
  }
  return values;
};

describe('closed sets and merged-table binding', () => {
  test('the operation and state sets are the merged I-SM tables, not a copy', () => {
    expect(M2_WORKER.OPERATIONS).toEqual(OPERATIONS);
    expect(M2_WORKER.STATES).toEqual(STATES);
    expect(M2_WORKER.OPERATIONS).toHaveLength(8);
    expect(M2_WORKER.STATES).toHaveLength(3);
  });

  test('the six message kinds are the request plus the five closed result kinds', () => {
    expect(M2_WORKER.MESSAGE_KINDS).toEqual([
      'REQUEST', 'SUCCESS', 'NO_CHANGE', 'NOT_COMMITTED', 'INDETERMINATE', 'REJECTED',
    ]);
  });

  test('the copied constants keep the ratified sizes', () => {
    expect(Object.keys(M2_WORKER.PROFILE)).toHaveLength(13);
    expect(M2_WORKER.SUCCESS_CODES).toHaveLength(10);
    expect(M2_WORKER.ERROR_CODES).toHaveLength(25);
    expect(M2_WORKER.DETAIL_TAGS).toHaveLength(10);
    expect(Object.keys(M2_WORKER.CODE_TO_KIND)).toHaveLength(37);
    expect(Object.keys(INPUT_FOR)).toEqual(M2_WORKER.OPERATIONS);
    expect(Object.keys(M2_WORKER.OUTPUT_BY_SUCCESS_CODE)).toHaveLength(10);
    expect(M2_WORKER.COMMIT_OUTCOMES).toEqual(['COMMITTED', 'NOT_COMMITTED', 'INDETERMINATE']);
  });

  test('every success and error code maps to exactly the kind C-API assigns', () => {
    for (const code of M2_WORKER.SUCCESS_CODES) {
      expect(['SUCCESS', 'NO_CHANGE']).toContain(M2_WORKER.CODE_TO_KIND[code]);
    }
    for (const code of M2_WORKER.ERROR_CODES) {
      expect(M2_WORKER.CODE_TO_KIND[code]).toBe('REJECTED');
    }
    expect(M2_WORKER.CODE_TO_KIND.NOT_COMMITTED).toBe('NOT_COMMITTED');
    expect(M2_WORKER.CODE_TO_KIND.INDETERMINATE).toBe('INDETERMINATE');
  });

  test('the metadata object and its nested members are frozen', () => {
    expect(Object.isFrozen(M2_WORKER)).toBe(true);
    expect(Object.isFrozen(M2_WORKER.BOUNDS)).toBe(true);
    expect(Object.isFrozen(M2_WORKER.PROFILE)).toBe(true);
    expect(Object.isFrozen(M2_WORKER.CODE_TO_KIND)).toBe(true);
    expect(Object.isFrozen(M2_WORKER.MESSAGE_KINDS)).toBe(true);
  });
});

describe('positive grammar: every request form', () => {
  test.each(OPERATIONS)('accepts the exact closed %s request', (operation) => {
    const validated = validateWorkerRequest(request(operation, INPUT_FOR[operation]));
    expect(Object.keys(validated).sort())
      .toEqual(['api', 'bindingRef', 'input', 'operation', 'profile', 'requestId']);
    expect(Object.keys(validated.input)).toEqual(Object.keys(INPUT_FOR[operation]));
    expect(validated.operation).toBe(operation);
    expect(validated.api).toBe(M2_WORKER.API);
    expect(Object.isFrozen(validated)).toBe(true);
    expect(Object.isFrozen(validated.input)).toBe(true);
    expect(Object.isFrozen(validated.profile)).toBe(true);
  });

  test('classifies and validates a request through the dispatcher', () => {
    const input = request('CREATE', INPUT_FOR.CREATE);
    expect(classifyWorkerMessage(input)).toBe('REQUEST');
    expect(validateWorkerMessage(input)).toEqual(validateWorkerRequest(input));
  });

  test('accepts a bindingRef at exactly the maximum length', () => {
    expect(validateWorkerRequest({ ...request('RESTORE', {}), bindingRef: new Uint8Array(B.MAX_BINDING_REF_BYTES) }))
      .toBeTruthy();
  });

  test('binary leaves are copied, never aliased', () => {
    const input = request('PROTECT_APPLICATION', { applicationBytes: bytes(9, 4) });
    const validated = validateWorkerRequest(input);
    expect(Array.from(validated.input.applicationBytes)).toEqual([9, 9, 9, 9]);
    input.input.applicationBytes[0] = 0;
    expect(validated.input.applicationBytes[0]).toBe(9);
  });

  test('the two empty-input operations accept exactly the empty object', () => {
    for (const operation of ['RESTORE', 'SELF_UPDATE']) {
      expect(Object.keys(validateWorkerRequest(request(operation, {})).input)).toEqual([]);
    }
  });
});

describe('positive grammar: every result kind', () => {
  test.each(RESULTS)('accepts the exact closed %s result', (kind, value) => {
    const validated = validateWorkerResult(value);
    expect(classifyWorkerMessage(value)).toBe(kind);
    expect(validateWorkerMessage(value)).toEqual(validated);
    expect(validated.kind).toBe(kind);
    expect(Object.isFrozen(validated)).toBe(true);
  });

  test('accepts every success code with exactly its assigned output keys', () => {
    const outputs = {
      CREATED: { embeddedTreeWelcome: bytes(1) },
      RESTORED: {},
      JOINED: {},
      APPLICATION_PROTECTED: { protectedApplicationBytes: bytes(2) },
      APPLICATION_OPENED: { applicationBytes: bytes(3) },
      SELF_UPDATED: { protectedCommitBytes: bytes(4) },
      PEER_UPDATE_APPLIED: {},
      CANDIDATE_SELECTED: { selectedCandidateRef: 'candidate:1' },
      RECONCILED_COMMITTED: {
        originalSuccessCode: 'APPLICATION_OPENED',
        originalOutput: { applicationBytes: bytes(5) },
      },
      DUPLICATE_IGNORED: undefined,
    };
    for (const code of M2_WORKER.SUCCESS_CODES) {
      const output = outputs[code];
      const kind = M2_WORKER.CODE_TO_KIND[code];
      const value = kind === 'NO_CHANGE'
        ? result('NO_CHANGE', { successCode: code })
        : (output === undefined ? result('SUCCESS', { successCode: code })
          : result('SUCCESS', { successCode: code, output }));
      const validated = validateWorkerResult(value);
      expect(validated.successCode).toBe(code);
      expect(validated.kind).toBe(kind);
      if (output !== undefined) expect(Object.keys(validated.output)).toEqual(Object.keys(output));
    }
  });

  test('accepts a SUCCESS carrying commitOutcome COMMITTED', () => {
    expect(validateWorkerResult({ ...SUCCESS_RESULT, commitOutcome: 'COMMITTED' }).commitOutcome)
      .toBe('COMMITTED');
  });

  test('accepts both originalStateBefore domain values', () => {
    for (const state of ['EMPTY', 'ACTIVE']) {
      expect(validateWorkerResult({ ...INDETERMINATE_RESULT, originalStateBefore: state }).originalStateBefore)
        .toBe(state);
    }
  });

  test('accepts every error code with and without every detail tag', () => {
    for (const code of M2_WORKER.ERROR_CODES) {
      expect(validateWorkerResult({ ...REJECTED_RESULT, error: { code } }).error.code).toBe(code);
      expect(validateWorkerError({ code }).code).toBe(code);
      for (const detailTag of M2_WORKER.DETAIL_TAGS) {
        expect(validateWorkerError({ code, detailTag }).detailTag).toBe(detailTag);
      }
    }
  });

  test('accepts all nine state pairs', () => {
    for (const stateBefore of STATES) {
      for (const stateAfter of STATES) {
        expect(validateWorkerResult(result('NO_CHANGE', { successCode: 'DUPLICATE_IGNORED' },
          { stateBefore, stateAfter }))).toBeTruthy();
      }
    }
  });
});

describe('negative grammar: closed request fields', () => {
  const base = request('CREATE', INPUT_FOR.CREATE);

  test('rejects every unrecognized request field', () => {
    for (const field of ['type', 'apiVersion', 'commitOutcome', 'epoch', 'stateBefore', 'a b']) {
      expectRejection(() => validateWorkerRequest({ ...base, [field]: 1 }), 'UNKNOWN_FIELD', 'FIELD');
    }
    // The four keys the contract names as never-own are refused as malformed rather
    // than as foreign: `$$` and the two wasm-bindgen handles are handle markers, not
    // unknown fields.
    for (const field of ['$$', '__wbg_ptr', 'ptr']) {
      expectRejection(() => validateWorkerRequest({ ...base, [field]: 1 }), 'INVALID_REQUEST', 'FIELD');
    }
  });

  test('rejects every missing required request field', () => {
    for (const field of Object.keys(base)) {
      const copy = { ...base };
      delete copy[field];
      expectRejection(() => validateWorkerRequest(copy), 'INVALID_REQUEST', 'FIELD');
    }
  });

  test('rejects an unassigned input member for every operation', () => {
    for (const operation of OPERATIONS) {
      const assigned = Object.keys(INPUT_FOR[operation]);
      const foreign = assigned.includes('applicationBytes') ? 'embeddedTreeWelcome' : 'applicationBytes';
      expectRejection(
        () => validateWorkerRequest(request(operation, { ...INPUT_FOR[operation], [foreign]: bytes(1) })),
        'UNKNOWN_FIELD', 'FIELD',
      );
    }
  });

  test('rejects an AP-supplied derived fact', () => {
    for (const field of ['profileFacts', 'memberIdentity', 'peerIdentity', 'committerIdentity',
      'replayIdentity', 'authenticationFacts', 'parentStateRef', 'witnessScore', 'proposalFree']) {
      expectRejection(
        () => validateWorkerRequest(request('CREATE', { ...INPUT_FOR.CREATE, [field]: 'x' })),
        'UNKNOWN_FIELD', 'FIELD',
      );
      expectRejection(
        () => validateWorkerRequest({ ...request('CREATE', INPUT_FOR.CREATE), [field]: 'x' }),
        'UNKNOWN_FIELD', 'FIELD',
      );
    }
  });

  test('rejects a wrong or missing api version', () => {
    for (const api of ['styx-m2-session-adapter/v0', '', 1, null, undefined]) {
      expectRejection(() => validateWorkerRequest({ ...base, api }), 'UNSUPPORTED_API_VERSION', 'PROFILE');
    }
  });

  test('rejects an unsupported operation', () => {
    for (const operation of ['RESET', 'create', 'CREATE ', 'DELETE', 7, null]) {
      expectRejection(() => validateWorkerRequest({ ...base, operation }), 'UNSUPPORTED_OPERATION', 'STATE');
    }
  });

  test('rejects every profile tuple drift, a missing field and an extra field', () => {
    for (const key of Object.keys(M2_WORKER.PROFILE)) {
      expectRejection(
        () => validateWorkerRequest({ ...base, profile: { ...M2_WORKER.PROFILE, [key]: 'drift' } }),
        'UNSUPPORTED_PROFILE', 'PROFILE',
      );
    }
    const missing = { ...M2_WORKER.PROFILE };
    delete missing.pastEpochWindow;
    expectRejection(() => validateWorkerRequest({ ...base, profile: missing }),
      'UNSUPPORTED_PROFILE', 'PROFILE');
    expectRejection(() => validateWorkerRequest({ ...base, profile: { ...M2_WORKER.PROFILE, extra: 1 } }),
      'UNSUPPORTED_PROFILE', 'PROFILE');
    expectRejection(() => validateWorkerRequest({ ...base, profile: { ...M2_WORKER.PROFILE, pastEpochWindow: 6 } }),
      'UNSUPPORTED_PROFILE', 'PROFILE');
    for (const profile of [null, 'profile', [], 7]) {
      expectRejection(() => validateWorkerRequest({ ...base, profile }), 'INVALID_REQUEST', 'FIELD');
    }
  });

  test('rejects an empty, over-long or non-binary bindingRef', () => {
    for (const bindingRef of [new Uint8Array(0), new Uint8Array(B.MAX_BINDING_REF_BYTES + 1),
      'opaque', null, {}, [1, 2, 3]]) {
      expectRejection(() => validateWorkerRequest({ ...base, bindingRef }), 'VALUE_OUT_OF_RANGE', 'BINDING');
    }
  });

  test('rejects requestId outside its bounds', () => {
    // The bounds table is normative: an over-limit value is VALUE_OUT_OF_RANGE, and a
    // malformed one is INVALID_REQUEST.
    expectRejection(() => validateWorkerRequest({ ...base, requestId: 'x'.repeat(B.MAX_REQUEST_ID_CHARS + 1) }),
      'VALUE_OUT_OF_RANGE', 'FIELD');
    for (const requestId of ['', 'a\nb', 7, null, {}]) {
      expectRejection(() => validateWorkerRequest({ ...base, requestId }), 'INVALID_REQUEST', 'FIELD');
    }
    expect(validateWorkerRequest({ ...base, requestId: 'x'.repeat(B.MAX_REQUEST_ID_CHARS) })).toBeTruthy();
  });

  test('rejects over-limit and empty opaque input bytes', () => {
    expectRejection(
      () => validateWorkerRequest(request('PROTECT_APPLICATION',
        { applicationBytes: new Uint8Array(B.MAX_OPAQUE_BYTES + 1) })),
      'VALUE_OUT_OF_RANGE', 'FIELD',
    );
    expectRejection(
      () => validateWorkerRequest(request('PROTECT_APPLICATION', { applicationBytes: new Uint8Array(0) })),
      'VALUE_OUT_OF_RANGE', 'FIELD',
    );
  });

  test('rejects an empty or over-long reconciliationRef input', () => {
    expectRejection(
      () => validateWorkerRequest(request('RECONCILE_INDETERMINATE', { reconciliationRef: '' })),
      'UNKNOWN_VALUE', 'FIELD',
    );
    expectRejection(
      () => validateWorkerRequest(request('RECONCILE_INDETERMINATE',
        { reconciliationRef: 'x'.repeat(B.MAX_STRING_CHARS + 1) })),
      'VALUE_OUT_OF_RANGE', 'FIELD',
    );
  });

  test('rejects a non-object, array or view input', () => {
    for (const input of [null, 7, 'x', [], new Uint8Array(1)]) {
      expectRejection(() => validateWorkerRequest({ ...base, input }), 'INVALID_REQUEST', 'FIELD');
    }
  });

  test('rejects a non-plain message outright and classifies it as null', () => {
    for (const value of [null, 7, 'x', [], new Uint8Array(1), new Date(0), new Map()]) {
      expectRejection(() => validateWorkerRequest(value), 'INVALID_REQUEST', 'FIELD');
      expect(classifyWorkerMessage(value)).toBeNull();
      expectRejection(() => validateWorkerMessage(value), 'INVALID_REQUEST', 'FIELD');
      expectRejection(() => toWireBytes(value), 'INVALID_REQUEST', 'FIELD');
    }
  });
});

describe('negative grammar: closed result fields', () => {
  test('rejects every unrecognized result field', () => {
    for (const field of ['input', 'error', 'epoch', 'kindOverride', 'success']) {
      if (field in SUCCESS_RESULT) continue;
      expectRejection(() => validateWorkerResult({ ...SUCCESS_RESULT, [field]: 1 }), 'UNKNOWN_FIELD', 'FIELD');
    }
    for (const field of ['$$', '__wbg_ptr', 'ptr']) {
      expectRejection(() => validateWorkerResult({ ...SUCCESS_RESULT, [field]: 1 }),
        'INVALID_REQUEST', 'FIELD');
    }
  });

  test('rejects a member that belongs to a different kind', () => {
    expectRejection(() => validateWorkerResult({ ...NO_CHANGE_RESULT, output: {} }), 'UNKNOWN_FIELD', 'FIELD');
    expectRejection(() => validateWorkerResult({ ...REJECTED_RESULT, successCode: 'CREATED' }),
      'UNKNOWN_FIELD', 'FIELD');
    expectRejection(() => validateWorkerResult({ ...NOT_COMMITTED_RESULT, successCode: 'CREATED' }),
      'UNKNOWN_FIELD', 'FIELD');
    expectRejection(() => validateWorkerResult({ ...INDETERMINATE_RESULT, output: {} }),
      'UNKNOWN_FIELD', 'FIELD');
    expectRejection(() => validateWorkerResult({ ...SUCCESS_RESULT, error: { code: 'INVALID_REQUEST' } }),
      'UNKNOWN_FIELD', 'FIELD');
  });

  test('rejects every missing required member of every kind', () => {
    const required = {
      SUCCESS: ['successCode'],
      NO_CHANGE: ['successCode'],
      NOT_COMMITTED: ['commitOutcome'],
      INDETERMINATE: ['commitOutcome', 'reconciliationRef', 'originalStateBefore'],
      REJECTED: ['error'],
    };
    for (const [kind, value] of RESULTS) {
      for (const field of required[kind]) {
        const copy = { ...value };
        delete copy[field];
        expectRejection(() => validateWorkerResult(copy), 'INVALID_REQUEST', 'FIELD');
      }
      for (const field of ['api', 'requestId', 'operation', 'kind', 'stateBefore', 'stateAfter']) {
        const copy = { ...value };
        delete copy[field];
        expectRejection(() => validateWorkerResult(copy), 'INVALID_REQUEST', 'FIELD');
      }
    }
  });

  test('rejects an unknown kind', () => {
    for (const kind of ['OK', 'success', 'SUCCESS ', 'COMMITTED', 7, null]) {
      expectRejection(() => validateWorkerResult({ ...SUCCESS_RESULT, kind }), 'UNKNOWN_VALUE', 'STATE');
    }
  });

  test('rejects an unknown state on either side', () => {
    expectRejection(() => validateWorkerResult({ ...SUCCESS_RESULT, stateBefore: 'INIT' }),
      'UNKNOWN_VALUE', 'STATE');
    expectRejection(() => validateWorkerResult({ ...SUCCESS_RESULT, stateAfter: 'INIT' }),
      'UNKNOWN_VALUE', 'STATE');
    expectRejection(() => validateWorkerResult({ ...SUCCESS_RESULT, stateBefore: ['EMPTY'] }),
      'UNKNOWN_VALUE', 'STATE');
    expectRejection(() => validateWorkerResult({ ...SUCCESS_RESULT, stateAfter: null }),
      'UNKNOWN_VALUE', 'STATE');
  });

  test('rejects a kind that disagrees with the code C-API assigns', () => {
    expectRejection(() => validateWorkerResult({ ...SUCCESS_RESULT, successCode: 'DUPLICATE_IGNORED' }),
      'UNKNOWN_VALUE', 'STATE');
    expectRejection(() => validateWorkerResult({ ...NO_CHANGE_RESULT, successCode: 'CREATED' }),
      'UNKNOWN_VALUE', 'STATE');
    expectRejection(() => validateWorkerResult({ ...REJECTED_RESULT, error: { code: 'CREATED' } }),
      'UNKNOWN_VALUE', 'STATE');
    expectRejection(() => validateWorkerResult({ ...REJECTED_RESULT, error: { code: 'INDETERMINATE' } }),
      'UNKNOWN_VALUE', 'STATE');
    expectRejection(() => validateWorkerResult({ ...SUCCESS_RESULT, successCode: 'NOT_COMMITTED' }),
      'UNKNOWN_VALUE', 'STATE');
  });

  test('rejects a commitOutcome that contradicts the kind', () => {
    expectRejection(() => validateWorkerResult({ ...NOT_COMMITTED_RESULT, commitOutcome: 'COMMITTED' }),
      'UNKNOWN_VALUE', 'STATE');
    expectRejection(() => validateWorkerResult({ ...INDETERMINATE_RESULT, commitOutcome: 'NOT_COMMITTED' }),
      'UNKNOWN_VALUE', 'STATE');
    expectRejection(() => validateWorkerResult({ ...SUCCESS_RESULT, commitOutcome: 'NOT_COMMITTED' }),
      'UNKNOWN_VALUE', 'STATE');
    expectRejection(() => validateWorkerResult({ ...SUCCESS_RESULT, commitOutcome: 'PENDING' }),
      'UNKNOWN_VALUE', 'STATE');
  });

  test('rejects an output whose keys are not exactly the assigned set', () => {
    expectRejection(() => validateWorkerResult({
      ...SUCCESS_RESULT, output: { protectedApplicationBytes: bytes(1) },
    }), 'UNKNOWN_FIELD', 'FIELD');
    expectRejection(() => validateWorkerResult({
      ...SUCCESS_RESULT, output: { embeddedTreeWelcome: bytes(1), extra: bytes(2) },
    }), 'UNKNOWN_FIELD', 'FIELD');
    expectRejection(() => validateWorkerResult({ ...SUCCESS_RESULT, output: {} }),
      'INVALID_REQUEST', 'FIELD');
    expectRejection(() => validateWorkerResult({ ...NO_CHANGE_RESULT, output: {} }),
      'UNKNOWN_FIELD', 'FIELD');
    expectRejection(() => validateWorkerResult({ ...SUCCESS_RESULT, output: [] }),
      'INVALID_REQUEST', 'FIELD');
  });

  test('rejects a nested originalOutput that is not closed for a held original code', () => {
    expectRejection(() => validateWorkerResult(result('SUCCESS', {
      successCode: 'RECONCILED_COMMITTED',
      output: { originalSuccessCode: 'CREATED', originalOutput: {} },
    })), 'INVALID_REQUEST', 'FIELD');
    expectRejection(() => validateWorkerResult(result('SUCCESS', {
      successCode: 'RECONCILED_COMMITTED',
      output: { originalSuccessCode: 'CREATED', originalOutput: { extra: bytes(1) } },
    })), 'UNKNOWN_FIELD', 'FIELD');
    expectRejection(() => validateWorkerResult(result('SUCCESS', {
      successCode: 'RECONCILED_COMMITTED',
      output: { originalSuccessCode: 'RESTORED', originalOutput: { extra: bytes(1) } },
    })), 'UNKNOWN_FIELD', 'FIELD');
    expect(validateWorkerResult(result('SUCCESS', {
      successCode: 'RECONCILED_COMMITTED',
      output: { originalSuccessCode: 'RESTORED', originalOutput: {} },
    })).output.originalSuccessCode).toBe('RESTORED');
    expectRejection(() => validateWorkerResult(result('SUCCESS', {
      successCode: 'RECONCILED_COMMITTED',
      output: { originalSuccessCode: 'NOT_A_CODE', originalOutput: {} },
    })), 'UNKNOWN_VALUE', 'STATE');
    expectRejection(() => validateWorkerResult(result('SUCCESS', {
      successCode: 'RECONCILED_COMMITTED',
      output: { originalSuccessCode: 'RECONCILED_COMMITTED', originalOutput: {} },
    })), 'UNKNOWN_VALUE', 'STATE');
    expectRejection(() => validateWorkerResult(result('SUCCESS', {
      successCode: 'RECONCILED_COMMITTED',
      output: { originalSuccessCode: 'RECONCILED_COMMITTED', originalOutput: {} },
    })), 'UNKNOWN_VALUE', 'STATE');
    expectRejection(() => validateWorkerResult(result('SUCCESS', {
      successCode: 'RECONCILED_COMMITTED',
      output: { originalSuccessCode: 'APPLICATION_OPENED' },
    })), 'INVALID_REQUEST', 'FIELD');
  });

  test('a held original code is any /successCodeEnum member but RECONCILED_COMMITTED', () => {
    // The contract: "`originalSuccessCode` is in `/successCodeEnum` and must not be
    // `RECONCILED_COMMITTED`". The module implements exactly that and records, without
    // enforcing it, that only the seven RS_TRI_STATE decision-row dispositions can
    // physically be held.
    const outputFor = {
      CREATED: { embeddedTreeWelcome: bytes(1) },
      RESTORED: {},
      JOINED: {},
      APPLICATION_PROTECTED: { protectedApplicationBytes: bytes(2) },
      APPLICATION_OPENED: { applicationBytes: bytes(3) },
      SELF_UPDATED: { protectedCommitBytes: bytes(4) },
      PEER_UPDATE_APPLIED: {},
      CANDIDATE_SELECTED: { selectedCandidateRef: 'candidate:1' },
      DUPLICATE_IGNORED: {},
    };
    const held = M2_WORKER.SUCCESS_CODES.filter((code) => code !== 'RECONCILED_COMMITTED');
    expect(held).toHaveLength(M2_WORKER.SUCCESS_CODES.length - 1);
    // Every permitted held code is exercised, so none can be skipped silently.
    expect(Object.keys(outputFor).sort()).toEqual([...held].sort());
    for (const code of held) {
      const output = outputFor[code];
      const validated = validateWorkerResult(result('SUCCESS', {
        successCode: 'RECONCILED_COMMITTED',
        output: { originalSuccessCode: code, originalOutput: output },
      }));
      expect(validated.output.originalSuccessCode).toBe(code);
      expect(Object.keys(validated.output.originalOutput)).toEqual(Object.keys(output));
    }
    // RESTORED and DUPLICATE_IGNORED are permitted by the grammar even though no
    // C-API decision row can produce them; that is recorded for the owner.
    for (const code of ['RESTORED', 'DUPLICATE_IGNORED']) {
      expect(held).toContain(code);
    }
    for (const code of ['RECONCILED_COMMITTED', 'NOT_A_CODE']) {
      expectRejection(() => validateWorkerResult(result('SUCCESS', {
        successCode: 'RECONCILED_COMMITTED',
        output: { originalSuccessCode: code, originalOutput: {} },
      })), 'UNKNOWN_VALUE', 'STATE');
    }
  });

  test('accepts a reconciliation reference carried opaquely at the held depth', () => {
    const validated = validateWorkerResult(result('SUCCESS', {
      successCode: 'RECONCILED_COMMITTED',
      output: {
        originalSuccessCode: 'APPLICATION_OPENED',
        originalOutput: { applicationBytes: bytes(4, 4) },
      },
    }));
    expect(validated.output.originalSuccessCode).toBe('APPLICATION_OPENED');
    expect(validated.output.originalOutput.applicationBytes.length).toBe(4);
    expect(Array.from(validated.output.originalOutput.applicationBytes)).toEqual([4, 4, 4, 4]);
  });

  test('rejects a non-binary or empty output byte leaf', () => {
    expectRejection(() => validateWorkerResult({
      ...SUCCESS_RESULT, output: { embeddedTreeWelcome: 'x' },
    }), 'VALUE_OUT_OF_RANGE', 'FIELD');
    expectRejection(() => validateWorkerResult({
      ...SUCCESS_RESULT, output: { embeddedTreeWelcome: new Uint8Array(0) },
    }), 'VALUE_OUT_OF_RANGE', 'FIELD');
  });

  test('rejects an over-long string output leaf', () => {
    expectRejection(() => validateWorkerResult(result('SUCCESS', {
      successCode: 'CANDIDATE_SELECTED',
      output: { selectedCandidateRef: 'x'.repeat(B.MAX_STRING_CHARS + 1) },
    })), 'VALUE_OUT_OF_RANGE', 'FIELD');
  });

  test('rejects an unknown error code, an unknown detail tag and a malformed error shape', () => {
    expectRejection(() => validateWorkerResult({ ...REJECTED_RESULT, error: { code: 'BOOM' } }),
      'UNKNOWN_VALUE', 'STATE');
    expectRejection(() => validateWorkerResult({
      ...REJECTED_RESULT, error: { code: 'INVALID_REQUEST', detailTag: 'WHY' },
    }), 'UNKNOWN_VALUE', 'STATE');
    expectRejection(() => validateWorkerResult({
      ...REJECTED_RESULT, error: { code: 'INVALID_REQUEST', detailTag: 1 },
    }), 'UNKNOWN_VALUE', 'STATE');
    expectRejection(() => validateWorkerResult({ ...REJECTED_RESULT, error: { detailTag: 'FIELD' } }),
      'INVALID_REQUEST', 'FIELD');
    expectRejection(() => validateWorkerError({ code: 'INVALID_REQUEST', extra: 1 }), 'UNKNOWN_FIELD', 'FIELD');
    expectRejection(() => validateWorkerError({}), 'INVALID_REQUEST', 'FIELD');
    expectRejection(() => validateWorkerError('INVALID_REQUEST'), 'INVALID_REQUEST', 'FIELD');
  });

  test('rejects originalStateBefore outside its two-value domain', () => {
    expectRejection(() => validateWorkerResult({
      ...INDETERMINATE_RESULT, originalStateBefore: 'RECONCILIATION_REQUIRED',
    }), 'UNKNOWN_VALUE', 'STATE');
  });

  test('rejects an empty or unbounded reconciliationRef result member', () => {
    expectRejection(() => validateWorkerResult({ ...INDETERMINATE_RESULT, reconciliationRef: '' }),
      'UNKNOWN_VALUE', 'FIELD');
    expectRejection(() => validateWorkerResult({
      ...INDETERMINATE_RESULT, reconciliationRef: 'x'.repeat(B.MAX_STRING_CHARS + 1),
    }), 'VALUE_OUT_OF_RANGE', 'FIELD');
  });

  test('rejects a wrong requestId, operation or api on a result', () => {
    expectRejection(() => validateWorkerResult({ ...SUCCESS_RESULT, requestId: '' }), 'INVALID_REQUEST', 'FIELD');
    expectRejection(() => validateWorkerResult({ ...SUCCESS_RESULT, operation: 'RESET' }),
      'UNSUPPORTED_OPERATION', 'STATE');
    expectRejection(() => validateWorkerResult({ ...SUCCESS_RESULT, api: 'other/v1' }),
      'UNSUPPORTED_API_VERSION', 'PROFILE');
  });
});

describe('bounds', () => {
  test('the bounds object holds exactly the selected limits', () => {
    expect(B).toEqual({
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
  });

  test('the closed grammar itself caps recursion at the held original code', () => {
    // The only recursive member is originalOutput, and originalSuccessCode may not
    // itself be RECONCILED_COMMITTED, so an encoding cannot nest beyond one level:
    // the second level sees a foreign member. The `MAX_DEPTH` limit proper is
    // exercised below through assertWireSafe, which sweeps the caller's value.
    let nested = {};
    for (let index = 0; index < B.MAX_DEPTH; index += 1) {
      nested = { originalSuccessCode: 'CREATED', originalOutput: nested };
    }
    expectRejection(() => validateWorkerResult(result('SUCCESS', {
      successCode: 'RECONCILED_COMMITTED', output: nested,
    })), 'UNKNOWN_FIELD', 'FIELD');
  });

  test('an over-limit message is rejected before it is parsed', () => {
    expectRejection(() => fromWireBytes(new Uint8Array(B.MAX_MESSAGE_BYTES + 1)),
      'VALUE_OUT_OF_RANGE', 'FIELD');
  });

  test('the bounds pass runs before the closed-object grammar', () => {
    // The bounds pass runs first, so an over-limit value is `VALUE_OUT_OF_RANGE` even
    // when it sits under a member the grammar would refuse for another reason. A member
    // that is merely foreign, with a valid wire value, still reaches the grammar and is
    // `UNKNOWN_FIELD`, and so does a foreign member holding an opaque value.
    expectRejection(() => assertWireSafe({ ...request('RESTORE', {}), input: [] }),
      'INVALID_REQUEST', 'FIELD');
    expectRejection(() => assertWireSafe({ ...request('RESTORE', {}), extra: 1 }),
      'UNKNOWN_FIELD', 'FIELD');
    expectRejection(() => assertWireSafe({ ...request('RESTORE', {}), extra: () => 1 }),
      'UNKNOWN_FIELD', 'FIELD');
    expectRejection(() => assertWireSafe({ ...result('REJECTED', { error: { code: 'INVALID_REQUEST' } }),
      output: [] }), 'UNKNOWN_FIELD', 'FIELD');
  });

  test('MAX_BINDING_REF_BYTES, MAX_OPAQUE_BYTES and MAX_STRING_CHARS are VALUE_OUT_OF_RANGE', () => {
    expectRejection(() => validateWorkerRequest(request('RESTORE', {}, {
      bindingRef: bytes(1, B.MAX_BINDING_REF_BYTES + 1),
    })), 'VALUE_OUT_OF_RANGE', 'BINDING');
    expectRejection(() => validateWorkerRequest(request('CREATE', {
      peerFramedKeyPackage: bytes(1, B.MAX_OPAQUE_BYTES + 1),
    })), 'VALUE_OUT_OF_RANGE', 'FIELD');
    expectRejection(() => validateWorkerRequest(request('RECONCILE_INDETERMINATE', {
      reconciliationRef: 'x'.repeat(B.MAX_STRING_CHARS + 1),
    })), 'VALUE_OUT_OF_RANGE', 'FIELD');
  });
});

describe('opaque values have no representation on this boundary', () => {
  test.each(opaqueValues())('a %s is refused in every allowed member shape', (name, value) => {
    expectRejection(() => validateWorkerRequest({
      ...request('RESTORE', {}), requestId: value,
    }), 'INVALID_REQUEST', 'FIELD');
    const shared = name === 'shared-view';
    expectRejection(() => validateWorkerRequest({
      ...request('RESTORE', {}), bindingRef: value,
    }), shared ? 'INVALID_REQUEST' : 'VALUE_OUT_OF_RANGE', 'BINDING');
    expectRejection(() => validateWorkerRequest(
      request('RECONCILE_INDETERMINATE', { reconciliationRef: value }),
    ), 'UNKNOWN_VALUE', 'FIELD');
    expectRejection(() => validateWorkerRequest({
      ...request('RESTORE', {}), input: value,
    }), 'INVALID_REQUEST', 'FIELD');
    expectRejection(() => validateWorkerResult({ ...SUCCESS_RESULT, kind: value }),
      'UNKNOWN_VALUE', 'STATE');
    expectRejection(() => validateWorkerResult({ ...SUCCESS_RESULT, output: value }),
      'INVALID_REQUEST', 'FIELD');
  });

  test.each(opaqueValues())('a %s is refused as an unrecognized field too', (name, value) => {
    expectRejection(() => validateWorkerRequest({ ...request('RESTORE', {}), extra: value }),
      'UNKNOWN_FIELD', 'FIELD');
    expectRejection(() => validateWorkerResult({ ...SUCCESS_RESULT, extra: value }),
      'UNKNOWN_FIELD', 'FIELD');
    expectRejection(() => toWireBytes({ ...request('RESTORE', {}), extra: value }),
      'UNKNOWN_FIELD', 'FIELD');
  });

  test('a real CryptoKey is refused where the platform defines the type', async () => {
    if (typeof CryptoKey === 'undefined' || typeof globalThis.crypto?.subtle === 'undefined') return;
    const key = await globalThis.crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 128 }, false, ['encrypt'],
    );
    expect(key instanceof CryptoKey).toBe(true);
    expectRejection(() => validateWorkerRequest({ ...request('RESTORE', {}), bindingRef: key }),
      'VALUE_OUT_OF_RANGE', 'BINDING');
    expectRejection(() => validateWorkerRequest({ ...request('RESTORE', {}), requestId: key }),
      'INVALID_REQUEST', 'FIELD');
    expectRejection(() => validateWorkerResult({ ...SUCCESS_RESULT, output: key }),
      'INVALID_REQUEST', 'FIELD');
    expectRejection(() => toWireBytes({ ...request('RESTORE', {}), extra: key }), 'UNKNOWN_FIELD', 'FIELD');
  });

  test('no field accepts key material under any name', () => {
    for (const field of ['keyBytes', 'rawKey', 'secret', 'privateKey', 'keyPackage', 'encryptionKey',
      'signaturePrivateKey', 'handle', 'cryptoKey', 'key', 'material']) {
      expectRejection(() => validateWorkerRequest({ ...request('RESTORE', {}), [field]: bytes(1) }),
        'UNKNOWN_FIELD', 'FIELD');
      expectRejection(() => validateWorkerResult({ ...SUCCESS_RESULT, [field]: bytes(1) }),
        'UNKNOWN_FIELD', 'FIELD');
      expectRejection(() => validateWorkerError({ [field]: bytes(1) }), 'UNKNOWN_FIELD', 'FIELD');
    }
    // The two handle-pointer names are refused even earlier, as forbidden own keys.
    for (const field of ['ptr', '__wbg_ptr']) {
      expectRejection(() => validateWorkerRequest({ ...request('RESTORE', {}), [field]: bytes(1) }),
        'INVALID_REQUEST', 'FIELD');
      expectRejection(() => validateWorkerResult({ ...SUCCESS_RESULT, [field]: bytes(1) }),
        'INVALID_REQUEST', 'FIELD');
    }
  });

  test('an accessor, a symbol key or a non-enumerable property is refused', () => {
    const accessor = request('RESTORE', {});
    Object.defineProperty(accessor, 'requestId', { get: () => 'req-0001', enumerable: true });
    expectRejection(() => validateWorkerRequest(accessor), 'INVALID_REQUEST', 'FIELD');

    const hidden = request('RESTORE', {});
    Object.defineProperty(hidden, 'keyBytes', { value: bytes(1), enumerable: false });
    expectRejection(() => validateWorkerRequest(hidden), 'INVALID_REQUEST', 'FIELD');

    const symbolised = request('RESTORE', {});
    symbolised[Symbol('key')] = bytes(1);
    expectRejection(() => validateWorkerRequest(symbolised), 'INVALID_REQUEST', 'FIELD');

    const resultAccessor = { ...NO_CHANGE_RESULT };
    Object.defineProperty(resultAccessor, 'successCode', {
      get: () => 'DUPLICATE_IGNORED', enumerable: true,
    });
    expectRejection(() => validateWorkerResult(resultAccessor), 'INVALID_REQUEST', 'FIELD');
  });

  test('a cycle is refused rather than walked forever', () => {
    const cyclic = request('RESTORE', {});
    cyclic.input.self = cyclic.input;
    expectRejection(() => validateWorkerRequest(cyclic), 'UNKNOWN_FIELD', 'FIELD');
    const cyclicResult = { ...NO_CHANGE_RESULT };
    cyclicResult.output = cyclicResult;
    expectRejection(() => validateWorkerResult(cyclicResult), 'UNKNOWN_FIELD', 'FIELD');
  });

  test('the error carries no input detail and no field name', () => {
    const secret = 'SUPER-SECRET-KEY-MATERIAL';
    const error = thrown(() => validateWorkerRequest({ ...request('RESTORE', {}), keyBytes: secret }));
    expect(error).toBeInstanceOf(M2WorkerError);
    expect(error.message).toBe('UNKNOWN_FIELD');
    expect(error.message).not.toContain(secret);
    expect(Object.keys(error).sort()).toEqual(['code', 'detailTag', 'name', 'valueFree']);
    expect(JSON.stringify(error)).not.toContain(secret);
    expect(Object.keys(error)).not.toContain('keyBytes');
  });
});

describe('wire encoding', () => {
  test.each([['request', request('CREATE', INPUT_FOR.CREATE)],
    ...RESULTS.map(([kind, value]) => [`result ${kind}`, value])])(
    'round-trips the %s byte for byte', (label, message) => {
      const encoded = toWireBytes(message);
      expect(encoded).toBeInstanceOf(Uint8Array);
      const decoded = fromWireBytes(encoded);
      expect(decoded).toEqual(validateWorkerMessage(message));
      expect(fromWireBytes(toWireBytes(decoded))).toEqual(decoded);
      expect(Array.from(toWireBytes(decoded))).toEqual(Array.from(encoded));
    },
  );

  test('encodes binary leaves with the reserved marker', () => {
    const encoded = new TextDecoder().decode(toWireBytes(request('RESTORE', {})));
    expect(encoded).toContain('"$bytes"');
    expect(encoded).not.toContain('"bindingRef":[8');
  });

  test('refuses a field literally named $bytes at the envelope', () => {
    const canonical = new TextDecoder().decode(toWireBytes(request('RESTORE', {})));
    const tampered = canonical.replace(/^\{/, '{"$bytes":"AAAA",');
    expect(tampered).not.toEqual(canonical);
    expectRejection(() => fromWireBytes(new TextEncoder().encode(tampered)),
      'UNKNOWN_FIELD', 'FIELD');
  });

  test('refuses malformed bytes, non-bytes and over-limit input', () => {
    expectRejection(() => fromWireBytes('{}'), 'INVALID_REQUEST', 'FIELD');
    expectRejection(() => fromWireBytes(Uint8Array.of(0xff, 0xfe, 0xfd)), 'INVALID_REQUEST', 'FIELD');
    expectRejection(() => fromWireBytes(new TextEncoder().encode('not json')), 'INVALID_REQUEST', 'FIELD');
    expectRejection(() => fromWireBytes(new Uint8Array(0)), 'INVALID_REQUEST', 'FIELD');
  });

  test('a decoded payload must still satisfy the closed grammar', () => {
    const canonical = new TextDecoder().decode(toWireBytes(request('RESTORE', {})));
    const tampered = canonical.replace('"input":{}', '"input":{"$bytes":"AAAAAAAAAAA="}');
    expect(tampered).not.toEqual(canonical);
    expectRejection(() => fromWireBytes(new TextEncoder().encode(tampered)),
      'INVALID_REQUEST', 'FIELD');
    const foreign = canonical.replace('"input":{}', '"input":{"input":1}');
    expectRejection(() => fromWireBytes(new TextEncoder().encode(foreign)), 'UNKNOWN_FIELD', 'FIELD');
  });

  test('assertWireSafe returns the validated frozen message', () => {
    const safe = assertWireSafe(SUCCESS_RESULT);
    expect(Object.isFrozen(safe)).toBe(true);
    expect(safe).toEqual(validateWorkerResult(SUCCESS_RESULT));
  });
});

describe('seeded property sweep', () => {
  const scalar = fc.oneof(
    fc.constant(null),
    fc.boolean(),
    fc.integer({ min: -1000, max: 1000 }),
    fc.string({ maxLength: 12 }),
  );
  const anyValue = fc.letrec((tie) => ({
    value: fc.oneof(
      { maxDepth: 4, depthSize: 'small' },
      scalar,
      fc.array(tie('value'), { maxLength: 4 }),
      fc.dictionary(fc.string({ minLength: 1, maxLength: 6 }), tie('value'), { maxKeys: 4 }),
      fc.uint8Array({ maxLength: 8 }),
    ),
  })).value;

  test('an arbitrary value is accepted only as a closed kind, never with an open shape', () => {
    fc.assert(fc.property(anyValue, (value) => {
      const error = thrown(() => validateWorkerMessage(value));
      if (error !== null) {
        expect(error).toBeInstanceOf(M2WorkerError);
        expect(M2_WORKER.ERROR_CODES).toContain(error.code);
        expect(M2_WORKER.DETAIL_TAGS).toContain(error.detailTag);
        return true;
      }
      const kind = classifyWorkerMessage(value);
      expect(M2_WORKER.MESSAGE_KINDS).toContain(kind);
      expect(fromWireBytes(toWireBytes(value))).toEqual(validateWorkerMessage(value));
      return true;
    }), { ...ANALYTIC, numRuns: 400 });
  });

  test('every mutation of a valid message either validates or throws a closed error', () => {
    const mutate = (seed) => {
      const target = seed % 2 === 0 ? request('CREATE', INPUT_FOR.CREATE) : SUCCESS_RESULT;
      const keys = Reflect.ownKeys(target);
      const key = keys[seed % keys.length];
      const next = structuredClone(target);
      const choice = Math.floor(seed / keys.length) % 6;
      if (choice === 0) delete next[key];
      else if (choice === 1) next[`foreign${seed}`] = seed;
      else if (choice === 2) next[key] = Symbol('handle');
      else if (choice === 3) next[key] = () => seed;
      else if (choice === 4) next[key] = { nested: { deeper: { deepest: seed } } };
      else next[key] = null;
      return next;
    };
    fc.assert(fc.property(fc.integer({ min: 0, max: 1000000 }), (seed) => {
      const candidate = mutate(seed);
      const error = thrown(() => validateWorkerMessage(candidate));
      if (error !== null) {
        expect(error).toBeInstanceOf(M2WorkerError);
        expect(M2_WORKER.ERROR_CODES).toContain(error.code);
        expect(M2_WORKER.DETAIL_TAGS).toContain(error.detailTag);
        return true;
      }
      expect(fromWireBytes(toWireBytes(candidate))).toEqual(validateWorkerMessage(candidate));
      return true;
    }), ANALYTIC);
  });

  test('a mutated bindingRef is always either accepted or refused with a bounded reason', () => {
    fc.assert(fc.property(fc.uint8Array({ minLength: 0, maxLength: 4097 }), (bindingRef) => {
      const error = thrown(() => validateWorkerRequest({ ...request('RESTORE', {}), bindingRef }));
      if (bindingRef.length === 0 || bindingRef.length > B.MAX_BINDING_REF_BYTES) {
        expect(error).toBeInstanceOf(M2WorkerError);
        expect(error.code).toBe('VALUE_OUT_OF_RANGE');
        expect(error.detailTag).toBe('BINDING');
        return true;
      }
      expect(error).toBeNull();
      return true;
    }), ANALYTIC);
  });

  test('canonical encoding is stable across equivalent rebuilds', () => {
    fc.assert(fc.property(fc.uint8Array({ minLength: 1, maxLength: 32 }), (payload) => {
      const left = toWireBytes(request('CREATE', { peerFramedKeyPackage: payload }));
      const right = toWireBytes(request('CREATE', {
        peerFramedKeyPackage: Uint8Array.from(payload),
      }));
      expect(Array.from(left)).toEqual(Array.from(right));
      expect(Array.from(fromWireBytes(left).input.peerFramedKeyPackage)).toEqual(Array.from(payload));
      return true;
    }), ANALYTIC);
  });
});

// The ratified O-SCEN scenario ids that bind the clause pointers this card
// implements. Generated by gen_scenario_table.py from
// M2-I-WORK-SCENARIO-MAPPING.json; the mapping matches by clause identity against
// the same clause registry O-SCEN derived from (sha256 dca7d92b…32cfc), so no
// content-token guesswork is involved. O-SCEN names no I-WORK identifier, so its
// owner reconciliation list stays OPEN and this card does not close it.
const SCENARIO_IDS = {
  '/profile': [
    'OSC-1cd3173a8d0d52bf', 'OSC-3d0ab107f2d76c19', 'OSC-3d3155950c9e5dce', 'OSC-4cf85dd6b70ef6d6',
    'OSC-535209f7230008ff', 'OSC-6ba7acf8b1c1f6ee', 'OSC-7ef76030cc0e9961', 'OSC-902c5a1f4709f544',
    'OSC-b1e08cba48935d8a', 'OSC-b28c0db8ec839cee', 'OSC-d42169b5c40b576a', 'OSC-dec7fa64138c6422',
    'OSC-eb6174b618c6b6cb',
  ],
  '/stateEnum': ['OSC-4f3aee29ce90e515', 'OSC-4fdb61c9157940c6', 'OSC-fe345e8b2cbf86a0'],
  '/operationEnum': [
    'OSC-0500d80b6edd43d3', 'OSC-3ebdc9b549cb083b', 'OSC-3ec84ecc3d97a9bb', 'OSC-c0044deacda4755c',
    'OSC-d091e02e83d3440f', 'OSC-e5eafaf7080ebadb', 'OSC-f25e07c2cfe9ef54', 'OSC-fd1692d4b0742c06',
  ],
  '/commitOutcomeEnum': ['OSC-06351931f9565a4f', 'OSC-b838434c7a3aca50', 'OSC-cb6c0a14b126b79d'],
  '/resultKindEnum': [
    'OSC-075f5520e0590d5c', 'OSC-3d9b7da2d4b40760', 'OSC-5a12253a1b94ba5c', 'OSC-9328985a79604cd9',
    'OSC-ed39d6a987385472',
  ],
  '/successCodeEnum': [
    'OSC-07f623df120e3185', 'OSC-11e5567a07066948', 'OSC-2c16d4de187cc4c7', 'OSC-35bc709df10f1678',
    'OSC-468ba4c368267b67', 'OSC-66ad56eda1ee122d', 'OSC-96f48e740ab1a1fb', 'OSC-eacfdc77b80c8a9f',
    'OSC-ef7ecc2413367875', 'OSC-f5228b30a34575bd',
  ],
  '/errorCodeEnum': [
    'OSC-063fc148c5c04141', 'OSC-0a2b86a4d9a82631', 'OSC-0b9e292740aa5a4f', 'OSC-0f07564a4d760568',
    'OSC-12279c4c75df3edf', 'OSC-1645969ce33304bc', 'OSC-3b06ac58d84b16eb', 'OSC-3c4f12b401aad67a',
    'OSC-43a45fcd05c5ec34', 'OSC-474416f91a5f4536', 'OSC-4b12bcf17ffa24f6', 'OSC-586c1d231b5c8008',
    'OSC-5b90530783018a77', 'OSC-6844abf9cf66be2b', 'OSC-69d537456a74ad7f', 'OSC-6b74356080755ec3',
    'OSC-771a222317da5140', 'OSC-8659e372e5836c35', 'OSC-9069cadd07ca854e', 'OSC-a085ba7e6260d7f1',
    'OSC-a99ab800bf228ea1', 'OSC-c70e41ad3bc5c2a3', 'OSC-cac04f870e530272', 'OSC-cd489d835b771f15',
    'OSC-f1c5d4ce4ea381e8',
  ],
  '/codeToResultKind': [
    'OSC-10e48bd21871e3ea', 'OSC-1657f97e7188028a', 'OSC-1b52765282159986', 'OSC-1f2bb6258d7ce675',
    'OSC-25242934bdd6ada6', 'OSC-2e491dff10c7033c', 'OSC-354dcdaff1f70a2e', 'OSC-390aa486bbfbab3b',
    'OSC-3f680f8750f81cf1', 'OSC-40889223667af929', 'OSC-4621a77987b57dfe', 'OSC-4a35f605fe18b4a1',
    'OSC-4addb8b8ac2df912', 'OSC-5ebf1c313821391a', 'OSC-6b26bea3a03cebc8', 'OSC-6dce17d6d6be15e5',
    'OSC-7eae050b0a74a6f8', 'OSC-84f20ffa1e94f592', 'OSC-8ae8b1a3906a9f71', 'OSC-8b30af2af9cfb39d',
    'OSC-952677fd636b2000', 'OSC-9b2d58abd5977e0d', 'OSC-9cda0c51a2eed7ca', 'OSC-ab6cf35c9b941722',
    'OSC-af6b40d35ad49c9d', 'OSC-b921ef10edae9564', 'OSC-bac934099642a48d', 'OSC-bb83d3f5d456d1dd',
    'OSC-beacf30e9803e7b5', 'OSC-c674b07f80aee1e4', 'OSC-cc89198a396c9326', 'OSC-cdfca40fd472b435',
    'OSC-d7dc6a8f3979ed1d', 'OSC-dac7a67b04490d26', 'OSC-ec27a4cc334ae142', 'OSC-f159789353f61495',
    'OSC-f8ff5f7899704255',
  ],
  '/request/closedObjects': ['OSC-c1e032420c68d1d0'],
  '/request/commonRequired': ['OSC-34717e0650a28b4c'],
  '/request/commonOptional': ['OSC-fb4395910e1fdfa1'],
  '/request/fieldSources': ['OSC-4ca49839a31c9dcf'],
  '/request/inputByOperation': ['OSC-ee1310a7fcd443b8'],
  '/request/derivedByOperation': ['OSC-50af871720d5f00c'],
  '/response/closedObjects': ['OSC-3c5dcaed0207d185'],
  '/response/commonRequired': ['OSC-b1a4b4e879fb2e12'],
  '/response/byKind': ['OSC-c99986582316e23c'],
  '/response/outputBySuccessCode': ['OSC-345d9f9fb61f4c7a'],
  '/response/errorShape': ['OSC-5db832538f6984b7'],
  '/response/valueDomains': ['OSC-5607d7e9474401de'],
  '/rules/closedObjects': ['OSC-a9bb2f1b3a69082e'],
  '/rules/derivedFacts': ['OSC-9ebe2108b66fc218'],
  '/rules/tupleDrift': ['OSC-f059cf9976ae30d3'],
  '/rules/singleWriter': ['OSC-7e009f23be2707b5'],
  '/rules/payloadRelease': ['OSC-ab20fdebafb24483'],
  '/rules/rsTriState': ['OSC-f4eb5de98aefe7dc'],
  '/rules/internalFailureBoundary': ['OSC-c614c21efa1f19d6'],
};

/** One probe per pointer: exercises the bound clause so its scenario can fail. */
const SCENARIO_PROBE = {
  '/profile': () => {
    expect(Object.keys(validateWorkerRequest(request('RESTORE', {})).profile)).toHaveLength(13);
    expectRejection(() => validateWorkerRequest({
      ...request('RESTORE', {}), profile: { ...M2_WORKER.PROFILE, topology: 'three-member' },
    }), 'UNSUPPORTED_PROFILE', 'PROFILE');
  },
  '/stateEnum': () => {
    for (const state of STATES) {
      expect(validateWorkerResult(result('NO_CHANGE', { successCode: 'DUPLICATE_IGNORED' },
        { stateBefore: state, stateAfter: state })).stateBefore).toBe(state);
    }
    expectRejection(() => validateWorkerResult({ ...NO_CHANGE_RESULT, stateAfter: 'MIXED' }),
      'UNKNOWN_VALUE', 'STATE');
  },
  '/operationEnum': () => {
    for (const operation of OPERATIONS) {
      expect(validateWorkerRequest(request(operation, INPUT_FOR[operation])).operation).toBe(operation);
    }
    expectRejection(() => validateWorkerRequest({ ...request('RESTORE', {}), operation: 'RESET' }),
      'UNSUPPORTED_OPERATION', 'STATE');
  },
  '/commitOutcomeEnum': () => {
    expect(validateWorkerResult(NOT_COMMITTED_RESULT).commitOutcome).toBe('NOT_COMMITTED');
    expect(validateWorkerResult(INDETERMINATE_RESULT).commitOutcome).toBe('INDETERMINATE');
    expectRejection(() => validateWorkerResult({ ...NOT_COMMITTED_RESULT, commitOutcome: 'MAYBE' }),
      'UNKNOWN_VALUE', 'STATE');
  },
  '/resultKindEnum': () => {
    for (const [kind, value] of RESULTS) expect(validateWorkerResult(value).kind).toBe(kind);
    expectRejection(() => validateWorkerResult({ ...SUCCESS_RESULT, kind: 'OK' }), 'UNKNOWN_VALUE', 'STATE');
  },
  '/successCodeEnum': () => {
    expect(validateWorkerResult(SUCCESS_RESULT).successCode).toBe('CREATED');
    expect(validateWorkerResult(NO_CHANGE_RESULT).successCode).toBe('DUPLICATE_IGNORED');
    expectRejection(() => validateWorkerResult({ ...SUCCESS_RESULT, successCode: 'DONE' }),
      'UNKNOWN_VALUE', 'STATE');
  },
  '/errorCodeEnum': () => {
    expect(validateWorkerError({ code: 'FAIL_CLOSED_INTERNAL' }).code).toBe('FAIL_CLOSED_INTERNAL');
    expectRejection(() => validateWorkerError({ code: 'BOOM' }), 'UNKNOWN_VALUE', 'STATE');
  },
  '/codeToResultKind': () => {
    for (const code of M2_WORKER.SUCCESS_CODES) {
      expect(['SUCCESS', 'NO_CHANGE']).toContain(M2_WORKER.CODE_TO_KIND[code]);
    }
    expectRejection(() => validateWorkerResult({ ...SUCCESS_RESULT, successCode: 'DUPLICATE_IGNORED' }),
      'UNKNOWN_VALUE', 'STATE');
  },
  '/request/closedObjects': () => {
    expect(Object.keys(validateWorkerRequest(request('RESTORE', {}))).sort())
      .toEqual(['api', 'bindingRef', 'input', 'operation', 'profile', 'requestId']);
    expectRejection(() => validateWorkerRequest({ ...request('RESTORE', {}), extra: 1 }),
      'UNKNOWN_FIELD', 'FIELD');
  },
  '/request/commonRequired': () => {
    const copy = { ...request('RESTORE', {}) };
    delete copy.bindingRef;
    expectRejection(() => validateWorkerRequest(copy), 'INVALID_REQUEST', 'FIELD');
    expect(request('RESTORE', {})).toHaveProperty('input');
  },
  '/request/commonOptional': () => {
    expect(Object.keys(request('RESTORE', {}))).toHaveLength(6);
    expect(validateWorkerRequest(request('RESTORE', {}))).toBeTruthy();
  },
  '/request/fieldSources': () => {
    expect(validateWorkerRequest(request('RESTORE', {})).api).toBe(M2_WORKER.API);
    expectRejection(() => validateWorkerRequest({ ...request('RESTORE', {}), api: 'other/v1' }),
      'UNSUPPORTED_API_VERSION', 'PROFILE');
  },
  '/request/inputByOperation': () => {
    expect(Object.keys(validateWorkerRequest(request('CREATE', INPUT_FOR.CREATE)).input))
      .toEqual(['peerFramedKeyPackage']);
    expectRejection(
      () => validateWorkerRequest(request('RESTORE', { applicationBytes: bytes(1) })),
      'UNKNOWN_FIELD', 'FIELD',
    );
  },
  '/request/derivedByOperation': () => {
    expectRejection(
      () => validateWorkerRequest(request('CREATE', { ...INPUT_FOR.CREATE, profileFacts: 'x' })),
      'UNKNOWN_FIELD', 'FIELD',
    );
    expectRejection(
      () => validateWorkerRequest({ ...request('CREATE', INPUT_FOR.CREATE), committerIdentity: 'x' }),
      'UNKNOWN_FIELD', 'FIELD',
    );
  },
  '/response/closedObjects': () => {
    expect(Object.keys(validateWorkerResult(NO_CHANGE_RESULT)).sort())
      .toEqual(['api', 'kind', 'operation', 'requestId', 'stateAfter', 'stateBefore', 'successCode']);
    expectRejection(() => validateWorkerResult({ ...NO_CHANGE_RESULT, extra: 1 }),
      'UNKNOWN_FIELD', 'FIELD');
  },
  '/response/commonRequired': () => {
    const copy = { ...NOT_COMMITTED_RESULT };
    delete copy.stateAfter;
    expectRejection(() => validateWorkerResult(copy), 'INVALID_REQUEST', 'FIELD');
  },
  '/response/byKind': () => {
    expectRejection(() => validateWorkerResult({ ...NO_CHANGE_RESULT, output: {} }),
      'UNKNOWN_FIELD', 'FIELD');
    expectRejection(() => validateWorkerResult({
      ...REJECTED_RESULT, error: { code: 'CREATED' },
    }), 'UNKNOWN_VALUE', 'STATE');
  },
  '/response/outputBySuccessCode': () => {
    expect(Object.keys(validateWorkerResult(result('SUCCESS', {
      successCode: 'CANDIDATE_SELECTED', output: { selectedCandidateRef: 'candidate:1' },
    })).output)).toEqual(['selectedCandidateRef']);
    expectRejection(() => validateWorkerResult({ ...SUCCESS_RESULT, output: {} }),
      'INVALID_REQUEST', 'FIELD');
  },
  '/response/errorShape': () => {
    expect(Object.keys(validateWorkerResult(REJECTED_RESULT).error).sort()).toEqual(['code', 'detailTag']);
    expectRejection(() => validateWorkerError({ code: 'INVALID_REQUEST', detailTag: 'WHY' }),
      'UNKNOWN_VALUE', 'STATE');
  },
  '/response/valueDomains': () => {
    expect(validateWorkerResult(INDETERMINATE_RESULT).originalStateBefore).toBe('EMPTY');
    expectRejection(() => validateWorkerResult({
      ...INDETERMINATE_RESULT, originalStateBefore: 'RECONCILIATION_REQUIRED',
    }), 'UNKNOWN_VALUE', 'STATE');
  },
  '/rules/closedObjects': () => {
    expectRejection(() => validateWorkerRequest({ ...request('RESTORE', {}), keyBytes: bytes(1) }),
      'UNKNOWN_FIELD', 'FIELD');
    expectRejection(() => validateWorkerResult({ ...SUCCESS_RESULT, keyBytes: bytes(1) }),
      'UNKNOWN_FIELD', 'FIELD');
  },
  '/rules/derivedFacts': () => {
    for (const field of ['memberIdentity', 'replayIdentity', 'authenticationFacts', 'parentStateRef']) {
      expectRejection(() => validateWorkerRequest({ ...request('CREATE', INPUT_FOR.CREATE), [field]: 'x' }),
        'UNKNOWN_FIELD', 'FIELD');
    }
  },
  '/rules/tupleDrift': () => {
    for (const key of Object.keys(M2_WORKER.PROFILE)) {
      expectRejection(() => validateWorkerRequest({
        ...request('RESTORE', {}), profile: { ...M2_WORKER.PROFILE, [key]: 'drift' },
      }), 'UNSUPPORTED_PROFILE', 'PROFILE');
    }
  },
  '/rules/singleWriter': () => {
    // This card adds no writer arbitration; it only carries the requested id.
    expect(validateWorkerRequest({ ...request('RESTORE', {}), requestId: 'req-0002' }).requestId)
      .toBe('req-0002');
    expectRejection(() => validateWorkerRequest({ ...request('RESTORE', {}), requestId: 'a\nb' }),
      'INVALID_REQUEST', 'FIELD');
  },
  '/rules/payloadRelease': () => {
    // Outputs travel opaquely; this card asserts nothing about release timing.
    expect(validateWorkerResult(SUCCESS_RESULT).output.embeddedTreeWelcome.length).toBe(8);
    expectRejection(() => validateWorkerResult({ ...SUCCESS_RESULT, output: { embeddedTreeWelcome: 'x' } }),
      'VALUE_OUT_OF_RANGE', 'FIELD');
  },
  '/rules/rsTriState': () => {
    expect(validateWorkerResult(NOT_COMMITTED_RESULT).commitOutcome).toBe('NOT_COMMITTED');
    expect(validateWorkerResult(INDETERMINATE_RESULT).commitOutcome).toBe('INDETERMINATE');
    expectRejection(() => validateWorkerResult({ ...SUCCESS_RESULT, commitOutcome: 'NOT_COMMITTED' }),
      'UNKNOWN_VALUE', 'STATE');
  },
  '/rules/internalFailureBoundary': () => {
    expect(validateWorkerError({ code: 'FAIL_CLOSED_INTERNAL', detailTag: 'INTERNAL' }).detailTag)
      .toBe('INTERNAL');
    expectRejection(() => validateWorkerError({ code: 'FAIL_CLOSED_INTERNAL', detailTag: 'INTERNAL', x: 1 }),
      'UNKNOWN_FIELD', 'FIELD');
  },
};

describe('review corrections: totality, decoding and the published metadata', () => {
  test('a revoked or throwing proxy never escapes a raw engine exception', () => {
    const revoked = Proxy.revocable({}, {});
    revoked.revoke();
    const throwing = new Proxy({}, {
      getPrototypeOf: () => { throw new Error('trap'); },
      ownKeys: () => { throw new Error('trap'); },
      getOwnPropertyDescriptor: () => { throw new Error('trap'); },
      has: () => { throw new Error('trap'); },
    });
    for (const value of [revoked.proxy, throwing]) {
      expect(classifyWorkerMessage(value)).toBeNull();
      expectRejection(() => validateWorkerMessage(value), 'INVALID_REQUEST', 'FIELD');
      expectRejection(() => validateWorkerRequest(value), 'INVALID_REQUEST', 'FIELD');
      expectRejection(() => validateWorkerResult(value), 'INVALID_REQUEST', 'FIELD');
    }
    // A proxy that looks like a request but throws on inspection is still total.
    const trap = new Proxy(request('RESTORE', {}), {
      getOwnPropertyDescriptor: (target, key) => (
        key === 'api' ? (() => { throw new Error('trap'); })() : Reflect.getOwnPropertyDescriptor(target, key)
      ),
    });
    expectRejection(() => validateWorkerRequest(trap), 'INVALID_REQUEST', 'FIELD');
  });

  test('a typed array or buffer carries no own member other than its indices', () => {
    const carriers = [
      (blob) => { blob.__wbg_ptr = 1; return blob; },
      (blob) => { blob.ptr = 1; return blob; },
      (blob) => { blob.attached = () => {}; return blob; },
      (blob) => { blob.memory = new WebAssembly.Memory({ initial: 1 }); return blob; },
      (blob) => Object.defineProperty(blob, 'extra', { value: 1, enumerable: false }),
    ];
    for (const carrier of carriers) {
      const blob = bytes(9, 32);
      carrier(blob);
      // The field-level copy runs before the full sweep, so the tag is the field's.
      expectRejection(() => assertWireSafe({ ...request('RESTORE', {}), bindingRef: blob }),
        'INVALID_REQUEST', 'BINDING');
    }
    const buffer = new ArrayBuffer(8);
    Object.defineProperty(buffer, 'ptr', { value: 1, enumerable: false });
    // A raw `ArrayBuffer` is not a valid binding reference at all: the field takes a
    // `Uint8Array` view and a buffer is rejected before the wire sweep.
    expectRejection(() => assertWireSafe({ ...request('RESTORE', {}), bindingRef: buffer }),
      'VALUE_OUT_OF_RANGE', 'BINDING');
  });

  test('a decoded member named __proto__ is preserved and then rejected, never dropped', () => {
    const canonical = new TextDecoder().decode(toWireBytes(request('RESTORE', {})));
    const tampered = canonical.replace(/^\{/, '{"__proto__":1,');
    expectRejection(() => fromWireBytes(new TextEncoder().encode(tampered)),
      'UNKNOWN_FIELD', 'FIELD');
    // The same document through the direct validator, holding a real own member.
    const carrying = { ...request('RESTORE', {}) };
    Object.defineProperty(carrying, '__proto__', { value: 1, enumerable: true, configurable: true });
    expect(Object.getPrototypeOf(carrying)).toBe(Object.prototype);
    expectRejection(() => validateWorkerRequest(carrying), 'UNKNOWN_FIELD', 'FIELD');
  });

  test('a $bytes marker must be a base64 string and must own its object', () => {
    const canonical = new TextDecoder().decode(toWireBytes(request('RESTORE', {})));
    for (const replacement of ['null', '7', '{}', '[]', 'true']) {
      const tampered = canonical.replace(/\{"\$bytes":"[^"]*"\}/, `{"$bytes":${replacement}}`);
      expect(tampered).not.toEqual(canonical);
      expectRejection(() => fromWireBytes(new TextEncoder().encode(tampered)),
        'INVALID_REQUEST', 'FIELD');
    }
    const beside = canonical.replace('"bindingRef":{', '"bindingRef":{"$bytes":"AAAA","extra":1,');
    expectRejection(() => fromWireBytes(new TextEncoder().encode(beside)), 'UNKNOWN_FIELD', 'FIELD');
  });

  test('a deeply nested document is a closed rejection, not a stack overflow', () => {
    const open = `${'['.repeat(B.MAX_DEPTH + 8)}1${']'.repeat(B.MAX_DEPTH + 8)}`;
    expectRejection(() => fromWireBytes(new TextEncoder().encode(open)), 'VALUE_OUT_OF_RANGE', 'FIELD');
    const deepObject = `${'{"a":'.repeat(B.MAX_DEPTH + 8)}1${'}'.repeat(B.MAX_DEPTH + 8)}`;
    expectRejection(() => fromWireBytes(new TextEncoder().encode(deepObject)),
      'VALUE_OUT_OF_RANGE', 'FIELD');
    // Far deeper than the stack can recurse: still a closed rejection, whichever
    // of the two closed codes the parser and the depth bound produce.
    const enormous = `${'['.repeat(20000)}1${']'.repeat(20000)}`;
    const error = thrown(() => fromWireBytes(new TextEncoder().encode(enormous)));
    expect(error).toBeInstanceOf(M2WorkerError);
    expect(['VALUE_OUT_OF_RANGE', 'INVALID_REQUEST']).toContain(error.code);
    expect(error.valueFree).toBe(true);
  });

  test('a shared view cannot hide behind a forged own buffer property', () => {
    // The attack: a view whose *real* buffer is shared, with an own `buffer` data
    // property returning a normal `ArrayBuffer` to evade `value.buffer instanceof …`.
    const evading = new Uint8Array(new SharedArrayBuffer(32));
    Object.defineProperty(evading, 'buffer', { value: new ArrayBuffer(32), enumerable: false });
    const shared = new Uint8Array(new SharedArrayBuffer(32));
    for (const blob of [shared, evading]) {
      expectRejection(() => validateWorkerRequest(request('RESTORE', {}, { bindingRef: blob })),
        'INVALID_REQUEST', 'BINDING');
      expectRejection(() => assertWireSafe({ ...request('RESTORE', {}), bindingRef: blob }),
        'INVALID_REQUEST', 'BINDING');
      expectRejection(() => toWireBytes(request('RESTORE', {}, { bindingRef: blob })),
        'INVALID_REQUEST', 'BINDING');
    }
    // The reverse decoy — a normal view carrying an own property that claims a shared
    // buffer — carries an own member that is not one of its indices, so the field-level
    // copy refuses it exactly as the wire sweep does, instead of accepting it.
    const decoy = new Uint8Array(32);
    Object.defineProperty(decoy, 'buffer', { value: shared.buffer, enumerable: false });
    expectRejection(() => validateWorkerRequest(request('RESTORE', {}, { bindingRef: decoy })),
      'INVALID_REQUEST', 'BINDING');
    expectRejection(() => assertWireSafe({ ...request('RESTORE', {}), bindingRef: decoy }),
      'INVALID_REQUEST', 'BINDING');
  });

  test('a real encodeBindingV0 output travels as the binding reference', () => {
    const encoded = encodeBindingV0({
      localContextId: bytes(0x11, 32),
      secureSessionIdentity: bytes(0x22, 32),
    });
    expect(encoded).toHaveLength(389);
    const validated = validateWorkerRequest(request('RESTORE', {}, { bindingRef: encoded }));
    expect(validated.bindingRef).toHaveLength(389);
    expect(validated.bindingRef).not.toBe(encoded);
    expect(Array.from(validated.bindingRef)).toEqual(Array.from(encoded));
    // The validated copy is independent of the caller's array.
    encoded[0] ^= 0xff;
    expect(validated.bindingRef[0]).not.toBe(encoded[0]);
  });

  test('a byte-order mark and C1 control characters are not carried values', () => {
    const canonical = toWireBytes(request('RESTORE', {}));
    const withBom = new Uint8Array(canonical.length + 3);
    withBom.set([0xef, 0xbb, 0xbf], 0);
    withBom.set(canonical, 3);
    expectRejection(() => fromWireBytes(withBom), 'INVALID_REQUEST', 'FIELD');
    expectRejection(() => validateWorkerRequest({ ...request('RESTORE', {}), requestId: 'a\u0085b' }),
      'INVALID_REQUEST', 'FIELD');
    expectRejection(() => validateWorkerRequest({ ...request('RESTORE', {}), requestId: 'a\u009fb' }),
      'INVALID_REQUEST', 'FIELD');
  });

  test('M2_WORKER exposes exactly the closed members the contract names', () => {
    expect(Object.keys(M2_WORKER).sort()).toEqual([
      'API', 'BOUNDS', 'CODE_TO_KIND', 'COMMIT_OUTCOMES', 'DETAIL_TAGS', 'ERROR_CODES',
      'MESSAGE_KINDS', 'OPERATIONS', 'OUTPUT_BY_SUCCESS_CODE', 'PROFILE', 'PROTOCOL_VERSION',
      'RESULT_KINDS', 'STATES', 'SUCCESS_CODES',
    ]);
    expect(Object.isFrozen(M2_WORKER)).toBe(true);
  });
});

describe('ratified O-SCEN scenario mapping', () => {
  test('every mapped pointer has at least one ratified scenario and every probe exists', () => {
    const pointers = Object.keys(SCENARIO_IDS);
    expect(pointers).toHaveLength(27);
    expect(Object.keys(SCENARIO_PROBE).sort()).toEqual(pointers.slice().sort());
    for (const pointer of pointers) {
      expect(SCENARIO_IDS[pointer].length).toBeGreaterThan(0);
      expect(M2_WORKER).toBeTruthy();
    }
  });

  test('the union of cited ids is exactly the 123 applicable ratified scenarios', () => {
    const ids = new Set();
    for (const list of Object.values(SCENARIO_IDS)) for (const id of list) ids.add(id);
    expect(ids.size).toBe(123);
    for (const id of ids) expect(id).toMatch(/^OSC-[0-9a-f]{16}$/);
  });

  test('this card adds twenty items the ratified set cannot bind and closes nothing', () => {
    // The ten selected limits and the ten boundary/message-kind non-claims carry no
    // C-API pointer: O-SCEN was derived blind and names no I-WORK identifier, so the
    // owner reconciliation list of O-SCEN stays OPEN.
    expect(M2_WORKER.BOUNDS.MAX_MESSAGE_BYTES).toBe(4194304);
    expect(M2_WORKER.MESSAGE_KINDS).toHaveLength(6);
  });

  test.each(Object.entries(SCENARIO_IDS).flatMap(
    ([pointer, ids]) => ids.map((id) => [id, pointer]),
  ))('ratified O-SCEN %s discharges the clause bound at %s', (id, pointer) => {
    expect(id).toMatch(/^OSC-[0-9a-f]{16}$/);
    SCENARIO_PROBE[pointer]();
  });
});

// --- review corrections -----------------------------------------------------

describe('correction: only this module\'s own errors may escape', () => {
  const ENTRIES = [
    ['validateWorkerRequest', validateWorkerRequest],
    ['validateWorkerResult', validateWorkerResult],
    ['validateWorkerError', validateWorkerError],
    ['validateWorkerMessage', validateWorkerMessage],
    ['assertWireSafe', assertWireSafe],
    ['toWireBytes', toWireBytes],
    ['fromWireBytes', fromWireBytes],
  ];

  const hostileProxy = (thrown) => new Proxy({}, {
    getPrototypeOf() { throw thrown(); },
    getOwnPropertyDescriptor() { throw thrown(); },
    ownKeys() { throw thrown(); },
    has() { throw thrown(); },
    get() { throw thrown(); },
  });

  test('a proxy trap that throws an engine error yields INVALID_REQUEST, never the raw error', () => {
    for (const [name, entry] of ENTRIES) {
      for (const thrown of [() => new TypeError('x'), () => new RangeError('x'), () => 12345]) {
        const value = hostileProxy(thrown);
        const error = expectRejection(() => entry(value), 'INVALID_REQUEST', 'FIELD');
        expect(error.constructor).toBe(M2WorkerError);
      }
    }
  });

  test('a forged M2WorkerError never escapes with its open code or free text', () => {
    const forged = Object.create(M2WorkerError.prototype);
    forged.code = 'MALFORMED_BINDING';
    forged.detailTag = 'secret-detail-from-caller';
    forged.valueFree = false;
    expect(forged).toBeInstanceOf(M2WorkerError);
    const hostile = new Proxy({}, {
      getOwnPropertyDescriptor() { throw forged; },
    });
    for (const [, entry] of ENTRIES) {
      const error = expectRejection(() => entry(hostile), 'INVALID_REQUEST', 'FIELD');
      expect(error).not.toBe(forged);
      expect(error.valueFree).toBe(true);
    }
  });

  test('every entry point is total against proxies and exotic values', () => {
    const values = [
      hostileProxy(() => new Error('x')),
      new Proxy({}, { get() { throw 'a string'; } }),
      Object.create(null),
      new Proxy(Object.create(null), { ownKeys() { throw new URIError('x'); } }),
    ];
    for (const [name, entry] of ENTRIES) {
      for (const value of values) {
        let caught;
        try {
          entry(value);
        } catch (error) {
          caught = error;
        }
        expect([name, caught instanceof M2WorkerError]).toEqual([name, true]);
        expect(M2_WORKER.ERROR_CODES).toContain(caught.code);
        expect(M2_WORKER.DETAIL_TAGS).toContain(caught.detailTag);
        expect(caught.valueFree).toBe(true);
      }
    }
  });

  test('a shared buffer re-prototyped to ArrayBuffer is still shared', () => {
    const SharedCtor = typeof SharedArrayBuffer === 'undefined' ? null : SharedArrayBuffer;
    if (SharedCtor === null) return;
    const shared = new SharedCtor(8);
    Object.setPrototypeOf(shared, ArrayBuffer.prototype);
    // A re-prototyped shared buffer is still brand-checked as shared; the field takes a
    // `Uint8Array` view, so a raw buffer is VALUE_OUT_OF_RANGE/BINDING either way.
    expectRejection(() => validateWorkerRequest(request('RESTORE', {}, { bindingRef: shared })),
      'VALUE_OUT_OF_RANGE', 'BINDING');
    expectRejection(() => assertWireSafe(request('RESTORE', {}, { bindingRef: shared })),
      'VALUE_OUT_OF_RANGE', 'BINDING');
    const view = new Uint8Array(new SharedCtor(8));
    expectRejection(() => assertWireSafe(request('RESTORE', {}, { bindingRef: view })),
      'INVALID_REQUEST', 'BINDING');
    expectRejection(() => validateWorkerRequest(request('RESTORE', {}, { bindingRef: view })),
      'INVALID_REQUEST', 'BINDING');
  });

  test('a view whose own members are not its indices is refused by both entry points', () => {
    const decoy = bytes(0x5a, 8);
    Object.defineProperty(decoy, 'buffer', { value: new ArrayBuffer(8), enumerable: true });
    expectRejection(() => validateWorkerRequest(request('RESTORE', {}, { bindingRef: decoy })),
      'INVALID_REQUEST', 'BINDING');
    expectRejection(() => assertWireSafe(request('RESTORE', {}, { bindingRef: decoy })),
      'INVALID_REQUEST', 'BINDING');
    const handle = bytes(0x5a, 8);
    handle.__wbg_ptr = 7;
    expectRejection(() => validateWorkerRequest(request('RESTORE', {}, { bindingRef: handle })),
      'INVALID_REQUEST', 'BINDING');
  });
});

describe('correction: every numeric bound is observable through the wire entry points', () => {
  const restore = (overrides) => ({ ...request('RESTORE', {}), ...overrides });

  test('MAX_MESSAGE_BYTES rejects an over-limit document', () => {
    expectRejection(() => fromWireBytes(new Uint8Array(B.MAX_MESSAGE_BYTES + 1)),
      'VALUE_OUT_OF_RANGE', 'FIELD');
  });

  test('MAX_DEPTH rejects a nesting one level over the limit', () => {
    let value = 1;
    for (let index = 0; index < B.MAX_DEPTH + 1; index += 1) value = [value];
    expectRejection(() => assertWireSafe(restore({ input: value })),
      'VALUE_OUT_OF_RANGE', 'FIELD');
  });

  test('MAX_ARRAY_LENGTH rejects an array one element over the limit', () => {
    expectRejection(() => assertWireSafe(restore({ input: new Array(B.MAX_ARRAY_LENGTH + 1).fill(1) })),
      'VALUE_OUT_OF_RANGE', 'FIELD');
  });

  test('MAX_NODES rejects an object graph one node over the limit', () => {
    const value = Array.from({ length: B.MAX_NODES / 16 }, () => new Array(16).fill(1));
    expectRejection(() => assertWireSafe(restore({ input: value })),
      'VALUE_OUT_OF_RANGE', 'FIELD');
  });

  test('MAX_STRING_CHARS and MAX_REQUEST_ID_CHARS reject a string one character over', () => {
    expectRejection(() => assertWireSafe(restore({ input: { reason: 'x'.repeat(B.MAX_STRING_CHARS + 1) } })),
      'VALUE_OUT_OF_RANGE', 'FIELD');
    expectRejection(() => validateWorkerRequest(restore({ requestId: 'x'.repeat(B.MAX_REQUEST_ID_CHARS + 1) })),
      'VALUE_OUT_OF_RANGE', 'FIELD');
  });

  test('MAX_BINDING_REF_BYTES rejects a reference one byte over the limit', () => {
    expectRejection(() => validateWorkerRequest(
      request('RESTORE', {}, { bindingRef: bytes(0x11, B.MAX_BINDING_REF_BYTES + 1) }),
    ), 'VALUE_OUT_OF_RANGE', 'BINDING');
  });

  test('MAX_OPAQUE_BYTES rejects a leaf one byte over the limit', () => {
    expectRejection(() => assertWireSafe(restore({ input: { blob: bytes(0x11, B.MAX_OPAQUE_BYTES + 1) } })),
      'VALUE_OUT_OF_RANGE', 'FIELD');
  });

  test('MAX_TOTAL_OPAQUE_BYTES rejects a set of leaves one byte over the total', () => {
    const leaf = bytes(0x11, B.MAX_OPAQUE_BYTES);
    const leaves = new Array(Math.floor(B.MAX_TOTAL_OPAQUE_BYTES / B.MAX_OPAQUE_BYTES) + 1).fill(leaf);
    expectRejection(() => assertWireSafe(restore({ input: leaves })),
      'VALUE_OUT_OF_RANGE', 'FIELD');
  });

  test('MAX_BINARY_LEAVES rejects one leaf over the limit', () => {
    const leaves = Array.from({ length: B.MAX_BINARY_LEAVES + 1 }, () => bytes(0x11, 1));
    expectRejection(() => assertWireSafe(restore({ input: leaves })),
      'VALUE_OUT_OF_RANGE', 'FIELD');
  });

  test('WebAssembly.Instance and WebAssembly.Table are refused wherever they appear', () => {
    if (typeof WebAssembly === 'undefined' || typeof WebAssembly.Table !== 'function') return;
    const module = new WebAssembly.Module(Uint8Array.of(0, 97, 115, 109, 1, 0, 0, 0));
    const opaque = [
      ['instance', new WebAssembly.Instance(module)],
      ['table', new WebAssembly.Table({ element: 'anyfunc', initial: 1 })],
    ];
    for (const [, value] of opaque) {
      expectRejection(() => validateWorkerRequest(request('RESTORE', {}, { bindingRef: value })),
        'VALUE_OUT_OF_RANGE', 'BINDING');
      expectRejection(() => validateWorkerRequest(
        request('PROTECT_APPLICATION', { applicationBytes: value }),
      ), 'VALUE_OUT_OF_RANGE', 'FIELD');
      expectRejection(() => assertWireSafe({ ...request('RESTORE', {}, { bindingRef: value }) }),
        'VALUE_OUT_OF_RANGE', 'BINDING');
      expectRejection(() => assertWireSafe({ ...request('RESTORE', {}), extra: value }),
        'UNKNOWN_FIELD', 'FIELD');
    }
  });

  test('the copied profile agrees with the merged m2-binding-v0 profile bytes', async () => {
    const binding = await import('../../../src/crypto/m2-binding-v0.js');
    const decoded = binding.decodeBindingV0(binding.encodeBindingV0({
      localContextId: bytes(0x11, 32),
      secureSessionIdentity: bytes(0x22, 32),
    }));
    // Recover the 13 framed profile fields from the adapter's own wire bytes.
    const profile = decoded.productProfile;
    const text = (part) => String.fromCharCode(...part);
    const hex = (part) => Array.from(part).map((byte) => byte.toString(16).padStart(2, '0')).join('');
    const be = (part) => part.reduce((total, byte) => (total * 256) + byte, 0);
    const read = [];
    for (let offset = 0; offset < profile.length;) {
      const tag = profile[offset];
      const length = (profile[offset + 1] << 8) | profile[offset + 2];
      read.push([tag, profile.slice(offset + 3, offset + 3 + length)]);
      offset += 3 + length;
    }
    expect(read.map(([tag]) => tag)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]);
    const values = read.map(([, value]) => value);
    const keys = Object.keys(M2_WORKER.PROFILE);
    expect(keys).toHaveLength(13);
    expect(M2_WORKER.PROFILE[keys[0]]).toBe(text(values[0]));
    expect(M2_WORKER.PROFILE[keys[1]]).toBe(text(values[1]));
    expect(M2_WORKER.PROFILE[keys[2]]).toBe(text(values[2]));
    expect(M2_WORKER.PROFILE[keys[3]]).toBe(text(values[3]));
    expect(M2_WORKER.PROFILE[keys[4]]).toBe(text(values[4]));
    expect(M2_WORKER.PROFILE[keys[5]]).toBe(text(values[5]));
    expect(M2_WORKER.PROFILE[keys[6]]).toBe(hex(values[6]));
    expect(M2_WORKER.PROFILE[keys[7]]).toBe(text(values[7]));
    expect(M2_WORKER.PROFILE[keys[8]]).toBe(hex(values[8]));
    expect(M2_WORKER.PROFILE[keys[9]]).toBe(`0x${be(values[9]).toString(16).padStart(4, '0')}`);
    expect(M2_WORKER.PROFILE[keys[10]]).toBe(text(values[10]));
    expect(M2_WORKER.PROFILE[keys[11]]).toBe(hex(values[11]));
    expect(M2_WORKER.PROFILE[keys[12]]).toBe(be(values[12]));
  });

  test('every accepted message round-trips through the canonical encoding', () => {
    const messages = [
      ...M2_WORKER.OPERATIONS.map((operation) => request(operation, INPUT_FOR[operation])),
      SUCCESS_RESULT,
      result('SUCCESS', { successCode: 'CREATED', output: { embeddedTreeWelcome: bytes(0x22, 4) } }),
      NO_CHANGE_RESULT,
      NOT_COMMITTED_RESULT,
      INDETERMINATE_RESULT,
      REJECTED_RESULT,
    ];
    for (const message of messages) {
      const decoded = fromWireBytes(toWireBytes(message));
      expect(decoded).toEqual(assertWireSafe(message));
      expect(fromWireBytes(toWireBytes(decoded))).toEqual(decoded);
    }
  });
});
