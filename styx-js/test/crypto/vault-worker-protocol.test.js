// vault-worker-protocol.test.js — closed-world protocol v1, worker errors,
// verified KDF loader and worker runtime (PR-3, mandate §19). All inputs are
// hostile until proven otherwise; all secrets are synthetic.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  MESSAGE_TYPES, ACTIVE_TYPES, MAX_WIRE_BYTES, MAX_WIRE_DEPTH, MAX_WIRE_NODES,
  MAX_WIRE_ARRAY_LENGTH,
  validateWireValue, validateRequestEnvelope, validateResponseEnvelope,
  extractEnvelopeId, buildResultResponse,
} from '../../src/crypto/vault-worker-protocol.js';
import {
  VaultWorkerError, VaultWorkerErrorCodes as Codes, sanitizeWorkerErrorDetails, toWireError,
} from '../../src/crypto/vault-worker-errors.js';
import {
  validateKdfWasmUrl, createVaultKdfLoader, KDF_WASM_SHA256, KDF_WASM_BYTES,
} from '../../src/crypto/vault-kdf-loader.js';
import { createVaultWorkerRuntime, WORKER_STATES } from '../../src/crypto/vault-worker-runtime.js';

const here = (rel) => fileURLToPath(new URL(rel, import.meta.url));

function expectCode(fn, code, reason) {
  let err = null;
  try { fn(); } catch (e) { err = e; }
  expect(err).toBeInstanceOf(VaultWorkerError);
  expect(err.code).toBe(code);
  if (reason !== undefined) expect(err.details?.reason).toBe(reason);
  return err;
}

async function expectAsyncCode(thunk, code, reason) {
  let err = null;
  try { await thunk(); } catch (e) { err = e; }
  expect(err).toBeInstanceOf(VaultWorkerError);
  expect(err.code).toBe(code);
  if (reason !== undefined) expect(err.details?.reason).toBe(reason);
  return err;
}

const req = (patch = {}) => ({ id: 1, type: 'STATUS', payload: null, ...patch });

describe('worker error discipline', () => {
  test('the code set is exactly the five mandated codes', () => {
    expect(Object.values(Codes).sort()).toEqual([
      'BAD_REQUEST', 'VAULT_WRONG_STATE', 'WORKER_CRASHED', 'WORKER_TERMINATED', 'WORKER_TIMEOUT',
    ]);
  });

  test('details allowlist admits only type/phase/reason/attempt with short primitives', () => {
    const ok = sanitizeWorkerErrorDetails({ type: 'INIT', phase: 'init', reason: 'x', attempt: 3 });
    expect(Object.isFrozen(ok)).toBe(true);
    expect(() => sanitizeWorkerErrorDetails({ payload: 'x' })).toThrow(TypeError);
    expect(() => sanitizeWorkerErrorDetails({ reason: 'r'.repeat(65) })).toThrow(TypeError);
    expect(() => sanitizeWorkerErrorDetails({ reason: { deep: 1 } })).toThrow(TypeError);
    expect(() => new VaultWorkerError('NOT_A_CODE', 'x')).toThrow(TypeError);
  });

  test('toWireError converts unrecognized exceptions to a bare WORKER_CRASHED', () => {
    const wire = toWireError(new RangeError('secret payload S3CR3T'));
    expect(wire.code).toBe(Codes.CRASHED);
    expect(JSON.stringify(wire)).not.toContain('S3CR3T');
    const typed = toWireError(new VaultWorkerError(Codes.TIMEOUT, 'x', { reason: 'timeout' }));
    expect(typed).toEqual({ code: Codes.TIMEOUT, details: { reason: 'timeout' } });
  });
});

describe('wire value grammar (mandate §19)', () => {
  test('accepts the closed grammar and rejects everything exotic', () => {
    expect(() => validateWireValue({ a: 1, b: 'x', c: [true, null], d: new Uint8Array(4), e: new ArrayBuffer(4) })).not.toThrow();
    expectCode(() => validateWireValue(() => {}), Codes.BAD_REQUEST, 'function');
    expectCode(() => validateWireValue(undefined), Codes.BAD_REQUEST, 'primitive-undefined');
    expectCode(() => validateWireValue(10n), Codes.BAD_REQUEST, 'primitive-bigint');
    expectCode(() => validateWireValue(NaN), Codes.BAD_REQUEST, 'non-finite-number');
    expectCode(() => validateWireValue(Infinity), Codes.BAD_REQUEST, 'non-finite-number');
    expectCode(() => validateWireValue(new Map()), Codes.BAD_REQUEST, 'custom-prototype');
    expectCode(() => validateWireValue(Promise.resolve(1)), Codes.BAD_REQUEST, 'promise');
    expectCode(() => validateWireValue(new Int8Array(2)), Codes.BAD_REQUEST, 'typed-array');
    expectCode(() => validateWireValue(new DataView(new ArrayBuffer(2))), Codes.BAD_REQUEST, 'typed-array');
  });

  test('SharedArrayBuffer and shared-backed views are rejected', () => {
    const sab = new SharedArrayBuffer(8);
    expectCode(() => validateWireValue(sab), Codes.BAD_REQUEST, 'shared-array-buffer');
    expectCode(() => validateWireValue(new Uint8Array(sab)), Codes.BAD_REQUEST, 'shared-array-buffer');
  });

  test('CryptoKey and wasm-like handles are rejected', async () => {
    const key = await crypto.subtle.importKey('raw', new Uint8Array(32), 'AES-GCM', false, ['encrypt', 'decrypt']);
    expectCode(() => validateWireValue({ key }), Codes.BAD_REQUEST, 'cryptokey');
    expectCode(() => validateWireValue({ handle: { __wbg_ptr: 12345 } }), Codes.BAD_REQUEST, 'wbg-handle');
    const mod = new WebAssembly.Module(new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]));
    expectCode(() => validateWireValue({ mod }), Codes.BAD_REQUEST, 'wasm-object');
    expectCode(() => validateWireValue(new WebAssembly.Memory({ initial: 1 })), Codes.BAD_REQUEST, 'wasm-object');
  });

  test('cycles, depth, node count, array/string bounds and byte budget', () => {
    const cyclic = { a: {} };
    cyclic.a.back = cyclic;
    expectCode(() => validateWireValue(cyclic), Codes.BAD_REQUEST, 'cycle');
    // a DAG that shares a node is NOT a cycle and must pass
    const shared = { x: 1 };
    expect(() => validateWireValue({ a: shared, b: shared })).not.toThrow();

    let deep = {};
    const root = deep;
    for (let i = 0; i < MAX_WIRE_DEPTH + 1; i += 1) { deep.next = {}; deep = deep.next; }
    expectCode(() => validateWireValue(root), Codes.BAD_REQUEST, 'over-depth');

    expectCode(
      () => validateWireValue(Array.from({ length: MAX_WIRE_ARRAY_LENGTH + 1 }, () => 0)),
      Codes.BAD_REQUEST, 'over-array-length',
    );
    const manyNodes = Array.from({ length: MAX_WIRE_ARRAY_LENGTH }, () => [0, 0, 0, 0]);
    expectCode(() => validateWireValue(manyNodes), Codes.BAD_REQUEST, 'over-node-count');
    expect(MAX_WIRE_NODES).toBe(65536);

    expectCode(
      () => validateWireValue({ big: new Uint8Array(MAX_WIRE_BYTES + 1) }),
      Codes.BAD_REQUEST, 'over-byte-budget',
    );
  });

  test('objects on the wire follow the strict-shape discipline', () => {
    const withGetter = {};
    let calls = 0;
    Object.defineProperty(withGetter, 'x', { get() { calls += 1; return 1; }, enumerable: true, configurable: true });
    expectCode(() => validateWireValue(withGetter), Codes.BAD_REQUEST, 'accessor-or-hidden');
    expect(calls).toBe(0);
    const hidden = {};
    Object.defineProperty(hidden, 'x', { value: 1, enumerable: false });
    expectCode(() => validateWireValue(hidden), Codes.BAD_REQUEST, 'accessor-or-hidden');
    expectCode(() => validateWireValue({ [Symbol('k')]: 1 }), Codes.BAD_REQUEST, 'symbol-key');
    const arr = [1, 2];
    arr.extra = 3;
    expectCode(() => validateWireValue(arr), Codes.BAD_REQUEST, 'exotic-array');
    // eslint-disable-next-line no-sparse-arrays
    expectCode(() => validateWireValue([1, , 3]), Codes.BAD_REQUEST, 'exotic-array');
  });
});

describe('request envelope (worker side)', () => {
  test('accepts exactly {id, type, payload} and nothing else', () => {
    expect(() => validateRequestEnvelope(req())).not.toThrow();
    for (const raw of [null, 7, 'x', [], new Date()]) {
      expectCode(() => validateRequestEnvelope(raw), Codes.BAD_REQUEST);
    }
    expectCode(() => validateRequestEnvelope({ id: 1, type: 'STATUS' }), Codes.BAD_REQUEST); // missing payload
    expectCode(() => validateRequestEnvelope(req({ extra: 1 })), Codes.BAD_REQUEST);
    const sym = req();
    sym[Symbol('s')] = 1;
    expectCode(() => validateRequestEnvelope(sym), Codes.BAD_REQUEST);
    const accessor = { id: 1, payload: null };
    Object.defineProperty(accessor, 'type', { get: () => 'STATUS', enumerable: true, configurable: true });
    expectCode(() => validateRequestEnvelope(accessor), Codes.BAD_REQUEST);
    const hidden = req();
    Object.defineProperty(hidden, 'smuggle', { value: 1, enumerable: false, configurable: true });
    expectCode(() => validateRequestEnvelope(hidden), Codes.BAD_REQUEST);
    expectCode(() => validateRequestEnvelope(Object.create(req())), Codes.BAD_REQUEST);
  });

  test('id must be a positive safe integer, never duplicated shape-wise', () => {
    for (const id of [0, -1, 1.5, 2 ** 53, '1', null, NaN]) {
      expectCode(() => validateRequestEnvelope(req({ id })), Codes.BAD_REQUEST, 'bad-id');
    }
    expect(extractEnvelopeId(req({ id: 42 }))).toBe(42);
    expect(extractEnvelopeId(req({ id: -1 }))).toBe(0);
    expect(extractEnvelopeId('garbage')).toBe(0);
    let calls = 0;
    const trap = {};
    Object.defineProperty(trap, 'id', { get() { calls += 1; return 9; }, enumerable: true, configurable: true });
    expect(extractEnvelopeId(trap)).toBe(0);
    expect(calls).toBe(0); // defensive extraction never invokes accessors
  });

  test('type must be a string inside the closed registry', () => {
    expect(MESSAGE_TYPES).toEqual([
      'INIT', 'CREATE_VAULT', 'UNLOCK', 'LOCK', 'GET', 'PUT', 'DELETE', 'LIST',
      'TRANSACTION', 'MIGRATE', 'STATUS', 'DESTROY', 'SHUTDOWN',
    ]);
    expect(ACTIVE_TYPES).toEqual(['INIT', 'STATUS', 'SHUTDOWN']);
    for (const type of ['status', 'EVAL', '', 7, null, Symbol('x')]) {
      expectCode(() => validateRequestEnvelope(req({ type })), Codes.BAD_REQUEST);
    }
  });
});

describe('response envelope (client side): every deviation is a protocol violation', () => {
  test('valid success and error envelopes pass', () => {
    expect(validateResponseEnvelope({ id: 1, ok: true, result: { a: 1 } }).result).toEqual({ a: 1 });
    const e = validateResponseEnvelope({ id: 2, ok: false, error: { code: 'BAD_REQUEST', details: { reason: 'x' } } });
    expect(e.error.code).toBe('BAD_REQUEST');
  });

  test('malformed responses are WORKER_CRASHED', () => {
    const cases = [
      { id: 1, ok: 'yes', result: 1 }, // non-boolean ok
      { id: 1, ok: true, result: 1, error: { code: 'BAD_REQUEST', details: {} } }, // both
      { id: 1, ok: true }, // missing result
      { id: 0, ok: true, result: 1 }, // bad id
      { id: 1, ok: false, error: { code: 'MADE_UP', details: {} } }, // unknown code
      { id: 1, ok: false, error: { code: 'BAD_REQUEST', details: { stack: 'x' } } }, // details off-allowlist
      { id: 1, ok: false, error: { code: 'BAD_REQUEST' } }, // missing details
      { id: 1, ok: true, result: { f: () => {} } }, // function in result
      null, [], 'x',
    ];
    for (const raw of cases) {
      expectCode(() => validateResponseEnvelope(raw), Codes.CRASHED);
    }
  });

  test('buildResultResponse refuses unserializable results with a typed error', () => {
    expect(buildResultResponse(1, { fine: true })).toEqual({ id: 1, ok: true, result: { fine: true } });
    expectCode(() => buildResultResponse(1, { evil: { __wbg_ptr: 3 } }), Codes.CRASHED);
    expectCode(() => buildResultResponse(1, { f: () => {} }), Codes.CRASHED);
  });
});

describe('KDF loader: URL policy (mandate §10)', () => {
  const ORIGIN = 'https://app.example';
  const GOOD = '/vendor/styx-kdf-wasm/pkg/styx_kdf_wasm_bg.wasm';

  test('accepts the canonical path, also under a deployment prefix and on loopback http', () => {
    expect(validateKdfWasmUrl(GOOD, ORIGIN).pathname).toBe(GOOD);
    expect(() => validateKdfWasmUrl(`/deploy/prefix${GOOD}`, ORIGIN)).not.toThrow();
    expect(() => validateKdfWasmUrl(GOOD, 'http://127.0.0.1:8080')).not.toThrow();
    expect(() => validateKdfWasmUrl(GOOD, 'http://localhost:3000')).not.toThrow();
  });

  test('rejects every forbidden URL shape', () => {
    const cases = [
      [42, 'bad-url-shape'], ['', 'bad-url-shape'], [`/${'a'.repeat(1100)}${GOOD}`, 'bad-url-shape'],
      [` ${GOOD}`, 'bad-url-chars'], [GOOD.replace('/pkg/', '\\pkg\\'), 'bad-url-chars'],
      [GOOD.replace('/pkg/', '/%2e%2e/pkg/'), 'dot-dot'],
      ['/vendor/%2f/styx_kdf_wasm_bg.wasm', 'encoded-slash'],
      [`https://evil.example${GOOD}`, 'cross-origin'],
      [`blob:${ORIGIN}/uuid`, 'bad-protocol'], // blob: inherits the origin; the protocol gate rejects it
      ['data:application/wasm;base64,AA==', 'cross-origin'],
      ['file:///etc/passwd', 'cross-origin'],
      [`javascript:alert(1)//${GOOD}`, 'cross-origin'],
      [`https://user:pw@app.example${GOOD}`, 'credentials'],
      [`${GOOD}?v=2`, 'query'],
      [`${GOOD}#frag`, 'fragment'],
      ['/vendor/styx-kdf-wasm/pkg/../pkg/styx_kdf_wasm_bg.wasm', 'dot-dot'],
      ['/vendor/styx-kdf-wasm/pkg/%2E%2E/pkg/styx_kdf_wasm_bg.wasm', 'dot-dot'], // parser would normalize this into `..`
      ['/vendor/openmls-wasm/openmls_wasm_bg.wasm', 'wrong-artifact-path'],
      ['/vendor/styx-kdf-wasm/pkg/styx_kdf_wasm.js', 'wrong-artifact-path'],
    ];
    for (const [url, reason] of cases) {
      expectCode(() => validateKdfWasmUrl(url, ORIGIN), Codes.BAD_REQUEST, reason);
    }
    // http only on loopback
    expectCode(() => validateKdfWasmUrl(GOOD, 'http://app.example'), Codes.BAD_REQUEST, 'bad-protocol');
  });

  test('`..` segments never reach the artifact check', () => {
    expectCode(
      () => validateKdfWasmUrl('/a/../vendor/styx-kdf-wasm/pkg/styx_kdf_wasm_bg.wasm/../../../../etc', ORIGIN),
      Codes.BAD_REQUEST,
    );
  });
});

describe('KDF loader: verified load sequence with the REAL artifact', () => {
  const ORIGIN = 'http://127.0.0.1:9999';
  const GOOD = '/vendor/styx-kdf-wasm/pkg/styx_kdf_wasm_bg.wasm';
  const artifact = () => new Uint8Array(readFileSync(here('../../vendor/styx-kdf-wasm/pkg/styx_kdf_wasm_bg.wasm')));
  const fakeFetch = (bytes, { ok = true } = {}) => async () => ({
    ok,
    body: null,
    arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
  });

  test('happy path: real bytes → digest ok → initSync(verified) → real KAT → READY summary', async () => {
    const glue = await import('../../vendor/styx-kdf-wasm/pkg/styx_kdf_wasm.js');
    let initArg = null;
    const loader = createVaultKdfLoader({
      origin: ORIGIN,
      fetchImpl: fakeFetch(artifact()),
      subtleImpl: crypto.subtle,
      initSyncImpl: (m) => { initArg = m.module; return glue.initSync(m); },
      deriveImpl: glue.argon2id_derive,
    });
    const out = await loader.load(GOOD);
    expect(out).toEqual({ wasmBytes: KDF_WASM_BYTES, digestVerified: true, katVerified: true });
    expect(loader.isLoaded()).toBe(true);
    // initSync received EXACTLY the verified bytes
    const digest = [...new Uint8Array(await crypto.subtle.digest('SHA-256', initArg))]
      .map((b) => b.toString(16).padStart(2, '0')).join('');
    expect(digest).toBe(KDF_WASM_SHA256);
  });

  test('size mismatch, oversize, digest mismatch and failed KAT all fail closed before READY', async () => {
    const base = {
      origin: ORIGIN, subtleImpl: crypto.subtle, initSyncImpl: () => {}, deriveImpl: () => new Uint8Array(16),
    };
    await expectAsyncCode(
      () => createVaultKdfLoader({ ...base, fetchImpl: fakeFetch(artifact().slice(0, 100)) }).load(GOOD),
      Codes.BAD_REQUEST, 'size-mismatch',
    );
    await expectAsyncCode(
      () => createVaultKdfLoader({ ...base, fetchImpl: fakeFetch(new Uint8Array(KDF_WASM_BYTES + 5)) }).load(GOOD),
      Codes.BAD_REQUEST, 'oversized-artifact',
    );
    const flipped = artifact();
    flipped[100] ^= 0x01;
    let initCalled = false;
    await expectAsyncCode(
      () => createVaultKdfLoader({
        ...base, initSyncImpl: () => { initCalled = true; }, fetchImpl: fakeFetch(flipped),
      }).load(GOOD),
      Codes.BAD_REQUEST, 'digest-mismatch',
    );
    expect(initCalled).toBe(false); // unverified bytes NEVER reach the engine
    await expectAsyncCode(
      () => createVaultKdfLoader({ ...base, fetchImpl: fakeFetch(artifact()) }).load(GOOD),
      Codes.BAD_REQUEST, 'kat-mismatch', // deriveImpl returns zeros ≠ anchor
    );
    await expectAsyncCode(
      () => createVaultKdfLoader({ ...base, fetchImpl: fakeFetch(artifact(), { ok: false }) }).load(GOOD),
      Codes.BAD_REQUEST, 'fetch-not-ok',
    );
  });
});

describe('worker runtime: states, active and reserved types', () => {
  const okLoader = (state = { loaded: false }) => ({
    load: async () => { state.loaded = true; return { wasmBytes: KDF_WASM_BYTES, digestVerified: true, katVerified: true }; },
    isLoaded: () => state.loaded,
  });

  function makeRuntime({ loader = okLoader(), testOverrides } = {}) {
    const posted = [];
    let closed = 0;
    const runtime = createVaultWorkerRuntime({
      postMessage: (m, t) => posted.push({ m, t }),
      close: () => { closed += 1; },
      kdfLoader: loader,
      testOverrides,
    });
    return { runtime, posted, closedCount: () => closed };
  }

  const initReq = (id = 1) => ({ id, type: 'INIT', payload: { wasmUrl: '/vendor/styx-kdf-wasm/pkg/styx_kdf_wasm_bg.wasm' } });

  test('INIT → READY; STATUS reports the mandated shape; SHUTDOWN closes', async () => {
    const { runtime, posted, closedCount } = makeRuntime();
    expect(runtime.getState()).toBe(WORKER_STATES.NEW);
    await runtime.handleMessage({ data: initReq(), origin: '' });
    expect(posted[0].m.ok).toBe(true);
    expect(posted[0].m.result.workerState).toBe('READY');
    expect(runtime.getState()).toBe(WORKER_STATES.READY);

    await runtime.handleMessage({ data: { id: 2, type: 'STATUS', payload: null } });
    expect(posted[1].m.result).toEqual({
      protocolVersion: 1,
      workerState: 'READY',
      vaultState: null,
      capabilities: { kdf: true, storage: false, lifecycle: false, openmls: false },
      versions: { wrapper: 1, record: 1, key: 1 },
    });

    await runtime.handleMessage({ data: { id: 3, type: 'SHUTDOWN', payload: null } });
    expect(posted[2].m).toEqual({ id: 3, ok: true, result: { closed: true } });
    expect(closedCount()).toBe(1);
    expect(runtime.getState()).toBe(WORKER_STATES.CLOSED);
    // after CLOSED nothing is processed
    await runtime.handleMessage({ data: { id: 4, type: 'STATUS', payload: null } });
    expect(posted.length).toBe(3);
  });

  test('INIT is idempotent only for the identical configuration', async () => {
    const { runtime, posted } = makeRuntime();
    await runtime.handleMessage({ data: initReq(1) });
    await runtime.handleMessage({ data: initReq(2) });
    expect(posted[1].m.ok).toBe(true); // same config → same summary
    await runtime.handleMessage({ data: { id: 3, type: 'INIT', payload: { wasmUrl: '/other/vendor/styx-kdf-wasm/pkg/styx_kdf_wasm_bg.wasm' } } });
    expect(posted[2].m.ok).toBe(false);
    expect(posted[2].m.error.code).toBe(Codes.WRONG_STATE);
    expect(posted[2].m.error.details.reason).toBe('config-mismatch');
  });

  test('a failed INIT leaves the worker FAILED (fail-closed)', async () => {
    const failing = {
      load: async () => { throw new VaultWorkerError(Codes.BAD_REQUEST, 'digest', { phase: 'init', reason: 'digest-mismatch' }); },
      isLoaded: () => false,
    };
    const { runtime, posted } = makeRuntime({ loader: failing });
    await runtime.handleMessage({ data: initReq() });
    expect(posted[0].m.error.details.reason).toBe('digest-mismatch');
    expect(runtime.getState()).toBe(WORKER_STATES.FAILED);
  });

  test('every reserved type answers VAULT_WRONG_STATE after generic validation', async () => {
    const { runtime, posted } = makeRuntime();
    await runtime.handleMessage({ data: initReq() });
    const reserved = MESSAGE_TYPES.filter((t) => !ACTIVE_TYPES.includes(t));
    let id = 10;
    for (const type of reserved) {
      await runtime.handleMessage({ data: { id, type, payload: {} } });
      const last = posted[posted.length - 1].m;
      expect(last.ok).toBe(false);
      expect(last.error.code).toBe(Codes.WRONG_STATE);
      expect(last.error.details).toEqual({ type, reason: 'reserved-type' });
      id += 1;
    }
    // size limits run BEFORE the reserved-type answer
    await runtime.handleMessage({ data: { id, type: 'PUT', payload: { big: new Uint8Array(MAX_WIRE_BYTES + 1) } } });
    expect(posted[posted.length - 1].m.error.code).toBe(Codes.BAD_REQUEST);
  });

  test('bad envelopes, non-empty origins and duplicate in-flight ids are BAD_REQUEST', async () => {
    const { runtime, posted } = makeRuntime();
    await runtime.handleMessage({ data: { id: 1, type: 'EVAL', payload: null } });
    expect(posted[0].m).toEqual({ id: 1, ok: false, error: { code: Codes.BAD_REQUEST, details: { reason: 'unknown-type' } } });
    await runtime.handleMessage({ data: 'garbage' });
    expect(posted[1].m.id).toBe(0); // unattributable
    await runtime.handleMessage({ data: { id: 2, type: 'STATUS', payload: null }, origin: 'https://evil.example' });
    expect(posted[2].m.error.details.reason).toBe('unexpected-origin');

    // duplicate id while in flight: slow override keeps id 5 pending
    let release;
    const gate = new Promise((r) => { release = r; });
    const { runtime: rt2, posted: p2 } = makeRuntime({
      testOverrides: { LIST: async () => { await gate; return { result: null }; } },
    });
    await rt2.handleMessage({ data: initReq() });
    const first = rt2.handleMessage({ data: { id: 5, type: 'LIST', payload: null } });
    await rt2.handleMessage({ data: { id: 5, type: 'STATUS', payload: null } });
    expect(p2[p2.length - 1].m.error.details.reason).toBe('duplicate-id');
    release();
    await first;
  });

  test('an unrecognized exception becomes WORKER_CRASHED and closes the worker', async () => {
    const { runtime, posted, closedCount } = makeRuntime({
      testOverrides: { DESTROY: async () => { throw new RangeError('S3CR3T internals'); } },
    });
    await runtime.handleMessage({ data: initReq() });
    await runtime.handleMessage({ data: { id: 2, type: 'DESTROY', payload: null } });
    const last = posted[posted.length - 1].m;
    expect(last.error).toEqual({ code: Codes.CRASHED, details: { reason: 'unhandled-exception' } });
    expect(JSON.stringify(posted)).not.toContain('S3CR3T');
    expect(closedCount()).toBe(1);
    expect(runtime.getState()).toBe(WORKER_STATES.FAILED);
  });

  test('a handler result carrying a WASM handle never reaches postMessage', async () => {
    const { runtime, posted, closedCount } = makeRuntime({
      testOverrides: { GET: async () => ({ result: { leak: { __wbg_ptr: 7 } } }) },
    });
    await runtime.handleMessage({ data: initReq() });
    await runtime.handleMessage({ data: { id: 2, type: 'GET', payload: null } });
    const last = posted[posted.length - 1].m;
    expect(last.ok).toBe(false);
    expect(last.error.code).toBe(Codes.CRASHED);
    expect(JSON.stringify(posted)).not.toContain('__wbg_ptr');
    expect(closedCount()).toBe(1); // fail-closed
  });

  test('test overrides can never touch active types or unknown names', () => {
    for (const bad of [{ INIT: () => {} }, { STATUS: () => {} }, { SHUTDOWN: () => {} }, { EVAL: () => {} }]) {
      expect(() => createVaultWorkerRuntime({
        postMessage: () => {}, close: () => {}, kdfLoader: okLoader(), testOverrides: bad,
      })).toThrow(TypeError);
    }
  });
});
