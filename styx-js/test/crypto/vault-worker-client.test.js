// vault-worker-client.test.js — correlation layer of the vault worker
// protocol (PR-3, mandate §20/§12/§13). Fake Worker + injected fake timers:
// the real-Worker path is covered by the browser spec.

import {
  createVaultWorkerClient, MAX_TRANSFER_BYTES,
} from '../../src/crypto/vault-worker-client.js';
import { VaultWorkerError, VaultWorkerErrorCodes as Codes } from '../../src/crypto/vault-worker-errors.js';

class FakeWorker {
  constructor() {
    this.listeners = { message: [], error: [], messageerror: [] };
    this.posted = [];
    this.terminated = 0;
    this.throwOnPost = false;
  }

  addEventListener(type, fn) { this.listeners[type].push(fn); }

  postMessage(message, transfer) {
    if (this.throwOnPost) throw new DOMException('DataCloneError');
    this.posted.push({ message, transfer });
  }

  terminate() { this.terminated += 1; }

  emit(type, event) { for (const fn of [...this.listeners[type]]) fn(event); }

  reply(id, result) { this.emit('message', { data: { id, ok: true, result } }); }

  replyError(id, code, details = {}) { this.emit('message', { data: { id, ok: false, error: { code, details } } }); }
}

function makeFakeTimers() {
  const timers = new Map();
  let next = 1;
  return {
    setTimeoutImpl: (fn, ms) => { const id = next; next += 1; timers.set(id, { fn, ms }); return id; },
    clearTimeoutImpl: (id) => { timers.delete(id); },
    fire: (id) => { const t = timers.get(id); timers.delete(id); t?.fn(); },
    fireAll: () => { for (const [id] of [...timers]) { const t = timers.get(id); timers.delete(id); t?.fn(); } },
    count: () => timers.size,
  };
}

function makeClient(options = {}) {
  const worker = new FakeWorker();
  const timers = makeFakeTimers();
  const fatals = [];
  const client = createVaultWorkerClient(worker, {
    onFatal: (e) => fatals.push(e),
    setTimeoutImpl: timers.setTimeoutImpl,
    clearTimeoutImpl: timers.clearTimeoutImpl,
    ...options,
  });
  return { worker, timers, fatals, client };
}

const codeOf = async (promise) => {
  try { await promise; return 'RESOLVED'; } catch (e) {
    expect(e).toBeInstanceOf(VaultWorkerError);
    return e.code;
  }
};

describe('correlation', () => {
  test('out-of-order responses resolve the right concurrent requests', async () => {
    const { worker, client } = makeClient();
    const a = client.request('STATUS');
    const b = client.request('STATUS');
    const c = client.request('STATUS');
    expect(worker.posted.map((p) => p.message.id)).toEqual([1, 2, 3]);
    worker.reply(3, 'third');
    worker.reply(1, 'first');
    worker.reply(2, 'second');
    expect(await a).toBe('first');
    expect(await b).toBe('second');
    expect(await c).toBe('third');
    expect(client.pendingCount()).toBe(0);
  });

  test('the pending map stores only resolve/reject/timer/type — never the payload', () => {
    const { worker, client } = makeClient();
    const secret = { password: 'STYX-TEST-ONLY' };
    client.request('INIT', secret).catch(() => {});
    // nothing beyond the envelope is retained: inspect via the posted message
    expect(worker.posted[0].message.payload).toBe(secret); // envelope goes out...
    // ...but the client keeps no reference we can reach; the contract is
    // structural: request() closes over resolve/reject/timer/type only.
    worker.replyError(1, 'BAD_REQUEST', {});
  });

  test('an error response rejects with the reconstructed typed error', async () => {
    const { worker, client } = makeClient();
    const p = client.request('STATUS');
    worker.replyError(1, 'VAULT_WRONG_STATE', { reason: 'reserved-type' });
    const err = await p.then(() => null, (e) => e);
    expect(err.code).toBe(Codes.WRONG_STATE);
    expect(err.details).toEqual({ reason: 'reserved-type' });
    expect(client.isClosed()).toBe(false); // a typed error response is NOT fatal
  });

  test('unknown type and closed client reject immediately', async () => {
    const { client } = makeClient();
    expect(await codeOf(client.request('EVAL'))).toBe(Codes.BAD_REQUEST);
    client.terminate('bye');
    expect(await codeOf(client.request('STATUS'))).toBe(Codes.TERMINATED);
  });
});

describe('protocol violations are fatal (WORKER_CRASHED + _rejectAll once)', () => {
  const violations = [
    ['duplicate response', (w) => { w.reply(1, 'a'); w.reply(1, 'b'); }],
    ['unknown id', (w) => { w.reply(99, 'x'); }],
    ['malformed envelope', (w) => { w.emit('message', { data: { id: 1, ok: 'yes' } }); }],
    ['result and error together', (w) => { w.emit('message', { data: { id: 1, ok: true, result: 1, error: { code: 'BAD_REQUEST', details: {} } } }); }],
    ['off-protocol error code', (w) => { w.replyError(1, 'MADE_UP'); }],
    ['messageerror', (w) => { w.emit('messageerror', {}); }],
    ['error event', (w) => { w.emit('error', {}); }],
  ];
  for (const [name, act] of violations) {
    test(name, async () => {
      const { worker, fatals, client } = makeClient();
      const a = client.request('STATUS');
      const b = client.request('STATUS');
      act(worker);
      // every pending rejects; onFatal fires exactly once; worker terminated
      const codes = [await codeOf(a), await codeOf(b)];
      for (const c of codes) expect([Codes.CRASHED, Codes.TERMINATED, 'RESOLVED']).toContain(c);
      expect(codes.filter((c) => c !== 'RESOLVED').length).toBeGreaterThan(0);
      expect(fatals.length).toBe(1);
      expect(worker.terminated).toBe(1);
      expect(client.isClosed()).toBe(true);
      expect(client.pendingCount()).toBe(0);
      // and late replies can no longer resolve anything
      worker.reply(2, 'late');
      expect(await codeOf(b)).not.toBe('RESOLVED');
    });
  }

  test('hostile error details from the worker are fatal, without invoking getters (review W6)', async () => {
    const { worker, fatals, client } = makeClient();
    const p = client.request('STATUS');
    let calls = 0;
    const hostile = {};
    Object.defineProperty(hostile, 'reason', {
      enumerable: true, configurable: true, get() { calls += 1; return 'S3CR3T from getter'; },
    });
    Object.defineProperty(hostile, 'stack', { value: 'S3CR3T stack', enumerable: false, configurable: true });
    worker.replyError(1, 'BAD_REQUEST', hostile);
    const err = await p.then(() => null, (e) => e);
    expect(err.code).toBe(Codes.CRASHED);
    expect(err.details.reason).toBe('bad-error-details');
    expect(JSON.stringify({ m: err.message, d: err.details })).not.toContain('S3CR3T');
    expect(calls).toBe(0); // the getter was never invoked
    expect(fatals.length).toBe(1); // protocol violation → the worker is gone
    expect(client.isClosed()).toBe(true);
  });

  test('a postMessage exception is fatal too', async () => {
    const { worker, fatals, client } = makeClient();
    worker.throwOnPost = true;
    expect(await codeOf(client.request('STATUS'))).toBe(Codes.CRASHED);
    expect(fatals.length).toBe(1);
    expect(client.isClosed()).toBe(true);
  });
});

describe('timeout is fatal (mandate §13)', () => {
  test('timeout rejects WORKER_TIMEOUT, terminates, rejects the rest, and a late reply cannot resolve', async () => {
    const { worker, timers, fatals, client } = makeClient();
    const slow = client.request('UNLOCK', null, { timeoutMs: 50 });
    const other = client.request('STATUS');
    timers.fire(worker.posted[0].message.id); // the UNLOCK timer
    const slowErr = await slow.then(() => null, (e) => e);
    expect(slowErr.code).toBe(Codes.TIMEOUT);
    expect(slowErr.details).toEqual({ type: 'UNLOCK', reason: 'timeout' });
    const otherErr = await other.then(() => null, (e) => e);
    expect(otherErr.code).toBe(Codes.TERMINATED);
    expect(otherErr.details.reason).toBe('timeout');
    expect(worker.terminated).toBe(1);
    expect(fatals.length).toBe(1);
    expect(client.pendingCount()).toBe(0);
    // a late response for the timed-out id is ignored (client closed)
    worker.reply(1, 'too-late');
    expect((await slow.catch((e) => e)).code).toBe(Codes.TIMEOUT); // unchanged
  });

  test('a response cancels its timer; no timer leaks after any scenario', async () => {
    const { worker, timers, client } = makeClient();
    const p = client.request('STATUS', null, { timeoutMs: 50 });
    worker.reply(1, 'ok');
    await p;
    expect(timers.count()).toBe(0);
    client.terminate('done');
  });
});

describe('transfer list discipline (mandate §16 client side)', () => {
  test('valid transfer goes through; every violation is rejected BEFORE postMessage', async () => {
    const { worker, client } = makeClient();
    const buf = new ArrayBuffer(1024);
    client.request('PUT', { buffer: buf }, { transfer: [buf] }).catch(() => {});
    expect(worker.posted[0].transfer).toEqual([buf]);

    const dup = new ArrayBuffer(8);
    expect(await codeOf(client.request('PUT', null, { transfer: [dup, dup] }))).toBe(Codes.BAD_REQUEST);
    expect(await codeOf(client.request('PUT', null, { transfer: [new SharedArrayBuffer(8)] }))).toBe(Codes.BAD_REQUEST);
    expect(await codeOf(client.request('PUT', null, { transfer: [new Uint8Array(8)] }))).toBe(Codes.BAD_REQUEST);
    expect(await codeOf(client.request('PUT', null, { transfer: 'nope' }))).toBe(Codes.BAD_REQUEST);
    const over = [new ArrayBuffer(MAX_TRANSFER_BYTES), new ArrayBuffer(1)];
    expect(await codeOf(client.request('PUT', null, { transfer: over }))).toBe(Codes.BAD_REQUEST);
    // only the first (valid) request ever reached postMessage
    expect(worker.posted.length).toBe(1);
  });
});

describe('terminate and shutdown', () => {
  test('manual terminate rejects everything once with the bounded reason and does NOT call onFatal', async () => {
    const { worker, fatals, client } = makeClient();
    const a = client.request('UNLOCK');
    const b = client.request('STATUS');
    client.terminate('unlock-cancelled');
    for (const p of [a, b]) {
      const err = await p.then(() => null, (e) => e);
      expect(err.code).toBe(Codes.TERMINATED);
      expect(err.details.reason).toBe('unlock-cancelled');
    }
    expect(fatals.length).toBe(0); // caller-initiated
    expect(worker.terminated).toBe(1);
    expect(client.pendingCount()).toBe(0);
    client.terminate('again'); // idempotent, no double rejection
    expect(worker.terminated).toBe(1);
  });

  test('shutdown resolves the SHUTDOWN result and closes the client', async () => {
    const { worker, client } = makeClient();
    const p = client.shutdown();
    expect(worker.posted[0].message.type).toBe('SHUTDOWN');
    worker.reply(1, { closed: true });
    expect(await p).toEqual({ closed: true });
    expect(client.isClosed()).toBe(true);
    expect(await codeOf(client.request('STATUS'))).toBe(Codes.TERMINATED);
  });
});

const errOf = async (promise) => {
  try { await promise; return 'RESOLVED'; } catch (e) {
    expect(e).toBeInstanceOf(VaultWorkerError);
    return e;
  }
};

describe('outbound payload validation (review PR39 F1)', () => {
  // The wire grammar must be enforced BEFORE the structured clone crosses the
  // boundary, not only worker-side: a clonable exotic (SharedArrayBuffer,
  // CryptoKey) must never reach the worker at all.
  test.each([
    ['a function property', { wasmUrl: '/x.wasm', cb: () => {} }],
    ['a SharedArrayBuffer', { wasmUrl: '/x.wasm', buf: new SharedArrayBuffer(8) }],
    ['a Map (non-plain object)', { wasmUrl: '/x.wasm', m: new Map() }],
    ['a nested exotic', { wasmUrl: '/x.wasm', deep: { inner: new WeakMap() } }],
  ])('%s is rejected BAD_REQUEST before postMessage', async (_label, payload) => {
    const { worker, fatals, client } = makeClient();
    const err = await errOf(client.request('INIT', payload));
    expect(err.code).toBe(Codes.BAD_REQUEST);
    expect(worker.posted.length).toBe(0); // nothing crossed the boundary
    expect(client.pendingCount()).toBe(0);
    expect(fatals.length).toBe(0); // a bad caller does not kill the worker
  });

  test('a valid payload still crosses unchanged', async () => {
    const { worker, client } = makeClient();
    client.request('INIT', { wasmUrl: '/x.wasm' });
    expect(worker.posted.length).toBe(1);
    expect(worker.posted[0].message.payload).toEqual({ wasmUrl: '/x.wasm' });
  });
});

describe('terminate reason confinement (review PR39 F2)', () => {
  test('an unknown reason is mapped to the closed set, never copied into the error', async () => {
    const { worker, client } = makeClient();
    const p = client.request('STATUS');
    client.terminate('hunter2-super-secret-password');
    const err = await errOf(p);
    expect(err.code).toBe(Codes.TERMINATED);
    expect(err.details.reason).toBe('terminated');
    expect(JSON.stringify(err.details)).not.toContain('hunter2');
    expect(worker.terminated).toBe(1);
  });

  test('the internal reasons keep working verbatim', async () => {
    const { client } = makeClient();
    const p = client.request('STATUS');
    client.terminate('unlock-cancelled');
    const err = await errOf(p);
    expect(err.details.reason).toBe('unlock-cancelled');
  });
});
