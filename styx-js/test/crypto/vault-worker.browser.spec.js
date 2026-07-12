// vault-worker.browser.spec.js — real module workers on Chromium + Firefox
// (PR-3, mandate §21): verified INIT with the REAL styx-kdf-wasm artifact,
// STATUS/SHUTDOWN, crash/terminate/respawn, fatal timeout, strong Argon2id
// cancellation, 8 MiB transferables, the REAL production CSP, and the proof
// that no WebAssembly object ever crosses the boundary.
// Run from styx-js/:  npx playwright test -c playwright.vault-worker.config.js
import { test, expect } from '@playwright/test';
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildCsp } from '../../apps/chat/static-server.mjs'; // the REAL production CSP

const STYX_JS_ROOT = normalize(join(fileURLToPath(new URL('.', import.meta.url)), '..', '..'));
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.wasm': 'application/wasm' };
const WASM_URL = '/vendor/styx-kdf-wasm/pkg/styx_kdf_wasm_bg.wasm';

function makeServer({ csp } = {}) {
  return http.createServer((req, res) => {
    try {
      if (req.url === '/harness') {
        const headers = { 'content-type': 'text/html' };
        if (csp) headers['content-security-policy'] = csp;
        res.writeHead(200, headers);
        res.end('<!doctype html><html><body>vault-worker</body></html>');
        return;
      }
      const path = normalize(join(STYX_JS_ROOT, req.url.split('?')[0]));
      if (!path.startsWith(STYX_JS_ROOT)) { res.writeHead(403); res.end(); return; }
      const body = readFileSync(path);
      const headers = { 'content-type': MIME[extname(path)] || 'application/octet-stream' };
      if (csp) headers['content-security-policy'] = csp;
      res.writeHead(200, headers);
      res.end(body);
    } catch { res.writeHead(404); res.end(); }
  });
}

let server; let base; // plain
let cspServer; let cspBase; // REAL production CSP on every response
test.beforeAll(async () => {
  server = makeServer({});
  cspServer = makeServer({ csp: buildCsp() });
  await new Promise((r) => { server.listen(0, '127.0.0.1', r); });
  await new Promise((r) => { cspServer.listen(0, '127.0.0.1', r); });
  base = `http://127.0.0.1:${server.address().port}`;
  cspBase = `http://127.0.0.1:${cspServer.address().port}`;
});
test.afterAll(async () => {
  await new Promise((r) => { server.close(r); });
  await new Promise((r) => { cspServer.close(r); });
});

const PROD_WORKER = '/src/crypto/vault-worker.js';
const TEST_WORKER = '/test/fixtures/vault-worker/test-worker.js';

test('production worker: verified INIT, STATUS, reserved types, idempotence, SHUTDOWN', async ({ page }, info) => {
  await page.goto(`${base}/harness`);
  const out = await page.evaluate(async ({ workerPath, wasmUrl }) => {
    const { createVaultWorkerClient } = await import('/src/crypto/vault-worker-client.js');
    const worker = new Worker(workerPath, { type: 'module' });
    const client = createVaultWorkerClient(worker);
    const r = {};
    r.init = await client.request('INIT', { wasmUrl });
    r.initAgain = await client.request('INIT', { wasmUrl }); // idempotent, same config
    r.status = await client.request('STATUS');
    r.reserved = await client.request('UNLOCK', {}).then(() => 'resolved', (e) => ({ code: e.code, details: e.details }));
    r.badInit = await client.request('INIT', { wasmUrl: '/elsewhere/styx_kdf_wasm_bg.wasm' })
      .then(() => 'resolved', (e) => ({ code: e.code }));
    r.shutdown = await client.request('SHUTDOWN');
    return r;
  }, { workerPath: PROD_WORKER, wasmUrl: WASM_URL });

  expect(out.init).toEqual({
    protocolVersion: 1, workerState: 'READY', wasmBytes: 42082, digestVerified: true, katVerified: true,
  });
  expect(out.initAgain).toEqual(out.init);
  expect(out.status).toEqual({
    protocolVersion: 1,
    workerState: 'READY',
    vaultState: null,
    capabilities: { kdf: true, storage: false, lifecycle: false, openmls: false },
    versions: { wrapper: 1, record: 1, key: 1 },
  });
  // production build has NO handler for reserved names — and a different
  // config after INIT is refused
  expect(out.reserved).toEqual({ code: 'VAULT_WRONG_STATE', details: { type: 'UNLOCK', reason: 'reserved-type' } });
  expect(out.badInit.code).toBe('VAULT_WRONG_STATE');
  expect(out.shutdown).toEqual({ closed: true });
  console.log(`[vault-worker:${info.project.name}] production worker verified (digest+KAT) and closed cleanly`);
});

test('a tampered artifact path fails INIT closed (no READY, worker FAILED)', async ({ page }) => {
  await page.goto(`${base}/harness`);
  const out = await page.evaluate(async ({ workerPath }) => {
    const { createVaultWorkerClient } = await import('/src/crypto/vault-worker-client.js');
    const client = createVaultWorkerClient(new Worker(workerPath, { type: 'module' }));
    const err = await client.request('INIT', { wasmUrl: '/vendor/openmls-wasm/openmls_wasm_bg.wasm' })
      .then(() => null, (e) => ({ code: e.code, reason: e.details?.reason }));
    const status = await client.request('STATUS');
    return { err, status };
  }, { workerPath: PROD_WORKER });
  expect(out.err).toEqual({ code: 'BAD_REQUEST', reason: 'wrong-artifact-path' });
  expect(out.status.workerState).toBe('FAILED');
  expect(out.status.capabilities.kdf).toBe(false);
});

test('supervisor: fatal timeout terminates and respawns; crash respawns; STATUS works again', async ({ page }, info) => {
  await page.goto(`${base}/harness`);
  const out = await page.evaluate(async ({ workerPath, wasmUrl }) => {
    const { createVaultWorkerSupervisor } = await import('/src/crypto/vault-worker-supervisor.js');
    const supervisor = createVaultWorkerSupervisor({
      createWorker: () => new Worker(workerPath, { type: 'module' }),
      wasmUrl,
      requestTimeoutMs: 15000,
    });
    await supervisor.start();
    const r = { gen0: supervisor.getGeneration() };

    // fatal timeout: LIST never answers
    r.timeout = await supervisor.request('LIST', null, { timeoutMs: 400 })
      .then(() => 'resolved', (e) => ({ code: e.code, reason: e.details?.reason }));
    await new Promise((resolve) => { setTimeout(resolve, 400); }); // backoff 100ms + INIT
    for (let i = 0; i < 40 && supervisor.getState() !== 'RUNNING'; i += 1) {
      await new Promise((resolve) => { setTimeout(resolve, 100); });
    }
    r.afterTimeout = { state: supervisor.getState(), gen: supervisor.getGeneration() };
    r.statusAfterTimeout = await supervisor.request('STATUS');

    // crash: DESTROY schedules an uncaught throw inside the worker
    await supervisor.request('DESTROY');
    for (let i = 0; i < 50 && !(supervisor.getState() === 'RUNNING' && supervisor.getGeneration() > r.afterTimeout.gen); i += 1) {
      await new Promise((resolve) => { setTimeout(resolve, 100); });
    }
    r.afterCrash = { state: supervisor.getState(), gen: supervisor.getGeneration() };
    r.statusAfterCrash = await supervisor.request('STATUS');
    supervisor.stop();
    return r;
  }, { workerPath: TEST_WORKER, wasmUrl: WASM_URL });

  expect(out.timeout).toEqual({ code: 'WORKER_TIMEOUT', reason: 'timeout' });
  expect(out.afterTimeout.state).toBe('RUNNING');
  expect(out.afterTimeout.gen).toBeGreaterThan(out.gen0);
  expect(out.statusAfterTimeout.workerState).toBe('READY');
  expect(out.afterCrash.state).toBe('RUNNING');
  expect(out.afterCrash.gen).toBeGreaterThan(out.afterTimeout.gen);
  expect(out.statusAfterCrash.workerState).toBe('READY');
  console.log(`[vault-worker:${info.project.name}] timeout→respawn and crash→respawn verified`);
});

test('strong cancellation: terminate DURING a real synchronous Argon2id run', async ({ page }, info) => {
  test.setTimeout(180000);
  await page.goto(`${base}/harness`);
  const out = await page.evaluate(async ({ workerPath, wasmUrl }) => {
    const { createVaultWorkerSupervisor } = await import('/src/crypto/vault-worker-supervisor.js');
    const supervisor = createVaultWorkerSupervisor({
      createWorker: () => new Worker(workerPath, { type: 'module' }),
      wasmUrl,
      requestTimeoutMs: 120000,
    });
    await supervisor.start();

    // baseline: how long the full synthetic UNLOCK takes uninterrupted
    const t0 = performance.now();
    await supervisor.request('UNLOCK', { rounds: 6, mKib: 65536, t: 3 });
    const baselineMs = performance.now() - t0;

    // cancellation: same load, terminate shortly after it started
    const t1 = performance.now();
    const pending = supervisor.request('UNLOCK', { rounds: 6, mKib: 65536, t: 3 });
    const otherPending = supervisor.request('LIST', null, { timeoutMs: 110000 });
    await new Promise((resolve) => { setTimeout(resolve, Math.min(150, baselineMs / 4)); });
    await supervisor.cancelUnlock();
    const cancelled = await pending.then(() => null, (e) => ({ code: e.code, reason: e.details?.reason }));
    const other = await otherPending.then(() => null, (e) => ({ code: e.code, reason: e.details?.reason }));
    const cancelMs = performance.now() - t1;

    const status = await supervisor.request('STATUS'); // the NEW worker answers
    const result = {
      baselineMs, cancelMs, cancelled, other, status, gen: supervisor.getGeneration(),
    };
    supervisor.stop();
    return result;
  }, { workerPath: TEST_WORKER, wasmUrl: WASM_URL });

  expect(out.cancelled).toEqual({ code: 'WORKER_TERMINATED', reason: 'unlock-cancelled' });
  expect(out.other).toEqual({ code: 'WORKER_TERMINATED', reason: 'unlock-cancelled' });
  // the WASM was really mid-run: the cancel path returned well before the
  // uninterrupted baseline (terminate is the only real cancellation)
  expect(out.cancelMs).toBeLessThan(out.baselineMs * 0.8);
  expect(out.status.workerState).toBe('READY');
  expect(out.gen).toBe(2);
  console.log(`[vault-worker:${info.project.name}] baseline ${Math.round(out.baselineMs)}ms, cancelled+respawned in ${Math.round(out.cancelMs)}ms`);
});

test('transferables: 8 MiB moves both ways without copies; the 32 MiB cap holds', async ({ page }, info) => {
  await page.goto(`${base}/harness`);
  const out = await page.evaluate(async ({ workerPath, wasmUrl }) => {
    const { createVaultWorkerClient } = await import('/src/crypto/vault-worker-client.js');
    const client = createVaultWorkerClient(new Worker(workerPath, { type: 'module' }));
    await client.request('INIT', { wasmUrl });

    const size = 8 * 1024 * 1024;
    const bytes = new Uint8Array(size);
    for (let o = 0; o < size; o += 65536) {
      crypto.getRandomValues(bytes.subarray(o, o + 65536)); // 64 KiB RNG cap per call
    }
    const sentDigest = [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))]
      .map((b) => b.toString(16).padStart(2, '0')).join('');
    const buffer = bytes.buffer;
    const echoedPromise = client.request('PUT', { buffer }, { transfer: [buffer] });
    const detachedAfterPost = buffer.byteLength === 0; // source neutralized
    const { echoed, byteLength } = await echoedPromise;
    const echoedDigest = [...new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(echoed)))]
      .map((b) => b.toString(16).padStart(2, '0')).join('');

    const over = new ArrayBuffer(32 * 1024 * 1024 + 1);
    const overErr = await client.request('PUT', { buffer: over }, { transfer: [over] })
      .then(() => 'resolved', (e) => ({ code: e.code, reason: e.details?.reason }));
    const overStillAttached = over.byteLength > 0; // rejected BEFORE postMessage
    const dup = new ArrayBuffer(16);
    const dupErr = await client.request('PUT', { buffer: dup }, { transfer: [dup, dup] })
      .then(() => 'resolved', (e) => ({ code: e.code, reason: e.details?.reason }));
    const status = await client.request('STATUS'); // client survived the rejected calls
    await client.request('SHUTDOWN');
    return {
      detachedAfterPost, sentDigest, echoedDigest, byteLength, overErr, overStillAttached, dupErr, ok: status.workerState,
    };
  }, { workerPath: TEST_WORKER, wasmUrl: WASM_URL });

  expect(out.detachedAfterPost).toBe(true);
  expect(out.byteLength).toBe(8 * 1024 * 1024);
  expect(out.echoedDigest).toBe(out.sentDigest);
  expect(out.overErr).toEqual({ code: 'BAD_REQUEST', reason: 'over-transfer-budget' });
  expect(out.overStillAttached).toBe(true);
  expect(out.dupErr).toEqual({ code: 'BAD_REQUEST', reason: 'duplicate-transferable' });
  expect(out.ok).toBe('READY');
  console.log(`[vault-worker:${info.project.name}] 8 MiB transferred both ways, byte-identical, caps enforced`);
});

test('no WebAssembly object crosses the boundary: the serializer refuses and fails closed', async ({ page }) => {
  await page.goto(`${base}/harness`);
  const out = await page.evaluate(async ({ workerPath, wasmUrl }) => {
    const { createVaultWorkerClient } = await import('/src/crypto/vault-worker-client.js');
    const client = createVaultWorkerClient(new Worker(workerPath, { type: 'module' }));
    await client.request('INIT', { wasmUrl });
    const leak = await client.request('GET')
      .then((r) => ({ resolved: JSON.stringify(r) }), (e) => ({ code: e.code, details: e.details }));
    // fail-closed: the worker closed itself after the serializer violation
    const after = await client.request('STATUS', null, { timeoutMs: 500 })
      .then(() => 'resolved', (e) => e.code);
    return { leak, after };
  }, { workerPath: TEST_WORKER, wasmUrl: WASM_URL });
  expect(out.leak.code).toBe('WORKER_CRASHED');
  expect(JSON.stringify(out.leak)).not.toContain('__wbg_ptr');
  expect(out.after).toBe('WORKER_TIMEOUT');
});

test('REAL production CSP: same-origin module worker allowed; blob:, data: and cross-origin denied', async ({ page }, info) => {
  await page.goto(`${cspBase}/harness`);
  const out = await page.evaluate(async ({ workerPath, wasmUrl, foreignOrigin }) => {
    const attempt = (make) => new Promise((resolve) => {
      let w;
      try {
        w = make();
      } catch (e) { resolve(`constructor:${e.name}`); return; }
      const timer = setTimeout(() => { w.terminate(); resolve('alive'); }, 1500);
      w.addEventListener('error', () => { clearTimeout(timer); w.terminate(); resolve('error-event'); });
    });

    const { createVaultWorkerClient } = await import('/src/crypto/vault-worker-client.js');
    const sameOrigin = new Worker(workerPath, { type: 'module' });
    const client = createVaultWorkerClient(sameOrigin);
    const init = await client.request('INIT', { wasmUrl }).then((r) => r.katVerified, (e) => e.code);
    await client.request('SHUTDOWN').catch(() => {});

    const blobUrl = URL.createObjectURL(new Blob(['self.postMessage(1)'], { type: 'text/javascript' }));
    const blobWorker = await attempt(() => new Worker(blobUrl));
    const dataWorker = await attempt(() => new Worker('data:text/javascript,self.postMessage(1)'));
    const crossWorker = await attempt(() => new Worker(`${foreignOrigin}${workerPath}`, { type: 'module' }));
    return {
      init, blobWorker, dataWorker, crossWorker,
    };
  }, { workerPath: PROD_WORKER, wasmUrl: WASM_URL, foreignOrigin: base });

  expect(out.init).toBe(true); // worker-src 'self' + connect-src 'self' + wasm-unsafe-eval suffice
  expect(['constructor:SecurityError', 'error-event']).toContain(out.blobWorker);
  expect(['constructor:SecurityError', 'error-event']).toContain(out.dataWorker);
  expect(['constructor:SecurityError', 'error-event']).toContain(out.crossWorker);
  console.log(`[vault-worker:${info.project.name}] CSP: same-origin module worker OK; blob=${out.blobWorker}, data=${out.dataWorker}, cross=${out.crossWorker}`);
});
