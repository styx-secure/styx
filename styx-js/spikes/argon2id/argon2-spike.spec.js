// argon2-spike.spec.js — STYX_SPIKE_PROTOTYPE. Argon2id candidate comparison and
// parameter benchmarks, run in the context the crypto-worker spike selected (a
// dedicated module worker). Candidates:
//   A: project-built Rust/WASM crate (RustCrypto argon2, pinned toolchain)
//   B: hash-wasm 4.12.0 (exact-pinned in the spike-local package.json)
// Results: docs/superpowers/spikes/2026-07-12-argon2id.md
import { test, expect, chromium } from '@playwright/test';
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const STYX_JS_ROOT = normalize(join(HERE, '..', '..'));
const MIME = {
  '.html': 'text/html', '.js': 'text/javascript', '.json': 'application/json', '.wasm': 'application/wasm',
};

let server; let base;
test.beforeAll(async () => {
  server = http.createServer((req, res) => {
    try {
      const path = normalize(join(STYX_JS_ROOT, req.url.split('?')[0]));
      if (!path.startsWith(STYX_JS_ROOT)) { res.writeHead(403); res.end(); return; }
      const body = readFileSync(path);
      res.writeHead(200, { 'content-type': MIME[extname(path)] || 'application/octet-stream' });
      res.end(body);
    } catch { res.writeHead(404); res.end(); }
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});
test.afterAll(async () => { await new Promise((r) => server.close(r)); });

async function harness(page) {
  await page.goto(`${base}/spikes/argon2id/harness.html`);
  await page.waitForFunction(() => window.__argonSpikeReady === true);
}

/** Candidate parameter profiles (KiB). Floors motivated in the spike doc. */
const PROFILES = {
  desktop: { mKib: 128 * 1024, t: 3, p: 1 },
  'mobile-balanced': { mKib: 64 * 1024, t: 3, p: 1 },
  'mobile-low-memory': { mKib: 19 * 1024, t: 4, p: 1 },
};

test.describe('Argon2id spike', () => {
  test('A1: both candidates initialize in the worker; artifact sizes recorded', async ({ page }, info) => {
    await harness(page);
    const out = await page.evaluate(async () => {
      window.client = window.newArgonClient();
      await window.client.ready;
      const a = await window.client.request('INIT_A', {});
      const b = await window.client.request('INIT_B', {});
      return { a, b };
    });
    expect(out.a.wasmBytes).toBeGreaterThan(0);
    console.log(`[spike:${info.project.name}] init:`, JSON.stringify(out));
  });

  test('A2: candidates agree byte-for-byte across parameter sets (cross test vectors)', async ({ page }, info) => {
    await harness(page);
    const out = await page.evaluate(async () => {
      const c = window.newArgonClient();
      await c.ready;
      await c.request('INIT_A', {});
      await c.request('INIT_B', {});
      const enc = (s) => new TextEncoder().encode(s);
      const salt = Uint8Array.from({ length: 16 }, (_, i) => i * 7 + 3);
      const cases = [
        { password: enc('synthetic-test-password'), salt, mKib: 19 * 1024, t: 2, p: 1, outLen: 32 },
        { password: enc('another synthetic pw €🔑'), salt, mKib: 64 * 1024, t: 3, p: 1, outLen: 32 },
        { password: enc('parallel-lanes'), salt, mKib: 32 * 1024, t: 3, p: 4, outLen: 64 },
      ];
      const results = [];
      for (const kase of cases) {
        // eslint-disable-next-line no-await-in-loop
        results.push(await c.request('CROSS_CHECK', kase));
      }
      c.terminate();
      return results;
    });
    for (const r of out) expect(r.equal).toBe(true);
    // Known-answer stability: the first case's prefix is a regression anchor.
    console.log(`[spike:${info.project.name}] cross-check:`, JSON.stringify(out.map((r) => ({ equal: r.equal, hex: r.hex, aMs: r.aMs, bMs: r.bMs }))));
  });

  test('A3: profile benchmarks for both candidates (median of 3)', async ({ page }, info) => {
    test.setTimeout(240000);
    await harness(page);
    const out = await page.evaluate(async (profiles) => {
      const c = window.newArgonClient();
      await c.ready;
      await c.request('INIT_A', {});
      await c.request('INIT_B', {});
      const enc = new TextEncoder();
      const median = (xs) => xs.sort((x, y) => x - y)[Math.floor(xs.length / 2)];
      const rows = {};
      for (const [name, prof] of Object.entries(profiles)) {
        rows[name] = {};
        for (const impl of ['A', 'B']) {
          const times = [];
          for (let i = 0; i < 3; i += 1) {
            const salt = crypto.getRandomValues(new Uint8Array(16));
            // eslint-disable-next-line no-await-in-loop
            const r = await c.request('DERIVE', {
              impl, password: enc.encode(`bench-${i}`), salt, ...prof, outLen: 32,
            });
            times.push(r.ms);
          }
          rows[name][impl] = Math.round(median(times));
        }
      }
      c.terminate();
      return rows;
    }, PROFILES);
    console.log(`[spike:${info.project.name}] profile ms (median of 3):`, JSON.stringify(out));
    // Sanity: work scales with memory; every profile completes.
    expect(out.desktop.A).toBeGreaterThan(out['mobile-low-memory'].A);
    for (const row of Object.values(out)) for (const v of Object.values(row)) expect(v).toBeGreaterThan(0);
  });

  test('A4: a main-thread derivation starves painting; the same work in the worker does not', async ({ page }, info) => {
    test.setTimeout(120000);
    await harness(page);
    const out = await page.evaluate(async () => {
      const opts = { password: 'block-probe', salt: new Uint8Array(16).fill(9), iterations: 3, memorySize: 64 * 1024, parallelism: 1, hashLength: 32 };
      const onMain = await window.measureFrameGaps(() => window.deriveOnMain(opts));
      const c = window.newArgonClient();
      await c.ready;
      await c.request('INIT_B', {});
      const enc = new TextEncoder();
      const inWorker = await window.measureFrameGaps(() => c.request('DERIVE', {
        impl: 'B', password: enc.encode('block-probe'), salt: new Uint8Array(16).fill(9), mKib: 64 * 1024, t: 3, p: 1, outLen: 32,
      }));
      c.terminate();
      return { onMain, inWorker };
    });
    console.log(`[spike:${info.project.name}] frame starvation ms:`, JSON.stringify(out));
    // The main-thread run must visibly starve rendering (worst gap ≈ job time);
    // the worker run must keep frames flowing (well under half the job time).
    expect(out.onMain.worstGapMs).toBeGreaterThan(out.onMain.jobMs * 0.5);
    expect(out.inWorker.worstGapMs).toBeLessThan(Math.max(out.inWorker.jobMs * 0.5, 100));
  });

  test('A5: repeated derivations are stable (no degradation across 10 runs)', async ({ page }, info) => {
    test.setTimeout(120000);
    await harness(page);
    const out = await page.evaluate(async () => {
      const c = window.newArgonClient();
      await c.ready;
      await c.request('INIT_A', {});
      const enc = new TextEncoder();
      const times = [];
      for (let i = 0; i < 10; i += 1) {
        // eslint-disable-next-line no-await-in-loop
        const r = await c.request('DERIVE', {
          impl: 'A', password: enc.encode(`stab-${i}`), salt: new Uint8Array(16).fill(i), mKib: 19 * 1024, t: 2, p: 1, outLen: 32,
        });
        times.push(r.ms);
      }
      c.terminate();
      const avg = (xs) => xs.reduce((a, b) => a + b, 0) / xs.length;
      return { first3: avg(times.slice(0, 3)), last3: avg(times.slice(-3)) };
    });
    console.log(`[spike:${info.project.name}] stability ms first3/last3:`, JSON.stringify(out));
    expect(out.last3).toBeLessThan(out.first3 * 3);
  });

  test('A6: absurd memory cost fails typed, without killing the worker permanently', async ({ page }, info) => {
    test.setTimeout(120000);
    await harness(page);
    const out = await page.evaluate(async () => {
      const c = window.newArgonClient();
      await c.ready;
      await c.request('INIT_A', {});
      await c.request('INIT_B', {});
      const enc = new TextEncoder();
      const huge = { password: enc.encode('oom'), salt: new Uint8Array(16), mKib: 3 * 1024 * 1024, t: 1, p: 1, outLen: 32 };
      const tryOne = async (impl) => {
        try { await c.request('DERIVE', { ...huge, impl }); return 'completed'; }
        catch (e) { return e.code || 'error'; }
      };
      const a = await tryOne('A');
      const b = await tryOne('B');
      // Recovery: a NEW worker derives normally afterwards (a dead one is expected
      // to be replaced by the supervisor — crypto-worker spike W-F5).
      const c2 = window.newArgonClient();
      await c2.ready;
      await c2.request('INIT_A', {});
      const ok = await c2.request('DERIVE', {
        impl: 'A', password: enc.encode('after-oom'), salt: new Uint8Array(16), mKib: 8 * 1024, t: 1, p: 1, outLen: 32,
      });
      c.terminate(); c2.terminate();
      return { a, b, recoveredLen: ok.out.length };
    });
    console.log(`[spike:${info.project.name}] OOM behavior A/B:`, JSON.stringify(out));
    expect(out.a).not.toBe('completed'); // 3 GiB must not silently "work"
    expect(out.b).not.toBe('completed');
    expect(out.recoveredLen).toBe(32);
  });

  test('A7: termination mid-derivation rejects cleanly; fresh worker recovers', async ({ page }) => {
    test.setTimeout(120000);
    await harness(page);
    const out = await page.evaluate(async () => {
      const c = window.newArgonClient();
      await c.ready;
      await c.request('INIT_A', {});
      const enc = new TextEncoder();
      const slow = c.request('DERIVE', {
        impl: 'A', password: enc.encode('cancel-me'), salt: new Uint8Array(16), mKib: 512 * 1024, t: 4, p: 1, outLen: 32,
      }).catch((e) => e.code);
      await new Promise((r) => setTimeout(r, 150)); // it is now grinding
      c.terminate();
      const code = await slow;
      const c2 = window.newArgonClient();
      await c2.ready;
      await c2.request('INIT_A', {});
      const ok = await c2.request('DERIVE', {
        impl: 'A', password: enc.encode('post-cancel'), salt: new Uint8Array(16), mKib: 8 * 1024, t: 1, p: 1, outLen: 32,
      });
      c2.terminate();
      return { code, recoveredLen: ok.out.length };
    });
    expect(out.code).toBe('WORKER_TERMINATED');
    expect(out.recoveredLen).toBe(32);
  });

  test('A8: 4x CPU throttling approximates a mid-range desktop (chromium only)', async ({ page, context, browserName }, info) => {
    test.skip(browserName !== 'chromium', 'CDP CPU throttling is chromium-only');
    test.setTimeout(240000);
    await harness(page);
    const cdp = await context.newCDPSession(page);
    await cdp.send('Emulation.setCPUThrottlingRate', { rate: 4 });
    const out = await page.evaluate(async (profiles) => {
      const c = window.newArgonClient();
      await c.ready;
      await c.request('INIT_A', {});
      const enc = new TextEncoder();
      const rows = {};
      for (const [name, prof] of Object.entries(profiles)) {
        // eslint-disable-next-line no-await-in-loop
        const r = await c.request('DERIVE', {
          impl: 'A', password: enc.encode('throttle'), salt: new Uint8Array(16), ...prof, outLen: 32,
        });
        rows[name] = Math.round(r.ms);
      }
      c.terminate();
      return rows;
    }, PROFILES);
    await cdp.send('Emulation.setCPUThrottlingRate', { rate: 1 });
    console.log(`[spike:${info.project.name}] 4x-throttled profile ms:`, JSON.stringify(out));
    expect(out.desktop).toBeGreaterThan(0);
  });
});
