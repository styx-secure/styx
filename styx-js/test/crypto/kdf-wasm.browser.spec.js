// kdf-wasm.browser.spec.js — known-answer tests for styx-kdf-wasm on real
// browsers (Chromium + Firefox). The same vectors are asserted natively by
// `cargo test` and in Node by kdf-wasm.test.js; byte-identical results across
// all engines are the cross-platform correctness proof (PR-1).
// Run from styx-js/:  npx playwright test -c playwright.kdf.config.js
import { test, expect } from '@playwright/test';
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import { KDF_KAT_VECTORS, toHex } from '../fixtures/kdf-kat-vectors.js';

const STYX_JS_ROOT = normalize(join(fileURLToPath(new URL('.', import.meta.url)), '..', '..'));
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.wasm': 'application/wasm' };

let server;
let base;
test.beforeAll(async () => {
  server = http.createServer((req, res) => {
    try {
      if (req.url === '/harness') {
        res.writeHead(200, { 'content-type': 'text/html' });
        res.end('<!doctype html><html><body>kdf-kat</body></html>');
        return;
      }
      const path = normalize(join(STYX_JS_ROOT, req.url.split('?')[0]));
      if (!path.startsWith(STYX_JS_ROOT)) { res.writeHead(403); res.end(); return; }
      const body = readFileSync(path);
      res.writeHead(200, { 'content-type': MIME[extname(path)] || 'application/octet-stream' });
      res.end(body);
    } catch { res.writeHead(404); res.end(); }
  });
  await new Promise((r) => { server.listen(0, '127.0.0.1', r); });
  base = `http://127.0.0.1:${server.address().port}`;
});
test.afterAll(async () => { await new Promise((r) => { server.close(r); }); });

test('KAT vectors are byte-identical on this browser', async ({ page }, info) => {
  await page.goto(`${base}/harness`);
  const vectors = KDF_KAT_VECTORS.map((v) => ({
    name: v.name,
    password: [...v.password],
    salt: [...v.salt],
    mKib: v.mKib,
    t: v.t,
    p: v.p,
    outLen: v.outLen,
    hex: v.hex,
  }));
  const results = await page.evaluate(async ({ moduleUrl, cases }) => {
    const mod = await import(moduleUrl);
    await mod.default();
    const hex = (u8) => [...u8].map((x) => x.toString(16).padStart(2, '0')).join('');
    const out = [];
    for (const c of cases) {
      const derived = mod.argon2id_derive(
        new Uint8Array(c.password), new Uint8Array(c.salt), c.mKib, c.t, c.p, c.outLen,
      );
      out.push({ name: c.name, hex: hex(derived) });
    }
    // Absolute bounds hold in the browser too: multi-GiB is rejected typed.
    let boundsError = null;
    try {
      mod.argon2id_derive(new Uint8Array([1]), new Uint8Array(16), 3 * 1024 * 1024, 2, 1, 32);
    } catch (e) {
      boundsError = { message: String(e.message), isTrap: e instanceof WebAssembly.RuntimeError };
    }
    // K7 in the browser: 2^32+1024 must be rejected, never wrap into 1024.
    let wrapError = null;
    try {
      mod.argon2id_derive(new Uint8Array([1]), new Uint8Array(16), 2 ** 32 + 1024, 1, 1, 32);
    } catch (e) {
      wrapError = { message: String(e.message), isTrap: e instanceof WebAssembly.RuntimeError };
    }
    return { out, boundsError, wrapError };
  }, { moduleUrl: `${base}/vendor/styx-kdf-wasm/pkg/styx_kdf_wasm.js`, cases: vectors });

  for (let i = 0; i < vectors.length; i += 1) {
    expect(results.out[i].name).toBe(vectors[i].name);
    expect(results.out[i].hex).toBe(vectors[i].hex);
  }
  expect(results.boundsError).not.toBeNull();
  expect(results.boundsError.isTrap).toBe(false);
  expect(results.boundsError.message).toMatch(/^KDF_PARAMS_INVALID/);
  expect(results.wrapError).not.toBeNull();
  expect(results.wrapError.isTrap).toBe(false);
  expect(results.wrapError.message).toMatch(/^KDF_PARAMS_INVALID/);
  console.log(`[kdf-kat:${info.project.name}] ${results.out.length} vectors byte-identical; bounds typed-fail OK`);
  expect(toHex(new Uint8Array([255, 0]))).toBe('ff00'); // fixture helper sanity
});
