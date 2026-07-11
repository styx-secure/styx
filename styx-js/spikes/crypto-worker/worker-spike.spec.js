// worker-spike.spec.js — STYX_SPIKE_PROTOTYPE. Real-browser probes for the Crypto
// Worker architecture (Blocco 3): WASM in a dedicated module worker, typed message
// boundary, transfers, errors, termination/recovery, Web Locks, IndexedDB ownership,
// and the REAL production CSP. Results: docs/superpowers/spikes/2026-07-12-crypto-worker.md
import { test, expect } from '@playwright/test';
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildCsp } from '../../apps/chat/static-server.mjs'; // the REAL production CSP

const HERE = fileURLToPath(new URL('.', import.meta.url));
const STYX_JS_ROOT = normalize(join(HERE, '..', '..'));
const MIME = {
  '.html': 'text/html', '.js': 'text/javascript', '.json': 'application/json', '.wasm': 'application/wasm',
};

function makeServer({ csp } = {}) {
  return http.createServer((req, res) => {
    try {
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

let server; let base;               // plain server
let cspServer; let cspBase;         // server with the REAL production CSP

test.beforeAll(async () => {
  server = makeServer({});
  cspServer = makeServer({ csp: buildCsp() });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  await new Promise((r) => cspServer.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
  cspBase = `http://127.0.0.1:${cspServer.address().port}`;
});
test.afterAll(async () => {
  await new Promise((r) => server.close(r));
  await new Promise((r) => cspServer.close(r));
});

async function harness(page, origin = base) {
  await page.goto(`${origin}/spikes/crypto-worker/harness.html`);
  await page.waitForFunction(() => window.__cryptoSpikeReady === true);
}

/** Boot a client + WASM inside the worker. Returns init timing. */
async function initClient(page) {
  return page.evaluate(async () => {
    window.client = window.newClient();
    await window.client.ready;
    return window.client.request('INIT', { wasmUrl: '/vendor/openmls-wasm/openmls_wasm_bg.wasm' });
  });
}

const FIXTURE = '/test/fixtures/mls-state-v1';

test.describe('Crypto Worker spike', () => {
  test('W1: the vendored WASM initializes inside a dedicated module worker', async ({ page }, info) => {
    await harness(page);
    const out = await initClient(page);
    expect(out.wasmInitMs).toBeGreaterThan(0);
    console.log(`[spike:${info.project.name}] worker wasm init ms:`, JSON.stringify(out));
  });

  test('W2: real fixture restores IN the worker; ratchet decrypts; serialize round-trips', async ({ page }) => {
    await harness(page);
    await initClient(page);
    const out = await page.evaluate(async (fixture) => {
      const envelope = await (await fetch(`${fixture}/envelope.json`)).json();
      const ctx = await (await fetch(`${fixture}/context.json`)).json();
      const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
      const { members } = await window.client.request('MLS_RESTORE', {
        name: ctx.name,
        idpk: b64(ctx.idpk),
        state: b64(envelope.payload),
        groupMap: ctx.groups,
      });
      const { plaintext } = await window.client.request('MLS_DECRYPT', {
        contact: ctx.peer,
        ciphertext: b64(ctx.refCiphertext),
      });
      const { state } = await window.client.request('MLS_SERIALIZE', {});
      // Round-trip: a SECOND worker restores from the serialized output.
      const c2 = window.newClient();
      await c2.ready;
      await c2.request('INIT', { wasmUrl: '/vendor/openmls-wasm/openmls_wasm_bg.wasm' });
      const again = await c2.request('MLS_RESTORE', {
        name: ctx.name, idpk: b64(ctx.idpk), state, groupMap: ctx.groups,
      });
      c2.terminate();
      return {
        members,
        expectedMembers: [ctx.name, ctx.peer].sort(),
        peer: ctx.peer,
        text: new TextDecoder().decode(plaintext),
        expected: ctx.refPlaintext,
        roundTripMembers: again.members,
      };
    }, FIXTURE);
    expect(out.members[out.peer].sort()).toEqual(out.expectedMembers);
    expect(out.text).toBe(out.expected);
    expect(out.roundTripMembers[out.peer].sort()).toEqual(out.expectedMembers);
  });

  test('W3: ArrayBuffer transfer is zero-copy (source neutered) and faster than clone for 8 MB', async ({ page }, info) => {
    await harness(page);
    await initClient(page);
    const out = await page.evaluate(async () => {
      const mk = () => new Uint8Array(8 * 1024 * 1024).fill(7);
      // Copy (structured clone): source stays intact.
      const a = mk();
      const t0 = performance.now();
      await window.client.request('ECHO_TRANSFER', { buf: a, transferBack: false });
      const cloneMs = performance.now() - t0;
      const cloneSourceIntact = a.byteLength === 8 * 1024 * 1024;
      // Transfer: source is neutered (byteLength 0) — proves no second copy exists.
      const b = mk();
      const t1 = performance.now();
      await window.client.request('ECHO_TRANSFER', { buf: b, transferBack: true }, [b.buffer]);
      const transferMs = performance.now() - t1;
      const transferSourceNeutered = b.byteLength === 0;
      return { cloneMs, transferMs, cloneSourceIntact, transferSourceNeutered };
    });
    expect(out.cloneSourceIntact).toBe(true);
    expect(out.transferSourceNeutered).toBe(true);
    console.log(`[spike:${info.project.name}] 8MB round-trip ms:`, JSON.stringify({ clone: out.cloneMs, transfer: out.transferMs }));
  });

  test('W4: errors cross the boundary typed and allowlisted; the worker survives them', async ({ page }) => {
    await harness(page);
    await initClient(page);
    const out = await page.evaluate(async () => {
      const garbage = new Uint8Array(256).fill(65);
      let err = null;
      try {
        await window.client.request('UNLOCK', { name: 'aa'.repeat(32), idpk: new Uint8Array(32), state: garbage });
      } catch (e) { err = { code: e.code, message: e.message }; }
      // The worker must still answer after the failure.
      const alive = await window.client.request('UNLOCK', { name: 'bb'.repeat(32) });
      const badType = await window.client.request('NOPE', {}).catch((e) => e.code);
      return { err, alive: alive.unlocked, badType };
    });
    expect(out.err.code).toBe('MLS_RESTORE_FAILED');
    expect(out.err.message).not.toContain('AAAA'); // no payload material in the error
    expect(out.alive).toBe(true);
    expect(out.badType).toBe('WORKER_BAD_REQUEST');
  });

  test('W5: termination mid-operation rejects pending requests; a fresh worker recovers', async ({ page }) => {
    await harness(page);
    await initClient(page);
    const out = await page.evaluate(async () => {
      const busy = window.client.request('BUSY', { ms: 15000 }).catch((e) => e.code);
      const alsoPending = window.client.request('MLS_SERIALIZE', {}).catch((e) => e.code);
      await new Promise((r) => setTimeout(r, 100)); // the worker is now inside BUSY
      window.client.terminate();
      const codes = [await busy, await alsoPending];
      const pendingAfter = window.client.pendingCount;
      // Recovery: a brand-new worker initializes and works.
      const c2 = window.newClient();
      await c2.ready;
      const init = await c2.request('INIT', { wasmUrl: '/vendor/openmls-wasm/openmls_wasm_bg.wasm' });
      const fresh = await c2.request('UNLOCK', { name: 'cc'.repeat(32) });
      c2.terminate();
      return { codes, pendingAfter, recovered: fresh.unlocked, initMs: init.wasmInitMs };
    });
    expect(out.codes).toEqual(['WORKER_TERMINATED', 'WORKER_TERMINATED']);
    expect(out.pendingAfter).toBe(0);
    expect(out.recovered).toBe(true);
  });

  test('W6: a posted WASM handle crosses as an inert pointer — NO DataCloneError safety net', async ({ page }) => {
    // The valuable (and initially counter-intuitive) finding W-F3: wasm-bindgen
    // wrappers structured-clone fine, so the platform will NOT catch an accidental
    // postMessage of a live Provider. The clone is inert (a bare pointer into the
    // worker's memory, no key material), but boundary safety must come from the
    // typed protocol's allowlist, not from DataCloneError.
    await harness(page);
    await initClient(page);
    const out = await page.evaluate(async () => {
      await window.client.request('UNLOCK', { name: 'dd'.repeat(32) });
      const stray = new Promise((resolve) => {
        window.client._worker.addEventListener('message', (ev) => {
          if (ev.data?.id === -1) resolve(ev.data.stray.leaked);
        });
      });
      const probe = await window.client.request('LEAK_PROBE', {});
      const leakedClone = await stray;
      return {
        probe,
        cloneKeys: Object.keys(leakedClone),
        cloneValues: Object.values(leakedClone).map((v) => typeof v),
      };
    });
    expect(out.probe.cloned).toBe(true); // the platform did NOT refuse
    // ...but what crossed is only the inert pointer, never byte arrays/keys.
    expect(out.cloneKeys).toEqual(['__wbg_ptr']);
    expect(out.cloneValues).toEqual(['number']);
  });

  test('W7: Web Locks are shared between page and worker (single-writer holds across the boundary)', async ({ page }) => {
    await harness(page);
    await initClient(page);
    const out = await page.evaluate(async () => {
      // Page takes the writer lock (as useStyxChat does today)...
      let release;
      await new Promise((resolve) => {
        navigator.locks.request('styx-worker-spike-lock', { mode: 'exclusive', ifAvailable: true }, (lock) => {
          resolve(lock !== null);
          return new Promise((free) => { release = free; });
        });
      });
      // ...the WORKER must see it as taken...
      const whileHeld = await window.client.request('LOCK_PROBE', { name: 'styx-worker-spike-lock' });
      release();
      await new Promise((r) => setTimeout(r, 50));
      // ...and can acquire it once the page releases.
      const afterRelease = await window.client.request('LOCK_PROBE', { name: 'styx-worker-spike-lock' });
      return { whileHeld: whileHeld.granted, afterRelease: afterRelease.granted };
    });
    expect(out.whileHeld).toBe(false);
    expect(out.afterRelease).toBe(true);
  });

  test('W8: the worker owns IndexedDB (vault prototype runs inside it, binary round-trip)', async ({ page }) => {
    await harness(page);
    await initClient(page);
    const out = await page.evaluate(async () => {
      const bytes = new Uint8Array(64 * 1024).map((_, i) => i % 251);
      await window.client.request('VAULT_PUT', { ns: 'mls', key: 'state:payload', value: bytes });
      const { value } = await window.client.request('VAULT_GET', { ns: 'mls', key: 'state:payload' });
      return { ok: value.length === bytes.length && value[12345] === bytes[12345] };
    });
    expect(out.ok).toBe(true);
  });

  test('W9: repeated restore/serialize cycles stay stable (coarse leak probe)', async ({ page }, info) => {
    await harness(page);
    await initClient(page);
    const out = await page.evaluate(async (fixture) => {
      const envelope = await (await fetch(`${fixture}/envelope.json`)).json();
      const ctx = await (await fetch(`${fixture}/context.json`)).json();
      const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
      const state = b64(envelope.payload);
      const idpk = b64(ctx.idpk);
      const times = [];
      for (let i = 0; i < 50; i += 1) {
        const t0 = performance.now();
        // eslint-disable-next-line no-await-in-loop
        await window.client.request('MLS_RESTORE', { name: ctx.name, idpk, state, groupMap: ctx.groups });
        // eslint-disable-next-line no-await-in-loop
        await window.client.request('MLS_SERIALIZE', {});
        times.push(performance.now() - t0);
      }
      const avg = (xs) => xs.reduce((a, b) => a + b, 0) / xs.length;
      return { first10: avg(times.slice(0, 10)), last10: avg(times.slice(-10)) };
    }, FIXTURE);
    // Stability, not micro-benchmarking: the tail must not degrade pathologically.
    expect(out.last10).toBeLessThan(Math.max(out.first10 * 5, 50));
    console.log(`[spike:${info.project.name}] restore+serialize avg ms first10/last10:`, JSON.stringify(out));
  });

  test('W10: everything works under the REAL production CSP; blob: workers stay blocked', async ({ page }, info) => {
    await harness(page, cspBase);
    const init = await initClient(page);
    const out = await page.evaluate(async (fixture) => {
      const envelope = await (await fetch(`${fixture}/envelope.json`)).json();
      const ctx = await (await fetch(`${fixture}/context.json`)).json();
      const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
      const { members } = await window.client.request('MLS_RESTORE', {
        name: ctx.name, idpk: b64(ctx.idpk), state: b64(envelope.payload), groupMap: ctx.groups,
      });
      // Negative control: worker-src 'self' must refuse a blob: worker.
      let blobBlocked = false;
      try {
        const url = URL.createObjectURL(new Blob(['self.postMessage(1)'], { type: 'text/javascript' }));
        const w = new Worker(url);
        await new Promise((resolve, reject) => {
          w.onmessage = resolve; w.onerror = reject;
          setTimeout(() => reject(new Error('no answer')), 2000);
        });
      } catch { blobBlocked = true; }
      return { restored: Object.keys(members).length === 1, blobBlocked };
    }, FIXTURE);
    expect(out.restored).toBe(true);
    expect(out.blobBlocked).toBe(true);
    console.log(`[spike:${info.project.name}] wasm init under production CSP ms:`, JSON.stringify(init));
  });
});
