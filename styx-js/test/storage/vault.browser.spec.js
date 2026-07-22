// vault.browser.spec.js — the vault lifecycle (vault.js) exercised end-to-end
// against the REAL IndexedDB engine and a REAL Argon2id KEK (US-006). The Jest
// suite covers the state machine and the deterministic §7.2 crash points with a
// fake db; this suite proves the wrapper round-trips through real structured
// clone and that recovery survives a real reopen. Databases are prefixed
// styx-vault-test-* (US-005 convention); no product data.
import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import http from 'node:http';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const STYX_JS_ROOT = normalize(join(HERE, '..', '..'));
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.wasm': 'application/wasm', '.json': 'application/json' };

let server;
let base;

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
  await page.goto(`${base}/test/fixtures/vault/harness.html`);
  await page.waitForFunction(() => window.__vaultLifecycleReady === true);
}

let seq = 0;
const dbName = (info) => `styx-vault-test-lc-${info.project.name}-${Date.now()}-${seq++}`;

test.describe('vault lifecycle on real IndexedDB', () => {
  test('create → lock → reopen → unlock persists across a fresh engine', async ({ page }, info) => {
    await harness(page);
    const out = await page.evaluate(async (name) => {
      const S = window.VAULT_STATES;
      const a = await window.openLifecycle(name);
      const created = (await a.createVault('correct-horse1', { profile: 'mobile-low-memory' })).state;
      await a.lock();
      // Fresh vault instance + fresh engine on the SAME database = real reopen.
      const b = await window.openLifecycle(name);
      const opened = (await b.status()).state;
      // Wrong password first (still LOCKED), non-destructive, then the real one.
      const wrongCode = await b.unlock('wrongpass1').then(() => 'RESOLVED', (e) => e.code);
      const unlocked = (await b.unlock('correct-horse1')).state;
      await b.destroy();
      return { created, opened, unlocked, wrongCode, S };
    }, dbName(info));
    expect(out.created).toBe(out.S.UNLOCKED);
    expect(out.opened).toBe(out.S.LOCKED);
    expect(out.unlocked).toBe(out.S.UNLOCKED);
    expect(out.wrongCode).toBe('VAULT_WRONG_PASSWORD');
  });

  test('changePassword persists: old password fails, new works after reopen', async ({ page }, info) => {
    await harness(page);
    const out = await page.evaluate(async (name) => {
      const a = await window.openLifecycle(name);
      await a.createVault('old-pass1', { profile: 'mobile-low-memory' });
      await a.changePassword('new-pass1', { profile: 'mobile-low-memory' });
      const b = await window.openLifecycle(name);
      const oldCode = await b.unlock('old-pass1').then(() => 'RESOLVED', (e) => e.code);
      const newState = (await b.unlock('new-pass1')).state;
      await b.destroy();
      return { oldCode, newState, unlocked: window.VAULT_STATES.UNLOCKED };
    }, dbName(info));
    expect(out.oldCode).toBe('VAULT_WRONG_PASSWORD');
    expect(out.newState).toBe(out.unlocked);
  });

  test('orphan pending re-wrap is recovered across a real reopen (§7.2 RECOVERING)', async ({ page }, info) => {
    await harness(page);
    const out = await page.evaluate(async (name) => {
      const S = window.VAULT_STATES;
      const a = await window.openLifecycle(name);
      await a.createVault('old-pass1', { profile: 'mobile-low-memory' });
      // Simulate a crash between staging and commit by writing an orphan
      // pending directly into the active wrapper on real IndexedDB, exactly as
      // a crashed re-wrap would leave it (the pending is a copy of the active,
      // which is enough to exercise the keyless RECOVERING sweep on reopen).
      const { openVaultDb } = await import('/src/storage/vault-db.js');
      const db = await openVaultDb({ name });
      const active = await db.get('meta', 'wrapper');
      await db.transaction(['meta'], (ops) => ops.put('meta', 'wrapper', { ...active, rewrapPending: { ...active, rewrapPending: null } }));
      db.close();
      // Reopen: loading must run RECOVERING, discard the orphan, land LOCKED.
      const b = await window.openLifecycle(name);
      const opened = (await b.status()).state;
      const unlocked = (await b.unlock('old-pass1')).state;
      await b.destroy();
      return { opened, unlocked, locked: S.LOCKED, unlockedState: S.UNLOCKED };
    }, dbName(info));
    expect(out.opened).toBe(out.locked); // orphan discarded, back to LOCKED
    expect(out.unlocked).toBe(out.unlockedState); // old password still works
  });

  test('destroy leaves no database behind', async ({ page }, info) => {
    await harness(page);
    const out = await page.evaluate(async (name) => {
      const a = await window.openLifecycle(name);
      await a.createVault('pw-eight!!', { profile: 'mobile-low-memory' });
      await a.destroy();
      const listed = indexedDB.databases ? (await indexedDB.databases()).map((d) => d.name) : null;
      return { listed, name };
    }, dbName(info));
    if (out.listed !== null) expect(out.listed).not.toContain(out.name);
  });
});
