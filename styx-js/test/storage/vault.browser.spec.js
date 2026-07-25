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

  test('canary records round-trip through a real reopen (create→put→lock→unlock→get)', async ({ page }, info) => {
    await harness(page);
    const out = await page.evaluate(async (name) => {
      const a = await window.openLifecycle(name);
      await a.createVault('canary-pass1', { profile: 'mobile-low-memory' });
      await a.putRecord('canary', 'doc:1', { synthetic: true, n: 7 }, { contentType: 'json' });
      await a.putRecord('canary', 'blob:1', new Uint8Array([1, 2, 3, 250]), { contentType: 'bytes' });
      await a.lock();
      const b = await window.openLifecycle(name);
      await b.unlock('canary-pass1');
      const json = (await b.getRecord('canary', 'doc:1')).value;
      const bin = Array.from((await b.getRecord('canary', 'blob:1')).value);
      const keys = (await b.listRecords('canary')).sort();
      await b.destroy();
      return { json, bin, keys };
    }, dbName(info));
    expect(out.json).toEqual({ synthetic: true, n: 7 });
    expect(out.bin).toEqual([1, 2, 3, 250]);
    expect(out.keys).toEqual(['blob:1', 'doc:1']);
  });

  test('a bit-flip in a stored record → VAULT_RECORD_CORRUPTED, the rest stays readable', async ({ page }, info) => {
    await harness(page);
    const out = await page.evaluate(async (name) => {
      const a = await window.openLifecycle(name);
      await a.createVault('canary-pass1', { profile: 'mobile-low-memory' });
      await a.putRecord('canary', 'victim', { s: 'v' }, { contentType: 'json' });
      await a.putRecord('canary', 'bystander', { s: 'b' }, { contentType: 'json' });
      // Corrupt the ciphertext directly on real IndexedDB.
      const { openVaultDb } = await import('/src/storage/vault-db.js');
      const raw = await openVaultDb({ name });
      const rec = await raw.get('canary', 'victim');
      rec.data[0] ^= 0xff;
      await raw.transaction(['canary'], (ops) => ops.put('canary', 'victim', rec));
      raw.close();
      const b = await window.openLifecycle(name);
      await b.unlock('canary-pass1');
      const victimCode = await b.getRecord('canary', 'victim').then(() => 'RESOLVED', (e) => e.code);
      const bystander = (await b.getRecord('canary', 'bystander')).value;
      const stillListed = await b.listRecords('canary');
      await b.destroy();
      return { victimCode, bystander, stillListed };
    }, dbName(info));
    expect(out.victimCode).toBe('VAULT_RECORD_CORRUPTED');
    expect(out.bystander).toEqual({ s: 'b' });
    expect(out.stillListed).toContain('victim'); // never auto-deleted (§11)
  });

  test('trial v1→v2 upgrade touches only canary and is reconciled into the signed manifest', async ({ page }, info) => {
    await harness(page);
    const out = await page.evaluate(async (name) => {
      const a = await window.openLifecycle(name); // schema v1
      await a.createVault('canary-pass1', { profile: 'mobile-low-memory' });
      await a.putRecord('canary', 'kept', { before: 'upgrade' }, { contentType: 'json' });
      await a.lock();
      // Reopen at version 2 with the TRIAL migrator: the upgrade runs keyless.
      const b = await window.openLifecycle(name, { version: 2, migrations: window.trialMigrations });
      await b.unlock('canary-pass1'); // reconciles the high-water mark
      const survived = (await b.getRecord('canary', 'kept')).value;
      // Only the canary store gained the trial index.
      const { openVaultDb } = await import('/src/storage/vault-db.js');
      const raw = await openVaultDb({ name, version: 2, migrations: window.trialMigrations });
      const dbVersion = raw.version;
      const indexed = await new Promise((resolve) => {
        const tx = raw._db.transaction(['canary', 'settings'], 'readonly');
        resolve({
          canary: Array.from(tx.objectStore('canary').indexNames),
          settings: Array.from(tx.objectStore('settings').indexNames),
        });
      });
      raw.close();
      await b.destroy();
      return { survived, dbVersion, indexed };
    }, dbName(info));
    expect(out.survived).toEqual({ before: 'upgrade' });
    expect(out.dbVersion).toBe(2);
    expect(out.indexed.canary).toEqual(['trial-by-rv']);
    expect(out.indexed.settings).toEqual([]); // no other store touched
  });

  test('the vault works fully offline (no network dependency)', async ({ page, context }, info) => {
    await harness(page);
    await context.setOffline(true);
    try {
      const out = await page.evaluate(async (name) => {
        const a = await window.openLifecycle(name);
        await a.createVault('canary-pass1', { profile: 'mobile-low-memory' });
        await a.putRecord('canary', 'offline', { works: true }, { contentType: 'json' });
        const value = (await a.getRecord('canary', 'offline')).value;
        await a.lock();
        await a.unlock('canary-pass1');
        await a.destroy();
        return value;
      }, dbName(info));
      expect(out).toEqual({ works: true });
    } finally {
      await context.setOffline(false);
    }
  });

  test('external eviction of the database is survivable: reopen is UNINITIALIZED', async ({ page }, info) => {
    await harness(page);
    const out = await page.evaluate(async (name) => {
      const a = await window.openLifecycle(name);
      await a.createVault('canary-pass1', { profile: 'mobile-low-memory' });
      await a.putRecord('canary', 'doomed', { s: 1 }, { contentType: 'json' });
      await a.lock(); // release the connection so the external delete is not blocked
      await new Promise((resolve, reject) => {
        const req = indexedDB.deleteDatabase(name); // storage eviction, from outside
        req.onsuccess = () => resolve();
        req.onerror = () => reject(req.error);
        req.onblocked = () => resolve();
      });
      const b = await window.openLifecycle(name);
      return { state: (await b.status()).state, uninitialized: window.VAULT_STATES.UNINITIALIZED };
    }, dbName(info));
    expect(out.state).toBe(out.uninitialized);
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
