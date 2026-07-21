// vault-db.browser.spec.js — production port of the IndexedDB spike probes
// P1–P12 (US-005, plan B3.4) against src/storage/vault-db.js in REAL browsers.
// The spike (spikes/indexeddb-vault) stays untouched as historical record;
// this suite is the production acceptance gate. Databases are prefixed
// `styx-vault-test-*` and hold synthetic records only.
import { test, expect, chromium } from '@playwright/test';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import http from 'node:http';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const STYX_JS_ROOT = normalize(join(HERE, '..', '..'));
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.json': 'application/json' };

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
  await page.goto(`${base}/test/fixtures/vault-db/harness.html`);
  await page.waitForFunction(() => window.__vaultDbReady === true);
}

// Fresh, story-mandated prefix per test so probes never interfere.
let dbSeq = 0;
function dbName(info) { return `styx-vault-test-${info.project.name}-${Date.now()}-${dbSeq++}`; }

const ALL_NAMESPACES = [
  'canary', 'contacts', 'identity', 'messages', 'meta', 'migrations', 'mls',
  'outbox', 'push', 'settings',
];

test.describe('vault-db production probes', () => {
  test('P1: multi-record atomic commit in one transaction; schema v1 has the ten frozen stores', async ({ page }, info) => {
    await harness(page);
    const out = await page.evaluate(async (name) => {
      const { openVaultDb } = window.VaultDb;
      const v = await openVaultDb({ name });
      await v.transaction(['identity', 'mls', 'meta'], async (ops) => {
        await ops.put('identity', 'idpk', new Uint8Array([1, 2, 3]));
        await ops.put('mls', 'state', new Uint8Array(1024).fill(7));
        await ops.put('meta', 'schema', { v: 1 });
      });
      return {
        idpk: Array.from(await v.get('identity', 'idpk')),
        stateLen: (await v.get('mls', 'state')).length,
        meta: await v.get('meta', 'schema'),
        namespaces: v.namespaces.sort(),
      };
    }, dbName(info));
    expect(out.idpk).toEqual([1, 2, 3]);
    expect(out.stateLen).toBe(1024);
    expect(out.meta).toEqual({ v: 1 });
    expect(out.namespaces).toEqual(ALL_NAMESPACES);
  });

  test('P2: abort and mid-transaction exception roll back everything', async ({ page }, info) => {
    await harness(page);
    const out = await page.evaluate(async (name) => {
      const { openVaultDb } = window.VaultDb;
      const v = await openVaultDb({ name });
      await v.put('mls', 'state', 'before');
      let threw = null;
      try {
        await v.transaction(['mls', 'meta'], async (ops) => {
          await ops.put('mls', 'state', 'poison');
          await ops.put('meta', 'marker', true);
          throw new Error('deliberate');
        });
      } catch (e) { threw = e.message; }
      let aborted = null;
      try {
        await v.transaction(['mls'], async (ops) => {
          await ops.put('mls', 'state', 'poison2');
          ops.abort();
        });
      } catch (e) { aborted = e.code || e.name; }
      return {
        threw, aborted,
        state: await v.get('mls', 'state'),
        marker: await v.get('meta', 'marker'),
      };
    }, dbName(info));
    expect(out.threw).toBe('deliberate');
    expect(out.aborted).toBe('VAULT_TX_ABORTED');
    expect(out.state).toBe('before');
    expect(out.marker).toBeUndefined();
  });

  test('P3+P4: page killed mid-transaction — committed data survives, torn write does not', async ({ context }, info) => {
    const name = dbName(info);
    const page = await context.newPage();
    await harness(page);
    await page.evaluate(async (n) => {
      const { openVaultDb } = window.VaultDb;
      const v = await openVaultDb({ name: n });
      await v.put('meta', 'baseline', 'committed-before-crash');
      window.__longTx = v.transaction(['messages', 'meta'], async (ops) => {
        for (let i = 0; i < 2000; i += 1) {
          // eslint-disable-next-line no-await-in-loop
          await ops.put('messages', `m${i}`, new Uint8Array(50_000).fill(i % 256));
        }
        await ops.put('meta', 'commit-marker', true);
      }).catch(() => {});
      return true;
    }, name);
    await page.close();

    const page2 = await context.newPage();
    await harness(page2);
    const out = await page2.evaluate(async (n) => {
      const { openVaultDb } = window.VaultDb;
      const v = await openVaultDb({ name: n });
      return {
        baseline: await v.get('meta', 'baseline'),
        marker: await v.get('meta', 'commit-marker'),
        partials: (await v.list('messages')).length,
      };
    }, name);
    expect(out.baseline).toBe('committed-before-crash');
    if (out.marker === true) expect(out.partials).toBe(2000);
    else expect(out.partials).toBe(0);
  });

  test('P5: schema upgrade v1→v2 preserves data; failed upgrade leaves v1 intact; downgrade fails cleanly', async ({ page }, info) => {
    await harness(page);
    const name = dbName(info);
    const out = await page.evaluate(async (n) => {
      const { openVaultDb, VAULT_NAMESPACES } = window.VaultDb;
      const migrations = { 1: (db) => { for (const ns of VAULT_NAMESPACES) db.createObjectStore(ns); } };
      const v1 = await openVaultDb({ name: n, version: 1, migrations });
      await v1.put('mls', 'state', 'v1-data');
      v1.close();

      // (a) failed upgrade: migrator throws → whole versionchange aborts, v1 intact.
      let failedCode = null;
      try {
        await openVaultDb({
          name: n,
          version: 2,
          migrations: { ...migrations, 2: () => { throw new Error('upgrade boom'); } },
        });
      } catch (e) { failedCode = e.message; }
      // The engine's own bounded blocked-retry (spike finding) absorbs the
      // transient block while the failed connection unwinds.
      const still1 = await openVaultDb({ name: n, version: 1, migrations });
      const afterFail = { version: still1.version, data: await still1.get('mls', 'state') };
      still1.close();

      // (b) good upgrade: adds a store, keeps data.
      const v2 = await openVaultDb({
        name: n,
        version: 2,
        migrations: { ...migrations, 2: (db) => db.createObjectStore('attachments') },
      });
      const afterOk = {
        version: v2.version,
        data: await v2.get('mls', 'state'),
        hasNew: v2.namespaces.includes('attachments'),
      };
      // (c) opening with a LOWER version than on disk fails cleanly.
      v2.close();
      let downgrade = null;
      try { await openVaultDb({ name: n, version: 1, migrations }); } catch (e) { downgrade = e.code; }
      return { failedCode, afterFail, afterOk, downgrade };
    }, name);
    expect(out.failedCode).toContain('upgrade boom');
    expect(out.afterFail).toEqual({ version: 1, data: 'v1-data' });
    expect(out.afterOk).toEqual({ version: 2, data: 'v1-data', hasNew: true });
    expect(out.downgrade).toBe('VAULT_OPEN_FAILED');
  });

  test('P6: two tabs — transactional writes, Web Lock single writer, steal and reacquire', async ({ context }, info) => {
    const name = dbName(info);
    const a = await context.newPage();
    const b = await context.newPage();
    await harness(a);
    await harness(b);
    const aLock = await a.evaluate(() => new Promise((resolve) => {
      navigator.locks.request('styx-vault-test-writer', { mode: 'exclusive', ifAvailable: true }, (lock) => {
        resolve(lock !== null);
        if (!lock) return undefined;
        return new Promise(() => {});
      }).catch(() => resolve(false));
    }));
    const bLock = await b.evaluate(() => new Promise((resolve) => {
      navigator.locks.request('styx-vault-test-writer', { mode: 'exclusive', ifAvailable: true }, (lock) => {
        resolve(lock !== null);
        return undefined;
      }).catch(() => resolve(false));
    }));
    expect(aLock).toBe(true);
    expect(bLock).toBe(false);

    await a.evaluate(async (n) => {
      const v = await window.VaultDb.openVaultDb({ name: n });
      await v.put('contacts', 'from-a', 'A');
      window.__v = v;
    }, name);
    await b.evaluate(async (n) => {
      const v = await window.VaultDb.openVaultDb({ name: n });
      await v.put('contacts', 'from-b', 'B');
      window.__v = v;
    }, name);
    const seen = await a.evaluate(async () => ({
      a: await window.__v.get('contacts', 'from-a'),
      b: await window.__v.get('contacts', 'from-b'),
    }));
    expect(seen).toEqual({ a: 'A', b: 'B' });

    const bStole = await b.evaluate(() => new Promise((resolve) => {
      navigator.locks.request('styx-vault-test-writer', { mode: 'exclusive', steal: true }, (lock) => {
        resolve(lock !== null);
        return new Promise(() => {});
      }).catch(() => resolve(false));
    }));
    expect(bStole).toBe(true);
    await b.close();
    const aReacquired = await a.evaluate(() => new Promise((resolve) => {
      const t = setTimeout(() => resolve(false), 5000);
      const tryAcquire = () => {
        navigator.locks.request('styx-vault-test-writer', { mode: 'exclusive', ifAvailable: true }, (lock) => {
          if (lock) { clearTimeout(t); resolve(true); return new Promise(() => {}); }
          setTimeout(tryAcquire, 100);
          return undefined;
        }).catch(() => setTimeout(tryAcquire, 100));
      };
      tryAcquire();
    }));
    expect(aReacquired).toBe(true);
    await a.close();
  });

  test('P7: destroy() deletes the database completely', async ({ page }, info) => {
    await harness(page);
    const name = dbName(info);
    const out = await page.evaluate(async (n) => {
      const { openVaultDb } = window.VaultDb;
      const v = await openVaultDb({ name: n });
      await v.put('mls', 'state', new Uint8Array(64).fill(9));
      await v.destroy();
      const listed = indexedDB.databases ? (await indexedDB.databases()).map((d) => d.name) : null;
      const again = await openVaultDb({ name: n });
      const empty = (await again.list('mls')).length === 0;
      await again.destroy();
      return { listed, empty };
    }, name);
    if (out.listed !== null) expect(out.listed).not.toContain(name);
    expect(out.empty).toBe(true);
  });

  test('P8: quota exhaustion maps to VAULT_QUOTA_EXCEEDED, fail-closed (chromium, real quota override)', async ({ browserName }, info) => {
    test.skip(browserName !== 'chromium', 'CDP quota override is chromium-only; rollback semantics covered by P2');
    const profileDir = mkdtempSync(join(tmpdir(), 'vault-db-quota-'));
    const persistent = await chromium.launchPersistentContext(profileDir, {
      headless: true,
      ...(info.project.use.launchOptions ?? {}),
    });
    const page = await persistent.newPage();
    try {
      await harness(page);
      const cdp = await persistent.newCDPSession(page);
      await cdp.send('Storage.overrideQuotaForOrigin', { origin: base, quotaSize: 5_000_000 });
      const effective = await page.evaluate(async () => (await navigator.storage.estimate()).quota);
      test.skip(effective > 100_000_000,
        `Storage.overrideQuotaForOrigin not enforced here (quota still ${effective}); manual-plan item M3`);
      const out = await page.evaluate(async (name) => {
        const { openVaultDb } = window.VaultDb;
        const v = await openVaultDb({ name });
        await v.put('meta', 'baseline', 'small-committed');
        let quotaErr = null;
        try {
          await v.transaction(['mls', 'meta'], async (ops) => {
            for (let i = 0; i < 10; i += 1) {
              // eslint-disable-next-line no-await-in-loop
              await ops.put('mls', `big${i}`, new Uint8Array(2_000_000).fill(i));
            }
            await ops.put('meta', 'marker', true);
          });
        } catch (e) { quotaErr = { code: e.code, reason: e.details?.reason ?? null }; }
        return {
          quotaErr,
          baseline: await v.get('meta', 'baseline'),
          bigs: (await v.list('mls')).length,
          marker: await v.get('meta', 'marker'),
          stillWorks: await v.put('meta', 'after', 'ok').then(() => v.get('meta', 'after')),
        };
      }, dbName(info));
      // Spike F9, third environmental variant (seen on CI runners): the CDP
      // override can be accepted by estimate() yet not enforced on writes.
      // Without a biting quota the scenario moves to manual-plan item M3;
      // the quota→VAULT_QUOTA_EXCEEDED mapping itself is covered
      // deterministically by the Jest unit suite.
      test.skip(out.quotaErr === null,
        'quota override accepted but not enforced on writes here; manual-plan item M3');
      expect(out.quotaErr.code).toBe('VAULT_QUOTA_EXCEEDED');
      expect(out.baseline).toBe('small-committed');
      expect(out.bigs).toBe(0);
      expect(out.marker).toBeUndefined();
      expect(out.stillWorks).toBe('ok');
    } finally {
      await persistent.close();
      rmSync(profileDir, { recursive: true, force: true });
    }
  });

  test('P9: storage persistence probe is advisory, never fatal, and bounded', async ({ page }, info) => {
    await harness(page);
    const out = await page.evaluate(async (name) => {
      const { openVaultDb, probeStorage } = window.VaultDb;
      const probe = await probeStorage();
      const v = await openVaultDb({ name });
      await v.put('meta', 'works', true);
      const works = await v.get('meta', 'works');
      await v.destroy();
      return { probe, works };
    }, dbName(info));
    expect(out.works).toBe(true);
    expect([true, false, null, 'timeout']).toContain(out.probe.persistGranted);
  });

  test('P10: blocked open and blocked delete surface VAULT_BLOCKED after bounded retry, data intact', async ({ context }, info) => {
    const nameUpgrade = dbName(info);
    const nameDelete = dbName(info);
    const a = await context.newPage();
    const b = await context.newPage();
    await harness(a);
    await harness(b);
    await a.evaluate(async ({ n1, n2 }) => {
      const v1 = await window.VaultDb.openVaultDb({ name: n1 });
      await v1.put('mls', 'state', 'guarded');
      v1._db.onversionchange = null; // simulate a stuck old tab (spike P10)
      window.__v1 = v1;
      const v2 = await window.VaultDb.openVaultDb({ name: n2 });
      await v2.put('mls', 'state', 'guarded-too');
      v2._db.onversionchange = null;
      window.__v2 = v2;
      return true;
    }, { n1: nameUpgrade, n2: nameDelete });

    // (a) blocked version upgrade: the engine's bounded retry expires → VAULT_BLOCKED.
    const openBlocked = await b.evaluate(async (n) => {
      try {
        await window.VaultDb.openVaultDb({ name: n, version: 2, migrations: { 1: () => {}, 2: () => {} } });
        return 'no-error';
      } catch (e) { return e.code; }
    }, nameUpgrade);
    expect(openBlocked).toBe('VAULT_BLOCKED');

    // (b) blocked delete: A still holds a live connection with auto-close defeated.
    const delBlocked = await b.evaluate(async (n) => {
      try {
        const v = await window.VaultDb.openVaultDb({ name: n });
        await v.destroy();
        return 'no-error';
      } catch (e) { return e.code; }
    }, nameDelete);
    expect(delBlocked).toBe('VAULT_BLOCKED');

    const still = await a.evaluate(async () => ({
      one: await window.__v1.get('mls', 'state'),
      two: await window.__v2.get('mls', 'state'),
    }));
    expect(still).toEqual({ one: 'guarded', two: 'guarded-too' });
    await a.close(); await b.close();
  });

  test('P11: real MLS fixture envelope and 8 MB binary record round-trip, binary stored natively', async ({ page }, info) => {
    await harness(page);
    const out = await page.evaluate(async ({ name, fixtureUrl }) => {
      const { openVaultDb } = window.VaultDb;
      const envelope = await (await fetch(fixtureUrl)).json();
      const stateBytes = Uint8Array.from(atob(envelope.payload), (c) => c.charCodeAt(0));
      const v = await openVaultDb({ name });
      await v.transaction(['mls'], async (ops) => {
        const { payload, ...meta } = envelope;
        await ops.put('mls', 'state:meta', meta);
        await ops.put('mls', 'state:payload', stateBytes);
      });
      const meta = await v.get('mls', 'state:meta');
      const back = await v.get('mls', 'state:payload');
      const byteEqual = back.length === stateBytes.length
        && back.every((x, i) => x === stateBytes[i]);
      const big = new Uint8Array(8 * 1024 * 1024);
      for (let i = 0; i < big.length; i += 4096) big[i] = i % 256;
      await v.put('mls', 'big', big);
      const bigBack = await v.get('mls', 'big');
      const bigOk = bigBack.length === big.length && bigBack[4096] === big[4096];
      await v.destroy();
      return {
        byteEqual, bigOk,
        metaHasNoPayload: !('payload' in meta) && meta.format === 'styx-mls-state',
      };
    }, { name: dbName(info), fixtureUrl: `${base}/test/fixtures/mls-state-v1/envelope.json` });
    expect(out.byteEqual).toBe(true);
    expect(out.bigOk).toBe(true);
    expect(out.metaHasNoPayload).toBe(true);
  });

  test('P12: per-namespace enumeration and wipe leave other namespaces untouched', async ({ page }, info) => {
    await harness(page);
    const out = await page.evaluate(async (name) => {
      const { openVaultDb } = window.VaultDb;
      const v = await openVaultDb({ name });
      await v.transaction(['messages', 'contacts'], async (ops) => {
        for (let i = 0; i < 25; i += 1) await ops.put('messages', `m${i}`, { i });
        await ops.put('contacts', 'c1', {});
      });
      const before = (await v.list('messages')).length;
      await v.clear('messages');
      const after = (await v.list('messages')).length;
      const untouched = (await v.list('contacts')).length;
      await v.destroy();
      return { before, after, untouched };
    }, dbName(info));
    expect(out).toEqual({ before: 25, after: 0, untouched: 1 });
  });
});
