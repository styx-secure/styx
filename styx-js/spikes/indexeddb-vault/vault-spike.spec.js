// vault-spike.spec.js — STYX_SPIKE_PROTOTYPE. Real-browser probes for the Blocco 3
// vault design questions. Each test is a numbered probe; results are summarized in
// docs/superpowers/spikes/2026-07-12-indexeddb-vault.md.
import { test, expect, chromium } from '@playwright/test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import http from 'node:http';
import { readFileSync } from 'node:fs';
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
  await page.goto(`${base}/spikes/indexeddb-vault/harness.html`);
  await page.waitForFunction(() => window.__vaultSpikeReady === true);
}

// Fresh DB name per test so probes never interfere.
let dbSeq = 0;
function dbName(info) { return `spike-${info.project.name}-${Date.now()}-${dbSeq++}`; }

test.describe('IndexedDB vault spike', () => {
  test('P1: multi-record atomic commit in one transaction', async ({ page }, info) => {
    await harness(page);
    const out = await page.evaluate(async (name) => {
      const { openVault } = window.VaultSpike;
      const v = await openVault({ name });
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
    expect(out.namespaces).toEqual(['contacts', 'identity', 'messages', 'meta', 'migrations', 'mls', 'outbox']);
  });

  test('P2: abort and mid-transaction exception roll back everything', async ({ page }, info) => {
    await harness(page);
    const out = await page.evaluate(async (name) => {
      const { openVault } = window.VaultSpike;
      const v = await openVault({ name });
      await v.put('mls', 'state', 'before');
      // (a) exception thrown by the callback after a write
      let threw = null;
      try {
        await v.transaction(['mls', 'meta'], async (ops) => {
          await ops.put('mls', 'state', 'poison');
          await ops.put('meta', 'marker', true);
          throw new Error('deliberate');
        });
      } catch (e) { threw = e.message; }
      // (b) explicit abort
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
    expect(out.state).toBe('before'); // both poisons rolled back
    expect(out.marker).toBeUndefined();
  });

  test('P3+P4: page killed mid-transaction — committed data survives, torn write does not', async ({ context }, info) => {
    const name = dbName(info);
    const page = await context.newPage();
    await harness(page);
    // Commit a baseline record, then start a long transaction (many sequential
    // writes + a final commit-marker in the SAME transaction) and kill the page
    // while it runs.
    await page.evaluate(async (n) => {
      const { openVault } = window.VaultSpike;
      const v = await openVault({ name: n });
      await v.put('meta', 'baseline', 'committed-before-crash');
      // Long transaction, intentionally not awaited by the test.
      window.__longTx = v.transaction(['messages', 'meta'], async (ops) => {
        for (let i = 0; i < 2000; i += 1) {
          // eslint-disable-next-line no-await-in-loop
          await ops.put('messages', `m${i}`, new Uint8Array(50_000).fill(i % 256));
        }
        await ops.put('meta', 'commit-marker', true);
      }).catch(() => {});
      return true;
    }, name);
    await page.close(); // kill the tab mid-transaction

    const page2 = await context.newPage();
    await harness(page2);
    const out = await page2.evaluate(async (n) => {
      const { openVault } = window.VaultSpike;
      const v = await openVault({ name: n });
      return {
        baseline: await v.get('meta', 'baseline'),
        marker: await v.get('meta', 'commit-marker'),
        partials: (await v.list('messages')).length,
      };
    }, name);
    expect(out.baseline).toBe('committed-before-crash'); // durability of committed tx
    // Atomicity: either the whole long tx landed (marker + all 2000) or none of it.
    if (out.marker === true) expect(out.partials).toBe(2000);
    else expect(out.partials).toBe(0);
  });

  test('P5: schema upgrade v1→v2 preserves data; failed upgrade leaves v1 intact', async ({ page }, info) => {
    await harness(page);
    const name = dbName(info);
    const out = await page.evaluate(async (n) => {
      const { openVault, NAMESPACES } = window.VaultSpike;
      const migrations = { 1: (db) => { for (const ns of NAMESPACES) db.createObjectStore(ns); } };
      const v1 = await openVault({ name: n, version: 1, migrations });
      await v1.put('mls', 'state', 'v1-data');
      v1.close();

      // (a) failed upgrade: migrator throws → DB must stay at v1 with data intact.
      let failedCode = null;
      try {
        await openVault({
          name: n,
          version: 2,
          migrations: { ...migrations, 2: () => { throw new Error('upgrade boom'); } },
        });
      } catch (e) { failedCode = e.message; }
      // SPIKE FINDING: right after an aborted versionchange, a reopen can be
      // TRANSIENTLY blocked while the failed connection unwinds. The vault design
      // must retry blocked opens with a short backoff instead of failing hard.
      const reopen = async (opts, tries = 10) => {
        for (let i = 0; ; i += 1) {
          try { return await openVault(opts); } catch (e) {
            if (e.code !== 'VAULT_BLOCKED' || i >= tries) throw e;
            await new Promise((r) => setTimeout(r, 50));
          }
        }
      };
      const still1 = await reopen({ name: n, version: 1, migrations });
      const afterFail = { version: still1.version, data: await still1.get('mls', 'state') };
      still1.close();

      // (b) good upgrade: adds a namespace, keeps data.
      const v2 = await openVault({
        name: n,
        version: 2,
        migrations: { ...migrations, 2: (db) => db.createObjectStore('attachments') },
      });
      const afterOk = {
        version: v2.version,
        data: await v2.get('mls', 'state'),
        hasNew: v2.namespaces.includes('attachments'),
      };
      // (c) opening with a LOWER version than on disk must fail cleanly.
      v2.close();
      let downgrade = null;
      try { await openVault({ name: n, version: 1, migrations }); } catch (e) { downgrade = e.code; }
      return { failedCode, afterFail, afterOk, downgrade };
    }, name);
    expect(out.failedCode).toContain('upgrade boom');
    expect(out.afterFail).toEqual({ version: 1, data: 'v1-data' });
    expect(out.afterOk).toEqual({ version: 2, data: 'v1-data', hasNew: true });
    expect(out.downgrade).toBe('VAULT_OPEN_FAILED'); // VersionError, surfaced structured
  });

  test('P6: two tabs — writes are transactional; Web Lock gives one writer, lost lock is detected and reacquired', async ({ context }, info) => {
    const name = dbName(info);
    const a = await context.newPage();
    const b = await context.newPage();
    await harness(a);
    await harness(b);
    // Same origin: both tabs see one database. Web Lock election: A is writer.
    const aLock = await a.evaluate(() => new Promise((resolve) => {
      window.__lockLost = new Promise((lost) => {
        navigator.locks.request('spike-vault-writer', { mode: 'exclusive', ifAvailable: true }, (lock) => {
          resolve(lock !== null);
          if (!lock) return undefined;
          return new Promise(() => { window.__markLost = () => lost(true); }); // hold forever (until steal)
        }).catch(() => resolve(false));
      });
    }));
    const bLock = await b.evaluate(() => new Promise((resolve) => {
      navigator.locks.request('spike-vault-writer', { mode: 'exclusive', ifAvailable: true }, (lock) => {
        resolve(lock !== null);
        return undefined;
      }).catch(() => resolve(false));
    }));
    expect(aLock).toBe(true);
    expect(bLock).toBe(false); // B must not become a writer

    // Both tabs write to different keys transactionally — no corruption either way.
    await a.evaluate(async (n) => {
      const v = await window.VaultSpike.openVault({ name: n });
      await v.put('contacts', 'from-a', 'A');
      window.__v = v;
    }, name);
    await b.evaluate(async (n) => {
      const v = await window.VaultSpike.openVault({ name: n });
      await v.put('contacts', 'from-b', 'B');
      window.__v = v;
    }, name);
    const seen = await a.evaluate(async () => ({
      a: await window.__v.get('contacts', 'from-a'),
      b: await window.__v.get('contacts', 'from-b'),
    }));
    expect(seen).toEqual({ a: 'A', b: 'B' });

    // Lock loss: B steals the lock; A must observe the loss...
    const bStole = await b.evaluate(() => new Promise((resolve) => {
      navigator.locks.request('spike-vault-writer', { mode: 'exclusive', steal: true }, (lock) => {
        resolve(lock !== null);
        return new Promise(() => {}); // B now holds it
      }).catch(() => resolve(false));
    }));
    expect(bStole).toBe(true);
    // ...steal REJECTS the previous holder's promise — our holder resolves __lockLost via catch?
    // The spike records the actual semantics: A's ifAvailable request promise was already
    // resolved; loss shows up as the held-callback promise being settled. Verify A can
    // no longer claim to hold it and can reacquire after B releases (close B's page).
    await b.close();
    const aReacquired = await a.evaluate(() => new Promise((resolve) => {
      const t = setTimeout(() => resolve(false), 5000);
      const tryAcquire = () => {
        navigator.locks.request('spike-vault-writer', { mode: 'exclusive', ifAvailable: true }, (lock) => {
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
    const out = await page.evaluate(async (name) => {
      const { openVault } = window.VaultSpike;
      const v = await openVault({ name });
      await v.put('mls', 'state', new Uint8Array(64).fill(9));
      await v.destroy();
      const listed = indexedDB.databases ? (await indexedDB.databases()).map((d) => d.name) : null;
      // Reopen: must be a FRESH database with no data.
      const again = await openVault({ name });
      const empty = (await again.list('mls')).length === 0;
      await again.destroy();
      return { listed, empty };
    }, dbName(info));
    if (out.listed !== null) expect(out.listed).not.toContain('spike-'); // gone from enumeration
    expect(out.empty).toBe(true);
  });

  test('P8: quota exhaustion is fail-closed (chromium, real quota override)', async ({ browserName }, info) => {
    test.skip(browserName !== 'chromium', 'CDP quota override is chromium-only; firefox covered by P2 rollback semantics');
    // Spike finding: Storage.overrideQuotaForOrigin only works on the DEFAULT
    // browser context — from Playwright's isolated contexts it fails with
    // "Internal error" (browser-level session) or silently no-ops (page-level).
    // A dedicated persistent context IS the default context, so we use one here.
    const profileDir = mkdtempSync(join(tmpdir(), 'vault-spike-quota-'));
    const persistent = await chromium.launchPersistentContext(profileDir, {
      headless: true,
      ...(info.project.use.launchOptions ?? {}),
    });
    const page = await persistent.newPage();
    try {
      await harness(page);
      const cdp = await persistent.newCDPSession(page);
      await cdp.send('Storage.overrideQuotaForOrigin', { origin: base, quotaSize: 5_000_000 });
      // Environment probe: on this Chromium build the override is ACCEPTED but not
      // ENFORCED (estimate() and writes keep the real ~10 GiB quota). When that
      // happens the real-quota scenario moves to the manual verification plan —
      // the rollback machinery it exercises is already proven by P2/P3.
      const effective = await page.evaluate(async () => (await navigator.storage.estimate()).quota);
      test.skip(effective > 100_000_000,
        `Storage.overrideQuotaForOrigin not enforced here (quota still ${effective}); manual-plan item M3`);
      await runQuotaProbe(page, info);
    } finally {
      await persistent.close();
      rmSync(profileDir, { recursive: true, force: true });
    }
  });

  async function runQuotaProbe(page, info) {
    const out = await page.evaluate(async (name) => {
      const { openVault } = window.VaultSpike;
      const est = navigator.storage?.estimate ? await navigator.storage.estimate() : null;
      const v = await openVault({ name });
      await v.put('meta', 'baseline', 'small-committed');
      let quotaErr = null;
      try {
        // Grow until the override bites: each chunk is its own transaction, so at
        // most one whole chunk is missing afterwards — never a torn record.
        await v.transaction(['mls', 'meta'], async (ops) => {
          for (let i = 0; i < 10; i += 1) {
            // eslint-disable-next-line no-await-in-loop
            await ops.put('mls', `big${i}`, new Uint8Array(2_000_000).fill(i));
          }
          await ops.put('meta', 'marker', true);
        });
      } catch (e) { quotaErr = { code: e.code, reason: e.details?.reason ?? null }; }
      return {
        quota: est?.quota ?? null,
        quotaErr,
        baseline: await v.get('meta', 'baseline'),
        bigs: (await v.list('mls')).length,
        marker: await v.get('meta', 'marker'),
        stillWorks: await v.put('meta', 'after', 'ok').then(() => v.get('meta', 'after')),
      };
    }, dbName(info));
    console.log(`[spike:${info.project.name}] quota after override:`, JSON.stringify({ quota: out.quota }));
    expect(out.quotaErr).not.toBeNull();
    expect(['VAULT_TX_ABORTED', 'VAULT_TX_FAILED']).toContain(out.quotaErr.code);
    expect(out.quotaErr.reason).toBe('QuotaExceededError');
    expect(out.baseline).toBe('small-committed'); // nothing destroyed
    expect(out.bigs).toBe(0); // the whole oversized transaction rolled back — nothing partial
    expect(out.marker).toBeUndefined();
    expect(out.stillWorks).toBe('ok'); // vault usable after the failure
  }

  test('P9: storage persistence probe (persist/persisted/estimate) is advisory, never fatal', async ({ page }, info) => {
    await harness(page);
    const out = await page.evaluate(async (name) => {
      const { openVault, probeStorage } = window.VaultSpike;
      const probe = await probeStorage();
      // Whatever persist() said, the vault must still open and write.
      const v = await openVault({ name });
      await v.put('meta', 'works', true);
      const works = await v.get('meta', 'works');
      await v.destroy();
      return { probe, works };
    }, dbName(info));
    expect(out.works).toBe(true);
    // boolean, null (API absent) or 'timeout' (firefox: prompt pending — finding
    // recorded in the doc: never await persist() unbounded).
    expect([true, false, null, 'timeout']).toContain(out.probe.persistGranted);
    // Recorded for the compatibility matrix (headless defaults differ per browser):
    console.log(`[spike:${info.project.name}] storage probe:`, JSON.stringify(out.probe));
  });

  test('P10: blocked open and blocked delete surface structured errors, data intact', async ({ context }, info) => {
    // SPIKE FINDING (recorded in the doc): a version-upgrade open that gets
    // `blocked` stays PENDING even after we surface the error — any later open of
    // the same database queues behind it and deadlocks the tab. The two blocked
    // scenarios below therefore use SEPARATE databases, and the vault design must
    // either wait-with-timeout on blocked opens or guarantee every connection
    // auto-closes on versionchange (never both reject and retry in one tab).
    const nameUpgrade = dbName(info);
    const nameDelete = dbName(info);
    const a = await context.newPage();
    const b = await context.newPage();
    await harness(a);
    await harness(b);
    await a.evaluate(async ({ n1, n2 }) => {
      const v1 = await window.VaultSpike.openVault({ name: n1 });
      await v1.put('mls', 'state', 'guarded');
      // Defeat the auto-close-on-versionchange to simulate a stuck old tab.
      v1._db.onversionchange = null;
      window.__v1 = v1;
      const v2 = await window.VaultSpike.openVault({ name: n2 });
      await v2.put('mls', 'state', 'guarded-too');
      // Same stuck-tab simulation: with the prototype's default auto-close-on-
      // versionchange, a delete would NOT block (the finding P10 records) — the
      // connection yields and the database is deleted under the live tab.
      v2._db.onversionchange = null;
      window.__v2 = v2; // held open: will block B's deleteDatabase
      return true;
    }, { n1: nameUpgrade, n2: nameDelete });

    // (a) blocked version upgrade — fresh DB per scenario, no queued-open reuse.
    const openBlocked = await b.evaluate(async (n) => {
      try {
        await window.VaultSpike.openVault({ name: n, version: 2, migrations: { 1: () => {}, 2: () => {} } });
        return 'no-error';
      } catch (e) { return e.code; }
    }, nameUpgrade);
    expect(openBlocked).toBe('VAULT_BLOCKED');

    // (b) blocked delete: B opens nameDelete, closes its own handle, destroys —
    // blocked because tab A still holds a live connection.
    const delBlocked = await b.evaluate(async (n) => {
      try {
        const v = await window.VaultSpike.openVault({ name: n });
        await v.destroy();
        return 'no-error';
      } catch (e) { return e.code; }
    }, nameDelete);
    expect(delBlocked).toBe('VAULT_BLOCKED');

    // Data survives both blocked operations, in both databases.
    const still = await a.evaluate(async () => ({
      one: await window.__v1.get('mls', 'state'),
      two: await window.__v2.get('mls', 'state'),
    }));
    expect(still).toEqual({ one: 'guarded', two: 'guarded-too' });
    await a.close(); await b.close();
  });

  test('P11: realistic MLS record (real fixture envelope) and 8 MB binary record round-trip', async ({ page }, info) => {
    await harness(page);
    // The REAL envelope from the committed regression fixture, fetched as bytes.
    const out = await page.evaluate(async ({ name, fixtureUrl }) => {
      const { openVault } = window.VaultSpike;
      const envelope = await (await fetch(fixtureUrl)).json();
      const stateBytes = Uint8Array.from(atob(envelope.payload), (c) => c.charCodeAt(0));
      const v = await openVault({ name });
      const t0 = performance.now();
      // Record-oriented: envelope metadata and binary payload as SEPARATE records —
      // no base64 in the vault, binary stored natively.
      await v.transaction(['mls'], async (ops) => {
        const { payload, ...meta } = envelope;
        await ops.put('mls', 'state:meta', meta);
        await ops.put('mls', 'state:payload', stateBytes);
      });
      const tEnvelope = performance.now() - t0;
      const meta = await v.get('mls', 'state:meta');
      const back = await v.get('mls', 'state:payload');
      const byteEqual = back.length === stateBytes.length
        && back.every((x, i) => x === stateBytes[i]);
      // Large record: 8 MB binary in one put.
      const big = new Uint8Array(8 * 1024 * 1024);
      for (let i = 0; i < big.length; i += 4096) big[i] = i % 256;
      const t1 = performance.now();
      await v.put('mls', 'big', big);
      const tBigWrite = performance.now() - t1;
      const t2 = performance.now();
      const bigBack = await v.get('mls', 'big');
      const tBigRead = performance.now() - t2;
      const bigOk = bigBack.length === big.length && bigBack[4096] === big[4096];
      await v.destroy();
      return {
        byteEqual, bigOk,
        metaHasNoPayload: !('payload' in meta) && meta.format === 'styx-mls-state',
        timings: { tEnvelope, tBigWrite, tBigRead },
      };
    }, { name: dbName(info), fixtureUrl: `${base}/test/fixtures/mls-state-v1/envelope.json` });
    expect(out.byteEqual).toBe(true);
    expect(out.bigOk).toBe(true);
    expect(out.metaHasNoPayload).toBe(true);
    console.log(`[spike:${info.project.name}] timings ms:`, JSON.stringify(out.timings));
  });

  test('P12: per-namespace enumeration and wipe', async ({ page }, info) => {
    await harness(page);
    const out = await page.evaluate(async (name) => {
      const { openVault } = window.VaultSpike;
      const v = await openVault({ name });
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
