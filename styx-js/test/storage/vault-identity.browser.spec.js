import { test, expect } from '@playwright/test';
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = normalize(join(fileURLToPath(new URL('.', import.meta.url)), '..', '..'));
const MIME = {
  '.html': 'text/html', '.js': 'text/javascript', '.json': 'application/json',
  '.wasm': 'application/wasm',
};
const WORKER = '/src/crypto/vault-worker-product.js';
const FIXTURE = '/test/fixtures/vault-identity/identity.json';
const WASM = '/vendor/styx-kdf-wasm/pkg/styx_kdf_wasm_bg.wasm';

let server; let base;
test.beforeAll(async () => {
  server = http.createServer((req, res) => {
    try {
      if (req.url === '/harness') {
        res.writeHead(200, { 'content-type': 'text/html' });
        res.end('<!doctype html><html><body>identity</body></html>');
        return;
      }
      const path = normalize(join(ROOT, req.url.split('?')[0]));
      if (!path.startsWith(ROOT)) { res.writeHead(403); res.end(); return; }
      const body = readFileSync(path);
      res.writeHead(200, { 'content-type': MIME[extname(path)] || 'application/octet-stream' });
      res.end(body);
    } catch {
      if (!res.headersSent) res.writeHead(404);
      res.end();
    }
  });
  await new Promise((resolve) => { server.listen(0, '127.0.0.1', resolve); });
  base = `http://127.0.0.1:${server.address().port}`;
});
test.afterAll(async () => { await new Promise((resolve) => { server.close(resolve); }); });

test('real worker gates pairing, migrates identity, reopens, and persists ciphertext only', async ({ page }, info) => {
  test.setTimeout(180000);
  await page.goto(`${base}/harness`);
  const result = await page.evaluate(async ({ workerPath, fixtureUrl, wasmUrl }) => {
    const { createVaultWorkerClient } = await import('/src/crypto/vault-worker-client.js');
    const open = async () => {
      const worker = new Worker(workerPath, { type: 'module' });
      const client = createVaultWorkerClient(worker);
      await client.request('INIT', { wasmUrl });
      return { worker, client };
    };
    const identity = await fetch(fixtureUrl).then((response) => response.json());
    const legacyKey = 'styxchat:styx:identity';
    const legacyBytes = JSON.stringify(identity);
    localStorage.setItem(legacyKey, legacyBytes);
    const password = 'STYX-TEST-ONLY-identity-password';

    let session = await open();
    await session.client.request('CREATE_VAULT', { password, profile: 'mobile-low-memory' });
    const activePairing = await session.client.request('MIGRATE', {
      namespace: 'identity', identity, pairingActive: true,
    }).then(
      () => ({ resolved: true }),
      (error) => ({ resolved: false, code: error.code }),
    );

    const before = await new Promise((resolve, reject) => {
      const request = indexedDB.open('styx-vault-default');
      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        const db = request.result;
        const tx = db.transaction(['identity', 'migrations'], 'readonly');
        const record = tx.objectStore('identity').get('self');
        const marker = tx.objectStore('migrations').get('identity');
        tx.oncomplete = () => {
          resolve({ record: record.result, marker: marker.result });
          db.close();
        };
        tx.onerror = () => reject(tx.error);
      };
    });

    const first = await session.client.request('MIGRATE', {
      namespace: 'identity', identity, pairingActive: false,
    });
    const read = await session.client.request('GET', {
      namespace: 'identity', recordKey: 'self',
    });
    await session.client.request('SHUTDOWN');
    session.worker.terminate();

    session = await open();
    await session.client.request('UNLOCK', { password });
    const resumed = await session.client.request('MIGRATE', {
      namespace: 'identity', identity, pairingActive: false,
    });
    const reopened = await session.client.request('GET', {
      namespace: 'identity', recordKey: 'self',
    });

    const persisted = await new Promise((resolve, reject) => {
      const request = indexedDB.open('styx-vault-default');
      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        const db = request.result;
        const tx = db.transaction(['identity', 'migrations', 'meta'], 'readonly');
        const record = tx.objectStore('identity').get('self');
        const marker = tx.objectStore('migrations').get('identity');
        const manifest = tx.objectStore('meta').get('manifest');
        tx.oncomplete = () => {
          resolve({ record: record.result, marker: marker.result, manifest: manifest.result });
          db.close();
        };
        tx.onerror = () => reject(tx.error);
      };
    });
    const legacyAfter = localStorage.getItem(legacyKey);
    await session.client.request('DESTROY');
    session.worker.terminate();
    return {
      identity, activePairing, before, first, read, resumed, reopened,
      persisted, legacyBytes, legacyAfter, serialized: JSON.stringify(persisted),
    };
  }, { workerPath: WORKER, fixtureUrl: FIXTURE, wasmUrl: WASM });

  expect(result.activePairing).toEqual({ resolved: false, code: 'VAULT_WRONG_STATE' });
  expect(result.before).toEqual({ record: undefined, marker: undefined });
  expect(result.first).toMatchObject({ state: 'verified', matched: true, recordVersion: 1 });
  expect(result.first).not.toHaveProperty('digest');
  expect(result.resumed).toEqual(result.first);
  expect(result.read).toMatchObject({
    found: true, record: { value: result.identity, recordVersion: 1 },
  });
  expect(result.reopened).toEqual(result.read);
  expect(result.persisted.record).toMatchObject({ ct: 'json', rv: 1 });
  expect(result.persisted.marker).toMatchObject({
    version: 1, namespace: 'identity', state: 'verified',
    counts: { source: 1, written: 1 },
  });
  expect(result.persisted.manifest.generation).toBeGreaterThanOrEqual(4);
  expect(result.legacyAfter).toBe(result.legacyBytes);
  expect(result.serialized).not.toContain(result.identity.salt);
  expect(result.serialized).not.toContain(result.identity.iv);
  expect(result.serialized).not.toContain(result.identity.ct);
  console.log(`[vault-identity:${info.project.name}] gated migration, restart, and ciphertext persistence verified`);
});
