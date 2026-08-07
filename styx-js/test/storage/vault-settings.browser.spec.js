import { test, expect } from '@playwright/test';
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = normalize(join(fileURLToPath(new URL('.', import.meta.url)), '..', '..'));
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.wasm': 'application/wasm' };
const WORKER = '/test/fixtures/vault-settings/settings-worker.js';
const WASM = '/vendor/styx-kdf-wasm/pkg/styx_kdf_wasm_bg.wasm';

let server; let base;
test.beforeAll(async () => {
  server = http.createServer((req, res) => {
    try {
      if (req.url === '/harness') {
        res.writeHead(200, { 'content-type': 'text/html' });
        res.end('<!doctype html><html><body>settings</body></html>');
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

test('real worker migrates, persists, resumes idempotently, and exposes ciphertext only', async ({ page }, info) => {
  test.setTimeout(180000);
  await page.goto(`${base}/harness`);
  const result = await page.evaluate(async ({ workerPath, wasmUrl }) => {
    const { createVaultWorkerClient } = await import('/src/crypto/vault-worker-client.js');
    const open = async () => {
      const worker = new Worker(workerPath, { type: 'module' });
      const client = createVaultWorkerClient(worker);
      await client.request('INIT', { wasmUrl });
      return { worker, client };
    };
    const password = 'STYX-TEST-ONLY-settings-password';
    const preferences = { v: 1, theme: 'light', installHintDismissed: true };
    let session = await open();
    const status = await session.client.request('STATUS');
    if (status.vaultState === 'UNINITIALIZED') {
      await session.client.request('CREATE_VAULT', { password, profile: 'mobile-low-memory' });
    } else {
      await session.client.request('UNLOCK', { password });
    }
    const first = await session.client.request('MIGRATE', { namespace: 'settings', preferences });
    const read = await session.client.request('GET', { namespace: 'settings', recordKey: 'preferences' });
    await session.client.request('SHUTDOWN');
    session.worker.terminate();

    session = await open();
    await session.client.request('UNLOCK', { password });
    const resumed = await session.client.request('MIGRATE', { namespace: 'settings', preferences });

    const persisted = await new Promise((resolve, reject) => {
      const request = indexedDB.open('styx-vault-test-settings-v1');
      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        const db = request.result;
        const tx = db.transaction(['settings', 'migrations', 'meta'], 'readonly');
        const record = tx.objectStore('settings').get('preferences');
        const marker = tx.objectStore('migrations').get('settings');
        const manifest = tx.objectStore('meta').get('manifest');
        tx.oncomplete = () => {
          const out = { record: record.result, marker: marker.result, manifest: manifest.result };
          db.close();
          resolve(out);
        };
        tx.onerror = () => reject(tx.error);
      };
    });
    await session.client.request('DESTROY');
    session.worker.terminate();
    return { first, read, resumed, persisted, serialized: JSON.stringify(persisted) };
  }, { workerPath: WORKER, wasmUrl: WASM });

  expect(result.first).toMatchObject({ state: 'verified', matched: true, recordVersion: 1 });
  expect(result.resumed).toEqual(result.first);
  expect(result.read).toMatchObject({
    found: true,
    record: { value: { v: 1, theme: 'light', installHintDismissed: true }, recordVersion: 1 },
  });
  expect(result.persisted.record).toMatchObject({ ct: 'json', rv: 1 });
  expect(result.persisted.marker).toMatchObject({
    version: 1, namespace: 'settings', state: 'verified',
    counts: { source: 1, written: 1 },
  });
  expect(result.persisted.manifest.generation).toBeGreaterThanOrEqual(4);
  expect(result.serialized).not.toContain('light');
  expect(result.serialized).not.toContain('installHintDismissed');
  console.log(`[vault-settings:${info.project.name}] encrypted migration and idempotent resume verified`);
});
