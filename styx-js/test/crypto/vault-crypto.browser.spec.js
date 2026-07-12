// vault-crypto.browser.spec.js — cross-engine check of the vault crypto
// formats on real browsers (Chromium + Firefox). The same frozen vectors are
// asserted in Node by the jest suites; byte-identical results across engines
// are the cross-platform correctness proof (PR-2, mandate §20).
// Run from styx-js/:  npx playwright test -c playwright.vault.config.js
import { test, expect } from '@playwright/test';
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const STYX_JS_ROOT = normalize(join(fileURLToPath(new URL('.', import.meta.url)), '..', '..'));
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.wasm': 'application/wasm' };
const fixture = (name) => JSON.parse(
  readFileSync(join(STYX_JS_ROOT, 'test', 'fixtures', 'vault-crypto-v1', name), 'utf8'),
);

let server;
let base;
test.beforeAll(async () => {
  server = http.createServer((req, res) => {
    try {
      if (req.url === '/harness') {
        res.writeHead(200, { 'content-type': 'text/html' });
        res.end('<!doctype html><html><body>vault-crypto</body></html>');
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

test('standard vectors and frozen Styx vectors hold on this browser', async ({ page }, info) => {
  await page.goto(`${base}/harness`);
  const payload = {
    wrapperFx: fixture('wrapper-v1.json'),
    jsonFx: fixture('record-v1-json.json'),
    bytesFx: fixture('record-v1-bytes.json'),
    hkdfFx: fixture('hkdf-v1.json'),
    manifestFx: fixture('manifest-hmac-v1.json'),
    keysUrl: `${base}/src/crypto/vault-keys.js`,
    wrapperUrl: `${base}/src/storage/vault-wrapper.js`,
    recordUrl: `${base}/src/storage/vault-record.js`,
  };
  const results = await page.evaluate(async (input) => {
    const toHex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, '0')).join('');
    const fromHex = (hex) => new Uint8Array(hex.match(/../g)?.map((b) => parseInt(b, 16)) ?? []);
    const UTF8 = new TextEncoder();
    const { subtle } = crypto;
    const out = {};

    // 1. independent standard vectors straight against the browser engine
    const ikm = await subtle.importKey('raw', new Uint8Array(22).fill(0x0b), 'HKDF', false, ['deriveBits']);
    out.rfc5869 = toHex(new Uint8Array(await subtle.deriveBits({
      name: 'HKDF',
      hash: 'SHA-256',
      salt: fromHex('000102030405060708090a0b0c'),
      info: fromHex('f0f1f2f3f4f5f6f7f8f9'),
    }, ikm, 42 * 8)));
    const zeroKey = await subtle.importKey('raw', new Uint8Array(32), 'AES-GCM', false, ['encrypt']);
    out.gcmEmpty = toHex(new Uint8Array(await subtle.encrypt(
      { name: 'AES-GCM', iv: new Uint8Array(12), tagLength: 128 }, zeroKey, new Uint8Array(0),
    )));
    const hmacKey = await subtle.importKey('raw', new Uint8Array(20).fill(0x0b), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    out.rfc4231 = toHex(new Uint8Array(await subtle.sign('HMAC', hmacKey, UTF8.encode('Hi There'))));

    // 2. frozen Styx vectors through the PRODUCTION modules
    const keys = await import(input.keysUrl);
    const wrapper = await import(input.wrapperUrl);
    const record = await import(input.recordUrl);
    const rootKey = fromHex(input.hkdfFx.rootKeyHex);

    const w = input.wrapperFx.wrapper;
    const unwrapped = await wrapper.unwrapSyntheticRootKey({
      format: w.format,
      version: w.version,
      kdf: w.kdf,
      kdfVersion: w.kdfVersion,
      mKib: w.mKib,
      t: w.t,
      p: w.p,
      profile: w.profile,
      saltB64: w.saltB64,
      outLen: w.outLen,
      wrapAlg: w.wrapAlg,
      wrapNonce: fromHex(w.wrapNonceHex),
      wrappedRootKey: fromHex(w.wrappedRootKeyHex),
      keyVersion: w.keyVersion,
      createdAt: w.createdAt,
      calibratedMs: w.calibratedMs,
      rewrapPending: null,
    }, fromHex(input.wrapperFx.inputs.kekHex));
    out.unwrappedRootKey = toHex(unwrapped);

    const settingsKey = await keys.deriveNamespaceKey(rootKey, 'settings', 1);
    const jr = input.jsonFx.record;
    const jsonOut = await record.decryptVaultRecord({
      v: jr.v, ns: jr.ns, k: jr.k, rv: jr.rv, kv: jr.kv, ct: jr.ct,
      nonce: fromHex(jr.nonceHex), data: fromHex(jr.dataHex),
    }, { namespace: 'settings', recordKey: jr.k }, settingsKey);
    out.jsonValue = JSON.stringify(jsonOut.value);

    const canaryKey = await keys.deriveNamespaceKey(rootKey, 'canary', 1);
    const br = input.bytesFx.record;
    const bytesOut = await record.decryptVaultRecord({
      v: br.v, ns: br.ns, k: br.k, rv: br.rv, kv: br.kv, ct: br.ct,
      nonce: fromHex(br.nonceHex), data: fromHex(br.dataHex),
    }, { namespace: 'canary', recordKey: br.k }, canaryKey);
    out.bytesValue = toHex(bytesOut.value);

    const manifestKey = await keys.deriveManifestKey(rootKey, 1);
    const mac = await keys.signManifestBytes(manifestKey, UTF8.encode(input.manifestFx.canonicalUtf8));
    out.manifestMac = toHex(mac);
    await keys.verifyManifestBytes(manifestKey, UTF8.encode(input.manifestFx.canonicalUtf8), mac);

    // 3. adversarial probes: tampering fails typed on this engine too
    out.tamperCode = null;
    try {
      const evil = fromHex(jr.dataHex);
      evil[0] ^= 1;
      await record.decryptVaultRecord({
        v: jr.v, ns: jr.ns, k: jr.k, rv: jr.rv, kv: jr.kv, ct: jr.ct,
        nonce: fromHex(jr.nonceHex), data: evil,
      }, { namespace: 'settings', recordKey: jr.k }, settingsKey);
    } catch (e) {
      out.tamperCode = e.code ?? String(e);
    }
    out.wrongKekCode = null;
    try {
      await wrapper.unwrapSyntheticRootKey({
        format: w.format,
        version: w.version,
        kdf: w.kdf,
        kdfVersion: w.kdfVersion,
        mKib: w.mKib,
        t: w.t,
        p: w.p,
        profile: w.profile,
        saltB64: w.saltB64,
        outLen: w.outLen,
        wrapAlg: w.wrapAlg,
        wrapNonce: fromHex(w.wrapNonceHex),
        wrappedRootKey: fromHex(w.wrappedRootKeyHex),
        keyVersion: w.keyVersion,
        createdAt: w.createdAt,
        calibratedMs: w.calibratedMs,
        rewrapPending: null,
      }, new Uint8Array(32));
    } catch (e) {
      out.wrongKekCode = e.code ?? String(e);
    }
    return out;
  }, payload);

  expect(results.rfc5869).toBe(
    '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
  );
  expect(results.gcmEmpty).toBe('530f8afbc74536b9a963b4f1c4cb738b');
  expect(results.rfc4231).toBe('b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7');
  expect(results.unwrappedRootKey).toBe(payload.wrapperFx.inputs.rootKeyHex);
  expect(results.jsonValue).toBe(JSON.stringify(payload.jsonFx.plaintextValue));
  expect(results.bytesValue).toBe(payload.bytesFx.plaintextHex);
  expect(results.manifestMac).toBe(payload.manifestFx.macHex);
  expect(results.tamperCode).toBe('VAULT_RECORD_CORRUPTED');
  expect(results.wrongKekCode).toBe('VAULT_WRONG_PASSWORD');
  console.log(`[vault-crypto:${info.project.name}] standard + frozen vectors byte-identical; tampering fails typed`);
});
