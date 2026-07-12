// vault-record.test.js — encrypted record v1 codec (PR-2): frozen KAT,
// adversarial matrix (mandate §22), binding read-side AAD rule, property
// tests. All keys and payloads are synthetic.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import fc from 'fast-check';
import {
  VAULT_RECORD_VERSION, RECORD_NONCE_BYTES, MIN_DATA_BYTES, MAX_PLAINTEXT_BYTES, MAX_RECORD_KEY_CHARS,
  validateVaultRecord, buildRecordAad, encryptVaultRecord, decryptVaultRecord,
} from '../../src/storage/vault-record.js';
import { deriveNamespaceKey } from '../../src/crypto/vault-keys.js';
import { VaultCryptoError, VaultCryptoErrorCodes as Codes } from '../../src/crypto/vault-errors.js';

const { subtle } = globalThis.crypto;
const fixture = (name) => JSON.parse(
  readFileSync(fileURLToPath(new URL(`../fixtures/vault-crypto-v1/${name}`, import.meta.url)), 'utf8'),
);
const toHex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, '0')).join('');
const fromHex = (hex) => new Uint8Array(hex.match(/../g)?.map((b) => parseInt(b, 16)) ?? []);

const jsonFx = fixture('record-v1-json.json');
const bytesFx = fixture('record-v1-bytes.json');
const hkdfFx = fixture('hkdf-v1.json');
const ROOT_KEY = fromHex(hkdfFx.rootKeyHex);

const importAes = (hex) => subtle.importKey('raw', fromHex(hex), 'AES-GCM', false, ['encrypt', 'decrypt']);

function fixtureRecord(fx) {
  const r = fx.record;
  return {
    v: r.v, ns: r.ns, k: r.k, rv: r.rv, kv: r.kv, ct: r.ct,
    nonce: fromHex(r.nonceHex), data: fromHex(r.dataHex),
  };
}

const mutated = (fx, patch) => ({ ...fixtureRecord(fx), ...patch });

function expectSyncCode(fn, code) {
  let err = null;
  try { fn(); } catch (e) { err = e; }
  expect(err).toBeInstanceOf(VaultCryptoError);
  expect(err.code).toBe(code);
  return err;
}

async function expectAsyncCode(thunk, code) {
  let err = null;
  try { await thunk(); } catch (e) { err = e; }
  expect(err).toBeInstanceOf(VaultCryptoError);
  expect(err.code).toBe(code);
  return err;
}

describe('frozen KAT (record fixtures are a compatibility contract)', () => {
  test('json record decrypts to the frozen plaintext through the PRODUCTION key hierarchy', async () => {
    const key = await deriveNamespaceKey(ROOT_KEY, 'settings', 1);
    const out = await decryptVaultRecord(
      fixtureRecord(jsonFx), { namespace: 'settings', recordKey: 'ui:theme' }, key,
    );
    expect(out.value).toEqual(jsonFx.plaintextValue);
    expect(out.contentType).toBe('json');
    expect(out.recordVersion).toBe(3);
    expect(out.keyVersion).toBe(1);
  });

  test('bytes record decrypts byte-for-byte', async () => {
    const key = await deriveNamespaceKey(ROOT_KEY, 'canary', 1);
    const out = await decryptVaultRecord(
      fixtureRecord(bytesFx), { namespace: 'canary', recordKey: 'canary:0001' }, key,
    );
    expect(out.value).toBeInstanceOf(Uint8Array);
    expect(toHex(out.value)).toBe(bytesFx.plaintextHex);
  });

  test('the canonical AAD bytes are exactly the frozen ones', () => {
    expect(toHex(buildRecordAad(fixtureRecord(jsonFx)))).toBe(jsonFx.aadHex);
    expect(new TextDecoder().decode(buildRecordAad(fixtureRecord(jsonFx)))).toBe(jsonFx.aadUtf8);
    expect(toHex(buildRecordAad(fixtureRecord(bytesFx)))).toBe(bytesFx.aadHex);
  });
});

describe('round-trip and nonce discipline', () => {
  let settingsKey;
  beforeAll(async () => { settingsKey = await deriveNamespaceKey(ROOT_KEY, 'settings', 1); });

  test('json and bytes round-trip through the production APIs', async () => {
    const jsonRec = await encryptVaultRecord({
      namespace: 'settings', recordKey: 'pref:locale', plaintext: { locale: 'it-IT' }, contentType: 'json', recordVersion: 7,
    }, settingsKey);
    validateVaultRecord(jsonRec);
    const jsonOut = await decryptVaultRecord(jsonRec, { namespace: 'settings', recordKey: 'pref:locale' }, settingsKey);
    expect(jsonOut.value).toEqual({ locale: 'it-IT' });
    expect(jsonOut.recordVersion).toBe(7);

    const payload = crypto.getRandomValues(new Uint8Array(1024));
    const bytesRec = await encryptVaultRecord({
      namespace: 'settings', recordKey: 'pref:blob', plaintext: payload, contentType: 'bytes',
    }, settingsKey);
    const bytesOut = await decryptVaultRecord(bytesRec, { namespace: 'settings', recordKey: 'pref:blob' }, settingsKey);
    expect(toHex(bytesOut.value)).toBe(toHex(payload));
  });

  test('encrypting the same plaintext twice yields different nonces and ciphertexts', async () => {
    const input = { namespace: 'settings', recordKey: 'pref:x', plaintext: 'same', contentType: 'json' };
    const a = await encryptVaultRecord(input, settingsKey);
    const b = await encryptVaultRecord(input, settingsKey);
    expect(toHex(a.nonce)).not.toBe(toHex(b.nonce));
    expect(toHex(a.data)).not.toBe(toHex(b.data));
  });

  test('nonces are unique over a meaningful sample (no fixed or counter nonce)', async () => {
    const seen = new Set();
    for (let i = 0; i < 128; i += 1) {
      const rec = await encryptVaultRecord({
        namespace: 'settings', recordKey: 'pref:x', plaintext: i, contentType: 'json',
      }, settingsKey);
      expect(rec.nonce.length).toBe(RECORD_NONCE_BYTES);
      seen.add(toHex(rec.nonce));
    }
    expect(seen.size).toBe(128);
  });

  test('the caller buffer is not mutated and not aliased into the record', async () => {
    const payload = new Uint8Array(64).fill(0x5a);
    const rec = await encryptVaultRecord({
      namespace: 'settings', recordKey: 'pref:immutability', plaintext: payload, contentType: 'bytes',
    }, settingsKey);
    expect(toHex(payload)).toBe('5a'.repeat(64)); // untouched
    expect(rec.data.buffer).not.toBe(payload.buffer);
  });

  test('empty plaintexts are supported (data is exactly the 16-byte tag for empty bytes)', async () => {
    const rec = await encryptVaultRecord({
      namespace: 'settings', recordKey: 'pref:empty', plaintext: new Uint8Array(0), contentType: 'bytes',
    }, settingsKey);
    expect(rec.data.length).toBe(MIN_DATA_BYTES);
    const out = await decryptVaultRecord(rec, { namespace: 'settings', recordKey: 'pref:empty' }, settingsKey);
    expect(out.value.length).toBe(0);
  });

  test('the 16 MiB plaintext cap is enforced BEFORE any crypto', async () => {
    const over = new Uint8Array(MAX_PLAINTEXT_BYTES + 1);
    await expectAsyncCode(() => encryptVaultRecord({
      namespace: 'settings', recordKey: 'pref:big', plaintext: over, contentType: 'bytes',
    }, settingsKey), Codes.RECORD_INVALID);
    // at the limit: accepted (one-off, proves the boundary is exact)
    const atLimit = new Uint8Array(MAX_PLAINTEXT_BYTES);
    const rec = await encryptVaultRecord({
      namespace: 'settings', recordKey: 'pref:big', plaintext: atLimit, contentType: 'bytes',
    }, settingsKey);
    expect(rec.data.length).toBe(MAX_PLAINTEXT_BYTES + MIN_DATA_BYTES);
  }, 30000);

  test('non-serializable json plaintext fails closed without touching crypto', async () => {
    const cyclic = {};
    cyclic.self = cyclic;
    for (const plaintext of [cyclic, undefined, () => {}, 1n]) {
      await expectAsyncCode(() => encryptVaultRecord({
        namespace: 'settings', recordKey: 'pref:bad', plaintext, contentType: 'json',
      }, settingsKey), Codes.RECORD_INVALID);
    }
  });
});

describe('adversarial matrix (mandate §22) — shape', () => {
  test('non-objects, arrays, custom prototypes, accessors, extra and missing fields', () => {
    for (const raw of [null, 7, 'record', [], new Date()]) {
      expectSyncCode(() => validateVaultRecord(raw), Codes.RECORD_INVALID);
    }
    expectSyncCode(() => validateVaultRecord(mutated(jsonFx, { evil: 1 })), Codes.RECORD_INVALID);
    expectSyncCode(() => validateVaultRecord(Object.create(fixtureRecord(jsonFx))), Codes.RECORD_INVALID);
    const withGetter = fixtureRecord(jsonFx);
    Object.defineProperty(withGetter, 'ns', { get: () => 'settings', enumerable: true, configurable: true });
    expectSyncCode(() => validateVaultRecord(withGetter), Codes.RECORD_INVALID);
    for (const key of Object.keys(fixtureRecord(jsonFx))) {
      const copy = fixtureRecord(jsonFx);
      delete copy[key];
      expectSyncCode(() => validateVaultRecord(copy), Codes.RECORD_INVALID);
    }
  });

  test('field bounds: v, ns, k, rv, kv, ct, nonce, data', () => {
    expectSyncCode(() => validateVaultRecord(mutated(jsonFx, { v: 2 })), Codes.RECORD_INVALID); // future record
    expectSyncCode(() => validateVaultRecord(mutated(jsonFx, { v: 0 })), Codes.RECORD_INVALID);
    expectSyncCode(() => validateVaultRecord(mutated(jsonFx, { ns: 'plaintext-store' })), Codes.NAMESPACE_UNSUPPORTED);
    expectSyncCode(() => validateVaultRecord(mutated(jsonFx, { ns: '__proto__' })), Codes.NAMESPACE_UNSUPPORTED);
    for (const k of ['', 'x'.repeat(MAX_RECORD_KEY_CHARS + 1), 'nul\u0000key', 'ctl\u001fkey', 'del\u007fkey', '\ud800lone', 42, null]) {
      expectSyncCode(() => validateVaultRecord(mutated(jsonFx, { k })), Codes.RECORD_INVALID);
    }
    // exactly at the length bound: shape-valid (decrypt would still fail on AAD)
    expect(() => validateVaultRecord(mutated(jsonFx, { k: 'x'.repeat(MAX_RECORD_KEY_CHARS) }))).not.toThrow();
    for (const rv of [0, -1, 1.5, '3', null]) {
      expectSyncCode(() => validateVaultRecord(mutated(jsonFx, { rv })), Codes.RECORD_INVALID);
    }
    for (const kv of [0, -2, 1.5]) {
      expectSyncCode(() => validateVaultRecord(mutated(jsonFx, { kv })), Codes.RECORD_INVALID);
    }
    expectSyncCode(() => validateVaultRecord(mutated(jsonFx, { kv: 2 })), Codes.KEY_VERSION_UNSUPPORTED); // future key version
    for (const ct of ['text', 'JSON', '', 7]) {
      expectSyncCode(() => validateVaultRecord(mutated(jsonFx, { ct })), Codes.RECORD_INVALID);
    }
    for (const nonce of [new Uint8Array(11), new Uint8Array(13), [...new Uint8Array(12)], null]) {
      expectSyncCode(() => validateVaultRecord(mutated(jsonFx, { nonce })), Codes.RECORD_INVALID);
    }
    for (const data of [new Uint8Array(MIN_DATA_BYTES - 1), new Uint8Array(0), 'deadbeef', null]) {
      expectSyncCode(() => validateVaultRecord(mutated(jsonFx, { data })), Codes.RECORD_INVALID);
    }
  });
});

describe('strict shape via descriptor snapshot (review F6) — records', () => {
  test('an ENUMERABLE getter on EVERY field is rejected without being invoked', () => {
    const base = fixtureRecord(jsonFx);
    for (const field of Object.keys(base)) {
      let calls = 0;
      const evil = { ...base };
      delete evil[field];
      Object.defineProperty(evil, field, {
        get() { calls += 1; return base[field]; }, enumerable: true, configurable: true,
      });
      expectSyncCode(() => validateVaultRecord(evil), Codes.RECORD_INVALID);
      expect(calls).toBe(0);
    }
  });

  test('non-enumerable getters, non-enumerable fields, Symbols, setters and throwing accessors are rejected typed', () => {
    let calls = 0;
    const hiddenGetter = { ...fixtureRecord(jsonFx) };
    delete hiddenGetter.ns;
    Object.defineProperty(hiddenGetter, 'ns', { get() { calls += 1; return 'settings'; }, enumerable: false, configurable: true });
    expectSyncCode(() => validateVaultRecord(hiddenGetter), Codes.RECORD_INVALID);
    expect(calls).toBe(0);

    const thrower = { ...fixtureRecord(jsonFx) };
    delete thrower.kv;
    Object.defineProperty(thrower, 'kv', { get() { throw new EvalError('boom'); }, enumerable: true, configurable: true });
    expectSyncCode(() => validateVaultRecord(thrower), Codes.RECORD_INVALID);

    const hiddenData = { ...fixtureRecord(jsonFx) };
    delete hiddenData.rv;
    Object.defineProperty(hiddenData, 'rv', { value: 3, enumerable: false, configurable: true });
    expectSyncCode(() => validateVaultRecord(hiddenData), Codes.RECORD_INVALID);

    const hiddenExtra = fixtureRecord(jsonFx);
    Object.defineProperty(hiddenExtra, 'smuggled', { value: 1, enumerable: false, configurable: true });
    expectSyncCode(() => validateVaultRecord(hiddenExtra), Codes.RECORD_INVALID);

    const sym = fixtureRecord(jsonFx);
    sym[Symbol('smuggle')] = 1;
    expectSyncCode(() => validateVaultRecord(sym), Codes.RECORD_INVALID);

    const setter = { ...fixtureRecord(jsonFx) };
    delete setter.ct;
    Object.defineProperty(setter, 'ct', { set() {}, enumerable: true, configurable: true });
    expectSyncCode(() => validateVaultRecord(setter), Codes.RECORD_INVALID);
  });

  test('null-prototype records with valid enumerable data fields stay accepted', () => {
    const rec = Object.assign(Object.create(null), fixtureRecord(jsonFx));
    expect(() => validateVaultRecord(rec)).not.toThrow();
  });
});

describe('exact namespace-key CryptoKey contract (review F7) — records', () => {
  test('non-conforming keys fail typed before any decrypt call', async () => {
    const { subtle } = globalThis.crypto;
    const wrongKeys = [
      await subtle.importKey('raw', new Uint8Array(16), 'AES-GCM', false, ['encrypt', 'decrypt']), // 128
      await subtle.importKey('raw', new Uint8Array(32), 'AES-GCM', true, ['encrypt', 'decrypt']), // extractable
      await subtle.importKey('raw', new Uint8Array(32), 'AES-GCM', false, ['decrypt']), // decrypt-only
      await subtle.importKey('raw', new Uint8Array(32), 'AES-CBC', false, ['encrypt', 'decrypt']),
      { type: 'secret', algorithm: { name: 'AES-GCM', length: 256 }, extractable: false, usages: ['encrypt', 'decrypt'] },
    ];
    const origDecrypt = SubtleCrypto.prototype.decrypt;
    let decryptCalls = 0;
    SubtleCrypto.prototype.decrypt = function patched(...a) { decryptCalls += 1; return origDecrypt.apply(this, a); };
    try {
      for (const key of wrongKeys) {
        const err = await expectAsyncCode(
          () => decryptVaultRecord(fixtureRecord(jsonFx), { namespace: 'settings', recordKey: 'ui:theme' }, key),
          Codes.CRYPTO_FAILED,
        );
        expect(err.message).toBe('VAULT_CRYPTO_FAILED: key does not satisfy the AES-256-GCM vault contract');
        await expectAsyncCode(() => encryptVaultRecord({
          namespace: 'settings', recordKey: 'x', plaintext: 1, contentType: 'json',
        }, key), Codes.CRYPTO_FAILED);
      }
      expect(decryptCalls).toBe(0);
    } finally {
      SubtleCrypto.prototype.decrypt = origDecrypt;
    }
  });
});

describe('adversarial matrix (mandate §22) — authentication and binding', () => {
  let sharedKey; // ONE key across namespaces isolates the AAD binding from key separation
  beforeAll(async () => { sharedKey = await importAes(jsonFx.namespaceKeyHex); });

  test('bit flips in ciphertext, tag and nonce → VAULT_RECORD_CORRUPTED', async () => {
    const flippedCt = fixtureRecord(jsonFx);
    flippedCt.data = flippedCt.data.slice();
    flippedCt.data[0] ^= 0x01;
    const flippedTag = fixtureRecord(jsonFx);
    flippedTag.data = flippedTag.data.slice();
    flippedTag.data[flippedTag.data.length - 1] ^= 0x80;
    const alteredNonce = fixtureRecord(jsonFx);
    alteredNonce.nonce = alteredNonce.nonce.slice();
    alteredNonce.nonce[0] ^= 0xff;
    const truncated = fixtureRecord(jsonFx);
    truncated.data = truncated.data.slice(0, truncated.data.length - 1);
    for (const record of [flippedCt, flippedTag, alteredNonce, truncated]) {
      await expectAsyncCode(
        () => decryptVaultRecord(record, { namespace: 'settings', recordKey: 'ui:theme' }, sharedKey),
        Codes.RECORD_CORRUPTED,
      );
    }
  });

  test('swapped self-declared fields fail GCM authentication (AAD from the REQUEST)', async () => {
    // Each record claims different metadata than what produced the ciphertext;
    // the request follows the claim, so the AAD differs → auth failure.
    const nsSwap = mutated(jsonFx, { ns: 'canary' });
    await expectAsyncCode(
      () => decryptVaultRecord(nsSwap, { namespace: 'canary', recordKey: 'ui:theme' }, sharedKey),
      Codes.RECORD_CORRUPTED,
    );
    const keySwap = mutated(jsonFx, { k: 'ui:other' });
    await expectAsyncCode(
      () => decryptVaultRecord(keySwap, { namespace: 'settings', recordKey: 'ui:other' }, sharedKey),
      Codes.RECORD_CORRUPTED,
    );
    const rvSwap = mutated(jsonFx, { rv: 4 });
    await expectAsyncCode(
      () => decryptVaultRecord(rvSwap, { namespace: 'settings', recordKey: 'ui:theme' }, sharedKey),
      Codes.RECORD_CORRUPTED,
    );
    const ctSwap = mutated(jsonFx, { ct: 'bytes' });
    await expectAsyncCode(
      () => decryptVaultRecord(ctSwap, { namespace: 'settings', recordKey: 'ui:theme' }, sharedKey),
      Codes.RECORD_CORRUPTED,
    );
  });

  test('requested ns/k different from the record fields → refused BEFORE any crypto attempt', async () => {
    const record = fixtureRecord(jsonFx);
    const err = await expectAsyncCode(
      () => decryptVaultRecord(record, { namespace: 'canary', recordKey: 'ui:theme' }, sharedKey),
      Codes.RECORD_INVALID,
    );
    expect(err.message).toContain('does not belong');
    await expectAsyncCode(
      () => decryptVaultRecord(record, { namespace: 'settings', recordKey: 'other-key' }, sharedKey),
      Codes.RECORD_INVALID,
    );
  });

  test('namespace separation through the real hierarchy: wrong subkey → CORRUPTED', async () => {
    const canaryKey = await deriveNamespaceKey(ROOT_KEY, 'canary', 1);
    // A record captured from `settings` replayed inside `canary` with matching
    // metadata still fails: the canary subkey cannot authenticate it.
    const record = mutated(jsonFx, { ns: 'canary' });
    await expectAsyncCode(
      () => decryptVaultRecord(record, { namespace: 'canary', recordKey: 'ui:theme' }, canaryKey),
      Codes.RECORD_CORRUPTED,
    );
  });

  test('DOCUMENTED LIMIT (spec §1.2): replaying an OLD record of the same key succeeds', async () => {
    // Per-record rollback is not detected by the record format alone: an old
    // (rv=3) record decrypts fine even if a newer rv exists elsewhere. The
    // manifest layer (later PR) is the mitigation; this test pins the limit
    // so a future change is a conscious one.
    const key = await deriveNamespaceKey(ROOT_KEY, 'settings', 1);
    const out = await decryptVaultRecord(
      fixtureRecord(jsonFx), { namespace: 'settings', recordKey: 'ui:theme' }, key,
    );
    expect(out.recordVersion).toBe(3);
  });

  test('an unknown field with an oversized name still raises the typed error (review F1)', () => {
    const err = expectSyncCode(
      () => validateVaultRecord(mutated(jsonFx, { ['y'.repeat(200)]: 1 })),
      Codes.RECORD_INVALID,
    );
    expect(err.details.field).toBe('y'.repeat(64));
  });

  test('mutating the record AFTER the decrypt call starts cannot bypass validation (review F2)', async () => {
    const raw = fixtureRecord(jsonFx);
    const pending = decryptVaultRecord(raw, { namespace: 'settings', recordKey: 'ui:theme' }, sharedKey);
    raw.nonce = new Uint8Array(13); // would be invalid — must be ignored
    raw.data.fill(0); // mutation of the original buffer — must be ignored
    const out = await pending;
    expect(out.value).toEqual(jsonFx.plaintextValue);
  });

  test('a wrong-shaped CryptoKey fails closed', async () => {
    const hmac = await subtle.importKey('raw', ROOT_KEY, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    await expectAsyncCode(
      () => decryptVaultRecord(fixtureRecord(jsonFx), { namespace: 'settings', recordKey: 'ui:theme' }, hmac),
      Codes.CRYPTO_FAILED,
    );
    await expectAsyncCode(() => encryptVaultRecord({
      namespace: 'settings', recordKey: 'x', plaintext: 1, contentType: 'json',
    }, ROOT_KEY), Codes.CRYPTO_FAILED);
  });
});

describe('property tests (fast-check, CI-friendly volumes)', () => {
  const jsonValue = fc.jsonValue({ maxDepth: 3 });

  test('json round-trip for arbitrary JSON values', async () => {
    const key = await deriveNamespaceKey(ROOT_KEY, 'outbox', 1);
    await fc.assert(fc.asyncProperty(jsonValue, async (value) => {
      const rec = await encryptVaultRecord({
        namespace: 'outbox', recordKey: 'prop:json', plaintext: value, contentType: 'json',
      }, key);
      const out = await decryptVaultRecord(rec, { namespace: 'outbox', recordKey: 'prop:json' }, key);
      return JSON.stringify(out.value) === JSON.stringify(value);
    }), { numRuns: 24 });
  });

  test('bytes round-trip and mutate-one-byte → auth failure', async () => {
    const key = await deriveNamespaceKey(ROOT_KEY, 'push', 1);
    await fc.assert(fc.asyncProperty(
      fc.uint8Array({ minLength: 0, maxLength: 512 }),
      fc.nat(1023),
      async (payload, flipAt) => {
        const rec = await encryptVaultRecord({
          namespace: 'push', recordKey: 'prop:bytes', plaintext: payload, contentType: 'bytes',
        }, key);
        const out = await decryptVaultRecord(rec, { namespace: 'push', recordKey: 'prop:bytes' }, key);
        if (toHex(out.value) !== toHex(payload)) return false;
        const evil = { ...rec, data: rec.data.slice() };
        evil.data[flipAt % evil.data.length] ^= 0x01 + (flipAt % 255);
        try {
          await decryptVaultRecord(evil, { namespace: 'push', recordKey: 'prop:bytes' }, key);
          return false;
        } catch (e) {
          return e instanceof VaultCryptoError && e.code === Codes.RECORD_CORRUPTED;
        }
      },
    ), { numRuns: 24 });
  });

  test('malformed record objects always fail closed with a VaultCryptoError', () => {
    fc.assert(fc.property(fc.anything(), (raw) => {
      try {
        validateVaultRecord(raw);
        return false; // fc.anything() can never produce a valid record
      } catch (e) {
        return e instanceof VaultCryptoError;
      }
    }), { numRuns: 256 });
  });

  test('records stay v1', () => {
    expect(VAULT_RECORD_VERSION).toBe(1);
  });
});
