// vault-keys.test.js — HKDF hierarchy, manifest HMAC, error discipline (PR-2).
//
// Layered proof strategy:
//  1. STANDARD vectors (RFC 5869, AES-256-GCM, RFC 4231) checked against
//     WebCrypto directly — literals in this file, NOT produced by our
//     generator, so producer and verifier cannot share a bug;
//  2. frozen Styx vectors (test/fixtures/vault-crypto-v1/) checked against the
//     production modules;
//  3. behavioral properties (separation, fail-closed bounds).

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  VAULT_NAMESPACES, VAULT_HKDF_INFO, VAULT_HKDF_SALT_LABEL, VAULT_KEY_VERSION,
  MANIFEST_MAC_BYTES, deriveNamespaceKey, deriveManifestKey,
  signManifestBytes, verifyManifestBytes,
} from '../../src/crypto/vault-keys.js';
import { VaultCryptoError, VaultCryptoErrorCodes as Codes } from '../../src/crypto/vault-errors.js';

const { subtle } = globalThis.crypto;
const UTF8 = new TextEncoder();
const fixture = (name) => JSON.parse(
  readFileSync(fileURLToPath(new URL(`../fixtures/vault-crypto-v1/${name}`, import.meta.url)), 'utf8'),
);
const toHex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, '0')).join('');
const fromHex = (hex) => new Uint8Array(hex.match(/../g)?.map((b) => parseInt(b, 16)) ?? []);

const expectCode = async (promise, code) => {
  let err = null;
  try { await promise; } catch (e) { err = e; }
  expect(err).toBeInstanceOf(VaultCryptoError);
  expect(err.code).toBe(code);
  return err;
};

const hkdf = fixture('hkdf-v1.json');
const manifestFx = fixture('manifest-hmac-v1.json');
const ROOT_KEY = fromHex(hkdf.rootKeyHex);

describe('independent standard vectors (engine sanity, not our code)', () => {
  test('RFC 5869 HKDF-SHA-256 test case 1', async () => {
    const ikm = await subtle.importKey('raw', new Uint8Array(22).fill(0x0b), 'HKDF', false, ['deriveBits']);
    const okm = new Uint8Array(await subtle.deriveBits({
      name: 'HKDF',
      hash: 'SHA-256',
      salt: fromHex('000102030405060708090a0b0c'),
      info: fromHex('f0f1f2f3f4f5f6f7f8f9'),
    }, ikm, 42 * 8));
    expect(toHex(okm)).toBe(
      '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
    );
  });

  test('RFC 5869 HKDF-SHA-256 test case 3 (empty salt and info)', async () => {
    const ikm = await subtle.importKey('raw', new Uint8Array(22).fill(0x0b), 'HKDF', false, ['deriveBits']);
    const okm = new Uint8Array(await subtle.deriveBits({
      name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new Uint8Array(0),
    }, ikm, 42 * 8));
    expect(toHex(okm)).toBe(
      '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8',
    );
  });

  test('AES-256-GCM empty-plaintext vector (GCM spec test case 13)', async () => {
    const key = await subtle.importKey('raw', new Uint8Array(32), 'AES-GCM', false, ['encrypt']);
    const out = new Uint8Array(await subtle.encrypt(
      { name: 'AES-GCM', iv: new Uint8Array(12), tagLength: 128 }, key, new Uint8Array(0),
    ));
    expect(toHex(out)).toBe('530f8afbc74536b9a963b4f1c4cb738b');
  });

  test('AES-256-GCM one-block vector (GCM spec test case 14)', async () => {
    const key = await subtle.importKey('raw', new Uint8Array(32), 'AES-GCM', false, ['encrypt']);
    const out = new Uint8Array(await subtle.encrypt(
      { name: 'AES-GCM', iv: new Uint8Array(12), tagLength: 128 }, key, new Uint8Array(16),
    ));
    expect(toHex(out)).toBe('cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919');
  });

  test('HMAC-SHA-256 RFC 4231 test cases 1 and 2', async () => {
    const k1 = await subtle.importKey(
      'raw', new Uint8Array(20).fill(0x0b), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
    );
    expect(toHex(new Uint8Array(await subtle.sign('HMAC', k1, UTF8.encode('Hi There')))))
      .toBe('b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7');
    const k2 = await subtle.importKey(
      'raw', UTF8.encode('Jefe'), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
    );
    expect(toHex(new Uint8Array(await subtle.sign('HMAC', k2, UTF8.encode('what do ya want for nothing?')))))
      .toBe('5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843');
  });
});

describe('HKDF hierarchy against the frozen fixture', () => {
  test('the closed namespace list and info strings are exactly the spec ones', () => {
    expect(VAULT_NAMESPACES).toEqual([
      'identity', 'contacts', 'messages', 'mls', 'outbox', 'push', 'settings', 'canary',
    ]);
    expect(Object.keys(VAULT_HKDF_INFO)).toEqual([...VAULT_NAMESPACES, 'manifest', 'backup']);
    for (const [name, info] of Object.entries(VAULT_HKDF_INFO)) {
      expect(info).toBe(`styx/vault/${name}/v1`);
    }
    expect(VAULT_HKDF_SALT_LABEL).toBe('styx-vault-v1');
  });

  test('fixture salt is SHA-256 of the public label', async () => {
    const salt = new Uint8Array(await subtle.digest('SHA-256', UTF8.encode(VAULT_HKDF_SALT_LABEL)));
    expect(toHex(salt)).toBe(hkdf.saltHex);
  });

  test('all 10 fixture derivations match raw WebCrypto deriveBits', async () => {
    const ikm = await subtle.importKey('raw', ROOT_KEY, 'HKDF', false, ['deriveBits']);
    for (const [name, { info, okmHex }] of Object.entries(hkdf.derivations)) {
      expect(info).toBe(VAULT_HKDF_INFO[name]);
      const okm = new Uint8Array(await subtle.deriveBits({
        name: 'HKDF', hash: 'SHA-256', salt: fromHex(hkdf.saltHex), info: UTF8.encode(info),
      }, ikm, 256));
      expect(toHex(okm)).toBe(okmHex);
    }
  });

  test('deriveNamespaceKey returns a non-extractable AES-GCM key equal to the fixture bits', async () => {
    const key = await deriveNamespaceKey(ROOT_KEY, 'settings', VAULT_KEY_VERSION);
    expect(key.extractable).toBe(false);
    expect(key.algorithm.name).toBe('AES-GCM');
    expect(key.algorithm.length).toBe(256);
    expect([...key.usages].sort()).toEqual(['decrypt', 'encrypt']);
    // Equality proof WITHOUT extraction: encrypt a probe with a fixed IV under
    // both the derived key and a key imported from the fixture bits.
    const reference = await subtle.importKey(
      'raw', fromHex(hkdf.derivations.settings.okmHex), 'AES-GCM', false, ['encrypt'],
    );
    const iv = new Uint8Array(12).fill(7);
    const probe = UTF8.encode('derived-key-equality-probe');
    const a = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, key, probe));
    const b = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, reference, probe));
    expect(toHex(a)).toBe(toHex(b));
  });

  test('namespace separation: every namespace derives a different key', async () => {
    const iv = new Uint8Array(12);
    const probe = UTF8.encode('separation-probe');
    const seen = new Set();
    for (const ns of VAULT_NAMESPACES) {
      const key = await deriveNamespaceKey(ROOT_KEY, ns, 1);
      const ct = toHex(new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, key, probe)));
      expect(seen.has(ct)).toBe(false);
      seen.add(ct);
    }
    expect(seen.size).toBe(VAULT_NAMESPACES.length);
  });

  test('unknown, reserved and prototype-chain namespaces are rejected', async () => {
    for (const ns of ['meta', 'migrations', 'manifest', 'backup', 'MESSAGES', 'settings ', '__proto__', 'constructor', 'toString', '', 42, null, undefined]) {
      await expectCode(deriveNamespaceKey(ROOT_KEY, ns, 1), Codes.NAMESPACE_UNSUPPORTED);
    }
  });

  test('only key version 1 is supported', async () => {
    for (const kv of [0, 2, -1, 1.5, NaN, '1', null]) {
      await expectCode(deriveNamespaceKey(ROOT_KEY, 'settings', kv), Codes.KEY_VERSION_UNSUPPORTED);
      await expectCode(deriveManifestKey(ROOT_KEY, kv), Codes.KEY_VERSION_UNSUPPORTED);
    }
  });

  test('a malformed root key fails closed', async () => {
    for (const rk of [new Uint8Array(31), new Uint8Array(33), new Uint8Array(0), [...ROOT_KEY], 'deadbeef', null]) {
      await expectCode(deriveNamespaceKey(rk, 'settings', 1), Codes.CRYPTO_FAILED);
    }
  });
});

describe('manifest HMAC primitives', () => {
  const canonical = UTF8.encode(manifestFx.canonicalUtf8);

  test('sign matches the frozen fixture and is exactly 32 bytes', async () => {
    const key = await deriveManifestKey(ROOT_KEY, 1);
    expect(key.extractable).toBe(false);
    const mac = await signManifestBytes(key, canonical);
    expect(mac.length).toBe(MANIFEST_MAC_BYTES);
    expect(toHex(mac)).toBe(manifestFx.macHex);
  });

  test('verify accepts the fixture MAC and rejects any deviation with ONE generic code', async () => {
    const key = await deriveManifestKey(ROOT_KEY, 1);
    const mac = fromHex(manifestFx.macHex);
    await expect(verifyManifestBytes(key, canonical, mac)).resolves.toBe(true);

    const flippedMac = mac.slice();
    flippedMac[0] ^= 0x01;
    const flippedBytes = canonical.slice();
    flippedBytes[0] ^= 0x01;
    const otherKey = await deriveManifestKey(fromHex(hkdf.rootKeyHex).fill(9), 1);
    const cases = [
      () => verifyManifestBytes(key, canonical, flippedMac), // wrong MAC
      () => verifyManifestBytes(key, flippedBytes, mac), // tampered bytes
      () => verifyManifestBytes(otherKey, canonical, mac), // wrong key
      () => verifyManifestBytes(key, canonical, mac.slice(0, 31)), // short MAC
      () => verifyManifestBytes(key, canonical, new Uint8Array(33)), // long MAC
      () => verifyManifestBytes(key, 'not-bytes', mac), // wrong type
    ];
    for (const c of cases) {
      const err = await expectCode(c(), Codes.CRYPTO_FAILED);
      expect(err.message).toBe('VAULT_CRYPTO_FAILED: manifest verification failed');
    }
  });

  test('manifest key is domain-separated from every payload namespace key', () => {
    for (const ns of VAULT_NAMESPACES) {
      expect(hkdf.derivations[ns].okmHex).not.toBe(hkdf.derivations.manifest.okmHex);
    }
  });

  test('an AES key is not accepted as manifest key', async () => {
    const aes = await deriveNamespaceKey(ROOT_KEY, 'settings', 1);
    await expectCode(signManifestBytes(aes, canonical), Codes.CRYPTO_FAILED);
  });

  test('exact HMAC CryptoKey contract (review F7): every non-conforming variant is rejected typed', async () => {
    const hmac = (hash, bytes, extractable, usages) => subtle.importKey(
      'raw', new Uint8Array(bytes), { name: 'HMAC', hash }, extractable, usages,
    );
    const wrongKeys = [
      await hmac('SHA-1', 32, false, ['sign', 'verify']),
      await hmac('SHA-384', 32, false, ['sign', 'verify']),
      await hmac('SHA-512', 32, false, ['sign', 'verify']),
      await hmac('SHA-256', 64, false, ['sign', 'verify']), // length 512, not 256
      await hmac('SHA-256', 32, true, ['sign', 'verify']), // extractable
      await hmac('SHA-256', 32, false, ['sign']), // sign-only
      await hmac('SHA-256', 32, false, ['verify']), // verify-only
      { type: 'secret', algorithm: { name: 'HMAC', hash: { name: 'SHA-256' }, length: 256 }, extractable: false, usages: ['sign', 'verify'] },
    ];
    const origSign = SubtleCrypto.prototype.sign;
    let signCalls = 0;
    SubtleCrypto.prototype.sign = function patched(...a) { signCalls += 1; return origSign.apply(this, a); };
    try {
      for (const key of wrongKeys) {
        const err = await expectCode(signManifestBytes(key, canonical), Codes.CRYPTO_FAILED);
        expect(err.message).toBe('VAULT_CRYPTO_FAILED: key does not satisfy the HMAC-SHA-256 vault contract');
        await expectCode(verifyManifestBytes(key, canonical, fromHex(manifestFx.macHex)), Codes.CRYPTO_FAILED);
      }
      expect(signCalls).toBe(0);
    } finally {
      SubtleCrypto.prototype.sign = origSign;
    }
    // the conforming derived key still reproduces the frozen vector
    const good = await deriveManifestKey(ROOT_KEY, 1);
    expect(toHex(await signManifestBytes(good, canonical))).toBe(manifestFx.macHex);
  });
});

describe('VaultCryptoError discipline', () => {
  test('message embeds the code; details are frozen and allowlisted', () => {
    const err = new VaultCryptoError(Codes.RECORD_INVALID, 'unknown record field', { field: 'evil' });
    expect(err.message).toBe('VAULT_RECORD_INVALID: unknown record field');
    expect(err.name).toBe('VaultCryptoError');
    expect(err.details).toEqual({ field: 'evil' });
    expect(Object.isFrozen(err.details)).toBe(true);
  });

  test('unknown codes and non-allowlisted details are programmer errors', () => {
    expect(() => new VaultCryptoError('VAULT_NOT_A_CODE', 'x')).toThrow(TypeError);
    expect(() => new VaultCryptoError(Codes.RECORD_INVALID, 'x', { plaintext: 'secret' })).toThrow(TypeError);
    expect(() => new VaultCryptoError(Codes.RECORD_INVALID, 'x', { field: 'a'.repeat(65) })).toThrow(TypeError);
    expect(() => new VaultCryptoError(Codes.RECORD_INVALID, 'x', { field: { deep: 1 } })).toThrow(TypeError);
    expect(() => new VaultCryptoError(Codes.RECORD_INVALID, 'x', [])).toThrow(TypeError);
  });

  test('the code set is exactly the fifteen mandated codes (nine crypto PR-2 + six engine US-005)', () => {
    expect(Object.values(Codes).sort()).toEqual([
      'VAULT_BLOCKED', 'VAULT_CRYPTO_FAILED', 'VAULT_DESTROY_FAILED',
      'VAULT_KDF_PARAMS_INVALID', 'VAULT_KEY_VERSION_UNSUPPORTED',
      'VAULT_NAMESPACE_UNSUPPORTED', 'VAULT_OPEN_FAILED', 'VAULT_QUOTA_EXCEEDED',
      'VAULT_RECORD_CORRUPTED', 'VAULT_RECORD_INVALID', 'VAULT_SCHEMA_GAP',
      'VAULT_TX_ABORTED', 'VAULT_WRAPPER_INVALID', 'VAULT_WRAPPER_UNSUPPORTED',
      'VAULT_WRONG_PASSWORD',
    ]);
  });
});
