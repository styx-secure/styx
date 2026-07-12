// vault-wrapper.test.js — strict wrapper v1 codec (PR-2): frozen KAT,
// adversarial matrix (mandate §21), uniform auth-failure mapping, property
// tests, and ONE integration path through the real styx-kdf-wasm artifact.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import fc from 'fast-check';
import {
  VAULT_WRAPPER_FORMAT, WRAP_NONCE_BYTES, WRAPPED_ROOT_KEY_BYTES, MAX_REWRAP_PENDING_DEPTH,
  validateVaultWrapper, parseVaultWrapper, encodeVaultWrapper, buildWrapperAad,
  wrapSyntheticRootKey, unwrapSyntheticRootKey,
} from '../../src/storage/vault-wrapper.js';
import { buildWrapperAadBytes, encodeBase64, decodeCanonicalBase64 } from '../../src/crypto/vault-aad.js';
import { VaultCryptoError, VaultCryptoErrorCodes as Codes } from '../../src/crypto/vault-errors.js';
import { KDF_PROFILES, deriveWithBounds } from '../../src/crypto/kdf-bounds.js';

const here = (rel) => fileURLToPath(new URL(rel, import.meta.url));
const fixture = JSON.parse(readFileSync(here('../fixtures/vault-crypto-v1/wrapper-v1.json'), 'utf8'));
const toHex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, '0')).join('');
const fromHex = (hex) => new Uint8Array(hex.match(/../g)?.map((b) => parseInt(b, 16)) ?? []);

const KEK = fromHex(fixture.inputs.kekHex);
const ROOT_KEY = fromHex(fixture.inputs.rootKeyHex);

/** The frozen fixture wrapper, rebuilt with real Uint8Array fields. */
function fixtureWrapper() {
  const w = fixture.wrapper;
  return {
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
  };
}

const mutated = (patch) => ({ ...fixtureWrapper(), ...patch });

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

describe('frozen KAT (wrapper-v1.json is a compatibility contract)', () => {
  test('the fixture wrapper validates and its AAD is byte-exact', () => {
    const w = fixtureWrapper();
    validateVaultWrapper(w);
    expect(toHex(buildWrapperAad(w))).toBe(fixture.aadHex);
    expect(new TextDecoder().decode(buildWrapperAad(w))).toBe(fixture.aadUtf8);
  });

  test('unwrap recovers the synthetic Root Key byte-for-byte', async () => {
    const rootKey = await unwrapSyntheticRootKey(fixtureWrapper(), KEK);
    expect(rootKey.length).toBe(32);
    expect(toHex(rootKey)).toBe(fixture.inputs.rootKeyHex);
  });
});

describe('round-trip and API discipline', () => {
  const wrapInput = () => ({
    kek: KEK.slice(),
    rootKey: ROOT_KEY.slice(),
    salt: fromHex(fixture.inputs.kdfSaltHex),
    mKib: 65536,
    t: 3,
    p: 1,
    profile: 'mobile-balanced',
    createdAt: '2026-07-12',
    calibratedMs: 130,
  });

  test('wrap → encode → parse → unwrap round-trips; inputs are never mutated', async () => {
    const input = wrapInput();
    const kekBefore = toHex(input.kek);
    const rootBefore = toHex(input.rootKey);
    const wrapper = await wrapSyntheticRootKey(input);
    expect(toHex(input.kek)).toBe(kekBefore);
    expect(toHex(input.rootKey)).toBe(rootBefore);

    const parsed = parseVaultWrapper(encodeVaultWrapper(wrapper));
    expect(Object.isFrozen(parsed)).toBe(true);
    const recovered = await unwrapSyntheticRootKey(parsed, KEK);
    expect(toHex(recovered)).toBe(fixture.inputs.rootKeyHex);
  });

  test('the wrap nonce is generated internally and differs on every call', async () => {
    const a = await wrapSyntheticRootKey(wrapInput());
    const b = await wrapSyntheticRootKey(wrapInput());
    expect(toHex(a.wrapNonce)).not.toBe(toHex(b.wrapNonce));
    expect(toHex(a.wrappedRootKey)).not.toBe(toHex(b.wrappedRootKey));
  });

  test('parse returns an independent copy: mutating the input cannot alter it', () => {
    const raw = fixtureWrapper();
    const parsed = parseVaultWrapper(raw);
    raw.wrapNonce.fill(0);
    raw.wrappedRootKey.fill(0);
    expect(toHex(parsed.wrapNonce)).toBe(fixture.wrapper.wrapNonceHex);
    expect(toHex(parsed.wrappedRootKey)).toBe(fixture.wrapper.wrappedRootKeyHex);
  });

  test('a KEK CryptoKey is accepted; a non-AES-GCM key is not', async () => {
    const key = await crypto.subtle.importKey('raw', KEK, 'AES-GCM', false, ['encrypt', 'decrypt']);
    const rootKey = await unwrapSyntheticRootKey(fixtureWrapper(), key);
    expect(toHex(rootKey)).toBe(fixture.inputs.rootKeyHex);
    const hmac = await crypto.subtle.importKey('raw', KEK, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    await expectAsyncCode(() => unwrapSyntheticRootKey(fixtureWrapper(), hmac), Codes.CRYPTO_FAILED);
    await expectAsyncCode(() => unwrapSyntheticRootKey(fixtureWrapper(), new Uint8Array(31)), Codes.CRYPTO_FAILED);
  });
});

describe('adversarial matrix (mandate §21) — fail-closed with exact codes', () => {
  test('non-objects, arrays and custom prototypes are rejected', () => {
    for (const raw of [null, undefined, 42, 'wrapper', [], new Map(), fixtureWrapper]) {
      expectSyncCode(() => validateVaultWrapper(raw), Codes.WRAPPER_INVALID);
    }
    class FakeWrapper {}
    expectSyncCode(() => validateVaultWrapper(Object.assign(new FakeWrapper(), fixtureWrapper())), Codes.WRAPPER_INVALID);
  });

  test('every missing field is rejected; null-prototype objects are accepted', () => {
    const full = fixtureWrapper();
    for (const key of Object.keys(full)) {
      const copy = { ...full };
      delete copy[key];
      const err = expectSyncCode(() => validateVaultWrapper(copy), Codes.WRAPPER_INVALID);
      expect(err.details).toEqual({ field: key });
    }
    const nullProto = Object.assign(Object.create(null), full);
    expect(() => validateVaultWrapper(nullProto)).not.toThrow();
  });

  test('extra fields, inherited fields and accessors are rejected', () => {
    expectSyncCode(() => validateVaultWrapper(mutated({ extra: 1 })), Codes.WRAPPER_INVALID);
    // All required fields live on the PROTOTYPE: own-property discipline must refuse them.
    expectSyncCode(() => validateVaultWrapper(Object.create(fixtureWrapper())), Codes.WRAPPER_INVALID);
    const withGetter = fixtureWrapper();
    let reads = 0;
    Object.defineProperty(withGetter, 'mKib', { get() { reads += 1; return 65536; }, enumerable: true, configurable: true });
    expectSyncCode(() => validateVaultWrapper(withGetter), Codes.WRAPPER_INVALID);
  });

  test('format and version', () => {
    expectSyncCode(() => validateVaultWrapper(mutated({ format: 'styx-vault-wrapper-v2' })), Codes.WRAPPER_INVALID);
    expectSyncCode(() => validateVaultWrapper(mutated({ version: 2 })), Codes.WRAPPER_UNSUPPORTED);
    for (const version of [0, -1, 1.5, '1', null, 2 ** 53]) {
      expectSyncCode(() => validateVaultWrapper(mutated({ version })), Codes.WRAPPER_INVALID);
    }
  });

  test('KDF fields are policed by the single kdf-bounds validator', () => {
    const cases = [
      { kdf: 'scrypt' }, { kdfVersion: 16 },
      { mKib: 19455 }, { mKib: 262145 }, { mKib: 65536.5 }, { mKib: -65536 },
      { t: 1 }, { t: 9 }, { t: NaN },
      { p: 2 }, { p: 0 },
      { outLen: 16 }, { outLen: 64 }, { outLen: '32' },
      { profile: 'paranoid' }, { profile: '__proto__' }, { profile: 'constructor' }, { profile: 7 },
      { profile: 'desktop' }, // combination mismatch: desktop numbers are 131072/3/1
      { mKib: 131072 }, // combination mismatch the other way
    ];
    for (const patch of cases) {
      expectSyncCode(() => validateVaultWrapper(mutated(patch)), Codes.KDF_PARAMS_INVALID);
    }
  });

  test('salt must be canonical Base64 of exactly 16 bytes', () => {
    const salt24 = encodeBase64(new Uint8Array(24));
    const canonical = fixtureWrapper().saltB64;
    const bad = [
      'not base64!!', `${canonical} `, ` ${canonical}`, canonical.replaceAll('=', ''),
      `${canonical.slice(0, -1)}\n`, canonical.toLowerCase() === canonical ? canonical.toUpperCase() : `${canonical.slice(0, -4)}Q===`,
      salt24, encodeBase64(new Uint8Array(8)), '', 42, null,
      // non-canonical trailing bits: 'QQF=' and 'QQE=' decode to the same 2 bytes
      'QQF=',
    ];
    for (const saltB64 of bad) {
      expectSyncCode(() => validateVaultWrapper(mutated({ saltB64 })), Codes.KDF_PARAMS_INVALID);
    }
  });

  test('wrap algorithm and buffers', () => {
    expectSyncCode(() => validateVaultWrapper(mutated({ wrapAlg: 'A128GCM' })), Codes.WRAPPER_UNSUPPORTED);
    for (const wrapNonce of [new Uint8Array(11), new Uint8Array(13), [...new Uint8Array(12)], 'AAAAAAAAAAAAAAAA', new ArrayBuffer(12)]) {
      expectSyncCode(() => validateVaultWrapper(mutated({ wrapNonce })), Codes.WRAPPER_INVALID);
    }
    for (const wrappedRootKey of [new Uint8Array(47), new Uint8Array(49), new Uint8Array(0), null]) {
      expectSyncCode(() => validateVaultWrapper(mutated({ wrappedRootKey })), Codes.WRAPPER_INVALID);
    }
  });

  test('keyVersion: zero/fractional/negative invalid, future unsupported', () => {
    for (const keyVersion of [0, -1, 1.5, '1', null]) {
      expectSyncCode(() => validateVaultWrapper(mutated({ keyVersion })), Codes.WRAPPER_INVALID);
    }
    expectSyncCode(() => validateVaultWrapper(mutated({ keyVersion: 2 })), Codes.KEY_VERSION_UNSUPPORTED);
  });

  test('createdAt must be a REAL calendar date', () => {
    for (const createdAt of ['2026-02-31', '2026-13-01', '2026-00-10', '2026-06-31', '12-07-2026', '2026-7-12', '2026-07-12T00:00:00Z', 'yesterday', '', 20260712, null]) {
      expectSyncCode(() => validateVaultWrapper(mutated({ createdAt })), Codes.WRAPPER_INVALID);
    }
    expect(() => validateVaultWrapper(mutated({ createdAt: '2024-02-29' }))).not.toThrow(); // real leap day
    expectSyncCode(() => validateVaultWrapper(mutated({ createdAt: '2025-02-29' })), Codes.WRAPPER_INVALID);
  });

  test('calibratedMs bounds', () => {
    for (const calibratedMs of [-1, 600001, 1.5, NaN, Infinity, '130', null]) {
      expectSyncCode(() => validateVaultWrapper(mutated({ calibratedMs })), Codes.WRAPPER_INVALID);
    }
    expect(() => validateVaultWrapper(mutated({ calibratedMs: 0 }))).not.toThrow();
    expect(() => validateVaultWrapper(mutated({ calibratedMs: 600000 }))).not.toThrow();
  });

  test('rewrapPending: depth 1 allowed, depth 2 rejected, broken pending rejected', () => {
    expect(MAX_REWRAP_PENDING_DEPTH).toBe(1);
    const pending = fixtureWrapper();
    expect(() => validateVaultWrapper(mutated({ rewrapPending: pending }))).not.toThrow();

    const nested = mutated({ rewrapPending: mutated({ rewrapPending: fixtureWrapper() }) });
    const err = expectSyncCode(() => validateVaultWrapper(nested), Codes.WRAPPER_INVALID);
    expect(err.details).toEqual({ field: 'rewrapPending' });

    expectSyncCode(
      () => validateVaultWrapper(mutated({ rewrapPending: mutated({ mKib: 19455 }) })),
      Codes.KDF_PARAMS_INVALID,
    );
    expectSyncCode(() => validateVaultWrapper(mutated({ rewrapPending: undefined })), Codes.WRAPPER_INVALID);
  });
});

describe('uniform authentication failure (no corruption oracle)', () => {
  test('wrong KEK, flipped ciphertext, flipped tag, altered nonce, AAD swaps → ONE code and message', async () => {
    const flippedCt = fixtureWrapper();
    flippedCt.wrappedRootKey = flippedCt.wrappedRootKey.slice();
    flippedCt.wrappedRootKey[0] ^= 0x01;
    const flippedTag = fixtureWrapper();
    flippedTag.wrappedRootKey = flippedTag.wrappedRootKey.slice();
    flippedTag.wrappedRootKey[47] ^= 0x80;
    const alteredNonce = fixtureWrapper();
    alteredNonce.wrapNonce = alteredNonce.wrapNonce.slice();
    alteredNonce.wrapNonce[11] ^= 0xff;
    // AAD-bound fields changed to OTHER VALID values: validation passes, unwrap must not.
    const profileSwap = mutated({ profile: 'desktop', mKib: 131072, t: 3, p: 1 });
    const saltSwap = mutated({ saltB64: encodeBase64(new Uint8Array(16).fill(0xab)) });

    const wrongKek = KEK.slice();
    wrongKek[0] ^= 0x01;

    const cases = [
      () => unwrapSyntheticRootKey(fixtureWrapper(), wrongKek),
      () => unwrapSyntheticRootKey(flippedCt, KEK),
      () => unwrapSyntheticRootKey(flippedTag, KEK),
      () => unwrapSyntheticRootKey(alteredNonce, KEK),
      () => unwrapSyntheticRootKey(profileSwap, KEK),
      () => unwrapSyntheticRootKey(saltSwap, KEK),
    ];
    for (const thunk of cases) {
      const err = await expectAsyncCode(thunk, Codes.WRONG_PASSWORD);
      expect(err.message).toBe('VAULT_WRONG_PASSWORD: wrong password or tampered wrapper');
      expect(err.details).toBeUndefined();
    }
  });

  test('fields OUTSIDE the AAD (createdAt, calibratedMs, profile alone cannot move) do not break the unwrap', async () => {
    // createdAt and calibratedMs are validated but deliberately unbound (see
    // vault-aad.js): editing them must NOT invalidate the wrapped key.
    const edited = mutated({ createdAt: '2026-12-31', calibratedMs: 599999 });
    const rootKey = await unwrapSyntheticRootKey(edited, KEK);
    expect(toHex(rootKey)).toBe(fixture.inputs.rootKeyHex);
  });
});

describe('property tests (fast-check, CI-friendly volumes)', () => {
  const bytes = (n) => fc.uint8Array({ minLength: n, maxLength: n });

  test('wrap/unwrap round-trips for arbitrary synthetic keys and salts', async () => {
    await fc.assert(fc.asyncProperty(bytes(32), bytes(32), bytes(16), async (kek, rootKey, salt) => {
      const wrapper = await wrapSyntheticRootKey({
        kek, rootKey, salt, mKib: 19456, t: 4, p: 1, profile: 'mobile-low-memory', createdAt: '2026-07-12',
      });
      const out = await unwrapSyntheticRootKey(wrapper, kek);
      return toHex(out) === toHex(rootKey);
    }), { numRuns: 16 });
  });

  test('encode(parse(x)) is canonical and stable', () => {
    fc.assert(fc.property(bytes(12), bytes(48), (nonce, wrapped) => {
      const w = mutated({ wrapNonce: nonce, wrappedRootKey: wrapped });
      const once = encodeVaultWrapper(parseVaultWrapper(w));
      const twice = encodeVaultWrapper(parseVaultWrapper(once));
      return JSON.stringify(Object.keys(once)) === JSON.stringify(Object.keys(twice))
        && toHex(once.wrapNonce) === toHex(twice.wrapNonce)
        && toHex(once.wrappedRootKey) === toHex(twice.wrappedRootKey)
        && toHex(buildWrapperAadBytes(once)) === toHex(buildWrapperAadBytes(twice));
    }), { numRuns: 64 });
  });

  test('canonical Base64: encode/decode round-trips, mutations never alias', () => {
    fc.assert(fc.property(fc.uint8Array({ minLength: 0, maxLength: 64 }), (raw) => {
      if (raw.length === 0) return true; // empty string is not accepted by design
      const s = encodeBase64(raw);
      const back = decodeCanonicalBase64(s);
      return back !== null && toHex(back) === toHex(raw);
    }), { numRuns: 256 });
    // Known aliases of the same bytes must be rejected.
    expect(decodeCanonicalBase64('QQF=')).toBeNull();
    expect(decodeCanonicalBase64('QQ==')).not.toBeNull();
    expect(decodeCanonicalBase64('QQ=')).toBeNull();
    expect(decodeCanonicalBase64('Q===')).toBeNull();
    expect(decodeCanonicalBase64('QQ==\n')).toBeNull();
  });

  test('malformed objects always fail closed with a VaultCryptoError, never a random throw', () => {
    fc.assert(fc.property(fc.anything(), (raw) => {
      try {
        validateVaultWrapper(raw);
        return false; // fc.anything() can never produce a complete valid wrapper
      } catch (e) {
        return e instanceof VaultCryptoError;
      }
    }), { numRuns: 256 });
  });
});

describe('integration: KEK derived through the REAL styx-kdf-wasm artifact (test-only path)', () => {
  test('deriveWithBounds → synthetic KEK → wrap → unwrap', async () => {
    const wasmPath = here('../../vendor/styx-kdf-wasm/pkg/styx_kdf_wasm.js');
    const mod = await import(wasmPath);
    await mod.default({ module_or_path: readFileSync(here('../../vendor/styx-kdf-wasm/pkg/styx_kdf_wasm_bg.wasm')) });

    const password = new TextEncoder().encode('STYX-VAULT-TEST-ONLY password');
    const salt = fromHex(fixture.inputs.kdfSaltHex);
    const { mKib, t, p } = KDF_PROFILES['mobile-low-memory'];
    const kek = deriveWithBounds(mod.argon2id_derive, password, {
      kdf: 'argon2id', kdfVersion: 19, mKib, t, p, salt, outLen: 32, profile: 'mobile-low-memory',
    });
    expect(kek.length).toBe(32);

    const rootKey = crypto.getRandomValues(new Uint8Array(32));
    const wrapper = await wrapSyntheticRootKey({
      kek, rootKey, salt, mKib, t, p, profile: 'mobile-low-memory', createdAt: '2026-07-12',
    });
    expect(wrapper.format).toBe(VAULT_WRAPPER_FORMAT);
    expect(wrapper.wrapNonce.length).toBe(WRAP_NONCE_BYTES);
    expect(wrapper.wrappedRootKey.length).toBe(WRAPPED_ROOT_KEY_BYTES);

    const recovered = await unwrapSyntheticRootKey(wrapper, kek);
    expect(toHex(recovered)).toBe(toHex(rootKey));

    const wrongPassword = new TextEncoder().encode('STYX-VAULT-TEST-ONLY wrong');
    const wrongKek = deriveWithBounds(mod.argon2id_derive, wrongPassword, {
      kdf: 'argon2id', kdfVersion: 19, mKib, t, p, salt, outLen: 32, profile: 'mobile-low-memory',
    });
    await expectAsyncCode(() => unwrapSyntheticRootKey(wrapper, wrongKek), Codes.WRONG_PASSWORD);
  }, 30000);
});
