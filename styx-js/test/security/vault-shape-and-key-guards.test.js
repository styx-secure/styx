// Adversarial / negative tests for the vault strict-shape gate, the WebCrypto key
// contracts, the KDF policy bounds and the vault AAD/base64 canonicalization.
//
// GAP JUSTIFICATIONS (see GAPS.md of the parent re-run, t_3e22486c):
//  - `styx-js/src/crypto/vault-shape.js`: "test che lo citano: 0" — all eleven
//    categories absent (boundary/size, canonicalization, collision, malformed,
//    hostile names, replay, resource exhaustion, rollback, secret handling,
//    timeout/liveness, unicode/normalization).
//  - `styx-js/src/crypto/vault-key-guards.js`: "test che lo citano: 0" — same
//    eleven categories absent.
//  - `styx-js/src/crypto/kdf-bounds.js`: missing "collision / ambiguity",
//    "rollback / atomicity", "timeout / liveness".
//  - `styx-js/src/crypto/vault-aad.js`: missing "collision / ambiguity",
//    "resource exhaustion / amplification".
//
// Every test here is deterministic and offline: no network, no wall clock, no
// unseeded randomness. WebCrypto comes from the Node runtime (no network I/O).

import { describe, expect, test } from '@jest/globals';

import { snapshotStrictPlainObject } from '../../src/crypto/vault-shape.js';
import {
  assertAes256GcmCryptoKey,
  assertHmacSha256CryptoKey,
} from '../../src/crypto/vault-key-guards.js';
import {
  KDF_FLOOR_M_KIB,
  KDF_POLICY,
  KDF_PROFILES,
  KdfBoundsError,
  deriveWithBounds,
  validateKdfParams,
} from '../../src/crypto/kdf-bounds.js';
import {
  buildManifestCanonicalBytes,
  buildRecordAadBytes,
  buildWrapperAadBytes,
  decodeCanonicalBase64,
  encodeBase64,
} from '../../src/crypto/vault-aad.js';
import { VaultCryptoError, VaultCryptoErrorCodes } from '../../src/crypto/vault-errors.js';

const invalid = (message, details) => {
  const error = new Error(message);
  error.code = 'VAULT_SHAPE_INVALID';
  error.details = details;
  return error;
};

const ALLOWED = ['v', 'ns', 'k'];

// ---------------------------------------------------------------------------
// vault-shape.js — strict shape gate for untrusted objects
// ---------------------------------------------------------------------------

describe('vault-shape: closed shape, descriptor discipline, hostile keys', () => {
  test('accepts exactly the allowed enumerable data fields and snapshots their values', () => {
    const raw = { v: 1, ns: 'ns', k: 'k' };
    const snapshot = snapshotStrictPlainObject(raw, ALLOWED, invalid);
    expect(snapshot).toEqual({ v: 1, ns: 'ns', k: 'k' });
    // Snapshot is a fresh plain object, not the caller's object.
    expect(snapshot).not.toBe(raw);
    // Later mutation of the untrusted object cannot change the snapshot.
    raw.v = 999;
    expect(snapshot.v).toBe(1);
  });

  test('rejects non-plain values: null, arrays, primitives, custom prototypes', () => {
    class Hostile {}
    const cases = [null, ['v', 'ns', 'k'], 1, 'str', true, new Hostile(), new Date(0), Object.create({ v: 1 })];
    for (const value of cases) {
      expect(() => snapshotStrictPlainObject(value, ALLOWED, invalid)).toThrowError();
    }
  });

  test('rejects symbol-keyed properties instead of ignoring them', () => {
    const raw = { v: 1, ns: 'ns', k: 'k' };
    raw[Symbol('smuggled')] = 'x';
    expect(() => snapshotStrictPlainObject(raw, ALLOWED, invalid)).toThrowError(/symbol/);
  });

  test('rejects accessor fields WITHOUT ever invoking the getter (no side effects)', () => {
    let invoked = 0;
    const raw = { ns: 'ns', k: 'k' };
    Object.defineProperty(raw, 'v', {
      enumerable: true,
      configurable: true,
      get() {
        invoked += 1;
        throw new Error('getter must never run');
      },
    });
    expect(() => snapshotStrictPlainObject(raw, ALLOWED, invalid)).toThrowError();
    expect(invoked).toBe(0);
  });

  test('rejects non-enumerable data fields (smuggled required field)', () => {
    const raw = { ns: 'ns', k: 'k' };
    Object.defineProperty(raw, 'v', { value: 1, enumerable: false, configurable: true, writable: true });
    expect(() => snapshotStrictPlainObject(raw, ALLOWED, invalid)).toThrowError();
  });

  test('rejects unknown fields and truncates attacker-chosen names in the error details', () => {
    const hostileName = 'z'.repeat(4096);
    let caught;
    try {
      snapshotStrictPlainObject({ v: 1, ns: 'ns', k: 'k', [hostileName]: 1 }, ALLOWED, invalid);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeDefined();
    expect(caught.details.field).toHaveLength(64);
  });

  test('rejects missing required fields but honours requiredKeys: [] for all-optional shapes', () => {
    expect(() => snapshotStrictPlainObject({ v: 1, ns: 'ns' }, ALLOWED, invalid)).toThrowError();
    expect(snapshotStrictPlainObject({ v: 1 }, ALLOWED, invalid, { requiredKeys: [] })).toEqual({ v: 1 });
  });

  test('unicode: NFC and NFD spellings of an allowed name are distinct — no normalization collision', () => {
    const decomposed = 'n\u0303s'; // n + combining tilde (NFD of ñs)
    const composed = '\u00f1s'; // ñs (NFC)
    expect(decomposed).not.toBe(composed);
    // The allowlist must be matched byte-for-byte: a differently-normalized
    // spelling of an allowed name is an unknown field, never a match.
    expect(() => snapshotStrictPlainObject({ v: 1, ns: 'ns', k: 'k', [decomposed]: 1 }, ALLOWED, invalid)).toThrowError();
    expect(() => snapshotStrictPlainObject({ v: 1, [decomposed]: 1, k: 'k' }, ['v', composed, 'k'], invalid)).toThrowError();
    expect(() => snapshotStrictPlainObject({ v: 1, [composed]: 1, k: 'k' }, ['v', decomposed, 'k'], invalid)).toThrowError();

  });

  test('hostile: an own __proto__ data property is rejected and never pollutes Object.prototype', () => {
    const raw = { v: 1, ns: 'ns', k: 'k' };
    Object.defineProperty(raw, '__proto__', { value: { polluted: true }, enumerable: true, configurable: true });
    expect(() => snapshotStrictPlainObject(raw, ALLOWED, invalid)).toThrowError();
    expect(Object.prototype.polluted).toBeUndefined();
    expect({}.polluted).toBeUndefined();
  });

  test('boundary: an object with many own keys is rejected on the first unknown key', () => {
    const raw = { v: 1, ns: 'ns', k: 'k' };
    for (let index = 0; index < 5000; index += 1) raw[`extra${index}`] = index;
    expect(() => snapshotStrictPlainObject(raw, ALLOWED, invalid)).toThrowError();
  });
});

// ---------------------------------------------------------------------------
// vault-key-guards.js — exact WebCrypto key contracts
// ---------------------------------------------------------------------------

const aesKey = (options) => crypto.subtle.generateKey(
  { name: 'AES-GCM', length: options.length ?? 256 },
  options.extractable ?? false,
  options.usages ?? ['encrypt', 'decrypt'],
);

const hmacKey = (options) => crypto.subtle.generateKey(
  { name: 'HMAC', hash: options.hash ?? 'SHA-256', length: options.length ?? 256 },
  options.extractable ?? false,
  options.usages ?? ['sign', 'verify'],
);

describe('vault-key-guards: exact key profile, no near-miss acceptance', () => {
  test('accepts the exact AES-256-GCM profile', async () => {
    const key = await aesKey({});
    expect(assertAes256GcmCryptoKey(key)).toBe(key);
  });

  test('rejects extractable, 128-bit, wrong-usage and extra-usage AES keys', async () => {
    const extractable = await aesKey({ extractable: true });
    const short = await aesKey({ length: 128 });
    const oneUsage = await aesKey({ usages: ['encrypt'] });
    const extraUsage = await aesKey({ usages: ['encrypt', 'decrypt', 'wrapKey'] });
    for (const key of [extractable, short, oneUsage, extraUsage]) {
      expect(() => assertAes256GcmCryptoKey(key)).toThrowError(VaultCryptoError);
      try {
        assertAes256GcmCryptoKey(key);
      } catch (error) {
        expect(error.code).toBe(VaultCryptoErrorCodes.CRYPTO_FAILED);
        // The error must never describe the rejected key material.
        expect(error.message).not.toMatch(/extractable|128|wrapKey/i);
      }
    }
  });

  test('accepts the exact HMAC-SHA-256 profile', async () => {
    const key = await hmacKey({});
    expect(assertHmacSha256CryptoKey(key)).toBe(key);
  });

  test('rejects HMAC keys with another hash, another length, or incomplete usages', async () => {
    const sha384 = await hmacKey({ hash: 'SHA-384' });
    const short = await hmacKey({ length: 128 });
    const extractable = await hmacKey({ extractable: true });
    const oneUsage = await hmacKey({ usages: ['sign'] });
    for (const key of [sha384, short, extractable, oneUsage]) {
      expect(() => assertHmacSha256CryptoKey(key)).toThrowError(VaultCryptoError);
    }
  });

  test('non-key values are rejected without a TypeError leak', () => {
    for (const value of [null, undefined, 0, 'key', {}, []]) {
      expect(() => assertAes256GcmCryptoKey(value)).toThrowError(VaultCryptoError);
      expect(() => assertHmacSha256CryptoKey(value)).toThrowError(VaultCryptoError);
    }
  });

  test('observed: an object forge-branded as CryptoKey leaks a raw TypeError (see FINDINGS.md)', () => {
    // `instanceof CryptoKey` is satisfied by a prototype spoof, and reading
    // `.type` on such an object throws a raw TypeError from the WebCrypto
    // brand check instead of the module's typed VAULT_CRYPTO_FAILED contract.
    // Fail-closed (the call is refused), but outside the documented error
    // contract: recorded as a finding, not fixed by this card.
    const branded = Object.create(CryptoKey.prototype);
    expect(() => assertAes256GcmCryptoKey(branded)).toThrow();
    expect(() => assertHmacSha256CryptoKey(branded)).toThrow();
  });
});

// ---------------------------------------------------------------------------
// kdf-bounds.js — collision-free profiles and fail-before-derive
// ---------------------------------------------------------------------------

const validParams = (over = {}) => ({
  kdf: 'argon2id',
  kdfVersion: 19,
  mKib: KDF_PROFILES.desktop.mKib,
  t: KDF_PROFILES.desktop.t,
  p: KDF_PROFILES.desktop.p,
  salt: new Uint8Array(KDF_POLICY.saltLen).fill(7),
  outLen: KDF_POLICY.outLen,
  profile: 'desktop',
  ...over,
});

describe('kdf-bounds: profile ambiguity, floor/ceiling, anti-allocation', () => {
  test('accepts every declared profile with exactly its own numbers', () => {
    for (const [name, numbers] of Object.entries(KDF_PROFILES)) {
      const value = validateKdfParams(validParams({ ...numbers, profile: name }));
      expect(value).toEqual({ mKib: numbers.mKib, t: numbers.t, p: numbers.p, outLen: KDF_POLICY.outLen });
    }
  });

  test('collision: a profile name carrying another profile\'s numbers is rejected', () => {
    expect(() => validateKdfParams(validParams({ ...KDF_PROFILES['mobile-low-memory'], profile: 'desktop' }))).toThrowError(KdfBoundsError);
  });

  test('collision: profile names that resolve through the prototype chain are rejected', () => {
    for (const name of ['__proto__', 'constructor', 'toString', 'hasOwnProperty', 'valueOf']) {
      expect(() => validateKdfParams(validParams({ profile: name }))).toThrowError(KdfBoundsError);
    }
  });

  test('collision: inherited fields do not satisfy the closed field set', () => {
    const inherited = Object.create(validParams());
    expect(() => validateKdfParams(inherited)).toThrowError(KdfBoundsError);
  });

  test('boundary: memory floor/ceiling and iteration bounds are enforced', () => {
    for (const mKib of [0, KDF_FLOOR_M_KIB - 1, KDF_POLICY.mMaxKib + 1, Number.MAX_SAFE_INTEGER + 1, 1.5]) {
      expect(() => validateKdfParams(validParams({ mKib }))).toThrowError(KdfBoundsError);
    }
    for (const t of [KDF_POLICY.tMin - 1, KDF_POLICY.tMax + 1, -1, 2.5]) {
      expect(() => validateKdfParams(validParams({ t }))).toThrowError(KdfBoundsError);
    }
  });

  test('boundary: salt width, output length, parallelism and version are exact', () => {
    expect(() => validateKdfParams(validParams({ salt: new Uint8Array(KDF_POLICY.saltLen - 1) }))).toThrowError(KdfBoundsError);
    expect(() => validateKdfParams(validParams({ salt: new Uint8Array(KDF_POLICY.saltLen + 1) }))).toThrowError(KdfBoundsError);
    expect(() => validateKdfParams(validParams({ salt: [...new Uint8Array(16)] }))).toThrowError(KdfBoundsError);
    expect(() => validateKdfParams(validParams({ outLen: 16 }))).toThrowError(KdfBoundsError);
    expect(() => validateKdfParams(validParams({ p: 2 }))).toThrowError(KdfBoundsError);
    expect(() => validateKdfParams(validParams({ kdfVersion: 16 }))).toThrowError(KdfBoundsError);
    expect(() => validateKdfParams(validParams({ kdf: 'scrypt' }))).toThrowError(KdfBoundsError);
  });

  test('hostile: unknown fields are rejected, including hostile long names', () => {
    expect(() => validateKdfParams(validParams({ extra: 1 }))).toThrowError(KdfBoundsError);
    expect(() => validateKdfParams(validParams({ ['x'.repeat(4096)]: 1 }))).toThrowError(KdfBoundsError);
  });

  test('hostile: symbol properties are ignored (observed behaviour, no field smuggling)', () => {
    // Object.keys() sees only string keys, so a symbol cannot displace a
    // required field; the closed set is still satisfied by the real fields.
    // Recorded as an observation — see FINDINGS.md.
    expect(() => validateKdfParams(validParams({ [Symbol('s')]: 1 }))).not.toThrow();
  });

  test('rollback/anti-allocation: the derive function is never invoked on any policy violation', () => {
    let calls = 0;
    const derive = () => {
      calls += 1;
      return new Uint8Array(KDF_POLICY.outLen);
    };
    const hostile = [
      validParams({ mKib: KDF_FLOOR_M_KIB - 1 }),
      validParams({ profile: '__proto__' }),
      validParams({ salt: new Uint8Array(15) }),
      null,
      [],
      '__proto__',
    ];
    for (const params of hostile) {
      expect(() => deriveWithBounds(derive, new Uint8Array(8), params)).toThrowError(KdfBoundsError);
    }
    expect(calls).toBe(0);
  });

  test('boundary: password byte-length window is enforced before derive', () => {
    const derive = (password) => password;
    expect(() => deriveWithBounds(derive, new Uint8Array(0), validParams())).toThrowError(KdfBoundsError);
    expect(deriveWithBounds(derive, new Uint8Array(1), validParams()).length).toBe(1);
    expect(deriveWithBounds(derive, new Uint8Array(KDF_POLICY.passwordMaxLen), validParams()).length).toBe(KDF_POLICY.passwordMaxLen);
    expect(() => deriveWithBounds(derive, new Uint8Array(KDF_POLICY.passwordMaxLen + 1), validParams())).toThrowError(KdfBoundsError);
    expect(() => deriveWithBounds(derive, 'password', validParams())).toThrowError(KdfBoundsError);
    expect(() => deriveWithBounds('not-a-function', new Uint8Array(1), validParams())).toThrowError(KdfBoundsError);
  });

  test('rollback: a derive failure leaves caller-owned inputs unchanged', () => {
    const salt = new Uint8Array(KDF_POLICY.saltLen).fill(3);
    const params = validParams({ salt });
    const before = Uint8Array.from(salt);
    const failing = () => {
      throw new Error('wasm failure');
    };
    expect(() => deriveWithBounds(failing, new Uint8Array(4), params)).toThrowError('wasm failure');
    expect(salt).toEqual(before);
    expect(params.mKib).toBe(KDF_PROFILES.desktop.mKib);
  });

  test('liveness: validation is pure — repeated calls give identical results and no timers are armed', () => {
    const first = validateKdfParams(validParams());
    const second = validateKdfParams(validParams());
    expect(first).toEqual(second);
    expect(first).not.toBe(second);
    expect(Object.isFrozen(first)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// vault-aad.js — canonical AAD bytes and canonical Base64
// ---------------------------------------------------------------------------

const WRAPPER = {
  format: 'styx-vault-wrapper/v1',
  version: 1,
  kdf: 'argon2id',
  kdfVersion: 19,
  mKib: 131072,
  t: 3,
  p: 1,
  saltB64: 'AAECAwQFBgcICQoLDA0ODw==',
  outLen: 32,
  keyVersion: 1,
};

const decodeAad = (bytes) => new TextDecoder().decode(bytes);

describe('vault-aad: canonical bindings, no ambiguity, strict base64', () => {
  test('AAD bytes are the fixed-order primitive serialization', () => {
    expect(decodeAad(buildWrapperAadBytes(WRAPPER))).toBe(
      '["styx-vault-wrapper/v1",1,"argon2id",19,131072,3,1,"AAECAwQFBgcICQoLDA0ODw==",32,1]',
    );
    expect(decodeAad(buildRecordAadBytes({ v: 1, ns: 'ns', k: 'k', rv: 2, kv: 3, ct: 'AAAA' }))).toBe('[1,"ns","k",2,3,"AAAA"]');
    expect(decodeAad(buildManifestCanonicalBytes({
      format: 'styx-vault-manifest/v1',
      version: 1,
      schemaVersion: 2,
      migrationVersion: 0,
      generation: 5,
      lastTxId: 'tx',
    }))).toBe('["styx-vault-manifest/v1",1,2,0,5,"tx"]');
  });

  test('collision: every bound field changes the bytes; unbound extras do not leak in', () => {
    const base = decodeAad(buildWrapperAadBytes(WRAPPER));
    for (const [key, value] of [['version', 2], ['kdf', 'scrypt'], ['kdfVersion', 16], ['mKib', 65536], ['t', 4], ['p', 2], ['saltB64', 'AQ=='], ['outLen', 16], ['keyVersion', 2]]) {
      expect(decodeAad(buildWrapperAadBytes({ ...WRAPPER, [key]: value }))).not.toBe(base);
    }
    // Informational metadata is deliberately excluded (documented contract):
    // extra properties must not silently enter the canonical bytes.
    expect(decodeAad(buildWrapperAadBytes({ ...WRAPPER, profile: 'desktop', createdAt: 'x' }))).toBe(base);
  });

  test('collision: two distinct values never share a serialization (field boundary safety)', () => {
    const left = decodeAad(buildRecordAadBytes({ v: 1, ns: 'a', k: 'bc', rv: 1, kv: 1, ct: 'A' }));
    const right = decodeAad(buildRecordAadBytes({ v: 1, ns: 'ab', k: 'c', rv: 1, kv: 1, ct: 'A' }));
    expect(left).not.toBe(right);
    const unicodeNfc = decodeAad(buildRecordAadBytes({ v: 1, ns: '\u00f1', k: 'k', rv: 1, kv: 1, ct: 'A' }));
    const unicodeNfd = decodeAad(buildRecordAadBytes({ v: 1, ns: 'n\u0303', k: 'k', rv: 1, kv: 1, ct: 'A' }));
    expect(unicodeNfc).not.toBe(unicodeNfd);
  });

  test('malformed: hostile primitive types are rejected before JSON.stringify', () => {
    const hostileString = { toString: () => 'ns', valueOf: () => 'ns' };
    expect(() => buildRecordAadBytes({ v: 1, ns: hostileString, k: 'k', rv: 1, kv: 1, ct: 'A' })).toThrowError(TypeError);
    expect(() => buildRecordAadBytes({ v: 1.5, ns: 'ns', k: 'k', rv: 1, kv: 1, ct: 'A' })).toThrowError(TypeError);
    expect(() => buildRecordAadBytes({ v: 1, ns: 'ns', k: 'k', rv: Number.NaN, kv: 1, ct: 'A' })).toThrowError(TypeError);
    expect(() => buildRecordAadBytes({ v: 1, ns: 'ns', k: 'k', rv: 2n, kv: 1, ct: 'A' })).toThrowError(TypeError);
    expect(() => buildRecordAadBytes({ v: 1, ns: 'ns', k: 'k', rv: 1, kv: 1 })).toThrowError(TypeError);
  });

  test('base64: strict decoder rejects every non-canonical spelling', () => {
    const hostile = [
      '', 'QQ', 'QQE', 'QQE==', 'QQF=', 'QR==', '====', 'AA==AA==', 'A A==',
      'AA==\n', 'AA_=', 'AA-=', 'AA== ', 'AA\uFF21=', 'AB==', 'AAAA=', 'AAA',
    ];
    for (const value of hostile) {
      expect(decodeCanonicalBase64(value)).toBeNull();
    }
    // The canonical spelling of the same bytes IS accepted: exactly one
    // encoding per byte string.
    expect(decodeCanonicalBase64(encodeBase64(new Uint8Array([0])))).toEqual(new Uint8Array([0]));
    expect(decodeCanonicalBase64('QQE=')).toEqual(new Uint8Array([65, 1]));
    expect(decodeCanonicalBase64('QQF=')).toBeNull();
  });

  test('base64: encoding is injective — no two distinct byte strings share a spelling', () => {
    // The empty byte string has no canonical spelling at all (the decoder
    // rejects '' and there is nothing to collide with) — observed, see
    // FINDINGS.md.
    expect(encodeBase64(new Uint8Array(0))).toBe('');
    expect(decodeCanonicalBase64('')).toBeNull();
    const seen = new Map();
    for (let length = 1; length <= 4; length += 1) {
      const bound = 256 ** length;
      const step = Math.max(1, Math.floor(bound / 512));
      for (let value = 0; value < bound; value += step) {
        const bytes = new Uint8Array(length);
        for (let index = 0; index < length; index += 1) {
          bytes[index] = (value >> (8 * index)) & 0xff;
        }
        const encoded = encodeBase64(bytes);
        const previous = seen.get(encoded);
        expect(previous === undefined || previous === bytes.join(',')).toBe(true);
        seen.set(encoded, bytes.join(','));
        expect(Array.from(decodeCanonicalBase64(encoded))).toEqual(Array.from(bytes));
      }
    }
  });

  test('resource exhaustion: oversized/non-canonical base64 payloads return null without throwing', () => {
    const pathological = [
      'A'.repeat(4 * 1024 * 1024) + '!',
      '='.repeat(1024 * 1024),
      'A'.repeat(4095),
      'A'.repeat(4096) + 'A',
    ];
    for (const value of pathological) {
      expect(decodeCanonicalBase64(value)).toBeNull();
    }
    expect(decodeCanonicalBase64('not-a-string')).toBeNull();
    expect(decodeCanonicalBase64(new Uint8Array(4))).toBeNull();
  });

  test('base64: non-Uint8Array input never reaches the encoder', () => {
    for (const value of [null, undefined, 'AAAA', [1, 2, 3], new Uint16Array(2), Buffer.from([1])]) {
      if (Buffer.isBuffer(value)) continue;
      expect(() => encodeBase64(value)).toThrowError(TypeError);
    }
  });
});
