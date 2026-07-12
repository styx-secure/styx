// vault-wrapper.js — strict codec for the KDF wrapper v1 (Blocco 3, PR-2;
// vault spec §7/§7.1). Pure module: no IndexedDB, no localStorage, no worker,
// no UI, no KDF call — it validates, encodes and (un)wraps an ALREADY
// AVAILABLE KEK against a SYNTHETIC Root Key. Deriving the KEK from a
// password is the caller's job through kdf-bounds.js (never this module's:
// `password → KDF` and `KEK → wrap/unwrap` stay separated by design).
//
// The wrapper is read BEFORE unlock, so every field is untrusted input:
// validation is fail-closed, works on a descriptor-based snapshot (accessors
// and non-enumerable smuggling rejected without ever invoking a getter —
// review F6), and completes BEFORE any WebCrypto or RNG call (review F8).
// KDF parameter policy is delegated to the single validator in kdf-bounds.js
// — never re-copied.

import {
  validateKdfParams, KdfBoundsError, KDF_POLICY,
} from '../crypto/kdf-bounds.js';
import { VaultCryptoError, VaultCryptoErrorCodes as Codes } from '../crypto/vault-errors.js';
import { buildWrapperAadBytes, encodeBase64, decodeCanonicalBase64 } from '../crypto/vault-aad.js';
import { snapshotStrictPlainObject } from '../crypto/vault-shape.js';
import { assertAes256GcmCryptoKey } from '../crypto/vault-key-guards.js';

export const VAULT_WRAPPER_FORMAT = 'styx-vault-wrapper';
export const VAULT_WRAPPER_VERSION = 1;
export const WRAP_ALG = 'A256GCM';
export const WRAP_NONCE_BYTES = 12;
export const WRAPPED_ROOT_KEY_BYTES = 48; // 32-byte Root Key + 16-byte GCM tag
export const ROOT_KEY_BYTES = 32;
export const KEK_BYTES = 32;
export const MAX_CALIBRATED_MS = 600000;
/**
 * `rewrapPending` recursion is capped at depth 1 (normative clarification of
 * spec §7.1): the ACTIVE wrapper may carry one pending wrapper (§7.2), and a
 * pending wrapper's own `rewrapPending` MUST be null. A pending-inside-pending
 * is rejected as VAULT_WRAPPER_INVALID.
 */
export const MAX_REWRAP_PENDING_DEPTH = 1;

const WRAPPER_KEYS = Object.freeze([
  'format', 'version', 'kdf', 'kdfVersion', 'mKib', 't', 'p', 'profile',
  'saltB64', 'outLen', 'wrapAlg', 'wrapNonce', 'wrappedRootKey',
  'keyVersion', 'createdAt', 'calibratedMs', 'rewrapPending',
]);

const CREATED_AT_RE = /^\d{4}-\d{2}-\d{2}$/;
const subtle = globalThis.crypto?.subtle;

const isSafeInt = (x) => typeof x === 'number' && Number.isSafeInteger(x);

function invalid(message, details) {
  return new VaultCryptoError(Codes.WRAPPER_INVALID, message, details);
}

function isRealCalendarDate(str) {
  if (!CREATED_AT_RE.test(str)) return false;
  const [y, m, d] = str.split('-').map(Number);
  const date = new Date(Date.UTC(y, m - 1, d));
  return date.getUTCFullYear() === y && date.getUTCMonth() === m - 1 && date.getUTCDate() === d;
}

/**
 * Validate one wrapper level from a strict descriptor snapshot (review F6)
 * and return an independent frozen copy. Everything downstream — AAD,
 * unwrap, persistence — uses ONLY the returned copy, never the input object.
 */
function parseWrapperAtDepth(raw, depth) {
  const s = snapshotStrictPlainObject(raw, WRAPPER_KEYS, invalid);

  if (s.format !== VAULT_WRAPPER_FORMAT) throw invalid('wrong wrapper format', { field: 'format' });
  if (!isSafeInt(s.version)) throw invalid('wrapper version must be an integer', { field: 'version' });
  if (s.version !== VAULT_WRAPPER_VERSION) {
    // A well-formed FUTURE version is "unsupported" (a newer build may read
    // it); anything else is plain invalid.
    if (s.version > VAULT_WRAPPER_VERSION) {
      throw new VaultCryptoError(Codes.WRAPPER_UNSUPPORTED, 'wrapper version not supported by this build', { field: 'version' });
    }
    throw invalid('wrapper version must be exactly 1', { field: 'version' });
  }

  // Canonical Base64, exactly one accepted encoding per salt value (§7.1).
  const salt = typeof s.saltB64 === 'string' && !/\s/.test(s.saltB64)
    ? decodeCanonicalBase64(s.saltB64)
    : null;
  if (salt === null) {
    throw new VaultCryptoError(Codes.KDF_PARAMS_INVALID, 'salt is not canonical base64', { field: 'saltB64' });
  }

  // THE single KDF policy validator (kdf-bounds.js): algorithm, version,
  // floor, maxima, profile allowlist and exact profile combination.
  try {
    validateKdfParams({
      kdf: s.kdf,
      kdfVersion: s.kdfVersion,
      mKib: s.mKib,
      t: s.t,
      p: s.p,
      salt,
      outLen: s.outLen,
      profile: s.profile,
    });
  } catch (e) {
    if (e instanceof KdfBoundsError) {
      throw new VaultCryptoError(Codes.KDF_PARAMS_INVALID, 'kdf parameters rejected by policy', { reason: e.message.slice(0, 64) });
    }
    throw e;
  } finally {
    salt.fill(0);
  }

  if (s.wrapAlg !== WRAP_ALG) {
    throw new VaultCryptoError(Codes.WRAPPER_UNSUPPORTED, 'unsupported wrap algorithm', { field: 'wrapAlg' });
  }
  if (!(s.wrapNonce instanceof Uint8Array) || s.wrapNonce.length !== WRAP_NONCE_BYTES) {
    throw invalid('wrap nonce must be a Uint8Array of 12 bytes', { field: 'wrapNonce' });
  }
  if (!(s.wrappedRootKey instanceof Uint8Array) || s.wrappedRootKey.length !== WRAPPED_ROOT_KEY_BYTES) {
    throw invalid('wrapped root key must be a Uint8Array of 48 bytes', { field: 'wrappedRootKey' });
  }

  if (!isSafeInt(s.keyVersion) || s.keyVersion < 1) {
    throw invalid('key version must be a safe integer >= 1', { field: 'keyVersion' });
  }
  if (s.keyVersion !== 1) {
    throw new VaultCryptoError(Codes.KEY_VERSION_UNSUPPORTED, 'wrapper key version not supported', { field: 'keyVersion' });
  }

  if (typeof s.createdAt !== 'string' || !isRealCalendarDate(s.createdAt)) {
    throw invalid('createdAt must be a real YYYY-MM-DD date', { field: 'createdAt' });
  }
  if (!isSafeInt(s.calibratedMs) || s.calibratedMs < 0 || s.calibratedMs > MAX_CALIBRATED_MS) {
    throw invalid('calibratedMs out of bounds', { field: 'calibratedMs' });
  }

  let rewrapPending = null;
  if (s.rewrapPending !== null) {
    if (depth >= MAX_REWRAP_PENDING_DEPTH) {
      throw invalid('rewrapPending exceeds the maximum depth of 1', { field: 'rewrapPending' });
    }
    rewrapPending = parseWrapperAtDepth(s.rewrapPending, depth + 1);
  }

  return Object.freeze({
    format: s.format,
    version: s.version,
    kdf: s.kdf,
    kdfVersion: s.kdfVersion,
    mKib: s.mKib,
    t: s.t,
    p: s.p,
    profile: s.profile,
    saltB64: s.saltB64,
    outLen: s.outLen,
    wrapAlg: s.wrapAlg,
    wrapNonce: s.wrapNonce.slice(),
    wrappedRootKey: s.wrappedRootKey.slice(),
    keyVersion: s.keyVersion,
    createdAt: s.createdAt,
    calibratedMs: s.calibratedMs,
    rewrapPending,
  });
}

/**
 * Fail-closed validation of an untrusted wrapper object (spec §7.1, full
 * table; `rewrapPending` capped at depth 1). Throws; returns nothing.
 * @throws {VaultCryptoError}
 */
export function validateVaultWrapper(raw) {
  parseWrapperAtDepth(raw, 0);
}

/**
 * Validate an untrusted wrapper and return an independent, frozen copy built
 * exclusively from property-descriptor values (buffers included): accessors
 * are never invoked and later mutation of the input cannot affect the result.
 * @returns {object} @throws {VaultCryptoError}
 */
export function parseVaultWrapper(raw) {
  return parseWrapperAtDepth(raw, 0);
}

/**
 * Validate a wrapper built in memory and return the plain object shape ready
 * for persistence (a later PR stores it via structured clone). Same strict
 * validation as parse: this module never emits what it would not accept.
 * @returns {object} @throws {VaultCryptoError}
 */
export function encodeVaultWrapper(wrapper) {
  return parseWrapperAtDepth(wrapper, 0);
}

/**
 * Canonical unwrap AAD of a wrapper, built from its VALIDATED snapshot
 * (delegates to vault-aad.js).
 * @returns {Uint8Array}
 */
export function buildWrapperAad(wrapper) {
  return buildWrapperAadBytes(parseWrapperAtDepth(wrapper, 0));
}

async function importKek(kek) {
  if (kek instanceof CryptoKey) {
    // Exact contract (review F7): secret AES-GCM-256, non-extractable,
    // usages exactly encrypt+decrypt.
    return assertAes256GcmCryptoKey(kek);
  }
  if (!(kek instanceof Uint8Array) || kek.length !== KEK_BYTES) {
    throw new VaultCryptoError(Codes.CRYPTO_FAILED, 'KEK must be a 32-byte Uint8Array or an AES-GCM CryptoKey');
  }
  // Non-extractable, exact contract usages; importKey copies, the caller
  // keeps ownership (and best-effort zeroization duty) of its own buffer.
  return subtle.importKey('raw', kek, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

/**
 * Wrap a SYNTHETIC 32-byte Root Key under an already-derived KEK and return a
 * complete, validated wrapper v1 object. PR-2 scope guard: no real Root
 * Storage Key exists yet — callers are tests and fixtures only.
 *
 * Order is normative (review F8): shape checks → draft with DETERMINISTIC
 * placeholders → FULL wrapper validation → KEK contract/import → nonce
 * generation → AAD → AES-GCM → output validation. No WebCrypto call and no
 * RNG call can happen while any metadata field is still unvalidated.
 *
 * The 12-byte nonce is generated INTERNALLY (`crypto.getRandomValues`); there
 * is deliberately no parameter to choose it (spec §6 discipline applies to
 * the wrapper too). The KDF metadata (`mKib`, `t`, `p`, `profile`, `salt`,
 * `outLen`) must describe how `kek` was derived and pass the kdf-bounds
 * policy; this function never sees the password and never runs the KDF.
 *
 * @param {object} input
 * @param {Uint8Array|CryptoKey} input.kek derived KEK (32 bytes if raw)
 * @param {Uint8Array} input.rootKey synthetic Root Key, exactly 32 bytes
 * @param {Uint8Array} input.salt the KDF salt used to derive `kek` (16 bytes)
 * @param {number} input.mKib @param {number} input.t @param {number} input.p
 * @param {string} input.profile @param {string} input.createdAt YYYY-MM-DD
 * @param {number} [input.calibratedMs=0] informational
 * @returns {Promise<object>} frozen wrapper v1
 * @throws {VaultCryptoError}
 */
export async function wrapSyntheticRootKey({
  kek, rootKey, salt, mKib, t, p, profile, createdAt, calibratedMs = 0,
}) {
  // 1. shape of the non-crypto inputs
  if (!(rootKey instanceof Uint8Array) || rootKey.length !== ROOT_KEY_BYTES) {
    throw new VaultCryptoError(Codes.CRYPTO_FAILED, 'root key must be a Uint8Array of 32 bytes');
  }
  if (!(salt instanceof Uint8Array) || salt.length !== KDF_POLICY.saltLen) {
    throw new VaultCryptoError(Codes.KDF_PARAMS_INVALID, 'salt must be a Uint8Array of 16 bytes', { field: 'salt' });
  }
  // 2. draft with deterministic placeholders — no RNG, no WebCrypto yet
  const draft = {
    format: VAULT_WRAPPER_FORMAT,
    version: VAULT_WRAPPER_VERSION,
    kdf: KDF_POLICY.kdf,
    kdfVersion: KDF_POLICY.kdfVersion,
    mKib,
    t,
    p,
    profile,
    saltB64: encodeBase64(salt),
    outLen: KDF_POLICY.outLen,
    wrapAlg: WRAP_ALG,
    wrapNonce: new Uint8Array(WRAP_NONCE_BYTES), // placeholder, replaced after validation
    wrappedRootKey: new Uint8Array(WRAPPED_ROOT_KEY_BYTES), // placeholder
    keyVersion: 1,
    createdAt,
    calibratedMs,
    rewrapPending: null,
  };
  // 3. FULL validation before any crypto or randomness (review F8)
  validateVaultWrapper(draft);
  // 4. KEK contract + import
  const key = await importKek(kek);
  // 5. nonce — only now that every metadata field is validated
  const wrapNonce = crypto.getRandomValues(new Uint8Array(WRAP_NONCE_BYTES));
  // 6. canonical AAD (the nonce is not part of it)
  const aad = buildWrapperAadBytes(draft);
  // 7. AES-256-GCM
  let wrapped;
  try {
    wrapped = new Uint8Array(await subtle.encrypt(
      { name: 'AES-GCM', iv: wrapNonce, additionalData: aad, tagLength: 128 },
      key,
      rootKey,
    ));
  } catch {
    throw new VaultCryptoError(Codes.CRYPTO_FAILED, 'root key wrap failed');
  }
  if (wrapped.length !== WRAPPED_ROOT_KEY_BYTES) {
    throw new VaultCryptoError(Codes.CRYPTO_FAILED, 'unexpected wrapped root key length');
  }
  // 8. output validation (this module never emits what it would not accept)
  return encodeVaultWrapper({ ...draft, wrapNonce, wrappedRootKey: wrapped });
}

/**
 * Fully validate the wrapper, rebuild its canonical AAD, then unwrap. On a
 * WELL-FORMED wrapper every authentication failure — wrong password, wrong
 * KEK, tampered ciphertext, tampered tag, tampered AAD field — maps to the
 * SAME `VAULT_WRONG_PASSWORD`: distinguishing them would add a corruption
 * oracle (the only password check in the design is this GCM unwrap, spec §7).
 * @param {object} wrapper untrusted wrapper v1 object
 * @param {Uint8Array|CryptoKey} kek
 * @returns {Promise<Uint8Array>} exactly 32 Root Key bytes (caller owns them)
 * @throws {VaultCryptoError}
 */
export async function unwrapSyntheticRootKey(wrapper, kek) {
  // parse = strict snapshot + validation + independent deep copy, taken
  // SYNCHRONOUSLY: a caller mutating the wrapper while we await cannot swap
  // what was validated for what gets decrypted (review F2, TOCTOU).
  const w = parseVaultWrapper(wrapper);
  const key = await importKek(kek);
  const aad = buildWrapperAadBytes(w);
  let plain;
  try {
    plain = new Uint8Array(await subtle.decrypt(
      { name: 'AES-GCM', iv: w.wrapNonce, additionalData: aad, tagLength: 128 },
      key,
      w.wrappedRootKey,
    ));
  } catch {
    throw new VaultCryptoError(Codes.WRONG_PASSWORD, 'wrong password or tampered wrapper');
  }
  if (plain.length !== ROOT_KEY_BYTES) {
    plain.fill(0);
    throw new VaultCryptoError(Codes.CRYPTO_FAILED, 'unexpected unwrapped root key length');
  }
  return plain;
}
