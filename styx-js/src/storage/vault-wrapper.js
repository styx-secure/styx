// vault-wrapper.js — strict codec for the KDF wrapper v1 (Blocco 3, PR-2;
// vault spec §7/§7.1). Pure module: no IndexedDB, no localStorage, no worker,
// no UI, no KDF call — it validates, encodes and (un)wraps an ALREADY
// AVAILABLE KEK against a SYNTHETIC Root Key. Deriving the KEK from a
// password is the caller's job through kdf-bounds.js (never this module's:
// `password → KDF` and `KEK → wrap/unwrap` stay separated by design).
//
// The wrapper is read BEFORE unlock, so every field is untrusted input:
// validation is fail-closed and completes BEFORE Argon2id or WebCrypto could
// ever be reached with out-of-shape values (spec §7.1). KDF parameter policy
// is delegated to the single validator in kdf-bounds.js — never re-copied.

import {
  validateKdfParams, KdfBoundsError, KDF_POLICY,
} from '../crypto/kdf-bounds.js';
import { VaultCryptoError, VaultCryptoErrorCodes as Codes } from '../crypto/vault-errors.js';
import { buildWrapperAadBytes, encodeBase64, decodeCanonicalBase64 } from '../crypto/vault-aad.js';

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

function assertStrictShape(raw) {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw invalid('wrapper must be a plain object');
  }
  const proto = Object.getPrototypeOf(raw);
  if (proto !== Object.prototype && proto !== null) {
    throw invalid('wrapper must not carry a custom prototype');
  }
  for (const key of Object.keys(raw)) {
    if (!WRAPPER_KEYS.includes(key)) throw invalid('unknown wrapper field', { field: key });
    const desc = Object.getOwnPropertyDescriptor(raw, key);
    if (desc === undefined || !Object.hasOwn(desc, 'value')) {
      throw invalid('wrapper fields must be plain data properties', { field: key });
    }
  }
  for (const key of WRAPPER_KEYS) {
    if (!Object.hasOwn(raw, key)) throw invalid('missing wrapper field', { field: key });
  }
}

function validateWrapperAtDepth(raw, depth) {
  assertStrictShape(raw);

  if (raw.format !== VAULT_WRAPPER_FORMAT) throw invalid('wrong wrapper format', { field: 'format' });
  if (!isSafeInt(raw.version)) throw invalid('wrapper version must be an integer', { field: 'version' });
  if (raw.version !== VAULT_WRAPPER_VERSION) {
    // A well-formed FUTURE version is "unsupported" (a newer build may read
    // it); anything else is plain invalid.
    if (raw.version > VAULT_WRAPPER_VERSION) {
      throw new VaultCryptoError(Codes.WRAPPER_UNSUPPORTED, 'wrapper version not supported by this build', { field: 'version' });
    }
    throw invalid('wrapper version must be exactly 1', { field: 'version' });
  }

  // Canonical Base64, exactly one accepted encoding per salt value (§7.1).
  const salt = typeof raw.saltB64 === 'string' && !/\s/.test(raw.saltB64)
    ? decodeCanonicalBase64(raw.saltB64)
    : null;
  if (salt === null) {
    throw new VaultCryptoError(Codes.KDF_PARAMS_INVALID, 'salt is not canonical base64', { field: 'saltB64' });
  }

  // THE single KDF policy validator (kdf-bounds.js): algorithm, version,
  // floor, maxima, profile allowlist and exact profile combination.
  try {
    validateKdfParams({
      kdf: raw.kdf,
      kdfVersion: raw.kdfVersion,
      mKib: raw.mKib,
      t: raw.t,
      p: raw.p,
      salt,
      outLen: raw.outLen,
      profile: raw.profile,
    });
  } catch (e) {
    if (e instanceof KdfBoundsError) {
      throw new VaultCryptoError(Codes.KDF_PARAMS_INVALID, 'kdf parameters rejected by policy', { reason: e.message.slice(0, 64) });
    }
    throw e;
  } finally {
    salt.fill(0);
  }

  if (raw.wrapAlg !== WRAP_ALG) {
    throw new VaultCryptoError(Codes.WRAPPER_UNSUPPORTED, 'unsupported wrap algorithm', { field: 'wrapAlg' });
  }
  if (!(raw.wrapNonce instanceof Uint8Array) || raw.wrapNonce.length !== WRAP_NONCE_BYTES) {
    throw invalid('wrap nonce must be a Uint8Array of 12 bytes', { field: 'wrapNonce' });
  }
  if (!(raw.wrappedRootKey instanceof Uint8Array) || raw.wrappedRootKey.length !== WRAPPED_ROOT_KEY_BYTES) {
    throw invalid('wrapped root key must be a Uint8Array of 48 bytes', { field: 'wrappedRootKey' });
  }

  if (!isSafeInt(raw.keyVersion) || raw.keyVersion < 1) {
    throw invalid('key version must be a safe integer >= 1', { field: 'keyVersion' });
  }
  if (raw.keyVersion !== 1) {
    throw new VaultCryptoError(Codes.KEY_VERSION_UNSUPPORTED, 'wrapper key version not supported', { field: 'keyVersion' });
  }

  if (typeof raw.createdAt !== 'string' || !isRealCalendarDate(raw.createdAt)) {
    throw invalid('createdAt must be a real YYYY-MM-DD date', { field: 'createdAt' });
  }
  if (!isSafeInt(raw.calibratedMs) || raw.calibratedMs < 0 || raw.calibratedMs > MAX_CALIBRATED_MS) {
    throw invalid('calibratedMs out of bounds', { field: 'calibratedMs' });
  }

  if (raw.rewrapPending !== null) {
    if (depth >= MAX_REWRAP_PENDING_DEPTH) {
      throw invalid('rewrapPending exceeds the maximum depth of 1', { field: 'rewrapPending' });
    }
    validateWrapperAtDepth(raw.rewrapPending, depth + 1);
  }
}

/**
 * Fail-closed validation of an untrusted wrapper object (spec §7.1, full
 * table; `rewrapPending` capped at depth 1). Throws; returns nothing.
 * @throws {VaultCryptoError}
 */
export function validateVaultWrapper(raw) {
  validateWrapperAtDepth(raw, 0);
}

function copyWrapper(wrapper) {
  return Object.freeze({
    format: wrapper.format,
    version: wrapper.version,
    kdf: wrapper.kdf,
    kdfVersion: wrapper.kdfVersion,
    mKib: wrapper.mKib,
    t: wrapper.t,
    p: wrapper.p,
    profile: wrapper.profile,
    saltB64: wrapper.saltB64,
    outLen: wrapper.outLen,
    wrapAlg: wrapper.wrapAlg,
    wrapNonce: wrapper.wrapNonce.slice(),
    wrappedRootKey: wrapper.wrappedRootKey.slice(),
    keyVersion: wrapper.keyVersion,
    createdAt: wrapper.createdAt,
    calibratedMs: wrapper.calibratedMs,
    rewrapPending: wrapper.rewrapPending === null ? null : copyWrapper(wrapper.rewrapPending),
  });
}

/**
 * Validate an untrusted wrapper and return an independent, frozen copy
 * (buffers included): later mutation of the input cannot affect the result.
 * @returns {object} @throws {VaultCryptoError}
 */
export function parseVaultWrapper(raw) {
  validateVaultWrapper(raw);
  return copyWrapper(raw);
}

/**
 * Validate a wrapper built in memory and return the plain object shape ready
 * for persistence (a later PR stores it via structured clone). Same strict
 * validation as parse: this module never emits what it would not accept.
 * @returns {object} @throws {VaultCryptoError}
 */
export function encodeVaultWrapper(wrapper) {
  validateVaultWrapper(wrapper);
  return copyWrapper(wrapper);
}

/**
 * Canonical unwrap AAD of a VALIDATED wrapper (delegates to vault-aad.js).
 * @returns {Uint8Array}
 */
export function buildWrapperAad(wrapper) {
  validateVaultWrapper(wrapper);
  return buildWrapperAadBytes(wrapper);
}

async function importKek(kek) {
  if (kek instanceof CryptoKey) {
    if (kek.algorithm?.name !== 'AES-GCM') {
      throw new VaultCryptoError(Codes.CRYPTO_FAILED, 'KEK CryptoKey must be AES-GCM');
    }
    return kek;
  }
  if (!(kek instanceof Uint8Array) || kek.length !== KEK_BYTES) {
    throw new VaultCryptoError(Codes.CRYPTO_FAILED, 'KEK must be a 32-byte Uint8Array or an AES-GCM CryptoKey');
  }
  // Non-extractable, single purpose; importKey copies, the caller keeps
  // ownership (and best-effort zeroization duty) of its own buffer.
  return subtle.importKey('raw', kek, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

/**
 * Wrap a SYNTHETIC 32-byte Root Key under an already-derived KEK and return a
 * complete, validated wrapper v1 object. PR-2 scope guard: no real Root
 * Storage Key exists yet — callers are tests and fixtures only.
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
  if (!(rootKey instanceof Uint8Array) || rootKey.length !== ROOT_KEY_BYTES) {
    throw new VaultCryptoError(Codes.CRYPTO_FAILED, 'root key must be a Uint8Array of 32 bytes');
  }
  if (!(salt instanceof Uint8Array) || salt.length !== KDF_POLICY.saltLen) {
    throw new VaultCryptoError(Codes.KDF_PARAMS_INVALID, 'salt must be a Uint8Array of 16 bytes', { field: 'salt' });
  }
  const key = await importKek(kek);
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
    wrapNonce: crypto.getRandomValues(new Uint8Array(WRAP_NONCE_BYTES)),
    wrappedRootKey: new Uint8Array(WRAPPED_ROOT_KEY_BYTES), // placeholder, replaced below
    keyVersion: 1,
    createdAt,
    calibratedMs,
  };
  // Validate BEFORE any crypto: bad KDF metadata or dates never reach AES-GCM.
  validateVaultWrapper({ ...draft, rewrapPending: null });
  const aad = buildWrapperAadBytes(draft);
  let wrapped;
  try {
    wrapped = new Uint8Array(await subtle.encrypt(
      { name: 'AES-GCM', iv: draft.wrapNonce, additionalData: aad, tagLength: 128 },
      key,
      rootKey,
    ));
  } catch {
    throw new VaultCryptoError(Codes.CRYPTO_FAILED, 'root key wrap failed');
  }
  if (wrapped.length !== WRAPPED_ROOT_KEY_BYTES) {
    throw new VaultCryptoError(Codes.CRYPTO_FAILED, 'unexpected wrapped root key length');
  }
  return encodeVaultWrapper({ ...draft, wrappedRootKey: wrapped, rewrapPending: null });
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
  validateVaultWrapper(wrapper);
  const key = await importKek(kek);
  const aad = buildWrapperAadBytes(wrapper);
  let plain;
  try {
    plain = new Uint8Array(await subtle.decrypt(
      { name: 'AES-GCM', iv: wrapper.wrapNonce, additionalData: aad, tagLength: 128 },
      key,
      wrapper.wrappedRootKey,
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
