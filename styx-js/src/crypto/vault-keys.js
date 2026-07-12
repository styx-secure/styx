// vault-keys.js — HKDF-SHA-256 key hierarchy of the vault (Blocco 3, PR-2;
// vault spec §5, amended with `settings`/`canary`). Pure WebCrypto module: no
// storage, no worker, no KDF — it receives an already-available Root Storage
// Key (in PR-2 always SYNTHETIC test material) and derives per-namespace
// subkeys with strict domain separation.
//
// Every derived key is a non-extractable CryptoKey: the subkey bytes never
// exist in JS. Zeroization caveat (spec §4): JavaScript cannot guarantee
// physical erasure of the caller's Root Key buffer; that remains best-effort
// and is the caller's responsibility.

import { VaultCryptoError, VaultCryptoErrorCodes as Codes } from './vault-errors.js';
import { assertHmacSha256CryptoKey } from './vault-key-guards.js';

/** Closed v1 namespace allowlist (spec §5/§8 as amended: settings, canary). */
export const VAULT_NAMESPACES = Object.freeze([
  'identity', 'contacts', 'messages', 'mls', 'outbox', 'push', 'settings', 'canary',
]);

/**
 * Exact HKDF info strings — the domain-separation contract (spec §5).
 * `manifest` and `backup` are NOT payload namespaces: manifest derives an
 * HMAC key (integrity, §11), backup is reserved for future export and has no
 * API yet. `meta` and `migrations` deliberately have NO entry: they never
 * hold user payloads, so they get no AES subkey.
 */
export const VAULT_HKDF_INFO = Object.freeze({
  identity: 'styx/vault/identity/v1',
  contacts: 'styx/vault/contacts/v1',
  messages: 'styx/vault/messages/v1',
  mls: 'styx/vault/mls/v1',
  outbox: 'styx/vault/outbox/v1',
  push: 'styx/vault/push/v1',
  settings: 'styx/vault/settings/v1',
  canary: 'styx/vault/canary/v1',
  manifest: 'styx/vault/manifest/v1',
  backup: 'styx/vault/backup/v1',
});

/** Public constant label; the HKDF salt is SHA-256 of its UTF-8 bytes (spec §5). */
export const VAULT_HKDF_SALT_LABEL = 'styx-vault-v1';

/** Only supported key version in v1; anything else fails closed. */
export const VAULT_KEY_VERSION = 1;

export const ROOT_KEY_BYTES = 32;
export const MANIFEST_MAC_BYTES = 32;

const UTF8 = new TextEncoder();
const subtle = globalThis.crypto?.subtle;

let saltPromise = null;
function hkdfSalt() {
  if (saltPromise === null) saltPromise = subtle.digest('SHA-256', UTF8.encode(VAULT_HKDF_SALT_LABEL));
  return saltPromise;
}

function assertKeyVersion(keyVersion) {
  if (typeof keyVersion !== 'number' || !Number.isSafeInteger(keyVersion) || keyVersion < 1) {
    throw new VaultCryptoError(Codes.KEY_VERSION_UNSUPPORTED, 'key version must be a safe integer >= 1');
  }
  if (keyVersion !== VAULT_KEY_VERSION) {
    throw new VaultCryptoError(Codes.KEY_VERSION_UNSUPPORTED, 'unsupported key version', { reason: 'only-v1' });
  }
}

async function importRootKey(rootKey) {
  if (!(rootKey instanceof Uint8Array) || rootKey.length !== ROOT_KEY_BYTES) {
    throw new VaultCryptoError(Codes.CRYPTO_FAILED, 'root key must be a Uint8Array of 32 bytes');
  }
  // importKey copies the bytes; the caller keeps ownership (and zeroization
  // duty) of its own buffer.
  return subtle.importKey('raw', rootKey, 'HKDF', false, ['deriveKey']);
}

/**
 * Derive the AES-256-GCM subkey of a payload namespace.
 * @param {Uint8Array} rootKey 32-byte Root Storage Key (synthetic in PR-2)
 * @param {string} namespace one of VAULT_NAMESPACES
 * @param {number} keyVersion must be VAULT_KEY_VERSION (1)
 * @returns {Promise<CryptoKey>} non-extractable, usages encrypt/decrypt
 * @throws {VaultCryptoError} VAULT_NAMESPACE_UNSUPPORTED | VAULT_KEY_VERSION_UNSUPPORTED | VAULT_CRYPTO_FAILED
 */
export async function deriveNamespaceKey(rootKey, namespace, keyVersion) {
  // Object.hasOwn + explicit allowlist: '__proto__', 'constructor', 'manifest'
  // and 'backup' must all fail here (manifest/backup are not payload namespaces).
  if (typeof namespace !== 'string' || !VAULT_NAMESPACES.includes(namespace)
    || !Object.hasOwn(VAULT_HKDF_INFO, namespace)) {
    throw new VaultCryptoError(Codes.NAMESPACE_UNSUPPORTED, 'unknown vault namespace');
  }
  assertKeyVersion(keyVersion);
  const ikm = await importRootKey(rootKey);
  return subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: await hkdfSalt(), info: UTF8.encode(VAULT_HKDF_INFO[namespace]) },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/**
 * Derive the HMAC-SHA-256 manifest key (spec §11).
 * @returns {Promise<CryptoKey>} non-extractable, usages sign/verify
 */
export async function deriveManifestKey(rootKey, keyVersion) {
  assertKeyVersion(keyVersion);
  const ikm = await importRootKey(rootKey);
  return subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: await hkdfSalt(), info: UTF8.encode(VAULT_HKDF_INFO.manifest) },
    ikm,
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    false,
    ['sign', 'verify'],
  );
}

// Exact contract (review F7): secret HMAC-SHA-256, 256-bit, non-extractable,
// usages exactly sign+verify — see vault-key-guards.js.
const assertManifestKey = assertHmacSha256CryptoKey;

/**
 * HMAC-SHA-256 over already-canonicalized manifest bytes. The persisted
 * manifest format itself is NOT defined in PR-2 — only the pure primitive.
 * @returns {Promise<Uint8Array>} 32-byte MAC
 */
export async function signManifestBytes(key, canonicalBytes) {
  assertManifestKey(key);
  if (!(canonicalBytes instanceof Uint8Array)) {
    throw new VaultCryptoError(Codes.CRYPTO_FAILED, 'manifest bytes must be a Uint8Array');
  }
  const mac = new Uint8Array(await subtle.sign('HMAC', key, canonicalBytes));
  if (mac.length !== MANIFEST_MAC_BYTES) {
    // Review F7: the persisted MAC contract is exactly 32 bytes.
    throw new VaultCryptoError(Codes.CRYPTO_FAILED, 'unexpected manifest MAC length');
  }
  return mac;
}

/**
 * Constant-time verification via WebCrypto (never a manual `===` compare).
 * @returns {Promise<true>} on success
 * @throws {VaultCryptoError} generic VAULT_CRYPTO_FAILED on ANY failure —
 *   wrong MAC, wrong length, tampered bytes are indistinguishable by design.
 */
export async function verifyManifestBytes(key, canonicalBytes, mac) {
  assertManifestKey(key);
  const shapeOk = canonicalBytes instanceof Uint8Array
    && mac instanceof Uint8Array && mac.length === MANIFEST_MAC_BYTES;
  const ok = shapeOk && await subtle.verify('HMAC', key, mac, canonicalBytes);
  if (ok !== true) {
    throw new VaultCryptoError(Codes.CRYPTO_FAILED, 'manifest verification failed');
  }
  return true;
}
