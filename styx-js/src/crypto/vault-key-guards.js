// vault-key-guards.js — exact WebCrypto key contracts for the vault (Blocco
// 3, PR-2; review F7). Pure module.
//
// `algorithm.name` alone is not a contract: an AES-GCM-128, an extractable
// key, or a single-usage key would silently violate what the persisted
// formats promise. Every CryptoKey that reaches a vault crypto operation must
// satisfy the EXACT profile below — anything else fails typed BEFORE any
// WebCrypto call, and the error never describes the key.

import { VaultCryptoError, VaultCryptoErrorCodes as Codes } from './vault-errors.js';

/** Usages must match EXACTLY (order-independent, no extras, no misses). */
function sameUsageSet(key, expected) {
  const usages = Array.from(key.usages ?? []);
  return usages.length === expected.length && expected.every((u) => usages.includes(u));
}

/**
 * KEK and namespace keys: secret AES-GCM, 256 bits, non-extractable, usages
 * exactly encrypt+decrypt.
 * @throws {VaultCryptoError} VAULT_CRYPTO_FAILED
 */
export function assertAes256GcmCryptoKey(key) {
  const ok = key instanceof CryptoKey
    && key.type === 'secret'
    && key.algorithm?.name === 'AES-GCM'
    && key.algorithm?.length === 256
    && key.extractable === false
    && sameUsageSet(key, ['encrypt', 'decrypt']);
  if (!ok) {
    throw new VaultCryptoError(Codes.CRYPTO_FAILED, 'key does not satisfy the AES-256-GCM vault contract');
  }
  return key;
}

/**
 * Manifest key: secret HMAC over SHA-256, 256-bit key, non-extractable,
 * usages exactly sign+verify.
 * @throws {VaultCryptoError} VAULT_CRYPTO_FAILED
 */
export function assertHmacSha256CryptoKey(key) {
  const ok = key instanceof CryptoKey
    && key.type === 'secret'
    && key.algorithm?.name === 'HMAC'
    && key.algorithm?.hash?.name === 'SHA-256'
    && key.algorithm?.length === 256
    && key.extractable === false
    && sameUsageSet(key, ['sign', 'verify']);
  if (!ok) {
    throw new VaultCryptoError(Codes.CRYPTO_FAILED, 'key does not satisfy the HMAC-SHA-256 vault contract');
  }
  return key;
}
