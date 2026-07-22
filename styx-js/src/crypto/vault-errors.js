// vault-errors.js — the single structured error type for the vault crypto
// formats (Blocco 3, PR-2; vault spec §6/§7). Pure module, zero dependencies.
//
// Messages and `details` NEVER contain: password, KEK, Root Key, full salt,
// full nonce, plaintext, ciphertext, record keys, or wrapper contents. To make
// that enforceable rather than aspirational, `details` is a CLOSED shape: only
// the allowlisted keys below are accepted, and their values must be short
// primitives (field names, machine-readable reasons — never data).

export const VaultCryptoErrorCodes = Object.freeze({
  WRAPPER_INVALID: 'VAULT_WRAPPER_INVALID',
  WRAPPER_UNSUPPORTED: 'VAULT_WRAPPER_UNSUPPORTED',
  KDF_PARAMS_INVALID: 'VAULT_KDF_PARAMS_INVALID',
  WRONG_PASSWORD: 'VAULT_WRONG_PASSWORD',
  RECORD_INVALID: 'VAULT_RECORD_INVALID',
  RECORD_CORRUPTED: 'VAULT_RECORD_CORRUPTED',
  KEY_VERSION_UNSUPPORTED: 'VAULT_KEY_VERSION_UNSUPPORTED',
  NAMESPACE_UNSUPPORTED: 'VAULT_NAMESPACE_UNSUPPORTED',
  CRYPTO_FAILED: 'VAULT_CRYPTO_FAILED',
  // Storage-engine codes (Blocco 3, PR-4 / US-005). Same discipline: the
  // closed set is the contract, details stay within the allowlist below.
  BLOCKED: 'VAULT_BLOCKED',
  QUOTA_EXCEEDED: 'VAULT_QUOTA_EXCEEDED',
  OPEN_FAILED: 'VAULT_OPEN_FAILED',
  TX_ABORTED: 'VAULT_TX_ABORTED',
  SCHEMA_GAP: 'VAULT_SCHEMA_GAP',
  DESTROY_FAILED: 'VAULT_DESTROY_FAILED',
  // Lifecycle state-machine code (Blocco 3, PR-5 / US-006). Already reserved
  // in plan B3.0.3; a forbidden state transition raises it.
  WRONG_STATE: 'VAULT_WRONG_STATE',
});

const KNOWN_CODES = new Set(Object.values(VaultCryptoErrorCodes));

/**
 * Closed allowlist for `details`. Every value must be a string of at most 64
 * characters or a safe integer — enough to say WHICH field or namespace failed
 * and WHY (a short slug), structurally too small to smuggle key material,
 * payloads or identifiers-with-content through an error path.
 */
const DETAIL_KEYS = Object.freeze(['field', 'reason', 'namespace', 'version']);
const MAX_DETAIL_VALUE_LENGTH = 64;

function assertDetailsAllowed(details) {
  if (details === undefined) return undefined;
  if (details === null || typeof details !== 'object' || Array.isArray(details)) {
    throw new TypeError('VaultCryptoError details must be a plain object');
  }
  const out = {};
  for (const key of Object.keys(details)) {
    if (!DETAIL_KEYS.includes(key)) {
      throw new TypeError(`VaultCryptoError details key not allowlisted: ${key}`);
    }
    const value = details[key];
    const ok = (typeof value === 'string' && value.length <= MAX_DETAIL_VALUE_LENGTH)
      || (typeof value === 'number' && Number.isSafeInteger(value));
    if (!ok) throw new TypeError(`VaultCryptoError details value for "${key}" is not a short primitive`);
    out[key] = value;
  }
  return Object.freeze(out);
}

/**
 * Structured, stable-coded error (same discipline as MlsStateError /
 * KdfBoundsError). `message` must be a static description; anything variable
 * belongs in the allowlisted `details`.
 */
export class VaultCryptoError extends Error {
  constructor(code, message, details = undefined) {
    if (!KNOWN_CODES.has(code)) throw new TypeError(`unknown VaultCryptoError code: ${code}`);
    super(`${code}: ${message}`);
    this.name = 'VaultCryptoError';
    this.code = code;
    this.details = assertDetailsAllowed(details);
  }
}
