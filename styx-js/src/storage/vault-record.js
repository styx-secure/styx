// vault-record.js — strict codec for encrypted vault records v1 (Blocco 3,
// PR-2; vault spec §6). Pure module: no IndexedDB, no localStorage, no
// worker — it encrypts/decrypts single records under an already-derived
// per-namespace AES-256-GCM CryptoKey (see vault-keys.js). In PR-2 every key
// and payload is SYNTHETIC test material.
//
// Binding read-side rule (spec §6, vincolante): on decrypt, `ns` and `k` in
// the AAD come from the caller's REQUEST, never from the record's
// self-declared fields — a valid record copied onto another key or namespace
// must fail authentication, not be "corrected".

import { VaultCryptoError, VaultCryptoErrorCodes as Codes } from '../crypto/vault-errors.js';
import { buildRecordAadBytes } from '../crypto/vault-aad.js';
import { VAULT_NAMESPACES, VAULT_KEY_VERSION } from '../crypto/vault-keys.js';
import { snapshotStrictPlainObject } from '../crypto/vault-shape.js';
import { assertAes256GcmCryptoKey } from '../crypto/vault-key-guards.js';

export const VAULT_RECORD_VERSION = 1;
export const RECORD_NONCE_BYTES = 12;
/** GCM tag: the smallest possible ciphertext (empty plaintext) is 16 bytes. */
export const MIN_DATA_BYTES = 16;
/** Same decoded-payload cap as the MLS envelope (hostile-JSON territory above). */
export const MAX_PLAINTEXT_BYTES = 16 * 1024 * 1024;
export const MAX_RECORD_KEY_CHARS = 256;
export const CONTENT_TYPES = Object.freeze(['json', 'bytes']);

const RECORD_KEYS = Object.freeze(['v', 'ns', 'k', 'rv', 'kv', 'ct', 'nonce', 'data']);
const NAMESPACE_SET = new Set(VAULT_NAMESPACES);
const UTF8 = new TextEncoder();
// fatal: authenticated-but-undecodable payload must fail loudly, not yield U+FFFD.
const UTF8_DECODER = new TextDecoder('utf-8', { fatal: true });
const subtle = globalThis.crypto?.subtle;

const isSafeInt = (x) => typeof x === 'number' && Number.isSafeInteger(x);

function invalid(message, details) {
  return new VaultCryptoError(Codes.RECORD_INVALID, message, details);
}

const CONTROL_CHARS_RE = /[\u0000-\u001F\u007F]/;

function assertRecordKeyString(k) {
  const ok = typeof k === 'string'
    && k.length >= 1 && k.length <= MAX_RECORD_KEY_CHARS
    && k.isWellFormed()
    && !CONTROL_CHARS_RE.test(k);
  if (!ok) throw invalid('record key must be a bounded well-formed string', { field: 'k' });
}

function assertNamespace(ns) {
  if (typeof ns !== 'string' || !NAMESPACE_SET.has(ns)) {
    throw new VaultCryptoError(Codes.NAMESPACE_UNSUPPORTED, 'unknown vault namespace', { field: 'ns' });
  }
}

/**
 * Fail-closed validation of an untrusted record object (spec §6 shape).
 * Throws; returns nothing.
 * @throws {VaultCryptoError}
 */
export function validateVaultRecord(raw) {
  parseRecordSnapshot(raw);
}

/**
 * Strict descriptor snapshot (review F6: Reflect.ownKeys, enumerable data
 * properties only, accessors rejected without invocation) + full field
 * validation. Returns the snapshot; with `copyBuffers` the byte fields are
 * independent copies so later mutation of the input cannot affect callers
 * (review F2, TOCTOU).
 */
function parseRecordSnapshot(raw, { copyBuffers = false } = {}) {
  const s = snapshotStrictPlainObject(raw, RECORD_KEYS, invalid);

  if (!isSafeInt(s.v) || s.v !== VAULT_RECORD_VERSION) {
    // No separate "unsupported" code exists for records in the closed v1
    // error list: any non-v1 record (including future versions) fails closed.
    throw invalid('record format version must be exactly 1', { field: 'v' });
  }
  assertNamespace(s.ns);
  assertRecordKeyString(s.k);
  if (!isSafeInt(s.rv) || s.rv < 1) {
    throw invalid('record version must be a safe integer >= 1', { field: 'rv' });
  }
  if (!isSafeInt(s.kv) || s.kv < 1) {
    throw invalid('key version must be a safe integer >= 1', { field: 'kv' });
  }
  if (s.kv !== VAULT_KEY_VERSION) {
    throw new VaultCryptoError(Codes.KEY_VERSION_UNSUPPORTED, 'record key version not supported', { field: 'kv' });
  }
  if (!CONTENT_TYPES.includes(s.ct)) {
    throw invalid('content type must be json or bytes', { field: 'ct' });
  }
  if (!(s.nonce instanceof Uint8Array) || s.nonce.length !== RECORD_NONCE_BYTES) {
    throw invalid('nonce must be a Uint8Array of 12 bytes', { field: 'nonce' });
  }
  const maxData = MAX_PLAINTEXT_BYTES + MIN_DATA_BYTES;
  if (!(s.data instanceof Uint8Array) || s.data.length < MIN_DATA_BYTES || s.data.length > maxData) {
    throw invalid('ciphertext length out of bounds', { field: 'data' });
  }
  if (copyBuffers) {
    s.nonce = s.nonce.slice();
    s.data = s.data.slice();
  }
  return s;
}

/**
 * Canonical record AAD (delegates to vault-aad.js). Exposed for fixture
 * generation and cross-implementation tests; production callers never need it
 * directly.
 * @returns {Uint8Array}
 */
export function buildRecordAad({ v, ns, k, rv, kv, ct }) {
  return buildRecordAadBytes({ v, ns, k, rv, kv, ct });
}

// Exact contract (review F7): secret AES-GCM-256, non-extractable, usages
// exactly encrypt+decrypt — see vault-key-guards.js.
const assertNamespaceKey = assertAes256GcmCryptoKey;

function serializePlaintext(contentType, plaintext) {
  if (contentType === 'bytes') {
    if (!(plaintext instanceof Uint8Array)) {
      throw invalid('bytes plaintext must be a Uint8Array', { field: 'plaintext' });
    }
    if (plaintext.length > MAX_PLAINTEXT_BYTES) {
      throw invalid('plaintext exceeds the 16 MiB cap', { field: 'plaintext' });
    }
    return plaintext.slice(); // never encrypt (or later zeroize) the caller's buffer
  }
  // 'json'
  let text;
  try {
    text = JSON.stringify(plaintext);
  } catch {
    throw invalid('json plaintext is not serializable', { field: 'plaintext' });
  }
  if (typeof text !== 'string') {
    // JSON.stringify(undefined) and functions yield undefined, not a throw.
    throw invalid('json plaintext is not serializable', { field: 'plaintext' });
  }
  const bytes = UTF8.encode(text);
  if (bytes.length > MAX_PLAINTEXT_BYTES) {
    throw invalid('plaintext exceeds the 16 MiB cap', { field: 'plaintext' });
  }
  return bytes;
}

/**
 * Encrypt one record under a per-namespace key. The 12-byte nonce is
 * generated INTERNALLY with `crypto.getRandomValues` at EVERY call (spec §6);
 * there is deliberately no way for a caller to choose it — deterministic
 * vectors are produced by the separate fixture generator, never through this
 * API.
 *
 * @param {object} input
 * @param {string} input.namespace one of VAULT_NAMESPACES
 * @param {string} input.recordKey bounded well-formed string (store key)
 * @param {*} input.plaintext JSON-serializable value (ct 'json') or Uint8Array (ct 'bytes')
 * @param {'json'|'bytes'} input.contentType
 * @param {number} [input.recordVersion=1] monotonic per key (anti-swap, in AAD)
 * @param {number} [input.keyVersion=1]
 * @param {CryptoKey} namespaceKey from deriveNamespaceKey (AES-GCM)
 * @returns {Promise<object>} frozen record v1 object
 * @throws {VaultCryptoError}
 */
export async function encryptVaultRecord(
  {
    namespace, recordKey, plaintext, contentType, recordVersion = 1, keyVersion = VAULT_KEY_VERSION,
  },
  namespaceKey,
) {
  assertNamespace(namespace);
  assertRecordKeyString(recordKey);
  if (!CONTENT_TYPES.includes(contentType)) {
    throw invalid('content type must be json or bytes', { field: 'ct' });
  }
  if (!isSafeInt(recordVersion) || recordVersion < 1) {
    throw invalid('record version must be a safe integer >= 1', { field: 'rv' });
  }
  if (keyVersion !== VAULT_KEY_VERSION) {
    throw new VaultCryptoError(Codes.KEY_VERSION_UNSUPPORTED, 'record key version not supported', { field: 'kv' });
  }
  assertNamespaceKey(namespaceKey);

  const plainBytes = serializePlaintext(contentType, plaintext);
  const nonce = crypto.getRandomValues(new Uint8Array(RECORD_NONCE_BYTES));
  const aad = buildRecordAadBytes({
    v: VAULT_RECORD_VERSION, ns: namespace, k: recordKey, rv: recordVersion, kv: keyVersion, ct: contentType,
  });
  let data;
  try {
    data = new Uint8Array(await subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 },
      namespaceKey,
      plainBytes,
    ));
  } catch {
    throw new VaultCryptoError(Codes.CRYPTO_FAILED, 'record encryption failed');
  } finally {
    plainBytes.fill(0); // best-effort zeroization of the internal copy
  }
  const record = Object.freeze({
    v: VAULT_RECORD_VERSION,
    ns: namespace,
    k: recordKey,
    rv: recordVersion,
    kv: keyVersion,
    ct: contentType,
    nonce,
    data,
  });
  validateVaultRecord(record); // never emit what decrypt would not accept
  return record;
}

/**
 * Validate and decrypt one record. The AAD is built with `ns`/`k` from the
 * REQUEST and `v`/`rv`/`kv`/`ct` from the record; additionally the record's
 * self-declared `ns`/`k` must EQUAL the requested ones — a mismatch fails
 * without any attempt to "repair" the record (spec §6).
 *
 * Error mapping: shape problems → VAULT_RECORD_INVALID; any GCM
 * authentication failure (bit flips, swapped AAD fields, wrong key) →
 * VAULT_RECORD_CORRUPTED.
 *
 * @param {object} record untrusted record v1 object
 * @param {object} request
 * @param {string} request.namespace the store being read
 * @param {string} request.recordKey the key being read
 * @param {CryptoKey} namespaceKey from deriveNamespaceKey (AES-GCM)
 * @returns {Promise<{value: *, contentType: string, recordVersion: number, keyVersion: number}>}
 *   `value` is the parsed JSON value (ct 'json') or a Uint8Array (ct 'bytes')
 * @throws {VaultCryptoError}
 */
export async function decryptVaultRecord(record, { namespace, recordKey }, namespaceKey) {
  assertNamespace(namespace);
  assertRecordKeyString(recordKey);
  assertNamespaceKey(namespaceKey);
  // Strict validated snapshot, taken synchronously BEFORE any await: the AAD
  // and decrypt below use only this copy (reviews F2/F6).
  const rec = parseRecordSnapshot(record, { copyBuffers: true });
  if (rec.ns !== namespace || rec.k !== recordKey) {
    throw invalid('record does not belong to the requested namespace and key');
  }

  const aad = buildRecordAadBytes({
    v: rec.v, ns: namespace, k: recordKey, rv: rec.rv, kv: rec.kv, ct: rec.ct,
  });
  let plainBytes;
  try {
    plainBytes = new Uint8Array(await subtle.decrypt(
      { name: 'AES-GCM', iv: rec.nonce, additionalData: aad, tagLength: 128 },
      namespaceKey,
      rec.data,
    ));
  } catch {
    throw new VaultCryptoError(Codes.RECORD_CORRUPTED, 'record authentication failed');
  }

  if (rec.ct === 'bytes') {
    return {
      value: plainBytes, contentType: rec.ct, recordVersion: rec.rv, keyVersion: rec.kv,
    };
  }
  let value;
  try {
    value = JSON.parse(UTF8_DECODER.decode(plainBytes));
  } catch {
    throw new VaultCryptoError(Codes.RECORD_CORRUPTED, 'authenticated payload is not decodable');
  } finally {
    plainBytes.fill(0); // best-effort: the JSON value survives, the raw buffer does not
  }
  return {
    value, contentType: rec.ct, recordVersion: rec.rv, keyVersion: rec.kv,
  };
}
