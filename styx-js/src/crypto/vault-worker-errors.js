// vault-worker-errors.js — stable error codes of the vault worker boundary
// (Blocco 3, PR-3; plan B3.0.3). Pure module.
//
// The closed v1 set. `WORKER_TIMEOUT` is the page-side verdict for a worker
// that stopped answering: the operation may have side effects in flight, so a
// timeout is never "ignore the late reply" — it makes the worker untrusted
// (terminate + respawn, see vault-worker-client.js).
//
// `details` is CLOSED: only the allowlisted keys below, short primitive
// values. Never payloads, passwords, URLs, stacks, cause messages, buffers,
// keys, KDF output or serialized state.

import { snapshotStrictPlainObject } from './vault-shape.js';

export const VaultWorkerErrorCodes = Object.freeze({
  BAD_REQUEST: 'BAD_REQUEST',
  WRONG_STATE: 'VAULT_WRONG_STATE',
  TERMINATED: 'WORKER_TERMINATED',
  CRASHED: 'WORKER_CRASHED',
  TIMEOUT: 'WORKER_TIMEOUT',
});

const KNOWN_CODES = new Set(Object.values(VaultWorkerErrorCodes));

const DETAIL_KEYS = Object.freeze(['type', 'phase', 'reason', 'attempt']);
const MAX_DETAIL_VALUE_LENGTH = 64;

/**
 * Validate and freeze a details object against the closed allowlist.
 * Exported for the protocol layer, which must sanitize error objects that
 * cross the postMessage boundary in BOTH directions.
 *
 * Same descriptor discipline as every other untrusted shape (review W6):
 * Reflect.ownKeys through the shared strict-shape helper with all keys
 * OPTIONAL — Symbols, non-enumerable extras, custom prototypes and accessors
 * are rejected without ever being invoked, and values are read exclusively
 * from the descriptor snapshot, never via details[key].
 * @throws {TypeError} on any non-allowlisted key, hostile shape or oversized value
 */
export function sanitizeWorkerErrorDetails(details) {
  if (details === undefined) return undefined;
  const invalid = (message, d) => new TypeError(
    `VaultWorkerError details: ${message}${d?.field !== undefined ? ` ("${String(d.field).slice(0, 64)}")` : ''}`,
  );
  const snapshot = snapshotStrictPlainObject(details, DETAIL_KEYS, invalid, { requiredKeys: [] });
  const out = {};
  for (const key of DETAIL_KEYS) {
    if (!Object.hasOwn(snapshot, key)) continue;
    const value = snapshot[key];
    const ok = (typeof value === 'string' && value.length <= MAX_DETAIL_VALUE_LENGTH)
      || (typeof value === 'number' && Number.isSafeInteger(value));
    if (!ok) throw new TypeError(`VaultWorkerError details value for "${key}" is not a short primitive`);
    out[key] = value;
  }
  return Object.freeze(out);
}

/**
 * Structured, stable-coded error for the worker boundary (same discipline as
 * VaultCryptoError). `message` must be static; anything variable goes in the
 * allowlisted `details`.
 */
export class VaultWorkerError extends Error {
  constructor(code, message, details = undefined) {
    if (!KNOWN_CODES.has(code)) throw new TypeError(`unknown VaultWorkerError code: ${code}`);
    super(`${code}: ${message}`);
    this.name = 'VaultWorkerError';
    this.code = code;
    this.details = sanitizeWorkerErrorDetails(details);
  }
}

/**
 * Fail-closed conversion of ANY thrown value into a wire-safe error object
 * `{code, details}`: a recognized VaultWorkerError keeps its code and
 * sanitized details; everything else — native exceptions, hostile objects,
 * throwing getters — becomes a bare WORKER_CRASHED with no message content
 * copied (an unrecognized exception must never leak payload through the
 * boundary).
 */
export function toWireError(err) {
  if (err instanceof VaultWorkerError && KNOWN_CODES.has(err.code)) {
    // Re-sanitize on the way out (review W6): the constructor already
    // validated, but a mutated `details`/`code` on a recognized instance must
    // not reach the wire either — fall through to the bare crash instead.
    try {
      return { code: err.code, details: sanitizeWorkerErrorDetails(err.details) ?? Object.freeze({}) };
    } catch { /* hostile or corrupted details: treat as unrecognized */ }
  }
  return { code: VaultWorkerErrorCodes.CRASHED, details: Object.freeze({ reason: 'unhandled-exception' }) };
}
