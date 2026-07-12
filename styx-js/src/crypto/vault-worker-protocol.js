// vault-worker-protocol.js — closed-world protocol v1 of the vault crypto
// worker boundary (Blocco 3, PR-3; vault spec §9). Pure module: validators
// and builders only, no Worker API, no I/O.
//
// Everything crossing postMessage — in BOTH directions — is untrusted:
// envelopes are snapshotted with the same descriptor-strict helper as the
// persisted formats (vault-shape.js, review F6 discipline), payloads are
// deep-validated against a closed value grammar with hard size bounds, and
// results are re-checked before they are ever handed to postMessage (no
// WebAssembly object, function, CryptoKey or handle can cross the boundary).

import { snapshotStrictPlainObject } from './vault-shape.js';
import {
  VaultWorkerError, VaultWorkerErrorCodes as Codes, sanitizeWorkerErrorDetails,
} from './vault-worker-errors.js';

export const VAULT_WORKER_PROTOCOL_VERSION = 1;

/**
 * The complete v1 message-type registry (vault spec §9). Adding a name is a
 * protocol change: it requires an explicit allowlist update plus review.
 */
export const MESSAGE_TYPES = Object.freeze([
  'INIT', 'CREATE_VAULT', 'UNLOCK', 'LOCK', 'GET', 'PUT', 'DELETE', 'LIST',
  'TRANSACTION', 'MIGRATE', 'STATUS', 'DESTROY', 'SHUTDOWN',
]);

/** Functionally active in PR-3; every other name is RESERVED and answers VAULT_WRONG_STATE. */
export const ACTIVE_TYPES = Object.freeze(['INIT', 'STATUS', 'SHUTDOWN']);

// --- wire limits (fail-closed; validated BEFORE any handler runs) -----------
export const MAX_WIRE_BYTES = 32 * 1024 * 1024; // whole-payload budget
export const MAX_WIRE_DEPTH = 16;
export const MAX_WIRE_NODES = 65536;
export const MAX_WIRE_ARRAY_LENGTH = 16384;
export const MAX_WIRE_STRING_CHARS = 1048576;

const REQUEST_KEYS = Object.freeze(['id', 'type', 'payload']);
const RESULT_KEYS = Object.freeze(['id', 'ok', 'result']);
const ERROR_KEYS = Object.freeze(['id', 'ok', 'error']);
const WIRE_ERROR_KEYS = Object.freeze(['code', 'details']);

const KNOWN_CODES = new Set(Object.values(Codes));

const badRequest = (message, details) => new VaultWorkerError(Codes.BAD_REQUEST, message, details);

/**
 * Adapt an error factory for snapshotStrictPlainObject: the shape helper
 * reports `{field}`, but the worker error allowlist only admits
 * type/phase/reason/attempt — fold the field name into `reason`.
 */
const asShapeFactory = (make) => (message, details) => make(
  message,
  { reason: (details?.field !== undefined ? `field:${details.field}` : 'shape').slice(0, 64) },
);

const isSafeInt = (x) => typeof x === 'number' && Number.isSafeInteger(x);

function isForbiddenExotic(value) {
  if (typeof WebAssembly !== 'undefined' && (
    value instanceof WebAssembly.Module
    || value instanceof WebAssembly.Instance
    || value instanceof WebAssembly.Memory
    || value instanceof WebAssembly.Table
  )) return 'wasm-object';
  if (typeof CryptoKey !== 'undefined' && value instanceof CryptoKey) return 'cryptokey';
  if (typeof SharedArrayBuffer !== 'undefined' && value instanceof SharedArrayBuffer) return 'shared-array-buffer';
  if (value instanceof Promise) return 'promise';
  return null;
}

function isSharedBacked(view) {
  return typeof SharedArrayBuffer !== 'undefined' && view.buffer instanceof SharedArrayBuffer;
}

/**
 * Deep validation of one wire value against the closed grammar: null,
 * booleans, finite numbers, bounded strings, strict plain objects (string
 * keys, enumerable data properties, no custom prototype, no Symbols),
 * bounded arrays, and — when `allowBinary` — Uint8Array/ArrayBuffer. Cycles,
 * functions, Promises, CryptoKeys, SharedArrayBuffers, every WebAssembly
 * object and anything carrying `__wbg_ptr` (wasm-bindgen handles) are
 * rejected. Enforces the byte budget, depth, node count and per-string /
 * per-array bounds. Returns the estimated byte cost.
 * @throws {VaultWorkerError} with the caller-supplied error factory's code
 */
export function validateWireValue(value, {
  allowBinary = true,
  maxBytes = MAX_WIRE_BYTES,
  error = badRequest,
} = {}) {
  const seen = new Set();
  let nodes = 0;
  let bytes = 0;

  const spend = (n) => {
    bytes += n;
    if (bytes > maxBytes) throw error('wire value exceeds the byte budget', { reason: 'over-byte-budget' });
  };

  const walk = (v, depth) => {
    if (depth > MAX_WIRE_DEPTH) throw error('wire value too deep', { reason: 'over-depth' });
    nodes += 1;
    if (nodes > MAX_WIRE_NODES) throw error('wire value has too many nodes', { reason: 'over-node-count' });

    if (v === null) { spend(4); return; }
    const t = typeof v;
    if (t === 'boolean') { spend(4); return; }
    if (t === 'number') {
      if (!Number.isFinite(v)) throw error('wire numbers must be finite', { reason: 'non-finite-number' });
      spend(8);
      return;
    }
    if (t === 'string') {
      if (v.length > MAX_WIRE_STRING_CHARS) throw error('wire string too long', { reason: 'over-string-length' });
      spend(v.length * 2);
      return;
    }
    if (t === 'function') throw error('functions cannot cross the worker boundary', { reason: 'function' });
    if (t === 'symbol' || t === 'bigint' || t === 'undefined') {
      throw error('unsupported primitive on the wire', { reason: `primitive-${t}` });
    }

    // objects
    const exotic = isForbiddenExotic(v);
    if (exotic) throw error('forbidden object on the wire', { reason: exotic });
    if (Object.hasOwn(v, '__wbg_ptr')) {
      throw error('wasm-bindgen handles cannot cross the worker boundary', { reason: 'wbg-handle' });
    }
    if (v instanceof Uint8Array) {
      if (!allowBinary) throw error('binary values are not allowed here', { reason: 'binary-not-allowed' });
      if (isSharedBacked(v)) throw error('shared memory cannot cross the worker boundary', { reason: 'shared-array-buffer' });
      spend(v.byteLength);
      return;
    }
    if (v instanceof ArrayBuffer) {
      if (!allowBinary) throw error('binary values are not allowed here', { reason: 'binary-not-allowed' });
      spend(v.byteLength);
      return;
    }
    if (ArrayBuffer.isView(v)) {
      // every other TypedArray / DataView: closed grammar, Uint8Array only
      throw error('only Uint8Array views are allowed on the wire', { reason: 'typed-array' });
    }
    if (seen.has(v)) throw error('cyclic wire values are rejected', { reason: 'cycle' });
    seen.add(v);

    if (Array.isArray(v)) {
      if (v.length > MAX_WIRE_ARRAY_LENGTH) throw error('wire array too long', { reason: 'over-array-length' });
      // reject sparse arrays and extra own props (e.g. named fields on arrays)
      if (Reflect.ownKeys(v).length !== v.length + 1) {
        throw error('arrays must be dense with no extra properties', { reason: 'exotic-array' });
      }
      spend(16);
      for (let i = 0; i < v.length; i += 1) walk(v[i], depth + 1);
      seen.delete(v);
      return;
    }

    const proto = Object.getPrototypeOf(v);
    if (proto !== Object.prototype && proto !== null) {
      throw error('wire objects must be plain', { reason: 'custom-prototype' });
    }
    spend(16);
    for (const key of Reflect.ownKeys(v)) {
      if (typeof key !== 'string') throw error('symbol keys are rejected on the wire', { reason: 'symbol-key' });
      if (key.length > 256) throw error('wire object key too long', { reason: 'over-key-length' });
      const desc = Object.getOwnPropertyDescriptor(v, key);
      if (desc === undefined || !Object.hasOwn(desc, 'value') || desc.enumerable !== true) {
        throw error('wire object fields must be enumerable data properties', { reason: 'accessor-or-hidden' });
      }
      spend(key.length * 2);
      walk(desc.value, depth + 1);
    }
    seen.delete(v);
  };

  walk(value, 0);
  return bytes;
}

/**
 * Defensive id extraction from a possibly hostile envelope, WITHOUT invoking
 * accessors: returns the id when it is an own enumerable data property with a
 * positive safe-integer value, otherwise 0 (the "unattributable" id used for
 * protocol-level error responses).
 */
export function extractEnvelopeId(raw) {
  if (raw === null || typeof raw !== 'object') return 0;
  const desc = Object.getOwnPropertyDescriptor(raw, 'id');
  if (!desc || !Object.hasOwn(desc, 'value') || desc.enumerable !== true) return 0;
  return isSafeInt(desc.value) && desc.value > 0 ? desc.value : 0;
}

/**
 * Worker-side validation of a request envelope: exactly {id, type, payload},
 * strict shape, id positive safe integer, type inside the closed registry,
 * payload within the wire grammar and size bounds. Returns the snapshot.
 * @throws {VaultWorkerError} BAD_REQUEST
 */
export function validateRequestEnvelope(raw) {
  const s = snapshotStrictPlainObject(raw, REQUEST_KEYS, asShapeFactory(badRequest));
  if (!isSafeInt(s.id) || s.id < 1) {
    throw badRequest('request id must be a positive safe integer', { reason: 'bad-id' });
  }
  if (typeof s.type !== 'string' || !MESSAGE_TYPES.includes(s.type)) {
    throw badRequest('unknown request type', { reason: 'unknown-type' });
  }
  validateWireValue(s.payload, {});
  return s;
}

/**
 * Client-side validation of a response envelope: exactly {id, ok, result} or
 * {id, ok, error} — never both; `ok` strictly boolean and coherent; the error
 * object exactly {code, details} with a KNOWN code and allowlisted details.
 * Any deviation is a PROTOCOL VIOLATION (the caller must treat the worker as
 * crashed, not just this response as failed).
 * @throws {VaultWorkerError} WORKER_CRASHED
 */
export function validateResponseEnvelope(raw) {
  const violation = (message, details) => new VaultWorkerError(Codes.CRASHED, message, details);
  // Branch on `ok` read defensively from its own data descriptor (accessors
  // are rejected by the snapshot either way).
  const okDesc = (raw !== null && typeof raw === 'object')
    ? Object.getOwnPropertyDescriptor(raw, 'ok')
    : undefined;
  const okValue = okDesc && Object.hasOwn(okDesc, 'value') ? okDesc.value : undefined;
  if (okValue !== true && okValue !== false) {
    throw violation('response ok flag must be a boolean', { reason: 'bad-ok-flag' });
  }
  const s = snapshotStrictPlainObject(raw, okValue === true ? RESULT_KEYS : ERROR_KEYS, asShapeFactory(violation));
  if (!isSafeInt(s.id) || s.id < 1) {
    throw violation('response id must be a positive safe integer', { reason: 'bad-id' });
  }
  if (okValue === true) {
    validateWireValue(s.result, { error: violation });
    return s;
  }
  const e = snapshotStrictPlainObject(s.error, WIRE_ERROR_KEYS, asShapeFactory(violation));
  if (typeof e.code !== 'string' || !KNOWN_CODES.has(e.code)) {
    throw violation('response error code is not part of the protocol', { reason: 'unknown-error-code' });
  }
  let details;
  try {
    details = sanitizeWorkerErrorDetails(e.details) ?? Object.freeze({});
  } catch {
    throw violation('response error details violate the allowlist', { reason: 'bad-error-details' });
  }
  return { id: s.id, ok: false, error: { code: e.code, details } };
}

/**
 * Build a success response, RE-CHECKING the result against the wire grammar
 * first: a handler that tries to return a WebAssembly object, a function, a
 * CryptoKey or a wasm-bindgen handle gets a typed error and nothing reaches
 * postMessage (vault spec §9 / mandate §11).
 * @throws {VaultWorkerError} WORKER_CRASHED when the result is unserializable
 */
export function buildResultResponse(id, result) {
  validateWireValue(result, {
    error: (message, details) => new VaultWorkerError(Codes.CRASHED, `unserializable result: ${message}`, details),
  });
  return { id, ok: true, result };
}

/**
 * Build an error response from ANY thrown value, fail-closed: recognized
 * VaultWorkerErrors keep code+details, anything else becomes a bare
 * WORKER_CRASHED (see toWireError) — no message content is copied.
 */
export function buildErrorResponse(id, code, details = {}) {
  return { id, ok: false, error: { code, details } };
}
