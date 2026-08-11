// STYX_SPIKE_PROTOTYPE — Phase B2.3 only; no product path may import this file.
//
// Canonical form follows the repository's reviewed vault convention: UTF-8 of
// JSON.stringify over a fixed-order array of already validated primitives.
// Large byte strings live in IndexedDB as Uint8Array and are represented in a
// canonical record only by their byte length and SHA-256 digest.

import { sha256 } from '@noble/hashes/sha256';

const UTF8 = new TextEncoder();

export const B23_FORMAT = 'styx-marmot-b2-3';
export const B23_VERSION = 1;
export const B23_PROFILE = 'marmot-current-profile-poc';
export const B23_DB_PREFIX = 'styx-b2-3-poc-';

export const B23_RUNTIME = Object.freeze({
  openMlsRevision: '09e92777dba0528d3d29e2e5e681b7e91637c7be',
  wasmArtifactSha256: '60dbbc1127fbfb0e7e479cf7e2f7e6e20183c60d0559268f039d8db58bf60a3a',
  ciphersuite: 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519',
});

export const B23_LIMITS = Object.freeze({
  maxSnapshotBytes: 8 * 1024 * 1024,
  maxSnapshotEntries: 4096,
  maxSnapshotKeyBytes: 64 * 1024,
  maxGroupContextBytes: 64 * 1024,
  maxCommitBytes: 1024 * 1024,
  maxWelcomeBytes: 2 * 1024 * 1024,
  maxArtifactBytes: 2 * 1024 * 1024,
  maxEvidenceBytes: 64 * 1024,
  maxMembers: 16,
  maxProposals: 32,
  maxPublishAttempts: 64,
  maxEvidence: 64,
});

export const B23_STORES = Object.freeze({
  head: 'head',
  snapshot: 'snapshot',
  transition: 'transition',
  evidence: 'evidence',
});

export const B23_STORE_NAMES = Object.freeze(Object.values(B23_STORES));

export const B23_ERROR = Object.freeze({
  INVALID: 'B23_INVALID',
  CORRUPT: 'B23_CORRUPT',
  INCOMPATIBLE: 'B23_INCOMPATIBLE',
  CAS_CONFLICT: 'B23_CAS_CONFLICT',
  NOT_FOUND: 'B23_NOT_FOUND',
  STATE_CONFLICT: 'B23_STATE_CONFLICT',
  ENGINE_REJECTED: 'B23_ENGINE_REJECTED',
  RESOURCE_LIMIT: 'B23_RESOURCE_LIMIT',
});

export class B23Error extends Error {
  constructor(code, message, details = {}, options = {}) {
    super(`${code}: ${message}`, 'cause' in options ? { cause: options.cause } : undefined);
    this.name = 'B23Error';
    this.code = code;
    this.details = Object.freeze({ ...details });
  }
}

export function fail(code, message, details, cause) {
  throw new B23Error(code, message, details, cause === undefined ? {} : { cause });
}

export function isPlainDataObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/** Snapshot a hostile object without invoking getters or toJSON hooks. */
export function snapshotClosedObject(value, fields, label) {
  if (!isPlainDataObject(value)) fail(B23_ERROR.INVALID, `${label} must be a plain object`);
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== 'string')) {
    fail(B23_ERROR.INVALID, `${label} contains a symbol field`);
  }
  for (const key of keys) {
    if (!fields.includes(key)) fail(B23_ERROR.INVALID, `${label} contains an unexpected field`);
  }
  if (keys.length !== fields.length) fail(B23_ERROR.INVALID, `${label} field count is invalid`);
  const out = {};
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) {
      fail(B23_ERROR.INVALID, `${label} contains a missing or accessor field`);
    }
    out[field] = descriptor.value;
  }
  return out;
}

export function assertSafeInteger(name, value, min = 0, max = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    fail(B23_ERROR.INVALID, `${name} must be a bounded safe integer`);
  }
  return value;
}

export function assertString(name, value, { min = 1, max = 256, pattern } = {}) {
  if (typeof value !== 'string' || value.length < min || value.length > max
    || (pattern && !pattern.test(value))) {
    fail(B23_ERROR.INVALID, `${name} is not canonical`);
  }
  return value;
}

const HEX64 = /^[0-9a-f]{64}$/;
const HEX40 = /^[0-9a-f]{40}$/;
const GROUP_HEX = /^(?:[0-9a-f]{2}){1,64}$/;
const EPOCH_DECIMAL = /^(?:0|[1-9][0-9]{0,19})$/;
const MAX_U64 = (1n << 64n) - 1n;

export function assertHex64(name, value) {
  return assertString(name, value, { min: 64, max: 64, pattern: HEX64 });
}

export function assertHex40(name, value) {
  return assertString(name, value, { min: 40, max: 40, pattern: HEX40 });
}

export function assertGroupIdHex(value) {
  return assertString('groupIdHex', value, { min: 2, max: 128, pattern: GROUP_HEX });
}

export function epochToDecimal(value) {
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) {
    fail(B23_ERROR.INVALID, 'epoch must be an unsigned 64-bit bigint');
  }
  return value.toString(10);
}

export function parseEpochDecimal(value, name = 'epochDec') {
  assertString(name, value, { min: 1, max: 20, pattern: EPOCH_DECIMAL });
  const parsed = BigInt(value);
  if (parsed > MAX_U64) fail(B23_ERROR.INVALID, `${name} is outside the unsigned 64-bit range`);
  return parsed;
}

export function assertBytes(name, value, { min = 0, max } = {}) {
  if (!(value instanceof Uint8Array) || value.length < min || value.length > max) {
    fail(B23_ERROR.INVALID, `${name} must be a bounded Uint8Array`);
  }
  return value;
}

export function copyBytes(value) {
  return value === null ? null : Uint8Array.from(value);
}

export function bytesEqual(left, right) {
  if (!(left instanceof Uint8Array) || !(right instanceof Uint8Array)
    || left.length !== right.length) return false;
  let different = 0;
  for (let index = 0; index < left.length; index += 1) different |= left[index] ^ right[index];
  return different === 0;
}

export function bytesToHex(bytes) {
  assertBytes('bytes', bytes, { max: B23_LIMITS.maxSnapshotBytes });
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
}

export function hexToBytes(name, value) {
  assertString(name, value, { min: 2, max: B23_LIMITS.maxSnapshotBytes * 2, pattern: /^(?:[0-9a-f]{2})+$/ });
  const out = new Uint8Array(value.length / 2);
  for (let index = 0; index < out.length; index += 1) {
    out[index] = Number.parseInt(value.slice(index * 2, (index * 2) + 2), 16);
  }
  return out;
}

export function digestHex(bytes) {
  return bytesToHex(Uint8Array.from(sha256(bytes)));
}

/** Strictly validate Provider::serialize_state before any OpenMLS restore. */
export function validateProviderSnapshot(value) {
  const bytes = assertBytes('Provider snapshot', value, { min: 8, max: B23_LIMITS.maxSnapshotBytes });
  let offset = 0;
  const readU64 = (label) => {
    if (offset + 8 > bytes.length) fail(B23_ERROR.INVALID, `${label} is truncated`);
    let result = 0n;
    for (let index = 0; index < 8; index += 1) result = (result << 8n) | BigInt(bytes[offset + index]);
    offset += 8;
    return result;
  };
  const boundedLength = (label, maximum) => {
    const length = readU64(label);
    if (length > BigInt(maximum) || length > BigInt(bytes.length - offset)) {
      fail(B23_ERROR.RESOURCE_LIMIT, `${label} exceeds its bound`);
    }
    return Number(length);
  };
  const count = readU64('Provider entry count');
  if (count > BigInt(B23_LIMITS.maxSnapshotEntries)) {
    fail(B23_ERROR.RESOURCE_LIMIT, 'Provider entry count exceeds its bound');
  }
  const keys = new Set();
  for (let entry = 0; entry < Number(count); entry += 1) {
    const keyLength = boundedLength('Provider key length', B23_LIMITS.maxSnapshotKeyBytes);
    const valueLength = boundedLength('Provider value length', B23_LIMITS.maxSnapshotBytes);
    if (keyLength + valueLength > bytes.length - offset) {
      fail(B23_ERROR.INVALID, 'Provider entry payload is truncated');
    }
    const keyHex = bytesToHex(bytes.subarray(offset, offset + keyLength));
    if (keys.has(keyHex)) fail(B23_ERROR.INVALID, 'Provider snapshot contains a duplicate key');
    keys.add(keyHex);
    offset += keyLength + valueLength;
  }
  if (offset !== bytes.length) fail(B23_ERROR.INVALID, 'Provider snapshot contains trailing bytes');
  return Object.freeze({ entryCount: Number(count), byteLength: bytes.length });
}

export function canonicalBytes(domain, values) {
  assertString('domain', domain, { min: 1, max: 96, pattern: /^[A-Z0-9-]+$/ });
  if (!Array.isArray(values)) fail(B23_ERROR.INVALID, 'canonical values must be an array');
  return UTF8.encode(JSON.stringify([domain, ...values]));
}

export function randomHex256(randomBytes = globalThis.crypto?.getRandomValues?.bind(globalThis.crypto)) {
  if (typeof randomBytes !== 'function') fail(B23_ERROR.INVALID, 'a cryptographic random byte source is required');
  const bytes = new Uint8Array(32);
  randomBytes(bytes);
  return bytesToHex(bytes);
}

export function assertRuntimeTuple(runtime) {
  if (!isPlainDataObject(runtime)) fail(B23_ERROR.INVALID, 'runtime tuple must be a plain object');
  const { openMlsRevision, wasmArtifactSha256, ciphersuite } = runtime;
  assertHex40('openMlsRevision', openMlsRevision);
  assertHex64('wasmArtifactSha256', wasmArtifactSha256);
  assertString('ciphersuite', ciphersuite, { min: 1, max: 128, pattern: /^[A-Za-z0-9_]+$/ });
  if (openMlsRevision !== B23_RUNTIME.openMlsRevision
    || wasmArtifactSha256 !== B23_RUNTIME.wasmArtifactSha256
    || ciphersuite !== B23_RUNTIME.ciphersuite) {
    fail(B23_ERROR.INCOMPATIBLE, 'runtime tuple is not the exact B2.2 tuple');
  }
  return runtime;
}
