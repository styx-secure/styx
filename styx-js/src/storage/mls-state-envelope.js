// mls-state-envelope.js — versioned, self-describing container for persisted MLS state.
//
// The legacy `mls:state` value was a bare base64 string: nothing said which OpenMLS
// revision, WASM artifact or ciphersuite wrote it, so a future format change would fail
// (or misread) undiagnosably. The envelope stamps that provenance next to the payload
// and makes loading fail-closed: unknown/incompatible state raises a structured error
// and NEVER falls through to "create a fresh engine" — losing an MLS session silently
// is the forbidden behavior (docs/architecture/mls-state-migration-policy.md §2).
//
// This module is pure: no UI, no passwords, no vault crypto, no transport, no WASM,
// no storage access (the legacy migration lives in mls-state-migration.js). The
// payload digest detects accidental corruption only — it is NOT authentication; the
// Block 3 vault will wrap this.

import { sha256 } from '@noble/hashes/sha256';
import { bytesToBase64, base64ToBytes, bytesToHex } from '../utils.js';
import {
  MLS_BUILD_INFO,
  COMPATIBLE_OPENMLS_REVISIONS,
} from '../crypto/mls/mls-build-info.js';

export const MLS_STATE_FORMAT = 'styx-mls-state';
export const MLS_ENVELOPE_VERSION = 1;
export const MLS_STORAGE_SCHEMA_VERSION = 1;
/**
 * Decoded-payload cap: far above any real 2-peer state, below hostile-JSON territory.
 * Defensive parser cap only — NOT a guaranteed capacity of the storage backend
 * (localStorage quotas are far smaller): see docs/storage-limits.md (US-004).
 */
export const MAX_PAYLOAD_BYTES = 16 * 1024 * 1024;

export const MlsStateErrorCodes = Object.freeze({
  INVALID: 'MLS_STATE_INVALID',
  CORRUPTED: 'MLS_STATE_CORRUPTED',
  VERSION_UNSUPPORTED: 'MLS_STATE_VERSION_UNSUPPORTED',
  SCHEMA_UNSUPPORTED: 'MLS_STATE_SCHEMA_UNSUPPORTED',
  OPENMLS_INCOMPATIBLE: 'MLS_STATE_OPENMLS_INCOMPATIBLE',
  CIPHERSUITE_MISMATCH: 'MLS_STATE_CIPHERSUITE_MISMATCH',
  MIGRATION_FAILED: 'MLS_STATE_MIGRATION_FAILED',
  RESTORE_FAILED: 'MLS_STATE_RESTORE_FAILED',
});

/**
 * Closed allowlist for `details`. Every value must be a string of at most 64
 * characters or a safe integer — enough to say WHICH version, revision, digest
 * or step is involved and WHY (a stable sub-code), structurally too small to
 * smuggle payload bytes, keys or runtime messages through an error path.
 *
 * `causeMessage` is excluded BY DESIGN (Issue #26): the underlying error's
 * message must never auto-propagate into publishable details — keep the raw
 * error inspectable via the standard `error.cause` instead, or map it to a
 * stable sub-code in `causeCode`.
 *
 * Special case: `actions` may be an ARRAY of short strings (each at most 64
 * characters, at most MAX_ACTIONS entries) — the suggested-actions list shown
 * on incompatibility errors.
 *
 * NOTE: this intentionally duplicates the assertDetailsAllowed pattern of
 * src/crypto/vault-errors.js — the crypto/vault area is under a separate human
 * gate (PR #39 boundary), so consolidation is deferred.
 */
const DETAIL_KEYS = Object.freeze([
  'limit', 'saved', 'supported', 'current', 'savedRevision', 'currentRevision',
  'envelopeVersion', 'storageSchemaVersion', 'actions', 'savedArtifactSha256',
  'currentArtifactSha256', 'step', 'causeCode',
]);
const MAX_DETAIL_VALUE_LENGTH = 64;
const MAX_ACTIONS = 8;

function isShortPrimitive(value) {
  return (typeof value === 'string' && value.length <= MAX_DETAIL_VALUE_LENGTH)
    || (typeof value === 'number' && Number.isSafeInteger(value));
}

function assertDetailsAllowed(details) {
  if (details === null || typeof details !== 'object' || Array.isArray(details)) {
    throw new TypeError('MlsStateError details must be a plain object');
  }
  const out = {};
  for (const key of Object.keys(details)) {
    if (!DETAIL_KEYS.includes(key)) {
      throw new TypeError(`MlsStateError details key not allowlisted: ${key}`);
    }
    const value = details[key];
    if (key === 'actions') {
      const ok = Array.isArray(value)
        && value.length <= MAX_ACTIONS
        && value.every((entry) => typeof entry === 'string' && entry.length <= MAX_DETAIL_VALUE_LENGTH);
      if (!ok) throw new TypeError('MlsStateError details "actions" must be a short array of short strings');
      out[key] = Object.freeze([...value]);
      continue;
    }
    if (!isShortPrimitive(value)) {
      throw new TypeError(`MlsStateError details value for "${key}" is not a short primitive`);
    }
    out[key] = value;
  }
  return Object.freeze(out);
}

/**
 * Structured, stable-coded error. `details` is a CLOSED shape (default-deny):
 * only the allowlisted keys above are accepted, so it may carry versions,
 * revisions, digests and suggested actions — never payload bytes, keys,
 * serialized MLS material or forwarded runtime messages. The underlying error,
 * when there is one, travels as the standard ES2022 `cause` (development-only
 * inspection; it never enters `details` or its JSON serialization).
 */
export class MlsStateError extends Error {
  constructor(code, message, details = {}, options = {}) {
    super(`${code}: ${message}`, 'cause' in options ? { cause: options.cause } : undefined);
    this.name = 'MlsStateError';
    this.code = code;
    this.details = assertDetailsAllowed(details);
  }
}

const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const HEX40_RE = /^[0-9a-f]{40}$/;
const HEX64_RE = /^[0-9a-f]{64}$/;

function isPlainObject(v) {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function isValidBase64(s) {
  return typeof s === 'string' && s.length > 0 && s.length % 4 === 0 && BASE64_RE.test(s);
}

/**
 * Classify a raw `mls:state` value without trusting it.
 * @param {unknown} value as returned by the backend (JSON-decoded)
 * @returns {'none'|'legacy-base64'|'envelope'|'unknown'}
 */
export function detectMlsStateFormat(value) {
  if (value === null || value === undefined) return 'none';
  if (typeof value === 'string') return isValidBase64(value) ? 'legacy-base64' : 'unknown';
  if (isPlainObject(value) && value.format === MLS_STATE_FORMAT) return 'envelope';
  return 'unknown';
}

/**
 * Wrap raw serialized MLS state into an envelope v1 object.
 * @param {Uint8Array} stateBytes output of Provider.serialize_state()
 * @param {object} [buildInfo] revision/artifact/ciphersuite of the writing runtime
 * @returns {object} envelope (plain JSON-serializable object)
 */
export function encodeMlsStateEnvelope(stateBytes, buildInfo = MLS_BUILD_INFO) {
  if (!(stateBytes instanceof Uint8Array) || stateBytes.length === 0) {
    throw new MlsStateError(MlsStateErrorCodes.INVALID, 'state bytes must be a non-empty Uint8Array');
  }
  if (stateBytes.length > MAX_PAYLOAD_BYTES) {
    throw new MlsStateError(MlsStateErrorCodes.INVALID, 'state exceeds the payload size limit', {
      limit: MAX_PAYLOAD_BYTES,
    });
  }
  return {
    format: MLS_STATE_FORMAT,
    envelopeVersion: MLS_ENVELOPE_VERSION,
    storageSchemaVersion: MLS_STORAGE_SCHEMA_VERSION,
    openMlsRevision: buildInfo.openMlsRevision,
    wasmArtifactSha256: buildInfo.wasmArtifactSha256,
    ciphersuite: buildInfo.ciphersuite,
    payloadEncoding: 'base64',
    payloadSha256: bytesToHex(sha256(stateBytes)),
    payload: bytesToBase64(stateBytes),
  };
}

const ENVELOPE_FIELDS = Object.freeze([
  'format', 'envelopeVersion', 'storageSchemaVersion', 'openMlsRevision',
  'wasmArtifactSha256', 'ciphersuite', 'payloadEncoding', 'payloadSha256', 'payload',
]);

/**
 * Strict, fail-closed envelope parser. Validates shape, versions, encoding, size and
 * payload digest; never touches storage, never invokes restore_state, never repairs.
 * @param {unknown} value the raw `mls:state` value
 * @param {object} [opts] @param {number} [opts.maxPayloadBytes]
 * @returns {{envelope: object, stateBytes: Uint8Array}}
 * @throws {MlsStateError}
 */
export function parseMlsStateEnvelope(value, { maxPayloadBytes = MAX_PAYLOAD_BYTES } = {}) {
  const { INVALID, CORRUPTED, VERSION_UNSUPPORTED, SCHEMA_UNSUPPORTED } = MlsStateErrorCodes;
  if (!isPlainObject(value)) {
    throw new MlsStateError(INVALID, 'MLS state is not an envelope object');
  }
  if (value.format !== MLS_STATE_FORMAT) {
    throw new MlsStateError(INVALID, 'unrecognized state format magic');
  }
  for (const field of ENVELOPE_FIELDS) {
    if (!Object.hasOwn(value, field)) {
      throw new MlsStateError(INVALID, `missing required field "${field}"`);
    }
  }
  for (const key of Object.keys(value)) {
    if (!ENVELOPE_FIELDS.includes(key)) {
      throw new MlsStateError(INVALID, `unexpected field "${key}"`);
    }
  }
  if (!Number.isInteger(value.envelopeVersion)) {
    throw new MlsStateError(INVALID, 'envelopeVersion must be an integer');
  }
  if (value.envelopeVersion !== MLS_ENVELOPE_VERSION) {
    // A newer (or otherwise unknown) envelope: typically an app rollback after an
    // upgrade. The data must stay untouched — the build that wrote it can read it.
    throw new MlsStateError(VERSION_UNSUPPORTED, 'unsupported envelope version', {
      saved: value.envelopeVersion,
      supported: MLS_ENVELOPE_VERSION,
    });
  }
  if (!Number.isInteger(value.storageSchemaVersion)) {
    throw new MlsStateError(INVALID, 'storageSchemaVersion must be an integer');
  }
  if (value.storageSchemaVersion !== MLS_STORAGE_SCHEMA_VERSION) {
    throw new MlsStateError(SCHEMA_UNSUPPORTED, 'unsupported storage schema version', {
      saved: value.storageSchemaVersion,
      supported: MLS_STORAGE_SCHEMA_VERSION,
    });
  }
  if (typeof value.openMlsRevision !== 'string' || !HEX40_RE.test(value.openMlsRevision)) {
    throw new MlsStateError(INVALID, 'openMlsRevision must be a 40-hex commit id');
  }
  if (typeof value.wasmArtifactSha256 !== 'string' || !HEX64_RE.test(value.wasmArtifactSha256)) {
    throw new MlsStateError(INVALID, 'wasmArtifactSha256 must be a 64-hex digest');
  }
  if (typeof value.ciphersuite !== 'string' || value.ciphersuite.length === 0) {
    throw new MlsStateError(INVALID, 'ciphersuite must be a non-empty string');
  }
  if (value.payloadEncoding !== 'base64') {
    throw new MlsStateError(INVALID, 'unsupported payload encoding', {
      saved: typeof value.payloadEncoding === 'string' ? value.payloadEncoding : typeof value.payloadEncoding,
    });
  }
  if (typeof value.payloadSha256 !== 'string' || !HEX64_RE.test(value.payloadSha256)) {
    throw new MlsStateError(INVALID, 'payloadSha256 must be a 64-hex digest');
  }
  if (typeof value.payload !== 'string') {
    throw new MlsStateError(INVALID, 'payload must be a string');
  }
  if (value.payload.length === 0) {
    throw new MlsStateError(CORRUPTED, 'payload is empty');
  }
  // Size gate BEFORE decoding, so an oversized hostile payload is never materialized.
  if (value.payload.length > Math.ceil(maxPayloadBytes / 3) * 4 + 4) {
    throw new MlsStateError(INVALID, 'payload exceeds the size limit', { limit: maxPayloadBytes });
  }
  if (!isValidBase64(value.payload)) {
    throw new MlsStateError(CORRUPTED, 'payload is not valid base64');
  }
  const stateBytes = base64ToBytes(value.payload);
  if (stateBytes.length === 0) {
    throw new MlsStateError(CORRUPTED, 'payload decodes to zero bytes');
  }
  if (stateBytes.length > maxPayloadBytes) {
    throw new MlsStateError(INVALID, 'payload exceeds the size limit', { limit: maxPayloadBytes });
  }
  if (bytesToHex(sha256(stateBytes)) !== value.payloadSha256) {
    throw new MlsStateError(CORRUPTED, 'payload digest mismatch — state is corrupted');
  }
  return { envelope: value, stateBytes };
}

/**
 * Enforce the load-compatibility policy (cases A/C of the migration policy §4):
 * only state written by a revision PROVEN compatible with the current runtime loads.
 * @param {object} envelope a parsed envelope
 * @param {object} [buildInfo] the current runtime's build info
 * @param {readonly string[]} [compatibleRevisions]
 * @throws {MlsStateError}
 */
export function assertMlsStateCompatibility(
  envelope,
  buildInfo = MLS_BUILD_INFO,
  compatibleRevisions = COMPATIBLE_OPENMLS_REVISIONS,
) {
  const { OPENMLS_INCOMPATIBLE, CIPHERSUITE_MISMATCH } = MlsStateErrorCodes;
  if (envelope.ciphersuite !== buildInfo.ciphersuite) {
    throw new MlsStateError(CIPHERSUITE_MISMATCH, 'state was written under a different ciphersuite', {
      saved: envelope.ciphersuite,
      current: buildInfo.ciphersuite,
    });
  }
  const incompatibleDetails = {
    savedRevision: envelope.openMlsRevision,
    currentRevision: buildInfo.openMlsRevision,
    envelopeVersion: envelope.envelopeVersion,
    storageSchemaVersion: envelope.storageSchemaVersion,
    actions: [
      'reopen with the app build that wrote this state',
      'wait for a build that migrates this revision',
      'explicit factory reset (destroys the session) as a last resort',
    ],
  };
  if (!compatibleRevisions.includes(envelope.openMlsRevision)) {
    throw new MlsStateError(OPENMLS_INCOMPATIBLE, 'state was written by an unvalidated OpenMLS revision', incompatibleDetails);
  }
  // Same revision but a different artifact means a different toolchain or patch —
  // the build is byte-reproducible, so this is NOT the runtime that wrote the state.
  if (
    envelope.openMlsRevision === buildInfo.openMlsRevision
    && envelope.wasmArtifactSha256 !== buildInfo.wasmArtifactSha256
  ) {
    throw new MlsStateError(OPENMLS_INCOMPATIBLE, 'state was written by a different WASM artifact of the same revision', {
      ...incompatibleDetails,
      savedArtifactSha256: envelope.wasmArtifactSha256,
      currentArtifactSha256: buildInfo.wasmArtifactSha256,
    });
  }
}

