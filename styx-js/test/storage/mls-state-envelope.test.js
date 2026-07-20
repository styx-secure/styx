// test/storage/mls-state-envelope.test.js — strict codec + build-info anti-drift.
import { describe, test, expect } from '@jest/globals';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  MLS_STATE_FORMAT,
  MLS_ENVELOPE_VERSION,
  MLS_STORAGE_SCHEMA_VERSION,
  MAX_PAYLOAD_BYTES,
  MlsStateError,
  MlsStateErrorCodes,
  detectMlsStateFormat,
  encodeMlsStateEnvelope,
  parseMlsStateEnvelope,
  assertMlsStateCompatibility,
} from '../../src/storage/mls-state-envelope.js';
import {
  MLS_BUILD_INFO,
  COMPATIBLE_OPENMLS_REVISIONS,
} from '../../src/crypto/mls/mls-build-info.js';
import { bytesToBase64 } from '../../src/utils.js';

const STATE = new Uint8Array([1, 2, 3, 4, 5, 250, 251, 252, 253, 254, 255, 0]);

function freshEnvelope(overrides = {}) {
  // JSON round-trip: exactly what the storage backend does to the value.
  return { ...JSON.parse(JSON.stringify(encodeMlsStateEnvelope(STATE))), ...overrides };
}

function expectCode(fn, code) {
  let caught;
  try { fn(); } catch (e) { caught = e; }
  expect(caught).toBeInstanceOf(MlsStateError);
  expect(caught.code).toBe(code);
  // Structured errors must never leak the payload or MLS material.
  expect(caught.message).not.toContain(bytesToBase64(STATE));
  expect(JSON.stringify(caught.details ?? {})).not.toContain(bytesToBase64(STATE));
  // causeMessage is not an allowlisted details field (Issue #26).
  expect(Object.keys(caught.details ?? {})).not.toContain('causeMessage');
  return caught;
}

describe('detectMlsStateFormat', () => {
  test('classifies every stored shape', () => {
    expect(detectMlsStateFormat(null)).toBe('none');
    expect(detectMlsStateFormat(undefined)).toBe('none');
    expect(detectMlsStateFormat(bytesToBase64(STATE))).toBe('legacy-base64');
    expect(detectMlsStateFormat(freshEnvelope())).toBe('envelope');
    // Anything else is unknown — and unknown must never load.
    expect(detectMlsStateFormat('')).toBe('unknown');
    expect(detectMlsStateFormat('not base64!!')).toBe('unknown');
    expect(detectMlsStateFormat(42)).toBe('unknown');
    expect(detectMlsStateFormat([1, 2])).toBe('unknown');
    expect(detectMlsStateFormat({ format: 'something-else' })).toBe('unknown');
    expect(detectMlsStateFormat({})).toBe('unknown');
  });
});

describe('encode → parse round-trip', () => {
  test('serialize → parse returns the same bytes and metadata', () => {
    const { envelope, stateBytes } = parseMlsStateEnvelope(freshEnvelope());
    expect(stateBytes).toEqual(STATE);
    expect(envelope.format).toBe(MLS_STATE_FORMAT);
    expect(envelope.envelopeVersion).toBe(MLS_ENVELOPE_VERSION);
    expect(envelope.storageSchemaVersion).toBe(MLS_STORAGE_SCHEMA_VERSION);
    expect(envelope.openMlsRevision).toBe(MLS_BUILD_INFO.openMlsRevision);
    expect(envelope.wasmArtifactSha256).toBe(MLS_BUILD_INFO.wasmArtifactSha256);
    expect(envelope.ciphersuite).toBe(MLS_BUILD_INFO.ciphersuite);
  });

  test('parse → serialize: a parsed envelope re-encodes to an identical envelope', () => {
    const { stateBytes } = parseMlsStateEnvelope(freshEnvelope());
    expect(JSON.parse(JSON.stringify(encodeMlsStateEnvelope(stateBytes)))).toEqual(freshEnvelope());
  });

  test('encode rejects empty and oversized state', () => {
    expectCode(() => encodeMlsStateEnvelope(new Uint8Array(0)), MlsStateErrorCodes.INVALID);
    expectCode(() => encodeMlsStateEnvelope('not bytes'), MlsStateErrorCodes.INVALID);
  });

  test('the envelope carries no timestamps or user identifiers', () => {
    expect(Object.keys(freshEnvelope()).sort()).toEqual([
      'ciphersuite', 'envelopeVersion', 'format', 'openMlsRevision', 'payload',
      'payloadEncoding', 'payloadSha256', 'storageSchemaVersion', 'wasmArtifactSha256',
    ]);
  });
});

describe('parseMlsStateEnvelope — fail-closed on every malformation', () => {
  test('non-object and wrong magic', () => {
    expectCode(() => parseMlsStateEnvelope('a string'), MlsStateErrorCodes.INVALID);
    expectCode(() => parseMlsStateEnvelope(null), MlsStateErrorCodes.INVALID);
    expectCode(() => parseMlsStateEnvelope(freshEnvelope({ format: 'evil' })), MlsStateErrorCodes.INVALID);
  });

  test('every missing required field is rejected', () => {
    for (const field of Object.keys(freshEnvelope())) {
      const env = freshEnvelope();
      delete env[field];
      expectCode(() => parseMlsStateEnvelope(env), MlsStateErrorCodes.INVALID);
    }
  });

  test('unexpected extra fields are rejected (strict, no smuggling)', () => {
    expectCode(() => parseMlsStateEnvelope(freshEnvelope({ extra: 1 })), MlsStateErrorCodes.INVALID);
  });

  test('wrong types are rejected field by field', () => {
    const bad = {
      envelopeVersion: '1',
      storageSchemaVersion: '1',
      openMlsRevision: 'not-hex',
      wasmArtifactSha256: 'abc',
      ciphersuite: '',
      payloadEncoding: 'hex',
      payloadSha256: 12,
      payload: 7,
    };
    for (const [field, value] of Object.entries(bad)) {
      expectCode(() => parseMlsStateEnvelope(freshEnvelope({ [field]: value })), MlsStateErrorCodes.INVALID);
    }
  });

  test('unknown envelope version → VERSION_UNSUPPORTED, with versions in details', () => {
    const err = expectCode(
      () => parseMlsStateEnvelope(freshEnvelope({ envelopeVersion: 2 })),
      MlsStateErrorCodes.VERSION_UNSUPPORTED,
    );
    expect(err.details).toEqual({ saved: 2, supported: MLS_ENVELOPE_VERSION });
  });

  test('unknown storage schema → SCHEMA_UNSUPPORTED', () => {
    expectCode(
      () => parseMlsStateEnvelope(freshEnvelope({ storageSchemaVersion: 9 })),
      MlsStateErrorCodes.SCHEMA_UNSUPPORTED,
    );
  });

  test('empty, malformed and truncated payloads → CORRUPTED', () => {
    expectCode(() => parseMlsStateEnvelope(freshEnvelope({ payload: '' })), MlsStateErrorCodes.CORRUPTED);
    expectCode(() => parseMlsStateEnvelope(freshEnvelope({ payload: '!!!not-base64!!!' })), MlsStateErrorCodes.CORRUPTED);
    // Truncation keeps valid base64 but breaks the digest.
    const env = freshEnvelope();
    env.payload = env.payload.slice(0, 4);
    expectCode(() => parseMlsStateEnvelope(env), MlsStateErrorCodes.CORRUPTED);
  });

  test('digest mismatch → CORRUPTED', () => {
    const env = freshEnvelope({ payloadSha256: '0'.repeat(64) });
    expectCode(() => parseMlsStateEnvelope(env), MlsStateErrorCodes.CORRUPTED);
  });

  test('payload over the size limit is rejected before decoding', () => {
    const env = freshEnvelope({ payload: 'AAAA'.repeat(64) });
    expectCode(() => parseMlsStateEnvelope(env, { maxPayloadBytes: 16 }), MlsStateErrorCodes.INVALID);
    expect(MAX_PAYLOAD_BYTES).toBe(16 * 1024 * 1024);
  });
});

describe('assertMlsStateCompatibility — cases A/C of the policy', () => {
  test('case A: the current build loads its own state', () => {
    const { envelope } = parseMlsStateEnvelope(freshEnvelope());
    expect(() => assertMlsStateCompatibility(envelope)).not.toThrow();
  });

  test('case C: unvalidated OpenMLS revision → OPENMLS_INCOMPATIBLE with full context', () => {
    const saved = 'a'.repeat(40);
    const err = expectCode(
      () => assertMlsStateCompatibility(freshEnvelope({ openMlsRevision: saved })),
      MlsStateErrorCodes.OPENMLS_INCOMPATIBLE,
    );
    expect(err.details.savedRevision).toBe(saved);
    expect(err.details.currentRevision).toBe(MLS_BUILD_INFO.openMlsRevision);
    expect(err.details.envelopeVersion).toBe(MLS_ENVELOPE_VERSION);
    expect(err.details.storageSchemaVersion).toBe(MLS_STORAGE_SCHEMA_VERSION);
    expect(err.details.actions.length).toBeGreaterThan(0);
  });

  test('same revision but different WASM artifact → OPENMLS_INCOMPATIBLE', () => {
    expectCode(
      () => assertMlsStateCompatibility(freshEnvelope({ wasmArtifactSha256: 'f'.repeat(64) })),
      MlsStateErrorCodes.OPENMLS_INCOMPATIBLE,
    );
  });

  test('different ciphersuite → CIPHERSUITE_MISMATCH', () => {
    const err = expectCode(
      () => assertMlsStateCompatibility(freshEnvelope({ ciphersuite: 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519' })),
      MlsStateErrorCodes.CIPHERSUITE_MISMATCH,
    );
    expect(err.details.current).toBe(MLS_BUILD_INFO.ciphersuite);
  });
});

describe('MlsStateError.details — closed allowlist (Issue #26)', () => {
  const { INVALID } = MlsStateErrorCodes;

  test('unknown details key → TypeError at construction (default-deny)', () => {
    expect(() => new MlsStateError(INVALID, 'x', { causeMessage: 'leaked runtime text' }))
      .toThrow(TypeError);
    expect(() => new MlsStateError(INVALID, 'x', { anythingElse: 1 })).toThrow(TypeError);
  });

  test('non-object details and over-long values are rejected', () => {
    expect(() => new MlsStateError(INVALID, 'x', ['step'])).toThrow(TypeError);
    expect(() => new MlsStateError(INVALID, 'x', { step: 'a'.repeat(65) })).toThrow(TypeError);
    expect(() => new MlsStateError(INVALID, 'x', { limit: Number.MAX_SAFE_INTEGER + 1 })).toThrow(TypeError);
    expect(() => new MlsStateError(INVALID, 'x', { step: { nested: true } })).toThrow(TypeError);
  });

  test('allowlisted short values pass and details is a frozen copy', () => {
    const input = { step: 'write', causeCode: 'unknown', limit: 16, saved: 'v1' };
    const err = new MlsStateError(INVALID, 'x', input);
    expect(err.details).toEqual(input);
    expect(Object.isFrozen(err.details)).toBe(true);
    input.step = 'mutated-later'; // the copy must not observe caller mutations
    expect(err.details.step).toBe('write');
  });

  test('actions: array of short strings accepted (frozen), abuses rejected', () => {
    const err = new MlsStateError(INVALID, 'x', { actions: ['do this', 'or that'] });
    expect(err.details.actions).toEqual(['do this', 'or that']);
    expect(Object.isFrozen(err.details.actions)).toBe(true);
    expect(() => new MlsStateError(INVALID, 'x', { actions: 'not an array' })).toThrow(TypeError);
    expect(() => new MlsStateError(INVALID, 'x', { actions: ['a'.repeat(65)] })).toThrow(TypeError);
    expect(() => new MlsStateError(INVALID, 'x', { actions: new Array(9).fill('a') })).toThrow(TypeError);
  });

  test('the underlying error travels as ES2022 cause, never inside details', () => {
    const inner = new Error('raw runtime text');
    const err = new MlsStateError(INVALID, 'x', { causeCode: 'unknown' }, { cause: inner });
    expect(err.cause).toBe(inner);
    expect(JSON.stringify(err.details)).not.toContain('raw runtime text');
    // Without options, no cause is attached at all.
    expect('cause' in new MlsStateError(INVALID, 'x')).toBe(false);
  });

  test('every details object built by this module passes its own allowlist', () => {
    // Representative construction sites: version/schema/size/compat errors.
    expectCode(() => parseMlsStateEnvelope(freshEnvelope({ envelopeVersion: 2 })), MlsStateErrorCodes.VERSION_UNSUPPORTED);
    expectCode(() => parseMlsStateEnvelope(freshEnvelope({ storageSchemaVersion: 9 })), MlsStateErrorCodes.SCHEMA_UNSUPPORTED);
    expectCode(() => encodeMlsStateEnvelope(new Uint8Array(MAX_PAYLOAD_BYTES + 1)), MlsStateErrorCodes.INVALID);
    const err = expectCode(
      () => assertMlsStateCompatibility(freshEnvelope({ openMlsRevision: 'a'.repeat(40) })),
      MlsStateErrorCodes.OPENMLS_INCOMPATIBLE,
    );
    expect(Object.isFrozen(err.details)).toBe(true);
  });
});

describe('build-info anti-drift — constants match the vendored artifact', () => {
  const vendor = fileURLToPath(new URL('../../vendor/openmls-wasm/', import.meta.url));

  test('openMlsRevision matches OPENMLS_COMMIT in build.sh', () => {
    const buildSh = readFileSync(`${vendor}build.sh`, 'utf8');
    expect(buildSh).toContain(MLS_BUILD_INFO.openMlsRevision);
  });

  test('wasmArtifactSha256 matches the committed .wasm', () => {
    const wasm = readFileSync(`${vendor}openmls_wasm_bg.wasm`);
    expect(createHash('sha256').update(wasm).digest('hex')).toBe(MLS_BUILD_INFO.wasmArtifactSha256);
  });

  test('ciphersuite matches the one compiled in patch/lib.rs', () => {
    const libRs = readFileSync(`${vendor}patch/lib.rs`, 'utf8');
    expect(libRs).toContain(MLS_BUILD_INFO.ciphersuite);
  });

  test('the compatible-revisions table contains exactly the pinned revision', () => {
    expect(COMPATIBLE_OPENMLS_REVISIONS).toEqual([MLS_BUILD_INFO.openMlsRevision]);
  });
});
