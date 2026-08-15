// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — exact B3.3a application-record codecs.

import { createHash } from 'node:crypto';

export const B33A_FORMAT = 'styx-marmot-b3.3a-application-journal';
export const B33A_VERSION = 1;
export const B33A_PROVIDER_FORMAT = 'phase-b32a-provider-canonical-v1';
export const B33A_RUN_ROOT = '/home/mverde/.local/share/styx-b3-3a-runs/issue-185';
export const B33A_PRIVATE_ROOT = '/home/mverde/.local/share/styx-b3-3a-private/issue-185';
export const B33A_BUILD_ROOT = '/home/mverde/.local/share/styx-b3-3a-builds/issue-185';
export const B33A_MDK_BUILD_ROOT =
  '/home/mverde/.local/share/styx-b3-3a-mdk-builds/issue-185';
export const B33A_REPORT_FORMAT = 'styx-marmot-b3.3a-application-evidence';
export const B33A_STATE = Object.freeze({ ACTIVE: 'ACTIVE' });
export const B33A_OUTCOME = Object.freeze({
  COMMITTED: 'COMMITTED',
  DUPLICATE: 'DUPLICATE',
});
export const B33A_ERROR = Object.freeze({
  CAS_CONFLICT: 'B33A_CAS_CONFLICT',
  CORRUPT: 'B33A_CORRUPT',
  DUPLICATE_INITIALIZATION: 'B33A_DUPLICATE_INITIALIZATION',
  ENGINE_REJECTED: 'B33A_ENGINE_REJECTED',
  INNER_EVENT_REJECTED: 'B33A_INNER_EVENT_REJECTED',
  INVALID: 'B33A_INVALID',
  PERSISTENCE_FAILED: 'B33A_PERSISTENCE_FAILED',
  RESOURCE_LIMIT: 'B33A_RESOURCE_LIMIT',
  STATE_CONFLICT: 'B33A_STATE_CONFLICT',
});
export const B33A_LIMITS = Object.freeze({
  maxCiphertextBytes: 1024 * 1024,
  maxContentBytes: 256 * 1024,
  maxEventBytes: 320 * 1024,
  maxJournalHeadBytes: 1024 * 1024,
  maxJournalRecords: 64,
  maxProviderBytes: 8 * 1024 * 1024,
  maxRequestIdBytes: 128,
  maxTagCount: 128,
  maxTagItems: 16,
  maxTagItemBytes: 4096,
});

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder('utf-8', { fatal: true });
const EVENT_FIELDS = Object.freeze(['id', 'pubkey', 'created_at', 'kind', 'tags', 'content']);

export class B33aError extends Error {
  constructor(code, message, details = {}, cause = undefined) {
    super(message, { cause });
    this.name = 'B33aError';
    this.code = code;
    this.details = Object.freeze({ ...details });
  }
}

export function failB33a(code, message, details = {}, cause = undefined) {
  throw new B33aError(code, message, details, cause);
}

export function sha256Hex(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function canonicalJsonBytes(value) {
  return textEncoder.encode(JSON.stringify(value));
}

export function bytesToHex(value) {
  return Buffer.from(assertBytes('bytes', value)).toString('hex');
}

export function hexToBytes(label, value, bytes = null) {
  assertHex(label, value, bytes);
  return Uint8Array.from(Buffer.from(value, 'hex'));
}

export function assertHex(label, value, bytes = null) {
  if (typeof value !== 'string' || !/^(?:[0-9a-f]{2})+$/.test(value)
    || (bytes !== null && value.length !== bytes * 2)) {
    failB33a(B33A_ERROR.INVALID, `${label} is not exact lowercase hexadecimal`);
  }
  return value;
}

export function assertDigest(label, value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) {
    failB33a(B33A_ERROR.INVALID, `${label} is not a SHA-256 digest`);
  }
  return value;
}

export function assertBytes(label, value, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  if (!(value instanceof Uint8Array) || value.byteLength < min || value.byteLength > max) {
    failB33a(B33A_ERROR.RESOURCE_LIMIT, `${label} is outside its byte envelope`);
  }
  return value;
}

export function copyBytes(value) { return Uint8Array.from(value); }

export function clearBytes(value) { value?.fill?.(0); }

export function appendB33aTranscript(transcript, operation, evidence) {
  if (!Array.isArray(transcript) || typeof operation !== 'string'
    || !/^[a-z0-9_]{1,96}$/.test(operation)) {
    failB33a(B33A_ERROR.INVALID, 'transcript append input is invalid');
  }
  const previousEntrySha256Hex = transcript.length === 0
    ? null : transcript.at(-1).entrySha256Hex;
  const payload = { ordinal: transcript.length + 1, operation,
    previousEntrySha256Hex, evidence };
  const entry = Object.freeze({
    ...payload,
    entrySha256Hex: sha256Hex(canonicalJsonBytes(payload)),
  });
  transcript.push(entry);
  return evidence;
}

export function validateB33aTranscript(transcript) {
  if (!Array.isArray(transcript) || transcript.length === 0) {
    failB33a(B33A_ERROR.INVALID, 'transcript is empty');
  }
  let previous = null;
  for (const [index, entry] of transcript.entries()) {
    const value = exactObject(entry, [
      'ordinal', 'operation', 'previousEntrySha256Hex', 'evidence', 'entrySha256Hex',
    ], 'B3.3a transcript entry');
    if (value.ordinal !== index + 1 || value.previousEntrySha256Hex !== previous
      || typeof value.operation !== 'string' || !/^[a-z0-9_]{1,96}$/.test(value.operation)) {
      failB33a(B33A_ERROR.INVALID, 'transcript sequence or operation is invalid');
    }
    const payload = { ordinal: value.ordinal, operation: value.operation,
      previousEntrySha256Hex: value.previousEntrySha256Hex, evidence: value.evidence };
    if (sha256Hex(canonicalJsonBytes(payload)) !== value.entrySha256Hex) {
      failB33a(B33A_ERROR.INVALID, 'transcript entry digest is invalid');
    }
    previous = value.entrySha256Hex;
  }
  return previous;
}

function validateCandidateTuple(value) {
  const tuple = exactObject(value, [
    'openmls_wasm.js', 'openmls_wasm.d.ts', 'openmls_wasm_bg.wasm',
    'openmls_wasm_bg.wasm.d.ts', 'package.json',
  ], 'B3.3a candidate tuple');
  for (const [name, digest] of Object.entries(tuple)) assertDigest(name, digest);
  return Object.freeze(tuple);
}

export function validateB33aReport(value, transcriptHeadSha256Hex) {
  if (value?.disposition === 'GO') {
    const report = exactObject(value, [
      'format', 'version', 'disposition', 'claim', 'applicationEventsCommitted',
      'bidirectionalApplicationTrafficEstablished', 'candidateTuple',
      'commitLifecycleTested', 'groupIdHex', 'replayPlaintextReleased',
      'transcriptHeadSha256Hex',
    ], 'B3.3a GO report');
    if (report.format !== B33A_REPORT_FORMAT || report.version !== 1
      || typeof report.claim !== 'string' || report.claim.length === 0
      || report.applicationEventsCommitted !== 4
      || report.bidirectionalApplicationTrafficEstablished !== true
      || report.commitLifecycleTested !== false || report.replayPlaintextReleased !== false
      || report.transcriptHeadSha256Hex !== transcriptHeadSha256Hex) {
      failB33a(B33A_ERROR.INVALID, 'B3.3a GO report claim or evidence is incoherent');
    }
    assertHex('GO report group id', report.groupIdHex);
    return Object.freeze({ ...report, candidateTuple: validateCandidateTuple(report.candidateTuple) });
  }
  if (value?.disposition === 'NO-GO') {
    const report = exactObject(value, [
      'format', 'version', 'disposition', 'claim', 'applicationEventsCommitted',
      'bidirectionalApplicationTrafficEstablished', 'commitLifecycleTested', 'failure',
      'firstIncompatibleOperation', 'transcriptHeadSha256Hex',
    ], 'B3.3a NO-GO report');
    if (report.format !== B33A_REPORT_FORMAT || report.version !== 1
      || !Number.isSafeInteger(report.applicationEventsCommitted)
      || report.applicationEventsCommitted < 0 || report.applicationEventsCommitted > 3
      || report.bidirectionalApplicationTrafficEstablished !== false
      || report.commitLifecycleTested !== false
      || typeof report.firstIncompatibleOperation !== 'string'
      || report.transcriptHeadSha256Hex !== transcriptHeadSha256Hex) {
      failB33a(B33A_ERROR.INVALID, 'B3.3a NO-GO report is incoherent');
    }
    const failure = exactObject(report.failure, ['code', 'message'], 'B3.3a typed failure');
    if (typeof failure.code !== 'string' || typeof failure.message !== 'string') {
      failB33a(B33A_ERROR.INVALID, 'B3.3a typed failure is invalid');
    }
    return Object.freeze({ ...report, failure: Object.freeze(failure) });
  }
  if (value?.disposition === 'BLOCKED') {
    const report = exactObject(value, [
      'format', 'version', 'disposition', 'claim', 'applicationEventsCommitted',
      'bidirectionalApplicationTrafficEstablished', 'commitLifecycleTested',
      'transcriptHeadSha256Hex',
    ], 'B3.3a BLOCKED report');
    if (report.format !== B33A_REPORT_FORMAT || report.version !== 1
      || !Number.isSafeInteger(report.applicationEventsCommitted)
      || report.applicationEventsCommitted < 0 || report.applicationEventsCommitted > 3
      || report.bidirectionalApplicationTrafficEstablished !== false
      || report.commitLifecycleTested !== false
      || report.transcriptHeadSha256Hex !== transcriptHeadSha256Hex) {
      failB33a(B33A_ERROR.INVALID, 'B3.3a BLOCKED report is incoherent');
    }
    return Object.freeze(report);
  }
  failB33a(B33A_ERROR.INVALID, 'B3.3a report disposition is invalid');
}

export function exactObject(value, fields, label, error = B33A_ERROR.INVALID) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    failB33a(error, `${label} is not an object`);
  }
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== 'string') || keys.length !== fields.length
    || keys.some((key, index) => key !== fields[index])) {
    failB33a(error, `${label} fields or field order are not exact`);
  }
  const result = {};
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) {
      failB33a(error, `${label} contains an accessor or missing field`);
    }
    result[field] = descriptor.value;
  }
  return result;
}

function assertBoundedString(label, value, maximumBytes) {
  if (typeof value !== 'string' || textEncoder.encode(value).byteLength > maximumBytes) {
    failB33a(B33A_ERROR.INNER_EVENT_REJECTED, `${label} is outside its UTF-8 envelope`);
  }
  return value;
}

function normalizeTags(value) {
  if (!Array.isArray(value) || value.length > B33A_LIMITS.maxTagCount) {
    failB33a(B33A_ERROR.INNER_EVENT_REJECTED, 'event tags exceed their envelope');
  }
  return value.map((tag, tagIndex) => {
    if (!Array.isArray(tag) || tag.length > B33A_LIMITS.maxTagItems) {
      failB33a(B33A_ERROR.INNER_EVENT_REJECTED, `event tag ${tagIndex} is invalid`);
    }
    return tag.map((item, itemIndex) => assertBoundedString(
      `event tag ${tagIndex}:${itemIndex}`, item, B33A_LIMITS.maxTagItemBytes,
    ));
  });
}

export function nip01EventId(event) {
  return sha256Hex(canonicalJsonBytes([
    0, event.pubkey, event.created_at, event.kind, event.tags, event.content,
  ]));
}

export function decodeMarmotAppEvent(bytes, expectedSenderIdentityHex) {
  assertBytes('Marmot application event', bytes, { min: 2, max: B33A_LIMITS.maxEventBytes });
  let text;
  let parsed;
  try {
    text = textDecoder.decode(bytes);
    parsed = JSON.parse(text);
  } catch (error) {
    failB33a(B33A_ERROR.INNER_EVENT_REJECTED, 'application event is not strict UTF-8 JSON', {}, error);
  }
  const event = exactObject(
    parsed, EVENT_FIELDS, 'Marmot application event', B33A_ERROR.INNER_EVENT_REJECTED,
  );
  assertHex('event id', event.id, 32);
  assertHex('event pubkey', event.pubkey, 32);
  if (!Number.isSafeInteger(event.created_at) || event.created_at < 0
    || !Number.isSafeInteger(event.kind) || event.kind < 0 || event.kind > 0xffff) {
    failB33a(B33A_ERROR.INNER_EVENT_REJECTED, 'event timestamp or kind is invalid');
  }
  event.tags = normalizeTags(event.tags);
  event.content = assertBoundedString('event content', event.content, B33A_LIMITS.maxContentBytes);
  const canonical = canonicalJsonBytes(event);
  if (!Buffer.from(canonical).equals(Buffer.from(bytes))) {
    failB33a(B33A_ERROR.INNER_EVENT_REJECTED,
      'application event is not the exact canonical JSON encoding');
  }
  if (nip01EventId(event) !== event.id) {
    failB33a(B33A_ERROR.INNER_EVENT_REJECTED, 'application event id is invalid');
  }
  if (event.pubkey !== expectedSenderIdentityHex) {
    failB33a(B33A_ERROR.INNER_EVENT_REJECTED,
      'application event pubkey differs from the MLS-authenticated sender');
  }
  return Object.freeze({ ...event, tags: Object.freeze(event.tags.map(Object.freeze)) });
}

export function encodeMarmotAppEvent(fields) {
  const value = exactObject(
    fields, ['pubkey', 'created_at', 'kind', 'tags', 'content'], 'event fields',
  );
  const unsigned = {
    pubkey: value.pubkey,
    created_at: value.created_at,
    kind: value.kind,
    tags: value.tags,
    content: value.content,
  };
  const event = {
    id: nip01EventId(unsigned),
    ...unsigned,
  };
  const bytes = canonicalJsonBytes(event);
  decodeMarmotAppEvent(bytes, event.pubkey);
  return bytes;
}
