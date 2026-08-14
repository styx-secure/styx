// SPDX-License-Identifier: AGPL-3.0-or-later

import { createHash } from 'node:crypto';
import { chmodSync, mkdirSync, realpathSync, statSync } from 'node:fs';
import { relative, resolve, sep } from 'node:path';

export const B31_FORMAT = 'styx-marmot-openmls-b3-1';
export const B31_VERSION = 1;
export const B31_BASE_SHA = 'a69df78c720bc679840172f68a68327ef603636c';
export const B31_BASE_TREE = '1fe41c7b11d8c2637933de827bc638023c3cd2f1';
export const B31_STAGE1_SHA = '7baca591c86840b45f2d7a1cb60b407dfe927130';
export const B31_STAGE1_TREE = '27ffefbb8de87c55ecb08d07d4b514ebc0801976';
export const B31_MARMOT_REVISION = '4ad4ae21479c3f3fa9950c6fc4556a76941a62e1';
export const B31_MARMOT_TREE = '10d941f358de5d9fe4ee1db75581f3e5363f5e92';
export const B31_MDK_REVISION = '9396adb6aa6b95b521a7979facd5ea7040c07288';
export const B31_MDK_TREE = 'a1145de604e616634dae9a1ef6bf5033c9c9e879';
export const B31_MDK_LOCK_SHA256 =
  'edb8c706e12934b8d94239203f73d24a2d480033c3ec6830f19d06c85a247b09';
export const B31_LOCAL_MDK_LOCK_SHA256 =
  'c42ccd8bc136421b265ee8544af260cbcdf9aa865fa7a1ace03c7c8cae257b4f';
export const B31_WASM_SHA256 =
  '26a41d86d7fd2c9ab4184344e4ff00f5eebb5bc7609ba22e98b12ce903d4a4dd';
export const B31_OPENMLS_REVISION = '09e92777dba0528d3d29e2e5e681b7e91637c7be';
export const B31_RUN_ROOT = '/home/mverde/.local/share/styx-b3-1-runs/issue-167';
export const B31_PRIVATE_ROOT = '/home/mverde/.local/share/styx-b3-1-private/issue-167';
export const B31_FOUNDING_NAME = 'Styx B3 synthetic interop';
export const B31_FOUNDING_DESCRIPTION = 'Exact-pin direct-MLS evidence only';

export const B31_GROUP_PROFILE_COMPONENT_ID = 0x8001;
export const B31_SUPPORTED_COMPONENT_IDS = Object.freeze([0x8001, 0x8003, 0x8009, 0x800c]);
export const B31_REQUIRED_COMPONENT_IDS = Object.freeze([0x8001, 0x8003, 0x8009, 0x800c]);
export const B31_GROUP_CONTEXT_COMPONENT_IDS = Object.freeze([1, 0x8001, 0x8003, 0x800c]);
export const B31_LEAF_COMPONENT_IDS = Object.freeze([1, 0x8009]);
export const B31_GROUP_PROFILE_LIMITS = Object.freeze({
  descriptionBytes: 4096,
  nameBytes: 256,
});

const fatalDecoder = new TextDecoder('utf-8', { fatal: true });

export class B31CanonicalError extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.name = 'B31CanonicalError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new B31CanonicalError(code, message);
}

export function assertBytes(value, label) {
  if (!(value instanceof Uint8Array)) fail('B31_INVALID', `${label} must be Uint8Array`);
  return value;
}

export function bytesEqual(left, right) {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

export function encodeCanonicalQuicVarint(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value >= 2 ** 53) {
    fail('B31_INVALID', 'QUIC varint must be a non-negative safe integer');
  }
  const numeric = BigInt(value);
  let width;
  let prefix;
  if (numeric < 2n ** 6n) {
    width = 1;
    prefix = 0n;
  } else if (numeric < 2n ** 14n) {
    width = 2;
    prefix = 1n << 14n;
  } else if (numeric < 2n ** 30n) {
    width = 4;
    prefix = 2n << 30n;
  } else if (numeric < 2n ** 62n) {
    width = 8;
    prefix = 3n << 62n;
  } else {
    fail('B31_RESOURCE_LIMIT', 'QUIC varint exceeds 62 bits');
  }
  let encoded = numeric | prefix;
  const bytes = new Uint8Array(width);
  for (let index = width - 1; index >= 0; index -= 1) {
    bytes[index] = Number(encoded & 0xffn);
    encoded >>= 8n;
  }
  return bytes;
}

export function decodeCanonicalQuicVarint(bytes, start = 0) {
  assertBytes(bytes, 'QUIC-varint input');
  if (!Number.isSafeInteger(start) || start < 0 || start >= bytes.length) {
    fail('B31_MALFORMED', 'truncated QUIC varint');
  }
  const width = 1 << (bytes[start] >> 6);
  if (start + width > bytes.length) fail('B31_MALFORMED', 'truncated QUIC varint');
  let value = BigInt(bytes[start] & 0x3f);
  for (let index = start + 1; index < start + width; index += 1) {
    value = (value << 8n) | BigInt(bytes[index]);
  }
  const minimum = width === 1 ? 0n : 2n ** BigInt(width === 2 ? 6 : width === 4 ? 14 : 30);
  if (value < minimum) fail('B31_NON_CANONICAL', 'QUIC varint is not minimally encoded');
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) fail('B31_RESOURCE_LIMIT', 'QUIC varint is unsafe');
  return Object.freeze({ nextOffset: start + width, value: Number(value), width });
}

function validateUtf8Field(bytes, maximum, label) {
  assertBytes(bytes, label);
  if (bytes.length > maximum) fail('B31_RESOURCE_LIMIT', `${label} exceeds ${maximum} bytes`);
  try {
    fatalDecoder.decode(bytes);
  } catch {
    fail('B31_MALFORMED', `${label} is not strict UTF-8`);
  }
}

export function encodeGroupProfileBytes(name, description) {
  validateUtf8Field(name, B31_GROUP_PROFILE_LIMITS.nameBytes, 'group-profile name');
  validateUtf8Field(
    description,
    B31_GROUP_PROFILE_LIMITS.descriptionBytes,
    'group-profile description',
  );
  const nameLength = encodeCanonicalQuicVarint(name.length);
  const descriptionLength = encodeCanonicalQuicVarint(description.length);
  const output = new Uint8Array(
    nameLength.length + name.length + descriptionLength.length + description.length,
  );
  let offset = 0;
  output.set(nameLength, offset);
  offset += nameLength.length;
  output.set(name, offset);
  offset += name.length;
  output.set(descriptionLength, offset);
  offset += descriptionLength.length;
  output.set(description, offset);
  return output;
}

export function decodeGroupProfileBytes(bytes) {
  assertBytes(bytes, 'group-profile payload');
  const nameLength = decodeCanonicalQuicVarint(bytes, 0);
  if (nameLength.value > B31_GROUP_PROFILE_LIMITS.nameBytes) {
    fail('B31_RESOURCE_LIMIT', 'group-profile name exceeds 256 bytes');
  }
  const nameEnd = nameLength.nextOffset + nameLength.value;
  if (nameEnd > bytes.length) fail('B31_MALFORMED', 'group-profile name is truncated');
  const name = bytes.slice(nameLength.nextOffset, nameEnd);
  validateUtf8Field(name, B31_GROUP_PROFILE_LIMITS.nameBytes, 'group-profile name');

  const descriptionLength = decodeCanonicalQuicVarint(bytes, nameEnd);
  if (descriptionLength.value > B31_GROUP_PROFILE_LIMITS.descriptionBytes) {
    fail('B31_RESOURCE_LIMIT', 'group-profile description exceeds 4096 bytes');
  }
  const descriptionEnd = descriptionLength.nextOffset + descriptionLength.value;
  if (descriptionEnd > bytes.length) {
    fail('B31_MALFORMED', 'group-profile description is truncated');
  }
  if (descriptionEnd !== bytes.length) fail('B31_MALFORMED', 'group-profile has trailing bytes');
  const description = bytes.slice(descriptionLength.nextOffset, descriptionEnd);
  validateUtf8Field(
    description,
    B31_GROUP_PROFILE_LIMITS.descriptionBytes,
    'group-profile description',
  );
  return Object.freeze({ description, name });
}

export function assertExactComponentIds(actual, expected, label) {
  if (!Array.isArray(actual) || actual.some((value) => !Number.isInteger(value))) {
    fail('B31_INVALID', `${label} must be an integer array`);
  }
  if (actual.length !== expected.length || actual.some((value, index) => value !== expected[index])) {
    fail('B31_PROFILE_MISMATCH', `${label} does not match the exact B3.1 profile`);
  }
  if (actual.some((value, index) => index > 0 && actual[index - 1] >= value)) {
    fail('B31_NON_CANONICAL', `${label} must be strictly ascending and unique`);
  }
  return Object.freeze([...actual]);
}

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function assertPlainObject(value, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(`${label} must be a plain object`);
  }
  if (Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError(`${label} must have the default object prototype`);
  }
  return value;
}

export function assertExactKeys(value, keys, label) {
  assertPlainObject(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])) {
    throw new TypeError(`${label} fields are not exact`);
  }
  return value;
}

export function assertLowerHex(value, byteLength, label) {
  if (typeof value !== 'string'
    || value.length !== byteLength * 2
    || !/^[0-9a-f]+$/.test(value)) {
    throw new TypeError(`${label} must be ${byteLength}-byte lowercase hex`);
  }
  return value;
}

export function hexBytes(value, label, maximumBytes = 2 * 1024 * 1024) {
  if (typeof value !== 'string'
    || value.length % 2 !== 0
    || value.length > maximumBytes * 2
    || (value.length > 0 && !/^[0-9a-f]+$/.test(value))) {
    throw new TypeError(`${label} must be bounded lowercase hex`);
  }
  return Uint8Array.from(Buffer.from(value, 'hex'));
}

export function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]),
    );
  }
  return value;
}

export function canonicalJson(value) {
  return `${JSON.stringify(canonicalize(value), null, 2)}\n`;
}

export function appendTranscript(transcript, operation, evidence) {
  const previousRecordSha256 = transcript.at(-1)?.recordSha256 ?? '0'.repeat(64);
  const record = {
    evidence: canonicalize(evidence),
    operation,
    previousRecordSha256,
    sequence: transcript.length + 1,
  };
  const frozen = Object.freeze({
    ...record,
    recordSha256: sha256(canonicalJson(record)),
  });
  transcript.push(frozen);
  return frozen.evidence;
}

export function validateTranscript(transcript) {
  if (!Array.isArray(transcript) || transcript.length === 0) {
    throw new TypeError('transcript must be a non-empty array');
  }
  let previous = '0'.repeat(64);
  for (const [index, record] of transcript.entries()) {
    assertExactKeys(
      record,
      ['evidence', 'operation', 'previousRecordSha256', 'recordSha256', 'sequence'],
      `transcript record ${index + 1}`,
    );
    if (record.sequence !== index + 1) throw new TypeError('transcript sequence is not contiguous');
    if (typeof record.operation !== 'string' || record.operation.length === 0) {
      throw new TypeError('transcript operation must be non-empty');
    }
    assertLowerHex(record.previousRecordSha256, 32, 'previous transcript digest');
    assertLowerHex(record.recordSha256, 32, 'transcript digest');
    if (record.previousRecordSha256 !== previous) throw new TypeError('transcript chain is broken');
    const expected = sha256(canonicalJson({
      evidence: record.evidence,
      operation: record.operation,
      previousRecordSha256: record.previousRecordSha256,
      sequence: record.sequence,
    }));
    if (record.recordSha256 !== expected) throw new TypeError('transcript record digest mismatch');
    previous = record.recordSha256;
  }
  return previous;
}

export function validateB31Report(report, transcriptHeadSha256) {
  assertExactKeys(report, [
    'acceptedBeforeBoundary',
    'claim',
    'compatibilityEstablished',
    'disposition',
    'firstIncompatibleOperation',
    'format',
    'profileEvidence',
    'rejectedValue',
    'testedPins',
    'transcriptHeadSha256',
    'typedOutcomes',
    'version',
  ], 'B3.1 report');
  if (report.format !== B31_FORMAT || report.version !== B31_VERSION) {
    throw new TypeError('B3.1 report identity mismatch');
  }
  if (!['NO-GO', 'BLOCKED'].includes(report.disposition)
    || report.compatibilityEstablished !== false) {
    throw new TypeError('B3.1 report must fail closed without compatibility');
  }
  if (typeof report.firstIncompatibleOperation !== 'string'
    || report.firstIncompatibleOperation.length === 0) {
    throw new TypeError('B3.1 report lacks the first incompatible operation');
  }
  assertExactKeys(report.acceptedBeforeBoundary, [
    'mdkAcceptedB31Advertisement',
    'styxDurableRestart',
    'styxDurableRestartEvidence',
    'styxInternalGroupProfileCodecValidated',
    'styxInternalGroupProfileStateSha256',
    'styxKeyPackageSha256',
    'styxSupportedComponentIdsDecodedFromEmittedBytes',
  ], 'B3.1 accepted-before-boundary evidence');
  if (report.acceptedBeforeBoundary?.styxDurableRestart !== true
    || report.acceptedBeforeBoundary?.styxInternalGroupProfileCodecValidated !== true) {
    throw new TypeError('B3.1 report lacks the independent Styx capability evidence');
  }
  const restart = report.acceptedBeforeBoundary.styxDurableRestartEvidence;
  assertExactKeys(restart, [
    'expectedLeafSignatureKeySha256',
    'providerStateCommitmentSha256',
    'restoredLeafSignatureKeySha256',
  ], 'B3.1 durable-restart evidence');
  for (const [label, digest] of [
    ['expected leaf-signature key', restart.expectedLeafSignatureKeySha256],
    ['provider-state commitment', restart.providerStateCommitmentSha256],
    ['restored leaf-signature key', restart.restoredLeafSignatureKeySha256],
    ['internal group-profile state',
      report.acceptedBeforeBoundary.styxInternalGroupProfileStateSha256],
  ]) assertLowerHex(digest, 32, label);
  if (restart.expectedLeafSignatureKeySha256 !== restart.restoredLeafSignatureKeySha256) {
    throw new TypeError('B3.1 durable-restart evidence does not preserve the leaf signature key');
  }
  if (report.firstIncompatibleOperation === 'styx_join_mdk_welcome') {
    if (report.disposition !== 'NO-GO'
      || report.acceptedBeforeBoundary?.mdkAcceptedB31Advertisement !== true
      || report.profileEvidence?.exactProfileByteEquality !== true) {
      throw new TypeError('B3.1 Welcome boundary lacks exact MDK/profile evidence');
    }
    assertExactKeys(report.typedOutcomes?.styx, [
      'boundaryLayer',
      'errorCode',
      'errorMessage',
      'errorName',
      'requiredArgument',
      'welcomeParsingAttempted',
      'welcomeSha256',
    ], 'B3.1 Styx Welcome boundary');
    if (report.typedOutcomes.styx.boundaryLayer !== 'wasm_bindgen_argument_binding'
      || report.typedOutcomes.styx.errorCode
        !== 'STYX_PUBLIC_JOIN_REQUIRES_EXTERNAL_RATCHET_TREE'
      || report.typedOutcomes.styx.requiredArgument !== 'PhaseB2RatchetTree'
      || report.typedOutcomes.styx.welcomeParsingAttempted !== false) {
      throw new TypeError('B3.1 Styx Welcome boundary is misclassified');
    }
    assertLowerHex(report.typedOutcomes.styx.welcomeSha256, 32, 'B3.1 Welcome digest');
  }
  assertLowerHex(report.transcriptHeadSha256, 32, 'report transcript head');
  if (report.transcriptHeadSha256 !== transcriptHeadSha256) {
    throw new TypeError('B3.1 report does not bind the transcript head');
  }
  if (!report.claim.includes('did not establish Styx/MDK interoperability')) {
    throw new TypeError('B3.1 report contains an invalid compatibility claim');
  }
  return report;
}

function isStrictChild(parent, child) {
  const rel = relative(parent, child);
  return rel.length > 0 && rel !== '..' && !rel.startsWith(`..${sep}`) && !rel.startsWith(sep);
}

export function prepareScopedDirectory(path, parent, mode = 0o700) {
  const absoluteParent = resolve(parent);
  mkdirSync(absoluteParent, { recursive: true, mode: 0o700 });
  chmodSync(absoluteParent, 0o700);
  const resolvedParent = realpathSync(absoluteParent);
  const candidate = resolve(path);
  if (!isStrictChild(resolvedParent, candidate)) {
    throw new Error(`refusing non-child directory ${candidate}`);
  }
  mkdirSync(candidate, { recursive: false, mode });
  chmodSync(candidate, mode);
  const real = realpathSync(candidate);
  if (!isStrictChild(resolvedParent, real) || !statSync(real).isDirectory()) {
    throw new Error(`directory escaped its approved parent: ${real}`);
  }
  return real;
}

export function assertExistingScopedDirectory(path, parent) {
  const resolvedParent = realpathSync(resolve(parent));
  const real = realpathSync(resolve(path));
  if (!isStrictChild(resolvedParent, real) || !statSync(real).isDirectory()) {
    throw new Error(`${real} is not a validated child of ${resolvedParent}`);
  }
  return real;
}
