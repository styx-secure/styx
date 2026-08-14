// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — isolated Phase B3.2 evidence only.

import { createHash } from 'node:crypto';

import { verifyAccountIdentityProofV2 } from '../marmot-phase-b1/identity-proof-v2.js';
import {
  B31_FOUNDING_DESCRIPTION,
  B31_FOUNDING_NAME,
  B31_LEAF_COMPONENT_IDS,
  B31_REQUIRED_COMPONENT_IDS,
  B31_SUPPORTED_COMPONENT_IDS,
  assertExactComponentIds,
} from '../marmot-phase-b3-1/b3-1-canonical.mjs';
import {
  B24_ACTIVE_LIFECYCLE_HEX,
} from '../marmot-phase-b2-4/b2-4-canonical.mjs';
import { decodeB24AdministratorPolicy } from '../marmot-phase-b2-4/b2-4-policy.mjs';

export const B32_FORMAT = 'styx-marmot-openmls-b3-2';
export const B32_VERSION = 1;
export const B32_PROJECTION_DOMAIN = 'STYX-B32-JOIN-PROJECTION-v1';
export const B32_PROJECTION_VERSION = 1;
export const B32_BASE_SHA = '019da38921deca8b9bb9a4ca6544c827db8ef3ac';
export const B32_BASE_TREE = 'fa593e0aa61889e98005ff402b3bc0aedcfa4f4c';
export const B32_OPENMLS_REVISION = '09e92777dba0528d3d29e2e5e681b7e91637c7be';
export const B32_MARMOT_REVISION = '4ad4ae21479c3f3fa9950c6fc4556a76941a62e1';
export const B32_MDK_REVISION = '9396adb6aa6b95b521a7979facd5ea7040c07288';
export const B32_RUN_ROOT = '/home/mverde/.local/share/styx-b3-2-runs/issue-173';
export const B32_PRIVATE_ROOT = '/home/mverde/.local/share/styx-b3-2-private/issue-173';

export const B32_STATE = Object.freeze({
  STABLE_ADVERTISED: 'STABLE_ADVERTISED',
  WELCOME_RECORDED: 'WELCOME_RECORDED',
  JOINED: 'JOINED',
});

export const B32_LIMITS = Object.freeze({
  maxProviderBytes: 8 * 1024 * 1024,
  maxJournalHeadBytes: 512 * 1024,
  maxWelcomeBytes: 1024 * 1024,
  maxKeyPackageBytes: 16 * 1024,
  maxGroupIdBytes: 64,
  maxMembers: 16,
  maxProfileNameBytes: 256,
  maxProfileDescriptionBytes: 4096,
});

export const B32_ERROR = Object.freeze({
  INVALID: 'B32_INVALID',
  CORRUPT: 'B32_CORRUPT',
  NOT_FOUND: 'B32_NOT_FOUND',
  CAS_CONFLICT: 'B32_CAS_CONFLICT',
  STATE_CONFLICT: 'B32_STATE_CONFLICT',
  DUPLICATE_REPLAY: 'B32_DUPLICATE_REPLAY',
  RESOURCE_LIMIT: 'B32_RESOURCE_LIMIT',
  PERSISTENCE_FAILED: 'B32_PERSISTENCE_FAILED',
  ENGINE_REJECTED: 'B32_ENGINE_REJECTED',
  PROJECTION_MISMATCH: 'B32_PROJECTION_MISMATCH',
  POLICY_REJECTED: 'B32_POLICY_REJECTED',
});

const PROJECTION_FIELDS = Object.freeze([
  'domain', 'version', 'groupIdHex', 'epochDec', 'ciphersuiteId', 'members',
  'ownLeafIndex', 'welcomeAuthor', 'requiredComponentIds', 'profile',
  'administratorPolicyHex', 'lifecycleHex', 'groupContextTlsHex',
  'groupContextSha256Hex', 'verifiedLeafDigestHex', 'welcomeSha256Hex',
  'expectedKeyPackageSha256Hex', 'predecessorStateSha256Hex',
  'candidateStateSha256Hex', 'nativeProjectionSha256Hex',
]);
const MEMBER_FIELDS = Object.freeze([
  'leafIndex', 'identityHex', 'signatureKeyHex', 'identityProofHex',
  'componentIds', 'supportedComponentIds',
]);
const AUTHOR_FIELDS = Object.freeze(['leafIndex', 'identityHex', 'signatureKeyHex']);
const PROFILE_FIELDS = Object.freeze(['nameHex', 'descriptionHex']);
const MAX_U64 = (1n << 64n) - 1n;
const UTF8 = new TextDecoder('utf-8', { fatal: true });

export class B32Error extends Error {
  constructor(code, message, details = {}, options = {}) {
    super(`${code}: ${message}`, 'cause' in options ? { cause: options.cause } : undefined);
    this.name = 'B32Error';
    this.code = code;
    this.details = Object.freeze({ ...details });
  }
}

export function failB32(code, message, details, cause) {
  throw new B32Error(code, message, details, cause === undefined ? {} : { cause });
}

export function isPlainDataObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/** Snapshot a hostile object without invoking getters or toJSON hooks. */
export function snapshotClosedObject(value, fields, label) {
  if (!isPlainDataObject(value)) failB32(B32_ERROR.INVALID, `${label} must be a plain object`);
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== 'string')
    || keys.length !== fields.length
    || keys.some((key) => !fields.includes(key))) {
    failB32(B32_ERROR.INVALID, `${label} fields are not exact`);
  }
  const out = {};
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) {
      failB32(B32_ERROR.INVALID, `${label} contains a missing or accessor field`);
    }
    out[field] = descriptor.value;
  }
  return out;
}

export function assertSafeInteger(label, value, min = 0, max = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    failB32(B32_ERROR.INVALID, `${label} must be a bounded safe integer`);
  }
  return value;
}

export function assertBytes(label, value, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  if (!(value instanceof Uint8Array) || value.length < min || value.length > max) {
    failB32(B32_ERROR.RESOURCE_LIMIT, `${label} must be a bounded Uint8Array`);
  }
  return value;
}

export function bytesEqual(left, right) {
  if (!(left instanceof Uint8Array) || !(right instanceof Uint8Array)
    || left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left[index] ^ right[index];
  return difference === 0;
}

export function bytesToHex(bytes) {
  assertBytes('bytes', bytes);
  return Buffer.from(bytes).toString('hex');
}

export function hexToBytes(label, value, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  if (typeof value !== 'string' || value.length % 2 !== 0
    || (value.length > 0 && !/^[0-9a-f]+$/.test(value))) {
    failB32(B32_ERROR.INVALID, `${label} must be lowercase hexadecimal`);
  }
  const bytes = Uint8Array.from(Buffer.from(value, 'hex'));
  return assertBytes(label, bytes, { min, max });
}

export function assertHexBytes(label, value, bytes) {
  return hexToBytes(label, value, { min: bytes, max: bytes });
}

export function assertDigest(label, value) {
  assertHexBytes(label, value, 32);
  return value;
}

export function sha256Hex(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
  }
  return value;
}

export function canonicalJsonBytes(value) {
  return Uint8Array.from(Buffer.from(`${JSON.stringify(canonicalize(value))}\n`, 'utf8'));
}

export function appendB32Transcript(transcript, operation, evidence) {
  if (!Array.isArray(transcript) || typeof operation !== 'string' || operation.length < 1) {
    failB32(B32_ERROR.INVALID, 'transcript append arguments are invalid');
  }
  const previousRecordSha256 = transcript.length === 0
    ? '0'.repeat(64)
    : transcript[transcript.length - 1].recordSha256;
  const payload = {
    sequence: transcript.length + 1,
    operation,
    previousRecordSha256,
    evidence,
  };
  const record = Object.freeze({
    ...payload,
    recordSha256: sha256Hex(canonicalJsonBytes(payload)),
  });
  transcript.push(record);
  return evidence;
}

export function validateB32Transcript(transcript) {
  if (!Array.isArray(transcript) || transcript.length < 1) {
    failB32(B32_ERROR.INVALID, 'transcript must be non-empty');
  }
  let previous = '0'.repeat(64);
  for (let index = 0; index < transcript.length; index += 1) {
    const record = snapshotClosedObject(transcript[index], [
      'sequence', 'operation', 'previousRecordSha256', 'evidence', 'recordSha256',
    ], `transcript record ${index + 1}`);
    if (record.sequence !== index + 1 || record.previousRecordSha256 !== previous
      || typeof record.operation !== 'string' || record.operation.length < 1) {
      failB32(B32_ERROR.CORRUPT, 'transcript sequence or chain is invalid');
    }
    assertDigest('transcript record digest', record.recordSha256);
    const expected = sha256Hex(canonicalJsonBytes({
      sequence: record.sequence,
      operation: record.operation,
      previousRecordSha256: record.previousRecordSha256,
      evidence: record.evidence,
    }));
    if (expected !== record.recordSha256) {
      failB32(B32_ERROR.CORRUPT, 'transcript digest mismatch');
    }
    previous = record.recordSha256;
  }
  return previous;
}

export function epochToDecimal(value) {
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) {
    failB32(B32_ERROR.INVALID, 'epoch must be an unsigned 64-bit bigint');
  }
  return value.toString(10);
}

export function parseEpochDecimal(value) {
  if (typeof value !== 'string' || !/^(?:0|[1-9][0-9]{0,19})$/.test(value)) {
    failB32(B32_ERROR.INVALID, 'epochDec is not canonical');
  }
  const epoch = BigInt(value);
  if (epoch > MAX_U64) failB32(B32_ERROR.INVALID, 'epochDec exceeds u64');
  return epoch;
}

function exactU16Array(label, value, expected = null) {
  if (!Array.isArray(value) || value.some((item) => !Number.isInteger(item) || item < 0 || item > 0xffff)
    || value.some((item, index) => index > 0 && value[index - 1] >= item)) {
    failB32(B32_ERROR.INVALID, `${label} must be strictly ascending unique u16 values`);
  }
  if (expected !== null) {
    try { assertExactComponentIds(value, expected, label); } catch (error) {
      failB32(B32_ERROR.POLICY_REJECTED, `${label} does not match B3.1`, {}, error);
    }
  }
  return Object.freeze([...value]);
}

function normalizeMember(value, index) {
  const member = snapshotClosedObject(value, MEMBER_FIELDS, `projection member ${index}`);
  assertSafeInteger('member leaf index', member.leafIndex, 0, 0xffffffff);
  assertHexBytes('member identity', member.identityHex, 32);
  assertHexBytes('member signature key', member.signatureKeyHex, 32);
  assertHexBytes('member identity proof', member.identityProofHex, 104);
  const componentIds = exactU16Array('member component ids', member.componentIds, B31_LEAF_COMPONENT_IDS);
  const supportedComponentIds = exactU16Array(
    'member supported component ids', member.supportedComponentIds, B31_SUPPORTED_COMPONENT_IDS,
  );
  try {
    verifyAccountIdentityProofV2(
      hexToBytes('member proof', member.identityProofHex),
      hexToBytes('member identity', member.identityHex),
      hexToBytes('member signature key', member.signatureKeyHex),
    );
  } catch (error) {
    failB32(B32_ERROR.POLICY_REJECTED, 'member account-identity-proof v2 is invalid', {
      leafIndex: member.leafIndex,
    }, error);
  }
  return Object.freeze({ ...member, componentIds, supportedComponentIds });
}

function normalizeProfile(value) {
  const profile = snapshotClosedObject(value, PROFILE_FIELDS, 'group profile');
  const name = hexToBytes('group profile name', profile.nameHex, {
    max: B32_LIMITS.maxProfileNameBytes,
  });
  const description = hexToBytes('group profile description', profile.descriptionHex, {
    max: B32_LIMITS.maxProfileDescriptionBytes,
  });
  try {
    if (UTF8.decode(name) !== B31_FOUNDING_NAME || UTF8.decode(description) !== B31_FOUNDING_DESCRIPTION) {
      failB32(B32_ERROR.POLICY_REJECTED, 'group profile text differs from B3.1');
    }
  } catch (error) {
    if (error instanceof B32Error) throw error;
    failB32(B32_ERROR.INVALID, 'group profile is not strict UTF-8', {}, error);
  }
  return Object.freeze({ ...profile });
}

export function normalizeB32Projection(value) {
  const projection = snapshotClosedObject(value, PROJECTION_FIELDS, 'B3.2 projection');
  if (projection.domain !== B32_PROJECTION_DOMAIN || projection.version !== B32_PROJECTION_VERSION) {
    failB32(B32_ERROR.INVALID, 'projection domain or version is invalid');
  }
  hexToBytes('group id', projection.groupIdHex, { min: 1, max: B32_LIMITS.maxGroupIdBytes });
  parseEpochDecimal(projection.epochDec);
  if (projection.ciphersuiteId !== 1) {
    failB32(B32_ERROR.POLICY_REJECTED, 'projection ciphersuite is not 0x0001');
  }
  if (!Array.isArray(projection.members) || projection.members.length < 2
    || projection.members.length > B32_LIMITS.maxMembers) {
    failB32(B32_ERROR.RESOURCE_LIMIT, 'projection member count is outside the B3.2 envelope');
  }
  const members = [];
  const identities = new Set();
  let priorLeaf = -1;
  for (let index = 0; index < projection.members.length; index += 1) {
    const member = normalizeMember(projection.members[index], index);
    if (member.leafIndex <= priorLeaf || identities.has(member.identityHex)) {
      failB32(B32_ERROR.POLICY_REJECTED, 'projection members are not uniquely ordered');
    }
    priorLeaf = member.leafIndex;
    identities.add(member.identityHex);
    members.push(member);
  }
  assertSafeInteger('own leaf index', projection.ownLeafIndex, 0, 0xffffffff);
  const own = members.find((member) => member.leafIndex === projection.ownLeafIndex);
  if (!own) failB32(B32_ERROR.POLICY_REJECTED, 'own leaf is absent from projection');

  const author = snapshotClosedObject(projection.welcomeAuthor, AUTHOR_FIELDS, 'Welcome author');
  assertSafeInteger('Welcome author leaf index', author.leafIndex, 0, 0xffffffff);
  assertHexBytes('Welcome author identity', author.identityHex, 32);
  assertHexBytes('Welcome author signature key', author.signatureKeyHex, 32);
  const authorMember = members.find((member) => member.leafIndex === author.leafIndex);
  if (!authorMember || authorMember.identityHex !== author.identityHex
    || authorMember.signatureKeyHex !== author.signatureKeyHex) {
    failB32(B32_ERROR.POLICY_REJECTED, 'authenticated Welcome author is not the projected member');
  }
  const requiredComponentIds = exactU16Array(
    'required components', projection.requiredComponentIds, B31_REQUIRED_COMPONENT_IDS,
  );
  const profile = normalizeProfile(projection.profile);
  const admins = decodeB24AdministratorPolicy(projection.administratorPolicyHex);
  if (!admins.includes(author.identityHex)) {
    failB32(B32_ERROR.POLICY_REJECTED, 'authenticated Welcome author is not an active administrator');
  }
  if (projection.lifecycleHex !== B24_ACTIVE_LIFECYCLE_HEX) {
    failB32(B32_ERROR.POLICY_REJECTED, 'joined group lifecycle is not active');
  }
  hexToBytes('GroupContext TLS', projection.groupContextTlsHex, { min: 1, max: 64 * 1024 });
  for (const [label, digest] of [
    ['GroupContext digest', projection.groupContextSha256Hex],
    ['verified-leaf digest', projection.verifiedLeafDigestHex],
    ['Welcome digest', projection.welcomeSha256Hex],
    ['expected KeyPackage digest', projection.expectedKeyPackageSha256Hex],
    ['predecessor state digest', projection.predecessorStateSha256Hex],
    ['candidate state digest', projection.candidateStateSha256Hex],
    ['native projection digest', projection.nativeProjectionSha256Hex],
  ]) assertDigest(label, digest);
  if (sha256Hex(hexToBytes('GroupContext TLS', projection.groupContextTlsHex))
    !== projection.groupContextSha256Hex) {
    failB32(B32_ERROR.PROJECTION_MISMATCH, 'GroupContext bytes and digest disagree');
  }
  return Object.freeze({
    ...projection,
    members: Object.freeze(members),
    welcomeAuthor: Object.freeze({ ...author }),
    requiredComponentIds,
    profile,
  });
}

function nativeBytes(value) {
  return Uint8Array.from(value);
}

export function projectB32Native(nativeProjection) {
  try {
    const members = [];
    const count = nativeProjection.member_count();
    assertSafeInteger('native member count', count, 2, B32_LIMITS.maxMembers);
    for (let index = 0; index < count; index += 1) {
      members.push({
        leafIndex: nativeProjection.member_leaf_index(index),
        identityHex: bytesToHex(nativeBytes(nativeProjection.member_identity(index))),
        signatureKeyHex: bytesToHex(nativeBytes(nativeProjection.member_signature_key(index))),
        identityProofHex: bytesToHex(nativeBytes(nativeProjection.member_identity_proof(index))),
        componentIds: [...nativeProjection.member_component_ids(index)],
        supportedComponentIds: [...nativeProjection.member_supported_component_ids(index)],
      });
    }
    return normalizeB32Projection({
      domain: nativeProjection.domain(),
      version: nativeProjection.version(),
      groupIdHex: bytesToHex(nativeBytes(nativeProjection.group_id())),
      epochDec: epochToDecimal(nativeProjection.epoch()),
      ciphersuiteId: nativeProjection.ciphersuite_id(),
      members,
      ownLeafIndex: nativeProjection.own_leaf_index(),
      welcomeAuthor: {
        leafIndex: nativeProjection.welcome_sender_leaf_index(),
        identityHex: bytesToHex(nativeBytes(nativeProjection.welcome_sender_identity())),
        signatureKeyHex: bytesToHex(nativeBytes(nativeProjection.welcome_sender_signature_key())),
      },
      requiredComponentIds: [...nativeProjection.required_component_ids()],
      profile: {
        nameHex: bytesToHex(nativeBytes(nativeProjection.group_profile_name())),
        descriptionHex: bytesToHex(nativeBytes(nativeProjection.group_profile_description())),
      },
      administratorPolicyHex: bytesToHex(nativeBytes(nativeProjection.administrator_policy())),
      lifecycleHex: bytesToHex(nativeBytes(nativeProjection.lifecycle())),
      groupContextTlsHex: bytesToHex(nativeBytes(nativeProjection.group_context_tls())),
      groupContextSha256Hex: bytesToHex(nativeBytes(nativeProjection.group_context_sha256())),
      verifiedLeafDigestHex: bytesToHex(nativeBytes(nativeProjection.verified_leaf_digest())),
      welcomeSha256Hex: bytesToHex(nativeBytes(nativeProjection.welcome_sha256())),
      expectedKeyPackageSha256Hex: bytesToHex(nativeBytes(nativeProjection.expected_key_package_sha256())),
      predecessorStateSha256Hex: bytesToHex(nativeBytes(nativeProjection.predecessor_state_sha256())),
      candidateStateSha256Hex: bytesToHex(nativeBytes(nativeProjection.candidate_state_sha256())),
      nativeProjectionSha256Hex: bytesToHex(nativeBytes(nativeProjection.projection_sha256())),
    });
  } catch (error) {
    if (error instanceof B32Error) throw error;
    failB32(B32_ERROR.ENGINE_REJECTED, 'native B3.2 projection failed closed', {}, error);
  }
}

export function b32ProjectionBytes(value) {
  return canonicalJsonBytes(normalizeB32Projection(value));
}

export function b32ProjectionRecordSha256(value) {
  return sha256Hex(b32ProjectionBytes(value));
}
