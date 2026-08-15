// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — isolated Phase B3.2a evidence only.

import { verifyAccountIdentityProofV2 } from '../marmot-phase-b1/identity-proof-v2.js';
import {
  B31_FOUNDING_DESCRIPTION,
  B31_FOUNDING_NAME,
  B31_REQUIRED_COMPONENT_IDS,
} from '../marmot-phase-b3-1/b3-1-canonical.mjs';
import { B24_ACTIVE_LIFECYCLE_HEX } from '../marmot-phase-b2-4/b2-4-canonical.mjs';
import { decodeB24AdministratorPolicy } from '../marmot-phase-b2-4/b2-4-policy.mjs';
import {
  B32_LIMITS,
  assertBytes,
  assertDigest,
  assertHexBytes,
  assertSafeInteger,
  bytesToHex,
  canonicalJsonBytes,
  epochToDecimal,
  hexToBytes,
  parseEpochDecimal,
  sha256Hex,
  snapshotClosedObject,
} from '../marmot-phase-b3-2/b3-2-canonical.mjs';

export const B32A_FORMAT = 'styx-marmot-openmls-b3-2a';
export const B32A_VERSION = 1;
export const B32A_PROVIDER_FORMAT = 'phase-b32a-provider-canonical-v1';
export const B32A_PROJECTION_DOMAIN = 'STYX-B32A-JOIN-PROJECTION-v1';
export const B32A_PROJECTION_VERSION = 1;
export const B32A_BASE_SHA = '675aa5e0e5ec9f0fdaae308953cd4c81863d90ea';
export const B32A_BASE_TREE = '7a71c9eaa7d5713185ac3ee3986cc73c625bd06f';
export const B32A_OPENMLS_REVISION = '09e92777dba0528d3d29e2e5e681b7e91637c7be';
export const B32A_MARMOT_REVISION = '4ad4ae21479c3f3fa9950c6fc4556a76941a62e1';
export const B32A_MDK_REVISION = '9396adb6aa6b95b521a7979facd5ea7040c07288';
export const B32A_RUN_ROOT = '/home/mverde/.local/share/styx-b3-2a-runs/issue-175';
export const B32A_PRIVATE_ROOT = '/home/mverde/.local/share/styx-b3-2a-private/issue-175';

export const B32A_STATE = Object.freeze({
  STABLE_ADVERTISED: 'STABLE_ADVERTISED',
  WELCOME_RECORDED: 'WELCOME_RECORDED',
  JOINED: 'JOINED',
});

export const B32A_PROFILE = Object.freeze({
  STYX: 'STYX_B32A',
  MDK: 'MDK_PIN_9396ADB',
});

export const B32A_PREPARATION = Object.freeze({
  BYTE_IDENTICAL: 'BYTE_IDENTICAL',
  RETENTION_TIMESTAMP_BOUNDED: 'RETENTION_TIMESTAMP_BOUNDED',
});

export const B32A_ERROR = Object.freeze({
  INVALID: 'B32A_INVALID',
  CORRUPT: 'B32A_CORRUPT',
  NOT_FOUND: 'B32A_NOT_FOUND',
  CAS_CONFLICT: 'B32A_CAS_CONFLICT',
  STATE_CONFLICT: 'B32A_STATE_CONFLICT',
  DUPLICATE_REPLAY: 'B32A_DUPLICATE_REPLAY',
  RESOURCE_LIMIT: 'B32A_RESOURCE_LIMIT',
  PERSISTENCE_FAILED: 'B32A_PERSISTENCE_FAILED',
  ENGINE_REJECTED: 'B32A_ENGINE_REJECTED',
  PROJECTION_MISMATCH: 'B32A_PROJECTION_MISMATCH',
  POLICY_REJECTED: 'B32A_POLICY_REJECTED',
  PREPARATION_EVIDENCE_INVALID: 'B32A_PREPARATION_EVIDENCE_INVALID',
});

const PROJECTION_FIELDS = Object.freeze([
  'domain', 'version', 'providerFormat', 'groupIdHex', 'epochDec', 'ciphersuiteId',
  'members', 'ownLeafIndex', 'welcomeAuthor', 'requiredComponentIds', 'profile',
  'administratorPolicyHex', 'lifecycleHex', 'groupContextTlsHex',
  'groupContextSha256Hex', 'verifiedLeafDigestHex', 'welcomeSha256Hex',
  'expectedKeyPackageSha256Hex', 'predecessorStateSha256Hex',
  'candidateStateSha256Hex', 'nativeProjectionSha256Hex',
]);
const MEMBER_FIELDS = Object.freeze([
  'leafIndex', 'identityHex', 'signatureKeyHex', 'identityProofHex', 'componentIds',
  'supportedComponentIds', 'profileTag', 'profileSha256Hex',
  'listsDefaultRequiredCapabilities', 'emitsEmptySafeAad',
]);
const AUTHOR_FIELDS = Object.freeze(['leafIndex', 'identityHex', 'signatureKeyHex']);
const PROFILE_FIELDS = Object.freeze(['nameHex', 'descriptionHex']);
const EVIDENCE_FIELDS = Object.freeze([
  'classification', 'secondCandidateStateSha256Hex', 'differingStorageKeyHex',
]);
const STYX_DICTIONARY_IDS = Object.freeze([0x0001, 0x8009]);
const MDK_DICTIONARY_IDS = Object.freeze([0x0001, 0x0002, 0x8009]);
const SUPPORTED_COMPONENT_IDS = Object.freeze([0x0001, 0x8001, 0x8003, 0x8009, 0x800c]);
const MESSAGE_SECRETS_PREFIX_HEX = Buffer.from('MessageSecrets', 'utf8').toString('hex');
const UTF8 = new TextDecoder('utf-8', { fatal: true });

export class B32aError extends Error {
  constructor(code, message, details = {}, options = {}) {
    super(`${code}: ${message}`, 'cause' in options ? { cause: options.cause } : undefined);
    this.name = 'B32aError';
    this.code = code;
    this.details = Object.freeze({ ...details });
  }
}

export function failB32a(code, message, details, cause) {
  throw new B32aError(code, message, details, cause === undefined ? {} : { cause });
}

function exactU16Array(label, value, expected) {
  if (!Array.isArray(value) || value.length !== expected.length
    || value.some((item, index) => item !== expected[index])) {
    failB32a(B32A_ERROR.POLICY_REJECTED, `${label} does not match the exact B3.2a profile`);
  }
  return Object.freeze([...value]);
}

function normalizeMember(value, index) {
  let member;
  try {
    member = snapshotClosedObject(value, MEMBER_FIELDS, `B3.2a projection member ${index}`);
    assertSafeInteger('member leaf index', member.leafIndex, 0, 0xffffffff);
    assertHexBytes('member identity', member.identityHex, 32);
    assertHexBytes('member signature key', member.signatureKeyHex, 32);
    assertHexBytes('member identity proof', member.identityProofHex, 104);
    assertDigest('member exact profile digest', member.profileSha256Hex);
  } catch (error) {
    failB32a(B32A_ERROR.INVALID, 'member encoding is invalid', { index }, error);
  }
  const expectedDictionary = member.profileTag === B32A_PROFILE.STYX
    ? STYX_DICTIONARY_IDS
    : member.profileTag === B32A_PROFILE.MDK ? MDK_DICTIONARY_IDS : null;
  if (expectedDictionary === null) {
    failB32a(B32A_ERROR.POLICY_REJECTED, 'member profile tag is not one of the exact two profiles');
  }
  const componentIds = exactU16Array('member dictionary ids', member.componentIds, expectedDictionary);
  const supportedComponentIds = exactU16Array(
    'member supported component ids', member.supportedComponentIds, SUPPORTED_COMPONENT_IDS,
  );
  const expectedFlags = member.profileTag === B32A_PROFILE.STYX
    ? [false, false]
    : [true, true];
  if (member.listsDefaultRequiredCapabilities !== expectedFlags[0]
    || member.emitsEmptySafeAad !== expectedFlags[1]) {
    failB32a(B32A_ERROR.POLICY_REJECTED, 'member profile evidence flags disagree with its exact tag');
  }
  try {
    verifyAccountIdentityProofV2(
      hexToBytes('member proof', member.identityProofHex),
      hexToBytes('member identity', member.identityHex),
      hexToBytes('member signature key', member.signatureKeyHex),
    );
  } catch (error) {
    failB32a(B32A_ERROR.POLICY_REJECTED, 'member account-identity-proof v2 is invalid', {
      leafIndex: member.leafIndex,
    }, error);
  }
  return Object.freeze({ ...member, componentIds, supportedComponentIds });
}

function normalizeProfile(value) {
  let profile;
  try {
    profile = snapshotClosedObject(value, PROFILE_FIELDS, 'B3.2a group profile');
    const name = hexToBytes('group profile name', profile.nameHex, {
      max: B32_LIMITS.maxProfileNameBytes,
    });
    const description = hexToBytes('group profile description', profile.descriptionHex, {
      max: B32_LIMITS.maxProfileDescriptionBytes,
    });
    if (UTF8.decode(name) !== B31_FOUNDING_NAME
      || UTF8.decode(description) !== B31_FOUNDING_DESCRIPTION) {
      failB32a(B32A_ERROR.POLICY_REJECTED, 'group profile text differs from the founding profile');
    }
  } catch (error) {
    if (error instanceof B32aError) throw error;
    failB32a(B32A_ERROR.INVALID, 'group profile is not strict UTF-8', {}, error);
  }
  return Object.freeze({ ...profile });
}

export function normalizeB32aProjection(value) {
  let projection;
  try {
    projection = snapshotClosedObject(value, PROJECTION_FIELDS, 'B3.2a projection');
  } catch (error) {
    failB32a(B32A_ERROR.INVALID, 'projection fields are not exact', {}, error);
  }
  if (projection.domain !== B32A_PROJECTION_DOMAIN
    || projection.version !== B32A_PROJECTION_VERSION
    || projection.providerFormat !== B32A_PROVIDER_FORMAT) {
    failB32a(B32A_ERROR.INVALID, 'projection domain, version or Provider format is invalid');
  }
  try {
    hexToBytes('group id', projection.groupIdHex, { min: 1, max: B32_LIMITS.maxGroupIdBytes });
    parseEpochDecimal(projection.epochDec);
  } catch (error) {
    failB32a(B32A_ERROR.INVALID, 'group id or epoch is invalid', {}, error);
  }
  if (projection.ciphersuiteId !== 1 || !Array.isArray(projection.members)
    || projection.members.length !== 2) {
    failB32a(B32A_ERROR.POLICY_REJECTED, 'B3.2a requires suite 0x0001 and exactly two members');
  }
  const members = projection.members.map(normalizeMember);
  if (members[0].leafIndex >= members[1].leafIndex
    || members[0].identityHex === members[1].identityHex) {
    failB32a(B32A_ERROR.POLICY_REJECTED, 'projection members are not uniquely ordered');
  }
  try { assertSafeInteger('own leaf index', projection.ownLeafIndex, 0, 0xffffffff); } catch (error) {
    failB32a(B32A_ERROR.INVALID, 'own leaf index is invalid', {}, error);
  }
  const own = members.find((member) => member.leafIndex === projection.ownLeafIndex);
  if (!own || own.profileTag !== B32A_PROFILE.STYX) {
    failB32a(B32A_ERROR.POLICY_REJECTED, 'own leaf is absent or is not the exact Styx profile');
  }
  let author;
  try {
    author = snapshotClosedObject(projection.welcomeAuthor, AUTHOR_FIELDS, 'B3.2a Welcome author');
    assertSafeInteger('Welcome author leaf index', author.leafIndex, 0, 0xffffffff);
    assertHexBytes('Welcome author identity', author.identityHex, 32);
    assertHexBytes('Welcome author signature key', author.signatureKeyHex, 32);
  } catch (error) {
    failB32a(B32A_ERROR.INVALID, 'Welcome author encoding is invalid', {}, error);
  }
  const founder = members.find((member) => member.leafIndex === author.leafIndex);
  if (!founder || founder.profileTag !== B32A_PROFILE.MDK
    || founder.identityHex !== author.identityHex
    || founder.signatureKeyHex !== author.signatureKeyHex) {
    failB32a(B32A_ERROR.POLICY_REJECTED, 'authenticated founder is not the exact MDK profile');
  }
  const requiredComponentIds = exactU16Array(
    'required components', projection.requiredComponentIds, B31_REQUIRED_COMPONENT_IDS,
  );
  const profile = normalizeProfile(projection.profile);
  let admins;
  try { admins = decodeB24AdministratorPolicy(projection.administratorPolicyHex); } catch (error) {
    failB32a(B32A_ERROR.POLICY_REJECTED, 'administrator policy is invalid', {}, error);
  }
  if (!admins.includes(author.identityHex) || projection.lifecycleHex !== B24_ACTIVE_LIFECYCLE_HEX) {
    failB32a(B32A_ERROR.POLICY_REJECTED, 'founder is not an active administrator');
  }
  try {
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
  } catch (error) {
    failB32a(B32A_ERROR.INVALID, 'projection digest or GroupContext encoding is invalid', {}, error);
  }
  if (sha256Hex(hexToBytes('GroupContext TLS', projection.groupContextTlsHex))
    !== projection.groupContextSha256Hex) {
    failB32a(B32A_ERROR.PROJECTION_MISMATCH, 'GroupContext bytes and digest disagree');
  }
  return Object.freeze({
    ...projection,
    members: Object.freeze(members),
    welcomeAuthor: Object.freeze({ ...author }),
    requiredComponentIds,
    profile,
  });
}

export function projectB32aNative(nativeProjection) {
  try {
    const count = nativeProjection.member_count();
    if (count !== 2) failB32a(B32A_ERROR.POLICY_REJECTED, 'native projection is not two-member');
    const members = [];
    for (let index = 0; index < count; index += 1) {
      members.push({
        leafIndex: nativeProjection.member_leaf_index(index),
        identityHex: bytesToHex(Uint8Array.from(nativeProjection.member_identity(index))),
        signatureKeyHex: bytesToHex(Uint8Array.from(nativeProjection.member_signature_key(index))),
        identityProofHex: bytesToHex(Uint8Array.from(nativeProjection.member_identity_proof(index))),
        componentIds: [...nativeProjection.member_component_ids(index)],
        supportedComponentIds: [...nativeProjection.member_supported_component_ids(index)],
        profileTag: nativeProjection.member_profile(index),
        profileSha256Hex: bytesToHex(Uint8Array.from(nativeProjection.member_profile_sha256(index))),
        listsDefaultRequiredCapabilities:
          nativeProjection.member_lists_default_required_capabilities(index),
        emitsEmptySafeAad: nativeProjection.member_emits_empty_safe_aad(index),
      });
    }
    return normalizeB32aProjection({
      domain: nativeProjection.domain(),
      version: nativeProjection.version(),
      providerFormat: nativeProjection.provider_format(),
      groupIdHex: bytesToHex(Uint8Array.from(nativeProjection.group_id())),
      epochDec: epochToDecimal(nativeProjection.epoch()),
      ciphersuiteId: nativeProjection.ciphersuite_id(),
      members,
      ownLeafIndex: nativeProjection.own_leaf_index(),
      welcomeAuthor: {
        leafIndex: nativeProjection.welcome_sender_leaf_index(),
        identityHex: bytesToHex(Uint8Array.from(nativeProjection.welcome_sender_identity())),
        signatureKeyHex: bytesToHex(Uint8Array.from(nativeProjection.welcome_sender_signature_key())),
      },
      requiredComponentIds: [...nativeProjection.required_component_ids()],
      profile: {
        nameHex: bytesToHex(Uint8Array.from(nativeProjection.group_profile_name())),
        descriptionHex: bytesToHex(Uint8Array.from(nativeProjection.group_profile_description())),
      },
      administratorPolicyHex: bytesToHex(Uint8Array.from(nativeProjection.administrator_policy())),
      lifecycleHex: bytesToHex(Uint8Array.from(nativeProjection.lifecycle())),
      groupContextTlsHex: bytesToHex(Uint8Array.from(nativeProjection.group_context_tls())),
      groupContextSha256Hex: bytesToHex(Uint8Array.from(nativeProjection.group_context_sha256())),
      verifiedLeafDigestHex: bytesToHex(Uint8Array.from(nativeProjection.verified_leaf_digest())),
      welcomeSha256Hex: bytesToHex(Uint8Array.from(nativeProjection.welcome_sha256())),
      expectedKeyPackageSha256Hex:
        bytesToHex(Uint8Array.from(nativeProjection.expected_key_package_sha256())),
      predecessorStateSha256Hex:
        bytesToHex(Uint8Array.from(nativeProjection.predecessor_state_sha256())),
      candidateStateSha256Hex:
        bytesToHex(Uint8Array.from(nativeProjection.candidate_state_sha256())),
      nativeProjectionSha256Hex:
        bytesToHex(Uint8Array.from(nativeProjection.projection_sha256())),
    });
  } catch (error) {
    if (error instanceof B32aError) throw error;
    failB32a(B32A_ERROR.ENGINE_REJECTED, 'native B3.2a projection failed closed', {}, error);
  }
}

export function b32aProjectionBytes(value) {
  return canonicalJsonBytes(normalizeB32aProjection(value));
}

export function b32aProjectionRecordSha256(value) {
  return sha256Hex(b32aProjectionBytes(value));
}

export function normalizeB32aPreparationEvidence(value, candidateStateSha256Hex) {
  let evidence;
  try {
    evidence = snapshotClosedObject(value, EVIDENCE_FIELDS, 'B3.2a preparation evidence');
    assertDigest('winning candidate digest', candidateStateSha256Hex);
    assertDigest('second candidate digest', evidence.secondCandidateStateSha256Hex);
  } catch (error) {
    failB32a(B32A_ERROR.PREPARATION_EVIDENCE_INVALID, 'preparation evidence fields are invalid', {}, error);
  }
  if (typeof evidence.differingStorageKeyHex !== 'string'
    || evidence.differingStorageKeyHex.length % 2 !== 0
    || !/^[0-9a-f]*$/.test(evidence.differingStorageKeyHex)
    || evidence.differingStorageKeyHex.length > 128 * 1024) {
    failB32a(B32A_ERROR.PREPARATION_EVIDENCE_INVALID, 'differing storage key is invalid');
  }
  if (evidence.classification === B32A_PREPARATION.BYTE_IDENTICAL) {
    if (evidence.differingStorageKeyHex !== ''
      || evidence.secondCandidateStateSha256Hex !== candidateStateSha256Hex) {
      failB32a(B32A_ERROR.PREPARATION_EVIDENCE_INVALID, 'byte-identical evidence is incoherent');
    }
  } else if (evidence.classification === B32A_PREPARATION.RETENTION_TIMESTAMP_BOUNDED) {
    if (!evidence.differingStorageKeyHex.startsWith(MESSAGE_SECRETS_PREFIX_HEX)
      || evidence.secondCandidateStateSha256Hex === candidateStateSha256Hex) {
      failB32a(B32A_ERROR.PREPARATION_EVIDENCE_INVALID, 'bounded timestamp evidence is incoherent');
    }
  } else {
    failB32a(B32A_ERROR.PREPARATION_EVIDENCE_INVALID, 'preparation classification is unknown');
  }
  return Object.freeze({ ...evidence });
}

export function clearBytes(value) {
  if (value instanceof Uint8Array) value.fill(0);
}

export { B32_LIMITS, assertBytes, bytesToHex, canonicalJsonBytes, hexToBytes, sha256Hex };
