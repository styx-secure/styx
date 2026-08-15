// SPDX-License-Identifier: AGPL-3.0-or-later
// Test-only synthetic support. No upstream fixture or real identity data.

import { createHash, randomBytes } from 'node:crypto';
import { schnorr } from '@noble/curves/secp256k1';

import { createAccountIdentityProofV2 } from '../marmot-phase-b1/identity-proof-v2.js';
import {
  B31_FOUNDING_DESCRIPTION,
  B31_FOUNDING_NAME,
  B31_REQUIRED_COMPONENT_IDS,
} from '../marmot-phase-b3-1/b3-1-canonical.mjs';
import {
  B32A_PROFILE,
  B32A_PROJECTION_DOMAIN,
  B32A_PROJECTION_VERSION,
  B32A_PROVIDER_FORMAT,
} from './b3-2a-canonical.mjs';

const encoder = new TextEncoder();
const SUPPORTED = [0x0001, 0x8001, 0x8003, 0x8009, 0x800c];

function privateKey() {
  for (;;) {
    const bytes = Uint8Array.from(randomBytes(32));
    try { schnorr.getPublicKey(bytes); return bytes; } catch { /* rejection sampling */ }
  }
}

function member(leafIndex, profileTag) {
  const secret = privateKey();
  const identity = Uint8Array.from(schnorr.getPublicKey(secret));
  const signatureKey = Uint8Array.from(randomBytes(32));
  const proof = createAccountIdentityProofV2(secret, signatureKey, 1_786_680_000 + leafIndex);
  const mdk = profileTag === B32A_PROFILE.MDK;
  return {
    leafIndex,
    identityHex: Buffer.from(identity).toString('hex'),
    signatureKeyHex: Buffer.from(signatureKey).toString('hex'),
    identityProofHex: Buffer.from(proof).toString('hex'),
    componentIds: mdk ? [0x0001, 0x0002, 0x8009] : [0x0001, 0x8009],
    supportedComponentIds: [...SUPPORTED],
    profileTag,
    profileSha256Hex: createHash('sha256').update(`profile-${profileTag}`).digest('hex'),
    listsDefaultRequiredCapabilities: mdk,
    emitsEmptySafeAad: mdk,
  };
}

export function b32aFixture() {
  const founder = member(0, B32A_PROFILE.MDK);
  const joiner = member(1, B32A_PROFILE.STYX);
  const predecessor = Uint8Array.from(randomBytes(2048));
  const keyPackage = Uint8Array.from(randomBytes(435));
  const welcome = Uint8Array.from(randomBytes(1024));
  const candidate = Uint8Array.from(randomBytes(3072));
  const groupContext = Uint8Array.from(randomBytes(160));
  const digest = (value) => createHash('sha256').update(value).digest('hex');
  return {
    founder, joiner, predecessor, keyPackage, welcome, candidate,
    projection: {
      domain: B32A_PROJECTION_DOMAIN,
      version: B32A_PROJECTION_VERSION,
      providerFormat: B32A_PROVIDER_FORMAT,
      groupIdHex: Buffer.from(randomBytes(32)).toString('hex'),
      epochDec: '1',
      ciphersuiteId: 1,
      members: [founder, joiner],
      ownLeafIndex: 1,
      welcomeAuthor: {
        leafIndex: 0,
        identityHex: founder.identityHex,
        signatureKeyHex: founder.signatureKeyHex,
      },
      requiredComponentIds: [...B31_REQUIRED_COMPONENT_IDS],
      profile: {
        nameHex: Buffer.from(encoder.encode(B31_FOUNDING_NAME)).toString('hex'),
        descriptionHex: Buffer.from(encoder.encode(B31_FOUNDING_DESCRIPTION)).toString('hex'),
      },
      administratorPolicyHex: `20${founder.identityHex}`,
      lifecycleHex: '00',
      groupContextTlsHex: Buffer.from(groupContext).toString('hex'),
      groupContextSha256Hex: digest(groupContext),
      verifiedLeafDigestHex: digest(encoder.encode('verified-leaf')),
      welcomeSha256Hex: digest(welcome),
      expectedKeyPackageSha256Hex: digest(keyPackage),
      predecessorStateSha256Hex: digest(predecessor),
      candidateStateSha256Hex: digest(candidate),
      nativeProjectionSha256Hex: digest(encoder.encode('native-projection')),
    },
  };
}

export function fakeNativeProjection(projection) {
  const bytes = (hex) => Uint8Array.from(Buffer.from(hex, 'hex'));
  return {
    domain: () => projection.domain,
    version: () => projection.version,
    provider_format: () => projection.providerFormat,
    group_id: () => bytes(projection.groupIdHex),
    epoch: () => BigInt(projection.epochDec),
    ciphersuite_id: () => projection.ciphersuiteId,
    member_count: () => projection.members.length,
    member_leaf_index: (index) => projection.members[index].leafIndex,
    member_identity: (index) => bytes(projection.members[index].identityHex),
    member_signature_key: (index) => bytes(projection.members[index].signatureKeyHex),
    member_identity_proof: (index) => bytes(projection.members[index].identityProofHex),
    member_component_ids: (index) => Uint16Array.from(projection.members[index].componentIds),
    member_supported_component_ids: (index) => (
      Uint16Array.from(projection.members[index].supportedComponentIds)
    ),
    member_profile: (index) => projection.members[index].profileTag,
    member_profile_sha256: (index) => bytes(projection.members[index].profileSha256Hex),
    member_lists_default_required_capabilities: (index) => (
      projection.members[index].listsDefaultRequiredCapabilities
    ),
    member_emits_empty_safe_aad: (index) => projection.members[index].emitsEmptySafeAad,
    own_leaf_index: () => projection.ownLeafIndex,
    welcome_sender_leaf_index: () => projection.welcomeAuthor.leafIndex,
    welcome_sender_identity: () => bytes(projection.welcomeAuthor.identityHex),
    welcome_sender_signature_key: () => bytes(projection.welcomeAuthor.signatureKeyHex),
    required_component_ids: () => Uint16Array.from(projection.requiredComponentIds),
    group_profile_name: () => bytes(projection.profile.nameHex),
    group_profile_description: () => bytes(projection.profile.descriptionHex),
    administrator_policy: () => bytes(projection.administratorPolicyHex),
    lifecycle: () => bytes(projection.lifecycleHex),
    group_context_tls: () => bytes(projection.groupContextTlsHex),
    group_context_sha256: () => bytes(projection.groupContextSha256Hex),
    verified_leaf_digest: () => bytes(projection.verifiedLeafDigestHex),
    welcome_sha256: () => bytes(projection.welcomeSha256Hex),
    expected_key_package_sha256: () => bytes(projection.expectedKeyPackageSha256Hex),
    predecessor_state_sha256: () => bytes(projection.predecessorStateSha256Hex),
    candidate_state_sha256: () => bytes(projection.candidateStateSha256Hex),
    projection_sha256: () => bytes(projection.nativeProjectionSha256Hex),
    free() {},
  };
}
