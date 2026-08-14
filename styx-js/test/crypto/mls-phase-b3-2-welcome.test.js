// SPDX-License-Identifier: AGPL-3.0-or-later

import { createHash, randomBytes } from 'node:crypto';

import { schnorr } from '@noble/curves/secp256k1';

import { createAccountIdentityProofV2 } from '../../spikes/marmot-phase-b1/identity-proof-v2.js';
import {
  B31_FOUNDING_DESCRIPTION,
  B31_FOUNDING_NAME,
  B31_LEAF_COMPONENT_IDS,
  B31_REQUIRED_COMPONENT_IDS,
  B31_SUPPORTED_COMPONENT_IDS,
} from '../../spikes/marmot-phase-b3-1/b3-1-canonical.mjs';
import {
  B32_ERROR,
  B32_PROJECTION_DOMAIN,
  B32_PROJECTION_VERSION,
  B32_STATE,
  b32ProjectionRecordSha256,
  normalizeB32Projection,
  projectB32Native,
  sha256Hex,
} from '../../spikes/marmot-phase-b3-2/b3-2-canonical.mjs';
import {
  B32Journal,
  MemoryB32Store,
} from '../../spikes/marmot-phase-b3-2/b3-2-journal.mjs';

const encoder = new TextEncoder();

function privateKey() {
  for (;;) {
    const bytes = Uint8Array.from(randomBytes(32));
    try {
      schnorr.getPublicKey(bytes);
      return bytes;
    } catch {
      // Rejection sampling for the negligible invalid-scalar case.
    }
  }
}

function member(leafIndex) {
  const secret = privateKey();
  const identity = Uint8Array.from(schnorr.getPublicKey(secret));
  const signatureKey = Uint8Array.from(randomBytes(32));
  const proof = createAccountIdentityProofV2(secret, signatureKey, 1_786_680_000 + leafIndex);
  return Object.freeze({
    leafIndex,
    identityHex: Buffer.from(identity).toString('hex'),
    signatureKeyHex: Buffer.from(signatureKey).toString('hex'),
    identityProofHex: Buffer.from(proof).toString('hex'),
    componentIds: [...B31_LEAF_COMPONENT_IDS],
    supportedComponentIds: [...B31_SUPPORTED_COMPONENT_IDS],
  });
}

function adminPolicyHex(accountHex) {
  return `20${accountHex}`;
}

function fixture() {
  const founder = member(0);
  const joiner = member(1);
  const predecessor = Uint8Array.from(randomBytes(2048));
  const keyPackage = Uint8Array.from(randomBytes(435));
  const welcome = Uint8Array.from(randomBytes(1024));
  const candidate = Uint8Array.from(randomBytes(3072));
  const groupContext = Uint8Array.from(randomBytes(160));
  const digest = (value) => createHash('sha256').update(value).digest('hex');
  const projection = {
    domain: B32_PROJECTION_DOMAIN,
    version: B32_PROJECTION_VERSION,
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
    administratorPolicyHex: adminPolicyHex(founder.identityHex),
    lifecycleHex: '00',
    groupContextTlsHex: Buffer.from(groupContext).toString('hex'),
    groupContextSha256Hex: digest(groupContext),
    verifiedLeafDigestHex: digest(encoder.encode('verified-leaf')),
    welcomeSha256Hex: digest(welcome),
    expectedKeyPackageSha256Hex: digest(keyPackage),
    predecessorStateSha256Hex: digest(predecessor),
    candidateStateSha256Hex: digest(candidate),
    nativeProjectionSha256Hex: digest(encoder.encode('native-projection')),
  };
  return { founder, joiner, predecessor, keyPackage, welcome, candidate, projection };
}

function nativeProjection(projection) {
  const bytes = (hex) => Uint8Array.from(Buffer.from(hex, 'hex'));
  return {
    domain: () => projection.domain,
    version: () => projection.version,
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
  };
}

async function stableJournal(values, store = new MemoryB32Store()) {
  const journal = new B32Journal(store);
  await journal.initializeStable({
    predecessorState: values.predecessor,
    keyPackage: values.keyPackage,
    accountIdentityHex: values.joiner.identityHex,
    leafSignatureKeyHex: values.joiner.signatureKeyHex,
    expectedAuthorHex: values.founder.identityHex,
  });
  return { journal, store };
}

describe('Phase B3.2 strict canonical projection', () => {
  test('validates every Schnorr proof and projects the complete native surface', () => {
    const values = fixture();
    const normalized = normalizeB32Projection(values.projection);
    expect(projectB32Native(nativeProjection(values.projection))).toEqual(normalized);
    expect(b32ProjectionRecordSha256(normalized)).toMatch(/^[0-9a-f]{64}$/);
  });

  test.each([
    ['wrong ciphersuite', (value) => { value.ciphersuiteId = 2; }],
    ['bad proof', (value) => { value.members[1].identityProofHex = '00'.repeat(104); }],
    ['non-admin author', (value) => { value.administratorPolicyHex = adminPolicyHex(value.members[1].identityHex); }],
    ['inactive lifecycle', (value) => { value.lifecycleHex = '01'; }],
    ['wrong component profile', (value) => { value.requiredComponentIds = [0x8001]; }],
    ['unknown field', (value) => { value.untrusted = true; }],
  ])('fails closed on %s', (_label, mutate) => {
    const value = structuredClone(fixture().projection);
    mutate(value);
    expect(() => normalizeB32Projection(value)).toThrow();
  });

  test('does not invoke hostile accessors', () => {
    const value = fixture().projection;
    let invoked = false;
    Object.defineProperty(value, 'domain', { get() { invoked = true; return B32_PROJECTION_DOMAIN; } });
    expect(() => normalizeB32Projection(value)).toThrow();
    expect(invoked).toBe(false);
  });
});

describe('Phase B3.2 durable activation journal', () => {
  test('linearizes only at JOINED and selects predecessor before it', async () => {
    const values = fixture();
    const { journal } = await stableJournal(values);
    let activation = await journal.activationState();
    expect(activation.state).toBe(B32_STATE.STABLE_ADVERTISED);
    expect(activation.bytes).toEqual(values.predecessor);

    const recorded = await journal.recordWelcome(values.welcome);
    expect(recorded.state).toBe(B32_STATE.WELCOME_RECORDED);
    activation = await journal.activationState();
    expect(activation.state).toBe(B32_STATE.WELCOME_RECORDED);
    expect(activation.bytes).toEqual(values.predecessor);
    expect((await journal.read()).blobs.welcomeBlobSha256Hex).toEqual(values.welcome);

    const joined = await journal.commitJoined(values.candidate, values.projection);
    expect(joined.state).toBe(B32_STATE.JOINED);
    activation = await journal.activationState();
    expect(activation.state).toBe(B32_STATE.JOINED);
    expect(activation.bytes).toEqual(values.candidate);
    expect(activation.head.projectionRecordSha256Hex)
      .toBe(b32ProjectionRecordSha256(values.projection));
  });

  test('persistence failure leaves the exact predecessor authoritative and retryable', async () => {
    const values = fixture();
    const { journal, store } = await stableJournal(values);
    store.failNext = new Error('synthetic disk failure');
    await expect(journal.recordWelcome(values.welcome)).rejects.toMatchObject({
      code: B32_ERROR.PERSISTENCE_FAILED,
    });
    const activation = await journal.activationState();
    expect(activation.state).toBe(B32_STATE.STABLE_ADVERTISED);
    expect(activation.bytes).toEqual(values.predecessor);
    await expect(journal.recordWelcome(values.welcome)).resolves.toMatchObject({
      state: B32_STATE.WELCOME_RECORDED,
    });
  });

  test('CAS race has one winner and never creates a split canonical head', async () => {
    const values = fixture();
    const { journal } = await stableJournal(values);
    const otherWelcome = Uint8Array.from(randomBytes(800));
    const outcomes = await Promise.allSettled([
      journal.recordWelcome(values.welcome),
      journal.recordWelcome(otherWelcome),
    ]);
    expect(outcomes.filter((outcome) => outcome.status === 'fulfilled')).toHaveLength(1);
    expect(outcomes.filter((outcome) => outcome.status === 'rejected')).toHaveLength(1);
    const bundle = await journal.read();
    expect(bundle.head.state).toBe(B32_STATE.WELCOME_RECORDED);
    expect([
      sha256Hex(values.welcome), sha256Hex(otherWelcome),
    ]).toContain(bundle.head.welcomeBlobSha256Hex);
  });

  test('duplicate replay and projection rebinding are typed failures', async () => {
    const values = fixture();
    const { journal } = await stableJournal(values);
    await journal.recordWelcome(values.welcome);
    await expect(journal.recordWelcome(values.welcome)).rejects.toMatchObject({
      code: B32_ERROR.DUPLICATE_REPLAY,
    });
    const rebound = { ...values.projection };
    rebound.expectedKeyPackageSha256Hex = '11'.repeat(32);
    await expect(journal.commitJoined(values.candidate, rebound)).rejects.toMatchObject({
      code: B32_ERROR.PROJECTION_MISMATCH,
    });
    const wrongOwnLeaf = { ...values.projection, ownLeafIndex: values.founder.leafIndex };
    await expect(journal.commitJoined(values.candidate, wrongOwnLeaf)).rejects.toMatchObject({
      code: B32_ERROR.PROJECTION_MISMATCH,
    });
    expect((await journal.activationState()).bytes).toEqual(values.predecessor);
  });

  test('corrupt blob and corrupt head fail closed', async () => {
    const values = fixture();
    const first = await stableJournal(values);
    first.store.blobs.set(sha256Hex(values.predecessor), Uint8Array.of(1, 2, 3));
    await expect(first.journal.read()).rejects.toMatchObject({ code: B32_ERROR.CORRUPT });

    const second = await stableJournal(values);
    second.store.head = { ...second.store.head, sequence: 99 };
    await expect(second.journal.read()).rejects.toMatchObject({ code: B32_ERROR.CORRUPT });
  });
});
