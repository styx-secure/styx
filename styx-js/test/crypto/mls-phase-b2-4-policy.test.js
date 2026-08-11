import { describe, expect, test } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { schnorr } from '@noble/curves/secp256k1';

import {
  B23_ERROR,
  B23_STORES,
  bytesToHex,
  digestHex,
  hexToBytes,
} from '../../spikes/marmot-phase-b2-3/b2-3-canonical.mjs';
import {
  createAccountIdentityProofV2,
} from '../../spikes/marmot-phase-b1/identity-proof-v2.js';
import { B23EngineAdapter } from '../../spikes/marmot-phase-b2-3/b2-3-engine-adapter.mjs';
import {
  B24_DB_PREFIX,
  B24_ERROR,
  B24_PARENT_FORMAT,
  B24_POLICY_VERSION,
  B24_REASON,
  B24_REQUIRED_COMPONENT_IDS,
} from '../../spikes/marmot-phase-b2-4/b2-4-canonical.mjs';
import {
  decodeB24AdministratorPolicy,
  evaluateB24Authorization,
  verifyB24DecisionBinding,
} from '../../spikes/marmot-phase-b2-4/b2-4-policy.mjs';
import {
  B24Journal,
  createB24JournalForDb,
} from '../../spikes/marmot-phase-b2-4/b2-4-journal.mjs';
import { B24EngineAdapter } from '../../spikes/marmot-phase-b2-4/b2-4-engine-adapter.mjs';
import { FakeVaultDb } from '../support/fake-vault-db.js';

const GROUP = 'ab'.repeat(32);
const PARENT_CONTEXT = 'cd'.repeat(32);
const COMPONENT_IDS = Object.freeze([1, 32777]);
const SUPPORTED_IDS = B24_REQUIRED_COMPONENT_IDS;
const COMMIT = Uint8Array.of(1, 2, 3, 4);

function peer(seed, leafIndex, createdAt = 1) {
  const privateKey = new Uint8Array(32);
  privateKey[31] = seed;
  const identity = Uint8Array.from(schnorr.getPublicKey(privateKey));
  const signatureKey = new Uint8Array(32).fill(0x40 + seed);
  const proof = createAccountIdentityProofV2(privateKey, signatureKey, createdAt);
  return Object.freeze({
    privateKey,
    leafIndex,
    identityHex: bytesToHex(identity),
    signatureKeyHex: bytesToHex(signatureKey),
    identityProofHex: bytesToHex(proof),
  });
}

const ALICE = peer(1, 0);
const BOB = peer(2, 1);
const CHARLIE = peer(3, 2);

function vlBytes(payload) {
  const length = payload.length;
  let prefix;
  if (length < 64) prefix = Uint8Array.of(length);
  else if (length < 16384) prefix = Uint8Array.of(0x40 | (length >> 8), length & 0xff);
  else throw new Error('test payload is too large');
  const out = new Uint8Array(prefix.length + payload.length);
  out.set(prefix);
  out.set(payload, prefix.length);
  return out;
}

function adminPolicy(...accounts) {
  const sorted = [...accounts].sort();
  const payload = new Uint8Array(sorted.length * 32);
  sorted.forEach((account, index) => payload.set(hexToBytes('admin', account), index * 32));
  return bytesToHex(vlBytes(payload));
}

function parent(members = [ALICE, BOB], admins = [ALICE.identityHex]) {
  return {
    format: B24_PARENT_FORMAT,
    version: B24_POLICY_VERSION,
    groupIdHex: GROUP,
    epochDec: '7',
    groupContextDigestHex: PARENT_CONTEXT,
    administratorPolicyHex: adminPolicy(...admins),
    lifecycleHex: '00',
    requiredComponentIds: [...B24_REQUIRED_COMPONENT_IDS],
    members: members.map((member) => ({
      leafIndex: member.leafIndex,
      identityHex: member.identityHex,
      signatureKeyHex: member.signatureKeyHex,
      identityProofHex: member.identityProofHex,
    })),
  };
}

function candidateMember(member) {
  return {
    leafIndex: member.leafIndex,
    identityHex: member.identityHex,
    signatureKeyHex: member.signatureKeyHex,
    identityProofHex: member.identityProofHex,
    componentIds: [...COMPONENT_IDS],
    supportedComponentIds: [...SUPPORTED_IDS],
  };
}

function updatePath(member) {
  return candidateMember(member);
}

function candidate({
  members = [ALICE, BOB],
  committer = ALICE,
  proposals = [],
  path = updatePath(committer),
  policy = adminPolicy(ALICE.identityHex),
  lifecycle = '00',
  required = [...B24_REQUIRED_COMPONENT_IDS],
  priorEpochDec = '7',
  candidateEpochDec = '8',
  tlsByte = 0x66,
} = {}) {
  const tls = Uint8Array.of(tlsByte);
  return {
    format: 'styx-b2-3-projection',
    version: 1,
    priorEpochDec,
    candidateEpochDec,
    committerSource: 'member',
    committerLeafIndex: committer.leafIndex,
    committerIdentityHex: committer.identityHex,
    committerSignatureKeyHex: committer.signatureKeyHex,
    administratorPolicyHex: policy,
    lifecycleHex: lifecycle,
    requiredComponentIds: required,
    candidateGroupContextTlsHex: bytesToHex(tls),
    candidateGroupContextDigestHex: digestHex(tls),
    verifiedLeafDigestHex: 'ef'.repeat(32),
    candidateMembers: members.map(candidateMember),
    proposals,
    updatePath: path,
  };
}

function proposal(kind, sender, details = {}) {
  return {
    kind,
    source: 'inline',
    senderSource: 'member',
    senderLeafIndex: sender.leafIndex,
    addedLeafIndex: null,
    addedIdentityHex: null,
    addedSignatureKeyHex: null,
    addedIdentityProofHex: null,
    addedComponentIds: null,
    addedSupportedComponentIds: null,
    removedParentLeafIndex: null,
    removedIdentityHex: null,
    removedSignatureKeyHex: null,
    removedIdentityProofHex: null,
    ...details,
  };
}

function addProposal(sender, added) {
  return proposal('add', sender, {
    addedLeafIndex: added.leafIndex,
    addedIdentityHex: added.identityHex,
    addedSignatureKeyHex: added.signatureKeyHex,
    addedIdentityProofHex: added.identityProofHex,
    addedComponentIds: [...COMPONENT_IDS],
    addedSupportedComponentIds: [...SUPPORTED_IDS],
  });
}

function removeProposal(sender, removed) {
  return proposal('remove', sender, {
    removedParentLeafIndex: removed.leafIndex,
    removedIdentityHex: removed.identityHex,
    removedSignatureKeyHex: removed.signatureKeyHex,
    removedIdentityProofHex: removed.identityProofHex,
  });
}

function evaluate(parentState, candidateState, commitBytes = COMMIT) {
  return evaluateB24Authorization({
    parent: parentState, candidate: candidateState, commitBytes,
  });
}

function plainClone(value) {
  return JSON.parse(JSON.stringify(value));
}

describe('Phase B2.4 canonical authorization policy', () => {
  test('canonical administrator vectors accept sorted members and reject malformed encodings', () => {
    expect(decodeB24AdministratorPolicy(adminPolicy(ALICE.identityHex)))
      .toEqual([ALICE.identityHex]);
    expect(decodeB24AdministratorPolicy(adminPolicy(ALICE.identityHex, BOB.identityHex)))
      .toEqual([ALICE.identityHex, BOB.identityHex].sort());
    expect(() => decodeB24AdministratorPolicy('00')).toThrow(
      expect.objectContaining({ code: B24_ERROR.INVALID }),
    );
    expect(() => decodeB24AdministratorPolicy(`4020${ALICE.identityHex}`)).toThrow(
      expect.objectContaining({ code: B24_ERROR.INVALID }),
    );
    expect(() => decodeB24AdministratorPolicy(`40${ALICE.identityHex}`)).toThrow(
      expect.objectContaining({ code: B24_ERROR.INVALID }),
    );
    expect(() => decodeB24AdministratorPolicy(adminPolicy(ALICE.identityHex, ALICE.identityHex)))
      .toThrow(expect.objectContaining({ code: B24_ERROR.INVALID }));
  });

  test('authorized Add, Remove and proposal-free self update have distinct bound decisions', () => {
    const self = evaluate(parent(), candidate());
    expect(self).toMatchObject({ allowed: true, reason: B24_REASON.ALLOW_SELF_UPDATE });

    const add = evaluate(parent(), candidate({
      members: [ALICE, BOB, CHARLIE], proposals: [addProposal(ALICE, CHARLIE)],
    }));
    expect(add).toMatchObject({ allowed: true, reason: B24_REASON.ALLOW_ADD });

    const remove = evaluate(parent([ALICE, BOB, CHARLIE]), candidate({
      members: [ALICE, BOB], proposals: [removeProposal(ALICE, CHARLIE)],
    }));
    expect(remove).toMatchObject({ allowed: true, reason: B24_REASON.ALLOW_REMOVE });
    expect(new Set([self.resultDigestHex, add.resultDigestHex, remove.resultDigestHex]).size).toBe(3);
  });

  test('old valid proof is accepted but malformed, zero-time and forged candidate proofs fail closed', () => {
    const ancient = peer(4, 3, 1);
    expect(evaluate(parent(), candidate({
      members: [ALICE, BOB, ancient], proposals: [addProposal(ALICE, ancient)],
    }))).toMatchObject({ allowed: true, reason: B24_REASON.ALLOW_ADD });

    const forged = plainClone(candidate());
    const forgedProof = hexToBytes('proof', forged.candidateMembers[1].identityProofHex);
    forgedProof[103] ^= 1;
    forged.candidateMembers[1].identityProofHex = bytesToHex(forgedProof);
    expect(evaluate(parent(), forged)).toMatchObject({
      allowed: false, reason: B24_REASON.INVALID_CANDIDATE_PROOF,
    });

    const zeroTime = plainClone(candidate());
    const proof = hexToBytes('proof', zeroTime.candidateMembers[1].identityProofHex);
    proof.fill(0, 32, 40);
    zeroTime.candidateMembers[1].identityProofHex = bytesToHex(proof);
    expect(evaluate(parent(), zeroTime)).toMatchObject({
      allowed: false, reason: B24_REASON.INVALID_CANDIDATE_PROOF,
    });
  });

  test('authority is taken only from the parent and all unsupported membership shapes reject', () => {
    const nonAdminAdd = candidate({
      members: [ALICE, BOB, CHARLIE], committer: BOB,
      proposals: [addProposal(BOB, CHARLIE)], path: updatePath(BOB),
    });
    expect(evaluate(parent(), nonAdminAdd)).toMatchObject({
      allowed: false, reason: B24_REASON.NOT_ADMIN,
    });

    expect(() => evaluate(parent(), candidate({
      members: [BOB], proposals: [removeProposal(ALICE, ALICE)],
    }))).toThrow(expect.objectContaining({ code: B23_ERROR.INVALID }));

    expect(evaluate(
      parent([ALICE, BOB], [ALICE.identityHex, BOB.identityHex]),
      candidate({
        members: [ALICE], proposals: [removeProposal(ALICE, BOB)],
        policy: adminPolicy(ALICE.identityHex, BOB.identityHex),
      }),
    )).toMatchObject({ allowed: false, reason: B24_REASON.ADMIN_REMOVE });

    const referenced = addProposal(ALICE, CHARLIE);
    referenced.source = 'referenced';
    expect(evaluate(parent(), candidate({
      members: [ALICE, BOB, CHARLIE], proposals: [referenced],
    }))).toMatchObject({ allowed: false, reason: B24_REASON.UNSUPPORTED_SHAPE });

    expect(evaluate(parent(), candidate({
      proposals: [proposal('update', ALICE)],
    }))).toMatchObject({ allowed: false, reason: B24_REASON.UNSUPPORTED_SHAPE });
    expect(evaluate(parent(), candidate({
      members: [ALICE, BOB, CHARLIE],
      proposals: [addProposal(ALICE, CHARLIE), proposal('psk', ALICE)],
    }))).toMatchObject({ allowed: false, reason: B24_REASON.UNSUPPORTED_SHAPE });
  });

  test.each([
    'update', 'psk', 'reinit', 'external_init', 'group_context_extensions',
    'self_remove', 'app_data_update', 'app_ephemeral', 'custom', 'unknown',
  ])('unsupported proposal class %s is default-deny', (kind) => {
    expect(evaluate(parent(), candidate({ proposals: [proposal(kind, ALICE)] })))
      .toMatchObject({ allowed: false, reason: B24_REASON.UNSUPPORTED_SHAPE });
  });

  test('external/non-member committers and malformed administrator membership reject', () => {
    const external = candidate();
    external.committerSource = 'external';
    expect(evaluate(parent(), external)).toMatchObject({
      allowed: false, reason: B24_REASON.COMMITTER,
    });
    const nonMemberSender = addProposal(ALICE, CHARLIE);
    nonMemberSender.senderLeafIndex = 99;
    expect(evaluate(parent(), candidate({
      members: [ALICE, BOB, CHARLIE], proposals: [nonMemberSender],
    }))).toMatchObject({ allowed: false, reason: B24_REASON.UNSUPPORTED_SHAPE });

    const invalidAdminParent = parent([ALICE], [BOB.identityHex]);
    expect(evaluate(
      invalidAdminParent,
      candidate({ members: [ALICE], policy: invalidAdminParent.administratorPolicyHex }),
    )).toMatchObject({ allowed: false, reason: B24_REASON.ADMIN_POLICY });
  });

  test('candidate-wide invariants reject policy, lifecycle, component and ghost mutations', () => {
    expect(evaluate(parent(), candidate({ policy: adminPolicy(BOB.identityHex) })))
      .toMatchObject({ allowed: false, reason: B24_REASON.POLICY_MUTATION });
    expect(evaluate(parent(), candidate({ lifecycle: '01' })))
      .toMatchObject({ allowed: false, reason: B24_REASON.LIFECYCLE });
    expect(evaluate(parent(), candidate({ required: [32771, 32777] })))
      .toMatchObject({ allowed: false, reason: B24_REASON.COMPONENTS });
    expect(evaluate(parent(), candidate({ members: [ALICE, BOB, CHARLIE] })))
      .toMatchObject({ allowed: false, reason: B24_REASON.MEMBER_TRANSITION });
    expect(() => evaluate(parent(), candidate({ candidateEpochDec: '9' })))
      .toThrow(expect.objectContaining({ code: B23_ERROR.INVALID }));

    const changedUnrelated = peer(2, 1, 2);
    const changedProof = candidate({ members: [ALICE, changedUnrelated] });
    expect(evaluate(parent(), changedProof)).toMatchObject({
      allowed: false, reason: B24_REASON.MEMBER_TRANSITION,
    });
  });

  test('credential swaps, duplicate accounts and signing-key rotation fail before authorization', () => {
    const duplicate = plainClone(candidate());
    duplicate.candidateMembers[0].identityHex = BOB.identityHex;
    duplicate.candidateMembers[0].signatureKeyHex = BOB.signatureKeyHex;
    duplicate.candidateMembers[0].identityProofHex = BOB.identityProofHex;
    duplicate.committerIdentityHex = BOB.identityHex;
    duplicate.committerSignatureKeyHex = BOB.signatureKeyHex;
    duplicate.updatePath = { ...duplicate.candidateMembers[0] };
    expect(evaluate(parent(), duplicate)).toMatchObject({
      allowed: false, reason: B24_REASON.DUPLICATE_ACCOUNT,
    });

    const rotatedKey = new Uint8Array(32).fill(0x91);
    const rotatedProof = createAccountIdentityProofV2(
      ALICE.privateKey, rotatedKey, 2,
    );
    const rotated = plainClone(candidate());
    rotated.candidateMembers[0].signatureKeyHex = bytesToHex(rotatedKey);
    rotated.candidateMembers[0].identityProofHex = bytesToHex(rotatedProof);
    rotated.committerSignatureKeyHex = bytesToHex(rotatedKey);
    rotated.updatePath = { ...rotated.candidateMembers[0] };
    expect(evaluate(parent(), rotated)).toMatchObject({
      allowed: false, reason: B24_REASON.SIGNING_KEY_ROTATION,
    });
  });

  test('an authorization result cannot be replayed across any changed transition binding', () => {
    const parentState = parent();
    const candidateState = candidate();
    const decision = evaluate(parentState, candidateState);
    expect(verifyB24DecisionBinding(decision, {
      parent: parentState, candidate: candidateState, commitBytes: COMMIT,
    })).toEqual(decision);
    for (const changedCommit of [Uint8Array.of(1, 2, 3, 5), Uint8Array.of(9)]) {
      expect(() => verifyB24DecisionBinding(decision, {
        parent: parentState, candidate: candidateState, commitBytes: changedCommit,
      })).toThrow(expect.objectContaining({ code: B24_ERROR.BINDING_MISMATCH }));
    }
    const changedParent = plainClone(parentState);
    changedParent.groupContextDigestHex = '12'.repeat(32);
    expect(() => verifyB24DecisionBinding(decision, {
      parent: changedParent, candidate: candidateState, commitBytes: COMMIT,
    })).toThrow(expect.objectContaining({ code: B24_ERROR.BINDING_MISMATCH }));

    const changedGroup = plainClone(parentState);
    changedGroup.groupIdHex = '13'.repeat(32);
    expect(() => verifyB24DecisionBinding(decision, {
      parent: changedGroup, candidate: candidateState, commitBytes: COMMIT,
    })).toThrow(expect.objectContaining({ code: B24_ERROR.BINDING_MISMATCH }));

    const changedCandidate = candidate({ tlsByte: 0x67 });
    expect(() => verifyB24DecisionBinding(decision, {
      parent: parentState, candidate: changedCandidate, commitBytes: COMMIT,
    })).toThrow(expect.objectContaining({ code: B24_ERROR.BINDING_MISMATCH }));

    const changedVerifiedDigest = plainClone(candidateState);
    changedVerifiedDigest.verifiedLeafDigestHex = '14'.repeat(32);
    expect(() => verifyB24DecisionBinding(decision, {
      parent: parentState, candidate: changedVerifiedDigest, commitBytes: COMMIT,
    })).toThrow(expect.objectContaining({ code: B24_ERROR.BINDING_MISMATCH }));
  });
});

function deterministicRandom(start = 1) {
  let value = start;
  return (target) => { target.fill(value); value += 1; return target; };
}

describe('Phase B2.4 namespace and public boundary', () => {
  test('the wrapper is distinct, keeps the permissive journal private and freezes v1 naming', () => {
    const wrapped = createB24JournalForDb(new FakeVaultDb(), {
      randomBytes: deterministicRandom(),
    });
    expect(wrapped).toBeInstanceOf(B24Journal);
    expect(Object.keys(wrapped)).toEqual([]);
    expect(B24_DB_PREFIX).toBe('styx-b2-4-poc-v1-');
    expect(B24EngineAdapter.prototype.acceptInbound.length).toBe(2);
    expect(() => new B23EngineAdapter({
      wasm: { Provider: class {}, PhaseB2Group: class {}, PhaseB2Identity: class {} },
      journal: wrapped,
    })).toThrow(expect.objectContaining({ code: B23_ERROR.INVALID }));
    expect(() => new B24EngineAdapter({ wasm: {}, journal: wrapped })).toThrow(
      expect.objectContaining({ code: B24_ERROR.INVALID }),
    );
  });
});

const HERE = dirname(fileURLToPath(import.meta.url));
const VENDOR = join(HERE, '../../vendor/openmls-wasm');
let wasmPromise;
async function loadWasm() {
  if (!wasmPromise) {
    wasmPromise = (async () => {
      const moduleUrl = pathToFileURL(join(VENDOR, 'openmls_wasm.js'));
      moduleUrl.searchParams.set('b2-4-policy-test', '1');
      const wasm = await import(moduleUrl.href);
      await wasm.default({ module_or_path: readFileSync(join(VENDOR, 'openmls_wasm_bg.wasm')) });
      return wasm;
    })();
  }
  return wasmPromise;
}

function free(value) {
  try { value?.free?.(); } catch { /* test cleanup */ }
}

function createEnginePeer(wasm, provider, createdAt = 1_786_435_200) {
  const privateKey = Uint8Array.from(schnorr.utils.randomPrivateKey());
  const publicKey = Uint8Array.from(schnorr.getPublicKey(privateKey));
  const identity = new wasm.PhaseB2Identity(provider, publicKey);
  const signatureKey = identity.leaf_signature_key();
  const proof = createAccountIdentityProofV2(privateKey, signatureKey, createdAt);
  const generated = identity.key_package(provider, proof);
  const framed = generated.to_framed_bytes();
  free(generated);
  const keyPackage = wasm.PhaseB2KeyPackage.from_framed_bytes(framed);
  return { privateKey, publicKey, identity, signatureKey, proof, keyPackage, framed };
}

function restoreGroup(wasm, bundle) {
  const provider = new wasm.Provider();
  provider.restore_state(bundle.snapshotBytes);
  const identity = wasm.PhaseB2Identity.load(
    provider,
    hexToBytes('account', bundle.head.accountKeyHex),
    hexToBytes('signature', bundle.head.signatureKeyHex),
  );
  const group = wasm.PhaseB2Group.load(
    provider, hexToBytes('group', bundle.head.groupIdHex),
  );
  return { provider, identity, group };
}

function assertLiveness(left, right) {
  const plaintext = new TextEncoder().encode('b2-4-policy-liveness');
  const ciphertext = left.group.create_application_message(
    left.provider, left.identity, plaintext,
  );
  expect(right.group.process_application_message(right.provider, ciphertext)).toEqual(plaintext);
}

describe('Phase B2.4 mandatory-policy OpenMLS lifecycle', () => {
  test('authorized self update survives prepare, inbound merge and recovered confirm', async () => {
    const wasm = await loadWasm();
    const aliceProvider = new wasm.Provider();
    const bobProvider = new wasm.Provider();
    const alice = createEnginePeer(wasm, aliceProvider);
    const bob = createEnginePeer(wasm, bobProvider);
    const groupId = crypto.getRandomValues(new Uint8Array(32));
    const aliceGroup = wasm.PhaseB2Group.create_new(
      aliceProvider, alice.identity, groupId, alice.proof,
    );
    const founding = aliceGroup.prepare_add(aliceProvider, alice.identity, bob.keyPackage);
    const foundingProjection = founding.projection();
    aliceGroup.confirm_pending(aliceProvider, founding, foundingProjection.verified_leaf_digest());
    const tree = aliceGroup.export_ratchet_tree();
    const parsedTree = wasm.PhaseB2RatchetTree.from_bytes(tree.to_bytes());
    const bobGroup = wasm.PhaseB2Group.join(bobProvider, founding.welcome(), parsedTree);
    const aliceSnapshot = aliceProvider.serialize_state();
    const bobSnapshot = bobProvider.serialize_state();

    const aliceDb = new FakeVaultDb();
    const bobDb = new FakeVaultDb();
    const aliceJournal = createB24JournalForDb(aliceDb, { randomBytes: deterministicRandom(1) });
    const bobJournal = createB24JournalForDb(bobDb, { randomBytes: deterministicRandom(80) });
    const aliceAdapter = new B24EngineAdapter({ wasm, journal: aliceJournal });
    const bobAdapter = new B24EngineAdapter({ wasm, journal: bobJournal });
    const groupIdHex = bytesToHex(groupId);
    try {
      await aliceAdapter.initializeStable({
        snapshotBytes: aliceSnapshot, groupId,
        accountKey: alice.publicKey, signatureKey: alice.signatureKey,
      });
      await bobAdapter.initializeStable({
        snapshotBytes: bobSnapshot, groupId,
        accountKey: bob.publicKey, signatureKey: bob.signatureKey,
      });
      const aliceBeforeFailedCas = await aliceJournal.read(groupIdHex);
      aliceDb.failOn = (namespace) => namespace === B23_STORES.head;
      await expect(aliceAdapter.prepare(groupIdHex, { kind: 'self-update' }))
        .rejects.toMatchObject({ code: B24_ERROR.ENGINE_REJECTED });
      aliceDb.failOn = null;
      expect(await aliceJournal.read(groupIdHex)).toEqual(aliceBeforeFailedCas);
      const outbound = await aliceAdapter.prepare(groupIdHex, { kind: 'self-update' });
      expect(outbound.authorization).toMatchObject({
        allowed: true, reason: B24_REASON.ALLOW_SELF_UPDATE,
      });
      const bobBeforeFailedCas = await bobJournal.read(groupIdHex);
      bobDb.failOn = (namespace) => namespace === B23_STORES.head;
      await expect(bobAdapter.acceptInbound(groupIdHex, outbound.commitBytes, false))
        .rejects.toMatchObject({ code: B24_ERROR.ENGINE_REJECTED });
      bobDb.failOn = null;
      expect(await bobJournal.read(groupIdHex)).toEqual(bobBeforeFailedCas);
      const inbound = await bobAdapter.acceptInbound(groupIdHex, outbound.commitBytes, false);
      expect(inbound).toMatchObject({ status: 'accepted' });
      expect(inbound.authorization.reason).toBe(B24_REASON.ALLOW_SELF_UPDATE);
      await aliceAdapter.recordPublishIntent(groupIdHex, {
        id: 'opaque:b2-4:self-update', bytes: outbound.commitBytes,
      });
      expect((await aliceAdapter.recoveryState(groupIdHex)).action)
        .toBe('confirm-after-authorization-recheck');
      await aliceAdapter.confirmAfterAttempt(groupIdHex);

      const aliceRestored = restoreGroup(wasm, await aliceJournal.read(groupIdHex));
      const bobRestored = restoreGroup(wasm, await bobJournal.read(groupIdHex));
      assertLiveness(aliceRestored, bobRestored);
      assertLiveness(bobRestored, aliceRestored);
      free(aliceRestored.group); free(aliceRestored.identity); free(aliceRestored.provider);
      free(bobRestored.group); free(bobRestored.identity); free(bobRestored.provider);

      expect((await bobAdapter.acceptInbound(groupIdHex, outbound.commitBytes, true)).status)
        .toBe('duplicate');
      expect((await aliceJournal.read(groupIdHex)).head.epochDec).toBe('2');
      expect((await bobJournal.read(groupIdHex)).head.epochDec).toBe('2');
    } finally {
      for (const value of [
        parsedTree, tree, foundingProjection, founding, aliceGroup, bobGroup,
        alice.keyPackage, alice.identity, bob.keyPackage, bob.identity,
        aliceProvider, bobProvider,
      ]) free(value);
    }
  });

  test('authorized Add and non-admin Remove converge through both mandatory adapters', async () => {
    const wasm = await loadWasm();
    const aliceProvider = new wasm.Provider();
    const bobProvider = new wasm.Provider();
    const charlieProvider = new wasm.Provider();
    const alice = createEnginePeer(wasm, aliceProvider);
    const bob = createEnginePeer(wasm, bobProvider);
    const charlie = createEnginePeer(wasm, charlieProvider);
    const groupId = crypto.getRandomValues(new Uint8Array(32));
    const aliceGroup = wasm.PhaseB2Group.create_new(
      aliceProvider, alice.identity, groupId, alice.proof,
    );
    const founding = aliceGroup.prepare_add(aliceProvider, alice.identity, bob.keyPackage);
    const foundingProjection = founding.projection();
    aliceGroup.confirm_pending(aliceProvider, founding, foundingProjection.verified_leaf_digest());
    const foundingTree = aliceGroup.export_ratchet_tree();
    const parsedFoundingTree = wasm.PhaseB2RatchetTree.from_bytes(foundingTree.to_bytes());
    const bobGroup = wasm.PhaseB2Group.join(
      bobProvider, founding.welcome(), parsedFoundingTree,
    );
    const aliceJournal = createB24JournalForDb(new FakeVaultDb(), {
      randomBytes: deterministicRandom(1),
    });
    const bobJournal = createB24JournalForDb(new FakeVaultDb(), {
      randomBytes: deterministicRandom(100),
    });
    const aliceAdapter = new B24EngineAdapter({ wasm, journal: aliceJournal });
    const bobAdapter = new B24EngineAdapter({ wasm, journal: bobJournal });
    const groupIdHex = bytesToHex(groupId);
    let charlieGroup;
    let addTree;
    let parsedAddTree;
    try {
      await aliceAdapter.initializeStable({
        snapshotBytes: aliceProvider.serialize_state(), groupId,
        accountKey: alice.publicKey, signatureKey: alice.signatureKey,
      });
      await bobAdapter.initializeStable({
        snapshotBytes: bobProvider.serialize_state(), groupId,
        accountKey: bob.publicKey, signatureKey: bob.signatureKey,
      });
      const added = await aliceAdapter.prepare(groupIdHex, {
        kind: 'add', keyPackageBytes: charlie.framed,
      });
      expect(added.authorization.reason).toBe(B24_REASON.ALLOW_ADD);
      expect((await bobAdapter.acceptInbound(groupIdHex, added.commitBytes)).authorization.reason)
        .toBe(B24_REASON.ALLOW_ADD);
      await aliceAdapter.recordPublishIntent(groupIdHex, {
        id: 'opaque:b2-4:add', bytes: added.commitBytes,
      });
      await aliceAdapter.confirmAfterAttempt(groupIdHex);
      const stableAliceAfterAdd = restoreGroup(wasm, await aliceJournal.read(groupIdHex));
      addTree = stableAliceAfterAdd.group.export_ratchet_tree();
      parsedAddTree = wasm.PhaseB2RatchetTree.from_bytes(addTree.to_bytes());
      charlieGroup = wasm.PhaseB2Group.join(
        charlieProvider, added.welcomeBytes, parsedAddTree,
      );
      free(stableAliceAfterAdd.group);
      free(stableAliceAfterAdd.identity);
      free(stableAliceAfterAdd.provider);

      const charlieLeaf = added.projection.proposals[0].addedLeafIndex;
      const removed = await aliceAdapter.prepare(groupIdHex, {
        kind: 'remove', removedLeafIndex: charlieLeaf,
      });
      expect(removed.authorization.reason).toBe(B24_REASON.ALLOW_REMOVE);
      expect((await bobAdapter.acceptInbound(groupIdHex, removed.commitBytes)).authorization.reason)
        .toBe(B24_REASON.ALLOW_REMOVE);
      await aliceAdapter.recordPublishIntent(groupIdHex, {
        id: 'opaque:b2-4:remove', bytes: removed.commitBytes,
      });
      await aliceAdapter.confirmAfterAttempt(groupIdHex);

      const aliceRestored = restoreGroup(wasm, await aliceJournal.read(groupIdHex));
      const bobRestored = restoreGroup(wasm, await bobJournal.read(groupIdHex));
      expect(aliceRestored.group.member_count()).toBe(2);
      expect(bobRestored.group.member_count()).toBe(2);
      assertLiveness(aliceRestored, bobRestored);
      assertLiveness(bobRestored, aliceRestored);
      free(aliceRestored.group); free(aliceRestored.identity); free(aliceRestored.provider);
      free(bobRestored.group); free(bobRestored.identity); free(bobRestored.provider);
    } finally {
      for (const value of [
        parsedAddTree, addTree, charlieGroup, parsedFoundingTree, foundingTree,
        foundingProjection, founding, aliceGroup, bobGroup,
        alice.keyPackage, alice.identity, bob.keyPackage, bob.identity,
        charlie.keyPackage, charlie.identity,
        aliceProvider, bobProvider, charlieProvider,
      ]) free(value);
    }
  });

  test('a non-admin local Add and an invalid proof reject with zero durable writes', async () => {
    const wasm = await loadWasm();
    const aliceProvider = new wasm.Provider();
    const bobProvider = new wasm.Provider();
    const charlieProvider = new wasm.Provider();
    const alice = createEnginePeer(wasm, aliceProvider);
    const bob = createEnginePeer(wasm, bobProvider);
    const charlie = createEnginePeer(wasm, charlieProvider);
    const groupId = crypto.getRandomValues(new Uint8Array(32));
    const aliceGroup = wasm.PhaseB2Group.create_new(aliceProvider, alice.identity, groupId, alice.proof);
    const founding = aliceGroup.prepare_add(aliceProvider, alice.identity, bob.keyPackage);
    const projection = founding.projection();
    aliceGroup.confirm_pending(aliceProvider, founding, projection.verified_leaf_digest());
    const tree = aliceGroup.export_ratchet_tree();
    const parsedTree = wasm.PhaseB2RatchetTree.from_bytes(tree.to_bytes());
    const bobGroup = wasm.PhaseB2Group.join(bobProvider, founding.welcome(), parsedTree);
    const journal = createB24JournalForDb(new FakeVaultDb(), { randomBytes: deterministicRandom() });
    const adapter = new B24EngineAdapter({ wasm, journal });
    const groupIdHex = bytesToHex(groupId);
    try {
      await adapter.initializeStable({
        snapshotBytes: bobProvider.serialize_state(), groupId,
        accountKey: bob.publicKey, signatureKey: bob.signatureKey,
      });
      const before = await journal.read(groupIdHex);
      await expect(adapter.prepare(groupIdHex, {
        kind: 'add', keyPackageBytes: charlie.framed,
      })).rejects.toMatchObject({
        code: B24_ERROR.POLICY_REJECTED,
        details: { reason: B24_REASON.NOT_ADMIN },
      });
      expect(await journal.read(groupIdHex)).toEqual(before);
      await expect(adapter.prepare(groupIdHex, {
        kind: 'remove', removedLeafIndex: 1,
      })).rejects.toMatchObject({
        code: B24_ERROR.POLICY_REJECTED,
        details: { reason: B24_REASON.SELF_REMOVE },
      });
      expect(await journal.read(groupIdHex)).toEqual(before);

      const nonAdminPending = bobGroup.prepare_add(
        bobProvider, bob.identity, charlie.keyPackage,
      );
      const aliceInboundJournal = createB24JournalForDb(new FakeVaultDb(), {
        randomBytes: deterministicRandom(60),
      });
      const aliceInboundAdapter = new B24EngineAdapter({
        wasm, journal: aliceInboundJournal,
      });
      await aliceInboundAdapter.initializeStable({
        snapshotBytes: aliceProvider.serialize_state(), groupId,
        accountKey: alice.publicKey, signatureKey: alice.signatureKey,
      });
      const aliceInboundBefore = await aliceInboundJournal.read(groupIdHex);
      const inboundRejected = await aliceInboundAdapter.acceptInbound(
        groupIdHex, nonAdminPending.commit(), true,
      );
      expect(inboundRejected).toMatchObject({
        status: 'rejected', authorization: { reason: B24_REASON.NOT_ADMIN },
      });
      expect(await aliceInboundJournal.read(groupIdHex)).toEqual(aliceInboundBefore);
      free(nonAdminPending);

      const forgedProvider = new wasm.Provider();
      const forged = createEnginePeer(wasm, forgedProvider);
      const invalidProof = Uint8Array.from(forged.proof);
      invalidProof[103] ^= 1;
      const invalidPackageHandle = forged.identity.key_package(forgedProvider, invalidProof);
      const invalidFramed = invalidPackageHandle.to_framed_bytes();
      free(invalidPackageHandle);

      const aliceJournal = createB24JournalForDb(new FakeVaultDb(), {
        randomBytes: deterministicRandom(100),
      });
      const aliceAdapter = new B24EngineAdapter({ wasm, journal: aliceJournal });
      await aliceAdapter.initializeStable({
        snapshotBytes: aliceProvider.serialize_state(), groupId,
        accountKey: alice.publicKey, signatureKey: alice.signatureKey,
      });
      const aliceBefore = await aliceJournal.read(groupIdHex);
      await expect(aliceAdapter.prepare(groupIdHex, {
        kind: 'add', keyPackageBytes: invalidFramed,
      })).rejects.toMatchObject({
        code: B24_ERROR.POLICY_REJECTED,
        details: { reason: B24_REASON.INVALID_CANDIDATE_PROOF },
      });
      expect(await aliceJournal.read(groupIdHex)).toEqual(aliceBefore);
      free(forged.keyPackage); free(forged.identity); free(forgedProvider);
    } finally {
      for (const value of [
        parsedTree, tree, projection, founding, aliceGroup, bobGroup,
        alice.keyPackage, alice.identity, bob.keyPackage, bob.identity,
        charlie.keyPackage, charlie.identity, aliceProvider, bobProvider, charlieProvider,
      ]) free(value);
    }
  });
});
