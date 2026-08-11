import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

import { schnorr } from '@noble/curves/secp256k1';

import { createAccountIdentityProofV2 } from '../marmot-phase-b1/identity-proof-v2.js';
import { runCompositionProbe } from './composition-probe.mjs';

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const committedDirectory = process.argv[2] ?? process.env.B2_COMMITTED_WASM_DIR;
const buildDirectory = process.argv[3] ?? process.env.B2_WASM_DIR;
if (!committedDirectory || !buildDirectory) {
  throw new Error('committed and candidate WASM directories are required');
}

const moduleUrl = pathToFileURL(join(buildDirectory, 'openmls_wasm.js'));
moduleUrl.searchParams.set('stage', 'b2-2-capability');
const wasm = await import(moduleUrl.href);
await wasm.default({
  module_or_path: readFileSync(join(buildDirectory, 'openmls_wasm_bg.wasm')),
});

const evidenceManifest = new Map();

function recordEvidence(marker, message) {
  const evidence = evidenceManifest.get(marker) ?? [];
  evidence.push(message);
  evidenceManifest.set(marker, evidence);
}

function check(condition, message, markers = []) {
  if (!condition) throw new Error(`Phase B2.2 capability probe failed: ${message}`);
  for (const marker of markers) recordEvidence(marker, message);
  console.log(`PASS ${message}`);
}

function evidenceMarker(name, minimumCount) {
  const evidence = evidenceManifest.get(name) ?? [];
  if (evidence.length < minimumCount) {
    throw new Error(
      `Phase B2.2 capability probe failed: ${name} has ${evidence.length}/${minimumCount} evidence assertions`,
    );
  }
  console.log(`PASS ${name}`);
}

function bytesEqual(left, right) {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function expectFailure(operation, fragment, message, markers = []) {
  try {
    operation();
  } catch (error) {
    check(String(error).includes(fragment), `${message} (${fragment})`, markers);
    return true;
  }
  throw new Error(`Phase B2.2 capability probe failed: ${message} did not fail`);
}

function randomAccount() {
  const privateKey = Uint8Array.from(schnorr.utils.randomPrivateKey());
  return { privateKey, publicKey: Uint8Array.from(schnorr.getPublicKey(privateKey)) };
}

function createB2Peer(provider) {
  const account = randomAccount();
  const identity = new wasm.PhaseB2Identity(provider, account.publicKey);
  const signatureKey = identity.leaf_signature_key();
  const proof = createAccountIdentityProofV2(
    account.privateKey,
    signatureKey,
    Math.floor(Date.now() / 1000),
  );
  const keyPackage = wasm.PhaseB2KeyPackage.from_framed_bytes(
    identity.key_package(provider, proof).to_framed_bytes(),
  );
  return { ...account, identity, keyPackage, proof, signatureKey };
}

function reloadB2Peer(provider, peer) {
  const identity = wasm.PhaseB2Identity.load(provider, peer.publicKey, peer.signatureKey);
  check(identity !== undefined, 'B2 identity reloads from the exact provider snapshot');
  return { ...peer, identity };
}

function restoredProvider(snapshot) {
  const provider = new wasm.Provider();
  provider.restore_state(snapshot);
  return provider;
}

function loadB2Group(provider, groupId, peer) {
  const group = wasm.PhaseB2Group.load(provider, groupId);
  check(group !== undefined, 'B2 group reloads from the exact provider snapshot');
  check(group.matches_own_identity(peer.publicKey, peer.signatureKey), 'restored group is bound to the exact own identity');
  return group;
}

function assertB2Liveness(left, right, label) {
  const leftPlaintext = encoder.encode(`${label}:left`);
  const leftMessage = left.group.create_application_message(
    left.provider,
    left.peer.identity,
    leftPlaintext,
  );
  check(
    decoder.decode(right.group.process_application_message(right.provider, leftMessage))
      === decoder.decode(leftPlaintext),
    `${label} left-to-right application liveness`,
  );
  const rightPlaintext = encoder.encode(`${label}:right`);
  const rightMessage = right.group.create_application_message(
    right.provider,
    right.peer.identity,
    rightPlaintext,
  );
  check(
    decoder.decode(left.group.process_application_message(left.provider, rightMessage))
      === decoder.decode(rightPlaintext),
    `${label} right-to-left application liveness`,
  );
}

function independentVerifiedLeafDigest(projection) {
  const memberCount = projection.candidate_member_count();
  const payload = new Uint8Array(27 + 4 + (172 * memberCount));
  payload.set(encoder.encode('STYX-B2-VERIFIED-LEAVES-v1'), 0);
  payload[26] = 0;
  const view = new DataView(payload.buffer);
  view.setUint32(27, memberCount, false);
  let offset = 31;
  let previousLeaf = -1;
  for (let index = 0; index < memberCount; index += 1) {
    const leafIndex = projection.candidate_leaf_index(index);
    check(leafIndex > previousLeaf, `candidate member ${index} is in increasing leaf-index order`);
    previousLeaf = leafIndex;
    view.setUint32(offset, leafIndex, false);
    offset += 4;
    for (const field of [
      projection.candidate_identity(index),
      projection.candidate_signature_key(index),
      projection.candidate_identity_proof(index),
    ]) {
      payload.set(field, offset);
      offset += field.length;
    }
  }
  check(offset === payload.length, 'verified-leaf digest preimage has the exact bounded length');
  return Uint8Array.from(createHash('sha256').update(payload).digest());
}

function inspectCandidate(projection, identities, label) {
  check(projection.candidate_epoch() === projection.prior_epoch() + 1n, `${label} advances one candidate epoch`);
  check(projection.committer_source() === 'member', `${label} has an authenticated member committer`);
  check(projection.verified_leaf_digest().length === 32, `${label} exposes a 32-byte verified-leaf digest`);
  check(
    bytesEqual(projection.verified_leaf_digest(), independentVerifiedLeafDigest(projection)),
    `${label} verified-leaf digest matches an independent JavaScript recomputation`,
    ['PHASE_B2_VERIFIED_LEAF_BINDING'],
  );
  check(projection.candidate_group_context_sha256().length === 32, `${label} exposes a 32-byte GroupContext hash`);
  check(
    Array.from(projection.required_component_ids()).join(',') === '32771,32777,32780',
    `${label} retains exact required component ids`,
  );
  check(bytesEqual(projection.lifecycle(), Uint8Array.of(0)), `${label} retains active lifecycle`);
  const observed = Array.from({ length: projection.candidate_member_count() }, (_, index) => {
    check(projection.candidate_identity(index).length === 32, `${label} member ${index} identity is bounded`);
    check(projection.candidate_signature_key(index).length === 32, `${label} member ${index} signature key is bounded`);
    check(projection.candidate_identity_proof(index).length === 104, `${label} member ${index} proof is bounded`);
    return projection.candidate_identity(index);
  });
  for (const identity of identities) {
    check(observed.some((candidate) => bytesEqual(candidate, identity)), `${label} contains expected candidate identity`);
  }
}

function b2CurrentProfileLifecycle() {
  const aliceProvider = new wasm.Provider();
  const bobProvider = new wasm.Provider();
  const charlieProvider = new wasm.Provider();
  const alice = createB2Peer(aliceProvider);
  const bob = createB2Peer(bobProvider);
  const charlie = createB2Peer(charlieProvider);
  const groupId = crypto.getRandomValues(new Uint8Array(32));

  check(bob.keyPackage.ciphersuite_id() === 1, 'B2 KeyPackage uses AES-128-GCM ciphersuite 0x0001');
  check(!bob.keyPackage.is_last_resort(), 'B2 KeyPackage is bounded and non-last-resort');
  check(
    Array.from(bob.keyPackage.supported_component_ids()).join(',') === '32771,32777,32780',
    'B2 leaf advertises the exact current component set',
  );
  expectFailure(
    () => alice.identity.key_package(aliceProvider, alice.proof.subarray(0, 103)),
    '104 bytes',
    'malformed proof is rejected',
  );

  const aliceGroup = wasm.PhaseB2Group.create_new(
    aliceProvider,
    alice.identity,
    groupId,
    alice.proof,
  );
  const addBob = aliceGroup.prepare_add(aliceProvider, alice.identity, bob.keyPackage);
  const addBobProjection = addBob.projection();
  inspectCandidate(addBobProjection, [alice.publicKey, bob.publicKey], 'founding Add');
  check(
    addBobProjection.proposal_kind(0) === 'add',
    'founding Add projection records inline Add',
    ['PHASE_B2_POLICY_PROJECTION'],
  );
  check(
    addBobProjection.proposal_source(0) === 'inline',
    'founding Add source is inline',
    ['PHASE_B2_POLICY_PROJECTION'],
  );
  check(addBobProjection.proposal_sender_source(0) === 'member', 'founding Add sender is authenticated');
  const wrongDigest = new Uint8Array(32);
  expectFailure(
    () => aliceGroup.confirm_pending(aliceProvider, addBob, wrongDigest),
    'digest mismatch',
    'wrong pending digest fails closed',
    ['PHASE_B2_VERIFIED_LEAF_BINDING'],
  );
  check(
    !addBob.is_consumed() && aliceGroup.epoch() === 0n,
    'wrong digest consumes no handle or epoch',
    ['PHASE_B2_VERIFIED_LEAF_BINDING'],
  );
  aliceGroup.confirm_pending(aliceProvider, addBob, addBobProjection.verified_leaf_digest());
  check(
    addBob.is_consumed() && aliceGroup.epoch() === 1n,
    'correct digest confirms exactly once',
    ['PHASE_B2_VERIFIED_LEAF_BINDING'],
  );
  expectFailure(
    () => aliceGroup.confirm_pending(aliceProvider, addBob, addBobProjection.verified_leaf_digest()),
    'already consumed',
    'pending handle replay is rejected',
    ['PHASE_B2_VERIFIED_LEAF_BINDING'],
  );

  const bobGroup = wasm.PhaseB2Group.join(
    bobProvider,
    addBob.welcome(),
    wasm.PhaseB2RatchetTree.from_bytes(aliceGroup.export_ratchet_tree().to_bytes()),
  );
  const privateApplication = aliceGroup.create_application_message(
    aliceProvider,
    alice.identity,
    encoder.encode('private-message-is-not-an-inbound-commit'),
  );
  const bobBeforePrivateRejection = bobProvider.serialize_state();
  expectFailure(
    () => bobGroup.stage_inbound_commit(bobProvider, privateApplication),
    'PrivateMessage Commit rejected',
    'PrivateMessage input is rejected before inbound Commit staging',
    ['PHASE_B2_PUBLIC_COMMIT_FRAMING'],
  );
  check(
    bytesEqual(bobBeforePrivateRejection, bobProvider.serialize_state()),
    'rejected PrivateMessage writes no provider state',
    ['PHASE_B2_PUBLIC_COMMIT_FRAMING'],
  );
  assertB2Liveness(
    { group: aliceGroup, peer: alice, provider: aliceProvider },
    { group: bobGroup, peer: bob, provider: bobProvider },
    'post-join',
  );

  const selfUpdate = aliceGroup.prepare_self_update(aliceProvider, alice.identity);
  const selfProjection = selfUpdate.projection();
  check(
    selfProjection.proposal_count() === 0,
    'self-update has no Proposal::Update',
    ['PHASE_B2_POLICY_PROJECTION'],
  );
  check(
    selfProjection.has_update_path(),
    'self-update exposes the replacement update-path leaf',
    ['PHASE_B2_POLICY_PROJECTION'],
  );
  const stagedUpdate = bobGroup.stage_inbound_commit(bobProvider, selfUpdate.commit());
  const stagedUpdateProjection = stagedUpdate.projection();
  bobGroup.discard_staged_commit(bobProvider, stagedUpdate);
  check(stagedUpdate.is_consumed() && bobGroup.epoch() === 1n, 'inbound discard advances no state');
  const restagedUpdate = bobGroup.stage_inbound_commit(bobProvider, selfUpdate.commit());
  bobGroup.merge_staged_commit(
    bobProvider,
    restagedUpdate,
    stagedUpdateProjection.verified_leaf_digest(),
  );
  aliceGroup.confirm_pending(aliceProvider, selfUpdate, selfProjection.verified_leaf_digest());
  check(aliceGroup.epoch() === 2n && bobGroup.epoch() === 2n, 'self-update converges after explicit confirm and merge');

  const addCharlie = aliceGroup.prepare_add(aliceProvider, alice.identity, charlie.keyPackage);
  const addCharlieProjection = addCharlie.projection();
  const bobStagedAdd = bobGroup.stage_inbound_commit(bobProvider, addCharlie.commit());
  bobGroup.merge_staged_commit(
    bobProvider,
    bobStagedAdd,
    addCharlieProjection.verified_leaf_digest(),
  );
  aliceGroup.confirm_pending(aliceProvider, addCharlie, addCharlieProjection.verified_leaf_digest());
  const charlieLeaf = addCharlieProjection.proposal_added_leaf_index(0);
  check(charlieLeaf !== undefined, 'Add projection exposes the candidate leaf index');

  const removeCharlie = bobGroup.prepare_remove(bobProvider, bob.identity, charlieLeaf);
  const removeProjection = removeCharlie.projection();
  check(
    removeProjection.proposal_kind(0) === 'remove',
    'Remove projection records inline Remove',
    ['PHASE_B2_POLICY_PROJECTION'],
  );
  check(removeProjection.proposal_removed_parent_leaf_index(0) === charlieLeaf, 'Remove projection binds the exact parent leaf');
  const aliceStagedRemove = aliceGroup.stage_inbound_commit(aliceProvider, removeCharlie.commit());
  aliceGroup.merge_staged_commit(
    aliceProvider,
    aliceStagedRemove,
    removeProjection.verified_leaf_digest(),
  );
  bobGroup.confirm_pending(bobProvider, removeCharlie, removeProjection.verified_leaf_digest());
  check(aliceGroup.member_count() === 2 && bobGroup.member_count() === 2, 'Remove converges on the exact candidate member set');
  assertB2Liveness(
    { group: aliceGroup, peer: alice, provider: aliceProvider },
    { group: bobGroup, peer: bob, provider: bobProvider },
    'post-remove',
  );

  const pendingRecovery = aliceGroup.prepare_self_update(aliceProvider, alice.identity);
  const pendingSnapshot = aliceProvider.serialize_state();
  const recoveredProvider = restoredProvider(pendingSnapshot);
  const recoveredAlice = reloadB2Peer(recoveredProvider, alice);
  const recoveredGroup = loadB2Group(recoveredProvider, groupId, recoveredAlice);
  check(recoveredGroup.has_pending_commit(recoveredProvider), 'durable recovery reports the pending Commit');
  const recoveredProjection = recoveredGroup.pending_projection(recoveredProvider);
  check(recoveredProjection !== undefined, 'durable recovery exposes the candidate projection');
  const recoveredEpochBeforeRejections = recoveredGroup.epoch();
  const recoveredBeforeRejections = recoveredProvider.serialize_state();
  expectFailure(
    () => recoveredGroup.confirm_pending_commit(
      recoveredProvider,
      recoveredGroup.epoch() + 1n,
      recoveredAlice.publicKey,
      recoveredAlice.signatureKey,
      recoveredProjection.verified_leaf_digest(),
    ),
    'stale epoch or wrong identity',
    'durable confirmation rejects a stale expected epoch',
  );
  expectFailure(
    () => recoveredGroup.confirm_pending_commit(
      recoveredProvider,
      recoveredGroup.epoch(),
      new Uint8Array(32).fill(0x91),
      recoveredAlice.signatureKey,
      recoveredProjection.verified_leaf_digest(),
    ),
    'stale epoch or wrong identity',
    'durable confirmation rejects the wrong account identity',
  );
  expectFailure(
    () => recoveredGroup.confirm_pending_commit(
      recoveredProvider,
      recoveredGroup.epoch(),
      recoveredAlice.publicKey,
      new Uint8Array(32).fill(0x92),
      recoveredProjection.verified_leaf_digest(),
    ),
    'stale epoch or wrong identity',
    'durable confirmation rejects the wrong leaf signature key',
  );
  expectFailure(
    () => recoveredGroup.confirm_pending_commit(
      recoveredProvider,
      recoveredGroup.epoch(),
      recoveredAlice.publicKey.subarray(0, 31),
      recoveredAlice.signatureKey,
      recoveredProjection.verified_leaf_digest(),
    ),
    'identity inputs must be exactly 32 bytes',
    'durable confirmation rejects malformed identity length',
  );
  check(recoveredGroup.has_pending_commit(recoveredProvider), 'rejected durable confirmations retain pending state');
  check(
    recoveredGroup.epoch() === recoveredEpochBeforeRejections,
    'rejected durable confirmations retain the prior epoch',
  );
  check(
    bytesEqual(recoveredBeforeRejections, recoveredProvider.serialize_state()),
    'rejected durable confirmations write no provider state',
  );
  recoveredGroup.confirm_pending_commit(
    recoveredProvider,
    recoveredGroup.epoch(),
    recoveredAlice.publicKey,
    recoveredAlice.signatureKey,
    recoveredProjection.verified_leaf_digest(),
  );
  check(recoveredGroup.epoch() === 5n, 'durable pending confirmation advances exactly once');

  const clearProvider = restoredProvider(pendingSnapshot);
  const clearAlice = reloadB2Peer(clearProvider, alice);
  const clearGroup = loadB2Group(clearProvider, groupId, clearAlice);
  const clearEpochBeforeRejections = clearGroup.epoch();
  const clearBeforeRejections = clearProvider.serialize_state();
  expectFailure(
    () => clearGroup.clear_pending_commit(
      clearProvider,
      clearGroup.epoch() + 1n,
      clearAlice.publicKey,
      clearAlice.signatureKey,
    ),
    'stale epoch or wrong identity',
    'durable clear rejects a stale expected epoch',
  );
  expectFailure(
    () => clearGroup.clear_pending_commit(
      clearProvider,
      clearGroup.epoch(),
      new Uint8Array(32).fill(0x93),
      clearAlice.signatureKey,
    ),
    'stale epoch or wrong identity',
    'durable clear rejects the wrong account identity',
  );
  expectFailure(
    () => clearGroup.clear_pending_commit(
      clearProvider,
      clearGroup.epoch(),
      clearAlice.publicKey,
      new Uint8Array(32).fill(0x94),
    ),
    'stale epoch or wrong identity',
    'durable clear rejects the wrong leaf signature key',
  );
  expectFailure(
    () => clearGroup.clear_pending_commit(
      clearProvider,
      clearGroup.epoch(),
      clearAlice.publicKey,
      clearAlice.signatureKey.subarray(0, 31),
    ),
    'identity inputs must be exactly 32 bytes',
    'durable clear rejects malformed signature-key length',
  );
  check(clearGroup.has_pending_commit(clearProvider), 'rejected durable clears retain pending state');
  check(
    clearGroup.epoch() === clearEpochBeforeRejections,
    'rejected durable clears retain the prior epoch',
  );
  check(
    bytesEqual(clearBeforeRejections, clearProvider.serialize_state()),
    'rejected durable clears write no provider state',
  );
  clearGroup.clear_pending_commit(
    clearProvider,
    clearGroup.epoch(),
    clearAlice.publicKey,
    clearAlice.signatureKey,
  );
  const clearedProvider = restoredProvider(clearProvider.serialize_state());
  const clearedGroup = loadB2Group(clearedProvider, groupId, clearAlice);
  check(!clearedGroup.has_pending_commit(clearedProvider), 'durable clear survives a second restore');
  expectFailure(
    () => clearedGroup.clear_pending_commit(
      clearedProvider,
      clearedGroup.epoch(),
      clearAlice.publicKey,
      clearAlice.signatureKey,
    ),
    'pending state is absent',
    'durable clear rejects replay after pending state is absent',
  );

  expectFailure(
    () => bobGroup.stage_inbound_commit(bobProvider, addBob.welcome()),
    'unsupported MLSMessage body',
    'non-Commit MLSMessage is rejected by the inbound staging path',
    ['PHASE_B2_PUBLIC_COMMIT_FRAMING'],
  );
  expectFailure(
    () => wasm.PhaseB2KeyPackage.from_framed_bytes(new Uint8Array([1, 2, 3])),
    'malformed MLSMessage framing',
    'malformed KeyPackage framing is rejected',
  );
  const legacyProvider = new wasm.Provider();
  const legacyPeer = createB1Peer(legacyProvider);
  expectFailure(
    () => wasm.PhaseB2KeyPackage.from_framed_bytes(legacyPeer.keyPackage.to_framed_bytes()),
    'unexpected supported components',
    'a genuine B1-profile KeyPackage is rejected at the generated B2 boundary',
  );
  check(!pendingRecovery.is_consumed(), 'a pending handle in the pre-restore instance remains local and unmerged');
  console.log('PASS B2_CURRENT_PROFILE_COMPLETE');
}

function createB1Peer(provider) {
  const account = randomAccount();
  const identity = new wasm.PhaseB1Identity(provider, account.publicKey);
  const leafKey = identity.leaf_signature_key();
  const proof = createAccountIdentityProofV2(
    account.privateKey,
    leafKey,
    Math.floor(Date.now() / 1000),
  );
  const keyPackage = wasm.PhaseB1KeyPackage.from_framed_bytes(
    identity.key_package(provider, proof).to_framed_bytes(),
  );
  return { ...account, identity, keyPackage, leafKey, proof };
}

function b1Group(provider, founder, label) {
  return wasm.PhaseB1Group.create_new(provider, founder.identity, encoder.encode(label), founder.proof);
}

function b1RecoveryMatrix() {
  for (const action of ['confirm', 'clear']) {
    for (const startingSize of [1, 2]) {
      const ownerProvider = new wasm.Provider();
      const peerProvider = new wasm.Provider();
      const candidateProvider = new wasm.Provider();
      const owner = createB1Peer(ownerProvider);
      const peer = createB1Peer(peerProvider);
      const candidate = createB1Peer(candidateProvider);
      const id = encoder.encode(`b2-2-b1-${action}-${startingSize}`);
      const ownerGroup = b1Group(ownerProvider, owner, decoder.decode(id));
      if (startingSize === 2) {
        const initial = ownerGroup.propose_and_commit_add(ownerProvider, owner.identity, peer.keyPackage);
        ownerGroup.confirm_pending_add(ownerProvider, initial);
      }
      ownerGroup.propose_and_commit_add(ownerProvider, owner.identity, candidate.keyPackage);
      const restored = restoredProvider(ownerProvider.serialize_state());
      const restoredIdentity = wasm.PhaseB1Identity.load(restored, owner.publicKey, owner.leafKey);
      const restoredGroup = wasm.PhaseB1Group.load(restored, id);
      check(restoredIdentity !== undefined && restoredGroup !== undefined, `B1 ${action}/${startingSize} reloads identity and group`);
      check(restoredGroup.has_pending_commit(restored), `B1 ${action}/${startingSize} reloads pending state`);
      if (action === 'confirm') restoredGroup.confirm_pending_commit(restored, BigInt(startingSize - 1));
      else restoredGroup.clear_pending_commit(restored, BigInt(startingSize - 1));
      check(
        restoredGroup.epoch() === BigInt(action === 'confirm' ? startingSize : startingSize - 1),
        `B1 ${action}/${startingSize} reaches the expected epoch`,
      );
    }
  }

  const aliceProvider = new wasm.Provider();
  const bobProvider = new wasm.Provider();
  const charlieProvider = new wasm.Provider();
  const alice = createB1Peer(aliceProvider);
  const bob = createB1Peer(bobProvider);
  const charlie = createB1Peer(charlieProvider);
  const id = encoder.encode('b2-2-b1-restage');
  const aliceGroup = b1Group(aliceProvider, alice, decoder.decode(id));
  const founding = aliceGroup.propose_and_commit_add(aliceProvider, alice.identity, bob.keyPackage);
  aliceGroup.confirm_pending_add(aliceProvider, founding);
  const bobGroup = wasm.PhaseB1Group.join(
    bobProvider,
    founding.welcome(),
    wasm.PhaseB1RatchetTree.from_bytes(aliceGroup.export_ratchet_tree().to_bytes()),
  );
  const pending = bobGroup.propose_and_commit_add(bobProvider, bob.identity, charlie.keyPackage);
  const stableSnapshot = aliceProvider.serialize_state();
  const mergeProvider = restoredProvider(stableSnapshot);
  const mergeGroup = wasm.PhaseB1Group.load(mergeProvider, id);
  const mergeStaged = mergeGroup.stage_inbound_commit(mergeProvider, pending.commit());
  mergeGroup.merge_staged_commit(mergeProvider, mergeStaged);
  check(mergeGroup.epoch() === 2n, 'B1 exact inbound bytes re-stage and merge');
  const discardProvider = restoredProvider(stableSnapshot);
  const discardGroup = wasm.PhaseB1Group.load(discardProvider, id);
  const discardStaged = discardGroup.stage_inbound_commit(discardProvider, pending.commit());
  discardGroup.discard_staged_commit(discardProvider, discardStaged);
  check(discardGroup.epoch() === 1n, 'B1 exact inbound bytes re-stage and discard');
  console.log('PASS RETAINED_B1_RECOVERY_MATRIX');
}

b2CurrentProfileLifecycle();
b1RecoveryMatrix();
const compositionEvidence = await runCompositionProbe(committedDirectory, buildDirectory);
check(
  compositionEvidence.addedNamedExports.length === 7
    && compositionEvidence.addedRuntimeClasses.PhaseB2Group !== undefined,
  'composition contains the exact seven Phase B2 runtime classes',
  ['PHASE_B2_EXPORTED_COMPOSITION'],
);
check(
  compositionEvidence.addedInitOutputMembers.length > 0
    && compositionEvidence.retainedNamedExportCount === 17,
  'composition preserves retained exports and adds only documented InitOutput members',
  ['PHASE_B2_EXPORTED_COMPOSITION', 'PHASE_B2_SURFACE_DELTA_EXACT'],
);
check(
  compositionEvidence.addedNamedExports.length === 7
    && compositionEvidence.addedInitOutputMembers.length > 0
    && compositionEvidence.retainedNamedExportCount === 17,
  'surface delta is the exact bounded Phase B2 addition',
  ['PHASE_B2_SURFACE_DELTA_EXACT'],
);
const evidenceSnapshot = Object.fromEntries(
  [...evidenceManifest.entries()].sort(([left], [right]) => left.localeCompare(right)),
);
const evidenceManifestSha256 = createHash('sha256')
  .update(JSON.stringify(evidenceSnapshot))
  .digest('hex');
console.log(JSON.stringify({ evidenceManifest: evidenceSnapshot, evidenceManifestSha256 }, null, 2));
evidenceMarker('PHASE_B2_EXPORTED_COMPOSITION', 2);
evidenceMarker('PHASE_B2_PUBLIC_COMMIT_FRAMING', 3);
evidenceMarker('PHASE_B2_POLICY_PROJECTION', 5);
evidenceMarker('PHASE_B2_VERIFIED_LEAF_BINDING', 5);
evidenceMarker('PHASE_B2_SURFACE_DELTA_EXACT', 2);
console.log('Phase B2.2 capability probe completed; this is isolated capability evidence, not a product migration.');
