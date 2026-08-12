import { describe, expect, test } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { schnorr } from '@noble/curves/secp256k1';

import {
  B25B_BATCH_STATE,
  B25B_CANDIDATE_STATE,
  B25B_DB_PREFIX,
  B25B_DISPOSITION,
  B25B_ERROR,
  B25B_HEAD_STATE,
  B25B_LIMITS,
  B25B_LOCAL_STATE,
  B25B_PUBLICATION_KIND,
  B25B_STORES,
  B25B_STORE_NAMES,
  bytesToHex,
  canonicalProviderEntries,
  compareCandidates,
  comparisonTupleDigest,
  copyBytes,
  digestHex,
} from '../../spikes/marmot-phase-b2-5b/b2-5b-canonical.mjs';
import {
  priorityForAuthorization,
  selectSameParentCandidate,
} from '../../spikes/marmot-phase-b2-5a/b2-5a-convergence.mjs';
import { B25BEngineAdapter } from '../../spikes/marmot-phase-b2-5b/b2-5b-engine-adapter.mjs';
import {
  B25BJournal,
  createB25BJournalForDb,
} from '../../spikes/marmot-phase-b2-5b/b2-5b-journal.mjs';
import { createB25BCoordinator }
  from '../../spikes/marmot-phase-b2-5b/b2-5b-coordinator.mjs';
import {
  buildCandidateEvidence,
  buildInput,
  buildRetainedState,
  buildTransition,
  parseBatch,
  parseHead,
  parseInput,
} from '../../spikes/marmot-phase-b2-5b/b2-5b-record.mjs';
import { FakeVaultDb, deepClone } from '../support/fake-vault-db.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const VENDOR = join(HERE, '../../vendor/openmls-wasm');
let wasmPromise;
const UTF8 = new TextEncoder();

// Test-only construction of the public account-identity-proof-v2 wire fact.
// Keeping it here avoids importing an earlier spike outside Issue #155's exact
// read-only module allowlist.
function createAccountIdentityProofV2(privateKey, leafSignatureKey, createdAt) {
  const publicKey = Uint8Array.from(schnorr.getPublicKey(privateKey));
  const publicKeyHex = bytesToHex(publicKey);
  const event = [
    0, publicKeyHex, createdAt, 450,
    [
      ['d', 'marmot.account-identity-proof.v2'],
      ['component', '0x8009'],
      ['ciphersuite', '0x0001'],
      ['signature_scheme', '0x0807'],
      ['mls_signature_key', bytesToHex(leafSignatureKey)],
    ],
    'Authorize this MLS leaf key for my Marmot account',
  ];
  const signature = Uint8Array.from(schnorr.sign(
    Uint8Array.from(Buffer.from(digestHex(UTF8.encode(JSON.stringify(event))), 'hex')),
    privateKey,
  ));
  const proof = new Uint8Array(104);
  proof.set(publicKey, 0);
  new DataView(proof.buffer).setBigUint64(32, BigInt(createdAt));
  proof.set(signature, 40);
  return proof;
}

async function loadWasm() {
  if (!wasmPromise) {
    wasmPromise = (async () => {
      const moduleUrl = pathToFileURL(join(VENDOR, 'openmls_wasm.js'));
      moduleUrl.searchParams.set('b2-5b-convergence-test', '1');
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

function b25bDb(tag = 'test') {
  const db = new FakeVaultDb();
  Object.defineProperty(db, 'name', { value: `${B25B_DB_PREFIX}${tag}` });
  return db;
}

function createPeer(wasm, provider, seed, createdAt = 1_786_435_200) {
  const privateKey = new Uint8Array(32);
  privateKey[31] = seed;
  const publicKey = Uint8Array.from(schnorr.getPublicKey(privateKey));
  const identity = new wasm.PhaseB2Identity(provider, publicKey);
  const signatureKey = copyBytes(identity.leaf_signature_key());
  const proof = createAccountIdentityProofV2(privateKey, signatureKey, createdAt + seed);
  const generated = identity.key_package(provider, proof);
  const framed = copyBytes(generated.to_framed_bytes());
  free(generated);
  const keyPackage = wasm.PhaseB2KeyPackage.from_framed_bytes(framed);
  return { privateKey, publicKey, identity, signatureKey, proof, framed, keyPackage };
}

function mergeInbound(group, provider, commitBytes) {
  const staged = group.stage_inbound_commit(provider, commitBytes);
  const projection = staged.projection();
  try {
    group.merge_staged_commit(provider, staged, projection.verified_leaf_digest());
  } finally {
    free(projection);
    free(staged);
  }
}

function restorePeer(wasm, state, groupId) {
  const provider = new wasm.Provider();
  provider.restore_state(state.snapshotBytes);
  const identity = wasm.PhaseB2Identity.load(provider, state.publicKey, state.signatureKey);
  const group = wasm.PhaseB2Group.load(provider, groupId);
  if (identity === undefined || group === undefined) throw new Error('test peer restore failed');
  return { provider, identity, group };
}

async function setupGroup(wasm, groupSeed = 1) {
  const groupId = Uint8Array.from({ length: 32 }, (_, index) => (index + groupSeed) & 0xff);
  const names = ['alice', 'bob', 'charlie', 'diana'];
  const peers = {};
  for (let index = 0; index < names.length; index += 1) {
    const provider = new wasm.Provider();
    const peer = createPeer(wasm, provider, index + 1);
    peers[names[index]] = { ...peer, provider, group: null };
  }
  peers.alice.group = wasm.PhaseB2Group.create_new(
    peers.alice.provider, peers.alice.identity, groupId, peers.alice.proof,
  );
  const active = [peers.alice];
  for (const joining of [peers.bob, peers.charlie, peers.diana]) {
    const pending = peers.alice.group.prepare_add(
      peers.alice.provider, peers.alice.identity, joining.keyPackage,
    );
    const commitBytes = copyBytes(pending.commit());
    const welcomeBytes = copyBytes(pending.welcome());
    for (const peer of active.slice(1)) mergeInbound(peer.group, peer.provider, commitBytes);
    const projection = pending.projection();
    joining.leafIndex = projection.proposal_added_leaf_index(0);
    peers.alice.group.confirm_pending(
      peers.alice.provider, pending, projection.verified_leaf_digest(),
    );
    const tree = peers.alice.group.export_ratchet_tree();
    const parsedTree = wasm.PhaseB2RatchetTree.from_bytes(tree.to_bytes());
    joining.group = wasm.PhaseB2Group.join(joining.provider, welcomeBytes, parsedTree);
    active.push(joining);
    free(parsedTree); free(tree); free(projection); free(pending);
  }
  for (const peer of active) {
    peer.snapshotBytes = copyBytes(peer.provider.serialize_state());
    expect(bytesToHex(peer.group.group_context_sha256(peer.provider)))
      .toBe(bytesToHex(peers.alice.group.group_context_sha256(peers.alice.provider)));
  }
  return { wasm, groupId, peers, cleanup() {
    for (const peer of Object.values(peers)) {
      free(peer.group); free(peer.keyPackage); free(peer.identity); free(peer.provider);
    }
  } };
}

function extendGroupWithoutJoining(wasm, fixture, observerName, count, firstSeed) {
  const newcomers = [];
  const alice = fixture.peers.alice;
  const observer = fixture.peers[observerName];
  for (let index = 0; index < count; index += 1) {
    const provider = new wasm.Provider();
    const newcomer = createPeer(wasm, provider, firstSeed + index);
    newcomers.push({ ...newcomer, provider });
    const pending = alice.group.prepare_add(
      alice.provider, alice.identity, newcomer.keyPackage,
    );
    const projection = pending.projection();
    try {
      mergeInbound(observer.group, observer.provider, copyBytes(pending.commit()));
      alice.group.confirm_pending(
        alice.provider, pending, projection.verified_leaf_digest(),
      );
    } finally {
      free(projection);
      free(pending);
    }
  }
  alice.snapshotBytes = copyBytes(alice.provider.serialize_state());
  observer.snapshotBytes = copyBytes(observer.provider.serialize_state());
  return newcomers;
}

function cleanupUnjoined(peers) {
  for (const peer of peers) {
    free(peer.keyPackage);
    free(peer.identity);
    free(peer.provider);
  }
}

function prepareFromParent(wasm, peer, groupId, operation, argument = null) {
  const restored = restorePeer(wasm, peer, groupId);
  let pending;
  if (operation === 'self-update') {
    pending = restored.group.prepare_self_update(restored.provider, restored.identity);
  } else if (operation === 'add') {
    pending = restored.group.prepare_add(
      restored.provider, restored.identity, argument.keyPackage,
    );
  } else if (operation === 'remove') {
    pending = restored.group.prepare_remove(restored.provider, restored.identity, argument);
  } else {
    throw new Error('unsupported test operation');
  }
  return { ...restored, pending, commitBytes: copyBytes(pending.commit()) };
}

function cleanupPrepared(value) {
  free(value.pending); free(value.group); free(value.identity); free(value.provider);
}

function confirmPrepared(value) {
  const projection = value.pending.projection();
  try {
    value.group.confirm_pending(
      value.provider, value.pending, projection.verified_leaf_digest(),
    );
  } finally {
    free(projection);
  }
}

async function createClient(wasm, peer, groupId, tag, beforeCandidate) {
  const db = b25bDb(tag);
  const journal = createB25BJournalForDb(db);
  const coordinator = createB25BCoordinator({ journal, wasm, beforeCandidate });
  await coordinator.initializeStable({
    snapshotBytes: peer.snapshotBytes, groupId,
    accountKey: peer.publicKey, signatureKey: peer.signatureKey,
  });
  return { db, journal, coordinator };
}

function restoredFromRetained(wasm, retained) {
  return restorePeer(wasm, {
    snapshotBytes: retained.snapshotBytes,
    publicKey: Uint8Array.from(Buffer.from(retained.accountKeyHex, 'hex')),
    signatureKey: Uint8Array.from(Buffer.from(retained.signatureKeyHex, 'hex')),
  }, Uint8Array.from(Buffer.from(retained.groupIdHex, 'hex')));
}

function assertBidirectional(left, right) {
  for (const [sender, receiver, text] of [
    [left, right, 'b2-5b-left-to-right'], [right, left, 'b2-5b-right-to-left'],
  ]) {
    const plaintext = new TextEncoder().encode(text);
    const ciphertext = sender.group.create_application_message(
      sender.provider, sender.identity, plaintext,
    );
    expect(receiver.group.process_application_message(receiver.provider, ciphertext))
      .toEqual(plaintext);
  }
}

describe('Phase B2.5b authority boundary', () => {
  test('uses exactly eight isolated stores and exposes no authority finalizer', () => {
    const db = b25bDb('boundary');
    const journal = createB25BJournalForDb(db);
    expect(B25B_STORE_NAMES).toHaveLength(8);
    expect(B25B_STORE_NAMES).toEqual(expect.arrayContaining([
      'local-pending', 'publication-evidence',
    ]));
    expect({ commitPrepared: journal.commitPrepared,
      appendPublication: journal.appendPublication,
      commitResolution: journal.commitResolution }).toEqual({
      commitPrepared: undefined, appendPublication: undefined, commitResolution: undefined,
    });
    const foreign = new FakeVaultDb();
    Object.defineProperty(foreign, 'name', { value: 'foreign' });
    expect(() => createB25BJournalForDb(foreign)).toThrow(
      expect.objectContaining({ code: B25B_ERROR.INVALID }),
    );
    expect(() => new B25BJournal(db)).toThrow(expect.objectContaining({ code: B25B_ERROR.INVALID }));
    expect(() => new B25BEngineAdapter({})).toThrow(
      expect.objectContaining({ code: B25B_ERROR.INVALID }),
    );
  });
});

describe('Phase B2.5b real OpenMLS local-publisher arbitration', () => {
  test('keeps the local Commit non-canonical until ACK and proves cross-admission equivalence',
    async () => {
      const wasm = await loadWasm();
      const fixture = await setupGroup(wasm);
      const groupIdHex = bytesToHex(fixture.groupId);
      const publisher = await createClient(wasm, fixture.peers.bob, fixture.groupId, 'publisher');
      const receiver = await createClient(wasm, fixture.peers.alice, fixture.groupId, 'receiver');
      let left;
      let right;
      try {
        const before = (await publisher.journal.readHead(groupIdHex)).head;
        await publisher.coordinator.queueSelfUpdate(groupIdHex);
        const prepared = await publisher.coordinator.runQueuedOpportunity(groupIdHex);
        expect(prepared.state).toBe(B25B_LOCAL_STATE.PREPARED);
        expect((await publisher.journal.readHead(groupIdHex)).head.headDigestHex)
          .toBe(before.headDigestHex);
        await expect(publisher.coordinator.freeze(groupIdHex)).rejects.toMatchObject({
          code: B25B_ERROR.STATE_CONFLICT,
        });
        await publisher.coordinator.recordAttempt(groupIdHex);
        await expect(publisher.coordinator.freeze(groupIdHex)).rejects.toMatchObject({
          code: B25B_ERROR.STATE_CONFLICT,
        });
        const pending = await publisher.journal.readLocal(groupIdHex);
        await publisher.coordinator.recordAcknowledgement(
          groupIdHex, 1, pending.recipientScope[0], UTF8.encode('accepted'),
        );
        const echo = await publisher.coordinator.retainCommit(groupIdHex, pending.commitBytes);
        expect(echo).toMatchObject({ status: 'own_echo', commitDigestHex: pending.commitDigestHex });
        expect(await publisher.db.list(B25B_STORES.input)).toHaveLength(0);

        const localBatch = await publisher.coordinator.freeze(groupIdHex);
        await receiver.coordinator.retainCommit(groupIdHex, pending.commitBytes);
        const inboundBatch = await receiver.coordinator.freeze(groupIdHex);
        expect(localBatch.protocolBatchDigestHex).toBe(inboundBatch.protocolBatchDigestHex);
        const [localResult, inboundResult] = await Promise.all([
          publisher.coordinator.resolve(localBatch.protocolBatchDigestHex),
          receiver.coordinator.resolve(inboundBatch.protocolBatchDigestHex),
        ]);
        expect(localResult.batch.winnerCommitDigestHex).toBe(pending.commitDigestHex);
        expect(inboundResult.batch.winnerCommitDigestHex).toBe(pending.commitDigestHex);
        expect(localResult.head.epochDec).toBe(inboundResult.head.epochDec);
        expect(localResult.head.groupContextDigestHex)
          .toBe(inboundResult.head.groupContextDigestHex);
        expect(localResult.candidates[0].evidenceDigestHex)
          .toBe(inboundResult.candidates[0].evidenceDigestHex);
        expect((await publisher.journal.readLocal(groupIdHex)).state)
          .toBe(B25B_LOCAL_STATE.CONFIRMED);
        left = restoredFromRetained(wasm, localResult.retained);
        right = restoredFromRetained(wasm, inboundResult.retained);
        assertBidirectional(left, right);
      } finally {
        free(left?.group); free(left?.identity); free(left?.provider);
        free(right?.group); free(right?.identity); free(right?.provider);
        fixture.cleanup();
      }
    });

  test('requires explicit failure discard, makes ACK dominant, and records late contradiction',
    async () => {
      const wasm = await loadWasm();
      const fixture = await setupGroup(wasm, 21);
      const groupIdHex = bytesToHex(fixture.groupId);
      const client = await createClient(wasm, fixture.peers.bob, fixture.groupId, 'failure');
      try {
        await client.coordinator.queueSelfUpdate(groupIdHex);
        await client.coordinator.runQueuedOpportunity(groupIdHex);
        await client.coordinator.recordAttempt(groupIdHex);
        let local = await client.journal.readLocal(groupIdHex);
        const recipient = local.recipientScope[0];
        await client.coordinator.recordFailure(groupIdHex, 1, recipient, UTF8.encode('failed'));
        local = await client.journal.readLocal(groupIdHex);
        expect(local.state).toBe(B25B_LOCAL_STATE.PUBLISHING);
        await client.coordinator.discardAfterFailure(groupIdHex);
        expect((await client.journal.readLocal(groupIdHex)).state)
          .toBe(B25B_LOCAL_STATE.DISCARDED);
        await client.coordinator.recordAcknowledgement(
          groupIdHex, 1, recipient, UTF8.encode('late-accept'),
        );
        const evidence = await client.journal.readPublication(groupIdHex);
        expect(evidence.at(-1).kind).toBe(B25B_PUBLICATION_KIND.LATE_ACK);
        expect((await client.journal.readLocal(groupIdHex)).state)
          .toBe(B25B_LOCAL_STATE.DISCARDED);
      } finally {
        fixture.cleanup();
      }
    });

  test('selects a privileged inbound sibling and tombstones the losing local pending state',
    async () => {
      const wasm = await loadWasm();
      const fixture = await setupGroup(wasm, 41);
      const groupIdHex = bytesToHex(fixture.groupId);
      const eveProvider = new wasm.Provider();
      const eve = createPeer(wasm, eveProvider, 12);
      const inboundAdd = prepareFromParent(wasm, fixture.peers.alice, fixture.groupId, 'add', eve);
      const client = await createClient(wasm, fixture.peers.bob, fixture.groupId, 'inbound-wins');
      try {
        await client.coordinator.queueSelfUpdate(groupIdHex);
        await client.coordinator.runQueuedOpportunity(groupIdHex);
        await client.coordinator.recordAttempt(groupIdHex);
        const local = await client.journal.readLocal(groupIdHex);
        await client.coordinator.recordAcknowledgement(
          groupIdHex, 1, local.recipientScope[0], UTF8.encode('accepted'),
        );
        await client.coordinator.retainCommit(groupIdHex, inboundAdd.commitBytes);
        const batch = await client.coordinator.freeze(groupIdHex);
        const result = await client.coordinator.resolve(batch.protocolBatchDigestHex);
        expect(result.batch.winnerCommitDigestHex).toBe(digestHex(inboundAdd.commitBytes));
        expect((await client.journal.readLocal(groupIdHex)).state)
          .toBe(B25B_LOCAL_STATE.CLEARED_LOST);
        expect(result.retained.snapshotDigestHex).not.toBe(local.pendingSnapshotDigestHex);
      } finally {
        cleanupPrepared(inboundAdd);
        free(eve.keyPackage); free(eve.identity); free(eve.provider);
        fixture.cleanup();
      }
    });
});
