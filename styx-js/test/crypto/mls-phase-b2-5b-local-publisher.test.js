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
  B25B_TERMINAL_DISPOSITION,
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
  parseCandidateEvidence,
  parseHead,
  parseInput,
  parseLocal,
  parsePublication,
  parseRetainedState,
  parseTransition,
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

async function queueOperation(client, groupIdHex, operation, argument = null) {
  if (operation === 'self-update') return client.coordinator.queueSelfUpdate(groupIdHex);
  if (operation === 'add') return client.coordinator.queueAdd(groupIdHex, argument.framed);
  if (operation === 'remove') return client.coordinator.queueRemove(groupIdHex, argument);
  throw new Error(`unsupported queued operation: ${operation}`);
}

async function acknowledgeFirstRecipient(client, groupIdHex, payload = 'accepted') {
  const local = await client.journal.readLocal(groupIdHex);
  await client.coordinator.recordAcknowledgement(
    groupIdHex, local.publishAttempts, local.recipientScope[0], UTF8.encode(payload),
  );
  return client.journal.readLocal(groupIdHex);
}

function durableImage(db) {
  return B25B_STORE_NAMES.map((store) => [store,
    [...db.stores.get(store)?.entries() ?? []]
      .sort(([left], [right]) => String(left).localeCompare(String(right)))
      .map(([key, value]) => [key, deepClone(value)])]);
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
        const confirmed = await publisher.journal.readLocal(groupIdHex);
        expect(confirmed.state).toBe(B25B_LOCAL_STATE.CONFIRMED);
        await publisher.coordinator.recordAcknowledgement(
          groupIdHex, 1, confirmed.recipientScope[1], UTF8.encode('post-confirmation'),
        );
        await publisher.coordinator.recordFailure(
          groupIdHex, 1, confirmed.recipientScope[1], UTF8.encode('post-confirmation-failure'),
        );
        const stillConfirmed = await publisher.journal.readLocal(groupIdHex);
        expect(stillConfirmed).toEqual(confirmed);
        const terminalEvidence = await publisher.journal.readPublication(groupIdHex);
        expect(terminalEvidence.at(-2).kind).toBe(B25B_PUBLICATION_KIND.LATE_ACK);
        expect(terminalEvidence.at(-1).kind).toBe(B25B_PUBLICATION_KIND.FAILURE);
        const terminalEcho = await publisher.coordinator.retainCommit(
          groupIdHex, pending.commitBytes,
        );
        expect(terminalEcho.status).toBe('own_echo');
        expect(await publisher.db.list(B25B_STORES.input)).toHaveLength(0);
        await publisher.coordinator.queueSelfUpdate(groupIdHex);
        expect((await publisher.journal.readLocal(groupIdHex)).state)
          .toBe(B25B_LOCAL_STATE.QUEUED);
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
        const cleared = await client.journal.readLocal(groupIdHex);
        expect(cleared.state).toBe(B25B_LOCAL_STATE.CLEARED_LOST);
        await client.coordinator.recordAcknowledgement(
          groupIdHex, 1, cleared.recipientScope[1], UTF8.encode('post-loss'),
        );
        await client.coordinator.recordFailure(
          groupIdHex, 1, cleared.recipientScope[1], UTF8.encode('post-loss-failure'),
        );
        expect(await client.journal.readLocal(groupIdHex)).toEqual(cleared);
        expect(result.retained.snapshotDigestHex).not.toBe(local.pendingSnapshotDigestHex);
      } finally {
        cleanupPrepared(inboundAdd);
        free(eve.keyPackage); free(eve.identity); free(eve.provider);
        fixture.cleanup();
      }
    });

  test.each(['add', 'remove'])('authorizes and confirms an acknowledged local %s',
    async (operation) => {
      const wasm = await loadWasm();
      const fixture = await setupGroup(wasm, operation === 'add' ? 61 : 71);
      const groupIdHex = bytesToHex(fixture.groupId);
      const newcomerProvider = new wasm.Provider();
      const newcomer = createPeer(wasm, newcomerProvider, operation === 'add' ? 13 : 14);
      const client = await createClient(wasm, fixture.peers.alice, fixture.groupId,
        `local-${operation}`);
      try {
        const before = (await client.journal.readHead(groupIdHex)).head;
        await queueOperation(client, groupIdHex, operation,
          operation === 'add' ? newcomer : fixture.peers.charlie.leafIndex);
        await client.coordinator.runQueuedOpportunity(groupIdHex);
        const prepared = await client.journal.readLocal(groupIdHex);
        expect(prepared.operationKind).toBe(operation);
        expect((await client.journal.readHead(groupIdHex)).head.headDigestHex)
          .toBe(before.headDigestHex);
        await client.coordinator.recordAttempt(groupIdHex);
        await acknowledgeFirstRecipient(client, groupIdHex);
        const result = await client.coordinator.settlePass(groupIdHex);
        expect(result.batch.winnerCommitDigestHex).toBe(prepared.commitDigestHex);
        expect((await client.journal.readLocal(groupIdHex)).state)
          .toBe(B25B_LOCAL_STATE.CONFIRMED);
        expect(result.head.epochDec).toBe('4');
        if (operation === 'add') expect(prepared.welcomeBytes.length).toBeGreaterThan(0);
      } finally {
        free(newcomer.keyPackage); free(newcomer.identity); free(newcomer.provider);
        fixture.cleanup();
      }
    });

  test.each(['add', 'remove'])('selects a contested local %s over an inbound self-update',
    async (operation) => {
      const wasm = await loadWasm();
      const fixture = await setupGroup(wasm, operation === 'add' ? 81 : 91);
      const groupIdHex = bytesToHex(fixture.groupId);
      const newcomerProvider = new wasm.Provider();
      const newcomer = createPeer(wasm, newcomerProvider, operation === 'add' ? 15 : 16);
      const inbound = prepareFromParent(
        wasm, fixture.peers.bob, fixture.groupId, 'self-update',
      );
      const client = await createClient(
        wasm, fixture.peers.alice, fixture.groupId, `contested-local-${operation}`,
      );
      try {
        await queueOperation(client, groupIdHex, operation,
          operation === 'add' ? newcomer : fixture.peers.charlie.leafIndex);
        await client.coordinator.runQueuedOpportunity(groupIdHex);
        await client.coordinator.recordAttempt(groupIdHex);
        const local = await acknowledgeFirstRecipient(client, groupIdHex, 'contested');
        await client.coordinator.retainCommit(groupIdHex, inbound.commitBytes);
        const result = await client.coordinator.settlePass(groupIdHex);
        expect(local.priority).toBe(0);
        expect(result.batch.winnerCommitDigestHex).toBe(local.commitDigestHex);
        expect(result.candidates.find((item) =>
          item.commitDigestHex === digestHex(inbound.commitBytes)).priority).toBe(1);
        expect((await client.journal.readLocal(groupIdHex)).state)
          .toBe(B25B_LOCAL_STATE.CONFIRMED);
      } finally {
        cleanupPrepared(inbound);
        free(newcomer.keyPackage); free(newcomer.identity); free(newcomer.provider);
        fixture.cleanup();
      }
    });

  test.each([
    ['wins', 0, 3, B25B_LOCAL_STATE.CONFIRMED],
    ['loses', 3, 0, B25B_LOCAL_STATE.CLEARED_LOST],
  ])('makes a contested local self-update %s by authenticated identity order',
    async (_outcome, localRank, inboundRank, expectedState) => {
      const wasm = await loadWasm();
      const fixture = await setupGroup(wasm, localRank === 0 ? 96 : 97);
      const groupIdHex = bytesToHex(fixture.groupId);
      const ordered = Object.values(fixture.peers)
        .sort((left, right) => bytesToHex(left.publicKey).localeCompare(bytesToHex(right.publicKey)));
      const localPeer = ordered[localRank];
      const inboundPeer = ordered[inboundRank];
      const inbound = prepareFromParent(wasm, inboundPeer, fixture.groupId, 'self-update');
      const client = await createClient(
        wasm, localPeer, fixture.groupId, `self-update-${_outcome}`,
      );
      try {
        await client.coordinator.queueSelfUpdate(groupIdHex);
        await client.coordinator.runQueuedOpportunity(groupIdHex);
        await client.coordinator.recordAttempt(groupIdHex);
        const local = await acknowledgeFirstRecipient(client, groupIdHex, _outcome);
        await client.coordinator.retainCommit(groupIdHex, inbound.commitBytes);
        const result = await client.coordinator.settlePass(groupIdHex);
        const expectedWinner = localRank < inboundRank
          ? local.commitDigestHex : digestHex(inbound.commitBytes);
        expect(result.batch.winnerCommitDigestHex).toBe(expectedWinner);
        expect((await client.journal.readLocal(groupIdHex)).state).toBe(expectedState);
      } finally {
        cleanupPrepared(inbound);
        fixture.cleanup();
      }
    });

  test('binds attempts and outcomes, retries exact bytes, and makes acknowledgement dominant',
    async () => {
      const wasm = await loadWasm();
      const fixture = await setupGroup(wasm, 101);
      const groupIdHex = bytesToHex(fixture.groupId);
      const client = await createClient(wasm, fixture.peers.bob, fixture.groupId, 'evidence');
      try {
        await client.coordinator.queueSelfUpdate(groupIdHex);
        await client.coordinator.runQueuedOpportunity(groupIdHex);
        let local = await client.journal.readLocal(groupIdHex);
        await expect(client.coordinator.recordAcknowledgement(
          groupIdHex, 1, local.recipientScope[0], UTF8.encode('early'),
        )).rejects.toMatchObject({ code: B25B_ERROR.INVALID });
        await client.coordinator.recordAttempt(groupIdHex);
        await expect(client.coordinator.recordAcknowledgement(
          groupIdHex, 2, local.recipientScope[0], UTF8.encode('wrong-attempt'),
        )).rejects.toMatchObject({ code: B25B_ERROR.INVALID });
        await expect(client.coordinator.recordAcknowledgement(
          groupIdHex, 1, 'ff'.repeat(32), UTF8.encode('wrong-recipient'),
        )).rejects.toMatchObject({ code: B25B_ERROR.INVALID });
        await client.coordinator.recordAttempt(groupIdHex);
        let evidence = await client.journal.readPublication(groupIdHex);
        expect(evidence.filter((item) => item.kind === B25B_PUBLICATION_KIND.ATTEMPT))
          .toHaveLength(2);
        expect(evidence[0].artifactBytes).toEqual(evidence[1].artifactBytes);
        expect(evidence[0].artifactDigestHex).toBe(evidence[1].artifactDigestHex);
        local = await client.journal.readLocal(groupIdHex);
        await client.coordinator.recordFailure(
          groupIdHex, 2, local.recipientScope[0], UTF8.encode('ambiguous'),
        );
        expect((await client.journal.readHead(groupIdHex)).head.epochDec).toBe('3');
        await client.coordinator.recordAcknowledgement(
          groupIdHex, 1, local.recipientScope[0], UTF8.encode('accepted'),
        );
        const duplicate = await client.coordinator.recordAcknowledgement(
          groupIdHex, 1, local.recipientScope[0], UTF8.encode('caller-payload-changed'),
        );
        expect(duplicate.status).toBe('duplicate');
        await client.coordinator.recordFailure(
          groupIdHex, 1, local.recipientScope[0], UTF8.encode('late-failure'),
        );
        expect((await client.journal.readLocal(groupIdHex)).state)
          .toBe(B25B_LOCAL_STATE.ACKNOWLEDGED);
        await expect(client.coordinator.discardAfterFailure(groupIdHex)).rejects.toMatchObject({
          code: B25B_ERROR.STATE_CONFLICT,
        });
        evidence = await client.journal.readPublication(groupIdHex);
        expect(evidence.every((item) => item.artifactDigestHex === local.commitDigestHex)).toBe(true);
      } finally {
        fixture.cleanup();
      }
    });

  test('cancels only before an attempt and recovers ambiguous publication without applying it',
    async () => {
      const wasm = await loadWasm();
      const fixture = await setupGroup(wasm, 111);
      const groupIdHex = bytesToHex(fixture.groupId);
      const cancelled = await createClient(wasm, fixture.peers.bob, fixture.groupId, 'cancel');
      const ambiguous = await createClient(wasm, fixture.peers.charlie, fixture.groupId, 'ambiguous');
      try {
        await cancelled.coordinator.queueSelfUpdate(groupIdHex);
        await cancelled.coordinator.runQueuedOpportunity(groupIdHex);
        await cancelled.coordinator.cancelBeforeAttempt(groupIdHex);
        expect((await cancelled.journal.readLocal(groupIdHex)).state)
          .toBe(B25B_LOCAL_STATE.CANCELLED);

        await ambiguous.coordinator.queueSelfUpdate(groupIdHex);
        await ambiguous.coordinator.runQueuedOpportunity(groupIdHex);
        await ambiguous.coordinator.recordAttempt(groupIdHex);
        const before = (await ambiguous.journal.readHead(groupIdHex)).head;
        const restarted = createB25BCoordinator({
          journal: createB25BJournalForDb(ambiguous.db), wasm,
        });
        const recovered = await ambiguous.journal.readLocal(groupIdHex);
        expect(recovered.state).toBe(B25B_LOCAL_STATE.PUBLISHING);
        await expect(restarted.freeze(groupIdHex)).rejects.toMatchObject({
          code: B25B_ERROR.STATE_CONFLICT,
        });
        await restarted.recordAttempt(groupIdHex);
        expect((await ambiguous.journal.readHead(groupIdHex)).head).toEqual(before);
        const attempts = (await ambiguous.journal.readPublication(groupIdHex))
          .filter((item) => item.kind === B25B_PUBLICATION_KIND.ATTEMPT);
        expect(attempts).toHaveLength(2);
        expect(attempts[0].artifactBytes).toEqual(attempts[1].artifactBytes);
      } finally {
        fixture.cleanup();
      }
    });

  test('terminally closes a failed queued preparation opportunity', async () => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm, 116);
    const groupIdHex = bytesToHex(fixture.groupId);
    const client = await createClient(wasm, fixture.peers.bob, fixture.groupId, 'prepare-fails');
    try {
      await client.coordinator.queueRemove(groupIdHex, fixture.peers.bob.leafIndex);
      await expect(client.coordinator.runQueuedOpportunity(groupIdHex)).rejects.toMatchObject({
        code: B25B_ERROR.INVALID,
      });
      const failed = await client.journal.readLocal(groupIdHex);
      expect(failed).toMatchObject({
        state: B25B_LOCAL_STATE.CANCELLED,
        terminalDisposition: B25B_TERMINAL_DISPOSITION.PREPARATION_FAILED,
        commitDigestHex: null,
        publishAttempts: 0,
      });
      await client.coordinator.queueSelfUpdate(groupIdHex);
      expect((await client.journal.readLocal(groupIdHex)).state)
        .toBe(B25B_LOCAL_STATE.QUEUED);
    } finally {
      fixture.cleanup();
    }
  });

  test('restarts cleanly through queued, prepared, acknowledged, and frozen states', async () => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm, 118);
    const groupIdHex = bytesToHex(fixture.groupId);
    const client = await createClient(wasm, fixture.peers.bob, fixture.groupId, 'restart-matrix');
    try {
      await client.coordinator.queueSelfUpdate(groupIdHex);
      let restarted = createB25BCoordinator({
        journal: createB25BJournalForDb(client.db), wasm,
      });
      expect((await client.journal.readLocal(groupIdHex)).state).toBe(B25B_LOCAL_STATE.QUEUED);
      await restarted.runQueuedOpportunity(groupIdHex);

      restarted = createB25BCoordinator({ journal: createB25BJournalForDb(client.db), wasm });
      expect((await client.journal.readLocal(groupIdHex)).state).toBe(B25B_LOCAL_STATE.PREPARED);
      await restarted.recordAttempt(groupIdHex);
      const publishing = await client.journal.readLocal(groupIdHex);
      await restarted.recordAcknowledgement(
        groupIdHex, 1, publishing.recipientScope[0], UTF8.encode('restart-ack'),
      );

      restarted = createB25BCoordinator({ journal: createB25BJournalForDb(client.db), wasm });
      expect((await client.journal.readLocal(groupIdHex)).state)
        .toBe(B25B_LOCAL_STATE.ACKNOWLEDGED);
      const batch = await restarted.freeze(groupIdHex);

      restarted = createB25BCoordinator({ journal: createB25BJournalForDb(client.db), wasm });
      expect((await client.journal.readFrozen(batch.protocolBatchDigestHex)).batch.state)
        .toBe(B25B_BATCH_STATE.FROZEN);
      const result = await restarted.resolve(batch.protocolBatchDigestHex);
      expect(result.batch.state).toBe(B25B_BATCH_STATE.RESOLVED);
      expect((await client.journal.readLocal(groupIdHex)).state)
        .toBe(B25B_LOCAL_STATE.CONFIRMED);
    } finally {
      fixture.cleanup();
    }
  });

  test('freezes eligibility at cutoff and retains post-cutoff input for later work', async () => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm, 121);
    const groupIdHex = bytesToHex(fixture.groupId);
    const first = prepareFromParent(wasm, fixture.peers.alice, fixture.groupId, 'self-update');
    const second = prepareFromParent(wasm, fixture.peers.charlie, fixture.groupId, 'self-update');
    const client = await createClient(wasm, fixture.peers.bob, fixture.groupId, 'cutoff');
    try {
      await client.coordinator.queueSelfUpdate(groupIdHex);
      await client.coordinator.runQueuedOpportunity(groupIdHex);
      await client.coordinator.recordAttempt(groupIdHex);
      const local = await client.journal.readLocal(groupIdHex);
      await client.coordinator.retainCommit(groupIdHex, first.commitBytes);
      const frozen = await client.coordinator.freeze(groupIdHex);
      expect(frozen.commitDigests).not.toContain(local.commitDigestHex);
      await client.coordinator.recordAcknowledgement(
        groupIdHex, 1, local.recipientScope[0], UTF8.encode('after-cutoff'),
      );
      await client.coordinator.retainCommit(groupIdHex, second.commitBytes);
      const result = await client.coordinator.resolve(frozen.protocolBatchDigestHex);
      expect(result.batch.commitDigests).toEqual([digestHex(first.commitBytes)]);
      expect(result.batch.winnerCommitDigestHex).toBe(digestHex(first.commitBytes));
      expect((await client.journal.readLocal(groupIdHex)).state)
        .toBe(B25B_LOCAL_STATE.CLEARED_LOST);
      const lateInput = parseInput(client.db.record(
        B25B_STORES.input, `${groupIdHex}:${digestHex(second.commitBytes)}`,
      ));
      expect(lateInput.disposition).toBe(B25B_DISPOSITION.COLLECTED);
    } finally {
      cleanupPrepared(first); cleanupPrepared(second); fixture.cleanup();
    }
  });

  test('reserves the sixteenth candidate slot for an active local opportunity', async () => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm, 126);
    const groupIdHex = bytesToHex(fixture.groupId);
    const prepared = [];
    const unique = new Set();
    const reserved = await createClient(wasm, fixture.peers.bob, fixture.groupId, 'cap-reserved');
    const inboundOnly = await createClient(wasm, fixture.peers.charlie, fixture.groupId, 'cap-full');
    try {
      for (let attempt = 0; unique.size < B25B_LIMITS.maxBatchCommits && attempt < 64;
        attempt += 1) {
        const sibling = prepareFromParent(
          wasm, fixture.peers.alice, fixture.groupId, 'self-update',
        );
        const digest = digestHex(sibling.commitBytes);
        if (unique.has(digest)) cleanupPrepared(sibling);
        else {
          unique.add(digest);
          prepared.push(sibling);
        }
      }
      expect(prepared).toHaveLength(B25B_LIMITS.maxBatchCommits);

      await reserved.coordinator.queueSelfUpdate(groupIdHex);
      for (const sibling of prepared.slice(0, B25B_LIMITS.maxBatchCommits - 1)) {
        await reserved.coordinator.retainCommit(groupIdHex, sibling.commitBytes);
      }
      await expect(reserved.coordinator.retainCommit(
        groupIdHex, prepared.at(-1).commitBytes,
      )).rejects.toMatchObject({ code: B25B_ERROR.RESOURCE_LIMIT });

      for (const sibling of prepared) {
        await inboundOnly.coordinator.retainCommit(groupIdHex, sibling.commitBytes);
      }
      await expect(inboundOnly.coordinator.queueSelfUpdate(groupIdHex)).rejects.toMatchObject({
        code: B25B_ERROR.RESOURCE_LIMIT,
      });
    } finally {
      prepared.forEach(cleanupPrepared);
      fixture.cleanup();
    }
  });

  test('strict local and publication codecs reject unknown, corrupt, and over-limit records',
    async () => {
      const wasm = await loadWasm();
      const fixture = await setupGroup(wasm, 131);
      const groupIdHex = bytesToHex(fixture.groupId);
      const client = await createClient(wasm, fixture.peers.bob, fixture.groupId, 'codec');
      try {
        await client.coordinator.queueSelfUpdate(groupIdHex);
        await client.coordinator.runQueuedOpportunity(groupIdHex);
        await client.coordinator.recordAttempt(groupIdHex);
        const local = deepClone(await client.journal.readLocal(groupIdHex));
        expect(() => parseLocal({ ...local, injected: true })).toThrow(
          expect.objectContaining({ code: B25B_ERROR.INVALID }),
        );
        expect(() => parseLocal({ ...local, state: 'MAGIC' })).toThrow(
          expect.objectContaining({ code: B25B_ERROR.INVALID }),
        );
        expect(() => parseLocal({ ...local, publishAttempts: 65 })).toThrow();
        expect(() => parseLocal({ ...local, recipientScope: [
          local.recipientScope[0], local.recipientScope[0],
        ] })).toThrow(expect.objectContaining({ code: B25B_ERROR.INVALID }));
        const publication = deepClone((await client.journal.readPublication(groupIdHex))[0]);
        expect(() => parsePublication({ ...publication, injected: true })).toThrow(
          expect.objectContaining({ code: B25B_ERROR.INVALID }),
        );
        expect(() => parsePublication({ ...publication, kind: 'SUCCESS' })).toThrow(
          expect.objectContaining({ code: B25B_ERROR.INVALID }),
        );
        const corrupt = deepClone(publication);
        corrupt.artifactBytes[0] ^= 1;
        expect(() => parsePublication(corrupt)).toThrow(
          expect.objectContaining({ code: B25B_ERROR.CORRUPT }),
        );
      } finally {
        fixture.cleanup();
      }
    });

  test('strictly parses every durable record and rejects incoherent frozen bindings', async () => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm, 136);
    const groupIdHex = bytesToHex(fixture.groupId);
    const inbound = prepareFromParent(wasm, fixture.peers.alice, fixture.groupId, 'self-update');
    const client = await createClient(wasm, fixture.peers.bob, fixture.groupId, 'all-codecs');
    try {
      await client.coordinator.retainCommit(groupIdHex, inbound.commitBytes);
      const batch = await client.coordinator.freeze(groupIdHex);
      const digest = digestHex(inbound.commitBytes);
      const inputKeyValue = `${groupIdHex}:${digest}`;
      const candidateKeyValue = `${batch.protocolBatchDigestHex}:${digest}`;
      const head = deepClone(client.db.record(B25B_STORES.head, groupIdHex));
      const retained = deepClone(client.db.record(B25B_STORES.retained, head.snapshotDigestHex));
      const input = deepClone(client.db.record(B25B_STORES.input, inputKeyValue));
      const frozen = deepClone(client.db.record(
        B25B_STORES.batch, batch.protocolBatchDigestHex,
      ));
      const candidate = deepClone(client.db.record(B25B_STORES.candidate, candidateKeyValue));
      const transition = deepClone(client.db.record(
        B25B_STORES.transition, head.transitionDigestHex,
      ));
      for (const [parser, record] of [
        [parseHead, head],
        [parseRetainedState, retained],
        [parseInput, input],
        [parseBatch, frozen],
        [parseCandidateEvidence, candidate],
        [parseTransition, transition],
      ]) {
        expect(() => parser({ ...record, injected: true })).toThrow(
          expect.objectContaining({ code: B25B_ERROR.INVALID }),
        );
      }

      const wrongGroupInput = buildInput({
        groupIdHex: 'ff'.repeat(32),
        batchDigestHex: batch.protocolBatchDigestHex,
        commitBytes: input.commitBytes,
        disposition: B25B_DISPOSITION.FROZEN,
      });
      client.db.stores.get(B25B_STORES.input).set(inputKeyValue, wrongGroupInput);
      await expect(client.journal.readFrozen(batch.protocolBatchDigestHex)).rejects.toMatchObject({
        code: B25B_ERROR.CORRUPT,
      });
      client.db.stores.get(B25B_STORES.input).set(inputKeyValue, input);
      expect((await client.journal.readFrozen(batch.protocolBatchDigestHex)).batch)
        .toEqual(batch);
    } finally {
      cleanupPrepared(inbound);
      fixture.cleanup();
    }
  });

  test('rolls back preparation and freeze transactions at each written store', async () => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm, 138);
    const groupIdHex = bytesToHex(fixture.groupId);
    const inbound = prepareFromParent(wasm, fixture.peers.alice, fixture.groupId, 'self-update');
    const client = await createClient(wasm, fixture.peers.bob, fixture.groupId, 'early-rollback');
    try {
      await client.coordinator.queueSelfUpdate(groupIdHex);
      for (const store of [B25B_STORES.retained, B25B_STORES.local]) {
        const before = durableImage(client.db);
        let injected = false;
        client.db.failOn = (candidateStore) => {
          if (!injected && candidateStore === store) { injected = true; return true; }
          return false;
        };
        await expect(client.coordinator.runQueuedOpportunity(groupIdHex))
          .rejects.toThrow('injected crash');
        client.db.failOn = null;
        expect(injected).toBe(true);
        expect(durableImage(client.db)).toEqual(before);
        expect((await client.journal.readLocal(groupIdHex)).state).toBe(B25B_LOCAL_STATE.QUEUED);
      }
      await client.coordinator.runQueuedOpportunity(groupIdHex);
      await client.coordinator.recordAttempt(groupIdHex);
      await acknowledgeFirstRecipient(client, groupIdHex, 'freeze-rollback');
      await client.coordinator.retainCommit(groupIdHex, inbound.commitBytes);
      for (const store of [
        B25B_STORES.batch, B25B_STORES.input, B25B_STORES.candidate, B25B_STORES.local,
      ]) {
        const before = durableImage(client.db);
        let injected = false;
        client.db.failOn = (candidateStore) => {
          if (!injected && candidateStore === store) { injected = true; return true; }
          return false;
        };
        await expect(client.coordinator.freeze(groupIdHex)).rejects.toThrow('injected crash');
        client.db.failOn = null;
        expect(injected).toBe(true);
        expect(durableImage(client.db)).toEqual(before);
      }
      expect((await client.coordinator.freeze(groupIdHex)).state).toBe(B25B_BATCH_STATE.FROZEN);
    } finally {
      cleanupPrepared(inbound);
      fixture.cleanup();
    }
  });

  test('rolls back every final logical-store write and retries deterministically', async () => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm, 141);
    const groupIdHex = bytesToHex(fixture.groupId);
    const inbound = prepareFromParent(wasm, fixture.peers.alice, fixture.groupId, 'self-update');
    const client = await createClient(wasm, fixture.peers.bob, fixture.groupId, 'rollback');
    try {
      await client.coordinator.queueSelfUpdate(groupIdHex);
      await client.coordinator.runQueuedOpportunity(groupIdHex);
      const preAttempt = durableImage(client.db);
      client.db.failOn = (store) => store === B25B_STORES.publication;
      await expect(client.coordinator.recordAttempt(groupIdHex)).rejects.toThrow('injected crash');
      client.db.failOn = null;
      expect(durableImage(client.db)).toEqual(preAttempt);
      await client.coordinator.recordAttempt(groupIdHex);
      await acknowledgeFirstRecipient(client, groupIdHex);
      await client.coordinator.retainCommit(groupIdHex, inbound.commitBytes);
      const batch = await client.coordinator.freeze(groupIdHex);
      const frozenLocal = await client.journal.readLocal(groupIdHex);
      for (const store of B25B_STORE_NAMES.filter((name) => name !== B25B_STORES.publication)) {
        const before = durableImage(client.db);
        let injected = false;
        client.db.failOn = (candidateStore) => {
          if (!injected && candidateStore === store) { injected = true; return true; }
          return false;
        };
        await expect(client.coordinator.resolve(batch.protocolBatchDigestHex))
          .rejects.toThrow('injected crash');
        client.db.failOn = null;
        expect(injected).toBe(true);
        expect(durableImage(client.db)).toEqual(before);
        expect((await client.journal.readHead(groupIdHex)).head.epochDec).toBe('3');
        expect((await client.journal.readLocal(groupIdHex)).localPendingDigestHex)
          .toBe(frozenLocal.localPendingDigestHex);
      }
      const result = await client.coordinator.resolve(batch.protocolBatchDigestHex);
      expect(result.batch.state).toBe(B25B_BATCH_STATE.RESOLVED);
      const replay = await client.coordinator.resolve(batch.protocolBatchDigestHex);
      expect(replay.head).toEqual(result.head);
      expect(replay.batch).toEqual(result.batch);
    } finally {
      cleanupPrepared(inbound); fixture.cleanup();
    }
  });

  test('binds publication outcomes to the active local generation', async () => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm, 19);
    const groupIdHex = bytesToHex(fixture.groupId);
    const client = await createClient(wasm, fixture.peers.bob, fixture.groupId, 'generations');
    try {
      for (const generation of [1, 2]) {
        await client.coordinator.queueSelfUpdate(groupIdHex);
        await client.coordinator.runQueuedOpportunity(groupIdHex);
        await client.coordinator.recordAttempt(groupIdHex);
        const publishing = await client.journal.readLocal(groupIdHex);
        expect(publishing.publishAttempts).toBe(1);
        await client.coordinator.recordAcknowledgement(
          groupIdHex, 1, publishing.recipientScope[0],
          UTF8.encode(`generation-${generation}-ack`),
        );
        const result = await client.coordinator.settlePass(groupIdHex);
        expect(result.batch.winnerCommitDigestHex).toBe(publishing.commitDigestHex);
        expect((await client.journal.readLocal(groupIdHex)).state)
          .toBe(B25B_LOCAL_STATE.CONFIRMED);
      }
    } finally {
      fixture.cleanup();
    }
  });

  test('gives a queued local intent the next bounded opportunity against the selected head',
    async () => {
      const wasm = await loadWasm();
      const fixture = await setupGroup(wasm, 151);
      const groupIdHex = bytesToHex(fixture.groupId);
      const firstInbound = prepareFromParent(
        wasm, fixture.peers.alice, fixture.groupId, 'self-update',
      );
      const client = await createClient(wasm, fixture.peers.bob, fixture.groupId, 'sequential');
      try {
        await client.coordinator.retainCommit(groupIdHex, firstInbound.commitBytes);
        const first = await client.coordinator.settlePass(groupIdHex);
        expect(first.head.epochDec).toBe('4');
        await client.coordinator.queueSelfUpdate(groupIdHex);
        const opportunity = await client.coordinator.runQueuedOpportunity(groupIdHex);
        expect(opportunity.state).toBe(B25B_LOCAL_STATE.PREPARED);
        expect(opportunity.parentHeadDigestHex).toBe(first.head.headDigestHex);
        expect((await client.journal.readHead(groupIdHex)).head).toEqual(first.head);
        await client.coordinator.recordAttempt(groupIdHex);
        await acknowledgeFirstRecipient(client, groupIdHex, 'sequential-ack');
        const second = await client.coordinator.settlePass(groupIdHex);
        expect(second.head.epochDec).toBe('5');
        expect(second.head.priorHeadDigestHex).toBe(first.head.headDigestHex);
      } finally {
        cleanupPrepared(firstInbound); fixture.cleanup();
      }
    });

  test('makes the cross-cutoff partition divergence boundary executable', async () => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm, 161);
    const groupIdHex = bytesToHex(fixture.groupId);
    const branchA = prepareFromParent(wasm, fixture.peers.alice, fixture.groupId, 'self-update');
    const branchB = prepareFromParent(wasm, fixture.peers.charlie, fixture.groupId, 'self-update');
    const clientA = await createClient(wasm, fixture.peers.bob, fixture.groupId, 'partition-a');
    const clientB = await createClient(wasm, fixture.peers.diana, fixture.groupId, 'partition-b');
    try {
      const baseA = (await clientA.journal.readHead(groupIdHex)).head;
      const baseB = (await clientB.journal.readHead(groupIdHex)).head;
      expect(baseA.epochDec).toBe(baseB.epochDec);
      expect(baseA.groupContextDigestHex).toBe(baseB.groupContextDigestHex);
      expect((await clientA.coordinator.retainCommit(groupIdHex, branchA.commitBytes)).status)
        .toBe('retained');
      expect((await clientA.coordinator.retainCommit(groupIdHex, branchA.commitBytes)).status)
        .toBe('duplicate');
      await clientB.coordinator.retainCommit(groupIdHex, branchB.commitBytes);
      const [resultA, resultB] = await Promise.all([
        clientA.coordinator.settlePass(groupIdHex),
        clientB.coordinator.settlePass(groupIdHex),
      ]);
      expect(resultA.batch.winnerCommitDigestHex).toBe(digestHex(branchA.commitBytes));
      expect(resultB.batch.winnerCommitDigestHex).toBe(digestHex(branchB.commitBytes));
      expect(resultA.head.groupContextDigestHex).not.toBe(resultB.head.groupContextDigestHex);
      expect(resultA.head.priorHeadDigestHex).toBe(baseA.headDigestHex);
      expect(resultB.head.priorHeadDigestHex).toBe(baseB.headDigestHex);
      // B2.5b deliberately has no retained-history rewind: exchanging the
      // late sibling now can only defer it and cannot revise either result.
      const lateA = await clientA.coordinator.retainCommit(groupIdHex, branchB.commitBytes);
      const lateB = await clientB.coordinator.retainCommit(groupIdHex, branchA.commitBytes);
      expect(lateA.status).toBe('retained');
      expect(lateB.status).toBe('retained');
      const [deferredA, deferredB] = await Promise.all([
        clientA.coordinator.settlePass(groupIdHex),
        clientB.coordinator.settlePass(groupIdHex),
      ]);
      expect(deferredA.batch.winnerCommitDigestHex).toBeNull();
      expect(deferredB.batch.winnerCommitDigestHex).toBeNull();
      expect(deferredA.candidates[0].state).toBe(B25B_CANDIDATE_STATE.NOT_CANDIDATE);
      expect(deferredB.candidates[0].state).toBe(B25B_CANDIDATE_STATE.NOT_CANDIDATE);
      expect(deferredA.head.groupContextDigestHex).toBe(resultA.head.groupContextDigestHex);
      expect(deferredB.head.groupContextDigestHex).toBe(resultB.head.groupContextDigestHex);
    } finally {
      cleanupPrepared(branchA); cleanupPrepared(branchB); fixture.cleanup();
    }
  });
});
