import { describe, expect, test } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { schnorr } from '@noble/curves/secp256k1';

import {
  B25_BATCH_STATE,
  B25_CANDIDATE_STATE,
  B25_DB_PREFIX,
  B25_DISPOSITION,
  B25_ERROR,
  B25_HEAD_STATE,
  B25_LIMITS,
  B25_STORES,
  B25_STORE_NAMES,
  bytesToHex,
  canonicalProviderEntries,
  compareCandidates,
  comparisonTupleDigest,
  copyBytes,
  digestHex,
} from '../../spikes/marmot-phase-b2-5a/b2-5a-canonical.mjs';
import {
  priorityForAuthorization,
  selectSameParentCandidate,
} from '../../spikes/marmot-phase-b2-5a/b2-5a-convergence.mjs';
import { B25EngineAdapter } from '../../spikes/marmot-phase-b2-5a/b2-5a-engine-adapter.mjs';
import {
  B25Journal,
  createB25JournalForDb,
} from '../../spikes/marmot-phase-b2-5a/b2-5a-journal.mjs';
import {
  buildCandidateEvidence,
  buildInput,
  buildRetainedState,
  buildTransition,
  parseBatch,
  parseHead,
  parseInput,
} from '../../spikes/marmot-phase-b2-5a/b2-5a-record.mjs';
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
      moduleUrl.searchParams.set('b2-5a-convergence-test', '1');
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

function b25Db(tag = 'test') {
  const db = new FakeVaultDb();
  Object.defineProperty(db, 'name', { value: `${B25_DB_PREFIX}${tag}` });
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

async function createAdapter(wasm, peer, groupId, tag, beforeCandidate) {
  const db = b25Db(tag);
  const journal = createB25JournalForDb(db);
  const adapter = journal.createEngineAdapter({ wasm, beforeCandidate });
  await adapter.initializeStable({
    snapshotBytes: peer.snapshotBytes,
    groupId,
    accountKey: peer.publicKey,
    signatureKey: peer.signatureKey,
  });
  return { db, journal, adapter };
}

async function collectFreeze(adapter, groupIdHex, commits) {
  for (const commit of commits) await adapter.retainCommit(groupIdHex, commit);
  return adapter.freeze(groupIdHex);
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
    [left, right, 'b2-5a-left-to-right'], [right, left, 'b2-5a-right-to-left'],
  ]) {
    const plaintext = new TextEncoder().encode(text);
    const ciphertext = sender.group.create_application_message(
      sender.provider, sender.identity, plaintext,
    );
    expect(receiver.group.process_application_message(receiver.provider, ciphertext))
      .toEqual(plaintext);
  }
}

function authorizedEvidence({ digest, priority, committer }) {
  return buildCandidateEvidence({
    groupIdHex: 'ab'.repeat(32), batchDigestHex: 'bc'.repeat(32),
    commitDigestHex: digest, state: B25_CANDIDATE_STATE.AUTHORIZED,
    reason: priority === 0 ? 'B24_ALLOW_ADD' : 'B24_ALLOW_SELF_UPDATE',
    parentEpochDec: '7', parentGroupContextDigestHex: 'cd'.repeat(32),
    projectionDigestHex: 'de'.repeat(32), candidateEpochDec: '8',
    candidateGroupContextDigestHex: digestHex(Uint8Array.from(Buffer.from(digest, 'hex'))),
    verifiedLeafDigestHex: 'ef'.repeat(32),
    operationKind: priority === 0 ? 'add' : 'self-update', priority,
    committerIdentityHex: committer,
    authorizationContextDigestHex: '11'.repeat(32),
    authorizationResultDigestHex: '22'.repeat(32),
    comparisonTupleDigestHex: comparisonTupleDigest({
      priority, committerIdentityHex: committer, commitDigestHex: digest,
    }),
  });
}

describe('Phase B2.5a closed ordering and namespace', () => {
  test('the tuple is total and independent of insertion order', () => {
    const lowCommit = '10'.repeat(32);
    const highCommit = '20'.repeat(32);
    const lowIdentity = '30'.repeat(32);
    const highIdentity = '40'.repeat(32);
    const candidates = [
      authorizedEvidence({ digest: highCommit, priority: 1, committer: lowIdentity }),
      authorizedEvidence({ digest: lowCommit, priority: 1, committer: lowIdentity }),
      authorizedEvidence({ digest: '50'.repeat(32), priority: 1, committer: highIdentity }),
      authorizedEvidence({ digest: '60'.repeat(32), priority: 0, committer: highIdentity }),
    ];
    for (const order of [candidates, [...candidates].reverse(), [candidates[2], candidates[0],
      candidates[3], candidates[1]]]) {
      expect(selectSameParentCandidate(order).commitDigestHex).toBe('60'.repeat(32));
    }
    expect(compareCandidates(candidates[1], candidates[0])).toBeLessThan(0);
    expect(priorityForAuthorization({ allowed: true, reason: 'B24_ALLOW_ADD' })).toBe(0);
    expect(priorityForAuthorization({ allowed: true, reason: 'B24_ALLOW_SELF_UPDATE' })).toBe(1);
  });

  test('the wrapper rejects construction and databases outside its isolated namespace', () => {
    const db = b25Db();
    expect(createB25JournalForDb(db)).toBeInstanceOf(B25Journal);
    expect(B25_DB_PREFIX).toBe('styx-b2-5a-poc-v1-');
    const foreign = new FakeVaultDb();
    Object.defineProperty(foreign, 'name', { value: 'styx-b2-4-poc-v1-test' });
    expect(() => createB25JournalForDb(foreign)).toThrow(
      expect.objectContaining({ code: B25_ERROR.INVALID }),
    );
    expect(() => new B25Journal(db)).toThrow(expect.objectContaining({ code: B25_ERROR.INVALID }));
    expect(() => new B25EngineAdapter({})).toThrow(
      expect.objectContaining({ code: B25_ERROR.INVALID }),
    );
    const isolated = createB25JournalForDb(db);
    expect({ initialize: isolated.initialize, commitResolution: isolated.commitResolution }).toEqual({
      initialize: undefined,
      commitResolution: undefined,
    });
    expect(B25_STORE_NAMES).toHaveLength(6);
  });
});

describe('Phase B2.5a real OpenMLS same-parent convergence', () => {
  test('permuted clients select the privileged branch and retain cross-member liveness', async () => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm);
    const eveProvider = new wasm.Provider();
    const eve = createPeer(wasm, eveProvider, 9);
    const add = prepareFromParent(wasm, fixture.peers.alice, fixture.groupId, 'add', eve);
    const bobUpdate = prepareFromParent(wasm, fixture.peers.bob, fixture.groupId, 'self-update');
    const aliceUpdate = prepareFromParent(wasm, fixture.peers.alice, fixture.groupId, 'self-update');
    const groupIdHex = bytesToHex(fixture.groupId);
    const clients = [];
    try {
      const orders = [
        [bobUpdate.commitBytes, add.commitBytes, aliceUpdate.commitBytes],
        [aliceUpdate.commitBytes, bobUpdate.commitBytes, add.commitBytes],
        [add.commitBytes, aliceUpdate.commitBytes, bobUpdate.commitBytes],
      ];
      clients.push(await createAdapter(wasm, fixture.peers.charlie, fixture.groupId, 'c-one',
        async (digest) => { if (digest.endsWith('0')) await Promise.resolve(); }));
      clients.push(await createAdapter(wasm, fixture.peers.charlie, fixture.groupId, 'c-two',
        async () => { await new Promise((resolve) => setImmediate(resolve)); }));
      clients.push(await createAdapter(wasm, fixture.peers.diana, fixture.groupId, 'd-one'));
      const batches = [];
      for (let index = 0; index < clients.length; index += 1) {
        batches.push(await collectFreeze(clients[index].adapter, groupIdHex, orders[index]));
      }
      expect(new Set(batches.map((batch) => batch.protocolBatchDigestHex)).size).toBe(1);
      const results = await Promise.all(clients.map((client, index) =>
        client.adapter.resolve(batches[index].protocolBatchDigestHex)));
      const addDigest = digestHex(add.commitBytes);
      expect(results.map((result) => result.batch.winnerCommitDigestHex))
        .toEqual([addDigest, addDigest, addDigest]);
      expect(new Set(results.map((result) => result.head.groupContextDigestHex)).size).toBe(1);
      expect(new Set(results.map((result) => result.head.epochDec)).size).toBe(1);
      expect(results.every((result) => result.batch.state === B25_BATCH_STATE.RESOLVED)).toBe(true);
      expect(canonicalProviderEntries(results[0].retained.snapshotBytes))
        .toEqual(canonicalProviderEntries(results[1].retained.snapshotBytes));

      const charlie = restoredFromRetained(wasm, results[0].retained);
      const diana = restoredFromRetained(wasm, results[2].retained);
      try { assertBidirectional(charlie, diana); } finally {
        free(charlie.group); free(charlie.identity); free(charlie.provider);
        free(diana.group); free(diana.identity); free(diana.provider);
      }
      const disposition = Object.fromEntries(results[0].batch.outcomes
        .map((item) => [item.commitDigestHex, item.disposition]));
      expect(disposition[addDigest]).toBe(B25_DISPOSITION.SELECTED);
      expect(disposition[digestHex(bobUpdate.commitBytes)]).toBe(B25_DISPOSITION.LOSING);
      expect(disposition[digestHex(aliceUpdate.commitBytes)]).toBe(B25_DISPOSITION.LOSING);
    } finally {
      for (const client of clients) client.journal.close();
      cleanupPrepared(add); cleanupPrepared(bobUpdate); cleanupPrepared(aliceUpdate);
      free(eve.keyPackage); free(eve.identity); free(eveProvider);
      fixture.cleanup();
    }
  }, 30000);

  test('same-committer fallback selects the lower exact Commit digest', async () => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm);
    const first = prepareFromParent(wasm, fixture.peers.alice, fixture.groupId, 'self-update');
    const second = prepareFromParent(wasm, fixture.peers.alice, fixture.groupId, 'self-update');
    const client = await createAdapter(wasm, fixture.peers.charlie, fixture.groupId, 'digest-fallback');
    try {
      const batch = await collectFreeze(client.adapter, bytesToHex(fixture.groupId),
        [first.commitBytes, second.commitBytes]);
      const result = await client.adapter.resolve(batch.protocolBatchDigestHex);
      expect(result.batch.winnerCommitDigestHex).toBe([
        digestHex(first.commitBytes), digestHex(second.commitBytes),
      ].sort()[0]);
    } finally {
      cleanupPrepared(first); cleanupPrepared(second); client.journal.close(); fixture.cleanup();
    }
  }, 30000);

  test('privileged Remove wins and a losing ordinary branch is not silently applied', async () => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm);
    const remove = prepareFromParent(
      wasm, fixture.peers.alice, fixture.groupId, 'remove', fixture.peers.diana.leafIndex,
    );
    const update = prepareFromParent(wasm, fixture.peers.bob, fixture.groupId, 'self-update');
    const clients = await Promise.all([
      createAdapter(wasm, fixture.peers.charlie, fixture.groupId, 'remove-priority-a'),
      createAdapter(wasm, fixture.peers.charlie, fixture.groupId, 'remove-priority-b'),
    ]);
    try {
      const results = [];
      for (let index = 0; index < clients.length; index += 1) {
        const order = index === 0
          ? [update.commitBytes, remove.commitBytes] : [remove.commitBytes, update.commitBytes];
        const batch = await collectFreeze(
          clients[index].adapter, bytesToHex(fixture.groupId), order,
        );
        results.push(await clients[index].adapter.resolve(batch.protocolBatchDigestHex));
      }
      const [resolved] = results;
      expect(results.map((item) => item.batch.protocolBatchDigestHex))
        .toEqual([resolved.batch.protocolBatchDigestHex, resolved.batch.protocolBatchDigestHex]);
      expect(results.map((item) => item.batch.winnerCommitDigestHex))
        .toEqual([digestHex(remove.commitBytes), digestHex(remove.commitBytes)]);
      expect(results.map((item) => item.head.groupContextDigestHex))
        .toEqual([resolved.head.groupContextDigestHex, resolved.head.groupContextDigestHex]);
      expect(resolved.batch.winnerCommitDigestHex).toBe(digestHex(remove.commitBytes));
      expect(resolved.candidates.find((item) =>
        item.commitDigestHex === digestHex(remove.commitBytes)).priority).toBe(0);
      confirmPrepared(remove);
      confirmPrepared(update);
      const canonical = restoredFromRetained(wasm, resolved.retained);
      try {
        assertBidirectional(canonical, remove);
        const losingMessage = update.group.create_application_message(
          update.provider, update.identity, new TextEncoder().encode('losing-branch'),
        );
        expect(() => canonical.group.process_application_message(
          canonical.provider, losingMessage,
        )).toThrow();
      } finally {
        free(canonical.group); free(canonical.identity); free(canonical.provider);
      }
    } finally {
      cleanupPrepared(remove); cleanupPrepared(update);
      for (const client of clients) client.journal.close();
      fixture.cleanup();
    }
  }, 30000);

  test('two ordinary committers are ordered by authenticated account identity', async () => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm);
    const alice = prepareFromParent(wasm, fixture.peers.alice, fixture.groupId, 'self-update');
    const bob = prepareFromParent(wasm, fixture.peers.bob, fixture.groupId, 'self-update');
    const clients = await Promise.all([
      createAdapter(wasm, fixture.peers.charlie, fixture.groupId, 'identity-order-a'),
      createAdapter(wasm, fixture.peers.charlie, fixture.groupId, 'identity-order-b'),
    ]);
    try {
      const expected = bytesToHex(fixture.peers.alice.publicKey) < bytesToHex(fixture.peers.bob.publicKey)
        ? digestHex(alice.commitBytes) : digestHex(bob.commitBytes);
      const winners = [];
      for (let index = 0; index < clients.length; index += 1) {
        const order = index === 0
          ? [bob.commitBytes, alice.commitBytes] : [alice.commitBytes, bob.commitBytes];
        const batch = await collectFreeze(
          clients[index].adapter, bytesToHex(fixture.groupId), order,
        );
        const resolved = await clients[index].adapter.resolve(batch.protocolBatchDigestHex);
        winners.push({
          batch: resolved.batch.protocolBatchDigestHex,
          commit: resolved.batch.winnerCommitDigestHex,
          context: resolved.head.groupContextDigestHex,
        });
      }
      expect(winners).toEqual([
        { batch: winners[0].batch, commit: expected, context: winners[0].context },
        { batch: winners[0].batch, commit: expected, context: winners[0].context },
      ]);
    } finally {
      cleanupPrepared(alice); cleanupPrepared(bob);
      for (const client of clients) client.journal.close();
      fixture.cleanup();
    }
  }, 30000);

  test('wrong-group, wrong-parent and non-admin branches cannot enter ordering', async () => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm);
    const foreign = await setupGroup(wasm, 65);
    const valid = prepareFromParent(wasm, fixture.peers.alice, fixture.groupId, 'self-update');
    const denied = prepareFromParent(
      wasm, fixture.peers.bob, fixture.groupId, 'remove', fixture.peers.diana.leafIndex,
    );
    const foreignUpdate = prepareFromParent(
      wasm, foreign.peers.alice, foreign.groupId, 'self-update',
    );
    const wrongParent = prepareFromParent(
      wasm, fixture.peers.alice, fixture.groupId, 'self-update',
    );
    confirmPrepared(wrongParent);
    free(wrongParent.pending);
    wrongParent.pending = wrongParent.group.prepare_self_update(
      wrongParent.provider, wrongParent.identity,
    );
    wrongParent.commitBytes = copyBytes(wrongParent.pending.commit());
    const client = await createAdapter(wasm, fixture.peers.charlie, fixture.groupId, 'closed-inputs');
    try {
      const batch = await collectFreeze(client.adapter, bytesToHex(fixture.groupId), [
        wrongParent.commitBytes, denied.commitBytes, foreignUpdate.commitBytes, valid.commitBytes,
      ]);
      const resolved = await client.adapter.resolve(batch.protocolBatchDigestHex);
      expect(resolved.batch.winnerCommitDigestHex).toBe(digestHex(valid.commitBytes));
      const byDigest = Object.fromEntries(resolved.candidates
        .map((candidate) => [candidate.commitDigestHex, candidate]));
      expect(byDigest[digestHex(denied.commitBytes)].state).toBe(B25_CANDIDATE_STATE.REJECTED);
      expect(byDigest[digestHex(foreignUpdate.commitBytes)].state)
        .toBe(B25_CANDIDATE_STATE.NOT_CANDIDATE);
      expect(byDigest[digestHex(wrongParent.commitBytes)].state)
        .toBe(B25_CANDIDATE_STATE.NOT_CANDIDATE);
    } finally {
      for (const value of [valid, denied, foreignUpdate, wrongParent]) cleanupPrepared(value);
      client.journal.close(); foreign.cleanup(); fixture.cleanup();
    }
  }, 30000);

  test('an over-profile branch is terminally ineligible without blocking a valid sibling', async () => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm);
    const newcomers = extendGroupWithoutJoining(
      wasm, fixture, 'charlie', B25_LIMITS.maxMembers - 4, 20,
    );
    const extraProvider = new wasm.Provider();
    const extra = createPeer(wasm, extraProvider, 40);
    const overProfile = prepareFromParent(
      wasm, fixture.peers.alice, fixture.groupId, 'add', extra,
    );
    const valid = prepareFromParent(
      wasm, fixture.peers.alice, fixture.groupId, 'self-update',
    );
    const client = await createAdapter(
      wasm, fixture.peers.charlie, fixture.groupId, 'over-profile-sibling',
    );
    try {
      expect(fixture.peers.alice.group.member_count()).toBe(B25_LIMITS.maxMembers);
      const batch = await collectFreeze(client.adapter, bytesToHex(fixture.groupId), [
        overProfile.commitBytes, valid.commitBytes,
      ]);
      const resolved = await client.adapter.resolve(batch.protocolBatchDigestHex);
      expect(resolved.batch.state).toBe(B25_BATCH_STATE.RESOLVED);
      expect(resolved.batch.winnerCommitDigestHex).toBe(digestHex(valid.commitBytes));
      expect(resolved.candidates.find((candidate) =>
        candidate.commitDigestHex === digestHex(overProfile.commitBytes)).state)
        .toBe(B25_CANDIDATE_STATE.NOT_CANDIDATE);
      expect(resolved.candidates.find((candidate) =>
        candidate.commitDigestHex === digestHex(valid.commitBytes)).state)
        .toBe(B25_CANDIDATE_STATE.AUTHORIZED);
    } finally {
      cleanupPrepared(overProfile);
      cleanupPrepared(valid);
      client.journal.close();
      cleanupUnjoined(newcomers);
      free(extra.keyPackage);
      free(extra.identity);
      free(extraProvider);
      fixture.cleanup();
    }
  }, 30000);

  test('post-freeze bytes are deferred and cannot change the frozen winner', async () => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm);
    const first = prepareFromParent(wasm, fixture.peers.alice, fixture.groupId, 'self-update');
    const deferred = prepareFromParent(wasm, fixture.peers.bob, fixture.groupId, 'self-update');
    const client = await createAdapter(wasm, fixture.peers.charlie, fixture.groupId, 'deferred-input');
    const groupIdHex = bytesToHex(fixture.groupId);
    try {
      await client.adapter.retainCommit(groupIdHex, first.commitBytes);
      const frozen = await client.adapter.freeze(groupIdHex);
      await client.adapter.retainCommit(groupIdHex, deferred.commitBytes);
      const firstResult = await client.adapter.resolve(frozen.protocolBatchDigestHex);
      expect(firstResult.batch.commitDigests).toEqual([digestHex(first.commitBytes)]);
      expect(firstResult.batch.winnerCommitDigestHex).toBe(digestHex(first.commitBytes));
      const later = await client.adapter.freeze(groupIdHex);
      expect(later.commitDigests).toEqual([digestHex(deferred.commitBytes)]);
      const laterResult = await client.adapter.resolve(later.protocolBatchDigestHex);
      expect(laterResult.batch.winnerCommitDigestHex).toBeNull();
    } finally {
      cleanupPrepared(first); cleanupPrepared(deferred); client.journal.close(); fixture.cleanup();
    }
  }, 30000);

  test('a resolved batch remains readable after a later canonical advance', async () => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm);
    const first = prepareFromParent(
      wasm, fixture.peers.alice, fixture.groupId, 'self-update',
    );
    const client = await createAdapter(
      wasm, fixture.peers.charlie, fixture.groupId, 'historical-resolution',
    );
    let second;
    let third;
    try {
      const firstBatch = await collectFreeze(
        client.adapter, bytesToHex(fixture.groupId), [first.commitBytes],
      );
      const firstResult = await client.adapter.resolve(firstBatch.protocolBatchDigestHex);
      confirmPrepared(first);
      first.snapshotBytes = copyBytes(first.provider.serialize_state());
      first.publicKey = fixture.peers.alice.publicKey;
      first.signatureKey = fixture.peers.alice.signatureKey;
      second = prepareFromParent(
        wasm, first, fixture.groupId, 'self-update',
      );
      const secondBatch = await collectFreeze(
        client.adapter, bytesToHex(fixture.groupId), [second.commitBytes],
      );
      const secondResult = await client.adapter.resolve(secondBatch.protocolBatchDigestHex);
      expect(secondResult.head.headDigestHex).not.toBe(firstResult.head.headDigestHex);

      const replay = await client.adapter.resolve(firstBatch.protocolBatchDigestHex);
      expect(replay.head).toEqual(firstResult.head);
      expect(replay.transition).toEqual(firstResult.transition);
      expect(replay.retained).toEqual(firstResult.retained);
      expect(replay.batch).toEqual(firstResult.batch);

      const nullBatch = await collectFreeze(
        client.adapter, bytesToHex(fixture.groupId), [Uint8Array.of(1, 2, 3, 4)],
      );
      const nullResult = await client.adapter.resolve(nullBatch.protocolBatchDigestHex);
      expect(nullResult.batch.winnerCommitDigestHex).toBeNull();
      expect(nullResult.head).toEqual(secondResult.head);

      confirmPrepared(second);
      second.snapshotBytes = copyBytes(second.provider.serialize_state());
      second.publicKey = fixture.peers.alice.publicKey;
      second.signatureKey = fixture.peers.alice.signatureKey;
      third = prepareFromParent(
        wasm, second, fixture.groupId, 'self-update',
      );
      const thirdBatch = await collectFreeze(
        client.adapter, bytesToHex(fixture.groupId), [third.commitBytes],
      );
      const thirdResult = await client.adapter.resolve(thirdBatch.protocolBatchDigestHex);

      const nullReplay = await client.adapter.resolve(nullBatch.protocolBatchDigestHex);
      expect(nullReplay.head).toEqual(secondResult.head);
      expect(nullReplay.transition).toBeNull();
      expect(nullReplay.retained).toBeNull();

      const spurious = buildTransition({
        groupIdHex: nullResult.head.groupIdHex,
        seq: thirdResult.head.seq + 1,
        kind: 'RESOLVE',
        priorHeadDigestHex: nullResult.head.headDigestHex,
        batchDigestHex: nullBatch.protocolBatchDigestHex,
        winnerCommitDigestHex: digestHex(third.commitBytes),
        snapshotDigestHex: thirdResult.head.snapshotDigestHex,
        epochDec: thirdResult.head.epochDec,
        groupContextDigestHex: thirdResult.head.groupContextDigestHex,
        outcomesDigestHex: '77'.repeat(32),
      });
      await client.db.transaction(B25_STORE_NAMES, (ops) =>
        ops.put(B25_STORES.transition, spurious.transitionDigestHex, spurious));
      await expect(client.adapter.resolve(nullBatch.protocolBatchDigestHex)).rejects.toMatchObject({
        code: B25_ERROR.CORRUPT,
      });
    } finally {
      cleanupPrepared(first);
      if (second !== undefined) cleanupPrepared(second);
      if (third !== undefined) cleanupPrepared(third);
      client.journal.close();
      fixture.cleanup();
    }
  }, 30000);

  test('OwnCommit and malformed bytes resolve to a terminal null winner without head mutation', async () => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm);
    const own = prepareFromParent(wasm, fixture.peers.alice, fixture.groupId, 'self-update');
    const client = await createAdapter(wasm, fixture.peers.alice, fixture.groupId, 'own-commit');
    const groupIdHex = bytesToHex(fixture.groupId);
    try {
      const before = (await client.journal.readHead(groupIdHex)).head;
      const mutable = Uint8Array.of(1, 2, 3, 4);
      await client.adapter.retainCommit(groupIdHex, mutable);
      mutable.fill(9);
      const duplicate = await client.adapter.retainCommit(groupIdHex, own.commitBytes);
      expect(duplicate.status).toBe('retained');
      expect((await client.adapter.retainCommit(groupIdHex, own.commitBytes)).status).toBe('duplicate');
      const batch = await client.adapter.freeze(groupIdHex);
      const result = await client.adapter.resolve(batch.protocolBatchDigestHex);
      expect(result.batch.winnerCommitDigestHex).toBeNull();
      expect(result.transition).toBeNull();
      expect(result.head).toEqual(before);
      expect(result.batch.outcomes.every((item) =>
        item.disposition === B25_DISPOSITION.NOT_CANDIDATE)).toBe(true);
      const replay = await client.adapter.resolve(batch.protocolBatchDigestHex);
      expect(replay.head).toEqual(before);
      expect(replay.batch.batchRecordDigestHex).toBe(result.batch.batchRecordDigestHex);
    } finally {
      cleanupPrepared(own); client.journal.close(); fixture.cleanup();
    }
  }, 30000);

  test('every six-store write failure rolls back and deterministic retry selects the same winner', async () => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm);
    const update = prepareFromParent(wasm, fixture.peers.alice, fixture.groupId, 'self-update');
    const client = await createAdapter(wasm, fixture.peers.charlie, fixture.groupId, 'atomicity');
    const groupIdHex = bytesToHex(fixture.groupId);
    try {
      const batch = await collectFreeze(client.adapter, groupIdHex, [update.commitBytes]);
      const original = await client.journal.readFrozen(batch.protocolBatchDigestHex);
      for (const store of [B25_STORES.candidate, B25_STORES.input, B25_STORES.batch,
        B25_STORES.retained, B25_STORES.transition, B25_STORES.head]) {
        let fired = false;
        client.db.failOn = (namespace) => {
          if (!fired && namespace === store) { fired = true; return true; }
          return false;
        };
        await expect(client.adapter.resolve(batch.protocolBatchDigestHex)).rejects.toThrow('injected crash');
        client.db.failOn = null;
        const after = await client.journal.readFrozen(batch.protocolBatchDigestHex);
        expect(after.head).toEqual(original.head);
        expect(after.batch).toEqual(original.batch);
        expect(after.inputs).toEqual(original.inputs);
        expect(after.candidates).toEqual(original.candidates);
      }
      const resolved = await client.adapter.resolve(batch.protocolBatchDigestHex);
      expect(resolved.batch.winnerCommitDigestHex).toBe(digestHex(update.commitBytes));
      expect((await client.adapter.resolve(batch.protocolBatchDigestHex)).head)
        .toEqual(resolved.head);
    } finally {
      cleanupPrepared(update); client.journal.close(); fixture.cleanup();
    }
  }, 30000);

  test('changed frozen inputs and missing retained parents fail closed', async () => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm);
    const update = prepareFromParent(wasm, fixture.peers.alice, fixture.groupId, 'self-update');
    const first = await createAdapter(wasm, fixture.peers.charlie, fixture.groupId, 'tamper');
    const second = await createAdapter(wasm, fixture.peers.charlie, fixture.groupId, 'missing');
    const groupIdHex = bytesToHex(fixture.groupId);
    try {
      const firstBatch = await collectFreeze(first.adapter, groupIdHex, [update.commitBytes]);
      const inputStoreKey = `${groupIdHex}:${digestHex(update.commitBytes)}`;
      const raw = deepClone(first.db.record(B25_STORES.input, inputStoreKey));
      raw.commitBytes[0] ^= 1;
      first.db._store(B25_STORES.input).set(inputStoreKey, raw);
      await expect(first.adapter.resolve(firstBatch.protocolBatchDigestHex)).rejects.toMatchObject({
        code: B25_ERROR.CORRUPT,
      });

      const secondBatch = await collectFreeze(second.adapter, groupIdHex, [update.commitBytes]);
      const head = parseHead(second.db.record(B25_STORES.head, groupIdHex));
      second.db._store(B25_STORES.retained).delete(head.snapshotDigestHex);
      await expect(second.adapter.resolve(secondBatch.protocolBatchDigestHex)).rejects.toMatchObject({
        code: B25_ERROR.UNRECOVERABLE,
      });
      expect(parseBatch(second.db.record(B25_STORES.batch,
        secondBatch.protocolBatchDigestHex)).state).toBe(B25_BATCH_STATE.FROZEN);
      const terminal = await second.journal.readHead(groupIdHex);
      expect(terminal.head.state).toBe(B25_HEAD_STATE.UNRECOVERABLE);
      expect(terminal.head.epochDec).toBe(head.epochDec);
      expect(terminal.head.groupContextDigestHex).toBe(head.groupContextDigestHex);
      expect(terminal.head.snapshotDigestHex).toBe(head.snapshotDigestHex);
      expect(terminal.head.seq).toBe(head.seq + 1);
      expect(terminal.retained).toBeNull();
      await expect(second.adapter.resolve(secondBatch.protocolBatchDigestHex)).rejects.toMatchObject({
        code: B25_ERROR.UNRECOVERABLE,
      });
      expect((await second.journal.readHead(groupIdHex)).head).toEqual(terminal.head);
    } finally {
      cleanupPrepared(update); first.journal.close(); second.journal.close(); fixture.cleanup();
    }
  }, 30000);

  test('strict records reject unknown fields, counter overflow and impossible disposition state', () => {
    const baseHead = {
      format: 'styx-marmot-b2-5a-head', version: 1,
      profile: 'same-parent-one-commit-branch-selection-poc', runtime: {
        openMlsRevision: '09e92777dba0528d3d29e2e5e681b7e91637c7be',
        wasmArtifactSha256: '60dbbc1127fbfb0e7e479cf7e2f7e6e20183c60d0559268f039d8db58bf60a3a',
        ciphersuite: 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519',
        marmotRevision: '4ad4ae21479c3f3fa9950c6fc4556a76941a62e1',
      },
      groupIdHex: 'aa', accountKeyHex: 'bb'.repeat(32), signatureKeyHex: 'cc'.repeat(32),
      seq: 1, state: 'STABLE', epochDec: '0',
      groupContextDigestHex: 'dd'.repeat(32), snapshotDigestHex: 'ee'.repeat(32),
      priorHeadDigestHex: null, transitionDigestHex: 'ff'.repeat(32),
      selectedCommitDigestHex: null, headDigestHex: '11'.repeat(32),
    };
    expect(() => parseHead({ ...baseHead, extra: true }))
      .toThrow(expect.objectContaining({ code: B25_ERROR.INVALID }));
    expect(() => parseHead({ ...baseHead, seq: Number.MAX_SAFE_INTEGER + 1 }))
      .toThrow(expect.objectContaining({ code: 'B23_INVALID' }));
    const input = {
      format: 'styx-marmot-b2-5a-input', version: 1, groupIdHex: 'aa',
      batchDigestHex: null, commitDigestHex: digestHex(Uint8Array.of(1)),
      commitByteLength: 1, commitBytes: Uint8Array.of(1), disposition: 'SELECTED',
      inputDigestHex: '00'.repeat(32),
    };
    expect(() => parseInput(input)).toThrow(expect.objectContaining({ code: B25_ERROR.INVALID }));
  });

  test('a coherent record stored under a conflicting Commit digest fails closed', async () => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm);
    const client = await createAdapter(wasm, fixture.peers.charlie, fixture.groupId, 'digest-collision');
    const groupIdHex = bytesToHex(fixture.groupId);
    const proposed = Uint8Array.of(9, 8, 7);
    const foreign = buildInput({ groupIdHex, commitBytes: Uint8Array.of(1, 2, 3) });
    const proposedKey = `${groupIdHex}:${digestHex(proposed)}`;
    try {
      client.db._store(B25_STORES.input).set(proposedKey, foreign);
      await expect(client.adapter.retainCommit(groupIdHex, proposed)).rejects.toMatchObject({
        code: B25_ERROR.CORRUPT,
      });
      expect(client.db.record(B25_STORES.input, proposedKey)).toEqual(foreign);
    } finally {
      client.journal.close(); fixture.cleanup();
    }
  }, 30000);

  test('empty, oversized and over-cap collection fail closed', async () => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm);
    const client = await createAdapter(wasm, fixture.peers.charlie, fixture.groupId, 'resource-bounds');
    const groupIdHex = bytesToHex(fixture.groupId);
    try {
      await expect(client.adapter.freeze(groupIdHex)).rejects.toMatchObject({
        code: B25_ERROR.STATE_CONFLICT,
      });
      await expect(client.adapter.retainCommit(
        groupIdHex, new Uint8Array(B25_LIMITS.maxCommitBytes + 1),
      )).rejects.toBeDefined();
      for (let index = 0; index < B25_LIMITS.maxBatchCommits; index += 1) {
        await client.adapter.retainCommit(groupIdHex, Uint8Array.of(index + 1));
      }
      await expect(client.adapter.retainCommit(groupIdHex, Uint8Array.of(0xff, 0xff)))
        .rejects.toMatchObject({ code: B25_ERROR.RESOURCE_LIMIT });
    } finally {
      client.journal.close(); fixture.cleanup();
    }
  }, 30000);

  test('the public journal exposes no authority-bearing finalization API', async () => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm);
    const client = await createAdapter(wasm, fixture.peers.charlie, fixture.groupId, 'forged-evidence');
    const groupIdHex = bytesToHex(fixture.groupId);
    try {
      await client.adapter.retainCommit(groupIdHex, Uint8Array.of(1, 2, 3));
      const batch = await client.adapter.freeze(groupIdHex);
      const bundle = await client.journal.readFrozen(batch.protocolBatchDigestHex);
      const digest = batch.commitDigests[0];
      const committer = '44'.repeat(32);
      const forged = buildCandidateEvidence({
        groupIdHex, batchDigestHex: batch.protocolBatchDigestHex,
        commitDigestHex: digest, state: B25_CANDIDATE_STATE.AUTHORIZED,
        reason: 'B24_ALLOW_SELF_UPDATE', parentEpochDec: batch.baseEpochDec,
        parentGroupContextDigestHex: batch.baseGroupContextDigestHex,
        projectionDigestHex: '11'.repeat(32),
        candidateEpochDec: (BigInt(batch.baseEpochDec) + 1n).toString(),
        candidateGroupContextDigestHex: '22'.repeat(32), verifiedLeafDigestHex: '33'.repeat(32),
        operationKind: 'self-update', priority: 1, committerIdentityHex: committer,
        authorizationContextDigestHex: '55'.repeat(32),
        authorizationResultDigestHex: '66'.repeat(32),
        comparisonTupleDigestHex: comparisonTupleDigest({
          priority: 1, committerIdentityHex: committer, commitDigestHex: digest,
        }),
      });
      const forgedSuccessor = buildRetainedState({
        groupIdHex,
        accountKeyHex: bundle.head.accountKeyHex,
        signatureKeyHex: bundle.head.signatureKeyHex,
        epochDec: forged.candidateEpochDec,
        groupContextDigestHex: forged.candidateGroupContextDigestHex,
        snapshotBytes: new Uint8Array(8),
      });
      const forgedResolution = {
        expectedHead: bundle.head, frozenBatch: bundle.batch,
        expectedInputs: bundle.inputs, expectedCandidates: bundle.candidates,
        candidates: [forged], successorRetained: forgedSuccessor,
      };
      expect(client.journal.commitResolution).toBeUndefined();
      expect(() => client.journal.commitResolution(forgedResolution)).toThrow(TypeError);
      expect((await client.journal.readFrozen(batch.protocolBatchDigestHex)).head)
        .toEqual(bundle.head);
    } finally {
      client.journal.close(); fixture.cleanup();
    }
  }, 30000);
});
