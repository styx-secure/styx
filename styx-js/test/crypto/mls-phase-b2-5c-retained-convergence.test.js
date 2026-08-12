import { describe, expect, test } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { schnorr } from '@noble/curves/secp256k1';

import {
  B25C_DB_PREFIX,
  B25C_ERROR,
  B25C_HEAD_STATE,
  B25C_LIMITS,
  B25C_STORES,
  bytesToHex,
  copyBytes,
  digestHex,
} from '../../spikes/marmot-phase-b2-5c/b2-5c-canonical.mjs';
import { createB25CJournalForDb }
  from '../../spikes/marmot-phase-b2-5c/b2-5c-journal.mjs';
import { createB25CCoordinator }
  from '../../spikes/marmot-phase-b2-5c/b2-5c-coordinator.mjs';
import { buildInput, buildRetainedState, parseInput }
  from '../../spikes/marmot-phase-b2-5c/b2-5c-record.mjs';
import { FakeVaultDb } from '../support/fake-vault-db.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const VENDOR = join(HERE, '../../vendor/openmls-wasm');
const UTF8 = new TextEncoder();
let wasmPromise;

function free(value) {
  try { value?.free?.(); } catch { /* test cleanup */ }
}

function createAccountIdentityProofV2(privateKey, leafSignatureKey, createdAt) {
  const publicKey = Uint8Array.from(schnorr.getPublicKey(privateKey));
  const publicKeyHex = bytesToHex(publicKey);
  const event = [0, publicKeyHex, createdAt, 450, [
    ['d', 'marmot.account-identity-proof.v2'],
    ['component', '0x8009'],
    ['ciphersuite', '0x0001'],
    ['signature_scheme', '0x0807'],
    ['mls_signature_key', bytesToHex(leafSignatureKey)],
  ], 'Authorize this MLS leaf key for my Marmot account'];
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
      moduleUrl.searchParams.set('b2-5c-convergence-test', '1');
      const wasm = await import(moduleUrl.href);
      await wasm.default({ module_or_path: readFileSync(join(VENDOR, 'openmls_wasm_bg.wasm')) });
      return wasm;
    })();
  }
  return wasmPromise;
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
  return { privateKey, publicKey, identity, signatureKey, proof, keyPackage };
}

function mergeInbound(group, provider, commitBytes) {
  const staged = group.stage_inbound_commit(provider, commitBytes);
  const projection = staged.projection();
  try {
    group.merge_staged_commit(provider, staged, projection.verified_leaf_digest());
  } finally {
    free(projection); free(staged);
  }
}

async function setupGroup(wasm) {
  const groupId = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
  const peers = {};
  const names = ['alice', 'bob', 'charlie', 'diana'];
  for (let index = 0; index < names.length; index += 1) {
    const provider = new wasm.Provider();
    peers[names[index]] = { ...createPeer(wasm, provider, index + 1), provider, group: null };
  }
  peers.alice.group = wasm.PhaseB2Group.create_new(
    peers.alice.provider, peers.alice.identity, groupId, peers.alice.proof);
  const active = [peers.alice];
  for (const name of names.slice(1)) {
    const joining = peers[name];
    const pending = peers.alice.group.prepare_add(
      peers.alice.provider, peers.alice.identity, joining.keyPackage);
    const commitBytes = copyBytes(pending.commit());
    const welcomeBytes = copyBytes(pending.welcome());
    for (const peer of active.slice(1)) mergeInbound(peer.group, peer.provider, commitBytes);
    const projection = pending.projection();
    peers.alice.group.confirm_pending(
      peers.alice.provider, pending, projection.verified_leaf_digest());
    const tree = peers.alice.group.export_ratchet_tree();
    const parsedTree = wasm.PhaseB2RatchetTree.from_bytes(tree.to_bytes());
    joining.group = wasm.PhaseB2Group.join(joining.provider, welcomeBytes, parsedTree);
    active.push(joining);
    free(parsedTree); free(tree); free(projection); free(pending);
  }
  for (const peer of active) peer.snapshotBytes = copyBytes(peer.provider.serialize_state());
  return { groupId, peers, cleanup() {
    for (const peer of Object.values(peers)) {
      free(peer.group); free(peer.keyPackage); free(peer.identity); free(peer.provider);
    }
  } };
}

function restoreSource(wasm, source, groupId, snapshotBytes) {
  const provider = new wasm.Provider();
  provider.restore_state(snapshotBytes);
  const identity = wasm.PhaseB2Identity.load(provider, source.publicKey, source.signatureKey);
  const group = wasm.PhaseB2Group.load(provider, groupId);
  if (identity === undefined || group === undefined) throw new Error('source restore failed');
  return { provider, identity, group };
}

function selfUpdateFrom(wasm, source, groupId, snapshotBytes) {
  const restored = restoreSource(wasm, source, groupId, snapshotBytes);
  const pending = restored.group.prepare_self_update(restored.provider, restored.identity);
  const projection = pending.projection();
  const commitBytes = copyBytes(pending.commit());
  restored.group.confirm_pending(
    restored.provider, pending, projection.verified_leaf_digest());
  const successorSnapshotBytes = copyBytes(restored.provider.serialize_state());
  free(projection); free(pending); free(restored.group); free(restored.identity); free(restored.provider);
  return { commitBytes, successorSnapshotBytes };
}

function inboundSuccessorFrom(wasm, source, groupId, snapshotBytes, commitBytes) {
  const restored = restoreSource(wasm, source, groupId, snapshotBytes);
  mergeInbound(restored.group, restored.provider, commitBytes);
  const result = Object.freeze({
    snapshotBytes: copyBytes(restored.provider.serialize_state()),
    epochDec: restored.group.epoch().toString(),
    groupContextDigestHex: bytesToHex(
      restored.group.group_context_sha256(restored.provider)),
  });
  free(restored.group); free(restored.identity); free(restored.provider);
  return result;
}

function clientFor(wasm, peer, groupId, tag, hooks = {}) {
  const db = new FakeVaultDb();
  Object.defineProperty(db, 'name', { value: `${B25C_DB_PREFIX}${tag}` });
  const journal = createB25CJournalForDb(db);
  const coordinator = createB25CCoordinator({ journal, wasm, ...hooks });
  return { db, journal, coordinator,
    initialize: () => coordinator.initializeStable({ snapshotBytes: peer.snapshotBytes,
      groupId, accountKey: peer.publicKey, signatureKey: peer.signatureKey }) };
}

async function settleInputs(client, groupId, commits) {
  for (const commit of commits) await client.coordinator.admitCommit(bytesToHex(groupId), commit);
  return client.coordinator.settlePass(bytesToHex(groupId));
}

describe('Phase B2.5c retained-history convergence', () => {
  test('child-before-parent and different cutoff partitions converge by depth then B2.5a tip',
    async () => {
      const wasm = await loadWasm();
      const fixture = await setupGroup(wasm);
      try {
        const base = fixture.peers.alice.snapshotBytes;
        const left = selfUpdateFrom(wasm, fixture.peers.alice, fixture.groupId, base);
        const right = selfUpdateFrom(wasm, fixture.peers.alice, fixture.groupId, base);
        const leftChild = selfUpdateFrom(
          wasm, fixture.peers.alice, fixture.groupId, left.successorSnapshotBytes);
        const clients = [
          clientFor(wasm, fixture.peers.bob, fixture.groupId, 'all'),
          clientFor(wasm, fixture.peers.charlie, fixture.groupId, 'split'),
          clientFor(wasm, fixture.peers.diana, fixture.groupId, 'reverse'),
        ];
        await Promise.all(clients.map((client) => client.initialize()));
        await settleInputs(clients[0], fixture.groupId,
          [right.commitBytes, leftChild.commitBytes, left.commitBytes]);
        await settleInputs(clients[1], fixture.groupId, [leftChild.commitBytes]);
        const deferred = await clients[1].journal.snapshot(bytesToHex(fixture.groupId));
        expect(deferred.head.canonicalPath).toEqual([]);
        expect(deferred.inputs.find((item) =>
          item.commitDigestHex === digestHex(leftChild.commitBytes)).state).toBe('DEFERRED');
        await settleInputs(clients[1], fixture.groupId, [right.commitBytes]);
        await settleInputs(clients[1], fixture.groupId, [left.commitBytes]);
        await settleInputs(clients[2], fixture.groupId, [right.commitBytes]);
        await settleInputs(clients[2], fixture.groupId,
          [left.commitBytes, leftChild.commitBytes]);
        const heads = await Promise.all(clients.map((client) =>
          client.journal.readHead(bytesToHex(fixture.groupId))));
        expect(heads.map((item) => item.head.canonicalPath))
          .toEqual([heads[0].head.canonicalPath, heads[0].head.canonicalPath,
            heads[0].head.canonicalPath]);
        expect(heads[0].head.canonicalPath).toHaveLength(2);
        expect(heads.map((item) => item.head.epochDec)).toEqual([
          heads[0].head.epochDec, heads[0].head.epochDec, heads[0].head.epochDec]);
        expect(heads.map((item) => item.head.groupContextDigestHex)).toEqual([
          heads[0].head.groupContextDigestHex,
          heads[0].head.groupContextDigestHex,
          heads[0].head.groupContextDigestHex,
        ]);
      } finally { fixture.cleanup(); }
    }, 20000);

  test('write-ahead probe is one-use across restart and remains selection-inert', async () => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm);
    try {
      const update = selfUpdateFrom(
        wasm, fixture.peers.alice, fixture.groupId, fixture.peers.alice.snapshotBytes);
      const bob = clientFor(wasm, fixture.peers.bob, fixture.groupId, 'probe-bob');
      const charlie = clientFor(wasm, fixture.peers.charlie, fixture.groupId, 'probe-charlie');
      await bob.initialize(); await charlie.initialize();
      await settleInputs(bob, fixture.groupId, [update.commitBytes]);
      await settleInputs(charlie, fixture.groupId, [update.commitBytes]);
      const plaintext = UTF8.encode('b2.5c one-use liveness');
      const probe = await bob.coordinator.createLivenessProbe(
        bytesToHex(fixture.groupId), plaintext);
      const received = await charlie.coordinator.processLivenessProbe(
        bytesToHex(fixture.groupId), probe.ciphertextBytes);
      expect(received).toEqual(plaintext);
      await bob.coordinator.completeLivenessProbe(probe,
        bytesToHex(fixture.peers.charlie.publicKey));
      const reverseProbe = await charlie.coordinator.createLivenessProbe(
        bytesToHex(fixture.groupId), UTF8.encode('b2.5c reverse liveness'));
      const reverseReceived = await bob.coordinator.processLivenessProbe(
        bytesToHex(fixture.groupId), reverseProbe.ciphertextBytes);
      expect(reverseReceived).toEqual(UTF8.encode('b2.5c reverse liveness'));
      await charlie.coordinator.completeLivenessProbe(reverseProbe,
        bytesToHex(fixture.peers.bob.publicKey));
      await expect(bob.coordinator.createLivenessProbe(
        bytesToHex(fixture.groupId), plaintext)).rejects.toMatchObject({
        code: B25C_ERROR.PROBE_ALREADY_RESERVED,
      });
      const restarted = createB25CCoordinator({ journal: bob.journal, wasm });
      await expect(restarted.createLivenessProbe(
        bytesToHex(fixture.groupId), plaintext)).rejects.toMatchObject({
        code: B25C_ERROR.PROBE_ALREADY_RESERVED,
      });
      expect((await bob.journal.readHead(bytesToHex(fixture.groupId))).head.canonicalPath)
        .toEqual((await charlie.journal.readHead(bytesToHex(fixture.groupId))).head.canonicalPath);
    } finally { fixture.cleanup(); }
  }, 20000);

  test('a crash after durable reservation produces refusal without completion', async () => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm);
    try {
      const client = clientFor(wasm, fixture.peers.bob, fixture.groupId, 'probe-crash', {
        afterProbeReservation: async () => { throw new Error('injected post-reservation crash'); },
      });
      await client.initialize();
      const headBefore = (await client.journal.readHead(bytesToHex(fixture.groupId))).head;
      await expect(client.coordinator.createLivenessProbe(
        bytesToHex(fixture.groupId), UTF8.encode('never emitted')))
        .rejects.toThrow('injected post-reservation crash');
      const reservations = client.db.stores.get('probe-reservation');
      expect(reservations.size).toBe(1);
      expect(client.db.stores.get('probe-completion')?.size ?? 0).toBe(0);
      expect((await client.journal.readHead(bytesToHex(fixture.groupId))).head.headDigestHex)
        .toBe(headBefore.headDigestHex);
      const restarted = createB25CCoordinator({ journal: client.journal, wasm });
      await expect(restarted.createLivenessProbe(
        bytesToHex(fixture.groupId), UTF8.encode('still refused'))).rejects.toMatchObject({
        code: B25C_ERROR.PROBE_ALREADY_RESERVED,
      });
    } finally { fixture.cleanup(); }
  }, 20000);

  test('historical local generations keep own-echo and late-ACK classification', async () => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm);
    try {
      const client = clientFor(wasm, fixture.peers.bob, fixture.groupId, 'local-history');
      await client.initialize();
      const groupIdHex = bytesToHex(fixture.groupId);
      const peerIdentityHex = bytesToHex(fixture.peers.alice.publicKey);
      const commits = [];
      for (let index = 0; index < 3; index += 1) {
        const generation = await client.coordinator.prepareSelfUpdate(groupIdHex);
        commits.push(generation.commitBytes);
        await client.coordinator.recordAttempt(groupIdHex);
        await client.coordinator.recordAcknowledgement(
          groupIdHex, 1, peerIdentityHex, UTF8.encode(`ack-${index}`));
        await client.coordinator.settlePass(groupIdHex);
      }
      expect((await client.coordinator.admitCommit(groupIdHex, commits[0])).status)
        .toBe('own_echo');
      const snapshot = await client.journal.snapshot(groupIdHex);
      const first = snapshot.generations.find((item) =>
        item.commitDigestHex === digestHex(commits[0]));
      const late = await client.coordinator.recordHistoricalAcknowledgement(
        groupIdHex, first.commitDigestHex, 1, peerIdentityHex, UTF8.encode('late-ack'));
      expect(late.evidence.kind).toBe('LATE_ACK');
      expect(late.generation.state).toBe('SELECTED');
      expect((await client.journal.readHead(groupIdHex)).head.canonicalPath).toHaveLength(3);
    } finally { fixture.cleanup(); }
  }, 20000);

  test('discarded local propagation contradiction terminalizes without changing canonical state',
    async () => {
      const wasm = await loadWasm();
      const fixture = await setupGroup(wasm);
      try {
        const client = clientFor(wasm, fixture.peers.bob, fixture.groupId, 'contradiction');
        await client.initialize();
        const groupIdHex = bytesToHex(fixture.groupId);
        const peerIdentityHex = bytesToHex(fixture.peers.alice.publicKey);
        const generation = await client.coordinator.prepareSelfUpdate(groupIdHex);
        await client.coordinator.recordAttempt(groupIdHex);
        await client.coordinator.recordFailure(
          groupIdHex, 1, peerIdentityHex, UTF8.encode('failed-publication'));
        await client.coordinator.discardAfterFailure(groupIdHex);
        const contradiction = await client.coordinator.recordHistoricalAcknowledgement(
          groupIdHex, generation.commitDigestHex, 1, peerIdentityHex,
          UTF8.encode('contradictory-late-ack'));
        expect(contradiction.evidence.kind).toBe('CONTRADICTION');
        for (let index = 0; index < B25C_LIMITS.maxGenerations; index += 1) {
          await client.coordinator.prepareSelfUpdate(groupIdHex);
          await client.coordinator.cancelBeforeAttempt(groupIdHex);
        }
        const bounded = await client.journal.snapshot(groupIdHex);
        expect(bounded.generations).toHaveLength(B25C_LIMITS.maxGenerations);
        expect(bounded.generations.some((item) =>
          item.commitDigestHex === generation.commitDigestHex && item.contradiction)).toBe(true);
        const inbound = selfUpdateFrom(
          wasm, fixture.peers.alice, fixture.groupId, fixture.peers.alice.snapshotBytes);
        await client.coordinator.admitCommit(groupIdHex, inbound.commitBytes);
        const pass = await client.coordinator.freeze(groupIdHex);
        const before = (await client.journal.readHead(groupIdHex)).head;
        await expect(client.coordinator.settle(pass.passDigestHex)).rejects.toMatchObject({
          code: B25C_ERROR.UNRECOVERABLE,
        });
        const terminal = (await client.journal.readHead(groupIdHex)).head;
        expect(terminal.state).toBe(B25C_HEAD_STATE.UNRECOVERABLE);
        expect(terminal.snapshotDigestHex).toBe(before.snapshotDigestHex);
        expect(terminal.anchorSnapshotDigestHex).toBe(before.anchorSnapshotDigestHex);
        expect(terminal.canonicalPath).toEqual(before.canonicalPath);
        expect(terminal.epochDec).toBe(before.epochDec);
      } finally { fixture.cleanup(); }
    }, 20000);

  test.each([
    B25C_STORES.retained,
    B25C_STORES.edge,
    B25C_STORES.input,
    B25C_STORES.pass,
    B25C_STORES.invalidation,
    B25C_STORES.transition,
    B25C_STORES.head,
  ])('settlement rolls back atomically when %s write fails', async (failedStore) => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm);
    try {
      const update = selfUpdateFrom(
        wasm, fixture.peers.alice, fixture.groupId, fixture.peers.alice.snapshotBytes);
      const client = clientFor(wasm, fixture.peers.bob, fixture.groupId,
        `rollback-${failedStore}`);
      await client.initialize();
      const groupIdHex = bytesToHex(fixture.groupId);
      await client.coordinator.admitCommit(groupIdHex, update.commitBytes);
      const pass = await client.coordinator.freeze(groupIdHex);
      const before = (await client.journal.readHead(groupIdHex)).head;
      let injected = false;
      client.db.failOn = (store) => {
        if (!injected && store === failedStore) { injected = true; return true; }
        return false;
      };
      await expect(client.coordinator.settle(pass.passDigestHex))
        .rejects.toThrow('injected crash');
      expect(injected).toBe(true);
      expect((await client.journal.readHead(groupIdHex)).head.headDigestHex)
        .toBe(before.headDigestHex);
      client.db.failOn = null;
      expect((await client.coordinator.settle(pass.passDigestHex)).head.epochDec).toBe('4');
    } finally { fixture.cleanup(); }
  }, 20000);

  test('new input admitted after the decision snapshot forces complete CAS retry', async () => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm);
    let entered;
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    const seen = new Promise((resolve) => { entered = resolve; });
    try {
      const first = selfUpdateFrom(
        wasm, fixture.peers.alice, fixture.groupId, fixture.peers.alice.snapshotBytes);
      const second = selfUpdateFrom(
        wasm, fixture.peers.alice, fixture.groupId, fixture.peers.alice.snapshotBytes);
      let armed = true;
      const client = clientFor(wasm, fixture.peers.bob, fixture.groupId, 'cas-new-input', {
        beforeReplay: async () => {
          if (!armed) return;
          armed = false;
          entered();
          await gate;
        },
      });
      await client.initialize();
      const groupIdHex = bytesToHex(fixture.groupId);
      await client.coordinator.admitCommit(groupIdHex, first.commitBytes);
      const pass = await client.coordinator.freeze(groupIdHex);
      const pending = client.coordinator.settle(pass.passDigestHex);
      await seen;
      await client.coordinator.admitCommit(groupIdHex, second.commitBytes);
      release();
      await expect(pending).rejects.toMatchObject({ code: B25C_ERROR.CAS_CONFLICT });
      expect((await client.journal.readHead(groupIdHex)).head.epochDec).toBe('3');
    } finally { release?.(); fixture.cleanup(); }
  }, 20000);

  test('sixth Commit advances the exact five-Commit anchor and leaves a RELEASED tombstone',
    async () => {
      const wasm = await loadWasm();
      const fixture = await setupGroup(wasm);
      try {
        let sourceSnapshot = fixture.peers.alice.snapshotBytes;
        const chain = [];
        for (let index = 0; index < 6; index += 1) {
          const update = selfUpdateFrom(
            wasm, fixture.peers.alice, fixture.groupId, sourceSnapshot);
          chain.push(update.commitBytes);
          sourceSnapshot = update.successorSnapshotBytes;
        }
        const client = clientFor(wasm, fixture.peers.bob, fixture.groupId, 'horizon');
        await client.initialize();
        const groupIdHex = bytesToHex(fixture.groupId);
        const initial = (await client.journal.readHead(groupIdHex)).retained;
        const settled = await settleInputs(client, fixture.groupId, chain.reverse());
        expect(settled.head.canonicalPath).toHaveLength(5);
        expect(settled.head.epochDec).toBe('9');
        await expect(client.journal.readRetained(initial.snapshotDigestHex)).rejects
          .toMatchObject({ code: B25C_ERROR.RELEASED });
        const snapshot = await client.journal.snapshot(groupIdHex);
        expect(snapshot.edges.length).toBeLessThanOrEqual(B25C_LIMITS.maxEdges);
        expect(snapshot.retained.length).toBeLessThanOrEqual(B25C_LIMITS.maxStates);
        expect(snapshot.inputs.find((item) =>
          item.commitDigestHex === digestHex(chain.at(-1))).state).toBe('STALE');
        expect(snapshot.released).toEqual([
          expect.objectContaining({ snapshotDigestHex: initial.snapshotDigestHex }),
        ]);
      } finally { fixture.cleanup(); }
    }, 20000);

  test('a superseded probed branch can return only through a deeper fresh tip', async () => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm);
    try {
      const base = fixture.peers.alice.snapshotBytes;
      const siblings = [
        selfUpdateFrom(wasm, fixture.peers.alice, fixture.groupId, base),
        selfUpdateFrom(wasm, fixture.peers.alice, fixture.groupId, base),
      ].sort((left, right) => digestHex(left.commitBytes) < digestHex(right.commitBytes) ? -1 : 1);
      const low = siblings[0];
      const high = siblings[1];
      const highChild = selfUpdateFrom(
        wasm, fixture.peers.alice, fixture.groupId, high.successorSnapshotBytes);
      const client = clientFor(wasm, fixture.peers.bob, fixture.groupId, 'readopt');
      const neverProbed = clientFor(
        wasm, fixture.peers.charlie, fixture.groupId, 'readopt-never-probed');
      await client.initialize();
      await neverProbed.initialize();
      const groupIdHex = bytesToHex(fixture.groupId);
      await settleInputs(client, fixture.groupId, [high.commitBytes]);
      await settleInputs(neverProbed, fixture.groupId, [high.commitBytes]);
      const firstProbe = await client.coordinator.createLivenessProbe(
        groupIdHex, UTF8.encode('high-first'));
      await settleInputs(client, fixture.groupId, [low.commitBytes]);
      await settleInputs(neverProbed, fixture.groupId, [low.commitBytes]);
      expect((await client.journal.readHead(groupIdHex)).head.selectedCommitDigestHex)
        .toBe(digestHex(low.commitBytes));
      await settleInputs(client, fixture.groupId, [highChild.commitBytes]);
      await settleInputs(neverProbed, fixture.groupId, [highChild.commitBytes]);
      const finalHead = (await client.journal.readHead(groupIdHex)).head;
      expect(finalHead.canonicalPath).toEqual([
        digestHex(high.commitBytes), digestHex(highChild.commitBytes),
      ]);
      const deeperProbe = await client.coordinator.createLivenessProbe(
        groupIdHex, UTF8.encode('high-deeper'));
      expect(deeperProbe.probeKeyHex).not.toBe(firstProbe.probeKeyHex);
      expect(client.db.stores.get(B25C_STORES.probeReservation).size).toBe(2);
      const neverProbedHead = (await neverProbed.journal.readHead(groupIdHex)).head;
      expect([finalHead.canonicalPath, finalHead.epochDec,
        finalHead.groupContextDigestHex]).toEqual([
        neverProbedHead.canonicalPath,
        neverProbedHead.epochDec,
        neverProbedHead.groupContextDigestHex,
      ]);
    } finally { fixture.cleanup(); }
  }, 20000);

  test('bounded generation history evicts terminal evidence with a durable marker',
    async () => {
      const wasm = await loadWasm();
      const fixture = await setupGroup(wasm);
      try {
        const client = clientFor(wasm, fixture.peers.bob, fixture.groupId, 'generation-cap');
        await client.initialize();
        const groupIdHex = bytesToHex(fixture.groupId);
        let first;
        for (let index = 0; index < B25C_LIMITS.maxGenerations + 1; index += 1) {
          const generation = await client.coordinator.prepareSelfUpdate(groupIdHex);
          first ??= generation;
          await client.coordinator.cancelBeforeAttempt(groupIdHex);
        }
        const snapshot = await client.journal.snapshot(groupIdHex);
        expect(snapshot.generations).toHaveLength(B25C_LIMITS.maxGenerations);
        expect(snapshot.generationTruncation).toEqual(expect.objectContaining({
          throughGeneration: 1,
          evictedCommitDigestHex: first.commitDigestHex,
        }));
        expect(snapshot.publications.filter((item) =>
          item.artifactDigestHex === first.commitDigestHex)).toHaveLength(0);
        await expect(client.coordinator.recordHistoricalAcknowledgement(
          groupIdHex, first.commitDigestHex, 1,
          bytesToHex(fixture.peers.alice.publicKey), UTF8.encode('evicted')))
          .rejects.toMatchObject({
            code: B25C_ERROR.UNKNOWN_GENERATION,
            details: { commitDigestHex: first.commitDigestHex },
          });
      } finally { fixture.cleanup(); }
    }, 20000);

  test('strict input codec and raw-input cap fail before mutation', async () => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm);
    try {
      const client = clientFor(wasm, fixture.peers.bob, fixture.groupId, 'strict-input');
      await client.initialize();
      const groupIdHex = bytesToHex(fixture.groupId);
      const valid = buildInput({ groupIdHex, commitBytes: Uint8Array.of(1) });
      expect(() => parseInput({ ...valid, unknownField: true })).toThrow();
      for (let index = 0; index < B25C_LIMITS.maxInputs; index += 1) {
        await client.coordinator.admitCommit(groupIdHex,
          Uint8Array.of(0xa0, index + 1));
      }
      const before = await client.journal.snapshot(groupIdHex);
      await expect(client.coordinator.admitCommit(groupIdHex,
        Uint8Array.of(0xa1, 0xff))).rejects.toMatchObject({
        code: B25C_ERROR.RESOURCE_LIMIT,
      });
      const after = await client.journal.snapshot(groupIdHex);
      expect(after.inputs.map((item) => item.inputDigestHex))
        .toEqual(before.inputs.map((item) => item.inputDigestHex));
    } finally { fixture.cleanup(); }
  }, 20000);

  test('two retained parents that accept one exact Commit fail closed as ambiguous',
    async () => {
      const wasm = await loadWasm();
      const fixture = await setupGroup(wasm);
      try {
        const parentCommit = selfUpdateFrom(
          wasm, fixture.peers.alice, fixture.groupId, fixture.peers.alice.snapshotBytes);
        const childCommit = selfUpdateFrom(
          wasm, fixture.peers.alice, fixture.groupId, parentCommit.successorSnapshotBytes);
        const first = inboundSuccessorFrom(wasm, fixture.peers.bob, fixture.groupId,
          fixture.peers.bob.snapshotBytes, parentCommit.commitBytes);
        const second = inboundSuccessorFrom(wasm, fixture.peers.bob, fixture.groupId,
          fixture.peers.bob.snapshotBytes, parentCommit.commitBytes);
        expect(digestHex(first.snapshotBytes)).not.toBe(digestHex(second.snapshotBytes));
        expect(first.epochDec).toBe(second.epochDec);
        expect(first.groupContextDigestHex).toBe(second.groupContextDigestHex);
        const client = clientFor(wasm, fixture.peers.bob, fixture.groupId, 'ambiguous-parent');
        await client.initialize();
        const groupIdHex = bytesToHex(fixture.groupId);
        for (const successor of [first, second]) {
          const retained = buildRetainedState({
            groupIdHex,
            accountKeyHex: bytesToHex(fixture.peers.bob.publicKey),
            signatureKeyHex: bytesToHex(fixture.peers.bob.signatureKey),
            epochDec: successor.epochDec,
            groupContextDigestHex: successor.groupContextDigestHex,
            snapshotBytes: successor.snapshotBytes,
          });
          client.db.stores.get(B25C_STORES.retained)
            .set(retained.snapshotDigestHex, retained);
        }
        const before = (await client.journal.readHead(groupIdHex)).head;
        await client.coordinator.admitCommit(groupIdHex, childCommit.commitBytes);
        await client.coordinator.settlePass(groupIdHex);
        const snapshot = await client.journal.snapshot(groupIdHex);
        expect(snapshot.head.snapshotDigestHex).toBe(before.snapshotDigestHex);
        expect(snapshot.inputs.find((item) =>
          item.commitDigestHex === digestHex(childCommit.commitBytes)).state).toBe('AMBIGUOUS');
      } finally { fixture.cleanup(); }
    }, 20000);

  test('missing required retained anchor terminalizes the group without moving its state',
    async () => {
      const wasm = await loadWasm();
      const fixture = await setupGroup(wasm);
      try {
        const client = clientFor(wasm, fixture.peers.bob, fixture.groupId, 'missing-anchor');
        await client.initialize();
        const groupIdHex = bytesToHex(fixture.groupId);
        const before = (await client.journal.readHead(groupIdHex)).head;
        client.db.stores.get(B25C_STORES.retained).delete(before.anchorSnapshotDigestHex);
        await client.coordinator.admitCommit(groupIdHex, Uint8Array.of(0xaa, 0x01));
        const pass = await client.coordinator.freeze(groupIdHex);
        await expect(client.coordinator.settle(pass.passDigestHex)).rejects.toMatchObject({
          code: B25C_ERROR.UNRECOVERABLE,
        });
        const after = (await client.journal.readHead(groupIdHex)).head;
        expect(after.state).toBe(B25C_HEAD_STATE.UNRECOVERABLE);
        expect(after.snapshotDigestHex).toBe(before.snapshotDigestHex);
        expect(after.anchorSnapshotDigestHex).toBe(before.anchorSnapshotDigestHex);
        expect(after.canonicalPath).toEqual(before.canonicalPath);
        await expect(client.coordinator.admitCommit(
          groupIdHex, Uint8Array.of(0xaa, 0x02))).rejects.toMatchObject({
          code: B25C_ERROR.UNRECOVERABLE,
        });
      } finally { fixture.cleanup(); }
    }, 20000);
});
