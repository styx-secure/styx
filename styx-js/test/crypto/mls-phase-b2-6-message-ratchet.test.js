import { describe, expect, test } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { schnorr } from '@noble/curves/secp256k1';

import {
  B26_DB_PREFIX,
  B26_ERROR,
  B26_HEAD_STATE,
  B26_LIMITS,
  B26_STORES,
  bytesToHex,
  copyBytes,
  digestHex,
  messageInstanceKey,
  messageStateKey,
} from '../../spikes/marmot-phase-b2-6/b2-6-canonical.mjs';
import { createB26JournalForDb }
  from '../../spikes/marmot-phase-b2-6/b2-6-journal.mjs';
import { createB26Coordinator }
  from '../../spikes/marmot-phase-b2-6/b2-6-coordinator.mjs';
import { buildEdge, buildInbound, buildInput, buildMessageState, buildRetainedState,
  parseInput }
  from '../../spikes/marmot-phase-b2-6/b2-6-record.mjs';
import { deepClone, FakeVaultDb } from '../support/fake-vault-db.js';

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
      moduleUrl.searchParams.set('b2-6-convergence-test', '1');
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

function selfUpdateChainFrom(wasm, source, groupId, snapshotBytes, length) {
  const chain = [];
  let currentSnapshotBytes = snapshotBytes;
  for (let index = 0; index < length; index += 1) {
    const update = selfUpdateFrom(wasm, source, groupId, currentSnapshotBytes);
    chain.push(update);
    currentSnapshotBytes = update.successorSnapshotBytes;
  }
  return chain;
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
  const { db = new FakeVaultDb(), ...coordinatorHooks } = hooks;
  Object.defineProperty(db, 'name', { value: `${B26_DB_PREFIX}${tag}` });
  const journal = createB26JournalForDb(db);
  const coordinator = createB26Coordinator({ journal, wasm, ...coordinatorHooks });
  return { db, journal, coordinator,
    initialize: () => coordinator.initializeStable({ snapshotBytes: peer.snapshotBytes,
      groupId, accountKey: peer.publicKey, signatureKey: peer.signatureKey }) };
}

function restartClient(wasm, client, hooks = {}) {
  const journal = createB26JournalForDb(client.db);
  return { ...client, journal,
    coordinator: createB26Coordinator({ journal, wasm, ...hooks }) };
}

class SerialFakeVaultDb extends FakeVaultDb {
  constructor(options) {
    super(options);
    this.transactionTail = Promise.resolve();
  }

  transaction(namespaces, callback) {
    const result = this.transactionTail.then(
      () => super.transaction(namespaces, callback));
    this.transactionTail = result.catch(() => {});
    return result;
  }
}

class PostWriteFailVaultDb extends FakeVaultDb {
  constructor(options) {
    super(options);
    this.failAfterStore = null;
  }

  async transaction(namespaces, callback) {
    const snapshot = new Map(namespaces.map((namespace) =>
      [namespace, new Map(this._store(namespace))]));
    const operations = {
      get: (namespace, key) => {
        const value = this._store(namespace).get(key);
        return value === undefined ? undefined : deepClone(value);
      },
      put: (namespace, key, value) => {
        this._store(namespace).set(key, deepClone(value));
        if (namespace === this.failAfterStore) throw new Error('injected post-write crash');
      },
      delete: (namespace, key) => this._store(namespace).delete(key),
      list: (namespace) => [...this._store(namespace).keys()],
      clear: (namespace) => this._store(namespace).clear(),
      abort: () => { throw new Error('aborted'); },
    };
    try {
      return await callback(operations);
    } catch (error) {
      for (const [namespace, values] of snapshot) this.stores.set(namespace, values);
      throw error;
    }
  }
}

async function settleInputs(client, groupId, commits) {
  for (const commit of commits) await client.coordinator.admitCommit(bytesToHex(groupId), commit);
  return client.coordinator.settlePass(bytesToHex(groupId));
}

function durableImage(db) {
  return deepClone([...db.stores.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([store, records]) => [store, [...records.entries()]
      .sort(([left], [right]) => String(left).localeCompare(String(right)))]));
}

describe('Phase B2.6 retained-history convergence', () => {
  test('message-state codec rejects the unreachable RELEASED disposition', () => {
    const binding = {
      groupIdHex: '11'.repeat(32),
      tipCommitDigestHex: '22'.repeat(32),
      epochDec: '7',
      groupContextDigestHex: '33'.repeat(32),
      localMemberIdentityHex: '44'.repeat(32),
    };
    expect(() => buildMessageState({
      groupIdHex: binding.groupIdHex,
      instanceKeyHex: messageInstanceKey(binding),
      baseHeadDigestHex: '55'.repeat(32),
      tipCommitDigestHex: binding.tipCommitDigestHex,
      epochDec: binding.epochDec,
      groupContextDigestHex: binding.groupContextDigestHex,
      localMemberIdentityHex: binding.localMemberIdentityHex,
      baseRetainedSnapshotDigestHex: '66'.repeat(32),
      sequence: 0,
      sentCount: 0,
      receivedCount: 0,
      snapshotDigestHex: '77'.repeat(32),
      priorStateDigestHex: null,
      state: 'RELEASED',
    })).toThrow(expect.objectContaining({ code: B26_ERROR.INVALID }));
  });

  test('six outbound messages survive restart and are delivered exactly once', async () => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm);
    try {
      let alice = clientFor(wasm, fixture.peers.alice, fixture.groupId, 'messages-alice');
      let bob = clientFor(wasm, fixture.peers.bob, fixture.groupId, 'messages-bob');
      await alice.initialize();
      await bob.initialize();
      const groupIdHex = bytesToHex(fixture.groupId);
      const first = [];
      for (let index = 1; index <= 3; index += 1) {
        const queued = await alice.coordinator.queueApplicationMessage(
          groupIdHex, 'request-' + index, UTF8.encode('message-' + index));
        expect(queued).toEqual(expect.objectContaining({
          status: 'committed', ordinal: index,
        }));
        expect(queued.ciphertextBytes).toBeUndefined();
        first.push(await alice.coordinator.readQueuedApplicationMessage(
          queued.instanceKeyHex, queued.ordinal));
      }
      for (let index = 0; index < first.length; index += 1) {
        const delivered = await bob.coordinator.processApplicationMessage(
          groupIdHex, first[index].ciphertextBytes);
        expect(new TextDecoder().decode(delivered.plaintextBytes))
          .toBe('message-' + (index + 1));
      }
      alice = restartClient(wasm, alice);
      bob = restartClient(wasm, bob);
      for (let index = 4; index <= 6; index += 1) {
        const queued = await alice.coordinator.queueApplicationMessage(
          groupIdHex, 'request-' + index, UTF8.encode('message-' + index));
        const durable = await alice.coordinator.readQueuedApplicationMessage(
          queued.instanceKeyHex, queued.ordinal);
        const delivered = await bob.coordinator.processApplicationMessage(
          groupIdHex, durable.ciphertextBytes);
        expect(new TextDecoder().decode(delivered.plaintextBytes)).toBe('message-' + index);
      }
      const replay = await bob.coordinator.processApplicationMessage(
        groupIdHex, first[0].ciphertextBytes);
      expect(replay.status).toBe('duplicate');
      expect(new TextDecoder().decode(replay.plaintextBytes)).toBe('message-1');
      const duplicateRequest = await alice.coordinator.queueApplicationMessage(
        groupIdHex, 'request-6', UTF8.encode('message-6'));
      expect(duplicateRequest.status).toBe('duplicate');
      expect(duplicateRequest.ordinal).toBe(6);
      await expect(alice.coordinator.queueApplicationMessage(
        groupIdHex, 'request-6', UTF8.encode('conflicting-message')))
        .rejects.toMatchObject({ code: B26_ERROR.REQUEST_CONFLICT });
    } finally { fixture.cleanup(); }
  }, 20000);

  test('pre-commit outbound and inbound crashes expose no computed output', async () => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm);
    let outboundArmed = true;
    let inboundArmed = true;
    try {
      let alice = clientFor(wasm, fixture.peers.alice, fixture.groupId, 'crash-alice', {
        beforeOutboundCommit: async () => {
          if (outboundArmed) {
            outboundArmed = false;
            throw new Error('injected outbound pre-commit crash');
          }
        },
      });
      let bob = clientFor(wasm, fixture.peers.bob, fixture.groupId, 'crash-bob', {
        beforeInboundCommit: async () => {
          if (inboundArmed) {
            inboundArmed = false;
            throw new Error('injected inbound pre-commit crash');
          }
        },
      });
      await alice.initialize();
      await bob.initialize();
      const groupIdHex = bytesToHex(fixture.groupId);
      await expect(alice.coordinator.queueApplicationMessage(
        groupIdHex, 'crash-request', UTF8.encode('survives')))
        .rejects.toThrow('injected outbound pre-commit crash');
      alice = restartClient(wasm, alice);
      const queued = await alice.coordinator.queueApplicationMessage(
        groupIdHex, 'crash-request', UTF8.encode('survives'));
      const durable = await alice.coordinator.readQueuedApplicationMessage(
        queued.instanceKeyHex, queued.ordinal);
      await expect(bob.coordinator.processApplicationMessage(
        groupIdHex, durable.ciphertextBytes))
        .rejects.toThrow('injected inbound pre-commit crash');
      bob = restartClient(wasm, bob);
      const delivered = await bob.coordinator.processApplicationMessage(
        groupIdHex, durable.ciphertextBytes);
      expect(new TextDecoder().decode(delivered.plaintextBytes)).toBe('survives');
    } finally { fixture.cleanup(); }
  }, 20000);

  test.each([
    ['before', B26_STORES.messageSnapshot],
    ['before', B26_STORES.messageState],
    ['before', B26_STORES.appOutbox],
    ['after', B26_STORES.messageSnapshot],
    ['after', B26_STORES.messageState],
    ['after', B26_STORES.appOutbox],
  ])('outbound %s-%s failure restores the exact predecessor', async (phase, store) => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm);
    try {
      const db = phase === 'after' ? new PostWriteFailVaultDb() : new FakeVaultDb();
      const client = clientFor(wasm, fixture.peers.alice, fixture.groupId,
        `outbound-${phase}-${store}`, { db });
      await client.initialize();
      const groupIdHex = bytesToHex(fixture.groupId);
      if (phase === 'after') db.failAfterStore = store;
      else db.failOn = (namespace) => namespace === store;
      await expect(client.coordinator.queueApplicationMessage(
        groupIdHex, 'atomic-outbound', UTF8.encode('atomic-outbound')))
        .rejects.toThrow(/injected/);
      expect(await db.transaction([B26_STORES.messageState],
        (ops) => ops.list(B26_STORES.messageState))).toEqual([]);
      expect(await db.transaction([B26_STORES.messageSnapshot],
        (ops) => ops.list(B26_STORES.messageSnapshot))).toEqual([]);
      expect(await db.transaction([B26_STORES.appOutbox],
        (ops) => ops.list(B26_STORES.appOutbox))).toEqual([]);
      db.failOn = null;
      db.failAfterStore = null;
      const committed = await client.coordinator.queueApplicationMessage(
        groupIdHex, 'atomic-outbound', UTF8.encode('atomic-outbound'));
      expect(committed).toEqual(expect.objectContaining({ status: 'committed', ordinal: 1 }));
      await expect(client.coordinator.readQueuedApplicationMessage(
        committed.instanceKeyHex, committed.ordinal)).resolves.toEqual(
        expect.objectContaining({ ciphertextBytes: expect.any(Uint8Array) }));
    } finally { fixture.cleanup(); }
  }, 20000);

  test.each([
    ['before', B26_STORES.messageSnapshot],
    ['before', B26_STORES.messageState],
    ['before', B26_STORES.appInbound],
    ['after', B26_STORES.messageSnapshot],
    ['after', B26_STORES.messageState],
    ['after', B26_STORES.appInbound],
  ])('inbound %s-%s failure exposes no plaintext and restores the predecessor',
    async (phase, store) => {
      const wasm = await loadWasm();
      const fixture = await setupGroup(wasm);
      try {
        const db = phase === 'after' ? new PostWriteFailVaultDb() : new FakeVaultDb();
        const client = clientFor(wasm, fixture.peers.bob, fixture.groupId,
          `inbound-${phase}-${store}`, { db });
        await client.initialize();
        const sender = restoreSource(
          wasm, fixture.peers.alice, fixture.groupId, fixture.peers.alice.snapshotBytes);
        const ciphertext = copyBytes(sender.group.create_application_message(
          sender.provider, sender.identity, UTF8.encode('atomic-inbound')));
        free(sender.group); free(sender.identity); free(sender.provider);
        if (phase === 'after') db.failAfterStore = store;
        else db.failOn = (namespace) => namespace === store;
        await expect(client.coordinator.processApplicationMessage(
          bytesToHex(fixture.groupId), ciphertext)).rejects.toThrow(/injected/);
        expect(await db.transaction([B26_STORES.messageState],
          (ops) => ops.list(B26_STORES.messageState))).toEqual([]);
        expect(await db.transaction([B26_STORES.messageSnapshot],
          (ops) => ops.list(B26_STORES.messageSnapshot))).toEqual([]);
        expect(await db.transaction([B26_STORES.appInbound],
          (ops) => ops.list(B26_STORES.appInbound))).toEqual([]);
        db.failOn = null;
        db.failAfterStore = null;
        const accepted = await client.coordinator.processApplicationMessage(
          bytesToHex(fixture.groupId), ciphertext);
        expect(new TextDecoder().decode(accepted.plaintextBytes)).toBe('atomic-inbound');
      } finally { fixture.cleanup(); }
    }, 20000);

  test('concurrent senders have one message-position CAS winner', async () => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm);
    try {
      const client = clientFor(wasm, fixture.peers.alice, fixture.groupId, 'message-cas',
        { db: new SerialFakeVaultDb() });
      await client.initialize();
      const groupIdHex = bytesToHex(fixture.groupId);
      const outcomes = await Promise.allSettled([
        client.coordinator.queueApplicationMessage(
          groupIdHex, 'race-a', UTF8.encode('race-a')),
        client.coordinator.queueApplicationMessage(
          groupIdHex, 'race-b', UTF8.encode('race-b')),
      ]);
      expect(outcomes.filter((item) => item.status === 'fulfilled')).toHaveLength(1);
      expect(outcomes.filter((item) => item.status === 'rejected')).toHaveLength(1);
      expect(outcomes.find((item) => item.status === 'rejected').reason)
        .toMatchObject({ code: B26_ERROR.CAS_CONFLICT });
      const stateKeys = await client.db.transaction([B26_STORES.messageState],
        (ops) => ops.list(B26_STORES.messageState));
      const outboxKeys = await client.db.transaction([B26_STORES.appOutbox],
        (ops) => ops.list(B26_STORES.appOutbox));
      expect(stateKeys).toHaveLength(1);
      expect(outboxKeys).toHaveLength(1);
    } finally { fixture.cleanup(); }
  }, 20000);

  test('a liveness probe and ordinary send cannot release the same message position',
    async () => {
      const wasm = await loadWasm();
      const fixture = await setupGroup(wasm);
      let entered = 0;
      let release;
      const barrier = new Promise((resolve) => { release = resolve; });
      try {
        const client = clientFor(wasm, fixture.peers.alice, fixture.groupId,
          'probe-message-cas', {
            db: new SerialFakeVaultDb(),
            beforeOutboundCommit: async () => {
              entered += 1;
              if (entered === 2) release();
              await barrier;
            },
          });
        await client.initialize();
        const groupIdHex = bytesToHex(fixture.groupId);
        const outcomes = await Promise.allSettled([
          client.coordinator.createLivenessProbe(
            groupIdHex, UTF8.encode('probe-race')),
          client.coordinator.queueApplicationMessage(
            groupIdHex, 'ordinary-race', UTF8.encode('ordinary-race')),
        ]);
        expect(outcomes.filter((item) => item.status === 'fulfilled')).toHaveLength(1);
        expect(outcomes.filter((item) => item.status === 'rejected')).toHaveLength(1);
        expect(outcomes.find((item) => item.status === 'rejected').reason)
          .toMatchObject({ code: B26_ERROR.CAS_CONFLICT });
        const context = await client.journal.readMessageContext(groupIdHex);
        expect(context.state.sentCount).toBe(1);
        expect(await client.db.transaction([B26_STORES.appOutbox],
          (ops) => ops.list(B26_STORES.appOutbox))).toHaveLength(1);
      } finally { fixture.cleanup(); }
    }, 20000);

  test('concurrent inbound plaintext computations have one durable CAS winner', async () => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm);
    let entered = 0;
    let release;
    const barrier = new Promise((resolve) => { release = resolve; });
    try {
      const client = clientFor(wasm, fixture.peers.bob, fixture.groupId,
        'inbound-message-cas', {
          db: new SerialFakeVaultDb(),
          beforeInboundCommit: async () => {
            entered += 1;
            if (entered === 2) release();
            await barrier;
          },
        });
      await client.initialize();
      const sender = restoreSource(
        wasm, fixture.peers.alice, fixture.groupId, fixture.peers.alice.snapshotBytes);
      const ciphertexts = [0, 1].map((index) => copyBytes(
        sender.group.create_application_message(
          sender.provider, sender.identity, UTF8.encode('inbound-race-' + index))));
      free(sender.group); free(sender.identity); free(sender.provider);
      const groupIdHex = bytesToHex(fixture.groupId);
      const outcomes = await Promise.allSettled(ciphertexts.map((ciphertext) =>
        client.coordinator.processApplicationMessage(groupIdHex, ciphertext)));
      expect(outcomes.filter((item) => item.status === 'fulfilled')).toHaveLength(1);
      expect(outcomes.filter((item) => item.status === 'rejected')).toEqual([
        expect.objectContaining({ reason: expect.objectContaining({
          code: B26_ERROR.CAS_CONFLICT,
        }) }),
      ]);
      expect(await client.db.transaction([B26_STORES.appInbound],
        (ops) => ops.list(B26_STORES.appInbound))).toHaveLength(1);
      expect((await client.journal.readMessageContext(groupIdHex)).state.receivedCount).toBe(1);
    } finally { release?.(); fixture.cleanup(); }
  }, 20000);

  test('publication retries expose exact durable bytes and evidence is idempotent',
    async () => {
      const wasm = await loadWasm();
      const fixture = await setupGroup(wasm);
      try {
        let alice = clientFor(wasm, fixture.peers.alice, fixture.groupId, 'message-retry');
        await alice.initialize();
        const groupIdHex = bytesToHex(fixture.groupId);
        const queued = await alice.coordinator.queueApplicationMessage(
          groupIdHex, 'retry-request', UTF8.encode('exact-byte-retry'));
        const first = await alice.coordinator.readQueuedApplicationMessage(
          queued.instanceKeyHex, queued.ordinal);
        const attempts = [];
        for (const recipientIdentityHex of first.recipientScope) {
          attempts.push(await alice.coordinator.recordApplicationAttempt(
            queued.instanceKeyHex, queued.ordinal, recipientIdentityHex));
        }
        alice = restartClient(wasm, alice);
        const retried = await alice.coordinator.readQueuedApplicationMessage(
          queued.instanceKeyHex, queued.ordinal);
        expect(bytesToHex(retried.ciphertextBytes)).toBe(bytesToHex(first.ciphertextBytes));
        let acknowledged;
        for (let index = 0; index < first.recipientScope.length; index += 1) {
          acknowledged = await alice.coordinator.recordApplicationAcknowledgement(
            queued.instanceKeyHex, queued.ordinal, attempts[index].attemptOrdinal,
            first.recipientScope[index], UTF8.encode('ack'));
        }
        expect(acknowledged.outbox.state).toBe('ACKNOWLEDGED');
        const duplicate = await alice.coordinator.recordApplicationAcknowledgement(
          queued.instanceKeyHex, queued.ordinal, attempts[0].attemptOrdinal,
          first.recipientScope[0], UTF8.encode('ack'));
        expect(duplicate.status).toBe('duplicate');
        expect(duplicate.outbox.ackCount).toBe(first.recipientScope.length);
        const late = await alice.coordinator.recordApplicationAcknowledgement(
          queued.instanceKeyHex, queued.ordinal, attempts[0].attemptOrdinal,
          first.recipientScope[0], UTF8.encode('late-ack'));
        expect(late.evidence.kind).toBe('LATE_ACK');
        expect(late.outbox.state).toBe('ACKNOWLEDGED');
        expect(late.outbox.ackCount).toBe(first.recipientScope.length);
        await expect(alice.coordinator.readQueuedApplicationMessage(
          queued.instanceKeyHex, queued.ordinal)).rejects.toMatchObject({
          code: B26_ERROR.OUTBOX_TERMINAL,
        });
        const failedQueued = await alice.coordinator.queueApplicationMessage(
          groupIdHex, 'failed-request', UTF8.encode('failed-message'));
        const failedDurable = await alice.coordinator.readQueuedApplicationMessage(
          failedQueued.instanceKeyHex, failedQueued.ordinal);
        const failedAttempt = await alice.coordinator.recordApplicationAttempt(
          failedQueued.instanceKeyHex, failedQueued.ordinal,
          failedDurable.recipientScope[0]);
        await alice.coordinator.recordApplicationFailure(
          failedQueued.instanceKeyHex, failedQueued.ordinal,
          failedAttempt.attemptOrdinal, failedDurable.recipientScope[0],
          UTF8.encode('publication-failed'));
        const discarded = await alice.coordinator.discardApplicationAfterFailure(
          failedQueued.instanceKeyHex, failedQueued.ordinal);
        expect(discarded.state).toBe('FAILED_DISCARDED');
        const lateAfterFailure = await alice.coordinator.recordApplicationAcknowledgement(
          failedQueued.instanceKeyHex, failedQueued.ordinal,
          failedAttempt.attemptOrdinal, failedDurable.recipientScope[0],
          UTF8.encode('late-after-failure'));
        expect(lateAfterFailure.evidence.kind).toBe('LATE_ACK');
        expect(lateAfterFailure.outbox.state).toBe('FAILED_DISCARDED');
        await expect(alice.coordinator.readQueuedApplicationMessage(
          failedQueued.instanceKeyHex, failedQueued.ordinal)).rejects.toMatchObject({
          code: B26_ERROR.OUTBOX_TERMINAL,
        });
      } finally { fixture.cleanup(); }
    }, 20000);

  test('message codecs reject sender attribution and bounds fail before mutation', async () => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm);
    try {
      const client = clientFor(wasm, fixture.peers.alice, fixture.groupId, 'message-bounds');
      await client.initialize();
      const groupIdHex = bytesToHex(fixture.groupId);
      expect(() => buildInbound({
        groupIdHex,
        instanceKeyHex: '11'.repeat(32),
        baseRetainedSnapshotDigestHex: '33'.repeat(32),
        ciphertextBytes: Uint8Array.of(1),
        ciphertextDigestHex: digestHex(Uint8Array.of(1)),
        disposition: 'DEFERRED',
        receivedOrdinal: 0,
        plaintextBytes: new Uint8Array(),
        plaintextDigestHex: null,
        senderIdentityHex: '22'.repeat(32),
      })).toThrow(/non-canonical field set/);
      await expect(client.coordinator.queueApplicationMessage(
        groupIdHex, 'x'.repeat(B26_LIMITS.maxRequestIdBytes + 1), UTF8.encode('x')))
        .rejects.toMatchObject({ code: expect.stringMatching(/_INVALID$/) });
      await expect(client.coordinator.queueApplicationMessage(
        groupIdHex, `styx-probe:${'11'.repeat(32)}`, UTF8.encode('x')))
        .rejects.toMatchObject({ code: B26_ERROR.INVALID });
      await expect(client.coordinator.queueApplicationMessage(
        groupIdHex, 'oversized', new Uint8Array(B26_LIMITS.maxApplicationPayloadBytes + 1)))
        .rejects.toBeDefined();
      expect(await client.db.transaction([B26_STORES.messageState],
        (ops) => ops.list(B26_STORES.messageState))).toEqual([]);
      for (let index = 0; index < B26_LIMITS.maxOutboxPerInstance; index += 1) {
        await client.coordinator.queueApplicationMessage(
          groupIdHex, `bounded-${index}`, UTF8.encode(`bounded-${index}`));
      }
      const before = await client.journal.readMessageContext(groupIdHex);
      await expect(client.coordinator.queueApplicationMessage(
        groupIdHex, 'bounded-overflow', UTF8.encode('bounded-overflow')))
        .rejects.toMatchObject({ code: B26_ERROR.RESOURCE_LIMIT });
      const after = await client.journal.readMessageContext(groupIdHex);
      expect(after.state.stateDigestHex).toBe(before.state.stateDigestHex);
      expect(await client.db.transaction([B26_STORES.appOutbox],
        (ops) => ops.list(B26_STORES.appOutbox)))
        .toHaveLength(B26_LIMITS.maxOutboxPerInstance);
    } finally { fixture.cleanup(); }
  }, 20000);

  test('terminal inbound history truncates oldest-first with a digest-linked marker',
    async () => {
      const wasm = await loadWasm();
      const fixture = await setupGroup(wasm);
      try {
        const bob = clientFor(wasm, fixture.peers.bob, fixture.groupId,
          'inbound-truncation');
        await bob.initialize();
        const sender = restoreSource(
          wasm, fixture.peers.alice, fixture.groupId, fixture.peers.alice.snapshotBytes);
        const ciphertexts = [];
        for (let index = 0; index <= B26_LIMITS.maxInboundPerInstance; index += 1) {
          ciphertexts.push(copyBytes(sender.group.create_application_message(
            sender.provider, sender.identity, UTF8.encode('inbound-' + index))));
        }
        free(sender.group); free(sender.identity); free(sender.provider);
        const groupIdHex = bytesToHex(fixture.groupId);
        for (const ciphertext of ciphertexts) {
          await bob.coordinator.processApplicationMessage(groupIdHex, ciphertext);
        }
        const context = await bob.journal.readMessageContext(groupIdHex);
        const inboundKeys = await bob.db.transaction([B26_STORES.appInbound],
          (ops) => ops.list(B26_STORES.appInbound));
        expect(inboundKeys).toHaveLength(B26_LIMITS.maxInboundPerInstance);
        const marker = await bob.db.transaction([B26_STORES.inboundTruncation],
          (ops) => ops.get(B26_STORES.inboundTruncation, context.instanceKeyHex));
        expect(marker).toEqual(expect.objectContaining({
          throughReceivedOrdinal: 1,
          evictedCiphertextDigestHex: digestHex(ciphertexts[0]),
        }));
      } finally { fixture.cleanup(); }
    }, 20000);

  test('accepting an existing deferred ciphertext at the cap does not truncate history',
    async () => {
      const wasm = await loadWasm();
      const fixture = await setupGroup(wasm);
      try {
        const base = fixture.peers.alice.snapshotBytes;
        const siblings = [
          selfUpdateFrom(wasm, fixture.peers.alice, fixture.groupId, base),
          selfUpdateFrom(wasm, fixture.peers.alice, fixture.groupId, base),
        ].sort((left, right) =>
          digestHex(left.commitBytes) < digestHex(right.commitBytes) ? -1 : 1);
        const [selected, displaced] = siblings;
        const client = clientFor(wasm, fixture.peers.bob, fixture.groupId,
          'deferred-cap-upgrade');
        await client.initialize();
        const groupIdHex = bytesToHex(fixture.groupId);
        await settleInputs(client, fixture.groupId,
          [displaced.commitBytes, selected.commitBytes]);
        const displacedEdge = (await client.journal.snapshot(groupIdHex)).edges.find(
          (edge) => edge.commitDigestHex === digestHex(displaced.commitBytes));
        const sender = restoreSource(wasm, fixture.peers.alice, fixture.groupId,
          displaced.successorSnapshotBytes);
        const ciphertexts = [];
        for (let index = 0; index < B26_LIMITS.maxInboundPerInstance; index += 1) {
          ciphertexts.push(copyBytes(sender.group.create_application_message(
            sender.provider, sender.identity, UTF8.encode('deferred-cap-' + index))));
        }
        free(sender.group); free(sender.identity); free(sender.provider);
        for (const ciphertext of ciphertexts) {
          const deferred = await client.coordinator.processApplicationMessage(
            groupIdHex, ciphertext, displacedEdge.successorSnapshotDigestHex);
          expect(deferred.status).toBe('deferred');
        }

        const child = selfUpdateFrom(
          wasm, fixture.peers.alice, fixture.groupId, displaced.successorSnapshotBytes);
        await settleInputs(client, fixture.groupId, [child.commitBytes]);
        const accepted = await client.coordinator.processApplicationMessage(
          groupIdHex, ciphertexts[0], displacedEdge.successorSnapshotDigestHex);
        expect(accepted.status).toBe('accepted');
        const inboundKeys = await client.db.transaction([B26_STORES.appInbound],
          (ops) => ops.list(B26_STORES.appInbound));
        expect(inboundKeys).toHaveLength(B26_LIMITS.maxInboundPerInstance);
        expect(client.db.stores.get(B26_STORES.inboundTruncation)?.size ?? 0).toBe(0);
      } finally { fixture.cleanup(); }
    }, 20000);

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

  test('concurrent local and inbound self-updates converge without replaying pending snapshots',
    async () => {
      const wasm = await loadWasm();
      const fixture = await setupGroup(wasm);
      try {
        const bob = clientFor(wasm, fixture.peers.bob, fixture.groupId, 'mixed-bob');
        const charlie = clientFor(wasm, fixture.peers.charlie, fixture.groupId,
          'mixed-charlie');
        await bob.initialize();
        await charlie.initialize();
        const groupIdHex = bytesToHex(fixture.groupId);
        const acknowledger = bytesToHex(fixture.peers.alice.publicKey);
        const bobGeneration = await bob.coordinator.prepareSelfUpdate(groupIdHex);
        const aliceInbound = selfUpdateFrom(
          wasm, fixture.peers.alice, fixture.groupId, fixture.peers.alice.snapshotBytes);
        await bob.coordinator.recordAttempt(groupIdHex);
        await bob.coordinator.recordAcknowledgement(
          groupIdHex, 1, acknowledger, UTF8.encode('bob-ack'));
        expect((await bob.coordinator.admitCommit(
          groupIdHex, aliceInbound.commitBytes)).status).toBe('retained');
        expect((await charlie.coordinator.admitCommit(
          groupIdHex, bobGeneration.commitBytes)).status).toBe('retained');
        expect((await charlie.coordinator.admitCommit(
          groupIdHex, aliceInbound.commitBytes)).status).toBe('retained');
        await Promise.all([
          bob.coordinator.settlePass(groupIdHex),
          charlie.coordinator.settlePass(groupIdHex),
        ]);
        const bobHead = (await bob.journal.readHead(groupIdHex)).head;
        const charlieHead = (await charlie.journal.readHead(groupIdHex)).head;
        expect(bobHead.canonicalPath).toHaveLength(1);
        expect(charlieHead.canonicalPath).toEqual(bobHead.canonicalPath);
        expect(charlieHead.groupContextDigestHex).toBe(bobHead.groupContextDigestHex);
      } finally { fixture.cleanup(); }
    }, 20000);

  test.each([
    ['PREPARED', false],
    ['PUBLISHING', true],
  ])('settlement retains an active %s local pending snapshot', async (_state, attempted) => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm);
    try {
      const client = clientFor(wasm, fixture.peers.bob, fixture.groupId,
        `active-${_state.toLowerCase()}`);
      await client.initialize();
      const groupIdHex = bytesToHex(fixture.groupId);
      const generation = await client.coordinator.prepareSelfUpdate(groupIdHex);
      if (attempted) await client.coordinator.recordAttempt(groupIdHex);
      await client.coordinator.admitCommit(groupIdHex, Uint8Array.of(1, 2, 3, 4));
      await client.coordinator.settlePass(groupIdHex);
      await expect(client.journal.readRetained(generation.pendingSnapshotDigestHex))
        .resolves.toEqual(expect.objectContaining({
          snapshotDigestHex: generation.pendingSnapshotDigestHex,
        }));
      if (!attempted) await client.coordinator.recordAttempt(groupIdHex);
      await client.coordinator.recordAcknowledgement(
        groupIdHex, 1, bytesToHex(fixture.peers.alice.publicKey), UTF8.encode('late-ack'));
      await client.coordinator.settlePass(groupIdHex);
      const head = (await client.journal.readHead(groupIdHex)).head;
      expect(head.state).toBe(B26_HEAD_STATE.STABLE);
      expect(head.epochDec).toBe('4');
      expect(head.canonicalPath).toEqual([generation.commitDigestHex]);
    } finally { fixture.cleanup(); }
  }, 20000);

  test('pinned out-of-order window accepts skipped messages and rejects excessive gaps',
    async () => {
      const wasm = await loadWasm();
      const fixture = await setupGroup(wasm);
      try {
        const bob = clientFor(wasm, fixture.peers.bob, fixture.groupId,
          'out-of-order-bob');
        const charlie = clientFor(wasm, fixture.peers.charlie, fixture.groupId,
          'out-of-order-charlie');
        await bob.initialize();
        await charlie.initialize();
        const sender = restoreSource(
          wasm, fixture.peers.alice, fixture.groupId, fixture.peers.alice.snapshotBytes);
        const early = [];
        let excessiveGap;
        for (let index = 0; index <= 1001; index += 1) {
          const ciphertext = copyBytes(sender.group.create_application_message(
            sender.provider, sender.identity, UTF8.encode('window-' + index)));
          if (index < 3) early.push(ciphertext);
          if (index === 1001) excessiveGap = ciphertext;
        }
        free(sender.group); free(sender.identity); free(sender.provider);
        const groupIdHex = bytesToHex(fixture.groupId);
        for (const index of [2, 0, 1]) {
          const delivered = await bob.coordinator.processApplicationMessage(
            groupIdHex, early[index]);
          expect(new TextDecoder().decode(delivered.plaintextBytes)).toBe('window-' + index);
        }
        const bobBefore = await bob.journal.readMessageContext(groupIdHex);
        await expect(bob.coordinator.processApplicationMessage(
          groupIdHex, Uint8Array.of(0xde, 0xad, 0xbe, 0xef)))
          .rejects.toBeDefined();
        const bobAfter = await bob.journal.readMessageContext(groupIdHex);
        expect(bobAfter.state.stateDigestHex).toBe(bobBefore.state.stateDigestHex);
        await expect(charlie.coordinator.processApplicationMessage(
          groupIdHex, excessiveGap)).rejects.toBeDefined();
        const charlieAfter = await charlie.journal.readMessageContext(groupIdHex);
        expect(charlieAfter.state).toBeNull();
        expect(await charlie.db.transaction([B26_STORES.appInbound],
          (ops) => ops.list(B26_STORES.appInbound))).toEqual([]);
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
      const afterProbe = await bob.coordinator.queueApplicationMessage(
        bytesToHex(fixture.groupId), 'after-probe-forward',
        UTF8.encode('ordinary message after probe'));
      const afterProbeDurable = await bob.coordinator.readQueuedApplicationMessage(
        afterProbe.instanceKeyHex, afterProbe.ordinal);
      const afterProbeReceived = await charlie.coordinator.processApplicationMessage(
        bytesToHex(fixture.groupId), afterProbeDurable.ciphertextBytes);
      expect(afterProbeReceived.plaintextBytes)
        .toEqual(UTF8.encode('ordinary message after probe'));
      expect(afterProbe.ordinal).toBe(2);
      expect(afterProbeReceived.receivedOrdinal).toBe(2);
      await expect(bob.coordinator.createLivenessProbe(
        bytesToHex(fixture.groupId), plaintext)).rejects.toMatchObject({
        code: B26_ERROR.PROBE_ALREADY_RESERVED,
      });
      const restarted = createB26Coordinator({ journal: bob.journal, wasm });
      await expect(restarted.createLivenessProbe(
        bytesToHex(fixture.groupId), plaintext)).rejects.toMatchObject({
        code: B26_ERROR.PROBE_ALREADY_RESERVED,
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
      expect(client.db.stores.get(B26_STORES.messageState)?.size ?? 0).toBe(0);
      expect(client.db.stores.get(B26_STORES.messageSnapshot)?.size ?? 0).toBe(0);
      expect(client.db.stores.get(B26_STORES.appOutbox)?.size ?? 0).toBe(0);
      expect((await client.journal.readHead(bytesToHex(fixture.groupId))).head.headDigestHex)
        .toBe(headBefore.headDigestHex);
      const restarted = createB26Coordinator({ journal: client.journal, wasm });
      await expect(restarted.createLivenessProbe(
        bytesToHex(fixture.groupId), UTF8.encode('still refused'))).rejects.toMatchObject({
        code: B26_ERROR.PROBE_ALREADY_RESERVED,
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
      expect(late.generation.ackCount).toBe(first.ackCount);
      expect(late.generation.failureCount).toBe(first.failureCount);
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
        expect(contradiction.generation.ackCount).toBe(0);
        expect(contradiction.generation.failureCount).toBe(1);
        for (let index = 0; index < B26_LIMITS.maxGenerations; index += 1) {
          await client.coordinator.prepareSelfUpdate(groupIdHex);
          await client.coordinator.cancelBeforeAttempt(groupIdHex);
        }
        const bounded = await client.journal.snapshot(groupIdHex);
        expect(bounded.generations).toHaveLength(B26_LIMITS.maxGenerations);
        expect(bounded.generations.some((item) =>
          item.commitDigestHex === generation.commitDigestHex && item.contradiction)).toBe(true);
        const inbound = selfUpdateFrom(
          wasm, fixture.peers.alice, fixture.groupId, fixture.peers.alice.snapshotBytes);
        await client.coordinator.admitCommit(groupIdHex, inbound.commitBytes);
        const pass = await client.coordinator.freeze(groupIdHex);
        const before = (await client.journal.readHead(groupIdHex)).head;
        await expect(client.coordinator.settle(pass.passDigestHex)).rejects.toMatchObject({
          code: B26_ERROR.UNRECOVERABLE,
        });
        const terminal = (await client.journal.readHead(groupIdHex)).head;
        expect(terminal.state).toBe(B26_HEAD_STATE.UNRECOVERABLE);
        expect(terminal.snapshotDigestHex).toBe(before.snapshotDigestHex);
        expect(terminal.anchorSnapshotDigestHex).toBe(before.anchorSnapshotDigestHex);
        expect(terminal.canonicalPath).toEqual(before.canonicalPath);
        expect(terminal.epochDec).toBe(before.epochDec);
        await expect(client.coordinator.prepareSelfUpdate(groupIdHex)).rejects.toMatchObject({
          code: B26_ERROR.STATE_CONFLICT,
        });
      } finally { fixture.cleanup(); }
    }, 20000);

  test.each([
    B26_STORES.retained,
    B26_STORES.edge,
    B26_STORES.input,
    B26_STORES.pass,
    B26_STORES.invalidation,
    B26_STORES.transition,
    B26_STORES.head,
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
      await expect(pending).rejects.toMatchObject({ code: B26_ERROR.CAS_CONFLICT });
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
        const queued = await client.coordinator.queueApplicationMessage(
          groupIdHex, 'release-bound-outbox', UTF8.encode('release-bound-outbox'));
        const durable = await client.coordinator.readQueuedApplicationMessage(
          queued.instanceKeyHex, queued.ordinal);
        const attempt = await client.coordinator.recordApplicationAttempt(
          queued.instanceKeyHex, queued.ordinal, durable.recipientScope[0]);
        const settled = await settleInputs(client, fixture.groupId, chain.reverse());
        expect(settled.head.canonicalPath).toHaveLength(5);
        expect(settled.head.epochDec).toBe('9');
        expect(settled.head.anchorTipCommitDigestHex).toBe(digestHex(chain.at(-1)));
        expect(settled.transition.anchorTipCommitDigestHex)
          .toBe(settled.head.anchorTipCommitDigestHex);
        await expect(client.journal.readRetained(initial.snapshotDigestHex)).rejects
          .toMatchObject({ code: B26_ERROR.RELEASED });
        await expect(client.journal.readRetainedMessageContext(
          groupIdHex, initial.snapshotDigestHex)).rejects
          .toMatchObject({ code: B26_ERROR.RELEASED });
        const snapshot = await client.journal.snapshot(groupIdHex);
        expect(snapshot.edges.length).toBeLessThanOrEqual(B26_LIMITS.maxEdges);
        expect(snapshot.retained.length).toBeLessThanOrEqual(B26_LIMITS.maxStates);
        expect(snapshot.inputs.find((item) =>
          item.commitDigestHex === digestHex(chain.at(-1))).state).toBe('STALE');
        expect(snapshot.released).toEqual([
          expect.objectContaining({ snapshotDigestHex: initial.snapshotDigestHex }),
        ]);
        await expect(client.coordinator.readQueuedApplicationMessage(
          queued.instanceKeyHex, queued.ordinal)).rejects.toMatchObject({
          code: B26_ERROR.OUTBOX_TERMINAL,
        });
        await expect(client.journal.readMessageContext(groupIdHex)).resolves
          .toEqual(expect.objectContaining({ instanceKeyHex: expect.any(String) }));
        expect(await client.journal.readOutbox(
          queued.instanceKeyHex, queued.ordinal)).toEqual(expect.objectContaining({
          state: 'INVALIDATED',
        }));
        const late = await client.coordinator.recordApplicationAcknowledgement(
          queued.instanceKeyHex, queued.ordinal, attempt.attemptOrdinal,
          durable.recipientScope[0], UTF8.encode('late-after-release'));
        expect(late.evidence.kind).toBe('LATE_ACK');
        expect(late.outbox.state).toBe('INVALIDATED');
        expect(client.db.stores.get(B26_STORES.messageRelease)?.size).toBe(1);
      } finally { fixture.cleanup(); }
    }, 20000);

  test('anchor advancement preserves a historical instance ratchet and replay namespace',
    async () => {
      const wasm = await loadWasm();
      const fixture = await setupGroup(wasm);
      try {
        let sourceSnapshot = fixture.peers.alice.snapshotBytes;
        const chain = [];
        for (let index = 0; index < 6; index += 1) {
          const update = selfUpdateFrom(
            wasm, fixture.peers.alice, fixture.groupId, sourceSnapshot);
          chain.push(update);
          sourceSnapshot = update.successorSnapshotBytes;
        }
        const sender = restoreSource(wasm, fixture.peers.alice, fixture.groupId,
          chain[0].successorSnapshotBytes);
        const ciphertext = copyBytes(sender.group.create_application_message(
          sender.provider, sender.identity, UTF8.encode('anchor-history')));
        free(sender.group); free(sender.identity); free(sender.provider);

        const client = clientFor(wasm, fixture.peers.bob, fixture.groupId,
          'anchor-message-identity');
        await client.initialize();
        const groupIdHex = bytesToHex(fixture.groupId);
        await settleInputs(client, fixture.groupId,
          chain.slice(0, 5).map((item) => item.commitBytes).reverse());
        const beforeAdvance = await client.journal.snapshot(groupIdHex);
        const firstEdge = beforeAdvance.edges.find((edge) =>
          edge.commitDigestHex === digestHex(chain[0].commitBytes));
        const first = await client.coordinator.processApplicationMessage(
          groupIdHex, ciphertext, firstEdge.successorSnapshotDigestHex);
        expect(first.status).toBe('accepted');

        await settleInputs(client, fixture.groupId, [chain[5].commitBytes]);
        const afterAdvance = await client.journal.readRetainedMessageContext(
          groupIdHex, firstEdge.successorSnapshotDigestHex);
        expect(afterAdvance.instanceKeyHex).toBe(first.instanceKeyHex);
        const replay = await client.coordinator.processApplicationMessage(
          groupIdHex, ciphertext, firstEdge.successorSnapshotDigestHex);
        expect(replay).toEqual(expect.objectContaining({
          status: 'duplicate',
          instanceKeyHex: first.instanceKeyHex,
          receivedOrdinal: first.receivedOrdinal,
        }));
      } finally { fixture.cleanup(); }
    }, 20000);

  test('contradictory adopted-anchor binding evidence fails closed without mutation',
    async () => {
      const wasm = await loadWasm();
      const fixture = await setupGroup(wasm);
      try {
        const chain = selfUpdateChainFrom(
          wasm, fixture.peers.alice, fixture.groupId, fixture.peers.alice.snapshotBytes, 6);
        const client = clientFor(wasm, fixture.peers.bob, fixture.groupId,
          'contradictory-anchor-binding');
        await client.initialize();
        const groupIdHex = bytesToHex(fixture.groupId);
        await settleInputs(client, fixture.groupId,
          chain.slice(0, 5).map((item) => item.commitBytes).reverse());
        const firstCommitDigestHex = digestHex(chain[0].commitBytes);
        const firstEdge = (await client.journal.snapshot(groupIdHex)).edges.find(
          (edge) => edge.commitDigestHex === firstCommitDigestHex);
        await settleInputs(client, fixture.groupId, [chain[5].commitBytes]);
        const adoptedHead = (await client.journal.readHead(groupIdHex)).head;
        expect(adoptedHead.anchorTipCommitDigestHex).toBe(firstCommitDigestHex);
        const { format, version, edgeDigestHex, ...edgeFields } = firstEdge;
        const contradictory = buildEdge({
          ...edgeFields,
          commitDigestHex: 'fe'.repeat(32),
        });
        client.db.stores.get(B26_STORES.edge)
          .set(`contradictory:${contradictory.edgeDigestHex}`, contradictory);
        const before = durableImage(client.db);
        await expect(client.journal.readRetainedMessageContext(
          groupIdHex, adoptedHead.anchorSnapshotDigestHex)).rejects.toMatchObject({
          code: B26_ERROR.CORRUPT,
        });
        expect(durableImage(client.db)).toEqual(before);
      } finally { fixture.cleanup(); }
    }, 20000);

  test('record-first release rejects a stored instance-key contradiction without mutation',
    async () => {
      const wasm = await loadWasm();
      const fixture = await setupGroup(wasm);
      try {
        const chain = selfUpdateChainFrom(
          wasm, fixture.peers.alice, fixture.groupId, fixture.peers.alice.snapshotBytes, 6);
        const client = clientFor(wasm, fixture.peers.bob, fixture.groupId,
          'record-first-release');
        await client.initialize();
        const groupIdHex = bytesToHex(fixture.groupId);
        const queued = await client.coordinator.queueApplicationMessage(
          groupIdHex, 'record-first', UTF8.encode('record-first'));
        const stateKey = messageStateKey(groupIdHex, queued.instanceKeyHex);
        const original = client.db.stores.get(B26_STORES.messageState).get(stateKey);
        const { format, version, profile, runtime, stateDigestHex, ...stateFields } = original;
        const contradictoryTipCommitDigestHex = 'fc'.repeat(32);
        const contradictory = buildMessageState({
          ...stateFields,
          tipCommitDigestHex: contradictoryTipCommitDigestHex,
          instanceKeyHex: messageInstanceKey({
            groupIdHex,
            tipCommitDigestHex: contradictoryTipCommitDigestHex,
            epochDec: original.epochDec,
            groupContextDigestHex: original.groupContextDigestHex,
            localMemberIdentityHex: original.localMemberIdentityHex,
          }),
        });
        client.db.stores.get(B26_STORES.messageState).delete(stateKey);
        client.db.stores.get(B26_STORES.messageState).set(
          messageStateKey(groupIdHex, contradictory.instanceKeyHex), contradictory);
        for (const update of [...chain].reverse()) {
          await client.coordinator.admitCommit(groupIdHex, update.commitBytes);
        }
        const pass = await client.coordinator.freeze(groupIdHex);
        const before = durableImage(client.db);
        await expect(client.coordinator.settle(pass.passDigestHex)).rejects.toMatchObject({
          code: B26_ERROR.CORRUPT,
        });
        expect(durableImage(client.db)).toEqual(before);
      } finally { fixture.cleanup(); }
    }, 20000);

  test('branch-changing anchor adoption preserves a never-head deferred instance identity',
    async () => {
      const wasm = await loadWasm();
      const fixture = await setupGroup(wasm);
      try {
        const base = fixture.peers.alice.snapshotBytes;
        const branchC = selfUpdateChainFrom(
          wasm, fixture.peers.alice, fixture.groupId, base, 7);
        const branchD = selfUpdateChainFrom(
          wasm, fixture.peers.alice, fixture.groupId, base, 2);
        const client = clientFor(wasm, fixture.peers.bob, fixture.groupId,
          'branch-anchor-never-head');
        await client.initialize();
        const groupIdHex = bytesToHex(fixture.groupId);

        await settleInputs(client, fixture.groupId,
          branchD.map((item) => item.commitBytes).reverse());
        await settleInputs(client, fixture.groupId, [branchC[0].commitBytes]);
        const c1DigestHex = digestHex(branchC[0].commitBytes);
        expect((await client.journal.readHead(groupIdHex)).head.canonicalPath)
          .toEqual(branchD.map((item) => digestHex(item.commitBytes)));
        const c1Edge = (await client.journal.snapshot(groupIdHex)).edges.find((edge) =>
          edge.commitDigestHex === c1DigestHex);
        const sender = restoreSource(wasm, fixture.peers.alice, fixture.groupId,
          branchC[0].successorSnapshotBytes);
        const ciphertext = copyBytes(sender.group.create_application_message(
          sender.provider, sender.identity, UTF8.encode('never-head-deferred')));
        free(sender.group); free(sender.identity); free(sender.provider);
        const deferred = await client.coordinator.processApplicationMessage(
          groupIdHex, ciphertext, c1Edge.successorSnapshotDigestHex);
        expect(deferred.status).toBe('deferred');

        const adoption = await settleInputs(client, fixture.groupId,
          branchC.slice(1, 6).map((item) => item.commitBytes).reverse());
        const adopted = await client.journal.readRetainedMessageContext(
          groupIdHex, c1Edge.successorSnapshotDigestHex);
        const adoptedHead = (await client.journal.readHead(groupIdHex)).head;
        expect(adoptedHead.anchorSnapshotDigestHex).toBe(c1Edge.successorSnapshotDigestHex);
        expect(adoptedHead.anchorTipCommitDigestHex).toBe(c1DigestHex);
        expect(adoption.transition.anchorTipCommitDigestHex).toBe(c1DigestHex);
        expect(adopted.instanceKeyHex).toBe(deferred.instanceKeyHex);
        expect(adopted.canonical).toBe(true);

        await settleInputs(client, fixture.groupId, [branchC[6].commitBytes]);
        expect(await client.journal.readInbound(
          deferred.instanceKeyHex, deferred.ciphertextDigestHex)).toEqual(
          expect.objectContaining({ disposition: 'INVALIDATED' }));
      } finally { fixture.cleanup(); }
    }, 20000);

  test('branch-changing anchor re-adoption preserves a prior-head durable ratchet',
    async () => {
      const wasm = await loadWasm();
      const fixture = await setupGroup(wasm);
      try {
        const base = fixture.peers.alice.snapshotBytes;
        const branchC = selfUpdateChainFrom(
          wasm, fixture.peers.alice, fixture.groupId, base, 7);
        const branchD = selfUpdateChainFrom(
          wasm, fixture.peers.alice, fixture.groupId, base, 2);
        const client = clientFor(wasm, fixture.peers.bob, fixture.groupId,
          'branch-anchor-prior-head');
        await client.initialize();
        const groupIdHex = bytesToHex(fixture.groupId);
        const c1DigestHex = digestHex(branchC[0].commitBytes);

        await settleInputs(client, fixture.groupId, [branchC[0].commitBytes]);
        const queued = await client.coordinator.queueApplicationMessage(
          groupIdHex, 'prior-head-message', UTF8.encode('prior-head-message'));
        await settleInputs(client, fixture.groupId,
          branchD.map((item) => item.commitBytes).reverse());
        expect((await client.journal.readHead(groupIdHex)).head.canonicalPath)
          .toEqual(branchD.map((item) => digestHex(item.commitBytes)));

        const adoption = await settleInputs(client, fixture.groupId,
          branchC.slice(1, 6).map((item) => item.commitBytes).reverse());
        const adoptedHead = (await client.journal.readHead(groupIdHex)).head;
        expect(adoptedHead.anchorTipCommitDigestHex).toBe(c1DigestHex);
        expect(adoption.transition.anchorTipCommitDigestHex).toBe(c1DigestHex);
        const adopted = await client.journal.readRetainedMessageContext(
          groupIdHex, adoptedHead.anchorSnapshotDigestHex);
        expect(adopted.instanceKeyHex).toBe(queued.instanceKeyHex);
        expect(adopted.state).toEqual(expect.objectContaining({
          instanceKeyHex: queued.instanceKeyHex,
          state: 'ACTIVE',
          sentCount: 1,
        }));

        await settleInputs(client, fixture.groupId, [branchC[6].commitBytes]);
        await expect(client.coordinator.readQueuedApplicationMessage(
          queued.instanceKeyHex, queued.ordinal)).rejects.toMatchObject({
          code: B26_ERROR.OUTBOX_TERMINAL,
        });
        expect(client.db.stores.get(B26_STORES.messageRelease)
          .has(messageStateKey(groupIdHex, queued.instanceKeyHex))).toBe(true);
      } finally { fixture.cleanup(); }
    }, 20000);

  test('single and split cutoffs converge when anchor advancement also discards a new sibling',
    async () => {
      const wasm = await loadWasm();
      const fixture = await setupGroup(wasm);
      try {
        const base = fixture.peers.alice.snapshotBytes;
        let sourceSnapshot = base;
        const chain = [];
        for (let index = 0; index < 6; index += 1) {
          const update = selfUpdateFrom(
            wasm, fixture.peers.alice, fixture.groupId, sourceSnapshot);
          chain.push(update.commitBytes);
          sourceSnapshot = update.successorSnapshotBytes;
        }
        const sibling = selfUpdateFrom(
          wasm, fixture.peers.alice, fixture.groupId, base);
        const single = clientFor(wasm, fixture.peers.bob, fixture.groupId,
          'sibling-single');
        const split = clientFor(wasm, fixture.peers.charlie, fixture.groupId,
          'sibling-split');
        await single.initialize();
        await split.initialize();
        await settleInputs(single, fixture.groupId,
          [sibling.commitBytes, ...chain.slice().reverse()]);
        await settleInputs(split, fixture.groupId, [sibling.commitBytes]);
        await settleInputs(split, fixture.groupId, chain.slice().reverse());
        const singleHead = (await single.journal.readHead(bytesToHex(fixture.groupId))).head;
        const splitHead = (await split.journal.readHead(bytesToHex(fixture.groupId))).head;
        expect(singleHead.canonicalPath).toHaveLength(B26_LIMITS.rewindCommits);
        expect(splitHead.canonicalPath).toEqual(singleHead.canonicalPath);
        expect(splitHead.epochDec).toBe(singleHead.epochDec);
        expect(splitHead.groupContextDigestHex).toBe(singleHead.groupContextDigestHex);
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
      expect(client.db.stores.get(B26_STORES.probeReservation).size).toBe(2);
      const neverProbedHead = (await neverProbed.journal.readHead(groupIdHex)).head;
      expect([finalHead.canonicalPath, finalHead.epochDec,
        finalHead.groupContextDigestHex]).toEqual([
        neverProbedHead.canonicalPath,
        neverProbedHead.epochDec,
        neverProbedHead.groupContextDigestHex,
      ]);
    } finally { fixture.cleanup(); }
  }, 20000);

  test('historical canonical input is accepted while sibling input waits for re-adoption',
    async () => {
      const wasm = await loadWasm();
      const fixture = await setupGroup(wasm);
      try {
        const base = fixture.peers.alice.snapshotBytes;
        const siblings = [
          selfUpdateFrom(wasm, fixture.peers.alice, fixture.groupId, base),
          selfUpdateFrom(wasm, fixture.peers.alice, fixture.groupId, base),
        ].sort((left, right) =>
          digestHex(left.commitBytes) < digestHex(right.commitBytes) ? -1 : 1);
        const selected = siblings[0];
        const displaced = siblings[1];
        const client = clientFor(wasm, fixture.peers.bob, fixture.groupId,
          'historical-message');
        await client.initialize();
        const groupIdHex = bytesToHex(fixture.groupId);
        const initialRetained = (await client.journal.readHead(groupIdHex)).retained;
        const initialSender = restoreSource(
          wasm, fixture.peers.alice, fixture.groupId, base);
        const historicalCiphertext = copyBytes(
          initialSender.group.create_application_message(
            initialSender.provider, initialSender.identity, UTF8.encode('historical')));
        free(initialSender.group); free(initialSender.identity); free(initialSender.provider);
        await settleInputs(client, fixture.groupId,
          [displaced.commitBytes, selected.commitBytes]);
        const historical = await client.coordinator.processApplicationMessage(
          groupIdHex, historicalCiphertext, initialRetained.snapshotDigestHex);
        expect(new TextDecoder().decode(historical.plaintextBytes)).toBe('historical');

        const displacedSender = restoreSource(
          wasm, fixture.peers.alice, fixture.groupId, displaced.successorSnapshotBytes);
        const displacedCiphertext = copyBytes(
          displacedSender.group.create_application_message(
            displacedSender.provider, displacedSender.identity, UTF8.encode('deferred')));
        free(displacedSender.group); free(displacedSender.identity); free(displacedSender.provider);
        const view = await client.journal.snapshot(groupIdHex);
        const displacedEdge = view.edges.find((edge) =>
          edge.commitDigestHex === digestHex(displaced.commitBytes));
        const deferred = await client.coordinator.processApplicationMessage(
          groupIdHex, displacedCiphertext, displacedEdge.successorSnapshotDigestHex);
        expect(deferred.status).toBe('deferred');
        expect(deferred.plaintextBytes).toBeUndefined();

        const child = selfUpdateFrom(
          wasm, fixture.peers.alice, fixture.groupId, displaced.successorSnapshotBytes);
        await settleInputs(client, fixture.groupId, [child.commitBytes]);
        const accepted = await client.coordinator.processApplicationMessage(
          groupIdHex, displacedCiphertext, displacedEdge.successorSnapshotDigestHex);
        expect(accepted.status).toBe('accepted');
        expect(new TextDecoder().decode(accepted.plaintextBytes)).toBe('deferred');
      } finally { fixture.cleanup(); }
    }, 20000);

  test('deferred sibling input is invalidated when its retained instance is released',
    async () => {
      const wasm = await loadWasm();
      const fixture = await setupGroup(wasm);
      try {
        const base = fixture.peers.alice.snapshotBytes;
        const siblings = [
          selfUpdateFrom(wasm, fixture.peers.alice, fixture.groupId, base),
          selfUpdateFrom(wasm, fixture.peers.alice, fixture.groupId, base),
        ].sort((left, right) =>
          digestHex(left.commitBytes) < digestHex(right.commitBytes) ? -1 : 1);
        const [selected, displaced] = siblings;
        const client = clientFor(wasm, fixture.peers.bob, fixture.groupId,
          'deferred-release');
        await client.initialize();
        const groupIdHex = bytesToHex(fixture.groupId);
        await settleInputs(client, fixture.groupId,
          [displaced.commitBytes, selected.commitBytes]);
        const displacedEdge = (await client.journal.snapshot(groupIdHex)).edges.find(
          (edge) => edge.commitDigestHex === digestHex(displaced.commitBytes));
        const sender = restoreSource(wasm, fixture.peers.alice, fixture.groupId,
          displaced.successorSnapshotBytes);
        const ciphertext = copyBytes(sender.group.create_application_message(
          sender.provider, sender.identity, UTF8.encode('release-deferred')));
        free(sender.group); free(sender.identity); free(sender.provider);
        const deferred = await client.coordinator.processApplicationMessage(
          groupIdHex, ciphertext, displacedEdge.successorSnapshotDigestHex);
        expect(deferred.status).toBe('deferred');
        expect(client.db.stores.get(B26_STORES.messageState)
          ?.has(messageStateKey(groupIdHex, deferred.instanceKeyHex)) ?? false).toBe(false);
        expect(await client.journal.readInbound(
          deferred.instanceKeyHex, deferred.ciphertextDigestHex)).toEqual(
          expect.objectContaining({
            disposition: 'DEFERRED',
            baseRetainedSnapshotDigestHex: displacedEdge.successorSnapshotDigestHex,
          }));

        let selectedSnapshot = selected.successorSnapshotBytes;
        const descendants = [];
        for (let index = 0; index < 5; index += 1) {
          const update = selfUpdateFrom(
            wasm, fixture.peers.alice, fixture.groupId, selectedSnapshot);
          descendants.push(update);
          selectedSnapshot = update.successorSnapshotBytes;
        }
        await settleInputs(client, fixture.groupId,
          descendants.map((item) => item.commitBytes).reverse());
        await expect(client.journal.readRetained(
          displacedEdge.successorSnapshotDigestHex)).rejects.toMatchObject({
          code: B26_ERROR.RELEASED,
        });
        expect(await client.journal.readInbound(
          deferred.instanceKeyHex, deferred.ciphertextDigestHex)).toEqual(
          expect.objectContaining({
            disposition: 'INVALIDATED',
            baseRetainedSnapshotDigestHex: displacedEdge.successorSnapshotDigestHex,
          }));
      } finally { fixture.cleanup(); }
    }, 20000);

  test('local-generation release wins atomically over a deferred inbound commit',
    async () => {
      const wasm = await loadWasm();
      const fixture = await setupGroup(wasm);
      try {
        const groupIdHex = bytesToHex(fixture.groupId);
        let client;
        let releaseArmed = true;
        client = clientFor(wasm, fixture.peers.bob, fixture.groupId,
          'deferred-generation-release', {
            beforeInboundCommit: async ({ disposition }) => {
              if (releaseArmed && disposition === 'DEFERRED') {
                releaseArmed = false;
                await client.coordinator.cancelBeforeAttempt(groupIdHex);
              }
            },
          });
        await client.initialize();
        const generation = await client.coordinator.prepareSelfUpdate(groupIdHex);
        const aliceSuccessor = inboundSuccessorFrom(
          wasm, fixture.peers.alice, fixture.groupId,
          fixture.peers.alice.snapshotBytes, generation.commitBytes);
        const sender = restoreSource(wasm, fixture.peers.alice, fixture.groupId,
          aliceSuccessor.snapshotBytes);
        const ciphertext = copyBytes(sender.group.create_application_message(
          sender.provider, sender.identity, UTF8.encode('release-race')));
        free(sender.group); free(sender.identity); free(sender.provider);

        await expect(client.coordinator.processApplicationMessage(
          groupIdHex, ciphertext, generation.pendingSnapshotDigestHex))
          .rejects.toMatchObject({ code: B26_ERROR.RELEASED });
        expect(client.db.stores.get(B26_STORES.appInbound)?.size ?? 0).toBe(0);
        expect(client.db.stores.get(B26_STORES.retained)
          .has(generation.pendingSnapshotDigestHex)).toBe(false);
        expect(client.db.stores.get(B26_STORES.released)
          .has(generation.pendingSnapshotDigestHex)).toBe(true);
      } finally { fixture.cleanup(); }
    }, 20000);

  test('message-state instance cap fails before ratchet mutation', async () => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm);
    try {
      const client = clientFor(wasm, fixture.peers.alice, fixture.groupId,
        'message-state-cap');
      await client.initialize();
      const groupIdHex = bytesToHex(fixture.groupId);
      const context = await client.journal.readMessageContext(groupIdHex);
      const store = client.db.stores.get(B26_STORES.messageState);
      for (let index = 0; index < B26_LIMITS.maxMessageStates; index += 1) {
        const tipCommitDigestHex = (index + 1).toString(16).padStart(64, '0');
        const instanceKeyHex = messageInstanceKey({
          groupIdHex,
          tipCommitDigestHex,
          epochDec: context.head.epochDec,
          groupContextDigestHex: context.head.groupContextDigestHex,
          localMemberIdentityHex: context.head.accountKeyHex,
        });
        const state = buildMessageState({
          groupIdHex,
          instanceKeyHex,
          baseHeadDigestHex: context.head.headDigestHex,
          tipCommitDigestHex,
          epochDec: context.head.epochDec,
          groupContextDigestHex: context.head.groupContextDigestHex,
          localMemberIdentityHex: context.head.accountKeyHex,
          baseRetainedSnapshotDigestHex: context.retained.snapshotDigestHex,
          sequence: 0,
          sentCount: 0,
          receivedCount: 0,
          snapshotDigestHex: (index + 100).toString(16).padStart(64, '0'),
          priorStateDigestHex: null,
          state: 'ACTIVE',
        });
        store.set(messageStateKey(groupIdHex, instanceKeyHex), state);
      }
      const before = store.size;
      await expect(client.coordinator.queueApplicationMessage(
        groupIdHex, 'over-message-state-cap', UTF8.encode('bounded')))
        .rejects.toMatchObject({ code: B26_ERROR.RESOURCE_LIMIT });
      expect(store.size).toBe(before);
      expect(client.db.stores.get(B26_STORES.appOutbox).size).toBe(0);
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
        for (let index = 0; index < B26_LIMITS.maxGenerations + 1; index += 1) {
          const generation = await client.coordinator.prepareSelfUpdate(groupIdHex);
          first ??= generation;
          await client.coordinator.cancelBeforeAttempt(groupIdHex);
        }
        const snapshot = await client.journal.snapshot(groupIdHex);
        expect(snapshot.generations).toHaveLength(B26_LIMITS.maxGenerations);
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
            code: B26_ERROR.UNKNOWN_GENERATION,
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
      for (let index = 0; index < B26_LIMITS.maxInputs; index += 1) {
        await client.coordinator.admitCommit(groupIdHex,
          Uint8Array.of(0xa0, index + 1));
      }
      const before = await client.journal.snapshot(groupIdHex);
      await expect(client.coordinator.admitCommit(groupIdHex,
        Uint8Array.of(0xa1, 0xff))).rejects.toMatchObject({
        code: B26_ERROR.RESOURCE_LIMIT,
      });
      const after = await client.journal.snapshot(groupIdHex);
      expect(after.inputs.map((item) => item.inputDigestHex))
        .toEqual(before.inputs.map((item) => item.inputDigestHex));
    } finally { fixture.cleanup(); }
  }, 20000);

  test('a displaced instance suspends exact-byte publication and resumes after re-adoption',
    async () => {
      const wasm = await loadWasm();
      const fixture = await setupGroup(wasm);
      try {
        const base = fixture.peers.alice.snapshotBytes;
        const siblings = [
          selfUpdateFrom(wasm, fixture.peers.alice, fixture.groupId, base),
          selfUpdateFrom(wasm, fixture.peers.alice, fixture.groupId, base),
        ].sort((left, right) =>
          digestHex(left.commitBytes) < digestHex(right.commitBytes) ? -1 : 1);
        const selected = siblings[0];
        const displaced = siblings[1];
        const displacedChild = selfUpdateFrom(
          wasm, fixture.peers.alice, fixture.groupId, displaced.successorSnapshotBytes);
        let client = clientFor(wasm, fixture.peers.bob, fixture.groupId,
          'message-readoption');
        await client.initialize();
        const groupIdHex = bytesToHex(fixture.groupId);
        await settleInputs(client, fixture.groupId, [displaced.commitBytes]);
        const queued = await client.coordinator.queueApplicationMessage(
          groupIdHex, 'readopted-request', UTF8.encode('readopted-message'));
        const original = await client.coordinator.readQueuedApplicationMessage(
          queued.instanceKeyHex, queued.ordinal);
        await settleInputs(client, fixture.groupId, [selected.commitBytes]);
        await expect(client.coordinator.readQueuedApplicationMessage(
          queued.instanceKeyHex, queued.ordinal)).rejects.toMatchObject({
          code: B26_ERROR.OUTBOX_SUSPENDED,
        });
        await settleInputs(client, fixture.groupId, [displacedChild.commitBytes]);
        client = restartClient(wasm, client);
        const resumed = await client.coordinator.readQueuedApplicationMessage(
          queued.instanceKeyHex, queued.ordinal);
        expect(bytesToHex(resumed.ciphertextBytes)).toBe(bytesToHex(original.ciphertextBytes));
        expect(resumed.state).toBe('DURABLE');
      } finally { fixture.cleanup(); }
    }, 20000);

  test('journal factory rejects databases outside the isolated B2.6 namespace', () => {
    const db = new FakeVaultDb();
    Object.defineProperty(db, 'name', { value: 'styx-unscoped-database' });
    expect(() => createB26JournalForDb(db)).toThrow(/outside the B2\.6 namespace/);
    const v1 = new FakeVaultDb();
    Object.defineProperty(v1, 'name', { value: 'styx-b2-6-poc-v1-retired' });
    expect(() => createB26JournalForDb(v1)).toThrow(/outside the B2\.6 namespace/);
  });

  test('head reads reject a missing transition audit record without mutation', async () => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm);
    try {
      const client = clientFor(wasm, fixture.peers.bob, fixture.groupId,
        'missing-transition-audit');
      await client.initialize();
      const groupIdHex = bytesToHex(fixture.groupId);
      const head = (await client.journal.readHead(groupIdHex)).head;
      client.db.stores.get(B26_STORES.transition).delete(head.transitionDigestHex);
      const before = durableImage(client.db);
      await expect(client.journal.readHead(groupIdHex)).rejects.toMatchObject({
        code: B26_ERROR.CORRUPT,
      });
      expect(durableImage(client.db)).toEqual(before);
    } finally { fixture.cleanup(); }
  }, 20000);

  test('message readers reject a state bound to a different retained base', async () => {
    const wasm = await loadWasm();
    const fixture = await setupGroup(wasm);
    try {
      const client = clientFor(wasm, fixture.peers.bob, fixture.groupId,
        'misbound-message-base');
      await client.initialize();
      const groupIdHex = bytesToHex(fixture.groupId);
      const queued = await client.coordinator.queueApplicationMessage(
        groupIdHex, 'misbound-base', UTF8.encode('misbound-base'));
      const key = messageStateKey(groupIdHex, queued.instanceKeyHex);
      const original = client.db.stores.get(B26_STORES.messageState).get(key);
      const { format, version, profile, runtime, stateDigestHex, ...stateFields } = original;
      const contradictory = buildMessageState({
        ...stateFields,
        baseRetainedSnapshotDigestHex: 'fd'.repeat(32),
      });
      client.db.stores.get(B26_STORES.messageState).set(key, contradictory);
      const before = durableImage(client.db);
      await expect(client.journal.readMessageContext(groupIdHex)).rejects.toMatchObject({
        code: B26_ERROR.CORRUPT,
      });
      expect(durableImage(client.db)).toEqual(before);
    } finally { fixture.cleanup(); }
  }, 20000);

  test('non-genesis retained states without identity evidence fail closed without mutation',
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
          client.db.stores.get(B26_STORES.retained)
            .set(retained.snapshotDigestHex, retained);
        }
        const before = (await client.journal.readHead(groupIdHex)).head;
        await client.coordinator.admitCommit(groupIdHex, childCommit.commitBytes);
        const pass = await client.coordinator.freeze(groupIdHex);
        const durableBefore = durableImage(client.db);
        await expect(client.coordinator.settle(pass.passDigestHex)).rejects.toMatchObject({
          code: B26_ERROR.CORRUPT,
        });
        expect(durableImage(client.db)).toEqual(durableBefore);
        expect((await client.journal.readHead(groupIdHex)).head.snapshotDigestHex)
          .toBe(before.snapshotDigestHex);
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
        client.db.stores.get(B26_STORES.retained).delete(before.anchorSnapshotDigestHex);
        await client.coordinator.admitCommit(groupIdHex, Uint8Array.of(0xaa, 0x01));
        const pass = await client.coordinator.freeze(groupIdHex);
        await expect(client.coordinator.settle(pass.passDigestHex)).rejects.toMatchObject({
          code: B26_ERROR.UNRECOVERABLE,
        });
        const after = (await client.journal.readHead(groupIdHex)).head;
        expect(after.state).toBe(B26_HEAD_STATE.UNRECOVERABLE);
        expect(after.snapshotDigestHex).toBe(before.snapshotDigestHex);
        expect(after.anchorSnapshotDigestHex).toBe(before.anchorSnapshotDigestHex);
        expect(after.canonicalPath).toEqual(before.canonicalPath);
        await expect(client.coordinator.admitCommit(
          groupIdHex, Uint8Array.of(0xaa, 0x02))).rejects.toMatchObject({
          code: B26_ERROR.UNRECOVERABLE,
        });
      } finally { fixture.cleanup(); }
    }, 20000);
});
