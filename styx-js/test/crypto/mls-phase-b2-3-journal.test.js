import { describe, expect, jest, test } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { schnorr } from '@noble/curves/secp256k1';

import {
  B23_ERROR,
  B23_LIMITS,
  B23_RUNTIME,
  B23_STORE_NAMES,
  B23_STORES,
  bytesToHex,
  digestHex,
  hexToBytes,
  validateProviderSnapshot,
} from '../../spikes/marmot-phase-b2-3/b2-3-canonical.mjs';
import {
  HEAD_PREPARED,
  HEAD_STABLE,
  buildHead,
  canonicalProjectionBytes,
  parseHead,
  parseTransition,
} from '../../spikes/marmot-phase-b2-3/b2-3-record.mjs';
import {
  createB23JournalForDb,
} from '../../spikes/marmot-phase-b2-3/b2-3-journal.mjs';
import { B23EngineAdapter } from '../../spikes/marmot-phase-b2-3/b2-3-engine-adapter.mjs';
import { createAccountIdentityProofV2 } from '../../spikes/marmot-phase-b1/identity-proof-v2.js';
import { VaultDb } from '../../src/storage/vault-db.js';
import { FakeVaultDb } from '../support/fake-vault-db.js';

const GROUP = 'ab'.repeat(32);
const ACCOUNT = '11'.repeat(32);
const SIGNATURE = '22'.repeat(32);
const EPOCH_0 = '33'.repeat(32);
const EPOCH_1 = digestHex(Uint8Array.of(0x66));
const VERIFIED = '55'.repeat(32);
const COMMIT = Uint8Array.of(1, 2, 3, 4);
const PROJECTION = Object.freeze({
  format: 'styx-b2-3-projection', version: 1, priorEpochDec: '0', candidateEpochDec: '1',
  committerSource: 'member', committerLeafIndex: 0,
  committerIdentityHex: ACCOUNT, committerSignatureKeyHex: SIGNATURE,
  administratorPolicyHex: `20${ACCOUNT}`, lifecycleHex: '00',
  requiredComponentIds: Object.freeze([32771, 32777, 32780]),
  candidateGroupContextTlsHex: '66', candidateGroupContextDigestHex: EPOCH_1,
  verifiedLeafDigestHex: VERIFIED,
  candidateMembers: Object.freeze([Object.freeze({
    leafIndex: 0, identityHex: ACCOUNT, signatureKeyHex: SIGNATURE,
    identityProofHex: '77'.repeat(104), componentIds: Object.freeze([1, 32777]),
    supportedComponentIds: Object.freeze([32771, 32777, 32780]),
  })]),
  proposals: Object.freeze([]), updatePath: null,
});

function deterministicRandom(start = 1) {
  let value = start;
  return (target) => { target.fill(value); value += 1; return target; };
}

class SerializedFakeVaultDb extends FakeVaultDb {
  constructor() {
    super();
    this.transactionTail = Promise.resolve();
  }

  transaction(namespaces, callback) {
    const result = this.transactionTail.then(() => super.transaction(namespaces, callback));
    this.transactionTail = result.catch(() => undefined);
    return result;
  }
}

function u64(value) {
  const out = new Uint8Array(8);
  let remaining = BigInt(value);
  for (let index = 7; index >= 0; index -= 1) {
    out[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return out;
}

function concatBytes(...parts) {
  const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
}

function duplicateProviderKeySnapshot() {
  const key = Uint8Array.of(1, 2);
  const value = Uint8Array.of(3);
  return concatBytes(
    u64(2), u64(key.length), u64(value.length), key, value,
    u64(key.length), u64(value.length), key, value,
  );
}

function journal(db = new FakeVaultDb(), randomStart = 1) {
  return { db, value: createB23JournalForDb(db, { randomBytes: deterministicRandom(randomStart) }) };
}

async function initialized() {
  const instance = journal();
  const snapshotBytes = Uint8Array.of(9, 8, 7);
  const head = await instance.value.initialize({
    bindings: { groupIdHex: GROUP, accountKeyHex: ACCOUNT, signatureKeyHex: SIGNATURE },
    snapshotBytes,
    epochDec: '0',
    epochDigestHex: EPOCH_0,
  });
  return { ...instance, head, snapshotBytes };
}

async function prepare(instance) {
  const { value, head } = instance;
  const projectionDigestHex = digestHex(canonicalProjectionBytes(PROJECTION));
  return value.cas({
    expectedHead: head,
    snapshotBytes: Uint8Array.of(9, 8, 7, 6),
    transitionFields: {
      kind: 'prepare', state: HEAD_PREPARED,
      epochDec: '0', epochDigestHex: EPOCH_0,
      commitBytes: COMMIT, welcomeBytes: null, projection: PROJECTION, projectionDigestHex,
      candidateEpochDec: '1', candidateEpochDigestHex: EPOCH_1,
      verifiedLeafDigestHex: VERIFIED,
      artifactId: null, artifactBytes: null, artifactDigestHex: null,
      publishAttempts: 0, evidenceCount: 0, appliedCommitDigestHex: null,
    },
    headFields: {
      state: HEAD_PREPARED,
      epochDec: '0', epochDigestHex: EPOCH_0,
      pendingCommitDigestHex: digestHex(COMMIT), pendingWelcomeDigestHex: null,
      candidateEpochDec: '1', candidateEpochDigestHex: EPOCH_1,
      verifiedLeafDigestHex: VERIFIED,
      artifactId: null, artifactDigestHex: null,
      publishAttempts: 0, evidenceCount: 0, lastAppliedCommitDigestHex: null,
    },
  });
}

function stableNoopCas(expectedHead, snapshotBytes) {
  const projectionDigestHex = digestHex(canonicalProjectionBytes(PROJECTION));
  return {
    expectedHead,
    snapshotBytes,
    transitionFields: {
      kind: 'discard', state: HEAD_STABLE,
      epochDec: expectedHead.epochDec, epochDigestHex: expectedHead.epochDigestHex,
      commitBytes: COMMIT, welcomeBytes: null, projection: PROJECTION, projectionDigestHex,
      candidateEpochDec: PROJECTION.candidateEpochDec,
      candidateEpochDigestHex: PROJECTION.candidateGroupContextDigestHex,
      verifiedLeafDigestHex: PROJECTION.verifiedLeafDigestHex,
      artifactId: null, artifactBytes: null, artifactDigestHex: null,
      publishAttempts: 0, evidenceCount: 0, appliedCommitDigestHex: null,
    },
    headFields: {
      state: HEAD_STABLE, epochDec: expectedHead.epochDec,
      epochDigestHex: expectedHead.epochDigestHex,
      pendingCommitDigestHex: null, pendingWelcomeDigestHex: null,
      candidateEpochDec: null, candidateEpochDigestHex: null, verifiedLeafDigestHex: null,
      artifactId: null, artifactDigestHex: null, publishAttempts: 0, evidenceCount: 0,
      lastAppliedCommitDigestHex: expectedHead.lastAppliedCommitDigestHex,
    },
  };
}

describe('Phase B2.3 strict record', () => {
  test('head canonicalization binds sequence, transition and the exact runtime tuple', () => {
    const head = buildHead({
      groupIdHex: GROUP, accountKeyHex: ACCOUNT, signatureKeyHex: SIGNATURE,
      ...B23_RUNTIME,
      seq: 1, state: HEAD_STABLE, epochDec: '18446744073709551615', epochDigestHex: EPOCH_0,
      snapshotKeyHex: '66'.repeat(32), snapshotBytes: 42, transitionIdHex: '77'.repeat(32),
      priorHeadDigestHex: null, pendingCommitDigestHex: null, pendingWelcomeDigestHex: null,
      candidateEpochDec: null, candidateEpochDigestHex: null, verifiedLeafDigestHex: null,
      artifactId: null, artifactDigestHex: null, publishAttempts: 0, evidenceCount: 0,
      lastAppliedCommitDigestHex: null,
    });
    expect(parseHead(head)).toEqual(head);
    expect(() => parseHead({ ...head, seq: 2 })).toThrow(expect.objectContaining({ code: B23_ERROR.CORRUPT }));
    expect(() => parseHead({ ...head, epochDec: '01' })).toThrow(expect.objectContaining({ code: B23_ERROR.INVALID }));
    expect(() => parseHead({ ...head, extra: true })).toThrow(expect.objectContaining({ code: B23_ERROR.INVALID }));
    const missing = { ...head };
    delete missing.groupIdHex;
    expect(() => parseHead(missing)).toThrow(expect.objectContaining({ code: B23_ERROR.INVALID }));
    expect(() => parseHead({ ...head, openMlsRevision: '00'.repeat(20) }))
      .toThrow(expect.objectContaining({ code: B23_ERROR.INCOMPATIBLE }));
    expect(() => parseHead({ ...head, groupIdHex: GROUP.toUpperCase() }))
      .toThrow(expect.objectContaining({ code: B23_ERROR.INVALID }));
    expect(() => parseHead({ ...head, seq: Number.MAX_SAFE_INTEGER + 1 }))
      .toThrow(expect.objectContaining({ code: B23_ERROR.INVALID }));
    expect(() => parseHead({ ...head, snapshotBytes: B23_LIMITS.maxSnapshotBytes + 1 }))
      .toThrow(expect.objectContaining({ code: B23_ERROR.INVALID }));
    expect(() => parseHead({ ...head, state: HEAD_PREPARED }))
      .toThrow(expect.objectContaining({ code: B23_ERROR.INVALID }));
    expect(buildHead({ ...head }).headDigestHex).toBe(head.headDigestHex);
    expect(buildHead({ ...head, transitionIdHex: '99'.repeat(32) }).headDigestHex)
      .not.toBe(head.headDigestHex);
  });

  test('accessor fields fail before their getter can run', () => {
    const getter = jest.fn(() => GROUP);
    const hostile = {};
    for (const field of [
      'format', 'version', 'profile', 'groupIdHex', 'accountKeyHex', 'signatureKeyHex',
      'openMlsRevision', 'wasmArtifactSha256', 'ciphersuite', 'seq', 'state', 'epochDec',
      'epochDigestHex', 'snapshotKeyHex', 'snapshotBytes', 'transitionIdHex',
      'priorHeadDigestHex', 'pendingCommitDigestHex', 'pendingWelcomeDigestHex',
      'candidateEpochDec', 'candidateEpochDigestHex', 'verifiedLeafDigestHex', 'artifactId',
      'artifactDigestHex', 'publishAttempts', 'evidenceCount', 'lastAppliedCommitDigestHex',
      'headDigestHex',
    ]) {
      if (field !== 'groupIdHex') Object.defineProperty(hostile, field, { value: null, enumerable: true });
    }
    Object.defineProperty(hostile, 'groupIdHex', { get: getter, enumerable: true, configurable: true });
    expect(() => parseHead(hostile)).toThrow(expect.objectContaining({ code: B23_ERROR.INVALID }));
    expect(getter).not.toHaveBeenCalled();
  });

  test('projection accessors and toJSON hooks fail without executing', () => {
    const accessor = jest.fn(() => '0');
    const toJSON = jest.fn(() => ({ format: 'substituted' }));
    const withAccessor = { format: 'styx-b2-3-projection', version: 1, candidateEpochDec: '1' };
    Object.defineProperty(withAccessor, 'priorEpochDec', { get: accessor, enumerable: true });
    expect(() => canonicalProjectionBytes(withAccessor)).toThrow(
      expect.objectContaining({ code: B23_ERROR.INVALID }),
    );
    expect(accessor).not.toHaveBeenCalled();
    expect(() => canonicalProjectionBytes({ ...PROJECTION, toJSON })).toThrow(
      expect.objectContaining({ code: B23_ERROR.INVALID }),
    );
    expect(toJSON).not.toHaveBeenCalled();
  });

  test('Provider snapshots reject truncation, trailing bytes, duplicate keys and bounds before restore', () => {
    expect(validateProviderSnapshot(u64(0))).toEqual({ entryCount: 0, byteLength: 8 });
    expect(() => validateProviderSnapshot(Uint8Array.of(0))).toThrow(
      expect.objectContaining({ code: B23_ERROR.INVALID }),
    );
    expect(() => validateProviderSnapshot(concatBytes(u64(0), Uint8Array.of(0)))).toThrow(
      expect.objectContaining({ code: B23_ERROR.INVALID }),
    );
    expect(() => validateProviderSnapshot(duplicateProviderKeySnapshot())).toThrow(
      expect.objectContaining({ code: B23_ERROR.INVALID }),
    );
    expect(() => validateProviderSnapshot(concatBytes(u64(1), u64(0xffffffffffffffffn), u64(0))))
      .toThrow(expect.objectContaining({ code: B23_ERROR.RESOURCE_LIMIT }));
    expect(() => validateProviderSnapshot(new Uint8Array(B23_LIMITS.maxSnapshotBytes + 1)))
      .toThrow(expect.objectContaining({ code: B23_ERROR.INVALID }));
  });
});

describe('Phase B2.3 CAS journal', () => {
  test('initialization and read bind one exact snapshot and transition', async () => {
    const instance = await initialized();
    const bundle = await instance.value.read(GROUP);
    expect(bundle.head).toEqual(instance.head);
    expect(bundle.snapshotBytes).toEqual(instance.snapshotBytes);
    expect(bundle.transition.kind).toBe('initialize');
    expect(instance.db.record(B23_STORES.snapshot, instance.head.snapshotKeyHex)).toEqual(instance.snapshotBytes);
    expect(parseTransition(bundle.transition)).toEqual(bundle.transition);
    expect(() => parseTransition({ ...bundle.transition, unexpected: true }))
      .toThrow(expect.objectContaining({ code: B23_ERROR.INVALID }));
    expect(() => parseTransition({ ...bundle.transition, transitionDigestHex: '00'.repeat(32) }))
      .toThrow(expect.objectContaining({ code: B23_ERROR.CORRUPT }));
  });

  test('a stale actor cannot overwrite the winning successor', async () => {
    const instance = await initialized();
    const winner = await prepare(instance);
    await expect(prepare(instance)).rejects.toMatchObject({ code: B23_ERROR.CAS_CONFLICT });
    const durable = await instance.value.read(GROUP);
    expect(durable.head).toEqual(winner.head);
    expect(durable.head.seq).toBe(2);
    expect(durable.head.state).toBe(HEAD_PREPARED);
  });

  test('CAS rejects stale/fresh digest mixtures, replay and local ABA', async () => {
    const instance = await initialized();
    const alternate = buildHead({ ...instance.head, transitionIdHex: '88'.repeat(32) });
    await expect(instance.value.cas(stableNoopCas(alternate, instance.snapshotBytes)))
      .rejects.toMatchObject({ code: B23_ERROR.CAS_CONFLICT });
    await expect(instance.value.cas({
      expectedHead: { ...instance.head, seq: instance.head.seq + 1 },
      snapshotBytes: instance.snapshotBytes,
      transitionFields: {},
      headFields: {},
    })).rejects.toMatchObject({ code: B23_ERROR.CORRUPT });

    const successor = await instance.value.cas(stableNoopCas(instance.head, instance.snapshotBytes));
    expect(successor.head.snapshotKeyHex).toBe(instance.head.snapshotKeyHex);
    expect(successor.head.seq).toBe(instance.head.seq + 1);
    expect(successor.head.headDigestHex).not.toBe(instance.head.headDigestHex);
    await expect(prepare(instance)).rejects.toMatchObject({ code: B23_ERROR.CAS_CONFLICT });
  });

  test('an injected write crash rolls back snapshot, transition and head together', async () => {
    const instance = await initialized();
    const before = await instance.value.read(GROUP);
    instance.db.failOn = (namespace) => namespace === B23_STORES.head;
    await expect(prepare(instance)).rejects.toThrow('injected crash');
    instance.db.failOn = null;
    const after = await instance.value.read(GROUP);
    expect(after).toEqual(before);
    expect(await instance.db.list(B23_STORES.snapshot)).toEqual([before.head.snapshotKeyHex]);
    expect(await instance.db.list(B23_STORES.transition)).toEqual([before.head.transitionIdHex]);
  });

  test('a deterministic quota failure leaves every predecessor store intact', async () => {
    const instance = await initialized();
    const before = await instance.value.read(GROUP);
    const beforeKeys = Object.fromEntries(await Promise.all(B23_STORE_NAMES.map(async (name) => [
      name, await instance.db.list(name),
    ])));
    instance.db.failOn = () => {
      const error = new Error('deterministic quota failure');
      error.code = 'VAULT_QUOTA_EXCEEDED';
      throw error;
    };
    await expect(prepare(instance)).rejects.toMatchObject({ code: 'VAULT_QUOTA_EXCEEDED' });
    instance.db.failOn = null;
    expect(await instance.value.read(GROUP)).toEqual(before);
    for (const name of B23_STORE_NAMES) expect(await instance.db.list(name)).toEqual(beforeKeys[name]);
  });

  test('missing and orphan snapshots fail closed without repair', async () => {
    const missing = await initialized();
    await missing.db.transaction([B23_STORES.snapshot], (ops) => ops.delete(
      B23_STORES.snapshot, missing.head.snapshotKeyHex,
    ));
    await expect(missing.value.read(GROUP)).rejects.toMatchObject({ code: B23_ERROR.CORRUPT });
    expect(await missing.db.list(B23_STORES.snapshot)).toEqual([]);

    const orphan = await initialized();
    await orphan.db.transaction([B23_STORES.snapshot], (ops) => ops.put(
      B23_STORES.snapshot, '99'.repeat(32), Uint8Array.of(1),
    ));
    const before = await orphan.db.list(B23_STORES.snapshot);
    await expect(orphan.value.read(GROUP)).rejects.toMatchObject({ code: B23_ERROR.CORRUPT });
    expect(await orphan.db.list(B23_STORES.snapshot)).toEqual(before);
  });

  test('publication retries accept only the exact frozen artifact', async () => {
    const instance = await initialized();
    const prepared = await prepare(instance);
    const artifact = { id: 'opaque:test:1', bytes: Uint8Array.of(7, 7, 7) };
    const first = await instance.value.recordPublishIntent(GROUP, artifact);
    expect(first.head.publishAttempts).toBe(1);
    const second = await instance.value.recordPublishIntent(GROUP, artifact);
    expect(second.head.publishAttempts).toBe(2);
    await expect(instance.value.recordPublishIntent(GROUP, {
      id: artifact.id, bytes: Uint8Array.of(7, 7, 8),
    })).rejects.toMatchObject({ code: B23_ERROR.STATE_CONFLICT });
    const durable = await instance.value.read(GROUP);
    expect(durable.head).toEqual(second.head);
    expect(durable.head.pendingCommitDigestHex).toBe(prepared.head.pendingCommitDigestHex);
  });

  test('a failed publication-intent CAS preserves the discardable prepared head', async () => {
    const instance = await initialized();
    const prepared = await prepare(instance);
    instance.db.failOn = (namespace) => namespace === B23_STORES.head;
    await expect(instance.value.recordPublishIntent(GROUP, {
      id: 'opaque:failure:1', bytes: Uint8Array.of(7),
    })).rejects.toThrow('injected crash');
    instance.db.failOn = null;
    const recovered = await instance.value.read(GROUP);
    expect(recovered.head).toEqual(prepared.head);
    expect(recovered.head.publishAttempts).toBe(0);
    expect(recovered.transition.artifactBytes).toBeNull();
  });

  test('opaque evidence is content-bound and bounded by the CAS head', async () => {
    const instance = await initialized();
    await prepare(instance);
    await instance.value.recordPublishIntent(GROUP, {
      id: 'opaque:test:2', bytes: Uint8Array.of(4, 5, 6),
    });
    const appended = await instance.value.appendPublicationEvidence(GROUP, Uint8Array.of(8, 9));
    expect(appended.head.evidenceCount).toBe(1);
    expect(appended.evidence).toHaveLength(1);
    const evidence = await instance.db.get(B23_STORES.evidence, appended.evidence[0].idHex);
    expect(evidence.payload).toEqual(Uint8Array.of(8, 9));
    expect(evidence.artifactDigestHex).toBe(appended.head.artifactDigestHex);
  });

  test('historical evidence may exceed the per-prepared cap without corrupting the head', async () => {
    const instance = await initialized();
    let current = instance.head;
    let evidenceRecords = 0;
    for (let cycle = 0; cycle < 9; cycle += 1) {
      instance.head = current;
      const prepared = await prepare(instance);
      await instance.value.recordPublishIntent(GROUP, {
        id: `opaque:history:${cycle}`, bytes: Uint8Array.of(cycle + 1),
      });
      const inCycle = cycle === 8 ? 1 : 8;
      let attempted = await instance.value.read(GROUP);
      for (let index = 0; index < inCycle; index += 1) {
        const appended = await instance.value.appendPublicationEvidence(
          GROUP, Uint8Array.of(cycle, index),
        );
        attempted = { head: appended.head, snapshotBytes: appended.snapshotBytes };
        evidenceRecords += 1;
      }
      const stable = await instance.value.cas(stableNoopCas(
        attempted.head, attempted.snapshotBytes,
      ));
      current = stable.head;
    }
    expect(evidenceRecords).toBe(B23_LIMITS.maxEvidence + 1);
    expect(await instance.db.list(B23_STORES.evidence)).toHaveLength(evidenceRecords);
    await expect(instance.value.read(GROUP)).resolves.toMatchObject({ head: current });
  });
});

const HERE = dirname(fileURLToPath(import.meta.url));
const VENDOR = join(HERE, '../../vendor/openmls-wasm');

let wasmPromise;
let wasmInitOutput;
async function loadWasm() {
  if (!wasmPromise) {
    wasmPromise = (async () => {
      const moduleUrl = pathToFileURL(join(VENDOR, 'openmls_wasm.js'));
      moduleUrl.searchParams.set('b2-3-journal-test', '1');
      const wasm = await import(moduleUrl.href);
      wasmInitOutput = await wasm.default({ module_or_path: readFileSync(join(VENDOR, 'openmls_wasm_bg.wasm')) });
      return wasm;
    })();
  }
  return wasmPromise;
}

function free(value) {
  try { value?.free?.(); } catch { /* test cleanup */ }
}

function createPeer(wasm, provider) {
  const privateKey = Uint8Array.from(schnorr.utils.randomPrivateKey());
  const publicKey = Uint8Array.from(schnorr.getPublicKey(privateKey));
  const identity = new wasm.PhaseB2Identity(provider, publicKey);
  const signatureKey = identity.leaf_signature_key();
  const proof = createAccountIdentityProofV2(privateKey, signatureKey, 1_786_435_200);
  const generated = identity.key_package(provider, proof);
  const framed = generated.to_framed_bytes();
  free(generated);
  const keyPackage = wasm.PhaseB2KeyPackage.from_framed_bytes(framed);
  return { privateKey, publicKey, identity, signatureKey, proof, keyPackage };
}

function setupStablePair(wasm) {
  const aliceProvider = new wasm.Provider();
  const bobProvider = new wasm.Provider();
  const alice = createPeer(wasm, aliceProvider);
  const bob = createPeer(wasm, bobProvider);
  const groupId = crypto.getRandomValues(new Uint8Array(32));
  const aliceGroup = wasm.PhaseB2Group.create_new(
    aliceProvider, alice.identity, groupId, alice.proof,
  );
  const pending = aliceGroup.prepare_add(aliceProvider, alice.identity, bob.keyPackage);
  const projection = pending.projection();
  aliceGroup.confirm_pending(aliceProvider, pending, projection.verified_leaf_digest());
  const tree = aliceGroup.export_ratchet_tree();
  const parsedTree = wasm.PhaseB2RatchetTree.from_bytes(tree.to_bytes());
  const bobGroup = wasm.PhaseB2Group.join(bobProvider, pending.welcome(), parsedTree);
  free(parsedTree);
  free(tree);
  free(projection);
  free(pending);
  return { aliceProvider, bobProvider, alice, bob, aliceGroup, bobGroup, groupId };
}

function assertLiveness(left, right) {
  const plaintext = new TextEncoder().encode('b2-3-liveness');
  const message = left.group.create_application_message(left.provider, left.identity, plaintext);
  expect(right.group.process_application_message(right.provider, message)).toEqual(plaintext);
}

describe('Phase B2.3 disposable OpenMLS composition', () => {
  test('outbound confirm, inbound re-stage, duplicate suppression and pre-attempt discard converge', async () => {
    const wasm = await loadWasm();
    const pair = setupStablePair(wasm);
    const initialAliceSnapshot = pair.aliceProvider.serialize_state();
    const instance = journal();
    const adapter = new B23EngineAdapter({ wasm, journal: instance.value });
    const groupIdHex = bytesToHex(pair.groupId);
    try {
      await adapter.initializeStable({
        snapshotBytes: initialAliceSnapshot,
        groupId: pair.groupId,
        accountKey: pair.alice.publicKey,
        signatureKey: pair.alice.signatureKey,
      });
      free(pair.aliceGroup);
      free(pair.alice.identity);
      free(pair.aliceProvider);
      pair.aliceGroup = null;
      pair.alice.identity = null;
      pair.aliceProvider = null;

      const beforeFailedPrepare = await instance.value.read(groupIdHex);
      instance.db.failOn = (namespace) => namespace === B23_STORES.head;
      await expect(adapter.prepare(groupIdHex, { kind: 'self-update' }))
        .rejects.toMatchObject({ code: B23_ERROR.ENGINE_REJECTED });
      instance.db.failOn = null;
      expect(await instance.value.read(groupIdHex)).toEqual(beforeFailedPrepare);

      const outbound = await adapter.prepare(groupIdHex, { kind: 'self-update' });
      const sameMemberProvider = new wasm.Provider();
      sameMemberProvider.restore_state(initialAliceSnapshot);
      const sameMemberGroup = wasm.PhaseB2Group.load(sameMemberProvider, pair.groupId);
      expect(() => sameMemberGroup.stage_inbound_commit(sameMemberProvider, outbound.commitBytes)).toThrow();
      free(sameMemberGroup);
      free(sameMemberProvider);

      const beforeFailedIntent = await instance.value.read(groupIdHex);
      instance.db.failOn = (namespace) => namespace === B23_STORES.head;
      await expect(instance.value.recordPublishIntent(groupIdHex, {
        id: 'opaque:self-update:1', bytes: outbound.commitBytes,
      })).rejects.toThrow('injected crash');
      instance.db.failOn = null;
      expect(await instance.value.read(groupIdHex)).toEqual(beforeFailedIntent);

      await instance.value.recordPublishIntent(groupIdHex, {
        id: 'opaque:self-update:1', bytes: outbound.commitBytes,
      });
      await expect(adapter.cancelBeforeAttempt(groupIdHex)).rejects.toMatchObject({
        code: B23_ERROR.STATE_CONFLICT,
      });
      const bobStaged = pair.bobGroup.stage_inbound_commit(pair.bobProvider, outbound.commitBytes);
      pair.bobGroup.merge_staged_commit(
        pair.bobProvider,
        bobStaged,
        hexToBytes('verifiedLeafDigestHex', outbound.projection.verifiedLeafDigestHex),
      );
      free(bobStaged);
      const beforeFailedConfirm = await instance.value.read(groupIdHex);
      instance.db.failOn = (namespace) => namespace === B23_STORES.head;
      await expect(adapter.confirmAfterAttempt(groupIdHex))
        .rejects.toMatchObject({ code: B23_ERROR.ENGINE_REJECTED });
      instance.db.failOn = null;
      expect(await instance.value.read(groupIdHex)).toEqual(beforeFailedConfirm);
      expect((await adapter.recoveryState(groupIdHex)).action).toBe('confirm-and-retry-exact-artifact');
      const confirmed = await adapter.confirmAfterAttempt(groupIdHex);
      expect(confirmed.head.epochDec).toBe('2');
      expect(confirmed.transition.commitBytes).toEqual(outbound.commitBytes);
      expect(confirmed.transition.artifactBytes).toEqual(outbound.commitBytes);
      expect((await adapter.recoveryState(groupIdHex)).action).toBe('resume-stable');

      const bobPending = pair.bobGroup.prepare_self_update(pair.bobProvider, pair.bob.identity);
      const bobProjection = bobPending.projection();
      const bobCommit = bobPending.commit();
      const beforeReject = await instance.value.read(groupIdHex);
      const rejected = await adapter.acceptInbound(groupIdHex, bobCommit, false);
      expect(rejected.status).toBe('rejected');
      expect(await instance.value.read(groupIdHex)).toEqual(beforeReject);

      instance.db.failOn = (namespace) => namespace === B23_STORES.head;
      await expect(adapter.acceptInbound(groupIdHex, bobCommit, true)).rejects.toThrow();
      instance.db.failOn = null;
      expect(await instance.value.read(groupIdHex)).toEqual(beforeReject);
      const accepted = await adapter.acceptInbound(groupIdHex, bobCommit, () => true);
      expect(accepted.status).toBe('accepted');
      expect(accepted.head.epochDec).toBe('3');
      expect(canonicalProjectionBytes(accepted.projection))
        .toEqual(canonicalProjectionBytes(rejected.projection));
      pair.bobGroup.confirm_pending(
        pair.bobProvider, bobPending, bobProjection.verified_leaf_digest(),
      );
      const liveWasm = adapter.wasm;
      adapter.wasm = Object.freeze({
        get Provider() { throw new Error('duplicate path invoked OpenMLS'); },
      });
      let duplicate;
      try {
        duplicate = await adapter.acceptInbound(groupIdHex, bobCommit, true);
      } finally {
        adapter.wasm = liveWasm;
      }
      expect(duplicate.status).toBe('duplicate');
      expect(duplicate.head.seq).toBe(accepted.head.seq);

      const beforeCancel = await instance.value.read(groupIdHex);
      await adapter.prepare(groupIdHex, { kind: 'self-update' });
      const beforeFailedCancel = await instance.value.read(groupIdHex);
      instance.db.failOn = (namespace) => namespace === B23_STORES.head;
      await expect(adapter.cancelBeforeAttempt(groupIdHex))
        .rejects.toMatchObject({ code: B23_ERROR.ENGINE_REJECTED });
      instance.db.failOn = null;
      expect(await instance.value.read(groupIdHex)).toEqual(beforeFailedCancel);
      const cancelled = await adapter.cancelBeforeAttempt(groupIdHex);
      expect(cancelled.head.state).toBe(HEAD_STABLE);
      expect(cancelled.head.epochDec).toBe(beforeCancel.head.epochDec);
      expect(cancelled.head.seq).toBe(beforeCancel.head.seq + 2);

      const aliceBundle = await instance.value.read(groupIdHex);
      const aliceProvider = new wasm.Provider();
      aliceProvider.restore_state(aliceBundle.snapshotBytes);
      const aliceIdentity = wasm.PhaseB2Identity.load(
        aliceProvider, pair.alice.publicKey, pair.alice.signatureKey,
      );
      const aliceGroup = wasm.PhaseB2Group.load(aliceProvider, pair.groupId);
      assertLiveness(
        { provider: aliceProvider, identity: aliceIdentity, group: aliceGroup },
        { provider: pair.bobProvider, identity: pair.bob.identity, group: pair.bobGroup },
      );
      assertLiveness(
        { provider: pair.bobProvider, identity: pair.bob.identity, group: pair.bobGroup },
        { provider: aliceProvider, identity: aliceIdentity, group: aliceGroup },
      );
      free(aliceGroup);
      free(aliceIdentity);
      free(aliceProvider);
      free(bobProjection);
      free(bobPending);
    } finally {
      free(pair.aliceGroup);
      free(pair.alice.identity);
      free(pair.alice.keyPackage);
      free(pair.aliceProvider);
      free(pair.bobGroup);
      free(pair.bob.identity);
      free(pair.bob.keyPackage);
      free(pair.bobProvider);
    }
  }, 30_000);

  test('malformed or foreign Provider snapshots never create a journal head', async () => {
    const wasm = await loadWasm();
    const pair = setupStablePair(wasm);
    const valid = pair.aliceProvider.serialize_state();
    const cases = [
      { label: 'truncated', snapshot: valid.slice(0, valid.length - 1), expected: B23_ERROR.INVALID },
      { label: 'trailing', snapshot: concatBytes(valid, Uint8Array.of(0)), expected: B23_ERROR.INVALID },
      { label: 'duplicate-key', snapshot: duplicateProviderKeySnapshot(), expected: B23_ERROR.INVALID },
    ];
    try {
      for (const item of cases) {
        const instance = journal();
        const adapter = new B23EngineAdapter({ wasm, journal: instance.value });
        let failure;
        try {
          await adapter.initializeStable({
            snapshotBytes: item.snapshot,
            groupId: pair.groupId,
            accountKey: pair.alice.publicKey,
            signatureKey: pair.alice.signatureKey,
          });
        } catch (error) { failure = error; }
        expect(failure).toMatchObject({ code: item.expected });
        expect(await instance.db.list(B23_STORES.head)).toEqual([]);
      }

      for (const overrides of [
        { groupId: Uint8Array.of(9) },
        { accountKey: Uint8Array.from(pair.alice.publicKey, (byte, index) => byte ^ (index === 0 ? 1 : 0)) },
        { signatureKey: Uint8Array.from(pair.alice.signatureKey, (byte, index) => byte ^ (index === 0 ? 1 : 0)) },
      ]) {
        const instance = journal();
        const adapter = new B23EngineAdapter({ wasm, journal: instance.value });
        await expect(adapter.initializeStable({
          snapshotBytes: valid,
          groupId: pair.groupId,
          accountKey: pair.alice.publicKey,
          signatureKey: pair.alice.signatureKey,
          ...overrides,
        })).rejects.toMatchObject({ code: B23_ERROR.ENGINE_REJECTED });
        expect(await instance.db.list(B23_STORES.head)).toEqual([]);
      }

      const wrongEpoch = journal();
      const wrongHead = await wrongEpoch.value.initialize({
        bindings: {
          groupIdHex: bytesToHex(pair.groupId), accountKeyHex: bytesToHex(pair.alice.publicKey),
          signatureKeyHex: bytesToHex(pair.alice.signatureKey),
        },
        snapshotBytes: valid, epochDec: '0', epochDigestHex: '00'.repeat(32),
      });
      const wrongAdapter = new B23EngineAdapter({ wasm, journal: wrongEpoch.value });
      await expect(wrongAdapter.prepare(wrongHead.groupIdHex, { kind: 'self-update' }))
        .rejects.toMatchObject({ code: B23_ERROR.ENGINE_REJECTED });
      expect((await wrongEpoch.value.read(wrongHead.groupIdHex)).head).toEqual(wrongHead);
    } finally {
      free(pair.aliceGroup); free(pair.alice.identity); free(pair.alice.keyPackage); free(pair.aliceProvider);
      free(pair.bobGroup); free(pair.bob.identity); free(pair.bob.keyPackage); free(pair.bobProvider);
    }
  }, 30_000);

  test('concurrent local prepare and inbound accept elect one canonical successor', async () => {
    const wasm = await loadWasm();
    const pair = setupStablePair(wasm);
    const sharedDb = new SerializedFakeVaultDb();
    const instance = journal(sharedDb, 1);
    const competing = journal(sharedDb, 128);
    const adapter = new B23EngineAdapter({ wasm, journal: instance.value });
    const competingAdapter = new B23EngineAdapter({ wasm, journal: competing.value });
    const groupIdHex = bytesToHex(pair.groupId);
    const bobPending = pair.bobGroup.prepare_self_update(pair.bobProvider, pair.bob.identity);
    const bobProjection = bobPending.projection();
    const bobCommit = bobPending.commit();
    try {
      await adapter.initializeStable({
        snapshotBytes: pair.aliceProvider.serialize_state(), groupId: pair.groupId,
        accountKey: pair.alice.publicKey, signatureKey: pair.alice.signatureKey,
      });
      const outcomes = await Promise.allSettled([
        adapter.prepare(groupIdHex, { kind: 'self-update' }),
        competingAdapter.acceptInbound(groupIdHex, bobCommit, true),
      ]);
      expect(outcomes.filter((outcome) => outcome.status === 'fulfilled')).toHaveLength(1);
      expect(outcomes.filter((outcome) => outcome.status === 'rejected')[0].reason)
        .toMatchObject({ code: B23_ERROR.CAS_CONFLICT });
      const durable = await instance.value.read(groupIdHex);
      expect(durable.head.seq).toBe(2);

      if (outcomes[1].status === 'fulfilled') {
        pair.bobGroup.confirm_pending(pair.bobProvider, bobPending, bobProjection.verified_leaf_digest());
        expect(durable.head.state).toBe(HEAD_STABLE);
      } else {
        expect(durable.head.state).toBe(HEAD_PREPARED);
      }
      const aliceProvider = new wasm.Provider();
      aliceProvider.restore_state(durable.snapshotBytes);
      const aliceIdentity = wasm.PhaseB2Identity.load(
        aliceProvider, pair.alice.publicKey, pair.alice.signatureKey,
      );
      const aliceGroup = wasm.PhaseB2Group.load(aliceProvider, pair.groupId);
      assertLiveness(
        { provider: aliceProvider, identity: aliceIdentity, group: aliceGroup },
        { provider: pair.bobProvider, identity: pair.bob.identity, group: pair.bobGroup },
      );
      assertLiveness(
        { provider: pair.bobProvider, identity: pair.bob.identity, group: pair.bobGroup },
        { provider: aliceProvider, identity: aliceIdentity, group: aliceGroup },
      );
      free(aliceGroup); free(aliceIdentity); free(aliceProvider);
    } finally {
      free(bobProjection); free(bobPending);
      free(pair.aliceGroup); free(pair.alice.identity); free(pair.alice.keyPackage); free(pair.aliceProvider);
      free(pair.bobGroup); free(pair.bob.identity); free(pair.bob.keyPackage); free(pair.bobProvider);
    }
  }, 30_000);

  test('the 16-member PoC cap remains inside the snapshot bound and records WASM peak', async () => {
    const wasm = await loadWasm();
    const provider = new wasm.Provider();
    const founder = createPeer(wasm, provider);
    const groupId = crypto.getRandomValues(new Uint8Array(32));
    const group = wasm.PhaseB2Group.create_new(provider, founder.identity, groupId, founder.proof);
    let maxSnapshotBytes = provider.serialize_state().length;
    const memoryBefore = wasmInitOutput.memory.buffer.byteLength;
    try {
      for (let member = 1; member < B23_LIMITS.maxMembers; member += 1) {
        const peerProvider = new wasm.Provider();
        const peer = createPeer(wasm, peerProvider);
        const pending = group.prepare_add(provider, founder.identity, peer.keyPackage);
        const projection = pending.projection();
        group.confirm_pending(provider, pending, projection.verified_leaf_digest());
        maxSnapshotBytes = Math.max(maxSnapshotBytes, provider.serialize_state().length);
        free(projection); free(pending); free(peer.keyPackage); free(peer.identity); free(peerProvider);
      }
      const memoryPeak = wasmInitOutput.memory.buffer.byteLength;
      expect(maxSnapshotBytes).toBeLessThanOrEqual(B23_LIMITS.maxSnapshotBytes);
      expect(group.member_count()).toBe(B23_LIMITS.maxMembers);
      console.log(`B23_CAP_MEASUREMENT members=${B23_LIMITS.maxMembers} max_snapshot_bytes=${maxSnapshotBytes} wasm_before_bytes=${memoryBefore} wasm_peak_bytes=${memoryPeak}`);
    } finally {
      free(group); free(founder.keyPackage); free(founder.identity); free(provider);
    }
  }, 30_000);
});

// The shared FakeVaultDb throws writes synchronously. This deterministic IDB
// double instead drives the real VaultDb request-rejection and abort mapping.
function makeRejectingIdb(storeNames, shouldFail) {
  const stores = new Map(storeNames.map((name) => [name, new Map()]));
  class Transaction {
    constructor(names) {
      this.oncomplete = null;
      this.onabort = null;
      this.onerror = null;
      this.error = null;
      this.pending = 0;
      this.done = false;
      this.started = false;
      this.staged = new Map(names.map((name) => [name, new Map(stores.get(name))]));
      queueMicrotask(() => { this.started = true; this.settle(); });
    }

    objectStore(name) {
      const staged = this.staged.get(name);
      const request = (operation, kind) => {
        const result = { onsuccess: null, onerror: null, result: undefined, error: null };
        this.pending += 1;
        queueMicrotask(() => {
          try {
            const failure = shouldFail(name, kind);
            if (failure) throw failure;
            result.result = operation();
            result.onsuccess?.();
          } catch (error) {
            result.error = error;
            result.onerror?.();
            this.abortWith(error);
          } finally {
            this.pending -= 1;
            this.settle();
          }
        });
        return result;
      };
      return {
        get: (key) => request(() => staged.get(key), 'read'),
        put: (value, key) => request(() => { staged.set(key, value); }, 'write'),
        delete: (key) => request(() => { staged.delete(key); }, 'write'),
        getAllKeys: () => request(() => [...staged.keys()], 'read'),
        clear: () => request(() => staged.clear(), 'write'),
      };
    }

    abortWith(error) {
      if (this.done) return;
      this.error = error;
      this.done = true;
      queueMicrotask(() => this.onabort?.());
    }

    abort() { this.abortWith(this.error ?? { name: 'AbortError' }); }

    settle() {
      if (this.done || !this.started || this.pending > 0) return;
      queueMicrotask(() => {
        if (this.done || this.pending > 0) return;
        this.done = true;
        for (const [name, records] of this.staged) stores.set(name, records);
        this.oncomplete?.();
      });
    }
  }
  return {
    stores,
    name: 'b2-3-request-failure',
    version: 1,
    objectStoreNames: storeNames,
    transaction: (names) => new Transaction(Array.isArray(names) ? names : [names]),
    close() {},
  };
}

test('a request-level write rejection rolls every store back and is never unhandled', async () => {
  const seen = [];
  const capture = (reason) => seen.push(reason?.name ?? String(reason));
  process.on('unhandledRejection', capture);
  try {
    const idb = makeRejectingIdb(B23_STORE_NAMES, (name, kind) => (
      name === B23_STORES.head && kind === 'write'
        ? Object.assign(new Error('quota'), { name: 'QuotaExceededError' })
        : null));
    const db = new VaultDb(idb, {});
    const value = createB23JournalForDb(db, { randomBytes: deterministicRandom(1) });
    await expect(value.initialize({
      bindings: { groupIdHex: GROUP, accountKeyHex: ACCOUNT, signatureKeyHex: SIGNATURE },
      snapshotBytes: Uint8Array.of(9, 8, 7), epochDec: '0', epochDigestHex: EPOCH_0,
    })).rejects.toMatchObject({ code: 'VAULT_QUOTA_EXCEEDED' });
    for (const name of B23_STORE_NAMES) expect([...idb.stores.get(name).keys()]).toEqual([]);
    await new Promise((resolve) => { setTimeout(resolve, 20); });
    expect(seen).toEqual([]);
  } finally {
    process.off('unhandledRejection', capture);
  }
});
