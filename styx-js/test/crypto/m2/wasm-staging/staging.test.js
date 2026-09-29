// SPDX-License-Identifier: AGPL-3.0-or-later

import { beforeAll, describe, expect, test } from '@jest/globals';
import { schnorr } from '@noble/curves/secp256k1';
import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '../../../../..');
const STYX_JS = resolve(REPO, 'styx-js');
const VENDOR = resolve(STYX_JS, 'vendor/openmls-wasm');
const WASM_PATH = resolve(VENDOR, 'openmls_wasm_bg.wasm');
const BASE = 'e1538ef9c070e463a8256872a3fd0882c424e2ef';
const WASM_SHA256 = 'fef05368f143de044274f8804d2ba195a1f886bc528651e98bd9c393fde4650e';
const ARTIFACT_TUPLE = Object.freeze({
  'openmls_wasm.js': '3de8fd46e4897aae117ee7b10ac41dffd02b507952c4024b0fe69d89fbb0c973',
  'openmls_wasm.d.ts': '057974ec53e3588da3dbf159f183b3e3ddb4a3b0a57d5391194f124a483ede86',
  'openmls_wasm_bg.wasm': WASM_SHA256,
  'openmls_wasm_bg.wasm.d.ts': 'c21ace2360b264437541025e4703bcb38b53010793829d1904cb85b3d2aa238a',
  'package.json': '88f2ec1e2a5c1904b0fc1d147221c32ba6dcbf1cb4441c53b04a1b2a03bd1d85',
});
const OPENMLS_REVISION = '09e92777dba0528d3d29e2e5e681b7e91637c7be';
const ALLOWED_PREFIX = 'styx-js/test/crypto/m2/wasm-staging/';
const PROBE_PATH = `${ALLOWED_PREFIX}staging.test.js`;
const UTF8 = new TextEncoder();

let wasm;
let runtimeEvidence;

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function verifyArtifactTuple(read = (name) => readFileSync(resolve(VENDOR, name))) {
  const actualTuple = {};
  for (const [name, expected] of Object.entries(ARTIFACT_TUPLE)) {
    const actual = sha256(read(name));
    if (actual !== expected) throw new Error(`frozen artifact tuple mismatch: ${name}`);
    actualTuple[name] = actual;
  }
  return Object.freeze(actualTuple);
}

function digestBytes(bytes) {
  return Uint8Array.from(Buffer.from(sha256(bytes), 'hex'));
}

function git(...args) {
  return execFileSync('git', args, { cwd: REPO, encoding: 'utf8' }).trim();
}

function free(...values) {
  for (const value of values) {
    try { value?.free?.(); } catch { /* test cleanup */ }
  }
}

function copy(bytes) {
  return Uint8Array.from(bytes);
}

function secret(seed) {
  const value = new Uint8Array(32);
  value[31] = seed;
  return value;
}

function groupId(seed) {
  return Uint8Array.from({ length: 32 }, (_, index) => (seed + index) & 0xff);
}

function accountProof(privateKey, leafSignatureKey, createdAt) {
  const publicKey = Uint8Array.from(schnorr.getPublicKey(privateKey));
  const event = [0, Buffer.from(publicKey).toString('hex'), createdAt, 450, [
    ['d', 'marmot.account-identity-proof.v2'],
    ['component', '0x8009'],
    ['ciphersuite', '0x0001'],
    ['signature_scheme', '0x0807'],
    ['mls_signature_key', Buffer.from(leafSignatureKey).toString('hex')],
  ], 'Authorize this MLS leaf key for my Marmot account'];
  const signature = Uint8Array.from(schnorr.sign(
    digestBytes(UTF8.encode(JSON.stringify(event))),
    privateKey,
  ));
  const proof = new Uint8Array(104);
  proof.set(publicKey, 0);
  new DataView(proof.buffer).setBigUint64(32, BigInt(createdAt));
  proof.set(signature, 40);
  return proof;
}

function createPeer(provider, seed) {
  const privateKey = secret(seed);
  const accountKey = Uint8Array.from(schnorr.getPublicKey(privateKey));
  const identity = new wasm.PhaseB2Identity(provider, accountKey);
  const signatureKey = copy(identity.leaf_signature_key());
  const proof = accountProof(privateKey, signatureKey, 1_800_000_000 + seed);
  const generated = identity.key_package(provider, proof);
  const keyPackageBytes = copy(generated.to_framed_bytes());
  const keyPackage = wasm.PhaseB2KeyPackage.from_framed_bytes(keyPackageBytes);
  free(generated);
  return { accountKey, identity, keyPackage, keyPackageBytes, privateKey, proof, signatureKey };
}

function restore(state, peer, id) {
  const provider = new wasm.Provider();
  provider.restore_state(state);
  const identity = wasm.PhaseB2Identity.load(provider, peer.accountKey, peer.signatureKey);
  const group = wasm.PhaseB2Group.load(provider, id);
  if (!identity) throw new Error('identity restore failed');
  return { group, identity, provider };
}

function assertLoadable(state, peer, id, expectedEpoch) {
  const restored = restore(state, peer, id);
  try {
    expect(restored.group).toBeDefined();
    expect(restored.group.epoch()).toBe(expectedEpoch);
  } finally {
    free(restored.group, restored.identity, restored.provider);
  }
}

class AuthoritySlot {
  constructor(authoritativeBytes) {
    this.authoritativeBytes = copy(authoritativeBytes);
    this.pending = new Map();
  }

  stage(operationId, candidateBytes) {
    if (this.pending.has(operationId)) throw new Error('duplicate operation identity');
    const candidate = copy(candidateBytes);
    this.pending.set(operationId, Object.freeze({
      bytes: candidate,
      digest: sha256(candidate),
      parentDigest: sha256(this.authoritativeBytes),
      state: 'STAGED',
    }));
    return this.pending.get(operationId).digest;
  }

  resolve(operationId, result) {
    const record = this.pending.get(operationId);
    if (!record) throw new Error('unknown operation identity');
    if (record.state === 'INDETERMINATE') {
      throw new Error('indeterminate requires durable reconciliation');
    }
    if (!['COMMITTED', 'NOT_COMMITTED', 'INDETERMINATE'].includes(result)) {
      throw new Error('unknown commit result');
    }
    if (result === 'COMMITTED') {
      if (sha256(this.authoritativeBytes) !== record.parentDigest) {
        throw new Error('candidate parent is no longer authoritative');
      }
      this.authoritativeBytes = copy(record.bytes);
      this.pending.delete(operationId);
    } else if (result === 'NOT_COMMITTED') {
      this.pending.delete(operationId);
    } else {
      this.pending.set(operationId, Object.freeze({ ...record, state: result }));
    }
  }

  reconcile(persistedReceipt) {
    if (!persistedReceipt || persistedReceipt.outcome !== 'COMMITTED') {
      throw new Error('persisted outcome is not COMMITTED');
    }
    const record = this.pending.get(persistedReceipt.operationId);
    if (!record || record.state !== 'INDETERMINATE') throw new Error('not indeterminate');
    if (persistedReceipt.candidateSha256 !== record.digest) {
      throw new Error('persisted identity mismatch');
    }
    if (sha256(this.authoritativeBytes) !== record.parentDigest) {
      throw new Error('candidate parent is no longer authoritative');
    }
    this.authoritativeBytes = copy(record.bytes);
    this.pending.delete(persistedReceipt.operationId);
  }
}

function preflight() {
  const artifactTuple = verifyArtifactTuple();
  const artifact = readFileSync(WASM_PATH);
  const provenance = readFileSync(resolve(VENDOR, 'PROVENANCE.md'), 'utf8');
  if (!provenance.includes(OPENMLS_REVISION)
    || !provenance.includes('MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519')
    || !provenance.includes(`openmls_wasm_bg.wasm\` | \`${WASM_SHA256}`)) {
    throw new Error('frozen OpenMLS/SS-0 tuple provenance mismatch');
  }
  const ancestor = spawnSync('git', ['merge-base', '--is-ancestor', BASE, 'HEAD'], { cwd: REPO });
  if (ancestor.status !== 0) throw new Error(`${BASE} is not an ancestor of HEAD`);
  const vendorDiff = spawnSync('git', ['diff', '--quiet', `${BASE}..HEAD`, '--',
    'styx-js/vendor/openmls-wasm'], { cwd: REPO });
  if (vendorDiff.status !== 0) throw new Error('frozen OpenMLS/WASM tuple changed');
  const cardCommit = git('log', '-1', '--format=%H', '--diff-filter=A', '--', PROBE_PATH);
  if (!cardCommit) throw new Error('F-WASM card commit not found');
  const cardAncestor = spawnSync('git', ['merge-base', '--is-ancestor', cardCommit, 'HEAD'], {
    cwd: REPO,
  });
  if (cardAncestor.status !== 0) throw new Error('F-WASM card commit is not an ancestor of HEAD');
  const cardParent = git('rev-parse', `${cardCommit}^`);
  if (cardParent !== BASE) throw new Error('F-WASM card commit parent is not the exact base');
  const changedPaths = git('diff', '--no-renames', '--name-only', `${cardParent}..${cardCommit}`)
    .split('\n').filter(Boolean);
  if (changedPaths.length === 0 || changedPaths.some((path) => !path.startsWith(ALLOWED_PREFIX))) {
    throw new Error(`card diff escaped allowlist: ${JSON.stringify(changedPaths)}`);
  }
  if (git('status', '--porcelain=v1', '--untracked-files=no')) {
    throw new Error('tracked working tree is dirty');
  }
  const packageJson = JSON.parse(readFileSync(resolve(STYX_JS, 'package.json'), 'utf8'));
  return Object.freeze({
    artifactSha256: WASM_SHA256,
    artifactTuple,
    base: BASE,
    cardCommit,
    changedPaths,
    command: 'npm test -- --runInBand test/crypto/m2/wasm-staging/staging.test.js',
    head: git('rev-parse', 'HEAD'),
    jest: packageJson.devDependencies.jest,
    node: process.version,
    npm: execFileSync('npm', ['--version'], { encoding: 'utf8' }).trim(),
    openMlsRevision: OPENMLS_REVISION,
    ss0Ciphersuite: 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 (0x0001)',
  });
}

function setupPair(seed = 10) {
  const id = groupId(seed);
  const aliceProvider = new wasm.Provider();
  const bobProvider = new wasm.Provider();
  const alice = createPeer(aliceProvider, seed);
  const bob = createPeer(bobProvider, seed + 1);
  const aliceGroup = wasm.PhaseB2Group.create_new(
    aliceProvider, alice.identity, id, alice.proof,
  );
  const pending = aliceGroup.prepare_add(aliceProvider, alice.identity, bob.keyPackage);
  const welcome = copy(pending.welcome());
  const commit = copy(pending.commit());
  const projection = pending.projection();
  aliceGroup.confirm_pending(aliceProvider, pending, projection.verified_leaf_digest());
  const tree = aliceGroup.export_ratchet_tree();
  const treeBytes = copy(tree.to_bytes());
  const bobPreJoin = copy(bobProvider.serialize_state());
  const parsedTree = wasm.PhaseB2RatchetTree.from_bytes(treeBytes);
  const bobGroup = wasm.PhaseB2Group.join(bobProvider, welcome, parsedTree);
  const aliceState = copy(aliceProvider.serialize_state());
  const bobState = copy(bobProvider.serialize_state());
  free(parsedTree, tree, projection, pending);
  return {
    alice, aliceGroup, aliceProvider, aliceState,
    bob, bobGroup, bobPreJoin, bobProvider, bobState,
    commit, id, treeBytes, welcome,
    cleanup() {
      free(aliceGroup, bobGroup, alice.identity, bob.identity,
        alice.keyPackage, bob.keyPackage, aliceProvider, bobProvider);
    },
  };
}

beforeAll(async () => {
  runtimeEvidence = preflight();
  const moduleUrl = pathToFileURL(resolve(VENDOR, 'openmls_wasm.js'));
  moduleUrl.searchParams.set('m2-f-wasm', runtimeEvidence.head);
  wasm = await import(moduleUrl.href);
  await wasm.default({ module_or_path: readFileSync(WASM_PATH) });
});

describe('F-WASM exact-artifact pre-apply staging feasibility', () => {
  test.each(Object.keys(ARTIFACT_TUPLE))(
    'negative artifact control rejects changed %s',
    (changedName) => {
      expect(() => verifyArtifactTuple((name) => {
        const bytes = copy(readFileSync(resolve(VENDOR, name)));
        if (name === changedName) bytes[0] ^= 1;
        return bytes;
      })).toThrow(`frozen artifact tuple mismatch: ${changedName}`);
    },
  );

  test('stages every required operation class and reconciles without replay', () => {
    const report = { runtime: runtimeEvidence, operations: {} };

    // Session creation boundary: Provider.serialize_state -> restore_state ->
    // PhaseB2Group.create_new -> Provider.serialize_state.
    const creationProvider = new wasm.Provider();
    const founder = createPeer(creationProvider, 30);
    const creationId = groupId(30);
    const creationBase = copy(creationProvider.serialize_state());
    const creationScratch = new wasm.Provider();
    creationScratch.restore_state(creationBase);
    const scratchFounder = wasm.PhaseB2Identity.load(
      creationScratch, founder.accountKey, founder.signatureKey,
    );
    const created = wasm.PhaseB2Group.create_new(
      creationScratch, scratchFounder, creationId, founder.proof,
    );
    const creationCandidate = copy(creationScratch.serialize_state());
    expect(wasm.PhaseB2Group.load(creationProvider, creationId)).toBeUndefined();
    const creationSlot = new AuthoritySlot(creationBase);
    const creationDigest = creationSlot.stage('session-create:30', creationCandidate);
    expect(sha256(creationSlot.authoritativeBytes)).toBe(sha256(creationBase));
    creationSlot.resolve('session-create:30', 'COMMITTED');
    assertLoadable(creationSlot.authoritativeBytes, founder, creationId, 0n);
    report.operations.sessionCreation = {
      boundary: ['Provider.serialize_state', 'Provider.restore_state',
        'PhaseB2Identity.load', 'PhaseB2Group.create_new', 'Provider.serialize_state'],
      candidateSha256: creationDigest,
      committedOnlyActivation: true,
      demonstrated: true,
    };
    free(created, scratchFounder, creationScratch, founder.identity,
      founder.keyPackage, creationProvider);

    const pair = setupPair(50);
    try {
      // Welcome boundary consumes the KeyPackage only in scratch state. A second
      // scratch restored from the durable predecessor can still join.
      const welcomeSlot = new AuthoritySlot(pair.bobPreJoin);
      const firstProvider = new wasm.Provider();
      firstProvider.restore_state(pair.bobPreJoin);
      const firstTree = wasm.PhaseB2RatchetTree.from_bytes(pair.treeBytes);
      const firstJoin = wasm.PhaseB2Group.join(firstProvider, pair.welcome, firstTree);
      const welcomeCandidate = copy(firstProvider.serialize_state());
      const welcomeDigest = welcomeSlot.stage('welcome:50', welcomeCandidate);
      let repeatedJoinError = '';
      try {
        wasm.PhaseB2Group.join(firstProvider, pair.welcome,
          wasm.PhaseB2RatchetTree.from_bytes(pair.treeBytes));
      } catch (error) {
        repeatedJoinError = String(error?.message ?? error);
      }
      expect(repeatedJoinError).toMatch(/key.?package|welcome.*secret|decrypt.*welcome/i);
      const retryProvider = new wasm.Provider();
      retryProvider.restore_state(pair.bobPreJoin);
      const retryTree = wasm.PhaseB2RatchetTree.from_bytes(pair.treeBytes);
      const retryJoin = wasm.PhaseB2Group.join(retryProvider, pair.welcome, retryTree);
      expect(retryJoin.epoch()).toBe(1n);
      expect(pair.bob.keyPackage.ciphersuite_id()).toBe(1);
      expect(sha256(welcomeSlot.authoritativeBytes)).toBe(sha256(pair.bobPreJoin));
      welcomeSlot.resolve('welcome:50', 'INDETERMINATE');
      expect(sha256(welcomeSlot.authoritativeBytes)).toBe(sha256(pair.bobPreJoin));
      expect(() => welcomeSlot.resolve('welcome:50', 'COMMITTED'))
        .toThrow('indeterminate requires durable reconciliation');
      expect(() => welcomeSlot.reconcile({
        operationId: 'welcome:50', outcome: 'COMMITTED', candidateSha256: '00'.repeat(32),
      })).toThrow('persisted identity mismatch');
      expect(() => welcomeSlot.reconcile({
        operationId: 'welcome:other', outcome: 'COMMITTED', candidateSha256: welcomeDigest,
      })).toThrow('not indeterminate');
      expect(() => welcomeSlot.reconcile({
        operationId: 'welcome:50', outcome: 'INDETERMINATE', candidateSha256: welcomeDigest,
      })).toThrow('persisted outcome is not COMMITTED');
      const durableReadback = Object.freeze({
        operationId: 'welcome:50',
        outcome: 'COMMITTED',
        candidateSha256: welcomeDigest,
      });
      welcomeSlot.reconcile(durableReadback);
      assertLoadable(welcomeSlot.authoritativeBytes, pair.bob, pair.id, 1n);
      report.operations.welcomeOnboarding = {
        boundary: ['Provider.restore_state', 'PhaseB2RatchetTree.from_bytes',
          'PhaseB2Group.join', 'Provider.serialize_state'],
        candidateSha256: welcomeDigest,
        indeterminateReconciledBy:
          'durable COMMITTED readback + operation identity + candidate SHA-256',
        keyPackageConsumedOnlyInCandidate: true,
        demonstrated: true,
      };
      free(firstJoin, firstTree, firstProvider, retryJoin, retryTree, retryProvider);

      // Application protect advances only an isolated state image.
      const outbound = restore(pair.aliceState, pair.alice, pair.id);
      const ciphertext = copy(outbound.group.create_application_message(
        outbound.provider, outbound.identity, UTF8.encode('F-WASM outbound'),
      ));
      const outboundCandidate = copy(outbound.provider.serialize_state());
      expect(sha256(outboundCandidate)).not.toBe(sha256(pair.aliceState));
      const outboundSlot = new AuthoritySlot(pair.aliceState);
      const outboundDigest = outboundSlot.stage('app-out:1', outboundCandidate);
      const oldOutbound = restore(outboundSlot.authoritativeBytes, pair.alice, pair.id);
      expect(() => oldOutbound.group.create_application_message(
        oldOutbound.provider, oldOutbound.identity, UTF8.encode('old remains usable'),
      )).not.toThrow();
      const nextOutbound = restore(outboundCandidate, pair.alice, pair.id);
      const nextCiphertext = copy(nextOutbound.group.create_application_message(
        nextOutbound.provider, nextOutbound.identity, UTF8.encode('candidate next generation'),
      ));
      const ratchetReceiver = restore(pair.bobState, pair.bob, pair.id);
      expect(ratchetReceiver.group.receive_application_message(
        ratchetReceiver.provider, ciphertext,
      ).plaintext()).toEqual(UTF8.encode('F-WASM outbound'));
      expect(ratchetReceiver.group.receive_application_message(
        ratchetReceiver.provider, nextCiphertext,
      ).plaintext()).toEqual(UTF8.encode('candidate next generation'));
      expect(() => ratchetReceiver.group.receive_application_message(
        ratchetReceiver.provider, nextCiphertext,
      )).toThrow();
      outboundSlot.resolve('app-out:1', 'COMMITTED');
      report.operations.applicationProtect = {
        boundary: ['Provider.restore_state', 'PhaseB2Group.load',
          'PhaseB2Group.create_application_message', 'Provider.serialize_state'],
        candidateSha256: outboundDigest,
        oldStateUsableBeforeCommit: true,
        demonstrated: true,
      };
      free(outbound.group, outbound.identity, outbound.provider,
        oldOutbound.group, oldOutbound.identity, oldOutbound.provider,
        nextOutbound.group, nextOutbound.identity, nextOutbound.provider,
        ratchetReceiver.group, ratchetReceiver.identity, ratchetReceiver.provider);

      // Application open likewise advances only an isolated receiver image.
      const inbound = restore(pair.bobState, pair.bob, pair.id);
      const received = inbound.group.receive_application_message(inbound.provider, ciphertext);
      expect(received.plaintext()).toEqual(UTF8.encode('F-WASM outbound'));
      const inboundCandidate = copy(inbound.provider.serialize_state());
      expect(sha256(inboundCandidate)).not.toBe(sha256(pair.bobState));
      const inboundSlot = new AuthoritySlot(pair.bobState);
      const inboundDigest = inboundSlot.stage('app-in:1', inboundCandidate);
      const oldInbound = restore(inboundSlot.authoritativeBytes, pair.bob, pair.id);
      expect(oldInbound.group.receive_application_message(oldInbound.provider, ciphertext).plaintext())
        .toEqual(UTF8.encode('F-WASM outbound'));
      const advancedInbound = restore(inboundCandidate, pair.bob, pair.id);
      expect(() => advancedInbound.group.receive_application_message(
        advancedInbound.provider, ciphertext,
      )).toThrow();
      inboundSlot.resolve('app-in:1', 'COMMITTED');
      report.operations.applicationOpen = {
        boundary: ['Provider.restore_state', 'PhaseB2Group.load',
          'PhaseB2Group.receive_application_message', 'Provider.serialize_state'],
        candidateSha256: inboundDigest,
        candidatePlaintextVerifiedBeforeAuthoritySelection: true,
        externalPlaintextReleaseClaimed: false,
        oldStateUsableBeforeCommit: true,
        demonstrated: true,
      };
      free(received, inbound.group, inbound.identity, inbound.provider,
        oldInbound.group, oldInbound.identity, oldInbound.provider,
        advancedInbound.group, advancedInbound.identity, advancedInbound.provider);

      // Outbound proposal-free self-update is prepared and confirmed on scratch.
      const local = restore(pair.aliceState, pair.alice, pair.id);
      const pendingLocal = local.group.prepare_self_update(local.provider, local.identity);
      const localProjection = pendingLocal.projection();
      expect(localProjection.proposal_count()).toBe(0);
      expect(localProjection.has_update_path()).toBe(true);
      const selfCommit = copy(pendingLocal.commit());
      local.group.confirm_pending(
        local.provider, pendingLocal, localProjection.verified_leaf_digest(),
      );
      const localCandidate = copy(local.provider.serialize_state());
      const localSlot = new AuthoritySlot(pair.aliceState);
      const localDigest = localSlot.stage('self-update-out:1', localCandidate);
      assertLoadable(localSlot.authoritativeBytes, pair.alice, pair.id, 1n);
      localSlot.resolve('self-update-out:1', 'COMMITTED');
      assertLoadable(localSlot.authoritativeBytes, pair.alice, pair.id, 2n);
      report.operations.outboundSelfUpdate = {
        boundary: ['Provider.restore_state', 'PhaseB2Group.load',
          'PhaseB2Group.prepare_self_update', 'PhaseB2PendingCommit.projection',
          'PhaseB2Group.confirm_pending', 'Provider.serialize_state'],
        candidateSha256: localDigest,
        oldEpochBeforeCommit: '1',
        candidateEpochAfterCommit: '2',
        demonstrated: true,
      };
      free(localProjection, pendingLocal, local.group, local.identity, local.provider);

      // Inbound proposal-free self-update is staged/merged only on scratch.
      const remote = restore(pair.bobState, pair.bob, pair.id);
      const staged = remote.group.stage_inbound_commit(remote.provider, selfCommit);
      const inboundProjection = staged.projection();
      expect(inboundProjection.proposal_count()).toBe(0);
      expect(inboundProjection.has_update_path()).toBe(true);
      remote.group.merge_staged_commit(
        remote.provider, staged, inboundProjection.verified_leaf_digest(),
      );
      const remoteCandidate = copy(remote.provider.serialize_state());
      const remoteSlot = new AuthoritySlot(pair.bobState);
      const remoteDigest = remoteSlot.stage('self-update-in:1', remoteCandidate);
      assertLoadable(remoteSlot.authoritativeBytes, pair.bob, pair.id, 1n);
      remoteSlot.resolve('self-update-in:1', 'COMMITTED');
      assertLoadable(remoteSlot.authoritativeBytes, pair.bob, pair.id, 2n);
      report.operations.inboundSelfUpdate = {
        boundary: ['Provider.restore_state', 'PhaseB2Group.load',
          'PhaseB2Group.stage_inbound_commit', 'PhaseB2StagedCommit.projection',
          'PhaseB2Group.merge_staged_commit', 'Provider.serialize_state'],
        candidateSha256: remoteDigest,
        oldEpochBeforeCommit: '1',
        candidateEpochAfterCommit: '2',
        demonstrated: true,
      };
      free(inboundProjection, staged, remote.group, remote.identity, remote.provider);

      // Two distinct committers produce candidates from Alice's same immutable
      // parent. The lower account identity wins; the losing candidate remains
      // bounded evidence and cannot overwrite the selected parent.
      const peerLocal = restore(pair.bobState, pair.bob, pair.id);
      const peerPending = peerLocal.group.prepare_self_update(
        peerLocal.provider, peerLocal.identity,
      );
      const peerProjection = peerPending.projection();
      expect(peerProjection.proposal_count()).toBe(0);
      expect(peerProjection.has_update_path()).toBe(true);
      const peerCommit = copy(peerPending.commit());
      peerLocal.group.confirm_pending(
        peerLocal.provider, peerPending, peerProjection.verified_leaf_digest(),
      );
      const peerInbound = restore(pair.aliceState, pair.alice, pair.id);
      const peerStaged = peerInbound.group.stage_inbound_commit(peerInbound.provider, peerCommit);
      const peerInboundProjection = peerStaged.projection();
      expect(peerInboundProjection.proposal_count()).toBe(0);
      expect(peerInboundProjection.has_update_path()).toBe(true);
      peerInbound.group.merge_staged_commit(
        peerInbound.provider, peerStaged, peerInboundProjection.verified_leaf_digest(),
      );
      const peerCandidate = copy(peerInbound.provider.serialize_state());
      const candidates = [
        {
          committer: Buffer.from(pair.alice.accountKey).toString('hex'),
          commitSha256: sha256(selfCommit),
          state: localCandidate,
          stateSha256: sha256(localCandidate),
        },
        {
          committer: Buffer.from(pair.bob.accountKey).toString('hex'),
          commitSha256: sha256(peerCommit),
          state: peerCandidate,
          stateSha256: sha256(peerCandidate),
        },
      ].sort((left, right) => left.committer.localeCompare(right.committer));
      expect(candidates[0].committer).not.toBe(candidates[1].committer);
      expect(candidates[0].commitSha256).not.toBe(candidates[1].commitSha256);
      expect(candidates[0].stateSha256).not.toBe(candidates[1].stateSha256);
      const forkSlot = new AuthoritySlot(pair.aliceState);
      const winnerDigest = forkSlot.stage('candidate:winner', candidates[0].state);
      const loserDigest = forkSlot.stage('candidate:loser', candidates[1].state);
      expect(sha256(forkSlot.authoritativeBytes)).toBe(sha256(pair.aliceState));
      forkSlot.resolve('candidate:winner', 'COMMITTED');
      expect(sha256(forkSlot.authoritativeBytes)).toBe(winnerDigest);
      assertLoadable(forkSlot.authoritativeBytes, pair.alice, pair.id, 2n);
      expect(forkSlot.pending.get('candidate:loser').digest).toBe(loserDigest);
      expect(() => forkSlot.resolve('candidate:loser', 'COMMITTED'))
        .toThrow('candidate parent is no longer authoritative');
      report.operations.twoCandidateCase = {
        boundary: ['two distinct committer identities',
          'PhaseB2Group.prepare_self_update for the local candidate',
          'PhaseB2Group.stage_inbound_commit for the peer candidate',
          'lower-identity selection after COMMITTED'],
        candidates: candidates.map(({ committer, commitSha256, stateSha256 }) => ({
          committer, commitSha256, stateSha256,
        })),
        loserRetainedAsBoundedEvidence: true,
        parentUnchangedUntilSelection: true,
        selectedCandidateSha256: winnerDigest,
        demonstrated: true,
      };
      free(peerInboundProjection, peerStaged, peerInbound.group, peerInbound.identity,
        peerInbound.provider, peerProjection, peerPending, peerLocal.group,
        peerLocal.identity, peerLocal.provider);

      const operationResults = Object.values(report.operations);
      report.overall = operationResults.every((entry) => entry.demonstrated)
        ? 'POSITIVE' : 'NEGATIVE';
      expect(operationResults).toHaveLength(7);
      expect(report.overall).toBe('POSITIVE');
      console.log(`F_WASM_REPORT=${JSON.stringify(report)}`);
    } finally {
      pair.cleanup();
    }
  }, 120_000);
});
