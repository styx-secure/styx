import { beforeAll, describe, expect, test } from '@jest/globals';
import { schnorr } from '@noble/curves/secp256k1';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { createAccountIdentityProofV2 } from '../../spikes/marmot-phase-b1/identity-proof-v2.js';
import { loadPhaseB1Wasm } from '../../spikes/marmot-phase-b1/wasm-loader.mjs';

let wasm;
const secret = (byte) => new Uint8Array(32).fill(byte);
const groupId = (byte) => new Uint8Array(32).fill(byte);

beforeAll(async () => { wasm = await loadPhaseB1Wasm(); });

function createPeer(provider, byte) {
  const privateKey = secret(byte);
  const accountKey = Uint8Array.from(schnorr.getPublicKey(privateKey));
  const identity = new wasm.PhaseB1Identity(provider, accountKey);
  const proof = createAccountIdentityProofV2(
    privateKey,
    identity.leaf_signature_key(),
    1_800_000_000 + byte,
  );
  const keyPackage = wasm.PhaseB1KeyPackage.from_framed_bytes(
    identity.key_package(provider, proof).to_framed_bytes(),
  );
  return { identity, proof, keyPackage, accountKey };
}

function pairedGroup(seed = 30) {
  const aliceProvider = new wasm.Provider();
  const bobProvider = new wasm.Provider();
  const alice = createPeer(aliceProvider, seed);
  const bob = createPeer(bobProvider, seed + 1);
  const aliceGroup = wasm.PhaseB1Group.create_new(
    aliceProvider,
    alice.identity,
    groupId(seed),
    alice.proof,
  );
  const add = aliceGroup.propose_and_commit_add(aliceProvider, alice.identity, bob.keyPackage);
  aliceGroup.confirm_pending_add(aliceProvider, add);
  const tree = wasm.PhaseB1RatchetTree.from_bytes(aliceGroup.export_ratchet_tree().to_bytes());
  const bobGroup = wasm.PhaseB1Group.join(bobProvider, add.welcome(), tree);
  return { aliceProvider, bobProvider, alice, bob, aliceGroup, bobGroup };
}

function pendingThirdMember(pair, byte) {
  const provider = new wasm.Provider();
  const peer = createPeer(provider, byte);
  const pending = pair.bobGroup.propose_and_commit_add(
    pair.bobProvider,
    pair.bob.identity,
    peer.keyPackage,
  );
  return { provider, peer, pending };
}

describe('Phase B1 explicit local pending lifecycle', () => {
  test('confirm and discard are explicit, single-use and epoch-safe', () => {
    const provider = new wasm.Provider();
    const founder = createPeer(provider, 40);
    const joinerProvider = new wasm.Provider();
    const joiner = createPeer(joinerProvider, 41);
    const group = wasm.PhaseB1Group.create_new(provider, founder.identity, groupId(40), founder.proof);

    const discarded = group.propose_and_commit_add(provider, founder.identity, joiner.keyPackage);
    expect(group.epoch()).toBe(0n);
    group.discard_pending_add(provider, discarded);
    expect(group.epoch()).toBe(0n);
    expect(group.member_count()).toBe(1);
    expect(discarded.is_consumed()).toBe(true);
    expect(() => group.discard_pending_add(provider, discarded)).toThrow(/consumed/);

    const confirmed = group.propose_and_commit_add(provider, founder.identity, joiner.keyPackage);
    expect(group.epoch()).toBe(0n);
    group.confirm_pending_add(provider, confirmed);
    expect(group.epoch()).toBe(1n);
    expect(group.member_count()).toBe(2);
    expect(confirmed.is_consumed()).toBe(true);
    expect(() => group.confirm_pending_add(provider, confirmed)).toThrow(/consumed/);
  });
});
describe('Phase B1 inbound staged Commit lifecycle', () => {
  test('stage does not mutate membership; merge and discard apply at most once', () => {
    const pair = pairedGroup(50);
    let third = pendingThirdMember(pair, 52);
    let staged = pair.aliceGroup.stage_inbound_commit(pair.aliceProvider, third.pending.commit());
    const projection = staged.projection();
    expect(pair.aliceGroup.epoch()).toBe(1n);
    expect(pair.aliceGroup.member_count()).toBe(2);
    expect(projection.prior_epoch()).toBe(1n);
    expect(projection.next_epoch()).toBe(2n);
    expect(projection.add_count()).toBe(1);
    expect(projection.added_member_count()).toBe(1);
    expect(projection.added_credential_identity(0)).toEqual(third.peer.accountKey);
    expect(Array.from(projection.added_component_ids(0))).toEqual([1, 0x8009]);

    pair.aliceGroup.discard_staged_commit(pair.aliceProvider, staged);
    expect(pair.aliceGroup.epoch()).toBe(1n);
    expect(pair.aliceGroup.member_count()).toBe(2);
    expect(staged.is_consumed()).toBe(true);
    expect(() => pair.aliceGroup.discard_staged_commit(pair.aliceProvider, staged)).toThrow(/consumed/);
    pair.bobGroup.discard_pending_add(pair.bobProvider, third.pending);

    third = pendingThirdMember(pair, 53);
    staged = pair.aliceGroup.stage_inbound_commit(pair.aliceProvider, third.pending.commit());
    pair.aliceGroup.merge_staged_commit(pair.aliceProvider, staged);
    pair.bobGroup.confirm_pending_add(pair.bobProvider, third.pending);
    expect(pair.aliceGroup.epoch()).toBe(2n);
    expect(pair.aliceGroup.member_count()).toBe(3);
    expect(staged.is_consumed()).toBe(true);
    expect(() => pair.aliceGroup.merge_staged_commit(pair.aliceProvider, staged)).toThrow(/consumed/);
  });

  test('rejects cross-provider, cross-group, stale-epoch and provider-restore use', () => {
    const pair = pairedGroup(60);
    let third = pendingThirdMember(pair, 62);
    let staged = pair.aliceGroup.stage_inbound_commit(pair.aliceProvider, third.pending.commit());

    expect(() => pair.aliceGroup.merge_staged_commit(new wasm.Provider(), staged)).toThrow(/wrong provider/);
    const other = wasm.PhaseB1Group.create_new(
      pair.aliceProvider,
      pair.alice.identity,
      groupId(99),
      pair.alice.proof,
    );
    expect(() => other.merge_staged_commit(pair.aliceProvider, staged)).toThrow(/wrong group/);
    pair.aliceGroup.discard_staged_commit(pair.aliceProvider, staged);
    pair.bobGroup.discard_pending_add(pair.bobProvider, third.pending);

    third = pendingThirdMember(pair, 63);
    const stale = pair.aliceGroup.stage_inbound_commit(pair.aliceProvider, third.pending.commit());
    pair.bobGroup.discard_pending_add(pair.bobProvider, third.pending);
    const fourth = pendingThirdMember(pair, 64);
    const winner = pair.aliceGroup.stage_inbound_commit(pair.aliceProvider, fourth.pending.commit());
    pair.aliceGroup.merge_staged_commit(pair.aliceProvider, winner);
    pair.bobGroup.confirm_pending_add(pair.bobProvider, fourth.pending);
    expect(() => pair.aliceGroup.merge_staged_commit(pair.aliceProvider, stale)).toThrow(/stale epoch/);

    const restoredPair = pairedGroup(70);
    const fifth = pendingThirdMember(restoredPair, 72);
    staged = restoredPair.aliceGroup.stage_inbound_commit(
      restoredPair.aliceProvider,
      fifth.pending.commit(),
    );
    const snapshot = restoredPair.aliceProvider.serialize_state();
    restoredPair.aliceProvider.restore_state(snapshot);
    expect(() => restoredPair.aliceGroup.merge_staged_commit(restoredPair.aliceProvider, staged))
      .toThrow(/invalidated by provider restore/);
  });

  test('application and handshake paths cannot masquerade as each other or leak plaintext', () => {
    const pair = pairedGroup(80);
    const plaintext = 'PHASE-B1-PLAINTEXT-MUST-NOT-LEAK';
    const appMessage = pair.aliceGroup.create_application_message(
      pair.aliceProvider,
      pair.alice.identity,
      new TextEncoder().encode(plaintext),
    );
    expect(() => pair.bobGroup.stage_inbound_commit(pair.bobProvider, appMessage))
      .toThrow(/not an inbound Commit/);

    const third = pendingThirdMember(pair, 82);
    let error;
    try {
      pair.aliceGroup.process_application_message(pair.aliceProvider, third.pending.commit());
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeTruthy();
    expect(String(error)).not.toContain(plaintext);
  });
});

describe('Phase B1 probe boundary', () => {
  test('no product source or app imports the probe harness or PhaseB1 exports', () => {
    const root = fileURLToPath(new URL('../../', import.meta.url));
    const scan = (directory) => readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
      const path = `${directory}/${entry.name}`;
      if (entry.isDirectory()) return scan(path);
      return /\.(?:js|mjs|ts|tsx|jsx)$/.test(entry.name) ? [path] : [];
    });
    const productFiles = [
      ...scan(`${root}src`),
      ...scan(`${root}apps`),
    ];
    for (const file of productFiles) {
      const source = readFileSync(file, 'utf8');
      expect(source).not.toMatch(/marmot-phase-b1|PhaseB1/);
    }
  });
});
