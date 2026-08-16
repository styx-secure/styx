// SPDX-License-Identifier: AGPL-3.0-or-later

import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { runInNewContext } from 'node:vm';
import {
  B33B1_ERROR,
  B33B1_RECOVERY,
  B33B1_STATE,
  exactFields,
  sha256Hex,
} from '../../spikes/marmot-phase-b3-3b-1/b3-3b-1-canonical.mjs';
import {
  B33b1Journal,
  FileB33b1Store,
  MemoryB33b1Store,
} from '../../spikes/marmot-phase-b3-3b-1/b3-3b-1-journal.mjs';

function bytes(marker, length = 96) {
  return Uint8Array.from({ length }, (_, index) => (marker + index) & 0xff);
}

function digest(marker) { return sha256Hex(bytes(marker)); }
function hex(marker, length) { return Buffer.from(bytes(marker, length)).toString('hex'); }

function activation() {
  const stateBytes = bytes(1, 256);
  return {
    stateBytes,
    sourceB32aHeadDigestHex: digest(2),
    groupIdHex: hex(3, 16),
    accountIdentityHex: hex(4, 32),
    leafSignatureKeyHex: hex(5, 32),
    epochDec: '1',
    groupContextSha256Hex: digest(6),
    rosterSha256Hex: digest(7),
  };
}

function projection(parentState, sourceEpoch, marker, activationFields = activation()) {
  return {
    authoritySha256Hex: digest(marker),
    candidateGroupContextSha256Hex: digest(marker + 1),
    commitSha256Hex: digest(marker + 2),
    committerAccountHex: activationFields.accountIdentityHex,
    committerLeafIndex: 1,
    committerSignatureKeyHex: activationFields.leafSignatureKeyHex,
    domain: 'phase-b33b1-authorized-commit-v1',
    groupIdHex: activationFields.groupIdHex,
    orderingPriority: 'ordinary',
    parentGroupContextSha256Hex: activationFields.groupContextSha256Hex,
    parentStateSha256Hex: sha256Hex(parentState),
    sourceEpoch: `${sourceEpoch}`,
    targetEpoch: `${sourceEpoch + 1}`,
    verifiedLeafDigestHex: digest(marker + 3),
  };
}

function localFields(parentState, sourceEpoch = 1, marker = 20, activationFields = activation()) {
  const pendingStateBytes = bytes(marker + 4, 320);
  const commitBytes = bytes(marker + 2);
  const projected = projection(parentState, sourceEpoch, marker, activationFields);
  projected.commitSha256Hex = sha256Hex(commitBytes);
  return {
    parentStateBytes: Uint8Array.from(parentState),
    pendingStateBytes,
    commitBytes,
    authoritySha256Hex: projected.authoritySha256Hex,
    projection: projected,
  };
}

function inboundFields(parentState, sourceEpoch, marker, activationFields) {
  const commitBytes = bytes(marker + 2);
  const projected = projection(parentState, sourceEpoch, marker, activationFields);
  projected.commitSha256Hex = sha256Hex(commitBytes);
  return {
    parentStateBytes: Uint8Array.from(parentState),
    commitBytes,
    authoritySha256Hex: projected.authoritySha256Hex,
    projection: projected,
  };
}

function acceptance(prepared) {
  return {
    commitSha256Hex: prepared.projection.commitSha256Hex,
    peerGroupContextSha256Hex: prepared.projection.candidateGroupContextSha256Hex,
    evidenceSha256Hex: digest(60),
  };
}

function committed(prepared, marker = 70) {
  const committedStateBytes = bytes(marker, 384);
  return {
    committedStateBytes,
    committedStateSha256Hex: sha256Hex(committedStateBytes),
    groupContextSha256Hex: prepared.projection.candidateGroupContextSha256Hex,
    rosterSha256Hex: digest(marker + 1),
    epochDec: prepared.projection.targetEpoch,
    commitSha256Hex: prepared.projection.commitSha256Hex,
    authoritySha256Hex: prepared.projection.authoritySha256Hex,
  };
}

async function activated(store = new MemoryB33b1Store()) {
  const journal = new B33b1Journal(store);
  const fields = activation();
  const current = await journal.activate(fields);
  return { journal, store, fields, current };
}

function clearRecovery(value) {
  value?.stateBytes?.fill(0);
  value?.parentStateBytes?.fill(0);
  value?.pendingStateBytes?.fill(0);
  value?.commitBytes?.fill(0);
}

describe('Phase B3.3b-1 durable epoch-transition journal', () => {
  test('strict records accept ordinary cross-realm objects but reject custom prototypes', () => {
    const crossRealm = runInNewContext('({ value: 7 })');
    expect(exactFields(crossRealm, ['value'], 'cross-realm record')).toEqual({ value: 7 });

    const inherited = Object.create({ value: 7 });
    Object.defineProperty(inherited, 'value', { enumerable: true, value: 7 });
    expect(() => exactFields(inherited, ['value'], 'custom record'))
      .toThrow(expect.objectContaining({ code: B33B1_ERROR.INVALID }));
  });

  test('activates exact B3.2a state once and restores stable authority', async () => {
    const { journal, fields, current } = await activated();
    expect(current.action).toBe(B33B1_RECOVERY.STABLE);
    expect(current.head).toEqual(expect.objectContaining({
      state: B33B1_STATE.ACTIVE,
      epochDec: '1',
      stateBlobSha256Hex: sha256Hex(fields.stateBytes),
    }));
    await expect(journal.activate(fields)).rejects.toMatchObject({
      code: B33B1_ERROR.DUPLICATE_INITIALIZATION,
    });
    clearRecovery(current);
  });

  test('local Commit is durable before release and ACK dominates restart recovery', async () => {
    const { journal, store, fields, current } = await activated();
    const prepared = localFields(fields.stateBytes, 1, 20, fields);
    const pending = await journal.prepareLocal(current.head.headDigestHex, prepared);
    expect(pending.action).toBe(B33B1_RECOVERY.REPUBLISH_LOCAL);
    expect(pending.commitBytes).toEqual(prepared.commitBytes);
    expect(pending.pendingStateBytes).toEqual(prepared.pendingStateBytes);

    const restarted = new B33b1Journal(store);
    const retry = await restarted.readRecovery();
    expect(retry.action).toBe(B33B1_RECOVERY.REPUBLISH_LOCAL);
    expect(retry.commitBytes).toEqual(prepared.commitBytes);

    const accepted = await restarted.acceptLocal(retry.head.headDigestHex, acceptance(prepared));
    expect(accepted.action).toBe(B33B1_RECOVERY.MERGE_ACCEPTED_LOCAL);
    const afterAckRestart = await new B33b1Journal(store).readRecovery();
    expect(afterAckRestart.action).toBe(B33B1_RECOVERY.MERGE_ACCEPTED_LOCAL);

    const stable = await restarted.commitAcceptedLocal(
      afterAckRestart.head.headDigestHex, committed(prepared),
    );
    expect(stable.action).toBe(B33B1_RECOVERY.STABLE);
    expect(stable.head).toEqual(expect.objectContaining({
      epochDec: '2',
      committedCommitSha256Hex: prepared.projection.commitSha256Hex,
    }));
    expect(stable.head.transitions).toEqual([expect.objectContaining({
      direction: 'LOCAL', disposition: 'LOCAL_COMMITTED',
    })]);
    [current, pending, retry, accepted, afterAckRestart, stable].forEach(clearRecovery);
  });

  test('inbound stage survives restart without serializing a staged handle', async () => {
    const { journal, store, fields, current } = await activated();
    const inbound = inboundFields(fields.stateBytes, 1, 80, fields);
    const staged = await journal.stageInbound(current.head.headDigestHex, inbound);
    expect(staged.action).toBe(B33B1_RECOVERY.RESTAGE_INBOUND);
    expect(staged.head.stagedInbound).not.toHaveProperty('stagedCommit');
    expect(staged.commitBytes).toEqual(inbound.commitBytes);

    const restarted = new B33b1Journal(store);
    const recovery = await restarted.readRecovery();
    expect(recovery.action).toBe(B33B1_RECOVERY.RESTAGE_INBOUND);
    const stable = await restarted.commitStagedInbound(
      recovery.head.headDigestHex, committed(inbound, 90),
    );
    expect(stable.head.transitions).toEqual([expect.objectContaining({
      direction: 'INBOUND', disposition: 'INBOUND_COMMITTED',
    })]);
    [current, staged, recovery, stable].forEach(clearRecovery);
  });

  test('application ratchet state is durable without changing epoch authority', async () => {
    const { journal, fields, current } = await activated();
    const outboundState = bytes(200, 300);
    const outboundCiphertext = bytes(201, 120);
    const outbound = await journal.commitApplication(current.head.headDigestHex, {
      direction: 'OUTBOUND',
      stateBytes: outboundState,
      ciphertextBytes: outboundCiphertext,
      plaintextBytes: null,
      currentEpochDec: '1',
      messageEpoch: '1',
      groupIdHex: fields.groupIdHex,
      senderLeafIndex: 1,
      senderIdentityHex: fields.accountIdentityHex,
      senderSignatureKeyHex: fields.leafSignatureKeyHex,
    });
    expect(outbound.head.epochDec).toBe('1');
    expect(outbound.ciphertextBytes).toEqual(outboundCiphertext);
    const inboundState = bytes(202, 310);
    const plaintext = bytes(203, 40);
    const inbound = await journal.commitApplication(outbound.head.headDigestHex, {
      direction: 'INBOUND',
      stateBytes: inboundState,
      ciphertextBytes: bytes(204, 130),
      plaintextBytes: plaintext,
      currentEpochDec: '1',
      messageEpoch: '0',
      groupIdHex: fields.groupIdHex,
      senderLeafIndex: 0,
      senderIdentityHex: hex(205, 32),
      senderSignatureKeyHex: hex(206, 32),
    });
    expect(inbound.head.applicationRecords).toHaveLength(2);
    expect(inbound.plaintextBytes).toEqual(plaintext);
    [current, outbound, inbound].forEach(clearRecovery);
    outbound.ciphertextBytes.fill(0);
    inbound.ciphertextBytes.fill(0);
    inbound.plaintextBytes.fill(0);
  });

  test('stale writers lose CAS and cannot replace the authoritative head', async () => {
    const { journal, store, fields, current } = await activated();
    const second = new B33b1Journal(store);
    const prepared = localFields(fields.stateBytes, 1, 100, fields);
    const pending = await journal.prepareLocal(current.head.headDigestHex, prepared);
    await expect(second.stageInbound(
      current.head.headDigestHex, inboundFields(fields.stateBytes, 1, 110, fields),
    )).rejects.toMatchObject({ code: B33B1_ERROR.CAS_CONFLICT });
    const authoritative = await second.readRecovery();
    expect(authoritative.action).toBe(B33B1_RECOVERY.REPUBLISH_LOCAL);
    [current, pending, authoritative].forEach(clearRecovery);
  });

  test('every journal write failure is fail-closed and the exact operation retries', async () => {
    const { journal, store, fields, current } = await activated();
    const prepared = localFields(fields.stateBytes, 1, 120, fields);
    for (let failOffset = 1; failOffset <= 4; failOffset += 1) {
      const baseline = store.writeOrdinal;
      store.beforeWrite = ({ ordinal }) => {
        if (ordinal === baseline + failOffset) throw new Error('injected write failure');
      };
      await expect(journal.prepareLocal(current.head.headDigestHex, prepared))
        .rejects.toMatchObject({ code: B33B1_ERROR.PERSISTENCE_FAILED });
      store.beforeWrite = null;
      const unchanged = await journal.readRecovery();
      expect(unchanged.action).toBe(B33B1_RECOVERY.STABLE);
      clearRecovery(unchanged);
    }
    const pending = await journal.prepareLocal(current.head.headDigestHex, prepared);
    const baseline = store.writeOrdinal;
    store.beforeWrite = ({ ordinal }) => {
      if (ordinal === baseline + 1) throw new Error('lost acknowledgement');
    };
    await expect(journal.acceptLocal(pending.head.headDigestHex, acceptance(prepared)))
      .rejects.toMatchObject({ code: B33B1_ERROR.PERSISTENCE_FAILED });
    store.beforeWrite = null;
    const retry = await journal.readRecovery();
    expect(retry.action).toBe(B33B1_RECOVERY.REPUBLISH_LOCAL);
    [current, pending, retry].forEach(clearRecovery);
  });

  test('private file journal reopens at each weakest recovery boundary', async () => {
    const root = mkdtempSync(resolve(tmpdir(), 'styx-b33b1-root-'));
    const directory = resolve(root, 'journal');
    try {
      const first = new B33b1Journal(new FileB33b1Store(directory, root));
      const fields = activation();
      const active = await first.activate(fields);
      const prepared = localFields(fields.stateBytes, 1, 140, fields);
      const pending = await first.prepareLocal(active.head.headDigestHex, prepared);
      const second = new B33b1Journal(new FileB33b1Store(directory, root));
      const retry = await second.readRecovery();
      expect(retry.action).toBe(B33B1_RECOVERY.REPUBLISH_LOCAL);
      const accepted = await second.acceptLocal(retry.head.headDigestHex, acceptance(prepared));
      const third = new B33b1Journal(new FileB33b1Store(directory, root));
      const merge = await third.readRecovery();
      expect(merge.action).toBe(B33B1_RECOVERY.MERGE_ACCEPTED_LOCAL);
      const stable = await third.commitAcceptedLocal(merge.head.headDigestHex, committed(prepared));
      expect(stable.action).toBe(B33B1_RECOVERY.STABLE);
      [active, pending, retry, accepted, merge, stable].forEach(clearRecovery);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test('private file journal serializes competing CAS writers across instances', async () => {
    const root = mkdtempSync(resolve(tmpdir(), 'styx-b33b1-cas-root-'));
    const directory = resolve(root, 'journal');
    try {
      const first = new B33b1Journal(new FileB33b1Store(directory, root));
      const second = new B33b1Journal(new FileB33b1Store(directory, root));
      const outcomes = await Promise.allSettled([
        first.activate(activation()), second.activate(activation()),
      ]);
      expect(outcomes.filter(({ status }) => status === 'fulfilled')).toHaveLength(1);
      const rejected = outcomes.find(({ status }) => status === 'rejected');
      expect(rejected?.reason).toMatchObject({ code: B33B1_ERROR.CAS_CONFLICT });
      const recovered = await first.readRecovery();
      expect(recovered.action).toBe(B33B1_RECOVERY.STABLE);
      clearRecovery(recovered);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test('private file journal treats a stale CAS lock as explicit fail-closed state', async () => {
    const root = mkdtempSync(resolve(tmpdir(), 'styx-b33b1-stale-lock-root-'));
    const directory = resolve(root, 'journal');
    try {
      const journal = new B33b1Journal(new FileB33b1Store(directory, root));
      mkdirSync(resolve(directory, 'cas.lock'), { mode: 0o700 });
      await expect(journal.activate(activation())).rejects.toMatchObject({
        code: B33B1_ERROR.CAS_CONFLICT,
      });
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
