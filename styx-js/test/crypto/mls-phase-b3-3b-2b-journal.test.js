// SPDX-License-Identifier: AGPL-3.0-or-later

import { TextEncoder } from 'node:util';

import {
  B33B1_PROVIDER_FORMAT,
  sha256Hex,
} from '../../spikes/marmot-phase-b3-3b-1/b3-3b-1-canonical.mjs';
import {
  B33b2bJournal,
  MemoryB33b2bStore,
  parseB33b2bHead,
} from '../../spikes/marmot-phase-b3-3b-2b/b3-3b-2b-journal.mjs';
import {
  B33B2B_ERROR,
  B33B2B_STATE,
} from '../../spikes/marmot-phase-b3-3b-2b/b3-3b-2b-canonical.mjs';

const encoder = new TextEncoder();
const bytes = (value) => encoder.encode(value);
const digest = (value) => sha256Hex(bytes(value));

function projection({
  account = '11'.repeat(32),
  authority = digest(`authority:${account}`),
  candidateContext = digest(`candidate:${account}`),
  commitBytes = bytes(`commit:${account}`),
  parentContext = digest('parent-context'),
  parentState = bytes('parent-state'),
} = {}) {
  return Object.freeze({
    authoritySha256Hex: authority,
    candidateGroupContextSha256Hex: candidateContext,
    commitSha256Hex: sha256Hex(commitBytes),
    committerAccountHex: account,
    committerLeafIndex: account.startsWith('11') ? 0 : 1,
    committerSignatureKeyHex: account.startsWith('11')
      ? 'aa'.repeat(32) : 'bb'.repeat(32),
    domain: 'STYX-B33B1-COMMIT-PROJECTION-v1',
    groupIdHex: 'abcd',
    orderingPriority: 'ordinary',
    parentGroupContextSha256Hex: parentContext,
    parentStateSha256Hex: sha256Hex(parentState),
    sourceEpoch: '7',
    targetEpoch: '8',
    verifiedLeafDigestHex: digest('verified-roster'),
  });
}

async function journalAtFrozen({ localAccount = '11'.repeat(32) } = {}) {
  const store = new MemoryB33b2bStore();
  const journal = new B33b2bJournal(store);
  const parentState = bytes('parent-state');
  const localCommit = bytes(`commit:${localAccount}`);
  const rivalAccount = localAccount.startsWith('11') ? '22'.repeat(32) : '11'.repeat(32);
  const rivalCommit = bytes(`commit:${rivalAccount}`);
  const common = { parentState };
  const localProjection = projection({
    ...common, account: localAccount, commitBytes: localCommit,
  });
  const rivalProjection = projection({
    ...common, account: rivalAccount, commitBytes: rivalCommit,
  });
  let head = await journal.activate({
    forkEpoch: '7',
    groupIdDigestHex: digest('group-id'),
    parentGroupContextSha256Hex: digest('parent-context'),
    parentStateBytes: parentState,
    rosterDigestHex: digest('roster'),
  });
  head = await journal.recordLocalBranch(head.headDigestHex, {
    authoritySha256Hex: localProjection.authoritySha256Hex,
    commitBytes: localCommit,
    projection: localProjection,
    stateBytes: bytes(`local-state:${localAccount}`),
  });
  head = await journal.recordRival(head.headDigestHex, {
    authoritySha256Hex: rivalProjection.authoritySha256Hex,
    commitBytes: rivalCommit,
    projection: rivalProjection,
  });
  head = await journal.freezeRace(head.headDigestHex);
  return {
    head,
    journal,
    localCommit,
    localProjection,
    parentState,
    rivalCommit,
    rivalProjection,
    store,
  };
}

async function prepare(fixture) {
  const winner = fixture.localProjection.committerAccountHex
    < fixture.rivalProjection.committerAccountHex
    ? fixture.localProjection : fixture.rivalProjection;
  const loser = winner === fixture.localProjection
    ? fixture.rivalProjection : fixture.localProjection;
  const successorState = bytes(`successor:${winner.commitSha256Hex}`);
  const head = await fixture.journal.prepareSettlement(fixture.head.headDigestHex, {
    losingCommitSha256Hex: loser.commitSha256Hex,
    losingDisposition: 'deferred',
    selectedCommitSha256Hex: winner.commitSha256Hex,
    selectedGroupContextSha256Hex: winner.candidateGroupContextSha256Hex,
    selectionTraceDigestHex: digest('selection-trace'),
    settlementRecordBytes: bytes('settlement-record'),
    successorStateBytes: successorState,
  });
  return { head, loser, successorState, winner };
}

describe('Phase B3.3b-2b durable settlement journal', () => {
  test('uses a new frozen format and advances through every durable phase', async () => {
    const fixture = await journalAtFrozen();
    expect(fixture.head).toEqual(expect.objectContaining({
      providerFormat: B33B1_PROVIDER_FORMAT,
      state: B33B2B_STATE.RACE_FROZEN,
      sequence: 4,
      forkEpoch: '7',
    }));
    expect(fixture.head.frozenSetDigestHex).toMatch(/^[0-9a-f]{64}$/);

    const prepared = await prepare(fixture);
    expect(prepared.head.state).toBe(B33B2B_STATE.SETTLEMENT_PREPARED);
    expect(prepared.head.settlement).toEqual(expect.objectContaining({
      effectDelivered: false,
      losingCommitSha256Hex: prepared.loser.commitSha256Hex,
      losingDisposition: 'deferred',
    }));
    const stable = await fixture.journal.commitStable(prepared.head.headDigestHex);
    expect(stable).toEqual(expect.objectContaining({
      state: B33B2B_STATE.STABLE,
      selectedCommitSha256Hex: prepared.winner.commitSha256Hex,
    }));
    expect(stable.canonical).toEqual(expect.objectContaining({
      epoch: '8',
      groupContextSha256Hex: prepared.winner.candidateGroupContextSha256Hex,
      stateBlobSha256Hex: sha256Hex(prepared.successorState),
    }));

    const recovered = await fixture.journal.readRecovery();
    expect(recovered.successorStateBytes).toEqual(prepared.successorState);
    expect(recovered.parentStateBytes).toEqual(fixture.parentState);
    const delivered = await fixture.journal.markEffectDelivered(
      stable.headDigestHex, stable.settlement.effectIdHex,
    );
    expect(delivered.settlement.effectDelivered).toBe(true);
    await expect(fixture.journal.markEffectDelivered(
      delivered.headDigestHex, delivered.settlement.effectIdHex,
    )).rejects.toHaveProperty('code', B33B2B_ERROR.CAS_CONFLICT);
  });

  test('selects the lower authenticated committer in either local role', async () => {
    for (const localAccount of ['11'.repeat(32), '22'.repeat(32)]) {
      const fixture = await journalAtFrozen({ localAccount });
      const prepared = await prepare(fixture);
      expect(prepared.winner.committerAccountHex).toBe('11'.repeat(32));
      expect(prepared.head.settlement.effectKind).toBe(
        localAccount.startsWith('11') ? 'canonical-selected' : 'local-branch-superseded',
      );
    }
  });

  test('rejects a caller-selected loser and frozen-set mutation', async () => {
    const fixture = await journalAtFrozen();
    await expect(fixture.journal.prepareSettlement(fixture.head.headDigestHex, {
      losingCommitSha256Hex: fixture.localProjection.commitSha256Hex,
      losingDisposition: 'deferred',
      selectedCommitSha256Hex: fixture.rivalProjection.commitSha256Hex,
      selectedGroupContextSha256Hex:
        fixture.rivalProjection.candidateGroupContextSha256Hex,
      selectionTraceDigestHex: digest('selection-trace'),
      settlementRecordBytes: bytes('settlement-record'),
      successorStateBytes: bytes('wrong-successor'),
    })).rejects.toHaveProperty('code', B33B2B_ERROR.STATE_CONFLICT);

    expect(() => parseB33b2bHead({
      ...fixture.head,
      frozenSetDigestHex: digest('forged-frozen-set'),
    })).toThrow(/frozen candidate set digest/);
  });

  test('permits exactly one CAS winner for a prepared settlement', async () => {
    const fixture = await journalAtFrozen();
    const prepared = await prepare(fixture);
    const competing = new B33b2bJournal(fixture.store);
    const outcomes = await Promise.allSettled([
      fixture.journal.commitStable(prepared.head.headDigestHex),
      competing.commitStable(prepared.head.headDigestHex),
    ]);
    expect(outcomes.filter((outcome) => outcome.status === 'fulfilled')).toHaveLength(1);
    const rejected = outcomes.find((outcome) => outcome.status === 'rejected');
    expect(rejected.reason.code).toBe(B33B2B_ERROR.CAS_CONFLICT);
    const recovery = await fixture.journal.readRecovery();
    expect(recovery.head.state).toBe(B33B2B_STATE.STABLE);
  });

  test('fails closed when retained authority is missing or corrupt', async () => {
    for (const mode of ['missing', 'corrupt']) {
      const fixture = await journalAtFrozen();
      const parentDigest = fixture.head.retainedParent.stateBlobSha256Hex;
      if (mode === 'missing') fixture.store.blobs.delete(parentDigest);
      else fixture.store.blobs.set(parentDigest, bytes('substituted-parent'));
      await expect(fixture.journal.readRecovery())
        .rejects.toHaveProperty('code', B33B2B_ERROR.CORRUPT);
      expect(fixture.store.head.state).toBe(B33B2B_STATE.RACE_FROZEN);
    }
  });

  test('records UNRECOVERABLE without mutating canonical authority', async () => {
    const fixture = await journalAtFrozen();
    const canonical = fixture.head.canonical;
    const failed = await fixture.journal.markUnrecoverable(
      fixture.head.headDigestHex, digest('retained-parent-unavailable'),
    );
    expect(failed.state).toBe(B33B2B_STATE.UNRECOVERABLE);
    expect(failed.canonical).toEqual(canonical);
    expect(failed.settlement).toBeNull();
    expect(failed.selectedCommitSha256Hex).toBeNull();
    expect(failed.unrecoverableReasonDigestHex)
      .toBe(digest('retained-parent-unavailable'));
  });

  test('rejects rewritten or skipped transition history', async () => {
    const fixture = await journalAtFrozen();
    expect(() => parseB33b2bHead({
      ...fixture.head,
      transitions: fixture.head.transitions.map((item, index) => (
        index === 1 ? { ...item, from: B33B2B_STATE.ACTIVATED } : item
      )),
    })).toThrow(/append-only state path/);
    expect(() => parseB33b2bHead({
      ...fixture.head,
      previousHeadDigestHex: digest('unrelated-head'),
    })).toThrow(/end of its transition history/);
  });
});
