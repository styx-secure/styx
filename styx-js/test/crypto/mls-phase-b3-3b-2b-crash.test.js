// SPDX-License-Identifier: AGPL-3.0-or-later

import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TextEncoder } from 'node:util';

import { sha256Hex }
  from '../../spikes/marmot-phase-b3-3b-1/b3-3b-1-canonical.mjs';
import {
  B33b2bJournal,
  MemoryB33b2bStore,
  openB33b2bFileJournal,
} from '../../spikes/marmot-phase-b3-3b-2b/b3-3b-2b-journal.mjs';
import { B33B2B_ERROR, B33B2B_STATE }
  from '../../spikes/marmot-phase-b3-3b-2b/b3-3b-2b-canonical.mjs';

const encoder = new TextEncoder();
const bytes = (value) => encoder.encode(value);
const digest = (value) => sha256Hex(bytes(value));
const WORKER = fileURLToPath(new URL(
  '../../spikes/marmot-phase-b3-3b-2b/journal-fresh-process.mjs', import.meta.url,
));

function projection(account, commitBytes) {
  return Object.freeze({
    authoritySha256Hex: digest(`authority:${account}`),
    candidateGroupContextSha256Hex: digest(`candidate:${account}`),
    commitSha256Hex: sha256Hex(commitBytes),
    committerAccountHex: account,
    committerLeafIndex: account.startsWith('11') ? 0 : 1,
    committerSignatureKeyHex: account.startsWith('11')
      ? 'aa'.repeat(32) : 'bb'.repeat(32),
    domain: 'STYX-B33B1-COMMIT-PROJECTION-v1',
    groupIdHex: 'abcd',
    orderingPriority: 'ordinary',
    parentGroupContextSha256Hex: digest('parent-context'),
    parentStateSha256Hex: sha256Hex(bytes('parent-state')),
    sourceEpoch: '7',
    targetEpoch: '8',
    verifiedLeafDigestHex: digest('verified-roster'),
  });
}

async function advance(journal, target) {
  const parentState = bytes('parent-state');
  const localCommit = bytes(`commit:${'22'.repeat(32)}`);
  const rivalCommit = bytes(`commit:${'11'.repeat(32)}`);
  const local = projection('22'.repeat(32), localCommit);
  const rival = projection('11'.repeat(32), rivalCommit);
  let head = await journal.activate({
    forkEpoch: '7',
    groupIdDigestHex: digest('group-id'),
    parentGroupContextSha256Hex: digest('parent-context'),
    parentStateBytes: parentState,
    rosterDigestHex: digest('roster'),
  });
  if (target === B33B2B_STATE.ACTIVATED) return { head, localCommit, rivalCommit };
  head = await journal.recordLocalBranch(head.headDigestHex, {
    authoritySha256Hex: local.authoritySha256Hex,
    commitBytes: localCommit,
    projection: local,
    stateBytes: bytes('local-state'),
  });
  if (target === B33B2B_STATE.LOCAL_BRANCH_DURABLE) {
    return { head, localCommit, rivalCommit };
  }
  head = await journal.recordRival(head.headDigestHex, {
    authoritySha256Hex: rival.authoritySha256Hex,
    commitBytes: rivalCommit,
    projection: rival,
  });
  if (target === B33B2B_STATE.RIVAL_RECORDED) return { head, localCommit, rivalCommit };
  head = await journal.freezeRace(head.headDigestHex);
  if (target === B33B2B_STATE.RACE_FROZEN) return { head, localCommit, rivalCommit };
  head = await journal.prepareSettlement(head.headDigestHex, {
    losingCommitSha256Hex: local.commitSha256Hex,
    losingDisposition: 'deferred',
    selectedCommitSha256Hex: rival.commitSha256Hex,
    selectedGroupContextSha256Hex: rival.candidateGroupContextSha256Hex,
    selectionTraceDigestHex: digest('trace'),
    settlementRecordBytes: bytes('settlement-record'),
    successorStateBytes: bytes('rival-state'),
  });
  if (target === B33B2B_STATE.SETTLEMENT_PREPARED) {
    return { head, localCommit, rivalCommit };
  }
  head = await journal.commitStable(head.headDigestHex);
  return { head, localCommit, rivalCommit };
}

function freshRecovery(directory, root) {
  const child = spawnSync(process.execPath, [WORKER, directory, root], {
    encoding: 'utf8', timeout: 20_000,
  });
  if (child.status !== 0 || child.signal !== null || child.error) {
    throw new Error(`fresh recovery failed: ${child.stderr}`);
  }
  const result = JSON.parse(child.stdout);
  expect(result.processId).not.toBe(process.pid);
  return result;
}

describe('Phase B3.3b-2b crash and fresh-process journal recovery', () => {
  test('distinguishes empty and foreign journals before activation', async () => {
    const empty = new B33b2bJournal(new MemoryB33b2bStore());
    await expect(empty.readRecovery())
      .rejects.toHaveProperty('code', B33B2B_ERROR.STATE_CONFLICT);
    const foreign = new MemoryB33b2bStore();
    foreign.head = { domain: 'FOREIGN' };
    await expect(new B33b2bJournal(foreign).readRecovery())
      .rejects.toHaveProperty('code', B33B2B_ERROR.CORRUPT);
  });

  test.each([
    B33B2B_STATE.ACTIVATED,
    B33B2B_STATE.LOCAL_BRANCH_DURABLE,
    B33B2B_STATE.RIVAL_RECORDED,
    B33B2B_STATE.RACE_FROZEN,
    B33B2B_STATE.SETTLEMENT_PREPARED,
    B33B2B_STATE.STABLE,
  ])('restores %s from a distinct process', async (state) => {
    const root = mkdtempSync(resolve(tmpdir(), 'styx-b33b2b-root-'));
    chmodSync(root, 0o700);
    const directory = resolve(root, 'journal');
    mkdirSync(directory, { mode: 0o700 });
    try {
      const fixture = await advance(openB33b2bFileJournal(directory, root), state);
      const recovered = freshRecovery(directory, root);
      expect(recovered.state).toBe(state);
      expect(recovered.headDigestHex).toBe(fixture.head.headDigestHex);
      if (state === B33B2B_STATE.LOCAL_BRANCH_DURABLE) {
        const reopened = await openB33b2bFileJournal(directory, root).readRecovery();
        expect(reopened.localCommitBytes).toEqual(fixture.localCommit);
      }
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  test('recovers after successor blobs but before prepared-head CAS', async () => {
    const store = new MemoryB33b2bStore();
    const journal = new B33b2bJournal(store);
    const fixture = await advance(journal, B33B2B_STATE.RACE_FROZEN);
    const blobsBefore = store.blobs.size;
    store.beforeWrite = ({ kind }) => {
      if (kind === 'head') throw new Error('injected crash before head CAS');
    };
    await expect(journal.prepareSettlement(fixture.head.headDigestHex, {
      losingCommitSha256Hex: sha256Hex(fixture.localCommit),
      losingDisposition: 'deferred',
      selectedCommitSha256Hex: sha256Hex(fixture.rivalCommit),
      selectedGroupContextSha256Hex: digest(`candidate:${'11'.repeat(32)}`),
      selectionTraceDigestHex: digest('trace'),
      settlementRecordBytes: bytes('settlement-record'),
      successorStateBytes: bytes('rival-state'),
    })).rejects.toHaveProperty('code', B33B2B_ERROR.PERSISTENCE_FAILED);
    expect(store.head.state).toBe(B33B2B_STATE.RACE_FROZEN);
    expect(store.blobs.size).toBeGreaterThan(blobsBefore);
    store.beforeWrite = null;
    const prepared = await journal.prepareSettlement(fixture.head.headDigestHex, {
      losingCommitSha256Hex: sha256Hex(fixture.localCommit),
      losingDisposition: 'deferred',
      selectedCommitSha256Hex: sha256Hex(fixture.rivalCommit),
      selectedGroupContextSha256Hex: digest(`candidate:${'11'.repeat(32)}`),
      selectionTraceDigestHex: digest('trace'),
      settlementRecordBytes: bytes('settlement-record'),
      successorStateBytes: bytes('rival-state'),
    });
    expect(prepared.state).toBe(B33B2B_STATE.SETTLEMENT_PREPARED);
  });
});
