// SPDX-License-Identifier: AGPL-3.0-or-later

import { B33B1_STAGE1_OPERATION_SEQUENCE }
  from '../../spikes/marmot-phase-b3-3b-1/stage1-probe.mjs';
import { validateStage2Pair, validateStage2Run }
  from '../../spikes/marmot-phase-b3-3b-1/stage2-paired-evidence.mjs';
import {
  B33B1_APPROVED_ARTIFACT_TUPLE,
  B33B1_APPROVED_SOURCE_SHA,
  B33B1_APPROVED_SOURCE_TREE,
  B33B1_MDK_LOCK_SHA256,
} from '../../spikes/marmot-phase-b3-3b-1/verify-pins.mjs';

const hex = (marker) => marker.repeat(64).slice(0, 64);

function run(marker) {
  return {
    artifactSourceCommit: B33B1_APPROVED_SOURCE_SHA,
    artifactSourceTree: B33B1_APPROVED_SOURCE_TREE,
    candidateTuple: B33B1_APPROVED_ARTIFACT_TUPLE,
    groupIdHex: marker.repeat(32).slice(0, 32),
    finalEpoch: '3',
    finalGroupContextSha256Hex: hex(`${marker}a`),
    finalRosterSha256Hex: hex(`${marker}b`),
    transitionCount: 2,
    applicationRecordCount: 4,
    freshProcessRecoveryCount: 3,
    mdkBuildEvidence: {
      cargoCommand: 'cargo build --locked --target-dir <fresh-build-child>',
      cargoVersion: 'cargo 1.96.0',
      mdkExecutableSha256Hex: hex('e'),
      mdkPeerCargoLockSha256Hex: B33B1_MDK_LOCK_SHA256,
    },
    operationSequence: B33B1_STAGE1_OPERATION_SEQUENCE,
    participantSetSha256Hex: hex(`${marker}c`),
    retentionPolicy: 5,
    sourceCommit: '1'.repeat(40),
    sourceTree: '2'.repeat(40),
    mdkPreparedCommitRecoveredExactly: true,
    styxLocalCommitRetriedExactly: true,
    retainedTrafficAcceptedBothDirections: true,
    retainedTrafficReplayRejectedBothDirections: true,
  };
}

describe('B3.3b-1 Stage 2 paired evidence', () => {
  test('accepts two exact-head reproducible and disjoint bounded GO runs', () => {
    expect(validateStage2Pair(run('3'), run('4'))).toEqual(expect.objectContaining({
      claim: 'B3.3b-1 BOUNDED_GO',
      sourceCommit: '1'.repeat(40),
      sourceTree: '2'.repeat(40),
    }));
  });

  test.each([
    ['artifact tuple', (value) => { value.candidateTuple = {}; }],
    ['group identifier', (value) => { value.groupIdHex = hex('f'); }],
    ['operation sequence', (value) => { value.operationSequence = []; }],
    ['retention', (value) => { value.retentionPolicy = 4; }],
    ['fresh-process recovery', (value) => { value.freshProcessRecoveryCount = 2; }],
    ['locked MDK build', (value) => { value.mdkBuildEvidence.mdkPeerCargoLockSha256Hex = hex('f'); }],
  ])('rejects %s drift', (_label, mutate) => {
    const value = run('3');
    mutate(value);
    expect(() => validateStage2Run(value)).toThrow(expect.objectContaining({
      code: 'B33B1_BLOCKED',
    }));
  });

  test.each([
    ['group', (first, second) => { second.groupIdHex = first.groupIdHex; }],
    ['participants', (first, second) => {
      second.participantSetSha256Hex = first.participantSetSha256Hex;
    }],
    ['source', (_first, second) => { second.sourceCommit = '9'.repeat(40); }],
    ['MDK executable', (_first, second) => {
      second.mdkBuildEvidence.mdkExecutableSha256Hex = hex('d');
    }],
  ])('rejects paired %s non-disjointness or drift', (_label, mutate) => {
    const first = run('3');
    const second = run('4');
    mutate(first, second);
    expect(() => validateStage2Pair(first, second)).toThrow(expect.objectContaining({
      code: 'B33B1_BLOCKED',
    }));
  });
});
