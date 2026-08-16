// SPDX-License-Identifier: AGPL-3.0-or-later

import { B33A_MDK_PEER_LOCK_SHA256 }
  from '../../spikes/marmot-phase-b3-3a/b3-3a-mdk-builder.mjs';
import {
  B33B1_APPROVED_ARTIFACT_TUPLE, B33B1_APPROVED_SOURCE_SHA,
  B33B1_APPROVED_SOURCE_TREE,
} from '../../spikes/marmot-phase-b3-3b-1/verify-pins.mjs';
import { B33B2A_OPERATION_SEQUENCE }
  from '../../spikes/marmot-phase-b3-3b-2a/b3-3b-2a-canonical.mjs';
import {
  validateRetainedWindowPair, validateRetainedWindowRun,
} from '../../spikes/marmot-phase-b3-3b-2a/paired-evidence.mjs';

const digest = (marker) => marker.repeat(64).slice(0, 64);

function report(marker) {
  return {
    alternateUpdateAuthors: true,
    applicationRecordCount: 5,
    artifactSourceCommit: B33B1_APPROVED_SOURCE_SHA,
    artifactSourceTree: B33B1_APPROVED_SOURCE_TREE,
    callerMetadataIgnored: true,
    candidateTuple: B33B1_APPROVED_ARTIFACT_TUPLE,
    corruptedInWindowRejectedWithoutMutation: true,
    finalEpoch: '7',
    finalGroupContextSha256Hex: digest(`${marker}a`),
    finalRosterSha256Hex: digest(`${marker}b`),
    freshProcessRecoveryCount: 9,
    freshStyxReceiverCount: 8,
    futureEpochRejectedWithoutMutation: true,
    groupIdHex: marker.repeat(32).slice(0, 32),
    mdkBuildEvidence: {
      cargoCommand: 'cargo build --locked --target-dir <fresh-build-child>',
      cargoVersion: 'cargo 1.96.0',
      mdkExecutableSha256Hex: digest('e'),
      mdkPeerCargoLockSha256Hex: B33A_MDK_PEER_LOCK_SHA256,
    },
    mdkDistance6Reason: { Ignored: { category: 'BeyondAppRetention' } },
    operationSequence: B33B2A_OPERATION_SEQUENCE,
    participantSetSha256Hex: digest(`${marker}c`),
    rejectedDistance: 6,
    retainedDistances: [4, 5],
    retainedWindowAcceptedBothDirectionsExactlyOnce: true,
    retentionPolicy: 5,
    safeCaseEvidence: Array.from({ length: 10 }, (_, index) => ({
      caseId: `case-${index}`,
      ciphertextSha256Hex: digest(`${index + 1}`),
      direction: index % 2 === 0 ? 'MDK_TO_STYX' : 'STYX_TO_MDK',
      messageEpoch: index < 2 ? '2' : '3',
      outcome: { accepted: index >= 4 && index < 8 },
      referenceTipEpoch: index < 2 ? '1' : '7',
    })),
    sourceCommit: '1'.repeat(40),
    sourceTree: '2'.repeat(40),
    staleWindowRejectedBothDirectionsWithoutMutation: true,
    transitionCount: 6,
  };
}

describe('B3.3b-2a paired evidence validation', () => {
  test('accepts two disjoint exact-head GO runs', () => {
    const first = report('3');
    const second = report('4');
    second.mdkBuildEvidence.mdkExecutableSha256Hex = digest('d');
    expect(validateRetainedWindowPair(first, second)).toEqual(expect.objectContaining({
      claim: 'B3.3b-2a BOUNDED_GO',
    }));
  });

  test.each([
    ['retention policy', (value) => { value.retentionPolicy = 4; }],
    ['distance boundary', (value) => { value.rejectedDistance = 5; }],
    ['operation sequence', (value) => { value.operationSequence = []; }],
    ['typed MDK reason', (value) => { value.mdkDistance6Reason = null; }],
    ['fresh process count', (value) => { value.freshProcessRecoveryCount = 8; }],
    ['case evidence', (value) => { value.safeCaseEvidence = []; }],
    ['locked build', (value) => { value.mdkBuildEvidence.mdkPeerCargoLockSha256Hex = digest('f'); }],
  ])('rejects %s drift', (_label, mutate) => {
    const value = report('3');
    mutate(value);
    expect(() => validateRetainedWindowRun(value)).toThrow(expect.objectContaining({
      code: 'B33B2A_BLOCKED',
    }));
  });
});
