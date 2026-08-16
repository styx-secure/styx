// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  B33B2A_OPERATION_SEQUENCE, createB33b2aOperationTrace,
} from '../../spikes/marmot-phase-b3-3b-2a/b3-3b-2a-canonical.mjs';
import { runRetainedWindowProbe }
  from '../../spikes/marmot-phase-b3-3b-2a/retained-window-probe.mjs';

const candidateDirectory = process.env.B33B1_CANDIDATE_DIR;

describe('Phase B3.3b-2a exact retained application window', () => {
  test('operation trace rejects omission, duplication, reordering, and unknown work', () => {
    const blocked = (action) => expect(action).toThrow(expect.objectContaining({
      code: 'B33B2A_BLOCKED',
    }));
    const omitted = createB33b2aOperationTrace();
    omitted.advance(B33B2A_OPERATION_SEQUENCE[0]);
    blocked(() => omitted.complete());
    const duplicate = createB33b2aOperationTrace();
    duplicate.advance(B33B2A_OPERATION_SEQUENCE[0]);
    blocked(() => duplicate.advance(B33B2A_OPERATION_SEQUENCE[0]));
    const reordered = createB33b2aOperationTrace();
    blocked(() => reordered.advance(B33B2A_OPERATION_SEQUENCE[1]));
    blocked(() => createB33b2aOperationTrace().advance('unknown'));
    const complete = createB33b2aOperationTrace();
    B33B2A_OPERATION_SEQUENCE.forEach((operation) => complete.advance(operation));
    expect(complete.complete()).toEqual(B33B2A_OPERATION_SEQUENCE);
  });

  test('proves distances 4/5 accepted and distance 6 rejected in both directions', async () => {
    const report = await runRetainedWindowProbe(candidateDirectory);
    expect(report).toEqual(expect.objectContaining({
      alternateUpdateAuthors: true,
      finalEpoch: '7',
      freshProcessRecoveryCount: 9,
      freshStyxReceiverCount: 7,
      rejectedDistance: 6,
      retainedDistances: [4, 5],
      retentionPolicy: 5,
      retainedWindowAcceptedBothDirectionsExactlyOnce: true,
      staleWindowRejectedBothDirectionsWithoutMutation: true,
      transitionCount: 6,
    }));
    expect(report.operationSequence).toEqual(B33B2A_OPERATION_SEQUENCE);
  }, 1_200_000);
});
