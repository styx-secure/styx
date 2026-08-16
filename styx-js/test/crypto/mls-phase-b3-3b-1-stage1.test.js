// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  B33B1_STAGE1_OPERATION_SEQUENCE, createB33b1Stage1OperationTrace, runStage1Probe,
}
  from '../../spikes/marmot-phase-b3-3b-1/stage1-probe.mjs';

const candidateDirectory = process.env.B33B1_CANDIDATE_DIR;

describe('Phase B3.3b-1 Stage 1 journalled sequence', () => {
  test('operation trace fails closed on omission, duplication, reordering, and unknown work', () => {
    const expectBlocked = (action) => expect(action).toThrow(expect.objectContaining({
      code: 'B33B1_BLOCKED',
    }));

    const omitted = createB33b1Stage1OperationTrace();
    omitted.advance(B33B1_STAGE1_OPERATION_SEQUENCE[0]);
    expectBlocked(() => omitted.complete());

    const duplicated = createB33b1Stage1OperationTrace();
    duplicated.advance(B33B1_STAGE1_OPERATION_SEQUENCE[0]);
    expectBlocked(() => duplicated.advance(B33B1_STAGE1_OPERATION_SEQUENCE[0]));

    const reordered = createB33b1Stage1OperationTrace();
    expectBlocked(() => reordered.advance(B33B1_STAGE1_OPERATION_SEQUENCE[1]));

    const unknown = createB33b1Stage1OperationTrace();
    expectBlocked(() => unknown.advance('unknown-operation'));

    const complete = createB33b1Stage1OperationTrace();
    B33B1_STAGE1_OPERATION_SEQUENCE.forEach((operation) => complete.advance(operation));
    expect(complete.complete()).toEqual(B33B1_STAGE1_OPERATION_SEQUENCE);
    expectBlocked(() => complete.advance(B33B1_STAGE1_OPERATION_SEQUENCE[0]));
  });

  test('recovers both commit directions and retained application traffic', async () => {
    expect(candidateDirectory).toBeTruthy();
    const report = await runStage1Probe(candidateDirectory);
    expect(report).toEqual(expect.objectContaining({
      finalEpoch: '3',
      freshProcessRecoveryCount: 3,
      transitionCount: 2,
      mdkPreparedCommitRecoveredExactly: true,
      styxLocalCommitRetriedExactly: true,
      retainedTrafficAcceptedBothDirections: true,
      retainedTrafficReplayRejectedBothDirections: true,
    }));
    expect(report.operationSequence).toEqual(B33B1_STAGE1_OPERATION_SEQUENCE);
    expect(report.applicationRecordCount).toBeGreaterThanOrEqual(4);
  }, 240_000);
});
