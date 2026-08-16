// SPDX-License-Identifier: AGPL-3.0-or-later

import { runStage1Probe }
  from '../../spikes/marmot-phase-b3-3b-1/stage1-probe.mjs';

const candidateDirectory = process.env.B33B1_CANDIDATE_DIR;

describe('Phase B3.3b-1 Stage 1 journalled sequence', () => {
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
    expect(report.applicationRecordCount).toBeGreaterThanOrEqual(4);
  }, 240_000);
});
