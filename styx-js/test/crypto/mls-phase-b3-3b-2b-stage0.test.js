// SPDX-License-Identifier: AGPL-3.0-or-later

import { compareIdentityHex }
  from '../../spikes/marmot-phase-b3-3b-2b/b3-3b-2b-canonical.mjs';
import { runStage0ForkProbe }
  from '../../spikes/marmot-phase-b3-3b-2b/stage0-fork-probe.mjs';

describe('Phase B3.3b-2b Stage 0 exact-pin concurrent fork', () => {
  test('orders canonical account identities as unsigned raw bytes', () => {
    expect(compareIdentityHex('00'.repeat(32), 'ff'.repeat(32))).toBe(-1);
    expect(compareIdentityHex('ff'.repeat(32), '00'.repeat(32))).toBe(1);
    expect(() => compareIdentityHex('00'.repeat(32), '00'.repeat(32)))
      .toThrow(/distinct canonical/);
  });

  test('settles every same-epoch rival through stored convergence for both winners', async () => {
    const result = await runStage0ForkProbe(process.env.B33B2B_CANDIDATE_DIR);
    expect(result.mdkRevision)
      .toBe('3fb4b4759ac676b0c21c4c3527074866c9fa4c89');
    expect(result.scenarios).toHaveLength(4);
    const byKey = new Map(result.scenarios.map((scenario) => [
      `${scenario.desiredWinner}:${scenario.deliveryMode}`, scenario,
    ]));

    // MDK removed the committer's pairwise fast path (marmot-protocol/mdk#1293):
    // a rival delivered before or after a restart is buffered at its source
    // epoch and settled by the same distributed-convergence pass.
    for (const winner of ['styx', 'mdk']) {
      for (const deliveryMode of ['after_restart', 'before_restart']) {
        const scenario = byKey.get(`${winner}:${deliveryMode}`);
        expect(scenario).toEqual(expect.objectContaining({
          deliveryMode,
          desiredWinner: winner,
          expectedWinner: winner,
          initialDisposition: 'buffered',
          sourceEpoch: '1',
          targetEpoch: '2',
        }));
        expect(scenario.selection).toEqual(expect.objectContaining({
          candidateCount: 2,
          decisiveRule: 'tip_committer',
          deferredReason: 'nonselectedeligiblebranch',
          eligibleCount: 2,
          status: 'settled',
        }));
        for (const field of [
          'groupIdDigest', 'parentGroupContextSha256Hex', 'rosterDigest',
          'selectedGroupContextSha256Hex',
        ]) {
          expect(scenario[field]).toMatch(/^[0-9a-f]{64}$/);
        }
      }
    }
  }, 600_000);
});
