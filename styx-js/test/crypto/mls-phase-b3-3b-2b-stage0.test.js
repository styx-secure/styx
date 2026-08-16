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

  test('freezes stored convergence and pairwise recovery for both winners', async () => {
    const result = await runStage0ForkProbe(process.env.B33B2B_CANDIDATE_DIR);
    expect(result.mdkRevision)
      .toBe('9396adb6aa6b95b521a7979facd5ea7040c07288');
    expect(result.scenarios).toHaveLength(4);
    const byKey = new Map(result.scenarios.map((scenario) => [
      `${scenario.desiredWinner}:${scenario.deliveryMode}`, scenario,
    ]));

    for (const winner of ['styx', 'mdk']) {
      const stored = byKey.get(`${winner}:after_restart`);
      expect(stored).toEqual(expect.objectContaining({
        deliveryMode: 'after_restart',
        desiredWinner: winner,
        expectedWinner: winner,
        initialDisposition: 'buffered',
        sourceEpoch: '1',
        targetEpoch: '2',
      }));
      expect(stored.selection).toEqual(expect.objectContaining({
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
        expect(stored[field]).toMatch(/^[0-9a-f]{64}$/);
      }

      const pairwise = byKey.get(`${winner}:before_restart`);
      expect(pairwise).toEqual(expect.objectContaining({
        deliveryMode: 'before_restart',
        desiredWinner: winner,
        expectedWinner: winner,
        sourceEpoch: '1',
        targetEpoch: '2',
      }));
      if (winner === 'styx') {
        expect(pairwise.initialDisposition).toBe('processed');
        expect(pairwise.selection).toEqual({
          disposition: 'processed',
          eventKinds: [
            'fork_recovered', 'group_state_invalidated', 'epoch_changed',
          ],
          winnerSideClassification: null,
        });
      } else {
        expect(pairwise.initialDisposition).toBe('stale');
        expect(pairwise.selection).toEqual({
          disposition: 'stale',
          eventKinds: [],
          winnerSideClassification: 'already_at_epoch',
        });
      }
    }
  }, 600_000);
});
