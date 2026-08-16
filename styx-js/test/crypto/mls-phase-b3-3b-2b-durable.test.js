// SPDX-License-Identifier: AGPL-3.0-or-later

import { runConcurrentForkProbe }
  from '../../spikes/marmot-phase-b3-3b-2b/concurrent-fork-probe.mjs';

describe('Phase B3.3b-2b exact-pin durable concurrent fork', () => {
  test('converges both winner assignments and arrival modes through the journal', async () => {
    const result = await runConcurrentForkProbe({
      candidatePath: process.env.B33B2B_CANDIDATE_DIR,
    });
    expect(result.verdict).toBe('B33B2B=BOUNDED_GO');
    expect(result.pairedRunsVerified).toBe(false);
    expect(result.scenarios).toHaveLength(4);
    for (const scenario of result.scenarios) {
      expect(scenario.expectedWinner).toBe(scenario.desiredWinner);
      expect(scenario.journalEvidence).toEqual(expect.objectContaining({
        effectCount: 1,
        state: 'STABLE',
      }));
      expect(['accepted', 'duplicate'])
        .toContain(scenario.journalEvidence.effectDisposition);
      expect(scenario.journalEvidence.injectedAfterAcceptance).toBe(
        scenario.desiredWinner === 'styx' && scenario.deliveryMode === 'after_restart',
      );
      expect(scenario.journalEvidence.selectedCommitSha256Hex)
        .toMatch(/^[0-9a-f]{64}$/);
      expect(scenario.journalEvidence.frozenSetDigestHex)
        .toMatch(/^[0-9a-f]{64}$/);
    }
  }, 600_000);
});
