// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  B33B1_BUILD_ROOT,
  B33B1_GENERATED_FILES,
  B33B1_MAX_PAST_EPOCHS,
  B33B1_PROVIDER_FORMAT,
} from '../../spikes/marmot-phase-b3-3b-1/b3-3b-1-canonical.mjs';
import { runStage0Probe }
  from '../../spikes/marmot-phase-b3-3b-1/stage0-probe.mjs';
import {
  B33B1_APPROVED_ARTIFACT_TUPLE,
  candidateTuple,
  installedArtifactTuple,
}
  from '../../spikes/marmot-phase-b3-3b-1/verify-pins.mjs';

describe('Phase B3.3b-1 Stage 0 exact-pin capabilities', () => {
  test('freezes the private candidate root and retained-state format', () => {
    expect(B33B1_BUILD_ROOT).toBe(
      '/home/mverde/.local/share/styx-b3-3b-1-builds/issue-188',
    );
    expect(B33B1_PROVIDER_FORMAT).toBe('phase-b33b1-provider-canonical-v1');
    expect(B33B1_MAX_PAST_EPOCHS).toBe(5);
    expect(B33B1_GENERATED_FILES).toEqual([
      'openmls_wasm.js', 'openmls_wasm.d.ts', 'openmls_wasm_bg.wasm',
      'openmls_wasm_bg.wasm.d.ts', 'package.json',
    ]);
  });

  test('binds the installed runtime to the owner-approved Stage 2 tuple', () => {
    expect(Object.isFrozen(B33B1_APPROVED_ARTIFACT_TUPLE)).toBe(true);
    expect(installedArtifactTuple()).toEqual(B33B1_APPROVED_ARTIFACT_TUPLE);
  });

  test('candidate is exact and pinned MDK accepts the Styx self-update', async () => {
    const candidate = process.env.B33B1_CANDIDATE_DIR;
    if (candidate) {
      expect(Object.keys(candidateTuple(candidate)).sort())
        .toEqual([...B33B1_GENERATED_FILES].sort());
    }
    const result = await runStage0Probe(candidate);
    expect(result).toEqual(expect.objectContaining({
      finalEpoch: '3',
      mdkSemanticallyAcceptedStyxSelfUpdate: true,
      mdkStyxSelfUpdateInitialDisposition: 'group_evolution_buffered',
      mdkStyxSelfUpdateReplayDisposition: 'duplicate',
      retentionPolicy: 5,
    }));
  }, 600_000);
});
