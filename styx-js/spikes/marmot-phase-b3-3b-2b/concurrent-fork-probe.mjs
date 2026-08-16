// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — exact-pin bounded durable fork convergence verdict.

import { fileURLToPath } from 'node:url';

import { canonicalJsonBytes, sha256Hex }
  from '../marmot-phase-b3-3b-1/b3-3b-1-canonical.mjs';
import { verifyPins } from '../marmot-phase-b3-3b-1/verify-pins.mjs';
import { B33B2B_ERROR, failB33b2b } from './b3-3b-2b-canonical.mjs';
import { runDurableForkProbe } from './stage0-fork-probe.mjs';

function normalizedScenario(scenario) {
  return Object.freeze({
    deliveryMode: scenario.deliveryMode,
    desiredWinner: scenario.desiredWinner,
    effectCount: scenario.journalEvidence?.effectCount,
    effectDisposition: scenario.journalEvidence?.effectDisposition,
    expectedWinner: scenario.expectedWinner,
    finalState: scenario.journalEvidence?.state,
    initialDisposition: scenario.initialDisposition,
    injectedAfterAcceptance: scenario.journalEvidence?.injectedAfterAcceptance,
    selectionDisposition: scenario.selection?.disposition ?? scenario.selection?.status,
    decisiveRule: scenario.selection?.decisiveRule ?? null,
    deferredReason: scenario.selection?.deferredReason ?? null,
    winnerSideClassification: scenario.selection?.winnerSideClassification ?? null,
  });
}

function normalize(run) {
  return Object.freeze(run.scenarios.map(normalizedScenario)
    .sort((left, right) => `${left.desiredWinner}:${left.deliveryMode}`
      .localeCompare(`${right.desiredWinner}:${right.deliveryMode}`)));
}

function validateRun(run) {
  if (run.scenarios.length !== 4) {
    failB33b2b(B33B2B_ERROR.ENGINE_REJECTED,
      'durable proof did not execute the four bounded scenarios');
  }
  for (const scenario of run.scenarios) {
    if (scenario.expectedWinner !== scenario.desiredWinner
      || scenario.journalEvidence?.state !== 'STABLE'
      || scenario.journalEvidence?.effectCount !== 1
      || (scenario.deliveryMode === 'after_restart'
        && scenario.journalEvidence?.selectedCommitSha256Hex
          !== scenario.selection?.selectedCommitSha256Hex)) {
      failB33b2b(B33B2B_ERROR.ENGINE_REJECTED,
        'durable scenario did not reach one converged stable result', { scenario });
    }
  }
}

export async function runConcurrentForkProbe({
  candidatePath = undefined, verifyPairedRuns = false,
} = {}) {
  const pins = verifyPins(candidatePath);
  const runs = [await runDurableForkProbe(candidatePath)];
  validateRun(runs[0]);
  if (verifyPairedRuns) {
    runs.push(await runDurableForkProbe(candidatePath));
    validateRun(runs[1]);
    const first = normalize(runs[0]);
    const second = normalize(runs[1]);
    if (JSON.stringify(first) !== JSON.stringify(second)) {
      failB33b2b(B33B2B_ERROR.ENGINE_REJECTED,
        'paired clean runs changed their normalized bounded verdicts');
    }
  }
  const normalized = normalize(runs[0]);
  return Object.freeze({
    verdict: 'B33B2B=BOUNDED_GO',
    pins: Object.freeze({
      artifactSourceCommit: pins.artifactSourceCommit,
      artifactSourceTree: pins.artifactSourceTree,
      artifactTuple: pins.candidateTuple,
      marmotRevision: pins.marmotRevision,
      mdkRevision: pins.mdkRevision,
      mdkTree: pins.mdkTree,
      openMlsRevision: pins.openMlsRevision,
      sourceCommit: pins.sourceCommit,
      sourceTree: pins.sourceTree,
    }),
    normalizedVerdictSha256Hex: sha256Hex(canonicalJsonBytes(normalized)),
    pairedRunsVerified: verifyPairedRuns,
    runCount: runs.length,
    scenarios: runs[0].scenarios,
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const arguments_ = process.argv.slice(2);
    const verifyPairedRuns = arguments_.includes('--verify-paired-runs');
    const paths = arguments_.filter((value) => value !== '--verify-paired-runs');
    if (paths.length > 1) {
      failB33b2b(B33B2B_ERROR.INVALID, 'expected at most one candidate artifact path');
    }
    const result = await runConcurrentForkProbe({
      candidatePath: paths[0], verifyPairedRuns,
    });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`${JSON.stringify({
      code: error?.code ?? null,
      details: error?.details ?? null,
      message: error instanceof Error ? error.message : `${error}`,
      name: error?.name ?? 'Error',
    }, null, 2)}\n`);
    process.exitCode = 1;
  }
}
