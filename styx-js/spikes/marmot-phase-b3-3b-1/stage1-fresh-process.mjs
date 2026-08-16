// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — fresh-process B3.3b-1 recovery executor.

import {
  B33B1_ERROR, B33B1_PRIVATE_ROOT, clearBytes, exactFields, failB33b1,
} from './b3-3b-1-canonical.mjs';
import { B33b1EvolutionAdapter } from './b3-3b-1-engine-adapter.mjs';
import { openB33b1FileJournal } from './b3-3b-1-journal.mjs';
import { loadCandidate } from './stage1-probe.mjs';
import { verifyPins } from './verify-pins.mjs';

const HEAD_FIELDS = Object.freeze([
  'committedCommitSha256Hex', 'epochDec', 'groupContextSha256Hex', 'groupIdHex',
  'headDigestHex', 'rosterSha256Hex',
]);

function checkpoint(head) {
  return exactFields({
    committedCommitSha256Hex: head.committedCommitSha256Hex,
    epochDec: head.epochDec,
    groupContextSha256Hex: head.groupContextSha256Hex,
    groupIdHex: head.groupIdHex,
    headDigestHex: head.headDigestHex,
    rosterSha256Hex: head.rosterSha256Hex,
  }, HEAD_FIELDS, 'fresh-process checkpoint');
}

async function main() {
  const [action, artifactSelector, journalDirectory, ...rest] = process.argv.slice(2);
  if (rest.length !== 0 || !['apply-staged-inbound', 'retry-local',
    'merge-accepted-local'].includes(action) || !artifactSelector || !journalDirectory) {
    failB33b1(B33B1_ERROR.INVALID, 'invalid fresh-process recovery invocation');
  }
  const candidatePath = artifactSelector === '--installed' ? undefined : artifactSelector;
  const pins = verifyPins(candidatePath);
  const loaded = await loadCandidate(candidatePath, pins.candidateTuple);
  const journal = openB33b1FileJournal(journalDirectory, B33B1_PRIVATE_ROOT);
  const adapter = new B33b1EvolutionAdapter({ journal, wasm: loaded.wasm });
  let result;
  try {
    if (action === 'apply-staged-inbound') {
      result = await adapter.applyStagedInbound();
      return { action, head: checkpoint(result.head), processId: process.pid };
    }
    if (action === 'retry-local') {
      result = await adapter.retryLocal();
      return {
        action,
        commitHex: Buffer.from(result.commitBytes).toString('hex'),
        commitSha256Hex: result.commitSha256Hex,
        headDigestHex: result.headDigestHex,
        processId: process.pid,
        projection: result.projection,
      };
    }
    result = await adapter.mergeAcceptedLocal();
    return { action, head: checkpoint(result.head), processId: process.pid };
  } finally {
    clearBytes(result?.commitBytes);
    clearBytes(result?.stateBytes);
    clearBytes(result?.parentStateBytes);
    clearBytes(result?.pendingStateBytes);
    clearBytes(loaded.wasmBytes);
  }
}

try {
  const output = await main();
  process.stdout.write(`${JSON.stringify(output)}\n`);
} catch (error) {
  process.stderr.write(`${JSON.stringify({
    code: error?.code ?? 'UNEXPECTED',
    message: error instanceof Error ? error.message : `${error}`,
  })}\n`);
  process.exitCode = 1;
}
