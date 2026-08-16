// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — isolated file-journal recovery observer.

import { fileURLToPath } from 'node:url';

import { clearBytes } from '../marmot-phase-b3-3b-1/b3-3b-1-canonical.mjs';
import { B33B2B_ERROR, failB33b2b } from './b3-3b-2b-canonical.mjs';
import { openB33b2bFileJournal } from './b3-3b-2b-journal.mjs';

async function main() {
  const [journalDirectory, approvedRoot, ...rest] = process.argv.slice(2);
  if (!journalDirectory || !approvedRoot || rest.length !== 0) {
    failB33b2b(B33B2B_ERROR.INVALID, 'invalid fresh-process journal invocation');
  }
  const recovery = await openB33b2bFileJournal(
    journalDirectory, approvedRoot,
  ).readRecovery();
  try {
    process.stdout.write(`${JSON.stringify({
      canonicalCommitSha256Hex: recovery.head.canonical.commitSha256Hex,
      canonicalGroupContextSha256Hex: recovery.head.canonical.groupContextSha256Hex,
      canonicalStateSha256Hex: recovery.head.canonical.stateBlobSha256Hex,
      effectDelivered: recovery.head.settlement?.effectDelivered ?? null,
      effectIdHex: recovery.head.settlement?.effectIdHex ?? null,
      forkEpoch: recovery.head.forkEpoch,
      frozenSetDigestHex: recovery.head.frozenSetDigestHex,
      headDigestHex: recovery.head.headDigestHex,
      processId: process.pid,
      selectedCommitSha256Hex: recovery.head.selectedCommitSha256Hex,
      state: recovery.head.state,
    })}\n`);
  } finally {
    for (const field of [
      'canonicalStateBytes', 'parentStateBytes', 'localCommitBytes',
      'rivalCommitBytes', 'successorStateBytes', 'settlementRecordBytes',
    ]) clearBytes(recovery[field]);
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { await main(); } catch (error) {
    process.stderr.write(`${JSON.stringify({
      code: error?.code ?? null,
      message: error instanceof Error ? error.message : `${error}`,
    })}\n`);
    process.exitCode = 1;
  }
}
