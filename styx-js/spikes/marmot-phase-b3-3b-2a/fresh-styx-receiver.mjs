// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — isolated fresh-process retained-message receiver.

import { B33B1_PRIVATE_ROOT, clearBytes }
  from '../marmot-phase-b3-3b-1/b3-3b-1-canonical.mjs';
import { B33b1EvolutionAdapter }
  from '../marmot-phase-b3-3b-1/b3-3b-1-engine-adapter.mjs';
import { openB33b1FileJournal }
  from '../marmot-phase-b3-3b-1/b3-3b-1-journal.mjs';
import { loadCandidate } from '../marmot-phase-b3-3b-1/stage1-probe.mjs';
import { verifyPins } from '../marmot-phase-b3-3b-1/verify-pins.mjs';

function checkpoint(recovery) {
  return Object.freeze({
    epochDec: recovery.head.epochDec,
    headDigestHex: recovery.head.headDigestHex,
    applicationRecordCount: recovery.head.applicationRecords.length,
  });
}

async function main() {
  const [artifactSelector, journalDirectory, ciphertextHex, forgedMetadataJson, ...rest]
    = process.argv.slice(2);
  if (rest.length !== 0 || !artifactSelector || !journalDirectory
    || typeof ciphertextHex !== 'string' || ciphertextHex.length < 2
    || ciphertextHex.length % 2 !== 0 || !/^[0-9a-f]+$/.test(ciphertextHex)
    || !forgedMetadataJson) {
    throw Object.assign(new Error('invalid fresh Styx receiver invocation'), {
      code: 'B33B2A_INVALID',
    });
  }
  const forgedMetadata = JSON.parse(forgedMetadataJson);
  const candidatePath = artifactSelector === '--installed' ? undefined : artifactSelector;
  const pins = verifyPins(candidatePath);
  const loaded = await loadCandidate(candidatePath, pins.candidateTuple);
  const journal = openB33b1FileJournal(journalDirectory, B33B1_PRIVATE_ROOT);
  const adapter = new B33b1EvolutionAdapter({ journal, wasm: loaded.wasm });
  const ciphertextBytes = Uint8Array.from(Buffer.from(ciphertextHex, 'hex'));
  let before;
  let after;
  let result;
  try {
    before = await journal.readRecovery();
    const beforeCheckpoint = checkpoint(before);
    clearBytes(before.stateBytes);
    before = undefined;
    try {
      // The second argument is deliberately caller-forged. The adapter accepts only the
      // ciphertext and must derive all security metadata from authenticated MLS output.
      result = await adapter.receiveApplication(ciphertextBytes, forgedMetadata);
      after = await journal.readRecovery();
      return Object.freeze({
        accepted: true,
        after: checkpoint(after),
        before: beforeCheckpoint,
        disposition: result.disposition,
        evidence: result.evidence ?? null,
        plaintextSha256Hex: result.plaintextSha256Hex ?? null,
        processId: process.pid,
      });
    } catch (error) {
      after = await journal.readRecovery();
      return Object.freeze({
        accepted: false,
        after: checkpoint(after),
        before: beforeCheckpoint,
        errorCode: error?.code ?? 'UNEXPECTED',
        errorMessage: error instanceof Error ? error.message : `${error}`,
        processId: process.pid,
      });
    }
  } finally {
    clearBytes(before?.stateBytes);
    clearBytes(after?.stateBytes);
    clearBytes(result?.plaintextBytes);
    clearBytes(ciphertextBytes);
    clearBytes(loaded.wasmBytes);
  }
}

try {
  process.stdout.write(`${JSON.stringify(await main())}\n`);
} catch (error) {
  process.stderr.write(`${JSON.stringify({
    code: error?.code ?? 'UNEXPECTED',
    message: error instanceof Error ? error.message : `${error}`,
  })}\n`);
  process.exitCode = 1;
}
