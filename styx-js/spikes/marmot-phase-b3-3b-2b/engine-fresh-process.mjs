// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — fresh-process OpenMLS recovery gate for B3.3b-2b.

import { readFileSync } from 'node:fs';

import { B32A_PRIVATE_ROOT }
  from '../marmot-phase-b3-2a/b3-2a-canonical.mjs';
import {
  bytesToHex,
  clearBytes,
  hexToBytes,
} from '../marmot-phase-b3-3b-1/b3-3b-1-canonical.mjs';
import { verifyPins } from '../marmot-phase-b3-3b-1/verify-pins.mjs';
import { B33B2B_ERROR, failB33b2b }
  from './b3-3b-2b-canonical.mjs';
import {
  B33b2bEvolutionAdapter,
  MemoryB33b2bEffectSink,
} from './b3-3b-2b-engine-adapter.mjs';
import { openB33b2bFileJournal } from './b3-3b-2b-journal.mjs';
import { loadCandidate } from './stage0-fork-probe.mjs';

function parseBinding(path) {
  const value = JSON.parse(readFileSync(path, 'utf8'));
  return Object.freeze({
    groupId: hexToBytes('group id', value.groupIdHex),
    ownIdentity: hexToBytes('own identity', value.ownIdentityHex, 32),
    ownSignatureKey: hexToBytes('own signature key', value.ownSignatureKeyHex, 32),
  });
}

function clearBinding(binding) {
  clearBytes(binding?.groupId);
  clearBytes(binding?.ownIdentity);
  clearBytes(binding?.ownSignatureKey);
}

async function run() {
  const [action, bindingPath, journalDirectory, rawCandidatePath, rivalCommitPath]
    = process.argv.slice(2);
  if (!action || !bindingPath || !journalDirectory) {
    failB33b2b(B33B2B_ERROR.INVALID, 'fresh-process adapter arguments are incomplete');
  }
  const candidatePath = rawCandidatePath || undefined;
  const pins = verifyPins(candidatePath);
  const loaded = await loadCandidate(candidatePath, pins.candidateTuple);
  const binding = parseBinding(bindingPath);
  const adapter = new B33b2bEvolutionAdapter({
    binding,
    effectSink: new MemoryB33b2bEffectSink(),
    journal: openB33b2bFileJournal(journalDirectory, B32A_PRIVATE_ROOT),
    wasm: loaded.wasm,
  });
  try {
    switch (action) {
      case 'verify': {
        const result = await adapter.verifyDurableAuthority();
        return { head: result.head, verified: result.verified };
      }
      case 'retry-local': {
        const result = await adapter.retryLocal();
        try {
          return {
            commitHex: bytesToHex(result.commitBytes),
            commitSha256Hex: result.commitSha256Hex,
          };
        } finally {
          clearBytes(result.commitBytes);
        }
      }
      case 'record-rival': {
        if (!rivalCommitPath) {
          failB33b2b(B33B2B_ERROR.INVALID, 'record-rival requires exact Commit bytes');
        }
        const rivalCommit = Uint8Array.from(readFileSync(rivalCommitPath));
        try { return await adapter.recordRival(rivalCommit); }
        finally { clearBytes(rivalCommit); }
      }
      case 'freeze': return adapter.freezeRace();
      case 'prepare': return adapter.prepareSettlement();
      case 'commit': return adapter.commitStable();
      default:
        failB33b2b(B33B2B_ERROR.INVALID, `unknown fresh-process action ${action}`);
    }
  } finally {
    adapter.close();
    clearBinding(binding);
    clearBytes(loaded.wasmBytes);
  }
  return undefined;
}

try {
  const result = await run();
  process.stdout.write(`${JSON.stringify(result)}\n`);
} catch (error) {
  process.stderr.write(`${JSON.stringify({
    code: error?.code ?? null,
    details: error?.details ?? null,
    message: error instanceof Error ? error.message : `${error}`,
  })}\n`);
  process.exitCode = 1;
}
