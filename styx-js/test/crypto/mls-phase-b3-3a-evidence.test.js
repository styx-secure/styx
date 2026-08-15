// SPDX-License-Identifier: AGPL-3.0-or-later

import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  B31_FORMAT,
  validateB31Report,
} from '../../spikes/marmot-phase-b3-1/b3-1-canonical.mjs';
import {
  B32Journal,
  MemoryB32Store,
  parseB32Head,
} from '../../spikes/marmot-phase-b3-2/b3-2-journal.mjs';
import { B32A_PREPARATION }
  from '../../spikes/marmot-phase-b3-2a/b3-2a-canonical.mjs';
import {
  B32aJournal,
  MemoryB32aStore,
  parseB32aHead,
} from '../../spikes/marmot-phase-b3-2a/b3-2a-journal.mjs';
import { b32aFixture }
  from '../../spikes/marmot-phase-b3-2a/b3-2a-test-support.mjs';
import {
  B33A_REPORT_FORMAT,
  appendB33aTranscript,
  validateB33aReport,
  validateB33aTranscript,
} from '../../spikes/marmot-phase-b3-3a/b3-3a-canonical.mjs';
import { readExactRegularFile }
  from '../../spikes/marmot-phase-b3-3a/b3-3a-artifact-reader.mjs';
import {
  B33aJournal,
  MemoryB33aStore,
  parseB33aHead,
} from '../../spikes/marmot-phase-b3-3a/b3-3a-journal.mjs';

const digest = (marker) => marker.repeat(64).slice(0, 64);

async function heads() {
  const b32 = new B32Journal(new MemoryB32Store());
  const b32Head = await b32.initializeStable({
    predecessorState: Uint8Array.from([1]),
    keyPackage: Uint8Array.from([2]),
    accountIdentityHex: '11'.repeat(32),
    leafSignatureKeyHex: '22'.repeat(32),
    expectedAuthorHex: '33'.repeat(32),
  });

  const values = b32aFixture();
  const b32a = new B32aJournal(new MemoryB32aStore());
  await b32a.initializeStable({
    predecessorState: values.predecessor,
    keyPackage: values.keyPackage,
    accountIdentityHex: values.joiner.identityHex,
    leafSignatureKeyHex: values.joiner.signatureKeyHex,
    expectedAuthorHex: values.founder.identityHex,
  });
  await b32a.recordWelcome(values.welcome);
  const b32aHead = await b32a.commitJoined(values.candidate, values.projection, {
    classification: B32A_PREPARATION.BYTE_IDENTICAL,
    secondCandidateStateSha256Hex: values.projection.candidateStateSha256Hex,
    differingStorageKeyHex: '',
  });
  const b33a = new B33aJournal(new MemoryB33aStore());
  const b33aHead = await b33a.initializeFromB32a(b32aHead, values.candidate);
  return { b32Head, b32aHead, b33aHead };
}

describe('Phase B3.3a evidence and format separation', () => {
  test('reads the exact artifact inode and rejects digest drift or symlinks', () => {
    const directory = mkdtempSync(join(tmpdir(), 'styx-b33a-artifact-'));
    const artifact = join(directory, 'artifact.bin');
    const link = join(directory, 'artifact-link.bin');
    const bytes = Buffer.from('exact immutable candidate bytes');
    const expected = createHash('sha256').update(bytes).digest('hex');
    try {
      writeFileSync(artifact, bytes);
      symlinkSync(artifact, link);
      const read = readExactRegularFile(artifact, expected);
      expect(Buffer.from(read.bytes)).toEqual(bytes);
      expect(read.sha256Hex).toBe(expected);
      expect(() => readExactRegularFile(artifact, '00'.repeat(32))).toThrow();
      expect(() => readExactRegularFile(link, expected)).toThrow();
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  test('validates a closed hash-linked GO report', () => {
    const transcript = [];
    appendB33aTranscript(transcript, 'synthetic_step', { ok: true });
    const transcriptHead = validateB33aTranscript(transcript);
    const report = {
      format: B33A_REPORT_FORMAT,
      version: 1,
      disposition: 'GO',
      claim: 'Synthetic closed report fixture.',
      applicationEventsCommitted: 4,
      bidirectionalApplicationTrafficEstablished: true,
      candidateTuple: {
        'openmls_wasm.js': digest('1'),
        'openmls_wasm.d.ts': digest('2'),
        'openmls_wasm_bg.wasm': digest('3'),
        'openmls_wasm_bg.wasm.d.ts': digest('4'),
        'package.json': digest('5'),
      },
      commitLifecycleTested: false,
      groupIdHex: '66'.repeat(16),
      replayPlaintextReleased: false,
      transcriptHeadSha256Hex: transcriptHead,
    };
    expect(validateB33aReport(report, transcriptHead)).toEqual(report);
    expect(() => validateB33aReport({ ...report, extra: true }, transcriptHead)).toThrow();
    expect(() => validateB33aReport(
      { ...report, replayPlaintextReleased: true }, transcriptHead,
    )).toThrow();
  });

  test('B3.1, B3.2, B3.2a and B3.3a readers do not cross-accept formats', async () => {
    const { b32Head, b32aHead, b33aHead } = await heads();
    expect(() => parseB32Head(b32aHead)).toThrow();
    expect(() => parseB32Head(b33aHead)).toThrow();
    expect(() => parseB32aHead(b32Head)).toThrow();
    expect(() => parseB32aHead(b33aHead)).toThrow();
    expect(() => parseB33aHead(b32Head)).toThrow();
    expect(() => parseB33aHead(b32aHead)).toThrow();
    expect(() => validateB31Report(b33aHead, b33aHead.headDigestHex)).toThrow();
    expect(() => parseB33aHead({ format: B31_FORMAT })).toThrow();
  });
});
