// SPDX-License-Identifier: AGPL-3.0-or-later

import { createHash } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
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
  B33A_MDK_BUILD_ROOT,
  B33A_PRIVATE_ROOT,
  B33A_RUN_ROOT,
  B33A_STAGE2_GO_OPERATIONS,
  appendB33aTranscript,
  validateB33aReport,
  validateB33aTranscript,
} from '../../spikes/marmot-phase-b3-3a/b3-3a-canonical.mjs';
import { readExactRegularFile }
  from '../../spikes/marmot-phase-b3-3a/b3-3a-artifact-reader.mjs';
import { B33A_MDK_PEER_LOCK_SHA256, executableSha256 }
  from '../../spikes/marmot-phase-b3-3a/b3-3a-mdk-builder.mjs';
import {
  B33aJournal,
  MemoryB33aStore,
  parseB33aHead,
} from '../../spikes/marmot-phase-b3-3a/b3-3a-journal.mjs';
import {
  B33A_APPROVED_ARTIFACT_TUPLE,
  B33A_MDK_LOCK_SHA256,
  B33A_MDK_REVISION,
  B33A_MDK_TREE,
  assertApprovedArtifactTuple,
  installedArtifactTuple,
} from '../../spikes/marmot-phase-b3-3a/verify-pins.mjs';

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

  test('binds both the installed runtime and candidate verifier to the approved tuple', () => {
    expect(Object.isFrozen(B33A_APPROVED_ARTIFACT_TUPLE)).toBe(true);
    expect(installedArtifactTuple()).toEqual(B33A_APPROVED_ARTIFACT_TUPLE);
    expect(assertApprovedArtifactTuple(B33A_APPROVED_ARTIFACT_TUPLE))
      .toBe(B33A_APPROVED_ARTIFACT_TUPLE);
    expect(() => assertApprovedArtifactTuple({
      ...B33A_APPROVED_ARTIFACT_TUPLE,
      'openmls_wasm_bg.wasm': '00'.repeat(32),
    })).toThrow('artifact openmls_wasm_bg.wasm drifted');
  });

  test('identifies only a stable bounded executable regular file', () => {
    const directory = mkdtempSync(join(tmpdir(), 'styx-b33a-executable-'));
    const executable = join(directory, 'peer');
    const link = join(directory, 'peer-link');
    try {
      writeFileSync(executable, '#!/bin/sh\nexit 0\n');
      chmodSync(executable, 0o700);
      symlinkSync(executable, link);
      expect(executableSha256(executable)).toBe(
        createHash('sha256').update('#!/bin/sh\nexit 0\n').digest('hex'),
      );
      expect(() => executableSha256(link)).toThrow();
      chmodSync(executable, 0o600);
      expect(() => executableSha256(executable)).toThrow('not a bounded executable regular file');
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

  test('paired Stage 2 runs, when present, bind disjoint locked MDK executables', () => {
    const names = ['stage2-final-a', 'stage2-final-b'];
    const runPaths = names.map((name) => join(B33A_RUN_ROOT, name));
    expect(existsSync(join(runPaths[0], 'report.json')))
      .toBe(existsSync(join(runPaths[1], 'report.json')));
    if (!existsSync(join(runPaths[0], 'report.json'))) return;

    const runs = runPaths.map((path, index) => {
      const report = JSON.parse(readFileSync(join(path, 'report.json'), 'utf8'));
      const transcript = JSON.parse(readFileSync(join(path, 'transcript.json'), 'utf8'));
      const transcriptHead = validateB33aTranscript(transcript);
      expect(validateB33aReport(report, transcriptHead)).toEqual(report);
      expect(report).toEqual(expect.objectContaining({
        disposition: 'GO',
        applicationEventsCommitted: 4,
        bidirectionalApplicationTrafficEstablished: true,
        candidateTuple: B33A_APPROVED_ARTIFACT_TUPLE,
        commitLifecycleTested: false,
        replayPlaintextReleased: false,
      }));
      const pins = transcript[0];
      expect(pins.operation).toBe('verify_exact_inputs');
      expect(pins.evidence).toEqual(expect.objectContaining({
        candidateTuple: B33A_APPROVED_ARTIFACT_TUPLE,
        mdkLockSha256: B33A_MDK_LOCK_SHA256,
        mdkRevision: B33A_MDK_REVISION,
        mdkTree: B33A_MDK_TREE,
      }));
      const build = transcript[1];
      expect(build.operation).toBe('build_locked_mdk_peer');
      expect(build.evidence).toEqual(expect.objectContaining({
        cargoCommand: 'cargo build --locked --target-dir <fresh-build-child>',
        mdkLockSha256: B33A_MDK_LOCK_SHA256,
        mdkPeerCargoLockSha256Hex: B33A_MDK_PEER_LOCK_SHA256,
        mdkRevision: B33A_MDK_REVISION,
        mdkTree: B33A_MDK_TREE,
      }));
      expect(build.evidence.cargoVersion).toMatch(/^cargo \d+\.\d+\.\d+/);
      expect(build.evidence.mdkExecutableSha256Hex).toMatch(/^[0-9a-f]{64}$/);
      const executable = join(
        B33A_MDK_BUILD_ROOT, names[index], 'debug', 'styx-b3-mdk-peer',
      );
      expect(executableSha256(executable)).toBe(build.evidence.mdkExecutableSha256Hex);
      const publicEvidence = JSON.stringify({ report, transcript });
      for (const forbidden of [B33A_PRIVATE_ROOT, 'accountPrivateKey', 'databaseKey',
        'databasePath', 'privateDirectory', 'providerState', 'secretPath']) {
        expect(publicEvidence).not.toContain(forbidden);
      }
      expect(existsSync(join(B33A_PRIVATE_ROOT, names[index]))).toBe(false);
      expect(transcript.map((record) => record.operation)).toEqual(B33A_STAGE2_GO_OPERATIONS);
      return { report, transcript };
    });
    expect(runs[0].transcript.map((record) => record.operation))
      .toEqual(runs[1].transcript.map((record) => record.operation));
    expect(runs[0].transcript[0].evidence.sourceCommit)
      .toBe(runs[1].transcript[0].evidence.sourceCommit);
  });
});
