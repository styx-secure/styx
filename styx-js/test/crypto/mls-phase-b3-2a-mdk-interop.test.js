// SPDX-License-Identifier: AGPL-3.0-or-later

import { randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';

import {
  B32A_MDK_REVISION,
  B32A_OPENMLS_REVISION,
  B32A_PREPARATION,
  B32A_PRIVATE_ROOT,
  B32A_PROFILE,
  B32A_RUN_ROOT,
  B32A_STATE,
  B32A_WASM_SHA256,
  sha256Hex,
} from '../../spikes/marmot-phase-b3-2a/b3-2a-canonical.mjs';
import { openB32aFileJournal } from '../../spikes/marmot-phase-b3-2a/b3-2a-journal.mjs';
import { B32_WASM_SHA256 } from '../../spikes/marmot-phase-b3-2/b3-2-canonical.mjs';
import { validateB32Transcript } from '../../spikes/marmot-phase-b3-2/b3-2-canonical.mjs';

const repoRoot = resolve(new URL('../../..', import.meta.url).pathname);
const patchSource = readFileSync(
  resolve(repoRoot, 'styx-js/vendor/openmls-wasm/patch/lib.rs'), 'utf8',
);
const orchestratorSource = readFileSync(
  resolve(repoRoot, 'styx-js/spikes/marmot-phase-b3-2a/b3-2a-orchestrator.mjs'), 'utf8',
);
const peerSource = readFileSync(
  resolve(repoRoot, 'styx-js/spikes/marmot-phase-b3-2a/b3-2a-styx-driver.mjs'), 'utf8',
);

describe('Phase B3.2a source boundary and exact pins', () => {
  test('the one-use candidate owns no public live Provider handle', () => {
    const start = patchSource.indexOf('impl PhaseB32aPendingWelcome');
    const end = patchSource.indexOf('impl PhaseB32aGroup', start);
    const surface = patchSource.slice(start, end);
    expect(start).toBeGreaterThan(0);
    expect(surface).toContain('prepare_from_durable_state');
    expect(surface).toContain('release_candidate_state');
    expect(surface).not.toMatch(/provider\s*:\s*Provider/);
  });

  test('durable Welcome recording precedes native preparation and the sole JOINED CAS', () => {
    const record = orchestratorSource.indexOf('await styx.recordWelcome');
    const prepare = orchestratorSource.indexOf('await styx.joinRecordedWelcome');
    expect(record).toBeGreaterThan(0);
    expect(prepare).toBeGreaterThan(record);
    expect(peerSource).toContain('PhaseB32aKeyPackage.from_framed_bytes');
    expect(peerSource).toContain('new B32aDurableJoinDriver');
  });

  test('freezes exact source pins and the installed B3.2a artifact', () => {
    const installed = readFileSync(
      resolve(repoRoot, 'styx-js/vendor/openmls-wasm/openmls_wasm_bg.wasm'),
    );
    expect(B32A_MDK_REVISION).toBe('9396adb6aa6b95b521a7979facd5ea7040c07288');
    expect(B32A_OPENMLS_REVISION).toBe('09e92777dba0528d3d29e2e5e681b7e91637c7be');
    expect(sha256Hex(installed)).toBe(B32A_WASM_SHA256);
    expect(B32A_WASM_SHA256).not.toBe(B32_WASM_SHA256);
  });
});

describe('Phase B3.2a file-backed restart boundary', () => {
  test('a relocated hermetic root rejects an escaping journal path', () => {
    const approvedRoot = mkdtempSync(resolve(tmpdir(), 'styx-b32a-jest-'));
    try {
      expect(() => openB32aFileJournal(resolve(approvedRoot, '..', 'escape'), approvedRoot))
        .toThrow('B32A_INVALID: journal directory is not a strict child of the private root');
    } finally {
      rmSync(approvedRoot, { recursive: true, force: true });
    }
  });

  test('a new journal instance reopens WELCOME_RECORDED with predecessor activation', async () => {
    const approvedRoot = mkdtempSync(resolve(tmpdir(), 'styx-b32a-jest-'));
    const directory = resolve(approvedRoot, 'journal');
    const predecessor = Uint8Array.from(randomBytes(2048));
    const keyPackage = Uint8Array.from(randomBytes(435));
    const welcome = Uint8Array.from(randomBytes(1024));
    try {
      const first = openB32aFileJournal(directory, approvedRoot);
      await first.initializeStable({
        predecessorState: predecessor,
        keyPackage,
        accountIdentityHex: randomBytes(32).toString('hex'),
        leafSignatureKeyHex: randomBytes(32).toString('hex'),
        expectedAuthorHex: randomBytes(32).toString('hex'),
      });
      await first.recordWelcome(welcome);
      const restarted = openB32aFileJournal(directory, approvedRoot);
      const activation = await restarted.activationState();
      expect(activation.state).toBe(B32A_STATE.WELCOME_RECORDED);
      expect(sha256Hex(activation.bytes)).toBe(sha256Hex(predecessor));
      const bundle = await restarted.read();
      expect(bundle.blobs.welcomeBlobSha256Hex).toEqual(welcome);
      expect(bundle.blobs.keyPackageBlobSha256Hex).toEqual(keyPackage);
    } finally {
      rmSync(approvedRoot, { recursive: true, force: true });
    }
  });
});

describe('Phase B3.2a exact-pin paired evidence', () => {
  test('paired runs, when present, agree on the bounded GO claim and expose no private paths', () => {
    const paths = ['run-a', 'run-b'].map((name) => resolve(B32A_RUN_ROOT, name));
    expect(existsSync(resolve(paths[0], 'report.json')))
      .toBe(existsSync(resolve(paths[1], 'report.json')));
    if (!existsSync(resolve(paths[0], 'report.json'))) return;
    const runs = paths.map((path) => ({
      report: JSON.parse(readFileSync(resolve(path, 'report.json'), 'utf8')),
      transcript: JSON.parse(readFileSync(resolve(path, 'transcript.json'), 'utf8')),
    }));
    for (const { report, transcript } of runs) {
      expect(validateB32Transcript(transcript)).toBe(report.transcriptHeadSha256);
      expect(report).toEqual(expect.objectContaining({
        applicationTrafficTested: false,
        compatibilityEstablished: false,
        disposition: 'GO',
        exactProfileDurableRestartedWelcomeJoinEstablished: true,
        memberProfiles: [B32A_PROFILE.MDK, B32A_PROFILE.STYX],
        preparationClassification: B32A_PREPARATION.RETENTION_TIMESTAMP_BOUNDED,
        retentionTimestampDifferenceAccepted: true,
      }));
      const publicEvidence = JSON.stringify({ report, transcript });
      for (const forbidden of [B32A_PRIVATE_ROOT, 'accountPrivateKey', 'databaseKey',
        'databasePath', 'privateDirectory', 'providerState', 'secretPath']) {
        expect(publicEvidence).not.toContain(forbidden);
      }
    }
    expect(runs[0].transcript.map((record) => record.operation))
      .toEqual(runs[1].transcript.map((record) => record.operation));
    expect(existsSync(resolve(B32A_PRIVATE_ROOT, 'run-a'))).toBe(false);
    expect(existsSync(resolve(B32A_PRIVATE_ROOT, 'run-b'))).toBe(false);
  });
});
