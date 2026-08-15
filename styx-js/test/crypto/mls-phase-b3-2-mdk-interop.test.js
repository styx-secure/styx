// SPDX-License-Identifier: AGPL-3.0-or-later

import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';

import {
  B32_MDK_REVISION,
  B32_OPENMLS_REVISION,
  B32_STATE,
  B32_WASM_SHA256,
  sha256Hex,
} from '../../spikes/marmot-phase-b3-2/b3-2-canonical.mjs';
import { B31_WASM_SHA256 } from '../../spikes/marmot-phase-b3-1/b3-1-canonical.mjs';
import { openB32FileJournal } from '../../spikes/marmot-phase-b3-2/b3-2-journal.mjs';
import {
  COMPATIBLE_MLS_STATE_TUPLES,
  MLS_BUILD_INFO,
} from '../../src/crypto/mls/mls-build-info.js';

const repoRoot = resolve(new URL('../../..', import.meta.url).pathname);
const patchSource = readFileSync(
  resolve(repoRoot, 'styx-js/vendor/openmls-wasm/patch/lib.rs'), 'utf8',
);
const orchestratorSource = readFileSync(
  resolve(repoRoot, 'styx-js/spikes/marmot-phase-b3-2/b3-2-orchestrator.mjs'), 'utf8',
);
const driverSource = readFileSync(
  resolve(repoRoot, 'styx-js/spikes/marmot-phase-b3-2/b3-2-styx-driver.mjs'), 'utf8',
);

describe('Phase B3.2 source boundary and exact pins', () => {
  test('the new wrapper makes external RatchetTree delivery structurally impossible', () => {
    const start = patchSource.indexOf('impl PhaseB32PendingWelcome');
    const end = patchSource.indexOf('impl PhaseB32Group', start);
    const surface = patchSource.slice(start, end);
    expect(surface).toContain('into_staged_welcome(&clone.inner, None)');
    expect(surface).not.toContain('PhaseB1RatchetTree');
    expect(surface).not.toContain('PhaseB2RatchetTree');
    expect(surface).not.toMatch(/ratchet_tree\s*:/);
  });

  test('Welcome durability precedes every wrapper preparation in the orchestrator', () => {
    const record = orchestratorSource.indexOf('await styx.recordWelcome');
    const prepare = orchestratorSource.indexOf('await styx.joinRecordedWelcome');
    expect(record).toBeGreaterThan(0);
    expect(prepare).toBeGreaterThan(record);
    expect(driverSource).toContain('PhaseB32PendingWelcome.prepare');
    expect(driverSource).toContain('release_candidate_state');
    expect(driverSource).toContain('await this.#journal.commitJoined');
  });

  test('freezes exact source pins and the installed B3.2 artifact in shallow CI', () => {
    const installed = readFileSync(
      resolve(repoRoot, 'styx-js/vendor/openmls-wasm/openmls_wasm_bg.wasm'),
    );
    expect(B32_MDK_REVISION).toBe('9396adb6aa6b95b521a7979facd5ea7040c07288');
    expect(B32_OPENMLS_REVISION).toBe('09e92777dba0528d3d29e2e5e681b7e91637c7be');
    expect(COMPATIBLE_MLS_STATE_TUPLES.map(({ wasmArtifactSha256 }) => wasmArtifactSha256))
      .toContain(B32_WASM_SHA256);
    expect(sha256Hex(installed)).toBe(MLS_BUILD_INFO.wasmArtifactSha256);
    expect(B31_WASM_SHA256).not.toBe(B32_WASM_SHA256);
  });
});

describe('Phase B3.2 file-backed crash boundary', () => {
  test('a relocated hermetic root does not permit an escaping journal path', () => {
    const approvedRoot = mkdtempSync(resolve(tmpdir(), 'styx-b32-jest-'));
    try {
      expect(() => openB32FileJournal(resolve(approvedRoot, '..', 'escape'), approvedRoot))
        .toThrow('B32_INVALID: journal directory escaped the approved B3.2 private root');
    } finally {
      rmSync(approvedRoot, { recursive: true, force: true });
    }
  });

  test('a new journal instance reopens WELCOME_RECORDED with predecessor activation', async () => {
    const approvedRoot = mkdtempSync(resolve(tmpdir(), 'styx-b32-jest-'));
    const directory = resolve(approvedRoot, 'journal');
    const predecessor = Uint8Array.from(randomBytes(2048));
    const keyPackage = Uint8Array.from(randomBytes(435));
    const welcome = Uint8Array.from(randomBytes(1024));
    try {
      const first = openB32FileJournal(directory, approvedRoot);
      await first.initializeStable({
        predecessorState: predecessor,
        keyPackage,
        accountIdentityHex: randomBytes(32).toString('hex'),
        leafSignatureKeyHex: randomBytes(32).toString('hex'),
        expectedAuthorHex: randomBytes(32).toString('hex'),
      });
      await first.recordWelcome(welcome);

      const restarted = openB32FileJournal(directory, approvedRoot);
      const activation = await restarted.activationState();
      expect(activation.state).toBe(B32_STATE.WELCOME_RECORDED);
      expect(sha256Hex(activation.bytes)).toBe(sha256Hex(predecessor));
      const bundle = await restarted.read();
      expect(bundle.blobs.welcomeBlobSha256Hex).toEqual(welcome);
      expect(bundle.blobs.keyPackageBlobSha256Hex).toEqual(keyPackage);
    } finally {
      rmSync(approvedRoot, { recursive: true, force: true });
    }
  });
});
