// SPDX-License-Identifier: AGPL-3.0-or-later

import { randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, rmSync } from 'node:fs';
import { resolve } from 'node:path';

import {
  B32_MDK_REVISION,
  B32_PRIVATE_ROOT,
  B32_STATE,
  sha256Hex,
} from '../../spikes/marmot-phase-b3-2/b3-2-canonical.mjs';
import { openB32FileJournal } from '../../spikes/marmot-phase-b3-2/b3-2-journal.mjs';
import { verifyPins } from '../../spikes/marmot-phase-b3-2/verify-pins.mjs';

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

  test('pins exact MDK and preserves the outgoing B3.1 tuple during Stage 1', () => {
    const pins = verifyPins();
    expect(pins.mdkRevision).toBe(B32_MDK_REVISION);
    expect(pins.installedWasmSha256).toBe(pins.outgoingB31WasmSha256);
    expect(pins.openMlsRevision).toBe('09e92777dba0528d3d29e2e5e681b7e91637c7be');
  });
});

describe('Phase B3.2 file-backed crash boundary', () => {
  test('a new journal instance reopens WELCOME_RECORDED with predecessor activation', async () => {
    mkdirSync(B32_PRIVATE_ROOT, { recursive: true, mode: 0o700 });
    const directory = resolve(B32_PRIVATE_ROOT, `jest-${process.pid}-${Date.now()}`);
    const predecessor = Uint8Array.from(randomBytes(2048));
    const keyPackage = Uint8Array.from(randomBytes(435));
    const welcome = Uint8Array.from(randomBytes(1024));
    try {
      const first = openB32FileJournal(directory);
      await first.initializeStable({
        predecessorState: predecessor,
        keyPackage,
        accountIdentityHex: randomBytes(32).toString('hex'),
        leafSignatureKeyHex: randomBytes(32).toString('hex'),
        expectedAuthorHex: randomBytes(32).toString('hex'),
      });
      await first.recordWelcome(welcome);

      const restarted = openB32FileJournal(directory);
      const activation = await restarted.activationState();
      expect(activation.state).toBe(B32_STATE.WELCOME_RECORDED);
      expect(sha256Hex(activation.bytes)).toBe(sha256Hex(predecessor));
      const bundle = await restarted.read();
      expect(bundle.blobs.welcomeBlobSha256Hex).toEqual(welcome);
      expect(bundle.blobs.keyPackageBlobSha256Hex).toEqual(keyPackage);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});
