// SPDX-License-Identifier: AGPL-3.0-or-later

import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  B33B1_APPROVED_SOURCE_SHA,
  B33B1_BASE_SHA,
  B33B1_DEFAULT_MDK_ROOT,
  verifyPins,
}
  from '../../spikes/marmot-phase-b3-3b-1/verify-pins.mjs';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

function withMdkRoot(value, action) {
  const previous = process.env.B33B1_MDK_ROOT;
  try {
    process.env.B33B1_MDK_ROOT = value;
    return action();
  } finally {
    if (previous === undefined) delete process.env.B33B1_MDK_ROOT;
    else process.env.B33B1_MDK_ROOT = previous;
  }
}

function capturedFailure(root) {
  try {
    withMdkRoot(root, () => verifyPins());
  } catch (error) {
    return error;
  }
  throw new Error('expected pin verification to fail');
}

describe('Phase B3.3b-1 pinned MDK diagnostics', () => {
  test.each(['', 'relative/mdk'])('rejects non-absolute MDK root %p', (root) => {
    expect(capturedFailure(root)).toEqual(expect.objectContaining({
      code: 'B33B1_INVALID',
    }));
  });

  test('classifies an unavailable checkout as environmental BLOCKED evidence', () => {
    const error = capturedFailure(
      join(tmpdir(), `styx-b33b1-missing-mdk-${process.pid}`),
    );
    expect(error).toEqual(expect.objectContaining({
      code: 'B33B1_BLOCKED',
      details: expect.objectContaining({
        errorCode: 'ENOENT',
        status: null,
      }),
    }));
    expect(() => JSON.stringify(error)).not.toThrow();
  });

  test('classifies a present non-Git checkout as pin drift with scalar diagnostics', () => {
    const directory = mkdtempSync(join(tmpdir(), 'styx-b33b1-not-git-'));
    try {
      const error = capturedFailure(directory);
      expect(error).toEqual(expect.objectContaining({
        code: 'B33B1_PIN_DRIFT',
        details: expect.objectContaining({
          status: expect.any(Number),
        }),
      }));
      const serialized = JSON.parse(JSON.stringify(error));
      expect(serialized.details).toEqual(expect.objectContaining({
        args: 'rev-parse HEAD',
        cwd: directory,
        errorCode: '',
        errorMessage: '',
        signal: '',
        status: expect.any(Number),
        stderr: expect.any(String),
      }));
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  test('accepts the installed tuple after the repository-required squash merge', () => {
    const directory = mkdtempSync(join(tmpdir(), 'styx-b33b1-squash-'));
    const clone = join(directory, 'repo');
    try {
      const candidateHead = execFileSync('git', ['rev-parse', 'HEAD'], {
        cwd: repoRoot,
        encoding: 'utf8',
      }).trim();
      execFileSync('git', ['clone', '--quiet', '--no-hardlinks', repoRoot, clone]);
      execFileSync('git', ['checkout', '--quiet', B33B1_BASE_SHA], { cwd: clone });
      execFileSync('git', ['merge', '--squash', candidateHead], {
        cwd: clone,
        stdio: 'ignore',
      });
      execFileSync('git', [
        '-c', 'user.name=Styx verifier',
        '-c', 'user.email=verifier@example.invalid',
        'commit', '--quiet', '-m', 'synthetic squash verification',
      ], { cwd: clone });

      const ancestry = spawnSync('git', [
        'merge-base', '--is-ancestor', B33B1_APPROVED_SOURCE_SHA, 'HEAD',
      ], { cwd: clone });
      expect(ancestry.status).toBe(1);

      const verification = spawnSync(process.execPath, [
        join(clone, 'styx-js/spikes/marmot-phase-b3-3b-1/verify-pins.mjs'),
      ], {
        cwd: clone,
        encoding: 'utf8',
        env: {
          ...process.env,
          B33B1_MDK_ROOT:
            process.env.B33B1_MDK_ROOT ?? B33B1_DEFAULT_MDK_ROOT,
        },
      });
      expect(verification).toEqual(expect.objectContaining({
        status: 0,
        stderr: '',
      }));
      expect(JSON.parse(verification.stdout)).toEqual(expect.objectContaining({
        artifactSourceCommit: B33B1_APPROVED_SOURCE_SHA,
      }));
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }, 30_000);
});
