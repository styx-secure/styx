// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — immutable input and external candidate verifier.

import { execFileSync } from 'node:child_process';
import { readdirSync, realpathSync, statSync } from 'node:fs';
import { dirname, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { readExactRegularFile }
  from '../marmot-phase-b3-3a/b3-3a-artifact-reader.mjs';
import {
  B33B1_BUILD_ROOT,
  B33B1_ERROR,
  B33B1_GENERATED_FILES,
  failB33b1,
} from './b3-3b-1-canonical.mjs';

export const B33B1_BASE_SHA = '83fb7b9255412e5e2f1ae96c1b5557e3a016939b';
export const B33B1_BASE_TREE = '675ab2facfde317c1740a08f13430e580b11aa0c';
export const B33B1_OPENMLS_REVISION =
  '09e92777dba0528d3d29e2e5e681b7e91637c7be';
export const B33B1_MARMOT_REVISION =
  '4ad4ae21479c3f3fa9950c6fc4556a76941a62e1';
export const B33B1_MDK_REVISION =
  '9396adb6aa6b95b521a7979facd5ea7040c07288';
export const B33B1_MDK_TREE = 'a1145de604e616634dae9a1ef6bf5033c9c9e879';
export const B33B1_MDK_LOCK_SHA256 =
  'edb8c706e12934b8d94239203f73d24a2d480033c3ec6830f19d06c85a247b09';
export const B33B1_VENDOR_LOCK_SHA256 =
  '33964e33f6a48e8b9982c5894c4a7e9ddc5ee2e5157c763596393a08c607672b';

const directory = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(directory, '..', '..', '..');
const mdkRoot = '/home/mverde/.local/share/styx-reviews/upstreams/mdk-9396adb6';

function git(cwd, ...args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
}

function requireEqual(actual, expected, label) {
  if (actual !== expected) {
    failB33b1(B33B1_ERROR.PIN_DRIFT,
      `${label} drifted: expected ${expected}, got ${actual}`);
  }
}

function sha256(path) {
  return readExactRegularFile(path).sha256Hex;
}

export function strictCandidateDirectory(path) {
  const root = realpathSync(B33B1_BUILD_ROOT);
  const candidate = realpathSync(path);
  const rel = relative(root, candidate);
  if (!rel || rel === '..' || rel.startsWith(`..${sep}`)
    || !statSync(candidate).isDirectory()) {
    failB33b1(B33B1_ERROR.INVALID,
      'candidate directory escaped the B3.3b-1 private build root');
  }
  const actual = readdirSync(candidate).sort();
  const expected = [...B33B1_GENERATED_FILES].sort();
  if (actual.length !== expected.length
    || actual.some((name, index) => name !== expected[index])) {
    failB33b1(B33B1_ERROR.INVALID,
      'candidate directory does not contain the exact five-file tuple');
  }
  return candidate;
}

export function candidateTuple(path) {
  const candidate = strictCandidateDirectory(path);
  return Object.freeze(Object.fromEntries(B33B1_GENERATED_FILES.map((name) => [
    name, sha256(resolve(candidate, name)),
  ])));
}

function allowedPath(path) {
  return path === 'styx-js/vendor/openmls-wasm/patch/lib.rs'
    || path === 'styx-js/spikes/marmot-phase-b3/mdk-peer/src/main.rs'
    || path === 'styx-js/spikes/marmot-phase-b3/README.md'
    || path.startsWith('styx-js/spikes/marmot-phase-b3-3b-1/')
    || /^styx-js\/test\/crypto\/mls-phase-b3-3b-1-.*\.test\.js$/.test(path)
    || /^docs\/architecture\/spikes\/2026-.*-marmot-openmls-phase-b3-3b-1\.md$/.test(path);
}

function verifyCommittedScope() {
  const changed = git(repoRoot, 'diff', '--name-only', '--no-renames',
    `${B33B1_BASE_SHA}..HEAD`, '--').split('\n').filter(Boolean);
  const forbidden = changed.filter((path) => !allowedPath(path));
  if (forbidden.length !== 0) {
    failB33b1(B33B1_ERROR.INVALID,
      `committed source escaped Issue #188: ${forbidden.join(', ')}`);
  }
  return Object.freeze(changed);
}

export function verifyPins(candidatePath) {
  requireEqual(git(repoRoot, 'rev-parse', `${B33B1_BASE_SHA}^{tree}`),
    B33B1_BASE_TREE, 'B3.3b-1 base tree');
  execFileSync('git', ['merge-base', '--is-ancestor', B33B1_BASE_SHA, 'HEAD'],
    { cwd: repoRoot });
  requireEqual(git(repoRoot, 'status', '--porcelain', '--untracked-files=no'),
    '', 'Styx tracked worktree');
  requireEqual(git(mdkRoot, 'rev-parse', 'HEAD'), B33B1_MDK_REVISION, 'MDK revision');
  requireEqual(git(mdkRoot, 'rev-parse', 'HEAD^{tree}'), B33B1_MDK_TREE, 'MDK tree');
  requireEqual(git(mdkRoot, 'status', '--porcelain'), '', 'MDK worktree');
  requireEqual(sha256(resolve(mdkRoot, 'Cargo.lock')),
    B33B1_MDK_LOCK_SHA256, 'external MDK Cargo.lock');
  requireEqual(sha256(resolve(repoRoot, 'styx-js/vendor/openmls-wasm/Cargo.lock')),
    B33B1_VENDOR_LOCK_SHA256, 'vendored Cargo.lock');
  return Object.freeze({
    baseSha: B33B1_BASE_SHA,
    baseTree: B33B1_BASE_TREE,
    candidateTuple: candidateTuple(candidatePath),
    changedPaths: verifyCommittedScope(),
    marmotRevision: B33B1_MARMOT_REVISION,
    mdkLockSha256: B33B1_MDK_LOCK_SHA256,
    mdkRevision: B33B1_MDK_REVISION,
    mdkTree: B33B1_MDK_TREE,
    openMlsRevision: B33B1_OPENMLS_REVISION,
    patchSha256: sha256(resolve(repoRoot, 'styx-js/vendor/openmls-wasm/patch/lib.rs')),
    sourceCommit: git(repoRoot, 'rev-parse', 'HEAD'),
    sourceTree: git(repoRoot, 'rev-parse', 'HEAD^{tree}'),
    vendorLockSha256: B33B1_VENDOR_LOCK_SHA256,
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 4 || process.argv[2] !== '--candidate-dir') {
    throw new Error('usage: verify-pins.mjs --candidate-dir PATH');
  }
  process.stdout.write(`${JSON.stringify(verifyPins(process.argv[3]))}\n`);
}
