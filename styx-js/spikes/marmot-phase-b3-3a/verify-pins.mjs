// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — immutable-input and approved-artifact verifier.

import { execFileSync } from 'node:child_process';
import { readdirSync, realpathSync, statSync } from 'node:fs';
import { dirname, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { B33A_BUILD_ROOT, B33A_ERROR, failB33a } from './b3-3a-canonical.mjs';
import { readExactRegularFile } from './b3-3a-artifact-reader.mjs';

export const B33A_BASE_SHA = '1404d05ed2604195e3b697caeccad9133a6cdc34';
export const B33A_BASE_TREE = '7d0ee0078385f3f7a85e1f8f23e11adc347cddf8';
export const B33A_OPENMLS_REVISION = '09e92777dba0528d3d29e2e5e681b7e91637c7be';
export const B33A_MARMOT_REVISION = '4ad4ae21479c3f3fa9950c6fc4556a76941a62e1';
export const B33A_MDK_REVISION = '9396adb6aa6b95b521a7979facd5ea7040c07288';
export const B33A_MDK_TREE = 'a1145de604e616634dae9a1ef6bf5033c9c9e879';
export const B33A_MDK_LOCK_SHA256 =
  'edb8c706e12934b8d94239203f73d24a2d480033c3ec6830f19d06c85a247b09';
export const B33A_VENDOR_LOCK_SHA256 =
  '33964e33f6a48e8b9982c5894c4a7e9ddc5ee2e5157c763596393a08c607672b';
export const B33A_APPROVED_ARTIFACT_TUPLE = Object.freeze({
  'openmls_wasm.js': '044a7cce67730ea45964f1bfc3e54ee79f3ff6ee277029efb87d9abd57a9aa6f',
  'openmls_wasm.d.ts': 'c64a515a55591d8c84bfe0386b2db984d83e39f3ace7a14553d2cd7f11dc8048',
  'openmls_wasm_bg.wasm': '7087b53f8f0597f0107802d5b629cd211d138d4f916b2ddd5831862088551624',
  'openmls_wasm_bg.wasm.d.ts': 'eb26390ba4b96299df0105ed72c1bf2a292217a8635f816488a64d65b7deb6dc',
  'package.json': '88f2ec1e2a5c1904b0fc1d147221c32ba6dcbf1cb4441c53b04a1b2a03bd1d85',
});

const GENERATED_FILES = Object.freeze([
  'openmls_wasm.js',
  'openmls_wasm.d.ts',
  'openmls_wasm_bg.wasm',
  'openmls_wasm_bg.wasm.d.ts',
  'package.json',
]);
const directory = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(directory, '..', '..', '..');
const mdkRoot = '/home/mverde/.local/share/styx-upstreams/mdk-9396adb6';
const EXACT_ALLOWED_PATHS = new Set([
  'styx-js/vendor/openmls-wasm/patch/lib.rs',
  'styx-js/vendor/openmls-wasm/openmls_wasm.js',
  'styx-js/vendor/openmls-wasm/openmls_wasm.d.ts',
  'styx-js/vendor/openmls-wasm/openmls_wasm_bg.wasm',
  'styx-js/vendor/openmls-wasm/openmls_wasm_bg.wasm.d.ts',
  'styx-js/vendor/openmls-wasm/package.json',
  'styx-js/vendor/openmls-wasm/README.md',
  'styx-js/vendor/openmls-wasm/PROVENANCE.md',
  'styx-js/src/crypto/mls/mls-build-info.js',
  'styx-js/spikes/marmot-phase-b3/mdk-peer/src/main.rs',
  'styx-js/spikes/marmot-phase-b3/README.md',
  'styx-js/test/crypto/mls-phase-b2-surface.test.js',
  'styx-js/test/crypto/mls-phase-b3-2-mdk-interop.test.js',
  'styx-js/test/crypto/kdf-wasm.test.js',
  'styx-js/test/storage/mls-state-envelope.test.js',
  'docs/architecture/spikes/2026-08-15-marmot-openmls-phase-b3-3a.md',
]);
const B33B1_STAGE2_ALLOWED_PATHS = new Set([
  'styx-js/spikes/marmot-phase-b3-3a/verify-pins.mjs',
  'styx-js/spikes/marmot-phase-b3-3a/README.md',
  'styx-js/test/crypto/mls-phase-b3-3a-evidence.test.js',
  'styx-js/test/crypto/mls-phase-b2-surface.test.js',
  'styx-js/test/crypto/kdf-wasm.test.js',
  'styx-js/test/storage/mls-state-envelope.test.js',
]);

function git(cwd, ...args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
}

function sha256(path) {
  return readExactRegularFile(path).sha256Hex;
}

function requireEqual(actual, expected, label) {
  if (actual !== expected) failB33a(B33A_ERROR.INVALID,
    `${label} drifted: expected ${expected}, got ${actual}`);
}

function strictBuildChild(path) {
  const root = realpathSync(B33A_BUILD_ROOT);
  const candidate = realpathSync(path);
  const rel = relative(root, candidate);
  if (!rel || rel === '..' || rel.startsWith(`..${sep}`) || !statSync(candidate).isDirectory()) {
    failB33a(B33A_ERROR.INVALID, 'candidate directory escaped the Stage 1 build root');
  }
  const names = readdirSync(candidate).sort();
  if (names.length !== GENERATED_FILES.length
    || names.some((name, index) => name !== [...GENERATED_FILES].sort()[index])) {
    failB33a(B33A_ERROR.INVALID, 'candidate directory does not contain the exact five-file tuple');
  }
  return candidate;
}

function allowedPath(path) {
  return EXACT_ALLOWED_PATHS.has(path) || B33B1_STAGE2_ALLOWED_PATHS.has(path)
    || path.startsWith('styx-js/spikes/marmot-phase-b3-3a/')
    || path.startsWith('styx-js/spikes/marmot-phase-b3-3b-1/')
    || /^styx-js\/test\/crypto\/mls-phase-b3-3a-.*\.test\.js$/.test(path)
    || /^styx-js\/test\/crypto\/mls-phase-b3-3b-1-.*\.test\.js$/.test(path)
    || /^styx-js\/test\/crypto\/mls-phase-b3-2a-.*\.test\.js$/.test(path);
}

function verifyCommittedScope() {
  const changed = git(
    repoRoot, 'diff', '--name-only', '--no-renames', `${B33A_BASE_SHA}..HEAD`, '--',
  ).split('\n').filter(Boolean);
  const forbidden = changed.filter((path) => !allowedPath(path));
  if (forbidden.length !== 0) {
    failB33a(B33A_ERROR.INVALID,
      `committed source escaped the Issue #185 path contract: ${forbidden.join(', ')}`);
  }
  const binary = git(
    repoRoot, 'diff', '--numstat', '--no-renames', `${B33A_BASE_SHA}..HEAD`, '--',
  ).split('\n').filter(Boolean).filter((line) => line.startsWith('-\t-\t')
    && !line.endsWith('\tstyx-js/vendor/openmls-wasm/openmls_wasm_bg.wasm'));
  if (binary.length !== 0) {
    failB33a(B33A_ERROR.INVALID,
      `unexpected binary source change before tuple installation: ${binary.join(', ')}`);
  }
  for (const path of changed) {
    const mode = git(repoRoot, 'ls-tree', 'HEAD', '--', path).split(/\s+/, 1)[0];
    if (mode === '120000' || mode === '160000') {
      failB33a(B33A_ERROR.INVALID, `symlink or submodule is forbidden: ${path}`);
    }
  }
  return Object.freeze(changed);
}

export function candidateTuple(candidatePath) {
  const candidate = strictBuildChild(candidatePath);
  return assertApprovedArtifactTuple(Object.freeze(Object.fromEntries(
    GENERATED_FILES.map((name) => [name, sha256(resolve(candidate, name))]),
  )), 'candidate');
}

export function assertApprovedArtifactTuple(tuple, label = 'artifact') {
  const names = Object.keys(tuple ?? {}).sort();
  const expectedNames = [...GENERATED_FILES].sort();
  if (names.length !== expectedNames.length
    || names.some((name, index) => name !== expectedNames[index])) {
    failB33a(B33A_ERROR.INVALID, `${label} tuple does not contain the exact approved files`);
  }
  for (const name of GENERATED_FILES) {
    requireEqual(tuple[name], B33A_APPROVED_ARTIFACT_TUPLE[name], `${label} ${name}`);
  }
  return tuple;
}

export function verifyPins(candidatePath) {
  if (candidatePath === undefined) {
    failB33a(B33A_ERROR.INVALID,
      'historical B3.3a candidate directory must be supplied explicitly');
  }
  requireEqual(git(repoRoot, 'rev-parse', `${B33A_BASE_SHA}^{tree}`),
    B33A_BASE_TREE, 'B3.3a base tree');
  execFileSync('git', ['merge-base', '--is-ancestor', B33A_BASE_SHA, 'HEAD'], { cwd: repoRoot });
  requireEqual(git(repoRoot, 'status', '--porcelain', '--untracked-files=no'),
    '', 'Styx tracked worktree');
  requireEqual(git(mdkRoot, 'rev-parse', 'HEAD'), B33A_MDK_REVISION, 'MDK revision');
  requireEqual(git(mdkRoot, 'rev-parse', 'HEAD^{tree}'), B33A_MDK_TREE, 'MDK tree');
  requireEqual(git(mdkRoot, 'status', '--porcelain'), '', 'MDK worktree');
  requireEqual(sha256(resolve(mdkRoot, 'Cargo.lock')),
    B33A_MDK_LOCK_SHA256, 'external MDK Cargo.lock');
  requireEqual(sha256(resolve(repoRoot, 'styx-js/vendor/openmls-wasm/Cargo.lock')),
    B33A_VENDOR_LOCK_SHA256, 'vendored Cargo.lock');
  const changedPaths = verifyCommittedScope();
  const exactCandidateTuple = candidateTuple(candidatePath);
  return Object.freeze({
    baseSha: B33A_BASE_SHA,
    baseTree: B33A_BASE_TREE,
    candidateTuple: exactCandidateTuple,
    changedPaths,
    marmotRevision: B33A_MARMOT_REVISION,
    mdkLockSha256: B33A_MDK_LOCK_SHA256,
    mdkRevision: B33A_MDK_REVISION,
    mdkTree: B33A_MDK_TREE,
    openMlsRevision: B33A_OPENMLS_REVISION,
    patchSha256: sha256(resolve(repoRoot, 'styx-js/vendor/openmls-wasm/patch/lib.rs')),
    sourceCommit: git(repoRoot, 'rev-parse', 'HEAD'),
    sourceTree: git(repoRoot, 'rev-parse', 'HEAD^{tree}'),
    vendorLockSha256: B33A_VENDOR_LOCK_SHA256,
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 4 || process.argv[2] !== '--candidate-dir') {
    throw new Error('usage: verify-pins.mjs --candidate-dir HISTORICAL_PATH');
  }
  process.stdout.write(`${JSON.stringify(verifyPins(process.argv[3]))}\n`);
}
