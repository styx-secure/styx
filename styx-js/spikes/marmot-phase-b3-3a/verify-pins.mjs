// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — Stage 1 immutable-input and candidate-tuple verifier.

import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync, realpathSync, statSync } from 'node:fs';
import { dirname, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { B33A_BUILD_ROOT, B33A_ERROR, failB33a } from './b3-3a-canonical.mjs';

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

function git(cwd, ...args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
}

function sha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
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
  return EXACT_ALLOWED_PATHS.has(path)
    || path.startsWith('styx-js/spikes/marmot-phase-b3-3a/')
    || /^styx-js\/test\/crypto\/mls-phase-b3-3a-.*\.test\.js$/.test(path)
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
  return Object.freeze(Object.fromEntries(GENERATED_FILES.map((name) => {
    const path = resolve(candidate, name);
    if (!statSync(path).isFile()) {
      failB33a(B33A_ERROR.INVALID, `${name} is not a regular candidate file`);
    }
    return [name, sha256(path)];
  })));
}

export function verifyPins(candidatePath) {
  requireEqual(git(repoRoot, 'rev-parse', `${B33A_BASE_SHA}^{tree}`),
    B33A_BASE_TREE, 'B3.3a base tree');
  execFileSync('git', ['merge-base', '--is-ancestor', B33A_BASE_SHA, 'HEAD'], { cwd: repoRoot });
  requireEqual(git(mdkRoot, 'rev-parse', 'HEAD'), B33A_MDK_REVISION, 'MDK revision');
  requireEqual(git(mdkRoot, 'rev-parse', 'HEAD^{tree}'), B33A_MDK_TREE, 'MDK tree');
  requireEqual(git(mdkRoot, 'status', '--porcelain'), '', 'MDK worktree');
  requireEqual(sha256(resolve(mdkRoot, 'Cargo.lock')),
    B33A_MDK_LOCK_SHA256, 'external MDK Cargo.lock');
  requireEqual(sha256(resolve(repoRoot, 'styx-js/vendor/openmls-wasm/Cargo.lock')),
    B33A_VENDOR_LOCK_SHA256, 'vendored Cargo.lock');
  const changedPaths = verifyCommittedScope();
  return Object.freeze({
    baseSha: B33A_BASE_SHA,
    baseTree: B33A_BASE_TREE,
    candidateTuple: candidateTuple(candidatePath),
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
    throw new Error('usage: verify-pins.mjs --candidate-dir PATH');
  }
  process.stdout.write(`${JSON.stringify(verifyPins(process.argv[3]))}\n`);
}
