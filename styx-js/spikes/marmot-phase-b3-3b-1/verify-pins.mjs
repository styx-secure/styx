// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — immutable input and external candidate verifier.

import { spawnSync } from 'node:child_process';
import { readdirSync, realpathSync, statSync } from 'node:fs';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
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
export const B33B1_APPROVED_SOURCE_SHA =
  'f7a7cb7b08e1f9a86652e2d5a2230c8aadc46f30';
export const B33B1_APPROVED_SOURCE_TREE =
  'd59f8192b8b97d94215266b93e9bc4f72c3a4380';
export const B33B1_APPROVED_ARTIFACT_TUPLE = Object.freeze({
  'openmls_wasm.js': '3de8fd46e4897aae117ee7b10ac41dffd02b507952c4024b0fe69d89fbb0c973',
  'openmls_wasm.d.ts': '057974ec53e3588da3dbf159f183b3e3ddb4a3b0a57d5391194f124a483ede86',
  'openmls_wasm_bg.wasm': 'fef05368f143de044274f8804d2ba195a1f886bc528651e98bd9c393fde4650e',
  'openmls_wasm_bg.wasm.d.ts': 'c21ace2360b264437541025e4703bcb38b53010793829d1904cb85b3d2aa238a',
  'package.json': '88f2ec1e2a5c1904b0fc1d147221c32ba6dcbf1cb4441c53b04a1b2a03bd1d85',
});

const directory = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(directory, '..', '..', '..');
export const B33B1_INSTALLED_ARTIFACT_DIRECTORY =
  resolve(repoRoot, 'styx-js/vendor/openmls-wasm');
export const B33B1_DEFAULT_MDK_ROOT =
  '/home/mverde/.local/share/styx-reviews/upstreams/mdk-9396adb6';
const MAX_GIT_DIAGNOSTIC_CHARS = 2048;
const STAGE2_ALLOWED_PATHS = new Set([
  '.github/workflows/styx-js-web.yml',
  'styx-js/vendor/openmls-wasm/openmls_wasm.js',
  'styx-js/vendor/openmls-wasm/openmls_wasm.d.ts',
  'styx-js/vendor/openmls-wasm/openmls_wasm_bg.wasm',
  'styx-js/vendor/openmls-wasm/openmls_wasm_bg.wasm.d.ts',
  'styx-js/vendor/openmls-wasm/package.json',
  'styx-js/vendor/openmls-wasm/README.md',
  'styx-js/vendor/openmls-wasm/PROVENANCE.md',
  'styx-js/src/crypto/mls/mls-build-info.js',
  'styx-js/spikes/marmot-phase-b3-3a/verify-pins.mjs',
  'styx-js/spikes/marmot-phase-b3-3a/README.md',
  'styx-js/test/crypto/mls-phase-b2-surface.test.js',
  'styx-js/test/crypto/mls-phase-b3-2a-welcome.test.js',
  'styx-js/test/crypto/mls-phase-b3-3a-evidence.test.js',
  'styx-js/test/crypto/kdf-wasm.test.js',
  'styx-js/test/storage/mls-state-envelope.test.js',
]);

function clipped(value) {
  return String(value ?? '').slice(0, MAX_GIT_DIAGNOSTIC_CHARS);
}

function gitFailureDetails(cwd, args, result, error = undefined) {
  return Object.freeze({
    args: args.join(' '),
    cwd,
    errorCode: clipped(error?.code || result?.error?.code),
    errorMessage: clipped(error?.message || result?.error?.message),
    signal: clipped(result?.signal),
    status: Number.isInteger(result?.status) ? result.status : null,
    stderr: clipped(result?.stderr),
  });
}

function git(cwd, ...args) {
  let result;
  try {
    result = spawnSync('git', args, { cwd, encoding: 'utf8' });
  } catch (error) {
    failB33b1(B33B1_ERROR.BLOCKED,
      'unable to execute the pinned Git verification',
      gitFailureDetails(cwd, args, undefined, error));
  }
  if (result.error) {
    failB33b1(B33B1_ERROR.BLOCKED,
      'unable to execute the pinned Git verification',
      gitFailureDetails(cwd, args, result));
  }
  if (result.status !== 0) {
    failB33b1(B33B1_ERROR.PIN_DRIFT,
      `pinned Git verification failed: git ${args.join(' ')}`,
      gitFailureDetails(cwd, args, result));
  }
  return result.stdout.trim();
}

function mdkRoot() {
  const configured = process.env.B33B1_MDK_ROOT;
  if (configured === undefined) return B33B1_DEFAULT_MDK_ROOT;
  if (configured.length === 0 || !isAbsolute(configured)) {
    failB33b1(B33B1_ERROR.INVALID,
      'B33B1_MDK_ROOT must be a non-empty absolute path');
  }
  return resolve(configured);
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
  return assertApprovedArtifactTuple(Object.freeze(Object.fromEntries(
    B33B1_GENERATED_FILES.map((name) => [
      name, sha256(resolve(candidate, name)),
    ])),
  ), 'candidate');
}

export function artifactDirectory(candidatePath) {
  return candidatePath === undefined
    ? B33B1_INSTALLED_ARTIFACT_DIRECTORY
    : strictCandidateDirectory(candidatePath);
}

export function assertApprovedArtifactTuple(tuple, label = 'artifact') {
  const names = Object.keys(tuple ?? {}).sort();
  const expectedNames = [...B33B1_GENERATED_FILES].sort();
  if (names.length !== expectedNames.length
    || names.some((name, index) => name !== expectedNames[index])) {
    failB33b1(B33B1_ERROR.INVALID,
      `${label} tuple does not contain the exact approved files`);
  }
  for (const name of B33B1_GENERATED_FILES) {
    requireEqual(tuple[name], B33B1_APPROVED_ARTIFACT_TUPLE[name], `${label} ${name}`);
  }
  return tuple;
}

export function installedArtifactTuple() {
  return assertApprovedArtifactTuple(Object.freeze(Object.fromEntries(
    B33B1_GENERATED_FILES.map((name) => [
      name,
      readExactRegularFile(
        resolve(B33B1_INSTALLED_ARTIFACT_DIRECTORY, name),
        B33B1_APPROVED_ARTIFACT_TUPLE[name],
      ).sha256Hex,
    ])),
  ), 'installed artifact');
}

function allowedPath(path) {
  return STAGE2_ALLOWED_PATHS.has(path)
    || path === 'styx-js/vendor/openmls-wasm/patch/lib.rs'
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
  const exactMdkRoot = mdkRoot();
  requireEqual(git(repoRoot, 'rev-parse', `${B33B1_APPROVED_SOURCE_SHA}^{tree}`),
    B33B1_APPROVED_SOURCE_TREE, 'approved artifact source tree');
  git(repoRoot, 'merge-base', '--is-ancestor', B33B1_APPROVED_SOURCE_SHA, 'HEAD');
  requireEqual(git(repoRoot, 'rev-parse', `${B33B1_BASE_SHA}^{tree}`),
    B33B1_BASE_TREE, 'B3.3b-1 base tree');
  git(repoRoot, 'merge-base', '--is-ancestor', B33B1_BASE_SHA, 'HEAD');
  requireEqual(git(repoRoot, 'status', '--porcelain', '--untracked-files=no'),
    '', 'Styx tracked worktree');
  requireEqual(git(exactMdkRoot, 'rev-parse', 'HEAD'),
    B33B1_MDK_REVISION, 'MDK revision');
  requireEqual(git(exactMdkRoot, 'rev-parse', 'HEAD^{tree}'),
    B33B1_MDK_TREE, 'MDK tree');
  requireEqual(git(exactMdkRoot, 'status', '--porcelain'), '', 'MDK worktree');
  requireEqual(sha256(resolve(exactMdkRoot, 'Cargo.lock')),
    B33B1_MDK_LOCK_SHA256, 'external MDK Cargo.lock');
  requireEqual(sha256(resolve(repoRoot, 'styx-js/vendor/openmls-wasm/Cargo.lock')),
    B33B1_VENDOR_LOCK_SHA256, 'vendored Cargo.lock');
  return Object.freeze({
    artifactSourceCommit: B33B1_APPROVED_SOURCE_SHA,
    artifactSourceTree: B33B1_APPROVED_SOURCE_TREE,
    baseSha: B33B1_BASE_SHA,
    baseTree: B33B1_BASE_TREE,
    candidateTuple: candidatePath === undefined
      ? installedArtifactTuple() : candidateTuple(candidatePath),
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
  try {
    if (process.argv.length !== 2
      && (process.argv.length !== 4 || process.argv[2] !== '--candidate-dir')) {
      throw new Error('usage: verify-pins.mjs [--candidate-dir PATH]');
    }
    process.stdout.write(`${JSON.stringify(verifyPins(process.argv[3]))}\n`);
  } catch (error) {
    process.stderr.write(`${JSON.stringify({
      code: clipped(error?.code),
      details: error?.details,
      message: clipped(error?.message),
      name: clipped(error?.name || 'Error'),
    })}\n`);
    process.exitCode = 1;
  }
}
