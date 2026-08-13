// SPDX-License-Identifier: AGPL-3.0-or-later

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  B3_BASE_SHA,
  B3_BASE_TREE,
  B3_MARMOT_REVISION,
  B3_MARMOT_TREE,
  B3_MDK_LOCK_SHA256,
  B3_MDK_REVISION,
  B3_MDK_TREE,
  B3_WASM_SHA256,
  sha256,
} from './b3-canonical.mjs';

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const styxJsDirectory = resolve(scriptDirectory, '..', '..');
const repositoryDirectory = resolve(styxJsDirectory, '..');
const marmotDirectory = '/home/mverde/.local/share/styx-upstreams/marmot-4ad4ae21';
const mdkDirectory = '/home/mverde/.local/share/styx-upstreams/mdk-9396adb6';
const openMlsRevision = '09e92777dba0528d3d29e2e5e681b7e91637c7be';
const generatedCargoTargetPrefix = 'styx-js/spikes/marmot-phase-b3/mdk-peer/target/';
const allowedPaths = new Set([
  'styx-js/spikes/marmot-phase-b3/README.md',
  'styx-js/spikes/marmot-phase-b3/b3-canonical.mjs',
  'styx-js/spikes/marmot-phase-b3/b3-mdk-driver.mjs',
  'styx-js/spikes/marmot-phase-b3/b3-orchestrator.mjs',
  'styx-js/spikes/marmot-phase-b3/b3-styx-driver.mjs',
  'styx-js/spikes/marmot-phase-b3/verify-pins.mjs',
  'styx-js/spikes/marmot-phase-b3/mdk-peer/Cargo.toml',
  'styx-js/spikes/marmot-phase-b3/mdk-peer/Cargo.lock',
  'styx-js/spikes/marmot-phase-b3/mdk-peer/src/main.rs',
  'styx-js/test/crypto/mls-phase-b3-mdk-interop.test.js',
  'docs/architecture/spikes/2026-08-13-marmot-openmls-phase-b3.md',
]);
const expectedDriverManifest = `[package]
name = "styx-b3-mdk-peer"
version = "0.0.0"
edition = "2024"
publish = false
license = "AGPL-3.0-or-later"

[dependencies]
async-trait = "0.1"
cgka-engine = { git = "https://github.com/marmot-protocol/mdk.git", rev = "${B3_MDK_REVISION}", features = ["test-conformance-snapshot"] }
cgka-traits = { git = "https://github.com/marmot-protocol/mdk.git", rev = "${B3_MDK_REVISION}" }
hex = "0.4"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sha2 = "0.10"
storage-sqlite = { git = "https://github.com/marmot-protocol/mdk.git", rev = "${B3_MDK_REVISION}" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
`;

function git(cwd, ...args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
}

function requireEqual(actual, expected, label) {
  if (actual !== expected) throw new Error(`${label} mismatch: ${actual}`);
}

export function verifyPins() {
  requireEqual(git(repositoryDirectory, 'rev-parse', `${B3_BASE_SHA}^{tree}`), B3_BASE_TREE, 'base tree');
  execFileSync('git', ['merge-base', '--is-ancestor', B3_BASE_SHA, 'HEAD'], {
    cwd: repositoryDirectory,
    stdio: 'ignore',
  });
  const trackedChanges = git(repositoryDirectory, 'diff', '--name-only', B3_BASE_SHA, '--')
    .split('\n')
    .filter(Boolean);
  const untrackedChanges = git(repositoryDirectory, 'ls-files', '--others', '--exclude-standard')
    .split('\n')
    .filter((path) => path && !path.startsWith(generatedCargoTargetPrefix));
  const changed = [...new Set([...trackedChanges, ...untrackedChanges])].sort();
  const outOfScope = changed.filter((path) => !allowedPaths.has(path));
  if (outOfScope.length > 0) throw new Error(`out-of-scope paths: ${outOfScope.join(', ')}`);

  const wasmBytes = readFileSync(resolve(styxJsDirectory, 'vendor', 'openmls-wasm', 'openmls_wasm_bg.wasm'));
  requireEqual(sha256(wasmBytes), B3_WASM_SHA256, 'OpenMLS-WASM artifact');
  const vendorReadme = readFileSync(resolve(styxJsDirectory, 'vendor', 'openmls-wasm', 'README.md'), 'utf8');
  if (!vendorReadme.includes(openMlsRevision)) throw new Error('OpenMLS source pin is absent');
  const b27Canonical = readFileSync(
    resolve(styxJsDirectory, 'spikes', 'marmot-phase-b2-7', 'b2-7-canonical.mjs'),
    'utf8',
  );
  if (!b27Canonical.includes(B3_MARMOT_REVISION)) throw new Error('Marmot specification pin drifted');

  requireEqual(git(marmotDirectory, 'rev-parse', 'HEAD'), B3_MARMOT_REVISION, 'Marmot head');
  requireEqual(git(marmotDirectory, 'rev-parse', 'HEAD^{tree}'), B3_MARMOT_TREE, 'Marmot tree');
  requireEqual(git(marmotDirectory, 'status', '--porcelain'), '', 'Marmot checkout cleanliness');

  requireEqual(git(mdkDirectory, 'rev-parse', 'HEAD'), B3_MDK_REVISION, 'MDK head');
  requireEqual(git(mdkDirectory, 'rev-parse', 'HEAD^{tree}'), B3_MDK_TREE, 'MDK tree');
  requireEqual(git(mdkDirectory, 'status', '--porcelain'), '', 'MDK checkout cleanliness');
  requireEqual(sha256(readFileSync(resolve(mdkDirectory, 'Cargo.lock'))), B3_MDK_LOCK_SHA256, 'MDK lock');
  const license = readFileSync(resolve(mdkDirectory, 'LICENSE'), 'utf8');
  if (!license.startsWith('MIT License') || !license.includes('2024-2026 Internet Privacy Foundation')) {
    throw new Error('MDK license identity drifted');
  }
  requireEqual(
    readFileSync(resolve(scriptDirectory, 'mdk-peer', 'Cargo.toml'), 'utf8'),
    expectedDriverManifest,
    'MDK driver manifest',
  );

  return {
    baseSha: B3_BASE_SHA,
    baseTree: B3_BASE_TREE,
    changedPaths: changed,
    marmotRevision: B3_MARMOT_REVISION,
    marmotTree: B3_MARMOT_TREE,
    mdkRevision: B3_MDK_REVISION,
    mdkTree: B3_MDK_TREE,
    mdkLockSha256: B3_MDK_LOCK_SHA256,
    openMlsRevision,
    wasmSha256: B3_WASM_SHA256,
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.stdout.write(`${JSON.stringify(verifyPins())}\n`);
}
