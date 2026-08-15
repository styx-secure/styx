// SPDX-License-Identifier: AGPL-3.0-or-later

import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { B31_MDK_LOCK_SHA256, B31_MDK_TREE } from '../marmot-phase-b3-1/b3-1-canonical.mjs';
import { B32_WASM_SHA256 } from '../marmot-phase-b3-2/b3-2-canonical.mjs';
import {
  B32A_BASE_SHA,
  B32A_BASE_TREE,
  B32A_MARMOT_REVISION,
  B32A_MDK_REVISION,
  B32A_OPENMLS_REVISION,
  B32A_WASM_SHA256,
} from './b3-2a-canonical.mjs';

const directory = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(directory, '..', '..', '..');
const mdkRoot = '/home/mverde/.local/share/styx-upstreams/mdk-9396adb6';

function git(cwd, ...args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
}
function sha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}
function requireEqual(actual, expected, label) {
  if (actual !== expected) throw new Error(`${label} drifted: expected ${expected}, got ${actual}`);
}

export function verifyPins() {
  requireEqual(git(repoRoot, 'rev-parse', `${B32A_BASE_SHA}^{tree}`), B32A_BASE_TREE, 'B3.2a base tree');
  execFileSync('git', ['merge-base', '--is-ancestor', B32A_BASE_SHA, 'HEAD'], { cwd: repoRoot });
  requireEqual(git(mdkRoot, 'rev-parse', 'HEAD'), B32A_MDK_REVISION, 'MDK revision');
  requireEqual(git(mdkRoot, 'rev-parse', 'HEAD^{tree}'), B31_MDK_TREE, 'MDK tree');
  requireEqual(git(mdkRoot, 'status', '--porcelain'), '', 'MDK worktree');
  requireEqual(sha256(resolve(mdkRoot, 'Cargo.lock')), B31_MDK_LOCK_SHA256, 'external MDK lockfile');
  const wasmSha256 = sha256(resolve(repoRoot, 'styx-js/vendor/openmls-wasm/openmls_wasm_bg.wasm'));
  requireEqual(wasmSha256, B32A_WASM_SHA256, 'installed B3.2a WASM');
  return Object.freeze({
    baseSha: B32A_BASE_SHA,
    baseTree: B32A_BASE_TREE,
    marmotRevision: B32A_MARMOT_REVISION,
    mdkRevision: B32A_MDK_REVISION,
    mdkTree: B31_MDK_TREE,
    mdkLockSha256: B31_MDK_LOCK_SHA256,
    openMlsRevision: B32A_OPENMLS_REVISION,
    outgoingB32WasmSha256: B32_WASM_SHA256,
    expectedB32aWasmSha256: B32A_WASM_SHA256,
    installedWasmSha256: wasmSha256,
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  process.stdout.write(`${JSON.stringify(verifyPins())}\n`);
}
