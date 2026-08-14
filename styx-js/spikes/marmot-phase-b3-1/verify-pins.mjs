// SPDX-License-Identifier: AGPL-3.0-or-later

import { execFileSync } from 'node:child_process';
import { readFileSync, statSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  B31_BASE_SHA,
  B31_BASE_TREE,
  B31_LOCAL_MDK_LOCK_SHA256,
  B31_MARMOT_REVISION,
  B31_MARMOT_TREE,
  B31_MDK_LOCK_SHA256,
  B31_MDK_REVISION,
  B31_MDK_TREE,
  B31_OPENMLS_REVISION,
  B31_STAGE1_SHA,
  B31_STAGE1_TREE,
  B31_WASM_SHA256,
  sha256,
} from './b3-1-canonical.mjs';

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const styxJsDirectory = resolve(scriptDirectory, '..', '..');
const repositoryDirectory = resolve(styxJsDirectory, '..');
const marmotDirectory = '/home/mverde/.local/share/styx-upstreams/marmot-4ad4ae21';
const mdkDirectory = '/home/mverde/.local/share/styx-upstreams/mdk-9396adb6';
const generatedCargoTargetPrefix = 'styx-js/spikes/marmot-phase-b3/mdk-peer/target/';

const allowedPaths = new Set([
  'docs/architecture/spikes/2026-08-14-marmot-openmls-phase-b3-1.md',
  'styx-js/spikes/marmot-phase-b2-7/b2-7-canonical.mjs',
  'styx-js/spikes/marmot-phase-b2-7/generate-b2-2-fixture.mjs',
  'styx-js/spikes/marmot-phase-b3/b3-mdk-driver.mjs',
  'styx-js/spikes/marmot-phase-b3/b3-styx-driver.mjs',
  'styx-js/spikes/marmot-phase-b3-1/README.md',
  'styx-js/spikes/marmot-phase-b3-1/b3-1-canonical.mjs',
  'styx-js/spikes/marmot-phase-b3-1/b3-1-mdk-driver.mjs',
  'styx-js/spikes/marmot-phase-b3-1/b3-1-orchestrator.mjs',
  'styx-js/spikes/marmot-phase-b3-1/b3-1-styx-driver.mjs',
  'styx-js/spikes/marmot-phase-b3-1/generate-b2-7-legacy-fixture.mjs',
  'styx-js/spikes/marmot-phase-b3-1/verify-pins.mjs',
  'styx-js/src/crypto/mls/mls-build-info.js',
  'styx-js/test/crypto/kdf-wasm.test.js',
  'styx-js/test/crypto/mls-phase-b2-7-sender-attribution.test.js',
  'styx-js/test/crypto/mls-phase-b2-surface.test.js',
  'styx-js/test/crypto/mls-phase-b3-1-group-profile.test.js',
  'styx-js/test/crypto/mls-phase-b3-1-mdk-interop.test.js',
  'styx-js/test/crypto/mls-state-restore.test.js',
  'styx-js/test/fixtures/mls-state-b2-2/README.md',
  'styx-js/test/fixtures/mls-state-b2-7/README.md',
  'styx-js/test/fixtures/mls-state-b2-7/context.json',
  'styx-js/test/fixtures/mls-state-b2-7/envelope.json',
  'styx-js/test/storage/mls-state-envelope.test.js',
  'styx-js/vendor/openmls-wasm/PROVENANCE.md',
  'styx-js/vendor/openmls-wasm/README.md',
  'styx-js/vendor/openmls-wasm/openmls_wasm.d.ts',
  'styx-js/vendor/openmls-wasm/openmls_wasm.js',
  'styx-js/vendor/openmls-wasm/openmls_wasm_bg.wasm',
  'styx-js/vendor/openmls-wasm/openmls_wasm_bg.wasm.d.ts',
  'styx-js/vendor/openmls-wasm/package.json',
  'styx-js/vendor/openmls-wasm/patch/lib.rs',
]);

const copyDetectionOperands = Object.freeze({
  'styx-js/spikes/marmot-phase-b2-7/generate-b2-2-fixture.mjs': Object.freeze({
    blob: 'ba5e0a98a35c48d88aac06752aeed6570b773a53',
    bytes: 7551,
    sha256: '28b203f136dcac524e44cdb8a05c57823135e9448f18f881ac1100c61cb593dd',
  }),
  'styx-js/spikes/marmot-phase-b3/b3-mdk-driver.mjs': Object.freeze({
    blob: 'eed2d4cfe5af56b7e58d4f27f15f94fbae0e1602',
    bytes: 4446,
    sha256: '4402958b3ba78755a298f63240de6cdd2cbcd1060137359209488f2c9adbc13d',
  }),
  'styx-js/spikes/marmot-phase-b3/b3-styx-driver.mjs': Object.freeze({
    blob: '33cea719ee49486f99b6094a282eb366aad6e4e6',
    bytes: 5353,
    sha256: 'bc757f16bf01d995a9d19a56dc7e6800edba460a54482d1bb7654caa78aba343',
  }),
  'styx-js/test/fixtures/mls-state-b2-2/README.md': Object.freeze({
    blob: '9d9d780ceebce77b6cb38e2b30c39afd19d79c6f',
    bytes: 2671,
    sha256: 'eb2bac1820f45a78648d804c2f2315b517e095cfa7d9a803fb00a52a75595314',
  }),
});

const artifactTuple = Object.freeze({
  'openmls_wasm.d.ts': Object.freeze({
    bytes: 38382,
    sha256: '12261438fb80343e691e72e4f724353440b2204b1b34dddbdc6b28deaff1ab25',
  }),
  'openmls_wasm.js': Object.freeze({
    bytes: 109796,
    sha256: 'd717ba80473bd83d1f2897b241db5398f34055af90cdc8bd077cdf5ed1131f10',
  }),
  'openmls_wasm_bg.wasm': Object.freeze({
    bytes: 2094818,
    sha256: B31_WASM_SHA256,
  }),
  'openmls_wasm_bg.wasm.d.ts': Object.freeze({
    bytes: 20950,
    sha256: '77be53fb3933aede8bf25375b1e233410ef6a62004cba4921d553ed9bfdd1023',
  }),
  'package.json': Object.freeze({
    bytes: 449,
    sha256: '88f2ec1e2a5c1904b0fc1d147221c32ba6dcbf1cb4441c53b04a1b2a03bd1d85',
  }),
});

function git(cwd, ...args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
}

function requireEqual(actual, expected, label) {
  if (actual !== expected) throw new Error(`${label} mismatch: ${actual}`);
}

function verifyArtifactTuple() {
  const vendor = resolve(styxJsDirectory, 'vendor', 'openmls-wasm');
  const result = {};
  for (const [name, expected] of Object.entries(artifactTuple)) {
    const path = resolve(vendor, name);
    const bytes = readFileSync(path);
    requireEqual(statSync(path).size, expected.bytes, `${name} byte length`);
    requireEqual(sha256(bytes), expected.sha256, `${name} digest`);
    result[name] = expected;
  }
  return result;
}

function verifyCopyDetectionOperands() {
  const result = {};
  for (const [path, expected] of Object.entries(copyDetectionOperands)) {
    const absolutePath = resolve(repositoryDirectory, path);
    const bytes = readFileSync(absolutePath);
    requireEqual(
      git(repositoryDirectory, 'rev-parse', `${B31_BASE_SHA}:${path}`),
      expected.blob,
      `${path} base blob`,
    );
    requireEqual(
      git(repositoryDirectory, 'hash-object', '--', path),
      expected.blob,
      `${path} working-tree blob`,
    );
    requireEqual(statSync(absolutePath).size, expected.bytes, `${path} byte length`);
    requireEqual(sha256(bytes), expected.sha256, `${path} digest`);
    result[path] = expected;
  }
  return result;
}

export function verifyPins() {
  requireEqual(git(repositoryDirectory, 'rev-parse', `${B31_BASE_SHA}^{tree}`),
    B31_BASE_TREE, 'base tree');
  requireEqual(git(repositoryDirectory, 'rev-parse', `${B31_STAGE1_SHA}^{tree}`),
    B31_STAGE1_TREE, 'Stage 1 tree');
  execFileSync('git', ['merge-base', '--is-ancestor', B31_STAGE1_SHA, 'HEAD'], {
    cwd: repositoryDirectory,
    stdio: 'ignore',
  });

  const trackedChanges = git(repositoryDirectory, 'diff', '--name-only', B31_BASE_SHA, '--')
    .split('\n').filter(Boolean);
  const untrackedChanges = git(repositoryDirectory, 'ls-files', '--others', '--exclude-standard')
    .split('\n').filter((path) => path && !path.startsWith(generatedCargoTargetPrefix));
  const changed = [...new Set([...trackedChanges, ...untrackedChanges])].sort();
  const outOfScope = changed.filter((path) => !allowedPaths.has(path));
  if (outOfScope.length > 0) throw new Error(`out-of-scope paths: ${outOfScope.join(', ')}`);

  const installedArtifactTuple = verifyArtifactTuple();
  const verifiedCopyDetectionOperands = verifyCopyDetectionOperands();
  const patchSource = readFileSync(
    resolve(styxJsDirectory, 'vendor', 'openmls-wasm', 'patch', 'lib.rs'),
    'utf8',
  );
  if (!patchSource.includes('const PHASE_B2_COMPONENTS: [ComponentId; 3]')) {
    throw new Error('frozen Phase B2 component profile is absent');
  }
  if (!patchSource.includes('const PHASE_B31_SUPPORTED_COMPONENTS: [ComponentId; 4]')) {
    throw new Error('isolated Phase B3.1 component profile is absent');
  }
  const vendorReadme = readFileSync(
    resolve(styxJsDirectory, 'vendor', 'openmls-wasm', 'README.md'),
    'utf8',
  );
  if (!vendorReadme.includes(B31_OPENMLS_REVISION)) throw new Error('OpenMLS pin is absent');

  requireEqual(
    sha256(readFileSync(resolve(styxJsDirectory, 'vendor', 'openmls-wasm', 'Cargo.lock'))),
    '33964e33f6a48e8b9982c5894c4a7e9ddc5ee2e5157c763596393a08c607672b',
    'OpenMLS-WASM lock',
  );
  requireEqual(
    sha256(readFileSync(resolve(styxJsDirectory, 'spikes', 'marmot-phase-b3',
      'mdk-peer', 'Cargo.lock'))),
    B31_LOCAL_MDK_LOCK_SHA256,
    'local MDK peer lock',
  );

  requireEqual(git(marmotDirectory, 'rev-parse', 'HEAD'), B31_MARMOT_REVISION, 'Marmot head');
  requireEqual(git(marmotDirectory, 'rev-parse', 'HEAD^{tree}'), B31_MARMOT_TREE, 'Marmot tree');
  requireEqual(git(marmotDirectory, 'status', '--porcelain'), '', 'Marmot cleanliness');
  requireEqual(git(mdkDirectory, 'rev-parse', 'HEAD'), B31_MDK_REVISION, 'MDK head');
  requireEqual(git(mdkDirectory, 'rev-parse', 'HEAD^{tree}'), B31_MDK_TREE, 'MDK tree');
  requireEqual(git(mdkDirectory, 'status', '--porcelain'), '', 'MDK cleanliness');
  requireEqual(sha256(readFileSync(resolve(mdkDirectory, 'Cargo.lock'))),
    B31_MDK_LOCK_SHA256, 'MDK lock');
  const license = readFileSync(resolve(mdkDirectory, 'LICENSE'), 'utf8');
  if (!license.startsWith('MIT License')
    || !license.includes('2024-2026 Internet Privacy Foundation')) {
    throw new Error('MDK license identity drifted');
  }

  const fixture = resolve(styxJsDirectory, 'test', 'fixtures', 'mls-state-b2-7');
  requireEqual(sha256(readFileSync(resolve(fixture, 'context.json'))),
    'bce0e4f5e1bafbbf0239145161557a748db4c2792a8aa5bd33c6ea7bb2fc047d',
    'B2.7 fixture context');
  requireEqual(sha256(readFileSync(resolve(fixture, 'envelope.json'))),
    'fe33df74090d6d792b2715c468d5e6c19b87ad6bb0aeab335ee2180c331d20ad',
    'B2.7 fixture envelope');

  return {
    artifactTuple: installedArtifactTuple,
    baseSha: B31_BASE_SHA,
    baseTree: B31_BASE_TREE,
    changedPaths: changed,
    copyDetectionOperands: verifiedCopyDetectionOperands,
    marmotRevision: B31_MARMOT_REVISION,
    marmotTree: B31_MARMOT_TREE,
    mdkLockSha256: B31_MDK_LOCK_SHA256,
    mdkRevision: B31_MDK_REVISION,
    mdkTree: B31_MDK_TREE,
    openMlsRevision: B31_OPENMLS_REVISION,
    stage1Sha: B31_STAGE1_SHA,
    stage1Tree: B31_STAGE1_TREE,
    wasmSha256: B31_WASM_SHA256,
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.stdout.write(`${JSON.stringify(verifyPins())}\n`);
}
