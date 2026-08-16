// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — fresh locked MDK peer build and executable identity.

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  constants,
  fstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  readdirSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { dirname, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { B33A_ERROR, B33A_MDK_BUILD_ROOT, failB33a }
  from './b3-3a-canonical.mjs';
import { readExactRegularFile } from './b3-3a-artifact-reader.mjs';

export const B33A_MDK_PEER_LOCK_SHA256 =
  'c42ccd8bc136421b265ee8544af260cbcdf9aa865fa7a1ace03c7c8cae257b4f';

const directory = dirname(fileURLToPath(import.meta.url));
const peerDirectory = resolve(directory, '..', 'marmot-phase-b3', 'mdk-peer');
const MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024;

function prepareEmptyBuildChild(path) {
  mkdirSync(B33A_MDK_BUILD_ROOT, { recursive: true, mode: 0o700 });
  chmodSync(B33A_MDK_BUILD_ROOT, 0o700);
  const candidate = resolve(path);
  const lexical = relative(resolve(B33A_MDK_BUILD_ROOT), candidate);
  if (!lexical || lexical === '..' || lexical.startsWith(`..${sep}`)) {
    failB33a(B33A_ERROR.INVALID, 'MDK build directory escaped its approved root');
  }
  mkdirSync(candidate, { recursive: false, mode: 0o700 });
  chmodSync(candidate, 0o700);
  const real = realpathSync(candidate);
  const rel = relative(realpathSync(B33A_MDK_BUILD_ROOT), real);
  if (!rel || rel === '..' || rel.startsWith(`..${sep}`) || readdirSync(real).length !== 0) {
    failB33a(B33A_ERROR.INVALID, 'MDK build directory is not a new empty strict child');
  }
  return real;
}

export function executableSha256(path) {
  if (!Number.isInteger(constants.O_NOFOLLOW)) {
    failB33a(B33A_ERROR.INVALID, 'O_NOFOLLOW is unavailable for MDK executable reads');
  }
  let descriptor;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.size < 1n
      || before.size > BigInt(MAX_EXECUTABLE_BYTES) || (before.mode & 0o111n) === 0n) {
      failB33a(B33A_ERROR.INVALID, 'MDK executable is not a bounded executable regular file');
    }
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor, { bigint: true });
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size
      || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs
      || BigInt(bytes.byteLength) !== after.size) {
      failB33a(B33A_ERROR.INVALID, 'MDK executable changed while it was being identified');
    }
    return createHash('sha256').update(bytes).digest('hex');
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function resolveCargo() {
  try {
    return Object.freeze({
      command: 'cargo',
      version: execFileSync('cargo', ['--version'], { encoding: 'utf8' }).trim(),
    });
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
    const command = resolve(homedir(), '.cargo', 'bin', 'cargo');
    return Object.freeze({
      command,
      version: execFileSync(command, ['--version'], { encoding: 'utf8' }).trim(),
    });
  }
}

export function buildMdkPeer(path) {
  const buildDirectory = prepareEmptyBuildChild(path);
  readExactRegularFile(
    resolve(peerDirectory, 'Cargo.lock'), B33A_MDK_PEER_LOCK_SHA256,
  );
  const cargo = resolveCargo();
  execFileSync(
    cargo.command, ['build', '--locked', '--target-dir', buildDirectory],
    { cwd: peerDirectory, stdio: 'inherit' },
  );
  const executable = resolve(buildDirectory, 'debug', 'styx-b3-mdk-peer');
  const executableReal = realpathSync(executable);
  const rel = relative(buildDirectory, executableReal);
  if (!rel || rel === '..' || rel.startsWith(`..${sep}`)) {
    failB33a(B33A_ERROR.INVALID, 'MDK executable escaped its fresh build directory');
  }
  return Object.freeze({
    executable: executableReal,
    evidence: Object.freeze({
      cargoCommand: 'cargo build --locked --target-dir <fresh-build-child>',
      cargoVersion: cargo.version,
      mdkExecutableSha256Hex: executableSha256(executableReal),
      mdkPeerCargoLockSha256Hex: B33A_MDK_PEER_LOCK_SHA256,
    }),
  });
}
