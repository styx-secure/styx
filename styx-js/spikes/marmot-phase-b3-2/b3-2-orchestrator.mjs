// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — exact-pin B3.2 bounded interoperability harness.

import { randomBytes } from 'node:crypto';
import {
  chmodSync,
  mkdirSync,
  realpathSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { spawnSync } from 'node:child_process';
import { relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { schnorr } from '@noble/curves/secp256k1';

import {
  B32Error,
  B32_ERROR,
  B32_FORMAT,
  B32_MDK_REVISION,
  B32_PRIVATE_ROOT,
  B32_RUN_ROOT,
  B32_VERSION,
  appendB32Transcript,
  canonicalJsonBytes,
  sha256Hex,
  validateB32Transcript,
} from './b3-2-canonical.mjs';
import { B32_MDK_DRIVER_PATH, MdkB32Peer } from './b3-2-mdk-driver.mjs';
import { StyxB32Peer } from './b3-2-styx-driver.mjs';
import { verifyPins } from './verify-pins.mjs';

const scriptPath = fileURLToPath(import.meta.url);

function parseArgs(args) {
  if (args.length === 3 && args[0] === '--verify-restart' && args[1] === '--private-dir') {
    return { mode: 'verify-restart', privateDirectory: args[2] };
  }
  if (args.length === 4 && args[0] === '--run-dir' && args[2] === '--private-dir') {
    return { mode: 'run', runDirectory: args[1], privateDirectory: args[3] };
  }
  throw new Error('usage: b3-2-orchestrator.mjs --run-dir PATH --private-dir PATH');
}

function prepareEmptyChild(path, root, label) {
  mkdirSync(root, { recursive: true, mode: 0o700 });
  chmodSync(root, 0o700);
  const candidate = resolve(path);
  const lexicalRel = relative(resolve(root), candidate);
  if (!lexicalRel || lexicalRel === '..' || lexicalRel.startsWith(`..${sep}`)) {
    throw new Error(`${label} escaped its approved root`);
  }
  mkdirSync(candidate, { recursive: false, mode: 0o700 });
  chmodSync(candidate, 0o700);
  const realRoot = realpathSync(root);
  const real = realpathSync(candidate);
  const rel = relative(realRoot, real);
  if (!rel || rel === '..' || rel.startsWith(`..${sep}`) || readdirSync(real).length !== 0
    || (statSync(real).mode & 0o077) !== 0) {
    throw new Error(`${label} is not an empty owner-only child of its approved root`);
  }
  return real;
}

function existingPrivateChild(path) {
  const root = realpathSync(B32_PRIVATE_ROOT);
  const real = realpathSync(path);
  const rel = relative(root, real);
  if (!rel || rel === '..' || rel.startsWith(`..${sep}`)) {
    throw new Error('B3.2 private path escaped its approved root');
  }
  return real;
}

function writeOwnerOnly(path, value) {
  writeFileSync(path, value, { flag: 'wx', mode: 0o600 });
  chmodSync(path, 0o600);
}

function accountSecret() {
  for (;;) {
    const candidate = Uint8Array.from(randomBytes(32));
    try {
      schnorr.getPublicKey(candidate);
      return candidate;
    } catch {
      // Rejection sampling for the negligible invalid-scalar case.
    }
  }
}

function validateMdkHello(value) {
  if (value?.mdk_revision !== B32_MDK_REVISION
    || value?.protocol !== 'styx-b3-mdk-peer-jsonl-v1'
    || value?.transport !== 'direct_mls_identity_wrapper') {
    throw new Error('MDK hello differs from the exact peer contract');
  }
  return value;
}

function validateMdkCreation(value) {
  if (value?.ratchet_tree_delivery !== 'embedded_in_encrypted_group_info_only'
    || value?.public_external_ratchet_tree_hex !== null
    || typeof value?.welcome_hex !== 'string'
    || sha256Hex(Buffer.from(value.welcome_hex, 'hex')) !== value.welcome_sha256) {
    throw new Error('MDK creation does not contain one exact embedded-tree Welcome');
  }
  return value;
}

async function restartMode(privateDirectory) {
  const peer = await StyxB32Peer.open(existingPrivateChild(privateDirectory));
  process.stdout.write(`${JSON.stringify(await peer.verifyJoined())}\n`);
}

function restartInFreshProcess(privateDirectory) {
  const child = spawnSync(process.execPath, [
    scriptPath, '--verify-restart', '--private-dir', privateDirectory,
  ], { encoding: 'utf8', timeout: 60_000 });
  if (child.error || child.status !== 0) {
    throw new Error(`fresh-process verification failed: ${child.error?.message ?? child.stderr}`);
  }
  const lines = child.stdout.trim().split('\n');
  return JSON.parse(lines.at(-1));
}

function typedFailure(error) {
  if (error instanceof B32Error) {
    return Object.freeze({ code: error.code, message: error.message.slice(0, 512) });
  }
  if (typeof error?.code === 'string' && /^[a-z0-9_-]{1,64}$/.test(error.code)) {
    return Object.freeze({ code: error.code, message: String(error.message).slice(0, 512) });
  }
  return null;
}

async function runMode(args) {
  const runDirectory = prepareEmptyChild(resolve(args.runDirectory), B32_RUN_ROOT, 'run directory');
  const privateDirectory = prepareEmptyChild(
    resolve(args.privateDirectory), B32_PRIVATE_ROOT, 'private directory',
  );
  const transcript = [];
  let mdk;
  let report;
  let blocked;
  try {
    const pins = appendB32Transcript(transcript, 'verify_pins', verifyPins());
    const mdkSecret = accountSecret();
    const mdkAccountIdentityHex = Buffer.from(schnorr.getPublicKey(mdkSecret)).toString('hex');
    const mdkSecretPath = resolve(privateDirectory, 'mdk-account-secret.hex');
    const databaseKeyPath = resolve(privateDirectory, 'mdk-database-key.hex');
    const databasePath = resolve(privateDirectory, 'mdk-account.sqlite3');
    writeOwnerOnly(mdkSecretPath, Buffer.from(mdkSecret).toString('hex'));
    writeOwnerOnly(databaseKeyPath, randomBytes(32).toString('hex'));

    const styx = await StyxB32Peer.create(privateDirectory, mdkAccountIdentityHex);
    const keyPackage = appendB32Transcript(
      transcript, 'styx_advertise_durable_b31_key_package', await styx.publicKeyPackage(),
    );
    mdk = new MdkB32Peer();
    appendB32Transcript(transcript, 'mdk_hello', validateMdkHello(await mdk.request('hello')));
    appendB32Transcript(transcript, 'mdk_initialize', await mdk.request('initialize', {
      account_identity_hex: mdkAccountIdentityHex,
      database_key_path: databaseKeyPath,
      database_path: databasePath,
      node_binary: process.execPath,
      signer_script: B32_MDK_DRIVER_PATH,
      signer_secret_path: mdkSecretPath,
    }));
    const creation = appendB32Transcript(
      transcript,
      'mdk_create_group_with_embedded_tree_welcome',
      validateMdkCreation(await mdk.request('create_group', {
        key_package_hex: keyPackage.keyPackageHex,
      })),
    );
    const recorded = await styx.recordWelcome(creation.welcome_hex);
    appendB32Transcript(transcript, 'styx_durable_welcome_recorded_before_engine', {
      headDigestHex: recorded.headDigestHex,
      sequence: recorded.sequence,
      state: recorded.state,
      welcomeSha256Hex: recorded.welcomeBlobSha256Hex,
    });
    const joined = await styx.joinRecordedWelcome();
    if (joined.projection.groupIdHex !== creation.group_id_hex
      || joined.projection.welcomeAuthor.identityHex !== mdkAccountIdentityHex) {
      throw new B32Error(B32_ERROR.PROJECTION_MISMATCH, 'joined projection differs from MDK creation');
    }
    appendB32Transcript(transcript, 'styx_joined_cas_and_fresh_provider_restore', {
      groupIdHex: joined.projection.groupIdHex,
      headDigestHex: joined.head.headDigestHex,
      independentPreparationsEqual: joined.independentPreparationsEqual,
      projectionRecordSha256Hex: joined.head.projectionRecordSha256Hex,
      restartedProjectionRecordSha256: joined.restartedProjectionRecordSha256,
      state: joined.head.state,
    });
    const processRestart = appendB32Transcript(
      transcript,
      'styx_kill_restart_fresh_process_restore',
      restartInFreshProcess(privateDirectory),
    );
    appendB32Transcript(transcript, 'mdk_acknowledge_durable_welcome_delivery', await mdk.request(
      'confirm_published', { welcome_message_id_hex: creation.welcome_message_id_hex },
    ));
    const transcriptHeadSha256 = validateB32Transcript(transcript);
    report = Object.freeze({
      format: B32_FORMAT,
      version: B32_VERSION,
      disposition: 'GO',
      compatibilityEstablished: false,
      durableRestartedWelcomeJoinEstablished: true,
      applicationTrafficTested: false,
      claim: 'B3.2 established only the exact pinned MDK-founder to Styx-joiner embedded-tree Welcome path through durable JOINED activation and a fresh process restart.',
      testedPins: pins,
      groupIdHex: joined.projection.groupIdHex,
      welcomeSha256Hex: joined.projection.welcomeSha256Hex,
      projectionRecordSha256Hex: joined.head.projectionRecordSha256Hex,
      processRestart,
      transcriptHeadSha256,
    });
  } catch (error) {
    const typed = typedFailure(error);
    if (typed && typed.code !== B32_ERROR.PERSISTENCE_FAILED) {
      appendB32Transcript(transcript, 'first_typed_incompatibility', typed);
      report = Object.freeze({
        format: B32_FORMAT,
        version: B32_VERSION,
        disposition: 'NO-GO',
        compatibilityEstablished: false,
        durableRestartedWelcomeJoinEstablished: false,
        applicationTrafficTested: false,
        claim: 'B3.2 stopped at the first typed exact-pin incompatibility without weakening either peer.',
        firstIncompatibleOperation: transcript.at(-2)?.operation ?? 'unknown',
        failure: typed,
        transcriptHeadSha256: validateB32Transcript(transcript),
      });
    } else {
      blocked = error;
      appendB32Transcript(transcript, 'environment_or_persistence_block', {
        code: error?.code ?? 'B32_BLOCKED',
        message: String(error?.message ?? error).slice(0, 512),
      });
      report = Object.freeze({
        format: B32_FORMAT,
        version: B32_VERSION,
        disposition: 'BLOCKED',
        compatibilityEstablished: false,
        durableRestartedWelcomeJoinEstablished: false,
        applicationTrafficTested: false,
        claim: 'B3.2 produced no interoperability classification because its environment or durability primitive failed.',
        transcriptHeadSha256: validateB32Transcript(transcript),
      });
    }
  } finally {
    if (mdk) await mdk.close().catch(() => {});
    writeOwnerOnly(resolve(runDirectory, 'transcript.json'), canonicalJsonBytes(transcript));
    writeOwnerOnly(resolve(runDirectory, 'report.json'), canonicalJsonBytes(report));
    rmSync(existingPrivateChild(privateDirectory), { recursive: true, force: false });
  }
  process.stdout.write(`${JSON.stringify({
    disposition: report.disposition,
    report: resolve(runDirectory, 'report.json'),
  })}\n`);
  if (blocked) throw blocked;
}

const args = parseArgs(process.argv.slice(2));
if (args.mode === 'verify-restart') await restartMode(args.privateDirectory);
else await runMode(args);
