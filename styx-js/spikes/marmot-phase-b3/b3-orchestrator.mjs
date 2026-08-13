// SPDX-License-Identifier: AGPL-3.0-or-later

import { randomBytes } from 'node:crypto';
import { chmodSync, rmSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { schnorr } from '@noble/curves/secp256k1';

import {
  B3_FORMAT,
  B3_MDK_REVISION,
  B3_PRIVATE_ROOT,
  B3_RUN_ROOT,
  B3_VERSION,
  assertExistingScopedDirectory,
  canonicalJson,
  prepareScopedDirectory,
  sha256,
} from './b3-canonical.mjs';
import { B3_MDK_DRIVER_PATH, MdkPeer } from './b3-mdk-driver.mjs';
import { StyxPeer } from './b3-styx-driver.mjs';
import { verifyPins } from './verify-pins.mjs';

function parseArgs(args) {
  if (args.length !== 4 || args[0] !== '--run-dir' || args[2] !== '--private-dir') {
    throw new Error('usage: b3-orchestrator.mjs --run-dir PATH --private-dir PATH');
  }
  return { runDirectory: args[1], privateDirectory: args[3] };
}

function ownerOnlyWrite(path, value) {
  writeFileSync(path, value, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
  chmodSync(path, 0o600);
}

function accountSecret() {
  for (;;) {
    const candidate = randomBytes(32);
    try {
      schnorr.getPublicKey(candidate);
      return Uint8Array.from(candidate);
    } catch {
      // Rejection sampling for the negligible out-of-range case.
    }
  }
}

function appendTranscript(transcript, operation, evidence) {
  const previous = transcript.length === 0 ? '0'.repeat(64) : transcript.at(-1).recordSha256;
  const record = { evidence, operation, previousRecordSha256: previous, sequence: transcript.length + 1 };
  record.recordSha256 = sha256(canonicalJson(record));
  transcript.push(record);
  return evidence;
}

async function run() {
  const args = parseArgs(process.argv.slice(2));
  const pins = verifyPins();
  const runDirectory = prepareScopedDirectory(args.runDirectory, B3_RUN_ROOT, 0o700);
  const privateDirectory = prepareScopedDirectory(args.privateDirectory, B3_PRIVATE_ROOT, 0o700);
  const transcript = [];
  let mdk;
  let report;
  try {
    appendTranscript(transcript, 'verify_pins', pins);
    const styx = await StyxPeer.create(privateDirectory);
    const keyPackage = appendTranscript(transcript, 'styx_key_package_after_restart', styx.publicKeyPackage());

    const mdkSecret = accountSecret();
    const mdkSecretPath = resolve(privateDirectory, 'mdk-account-secret.hex');
    const databaseKeyPath = resolve(privateDirectory, 'mdk-database-key.hex');
    const databasePath = resolve(privateDirectory, 'mdk-account.sqlite3');
    ownerOnlyWrite(mdkSecretPath, Buffer.from(mdkSecret).toString('hex'));
    ownerOnlyWrite(databaseKeyPath, randomBytes(32).toString('hex'));
    const mdkAccountIdentityHex = Buffer.from(schnorr.getPublicKey(mdkSecret)).toString('hex');

    mdk = new MdkPeer();
    appendTranscript(transcript, 'mdk_hello', await mdk.request('hello'));
    appendTranscript(
      transcript,
      'mdk_initialize',
      await mdk.request('initialize', {
        account_identity_hex: mdkAccountIdentityHex,
        database_key_path: databaseKeyPath,
        database_path: databasePath,
        node_binary: process.execPath,
        signer_script: B3_MDK_DRIVER_PATH,
        signer_secret_path: mdkSecretPath,
      }),
    );
    let creation;
    try {
      creation = appendTranscript(
        transcript,
        'mdk_create_group_from_styx_key_package',
        await mdk.request('create_group', { key_package_hex: keyPackage.keyPackageHex }),
      );
    } catch (error) {
      if (error.code !== 'mdk_missing_required_capabilities') throw error;
      const rejection = appendTranscript(transcript, 'mdk_reject_styx_key_package', {
        code: error.code,
        details: error.details,
        message: error.message,
      });
      const missing = rejection.details?.missing_app_components;
      if (!Array.isArray(missing) || missing.length !== 1 || missing[0] !== 0x8001) {
        throw new Error('MDK rejection did not identify the expected single 0x8001 gap');
      }
      report = {
        format: B3_FORMAT,
        version: B3_VERSION,
        disposition: 'NO-GO',
        compatibilityEstablished: false,
        firstIncompatibleOperation: 'mdk_create_group_from_styx_key_package',
        testedPins: pins,
        acceptedBeforeBoundary: {
          styxDurableRestart: true,
          styxKeyPackageSha256: keyPackage.keyPackageSha256,
          styxKeyPackageParsedByItsPublicCurrentProfileReader: true,
        },
        rejectedValue: {
          componentIdDecimal: 0x8001,
          componentIdHex: '8001',
          kind: 'missing_required_application_component',
          keyPackageSha256: keyPackage.keyPackageSha256,
        },
        typedOutcomes: {
          mdk: rejection,
          styx: {
            advertisedComponentIds: keyPackage.supportedComponentIds,
            code: 'STYX_KEY_PACKAGE_MISSING_MDK_REQUIRED_GROUP_PROFILE_COMPONENT',
            missingComponentIds: [0x8001],
          },
        },
        pinnedNormativeRule: {
          mdk: 'At 9396adb6, current-profile founding requires every invitee KeyPackage to advertise all engine-owned default group components; 0x8001 is marmot.group.profile.v1.',
          styx: 'The exact B2.7 public KeyPackage advertises 0x8003, 0x8009 and 0x800c, but not 0x8001.',
        },
        smallestHypotheticalRemedy: 'Extend the Styx current-profile KeyPackage capability set and validated component model to include marmot.group.profile.v1 (0x8001), then rebuild the pinned OpenMLS-WASM artifact and repeat B3 from a new approved baseline.',
        remedyOutsideContract: 'Issue #165 freezes the OpenMLS-WASM interface, feature set and artifact and forbids vendor changes or validator relaxation.',
        claim: `B3 did not establish Styx/MDK interoperability at MDK ${B3_MDK_REVISION}; MDK rejected the exact Styx KeyPackage before group creation.`,
        transcriptHeadSha256: transcript.at(-1).recordSha256,
      };
    }

    if (!report) {
      appendTranscript(
        transcript,
        'mdk_acknowledge_welcome_delivery',
        await mdk.request('confirm_published', {
          welcome_message_id_hex: creation.welcome_message_id_hex,
        }),
      );
      const styxJoinError = appendTranscript(
        transcript,
        'styx_join_without_external_ratchet_tree',
        styx.proveJoinRequiresExternalRatchetTree(creation.welcome_hex),
      );
      report = {
        format: B3_FORMAT,
        version: B3_VERSION,
        disposition: 'NO-GO',
        compatibilityEstablished: false,
        firstIncompatibleOperation: 'styx_join_mdk_welcome',
        testedPins: pins,
        acceptedBeforeBoundary: {
          styxKeyPackageSha256: keyPackage.keyPackageSha256,
          mdkGroupIdHex: creation.group_id_hex,
          mdkWelcomeSha256: creation.welcome_sha256,
        },
        rejectedValue: {
          kind: 'missing_public_external_ratchet_tree',
          welcomeSha256: creation.welcome_sha256,
          value: null,
        },
        typedOutcomes: {
          mdk: {
            code: 'MDK_PUBLIC_API_EMBEDS_TREE_WITHOUT_EXTERNAL_EXPORT',
            createDisposition: 'FoundingGroupCreated',
            ratchetTreeDelivery: creation.ratchet_tree_delivery,
          },
          styx: styxJoinError,
        },
        pinnedNormativeRule: {
          mdk: 'Current-profile groups set use_ratchet_tree_extension(true); the public founding result carries Welcome transport messages, not an external RatchetTree value.',
          styx: 'PhaseB2Group.join(provider, welcome_bytes, ratchet_tree) requires a PhaseB2RatchetTree object and exposes no embedded-tree join overload.',
        },
        smallestHypotheticalRemedy: 'Add a separate Styx Phase B join API that permits OpenMLS to consume the authenticated RatchetTree extension embedded in the Welcome GroupInfo, while retaining all current-profile validation.',
        remedyOutsideContract: 'The OpenMLS-WASM interface and vendored artifact are frozen and forbidden paths in Issue #165.',
        claim: `B3 did not establish Styx/MDK interoperability at MDK ${B3_MDK_REVISION}; the exact flow stops at Welcome join.`,
        transcriptHeadSha256: transcript.at(-1).recordSha256,
      };
    }
    writeFileSync(resolve(runDirectory, 'transcript.json'), canonicalJson(transcript), {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o600,
    });
    writeFileSync(resolve(runDirectory, 'report.json'), canonicalJson(report), {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o600,
    });
  } finally {
    if (mdk) await mdk.close().catch(() => {});
    const validatedPrivateDirectory = assertExistingScopedDirectory(privateDirectory, B3_PRIVATE_ROOT);
    rmSync(validatedPrivateDirectory, { recursive: true, force: false });
  }
  process.stdout.write(`${JSON.stringify({ disposition: report.disposition, report: resolve(runDirectory, 'report.json') })}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await run();
}
