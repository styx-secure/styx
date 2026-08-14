// SPDX-License-Identifier: AGPL-3.0-or-later

import { randomBytes } from 'node:crypto';
import { chmodSync, rmSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { schnorr } from '@noble/curves/secp256k1';

import {
  B31_FORMAT,
  B31_FOUNDING_DESCRIPTION,
  B31_FOUNDING_NAME,
  B31_GROUP_CONTEXT_COMPONENT_IDS,
  B31_PRIVATE_ROOT,
  B31_REQUIRED_COMPONENT_IDS,
  B31_RUN_ROOT,
  B31_SUPPORTED_COMPONENT_IDS,
  B31_VERSION,
  appendTranscript,
  assertExactComponentIds,
  assertExactKeys,
  assertExistingScopedDirectory,
  assertLowerHex,
  bytesEqual,
  canonicalJson,
  decodeGroupProfileBytes,
  hexBytes,
  prepareScopedDirectory,
  sha256,
  validateB31Report,
  validateTranscript,
} from './b3-1-canonical.mjs';
import { B31_MDK_DRIVER_PATH, MdkB31Peer } from './b3-1-mdk-driver.mjs';
import { StyxB31Peer } from './b3-1-styx-driver.mjs';
import { verifyPins } from './verify-pins.mjs';

function parseArgs(args) {
  if (args.length !== 4 || args[0] !== '--run-dir' || args[2] !== '--private-dir') {
    throw new Error('usage: b3-1-orchestrator.mjs --run-dir PATH --private-dir PATH');
  }
  return { privateDirectory: args[3], runDirectory: args[1] };
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

function typedPeerError(error, fallbackCode) {
  const code = typeof error?.code === 'string' && /^[a-z0-9_-]{1,64}$/.test(error.code)
    ? error.code
    : fallbackCode;
  let details = null;
  if (code === 'mdk_missing_required_capabilities') {
    const missing = error?.details?.missing_app_components;
    const required = error?.details?.required?.app_components;
    const had = error?.details?.had?.app_components;
    if (Array.isArray(missing) && Array.isArray(required) && Array.isArray(had)
      && [...missing, ...required, ...had].every(Number.isInteger)) {
      details = {
        hadAppComponents: [...had],
        missingAppComponents: [...missing],
        requiredAppComponents: [...required],
      };
    }
  }
  return Object.freeze({ code, details });
}

function initialProfileEvidence(expected) {
  return {
    descriptionSha256: sha256(expected.description),
    exactProfileByteEquality: null,
    expectedProfileStateSha256: sha256(expected.encoded),
    groupContextSha256: null,
    groupContextComponentIds: null,
    nameSha256: sha256(expected.name),
    profileStateSha256: null,
    projectionSha256: null,
    requiredComponentIds: null,
    styxDecodedMdkProfile: false,
  };
}

function validateMdkProjection(projection, creationGroupIdHex, expected) {
  assertExactKeys(projection, [
    'admin_identities_hex',
    'app_components',
    'convergence_status',
    'epoch',
    'exporter_commitment_sha256',
    'group_context_sha256',
    'group_description',
    'group_id_hex',
    'group_name',
    'leaves',
    'protocol_lifecycle',
    'protocol_profile',
    'required_capabilities',
    'selected_branch_id',
    'sorted_member_identities_hex',
  ], 'MDK conformance projection');
  if (projection.group_id_hex !== creationGroupIdHex) {
    throw new Error('MDK projection group id differs from creation result');
  }
  if (projection.group_name !== B31_FOUNDING_NAME
    || projection.group_description !== B31_FOUNDING_DESCRIPTION) {
    throw new Error('MDK projection changed the exact founding profile text');
  }
  assertLowerHex(projection.group_context_sha256, 32, 'MDK GroupContext digest');
  assertExactKeys(projection.required_capabilities, [
    'app_components', 'credentials', 'extensions', 'proposals',
  ], 'MDK required capabilities');
  const required = [...projection.required_capabilities.app_components];
  assertExactComponentIds(required, B31_REQUIRED_COMPONENT_IDS, 'MDK required components');

  if (!Array.isArray(projection.app_components)) {
    throw new TypeError('MDK app_components must be an array');
  }
  for (const component of projection.app_components) {
    assertExactKeys(component, ['component_id', 'data_hex'], 'MDK app component');
    if (!Number.isInteger(component.component_id)) {
      throw new TypeError('MDK component id must be an integer');
    }
  }
  const groupContextComponentIds = projection.app_components.map((entry) => entry.component_id);
  assertExactComponentIds(
    groupContextComponentIds,
    B31_GROUP_CONTEXT_COMPONENT_IDS,
    'MDK GroupContext components',
  );
  const profile = projection.app_components.find(
    (entry) => entry.component_id === 0x8001,
  );
  if (!profile) throw new Error('MDK projection lacks group-profile state');
  const profileBytes = hexBytes(profile.data_hex, 'MDK group-profile state', 4098);
  const decoded = decodeGroupProfileBytes(profileBytes);
  const exactProfileByteEquality = bytesEqual(profileBytes, expected.encoded);
  if (!exactProfileByteEquality
    || !bytesEqual(decoded.name, expected.name)
    || !bytesEqual(decoded.description, expected.description)) {
    throw new Error('MDK group-profile bytes differ from the Styx canonical encoding');
  }
  return {
    descriptionSha256: sha256(decoded.description),
    exactProfileByteEquality,
    expectedProfileStateSha256: sha256(expected.encoded),
    groupContextComponentIds,
    groupContextSha256: projection.group_context_sha256,
    nameSha256: sha256(decoded.name),
    profileStateSha256: sha256(profileBytes),
    projectionSha256: sha256(canonicalJson(projection)),
    requiredComponentIds: required,
    styxDecodedMdkProfile: true,
  };
}

function finalizeReport({
  acceptedBeforeBoundary,
  claim,
  disposition,
  firstIncompatibleOperation,
  pins,
  profileEvidence,
  rejectedValue,
  transcript,
  typedOutcomes,
}) {
  const transcriptHeadSha256 = validateTranscript(transcript);
  const report = {
    acceptedBeforeBoundary,
    claim,
    compatibilityEstablished: false,
    disposition,
    firstIncompatibleOperation,
    format: B31_FORMAT,
    profileEvidence,
    rejectedValue,
    testedPins: pins,
    transcriptHeadSha256,
    typedOutcomes,
    version: B31_VERSION,
  };
  validateB31Report(report, transcriptHeadSha256);
  return report;
}

async function run() {
  const args = parseArgs(process.argv.slice(2));
  const pins = verifyPins();
  const runDirectory = prepareScopedDirectory(args.runDirectory, B31_RUN_ROOT, 0o700);
  const privateDirectory = prepareScopedDirectory(
    args.privateDirectory,
    B31_PRIVATE_ROOT,
    0o700,
  );
  const transcript = [];
  let mdk;
  let report;
  try {
    appendTranscript(transcript, 'verify_pins', pins);
    const styx = await StyxB31Peer.create(privateDirectory);
    const keyPackage = appendTranscript(
      transcript,
      'styx_b31_key_package_after_restart',
      styx.publicKeyPackage(),
    );
    assertExactComponentIds(
      keyPackage.supportedComponentIds,
      B31_SUPPORTED_COMPONENT_IDS,
      'emitted Styx B3.1 supported components',
    );
    const expectedProfile = styx.expectedGroupProfile();
    let profileEvidence = initialProfileEvidence(expectedProfile);
    const acceptedBeforeBoundary = {
      mdkAcceptedB31Advertisement: false,
      styxDurableRestart: true,
      styxInternalGroupProfileCodecValidated:
        keyPackage.internalGroupProfileCodecValidated === true,
      styxKeyPackageSha256: keyPackage.keyPackageSha256,
      styxSupportedComponentIdsDecodedFromEmittedBytes:
        keyPackage.supportedComponentIds,
    };

    const mdkSecret = accountSecret();
    const mdkSecretPath = resolve(privateDirectory, 'mdk-account-secret.hex');
    const databaseKeyPath = resolve(privateDirectory, 'mdk-database-key.hex');
    const databasePath = resolve(privateDirectory, 'mdk-account.sqlite3');
    ownerOnlyWrite(mdkSecretPath, Buffer.from(mdkSecret).toString('hex'));
    ownerOnlyWrite(databaseKeyPath, randomBytes(32).toString('hex'));
    const mdkAccountIdentityHex = Buffer.from(schnorr.getPublicKey(mdkSecret)).toString('hex');

    mdk = new MdkB31Peer();
    appendTranscript(transcript, 'mdk_hello', await mdk.request('hello'));
    appendTranscript(
      transcript,
      'mdk_initialize',
      await mdk.request('initialize', {
        account_identity_hex: mdkAccountIdentityHex,
        database_key_path: databaseKeyPath,
        database_path: databasePath,
        node_binary: process.execPath,
        signer_script: B31_MDK_DRIVER_PATH,
        signer_secret_path: mdkSecretPath,
      }),
    );

    let creation;
    try {
      creation = await mdk.request('create_group', {
        key_package_hex: keyPackage.keyPackageHex,
      });
    } catch (error) {
      if (typeof error?.code !== 'string') throw error;
      const typed = typedPeerError(error, 'mdk_create_group_rejected');
      appendTranscript(transcript, 'mdk_reject_b31_key_package', typed);
      report = finalizeReport({
        acceptedBeforeBoundary,
        claim: 'B3.1 did not establish Styx/MDK interoperability; MDK rejected the exact B3.1 KeyPackage at group creation.',
        disposition: 'NO-GO',
        firstIncompatibleOperation: 'mdk_create_group_from_styx_b31_key_package',
        pins,
        profileEvidence,
        rejectedValue: {
          keyPackageSha256: keyPackage.keyPackageSha256,
          kind: typed.code === 'mdk_missing_required_capabilities'
            ? 'new_missing_required_capability'
            : 'mdk_group_creation_rejection',
        },
        transcript,
        typedOutcomes: {
          mdk: typed,
          styx: {
            code: 'STYX_B31_ADVERTISEMENT_NOT_ACCEPTED',
            supportedComponentIds: keyPackage.supportedComponentIds,
          },
        },
      });
    }

    if (!report) {
      acceptedBeforeBoundary.mdkAcceptedB31Advertisement = true;
      appendTranscript(transcript, 'mdk_create_group_accepts_b31_key_package', {
        groupIdHex: creation.group_id_hex,
        projection: creation.projection,
        publicExternalRatchetTree: creation.public_external_ratchet_tree_hex,
        ratchetTreeDelivery: creation.ratchet_tree_delivery,
        welcomeMessageIdHex: creation.welcome_message_id_hex,
        welcomeSha256: creation.welcome_sha256,
      });
      try {
        profileEvidence = validateMdkProjection(
          creation.projection,
          creation.group_id_hex,
          expectedProfile,
        );
        appendTranscript(transcript, 'styx_validate_mdk_group_profile_projection', profileEvidence);
      } catch (error) {
        const typed = {
          code: 'STYX_B31_MDK_PROFILE_PROJECTION_MISMATCH',
          reason: String(error?.message ?? error).slice(0, 256),
        };
        appendTranscript(transcript, 'styx_reject_mdk_group_profile_projection', typed);
        report = finalizeReport({
          acceptedBeforeBoundary,
          claim: 'B3.1 did not establish Styx/MDK interoperability; the MDK GroupContext projection failed exact Styx B3.1 validation.',
          disposition: 'NO-GO',
          firstIncompatibleOperation: 'styx_validate_mdk_group_profile_projection',
          pins,
          profileEvidence,
          rejectedValue: {
            groupContextSha256: creation.projection?.group_context_sha256 ?? null,
            kind: 'group_profile_projection_mismatch',
          },
          transcript,
          typedOutcomes: {
            mdk: { code: 'MDK_ACCEPTED_B31_ADVERTISEMENT' },
            styx: typed,
          },
        });
      }
    }

    if (!report) {
      try {
        appendTranscript(
          transcript,
          'mdk_acknowledge_welcome_delivery',
          await mdk.request('confirm_published', {
            welcome_message_id_hex: creation.welcome_message_id_hex,
          }),
        );
      } catch (error) {
        const typed = typedPeerError(error, 'mdk_confirm_published_failed');
        appendTranscript(transcript, 'mdk_confirm_published_blocked', typed);
        report = finalizeReport({
          acceptedBeforeBoundary,
          claim: 'B3.1 did not establish Styx/MDK interoperability; Welcome publication acknowledgement was blocked.',
          disposition: 'BLOCKED',
          firstIncompatibleOperation: 'mdk_confirm_published',
          pins,
          profileEvidence,
          rejectedValue: {
            kind: 'welcome_publication_acknowledgement_failed',
            welcomeSha256: creation.welcome_sha256,
          },
          transcript,
          typedOutcomes: {
            mdk: typed,
            styx: { code: 'STYX_JOIN_NOT_ATTEMPTED' },
          },
        });
      }
    }

    if (!report) {
      const styxJoinError = appendTranscript(
        transcript,
        'styx_join_without_external_ratchet_tree',
        styx.proveJoinRequiresExternalRatchetTree(creation.welcome_hex),
      );
      report = finalizeReport({
        acceptedBeforeBoundary,
        claim: 'B3.1 cleared the exact 0x8001 capability gate but did not establish Styx/MDK interoperability; the bounded flow stops at Styx Welcome join.',
        disposition: 'NO-GO',
        firstIncompatibleOperation: 'styx_join_mdk_welcome',
        pins,
        profileEvidence,
        rejectedValue: {
          kind: 'missing_public_external_ratchet_tree',
          value: null,
          welcomeSha256: creation.welcome_sha256,
        },
        transcript,
        typedOutcomes: {
          mdk: {
            code: 'MDK_ACCEPTED_B31_ADVERTISEMENT_AND_PROFILE',
            createDisposition: 'FoundingGroupCreated',
            ratchetTreeDelivery: creation.ratchet_tree_delivery,
          },
          styx: styxJoinError,
        },
      });
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
    const validatedPrivateDirectory = assertExistingScopedDirectory(
      privateDirectory,
      B31_PRIVATE_ROOT,
    );
    rmSync(validatedPrivateDirectory, { recursive: true, force: false });
  }
  process.stdout.write(`${JSON.stringify({
    disposition: report.disposition,
    report: resolve(runDirectory, 'report.json'),
  })}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await run();
}
