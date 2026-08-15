// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — exact-pin B3.3a paired application-traffic harness.

import { randomBytes } from 'node:crypto';
import {
  chmodSync, mkdirSync, realpathSync, readdirSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import { relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { schnorr } from '@noble/curves/secp256k1';

import {
  B33A_ERROR,
  B33A_OUTCOME,
  B33A_PRIVATE_ROOT,
  B33A_REPORT_FORMAT,
  B33A_RUN_ROOT,
  appendB33aTranscript,
  canonicalJsonBytes,
  encodeMarmotAppEvent,
  sha256Hex,
  validateB33aReport,
  validateB33aTranscript,
} from './b3-3a-canonical.mjs';
import { MdkB33aProcess } from './b3-3a-mdk-driver.mjs';
import { B33A_MDK_SIGNER_PATH } from './b3-3a-mdk-signer.mjs';
import { StyxB33aProcess } from './b3-3a-styx-driver.mjs';
import { verifyPins } from './verify-pins.mjs';

const MDK_PROTOCOL = 'styx-b3-mdk-peer-jsonl-v1';
const scriptPath = fileURLToPath(import.meta.url);

function parseArgs(args) {
  if (args.length !== 6 || args[0] !== '--run-dir' || args[2] !== '--private-dir'
    || args[4] !== '--candidate-dir') {
    throw new Error(
      'usage: b3-3a-orchestrator.mjs --run-dir PATH --private-dir PATH --candidate-dir PATH',
    );
  }
  return { runDirectory: args[1], privateDirectory: args[3], candidateDirectory: args[5] };
}

function prepareEmptyChild(path, root, label) {
  mkdirSync(root, { recursive: true, mode: 0o700 });
  chmodSync(root, 0o700);
  const candidate = resolve(path);
  const lexical = relative(resolve(root), candidate);
  if (!lexical || lexical === '..' || lexical.startsWith(`..${sep}`)) {
    throw new Error(`${label} escaped its approved root`);
  }
  mkdirSync(candidate, { recursive: false, mode: 0o700 });
  chmodSync(candidate, 0o700);
  const real = realpathSync(candidate);
  const rel = relative(realpathSync(root), real);
  if (!rel || rel === '..' || rel.startsWith(`..${sep}`)
    || readdirSync(real).length !== 0 || (statSync(real).mode & 0o077) !== 0) {
    throw new Error(`${label} is not an empty owner-only child`);
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
    try { schnorr.getPublicKey(candidate); return candidate; } catch { candidate.fill(0); }
  }
}

function validateMdkHello(value) {
  if (value?.protocol !== MDK_PROTOCOL
    || value?.mdk_revision !== '9396adb6aa6b95b521a7979facd5ea7040c07288'
    || value?.transport !== 'direct_mls_identity_wrapper') {
    throw new Error('MDK hello differs from the frozen peer contract');
  }
  return value;
}

function validateCreation(value) {
  if (value?.creation_event_count !== 1
    || value?.ratchet_tree_delivery !== 'embedded_in_encrypted_group_info_only'
    || value?.public_external_ratchet_tree_hex !== null
    || typeof value?.group_id_hex !== 'string' || typeof value?.welcome_hex !== 'string'
    || sha256Hex(Buffer.from(value.welcome_hex, 'hex')) !== value.welcome_sha256) {
    throw new Error('MDK creation differs from one exact embedded-tree Welcome');
  }
  return value;
}

function syntheticEvent(identityHex, groupIdHex, ordinal, direction) {
  return encodeMarmotAppEvent({
    pubkey: identityHex,
    created_at: 1_786_680_100 + ordinal,
    kind: 9,
    tags: [['h', groupIdHex], ['styx-direction', direction]],
    content: `synthetic B3.3a application event ${ordinal} ${direction}`,
  });
}

function publicSendEvidence(result, expectedEventIdHex) {
  if (result?.disposition !== 'application_message_durably_prepared'
    || result?.app_event_id_hex !== expectedEventIdHex
    || typeof result?.group_message_hex !== 'string') {
    const error = new Error('MDK send result differs from the exact application outcome');
    error.code = 'B33A_MDK_SEND_MISMATCH';
    throw error;
  }
  return Object.freeze({
    appEventIdHex: result.app_event_id_hex,
    ciphertextSha256Hex: sha256Hex(Buffer.from(result.group_message_hex, 'hex')),
    messageIdHex: result.message_id_hex,
    sourceEpoch: result.source_epoch,
  });
}

function publicStyxReceiveEvidence(result, expectedEventBytes, expectedSenderHex) {
  if (result?.status !== B33A_OUTCOME.COMMITTED
    || result?.senderIdentityHex !== expectedSenderHex
    || result?.plaintext_hex !== Buffer.from(expectedEventBytes).toString('hex')) {
    const error = new Error('Styx receive result differs from the durable authenticated event');
    error.code = 'B33A_STYX_RECEIVE_MISMATCH';
    throw error;
  }
  return Object.freeze({
    eventIdHex: result.eventIdHex,
    headDigestHex: result.headDigestHex,
    senderIdentityHex: result.senderIdentityHex,
    senderLeafIndex: result.senderLeafIndex,
    verifiedLeafDigestHex: result.verifiedLeafDigestHex,
  });
}

function publicStyxSendEvidence(result, expectedEventIdHex) {
  if (result?.status !== B33A_OUTCOME.COMMITTED || result?.eventIdHex !== expectedEventIdHex
    || typeof result?.ciphertext_hex !== 'string') {
    const error = new Error('Styx send result differs from the durable outbox outcome');
    error.code = 'B33A_STYX_SEND_MISMATCH';
    throw error;
  }
  return Object.freeze({
    ciphertextSha256Hex: sha256Hex(Buffer.from(result.ciphertext_hex, 'hex')),
    eventIdHex: result.eventIdHex,
    headDigestHex: result.headDigestHex,
    requestId: result.requestId,
  });
}

function publicMdkReceiveEvidence(result, expectedEventBytes, expectedSenderHex) {
  if (result?.disposition !== 'application_message_processed'
    || result?.sender_identity_hex !== expectedSenderHex
    || result?.payload_hex !== Buffer.from(expectedEventBytes).toString('hex')) {
    const error = new Error('MDK receive result differs from the authenticated application event');
    error.code = 'B33A_MDK_RECEIVE_MISMATCH';
    throw error;
  }
  return Object.freeze({
    appEventIdHex: result.app_event_id_hex,
    epoch: result.epoch,
    messageIdHex: result.message_id_hex,
    senderIdentityHex: result.sender_identity_hex,
  });
}

function typedFailure(error) {
  if (typeof error?.code !== 'string' || !/^[A-Za-z0-9_.-]{1,96}$/.test(error.code)) return null;
  if (!(error.code.startsWith('B33A_') || error.code === 'bounded_nogo'
    || error.code === 'mdk_peer_quarantined')) return null;
  return Object.freeze({ code: error.code, message: String(error.message).slice(0, 512) });
}

async function initializeMdk(peer, fields) {
  appendB33aTranscript(fields.transcript, 'mdk_hello', validateMdkHello(await peer.request('hello')));
  return peer.request('initialize', {
    account_identity_hex: fields.identityHex,
    database_key_path: fields.databaseKeyPath,
    database_path: fields.databasePath,
    node_binary: process.execPath,
    signer_script: B33A_MDK_SIGNER_PATH,
    signer_secret_path: fields.secretPath,
  });
}

async function runMode(args) {
  const runDirectory = prepareEmptyChild(resolve(args.runDirectory), B33A_RUN_ROOT, 'run directory');
  const privateDirectory = prepareEmptyChild(
    resolve(args.privateDirectory), B33A_PRIVATE_ROOT, 'private directory',
  );
  const transcript = [];
  let styx;
  let mdk;
  let mdkSecret;
  let report;
  let blocked;
  let applicationEventsCommitted = 0;
  try {
    const pins = appendB33aTranscript(
      transcript, 'verify_exact_inputs', verifyPins(args.candidateDirectory),
    );
    mdkSecret = accountSecret();
    const mdkIdentityHex = Buffer.from(schnorr.getPublicKey(mdkSecret)).toString('hex');
    const mdkSecretPath = resolve(privateDirectory, 'mdk-account-secret.hex');
    const databaseKeyPath = resolve(privateDirectory, 'mdk-database-key.hex');
    const databasePath = resolve(privateDirectory, 'mdk-account.sqlite3');
    const styxPrivateDirectory = resolve(privateDirectory, 'styx');
    mkdirSync(styxPrivateDirectory, { mode: 0o700 });
    writeOwnerOnly(mdkSecretPath, Buffer.from(mdkSecret).toString('hex'));
    writeOwnerOnly(databaseKeyPath, randomBytes(32).toString('hex'));

    styx = new StyxB33aProcess();
    appendB33aTranscript(transcript, 'styx_initialize_new', await styx.request('initialize_new', {
      artifact_directory: args.candidateDirectory,
      expected_author_hex: mdkIdentityHex,
      private_directory: styxPrivateDirectory,
    }));
    const keyPackage = appendB33aTranscript(
      transcript, 'styx_advertise_exact_key_package', await styx.request('public_key_package'),
    );
    mdk = new MdkB33aProcess();
    appendB33aTranscript(transcript, 'mdk_initialize_new', await initializeMdk(mdk, {
      transcript, identityHex: mdkIdentityHex, databaseKeyPath, databasePath,
      secretPath: mdkSecretPath,
    }));
    const creation = appendB33aTranscript(
      transcript, 'mdk_create_exact_group', validateCreation(await mdk.request('create_group', {
        key_package_hex: keyPackage.keyPackageHex,
      })),
    );
    appendB33aTranscript(transcript, 'styx_record_welcome', await styx.request('record_welcome', {
      welcome_hex: creation.welcome_hex,
    }));
    const joined = appendB33aTranscript(
      transcript, 'styx_join_and_activate_b33a', await styx.request('join_activate'),
    );
    if (joined.groupIdHex !== creation.group_id_hex) {
      const error = new Error('Styx activation group differs from MDK');
      error.code = 'B33A_GROUP_ID_MISMATCH';
      throw error;
    }
    appendB33aTranscript(transcript, 'mdk_confirm_welcome_delivery', await mdk.request(
      'confirm_published', { welcome_message_id_hex: creation.welcome_message_id_hex },
    ));

    const mdkEvent1 = syntheticEvent(mdkIdentityHex, creation.group_id_hex, 1, 'mdk-to-styx');
    const mdkEvent1Id = JSON.parse(Buffer.from(mdkEvent1).toString('utf8')).id;
    const mdkSent1 = await mdk.request('send_application', {
      payload_hex: Buffer.from(mdkEvent1).toString('hex'),
    });
    appendB33aTranscript(transcript, 'mdk_send_application_1',
      publicSendEvidence(mdkSent1, mdkEvent1Id));
    const styxReceived1 = await styx.request('receive_application', {
      ciphertext_hex: mdkSent1.group_message_hex,
    });
    appendB33aTranscript(transcript, 'styx_receive_durable_application_1',
      publicStyxReceiveEvidence(styxReceived1, mdkEvent1, mdkIdentityHex));
    applicationEventsCommitted += 1;

    const styxEvent1 = syntheticEvent(
      keyPackage.accountIdentityHex, creation.group_id_hex, 2, 'styx-to-mdk',
    );
    const styxEvent1Id = JSON.parse(Buffer.from(styxEvent1).toString('utf8')).id;
    const styxSent1 = await styx.request('send_application', {
      event_hex: Buffer.from(styxEvent1).toString('hex'), request_id: 'styx-send-1',
    });
    appendB33aTranscript(transcript, 'styx_send_durable_application_1',
      publicStyxSendEvidence(styxSent1, styxEvent1Id));
    const mdkReceived1 = await mdk.request('ingest_group_message', {
      group_message_hex: styxSent1.ciphertext_hex,
    });
    appendB33aTranscript(transcript, 'mdk_receive_application_1',
      publicMdkReceiveEvidence(mdkReceived1, styxEvent1, keyPackage.accountIdentityHex));
    applicationEventsCommitted += 1;

    await styx.close();
    styx = null;
    await mdk.close();
    mdk = null;

    styx = new StyxB33aProcess();
    appendB33aTranscript(transcript, 'styx_fresh_process_restore', await styx.request(
      'initialize_existing', {
        artifact_directory: args.candidateDirectory,
        private_directory: styxPrivateDirectory,
      },
    ));
    appendB33aTranscript(transcript, 'styx_restored_head', await styx.request('verify_active'));
    mdk = new MdkB33aProcess();
    appendB33aTranscript(transcript, 'mdk_fresh_process_initialize', await initializeMdk(mdk, {
      transcript, identityHex: mdkIdentityHex, databaseKeyPath, databasePath,
      secretPath: mdkSecretPath,
    }));
    appendB33aTranscript(transcript, 'mdk_fresh_process_restore_group', await mdk.request(
      'restore_group', { group_id_hex: creation.group_id_hex },
    ));

    const styxReplay = await styx.request('receive_application', {
      ciphertext_hex: mdkSent1.group_message_hex,
    });
    if (styxReplay?.status !== B33A_OUTCOME.DUPLICATE || styxReplay?.plaintext_hex !== null) {
      const error = new Error('Styx replay released plaintext or changed disposition');
      error.code = 'B33A_STYX_REPLAY_MISMATCH';
      throw error;
    }
    appendB33aTranscript(transcript, 'styx_replay_rejected_without_plaintext', {
      eventIdHex: styxReplay.eventIdHex, status: styxReplay.status,
    });
    const mdkReplay = await mdk.request('ingest_group_message', {
      group_message_hex: styxSent1.ciphertext_hex,
    });
    if (!['duplicate', 'own_echo'].includes(mdkReplay?.disposition)
      || Object.hasOwn(mdkReplay, 'payload_hex')) {
      const error = new Error('MDK replay released a second application event');
      error.code = 'B33A_MDK_REPLAY_MISMATCH';
      throw error;
    }
    appendB33aTranscript(transcript, 'mdk_replay_rejected_without_event', mdkReplay);

    const mdkEvent2 = syntheticEvent(mdkIdentityHex, creation.group_id_hex, 3, 'mdk-to-styx');
    const mdkEvent2Id = JSON.parse(Buffer.from(mdkEvent2).toString('utf8')).id;
    const mdkSent2 = await mdk.request('send_application', {
      payload_hex: Buffer.from(mdkEvent2).toString('hex'),
    });
    appendB33aTranscript(transcript, 'mdk_send_application_2',
      publicSendEvidence(mdkSent2, mdkEvent2Id));
    appendB33aTranscript(transcript, 'styx_receive_durable_application_2',
      publicStyxReceiveEvidence(await styx.request('receive_application', {
        ciphertext_hex: mdkSent2.group_message_hex,
      }), mdkEvent2, mdkIdentityHex));
    applicationEventsCommitted += 1;

    const styxEvent2 = syntheticEvent(
      keyPackage.accountIdentityHex, creation.group_id_hex, 4, 'styx-to-mdk',
    );
    const styxEvent2Id = JSON.parse(Buffer.from(styxEvent2).toString('utf8')).id;
    const styxSent2 = await styx.request('send_application', {
      event_hex: Buffer.from(styxEvent2).toString('hex'), request_id: 'styx-send-2',
    });
    appendB33aTranscript(transcript, 'styx_send_durable_application_2',
      publicStyxSendEvidence(styxSent2, styxEvent2Id));
    appendB33aTranscript(transcript, 'mdk_receive_application_2',
      publicMdkReceiveEvidence(await mdk.request('ingest_group_message', {
        group_message_hex: styxSent2.ciphertext_hex,
      }), styxEvent2, keyPackage.accountIdentityHex));
    applicationEventsCommitted += 1;

    const transcriptHeadSha256Hex = validateB33aTranscript(transcript);
    report = Object.freeze({
      format: B33A_REPORT_FORMAT,
      version: 1,
      disposition: 'GO',
      claim: 'The exact candidate exchanged two synthetic application events in each direction across a durable fresh-process restart without epoch changes.',
      applicationEventsCommitted,
      bidirectionalApplicationTrafficEstablished: true,
      candidateTuple: pins.candidateTuple,
      commitLifecycleTested: false,
      groupIdHex: creation.group_id_hex,
      replayPlaintextReleased: false,
      transcriptHeadSha256Hex,
    });
  } catch (error) {
    const typed = typedFailure(error);
    if (typed && typed.code !== B33A_ERROR.PERSISTENCE_FAILED) {
      appendB33aTranscript(transcript, 'first_typed_incompatibility', typed);
      report = Object.freeze({
        format: B33A_REPORT_FORMAT,
        version: 1,
        disposition: 'NO-GO',
        claim: 'B3.3a stopped at the first typed incompatibility without relaxing either peer.',
        applicationEventsCommitted,
        bidirectionalApplicationTrafficEstablished: false,
        commitLifecycleTested: false,
        failure: typed,
        firstIncompatibleOperation: transcript.at(-2)?.operation ?? 'unknown',
        transcriptHeadSha256Hex: validateB33aTranscript(transcript),
      });
    } else {
      blocked = error;
      appendB33aTranscript(transcript, 'environment_or_persistence_block', {
        code: String(error?.code ?? 'B33A_BLOCKED').slice(0, 96),
        message: String(error?.message ?? error).slice(0, 512),
      });
      report = Object.freeze({
        format: B33A_REPORT_FORMAT,
        version: 1,
        disposition: 'BLOCKED',
        claim: 'B3.3a emitted no protocol verdict because its environment or durability boundary failed.',
        applicationEventsCommitted,
        bidirectionalApplicationTrafficEstablished: false,
        commitLifecycleTested: false,
        transcriptHeadSha256Hex: validateB33aTranscript(transcript),
      });
    }
  } finally {
    await styx?.close().catch(() => {});
    await mdk?.close().catch(() => {});
    mdkSecret?.fill?.(0);
    try {
      report = validateB33aReport(report, validateB33aTranscript(transcript));
      writeOwnerOnly(resolve(runDirectory, 'transcript.json'), canonicalJsonBytes(transcript));
      writeOwnerOnly(resolve(runDirectory, 'report.json'), canonicalJsonBytes(report));
    } finally {
      rmSync(privateDirectory, { recursive: true, force: false });
    }
  }
  process.stdout.write(`${JSON.stringify({ disposition: report.disposition,
    report: resolve(runDirectory, 'report.json') })}\n`);
  if (blocked) throw blocked;
}

if (process.argv[1] === scriptPath) await runMode(parseArgs(process.argv.slice(2)));
