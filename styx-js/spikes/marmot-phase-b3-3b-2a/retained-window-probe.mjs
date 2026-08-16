// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — exact retained application-message window probe.

import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  chmodSync, copyFileSync, cpSync, existsSync, mkdirSync, mkdtempSync, rmSync,
  writeFileSync,
} from 'node:fs';
import { isAbsolute, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { schnorr } from '@noble/curves/secp256k1';

import { B32A_PRIVATE_ROOT } from '../marmot-phase-b3-2a/b3-2a-canonical.mjs';
import { openB32aFileJournal } from '../marmot-phase-b3-2a/b3-2a-journal.mjs';
import { StyxB32aPeer } from '../marmot-phase-b3-2a/b3-2a-styx-driver.mjs';
import {
  B33A_MDK_BUILD_ROOT, B33A_PRIVATE_ROOT, encodeMarmotAppEvent,
} from '../marmot-phase-b3-3a/b3-3a-canonical.mjs';
import { buildMdkPeer } from '../marmot-phase-b3-3a/b3-3a-mdk-builder.mjs';
import { MdkB33aProcess } from '../marmot-phase-b3-3a/b3-3a-mdk-driver.mjs';
import { B33A_MDK_SIGNER_PATH } from '../marmot-phase-b3-3a/b3-3a-mdk-signer.mjs';
import {
  B33B1_PRIVATE_ROOT, B33B1_RECOVERY, bytesToHex, canonicalJsonBytes, clearBytes,
  sha256Hex,
} from '../marmot-phase-b3-3b-1/b3-3b-1-canonical.mjs';
import { B33b1EvolutionAdapter }
  from '../marmot-phase-b3-3b-1/b3-3b-1-engine-adapter.mjs';
import { openB33b1FileJournal }
  from '../marmot-phase-b3-3b-1/b3-3b-1-journal.mjs';
import { loadCandidate } from '../marmot-phase-b3-3b-1/stage1-probe.mjs';
import { verifyPins } from '../marmot-phase-b3-3b-1/verify-pins.mjs';
import {
  B33B2A_FINAL_EPOCH, B33B2A_REJECTED_DISTANCE, B33B2A_RETAINED_DISTANCES,
  B33B2A_RETENTION_POLICY, createB33b2aOperationTrace, failB33b2a,
} from './b3-3b-2a-canonical.mjs';

const RECOVERY_WORKER = fileURLToPath(
  new URL('../marmot-phase-b3-3b-1/stage1-fresh-process.mjs', import.meta.url),
);
const RECEIVER_WORKER = fileURLToPath(new URL('./fresh-styx-receiver.mjs', import.meta.url));

function provisionExactMdkRoot() {
  const configured = process.env.B33B2A_MDK_ROOT;
  if (configured === undefined) return;
  if (configured.length === 0 || !isAbsolute(configured)) {
    failB33b2a('B33B2A_INVALID', 'B33B2A_MDK_ROOT must be a non-empty absolute path');
  }
  const exact = resolve(configured);
  if (process.env.B33B1_MDK_ROOT !== undefined
    && resolve(process.env.B33B1_MDK_ROOT) !== exact) {
    failB33b2a('B33B2A_PIN_DRIFT', 'B3.3b-1 and B3.3b-2a MDK roots disagree');
  }
  process.env.B33B1_MDK_ROOT = exact;
}

function accountSecret() {
  for (;;) {
    const candidate = Uint8Array.from(randomBytes(32));
    try { schnorr.getPublicKey(candidate); return candidate; } catch { candidate.fill(0); }
  }
}

function freshDirectory(root, prefix) {
  mkdirSync(root, { recursive: true, mode: 0o700 });
  chmodSync(root, 0o700);
  const directory = mkdtempSync(resolve(root, prefix));
  chmodSync(directory, 0o700);
  return directory;
}

function writeOwnerOnly(path, value) {
  writeFileSync(path, value, { flag: 'wx', mode: 0o600 });
  chmodSync(path, 0o600);
}

function event(identityHex, groupIdHex, marker) {
  return encodeMarmotAppEvent({
    pubkey: identityHex,
    created_at: 1_787_000_000 + marker,
    kind: 9,
    tags: [['h', groupIdHex]],
    content: `B3.3b-2a retained-window event ${marker}`,
  });
}

function mutate(bytes) {
  const corrupted = Uint8Array.from(bytes);
  corrupted[corrupted.length - 1] ^= 0x01;
  return corrupted;
}

function runWorker(worker, args, label) {
  const result = spawnSync(process.execPath, [worker, ...args], {
    encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, timeout: 180_000,
  });
  if (result.error || result.status !== 0 || result.signal !== null) {
    failB33b2a('B33B2A_ENGINE_REJECTED', `${label} failed`, {
      error: result.error?.message ?? null,
      signal: result.signal,
      status: result.status,
      stderr: (result.stderr ?? '').slice(0, 4096),
    });
  }
  try {
    const parsed = JSON.parse(result.stdout);
    if (!Number.isSafeInteger(parsed?.processId) || parsed.processId <= 0
      || parsed.processId === process.pid) {
      failB33b2a('B33B2A_CORRUPT', `${label} did not run in a fresh process`);
    }
    return parsed;
  } catch (error) {
    failB33b2a('B33B2A_CORRUPT', `${label} returned invalid JSON`, {
      cause: error instanceof Error ? error.message : `${error}`,
      stdout: (result.stdout ?? '').slice(0, 4096),
    });
  }
}

function recover(action, candidatePath, journalDirectory) {
  return runWorker(RECOVERY_WORKER, [
    action, candidatePath === undefined ? '--installed' : candidatePath, journalDirectory,
  ], `fresh-process ${action}`);
}

function receiveInFreshStyx(context, journalDirectory, ciphertextBytes, forgedMetadata) {
  context.freshStyxReceiverCount += 1;
  return runWorker(RECEIVER_WORKER, [
    context.candidatePath === undefined ? '--installed' : context.candidatePath,
    journalDirectory,
    bytesToHex(ciphertextBytes),
    JSON.stringify(forgedMetadata),
  ], 'fresh-process application receive');
}

async function initializeMdk(peer, fields) {
  const hello = await peer.request('hello');
  if (hello?.mdk_revision !== fields.expectedRevision) {
    failB33b2a('B33B2A_PIN_DRIFT', 'MDK peer revision drifted');
  }
  return peer.request('initialize', {
    account_identity_hex: fields.identityHex,
    database_key_path: fields.databaseKeyPath,
    database_path: fields.databasePath,
    node_binary: process.execPath,
    signer_script: B33A_MDK_SIGNER_PATH,
    signer_secret_path: fields.secretPath,
  });
}

function clearRecovery(value) {
  clearBytes(value?.stateBytes);
  clearBytes(value?.parentStateBytes);
  clearBytes(value?.pendingStateBytes);
  clearBytes(value?.commitBytes);
}

function stableCheckpoint(recovery) {
  return Object.freeze({
    applicationRecordCount: recovery.head.applicationRecords.length,
    epochDec: recovery.head.epochDec,
    groupContextSha256Hex: recovery.head.groupContextSha256Hex,
    headDigestHex: recovery.head.headDigestHex,
  });
}

function safeMdkCheckpoint(projection) {
  return Object.freeze({
    convergenceStatus: projection.convergence_status,
    epochDec: `${projection.epoch}`,
    groupContextSha256Hex: projection.group_context_sha256,
    participantSetSha256Hex: sha256Hex(canonicalJsonBytes(
      [...projection.sorted_member_identities_hex].sort(),
    )),
    selectedBranchId: projection.selected_branch_id,
  });
}

async function readStyxCheckpoint(journalDirectory) {
  const journal = openB33b1FileJournal(journalDirectory, B33B1_PRIVATE_ROOT);
  const recovery = await journal.readRecovery();
  try {
    if (recovery.action !== B33B1_RECOVERY.STABLE) {
      failB33b2a('B33B2A_STATE_CONFLICT', 'Styx authority is not stable');
    }
    return stableCheckpoint(recovery);
  } finally { clearRecovery(recovery); }
}

function sameJson(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

async function assertPeers(context, epoch, label) {
  const journal = openB33b1FileJournal(context.journalDirectory, B33B1_PRIVATE_ROOT);
  const styx = await journal.readRecovery();
  const mdk = await context.mdk.request('public_projection');
  try {
    if (styx.action !== B33B1_RECOVERY.STABLE
      || styx.head.epochDec !== `${epoch}`
      || mdk?.epoch?.toString() !== `${epoch}`
      || mdk?.group_id_hex !== styx.head.groupIdHex
      || mdk?.group_context_sha256 !== styx.head.groupContextSha256Hex) {
      failB33b2a('B33B2A_ENGINE_REJECTED', `${label} peer projections diverged`, {
        mdk, styx: stableCheckpoint(styx),
      });
    }
  } finally { clearRecovery(styx); }
}

async function restartMdk(context) {
  await context.mdk?.close().catch(() => {});
  context.mdk = new MdkB33aProcess(context.mdkExecutable);
  await initializeMdk(context.mdk, context.mdkFields);
  return context.mdk.request('restore_group', { group_id_hex: context.groupIdHex });
}

async function applyMdkUpdate(context, sourceEpoch) {
  const prepared = await context.mdk.request('self_update');
  await restartMdk(context);
  const recovered = await context.mdk.request('drain_auto_publish');
  if (recovered?.disposition !== 'group_evolution_recovered_for_publication'
    || recovered.group_message_hex !== prepared.group_message_hex
    || recovered.message_id_hex !== prepared.message_id_hex) {
    failB33b2a('B33B2A_ENGINE_REJECTED', 'MDK update did not recover exactly', { recovered });
  }
  await context.adapter.stageInbound(Uint8Array.from(Buffer.from(
    recovered.group_message_hex, 'hex',
  )));
  context.adapter = undefined;
  const applied = recover('apply-staged-inbound', context.candidatePath, context.journalDirectory);
  context.freshProcessRecoveryCount += 1;
  if (applied?.head?.epochDec !== `${sourceEpoch + 1}`) {
    failB33b2a('B33B2A_ENGINE_REJECTED', 'fresh Styx process applied wrong MDK epoch');
  }
  context.adapter = new B33b1EvolutionAdapter({
    journal: openB33b1FileJournal(context.journalDirectory), wasm: context.loaded.wasm,
  });
  const confirmed = await context.mdk.request('confirm_group_published', {
    message_id_hex: recovered.message_id_hex,
  });
  if (confirmed?.from_epoch?.toString() !== `${sourceEpoch}`
    || confirmed?.to_epoch?.toString() !== `${sourceEpoch + 1}`) {
    failB33b2a('B33B2A_ENGINE_REJECTED', 'MDK confirmed wrong epoch transition', { confirmed });
  }
  await assertPeers(context, sourceEpoch + 1, 'MDK-authored update');
}

async function applyStyxUpdate(context, sourceEpoch) {
  const prepared = await context.adapter.prepareLocal();
  context.adapter = undefined;
  const retry = recover('retry-local', context.candidatePath, context.journalDirectory);
  context.freshProcessRecoveryCount += 1;
  if (retry.commitSha256Hex !== prepared.commitSha256Hex
    || retry.projection?.sourceEpoch !== `${sourceEpoch}`
    || retry.projection?.targetEpoch !== `${sourceEpoch + 1}`) {
    failB33b2a('B33B2A_CORRUPT', 'fresh Styx retry changed the local Commit');
  }
  context.adapter = new B33b1EvolutionAdapter({
    journal: openB33b1FileJournal(context.journalDirectory), wasm: context.loaded.wasm,
  });
  const buffered = await context.mdk.request('ingest_group_evolution', {
    group_message_hex: retry.commitHex,
  });
  if (buffered?.disposition !== 'group_evolution_buffered'
    || buffered?.content_sha256 !== retry.commitSha256Hex) {
    failB33b2a('B33B2A_ENGINE_REJECTED', 'MDK did not buffer exact Styx Commit', { buffered });
  }
  await restartMdk(context);
  const convergence = {
    expected_accepted_app_message_ids: Object.freeze([...context.mdkAcceptedIds].sort()),
    expected_already_seen_message_ids: Object.freeze([...context.mdkSeenStyxIds].sort()),
    expected_content_sha256: retry.commitSha256Hex,
    expected_from_epoch: sourceEpoch,
    expected_to_epoch: sourceEpoch + 1,
  };
  const waiting = await context.mdk.request('converge_group_evolution', {
    ...convergence,
    expected_accepted_app_message_ids: [],
    expected_already_seen_message_ids: [],
    monotonic_ms: 1_000_000,
  });
  const settled = await context.mdk.request('converge_group_evolution', {
    ...convergence, monotonic_ms: 1_000_000_000,
  });
  if (waiting?.disposition !== 'group_evolution_waiting'
    || settled?.disposition !== 'group_evolution_settled'
    || settled?.accepted_content_sha256 !== retry.commitSha256Hex
    || settled?.from_epoch?.toString() !== `${sourceEpoch}`
    || settled?.to_epoch?.toString() !== `${sourceEpoch + 1}`) {
    failB33b2a('B33B2A_ENGINE_REJECTED', 'MDK convergence lifecycle drifted', {
      waiting, settled,
    });
  }
  await context.adapter.recordLocalAcceptance(retry.headDigestHex, {
    commitSha256Hex: retry.commitSha256Hex,
    peerGroupContextSha256Hex: retry.projection.candidateGroupContextSha256Hex,
    evidenceSha256Hex: sha256Hex(canonicalJsonBytes(settled)),
  });
  context.adapter = undefined;
  const merged = recover('merge-accepted-local', context.candidatePath, context.journalDirectory);
  context.freshProcessRecoveryCount += 1;
  if (merged?.head?.epochDec !== `${sourceEpoch + 1}`) {
    failB33b2a('B33B2A_ENGINE_REJECTED', 'fresh Styx merge reached wrong epoch');
  }
  context.adapter = new B33b1EvolutionAdapter({
    journal: openB33b1FileJournal(context.journalDirectory), wasm: context.loaded.wasm,
  });
  context.mdkSeenStyxIds = [...new Set([
    ...context.mdkSeenStyxIds,
    ...context.mdkAcceptedIds,
  ])].sort();
  context.mdkAcceptedIds.length = 0;
  clearBytes(prepared.commitBytes);
  await assertPeers(context, sourceEpoch + 1, 'Styx-authored update');
}

async function preparePair(context, sourceEpoch, distance, marker) {
  const fromMdk = await context.mdk.request('send_application', {
    payload_hex: bytesToHex(event(context.mdkIdentityHex, context.groupIdHex, marker)),
  });
  context.mdkAcceptedIds.push(fromMdk.message_id_hex);
  const fromStyx = await context.adapter.prepareApplicationOutbound(
    event(context.styxIdentityHex, context.groupIdHex, marker + 1),
  );
  if (fromMdk?.source_epoch?.toString() !== `${sourceEpoch}`
    || fromStyx.evidence.messageEpoch !== `${sourceEpoch}`) {
    failB33b2a('B33B2A_ENGINE_REJECTED', 'retained traffic was prepared at wrong epoch');
  }
  return Object.freeze({ distance, fromMdk, fromStyx, sourceEpoch });
}

async function rejectedByMdkWithoutProjectionMutation(
  context, ciphertextBytes, expectedReason, allowDuplicate = false,
) {
  const before = await context.mdk.request('public_projection');
  let rejection;
  try {
    const result = await context.mdk.request('ingest_group_message', {
      group_message_hex: bytesToHex(ciphertextBytes),
    });
    if (!allowDuplicate || !['duplicate', 'own_echo'].includes(result?.disposition)) {
      failB33b2a('B33B2A_ENGINE_REJECTED', 'MDK unexpectedly accepted rejected control');
    }
    rejection = Object.freeze({ code: result.disposition, details: null, message: 'replay' });
  } catch (error) {
    if (error?.code?.startsWith?.('B33B2A_')) throw error;
    rejection = Object.freeze({
      code: error?.code ?? 'unknown',
      details: error?.details ?? null,
      message: error instanceof Error ? error.message : `${error}`,
    });
  }
  await restartMdk(context);
  const after = await context.mdk.request('public_projection');
  if (!sameJson(before, after)) {
    failB33b2a('B33B2A_CORRUPT', 'MDK canonical projection mutated on rejection');
  }
  if (expectedReason && !new RegExp(expectedReason, 'i').test(JSON.stringify(rejection))) {
    failB33b2a('B33B2A_ENGINE_REJECTED', 'MDK rejection lacked the pinned typed reason', {
      rejection,
    });
  }
  return Object.freeze({
    after: safeMdkCheckpoint(after),
    before: safeMdkCheckpoint(before),
    rejection,
  });
}

async function forgedMetadataRejectedByMdk(context, ciphertextBytes) {
  const before = await context.mdk.request('public_projection');
  let rejected = false;
  try {
    await context.mdk.request('ingest_group_message', {
      group_message_hex: bytesToHex(ciphertextBytes),
      message_epoch: 999,
      sender_leaf_index: 999,
      disposition: 'application_message_processed',
    });
  } catch (error) {
    rejected = error?.code === 'invalid_request';
  }
  const after = await context.mdk.request('public_projection');
  if (!rejected || !sameJson(before, after)) {
    failB33b2a('B33B2A_CORRUPT', 'MDK accepted caller-forged application metadata');
  }
  return Object.freeze({
    after: safeMdkCheckpoint(after), before: safeMdkCheckpoint(before),
  });
}

function requireFreshStyxRejection(result, label) {
  if (result.accepted !== false || !sameJson(result.before, result.after)) {
    failB33b2a('B33B2A_CORRUPT', `${label} mutated or accepted in fresh Styx receiver`, result);
  }
}

function requireFreshStyxDelivery(result, sourceEpoch, distance, label) {
  if (result.accepted !== true || result.disposition !== 'application_inbound_durable'
    || result.evidence?.messageEpoch !== `${sourceEpoch}`
    || result.evidence?.currentEpoch !== B33B2A_FINAL_EPOCH
    || Number(result.evidence.currentEpoch) - Number(result.evidence.messageEpoch) !== distance) {
    failB33b2a('B33B2A_ENGINE_REJECTED', `${label} retained delivery drifted`, result);
  }
}

export async function runRetainedWindowProbe(candidatePath) {
  provisionExactMdkRoot();
  const pins = verifyPins(candidatePath);
  const operations = createB33b2aOperationTrace();
  const b32Root = freshDirectory(B32A_PRIVATE_ROOT, 'b33b2a-b32-');
  const b33Root = freshDirectory(B33B1_PRIVATE_ROOT, 'b33b2a-journal-');
  const futureRoot = freshDirectory(B33B1_PRIVATE_ROOT, 'b33b2a-future-');
  const mdkRoot = freshDirectory(B33A_PRIVATE_ROOT, 'b33b2a-mdk-');
  mkdirSync(B33A_MDK_BUILD_ROOT, { recursive: true, mode: 0o700 });
  const mdkBuildPath = resolve(B33A_MDK_BUILD_ROOT,
    `b33b2a-${process.pid}-${randomBytes(6).toString('hex')}`);
  const context = {
    adapter: undefined,
    candidatePath,
    freshProcessRecoveryCount: 0,
    freshStyxReceiverCount: 0,
    loaded: undefined,
    mdk: undefined,
    mdkAcceptedIds: [],
    mdkSeenStyxIds: [],
    mdkExecutable: undefined,
    mdkFields: undefined,
    safeCaseEvidence: [],
  };
  let mdkSecret;
  let futureFromStyx;
  const retained = new Map();
  try {
    const mdkBuild = buildMdkPeer(mdkBuildPath);
    context.mdkExecutable = mdkBuild.executable;
    mdkSecret = accountSecret();
    context.mdkIdentityHex = bytesToHex(schnorr.getPublicKey(mdkSecret));
    const secretPath = resolve(mdkRoot, 'account-secret.hex');
    const databaseKeyPath = resolve(mdkRoot, 'database-key.hex');
    const databasePath = resolve(mdkRoot, 'account.sqlite3');
    context.mdkFields = {
      databaseKeyPath, databasePath, expectedRevision: pins.mdkRevision,
      identityHex: context.mdkIdentityHex, secretPath,
    };
    writeOwnerOnly(secretPath, bytesToHex(mdkSecret));
    writeOwnerOnly(databaseKeyPath, randomBytes(32).toString('hex'));

    const styx = await StyxB32aPeer.create(b32Root, context.mdkIdentityHex);
    const keyPackage = await styx.publicKeyPackage();
    context.styxIdentityHex = keyPackage.accountIdentityHex;
    context.mdk = new MdkB33aProcess(context.mdkExecutable);
    await initializeMdk(context.mdk, context.mdkFields);
    const creation = await context.mdk.request('create_group', {
      key_package_hex: keyPackage.keyPackageHex,
    });
    context.groupIdHex = creation.group_id_hex;
    await styx.recordWelcome(creation.welcome_hex);
    const joined = await styx.joinRecordedWelcome();
    await context.mdk.request('confirm_published', {
      welcome_message_id_hex: creation.welcome_message_id_hex,
    });
    if (joined.projection.groupIdHex !== context.groupIdHex) {
      failB33b2a('B33B2A_ENGINE_REJECTED', 'peers joined different groups');
    }
    operations.advance('group-created-and-joined');

    context.loaded = await loadCandidate(candidatePath, pins.candidateTuple);
    const activationJournal = openB32aFileJournal(resolve(b32Root, 'journal'));
    const activation = await activationJournal.activationState();
    context.journalDirectory = resolve(b33Root, 'journal');
    context.adapter = new B33b1EvolutionAdapter({
      journal: openB33b1FileJournal(context.journalDirectory), wasm: context.loaded.wasm,
    });
    let active;
    try { active = await context.adapter.activateFromB32a(activation.head, activation.bytes); }
    finally { clearBytes(activation.bytes); }
    clearRecovery(active);
    operations.advance('b33b1-authority-activated');

    retained.set(6, await preparePair(context, 1, 6, 10));
    operations.advance('epoch1-distance6-prepared');
    const futureSnapshot = resolve(futureRoot, 'journal');
    cpSync(context.journalDirectory, futureSnapshot, { recursive: true, errorOnExist: true });
    const futureDatabasePath = resolve(mdkRoot, 'future-account.sqlite3');
    await context.mdk.close();
    context.mdk = undefined;
    copyFileSync(databasePath, futureDatabasePath);
    for (const suffix of ['-wal', '-shm']) {
      if (existsSync(`${databasePath}${suffix}`)) {
        copyFileSync(`${databasePath}${suffix}`, `${futureDatabasePath}${suffix}`);
      }
    }
    context.mdk = new MdkB33aProcess(context.mdkExecutable);
    await initializeMdk(context.mdk, context.mdkFields);
    await context.mdk.request('restore_group', { group_id_hex: context.groupIdHex });

    await applyMdkUpdate(context, 1);
    operations.advance('epoch2-mdk-update-applied');
    const future = await context.mdk.request('send_application', {
      payload_hex: bytesToHex(event(context.mdkIdentityHex, context.groupIdHex, 20)),
    });
    context.mdkAcceptedIds.push(future.message_id_hex);
    const futureResult = receiveInFreshStyx(
      context, futureSnapshot,
      Uint8Array.from(Buffer.from(future.group_message_hex, 'hex')),
      { currentEpoch: '2', messageEpoch: '2', source: 'caller-forged' },
    );
    requireFreshStyxRejection(futureResult, 'future-epoch control');
    context.safeCaseEvidence.push(Object.freeze({
      after: futureResult.after,
      before: futureResult.before,
      caseId: 'future-mdk-to-styx',
      ciphertextSha256Hex: sha256Hex(Buffer.from(future.group_message_hex, 'hex')),
      direction: 'MDK_TO_STYX',
      messageEpoch: '2',
      outcome: Object.freeze({ accepted: false, errorCode: futureResult.errorCode }),
      referenceTipEpoch: '1',
      type: 'future_epoch',
    }));
    futureFromStyx = await context.adapter.prepareApplicationOutbound(
      event(context.styxIdentityHex, context.groupIdHex, 21),
    );
    let futureMdk = new MdkB33aProcess(context.mdkExecutable);
    const futureMdkFields = { ...context.mdkFields, databasePath: futureDatabasePath };
    await initializeMdk(futureMdk, futureMdkFields);
    await futureMdk.request('restore_group', { group_id_hex: context.groupIdHex });
    const futureMdkBefore = await futureMdk.request('public_projection');
    let futureMdkRejected = false;
    try {
      await futureMdk.request('ingest_group_message', {
        group_message_hex: bytesToHex(futureFromStyx.ciphertextBytes),
      });
    } catch { futureMdkRejected = true; }
    await futureMdk.close().catch(() => {});
    futureMdk = new MdkB33aProcess(context.mdkExecutable);
    await initializeMdk(futureMdk, futureMdkFields);
    await futureMdk.request('restore_group', { group_id_hex: context.groupIdHex });
    const futureMdkAfter = await futureMdk.request('public_projection');
    await futureMdk.close();
    if (!futureMdkRejected || !sameJson(futureMdkBefore, futureMdkAfter)) {
      failB33b2a('B33B2A_CORRUPT', 'future-epoch MDK control mutated or was accepted');
    }
    context.safeCaseEvidence.push(Object.freeze({
      after: safeMdkCheckpoint(futureMdkAfter),
      before: safeMdkCheckpoint(futureMdkBefore),
      caseId: 'future-styx-to-mdk',
      ciphertextSha256Hex: sha256Hex(futureFromStyx.ciphertextBytes),
      direction: 'STYX_TO_MDK',
      messageEpoch: '2',
      outcome: Object.freeze({ accepted: false }),
      referenceTipEpoch: '1',
      type: 'future_epoch',
    }));
    operations.advance('future-epoch-control-rejected');

    retained.set(5, await preparePair(context, 2, 5, 30));
    operations.advance('epoch2-distance5-prepared');
    await applyStyxUpdate(context, 2);
    operations.advance('epoch3-styx-update-applied');
    retained.set(4, await preparePair(context, 3, 4, 40));
    operations.advance('epoch3-distance4-prepared');
    await applyMdkUpdate(context, 3);
    operations.advance('epoch4-mdk-update-applied');
    await applyStyxUpdate(context, 4);
    operations.advance('epoch5-styx-update-applied');
    await applyMdkUpdate(context, 5);
    operations.advance('epoch6-mdk-update-applied');
    await applyStyxUpdate(context, 6);
    operations.advance('epoch7-styx-update-applied');
    context.adapter = undefined;
    await restartMdk(context);
    operations.advance('receivers-restarted');

    const distance4 = retained.get(4);
    const forgedMdkResult = await forgedMetadataRejectedByMdk(
      context, distance4.fromStyx.ciphertextBytes,
    );
    context.safeCaseEvidence.push(Object.freeze({
      after: forgedMdkResult.after,
      before: forgedMdkResult.before,
      caseId: 'forged-metadata-styx-to-mdk',
      ciphertextSha256Hex: sha256Hex(distance4.fromStyx.ciphertextBytes),
      direction: 'STYX_TO_MDK',
      messageEpoch: '3',
      outcome: Object.freeze({ accepted: false, errorCode: 'invalid_request' }),
      referenceTipEpoch: '7',
      type: 'caller_forged_metadata',
    }));
    const corruptFromMdk = mutate(Buffer.from(distance4.fromMdk.group_message_hex, 'hex'));
    const corruptStyxResult = receiveInFreshStyx(
      context, context.journalDirectory, corruptFromMdk,
      { currentEpoch: '3', messageEpoch: '3', source: 'caller-forged' },
    );
    requireFreshStyxRejection(corruptStyxResult, 'corrupted distance-4 control');
    context.safeCaseEvidence.push(Object.freeze({
      after: corruptStyxResult.after,
      before: corruptStyxResult.before,
      caseId: 'corrupt-distance4-mdk-to-styx',
      ciphertextSha256Hex: sha256Hex(corruptFromMdk),
      direction: 'MDK_TO_STYX',
      distance: 4,
      messageEpoch: '3',
      outcome: Object.freeze({ accepted: false, errorCode: corruptStyxResult.errorCode }),
      referenceTipEpoch: '7',
      type: 'corrupted_in_window',
    }));
    clearBytes(corruptFromMdk);
    const corruptFromStyx = mutate(distance4.fromStyx.ciphertextBytes);
    const corruptMdkResult = await rejectedByMdkWithoutProjectionMutation(
      context, corruptFromStyx,
    );
    context.safeCaseEvidence.push(Object.freeze({
      after: corruptMdkResult.after,
      before: corruptMdkResult.before,
      caseId: 'corrupt-distance4-styx-to-mdk',
      ciphertextSha256Hex: sha256Hex(corruptFromStyx),
      direction: 'STYX_TO_MDK',
      distance: 4,
      messageEpoch: '3',
      outcome: Object.freeze({
        accepted: false, errorCode: corruptMdkResult.rejection.code,
      }),
      referenceTipEpoch: '7',
      type: 'corrupted_in_window',
    }));
    clearBytes(corruptFromStyx);
    operations.advance('corrupted-distance4-rejected');

    const distance4Styx = receiveInFreshStyx(
      context, context.journalDirectory,
      Uint8Array.from(Buffer.from(distance4.fromMdk.group_message_hex, 'hex')),
      { currentEpoch: '999', messageEpoch: '999', senderLeafIndex: 999 },
    );
    requireFreshStyxDelivery(distance4Styx, 3, 4, 'distance-4 Styx');
    const distance4MdkBefore = await context.mdk.request('public_projection');
    const distance4Mdk = await context.mdk.request('ingest_group_message', {
      group_message_hex: bytesToHex(distance4.fromStyx.ciphertextBytes),
    });
    const distance4StyxReplay = receiveInFreshStyx(
      context, context.journalDirectory,
      Uint8Array.from(Buffer.from(distance4.fromMdk.group_message_hex, 'hex')),
      { currentEpoch: '0', messageEpoch: '0' },
    );
    const distance4MdkReplay = await context.mdk.request('ingest_group_message', {
      group_message_hex: bytesToHex(distance4.fromStyx.ciphertextBytes),
    });
    const distance4MdkAfter = await context.mdk.request('public_projection');
    if (distance4Mdk?.disposition !== 'application_message_processed'
      || distance4StyxReplay?.disposition !== 'duplicate'
      || !['duplicate', 'own_echo'].includes(distance4MdkReplay?.disposition)) {
      failB33b2a('B33B2A_ENGINE_REJECTED', 'distance-4 traffic was not exactly once');
    }
    if (!sameJson(distance4MdkBefore, distance4MdkAfter)) {
      failB33b2a('B33B2A_CORRUPT', 'distance-4 MDK delivery advanced canonical authority');
    }
    context.safeCaseEvidence.push(
      Object.freeze({
        after: distance4Styx.after,
        before: distance4Styx.before,
        caseId: 'distance4-mdk-to-styx',
        ciphertextSha256Hex: sha256Hex(Buffer.from(distance4.fromMdk.group_message_hex, 'hex')),
        direction: 'MDK_TO_STYX',
        distance: 4,
        messageEpoch: '3',
        outcome: Object.freeze({ accepted: true, disposition: distance4Styx.disposition }),
        referenceTipEpoch: '7',
        replayDisposition: distance4StyxReplay.disposition,
        senderEvidence: distance4Styx.evidence,
        type: 'retained_delivery',
      }),
      Object.freeze({
        after: safeMdkCheckpoint(distance4MdkAfter),
        before: safeMdkCheckpoint(distance4MdkBefore),
        caseId: 'distance4-styx-to-mdk',
        ciphertextSha256Hex: sha256Hex(distance4.fromStyx.ciphertextBytes),
        direction: 'STYX_TO_MDK',
        distance: 4,
        messageEpoch: '3',
        outcome: Object.freeze({ accepted: true, disposition: distance4Mdk.disposition }),
        referenceTipEpoch: '7',
        replayDisposition: distance4MdkReplay.disposition,
        senderEvidence: Object.freeze({
          appEventIdHex: distance4Mdk.app_event_id_hex,
          epoch: distance4Mdk.epoch,
          messageIdHex: distance4Mdk.message_id_hex,
          senderIdentityHex: distance4Mdk.sender_identity_hex,
        }),
        type: 'retained_delivery',
      }),
    );
    operations.advance('distance4-delivered-exactly-once');

    const distance5 = retained.get(5);
    await restartMdk(context);
    const distance5Styx = receiveInFreshStyx(
      context, context.journalDirectory,
      Uint8Array.from(Buffer.from(distance5.fromMdk.group_message_hex, 'hex')),
      { currentEpoch: '-1', messageEpoch: '-1' },
    );
    requireFreshStyxDelivery(distance5Styx, 2, 5, 'distance-5 Styx');
    const distance5MdkBefore = await context.mdk.request('public_projection');
    const distance5Mdk = await context.mdk.request('ingest_group_message', {
      group_message_hex: bytesToHex(distance5.fromStyx.ciphertextBytes),
    });
    const distance5StyxReplay = receiveInFreshStyx(
      context, context.journalDirectory,
      Uint8Array.from(Buffer.from(distance5.fromMdk.group_message_hex, 'hex')), {},
    );
    const distance5MdkReplay = await context.mdk.request('ingest_group_message', {
      group_message_hex: bytesToHex(distance5.fromStyx.ciphertextBytes),
    });
    const distance5MdkAfter = await context.mdk.request('public_projection');
    if (distance5Mdk?.disposition !== 'application_message_processed'
      || distance5StyxReplay?.disposition !== 'duplicate'
      || !['duplicate', 'own_echo'].includes(distance5MdkReplay?.disposition)) {
      failB33b2a('B33B2A_ENGINE_REJECTED', 'distance-5 traffic was not exactly once');
    }
    if (!sameJson(distance5MdkBefore, distance5MdkAfter)) {
      failB33b2a('B33B2A_CORRUPT', 'distance-5 MDK delivery advanced canonical authority');
    }
    context.safeCaseEvidence.push(
      Object.freeze({
        after: distance5Styx.after,
        before: distance5Styx.before,
        caseId: 'distance5-mdk-to-styx',
        ciphertextSha256Hex: sha256Hex(Buffer.from(distance5.fromMdk.group_message_hex, 'hex')),
        direction: 'MDK_TO_STYX',
        distance: 5,
        messageEpoch: '2',
        outcome: Object.freeze({ accepted: true, disposition: distance5Styx.disposition }),
        referenceTipEpoch: '7',
        replayDisposition: distance5StyxReplay.disposition,
        senderEvidence: distance5Styx.evidence,
        type: 'retained_delivery',
      }),
      Object.freeze({
        after: safeMdkCheckpoint(distance5MdkAfter),
        before: safeMdkCheckpoint(distance5MdkBefore),
        caseId: 'distance5-styx-to-mdk',
        ciphertextSha256Hex: sha256Hex(distance5.fromStyx.ciphertextBytes),
        direction: 'STYX_TO_MDK',
        distance: 5,
        messageEpoch: '2',
        outcome: Object.freeze({ accepted: true, disposition: distance5Mdk.disposition }),
        referenceTipEpoch: '7',
        replayDisposition: distance5MdkReplay.disposition,
        senderEvidence: Object.freeze({
          appEventIdHex: distance5Mdk.app_event_id_hex,
          epoch: distance5Mdk.epoch,
          messageIdHex: distance5Mdk.message_id_hex,
          senderIdentityHex: distance5Mdk.sender_identity_hex,
        }),
        type: 'retained_delivery',
      }),
    );
    operations.advance('distance5-delivered-exactly-once');

    const distance6 = retained.get(6);
    await restartMdk(context);
    const styxBeforeDistance6 = await readStyxCheckpoint(context.journalDirectory);
    const distance6Styx = receiveInFreshStyx(
      context, context.journalDirectory,
      Uint8Array.from(Buffer.from(distance6.fromMdk.group_message_hex, 'hex')), {},
    );
    requireFreshStyxRejection(distance6Styx, 'distance-6 Styx control');
    const distance6StyxReplay = receiveInFreshStyx(
      context, context.journalDirectory,
      Uint8Array.from(Buffer.from(distance6.fromMdk.group_message_hex, 'hex')),
      { disposition: 'application_message_processed' },
    );
    requireFreshStyxRejection(distance6StyxReplay, 'distance-6 Styx replay control');
    if (distance6Styx.errorCode !== corruptStyxResult.errorCode
      || distance6StyxReplay.errorCode !== corruptStyxResult.errorCode) {
      failB33b2a('B33B2A_CORRUPT',
        'Styx distance-6 rejection became distinguishable from corrupted traffic');
    }
    const styxAfterDistance6 = await readStyxCheckpoint(context.journalDirectory);
    if (!sameJson(styxBeforeDistance6, styxAfterDistance6)) {
      failB33b2a('B33B2A_CORRUPT', 'Styx durable authority changed after distance-6 rejection');
    }
    const mdkDistance6Result = await rejectedByMdkWithoutProjectionMutation(
      context, distance6.fromStyx.ciphertextBytes, 'BeyondAppRetention|beyond_app_retention',
    );
    const mdkDistance6Replay = await rejectedByMdkWithoutProjectionMutation(
      context, distance6.fromStyx.ciphertextBytes, undefined, true,
    );
    context.safeCaseEvidence.push(
      Object.freeze({
        after: distance6Styx.after,
        before: distance6Styx.before,
        caseId: 'distance6-mdk-to-styx',
        ciphertextSha256Hex: sha256Hex(Buffer.from(distance6.fromMdk.group_message_hex, 'hex')),
        direction: 'MDK_TO_STYX',
        distance: 6,
        messageEpoch: '1',
        outcome: Object.freeze({ accepted: false, errorCode: distance6Styx.errorCode }),
        referenceTipEpoch: '7',
        replayDisposition: distance6StyxReplay.errorCode,
        type: 'stale_rejection',
      }),
      Object.freeze({
        after: mdkDistance6Result.after,
        before: mdkDistance6Result.before,
        caseId: 'distance6-styx-to-mdk',
        ciphertextSha256Hex: sha256Hex(distance6.fromStyx.ciphertextBytes),
        direction: 'STYX_TO_MDK',
        distance: 6,
        messageEpoch: '1',
        outcome: Object.freeze({
          accepted: false,
          errorCode: mdkDistance6Result.rejection.code,
          reason: mdkDistance6Result.rejection.details,
        }),
        referenceTipEpoch: '7',
        replayDisposition: mdkDistance6Replay.rejection.code,
        type: 'stale_rejection',
      }),
    );
    operations.advance('distance6-rejected-without-mutation');

    const final = openB33b1FileJournal(context.journalDirectory, B33B1_PRIVATE_ROOT);
    const finalRecovery = await final.readRecovery();
    try {
      if (finalRecovery.action !== B33B1_RECOVERY.STABLE
        || finalRecovery.head.epochDec !== B33B2A_FINAL_EPOCH) {
        failB33b2a('B33B2A_CORRUPT', 'final durable authority is not epoch seven');
      }
      await assertPeers(context, 7, 'final retained-window state');
      operations.advance('final-authority-verified');
      return Object.freeze({
        artifactSourceCommit: pins.artifactSourceCommit,
        artifactSourceTree: pins.artifactSourceTree,
        candidateTuple: pins.candidateTuple,
        applicationRecordCount: finalRecovery.head.applicationRecords.length,
        finalEpoch: finalRecovery.head.epochDec,
        finalGroupContextSha256Hex: finalRecovery.head.groupContextSha256Hex,
        finalRosterSha256Hex: finalRecovery.head.rosterSha256Hex,
        freshProcessRecoveryCount: context.freshProcessRecoveryCount,
        freshStyxReceiverCount: context.freshStyxReceiverCount,
        mdkBuildEvidence: mdkBuild.evidence,
        mdkDistance6Reason: mdkDistance6Result.rejection.details,
        operationSequence: operations.complete(),
        groupIdHex: context.groupIdHex,
        participantSetSha256Hex: sha256Hex(canonicalJsonBytes([
          context.mdkIdentityHex, context.styxIdentityHex,
        ].sort())),
        rejectedDistance: B33B2A_REJECTED_DISTANCE,
        retainedDistances: B33B2A_RETAINED_DISTANCES,
        retentionPolicy: B33B2A_RETENTION_POLICY,
        sourceCommit: pins.sourceCommit,
        sourceTree: pins.sourceTree,
        safeCaseEvidence: Object.freeze([...context.safeCaseEvidence]),
        transitionCount: finalRecovery.head.transitions.length,
        alternateUpdateAuthors: true,
        callerMetadataIgnored: true,
        corruptedInWindowRejectedWithoutMutation: true,
        futureEpochRejectedWithoutMutation: true,
        retainedWindowAcceptedBothDirectionsExactlyOnce: true,
        staleWindowRejectedBothDirectionsWithoutMutation: true,
      });
    } finally { clearRecovery(finalRecovery); }
  } finally {
    await context.mdk?.close().catch(() => {});
    clearBytes(mdkSecret);
    clearBytes(context.loaded?.wasmBytes);
    clearBytes(futureFromStyx?.ciphertextBytes);
    for (const value of retained.values()) clearBytes(value.fromStyx.ciphertextBytes);
    rmSync(b32Root, { recursive: true, force: true });
    rmSync(b33Root, { recursive: true, force: true });
    rmSync(futureRoot, { recursive: true, force: true });
    rmSync(mdkRoot, { recursive: true, force: true });
    rmSync(mdkBuildPath, { recursive: true, force: true });
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [candidateSelector, ...rest] = process.argv.slice(2);
  if (rest.length !== 0) throw new Error('usage: retained-window-probe.mjs [candidate-directory]');
  try {
    const report = await runRetainedWindowProbe(candidateSelector);
    for (const record of report.safeCaseEvidence) {
      process.stdout.write(`${JSON.stringify(record)}\n`);
    }
    process.stdout.write('B33B2A=GO\n');
  } catch (error) {
    const code = typeof error?.code === 'string' ? error.code : 'UNEXPECTED';
    process.stdout.write(`${JSON.stringify({ code, outcome: 'NO_GO' })}\n`);
    process.stdout.write(`B33B2A=NO_GO:${code}\n`);
    process.exitCode = 1;
  }
}
