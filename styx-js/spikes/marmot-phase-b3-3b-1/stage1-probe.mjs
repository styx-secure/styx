// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — journalled sequential evolution and retained-traffic probe.

import { randomBytes } from 'node:crypto';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { schnorr } from '@noble/curves/secp256k1';

import { B32A_PRIVATE_ROOT } from '../marmot-phase-b3-2a/b3-2a-canonical.mjs';
import { openB32aFileJournal } from '../marmot-phase-b3-2a/b3-2a-journal.mjs';
import { StyxB32aPeer } from '../marmot-phase-b3-2a/b3-2a-styx-driver.mjs';
import {
  B33A_MDK_BUILD_ROOT, B33A_PRIVATE_ROOT, encodeMarmotAppEvent,
} from '../marmot-phase-b3-3a/b3-3a-canonical.mjs';
import { readExactRegularFile } from '../marmot-phase-b3-3a/b3-3a-artifact-reader.mjs';
import { buildMdkPeer } from '../marmot-phase-b3-3a/b3-3a-mdk-builder.mjs';
import { MdkB33aProcess } from '../marmot-phase-b3-3a/b3-3a-mdk-driver.mjs';
import { B33A_MDK_SIGNER_PATH } from '../marmot-phase-b3-3a/b3-3a-mdk-signer.mjs';
import {
  B33B1_ERROR, B33B1_PRIVATE_ROOT, B33B1_RECOVERY, bytesToHex,
  canonicalJsonBytes, clearBytes, failB33b1, sha256Hex,
} from './b3-3b-1-canonical.mjs';
import { B33b1EvolutionAdapter } from './b3-3b-1-engine-adapter.mjs';
import { openB33b1FileJournal } from './b3-3b-1-journal.mjs';
import { strictCandidateDirectory, verifyPins } from './verify-pins.mjs';

function accountSecret() {
  for (;;) {
    const candidate = Uint8Array.from(randomBytes(32));
    try { schnorr.getPublicKey(candidate); return candidate; } catch { candidate.fill(0); }
  }
}

function writeOwnerOnly(path, value) {
  writeFileSync(path, value, { flag: 'wx', mode: 0o600 });
  chmodSync(path, 0o600);
}

function freshDirectory(root, prefix) {
  mkdirSync(root, { recursive: true, mode: 0o700 });
  chmodSync(root, 0o700);
  const path = mkdtempSync(resolve(root, prefix));
  chmodSync(path, 0o700);
  return path;
}

async function loadCandidate(candidatePath, tuple) {
  const directory = strictCandidateDirectory(candidatePath);
  const wasmRead = readExactRegularFile(
    resolve(directory, 'openmls_wasm_bg.wasm'), tuple['openmls_wasm_bg.wasm'],
  );
  const moduleRead = readExactRegularFile(
    resolve(directory, 'openmls_wasm.js'), tuple['openmls_wasm.js'],
  );
  try {
    const moduleUrl = `data:text/javascript;base64,${Buffer.from(moduleRead.bytes).toString('base64')}`
      + `#b33b1-stage1-${process.pid}-${randomBytes(8).toString('hex')}`;
    const wasm = await import(moduleUrl);
    await wasm.default({ module_or_path: wasmRead.bytes });
    for (const name of [
      'PhaseB33b1PendingActivation', 'PhaseB33b1Group',
      'PhaseB33b1PendingApplicationOutbound', 'PhaseB33b1PendingApplicationInbound',
    ]) {
      if (typeof wasm[name] !== 'function') {
        failB33b1(B33B1_ERROR.ENGINE_REJECTED, `candidate WASM lacks ${name}`);
      }
    }
    return Object.freeze({ wasm, wasmBytes: wasmRead.bytes });
  } finally {
    clearBytes(moduleRead.bytes);
  }
}

async function initializeMdk(peer, fields) {
  const hello = await peer.request('hello');
  if (hello?.mdk_revision !== fields.expectedRevision) {
    failB33b1(B33B1_ERROR.PIN_DRIFT, 'MDK peer revision drifted');
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

function event(identityHex, groupIdHex, marker) {
  return encodeMarmotAppEvent({
    pubkey: identityHex,
    created_at: 1_786_680_000 + marker,
    kind: 9,
    tags: [['h', groupIdHex]],
    content: `B3.3b-1 synthetic event ${marker}`,
  });
}

function requireProjection(styxHead, mdkProjection, label) {
  if (mdkProjection?.epoch?.toString() !== styxHead.epochDec
    || mdkProjection?.group_context_sha256 !== styxHead.groupContextSha256Hex
    || mdkProjection?.group_id_hex !== styxHead.groupIdHex) {
    failB33b1(B33B1_ERROR.ENGINE_REJECTED, `${label} peer projections diverged`, {
      mdkProjection, styxHead,
    });
  }
}

function clearRecovery(value) {
  clearBytes(value?.stateBytes);
  clearBytes(value?.parentStateBytes);
  clearBytes(value?.pendingStateBytes);
  clearBytes(value?.commitBytes);
}

export async function runStage1Probe(candidatePath) {
  const pins = verifyPins(candidatePath);
  const b32Root = freshDirectory(B32A_PRIVATE_ROOT, 'b33b1-stage1-b32-');
  const b33Root = freshDirectory(B33B1_PRIVATE_ROOT, 'b33b1-stage1-journal-');
  const mdkRoot = freshDirectory(B33A_PRIVATE_ROOT, 'b33b1-stage1-mdk-');
  mkdirSync(B33A_MDK_BUILD_ROOT, { recursive: true, mode: 0o700 });
  const mdkBuildPath = resolve(B33A_MDK_BUILD_ROOT,
    `b33b1-stage1-${process.pid}-${randomBytes(6).toString('hex')}`);
  let mdk;
  let mdkSecret;
  let loaded;
  let withheldStyx;
  let withheldMdk;
  try {
    const mdkBuild = buildMdkPeer(mdkBuildPath);
    mdkSecret = accountSecret();
    const mdkIdentityHex = bytesToHex(schnorr.getPublicKey(mdkSecret));
    const secretPath = resolve(mdkRoot, 'account-secret.hex');
    const databaseKeyPath = resolve(mdkRoot, 'database-key.hex');
    const databasePath = resolve(mdkRoot, 'account.sqlite3');
    const mdkFields = {
      databaseKeyPath, databasePath, expectedRevision: pins.mdkRevision,
      identityHex: mdkIdentityHex, secretPath,
    };
    writeOwnerOnly(secretPath, bytesToHex(mdkSecret));
    writeOwnerOnly(databaseKeyPath, randomBytes(32).toString('hex'));

    const styx = await StyxB32aPeer.create(b32Root, mdkIdentityHex);
    const keyPackage = await styx.publicKeyPackage();
    mdk = new MdkB33aProcess(mdkBuild.executable);
    await initializeMdk(mdk, mdkFields);
    const creation = await mdk.request('create_group', {
      key_package_hex: keyPackage.keyPackageHex,
    });
    await styx.recordWelcome(creation.welcome_hex);
    const joined = await styx.joinRecordedWelcome();
    await mdk.request('confirm_published', {
      welcome_message_id_hex: creation.welcome_message_id_hex,
    });
    if (joined.projection.groupIdHex !== creation.group_id_hex) {
      failB33b1(B33B1_ERROR.ENGINE_REJECTED, 'peers joined different groups');
    }

    loaded = await loadCandidate(candidatePath, pins.candidateTuple);
    const b32Journal = openB32aFileJournal(resolve(b32Root, 'journal'));
    const activation = await b32Journal.activationState();
    const journalDirectory = resolve(b33Root, 'journal');
    let journal = openB33b1FileJournal(journalDirectory);
    let adapter = new B33b1EvolutionAdapter({ journal, wasm: loaded.wasm });
    let active;
    try { active = await adapter.activateFromB32a(activation.head, activation.bytes); }
    finally { clearBytes(activation.bytes); }
    clearRecovery(active);

    withheldMdk = await mdk.request('send_application', {
      payload_hex: bytesToHex(event(mdkIdentityHex, creation.group_id_hex, 1)),
    });
    withheldStyx = await adapter.prepareApplicationOutbound(
      event(keyPackage.accountIdentityHex, creation.group_id_hex, 2),
    );

    const mdkPrepared = await mdk.request('self_update');
    await mdk.close();
    mdk = new MdkB33aProcess(mdkBuild.executable);
    await initializeMdk(mdk, mdkFields);
    await mdk.request('restore_group', { group_id_hex: creation.group_id_hex });
    const recoveredMdk = await mdk.request('drain_auto_publish');
    if (recoveredMdk?.disposition !== 'group_evolution_recovered_for_publication'
      || recoveredMdk?.group_message_hex !== mdkPrepared.group_message_hex
      || recoveredMdk?.message_id_hex !== mdkPrepared.message_id_hex) {
      failB33b1(B33B1_ERROR.ENGINE_REJECTED,
        'MDK did not recover byte-identical publication material', recoveredMdk);
    }

    const staged = await adapter.stageInbound(
      Uint8Array.from(Buffer.from(recoveredMdk.group_message_hex, 'hex')),
    );
    journal = openB33b1FileJournal(journalDirectory);
    adapter = new B33b1EvolutionAdapter({ journal, wasm: loaded.wasm });
    const applied = await adapter.applyStagedInbound();
    await mdk.request('confirm_group_published', {
      message_id_hex: recoveredMdk.message_id_hex,
    });
    requireProjection(applied.head, await mdk.request('public_projection'), 'epoch two');

    const liveMdk = await mdk.request('send_application', {
      payload_hex: bytesToHex(event(mdkIdentityHex, creation.group_id_hex, 3)),
    });
    const liveStyxReceive = await adapter.receiveApplication(
      Uint8Array.from(Buffer.from(liveMdk.group_message_hex, 'hex')),
    );
    clearBytes(liveStyxReceive.plaintextBytes);
    const liveStyx = await adapter.prepareApplicationOutbound(
      event(keyPackage.accountIdentityHex, creation.group_id_hex, 4),
    );
    const liveMdkReceive = await mdk.request('ingest_group_message', {
      group_message_hex: bytesToHex(liveStyx.ciphertextBytes),
    });
    if (liveMdkReceive?.disposition !== 'application_message_processed') {
      failB33b1(B33B1_ERROR.ENGINE_REJECTED, 'epoch-two Styx traffic was not processed');
    }
    const liveStyxContentSha256Hex = sha256Hex(liveStyx.ciphertextBytes);
    clearBytes(liveStyx.ciphertextBytes);

    const styxPrepared = await adapter.prepareLocal();
    journal = openB33b1FileJournal(journalDirectory);
    adapter = new B33b1EvolutionAdapter({ journal, wasm: loaded.wasm });
    const retry = await adapter.retryLocal();
    if (!Buffer.from(retry.commitBytes).equals(Buffer.from(styxPrepared.commitBytes))) {
      failB33b1(B33B1_ERROR.CORRUPT, 'local retry changed exact Commit bytes');
    }
    const buffered = await mdk.request('ingest_group_evolution', {
      group_message_hex: bytesToHex(retry.commitBytes),
    });
    await mdk.close();
    mdk = new MdkB33aProcess(mdkBuild.executable);
    await initializeMdk(mdk, mdkFields);
    await mdk.request('restore_group', { group_id_hex: creation.group_id_hex });
    const waiting = await mdk.request('converge_group_evolution', {
      expected_accepted_app_message_ids: [],
      expected_already_seen_message_ids: [],
      expected_content_sha256: retry.commitSha256Hex,
      expected_from_epoch: 2,
      expected_to_epoch: 3,
      monotonic_ms: 1_000_000,
    });
    const settled = await mdk.request('converge_group_evolution', {
      expected_accepted_app_message_ids: [
        withheldMdk.message_id_hex,
        liveMdk.message_id_hex,
      ].sort(),
      expected_already_seen_message_ids: [liveStyxContentSha256Hex],
      expected_content_sha256: retry.commitSha256Hex,
      expected_from_epoch: 2,
      expected_to_epoch: 3,
      monotonic_ms: 1_000_000_000,
    });
    if (buffered?.disposition !== 'group_evolution_buffered'
      || waiting?.disposition !== 'group_evolution_waiting'
      || settled?.disposition !== 'group_evolution_settled') {
      failB33b1(B33B1_ERROR.ENGINE_REJECTED, 'MDK convergence lifecycle drifted', {
        buffered, waiting, settled,
      });
    }
    await adapter.recordLocalAcceptance(retry.headDigestHex, {
      commitSha256Hex: retry.commitSha256Hex,
      peerGroupContextSha256Hex: retry.projection.candidateGroupContextSha256Hex,
      evidenceSha256Hex: sha256Hex(canonicalJsonBytes(settled)),
    });
    journal = openB33b1FileJournal(journalDirectory);
    adapter = new B33b1EvolutionAdapter({ journal, wasm: loaded.wasm });
    const merged = await adapter.mergeAcceptedLocal();
    requireProjection(merged.head, await mdk.request('public_projection'), 'epoch three');
    clearBytes(styxPrepared.commitBytes);
    clearBytes(retry.commitBytes);

    const delayedFromMdk = await adapter.receiveApplication(
      Uint8Array.from(Buffer.from(withheldMdk.group_message_hex, 'hex')),
    );
    if (delayedFromMdk.evidence.messageEpoch !== '1'
      || delayedFromMdk.evidence.currentEpoch !== '3') {
      failB33b1(B33B1_ERROR.ENGINE_REJECTED, 'Styx did not authenticate retained MDK traffic');
    }
    const delayedFromStyx = await mdk.request('ingest_group_message', {
      group_message_hex: bytesToHex(withheldStyx.ciphertextBytes),
    });
    if (delayedFromStyx?.disposition !== 'application_message_processed') {
      failB33b1(B33B1_ERROR.ENGINE_REJECTED, 'MDK did not authenticate retained Styx traffic');
    }
    const styxReplay = await adapter.receiveApplication(
      Uint8Array.from(Buffer.from(withheldMdk.group_message_hex, 'hex')),
    );
    const mdkReplay = await mdk.request('ingest_group_message', {
      group_message_hex: bytesToHex(withheldStyx.ciphertextBytes),
    });
    if (styxReplay?.disposition !== 'duplicate'
      || !['duplicate', 'own_echo'].includes(mdkReplay?.disposition)) {
      failB33b1(B33B1_ERROR.ENGINE_REJECTED, 'retained traffic replay was not rejected');
    }
    clearBytes(delayedFromMdk.plaintextBytes);

    const final = await journal.readRecovery();
    try {
      if (final.action !== B33B1_RECOVERY.STABLE || final.head.epochDec !== '3') {
        failB33b1(B33B1_ERROR.CORRUPT, 'final durable authority is not epoch three');
      }
      return Object.freeze({
        candidateTuple: pins.candidateTuple,
        groupIdHex: creation.group_id_hex,
        finalEpoch: final.head.epochDec,
        finalGroupContextSha256Hex: final.head.groupContextSha256Hex,
        transitionCount: final.head.transitions.length,
        applicationRecordCount: final.head.applicationRecords.length,
        mdkPreparedCommitRecoveredExactly: true,
        styxLocalCommitRetriedExactly: true,
        retainedTrafficAcceptedBothDirections: true,
        retainedTrafficReplayRejectedBothDirections: true,
      });
    } finally { clearRecovery(final); }
  } finally {
    await mdk?.close().catch(() => {});
    clearBytes(mdkSecret);
    clearBytes(loaded?.wasmBytes);
    clearBytes(withheldStyx?.ciphertextBytes);
    rmSync(b32Root, { recursive: true, force: true });
    rmSync(b33Root, { recursive: true, force: true });
    rmSync(mdkRoot, { recursive: true, force: true });
    rmSync(mdkBuildPath, { recursive: true, force: true });
  }
}
