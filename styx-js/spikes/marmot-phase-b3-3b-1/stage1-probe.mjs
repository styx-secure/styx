// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — journalled sequential evolution and retained-traffic probe.

import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
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
  B33B1_ERROR, B33B1_LIMITS, B33B1_PRIVATE_ROOT, B33B1_RECOVERY,
  b33b1RosterSha256, bytesToHex, canonicalJsonBytes, clearBytes, exactFields,
  failB33b1, sha256Hex,
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

export async function loadCandidate(candidatePath, tuple) {
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

const FRESH_PROCESS_WORKER = fileURLToPath(new URL('./stage1-fresh-process.mjs', import.meta.url));
const FRESH_CHECKPOINT_FIELDS = Object.freeze([
  'committedCommitSha256Hex', 'epochDec', 'groupContextSha256Hex', 'groupIdHex',
  'headDigestHex', 'rosterSha256Hex',
]);
const FRESH_PROJECTION_FIELDS = Object.freeze([
  'authoritySha256Hex', 'candidateGroupContextSha256Hex', 'commitSha256Hex',
  'committerAccountHex', 'committerLeafIndex', 'committerSignatureKeyHex', 'domain',
  'groupIdHex', 'orderingPriority', 'parentGroupContextSha256Hex',
  'parentStateSha256Hex', 'sourceEpoch', 'targetEpoch', 'verifiedLeafDigestHex',
]);

export const B33B1_STAGE1_OPERATION_SEQUENCE = Object.freeze([
  'group-created-and-joined',
  'b33b1-activated',
  'epoch1-retained-traffic-prepared',
  'mdk-self-update-prepared',
  'mdk-self-update-recovered-after-restart',
  'styx-inbound-staged',
  'styx-inbound-applied-after-restart',
  'mdk-self-update-confirmed',
  'epoch2-projection-verified',
  'epoch2-live-traffic',
  'styx-self-update-prepared',
  'styx-self-update-retried-after-restart',
  'mdk-styx-update-buffered',
  'mdk-restarted-from-buffered-parent',
  'mdk-convergence-waiting',
  'mdk-convergence-settled',
  'peer-acceptance-durable',
  'styx-local-merge-after-restart',
  'epoch3-projection-verified',
  'retained-traffic-delivered',
  'retained-traffic-replay-rejected',
  'final-durable-state-verified',
]);

function stage1OperationTrace() {
  const observed = [];
  return Object.freeze({
    advance(name) {
      const expected = B33B1_STAGE1_OPERATION_SEQUENCE[observed.length];
      if (name !== expected) {
        failB33b1(B33B1_ERROR.BLOCKED, 'Stage 1 operation sequence drifted', {
          expected, observed: Object.freeze([...observed]), received: name,
        });
      }
      observed.push(name);
    },
    complete() {
      if (observed.length !== B33B1_STAGE1_OPERATION_SEQUENCE.length) {
        failB33b1(B33B1_ERROR.BLOCKED, 'Stage 1 operation sequence is incomplete', {
          expected: B33B1_STAGE1_OPERATION_SEQUENCE,
          observed: Object.freeze([...observed]),
        });
      }
      return Object.freeze([...observed]);
    },
  });
}

function requireDigest(value, label) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) {
    failB33b1(B33B1_ERROR.CORRUPT, `${label} is not a SHA-256 digest`);
  }
}

function parseFreshProcessResult(action, value) {
  if (action === 'retry-local') {
    const parsed = exactFields(value, [
      'action', 'commitHex', 'commitSha256Hex', 'headDigestHex', 'processId', 'projection',
    ], 'fresh-process local retry');
    const projection = exactFields(
      parsed.projection, FRESH_PROJECTION_FIELDS, 'fresh-process local projection',
    );
    if (parsed.action !== action || typeof parsed.commitHex !== 'string'
      || parsed.commitHex.length < 2 || parsed.commitHex.length % 2 !== 0
      || parsed.commitHex.length > B33B1_LIMITS.maxCommitBytes * 2
      || !/^[0-9a-f]+$/.test(parsed.commitHex)) {
      failB33b1(B33B1_ERROR.CORRUPT, 'fresh-process local retry is not canonical');
    }
    requireDigest(parsed.commitSha256Hex, 'fresh-process Commit');
    requireDigest(parsed.headDigestHex, 'fresh-process head');
    if (!Number.isSafeInteger(parsed.processId) || parsed.processId <= 0
      || parsed.processId === process.pid
      || sha256Hex(Buffer.from(parsed.commitHex, 'hex')) !== parsed.commitSha256Hex
      || projection.commitSha256Hex !== parsed.commitSha256Hex) {
      failB33b1(B33B1_ERROR.CORRUPT, 'fresh-process local retry digest disagrees');
    }
    return Object.freeze({ ...parsed, projection: Object.freeze({ ...projection }) });
  }
  const parsed = exactFields(
    value, ['action', 'head', 'processId'], 'fresh-process recovery result',
  );
  const head = exactFields(parsed.head, FRESH_CHECKPOINT_FIELDS, 'fresh-process checkpoint');
  if (parsed.action !== action || !Number.isSafeInteger(parsed.processId)
    || parsed.processId <= 0 || parsed.processId === process.pid) {
    failB33b1(B33B1_ERROR.CORRUPT, 'fresh-process recovery action changed');
  }
  for (const field of [
    'committedCommitSha256Hex', 'groupContextSha256Hex', 'headDigestHex', 'rosterSha256Hex',
  ]) requireDigest(head[field], `fresh-process ${field}`);
  return Object.freeze({ action, head: Object.freeze({ ...head }) });
}

function recoverInFreshProcess(action, candidatePath, journalDirectory) {
  const result = spawnSync(process.execPath, [
    FRESH_PROCESS_WORKER, action, candidatePath, journalDirectory,
  ], {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
    timeout: 120_000,
  });
  if (result.error || result.status !== 0 || result.signal !== null) {
    failB33b1(B33B1_ERROR.ENGINE_REJECTED, `fresh-process ${action} failed`, {
      error: result.error?.message ?? null,
      signal: result.signal,
      status: result.status,
      stderr: (result.stderr ?? '').slice(0, 4096),
    });
  }
  try {
    return parseFreshProcessResult(action, JSON.parse(result.stdout));
  } catch (error) {
    failB33b1(B33B1_ERROR.CORRUPT, `fresh-process ${action} returned invalid JSON`, {
      cause: error instanceof Error ? error.message : `${error}`,
      stdout: result.stdout.slice(0, 4096),
    });
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

function mdkRosterSha256(mdkProjection, label) {
  if (!Array.isArray(mdkProjection?.leaves)
    || !Array.isArray(mdkProjection?.sorted_member_identities_hex)
    || mdkProjection.leaves.length !== mdkProjection.sorted_member_identities_hex.length) {
    failB33b1(B33B1_ERROR.ENGINE_REJECTED, `${label} MDK roster is incomplete`);
  }
  const members = mdkProjection.leaves.map((leaf) => {
    if (!Number.isSafeInteger(leaf?.leaf_index) || leaf.leaf_index < 0
      || typeof leaf.account_identity_hex !== 'string'
      || !/^[0-9a-f]{64}$/.test(leaf.account_identity_hex)
      || typeof leaf.signature_public_key_hex !== 'string'
      || !/^[0-9a-f]{64}$/.test(leaf.signature_public_key_hex)) {
      failB33b1(B33B1_ERROR.ENGINE_REJECTED, `${label} MDK roster leaf is invalid`);
    }
    return {
      leafIndex: leaf.leaf_index,
      identityHex: leaf.account_identity_hex,
      signatureKeyHex: leaf.signature_public_key_hex,
    };
  });
  const identities = members.map(({ identityHex }) => identityHex).sort();
  if (new Set(members.map(({ leafIndex }) => leafIndex)).size !== members.length
    || !identities.every((identity, index) => (
      identity === mdkProjection.sorted_member_identities_hex[index]
    ))) {
    failB33b1(B33B1_ERROR.ENGINE_REJECTED, `${label} MDK roster projection disagrees`);
  }
  return b33b1RosterSha256(members);
}

function requireProjection(styxHead, mdkProjection, mdkCommitSha256Hex, label) {
  if (mdkProjection?.epoch?.toString() !== styxHead.epochDec
    || mdkProjection?.group_context_sha256 !== styxHead.groupContextSha256Hex
    || mdkProjection?.group_id_hex !== styxHead.groupIdHex
    || mdkRosterSha256(mdkProjection, label) !== styxHead.rosterSha256Hex
    || mdkCommitSha256Hex !== styxHead.committedCommitSha256Hex) {
    failB33b1(B33B1_ERROR.ENGINE_REJECTED, `${label} peer projections diverged`, {
      mdkCommitSha256Hex, mdkProjection, styxHead,
    });
  }
}

function requireProjectedCandidate(evidence, durableHead, mdkProjection, label) {
  if (mdkProjection?.epoch?.toString() !== evidence.targetEpoch
    || mdkProjection?.group_context_sha256 !== evidence.candidateGroupContextSha256Hex
    || mdkProjection?.group_id_hex !== evidence.groupIdHex
    || mdkRosterSha256(mdkProjection, label) !== durableHead.rosterSha256Hex) {
    failB33b1(B33B1_ERROR.ENGINE_REJECTED, `${label} candidate projection diverged`, {
      durableHead, evidence, mdkProjection,
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
  const operations = stage1OperationTrace();
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
  let freshProcessRecoveryCount = 0;
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
    operations.advance('group-created-and-joined');

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
    operations.advance('b33b1-activated');

    withheldMdk = await mdk.request('send_application', {
      payload_hex: bytesToHex(event(mdkIdentityHex, creation.group_id_hex, 1)),
    });
    withheldStyx = await adapter.prepareApplicationOutbound(
      event(keyPackage.accountIdentityHex, creation.group_id_hex, 2),
    );
    operations.advance('epoch1-retained-traffic-prepared');

    const mdkPrepared = await mdk.request('self_update');
    operations.advance('mdk-self-update-prepared');
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
    operations.advance('mdk-self-update-recovered-after-restart');

    await adapter.stageInbound(
      Uint8Array.from(Buffer.from(recoveredMdk.group_message_hex, 'hex')),
    );
    operations.advance('styx-inbound-staged');
    adapter = undefined;
    const applied = recoverInFreshProcess(
      'apply-staged-inbound', candidatePath, journalDirectory,
    );
    freshProcessRecoveryCount += 1;
    operations.advance('styx-inbound-applied-after-restart');
    journal = openB33b1FileJournal(journalDirectory);
    adapter = new B33b1EvolutionAdapter({ journal, wasm: loaded.wasm });
    await mdk.request('confirm_group_published', {
      message_id_hex: recoveredMdk.message_id_hex,
    });
    operations.advance('mdk-self-update-confirmed');
    requireProjection(
      applied.head, await mdk.request('public_projection'), recoveredMdk.commit_sha256,
      'epoch two',
    );
    operations.advance('epoch2-projection-verified');

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
    operations.advance('epoch2-live-traffic');

    const styxPrepared = await adapter.prepareLocal();
    operations.advance('styx-self-update-prepared');
    adapter = undefined;
    const retry = recoverInFreshProcess('retry-local', candidatePath, journalDirectory);
    freshProcessRecoveryCount += 1;
    journal = openB33b1FileJournal(journalDirectory);
    adapter = new B33b1EvolutionAdapter({ journal, wasm: loaded.wasm });
    const retryCommitBytes = Uint8Array.from(Buffer.from(retry.commitHex, 'hex'));
    if (!Buffer.from(retryCommitBytes).equals(Buffer.from(styxPrepared.commitBytes))) {
      failB33b1(B33B1_ERROR.CORRUPT, 'local retry changed exact Commit bytes');
    }
    operations.advance('styx-self-update-retried-after-restart');
    const buffered = await mdk.request('ingest_group_evolution', {
      group_message_hex: retry.commitHex,
    });
    if (buffered?.disposition !== 'group_evolution_buffered'
      || buffered?.epoch?.toString() !== '2'
      || buffered?.content_sha256 !== retry.commitSha256Hex) {
      failB33b1(B33B1_ERROR.ENGINE_REJECTED,
        'MDK did not buffer the exact epoch-two Styx candidate', buffered);
    }
    operations.advance('mdk-styx-update-buffered');
    await mdk.close();
    mdk = new MdkB33aProcess(mdkBuild.executable);
    await initializeMdk(mdk, mdkFields);
    const restoredBufferedParent = await mdk.request('restore_group', {
      group_id_hex: creation.group_id_hex,
    });
    if (restoredBufferedParent?.projection?.epoch?.toString() !== '2'
      || restoredBufferedParent?.projection?.group_context_sha256
        !== retry.projection.parentGroupContextSha256Hex) {
      failB33b1(B33B1_ERROR.ENGINE_REJECTED,
        'fresh MDK process did not restore the buffered candidate parent', restoredBufferedParent);
    }
    operations.advance('mdk-restarted-from-buffered-parent');
    const waiting = await mdk.request('converge_group_evolution', {
      expected_accepted_app_message_ids: [],
      expected_already_seen_message_ids: [],
      expected_content_sha256: retry.commitSha256Hex,
      expected_from_epoch: 2,
      expected_to_epoch: 3,
      monotonic_ms: 1_000_000,
    });
    if (waiting?.disposition !== 'group_evolution_waiting'
      || waiting?.from_epoch?.toString() !== '2'
      || waiting?.candidate_count !== 0
      || waiting?.eligible_count !== 0) {
      failB33b1(B33B1_ERROR.ENGINE_REJECTED,
        'MDK convergence did not enter the bounded waiting state', waiting);
    }
    operations.advance('mdk-convergence-waiting');
    const expectedAcceptedAppMessageIds = Object.freeze([
      withheldMdk.message_id_hex,
      liveMdk.message_id_hex,
    ].sort());
    const expectedAlreadySeenMessageIds = Object.freeze([liveStyxContentSha256Hex]);
    const settled = await mdk.request('converge_group_evolution', {
      expected_accepted_app_message_ids: expectedAcceptedAppMessageIds,
      expected_already_seen_message_ids: expectedAlreadySeenMessageIds,
      expected_content_sha256: retry.commitSha256Hex,
      expected_from_epoch: 2,
      expected_to_epoch: 3,
      monotonic_ms: 1_000_000_000,
    });
    if (settled?.disposition !== 'group_evolution_settled'
      || JSON.stringify(settled?.accepted_app_message_ids)
        !== JSON.stringify(expectedAcceptedAppMessageIds)
      || JSON.stringify(settled?.already_seen_message_ids)
        !== JSON.stringify(expectedAlreadySeenMessageIds)) {
      failB33b1(B33B1_ERROR.ENGINE_REJECTED, 'MDK convergence lifecycle drifted', {
        buffered, waiting, settled,
      });
    }
    operations.advance('mdk-convergence-settled');
    const preAcceptance = await journal.readRecovery();
    try {
      requireProjectedCandidate(
        retry.projection, preAcceptance.head, await mdk.request('public_projection'),
        'pre-acceptance epoch three',
      );
    } finally { clearRecovery(preAcceptance); }
    await adapter.recordLocalAcceptance(retry.headDigestHex, {
      commitSha256Hex: retry.commitSha256Hex,
      peerGroupContextSha256Hex: retry.projection.candidateGroupContextSha256Hex,
      evidenceSha256Hex: sha256Hex(canonicalJsonBytes(settled)),
    });
    operations.advance('peer-acceptance-durable');
    adapter = undefined;
    const merged = recoverInFreshProcess(
      'merge-accepted-local', candidatePath, journalDirectory,
    );
    freshProcessRecoveryCount += 1;
    operations.advance('styx-local-merge-after-restart');
    journal = openB33b1FileJournal(journalDirectory);
    adapter = new B33b1EvolutionAdapter({ journal, wasm: loaded.wasm });
    requireProjection(
      merged.head, await mdk.request('public_projection'), settled.accepted_content_sha256,
      'epoch three',
    );
    operations.advance('epoch3-projection-verified');
    clearBytes(styxPrepared.commitBytes);
    clearBytes(retryCommitBytes);

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
    operations.advance('retained-traffic-delivered');
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
    operations.advance('retained-traffic-replay-rejected');

    const final = await journal.readRecovery();
    try {
      if (final.action !== B33B1_RECOVERY.STABLE || final.head.epochDec !== '3') {
        failB33b1(B33B1_ERROR.CORRUPT, 'final durable authority is not epoch three');
      }
      operations.advance('final-durable-state-verified');
      const operationSequence = operations.complete();
      return Object.freeze({
        candidateTuple: pins.candidateTuple,
        groupIdHex: creation.group_id_hex,
        finalEpoch: final.head.epochDec,
        finalGroupContextSha256Hex: final.head.groupContextSha256Hex,
        transitionCount: final.head.transitions.length,
        applicationRecordCount: final.head.applicationRecords.length,
        freshProcessRecoveryCount,
        operationSequence,
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
