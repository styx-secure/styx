// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — exact-pin B3.3b-1 capability probe.

import { randomBytes } from 'node:crypto';
import {
  chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync,
} from 'node:fs';
import { resolve } from 'node:path';

import { schnorr } from '@noble/curves/secp256k1';

import { B32A_PRIVATE_ROOT }
  from '../marmot-phase-b3-2a/b3-2a-canonical.mjs';
import { openB32aFileJournal }
  from '../marmot-phase-b3-2a/b3-2a-journal.mjs';
import { StyxB32aPeer }
  from '../marmot-phase-b3-2a/b3-2a-styx-driver.mjs';
import {
  B33A_MDK_BUILD_ROOT,
  B33A_PRIVATE_ROOT,
} from '../marmot-phase-b3-3a/b3-3a-canonical.mjs';
import { readExactRegularFile }
  from '../marmot-phase-b3-3a/b3-3a-artifact-reader.mjs';
import { buildMdkPeer }
  from '../marmot-phase-b3-3a/b3-3a-mdk-builder.mjs';
import { MdkB33aProcess }
  from '../marmot-phase-b3-3a/b3-3a-mdk-driver.mjs';
import { B33A_MDK_SIGNER_PATH }
  from '../marmot-phase-b3-3a/b3-3a-mdk-signer.mjs';
import {
  B33B1_ERROR,
  B33B1_MAX_PAST_EPOCHS,
  B33B1_PROVIDER_FORMAT,
  bytesToHex,
  clearBytes,
  failB33b1,
  hexToBytes,
  projectionEvidence,
  safeFree,
  sha256Hex,
} from './b3-3b-1-canonical.mjs';
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

function freshPrivateDirectory(root, prefix) {
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
      + `#b33b1-stage0-${process.pid}-${randomBytes(8).toString('hex')}`;
    const wasm = await import(moduleUrl);
    await wasm.default({ module_or_path: wasmRead.bytes });
    for (const name of [
      'PhaseB33b1PendingActivation', 'PhaseB33b1Group',
      'PhaseB33b1PendingLocalCommit', 'PhaseB33b1PendingInboundCommit',
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

function activate(wasm, activation) {
  const predecessorDigest = hexToBytes(
    'B3.2a candidate digest', activation.head.candidateBlobSha256Hex, 32,
  );
  const groupId = hexToBytes('group id', activation.head.groupIdHex);
  const ownIdentity = hexToBytes('own identity', activation.head.accountIdentityHex, 32);
  const ownSignatureKey = hexToBytes(
    'own signature key', activation.head.leafSignatureKeyHex, 32,
  );
  let pending;
  let release;
  let candidateState;
  try {
    pending = wasm.PhaseB33b1PendingActivation.prepare_from_b32a_state(
      activation.bytes, predecessorDigest, groupId, ownIdentity, ownSignatureKey,
    );
    if (!pending) {
      failB33b1(B33B1_ERROR.ENGINE_REJECTED,
        'B3.2a joined state did not contain the expected group');
    }
    if (pending.provider_format() !== B33B1_PROVIDER_FORMAT
      || pending.max_past_epochs() !== B33B1_MAX_PAST_EPOCHS) {
      failB33b1(B33B1_ERROR.ENGINE_REJECTED,
        'retention activation did not expose the exact B3.3b-1 format');
    }
    const candidateDigest = Uint8Array.from(pending.candidate_state_sha256());
    const contextDigest = Uint8Array.from(pending.group_context_sha256());
    const leafDigest = Uint8Array.from(pending.verified_leaf_digest());
    try {
      release = pending.release(
        predecessorDigest, candidateDigest, contextDigest, leafDigest,
      );
      candidateState = Uint8Array.from(release.take_candidate_state());
      if (sha256Hex(candidateState) !== bytesToHex(candidateDigest)) {
        failB33b1(B33B1_ERROR.ENGINE_REJECTED,
          'released activation state differs from the authenticated digest');
      }
      return Object.freeze({
        candidateState,
        contextSha256Hex: bytesToHex(contextDigest),
        groupId,
        ownIdentity,
        ownSignatureKey,
      });
    } finally {
      clearBytes(candidateDigest);
      clearBytes(contextDigest);
      clearBytes(leafDigest);
    }
  } finally {
    clearBytes(predecessorDigest);
    safeFree(release);
    safeFree(pending);
  }
}

function applyInbound(wasm, state, binding, commitHex) {
  const commit = hexToBytes('MDK self-update Commit', commitHex);
  let group;
  let pending;
  let projection;
  let released;
  let applied;
  let parentState;
  let exactCommit;
  try {
    group = wasm.PhaseB33b1Group.load_clean_canonical_state(
      state, binding.groupId, binding.ownIdentity, binding.ownSignatureKey,
    );
    if (!group) failB33b1(B33B1_ERROR.ENGINE_REJECTED, 'active group did not reload');
    pending = group.stage_inbound_commit(commit);
    projection = pending.projection();
    const evidence = projectionEvidence(projection);
    const parentDigest = Uint8Array.from(pending.parent_state_sha256());
    const commitDigest = Uint8Array.from(pending.commit_sha256());
    const authorityDigest = Uint8Array.from(pending.authority_sha256());
    try {
      released = pending.release(parentDigest, commitDigest, authorityDigest);
      parentState = Uint8Array.from(released.take_parent_state());
      exactCommit = Uint8Array.from(released.take_commit());
      applied = wasm.PhaseB33b1Group.apply_inbound_commit(
        parentState, binding.groupId, binding.ownIdentity, binding.ownSignatureKey,
        exactCommit, parentDigest, commitDigest, authorityDigest,
      );
      const committedState = Uint8Array.from(applied.take_committed_state());
      return Object.freeze({ committedState, evidence });
    } finally {
      clearBytes(parentDigest);
      clearBytes(commitDigest);
      clearBytes(authorityDigest);
    }
  } finally {
    clearBytes(commit);
    clearBytes(parentState);
    clearBytes(exactCommit);
    safeFree(applied);
    safeFree(released);
    safeFree(projection);
    safeFree(pending);
    safeFree(group);
  }
}

function prepareLocal(wasm, state, binding) {
  let group;
  let pending;
  let projection;
  let release;
  try {
    group = wasm.PhaseB33b1Group.load_clean_canonical_state(
      state, binding.groupId, binding.ownIdentity, binding.ownSignatureKey,
    );
    if (!group) failB33b1(B33B1_ERROR.ENGINE_REJECTED, 'active group did not reload');
    pending = group.prepare_self_update();
    projection = pending.projection();
    const evidence = projectionEvidence(projection);
    const parentDigest = Uint8Array.from(pending.parent_state_sha256());
    const pendingDigest = Uint8Array.from(pending.pending_state_sha256());
    const commitDigest = Uint8Array.from(pending.commit_sha256());
    const authorityDigest = Uint8Array.from(pending.authority_sha256());
    try {
      release = pending.release(
        parentDigest, pendingDigest, commitDigest, authorityDigest,
      );
      return Object.freeze({
        authorityDigest: Uint8Array.from(authorityDigest),
        commit: Uint8Array.from(release.take_commit()),
        commitDigest: Uint8Array.from(commitDigest),
        evidence,
        parentDigest: Uint8Array.from(parentDigest),
        pendingDigest: Uint8Array.from(pendingDigest),
        pendingState: Uint8Array.from(release.take_pending_state()),
      });
    } finally {
      clearBytes(parentDigest);
      clearBytes(pendingDigest);
      clearBytes(commitDigest);
      clearBytes(authorityDigest);
    }
  } finally {
    safeFree(release);
    safeFree(projection);
    safeFree(pending);
    safeFree(group);
  }
}

function confirmLocal(wasm, prepared, binding) {
  let release;
  try {
    release = wasm.PhaseB33b1Group.confirm_local_commit(
      prepared.pendingState, binding.groupId, binding.ownIdentity, binding.ownSignatureKey,
      prepared.commit, prepared.parentDigest, prepared.pendingDigest,
      prepared.commitDigest, prepared.authorityDigest,
    );
    return Uint8Array.from(release.take_committed_state());
  } finally {
    safeFree(release);
  }
}

async function initializeMdk(peer, fields) {
  const hello = await peer.request('hello');
  if (hello?.mdk_revision !== fields.expectedRevision) {
    failB33b1(B33B1_ERROR.PIN_DRIFT, 'MDK peer hello revision drifted');
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

function requireMdkRoster(projection, expectedIdentities, label) {
  const expected = [...expectedIdentities].sort();
  const projected = projection?.sorted_member_identities_hex;
  const leafIdentities = projection?.leaves?.map((leaf) => leaf.account_identity_hex);
  if (!Array.isArray(projected) || !Array.isArray(leafIdentities)
    || projected.length !== expected.length || leafIdentities.length !== expected.length
    || projected.some((identity, index) => identity !== expected[index])
    || [...leafIdentities].sort().some((identity, index) => identity !== expected[index])) {
    failB33b1(B33B1_ERROR.MDK_REJECTS_STYX_SELF_UPDATE,
      `${label} projected a different member roster`, {
        expected, leafIdentities, projected,
      });
  }
}

export async function runStage0Probe(candidatePath) {
  const pins = verifyPins(candidatePath);
  const styxRoot = freshPrivateDirectory(B32A_PRIVATE_ROOT, 'b33b1-stage0-styx-');
  const mdkRoot = freshPrivateDirectory(B33A_PRIVATE_ROOT, 'b33b1-stage0-mdk-');
  mkdirSync(B33A_MDK_BUILD_ROOT, { recursive: true, mode: 0o700 });
  const mdkBuildPath = resolve(B33A_MDK_BUILD_ROOT,
    `b33b1-stage0-${process.pid}-${randomBytes(6).toString('hex')}`);
  let mdk;
  let mdkSecret;
  let loaded;
  let active;
  let first;
  let local;
  let competingLocal;
  let finalState;
  try {
    const mdkBuild = buildMdkPeer(mdkBuildPath);
    mdkSecret = accountSecret();
    const mdkIdentityHex = bytesToHex(schnorr.getPublicKey(mdkSecret));
    const secretPath = resolve(mdkRoot, 'account-secret.hex');
    const databaseKeyPath = resolve(mdkRoot, 'database-key.hex');
    const databasePath = resolve(mdkRoot, 'account.sqlite3');
    const mdkFields = {
      databaseKeyPath,
      databasePath,
      expectedRevision: pins.mdkRevision,
      identityHex: mdkIdentityHex,
      secretPath,
    };
    writeOwnerOnly(secretPath, bytesToHex(mdkSecret));
    writeOwnerOnly(databaseKeyPath, randomBytes(32).toString('hex'));

    const styx = await StyxB32aPeer.create(styxRoot, mdkIdentityHex);
    const keyPackage = await styx.publicKeyPackage();
    mdk = new MdkB33aProcess(mdkBuild.executable);
    await initializeMdk(mdk, mdkFields);
    const creation = await mdk.request('create_group', {
      key_package_hex: keyPackage.keyPackageHex,
    });
    await styx.recordWelcome(creation.welcome_hex);
    const joined = await styx.joinRecordedWelcome();
    if (joined.projection.groupIdHex !== creation.group_id_hex) {
      failB33b1(B33B1_ERROR.ENGINE_REJECTED, 'Styx and MDK joined different groups');
    }
    await mdk.request('confirm_published', {
      welcome_message_id_hex: creation.welcome_message_id_hex,
    });

    loaded = await loadCandidate(candidatePath, pins.candidateTuple);
    const journal = openB32aFileJournal(resolve(styxRoot, 'journal'));
    const activation = await journal.activationState();
    try { active = activate(loaded.wasm, activation); } finally { clearBytes(activation.bytes); }

    const mdkUpdate = await mdk.request('self_update');
    first = applyInbound(loaded.wasm, active.candidateState, active, mdkUpdate.group_message_hex);
    await mdk.request('confirm_group_published', {
      message_id_hex: mdkUpdate.message_id_hex,
    });
    const afterMdk = await mdk.request('public_projection');
    if (afterMdk.epoch.toString() !== first.evidence.targetEpoch
      || afterMdk.group_context_sha256 !== first.evidence.candidateGroupContextSha256Hex) {
      failB33b1(B33B1_ERROR.ENGINE_REJECTED,
        'MDK-originated self-update did not converge on the staged Styx projection');
    }
    const expectedRoster = [bytesToHex(active.ownIdentity), mdkIdentityHex];
    requireMdkRoster(afterMdk, expectedRoster, 'post-MDK-update state');

    local = prepareLocal(loaded.wasm, first.committedState, active);
    try {
      competingLocal = prepareLocal(loaded.wasm, first.committedState, active);
    } catch (error) {
      failB33b1(B33B1_ERROR.DUAL_CANDIDATE_STAGING_INSUFFICIENT,
        'candidate WASM could not stage two self-updates from the same durable parent', {
          cause: error instanceof Error ? error.message : `${error}`,
        });
    }
    if (local.evidence.sourceEpoch !== competingLocal.evidence.sourceEpoch
      || local.evidence.targetEpoch !== competingLocal.evidence.targetEpoch
      || local.evidence.orderingPriority !== competingLocal.evidence.orderingPriority
      || local.evidence.orderingPriority !== 'ordinary'
      || local.evidence.committerAccountHex !== competingLocal.evidence.committerAccountHex
      || !/^[0-9a-f]{64}$/.test(local.evidence.committerAccountHex)
      || local.evidence.groupIdHex !== competingLocal.evidence.groupIdHex
      || !/^[0-9a-f]{64}$/.test(local.evidence.commitSha256Hex)
      || !/^[0-9a-f]{64}$/.test(competingLocal.evidence.commitSha256Hex)
      || local.evidence.commitSha256Hex === competingLocal.evidence.commitSha256Hex) {
      failB33b1(B33B1_ERROR.DUAL_CANDIDATE_STAGING_INSUFFICIENT,
        'same-parent candidate ordering inputs were absent, invalid, or indistinguishable', {
          first: local.evidence,
          second: competingLocal.evidence,
        });
    }
    let buffered;
    try {
      buffered = await mdk.request('ingest_group_evolution', {
        group_message_hex: bytesToHex(local.commit),
      });
    } catch (error) {
      failB33b1(B33B1_ERROR.MDK_REJECTS_STYX_SELF_UPDATE,
        'pinned MDK rejected the exact Styx self-update', {
          code: error?.code, details: error?.details, message: error?.message,
        });
    }
    if (buffered?.disposition !== 'group_evolution_buffered'
      || buffered?.group_id_hex !== creation.group_id_hex
      || buffered?.epoch?.toString() !== local.evidence.sourceEpoch
      || buffered?.content_sha256 !== local.evidence.commitSha256Hex) {
      failB33b1(B33B1_ERROR.MDK_REJECTS_STYX_SELF_UPDATE,
        'pinned MDK did not durably buffer the exact Styx self-update', buffered);
    }

    await mdk.close();
    mdk = new MdkB33aProcess(mdkBuild.executable);
    await initializeMdk(mdk, mdkFields);
    const restored = await mdk.request('restore_group', {
      group_id_hex: creation.group_id_hex,
    });
    if (restored?.disposition !== 'durable_group_restored'
      || restored?.projection?.epoch?.toString() !== local.evidence.sourceEpoch
      || restored?.projection?.group_context_sha256
        !== local.evidence.parentGroupContextSha256Hex) {
      failB33b1(B33B1_ERROR.MDK_REJECTS_STYX_SELF_UPDATE,
        'fresh MDK process did not restore the durable parent before convergence', restored);
    }
    requireMdkRoster(restored.projection, expectedRoster, 'restored parent state');

    const waiting = await mdk.request('converge_group_evolution', {
      expected_accepted_app_message_ids: [],
      expected_already_seen_message_ids: [],
      expected_content_sha256: local.evidence.commitSha256Hex,
      expected_from_epoch: Number(local.evidence.sourceEpoch),
      expected_to_epoch: Number(local.evidence.targetEpoch),
      monotonic_ms: 1_000_000,
    });
    if (waiting?.disposition !== 'group_evolution_waiting'
      || waiting?.status !== 'syncing'
      || waiting?.candidate_count !== 0
      || waiting?.eligible_count !== 0
      || waiting?.from_epoch?.toString() !== local.evidence.sourceEpoch
      || waiting?.group_id_hex !== creation.group_id_hex) {
      failB33b1(B33B1_ERROR.MDK_REJECTS_STYX_SELF_UPDATE,
        'fresh MDK process did not rebase the durable convergence cutoff', waiting);
    }

    const settled = await mdk.request('converge_group_evolution', {
      expected_accepted_app_message_ids: [],
      expected_already_seen_message_ids: [],
      expected_content_sha256: local.evidence.commitSha256Hex,
      expected_from_epoch: Number(local.evidence.sourceEpoch),
      expected_to_epoch: Number(local.evidence.targetEpoch),
      monotonic_ms: 1_000_000_000,
    });
    if (settled?.disposition !== 'group_evolution_settled'
      || settled?.status !== 'settled'
      || settled?.candidate_count !== 1
      || settled?.eligible_count !== 1
      || settled?.accepted_content_sha256 !== local.evidence.commitSha256Hex
      || settled?.from_epoch?.toString() !== local.evidence.sourceEpoch
      || settled?.to_epoch?.toString() !== local.evidence.targetEpoch
      || settled?.group_id_hex !== creation.group_id_hex
      || !Array.isArray(settled?.accepted_app_message_ids)
      || settled.accepted_app_message_ids.length !== 0
      || !Array.isArray(settled?.already_seen_message_ids)
      || settled.already_seen_message_ids.length !== 0) {
      failB33b1(B33B1_ERROR.MDK_REJECTS_STYX_SELF_UPDATE,
        'pinned MDK did not select exactly the buffered Styx self-update', settled);
    }

    const beforeStyx = await mdk.request('public_projection');
    if (beforeStyx.epoch.toString() !== local.evidence.targetEpoch
      || beforeStyx.group_context_sha256 !== local.evidence.candidateGroupContextSha256Hex
      || beforeStyx.group_id_hex !== local.evidence.groupIdHex
      || settled.accepted_content_sha256 !== local.evidence.commitSha256Hex) {
      failB33b1(B33B1_ERROR.MDK_REJECTS_STYX_SELF_UPDATE,
        'MDK projection diverged before local confirmation', { beforeStyx, settled });
    }
    requireMdkRoster(beforeStyx, expectedRoster, 'pre-confirmation Styx-update state');

    finalState = confirmLocal(loaded.wasm, local, active);
    const afterStyx = await mdk.request('public_projection');
    if (afterStyx.epoch.toString() !== local.evidence.targetEpoch
      || afterStyx.group_context_sha256 !== local.evidence.candidateGroupContextSha256Hex) {
      failB33b1(B33B1_ERROR.MDK_REJECTS_STYX_SELF_UPDATE,
        'pinned MDK accepted the Commit but projected a different group state');
    }
    requireMdkRoster(afterStyx, expectedRoster, 'post-Styx-update state');

    const replay = await mdk.request('ingest_group_evolution', {
      group_message_hex: bytesToHex(local.commit),
    });
    if (replay?.disposition !== 'duplicate'
      || replay?.message_id_hex !== buffered.message_id_hex) {
      failB33b1(B33B1_ERROR.MDK_REJECTS_STYX_SELF_UPDATE,
        'settled Styx self-update replay was not an event-free duplicate', replay);
    }
    const afterReplay = await mdk.request('public_projection');
    if (afterReplay.epoch !== afterStyx.epoch
      || afterReplay.group_context_sha256 !== afterStyx.group_context_sha256) {
      failB33b1(B33B1_ERROR.MDK_REJECTS_STYX_SELF_UPDATE,
        'duplicate replay changed the selected MDK group state');
    }
    requireMdkRoster(afterReplay, expectedRoster, 'post-replay state');

    return Object.freeze({
      candidateTuple: pins.candidateTuple,
      finalEpoch: local.evidence.targetEpoch,
      finalGroupContextSha256Hex: local.evidence.candidateGroupContextSha256Hex,
      groupIdHex: creation.group_id_hex,
      mdkOriginatedCommitSha256Hex: first.evidence.commitSha256Hex,
      mdkSemanticallyAcceptedStyxSelfUpdate: true,
      mdkStyxSelfUpdateInitialDisposition: buffered.disposition,
      mdkStyxSelfUpdateReplayDisposition: replay.disposition,
      retentionPolicy: B33B1_MAX_PAST_EPOCHS,
      styxOriginatedCommitSha256Hex: local.evidence.commitSha256Hex,
    });
  } finally {
    await mdk?.close().catch(() => {});
    clearBytes(mdkSecret);
    clearBytes(loaded?.wasmBytes);
    clearBytes(active?.candidateState);
    clearBytes(active?.groupId);
    clearBytes(active?.ownIdentity);
    clearBytes(active?.ownSignatureKey);
    clearBytes(first?.committedState);
    clearBytes(local?.authorityDigest);
    clearBytes(local?.commit);
    clearBytes(local?.commitDigest);
    clearBytes(local?.parentDigest);
    clearBytes(local?.pendingDigest);
    clearBytes(local?.pendingState);
    clearBytes(competingLocal?.authorityDigest);
    clearBytes(competingLocal?.commit);
    clearBytes(competingLocal?.commitDigest);
    clearBytes(competingLocal?.parentDigest);
    clearBytes(competingLocal?.pendingDigest);
    clearBytes(competingLocal?.pendingState);
    clearBytes(finalState);
    rmSync(styxRoot, { recursive: true, force: true });
    rmSync(mdkRoot, { recursive: true, force: true });
    rmSync(mdkBuildPath, { recursive: true, force: true });
  }
}
