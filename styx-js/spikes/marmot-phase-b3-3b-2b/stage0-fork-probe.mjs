// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — observe the exact pinned concurrent-fork behavior.

import { createHash, randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import {
  chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync,
} from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

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
  B33B1_MAX_PAST_EPOCHS,
  B33B1_PROVIDER_FORMAT,
  bytesToHex,
  clearBytes,
  hexToBytes,
  projectionEvidence,
  safeFree,
  sha256Hex,
} from '../marmot-phase-b3-3b-1/b3-3b-1-canonical.mjs';
import { artifactDirectory, verifyPins }
  from '../marmot-phase-b3-3b-1/verify-pins.mjs';
import {
  B33B2B_ERROR,
  compareIdentityHex,
  failB33b2b,
} from './b3-3b-2b-canonical.mjs';
import {
  B33b2bEvolutionAdapter,
  MemoryB33b2bEffectSink,
} from './b3-3b-2b-engine-adapter.mjs';
import { openB33b2bFileJournal } from './b3-3b-2b-journal.mjs';

const MAX_IDENTITY_ATTEMPTS = 32;

function accountSecret() {
  for (;;) {
    const candidate = Uint8Array.from(randomBytes(32));
    try { schnorr.getPublicKey(candidate); return candidate; } catch { candidate.fill(0); }
  }
}

function freshPrivateDirectory(root, prefix) {
  mkdirSync(root, { recursive: true, mode: 0o700 });
  chmodSync(root, 0o700);
  const path = mkdtempSync(resolve(root, prefix));
  chmodSync(path, 0o700);
  return path;
}

function digestFields(domain, ...fields) {
  const hash = createHash('sha256');
  hash.update(domain, 'utf8');
  for (const field of fields) {
    const bytes = typeof field === 'string' ? Buffer.from(field, 'hex') : Buffer.from(field);
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.length);
    hash.update(length);
    hash.update(bytes);
  }
  return hash.digest('hex');
}

function sameBytes(left, right) {
  return left.byteLength === right.byteLength
    && left.every((value, index) => value === right[index]);
}

export async function loadCandidate(candidatePath, tuple) {
  const directory = artifactDirectory(candidatePath);
  const wasmRead = readExactRegularFile(
    resolve(directory, 'openmls_wasm_bg.wasm'), tuple['openmls_wasm_bg.wasm'],
  );
  const moduleRead = readExactRegularFile(
    resolve(directory, 'openmls_wasm.js'), tuple['openmls_wasm.js'],
  );
  try {
    const suffix = randomBytes(8).toString('hex');
    const moduleUrl = `data:text/javascript;base64,${Buffer.from(moduleRead.bytes).toString('base64')}`
      + `#b33b2b-stage0-${process.pid}-${suffix}`;
    const wasm = await import(moduleUrl);
    await wasm.default({ module_or_path: wasmRead.bytes });
    for (const name of [
      'PhaseB33b1PendingActivation', 'PhaseB33b1Group',
      'PhaseB33b1PendingLocalCommit', 'PhaseB33b1PendingInboundCommit',
    ]) {
      if (typeof wasm[name] !== 'function') {
        failB33b2b(B33B2B_ERROR.ENGINE_REJECTED, `candidate WASM lacks ${name}`);
      }
    }
    return Object.freeze({ wasm, wasmBytes: wasmRead.bytes });
  } finally {
    clearBytes(moduleRead.bytes);
  }
}

function runFreshAdapterProcess({
  action, bindingPath, candidatePath, journalDirectory, rivalCommitPath = '',
}) {
  const workerPath = fileURLToPath(new URL('./engine-fresh-process.mjs', import.meta.url));
  try {
    return JSON.parse(execFileSync(process.execPath, [
      workerPath,
      action,
      bindingPath,
      journalDirectory,
      candidatePath ?? '',
      rivalCommitPath,
    ], {
      encoding: 'utf8',
      maxBuffer: 4 * 1024 * 1024,
      timeout: 120_000,
    }));
  } catch (error) {
    failB33b2b(B33B2B_ERROR.ENGINE_REJECTED,
      `fresh-process adapter action ${action} failed`, {
        nativeMessage: error instanceof Error ? error.message : `${error}`,
      });
  }
  return undefined;
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
  try {
    pending = wasm.PhaseB33b1PendingActivation.prepare_from_b32a_state(
      activation.bytes, predecessorDigest, groupId, ownIdentity, ownSignatureKey,
    );
    if (!pending) {
      failB33b2b(B33B2B_ERROR.ENGINE_REJECTED,
        'B3.2a joined state did not contain the expected group');
    }
    if (pending.provider_format() !== B33B1_PROVIDER_FORMAT
      || pending.max_past_epochs() !== B33B1_MAX_PAST_EPOCHS) {
      failB33b2b(B33B2B_ERROR.ENGINE_REJECTED,
        'retention activation did not expose the frozen B3.3b-1 profile');
    }
    const candidateDigest = Uint8Array.from(pending.candidate_state_sha256());
    const contextDigest = Uint8Array.from(pending.group_context_sha256());
    const leafDigest = Uint8Array.from(pending.verified_leaf_digest());
    try {
      release = pending.release(
        predecessorDigest, candidateDigest, contextDigest, leafDigest,
      );
      const candidateState = Uint8Array.from(release.take_candidate_state());
      if (sha256Hex(candidateState) !== bytesToHex(candidateDigest)) {
        clearBytes(candidateState);
        failB33b2b(B33B2B_ERROR.ENGINE_REJECTED,
          'released activation state differs from its authenticated digest');
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

function prepareLocal(wasm, state, binding) {
  let group;
  let pending;
  let projection;
  let release;
  try {
    group = wasm.PhaseB33b1Group.load_clean_canonical_state(
      state, binding.groupId, binding.ownIdentity, binding.ownSignatureKey,
    );
    if (!group) failB33b2b(B33B2B_ERROR.ENGINE_REJECTED, 'active group did not reload');
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

function requireRestoredStyxBranch(wasm, state, binding, expectedEvidence) {
  let group;
  let pending;
  let projection;
  try {
    group = wasm.PhaseB33b1Group.load_clean_canonical_state(
      state, binding.groupId, binding.ownIdentity, binding.ownSignatureKey,
    );
    if (!group) {
      failB33b2b(B33B2B_ERROR.ENGINE_REJECTED,
        'durably restored Styx branch did not reload');
    }
    pending = group.prepare_self_update();
    projection = pending.projection();
    const evidence = projectionEvidence(projection);
    requireEqual(evidence.sourceEpoch, expectedEvidence.targetEpoch,
      'durably restored Styx branch changed its epoch');
    requireEqual(evidence.parentGroupContextSha256Hex,
      expectedEvidence.candidateGroupContextSha256Hex,
      'durably restored Styx branch changed its GroupContext');
    pending.discard();
  } finally {
    safeFree(projection);
    safeFree(pending);
    safeFree(group);
  }
}

function applyInbound(wasm, parentState, binding, commitHex) {
  const commit = hexToBytes('rival Commit', commitHex);
  let group;
  let pending;
  let projection;
  let released;
  let applied;
  let exactParent;
  let exactCommit;
  try {
    group = wasm.PhaseB33b1Group.load_clean_canonical_state(
      parentState, binding.groupId, binding.ownIdentity, binding.ownSignatureKey,
    );
    if (!group) failB33b2b(B33B2B_ERROR.ENGINE_REJECTED, 'retained parent did not reload');
    pending = group.stage_inbound_commit(commit);
    projection = pending.projection();
    const evidence = projectionEvidence(projection);
    const parentDigest = Uint8Array.from(pending.parent_state_sha256());
    const commitDigest = Uint8Array.from(pending.commit_sha256());
    const authorityDigest = Uint8Array.from(pending.authority_sha256());
    try {
      released = pending.release(parentDigest, commitDigest, authorityDigest);
      exactParent = Uint8Array.from(released.take_parent_state());
      exactCommit = Uint8Array.from(released.take_commit());
      applied = wasm.PhaseB33b1Group.apply_inbound_commit(
        exactParent, binding.groupId, binding.ownIdentity, binding.ownSignatureKey,
        exactCommit, parentDigest, commitDigest, authorityDigest,
      );
      return Object.freeze({
        committedState: Uint8Array.from(applied.take_committed_state()),
        evidence,
      });
    } finally {
      clearBytes(parentDigest);
      clearBytes(commitDigest);
      clearBytes(authorityDigest);
    }
  } finally {
    clearBytes(commit);
    clearBytes(exactParent);
    clearBytes(exactCommit);
    safeFree(applied);
    safeFree(released);
    safeFree(projection);
    safeFree(pending);
    safeFree(group);
  }
}

async function initializeMdk(peer, fields) {
  const hello = await peer.request('hello');
  if (hello?.mdk_revision !== fields.expectedRevision) {
    failB33b2b(B33B2B_ERROR.PIN_DRIFT, 'MDK peer hello revision drifted');
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

async function selectStyxIdentity(root, mdkIdentityHex, desiredWinner) {
  for (let attempt = 0; attempt < MAX_IDENTITY_ATTEMPTS; attempt += 1) {
    const styxRoot = freshPrivateDirectory(root, `identity-${attempt}-`);
    const styx = await StyxB32aPeer.create(styxRoot, mdkIdentityHex);
    const keyPackage = await styx.publicKeyPackage();
    const styxWins = compareIdentityHex(keyPackage.accountIdentityHex, mdkIdentityHex) < 0;
    if ((desiredWinner === 'styx') === styxWins) {
      return Object.freeze({ keyPackage, styx, styxRoot });
    }
    rmSync(styxRoot, { recursive: true, force: true });
  }
  failB33b2b(B33B2B_ERROR.BLOCKED,
    'could not obtain the requested synthetic identity ordering within the bound');
}

function requireEqual(actual, expected, message, details = undefined) {
  if (actual !== expected) {
    failB33b2b(B33B2B_ERROR.MDK_BEHAVIOR_DRIFT, message, {
      actual, expected, ...details,
    });
  }
}

function requireArray(value, length, message) {
  if (!Array.isArray(value) || value.length !== length) {
    failB33b2b(B33B2B_ERROR.MDK_BEHAVIOR_DRIFT, message, { value });
  }
  return value;
}

function requireBoundedSelection(pass, candidates, expectedWinner) {
  requireEqual(pass?.status, 'settled', 'fork pass did not settle');
  requireEqual(pass?.candidate_count, 2, 'fork pass did not expose exactly two candidates');
  requireEqual(pass?.eligible_count, 2, 'fork pass did not expose two eligible candidates');
  requireEqual(pass?.accepted_proposal_count, 0, 'fork pass admitted a proposal');
  requireEqual(pass?.accepted_app_message_count, 0,
    'fork pass admitted an application message');
  requireEqual(pass?.invalidated_app_message_count, 0,
    'fork pass invalidated an application message');
  requireEqual(pass?.dropped_message_count, 0, 'fork pass dropped a bounded candidate');
  requireEqual(pass?.error_count, 0, 'fork pass exposed an engine error');
  requireEqual(pass?.queued_outbound_intent_count, 0,
    'fork pass queued an outbound intent');
  requireEqual(pass?.publishable_outbound_message_count, 0,
    'fork pass emitted publishable output');
  const trace = pass?.selection_trace;
  const projected = requireArray(trace?.candidates, 2,
    'selection trace did not expose exactly two candidates');
  const byDigest = new Map(projected.map((candidate) => [candidate.tip_digest, candidate]));
  for (const candidate of candidates) {
    const observed = byDigest.get(candidate.evidence.commitSha256Hex);
    if (!observed) {
      failB33b2b(B33B2B_ERROR.MDK_BEHAVIOR_DRIFT,
        'selection trace omitted an authenticated candidate Commit');
    }
    requireEqual(observed.tip_committer, candidate.evidence.committerAccountHex,
      'selection trace changed the authenticated committer');
    requireEqual(observed.tip_priority, 'ordinary',
      'selection trace changed the ordinary priority');
    requireEqual(observed.fork_epoch.toString(), candidate.evidence.sourceEpoch,
      'selection trace changed the fork epoch');
    requireEqual(observed.tip_epoch.toString(), candidate.evidence.targetEpoch,
      'selection trace changed the target epoch');
    requireEqual(observed.eligible, true, 'selection trace rejected a valid candidate');
    requireArray(observed.rejection_reasons, 0,
      'selection trace attached a rejection reason to an eligible candidate');
    requireEqual(observed.app_witness_count, 0, 'candidate carried an application witness');
    requireEqual(observed.score?.valid_commit_depth, 1, 'candidate depth was not one');
    requireEqual(observed.score?.effective_commit_depth, 1,
      'effective candidate depth was not one');
    requireEqual(observed.score?.witness_quorum_met, false,
      'candidate unexpectedly met witness quorum');
    requireEqual(observed.score?.app_witness_score, 0,
      'candidate unexpectedly carried a witness score');
    requireEqual(observed.score?.tip_priority, 'ordinary',
      'candidate score changed the ordinary priority');
    requireEqual(observed.score?.tip_committer, candidate.evidence.committerAccountHex,
      'candidate score changed the authenticated committer');
    requireEqual(observed.score?.tip_digest, candidate.evidence.commitSha256Hex,
      'candidate score changed the exact Commit digest');
  }
  const selected = projected.find((candidate) => candidate.branch_id === trace.selected_branch_id);
  if (!selected) {
    failB33b2b(B33B2B_ERROR.MDK_BEHAVIOR_DRIFT,
      'selection trace did not identify one of its candidates');
  }
  requireEqual(selected.tip_digest, expectedWinner.evidence.commitSha256Hex,
    'pinned MDK selected a different Commit from the authenticated ordering rule');
  requireEqual(selected.tip_committer, expectedWinner.evidence.committerAccountHex,
    'pinned MDK selected a different committer from the authenticated ordering rule');

  const rules = requireArray(trace.rule_trace, 6,
    'selection trace changed the bounded ordering rule count');
  const expectedRules = [
    ['effective_commit_depth', false],
    ['witness_quorum_met', false],
    ['app_witness_score', false],
    ['tip_priority', false],
    ['tip_committer', true],
    ['tip_digest', false],
  ];
  expectedRules.forEach(([name, decisive], index) => {
    requireEqual(rules[index]?.rule_name, name, 'selection rule ordering drifted');
    requireEqual(rules[index]?.decisive, decisive,
      `selection rule ${name} changed its decisive status`);
  });
  const deferred = requireArray(pass.deferred_messages, 1,
    'fork pass did not retain exactly one losing candidate');
  requireEqual(deferred[0]?.kind, 'commit', 'deferred object was not a Commit');
  requireEqual(deferred[0]?.reason, 'nonselectedeligiblebranch',
    'losing valid Commit did not remain a non-selected eligible branch');
  const events = requireArray(pass.events, 2,
    'fork pass changed its exact application-visible event count');
  requireEqual(events[0]?.kind, 'commit_rolled_back',
    'fork pass did not first expose the upstream rollback event');
  requireEqual(events[1]?.kind, 'group_state_invalidated',
    'fork pass did not expose the upstream superseded-state event');
  requireEqual(events[1]?.reason, 'supersededbybranchselection',
    'fork pass changed the upstream supersession reason');
  return Object.freeze({
    candidateCount: pass.candidate_count,
    decisiveRule: 'tip_committer',
    deferredReason: deferred[0].reason,
    eligibleCount: pass.eligible_count,
    selectedCommitSha256Hex: selected.tip_digest,
    status: pass.status,
  });
}

function requireEmptyReplayPass(pass) {
  requireEqual(pass?.status, 'settled', 'idempotent convergence pass did not settle');
  for (const field of [
    'candidate_count', 'eligible_count', 'accepted_proposal_count',
    'accepted_app_message_count', 'invalidated_app_message_count',
    'dropped_message_count', 'already_seen_count', 'queued_outbound_intent_count',
    'publishable_outbound_message_count', 'error_count', 'replay_probe_count',
  ]) {
    requireEqual(pass?.[field], 0, `idempotent convergence pass changed ${field}`);
  }
  requireArray(pass?.accepted_commits, 0,
    'idempotent convergence pass reaccepted a Commit');
  requireArray(pass?.deferred_messages, 0,
    'idempotent convergence pass redeferred a Commit');
  requireArray(pass?.events, 0,
    'idempotent convergence pass repeated application-visible events');
  requireEqual(pass?.selection_trace, null,
    'idempotent convergence pass repeated a selection trace');
}

function requirePairwiseDisposition(ingest, candidates, expectedWinner) {
  const losing = candidates.find((candidate) => candidate.role !== expectedWinner.role);
  if (expectedWinner.role === 'mdk') {
    requireEqual(ingest.disposition, 'stale',
      'winning MDK branch did not classify the rival as stale');
    requireArray(ingest.events, 0,
      'winner-side stale classification released an event');
    requireEqual(ingest.reason?.AlreadyAtEpoch?.current?.toString(),
      expectedWinner.evidence.targetEpoch,
      'winner-side stale classification changed the current epoch');
    requireEqual(ingest.reason?.AlreadyAtEpoch?.msg_epoch?.toString(),
      expectedWinner.evidence.sourceEpoch,
      'winner-side stale classification changed the rival source epoch');
    return Object.freeze({
      disposition: 'stale',
      eventKinds: Object.freeze([]),
      winnerSideClassification: 'already_at_epoch',
    });
  }

  requireEqual(ingest.disposition, 'processed',
    'displacing rival did not enter the pairwise recovery path');
  const events = requireArray(ingest.events, 3,
    'pairwise recovery changed its exact event count');
  const recovered = events[0];
  requireEqual(recovered?.kind, 'fork_recovered',
    'pairwise recovery did not first emit fork recovery');
  requireEqual(recovered?.source_epoch?.toString(), expectedWinner.evidence.sourceEpoch,
    'pairwise recovery changed the source epoch');
  requireEqual(recovered?.recovered_epoch?.toString(), expectedWinner.evidence.targetEpoch,
    'pairwise recovery changed the recovered epoch');
  for (const [label, observed, candidate] of [
    ['winner', recovered?.winner, expectedWinner],
    ['invalidated', recovered?.invalidated, losing],
  ]) {
    requireEqual(observed?.commit_digest, candidate.evidence.commitSha256Hex,
      `pairwise ${label} changed the exact Commit digest`);
    requireEqual(observed?.committer, candidate.evidence.committerAccountHex,
      `pairwise ${label} changed the authenticated committer`);
    requireEqual(observed?.priority, 'ordinary',
      `pairwise ${label} changed the Commit priority`);
    requireEqual(observed?.source_epoch?.toString(), candidate.evidence.sourceEpoch,
      `pairwise ${label} changed the source epoch`);
  }
  requireEqual(events[1]?.kind, 'group_state_invalidated',
    'pairwise recovery did not expose upstream superseded-state evidence');
  requireEqual(events[1]?.reason, 'supersededbybranchselection',
    'pairwise recovery changed the upstream supersession reason');
  requireEqual(events[2]?.kind, 'epoch_changed',
    'pairwise recovery did not finish with the epoch transition');
  requireEqual(events[2]?.from_epoch?.toString(), expectedWinner.evidence.sourceEpoch,
    'pairwise epoch event changed its source epoch');
  requireEqual(events[2]?.to_epoch?.toString(), expectedWinner.evidence.targetEpoch,
    'pairwise epoch event changed its target epoch');
  return Object.freeze({
    disposition: 'processed',
    eventKinds: Object.freeze(events.map((event) => event.kind)),
    winnerSideClassification: null,
  });
}

function releasePrepared(prepared) {
  clearBytes(prepared?.authorityDigest);
  clearBytes(prepared?.commit);
  clearBytes(prepared?.commitDigest);
  clearBytes(prepared?.parentDigest);
  clearBytes(prepared?.pendingDigest);
  clearBytes(prepared?.pendingState);
}

async function runScenario(
  candidatePath, pins, mdkBuild, desiredWinner, deliveryMode, durableProof = false,
) {
  const scenarioRoot = freshPrivateDirectory(
    B32A_PRIVATE_ROOT, `b33b2b-${desiredWinner}-${deliveryMode}-`,
  );
  const mdkRoot = freshPrivateDirectory(
    B33A_PRIVATE_ROOT, `b33b2b-${desiredWinner}-${deliveryMode}-`,
  );
  let mdk;
  let mdkSecret;
  let loaded;
  let active;
  let local;
  let localBranch;
  let rivalOnStyx;
  let selected;
  let forkAdapter;
  let forkJournal;
  let effectSink;
  let forkBindingPath;
  let forkJournalDirectory;
  let journalEvidence;
  try {
    mdkSecret = accountSecret();
    const mdkIdentityHex = bytesToHex(schnorr.getPublicKey(mdkSecret));
    const identitySelection = await selectStyxIdentity(
      scenarioRoot, mdkIdentityHex, desiredWinner,
    );
    const { keyPackage, styx, styxRoot } = identitySelection;
    const secretPath = resolve(mdkRoot, 'account-secret.hex');
    const databaseKeyPath = resolve(mdkRoot, 'database-key.hex');
    const databasePath = resolve(mdkRoot, 'account.sqlite3');
    writeFileSync(secretPath, bytesToHex(mdkSecret), { flag: 'wx', mode: 0o600 });
    writeFileSync(databaseKeyPath, randomBytes(32).toString('hex'), { flag: 'wx', mode: 0o600 });
    chmodSync(secretPath, 0o600);
    chmodSync(databaseKeyPath, 0o600);
    const mdkFields = {
      databaseKeyPath,
      databasePath,
      expectedRevision: pins.mdkRevision,
      identityHex: mdkIdentityHex,
      secretPath,
    };

    mdk = new MdkB33aProcess(mdkBuild.executable);
    await initializeMdk(mdk, mdkFields);
    const creation = await mdk.request('create_group', {
      key_package_hex: keyPackage.keyPackageHex,
    });
    await styx.recordWelcome(creation.welcome_hex);
    const joined = await styx.joinRecordedWelcome();
    if (joined.projection.groupIdHex !== creation.group_id_hex) {
      failB33b2b(B33B2B_ERROR.ENGINE_REJECTED, 'Styx and MDK joined different groups');
    }
    await mdk.request('confirm_published', {
      welcome_message_id_hex: creation.welcome_message_id_hex,
    });

    loaded = await loadCandidate(candidatePath, pins.candidateTuple);
    const journal = openB32aFileJournal(resolve(styxRoot, 'journal'));
    const activation = await journal.activationState();
    try { active = activate(loaded.wasm, activation); } finally { clearBytes(activation.bytes); }

    if (durableProof) {
      forkJournalDirectory = resolve(styxRoot, 'b33b2b-journal');
      mkdirSync(forkJournalDirectory, { mode: 0o700 });
      forkBindingPath = resolve(styxRoot, 'b33b2b-binding.json');
      writeFileSync(forkBindingPath, JSON.stringify({
        groupIdHex: bytesToHex(active.groupId),
        ownIdentityHex: bytesToHex(active.ownIdentity),
        ownSignatureKeyHex: bytesToHex(active.ownSignatureKey),
      }), { flag: 'wx', mode: 0o600 });
      chmodSync(forkBindingPath, 0o600);
      forkJournal = openB33b2bFileJournal(forkJournalDirectory, B32A_PRIVATE_ROOT);
      effectSink = new MemoryB33b2bEffectSink();
      forkAdapter = new B33b2bEvolutionAdapter({
        binding: active, effectSink, journal: forkJournal, wasm: loaded.wasm,
      });
      const initialRoster = [keyPackage.accountIdentityHex, mdkIdentityHex].sort();
      await forkAdapter.activate({
        forkEpoch: activation.head.projection.epochDec,
        groupIdDigestHex: digestFields(
          'STYX-B33B2B-GROUP-ID-v1', creation.group_id_hex,
        ),
        parentGroupContextSha256Hex: active.contextSha256Hex,
        parentStateBytes: active.candidateState,
        rosterDigestHex: digestFields('STYX-B33B2B-ROSTER-v1', ...initialRoster),
      });
      const prepared = await forkAdapter.prepareLocal();
      local = Object.freeze({ commit: prepared.commitBytes, evidence: prepared.projection });
    } else {
      local = prepareLocal(loaded.wasm, active.candidateState, active);
    }
    const mdkLocal = await mdk.request('self_update');
    if (mdkLocal.source_epoch.toString() !== local.evidence.sourceEpoch) {
      failB33b2b(B33B2B_ERROR.ENGINE_REJECTED,
        'same-parent race did not begin from one epoch');
    }
    if (durableProof) {
      const localRecovery = await forkJournal.readRecovery();
      try { localBranch = Uint8Array.from(localRecovery.canonicalStateBytes); }
      finally {
        clearBytes(localRecovery.canonicalStateBytes);
        clearBytes(localRecovery.parentStateBytes);
        clearBytes(localRecovery.localCommitBytes);
      }
      forkAdapter.close();
      forkAdapter = null;
      const retry = runFreshAdapterProcess({
        action: 'retry-local',
        bindingPath: forkBindingPath,
        candidatePath,
        journalDirectory: forkJournalDirectory,
      });
      const retryBytes = Uint8Array.from(Buffer.from(retry.commitHex, 'hex'));
      if (!sameBytes(retryBytes, local.commit)
        || retry.commitSha256Hex !== local.evidence.commitSha256Hex) {
        clearBytes(retryBytes);
        failB33b2b(B33B2B_ERROR.CORRUPT,
          'restart regenerated the unresolved local publication obligation');
      }
      clearBytes(retryBytes);
      const rivalCommitPath = resolve(styxRoot, 'b33b2b-rival-commit.bin');
      writeFileSync(rivalCommitPath, Buffer.from(mdkLocal.group_message_hex, 'hex'), {
        flag: 'wx', mode: 0o600,
      });
      chmodSync(rivalCommitPath, 0o600);
      const rival = runFreshAdapterProcess({
        action: 'record-rival',
        bindingPath: forkBindingPath,
        candidatePath,
        journalDirectory: forkJournalDirectory,
        rivalCommitPath,
      });
      rivalOnStyx = Object.freeze({ evidence: rival.projection });
    } else {
      rivalOnStyx = applyInbound(
        loaded.wasm, active.candidateState, active, mdkLocal.group_message_hex,
      );
    }
    if (rivalOnStyx.evidence.sourceEpoch !== local.evidence.sourceEpoch
      || rivalOnStyx.evidence.targetEpoch !== local.evidence.targetEpoch
      || rivalOnStyx.evidence.orderingPriority !== 'ordinary'
      || local.evidence.orderingPriority !== 'ordinary') {
      failB33b2b(B33B2B_ERROR.ENGINE_REJECTED,
        'candidate projections are not the bounded ordinary depth-one race');
    }

    if (!durableProof) localBranch = confirmLocal(loaded.wasm, local, active);
    const styxBranchPath = resolve(styxRoot, 'b33b2b-local-branch.bin');
    writeFileSync(styxBranchPath, localBranch, { flag: 'wx', mode: 0o600 });
    chmodSync(styxBranchPath, 0o600);
    clearBytes(localBranch);
    localBranch = Uint8Array.from(readFileSync(styxBranchPath));
    requireRestoredStyxBranch(loaded.wasm, localBranch, active, local.evidence);
    await mdk.request('confirm_group_published', {
      message_id_hex: mdkLocal.message_id_hex,
    });
    const mdkOwnBranch = await mdk.request('public_projection');
    if (mdkOwnBranch.epoch.toString() !== local.evidence.targetEpoch
      || mdkOwnBranch.group_context_sha256
        !== rivalOnStyx.evidence.candidateGroupContextSha256Hex
      || mdkOwnBranch.group_context_sha256
        === local.evidence.candidateGroupContextSha256Hex) {
      failB33b2b(B33B2B_ERROR.ENGINE_REJECTED,
        'peers did not durably confirm distinct E+1 branches before exchange');
    }

    let restoredOwn;
    if (deliveryMode === 'after_restart') {
      await mdk.close();
      mdk = new MdkB33aProcess(mdkBuild.executable);
      await initializeMdk(mdk, mdkFields);
      restoredOwn = await mdk.request('restore_group', {
        group_id_hex: creation.group_id_hex,
      });
      if (restoredOwn?.projection?.group_context_sha256
        !== mdkOwnBranch.group_context_sha256) {
        failB33b2b(B33B2B_ERROR.ENGINE_REJECTED,
          'fresh MDK process did not restore its own conflicting branch');
      }
    }
    const ingest = await mdk.request('ingest_fork_evolution', {
      group_message_hex: bytesToHex(local.commit),
    });
    const expectedIngest = deliveryMode === 'after_restart'
      ? 'buffered' : (desiredWinner === 'styx' ? 'processed' : 'stale');
    requireEqual(ingest.disposition, expectedIngest,
      'rival Commit changed its exact pinned ingest disposition', { ingest });
    if (deliveryMode === 'after_restart') {
      requireEqual(ingest.epoch?.toString(), local.evidence.targetEpoch,
        'buffered rival Commit was assigned to a different epoch');
    }
    requireEqual(ingest.content_sha256, local.evidence.commitSha256Hex,
      'MDK ingest changed the exact rival Commit digest');
    const candidates = [
      Object.freeze({ evidence: local.evidence, role: 'styx' }),
      Object.freeze({ evidence: rivalOnStyx.evidence, role: 'mdk' }),
    ];
    const expectedWinnerCandidate = candidates.reduce((winner, candidate) => (
      compareIdentityHex(
        candidate.evidence.committerAccountHex,
        winner.evidence.committerAccountHex,
      ) < 0 ? candidate : winner
    ));
    requireEqual(expectedWinnerCandidate.role, desiredWinner,
      'synthetic identity assignment did not produce the requested winner');
    let selection;
    if (deliveryMode === 'after_restart') {
      requireArray(ingest.events, 0,
        'stored rival admission released an event before settlement');
      const firstPass = await mdk.request(
        'converge_fork_evolution', { monotonic_ms: 1_000_000 },
      );
      const secondPass = await mdk.request(
        'converge_fork_evolution', { monotonic_ms: 1_000_000_000 },
      );
      selection = requireBoundedSelection(
        firstPass, candidates, expectedWinnerCandidate,
      );
      requireEmptyReplayPass(secondPass);
    } else {
      selection = requirePairwiseDisposition(
        ingest, candidates, expectedWinnerCandidate,
      );
    }
    selected = await mdk.request('public_projection');
    requireEqual(
      selected.group_context_sha256,
      expectedWinnerCandidate.evidence.candidateGroupContextSha256Hex,
      'post-settlement MDK projection did not match the selected branch',
    );

    if (durableProof) {
      const frozen = runFreshAdapterProcess({
        action: 'freeze',
        bindingPath: forkBindingPath,
        candidatePath,
        journalDirectory: forkJournalDirectory,
      });
      const prepared = runFreshAdapterProcess({
        action: 'prepare',
        bindingPath: forkBindingPath,
        candidatePath,
        journalDirectory: forkJournalDirectory,
      });
      const stable = runFreshAdapterProcess({
        action: 'commit',
        bindingPath: forkBindingPath,
        candidatePath,
        journalDirectory: forkJournalDirectory,
      });
      forkAdapter = new B33b2bEvolutionAdapter({
        binding: active, effectSink,
        journal: openB33b2bFileJournal(
          forkJournalDirectory, B32A_PRIVATE_ROOT,
        ),
        wasm: loaded.wasm,
      });
      let injectedAfterAcceptance = false;
      if (desiredWinner === 'styx' && deliveryMode === 'after_restart') {
        effectSink.afterAccept = () => {
          effectSink.afterAccept = null;
          injectedAfterAcceptance = true;
          throw new Error('injected crash after effect acceptance before journal acknowledgement');
        };
        try {
          await forkAdapter.deliverStableEffect();
          failB33b2b(B33B2B_ERROR.BLOCKED,
            'effect crash injection did not interrupt acknowledgement');
        } catch (error) {
          if (error?.message !==
            'injected crash after effect acceptance before journal acknowledgement') throw error;
        }
        forkAdapter.close();
        forkAdapter = new B33b2bEvolutionAdapter({
          binding: active, effectSink,
          journal: openB33b2bFileJournal(
            resolve(styxRoot, 'b33b2b-journal'), B32A_PRIVATE_ROOT,
          ),
          wasm: loaded.wasm,
        });
      }
      const delivered = await forkAdapter.deliverStableEffect();
      const repeatedDelivery = await forkAdapter.deliverStableEffect();
      if (repeatedDelivery.disposition !== 'already_delivered') {
        failB33b2b(B33B2B_ERROR.CORRUPT,
          'acknowledged settlement effect was offered again');
      }
      const finalRecovery = await forkAdapter.journal.readRecovery();
      try {
        requireEqual(finalRecovery.head.canonical.groupContextSha256Hex,
          selected.group_context_sha256,
          'durable Styx canonical head did not match the selected MDK branch');
        requireEqual(finalRecovery.head.selectedCommitSha256Hex,
          expectedWinnerCandidate.evidence.commitSha256Hex,
          'durable Styx head selected a different exact Commit');
        journalEvidence = Object.freeze({
          effectCount: effectSink.effects.size,
          effectDisposition: delivered.disposition,
          injectedAfterAcceptance,
          finalHeadDigestHex: finalRecovery.head.headDigestHex,
          frozenSetDigestHex: frozen.frozenSetDigestHex,
          preparedHeadDigestHex: prepared.headDigestHex,
          selectedCommitSha256Hex: finalRecovery.head.selectedCommitSha256Hex,
          stableHeadDigestHex: stable.headDigestHex,
          state: finalRecovery.head.state,
        });
      } finally {
        clearBytes(finalRecovery.canonicalStateBytes);
        clearBytes(finalRecovery.parentStateBytes);
        clearBytes(finalRecovery.localCommitBytes);
        clearBytes(finalRecovery.rivalCommitBytes);
        clearBytes(finalRecovery.successorStateBytes);
        clearBytes(finalRecovery.settlementRecordBytes);
      }
    }

    let restoredSelected;
    if (deliveryMode === 'before_restart') {
      await mdk.close();
      mdk = new MdkB33aProcess(mdkBuild.executable);
      await initializeMdk(mdk, mdkFields);
      restoredSelected = await mdk.request('restore_group', {
        group_id_hex: creation.group_id_hex,
      });
      requireEqual(
        restoredSelected?.projection?.group_context_sha256,
        selected.group_context_sha256,
        'fresh MDK process did not restore the selected branch',
      );
    }

    const sortedRoster = [...selected.sorted_member_identities_hex].sort();
    return Object.freeze({
      deliveryMode,
      desiredWinner,
      expectedWinner: expectedWinnerCandidate.role,
      groupIdDigest: digestFields(
        'STYX-B33B2B-GROUP-ID-v1', creation.group_id_hex,
      ),
      initialDisposition: ingest.disposition,
      journalEvidence,
      parentGroupContextSha256Hex: local.evidence.parentGroupContextSha256Hex,
      rosterDigest: digestFields('STYX-B33B2B-ROSTER-v1', ...sortedRoster),
      selectedGroupContextSha256Hex: selected.group_context_sha256,
      selection,
      sourceEpoch: local.evidence.sourceEpoch,
      targetEpoch: local.evidence.targetEpoch,
    });
  } finally {
    forkAdapter?.close();
    await mdk?.close().catch(() => {});
    clearBytes(mdkSecret);
    clearBytes(loaded?.wasmBytes);
    clearBytes(active?.candidateState);
    clearBytes(active?.groupId);
    clearBytes(active?.ownIdentity);
    clearBytes(active?.ownSignatureKey);
    releasePrepared(local);
    clearBytes(localBranch);
    clearBytes(rivalOnStyx?.committedState);
    if (process.env.B33B2B_DEBUG_KEEP === '1') {
      process.stderr.write(`B33B2B_DEBUG_ROOT=${scenarioRoot}\n`);
      process.stderr.write(`B33B2B_DEBUG_MDK_ROOT=${mdkRoot}\n`);
    } else {
      rmSync(scenarioRoot, { recursive: true, force: true });
      rmSync(mdkRoot, { recursive: true, force: true });
    }
  }
}

export async function runStage0ForkProbe(candidatePath) {
  const pins = verifyPins(candidatePath);
  mkdirSync(B33A_MDK_BUILD_ROOT, { recursive: true, mode: 0o700 });
  const mdkBuildPath = resolve(
    B33A_MDK_BUILD_ROOT, `b33b2b-stage0-${process.pid}-${randomBytes(6).toString('hex')}`,
  );
  try {
    const mdkBuild = buildMdkPeer(mdkBuildPath);
    const scenarios = [];
    for (const desiredWinner of ['styx', 'mdk']) {
      for (const deliveryMode of ['after_restart', 'before_restart']) {
        scenarios.push(await runScenario(
          candidatePath, pins, mdkBuild, desiredWinner, deliveryMode,
        ));
      }
    }
    return Object.freeze({
      mdkRevision: pins.mdkRevision,
      scenarios: Object.freeze(scenarios),
    });
  } finally {
    rmSync(mdkBuildPath, { recursive: true, force: true });
  }
}

export async function runDurableForkProbe(candidatePath) {
  const pins = verifyPins(candidatePath);
  mkdirSync(B33A_MDK_BUILD_ROOT, { recursive: true, mode: 0o700 });
  const mdkBuildPath = resolve(
    B33A_MDK_BUILD_ROOT, `b33b2b-durable-${process.pid}-${randomBytes(6).toString('hex')}`,
  );
  try {
    const mdkBuild = buildMdkPeer(mdkBuildPath);
    const scenarios = [];
    for (const desiredWinner of ['styx', 'mdk']) {
      for (const deliveryMode of ['after_restart', 'before_restart']) {
        scenarios.push(await runScenario(
          candidatePath, pins, mdkBuild, desiredWinner, deliveryMode, true,
        ));
      }
    }
    return Object.freeze({
      mdkRevision: pins.mdkRevision,
      scenarios: Object.freeze(scenarios),
    });
  } finally {
    rmSync(mdkBuildPath, { recursive: true, force: true });
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const result = await runStage0ForkProbe();
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`${JSON.stringify({
      code: error?.code,
      details: error?.details,
      message: error?.message,
      name: error?.name || 'Error',
    }, null, 2)}\n`);
    process.exitCode = 1;
  }
}
