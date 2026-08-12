// STYX_SPIKE_PROTOTYPE — OpenMLS adapter for the Phase B2.5b branch kernel.

import {
  B23_ERROR,
  B23_LIMITS,
  assertBytes,
  assertSafeInteger,
  bytesEqual,
  bytesToHex,
  copyBytes,
  digestHex,
  epochToDecimal,
  hexToBytes,
  validateProviderSnapshot,
} from '../marmot-phase-b2-3/b2-3-canonical.mjs';
import { projectB2Commit } from '../marmot-phase-b2-3/b2-3-engine-adapter.mjs';
import {
  evaluateB24Authorization,
  projectB24Parent,
  validateB24Parent,
  verifyB24DecisionBinding,
  requireB24Allow,
} from '../marmot-phase-b2-4/b2-4-policy.mjs';
import {
  B25B_CANDIDATE_STATE,
  B25B_ERROR,
  B25B_LIMITS,
  B25B_LOCAL_STATE,
  B25B_PUBLICATION_KIND,
  B25B_REASON,
  B25B_TERMINAL_DISPOSITION,
  comparisonTupleDigest,
  compareCandidates,
  digestB25B,
  failB25B,
} from './b2-5b-canonical.mjs';
import { priorityForAuthorization }
  from '../marmot-phase-b2-5a/b2-5a-convergence.mjs';
import {
  LOCAL_FIELDS,
  buildCandidateEvidence,
  buildLocal,
  buildPublication,
  buildRetainedState,
  parseLocal,
  projectionDigestHex,
} from './b2-5b-record.mjs';

const ADAPTER_TOKEN = Symbol('B25B_ENGINE_ADAPTER_TOKEN');
const CANDIDATE_DECODE_ERRORS = new Set([
  B23_ERROR.INVALID,
  B23_ERROR.ENGINE_REJECTED,
  B23_ERROR.RESOURCE_LIMIT,
]);

function isClosedCandidateFailure(error) {
  return error?.code === undefined || CANDIDATE_DECODE_ERRORS.has(error.code);
}

function safeFree(value) {
  if (value && typeof value.free === 'function') {
    try { value.free(); } catch { /* release cannot change durable state */ }
  }
}

function disposeSession(session) {
  if (!session) return;
  safeFree(session.group);
  safeFree(session.identity);
  safeFree(session.provider);
  session.group = null;
  session.identity = null;
  session.provider = null;
}

function parentHead(retained) {
  return Object.freeze({
    groupIdHex: retained.groupIdHex,
    epochDec: retained.epochDec,
    epochDigestHex: retained.groupContextDigestHex,
  });
}

function notCandidateEvidence(bundle, input) {
  return buildCandidateEvidence({
    groupIdHex: bundle.batch.groupIdHex,
    batchDigestHex: bundle.batch.protocolBatchDigestHex,
    commitDigestHex: input.commitDigestHex,
    state: B25B_CANDIDATE_STATE.NOT_CANDIDATE,
    reason: B25B_REASON.NOT_CANDIDATE_FOR_RETAINED_PARENT,
    parentEpochDec: bundle.batch.baseEpochDec,
    parentGroupContextDigestHex: bundle.batch.baseGroupContextDigestHex,
    projectionDigestHex: null,
    candidateEpochDec: null,
    candidateGroupContextDigestHex: null,
    verifiedLeafDigestHex: null,
    operationKind: null,
    priority: null,
    committerIdentityHex: null,
    authorizationContextDigestHex: null,
    authorizationResultDigestHex: null,
    comparisonTupleDigestHex: null,
  });
}

function evidenceFromDecision(bundle, input, projection, decision) {
  const authorized = decision.allowed === true;
  const priority = authorized ? priorityForAuthorization(decision) : null;
  const committerIdentityHex = authorized ? projection.committerIdentityHex : null;
  return buildCandidateEvidence({
    groupIdHex: bundle.batch.groupIdHex,
    batchDigestHex: bundle.batch.protocolBatchDigestHex,
    commitDigestHex: input.commitDigestHex,
    state: authorized ? B25B_CANDIDATE_STATE.AUTHORIZED : B25B_CANDIDATE_STATE.REJECTED,
    reason: decision.reason,
    parentEpochDec: bundle.batch.baseEpochDec,
    parentGroupContextDigestHex: bundle.batch.baseGroupContextDigestHex,
    projectionDigestHex: projectionDigestHex(projection),
    candidateEpochDec: projection.candidateEpochDec,
    candidateGroupContextDigestHex: projection.candidateGroupContextDigestHex,
    verifiedLeafDigestHex: projection.verifiedLeafDigestHex,
    operationKind: decision.operationKind,
    priority,
    committerIdentityHex,
    authorizationContextDigestHex: decision.contextDigestHex,
    authorizationResultDigestHex: decision.resultDigestHex,
    comparisonTupleDigestHex: authorized ? comparisonTupleDigest({
      priority, committerIdentityHex, commitDigestHex: input.commitDigestHex,
    }) : null,
  });
}

function mutateLocal(record, changes) {
  const fields = {};
  for (const field of LOCAL_FIELDS) {
    if (!['format', 'version', 'localPendingDigestHex'].includes(field)) fields[field] = record[field];
  }
  return buildLocal({ ...fields, ...changes });
}

function selectCandidate(records) {
  const authorized = records.filter((item) => item.state === B25B_CANDIDATE_STATE.AUTHORIZED)
    .sort(compareCandidates);
  for (let index = 1; index < authorized.length; index += 1) {
    if (compareCandidates(authorized[index - 1], authorized[index]) === 0) {
      failB25B(B25B_ERROR.CORRUPT, 'authorized candidates have duplicate total-order identity');
    }
  }
  return authorized[0] ?? null;
}

const TERMINAL_LOCAL_STATES = new Set([
  B25B_LOCAL_STATE.CANCELLED, B25B_LOCAL_STATE.DISCARDED,
  B25B_LOCAL_STATE.CONFIRMED, B25B_LOCAL_STATE.CLEARED_LOST,
  B25B_LOCAL_STATE.CLEARED_REJECTED,
]);

export class B25BEngineAdapter {
  #wasm;
  #journal;
  #initializeJournal;
  #commitPrepared;
  #appendPublication;
  #replaceLocal;
  #commitResolution;
  #beforeCandidate;

  constructor({ wasm, journal, initializeJournal, commitPrepared, appendPublication,
    replaceLocal, commitResolution,
    beforeCandidate = async () => {} }, token) {
    if (token !== ADAPTER_TOKEN || typeof initializeJournal !== 'function'
      || typeof commitPrepared !== 'function' || typeof appendPublication !== 'function'
      || typeof replaceLocal !== 'function'
      || typeof commitResolution !== 'function') {
      failB25B(B25B_ERROR.INVALID, 'B2.5b adapters must be bound by their journal');
    }
    if (!journal || typeof journal.readFrozen !== 'function'
      || typeof journal.readResolved !== 'function'
      || typeof journal.retainCommit !== 'function' || typeof journal.freeze !== 'function') {
      failB25B(B25B_ERROR.INVALID, 'the isolated B2.5b journal API is required');
    }
    if (!wasm?.Provider || !wasm?.PhaseB2Group || !wasm?.PhaseB2Identity) {
      failB25B(B25B_ERROR.INVALID, 'the exact initialized Phase B2 WASM module is required');
    }
    if (typeof beforeCandidate !== 'function') {
      failB25B(B25B_ERROR.INVALID, 'beforeCandidate must be a test scheduling function');
    }
    this.#wasm = wasm;
    this.#journal = journal;
    this.#initializeJournal = initializeJournal;
    this.#commitPrepared = commitPrepared;
    this.#appendPublication = appendPublication;
    this.#replaceLocal = replaceLocal;
    this.#commitResolution = commitResolution;
    this.#beforeCandidate = beforeCandidate;
    Object.freeze(this);
  }

  #restore(retained) {
    let provider;
    let identity;
    let group;
    try {
      validateProviderSnapshot(retained.snapshotBytes);
      provider = new this.#wasm.Provider();
      provider.restore_state(retained.snapshotBytes);
      const accountKey = hexToBytes('accountKeyHex', retained.accountKeyHex);
      const signatureKey = hexToBytes('signatureKeyHex', retained.signatureKeyHex);
      const groupId = hexToBytes('groupIdHex', retained.groupIdHex);
      identity = this.#wasm.PhaseB2Identity.load(provider, accountKey, signatureKey);
      group = this.#wasm.PhaseB2Group.load(provider, groupId);
      if (identity === undefined || group === undefined
        || !group.matches_own_identity(accountKey, signatureKey)
        || group.has_pending_commit(provider)
        || epochToDecimal(group.epoch()) !== retained.epochDec
        || bytesToHex(group.group_context_sha256(provider)) !== retained.groupContextDigestHex) {
        failB25B(B25B_ERROR.ENGINE_REJECTED, 'retained OpenMLS parent binding is invalid');
      }
      const parent = projectB24Parent({ provider, group, head: parentHead(retained) });
      validateB24Parent(parent);
      return { provider, identity, group, accountKey, signatureKey, groupId, parent };
    } catch (error) {
      disposeSession({ provider, identity, group });
      if (error?.code === B25B_ERROR.ENGINE_REJECTED) throw error;
      failB25B(B25B_ERROR.ENGINE_REJECTED, 'retained OpenMLS parent restore failed', {}, error);
    }
  }

  #restorePending(local, retained) {
    const session = this.#restoreRaw(retained, true);
    if (!session.group.has_pending_commit(session.provider)) {
      disposeSession(session);
      failB25B(B25B_ERROR.ENGINE_REJECTED, 'pending OpenMLS snapshot lacks pending state');
    }
    if (local.pendingSnapshotDigestHex !== retained.snapshotDigestHex
      || local.parentEpochDec !== retained.epochDec
      || local.parentGroupContextDigestHex !== retained.groupContextDigestHex) {
      disposeSession(session);
      failB25B(B25B_ERROR.CORRUPT, 'pending snapshot does not bind the local record');
    }
    return session;
  }

  #restoreRaw(retained, allowPending) {
    let provider;
    let identity;
    let group;
    try {
      validateProviderSnapshot(retained.snapshotBytes);
      provider = new this.#wasm.Provider();
      provider.restore_state(retained.snapshotBytes);
      const accountKey = hexToBytes('accountKeyHex', retained.accountKeyHex);
      const signatureKey = hexToBytes('signatureKeyHex', retained.signatureKeyHex);
      const groupId = hexToBytes('groupIdHex', retained.groupIdHex);
      identity = this.#wasm.PhaseB2Identity.load(provider, accountKey, signatureKey);
      group = this.#wasm.PhaseB2Group.load(provider, groupId);
      if (identity === undefined || group === undefined
        || !group.matches_own_identity(accountKey, signatureKey)
        || (!allowPending && group.has_pending_commit(provider))
        || epochToDecimal(group.epoch()) !== retained.epochDec
        || bytesToHex(group.group_context_sha256(provider)) !== retained.groupContextDigestHex) {
        failB25B(B25B_ERROR.ENGINE_REJECTED, 'retained OpenMLS binding is invalid');
      }
      const parent = projectB24Parent({ provider, group, head: parentHead(retained) });
      validateB24Parent(parent);
      return { provider, identity, group, accountKey, signatureKey, groupId, parent };
    } catch (error) {
      disposeSession({ provider, identity, group });
      if (error?.code) throw error;
      failB25B(B25B_ERROR.ENGINE_REJECTED, 'retained OpenMLS restore failed', {}, error);
    }
  }

  async initializeStable({ snapshotBytes, groupId, accountKey, signatureKey }) {
    assertBytes('groupId', groupId, { min: 1, max: 64 });
    assertBytes('accountKey', accountKey, { min: 32, max: 32 });
    assertBytes('signatureKey', signatureKey, { min: 32, max: 32 });
    assertBytes('snapshotBytes', snapshotBytes, { min: 8, max: B23_LIMITS.maxSnapshotBytes });
    validateProviderSnapshot(snapshotBytes);
    const exactSnapshot = copyBytes(snapshotBytes);
    let provider;
    let identity;
    let group;
    try {
      provider = new this.#wasm.Provider();
      provider.restore_state(exactSnapshot);
      identity = this.#wasm.PhaseB2Identity.load(provider, accountKey, signatureKey);
      group = this.#wasm.PhaseB2Group.load(provider, groupId);
      if (identity === undefined || group === undefined
        || !group.matches_own_identity(accountKey, signatureKey)
        || group.has_pending_commit(provider)) {
        failB25B(B25B_ERROR.ENGINE_REJECTED, 'initial state is not a stable identity binding');
      }
      const epochDec = epochToDecimal(group.epoch());
      const groupContextDigestHex = bytesToHex(group.group_context_sha256(provider));
      validateB24Parent(projectB24Parent({
        provider, group, head: { groupIdHex: bytesToHex(groupId), epochDec,
          epochDigestHex: groupContextDigestHex },
      }));
      return await this.#initializeJournal({
        groupIdHex: bytesToHex(groupId), accountKeyHex: bytesToHex(accountKey),
        signatureKeyHex: bytesToHex(signatureKey), epochDec,
        groupContextDigestHex, snapshotBytes: exactSnapshot,
      });
    } catch (error) {
      if (error?.code) throw error;
      failB25B(B25B_ERROR.ENGINE_REJECTED, 'stable B2.5b initialization failed', {}, error);
    } finally {
      disposeSession({ provider, identity, group });
    }
  }

  retainCommit(groupIdHex, commitBytes) {
    return this.#journal.retainCommit(groupIdHex, commitBytes);
  }

  freeze(groupIdHex) { return this.#journal.freeze(groupIdHex); }

  async prepareQueued(groupIdHex) {
    const bundle = await this.#journal.readHead(groupIdHex);
    const intent = await this.#journal.readLocal(groupIdHex);
    if (intent?.state !== B25B_LOCAL_STATE.QUEUED) {
      failB25B(B25B_ERROR.STATE_CONFLICT, 'preparation requires one queued local intent');
    }
    let session;
    let pending;
    let keyPackage;
    let projectionHandle;
    let commitStarted = false;
    try {
      session = this.#restore(bundle.retained);
      if (intent.operationKind === 'self-update') {
        if (intent.operationPayloadBytes.length !== 0) {
          failB25B(B25B_ERROR.INVALID, 'self-update payload must be empty');
        }
        pending = session.group.prepare_self_update(session.provider, session.identity);
      } else if (intent.operationKind === 'add') {
        assertBytes('keyPackageBytes', intent.operationPayloadBytes,
          { min: 1, max: B23_LIMITS.maxCommitBytes });
        keyPackage = this.#wasm.PhaseB2KeyPackage.from_framed_bytes(intent.operationPayloadBytes);
        pending = session.group.prepare_add(session.provider, session.identity, keyPackage);
      } else {
        if (intent.operationPayloadBytes.length !== 4) {
          failB25B(B25B_ERROR.INVALID, 'remove payload must be one u32 leaf index');
        }
        const view = new DataView(intent.operationPayloadBytes.buffer,
          intent.operationPayloadBytes.byteOffset, 4);
        const removedLeafIndex = view.getUint32(0, false);
        const own = session.parent.members.find((member) =>
          member.identityHex === bundle.head.accountKeyHex
          && member.signatureKeyHex === bundle.head.signatureKeyHex);
        if (own?.leafIndex === removedLeafIndex) {
          failB25B(B25B_ERROR.INVALID, 'self-removal is outside the bounded policy');
        }
        pending = session.group.prepare_remove(session.provider, session.identity, removedLeafIndex);
      }
      const commitBytes = copyBytes(pending.commit());
      const welcome = pending.welcome();
      const welcomeBytes = welcome === undefined ? new Uint8Array() : copyBytes(welcome);
      projectionHandle = pending.projection();
      const projection = projectB2Commit(projectionHandle);
      const inputs = { parent: session.parent, candidate: projection, commitBytes };
      const decision = verifyB24DecisionBinding(evaluateB24Authorization(inputs), inputs);
      requireB24Allow(decision);
      const scope = session.parent.members
        .map((member) => member.identityHex)
        .filter((identity) => identity !== bundle.head.accountKeyHex).sort();
      if (scope.length === 0 || new Set(scope).size !== scope.length) {
        failB25B(B25B_ERROR.INVALID, 'publication scope must contain unique prior members');
      }
      const pendingRetained = buildRetainedState({
        groupIdHex: bundle.head.groupIdHex, accountKeyHex: bundle.head.accountKeyHex,
        signatureKeyHex: bundle.head.signatureKeyHex, epochDec: bundle.head.epochDec,
        groupContextDigestHex: bundle.head.groupContextDigestHex,
        snapshotBytes: copyBytes(session.provider.serialize_state()),
      });
      const commitDigestHex = digestHex(commitBytes);
      const local = buildLocal({
        groupIdHex, state: B25B_LOCAL_STATE.PREPARED,
        operationKind: intent.operationKind,
        operationPayloadBytes: intent.operationPayloadBytes,
        parentHeadDigestHex: bundle.head.headDigestHex,
        parentEpochDec: bundle.head.epochDec,
        parentGroupContextDigestHex: bundle.head.groupContextDigestHex,
        cleanSnapshotDigestHex: bundle.head.snapshotDigestHex,
        pendingSnapshotDigestHex: pendingRetained.snapshotDigestHex,
        commitDigestHex, commitBytes, welcomeBytes,
        candidateEpochDec: projection.candidateEpochDec,
        candidateGroupContextDigestHex: projection.candidateGroupContextDigestHex,
        verifiedLeafDigestHex: projection.verifiedLeafDigestHex,
        projectionDigestHex: projectionDigestHex(projection),
        priority: priorityForAuthorization(decision),
        committerIdentityHex: projection.committerIdentityHex,
        authorizationContextDigestHex: decision.contextDigestHex,
        authorizationResultDigestHex: decision.resultDigestHex,
        recipientScope: scope,
        recipientScopeDigestHex: digestB25B('RECIPIENT-SCOPE', [groupIdHex,
          bundle.head.headDigestHex, scope]),
        publishAttempts: 0, ackCount: 0, failureCount: 0,
        activeBatchDigestHex: null, terminalDisposition: null,
      });
      commitStarted = true;
      return await this.#commitPrepared({ expectedHead: bundle.head,
        expectedIntent: intent, pending: local, pendingRetained });
    } catch (error) {
      if (!commitStarted && error?.code !== B25B_ERROR.CAS_CONFLICT) {
        const failed = mutateLocal(intent, {
          state: B25B_LOCAL_STATE.CANCELLED,
          terminalDisposition: B25B_TERMINAL_DISPOSITION.PREPARATION_FAILED,
        });
        await this.#replaceLocal(intent, failed);
      }
      if (commitStarted) throw error;
      if (error?.code) throw error;
      failB25B(B25B_ERROR.ENGINE_REJECTED, 'local preparation failed closed', {}, error);
    } finally {
      safeFree(projectionHandle);
      safeFree(pending);
      safeFree(keyPackage);
      disposeSession(session);
    }
  }

  async recordAttempt(groupIdHex) {
    const local = await this.#journal.readLocal(groupIdHex);
    if (![B25B_LOCAL_STATE.PREPARED, B25B_LOCAL_STATE.PUBLISHING].includes(local?.state)) {
      failB25B(B25B_ERROR.STATE_CONFLICT, 'publication attempt requires prepared state');
    }
    const existing = await this.#journal.readPublication(groupIdHex);
    if (existing.length >= B25B_LIMITS.maxPublicationRecords - 1) {
      failB25B(B25B_ERROR.RESOURCE_LIMIT,
        'publication evidence capacity cannot reserve an outcome');
    }
    const ordinal = local.publishAttempts + 1;
    const evidence = buildPublication({
      groupIdHex, sequence: existing.length + 1, kind: B25B_PUBLICATION_KIND.ATTEMPT,
      attemptOrdinal: ordinal, artifactDigestHex: local.commitDigestHex,
      artifactBytes: local.commitBytes, recipientScopeDigestHex: local.recipientScopeDigestHex,
      recipientIdentityHex: null, payloadBytes: new Uint8Array(),
    });
    return this.#appendPublication({ expectedLocal: local, evidence,
      nextLocal: mutateLocal(local, { state: B25B_LOCAL_STATE.PUBLISHING,
        publishAttempts: ordinal }) });
  }

  async recordAcknowledgement(groupIdHex, attemptOrdinal, recipientIdentityHex,
    payloadBytes = new Uint8Array()) {
    return this.#recordOutcome(groupIdHex, B25B_PUBLICATION_KIND.ACK,
      attemptOrdinal, recipientIdentityHex, payloadBytes);
  }

  async recordFailure(groupIdHex, attemptOrdinal, recipientIdentityHex,
    payloadBytes = new Uint8Array()) {
    return this.#recordOutcome(groupIdHex, B25B_PUBLICATION_KIND.FAILURE,
      attemptOrdinal, recipientIdentityHex, payloadBytes);
  }

  async #recordOutcome(groupIdHex, requestedKind, attemptOrdinal, recipientIdentityHex,
    payloadBytes) {
    assertSafeInteger('attemptOrdinal', attemptOrdinal,
      1, B25B_LIMITS.maxPublicationAttempts);
    assertBytes('payloadBytes', payloadBytes,
      { min: 0, max: B25B_LIMITS.maxPublicationPayloadBytes });
    const local = await this.#journal.readLocal(groupIdHex);
    if (local === null || local.commitDigestHex === null) {
      failB25B(B25B_ERROR.STATE_CONFLICT, 'publication outcome lacks pending state');
    }
    const evidenceSet = await this.#journal.readPublication(groupIdHex);
    const attempt = evidenceSet.find((item) => item.kind === B25B_PUBLICATION_KIND.ATTEMPT
      && item.attemptOrdinal === attemptOrdinal
      && item.artifactDigestHex === local.commitDigestHex);
    if (attempt === undefined) {
      failB25B(B25B_ERROR.INVALID, 'publication outcome lacks its exact durable attempt');
    }
    if (!local.recipientScope.includes(recipientIdentityHex)) {
      failB25B(B25B_ERROR.INVALID, 'publication recipient is outside the frozen scope');
    }
    const terminal = TERMINAL_LOCAL_STATES.has(local.state);
    const kind = requestedKind === B25B_PUBLICATION_KIND.ACK && terminal
      ? B25B_PUBLICATION_KIND.LATE_ACK : requestedKind;
    const duplicate = evidenceSet.find((item) => item.kind === kind
      && item.attemptOrdinal === attemptOrdinal
      && item.recipientIdentityHex === recipientIdentityHex
      && item.artifactDigestHex === local.commitDigestHex);
    if (duplicate !== undefined) return Object.freeze({ status: 'duplicate', evidence: duplicate,
      local });
    const evidence = buildPublication({
      groupIdHex, sequence: evidenceSet.length + 1, kind, attemptOrdinal,
      artifactDigestHex: local.commitDigestHex, artifactBytes: local.commitBytes,
      recipientScopeDigestHex: local.recipientScopeDigestHex, recipientIdentityHex,
      payloadBytes,
    });
    let next = local;
    if (!terminal && requestedKind === B25B_PUBLICATION_KIND.ACK) {
      next = mutateLocal(local, { state: B25B_LOCAL_STATE.ACKNOWLEDGED,
        ackCount: local.ackCount + 1 });
    } else if (!terminal && requestedKind === B25B_PUBLICATION_KIND.FAILURE) {
      next = mutateLocal(local, { failureCount: local.failureCount + 1 });
    }
    return this.#appendPublication({ expectedLocal: local, evidence, nextLocal: next });
  }

  async cancelBeforeAttempt(groupIdHex) {
    const local = await this.#journal.readLocal(groupIdHex);
    if (local?.state !== B25B_LOCAL_STATE.PREPARED || local.publishAttempts !== 0) {
      failB25B(B25B_ERROR.STATE_CONFLICT, 'cancel requires pre-attempt prepared state');
    }
    return this.#clearPending(local, B25B_LOCAL_STATE.CANCELLED,
      B25B_TERMINAL_DISPOSITION.CANCELLED);
  }

  async discardAfterFailure(groupIdHex) {
    const local = await this.#journal.readLocal(groupIdHex);
    if (local?.state !== B25B_LOCAL_STATE.PUBLISHING || local.failureCount < 1
      || local.ackCount !== 0) {
      failB25B(B25B_ERROR.STATE_CONFLICT, 'discard requires failure and no acknowledgement');
    }
    return this.#clearPending(local, B25B_LOCAL_STATE.DISCARDED,
      B25B_TERMINAL_DISPOSITION.DISCARDED_AFTER_FAILURE);
  }

  async #clearPending(local, state, terminalDisposition) {
    const retained = await this.#readRetained(local.pendingSnapshotDigestHex, local.groupIdHex);
    const session = this.#restorePending(local, retained);
    try {
      session.group.clear_pending_commit(session.provider, BigInt(local.parentEpochDec),
        session.accountKey, session.signatureKey);
      if (session.group.has_pending_commit(session.provider)
        || epochToDecimal(session.group.epoch()) !== local.parentEpochDec
        || bytesToHex(session.group.group_context_sha256(session.provider))
          !== local.parentGroupContextDigestHex) {
        failB25B(B25B_ERROR.ENGINE_REJECTED, 'pending clear did not restore its exact parent');
      }
      return this.#replaceLocal(local, mutateLocal(local, { state, terminalDisposition,
        activeBatchDigestHex: null }));
    } finally {
      disposeSession(session);
    }
  }

  async #readRetained(snapshotDigestHex, groupIdHex) {
    const headBundle = await this.#journal.readHead(groupIdHex);
    if (headBundle.retained?.snapshotDigestHex === snapshotDigestHex) return headBundle.retained;
    if (typeof this.#journal.readRetained !== 'function') {
      failB25B(B25B_ERROR.CORRUPT, 'pending retained-state reader is unavailable');
    }
    return this.#journal.readRetained(snapshotDigestHex);
  }

  async #evaluate(bundle, input) {
    await this.#beforeCandidate(input.commitDigestHex);
    const session = this.#restore(bundle.retained);
    let staged;
    let projectionHandle;
    let finalized = false;
    try {
      const before = copyBytes(session.provider.serialize_state());
      let projection;
      try {
        staged = session.group.stage_inbound_commit(session.provider, input.commitBytes);
        projectionHandle = staged.projection();
        projection = projectB2Commit(projectionHandle);
      } catch (error) {
        if (!isClosedCandidateFailure(error)) throw error;
        if (staged !== undefined) {
          try { session.group.discard_staged_commit(session.provider, staged); } catch { /* disposable */ }
          finalized = true;
        }
        return notCandidateEvidence(bundle, input);
      }
      if (!bytesEqual(before, session.provider.serialize_state())) {
        failB25B(B25B_ERROR.ENGINE_REJECTED, 'candidate staging mutated its retained parent');
      }
      const policyInputs = { parent: session.parent, candidate: projection,
        commitBytes: input.commitBytes };
      const decision = evaluateB24Authorization(policyInputs);
      verifyB24DecisionBinding(decision, policyInputs);
      session.group.discard_staged_commit(session.provider, staged);
      finalized = true;
      return evidenceFromDecision(bundle, input, projection, decision);
    } catch (error) {
      if (staged !== undefined && !finalized) {
        try { session.group.discard_staged_commit(session.provider, staged); } catch { /* disposable */ }
      }
      throw error;
    } finally {
      safeFree(projectionHandle);
      safeFree(staged);
      disposeSession(session);
    }
  }

  async #evaluateLocal(bundle) {
    const local = parseLocal(bundle.local);
    await this.#beforeCandidate(local.commitDigestHex);
    const retained = await this.#journal.readRetained(local.pendingSnapshotDigestHex);
    const session = this.#restorePending(local, retained);
    let projectionHandle;
    try {
      projectionHandle = session.group.pending_projection(session.provider);
      if (projectionHandle === undefined) {
        failB25B(B25B_ERROR.ENGINE_REJECTED, 'pending projection is absent');
      }
      const projection = projectB2Commit(projectionHandle);
      if (projectionDigestHex(projection) !== local.projectionDigestHex
        || projection.candidateEpochDec !== local.candidateEpochDec
        || projection.candidateGroupContextDigestHex !== local.candidateGroupContextDigestHex
        || projection.verifiedLeafDigestHex !== local.verifiedLeafDigestHex
        || digestHex(local.commitBytes) !== local.commitDigestHex) {
        failB25B(B25B_ERROR.CORRUPT, 'local projection differs from durable pending evidence');
      }
      const inputs = { parent: session.parent, candidate: projection,
        commitBytes: local.commitBytes };
      const decision = verifyB24DecisionBinding(evaluateB24Authorization(inputs), inputs);
      if (decision.contextDigestHex !== local.authorizationContextDigestHex
        || decision.resultDigestHex !== local.authorizationResultDigestHex) {
        failB25B(B25B_ERROR.CORRUPT, 'local authorization differs from durable evidence');
      }
      return evidenceFromDecision(bundle, { commitDigestHex: local.commitDigestHex },
        projection, decision);
    } finally {
      safeFree(projectionHandle);
      disposeSession(session);
    }
  }

  async #confirmLocal(bundle, winner) {
    const local = parseLocal(bundle.local);
    const retained = await this.#journal.readRetained(local.pendingSnapshotDigestHex);
    const session = this.#restorePending(local, retained);
    let projectionHandle;
    try {
      projectionHandle = session.group.pending_projection(session.provider);
      const projection = projectB2Commit(projectionHandle);
      const inputs = { parent: session.parent, candidate: projection,
        commitBytes: local.commitBytes };
      const decision = verifyB24DecisionBinding(evaluateB24Authorization(inputs), inputs);
      requireB24Allow(decision);
      const repeated = evidenceFromDecision(bundle, { commitDigestHex: local.commitDigestHex },
        projection, decision);
      if (repeated.evidenceDigestHex !== winner.evidenceDigestHex) {
        failB25B(B25B_ERROR.ENGINE_REJECTED, 'local winner changed before confirmation');
      }
      session.group.confirm_pending_commit(session.provider, BigInt(local.parentEpochDec),
        session.accountKey, session.signatureKey,
        hexToBytes('verifiedLeafDigestHex', local.verifiedLeafDigestHex));
      const epochDec = epochToDecimal(session.group.epoch());
      const groupContextDigestHex = bytesToHex(session.group.group_context_sha256(session.provider));
      if (session.group.has_pending_commit(session.provider)
        || epochDec !== winner.candidateEpochDec
        || groupContextDigestHex !== winner.candidateGroupContextDigestHex) {
        failB25B(B25B_ERROR.ENGINE_REJECTED, 'local confirmation produced an unexpected successor');
      }
      return buildRetainedState({
        groupIdHex: bundle.head.groupIdHex, accountKeyHex: bundle.head.accountKeyHex,
        signatureKeyHex: bundle.head.signatureKeyHex, epochDec, groupContextDigestHex,
        snapshotBytes: copyBytes(session.provider.serialize_state()),
      });
    } finally {
      safeFree(projectionHandle);
      disposeSession(session);
    }
  }

  #mergeWinner(bundle, winner) {
    const input = bundle.inputs.find((item) => item.commitDigestHex === winner.commitDigestHex);
    if (input === undefined) failB25B(B25B_ERROR.CORRUPT, 'selected candidate input is absent');
    const session = this.#restore(bundle.retained);
    let staged;
    let projectionHandle;
    try {
      const before = copyBytes(session.provider.serialize_state());
      staged = session.group.stage_inbound_commit(session.provider, input.commitBytes);
      projectionHandle = staged.projection();
      const projection = projectB2Commit(projectionHandle);
      if (!bytesEqual(before, session.provider.serialize_state())) {
        failB25B(B25B_ERROR.ENGINE_REJECTED, 'selected staging mutated its retained parent');
      }
      const policyInputs = { parent: session.parent, candidate: projection,
        commitBytes: input.commitBytes };
      const decision = evaluateB24Authorization(policyInputs);
      verifyB24DecisionBinding(decision, policyInputs);
      const repeated = evidenceFromDecision(bundle, input, projection, decision);
      if (repeated.evidenceDigestHex !== winner.evidenceDigestHex
        || repeated.state !== B25B_CANDIDATE_STATE.AUTHORIZED) {
        failB25B(B25B_ERROR.ENGINE_REJECTED, 'selected candidate changed between staging passes');
      }
      session.group.merge_staged_commit(
        session.provider, staged,
        hexToBytes('verifiedLeafDigestHex', projection.verifiedLeafDigestHex),
      );
      staged = undefined;
      const epochDec = epochToDecimal(session.group.epoch());
      const groupContextDigestHex = bytesToHex(session.group.group_context_sha256(session.provider));
      if (epochDec !== winner.candidateEpochDec
        || groupContextDigestHex !== winner.candidateGroupContextDigestHex) {
        failB25B(B25B_ERROR.ENGINE_REJECTED, 'selected merge produced an unexpected successor');
      }
      return buildRetainedState({
        groupIdHex: bundle.head.groupIdHex,
        accountKeyHex: bundle.head.accountKeyHex,
        signatureKeyHex: bundle.head.signatureKeyHex,
        epochDec, groupContextDigestHex,
        snapshotBytes: copyBytes(session.provider.serialize_state()),
      });
    } catch (error) {
      if (error?.code) throw error;
      failB25B(B25B_ERROR.ENGINE_REJECTED, 'selected Commit merge failed', {}, error);
    } finally {
      safeFree(projectionHandle);
      safeFree(staged);
      disposeSession(session);
    }
  }

  async resolve(batchDigestHex) {
    try {
      const resolved = await this.#journal.readResolved(batchDigestHex);
      return Object.freeze({ status: 'resolved', ...resolved });
    } catch (error) {
      if (error?.code !== B25B_ERROR.STATE_CONFLICT) throw error;
    }
    const bundle = await this.#journal.readFrozen(batchDigestHex);
    const candidates = await Promise.all(bundle.inputs.map((input) => this.#evaluate(bundle, input)));
    if (bundle.local?.activeBatchDigestHex === bundle.batch.protocolBatchDigestHex) {
      candidates.push(await this.#evaluateLocal(bundle));
    }
    const winner = selectCandidate(candidates);
    const localWins = winner !== null && bundle.local?.commitDigestHex === winner.commitDigestHex;
    const successorRetained = winner === null ? null
      : localWins ? await this.#confirmLocal(bundle, winner) : this.#mergeWinner(bundle, winner);
    const result = await this.#commitResolution({
      expectedHead: bundle.head,
      frozenBatch: bundle.batch,
      expectedInputs: bundle.inputs,
      expectedCandidates: bundle.candidates,
      expectedLocal: bundle.local,
      candidates,
      successorRetained,
    });
    return Object.freeze({ status: 'resolved', ...result });
  }
}

// This factory is intentionally useful only to B25BJournal: callers can create
// an adapter around their own closures, but the real journal never exposes its
// private initialization or resolution capabilities.
export function createBoundB25BEngineAdapter(options) {
  return new B25BEngineAdapter(options, ADAPTER_TOKEN);
}
