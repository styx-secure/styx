// STYX_SPIKE_PROTOTYPE — OpenMLS adapter for the Phase B2.5a branch kernel.

import {
  B23_LIMITS,
  assertBytes,
  bytesEqual,
  bytesToHex,
  copyBytes,
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
} from '../marmot-phase-b2-4/b2-4-policy.mjs';
import {
  B25_CANDIDATE_STATE,
  B25_ERROR,
  B25_REASON,
  comparisonTupleDigest,
  failB25,
} from './b2-5a-canonical.mjs';
import { priorityForAuthorization, selectSameParentCandidate } from './b2-5a-convergence.mjs';
import {
  buildCandidateEvidence,
  buildRetainedState,
  projectionDigestHex,
} from './b2-5a-record.mjs';

const ADAPTER_TOKEN = Symbol('B25_ENGINE_ADAPTER_TOKEN');

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
    state: B25_CANDIDATE_STATE.NOT_CANDIDATE,
    reason: B25_REASON.NOT_CANDIDATE_FOR_RETAINED_PARENT,
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
    state: authorized ? B25_CANDIDATE_STATE.AUTHORIZED : B25_CANDIDATE_STATE.REJECTED,
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

export class B25EngineAdapter {
  #wasm;
  #journal;
  #initializeJournal;
  #commitResolution;
  #beforeCandidate;

  constructor({ wasm, journal, initializeJournal, commitResolution,
    beforeCandidate = async () => {} }, token) {
    if (token !== ADAPTER_TOKEN || typeof initializeJournal !== 'function'
      || typeof commitResolution !== 'function') {
      failB25(B25_ERROR.INVALID, 'B2.5a adapters must be bound by their journal');
    }
    if (!journal || typeof journal.readFrozen !== 'function'
      || typeof journal.readResolved !== 'function'
      || typeof journal.retainCommit !== 'function' || typeof journal.freeze !== 'function') {
      failB25(B25_ERROR.INVALID, 'the isolated B2.5a journal API is required');
    }
    if (!wasm?.Provider || !wasm?.PhaseB2Group || !wasm?.PhaseB2Identity) {
      failB25(B25_ERROR.INVALID, 'the exact initialized Phase B2 WASM module is required');
    }
    if (typeof beforeCandidate !== 'function') {
      failB25(B25_ERROR.INVALID, 'beforeCandidate must be a test scheduling function');
    }
    this.#wasm = wasm;
    this.#journal = journal;
    this.#initializeJournal = initializeJournal;
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
        failB25(B25_ERROR.ENGINE_REJECTED, 'retained OpenMLS parent binding is invalid');
      }
      const parent = projectB24Parent({ provider, group, head: parentHead(retained) });
      validateB24Parent(parent);
      return { provider, identity, group, accountKey, signatureKey, groupId, parent };
    } catch (error) {
      disposeSession({ provider, identity, group });
      if (error?.code === B25_ERROR.ENGINE_REJECTED) throw error;
      failB25(B25_ERROR.ENGINE_REJECTED, 'retained OpenMLS parent restore failed', {}, error);
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
        failB25(B25_ERROR.ENGINE_REJECTED, 'initial state is not a stable identity binding');
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
      failB25(B25_ERROR.ENGINE_REJECTED, 'stable B2.5a initialization failed', {}, error);
    } finally {
      disposeSession({ provider, identity, group });
    }
  }

  retainCommit(groupIdHex, commitBytes) {
    return this.#journal.retainCommit(groupIdHex, commitBytes);
  }

  freeze(groupIdHex) { return this.#journal.freeze(groupIdHex); }

  async #evaluate(bundle, input) {
    await this.#beforeCandidate(input.commitDigestHex);
    const session = this.#restore(bundle.retained);
    let staged;
    let projectionHandle;
    let finalized = false;
    try {
      const before = copyBytes(session.provider.serialize_state());
      staged = session.group.stage_inbound_commit(session.provider, input.commitBytes);
      projectionHandle = staged.projection();
      const projection = projectB2Commit(projectionHandle);
      if (!bytesEqual(before, session.provider.serialize_state())) {
        failB25(B25_ERROR.ENGINE_REJECTED, 'candidate staging mutated its retained parent');
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
      if (error?.code) throw error;
      return notCandidateEvidence(bundle, input);
    } finally {
      safeFree(projectionHandle);
      safeFree(staged);
      disposeSession(session);
    }
  }

  #mergeWinner(bundle, winner) {
    const input = bundle.inputs.find((item) => item.commitDigestHex === winner.commitDigestHex);
    if (input === undefined) failB25(B25_ERROR.CORRUPT, 'selected candidate input is absent');
    const session = this.#restore(bundle.retained);
    let staged;
    let projectionHandle;
    try {
      const before = copyBytes(session.provider.serialize_state());
      staged = session.group.stage_inbound_commit(session.provider, input.commitBytes);
      projectionHandle = staged.projection();
      const projection = projectB2Commit(projectionHandle);
      if (!bytesEqual(before, session.provider.serialize_state())) {
        failB25(B25_ERROR.ENGINE_REJECTED, 'selected staging mutated its retained parent');
      }
      const policyInputs = { parent: session.parent, candidate: projection,
        commitBytes: input.commitBytes };
      const decision = evaluateB24Authorization(policyInputs);
      verifyB24DecisionBinding(decision, policyInputs);
      const repeated = evidenceFromDecision(bundle, input, projection, decision);
      if (repeated.evidenceDigestHex !== winner.evidenceDigestHex
        || repeated.state !== B25_CANDIDATE_STATE.AUTHORIZED) {
        failB25(B25_ERROR.ENGINE_REJECTED, 'selected candidate changed between staging passes');
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
        failB25(B25_ERROR.ENGINE_REJECTED, 'selected merge produced an unexpected successor');
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
      failB25(B25_ERROR.ENGINE_REJECTED, 'selected Commit merge failed', {}, error);
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
      if (error?.code !== B25_ERROR.STATE_CONFLICT) throw error;
    }
    const bundle = await this.#journal.readFrozen(batchDigestHex);
    const candidates = await Promise.all(bundle.inputs.map((input) => this.#evaluate(bundle, input)));
    const winner = selectSameParentCandidate(candidates);
    const successorRetained = winner === null ? null : this.#mergeWinner(bundle, winner);
    const result = await this.#commitResolution({
      expectedHead: bundle.head,
      frozenBatch: bundle.batch,
      expectedInputs: bundle.inputs,
      expectedCandidates: bundle.candidates,
      candidates,
      successorRetained,
    });
    return Object.freeze({ status: 'resolved', ...result });
  }
}

// This factory is intentionally useful only to B25Journal: callers can create
// an adapter around their own closures, but the real journal never exposes its
// private initialization or resolution capabilities.
export function createBoundB25EngineAdapter(options) {
  return new B25EngineAdapter(options, ADAPTER_TOKEN);
}
