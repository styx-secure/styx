// STYX_SPIKE_PROTOTYPE — mandatory-policy lifecycle adapter for Phase B2.4.

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
  fail,
  hexToBytes,
  validateProviderSnapshot,
} from '../marmot-phase-b2-3/b2-3-canonical.mjs';
import { HEAD_PREPARED, HEAD_STABLE, canonicalProjectionBytes } from '../marmot-phase-b2-3/b2-3-record.mjs';
import {
  projectB2Commit,
} from '../marmot-phase-b2-3/b2-3-engine-adapter.mjs';
import { B24_ERROR, B24_REASON, failB24 } from './b2-4-canonical.mjs';
import { B24Journal } from './b2-4-journal.mjs';
import {
  evaluateB24Authorization,
  projectB24Parent,
  requireB24Allow,
  validateB24Parent,
  verifyB24DecisionBinding,
} from './b2-4-policy.mjs';

function safeFree(value) {
  if (value && typeof value.free === 'function') {
    try { value.free(); } catch { /* release never changes durable state */ }
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

function projectionDigest(projection) {
  return digestHex(canonicalProjectionBytes(projection));
}

function rejectRawSelfRemove(projection) {
  if (projection.proposal_count() === 1
    && projection.proposal_kind(0) === 'remove'
    && projection.proposal_source(0) === 'inline'
    && projection.proposal_sender_source(0) === 'member'
    && projection.proposal_removed_parent_leaf_index(0) === projection.committer_leaf_index()) {
    failB24(B24_ERROR.POLICY_REJECTED, 'self-removal is outside the bounded policy', {
      reason: B24_REASON.SELF_REMOVE,
    });
  }
}

function pendingTransitionFields(bundle) {
  return {
    commitBytes: copyBytes(bundle.transition.commitBytes),
    welcomeBytes: copyBytes(bundle.transition.welcomeBytes),
    projection: bundle.transition.projection,
    projectionDigestHex: bundle.transition.projectionDigestHex,
    candidateEpochDec: bundle.transition.candidateEpochDec,
    candidateEpochDigestHex: bundle.transition.candidateEpochDigestHex,
    verifiedLeafDigestHex: bundle.transition.verifiedLeafDigestHex,
    artifactId: bundle.transition.artifactId,
    artifactBytes: copyBytes(bundle.transition.artifactBytes),
    artifactDigestHex: bundle.transition.artifactDigestHex,
    publishAttempts: bundle.transition.publishAttempts,
    evidenceCount: bundle.transition.evidenceCount,
  };
}

export class B24EngineAdapter {
  #wasm;
  #journal;

  constructor({ wasm, journal }) {
    if (!(journal instanceof B24Journal)) {
      failB24(B24_ERROR.INVALID, 'the isolated B2.4 journal wrapper is required');
    }
    if (!wasm?.Provider || !wasm?.PhaseB2Group || !wasm?.PhaseB2Identity
      || !wasm?.PhaseB2KeyPackage) {
      failB24(B24_ERROR.INVALID, 'the exact initialized B2.2 WASM module is required');
    }
    this.#wasm = wasm;
    this.#journal = journal;
    Object.freeze(this);
  }

  #restoreBundle(bundle) {
    const { head, transition, snapshotBytes } = bundle;
    let provider;
    let identity;
    let group;
    try {
      validateProviderSnapshot(snapshotBytes);
      provider = new this.#wasm.Provider();
      provider.restore_state(snapshotBytes);
      const accountKey = hexToBytes('accountKeyHex', head.accountKeyHex);
      const signatureKey = hexToBytes('signatureKeyHex', head.signatureKeyHex);
      const groupId = hexToBytes('groupIdHex', head.groupIdHex);
      identity = this.#wasm.PhaseB2Identity.load(provider, accountKey, signatureKey);
      group = this.#wasm.PhaseB2Group.load(provider, groupId);
      if (identity === undefined || group === undefined
        || !group.matches_own_identity(accountKey, signatureKey)) {
        failB24(B24_ERROR.ENGINE_REJECTED, 'restored group identity binding is invalid');
      }
      if (epochToDecimal(group.epoch()) !== head.epochDec
        || bytesToHex(group.group_context_sha256(provider)) !== head.epochDigestHex) {
        failB24(B24_ERROR.ENGINE_REJECTED, 'restored GroupContext differs from the durable head');
      }
      const hasPending = group.has_pending_commit(provider);
      if (hasPending !== (head.state === HEAD_PREPARED)) {
        failB24(B24_ERROR.ENGINE_REJECTED, 'restored pending state differs from the durable head');
      }
      if (head.state === HEAD_PREPARED) {
        const pendingProjection = group.pending_projection(provider);
        if (pendingProjection === undefined) {
          failB24(B24_ERROR.ENGINE_REJECTED, 'restored pending projection is absent');
        }
        try {
          rejectRawSelfRemove(pendingProjection);
          const projected = projectB2Commit(pendingProjection);
          if (projectionDigest(projected) !== transition.projectionDigestHex
            || projected.candidateEpochDec !== head.candidateEpochDec
            || projected.candidateGroupContextDigestHex !== head.candidateEpochDigestHex
            || projected.verifiedLeafDigestHex !== head.verifiedLeafDigestHex) {
            failB24(B24_ERROR.ENGINE_REJECTED, 'restored pending projection differs from durable evidence');
          }
        } finally {
          safeFree(pendingProjection);
        }
      }
      return { provider, identity, group, accountKey, signatureKey, groupId };
    } catch (error) {
      disposeSession({ provider, identity, group });
      if (error?.code) throw error;
      failB24(B24_ERROR.ENGINE_REJECTED, 'B2.4 restore failed closed', {}, error);
    }
  }

  async initializeStable({ snapshotBytes, groupId, accountKey, signatureKey }) {
    assertBytes('groupId', groupId, { min: 1, max: 64 });
    assertBytes('accountKey', accountKey, { min: 32, max: 32 });
    assertBytes('signatureKey', signatureKey, { min: 32, max: 32 });
    assertBytes('snapshotBytes', snapshotBytes, { min: 1, max: B23_LIMITS.maxSnapshotBytes });
    validateProviderSnapshot(snapshotBytes);
    let provider;
    let identity;
    let group;
    try {
      provider = new this.#wasm.Provider();
      provider.restore_state(snapshotBytes);
      identity = this.#wasm.PhaseB2Identity.load(provider, accountKey, signatureKey);
      group = this.#wasm.PhaseB2Group.load(provider, groupId);
      if (identity === undefined || group === undefined
        || !group.matches_own_identity(accountKey, signatureKey)
        || group.has_pending_commit(provider)) {
        failB24(B24_ERROR.ENGINE_REJECTED, 'initial snapshot is not an exact stable binding');
      }
      const head = {
        groupIdHex: bytesToHex(groupId),
        epochDec: epochToDecimal(group.epoch()),
        epochDigestHex: bytesToHex(group.group_context_sha256(provider)),
      };
      validateB24Parent(projectB24Parent({ provider, group, head }));
      return await this.#journal.initialize({
        bindings: {
          groupIdHex: head.groupIdHex,
          accountKeyHex: bytesToHex(accountKey),
          signatureKeyHex: bytesToHex(signatureKey),
        },
        snapshotBytes,
        epochDec: head.epochDec,
        epochDigestHex: head.epochDigestHex,
      });
    } catch (error) {
      if (error?.code) throw error;
      failB24(B24_ERROR.ENGINE_REJECTED, 'B2.4 stable initialization failed', {}, error);
    } finally {
      disposeSession({ provider, identity, group });
    }
  }

  async prepare(groupIdHex, operation) {
    const bundle = await this.#journal.read(groupIdHex);
    if (bundle.head.state !== HEAD_STABLE) {
      fail(B23_ERROR.STATE_CONFLICT, 'prepare requires a stable head');
    }
    const session = this.#restoreBundle(bundle);
    let parent;
    let keyPackage;
    let pending;
    let projectionHandle;
    try {
      parent = projectB24Parent({
        provider: session.provider, group: session.group, head: bundle.head,
      });
      validateB24Parent(parent);
      if (operation?.kind === 'self-update') {
        pending = session.group.prepare_self_update(session.provider, session.identity);
      } else if (operation?.kind === 'add') {
        assertBytes('keyPackageBytes', operation.keyPackageBytes, {
          min: 1, max: B23_LIMITS.maxCommitBytes,
        });
        keyPackage = this.#wasm.PhaseB2KeyPackage.from_framed_bytes(operation.keyPackageBytes);
        pending = session.group.prepare_add(session.provider, session.identity, keyPackage);
      } else if (operation?.kind === 'remove') {
        assertSafeInteger('removedLeafIndex', operation.removedLeafIndex, 0, 0xffffffff);
        const own = parent.members.find((member) =>
          member.identityHex === bundle.head.accountKeyHex
            && member.signatureKeyHex === bundle.head.signatureKeyHex);
        if (own?.leafIndex === operation.removedLeafIndex) {
          failB24(B24_ERROR.POLICY_REJECTED, 'self-removal is outside the bounded policy', {
            reason: B24_REASON.SELF_REMOVE,
          });
        }
        pending = session.group.prepare_remove(
          session.provider, session.identity, operation.removedLeafIndex,
        );
      } else {
        failB24(B24_ERROR.INVALID, 'prepare operation kind is invalid');
      }
      const commitBytes = copyBytes(pending.commit());
      const welcome = pending.welcome();
      const welcomeBytes = welcome === undefined ? null : copyBytes(welcome);
      projectionHandle = pending.projection();
      const projection = projectB2Commit(projectionHandle);
      const inputs = { parent, candidate: projection, commitBytes };
      const policyDecision = evaluateB24Authorization(inputs);
      requireB24Allow(verifyB24DecisionBinding(policyDecision, inputs));
      const snapshotBytes = copyBytes(session.provider.serialize_state());
      const projectionDigestHex = projectionDigest(projection);
      const result = await this.#journal.cas({
        expectedHead: bundle.head,
        snapshotBytes,
        transitionFields: {
          kind: 'prepare', state: HEAD_PREPARED,
          epochDec: bundle.head.epochDec, epochDigestHex: bundle.head.epochDigestHex,
          commitBytes, welcomeBytes, projection, projectionDigestHex,
          candidateEpochDec: projection.candidateEpochDec,
          candidateEpochDigestHex: projection.candidateGroupContextDigestHex,
          verifiedLeafDigestHex: projection.verifiedLeafDigestHex,
          artifactId: null, artifactBytes: null, artifactDigestHex: null,
          publishAttempts: 0, evidenceCount: 0, appliedCommitDigestHex: null,
        },
        headFields: {
          state: HEAD_PREPARED,
          epochDec: bundle.head.epochDec, epochDigestHex: bundle.head.epochDigestHex,
          pendingCommitDigestHex: digestHex(commitBytes),
          pendingWelcomeDigestHex: welcomeBytes === null ? null : digestHex(welcomeBytes),
          candidateEpochDec: projection.candidateEpochDec,
          candidateEpochDigestHex: projection.candidateGroupContextDigestHex,
          verifiedLeafDigestHex: projection.verifiedLeafDigestHex,
          artifactId: null, artifactDigestHex: null,
          publishAttempts: 0, evidenceCount: 0,
          lastAppliedCommitDigestHex: bundle.head.lastAppliedCommitDigestHex,
        },
      });
      return Object.freeze({
        head: result.head,
        commitBytes: copyBytes(commitBytes),
        welcomeBytes: copyBytes(welcomeBytes),
        projection,
        authorization: policyDecision,
      });
    } catch (error) {
      if (error?.code) throw error;
      failB24(B24_ERROR.ENGINE_REJECTED, 'B2.4 outbound preparation failed', {}, error);
    } finally {
      safeFree(projectionHandle);
      safeFree(pending);
      safeFree(keyPackage);
      disposeSession(session);
    }
  }

  async cancelBeforeAttempt(groupIdHex) {
    const bundle = await this.#journal.read(groupIdHex);
    if (bundle.head.state !== HEAD_PREPARED || bundle.head.publishAttempts !== 0) {
      fail(B23_ERROR.STATE_CONFLICT, 'discard is allowed only before the first publication attempt');
    }
    const session = this.#restoreBundle(bundle);
    try {
      session.group.clear_pending_commit(
        session.provider, BigInt(bundle.head.epochDec), session.accountKey, session.signatureKey,
      );
      if (session.group.has_pending_commit(session.provider)
        || epochToDecimal(session.group.epoch()) !== bundle.head.epochDec
        || bytesToHex(session.group.group_context_sha256(session.provider))
          !== bundle.head.epochDigestHex) {
        failB24(B24_ERROR.ENGINE_REJECTED, 'pending clear did not restore the exact stable epoch');
      }
      return await this.#journal.cas({
        expectedHead: bundle.head,
        snapshotBytes: copyBytes(session.provider.serialize_state()),
        transitionFields: {
          kind: 'discard', state: HEAD_STABLE,
          epochDec: bundle.head.epochDec, epochDigestHex: bundle.head.epochDigestHex,
          ...pendingTransitionFields(bundle),
          artifactId: null, artifactBytes: null, artifactDigestHex: null,
          publishAttempts: 0, evidenceCount: 0, appliedCommitDigestHex: null,
        },
        headFields: {
          state: HEAD_STABLE,
          epochDec: bundle.head.epochDec, epochDigestHex: bundle.head.epochDigestHex,
          pendingCommitDigestHex: null, pendingWelcomeDigestHex: null,
          candidateEpochDec: null, candidateEpochDigestHex: null,
          verifiedLeafDigestHex: null, artifactId: null, artifactDigestHex: null,
          publishAttempts: 0, evidenceCount: 0,
          lastAppliedCommitDigestHex: bundle.head.lastAppliedCommitDigestHex,
        },
      });
    } finally {
      disposeSession(session);
    }
  }

  recordPublishIntent(groupIdHex, artifact) {
    return this.#journal.recordPublishIntent(groupIdHex, artifact);
  }

  appendPublicationEvidence(groupIdHex, payloadBytes) {
    return this.#journal.appendPublicationEvidence(groupIdHex, payloadBytes);
  }

  async confirmAfterAttempt(groupIdHex) {
    const bundle = await this.#journal.read(groupIdHex);
    if (bundle.head.state !== HEAD_PREPARED || bundle.head.publishAttempts < 1) {
      fail(B23_ERROR.STATE_CONFLICT, 'confirmation requires a durable publication attempt');
    }
    const session = this.#restoreBundle(bundle);
    let projectionHandle;
    try {
      const parent = projectB24Parent({
        provider: session.provider, group: session.group, head: bundle.head,
      });
      validateB24Parent(parent);
      projectionHandle = session.group.pending_projection(session.provider);
      if (projectionHandle === undefined) {
        failB24(B24_ERROR.RECOVERY_MISMATCH, 'recovered pending projection is absent');
      }
      const projection = projectB2Commit(projectionHandle);
      if (projectionDigest(projection) !== bundle.transition.projectionDigestHex) {
        failB24(B24_ERROR.RECOVERY_MISMATCH, 'recovered projection differs from durable evidence');
      }
      const inputs = {
        parent, candidate: projection, commitBytes: bundle.transition.commitBytes,
      };
      const policyDecision = evaluateB24Authorization(inputs);
      requireB24Allow(verifyB24DecisionBinding(policyDecision, inputs));
      session.group.confirm_pending_commit(
        session.provider, BigInt(bundle.head.epochDec), session.accountKey,
        session.signatureKey,
        hexToBytes('verifiedLeafDigestHex', projection.verifiedLeafDigestHex),
      );
      if (epochToDecimal(session.group.epoch()) !== bundle.head.candidateEpochDec
        || bytesToHex(session.group.group_context_sha256(session.provider))
          !== bundle.head.candidateEpochDigestHex
        || session.group.has_pending_commit(session.provider)) {
        failB24(B24_ERROR.ENGINE_REJECTED, 'pending confirmation produced an unexpected successor');
      }
      verifyB24DecisionBinding(policyDecision, inputs);
      const appliedCommitDigestHex = digestHex(bundle.transition.commitBytes);
      return await this.#journal.cas({
        expectedHead: bundle.head,
        snapshotBytes: copyBytes(session.provider.serialize_state()),
        transitionFields: {
          kind: 'confirm', state: HEAD_STABLE,
          epochDec: bundle.head.candidateEpochDec,
          epochDigestHex: bundle.head.candidateEpochDigestHex,
          ...pendingTransitionFields(bundle),
          appliedCommitDigestHex,
        },
        headFields: {
          state: HEAD_STABLE,
          epochDec: bundle.head.candidateEpochDec,
          epochDigestHex: bundle.head.candidateEpochDigestHex,
          pendingCommitDigestHex: null, pendingWelcomeDigestHex: null,
          candidateEpochDec: null, candidateEpochDigestHex: null,
          verifiedLeafDigestHex: null, artifactId: null, artifactDigestHex: null,
          publishAttempts: 0, evidenceCount: 0,
          lastAppliedCommitDigestHex: appliedCommitDigestHex,
        },
      });
    } catch (error) {
      if (error?.code) throw error;
      failB24(B24_ERROR.RECOVERY_MISMATCH, 'recovered authorization failed closed', {}, error);
    } finally {
      safeFree(projectionHandle);
      disposeSession(session);
    }
  }

  async acceptInbound(groupIdHex, commitBytes) {
    assertBytes('inbound Commit', commitBytes, { min: 1, max: B23_LIMITS.maxCommitBytes });
    const exactCommit = copyBytes(commitBytes);
    const commitDigestHex = digestHex(exactCommit);
    const bundle = await this.#journal.read(groupIdHex);
    if (bundle.head.lastAppliedCommitDigestHex === commitDigestHex) {
      return Object.freeze({ status: 'duplicate', head: bundle.head });
    }
    if (bundle.head.state !== HEAD_STABLE) {
      fail(B23_ERROR.STATE_CONFLICT, 'inbound Commit requires a stable head');
    }
    const session = this.#restoreBundle(bundle);
    let parent;
    let staged;
    let stagedFinalized = false;
    let projectionHandle;
    try {
      parent = projectB24Parent({
        provider: session.provider, group: session.group, head: bundle.head,
      });
      validateB24Parent(parent);
      const preStageSnapshot = copyBytes(session.provider.serialize_state());
      staged = session.group.stage_inbound_commit(session.provider, exactCommit);
      projectionHandle = staged.projection();
      rejectRawSelfRemove(projectionHandle);
      const projection = projectB2Commit(projectionHandle);
      if (!bytesEqual(preStageSnapshot, session.provider.serialize_state())) {
        failB24(B24_ERROR.ENGINE_REJECTED, 'inbound staging changed Provider state');
      }
      const inputs = { parent, candidate: projection, commitBytes: exactCommit };
      const policyDecision = evaluateB24Authorization(inputs);
      verifyB24DecisionBinding(policyDecision, inputs);
      if (!policyDecision.allowed) {
        session.group.discard_staged_commit(session.provider, staged);
        stagedFinalized = true;
        return Object.freeze({
          status: 'rejected', head: bundle.head, projection, authorization: policyDecision,
        });
      }
      stagedFinalized = true;
      session.group.merge_staged_commit(
        session.provider, staged,
        hexToBytes('verifiedLeafDigestHex', projection.verifiedLeafDigestHex),
      );
      const successorEpochDec = epochToDecimal(session.group.epoch());
      const successorEpochDigestHex = bytesToHex(session.group.group_context_sha256(session.provider));
      if (successorEpochDec !== projection.candidateEpochDec
        || successorEpochDigestHex !== projection.candidateGroupContextDigestHex) {
        failB24(B24_ERROR.ENGINE_REJECTED, 'inbound merge produced an unexpected successor');
      }
      verifyB24DecisionBinding(policyDecision, inputs);
      const result = await this.#journal.cas({
        expectedHead: bundle.head,
        snapshotBytes: copyBytes(session.provider.serialize_state()),
        transitionFields: {
          kind: 'inbound-accept', state: HEAD_STABLE,
          epochDec: successorEpochDec, epochDigestHex: successorEpochDigestHex,
          commitBytes: exactCommit, welcomeBytes: null, projection,
          projectionDigestHex: projectionDigest(projection),
          candidateEpochDec: projection.candidateEpochDec,
          candidateEpochDigestHex: projection.candidateGroupContextDigestHex,
          verifiedLeafDigestHex: projection.verifiedLeafDigestHex,
          artifactId: null, artifactBytes: null, artifactDigestHex: null,
          publishAttempts: 0, evidenceCount: 0, appliedCommitDigestHex: commitDigestHex,
        },
        headFields: {
          state: HEAD_STABLE,
          epochDec: successorEpochDec, epochDigestHex: successorEpochDigestHex,
          pendingCommitDigestHex: null, pendingWelcomeDigestHex: null,
          candidateEpochDec: null, candidateEpochDigestHex: null,
          verifiedLeafDigestHex: null, artifactId: null, artifactDigestHex: null,
          publishAttempts: 0, evidenceCount: 0,
          lastAppliedCommitDigestHex: commitDigestHex,
        },
      });
      return Object.freeze({
        status: 'accepted', head: result.head, projection, authorization: policyDecision,
      });
    } catch (error) {
      if (staged !== undefined && !stagedFinalized) {
        try { session.group.discard_staged_commit(session.provider, staged); } catch { /* dispose below */ }
      }
      if (error?.code) throw error;
      failB24(B24_ERROR.ENGINE_REJECTED, 'B2.4 inbound staging or merge failed', {}, error);
    } finally {
      safeFree(projectionHandle);
      safeFree(staged);
      disposeSession(session);
    }
  }

  async recoveryState(groupIdHex) {
    const bundle = await this.#journal.read(groupIdHex);
    if (bundle.head.state === HEAD_STABLE) {
      return Object.freeze({ action: 'resume-stable', head: bundle.head });
    }
    if (bundle.head.publishAttempts === 0) {
      return Object.freeze({ action: 'discard-or-publish', head: bundle.head });
    }
    return Object.freeze({ action: 'confirm-after-authorization-recheck', head: bundle.head });
  }
}
