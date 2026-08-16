// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — retained-parent fork settlement through the pinned WASM boundary.

import {
  bytesToHex,
  canonicalJsonBytes,
  clearBytes,
  hexToBytes,
  projectionEvidence,
  safeFree,
  sha256Hex,
} from '../marmot-phase-b3-3b-1/b3-3b-1-canonical.mjs';
import {
  B33B2B_ERROR,
  B33B2B_STATE,
  B33b2bError,
  compareIdentityHex,
  failB33b2b,
} from './b3-3b-2b-canonical.mjs';

const SELECTION_TRACE_DOMAIN = 'STYX-B33B2B-SELECTION-TRACE-v1';
const SETTLEMENT_RECORD_DOMAIN = 'STYX-B33B2B-SETTLEMENT-RECORD-v1';
const UNRECOVERABLE_DOMAIN = 'STYX-B33B2B-UNRECOVERABLE-REASON-v1';

function sameBytes(left, right) {
  return left.byteLength === right.byteLength
    && left.every((value, index) => value === right[index]);
}

function sameProjection(left, right) {
  return sameBytes(canonicalJsonBytes(left), canonicalJsonBytes(right));
}

function requireBytes(label, value, exactLength = undefined) {
  if (!(value instanceof Uint8Array) || value.byteLength === 0
    || (exactLength !== undefined && value.byteLength !== exactLength)) {
    failB33b2b(B33B2B_ERROR.INVALID, `${label} is not exact byte input`);
  }
}

function copyBinding(value) {
  requireBytes('group id', value?.groupId);
  requireBytes('own account identity', value?.ownIdentity, 32);
  requireBytes('own signature key', value?.ownSignatureKey, 32);
  return Object.freeze({
    groupId: Uint8Array.from(value.groupId),
    ownIdentity: Uint8Array.from(value.ownIdentity),
    ownSignatureKey: Uint8Array.from(value.ownSignatureKey),
  });
}

function clearBinding(value) {
  clearBytes(value?.groupId);
  clearBytes(value?.ownIdentity);
  clearBytes(value?.ownSignatureKey);
}

function nativeFailure(operation, error) {
  if (error instanceof B33b2bError) throw error;
  failB33b2b(B33B2B_ERROR.ENGINE_REJECTED, `${operation} failed closed`, {
    nativeMessage: error instanceof Error ? error.message : `${error}`,
  });
}

function candidateOrdering(localCandidate, rivalCandidate) {
  const candidates = [localCandidate, rivalCandidate]
    .map((candidate) => Object.freeze({
      authoritySha256Hex: candidate.authoritySha256Hex,
      commitSha256Hex: candidate.projection.commitSha256Hex,
      committerAccountHex: candidate.projection.committerAccountHex,
      effectiveCommitDepth: 1,
      priority: candidate.projection.orderingPriority,
      sourceEpoch: candidate.projection.sourceEpoch,
      targetEpoch: candidate.projection.targetEpoch,
      witnessQuorumMet: false,
      appWitnessScore: 0,
    }))
    .sort((left, right) => left.commitSha256Hex.localeCompare(right.commitSha256Hex));
  const winner = compareIdentityHex(
    localCandidate.projection.committerAccountHex,
    rivalCandidate.projection.committerAccountHex,
  ) < 0 ? localCandidate : rivalCandidate;
  const trace = Object.freeze({
    domain: SELECTION_TRACE_DOMAIN,
    candidateCount: 2,
    eligibleCount: 2,
    proposalCount: 0,
    applicationPayloadCount: 0,
    witnessCount: 0,
    decisiveRule: 'tip_committer',
    candidates: Object.freeze(candidates),
    selectedCommitSha256Hex: winner.projection.commitSha256Hex,
  });
  return Object.freeze({
    trace,
    traceDigestHex: sha256Hex(canonicalJsonBytes(trace)),
    winner,
    loser: winner.role === 'LOCAL' ? rivalCandidate : localCandidate,
  });
}

function settlementRecord(head, ordering) {
  return canonicalJsonBytes({
    domain: SETTLEMENT_RECORD_DOMAIN,
    forkEpoch: head.forkEpoch,
    frozenSetDigestHex: head.frozenSetDigestHex,
    selectedCommitSha256Hex: ordering.winner.projection.commitSha256Hex,
    losingCommitSha256Hex: ordering.loser.projection.commitSha256Hex,
    losingDisposition: 'deferred',
    selectionTraceDigestHex: ordering.traceDigestHex,
  });
}

function safeFreeAll(...values) {
  for (const value of values) safeFree(value);
}

export class B33b2bEvolutionAdapter {
  constructor({ binding, effectSink, journal, wasm }) {
    if (!journal || typeof journal.readRecovery !== 'function'
      || typeof journal.readHead !== 'function'
      || !wasm?.PhaseB33b1Group
      || effectSink === null || typeof effectSink?.deliver !== 'function') {
      failB33b2b(B33B2B_ERROR.INVALID, 'fork adapter dependencies are incomplete');
    }
    this.binding = copyBinding(binding);
    this.effectSink = effectSink;
    this.journal = journal;
    this.wasm = wasm;
  }

  close() {
    clearBinding(this.binding);
  }

  #loadClean(stateBytes, label) {
    let group;
    try {
      group = this.wasm.PhaseB33b1Group.load_clean_canonical_state(
        stateBytes, this.binding.groupId,
        this.binding.ownIdentity, this.binding.ownSignatureKey,
      );
      if (!group) {
        safeFree(group);
        failB33b2b(B33B2B_ERROR.ENGINE_REJECTED,
          `${label} did not reload under the frozen provider profile`);
      }
      return group;
    } catch (error) {
      safeFree(group);
      nativeFailure(`${label} reload`, error);
    }
    return undefined;
  }

  #stageExact(parentStateBytes, commitBytes, expected = undefined, apply = false) {
    let group;
    let pending;
    let projection;
    let release;
    let applied;
    let exactParent;
    let exactCommit;
    let committedState;
    let parentDigest;
    let commitDigest;
    let authorityDigest;
    try {
      group = this.#loadClean(parentStateBytes, 'retained parent');
      pending = group.stage_inbound_commit(commitBytes);
      projection = pending.projection();
      const evidence = projectionEvidence(projection);
      parentDigest = Uint8Array.from(pending.parent_state_sha256());
      commitDigest = Uint8Array.from(pending.commit_sha256());
      authorityDigest = Uint8Array.from(pending.authority_sha256());
      if (expected !== undefined && (!sameProjection(evidence, expected.projection)
        || bytesToHex(authorityDigest) !== expected.authoritySha256Hex)) {
        failB33b2b(B33B2B_ERROR.ENGINE_REJECTED,
          'authenticated candidate projection changed after restart');
      }
      release = pending.release(parentDigest, commitDigest, authorityDigest);
      exactParent = Uint8Array.from(release.take_parent_state());
      exactCommit = Uint8Array.from(release.take_commit());
      if (!sameBytes(exactParent, parentStateBytes) || !sameBytes(exactCommit, commitBytes)
        || sha256Hex(exactParent) !== evidence.parentStateSha256Hex
        || sha256Hex(exactCommit) !== evidence.commitSha256Hex
        || bytesToHex(commitDigest) !== evidence.commitSha256Hex
        || bytesToHex(authorityDigest) !== evidence.authoritySha256Hex) {
        failB33b2b(B33B2B_ERROR.ENGINE_REJECTED,
          'stage/release changed an exact candidate binding');
      }
      if (apply) {
        applied = this.wasm.PhaseB33b1Group.apply_inbound_commit(
          exactParent, this.binding.groupId,
          this.binding.ownIdentity, this.binding.ownSignatureKey,
          exactCommit, parentDigest, commitDigest, authorityDigest,
        );
        committedState = Uint8Array.from(applied.take_committed_state());
        this.#verifyCanonicalState(committedState, {
          epoch: evidence.targetEpoch,
          groupContextSha256Hex: evidence.candidateGroupContextSha256Hex,
        });
      }
      return Object.freeze({
        authoritySha256Hex: bytesToHex(authorityDigest),
        committedState: committedState === undefined
          ? undefined : Uint8Array.from(committedState),
        evidence,
      });
    } catch (error) {
      nativeFailure('exact candidate authentication', error);
    } finally {
      clearBytes(exactParent);
      clearBytes(exactCommit);
      clearBytes(committedState);
      clearBytes(parentDigest);
      clearBytes(commitDigest);
      clearBytes(authorityDigest);
      safeFreeAll(applied, release, projection, pending, group);
    }
    return undefined;
  }

  #verifyCanonicalState(stateBytes, authority) {
    let group;
    let pending;
    let projection;
    try {
      group = this.#loadClean(stateBytes, 'canonical branch');
      pending = group.prepare_self_update();
      projection = pending.projection();
      const evidence = projectionEvidence(projection);
      if (evidence.sourceEpoch !== authority.epoch
        || evidence.parentGroupContextSha256Hex !== authority.groupContextSha256Hex
        || evidence.groupIdHex !== bytesToHex(this.binding.groupId)) {
        failB33b2b(B33B2B_ERROR.ENGINE_REJECTED,
          'canonical branch authority changed after restart');
      }
      pending.discard();
    } catch (error) {
      nativeFailure('canonical branch verification', error);
    } finally {
      safeFreeAll(projection, pending, group);
    }
  }

  async #markUnrecoverable(head, operation, error) {
    if (head.state === B33B2B_STATE.STABLE || head.state === B33B2B_STATE.UNRECOVERABLE) {
      throw error;
    }
    const reasonDigestHex = sha256Hex(canonicalJsonBytes({
      domain: UNRECOVERABLE_DOMAIN,
      operation,
      code: error?.code ?? B33B2B_ERROR.ENGINE_REJECTED,
    }));
    await this.journal.markUnrecoverable(head.headDigestHex, reasonDigestHex);
    failB33b2b(B33B2B_ERROR.UNRECOVERABLE,
      `${operation} made the bounded fork unrecoverable`, {
        causeCode: error?.code ?? null,
        causeDetails: error?.details ?? null,
        causeMessage: error instanceof Error ? error.message : `${error}`,
        reasonDigestHex,
      });
  }

  async verifyDurableAuthority() {
    const head = await this.journal.readHead();
    let recovery;
    try {
      recovery = await this.journal.readRecovery();
      this.#verifyCanonicalState(recovery.canonicalStateBytes, head.canonical);
      const expectedGroupId = bytesToHex(this.binding.groupId);
      for (const [candidate, commitBytes] of [
        [head.localCandidate, recovery.localCommitBytes],
        [head.rivalCandidate, recovery.rivalCommitBytes],
      ]) {
        if (candidate !== null) {
          const repeated = this.#stageExact(
            recovery.parentStateBytes, commitBytes, candidate, false,
          );
          if (repeated.evidence.groupIdHex !== expectedGroupId) {
            failB33b2b(B33B2B_ERROR.ENGINE_REJECTED,
              'candidate group binding changed after restart');
          }
        }
      }
      if (head.successorStateBlobSha256Hex !== null) {
        const ordering = candidateOrdering(head.localCandidate, head.rivalCandidate);
        this.#verifyCanonicalState(recovery.successorStateBytes, {
          epoch: ordering.winner.projection.targetEpoch,
          groupContextSha256Hex:
            ordering.winner.projection.candidateGroupContextSha256Hex,
        });
        if (head.settlement.selectionTraceDigestHex !== ordering.traceDigestHex
          || !sameBytes(recovery.settlementRecordBytes, settlementRecord(head, ordering))) {
          failB33b2b(B33B2B_ERROR.CORRUPT,
            'durable settlement evidence changed after restart');
        }
      }
      return Object.freeze({ head, verified: true });
    } catch (error) {
      if (error?.code === B33B2B_ERROR.PERSISTENCE_FAILED
        || error?.code === B33B2B_ERROR.CAS_CONFLICT) throw error;
      return this.#markUnrecoverable(head, 'durable authority verification', error);
    } finally {
      clearBytes(recovery?.canonicalStateBytes);
      clearBytes(recovery?.parentStateBytes);
      clearBytes(recovery?.localCommitBytes);
      clearBytes(recovery?.rivalCommitBytes);
      clearBytes(recovery?.successorStateBytes);
      clearBytes(recovery?.settlementRecordBytes);
    }
  }

  async activate(fields) {
    this.#verifyCanonicalState(fields.parentStateBytes, {
      epoch: fields.forkEpoch,
      groupContextSha256Hex: fields.parentGroupContextSha256Hex,
    });
    return this.journal.activate(fields);
  }

  async prepareLocal() {
    const recovery = await this.journal.readRecovery();
    if (recovery.head.state !== B33B2B_STATE.ACTIVATED) {
      clearBytes(recovery.canonicalStateBytes);
      clearBytes(recovery.parentStateBytes);
      failB33b2b(B33B2B_ERROR.STATE_CONFLICT,
        'local fork branch requires the activated parent');
    }
    let group;
    let pending;
    let projection;
    let release;
    let confirmed;
    let pendingState;
    let commitBytes;
    let committedState;
    let parentDigest;
    let pendingDigest;
    let commitDigest;
    let authorityDigest;
    try {
      group = this.#loadClean(recovery.parentStateBytes, 'local branch parent');
      pending = group.prepare_self_update();
      projection = pending.projection();
      const evidence = projectionEvidence(projection);
      parentDigest = Uint8Array.from(pending.parent_state_sha256());
      pendingDigest = Uint8Array.from(pending.pending_state_sha256());
      commitDigest = Uint8Array.from(pending.commit_sha256());
      authorityDigest = Uint8Array.from(pending.authority_sha256());
      release = pending.release(parentDigest, pendingDigest, commitDigest, authorityDigest);
      pendingState = Uint8Array.from(release.take_pending_state());
      commitBytes = Uint8Array.from(release.take_commit());
      if (sha256Hex(commitBytes) !== evidence.commitSha256Hex
        || bytesToHex(commitDigest) !== evidence.commitSha256Hex
        || bytesToHex(authorityDigest) !== evidence.authoritySha256Hex) {
        failB33b2b(B33B2B_ERROR.ENGINE_REJECTED,
          'local Commit release changed authenticated bytes');
      }
      confirmed = this.wasm.PhaseB33b1Group.confirm_local_commit(
        pendingState, this.binding.groupId,
        this.binding.ownIdentity, this.binding.ownSignatureKey,
        commitBytes, parentDigest, pendingDigest, commitDigest, authorityDigest,
      );
      committedState = Uint8Array.from(confirmed.take_committed_state());
      this.#verifyCanonicalState(committedState, {
        epoch: evidence.targetEpoch,
        groupContextSha256Hex: evidence.candidateGroupContextSha256Hex,
      });
      const durable = await this.journal.recordLocalBranch(
        recovery.head.headDigestHex, {
          authoritySha256Hex: bytesToHex(authorityDigest),
          commitBytes,
          projection: evidence,
          stateBytes: committedState,
        },
      );
      return Object.freeze({
        disposition: 'local_branch_durable',
        commitBytes: Uint8Array.from(commitBytes),
        commitSha256Hex: evidence.commitSha256Hex,
        headDigestHex: durable.headDigestHex,
        projection: evidence,
      });
    } catch (error) {
      nativeFailure('local fork branch preparation', error);
    } finally {
      clearBytes(recovery.canonicalStateBytes);
      clearBytes(recovery.parentStateBytes);
      clearBytes(pendingState);
      clearBytes(commitBytes);
      clearBytes(committedState);
      clearBytes(parentDigest);
      clearBytes(pendingDigest);
      clearBytes(commitDigest);
      clearBytes(authorityDigest);
      safeFreeAll(confirmed, release, projection, pending, group);
    }
    return undefined;
  }

  async retryLocal() {
    await this.verifyDurableAuthority();
    const recovery = await this.journal.readRecovery();
    try {
      if (recovery.head.state !== B33B2B_STATE.LOCAL_BRANCH_DURABLE) {
        failB33b2b(B33B2B_ERROR.STATE_CONFLICT,
          'no unresolved local publication obligation exists');
      }
      return Object.freeze({
        disposition: 'local_branch_retry',
        commitBytes: Uint8Array.from(recovery.localCommitBytes),
        commitSha256Hex: recovery.head.localCandidate.projection.commitSha256Hex,
        headDigestHex: recovery.head.headDigestHex,
      });
    } finally {
      clearBytes(recovery.canonicalStateBytes);
      clearBytes(recovery.parentStateBytes);
      clearBytes(recovery.localCommitBytes);
    }
  }

  async recordRival(commitBytes) {
    const verified = await this.verifyDurableAuthority();
    if (verified.head.state !== B33B2B_STATE.LOCAL_BRANCH_DURABLE) {
      failB33b2b(B33B2B_ERROR.STATE_CONFLICT,
        'rival admission requires one durable local branch');
    }
    const recovery = await this.journal.readRecovery();
    try {
      const staged = this.#stageExact(recovery.parentStateBytes, commitBytes);
      const head = await this.journal.recordRival(verified.head.headDigestHex, {
        authoritySha256Hex: staged.authoritySha256Hex,
        commitBytes,
        projection: staged.evidence,
      });
      return Object.freeze({
        disposition: 'rival_recorded',
        headDigestHex: head.headDigestHex,
        projection: staged.evidence,
      });
    } finally {
      clearBytes(recovery.canonicalStateBytes);
      clearBytes(recovery.parentStateBytes);
      clearBytes(recovery.localCommitBytes);
    }
  }

  async freezeRace() {
    const verified = await this.verifyDurableAuthority();
    if (verified.head.state !== B33B2B_STATE.RIVAL_RECORDED) {
      failB33b2b(B33B2B_ERROR.STATE_CONFLICT,
        'candidate freeze requires the exact two recorded branches');
    }
    return this.journal.freezeRace(verified.head.headDigestHex);
  }

  async prepareSettlement() {
    const verified = await this.verifyDurableAuthority();
    if (verified.head.state !== B33B2B_STATE.RACE_FROZEN) {
      failB33b2b(B33B2B_ERROR.STATE_CONFLICT,
        'settlement requires one immutable frozen race');
    }
    const recovery = await this.journal.readRecovery();
    let successorState;
    let recordBytes;
    try {
      const ordering = candidateOrdering(
        recovery.head.localCandidate, recovery.head.rivalCandidate,
      );
      if (ordering.winner.role === 'LOCAL') {
        successorState = Uint8Array.from(recovery.canonicalStateBytes);
      } else {
        const rebuilt = this.#stageExact(
          recovery.parentStateBytes, recovery.rivalCommitBytes,
          recovery.head.rivalCandidate, true,
        );
        successorState = Uint8Array.from(rebuilt.committedState);
      }
      recordBytes = settlementRecord(recovery.head, ordering);
      return await this.journal.prepareSettlement(recovery.head.headDigestHex, {
        losingCommitSha256Hex: ordering.loser.projection.commitSha256Hex,
        losingDisposition: 'deferred',
        selectedCommitSha256Hex: ordering.winner.projection.commitSha256Hex,
        selectedGroupContextSha256Hex:
          ordering.winner.projection.candidateGroupContextSha256Hex,
        selectionTraceDigestHex: ordering.traceDigestHex,
        settlementRecordBytes: recordBytes,
        successorStateBytes: successorState,
      });
    } finally {
      clearBytes(recovery.canonicalStateBytes);
      clearBytes(recovery.parentStateBytes);
      clearBytes(recovery.localCommitBytes);
      clearBytes(recovery.rivalCommitBytes);
      clearBytes(successorState);
      clearBytes(recordBytes);
    }
  }

  async commitStable() {
    const verified = await this.verifyDurableAuthority();
    if (verified.head.state !== B33B2B_STATE.SETTLEMENT_PREPARED) {
      failB33b2b(B33B2B_ERROR.STATE_CONFLICT,
        'stable switch requires a durable prepared successor');
    }
    return this.journal.commitStable(verified.head.headDigestHex);
  }

  async deliverStableEffect() {
    const verified = await this.verifyDurableAuthority();
    const head = verified.head;
    if (head.state !== B33B2B_STATE.STABLE) {
      failB33b2b(B33B2B_ERROR.STATE_CONFLICT,
        'effect delivery requires stable canonical authority');
    }
    if (head.settlement.effectDelivered) {
      return Object.freeze({
        disposition: 'already_delivered', effectIdHex: head.settlement.effectIdHex,
      });
    }
    const effect = Object.freeze({
      effectIdHex: head.settlement.effectIdHex,
      effectKind: head.settlement.effectKind,
      forkEpoch: head.forkEpoch,
      selectedCommitSha256Hex: head.selectedCommitSha256Hex,
      losingCommitSha256Hex: head.settlement.losingCommitSha256Hex,
      losingDisposition: head.settlement.losingDisposition,
    });
    const outcome = await this.effectSink.deliver(effect);
    if (!outcome || outcome.effectIdHex !== effect.effectIdHex
      || !['accepted', 'duplicate'].includes(outcome.disposition)) {
      failB33b2b(B33B2B_ERROR.STATE_CONFLICT,
        'idempotent effect sink did not acknowledge the stable effect');
    }
    try {
      const delivered = await this.journal.markEffectDelivered(
        head.headDigestHex, effect.effectIdHex,
      );
      return Object.freeze({
        disposition: outcome.disposition,
        effectIdHex: effect.effectIdHex,
        headDigestHex: delivered.headDigestHex,
      });
    } catch (error) {
      if (error?.code !== B33B2B_ERROR.CAS_CONFLICT) throw error;
      const current = await this.journal.readHead();
      if (current.state !== B33B2B_STATE.STABLE
        || current.settlement.effectIdHex !== effect.effectIdHex
        || !current.settlement.effectDelivered) throw error;
      return Object.freeze({
        disposition: 'concurrent_acknowledgement', effectIdHex: effect.effectIdHex,
        headDigestHex: current.headDigestHex,
      });
    }
  }
}

export class MemoryB33b2bEffectSink {
  constructor() {
    this.effects = new Map();
    this.afterAccept = null;
  }

  async deliver(effect) {
    const previous = this.effects.get(effect.effectIdHex);
    if (previous !== undefined) {
      if (!sameBytes(canonicalJsonBytes(previous), canonicalJsonBytes(effect))) {
        failB33b2b(B33B2B_ERROR.STATE_CONFLICT,
          'stable effect identifier was reused for different evidence');
      }
      return Object.freeze({ disposition: 'duplicate', effectIdHex: effect.effectIdHex });
    }
    this.effects.set(effect.effectIdHex, structuredClone(effect));
    await this.afterAccept?.(effect);
    return Object.freeze({ disposition: 'accepted', effectIdHex: effect.effectIdHex });
  }
}
