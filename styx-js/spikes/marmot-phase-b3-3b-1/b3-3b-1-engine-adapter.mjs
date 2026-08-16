// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — journal-first adapter for B3.3b-1 native operations.

import { parseB32aHead } from '../marmot-phase-b3-2a/b3-2a-journal.mjs';
import {
  B33B1_ERROR,
  B33B1_MAX_PAST_EPOCHS,
  B33B1_PROVIDER_FORMAT,
  B33B1_RECOVERY,
  B33b1Error,
  b33b1RosterSha256,
  bytesToHex,
  canonicalJsonBytes,
  clearBytes,
  failB33b1,
  hexToBytes,
  projectionEvidence,
  safeFree,
  sha256Hex,
} from './b3-3b-1-canonical.mjs';

function sameBytes(left, right) {
  return left.byteLength === right.byteLength
    && left.every((value, index) => value === right[index]);
}

function sameProjection(left, right) {
  return sameBytes(canonicalJsonBytes(left), canonicalJsonBytes(right));
}

function binding(head) {
  return {
    groupId: hexToBytes('group id', head.groupIdHex),
    ownIdentity: hexToBytes('own identity', head.accountIdentityHex, 32),
    ownSignatureKey: hexToBytes('own signature key', head.leafSignatureKeyHex, 32),
  };
}

function clearBinding(value) {
  clearBytes(value?.groupId);
  clearBytes(value?.ownIdentity);
  clearBytes(value?.ownSignatureKey);
}

function nativeFailure(operation, error) {
  if (error instanceof B33b1Error) throw error;
  failB33b1(B33B1_ERROR.ENGINE_REJECTED, `${operation} failed closed`, {
    nativeMessage: error?.message ?? `${error}`,
  });
}

export class B33b1EvolutionAdapter {
  constructor({ journal, wasm }) {
    if (!journal || typeof journal.readRecovery !== 'function'
      || !wasm?.PhaseB33b1PendingActivation || !wasm?.PhaseB33b1Group) {
      failB33b1(B33B1_ERROR.INVALID, 'adapter dependencies are incomplete');
    }
    this.journal = journal;
    this.wasm = wasm;
  }

  async activateFromB32a(sourceHeadValue, predecessorState) {
    const sourceHead = parseB32aHead(sourceHeadValue);
    if (sourceHead.state !== 'JOINED'
      || sourceHead.candidateBlobSha256Hex !== sha256Hex(predecessorState)) {
      failB33b1(B33B1_ERROR.STATE_CONFLICT, 'activation source is not exact B3.2a JOINED');
    }
    const expectedPredecessor = hexToBytes(
      'predecessor digest', sourceHead.candidateBlobSha256Hex, 32,
    );
    const groupId = hexToBytes('group id', sourceHead.groupIdHex);
    const ownIdentity = hexToBytes('own identity', sourceHead.accountIdentityHex, 32);
    const ownSignatureKey = hexToBytes(
      'own signature key', sourceHead.leafSignatureKeyHex, 32,
    );
    let pending;
    let release;
    let candidateState;
    let candidateDigest;
    let contextDigest;
    let leafDigest;
    try {
      try {
        pending = this.wasm.PhaseB33b1PendingActivation.prepare_from_b32a_state(
          predecessorState, expectedPredecessor, groupId, ownIdentity, ownSignatureKey,
        );
      } catch (error) { nativeFailure('B3.3b-1 activation preparation', error); }
      if (!pending || pending.provider_format() !== B33B1_PROVIDER_FORMAT
        || pending.max_past_epochs() !== B33B1_MAX_PAST_EPOCHS
        || pending.epoch().toString() !== sourceHead.projection.epochDec) {
        failB33b1(B33B1_ERROR.ENGINE_REJECTED, 'activation profile or epoch drifted');
      }
      candidateDigest = Uint8Array.from(pending.candidate_state_sha256());
      contextDigest = Uint8Array.from(pending.group_context_sha256());
      leafDigest = Uint8Array.from(pending.verified_leaf_digest());
      if (bytesToHex(contextDigest) !== sourceHead.projection.groupContextSha256Hex
        || bytesToHex(leafDigest) !== sourceHead.projection.verifiedLeafDigestHex) {
        failB33b1(B33B1_ERROR.ENGINE_REJECTED, 'activation changed the public group projection');
      }
      release = pending.release(expectedPredecessor, candidateDigest, contextDigest, leafDigest);
      candidateState = Uint8Array.from(release.take_candidate_state());
      if (sha256Hex(candidateState) !== bytesToHex(candidateDigest)) {
        failB33b1(B33B1_ERROR.ENGINE_REJECTED, 'activation release changed its state binding');
      }
      return await this.journal.activate({
        stateBytes: candidateState,
        sourceB32aHeadDigestHex: sourceHead.headDigestHex,
        groupIdHex: sourceHead.groupIdHex,
        accountIdentityHex: sourceHead.accountIdentityHex,
        leafSignatureKeyHex: sourceHead.leafSignatureKeyHex,
        epochDec: sourceHead.projection.epochDec,
        groupContextSha256Hex: sourceHead.projection.groupContextSha256Hex,
        rosterSha256Hex: b33b1RosterSha256(sourceHead.projection.members),
      });
    } finally {
      clearBytes(expectedPredecessor);
      clearBytes(groupId);
      clearBytes(ownIdentity);
      clearBytes(ownSignatureKey);
      clearBytes(candidateState);
      clearBytes(candidateDigest);
      clearBytes(contextDigest);
      clearBytes(leafDigest);
      safeFree(release);
      safeFree(pending);
    }
  }

  async prepareLocal() {
    const current = await this.journal.readRecovery();
    if (current.action !== B33B1_RECOVERY.STABLE) {
      clearBytes(current.stateBytes);
      failB33b1(B33B1_ERROR.STATE_CONFLICT, 'local update requires stable authority');
    }
    const keys = binding(current.head);
    let group;
    let pending;
    let projection;
    let release;
    let pendingState;
    let commit;
    let parentDigest;
    let pendingDigest;
    let commitDigest;
    let authorityDigest;
    let durable;
    try {
      group = this.wasm.PhaseB33b1Group.load_clean_canonical_state(
        current.stateBytes, keys.groupId, keys.ownIdentity, keys.ownSignatureKey,
      );
      if (!group) failB33b1(B33B1_ERROR.ENGINE_REJECTED, 'active state did not reload');
      pending = group.prepare_self_update();
      projection = pending.projection();
      const evidence = projectionEvidence(projection);
      parentDigest = Uint8Array.from(pending.parent_state_sha256());
      pendingDigest = Uint8Array.from(pending.pending_state_sha256());
      commitDigest = Uint8Array.from(pending.commit_sha256());
      authorityDigest = Uint8Array.from(pending.authority_sha256());
      release = pending.release(parentDigest, pendingDigest, commitDigest, authorityDigest);
      pendingState = Uint8Array.from(release.take_pending_state());
      commit = Uint8Array.from(release.take_commit());
      durable = await this.journal.prepareLocal(current.head.headDigestHex, {
        parentStateBytes: current.stateBytes,
        pendingStateBytes: pendingState,
        commitBytes: commit,
        authoritySha256Hex: bytesToHex(authorityDigest),
        projection: evidence,
      });
      return Object.freeze({
        disposition: 'local_commit_durable',
        headDigestHex: durable.head.headDigestHex,
        commitSha256Hex: evidence.commitSha256Hex,
        commitBytes: Uint8Array.from(durable.commitBytes),
        projection: evidence,
      });
    } catch (error) {
      nativeFailure('local self-update preparation', error);
    } finally {
      clearBinding(keys);
      clearBytes(current.stateBytes);
      clearBytes(pendingState);
      clearBytes(commit);
      clearBytes(parentDigest);
      clearBytes(pendingDigest);
      clearBytes(commitDigest);
      clearBytes(authorityDigest);
      clearBytes(durable?.stateBytes);
      clearBytes(durable?.parentStateBytes);
      clearBytes(durable?.pendingStateBytes);
      clearBytes(durable?.commitBytes);
      safeFree(release);
      safeFree(projection);
      safeFree(pending);
      safeFree(group);
    }
  }

  async retryLocal() {
    const recovery = await this.journal.readRecovery();
    try {
      if (recovery.action !== B33B1_RECOVERY.REPUBLISH_LOCAL) {
        failB33b1(B33B1_ERROR.STATE_CONFLICT, 'journal has no unpublished local Commit');
      }
      return Object.freeze({
        disposition: 'local_commit_retry',
        headDigestHex: recovery.head.headDigestHex,
        commitSha256Hex: recovery.head.pendingLocal.projection.commitSha256Hex,
        commitBytes: Uint8Array.from(recovery.commitBytes),
        projection: recovery.head.pendingLocal.projection,
      });
    } finally {
      clearBytes(recovery.stateBytes);
      clearBytes(recovery.parentStateBytes);
      clearBytes(recovery.pendingStateBytes);
      clearBytes(recovery.commitBytes);
    }
  }

  async recordLocalAcceptance(headDigestHex, acceptance) {
    const recovery = await this.journal.acceptLocal(headDigestHex, acceptance);
    try {
      return Object.freeze({ disposition: 'local_acceptance_durable',
        headDigestHex: recovery.head.headDigestHex });
    } finally {
      clearBytes(recovery.stateBytes);
      clearBytes(recovery.parentStateBytes);
      clearBytes(recovery.pendingStateBytes);
      clearBytes(recovery.commitBytes);
    }
  }

  async mergeAcceptedLocal() {
    const recovery = await this.journal.readRecovery();
    if (recovery.action !== B33B1_RECOVERY.MERGE_ACCEPTED_LOCAL) {
      clearBytes(recovery.stateBytes);
      clearBytes(recovery.parentStateBytes);
      clearBytes(recovery.pendingStateBytes);
      clearBytes(recovery.commitBytes);
      failB33b1(B33B1_ERROR.STATE_CONFLICT, 'journal lacks durable local acceptance');
    }
    const keys = binding(recovery.head);
    const pending = recovery.head.pendingLocal;
    let release;
    let committedState;
    let stable;
    try {
      release = this.wasm.PhaseB33b1Group.confirm_local_commit(
        recovery.pendingStateBytes, keys.groupId, keys.ownIdentity, keys.ownSignatureKey,
        recovery.commitBytes,
        hexToBytes('parent digest', pending.parentStateBlobSha256Hex, 32),
        hexToBytes('pending digest', pending.pendingStateBlobSha256Hex, 32),
        hexToBytes('Commit digest', pending.commitBlobSha256Hex, 32),
        hexToBytes('authority digest', pending.authoritySha256Hex, 32),
      );
      committedState = Uint8Array.from(release.take_committed_state());
      stable = await this.journal.commitAcceptedLocal(recovery.head.headDigestHex, {
        committedStateBytes: committedState,
        committedStateSha256Hex: sha256Hex(committedState),
        groupContextSha256Hex: pending.projection.candidateGroupContextSha256Hex,
        rosterSha256Hex: recovery.head.rosterSha256Hex,
        epochDec: pending.projection.targetEpoch,
        commitSha256Hex: pending.projection.commitSha256Hex,
        authoritySha256Hex: pending.authoritySha256Hex,
      });
      return Object.freeze({ disposition: 'local_commit_merged', head: stable.head });
    } catch (error) {
      nativeFailure('accepted local Commit merge', error);
    } finally {
      clearBinding(keys);
      clearBytes(recovery.stateBytes);
      clearBytes(recovery.parentStateBytes);
      clearBytes(recovery.pendingStateBytes);
      clearBytes(recovery.commitBytes);
      clearBytes(committedState);
      clearBytes(stable?.stateBytes);
      safeFree(release);
    }
  }

  async prepareApplicationOutbound(plaintextBytes) {
    const current = await this.journal.readRecovery();
    if (current.action !== B33B1_RECOVERY.STABLE) {
      clearBytes(current.stateBytes);
      failB33b1(B33B1_ERROR.STATE_CONFLICT, 'application send requires stable authority');
    }
    const keys = binding(current.head);
    let group;
    let pending;
    let release;
    let stateBytes;
    let ciphertextBytes;
    let stateDigest;
    let ciphertextDigest;
    let durable;
    try {
      group = this.wasm.PhaseB33b1Group.load_clean_canonical_state(
        current.stateBytes, keys.groupId, keys.ownIdentity, keys.ownSignatureKey,
      );
      if (!group) failB33b1(B33B1_ERROR.ENGINE_REJECTED, 'active state did not reload');
      pending = group.prepare_application_outbound(plaintextBytes);
      stateDigest = Uint8Array.from(pending.canonical_state_sha256());
      ciphertextDigest = Uint8Array.from(pending.ciphertext_sha256());
      const evidence = Object.freeze({
        currentEpoch: pending.current_epoch().toString(),
        messageEpoch: pending.message_epoch().toString(),
        senderLeafIndex: pending.sender_leaf_index(),
        senderIdentityHex: bytesToHex(pending.sender_credential_identity()),
        senderSignatureKeyHex: bytesToHex(pending.sender_signature_key()),
      });
      release = pending.release(stateDigest, ciphertextDigest);
      stateBytes = Uint8Array.from(release.take_canonical_state());
      ciphertextBytes = Uint8Array.from(release.take_ciphertext());
      durable = await this.journal.commitApplication(current.head.headDigestHex, {
        direction: 'OUTBOUND',
        stateBytes,
        ciphertextBytes,
        plaintextBytes: null,
        currentEpochDec: evidence.currentEpoch,
        messageEpoch: evidence.messageEpoch,
        groupIdHex: current.head.groupIdHex,
        senderLeafIndex: evidence.senderLeafIndex,
        senderIdentityHex: evidence.senderIdentityHex,
        senderSignatureKeyHex: evidence.senderSignatureKeyHex,
      });
      return Object.freeze({
        disposition: 'application_outbound_durable',
        headDigestHex: durable.head.headDigestHex,
        ciphertextSha256Hex: durable.record.ciphertextBlobSha256Hex,
        ciphertextBytes: Uint8Array.from(durable.ciphertextBytes),
        evidence,
      });
    } catch (error) {
      nativeFailure('application outbound preparation', error);
    } finally {
      clearBinding(keys);
      clearBytes(current.stateBytes);
      clearBytes(stateBytes);
      clearBytes(ciphertextBytes);
      clearBytes(stateDigest);
      clearBytes(ciphertextDigest);
      clearBytes(durable?.stateBytes);
      clearBytes(durable?.ciphertextBytes);
      safeFree(release);
      safeFree(pending);
      safeFree(group);
    }
  }

  async receiveApplication(ciphertextBytes) {
    const digest = sha256Hex(ciphertextBytes);
    const current = await this.journal.readRecovery();
    const duplicate = current.head.applicationRecords.find(
      (record) => record.direction === 'INBOUND'
        && record.ciphertextBlobSha256Hex === digest,
    );
    if (duplicate) {
      clearBytes(current.stateBytes);
      return Object.freeze({ disposition: 'duplicate', record: duplicate });
    }
    if (current.action !== B33B1_RECOVERY.STABLE) {
      clearBytes(current.stateBytes);
      failB33b1(B33B1_ERROR.STATE_CONFLICT, 'application receive requires stable authority');
    }
    const keys = binding(current.head);
    let group;
    let pending;
    let release;
    let stateBytes;
    let exactCiphertext;
    let plaintextBytes;
    let stateDigest;
    let ciphertextDigest;
    let plaintextDigest;
    let durable;
    try {
      group = this.wasm.PhaseB33b1Group.load_clean_canonical_state(
        current.stateBytes, keys.groupId, keys.ownIdentity, keys.ownSignatureKey,
      );
      if (!group) failB33b1(B33B1_ERROR.ENGINE_REJECTED, 'active state did not reload');
      pending = group.prepare_application_inbound(ciphertextBytes);
      stateDigest = Uint8Array.from(pending.canonical_state_sha256());
      ciphertextDigest = Uint8Array.from(pending.ciphertext_sha256());
      plaintextDigest = Uint8Array.from(pending.plaintext_sha256());
      const evidence = Object.freeze({
        currentEpoch: pending.current_epoch().toString(),
        messageEpoch: pending.message_epoch().toString(),
        senderLeafIndex: pending.sender_leaf_index(),
        senderIdentityHex: bytesToHex(pending.sender_credential_identity()),
        senderSignatureKeyHex: bytesToHex(pending.sender_signature_key()),
      });
      release = pending.release(stateDigest, ciphertextDigest, plaintextDigest);
      stateBytes = Uint8Array.from(release.take_canonical_state());
      exactCiphertext = Uint8Array.from(release.take_ciphertext());
      plaintextBytes = Uint8Array.from(release.take_plaintext());
      if (!sameBytes(exactCiphertext, ciphertextBytes)) {
        failB33b1(B33B1_ERROR.ENGINE_REJECTED, 'application release changed ciphertext');
      }
      durable = await this.journal.commitApplication(current.head.headDigestHex, {
        direction: 'INBOUND',
        stateBytes,
        ciphertextBytes: exactCiphertext,
        plaintextBytes,
        currentEpochDec: evidence.currentEpoch,
        messageEpoch: evidence.messageEpoch,
        groupIdHex: current.head.groupIdHex,
        senderLeafIndex: evidence.senderLeafIndex,
        senderIdentityHex: evidence.senderIdentityHex,
        senderSignatureKeyHex: evidence.senderSignatureKeyHex,
      });
      return Object.freeze({
        disposition: 'application_inbound_durable',
        headDigestHex: durable.head.headDigestHex,
        plaintextSha256Hex: durable.record.plaintextBlobSha256Hex,
        plaintextBytes: Uint8Array.from(durable.plaintextBytes),
        evidence,
      });
    } catch (error) {
      nativeFailure('application inbound processing', error);
    } finally {
      clearBinding(keys);
      clearBytes(current.stateBytes);
      clearBytes(stateBytes);
      clearBytes(exactCiphertext);
      clearBytes(plaintextBytes);
      clearBytes(stateDigest);
      clearBytes(ciphertextDigest);
      clearBytes(plaintextDigest);
      clearBytes(durable?.stateBytes);
      clearBytes(durable?.ciphertextBytes);
      clearBytes(durable?.plaintextBytes);
      safeFree(release);
      safeFree(pending);
      safeFree(group);
    }
  }

  async stageInbound(commitBytes) {
    const commitSha256Hex = sha256Hex(commitBytes);
    const previous = await this.journal.committedTransition(commitSha256Hex);
    if (previous !== null) {
      return Object.freeze({ disposition: 'duplicate', transition: previous });
    }
    const current = await this.journal.readRecovery();
    if (current.action !== B33B1_RECOVERY.STABLE) {
      clearBytes(current.stateBytes);
      failB33b1(B33B1_ERROR.STATE_CONFLICT, 'inbound stage requires stable authority');
    }
    const keys = binding(current.head);
    let group;
    let pending;
    let projection;
    let release;
    let parentState;
    let exactCommit;
    let parentDigest;
    let commitDigest;
    let authorityDigest;
    let durable;
    try {
      group = this.wasm.PhaseB33b1Group.load_clean_canonical_state(
        current.stateBytes, keys.groupId, keys.ownIdentity, keys.ownSignatureKey,
      );
      if (!group) failB33b1(B33B1_ERROR.ENGINE_REJECTED, 'active state did not reload');
      pending = group.stage_inbound_commit(commitBytes);
      projection = pending.projection();
      const evidence = projectionEvidence(projection);
      parentDigest = Uint8Array.from(pending.parent_state_sha256());
      commitDigest = Uint8Array.from(pending.commit_sha256());
      authorityDigest = Uint8Array.from(pending.authority_sha256());
      release = pending.release(parentDigest, commitDigest, authorityDigest);
      parentState = Uint8Array.from(release.take_parent_state());
      exactCommit = Uint8Array.from(release.take_commit());
      if (!sameBytes(parentState, current.stateBytes) || !sameBytes(exactCommit, commitBytes)) {
        failB33b1(B33B1_ERROR.ENGINE_REJECTED, 'inbound release changed exact bytes');
      }
      durable = await this.journal.stageInbound(current.head.headDigestHex, {
        parentStateBytes: parentState,
        commitBytes: exactCommit,
        authoritySha256Hex: bytesToHex(authorityDigest),
        projection: evidence,
      });
      return Object.freeze({ disposition: 'inbound_commit_durable',
        headDigestHex: durable.head.headDigestHex, projection: evidence });
    } catch (error) {
      nativeFailure('inbound Commit stage', error);
    } finally {
      clearBinding(keys);
      clearBytes(current.stateBytes);
      clearBytes(parentState);
      clearBytes(exactCommit);
      clearBytes(parentDigest);
      clearBytes(commitDigest);
      clearBytes(authorityDigest);
      clearBytes(durable?.stateBytes);
      clearBytes(durable?.parentStateBytes);
      clearBytes(durable?.commitBytes);
      safeFree(release);
      safeFree(projection);
      safeFree(pending);
      safeFree(group);
    }
  }

  async applyStagedInbound() {
    const recovery = await this.journal.readRecovery();
    if (recovery.action !== B33B1_RECOVERY.RESTAGE_INBOUND) {
      clearBytes(recovery.stateBytes);
      clearBytes(recovery.parentStateBytes);
      clearBytes(recovery.commitBytes);
      failB33b1(B33B1_ERROR.STATE_CONFLICT, 'journal has no staged inbound Commit');
    }
    const keys = binding(recovery.head);
    const staged = recovery.head.stagedInbound;
    let group;
    let pending;
    let projection;
    let released;
    let parentState;
    let exactCommit;
    let applied;
    let committedState;
    let stable;
    try {
      group = this.wasm.PhaseB33b1Group.load_clean_canonical_state(
        recovery.parentStateBytes, keys.groupId, keys.ownIdentity, keys.ownSignatureKey,
      );
      if (!group) failB33b1(B33B1_ERROR.ENGINE_REJECTED, 'clean parent did not reload');
      pending = group.stage_inbound_commit(recovery.commitBytes);
      projection = pending.projection();
      const repeated = projectionEvidence(projection);
      if (!sameProjection(repeated, staged.projection)) {
        failB33b1(B33B1_ERROR.ENGINE_REJECTED, 're-staged projection changed after restart');
      }
      const parentDigest = hexToBytes('parent digest', staged.parentStateBlobSha256Hex, 32);
      const commitDigest = hexToBytes('Commit digest', staged.commitBlobSha256Hex, 32);
      const authorityDigest = hexToBytes('authority digest', staged.authoritySha256Hex, 32);
      try {
        released = pending.release(parentDigest, commitDigest, authorityDigest);
        parentState = Uint8Array.from(released.take_parent_state());
        exactCommit = Uint8Array.from(released.take_commit());
        if (!sameBytes(parentState, recovery.parentStateBytes)
          || !sameBytes(exactCommit, recovery.commitBytes)) {
          failB33b1(B33B1_ERROR.ENGINE_REJECTED, 're-stage changed exact durable inputs');
        }
        applied = this.wasm.PhaseB33b1Group.apply_inbound_commit(
          parentState, keys.groupId, keys.ownIdentity, keys.ownSignatureKey, exactCommit,
          parentDigest, commitDigest, authorityDigest,
        );
        committedState = Uint8Array.from(applied.take_committed_state());
      } finally {
        clearBytes(parentDigest);
        clearBytes(commitDigest);
        clearBytes(authorityDigest);
      }
      stable = await this.journal.commitStagedInbound(recovery.head.headDigestHex, {
        committedStateBytes: committedState,
        committedStateSha256Hex: sha256Hex(committedState),
        groupContextSha256Hex: staged.projection.candidateGroupContextSha256Hex,
        rosterSha256Hex: recovery.head.rosterSha256Hex,
        epochDec: staged.projection.targetEpoch,
        commitSha256Hex: staged.projection.commitSha256Hex,
        authoritySha256Hex: staged.authoritySha256Hex,
      });
      return Object.freeze({ disposition: 'inbound_commit_merged', head: stable.head });
    } catch (error) {
      nativeFailure('inbound Commit recovery and merge', error);
    } finally {
      clearBinding(keys);
      clearBytes(recovery.stateBytes);
      clearBytes(recovery.parentStateBytes);
      clearBytes(recovery.commitBytes);
      clearBytes(parentState);
      clearBytes(exactCommit);
      clearBytes(committedState);
      clearBytes(stable?.stateBytes);
      safeFree(applied);
      safeFree(released);
      safeFree(projection);
      safeFree(pending);
      safeFree(group);
    }
  }
}
