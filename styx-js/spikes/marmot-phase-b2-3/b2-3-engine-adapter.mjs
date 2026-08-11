// STYX_SPIKE_PROTOTYPE — disposable OpenMLS composition for Phase B2.3.

import {
  B23_DB_PREFIX,
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
} from './b2-3-canonical.mjs';
import { HEAD_PREPARED, HEAD_STABLE, canonicalProjectionBytes } from './b2-3-record.mjs';
import { B23Journal } from './b2-3-journal.mjs';

function safeFree(value) {
  if (value && typeof value.free === 'function') {
    try { value.free(); } catch { /* best-effort release; never changes durable state */ }
  }
}

function boundedU16(name, value) {
  if (!(value instanceof Uint16Array) || value.length > 64) {
    fail(B23_ERROR.RESOURCE_LIMIT, `${name} is not a bounded Uint16Array`);
  }
  return Array.from(value);
}

function optionalBytesHex(value) {
  return value === undefined ? null : bytesToHex(value);
}

function optionalNumber(value) {
  if (value === undefined) return null;
  return assertSafeInteger('optional projection integer', value, 0, 0xffffffff);
}

function optionalU16(value) {
  return value === undefined ? null : boundedU16('optional component ids', value);
}

function freezeProjection(value) {
  for (const member of value.candidateMembers) Object.freeze(member);
  for (const proposal of value.proposals) Object.freeze(proposal);
  if (value.updatePath !== null) Object.freeze(value.updatePath);
  Object.freeze(value.candidateMembers);
  Object.freeze(value.proposals);
  Object.freeze(value.requiredComponentIds);
  const frozen = Object.freeze(value);
  canonicalProjectionBytes(frozen);
  return frozen;
}

/** Complete bounded B2.2 projection, represented only by primitives/arrays. */
export function projectB2Commit(projection) {
  const memberCount = assertSafeInteger(
    'candidate member count', projection.candidate_member_count(), 1, B23_LIMITS.maxMembers,
  );
  const proposalCount = assertSafeInteger(
    'proposal count', projection.proposal_count(), 0, B23_LIMITS.maxProposals,
  );
  const candidateMembers = [];
  let priorLeaf = -1;
  for (let index = 0; index < memberCount; index += 1) {
    const leafIndex = assertSafeInteger('candidate leaf index', projection.candidate_leaf_index(index), 0, 0xffffffff);
    if (leafIndex <= priorLeaf) fail(B23_ERROR.ENGINE_REJECTED, 'candidate leaves are not strictly ordered');
    priorLeaf = leafIndex;
    const identity = projection.candidate_identity(index);
    const signatureKey = projection.candidate_signature_key(index);
    const proof = projection.candidate_identity_proof(index);
    assertBytes('candidate identity', identity, { min: 32, max: 32 });
    assertBytes('candidate signature key', signatureKey, { min: 32, max: 32 });
    assertBytes('candidate identity proof', proof, { min: 104, max: 104 });
    candidateMembers.push({
      leafIndex,
      identityHex: bytesToHex(identity),
      signatureKeyHex: bytesToHex(signatureKey),
      identityProofHex: bytesToHex(proof),
      componentIds: boundedU16('candidate component ids', projection.candidate_component_ids(index)),
      supportedComponentIds: boundedU16(
        'candidate supported component ids', projection.candidate_supported_component_ids(index),
      ),
    });
  }
  const proposals = [];
  for (let index = 0; index < proposalCount; index += 1) {
    proposals.push({
      kind: projection.proposal_kind(index),
      source: projection.proposal_source(index),
      senderSource: projection.proposal_sender_source(index),
      senderLeafIndex: assertSafeInteger(
        'proposal sender leaf', projection.proposal_sender_leaf_index(index), 0, 0xffffffff,
      ),
      addedLeafIndex: optionalNumber(projection.proposal_added_leaf_index(index)),
      addedIdentityHex: optionalBytesHex(projection.proposal_added_identity(index)),
      addedSignatureKeyHex: optionalBytesHex(projection.proposal_added_signature_key(index)),
      addedIdentityProofHex: optionalBytesHex(projection.proposal_added_identity_proof(index)),
      addedComponentIds: optionalU16(projection.proposal_added_component_ids(index)),
      addedSupportedComponentIds: optionalU16(projection.proposal_added_supported_component_ids(index)),
      removedParentLeafIndex: optionalNumber(projection.proposal_removed_parent_leaf_index(index)),
      removedIdentityHex: optionalBytesHex(projection.proposal_removed_identity(index)),
      removedSignatureKeyHex: optionalBytesHex(projection.proposal_removed_signature_key(index)),
      removedIdentityProofHex: optionalBytesHex(projection.proposal_removed_identity_proof(index)),
    });
  }
  const updatePath = projection.has_update_path() ? {
    leafIndex: optionalNumber(projection.update_path_leaf_index()),
    identityHex: optionalBytesHex(projection.update_path_identity()),
    signatureKeyHex: optionalBytesHex(projection.update_path_signature_key()),
    identityProofHex: optionalBytesHex(projection.update_path_identity_proof()),
    componentIds: optionalU16(projection.update_path_component_ids()),
    supportedComponentIds: optionalU16(projection.update_path_supported_component_ids()),
  } : null;
  const candidateGroupContextTls = projection.candidate_group_context_tls();
  assertBytes('candidate GroupContext TLS', candidateGroupContextTls, {
    min: 1, max: B23_LIMITS.maxGroupContextBytes,
  });
  const verifiedLeafDigest = projection.verified_leaf_digest();
  assertBytes('verified-leaf digest', verifiedLeafDigest, { min: 32, max: 32 });
  return freezeProjection({
    format: 'styx-b2-3-projection',
    version: 1,
    priorEpochDec: epochToDecimal(projection.prior_epoch()),
    candidateEpochDec: epochToDecimal(projection.candidate_epoch()),
    committerSource: projection.committer_source(),
    committerLeafIndex: assertSafeInteger('committer leaf', projection.committer_leaf_index(), 0, 0xffffffff),
    committerIdentityHex: bytesToHex(projection.committer_identity()),
    committerSignatureKeyHex: bytesToHex(projection.committer_signature_key()),
    administratorPolicyHex: bytesToHex(projection.administrator_policy()),
    lifecycleHex: bytesToHex(projection.lifecycle()),
    requiredComponentIds: boundedU16('required component ids', projection.required_component_ids()),
    candidateGroupContextTlsHex: bytesToHex(candidateGroupContextTls),
    candidateGroupContextDigestHex: bytesToHex(projection.candidate_group_context_sha256()),
    verifiedLeafDigestHex: bytesToHex(verifiedLeafDigest),
    candidateMembers,
    proposals,
    updatePath,
  });
}

function projectionDigest(projection) {
  return digestHex(canonicalProjectionBytes(projection));
}

function sessionDispose(session) {
  if (!session) return;
  safeFree(session.group);
  safeFree(session.identity);
  safeFree(session.provider);
  session.group = null;
  session.identity = null;
  session.provider = null;
}

export class B23EngineAdapter {
  constructor({ wasm, journal }) {
    if (!wasm?.Provider || !wasm?.PhaseB2Group || !wasm?.PhaseB2Identity) {
      fail(B23_ERROR.INVALID, 'the exact initialized B2.2 WASM module is required');
    }
    if (!(journal instanceof B23Journal)
      || typeof journal.db?.name !== 'string'
      || !journal.db.name.startsWith(B23_DB_PREFIX)) {
      fail(B23_ERROR.INVALID, 'the exact B2.3 journal and namespace are required');
    }
    this.wasm = wasm;
    this.journal = journal;
  }

  restoreBundle(bundle) {
    const { head, transition, snapshotBytes } = bundle;
    let provider;
    let identity;
    let group;
    try {
      validateProviderSnapshot(snapshotBytes);
      provider = new this.wasm.Provider();
      provider.restore_state(snapshotBytes);
      const accountKey = hexToBytes('accountKeyHex', head.accountKeyHex);
      const signatureKey = hexToBytes('signatureKeyHex', head.signatureKeyHex);
      const groupId = hexToBytes('groupIdHex', head.groupIdHex);
      identity = this.wasm.PhaseB2Identity.load(provider, accountKey, signatureKey);
      if (identity === undefined) fail(B23_ERROR.ENGINE_REJECTED, 'identity is absent from the restored Provider');
      group = this.wasm.PhaseB2Group.load(provider, groupId);
      if (group === undefined) fail(B23_ERROR.ENGINE_REJECTED, 'group is absent from the restored Provider');
      if (!group.matches_own_identity(accountKey, signatureKey)) {
        fail(B23_ERROR.ENGINE_REJECTED, 'restored group does not match the durable own identity');
      }
      if (epochToDecimal(group.epoch()) !== head.epochDec
        || bytesToHex(group.group_context_sha256(provider)) !== head.epochDigestHex) {
        fail(B23_ERROR.ENGINE_REJECTED, 'restored GroupContext does not match the durable epoch identity');
      }
      const hasPending = group.has_pending_commit(provider);
      if (hasPending !== (head.state === HEAD_PREPARED)) {
        fail(B23_ERROR.ENGINE_REJECTED, 'restored pending state does not match the durable head');
      }
      if (head.state === HEAD_PREPARED) {
        const pendingProjection = group.pending_projection(provider);
        if (pendingProjection === undefined) fail(B23_ERROR.ENGINE_REJECTED, 'durable pending projection is absent');
        try {
          const projected = projectB2Commit(pendingProjection);
          if (projectionDigest(projected) !== transition.projectionDigestHex
            || projected.candidateEpochDec !== head.candidateEpochDec
            || projected.candidateGroupContextDigestHex !== head.candidateEpochDigestHex
            || projected.verifiedLeafDigestHex !== head.verifiedLeafDigestHex) {
            fail(B23_ERROR.ENGINE_REJECTED, 'restored pending projection does not match durable evidence');
          }
        } finally {
          safeFree(pendingProjection);
        }
      }
      return { provider, identity, group, accountKey, signatureKey, groupId };
    } catch (error) {
      sessionDispose({ provider, identity, group });
      if (error?.code) throw error;
      fail(B23_ERROR.ENGINE_REJECTED, 'OpenMLS restore or binding validation failed', {}, error);
    }
  }

  async initializeStable({ snapshotBytes, groupId, accountKey, signatureKey }) {
    assertBytes('groupId', groupId, { min: 1, max: 64 });
    assertBytes('accountKey', accountKey, { min: 32, max: 32 });
    assertBytes('signatureKey', signatureKey, { min: 32, max: 32 });
    assertBytes('snapshotBytes', snapshotBytes, { min: 1, max: B23_LIMITS.maxSnapshotBytes });
    validateProviderSnapshot(snapshotBytes);
    const provisional = {
      head: {
        groupIdHex: bytesToHex(groupId), accountKeyHex: bytesToHex(accountKey),
        signatureKeyHex: bytesToHex(signatureKey), state: HEAD_STABLE,
      },
      snapshotBytes,
    };
    let provider;
    let identity;
    let group;
    try {
      provider = new this.wasm.Provider();
      provider.restore_state(snapshotBytes);
      identity = this.wasm.PhaseB2Identity.load(provider, accountKey, signatureKey);
      group = this.wasm.PhaseB2Group.load(provider, groupId);
      if (identity === undefined || group === undefined || !group.matches_own_identity(accountKey, signatureKey)
        || group.has_pending_commit(provider)) {
        fail(B23_ERROR.ENGINE_REJECTED, 'initial snapshot is not an exact stable one-group binding');
      }
      return await this.journal.initialize({
        bindings: {
          groupIdHex: provisional.head.groupIdHex,
          accountKeyHex: provisional.head.accountKeyHex,
          signatureKeyHex: provisional.head.signatureKeyHex,
        },
        snapshotBytes,
        epochDec: epochToDecimal(group.epoch()),
        epochDigestHex: bytesToHex(group.group_context_sha256(provider)),
      });
    } catch (error) {
      if (error?.code) throw error;
      fail(B23_ERROR.ENGINE_REJECTED, 'OpenMLS stable initialization failed', {}, error);
    } finally {
      sessionDispose({ provider, identity, group });
    }
  }

  async prepare(groupIdHex, operation) {
    const bundle = await this.journal.read(groupIdHex);
    if (bundle.head.state !== HEAD_STABLE) fail(B23_ERROR.STATE_CONFLICT, 'prepare requires a stable head');
    const session = this.restoreBundle(bundle);
    let keyPackage;
    let pending;
    let projectionHandle;
    try {
      if (operation?.kind === 'self-update') {
        pending = session.group.prepare_self_update(session.provider, session.identity);
      } else if (operation?.kind === 'add') {
        assertBytes('keyPackageBytes', operation.keyPackageBytes, { min: 1, max: B23_LIMITS.maxCommitBytes });
        keyPackage = this.wasm.PhaseB2KeyPackage.from_framed_bytes(operation.keyPackageBytes);
        pending = session.group.prepare_add(session.provider, session.identity, keyPackage);
      } else if (operation?.kind === 'remove') {
        assertSafeInteger('removedLeafIndex', operation.removedLeafIndex, 0, 0xffffffff);
        pending = session.group.prepare_remove(session.provider, session.identity, operation.removedLeafIndex);
      } else {
        fail(B23_ERROR.INVALID, 'prepare operation kind is invalid');
      }
      const commitBytes = copyBytes(pending.commit());
      const welcome = pending.welcome();
      const welcomeBytes = welcome === undefined ? null : copyBytes(welcome);
      projectionHandle = pending.projection();
      const projection = projectB2Commit(projectionHandle);
      const snapshotBytes = copyBytes(session.provider.serialize_state());
      const projectionDigestHex = projectionDigest(projection);
      const commitDigestHex = digestHex(commitBytes);
      const welcomeDigestHex = welcomeBytes === null ? null : digestHex(welcomeBytes);
      const result = await this.journal.cas({
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
          epochDec: bundle.head.epochDec,
          epochDigestHex: bundle.head.epochDigestHex,
          pendingCommitDigestHex: commitDigestHex,
          pendingWelcomeDigestHex: welcomeDigestHex,
          candidateEpochDec: projection.candidateEpochDec,
          candidateEpochDigestHex: projection.candidateGroupContextDigestHex,
          verifiedLeafDigestHex: projection.verifiedLeafDigestHex,
          artifactId: null, artifactDigestHex: null,
          publishAttempts: 0, evidenceCount: 0,
          lastAppliedCommitDigestHex: bundle.head.lastAppliedCommitDigestHex,
        },
      });
      return {
        head: result.head,
        commitBytes: copyBytes(commitBytes),
        welcomeBytes: copyBytes(welcomeBytes),
        projection,
      };
    } catch (error) {
      if (error?.code) throw error;
      fail(B23_ERROR.ENGINE_REJECTED, 'OpenMLS outbound preparation failed', {}, error);
    } finally {
      safeFree(projectionHandle);
      safeFree(pending);
      safeFree(keyPackage);
      sessionDispose(session);
    }
  }

  async cancelBeforeAttempt(groupIdHex) {
    const bundle = await this.journal.read(groupIdHex);
    if (bundle.head.state !== HEAD_PREPARED || bundle.head.publishAttempts !== 0) {
      fail(B23_ERROR.STATE_CONFLICT, 'discard is allowed only before the first publication attempt');
    }
    const session = this.restoreBundle(bundle);
    try {
      session.group.clear_pending_commit(
        session.provider, BigInt(bundle.head.epochDec), session.accountKey, session.signatureKey,
      );
      const snapshotBytes = copyBytes(session.provider.serialize_state());
      if (session.group.has_pending_commit(session.provider)
        || epochToDecimal(session.group.epoch()) !== bundle.head.epochDec
        || bytesToHex(session.group.group_context_sha256(session.provider)) !== bundle.head.epochDigestHex) {
        fail(B23_ERROR.ENGINE_REJECTED, 'pending clear did not restore the exact stable epoch');
      }
      return await this.journal.cas({
        expectedHead: bundle.head,
        snapshotBytes,
        transitionFields: {
          kind: 'discard', state: HEAD_STABLE,
          epochDec: bundle.head.epochDec, epochDigestHex: bundle.head.epochDigestHex,
          commitBytes: copyBytes(bundle.transition.commitBytes),
          welcomeBytes: copyBytes(bundle.transition.welcomeBytes),
          projection: bundle.transition.projection,
          projectionDigestHex: bundle.transition.projectionDigestHex,
          candidateEpochDec: bundle.transition.candidateEpochDec,
          candidateEpochDigestHex: bundle.transition.candidateEpochDigestHex,
          verifiedLeafDigestHex: bundle.transition.verifiedLeafDigestHex,
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
    } catch (error) {
      if (error?.code) throw error;
      fail(B23_ERROR.ENGINE_REJECTED, 'OpenMLS pending discard failed', {}, error);
    } finally {
      sessionDispose(session);
    }
  }

  async confirmAfterAttempt(groupIdHex) {
    const bundle = await this.journal.read(groupIdHex);
    if (bundle.head.state !== HEAD_PREPARED || bundle.head.publishAttempts < 1) {
      fail(B23_ERROR.STATE_CONFLICT, 'confirmation requires a durable publication attempt');
    }
    const session = this.restoreBundle(bundle);
    try {
      const verifiedDigest = hexToBytes('verifiedLeafDigestHex', bundle.head.verifiedLeafDigestHex);
      session.group.confirm_pending_commit(
        session.provider, BigInt(bundle.head.epochDec), session.accountKey,
        session.signatureKey, verifiedDigest,
      );
      if (epochToDecimal(session.group.epoch()) !== bundle.head.candidateEpochDec
        || bytesToHex(session.group.group_context_sha256(session.provider)) !== bundle.head.candidateEpochDigestHex
        || session.group.has_pending_commit(session.provider)) {
        fail(B23_ERROR.ENGINE_REJECTED, 'pending confirmation produced an unexpected successor');
      }
      const snapshotBytes = copyBytes(session.provider.serialize_state());
      const appliedCommitDigestHex = digestHex(bundle.transition.commitBytes);
      return await this.journal.cas({
        expectedHead: bundle.head,
        snapshotBytes,
        transitionFields: {
          kind: 'confirm', state: HEAD_STABLE,
          epochDec: bundle.head.candidateEpochDec,
          epochDigestHex: bundle.head.candidateEpochDigestHex,
          ...{
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
            appliedCommitDigestHex,
          },
        },
        headFields: {
          state: HEAD_STABLE,
          epochDec: bundle.head.candidateEpochDec,
          epochDigestHex: bundle.head.candidateEpochDigestHex,
          pendingCommitDigestHex: null, pendingWelcomeDigestHex: null,
          candidateEpochDec: null, candidateEpochDigestHex: null,
          verifiedLeafDigestHex: null, artifactId: null, artifactDigestHex: null,
          publishAttempts: 0, evidenceCount: 0, lastAppliedCommitDigestHex: appliedCommitDigestHex,
        },
      });
    } catch (error) {
      if (error?.code) throw error;
      fail(B23_ERROR.ENGINE_REJECTED, 'OpenMLS pending confirmation failed', {}, error);
    } finally {
      sessionDispose(session);
    }
  }

  async acceptInbound(groupIdHex, commitBytes, decision) {
    assertBytes('inbound Commit', commitBytes, { min: 1, max: B23_LIMITS.maxCommitBytes });
    const exactCommit = copyBytes(commitBytes);
    const commitDigestHex = digestHex(exactCommit);
    const bundle = await this.journal.read(groupIdHex);
    if (bundle.head.lastAppliedCommitDigestHex === commitDigestHex) {
      return { status: 'duplicate', head: bundle.head };
    }
    if (bundle.head.state !== HEAD_STABLE) {
      fail(B23_ERROR.STATE_CONFLICT, 'inbound Commit requires a stable head');
    }
    const session = this.restoreBundle(bundle);
    let staged;
    let projectionHandle;
    try {
      const preStageSnapshot = session.provider.serialize_state();
      staged = session.group.stage_inbound_commit(session.provider, exactCommit);
      projectionHandle = staged.projection();
      const projection = projectB2Commit(projectionHandle);
      const postStageSnapshot = session.provider.serialize_state();
      if (!bytesEqual(preStageSnapshot, postStageSnapshot)) {
        fail(B23_ERROR.ENGINE_REJECTED, 'inbound staging changed Provider state');
      }
      const allowed = typeof decision === 'function' ? decision(projection) : decision;
      if (allowed && typeof allowed.then === 'function') {
        fail(B23_ERROR.INVALID, 'inbound decision must be synchronous');
      }
      if (allowed !== true) {
        session.group.discard_staged_commit(session.provider, staged);
        return { status: 'rejected', head: bundle.head, projection };
      }
      session.group.merge_staged_commit(
        session.provider, staged, hexToBytes('verifiedLeafDigestHex', projection.verifiedLeafDigestHex),
      );
      const successorEpochDec = epochToDecimal(session.group.epoch());
      const successorEpochDigestHex = bytesToHex(session.group.group_context_sha256(session.provider));
      if (successorEpochDec !== projection.candidateEpochDec
        || successorEpochDigestHex !== projection.candidateGroupContextDigestHex) {
        fail(B23_ERROR.ENGINE_REJECTED, 'inbound merge produced an unexpected successor');
      }
      const snapshotBytes = copyBytes(session.provider.serialize_state());
      const projectionDigestHex = projectionDigest(projection);
      const result = await this.journal.cas({
        expectedHead: bundle.head,
        snapshotBytes,
        transitionFields: {
          kind: 'inbound-accept', state: HEAD_STABLE,
          epochDec: successorEpochDec, epochDigestHex: successorEpochDigestHex,
          commitBytes: exactCommit, welcomeBytes: null, projection, projectionDigestHex,
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
          publishAttempts: 0, evidenceCount: 0, lastAppliedCommitDigestHex: commitDigestHex,
        },
      });
      return { status: 'accepted', head: result.head, projection };
    } catch (error) {
      if (!error?.code) fail(B23_ERROR.ENGINE_REJECTED, 'inbound staging or merge failed', {}, error);
      throw error;
    } finally {
      safeFree(projectionHandle);
      safeFree(staged);
      sessionDispose(session);
    }
  }

  async recoveryState(groupIdHex) {
    const bundle = await this.journal.read(groupIdHex);
    if (bundle.head.state === HEAD_STABLE) return Object.freeze({ action: 'resume-stable', head: bundle.head });
    if (bundle.head.publishAttempts === 0) {
      return Object.freeze({ action: 'discard-or-publish', head: bundle.head });
    }
    return Object.freeze({ action: 'confirm-and-retry-exact-artifact', head: bundle.head });
  }
}
