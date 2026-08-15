// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — exact durable-input B3.2a join boundary.

import {
  B32A_ERROR,
  B32A_STATE,
  B32aError,
  b32aProjectionBytes,
  bytesToHex,
  clearBytes,
  failB32a,
  hexToBytes,
  normalizeB32aPreparationEvidence,
  projectB32aNative,
  sha256Hex,
} from './b3-2a-canonical.mjs';

function free(value) {
  try { value?.free?.(); } catch { /* best-effort wasm handle cleanup */ }
}

function exactBytes(left, right) {
  return Buffer.from(left).equals(Buffer.from(right));
}

function rethrowNative(error, operation) {
  if (error instanceof B32aError) throw error;
  failB32a(B32A_ERROR.ENGINE_REJECTED, `${operation} failed closed`, {}, error);
}

export class WasmB32aEngine {
  constructor(wasm) {
    if (!wasm?.PhaseB32aPendingWelcome?.prepare_from_durable_state
      || !wasm?.PhaseB32aGroup?.load_canonical_state) {
      failB32a(B32A_ERROR.INVALID, 'WASM module does not expose the isolated B3.2a surface');
    }
    this.wasm = wasm;
  }

  prepare(inputs) {
    return this.wasm.PhaseB32aPendingWelcome.prepare_from_durable_state(
      inputs.predecessorState,
      inputs.expectedPredecessorSha256,
      inputs.accountIdentity,
      inputs.leafSignatureKey,
      inputs.welcome,
      inputs.keyPackage,
      inputs.expectedAuthor,
    );
  }

  load(candidateState, groupId) {
    return this.wasm.PhaseB32aGroup.load_canonical_state(candidateState, groupId);
  }
}

export class B32aDurableJoinDriver {
  constructor(journal, engine) {
    if (!journal?.read || !journal?.commitJoined || !engine?.prepare || !engine?.load) {
      failB32a(B32A_ERROR.INVALID, 'driver dependencies do not implement the closed B3.2a surface');
    }
    this.journal = journal;
    this.engine = engine;
  }

  async joinRecordedWelcome() {
    const bundle = await this.journal.read();
    if (bundle.head.state !== B32A_STATE.WELCOME_RECORDED) {
      failB32a(B32A_ERROR.STATE_CONFLICT, 'join requires WELCOME_RECORDED');
    }
    const predecessor = Uint8Array.from(bundle.blobs.predecessorBlobSha256Hex);
    const keyPackage = Uint8Array.from(bundle.blobs.keyPackageBlobSha256Hex);
    const welcome = Uint8Array.from(bundle.blobs.welcomeBlobSha256Hex);
    const account = hexToBytes('account identity', bundle.head.accountIdentityHex, {
      min: 32, max: 32,
    });
    const leaf = hexToBytes('leaf signature key', bundle.head.leafSignatureKeyHex, {
      min: 32, max: 32,
    });
    const author = hexToBytes('expected founder', bundle.head.expectedAuthorHex, {
      min: 32, max: 32,
    });
    const predecessorDigest = hexToBytes(
      'predecessor digest', bundle.head.predecessorBlobSha256Hex, { min: 32, max: 32 },
    );
    let pending;
    let nativeProjection;
    let candidate;
    try {
      if (sha256Hex(predecessor) !== bundle.head.predecessorBlobSha256Hex
        || sha256Hex(keyPackage) !== bundle.head.keyPackageBlobSha256Hex
        || sha256Hex(welcome) !== bundle.head.welcomeBlobSha256Hex) {
        failB32a(B32A_ERROR.CORRUPT, 'durable input digest changed before native preparation');
      }
      pending = this.engine.prepare({
        predecessorState: predecessor,
        expectedPredecessorSha256: predecessorDigest,
        accountIdentity: account,
        leafSignatureKey: leaf,
        welcome,
        keyPackage,
        expectedAuthor: author,
      });
      nativeProjection = pending.projection();
      const projection = projectB32aNative(nativeProjection);
      if (projection.predecessorStateSha256Hex !== bundle.head.predecessorBlobSha256Hex
        || projection.expectedKeyPackageSha256Hex !== bundle.head.keyPackageBlobSha256Hex
        || projection.welcomeSha256Hex !== bundle.head.welcomeBlobSha256Hex
        || projection.welcomeAuthor.identityHex !== bundle.head.expectedAuthorHex) {
        failB32a(B32A_ERROR.PROJECTION_MISMATCH, 'native projection does not bind the durable head');
      }
      const own = projection.members.find((member) => member.leafIndex === projection.ownLeafIndex);
      if (own?.identityHex !== bundle.head.accountIdentityHex
        || own?.signatureKeyHex !== bundle.head.leafSignatureKeyHex) {
        failB32a(B32A_ERROR.PROJECTION_MISMATCH, 'native own leaf does not bind the durable head');
      }
      const evidence = normalizeB32aPreparationEvidence({
        classification: pending.preparation_classification(),
        secondCandidateStateSha256Hex:
          bytesToHex(Uint8Array.from(pending.second_candidate_state_sha256())),
        differingStorageKeyHex: bytesToHex(Uint8Array.from(pending.differing_storage_key())),
      }, projection.candidateStateSha256Hex);
      candidate = pending.release_candidate_state(
        hexToBytes('native projection digest', projection.nativeProjectionSha256Hex, {
          min: 32, max: 32,
        }),
        author,
      );
      if (!(candidate instanceof Uint8Array) || !pending.is_consumed()
        || sha256Hex(candidate) !== projection.candidateStateSha256Hex) {
        failB32a(B32A_ERROR.PROJECTION_MISMATCH, 'one-use release changed the candidate commitment');
      }
      await this.#verifyCandidate(candidate, projection);
      const head = await this.journal.commitJoined(candidate, projection, evidence);
      const restarted = await this.verifyJoined();
      if (restarted.projectionRecordSha256Hex !== head.projectionRecordSha256Hex) {
        failB32a(B32A_ERROR.STATE_CONFLICT,
          'post-CAS durable head does not match the committed projection');
      }
      return Object.freeze({
        head,
        projection,
        preparationEvidence: evidence,
        restartedProjectionRecordSha256Hex: restarted.projectionRecordSha256Hex,
      });
    } catch (error) {
      if (pending && !pending.is_consumed?.()) {
        try { pending.discard(); } catch { /* preserve the primary failure */ }
      }
      rethrowNative(error, 'B3.2a durable Welcome join');
    } finally {
      for (const bytes of Object.values(bundle.blobs)) clearBytes(bytes);
      clearBytes(candidate);
      clearBytes(predecessor);
      clearBytes(keyPackage);
      clearBytes(welcome);
      clearBytes(account);
      clearBytes(leaf);
      clearBytes(author);
      clearBytes(predecessorDigest);
      free(nativeProjection);
      free(pending);
    }
  }

  async #verifyCandidate(candidate, projection) {
    let group;
    let nativeProjection;
    let canonicalAgain;
    try {
      group = this.engine.load(
        candidate,
        hexToBytes('group id', projection.groupIdHex, { min: 1, max: 64 }),
      );
      if (!group) failB32a(B32A_ERROR.CORRUPT, 'candidate group is absent after scratch restore');
      canonicalAgain = Uint8Array.from(group.canonical_state());
      if (!exactBytes(canonicalAgain, candidate)) {
        failB32a(B32A_ERROR.CORRUPT, 'canonical candidate changed after scratch restore');
      }
      nativeProjection = group.projection(
        projection.welcomeAuthor.leafIndex,
        hexToBytes('expected founder', projection.welcomeAuthor.identityHex, { min: 32, max: 32 }),
        hexToBytes('own identity', projection.members.find(
          (member) => member.leafIndex === projection.ownLeafIndex,
        ).identityHex, { min: 32, max: 32 }),
        hexToBytes('own signature key', projection.members.find(
          (member) => member.leafIndex === projection.ownLeafIndex,
        ).signatureKeyHex, { min: 32, max: 32 }),
        hexToBytes('Welcome digest', projection.welcomeSha256Hex, { min: 32, max: 32 }),
        hexToBytes('KeyPackage digest', projection.expectedKeyPackageSha256Hex, {
          min: 32, max: 32,
        }),
        hexToBytes('predecessor digest', projection.predecessorStateSha256Hex, {
          min: 32, max: 32,
        }),
        hexToBytes('candidate digest', projection.candidateStateSha256Hex, {
          min: 32, max: 32,
        }),
      );
      const restored = projectB32aNative(nativeProjection);
      if (!exactBytes(b32aProjectionBytes(restored), b32aProjectionBytes(projection))) {
        failB32a(B32A_ERROR.PROJECTION_MISMATCH, 'scratch restore changed the projection');
      }
    } catch (error) {
      rethrowNative(error, 'B3.2a candidate verification');
    } finally {
      clearBytes(canonicalAgain);
      free(nativeProjection);
      free(group);
    }
  }

  async verifyJoined() {
    const activation = await this.journal.activationState();
    if (activation.state !== B32A_STATE.JOINED) {
      clearBytes(activation.bytes);
      failB32a(B32A_ERROR.STATE_CONFLICT, 'fresh activation did not select JOINED');
    }
    try {
      await this.#verifyCandidate(activation.bytes, activation.head.projection);
      return Object.freeze({
        groupIdHex: activation.head.groupIdHex,
        projectionRecordSha256Hex: activation.head.projectionRecordSha256Hex,
        preparationEvidence: activation.head.preparationEvidence,
        state: activation.state,
      });
    } finally {
      clearBytes(activation.bytes);
    }
  }
}
