// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — trusted write-ahead B3.3a WASM adapter.

import { verifyAccountIdentityProofV2 }
  from '../marmot-phase-b1/identity-proof-v2.js';
import {
  B33A_ERROR,
  B33A_OUTCOME,
  B33aError,
  assertBytes,
  bytesToHex,
  clearBytes,
  copyBytes,
  decodeMarmotAppEvent,
  failB33a,
  hexToBytes,
  sha256Hex,
} from './b3-3a-canonical.mjs';

function safeFree(value) {
  if (value && typeof value.free === 'function') {
    try { value.free(); } catch { /* cleanup cannot change durable authority */ }
  }
}

function decimalEpoch(value) {
  try {
    const epoch = BigInt(value);
    if (epoch < 0n) throw new Error('negative epoch');
    return epoch.toString(10);
  } catch (error) {
    failB33a(B33A_ERROR.ENGINE_REJECTED, 'WASM returned an invalid epoch', {}, error);
  }
}

function exactBytes(left, right) {
  return left.byteLength === right.byteLength
    && Buffer.from(left).equals(Buffer.from(right));
}

function reverifySourceProofs(head) {
  const projection = head.sourceB32aHead.value.projection;
  for (const member of projection.members) {
    const proof = hexToBytes('member identity proof', member.identityProofHex, 104);
    const identity = hexToBytes('member identity', member.identityHex, 32);
    const signatureKey = hexToBytes('member signature key', member.signatureKeyHex, 32);
    try {
      verifyAccountIdentityProofV2(proof, identity, signatureKey);
    } catch (error) {
      failB33a(B33A_ERROR.ENGINE_REJECTED,
        'B3.2a member account-identity-proof v2 no longer verifies',
        { leafIndex: member.leafIndex }, error);
    } finally {
      clearBytes(proof);
      clearBytes(identity);
      clearBytes(signatureKey);
    }
  }
  return projection;
}

function requireMember(projection, leafIndex, identityHex, signatureKeyHex) {
  const matches = projection.members.filter((member) => member.leafIndex === leafIndex);
  if (matches.length !== 1 || matches[0].identityHex !== identityHex
    || matches[0].signatureKeyHex !== signatureKeyHex) {
    failB33a(B33A_ERROR.ENGINE_REJECTED,
      'WASM-authenticated sender differs from the exact B3.2a roster');
  }
  return matches[0];
}

function requirePendingContext(pending, head) {
  if (bytesToHex(Uint8Array.from(pending.group_id())) !== head.groupIdHex
    || decimalEpoch(pending.epoch()) !== head.epochDec) {
    failB33a(B33A_ERROR.ENGINE_REJECTED,
      'WASM operation differs from its durable group or epoch');
  }
}

export class B33aApplicationAdapter {
  constructor({ journal, wasm }) {
    if (!journal || typeof journal.readCurrent !== 'function'
      || typeof journal.commitOutbound !== 'function'
      || typeof journal.commitInbound !== 'function'
      || typeof journal.duplicateInbound !== 'function'
      || !wasm || typeof wasm.PhaseB33aGroup !== 'function') {
      failB33a(B33A_ERROR.INVALID, 'adapter dependencies are incomplete');
    }
    this.journal = journal;
    this.wasm = wasm;
  }

  async initializeFromB32a(joinedHead, canonicalState) {
    return this.journal.initializeFromB32a(joinedHead, canonicalState);
  }

  #loadGroup(current) {
    reverifySourceProofs(current.head);
    const groupId = hexToBytes('group id', current.head.groupIdHex);
    const identity = hexToBytes('account identity', current.head.accountIdentityHex, 32);
    const signatureKey = hexToBytes('leaf signature key', current.head.leafSignatureKeyHex, 32);
    try {
      const group = this.wasm.PhaseB33aGroup.load_canonical_state(
        current.stateBytes, groupId, identity, signatureKey,
      );
      if (!group) {
        failB33a(B33A_ERROR.ENGINE_REJECTED, 'canonical state does not contain the exact group');
      }
      return group;
    } catch (error) {
      if (error instanceof B33aError) throw error;
      failB33a(B33A_ERROR.ENGINE_REJECTED, 'WASM rejected canonical B3.3a activation', {}, error);
    } finally {
      clearBytes(groupId);
      clearBytes(identity);
      clearBytes(signatureKey);
    }
  }

  async send(requestId, eventBytes) {
    const current = await this.journal.readCurrent();
    let group;
    let pending;
    let release;
    let candidateState;
    let ciphertext;
    let durable;
    try {
      const duplicate = current.head.outboundRecords.find(
        (record) => record.requestId === requestId,
      );
      if (duplicate) {
        return Object.freeze({ status: B33A_OUTCOME.DUPLICATE,
          requestId, eventIdHex: duplicate.eventIdHex });
      }
      const event = decodeMarmotAppEvent(eventBytes, current.head.accountIdentityHex);
      const projection = reverifySourceProofs(current.head);
      group = this.#loadGroup(current);
      try { pending = group.prepare_outbound(eventBytes); } catch (error) {
        failB33a(B33A_ERROR.ENGINE_REJECTED, 'WASM rejected outbound application data', {}, error);
      }
      requirePendingContext(pending, current.head);
      const senderIdentityHex = bytesToHex(Uint8Array.from(
        pending.sender_credential_identity(),
      ));
      const senderSignatureKeyHex = bytesToHex(Uint8Array.from(
        pending.sender_signature_key(),
      ));
      const own = requireMember(
        projection, projection.ownLeafIndex, senderIdentityHex, senderSignatureKeyHex,
      );
      if (own.identityHex !== current.head.accountIdentityHex
        || own.signatureKeyHex !== current.head.leafSignatureKeyHex) {
        failB33a(B33A_ERROR.ENGINE_REJECTED, 'outbound sender is not the durable local identity');
      }
      const expectedStateDigest = Uint8Array.from(pending.canonical_state_sha256());
      const expectedCiphertextDigest = Uint8Array.from(pending.ciphertext_sha256());
      release = pending.release(expectedStateDigest, expectedCiphertextDigest);
      candidateState = Uint8Array.from(release.take_canonical_state());
      ciphertext = Uint8Array.from(release.take_ciphertext());
      if (sha256Hex(candidateState) !== bytesToHex(expectedStateDigest)
        || sha256Hex(ciphertext) !== bytesToHex(expectedCiphertextDigest)) {
        failB33a(B33A_ERROR.ENGINE_REJECTED, 'released outbound bytes break their WASM digest binding');
      }
      durable = await this.journal.commitOutbound(current.head.headDigestHex, {
        requestId,
        eventIdHex: event.id,
        candidateState,
        ciphertext,
        senderIdentityHex,
        senderSignatureKeyHex,
      });
      const resultCiphertext = copyBytes(durable.ciphertext);
      return Object.freeze({ status: B33A_OUTCOME.COMMITTED, requestId,
        eventIdHex: event.id, ciphertextBytes: resultCiphertext,
        headDigestHex: durable.head.headDigestHex });
    } catch (error) {
      if (error instanceof B33aError) throw error;
      failB33a(B33A_ERROR.ENGINE_REJECTED, 'outbound operation failed closed', {}, error);
    } finally {
      try { if (pending && !pending.is_consumed()) pending.discard(); } catch { /* best effort */ }
      clearBytes(current.stateBytes);
      clearBytes(candidateState);
      clearBytes(ciphertext);
      clearBytes(durable?.stateBytes);
      clearBytes(durable?.ciphertext);
      safeFree(release);
      safeFree(pending);
      safeFree(group);
    }
  }

  async receive(ciphertextBytes) {
    assertBytes('inbound ciphertext', ciphertextBytes, { min: 1, max: 1024 * 1024 });
    const ciphertextDigestHex = sha256Hex(ciphertextBytes);
    const duplicate = await this.journal.duplicateInbound(ciphertextDigestHex);
    if (duplicate !== null) return duplicate;

    const current = await this.journal.readCurrent();
    let group;
    let pending;
    let release;
    let candidateState;
    let retainedCiphertext;
    let plaintext;
    let durable;
    try {
      const projection = reverifySourceProofs(current.head);
      group = this.#loadGroup(current);
      try { pending = group.prepare_inbound(ciphertextBytes); } catch (error) {
        failB33a(B33A_ERROR.ENGINE_REJECTED, 'WASM rejected inbound application data', {}, error);
      }
      requirePendingContext(pending, current.head);
      const senderLeafIndex = pending.sender_leaf_index();
      const senderIdentityHex = bytesToHex(Uint8Array.from(
        pending.sender_credential_identity(),
      ));
      const senderSignatureKeyHex = bytesToHex(Uint8Array.from(
        pending.sender_signature_key(),
      ));
      requireMember(projection, senderLeafIndex, senderIdentityHex, senderSignatureKeyHex);
      if (senderIdentityHex === current.head.accountIdentityHex) {
        failB33a(B33A_ERROR.ENGINE_REJECTED, 'own-ciphertext echo is not inbound traffic');
      }
      const expectedStateDigest = Uint8Array.from(pending.canonical_state_sha256());
      const expectedCiphertextDigest = Uint8Array.from(pending.ciphertext_sha256());
      const expectedPlaintextDigest = Uint8Array.from(pending.plaintext_sha256());
      release = pending.release(
        expectedStateDigest, expectedCiphertextDigest, expectedPlaintextDigest,
      );
      candidateState = Uint8Array.from(release.take_canonical_state());
      retainedCiphertext = Uint8Array.from(release.take_ciphertext());
      plaintext = Uint8Array.from(release.take_plaintext());
      if (!exactBytes(retainedCiphertext, ciphertextBytes)
        || sha256Hex(candidateState) !== bytesToHex(expectedStateDigest)
        || sha256Hex(retainedCiphertext) !== bytesToHex(expectedCiphertextDigest)
        || sha256Hex(plaintext) !== bytesToHex(expectedPlaintextDigest)) {
        failB33a(B33A_ERROR.ENGINE_REJECTED, 'released inbound bytes break their WASM binding');
      }
      const event = decodeMarmotAppEvent(plaintext, senderIdentityHex);
      durable = await this.journal.commitInbound(current.head.headDigestHex, {
        candidateState,
        ciphertext: retainedCiphertext,
        plaintext,
        eventIdHex: event.id,
        senderLeafIndex,
        senderIdentityHex,
        senderSignatureKeyHex,
        verifiedLeafDigestHex: projection.verifiedLeafDigestHex,
      });
      const resultPlaintext = copyBytes(durable.plaintext);
      return Object.freeze({ status: B33A_OUTCOME.COMMITTED,
        eventIdHex: event.id, plaintextBytes: resultPlaintext,
        senderLeafIndex, senderIdentityHex, senderSignatureKeyHex,
        verifiedLeafDigestHex: projection.verifiedLeafDigestHex,
        headDigestHex: durable.head.headDigestHex });
    } catch (error) {
      if (error instanceof B33aError) throw error;
      failB33a(B33A_ERROR.ENGINE_REJECTED, 'inbound operation failed closed', {}, error);
    } finally {
      try { if (pending && !pending.is_consumed()) pending.discard(); } catch { /* best effort */ }
      clearBytes(current.stateBytes);
      clearBytes(candidateState);
      clearBytes(retainedCiphertext);
      clearBytes(plaintext);
      clearBytes(durable?.stateBytes);
      clearBytes(durable?.ciphertext);
      clearBytes(durable?.plaintext);
      safeFree(release);
      safeFree(pending);
      safeFree(group);
    }
  }
}
