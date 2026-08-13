// STYX_SPIKE_PROTOTYPE — explicit, clock-free B2.6 orchestration boundary.

import { B26_ERROR, failB26 } from './b2-6-canonical.mjs';

function removePayload(leafIndex) {
  if (!Number.isSafeInteger(leafIndex) || leafIndex < 0 || leafIndex > 0xffffffff) {
    failB26(B26_ERROR.INVALID, 'removed leaf index must be one u32');
  }
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, leafIndex, false);
  return bytes;
}

export class B26Coordinator {
  #adapter;

  constructor({ journal, wasm, beforeReplay = async () => {},
    afterProbeReservation = async () => {},
    beforeOutboundCommit = async () => {},
    beforeInboundCommit = async () => {} }) {
    if (!journal || typeof journal.createEngineAdapter !== 'function') {
      failB26(B26_ERROR.INVALID, 'coordinator requires isolated B2.6 journal');
    }
    this.#adapter = journal.createEngineAdapter({ wasm, beforeReplay, afterProbeReservation,
      beforeOutboundCommit, beforeInboundCommit });
    Object.freeze(this);
  }

  initializeStable(fields) { return this.#adapter.initializeStable(fields); }

  admitCommit(groupIdHex, commitBytes) {
    return this.#adapter.admitCommit(groupIdHex, commitBytes);
  }

  freeze(groupIdHex) { return this.#adapter.freeze(groupIdHex); }

  settle(passDigestHex) { return this.#adapter.settle(passDigestHex); }

  async settlePass(groupIdHex) {
    const pass = await this.freeze(groupIdHex);
    return this.settle(pass.passDigestHex);
  }

  prepareSelfUpdate(groupIdHex) {
    return this.#adapter.prepareLocal(groupIdHex, 'self-update', new Uint8Array());
  }

  prepareAdd(groupIdHex, keyPackageBytes) {
    return this.#adapter.prepareLocal(groupIdHex, 'add', keyPackageBytes);
  }

  prepareRemove(groupIdHex, leafIndex) {
    return this.#adapter.prepareLocal(groupIdHex, 'remove', removePayload(leafIndex));
  }

  recordAttempt(groupIdHex) { return this.#adapter.recordAttempt(groupIdHex); }

  recordAcknowledgement(groupIdHex, attemptOrdinal, recipientIdentityHex, payloadBytes) {
    return this.#adapter.recordAcknowledgement(
      groupIdHex, attemptOrdinal, recipientIdentityHex, payloadBytes);
  }

  recordFailure(groupIdHex, attemptOrdinal, recipientIdentityHex, payloadBytes) {
    return this.#adapter.recordFailure(
      groupIdHex, attemptOrdinal, recipientIdentityHex, payloadBytes);
  }

  recordHistoricalAcknowledgement(groupIdHex, commitDigestHex, attemptOrdinal,
    recipientIdentityHex, payloadBytes) {
    return this.#adapter.recordHistoricalAcknowledgement(
      groupIdHex, commitDigestHex, attemptOrdinal, recipientIdentityHex, payloadBytes);
  }

  cancelBeforeAttempt(groupIdHex) { return this.#adapter.cancelBeforeAttempt(groupIdHex); }

  discardAfterFailure(groupIdHex) { return this.#adapter.discardAfterFailure(groupIdHex); }

  queueApplicationMessage(groupIdHex, requestId, plaintextBytes) {
    return this.#adapter.queueApplicationMessage(groupIdHex, requestId, plaintextBytes);
  }

  readQueuedApplicationMessage(instanceKeyHex, ordinal) {
    return this.#adapter.readQueuedApplicationMessage(instanceKeyHex, ordinal);
  }

  recordApplicationAttempt(instanceKeyHex, ordinal, recipientIdentityHex) {
    return this.#adapter.recordApplicationAttempt(
      instanceKeyHex, ordinal, recipientIdentityHex);
  }

  recordApplicationAcknowledgement(instanceKeyHex, ordinal, attemptOrdinal,
    recipientIdentityHex, payloadBytes) {
    return this.#adapter.recordApplicationAcknowledgement(
      instanceKeyHex, ordinal, attemptOrdinal, recipientIdentityHex, payloadBytes);
  }

  recordApplicationFailure(instanceKeyHex, ordinal, attemptOrdinal,
    recipientIdentityHex, payloadBytes) {
    return this.#adapter.recordApplicationFailure(
      instanceKeyHex, ordinal, attemptOrdinal, recipientIdentityHex, payloadBytes);
  }

  discardApplicationAfterFailure(instanceKeyHex, ordinal) {
    return this.#adapter.discardApplicationAfterFailure(instanceKeyHex, ordinal);
  }

  processApplicationMessage(groupIdHex, ciphertextBytes,
    retainedSnapshotDigestHex = null) {
    return this.#adapter.processApplicationMessage(
      groupIdHex, ciphertextBytes, retainedSnapshotDigestHex);
  }

  createLivenessProbe(groupIdHex, plaintextBytes) {
    return this.#adapter.createLivenessProbe(groupIdHex, plaintextBytes);
  }

  processLivenessProbe(groupIdHex, ciphertextBytes) {
    return this.#adapter.processLivenessProbe(groupIdHex, ciphertextBytes);
  }

  completeLivenessProbe(probe, peerIdentityHex) {
    return this.#adapter.completeLivenessProbe(probe, peerIdentityHex);
  }
}

export function createB26Coordinator(options) {
  return new B26Coordinator(options);
}
