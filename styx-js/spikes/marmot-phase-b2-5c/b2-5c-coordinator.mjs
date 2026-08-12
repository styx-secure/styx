// STYX_SPIKE_PROTOTYPE — explicit, clock-free B2.5c orchestration boundary.

import { B25C_ERROR, failB25C } from './b2-5c-canonical.mjs';

function removePayload(leafIndex) {
  if (!Number.isSafeInteger(leafIndex) || leafIndex < 0 || leafIndex > 0xffffffff) {
    failB25C(B25C_ERROR.INVALID, 'removed leaf index must be one u32');
  }
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, leafIndex, false);
  return bytes;
}

export class B25CCoordinator {
  #adapter;

  constructor({ journal, wasm, beforeReplay = async () => {},
    afterProbeReservation = async () => {} }) {
    if (!journal || typeof journal.createEngineAdapter !== 'function') {
      failB25C(B25C_ERROR.INVALID, 'coordinator requires isolated B2.5c journal');
    }
    this.#adapter = journal.createEngineAdapter({ wasm, beforeReplay, afterProbeReservation });
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

export function createB25CCoordinator(options) {
  return new B25CCoordinator(options);
}
