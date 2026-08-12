// STYX_SPIKE_PROTOTYPE — explicit, clock-free B2.5b orchestration boundary.

import { B25B_ERROR, failB25B } from './b2-5b-canonical.mjs';

function removePayload(leafIndex) {
  if (!Number.isSafeInteger(leafIndex) || leafIndex < 0 || leafIndex > 0xffffffff) {
    failB25B(B25B_ERROR.INVALID, 'removed leaf index must be one u32');
  }
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, leafIndex, false);
  return bytes;
}

export class B25BCoordinator {
  #journal;
  #adapter;

  constructor({ journal, wasm, beforeCandidate = async () => {} }) {
    if (!journal || typeof journal.createEngineAdapter !== 'function'
      || typeof journal.queueLocal !== 'function') {
      failB25B(B25B_ERROR.INVALID, 'coordinator requires the isolated B2.5b journal');
    }
    this.#journal = journal;
    this.#adapter = journal.createEngineAdapter({ wasm, beforeCandidate });
    Object.freeze(this);
  }

  initializeStable(fields) { return this.#adapter.initializeStable(fields); }

  queueSelfUpdate(groupIdHex) {
    return this.#journal.queueLocal(groupIdHex, 'self-update', new Uint8Array());
  }

  queueAdd(groupIdHex, keyPackageBytes) {
    return this.#journal.queueLocal(groupIdHex, 'add', keyPackageBytes);
  }

  queueRemove(groupIdHex, removedLeafIndex) {
    return this.#journal.queueLocal(groupIdHex, 'remove', removePayload(removedLeafIndex));
  }

  runQueuedOpportunity(groupIdHex) { return this.#adapter.prepareQueued(groupIdHex); }

  recordAttempt(groupIdHex) { return this.#adapter.recordAttempt(groupIdHex); }

  recordAcknowledgement(groupIdHex, attemptOrdinal, recipientIdentityHex, payloadBytes) {
    return this.#adapter.recordAcknowledgement(
      groupIdHex, attemptOrdinal, recipientIdentityHex, payloadBytes,
    );
  }

  recordFailure(groupIdHex, attemptOrdinal, recipientIdentityHex, payloadBytes) {
    return this.#adapter.recordFailure(
      groupIdHex, attemptOrdinal, recipientIdentityHex, payloadBytes,
    );
  }

  cancelBeforeAttempt(groupIdHex) { return this.#adapter.cancelBeforeAttempt(groupIdHex); }

  discardAfterFailure(groupIdHex) { return this.#adapter.discardAfterFailure(groupIdHex); }

  retainCommit(groupIdHex, commitBytes) {
    return this.#adapter.retainCommit(groupIdHex, commitBytes);
  }

  freeze(groupIdHex) { return this.#adapter.freeze(groupIdHex); }

  resolve(batchDigestHex) { return this.#adapter.resolve(batchDigestHex); }

  async settlePass(groupIdHex) {
    const batch = await this.freeze(groupIdHex);
    return this.resolve(batch.protocolBatchDigestHex);
  }
}

export function createB25BCoordinator(options) {
  return new B25BCoordinator(options);
}
