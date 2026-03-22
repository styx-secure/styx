// styx-js/src/ledger/pruning.js
// GDPR-compliant pruning protocol and retention management

import { EventType, PruneReason } from './event.js';

/** @enum {string} */
export const PruneState = {
  IDLE: 'idle',
  REQUEST_SENT: 'requestSent',
  WAITING_ACK: 'waitingAck',
  PRUNED: 'pruned',
  UNILATERAL_PRUNED: 'unilateralPruned',
};

/**
 * Bilateral pruning protocol for GDPR compliance.
 */
export class PruneProtocol {
  /**
   * @param {import('./event-factory.js').EventFactory} eventFactory
   */
  constructor(eventFactory) {
    this._eventFactory = eventFactory;
  }

  /**
   * Create a PRUNE_REQUEST event
   */
  async requestPrune({
    targetEventId,
    targetEventHash,
    reason,
    privateKey,
    publicKey,
    previousEvent,
    currentVectorClock,
    localPeerRole,
  }) {
    const payload = new TextEncoder().encode(
      JSON.stringify({
        type: 'prune_request',
        targetEventId,
        targetEventHash,
        reason,
      })
    );

    return this._eventFactory.createEvent({
      type: EventType.PRUNE_REQUEST,
      payload,
      privateKey,
      publicKey,
      previousEvent,
      currentVectorClock,
      localPeerRole,
    });
  }

  /**
   * Create a PRUNE_ACK event in response to a request
   */
  async acknowledgePrune({
    pruneRequest,
    privateKey,
    publicKey,
    previousEvent,
    currentVectorClock,
    localPeerRole,
  }) {
    const requestData = JSON.parse(new TextDecoder().decode(pruneRequest.payload));

    const payload = new TextEncoder().encode(
      JSON.stringify({
        type: 'prune_ack',
        targetEventId: requestData.targetEventId,
        requestEventId: pruneRequest.eventId,
      })
    );

    return this._eventFactory.createEvent({
      type: EventType.PRUNE_ACK,
      payload,
      privateKey,
      publicKey,
      previousEvent,
      currentVectorClock,
      localPeerRole,
    });
  }

  /**
   * Nullify payload after both REQUEST and ACK (bilateral prune).
   * @param {string} targetEventId
   * @param {import('../storage/store-interface.js').LedgerStore} store
   */
  async executeBilateralPrune(targetEventId, store) {
    await store.pruneEvent(targetEventId);
  }

  /**
   * Immediately nullify payload — GDPR Art. 17, no ACK needed.
   * @param {string} targetEventId
   * @param {import('../storage/store-interface.js').LedgerStore} store
   */
  async executeUnilateralPrune(targetEventId, store) {
    await store.pruneEvent(targetEventId);
  }
}

/**
 * Evaluates retention policies to identify expired events.
 */
export class RetentionManager {
  /**
   * Return events that exceed the retention period.
   * Already-pruned events are excluded.
   * @param {import('./event.js').LedgerEvent[]} events
   * @param {number} retentionMs - Retention period in milliseconds
   * @param {string[]} applicableTypes - EventType values to evaluate
   * @returns {import('./event.js').LedgerEvent[]}
   */
  getExpiredEvents(events, retentionMs, applicableTypes) {
    const cutoff = Date.now() - retentionMs;
    return events.filter(
      (e) =>
        !e.isPruned &&
        applicableTypes.includes(e.eventType) &&
        e.createdAt.getTime() < cutoff
    );
  }
}
