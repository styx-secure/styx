// styx-js/src/ledger/pruning.js
// Pruning containment and retention management

/** Stable public code for the fail-closed v1 pruning containment. */
export const V1_PRUNING_DISABLED_CODE = 'STYX_V1_PRUNING_DISABLED';

/** Stable, non-secret message for errors and security telemetry. */
export const V1_PRUNING_DISABLED_MESSAGE =
  'Styx v1 pruning is disabled because it cannot preserve verifiable chain integrity.';

/** Immutable rejection receipt emitted for inbound v1 pruning control events. */
export const V1_PRUNING_DISABLED_RESULT = Object.freeze({
  accepted: false,
  code: V1_PRUNING_DISABLED_CODE,
  message: V1_PRUNING_DISABLED_MESSAGE,
});

/** Typed error raised before any local v1 pruning side effect. */
export class V1PruningDisabledError extends Error {
  constructor() {
    super(V1_PRUNING_DISABLED_MESSAGE);
    this.name = 'V1PruningDisabledError';
    this.code = V1_PRUNING_DISABLED_CODE;
    Object.freeze(this);
  }
}

/** @enum {string} */
export const PruneState = {
  IDLE: 'idle',
  REQUEST_SENT: 'requestSent',
  WAITING_ACK: 'waitingAck',
  PRUNED: 'pruned',
  UNILATERAL_PRUNED: 'unilateralPruned',
};

/**
 * Legacy v1 pruning API retained only to fail closed.
 *
 * Creating, acknowledging, or executing v1 prune operations is disabled because
 * replacing an event payload without recomputing its committed hash breaks full
 * chain verification. Existing persisted v1 records remain readable.
 */
export class PruneProtocol {
  /**
   * Reject creation of a v1 PRUNE_REQUEST before serializing any payload.
   */
  async requestPrune() {
    throw new V1PruningDisabledError();
  }

  /**
   * Reject creation of a v1 PRUNE_ACK before reading the request payload.
   */
  async acknowledgePrune() {
    throw new V1PruningDisabledError();
  }

  /**
   * Reject bilateral v1 payload replacement before accessing the store.
   */
  async executeBilateralPrune() {
    throw new V1PruningDisabledError();
  }

  /**
   * Reject unilateral v1 payload replacement before accessing the store.
   */
  async executeUnilateralPrune() {
    throw new V1PruningDisabledError();
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
