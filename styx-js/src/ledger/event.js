// styx-js/src/ledger/event.js
// Event types and LedgerEvent data structure

/** @enum {string} */
export const EventType = {
  TRANSACTION: 'transaction',
  MESSAGE: 'message',
  SOS: 'sos',
  CONFIG: 'config',
  REKEY: 'rekey',
  MERGE: 'merge',
  PRUNE_REQUEST: 'pruneRequest',
  PRUNE_ACK: 'pruneAck',
};

/**
 * Immutable representation of a ledger event in the hash chain.
 */
export class LedgerEvent {
  /**
   * @param {object} params
   * @param {string} params.eventId - UUID v4
   * @param {string} params.eventType - EventType value
   * @param {Uint8Array|null} params.payload - Event data (null after pruning)
   * @param {string|null} params.previousHash - Hash of preceding event (null for genesis)
   * @param {string} params.eventHash - SHA-256 hash of this event
   * @param {import('./hlc.js').HybridLogicalClock} params.hlc
   * @param {import('./vector-clock.js').VectorClock} params.vectorClock
   * @param {string} params.senderPubkey - Hex-encoded sender public key
   * @param {Uint8Array} params.signature - Ed25519 signature
   * @param {Date} params.createdAt - Wall-clock creation time (UTC)
   * @param {boolean} [params.isPruned=false]
   */
  constructor({
    eventId,
    eventType,
    payload,
    previousHash,
    eventHash,
    hlc,
    vectorClock,
    senderPubkey,
    signature,
    createdAt,
    isPruned = false,
  }) {
    this.eventId = eventId;
    this.eventType = eventType;
    this.payload = payload;
    this.previousHash = previousHash;
    this.eventHash = eventHash;
    this.hlc = hlc;
    this.vectorClock = vectorClock;
    this.senderPubkey = senderPubkey;
    this.signature = signature;
    this.createdAt = createdAt;
    this.isPruned = isPruned;
    Object.freeze(this);
  }

  /**
   * Create a pruned copy (payload nullified)
   * @returns {LedgerEvent}
   */
  toPruned() {
    return new LedgerEvent({
      ...this,
      payload: null,
      isPruned: true,
    });
  }

  /**
   * Serialize to JSON-compatible object
   */
  toJSON() {
    return {
      eventId: this.eventId,
      eventType: this.eventType,
      payload: this.payload ? Array.from(this.payload) : null,
      previousHash: this.previousHash,
      eventHash: this.eventHash,
      hlc: this.hlc.toCanonical(),
      vectorClock: this.vectorClock.toJSON(),
      senderPubkey: this.senderPubkey,
      signature: Array.from(this.signature),
      createdAt: this.createdAt.toISOString(),
      isPruned: this.isPruned,
    };
  }

  /**
   * Deserialize from JSON object
   * @param {object} json
   * @param {typeof import('./hlc.js').HybridLogicalClock} HLC
   * @param {typeof import('./vector-clock.js').VectorClock} VC
   * @returns {LedgerEvent}
   */
  static fromJSON(json, HLC, VC) {
    return new LedgerEvent({
      eventId: json.eventId,
      eventType: json.eventType,
      payload: json.payload ? new Uint8Array(json.payload) : null,
      previousHash: json.previousHash,
      eventHash: json.eventHash,
      hlc: HLC.fromCanonical(json.hlc),
      vectorClock: VC.fromJSON(json.vectorClock),
      senderPubkey: json.senderPubkey,
      signature: new Uint8Array(json.signature),
      createdAt: new Date(json.createdAt),
      isPruned: json.isPruned || false,
    });
  }
}

/** @enum {string} */
export const PruneReason = {
  RETENTION_EXPIRED: 'retentionExpired',
  USER_REQUEST: 'userRequest',
  GDPR_ARTICLE_17: 'gdprArticle17',
};

/** @enum {string} */
export const ChainErrorType = {
  HASH_MISMATCH: 'hashMismatch',
  SIGNATURE_INVALID: 'signatureInvalid',
  PREVIOUS_HASH_MISSING: 'previousHashMissing',
  HLC_VIOLATION: 'hlcViolation',
  GENESIS_VIOLATION: 'genesisViolation',
};

/**
 * Describes a chain validation error.
 */
export class ChainValidationError {
  constructor(eventId, errorType, message) {
    this.eventId = eventId;
    this.errorType = errorType;
    this.message = message;
  }
}
