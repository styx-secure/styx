// styx-js/src/ledger/event-factory.js
// Creates signed, hashed events for the ledger chain

import { LedgerEvent, EventType } from './event.js';
import { HybridLogicalClock } from './hlc.js';
import { uuidv4, bytesToHex, utf8Encode, concatBytes } from '../utils.js';

/**
 * Creates signed, hashed events for the ledger chain.
 */
export class EventFactory {
  /**
   * @param {import('../crypto/signer.js').Signer} signer
   * @param {import('../crypto/hasher.js').Hasher} hasher
   */
  constructor(signer, hasher) {
    this._signer = signer;
    this._hasher = hasher;
  }

  /**
   * Create a new event appended to the chain.
   * Generates UUID, computes HLC, increments vector clock, computes SHA-256, signs Ed25519.
   */
  async createEvent({
    type,
    payload,
    privateKey,
    publicKey,
    previousEvent,
    currentVectorClock,
    localPeerRole,
  }) {
    const eventId = uuidv4();
    const nodeId = publicKey.nodeId;

    // Compute HLC
    const previousHlc = previousEvent ? previousEvent.hlc : null;
    const hlc = HybridLogicalClock.now(previousHlc, nodeId);

    // Increment vector clock
    const vectorClock = currentVectorClock.increment(localPeerRole);

    // Previous hash
    const previousHash = previousEvent ? previousEvent.eventHash : null;

    // Compute event hash: SHA-256(previousHash || eventType || payload || hlcBytes)
    const hashBytes = this.computeHashBytes({
      previousHash,
      eventType: type,
      payload,
      hlcBytes: hlc.toBytes(),
    });
    const eventHash = bytesToHex(hashBytes);

    // Sign the hash
    const signature = await this._signer.sign(hashBytes, privateKey);

    return new LedgerEvent({
      eventId,
      eventType: type,
      payload,
      previousHash,
      eventHash,
      hlc,
      vectorClock,
      senderPubkey: publicKey.toHex(),
      signature,
      createdAt: new Date(),
      isPruned: false,
    });
  }

  /**
   * Create the first event in the chain (genesis).
   */
  async createGenesisEvent({ privateKey, publicKey, nodeId }) {
    const { VectorClock } = await import('./vector-clock.js');

    const eventId = uuidv4();
    const hlc = HybridLogicalClock.now(null, nodeId);
    const vectorClock = VectorClock.zero();
    const payload = utf8Encode(JSON.stringify({ type: 'genesis', nodeId }));

    const hashBytes = this.computeHashBytes({
      previousHash: null,
      eventType: EventType.CONFIG,
      payload,
      hlcBytes: hlc.toBytes(),
    });
    const eventHash = bytesToHex(hashBytes);
    const signature = await this._signer.sign(hashBytes, privateKey);

    return new LedgerEvent({
      eventId,
      eventType: EventType.CONFIG,
      payload,
      previousHash: null,
      eventHash,
      hlc,
      vectorClock,
      senderPubkey: publicKey.toHex(),
      signature,
      createdAt: new Date(),
      isPruned: false,
    });
  }

  /**
   * Compute SHA-256(previousHash || eventType || payload || hlcBytes)
   */
  computeHashBytes({ previousHash, eventType, payload, hlcBytes }) {
    const segments = [];

    if (previousHash) {
      segments.push(utf8Encode(previousHash));
    }

    segments.push(utf8Encode(eventType));

    if (payload) {
      segments.push(payload);
    }

    segments.push(hlcBytes);

    return this._hasher.compositeHash(segments);
  }
}
