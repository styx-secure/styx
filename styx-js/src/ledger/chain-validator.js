// styx-js/src/ledger/chain-validator.js
// Chain integrity validation

import { ChainValidationError, ChainErrorType } from './event.js';
import { bytesToHex, utf8Encode } from '../utils.js';
import { StyxPublicKey } from '../crypto/identity.js';

/**
 * Validates the integrity of the ledger chain.
 */
export class ChainValidator {
  /**
   * @param {import('../crypto/hasher.js').Hasher} hasher
   * @param {import('../crypto/signer.js').Verifier} verifier
   */
  constructor(hasher, verifier) {
    this._hasher = hasher;
    this._verifier = verifier;
  }

  /**
   * Validate every event in sequence.
   * @param {import('./event.js').LedgerEvent[]} events - Events ordered by HLC
   * @returns {Promise<ChainValidationError|null>} null if valid
   */
  async validateFullChain(events) {
    if (events.length === 0) return null;

    // Validate genesis
    const genesis = events[0];
    if (genesis.previousHash !== null) {
      return new ChainValidationError(
        genesis.eventId,
        ChainErrorType.GENESIS_VIOLATION,
        'Genesis event must have null previousHash'
      );
    }

    for (let i = 0; i < events.length; i++) {
      const event = events[i];
      const previous = i > 0 ? events[i - 1] : null;
      const pubkey = StyxPublicKey.fromHex(event.senderPubkey);

      const error = await this.validateEvent(event, previous, pubkey);
      if (error) return error;
    }

    return null;
  }

  /**
   * Validate a single event against its predecessor.
   */
  async validateEvent(event, previousEvent, senderPublicKey) {
    // Check hash linkage
    if (previousEvent && event.previousHash !== previousEvent.eventHash) {
      return new ChainValidationError(
        event.eventId,
        ChainErrorType.PREVIOUS_HASH_MISSING,
        `previousHash ${event.previousHash} does not match preceding event hash ${previousEvent?.eventHash}`
      );
    }

    // Verify hash integrity
    const hashValid = await this.verifyEventHash(
      event,
      event.previousHash
    );
    if (!hashValid) {
      return new ChainValidationError(
        event.eventId,
        ChainErrorType.HASH_MISMATCH,
        'Computed hash differs from stored hash'
      );
    }

    // Verify signature
    const sigValid = await this.verifyEventSignature(event, senderPublicKey);
    if (!sigValid) {
      return new ChainValidationError(
        event.eventId,
        ChainErrorType.SIGNATURE_INVALID,
        'Ed25519 signature verification failed'
      );
    }

    // Check HLC monotonicity
    if (previousEvent && event.hlc.compareTo(previousEvent.hlc) <= 0) {
      return new ChainValidationError(
        event.eventId,
        ChainErrorType.HLC_VIOLATION,
        'HLC is not monotonically increasing'
      );
    }

    return null;
  }

  /**
   * Verify event hash matches computed hash
   */
  async verifyEventHash(event, previousHash) {
    const segments = [];
    if (previousHash) segments.push(utf8Encode(previousHash));
    segments.push(utf8Encode(event.eventType));
    if (event.payload) segments.push(event.payload);
    segments.push(event.hlc.toBytes());

    const computed = bytesToHex(this._hasher.compositeHash(segments));
    return computed === event.eventHash;
  }

  /**
   * Verify Ed25519 signature on the event
   */
  async verifyEventSignature(event, publicKey) {
    const hashBytes = this._hasher.hash(utf8Encode(event.eventHash));
    // The signature is over the event hash bytes
    const segments = [];
    if (event.previousHash) segments.push(utf8Encode(event.previousHash));
    segments.push(utf8Encode(event.eventType));
    if (event.payload) segments.push(event.payload);
    segments.push(event.hlc.toBytes());
    const hashBytesComputed = this._hasher.compositeHash(segments);

    return this._verifier.verify(hashBytesComputed, event.signature, publicKey);
  }
}
