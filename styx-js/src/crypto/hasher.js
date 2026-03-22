// styx-js/src/crypto/hasher.js
// SHA-256 hashing utilities for chain linkage and composite hashes

import { sha256 } from '@noble/hashes/sha256';
import { concatBytes } from '../utils.js';

/**
 * SHA-256 hashing utilities.
 */
export class Hasher {
  /**
   * Compute SHA-256 hash
   * @param {Uint8Array} data
   * @returns {Uint8Array} 32-byte hash
   */
  hash(data) {
    return sha256(data);
  }

  /**
   * Compute chain hash: SHA-256(previousHash || payload)
   * For genesis events, previousHash is null (only payload is hashed).
   * @param {Uint8Array|null} previousHash
   * @param {Uint8Array} payload
   * @returns {Uint8Array}
   */
  chainHash(previousHash, payload) {
    if (previousHash === null || previousHash === undefined) {
      return sha256(payload);
    }
    return sha256(concatBytes(previousHash, payload));
  }

  /**
   * Compute composite hash: SHA-256(segment[0] || segment[1] || ... || segment[n])
   * Used for event hash computation: SHA-256(previousHash || eventType || payload || hlcBytes)
   * @param {Uint8Array[]} segments
   * @returns {Uint8Array}
   */
  compositeHash(segments) {
    return sha256(concatBytes(...segments));
  }
}
