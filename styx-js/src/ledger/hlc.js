// styx-js/src/ledger/hlc.js
// Hybrid Logical Clock — combines wall-clock time with logical counter and node ID

import { concatBytes, utf8Encode } from '../utils.js';

/**
 * Hybrid Logical Clock combining wall-clock time, logical counter, and node ID.
 */
export class HybridLogicalClock {
  /**
   * @param {Date} timestamp - UTC wall-clock time
   * @param {number} counter - Logical counter (tiebreaker within same millisecond)
   * @param {string} nodeId - Node identifier (first 8 hex chars of pubkey)
   */
  constructor(timestamp, counter, nodeId) {
    this.timestamp = timestamp;
    this.counter = counter;
    this.nodeId = nodeId;
    Object.freeze(this);
  }

  /**
   * Create HLC for the current instant, ensuring monotonicity with previous HLC
   * @param {HybridLogicalClock|null} previous
   * @param {string} nodeId
   * @returns {HybridLogicalClock}
   */
  static now(previous, nodeId) {
    const now = new Date();

    if (!previous) {
      return new HybridLogicalClock(now, 0, nodeId);
    }

    if (now.getTime() > previous.timestamp.getTime()) {
      return new HybridLogicalClock(now, 0, nodeId);
    }

    // Wall clock hasn't advanced — increment logical counter
    return new HybridLogicalClock(previous.timestamp, previous.counter + 1, nodeId);
  }

  /**
   * Parse from canonical format: "2026-02-24T12:00:00.000Z-0042-a1b2c3d4"
   * @param {string} s
   * @returns {HybridLogicalClock}
   */
  static fromCanonical(s) {
    const parts = s.split('-');
    // Rejoin the ISO date parts (which contain dashes themselves)
    // Format: YYYY-MM-DDTHH:MM:SS.sssZ-CCCC-NNNNNNNN
    // The timestamp portion is everything before the counter, which is a 4-digit hex
    // Strategy: find the Z, everything before Z+1 is timestamp, then -counter-nodeId
    const zIdx = s.indexOf('Z');
    if (zIdx === -1) throw new Error(`Invalid HLC canonical format: ${s}`);

    const timestampStr = s.substring(0, zIdx + 1);
    const rest = s.substring(zIdx + 2); // skip "Z-"
    const dashIdx = rest.indexOf('-');
    if (dashIdx === -1) throw new Error(`Invalid HLC canonical format: ${s}`);

    const counterStr = rest.substring(0, dashIdx);
    const nodeId = rest.substring(dashIdx + 1);

    return new HybridLogicalClock(
      new Date(timestampStr),
      parseInt(counterStr, 10),
      nodeId
    );
  }

  /**
   * Canonical string: "2026-02-24T12:00:00.000Z-0042-a1b2c3d4"
   * @returns {string}
   */
  toCanonical() {
    const ts = this.timestamp.toISOString();
    const counter = this.counter.toString().padStart(4, '0');
    return `${ts}-${counter}-${this.nodeId}`;
  }

  /**
   * Serialize to bytes for hash computation
   * @returns {Uint8Array}
   */
  toBytes() {
    return utf8Encode(this.toCanonical());
  }

  /**
   * Compare by timestamp, then counter, then nodeId
   * @param {HybridLogicalClock} other
   * @returns {number} -1, 0, or 1
   */
  compareTo(other) {
    const tsDiff = this.timestamp.getTime() - other.timestamp.getTime();
    if (tsDiff !== 0) return tsDiff < 0 ? -1 : 1;
    if (this.counter !== other.counter) return this.counter < other.counter ? -1 : 1;
    if (this.nodeId < other.nodeId) return -1;
    if (this.nodeId > other.nodeId) return 1;
    return 0;
  }

  toString() {
    return this.toCanonical();
  }
}
