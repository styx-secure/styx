// styx-js/src/ledger/vector-clock.js
// 2-element vector clock for the Styx 2-peer system

import { uint32BE, readUint32BE, concatBytes } from '../utils.js';

/** @enum {string} */
export const CausalRelation = {
  BEFORE: 'before',
  AFTER: 'after',
  CONCURRENT: 'concurrent',
  EQUAL: 'equal',
};

/**
 * 2-element vector clock for Styx peers A and B.
 * Immutable — all mutations return a new VectorClock.
 */
export class VectorClock {
  /**
   * @param {number} a - Counter for peer A
   * @param {number} b - Counter for peer B
   */
  constructor(a, b) {
    this.a = a;
    this.b = b;
    Object.freeze(this);
  }

  /** Zero vector clock */
  static zero() {
    return new VectorClock(0, 0);
  }

  /** From JSON { a, b } */
  static fromJSON(json) {
    return new VectorClock(json.a, json.b);
  }

  /** From 8-byte big-endian buffer */
  static fromBytes(bytes) {
    return new VectorClock(readUint32BE(bytes, 0), readUint32BE(bytes, 4));
  }

  /** Sum a + b (used for deterministic merge ordering) */
  get total() {
    return this.a + this.b;
  }

  /**
   * Return new VectorClock with counter for given role incremented
   * @param {string} localPeerRole - 'A' or 'B'
   * @returns {VectorClock}
   */
  increment(localPeerRole) {
    if (localPeerRole === 'A') return new VectorClock(this.a + 1, this.b);
    if (localPeerRole === 'B') return new VectorClock(this.a, this.b + 1);
    throw new Error(`Invalid peer role: ${localPeerRole}. Must be 'A' or 'B'`);
  }

  /**
   * Component-wise maximum (merge)
   * @param {VectorClock} other
   * @returns {VectorClock}
   */
  merge(other) {
    return new VectorClock(
      Math.max(this.a, other.a),
      Math.max(this.b, other.b)
    );
  }

  /**
   * Causal relationship with another vector clock
   * @param {VectorClock} other
   * @returns {string} CausalRelation value
   */
  causalRelation(other) {
    const thisLeqA = this.a <= other.a;
    const thisLeqB = this.b <= other.b;
    const otherLeqA = other.a <= this.a;
    const otherLeqB = other.b <= this.b;

    const thisLeq = thisLeqA && thisLeqB;
    const otherLeq = otherLeqA && otherLeqB;

    if (thisLeq && otherLeq) return CausalRelation.EQUAL;
    if (thisLeq) return CausalRelation.BEFORE;
    if (otherLeq) return CausalRelation.AFTER;
    return CausalRelation.CONCURRENT;
  }

  toJSON() {
    return { a: this.a, b: this.b };
  }

  /**
   * Serialize to 8 bytes (4 for A, 4 for B, big-endian)
   * @returns {Uint8Array}
   */
  toBytes() {
    return concatBytes(uint32BE(this.a), uint32BE(this.b));
  }

  toString() {
    return `VC(${this.a}, ${this.b})`;
  }

  equals(other) {
    return this.a === other.a && this.b === other.b;
  }
}

/**
 * Determines causal relationships between vector clocks.
 */
export class CausalityChecker {
  compare(a, b) {
    return a.causalRelation(b);
  }

  isAfter(event, reference) {
    return event.causalRelation(reference) === CausalRelation.AFTER;
  }

  isConcurrent(a, b) {
    return a.causalRelation(b) === CausalRelation.CONCURRENT;
  }
}
