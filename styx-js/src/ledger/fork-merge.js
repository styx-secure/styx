// styx-js/src/ledger/fork-merge.js
// Fork detection and deterministic merge

import { CausalRelation, CausalityChecker } from './vector-clock.js';

/**
 * Represents a fork where two branches diverge from a common ancestor.
 */
export class Fork {
  /**
   * @param {string} commonAncestorHash
   * @param {import('./event.js').LedgerEvent[]} branchA - Local branch
   * @param {import('./event.js').LedgerEvent[]} branchB - Remote branch
   */
  constructor(commonAncestorHash, branchA, branchB) {
    this.commonAncestorHash = commonAncestorHash;
    this.branchA = branchA;
    this.branchB = branchB;
  }
}

/**
 * Detects forks in the event chain.
 */
export class ForkDetector {
  constructor(causalityChecker) {
    this._causality = causalityChecker || new CausalityChecker();
  }

  /**
   * Scan all events for forks (events sharing the same previousHash).
   * @param {import('./event.js').LedgerEvent[]} events
   * @returns {Fork[]}
   */
  detectForks(events) {
    const byPrevHash = new Map();
    for (const event of events) {
      if (event.previousHash === null) continue;
      if (!byPrevHash.has(event.previousHash)) {
        byPrevHash.set(event.previousHash, []);
      }
      byPrevHash.get(event.previousHash).push(event);
    }

    const forks = [];
    for (const [hash, children] of byPrevHash) {
      if (children.length > 1) {
        // Simple 2-peer fork: split into branch A and B
        forks.push(new Fork(hash, [children[0]], children.slice(1)));
      }
    }
    return forks;
  }

  /**
   * Detect if a received remote event creates a fork with the local head.
   * @param {import('./event.js').LedgerEvent} remoteEvent
   * @param {import('./event.js').LedgerEvent} localHead
   * @returns {Fork|null}
   */
  detectForkOnReceive(remoteEvent, localHead) {
    // Fork occurs when both events share the same previousHash
    if (
      remoteEvent.previousHash === localHead.previousHash &&
      remoteEvent.eventId !== localHead.eventId
    ) {
      return new Fork(
        remoteEvent.previousHash,
        [localHead],
        [remoteEvent]
      );
    }

    // Or when events are concurrent (neither is causally before the other)
    const relation = this._causality.compare(
      remoteEvent.vectorClock,
      localHead.vectorClock
    );

    if (relation === CausalRelation.CONCURRENT) {
      return new Fork(
        remoteEvent.previousHash,
        [localHead],
        [remoteEvent]
      );
    }

    return null;
  }
}

/**
 * Result of a deterministic merge.
 */
export class MergeResult {
  /**
   * @param {import('./event.js').LedgerEvent[]} orderedEvents
   * @param {boolean} mergeEventNeeded
   */
  constructor(orderedEvents, mergeEventNeeded) {
    this.orderedEvents = orderedEvents;
    this.mergeEventNeeded = mergeEventNeeded;
  }
}

/**
 * Deterministic merge of forked branches.
 * Both peers apply the same ordering rule, guaranteeing convergence.
 */
export class DeterministicMerge {
  /**
   * Order concurrent events deterministically:
   * 1. By vector clock total (ascending)
   * 2. Tiebreak by sender pubkey (lexicographic)
   * @param {import('./event.js').LedgerEvent[]} events
   * @returns {import('./event.js').LedgerEvent[]}
   */
  orderConcurrentEvents(events) {
    return [...events].sort((a, b) => {
      const totalDiff = a.vectorClock.total - b.vectorClock.total;
      if (totalDiff !== 0) return totalDiff;
      return a.senderPubkey.localeCompare(b.senderPubkey);
    });
  }

  /**
   * Merge a fork into a linear sequence.
   * @param {Fork} fork
   * @param {string} localPeerRole
   * @returns {MergeResult}
   */
  merge(fork, localPeerRole) {
    const allEvents = [...fork.branchA, ...fork.branchB];
    const ordered = this.orderConcurrentEvents(allEvents);
    return new MergeResult(ordered, true);
  }
}

/**
 * Creates MERGE events that reference both tips of a fork.
 */
export class MergeEventFactory {
  /**
   * @param {import('./event-factory.js').EventFactory} eventFactory
   */
  constructor(eventFactory) {
    this._eventFactory = eventFactory;
  }

  /**
   * Create a MERGE event
   */
  async createMergeEvent({
    branchAHeadHash,
    branchBHeadHash,
    ancestorHash,
    newPreviousEvent,
    privateKey,
    publicKey,
    mergedVectorClock,
    localPeerRole,
  }) {
    const { EventType } = await import('./event.js');

    const payload = new TextEncoder().encode(
      JSON.stringify({
        type: 'merge',
        branch_a_head: branchAHeadHash,
        branch_b_head: branchBHeadHash,
        ancestor: ancestorHash,
      })
    );

    return this._eventFactory.createEvent({
      type: EventType.MERGE,
      payload,
      privateKey,
      publicKey,
      previousEvent: newPreviousEvent,
      currentVectorClock: mergedVectorClock,
      localPeerRole,
    });
  }
}
