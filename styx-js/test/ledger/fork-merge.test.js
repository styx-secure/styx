// test/ledger/fork-merge.test.js
import { describe, test, expect, beforeAll } from '@jest/globals';
import {
  ForkDetector,
  DeterministicMerge,
  MergeEventFactory,
  Fork,
} from '../../src/ledger/fork-merge.js';
import { EventFactory } from '../../src/ledger/event-factory.js';
import { EventType, LedgerEvent } from '../../src/ledger/event.js';
import { VectorClock } from '../../src/ledger/vector-clock.js';
import { Signer } from '../../src/crypto/signer.js';
import { Hasher } from '../../src/crypto/hasher.js';
import { createTestEvent, createTestKeyPair } from '../setup.js';
import { utf8Encode } from '../../src/utils.js';

describe('ForkDetector', () => {
  const detector = new ForkDetector();

  describe('detectForks()', () => {
    test('returns empty array when no forks exist', async () => {
      const genesis = await createTestEvent();
      const kp = await createTestKeyPair();
      const event2 = await createTestEvent({
        keyPair: kp,
        previousEvent: genesis,
        vectorClock: VectorClock.zero(),
      });
      const forks = detector.detectForks([genesis, event2]);
      expect(forks).toEqual([]);
    });

    test('detects fork when two events share the same previousHash', async () => {
      const genesis = await createTestEvent();
      const kpA = await createTestKeyPair();
      const kpB = await createTestKeyPair();

      const eventA = await createTestEvent({
        keyPair: kpA,
        previousEvent: genesis,
        vectorClock: VectorClock.zero(),
        peerRole: 'A',
      });
      const eventB = await createTestEvent({
        keyPair: kpB,
        previousEvent: genesis,
        vectorClock: VectorClock.zero(),
        peerRole: 'B',
      });

      const forks = detector.detectForks([genesis, eventA, eventB]);
      expect(forks.length).toBe(1);
      expect(forks[0].commonAncestorHash).toBe(genesis.eventHash);
    });
  });

  describe('detectForkOnReceive()', () => {
    test('concurrent events create a fork', async () => {
      const genesis = await createTestEvent();
      const kpA = await createTestKeyPair();
      const kpB = await createTestKeyPair();

      // Local and remote both build on genesis but with concurrent VCs
      const localHead = await createTestEvent({
        keyPair: kpA,
        previousEvent: genesis,
        vectorClock: VectorClock.zero(),
        peerRole: 'A',
      });
      const remoteEvent = await createTestEvent({
        keyPair: kpB,
        previousEvent: genesis,
        vectorClock: VectorClock.zero(),
        peerRole: 'B',
      });

      const fork = detector.detectForkOnReceive(remoteEvent, localHead);
      expect(fork).not.toBeNull();
      expect(fork.branchA).toHaveLength(1);
      expect(fork.branchB).toHaveLength(1);
    });

    test('causal event (remote after local) returns null', async () => {
      const genesis = await createTestEvent();
      const kp = await createTestKeyPair();

      const localHead = await createTestEvent({
        keyPair: kp,
        previousEvent: genesis,
        vectorClock: VectorClock.zero(),
        peerRole: 'A',
      });

      // Remote event that is causally after local (higher VC in both components)
      const remoteEvent = await createTestEvent({
        keyPair: kp,
        previousEvent: localHead,
        vectorClock: localHead.vectorClock,
        peerRole: 'A',
      });

      const fork = detector.detectForkOnReceive(remoteEvent, localHead);
      expect(fork).toBeNull();
    });
  });
});

describe('DeterministicMerge', () => {
  const merger = new DeterministicMerge();

  test('orderConcurrentEvents orders by VC total ascending', async () => {
    const kpA = await createTestKeyPair();
    const kpB = await createTestKeyPair();
    const genesis = await createTestEvent({ keyPair: kpA });

    const eventLow = await createTestEvent({
      keyPair: kpA,
      previousEvent: genesis,
      vectorClock: VectorClock.zero(),
      peerRole: 'A',
    });
    const eventHigh = await createTestEvent({
      keyPair: kpB,
      previousEvent: genesis,
      vectorClock: new VectorClock(2, 3),
      peerRole: 'B',
    });

    const ordered = merger.orderConcurrentEvents([eventHigh, eventLow]);
    expect(ordered[0].vectorClock.total).toBeLessThanOrEqual(
      ordered[1].vectorClock.total
    );
  });

  test('tiebreaks by senderPubkey lexicographic', async () => {
    const kpA = await createTestKeyPair();
    const kpB = await createTestKeyPair();
    const genesis = await createTestEvent({ keyPair: kpA });

    // Same VC total
    const eventA = await createTestEvent({
      keyPair: kpA,
      previousEvent: genesis,
      vectorClock: VectorClock.zero(),
      peerRole: 'A',
    });
    const eventB = await createTestEvent({
      keyPair: kpB,
      previousEvent: genesis,
      vectorClock: VectorClock.zero(),
      peerRole: 'B',
    });

    const ordered = merger.orderConcurrentEvents([eventA, eventB]);
    // Both have same VC total (1), so order by pubkey
    expect(
      ordered[0].senderPubkey.localeCompare(ordered[1].senderPubkey)
    ).toBeLessThanOrEqual(0);
  });

  test('merge returns MergeResult with mergeEventNeeded=true', async () => {
    const kpA = await createTestKeyPair();
    const kpB = await createTestKeyPair();
    const genesis = await createTestEvent({ keyPair: kpA });

    const eventA = await createTestEvent({
      keyPair: kpA,
      previousEvent: genesis,
      vectorClock: VectorClock.zero(),
      peerRole: 'A',
    });
    const eventB = await createTestEvent({
      keyPair: kpB,
      previousEvent: genesis,
      vectorClock: VectorClock.zero(),
      peerRole: 'B',
    });

    const fork = new Fork(genesis.eventHash, [eventA], [eventB]);
    const result = merger.merge(fork, 'A');
    expect(result.mergeEventNeeded).toBe(true);
    expect(result.orderedEvents).toHaveLength(2);
  });
});

describe('MergeEventFactory', () => {
  test('createMergeEvent produces a valid MERGE event', async () => {
    const signer = new Signer();
    const hasher = new Hasher();
    const eventFactory = new EventFactory(signer, hasher);
    const mergeFactory = new MergeEventFactory(eventFactory);
    const kp = await createTestKeyPair();
    const genesis = await createTestEvent({ keyPair: kp });

    const eventA = await createTestEvent({
      keyPair: kp,
      previousEvent: genesis,
      vectorClock: VectorClock.zero(),
      peerRole: 'A',
    });

    const mergeEvent = await mergeFactory.createMergeEvent({
      branchAHeadHash: eventA.eventHash,
      branchBHeadHash: genesis.eventHash,
      ancestorHash: genesis.eventHash,
      newPreviousEvent: eventA,
      privateKey: kp.privateKey,
      publicKey: kp.publicKey,
      mergedVectorClock: eventA.vectorClock,
      localPeerRole: 'A',
    });

    expect(mergeEvent.eventType).toBe(EventType.MERGE);
    expect(mergeEvent.previousHash).toBe(eventA.eventHash);
    expect(mergeEvent.signature).toBeInstanceOf(Uint8Array);
    expect(mergeEvent.signature.byteLength).toBe(64);

    // Verify payload contains merge metadata
    const payloadData = JSON.parse(new TextDecoder().decode(mergeEvent.payload));
    expect(payloadData.type).toBe('merge');
    expect(payloadData.branch_a_head).toBe(eventA.eventHash);
    expect(payloadData.branch_b_head).toBe(genesis.eventHash);
    expect(payloadData.ancestor).toBe(genesis.eventHash);
  });
});
