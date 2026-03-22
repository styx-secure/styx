// test/ledger/pruning.test.js
import { describe, test, expect, beforeAll, beforeEach } from '@jest/globals';
import { PruneProtocol, RetentionManager } from '../../src/ledger/pruning.js';
import { EventFactory } from '../../src/ledger/event-factory.js';
import { EventType, PruneReason, LedgerEvent } from '../../src/ledger/event.js';
import { VectorClock } from '../../src/ledger/vector-clock.js';
import { Signer } from '../../src/crypto/signer.js';
import { Hasher } from '../../src/crypto/hasher.js';
import { MemoryLedgerStore } from '../../src/storage/memory-store.js';
import { createTestEvent, createTestKeyPair } from '../setup.js';

describe('PruneProtocol', () => {
  let protocol;
  let keyPair;
  let genesis;

  beforeAll(async () => {
    const signer = new Signer();
    const hasher = new Hasher();
    const eventFactory = new EventFactory(signer, hasher);
    protocol = new PruneProtocol(eventFactory);
    keyPair = await createTestKeyPair();
    genesis = await createTestEvent({ keyPair });
  });

  describe('requestPrune()', () => {
    test('creates event with type PRUNE_REQUEST', async () => {
      const request = await protocol.requestPrune({
        targetEventId: genesis.eventId,
        targetEventHash: genesis.eventHash,
        reason: PruneReason.USER_REQUEST,
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        previousEvent: genesis,
        currentVectorClock: VectorClock.zero(),
        localPeerRole: 'A',
      });

      expect(request.eventType).toBe(EventType.PRUNE_REQUEST);
    });

    test('payload contains targetEventId', async () => {
      const request = await protocol.requestPrune({
        targetEventId: genesis.eventId,
        targetEventHash: genesis.eventHash,
        reason: PruneReason.GDPR_ARTICLE_17,
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        previousEvent: genesis,
        currentVectorClock: VectorClock.zero(),
        localPeerRole: 'A',
      });

      const data = JSON.parse(new TextDecoder().decode(request.payload));
      expect(data.targetEventId).toBe(genesis.eventId);
      expect(data.targetEventHash).toBe(genesis.eventHash);
      expect(data.reason).toBe(PruneReason.GDPR_ARTICLE_17);
    });
  });

  describe('acknowledgePrune()', () => {
    test('creates PRUNE_ACK event', async () => {
      const request = await protocol.requestPrune({
        targetEventId: genesis.eventId,
        targetEventHash: genesis.eventHash,
        reason: PruneReason.USER_REQUEST,
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        previousEvent: genesis,
        currentVectorClock: VectorClock.zero(),
        localPeerRole: 'A',
      });

      const ack = await protocol.acknowledgePrune({
        pruneRequest: request,
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        previousEvent: request,
        currentVectorClock: request.vectorClock,
        localPeerRole: 'A',
      });

      expect(ack.eventType).toBe(EventType.PRUNE_ACK);

      const data = JSON.parse(new TextDecoder().decode(ack.payload));
      expect(data.targetEventId).toBe(genesis.eventId);
      expect(data.requestEventId).toBe(request.eventId);
    });
  });

  describe('executeBilateralPrune()', () => {
    test('calls store.pruneEvent', async () => {
      const store = new MemoryLedgerStore();
      const event = await createTestEvent();
      await store.appendEvent(event);

      await protocol.executeBilateralPrune(event.eventId, store);

      const pruned = await store.getEventById(event.eventId);
      expect(pruned.isPruned).toBe(true);
      expect(pruned.payload).toBeNull();
    });
  });

  describe('executeUnilateralPrune()', () => {
    test('calls store.pruneEvent', async () => {
      const store = new MemoryLedgerStore();
      const event = await createTestEvent();
      await store.appendEvent(event);

      await protocol.executeUnilateralPrune(event.eventId, store);

      const pruned = await store.getEventById(event.eventId);
      expect(pruned.isPruned).toBe(true);
      expect(pruned.payload).toBeNull();
    });
  });
});

describe('RetentionManager', () => {
  const manager = new RetentionManager();

  test('getExpiredEvents filters by time and type', async () => {
    // createTestEvent without previousEvent creates a genesis (CONFIG type)
    const oldEvent = await createTestEvent();
    const recentEvent = await createTestEvent();

    // Create an "old" event by reconstructing with old createdAt
    const oldCopy = new LedgerEvent({
      ...oldEvent,
      createdAt: new Date(Date.now() - 100000),
    });

    const events = [oldCopy, recentEvent];
    const expired = manager.getExpiredEvents(
      events,
      50000, // 50 seconds retention
      [EventType.CONFIG] // genesis events are CONFIG type
    );

    expect(expired).toHaveLength(1);
    expect(expired[0].eventId).toBe(oldCopy.eventId);
  });

  test('excludes already-pruned events', async () => {
    const event = await createTestEvent();
    const oldPruned = new LedgerEvent({
      ...event,
      createdAt: new Date(Date.now() - 100000),
      payload: null,
      isPruned: true,
    });

    const expired = manager.getExpiredEvents(
      [oldPruned],
      50000,
      [EventType.CONFIG]
    );

    expect(expired).toHaveLength(0);
  });

  test('excludes events of non-applicable types', async () => {
    const event = await createTestEvent();
    const oldEvent = new LedgerEvent({
      ...event,
      createdAt: new Date(Date.now() - 100000),
    });

    const expired = manager.getExpiredEvents(
      [oldEvent],
      50000,
      [EventType.MESSAGE] // event is CONFIG, so this should exclude it
    );

    expect(expired).toHaveLength(0);
  });
});
