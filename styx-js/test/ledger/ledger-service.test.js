// test/ledger/ledger-service.test.js
import { describe, test, expect, beforeAll, beforeEach } from '@jest/globals';
import { LedgerService } from '../../src/ledger/ledger-service.js';
import { EventFactory } from '../../src/ledger/event-factory.js';
import { ChainValidator } from '../../src/ledger/chain-validator.js';
import { EventType } from '../../src/ledger/event.js';
import { Signer, Verifier } from '../../src/crypto/signer.js';
import { Hasher } from '../../src/crypto/hasher.js';
import { MemoryLedgerStore } from '../../src/storage/memory-store.js';
import { createTestKeyPair, createTestEvent } from '../setup.js';
import { utf8Encode } from '../../src/utils.js';

describe('LedgerService', () => {
  let service;
  let store;
  let keyPair;

  beforeAll(async () => {
    keyPair = await createTestKeyPair();
  });

  beforeEach(() => {
    const signer = new Signer();
    const hasher = new Hasher();
    const verifier = new Verifier();
    const eventFactory = new EventFactory(signer, hasher);
    const chainValidator = new ChainValidator(hasher, verifier);
    store = new MemoryLedgerStore();
    service = new LedgerService(eventFactory, chainValidator, store, 'A');
  });

  describe('appendEvent()', () => {
    test('stores the event', async () => {
      const event = await service.appendEvent({
        type: EventType.MESSAGE,
        payload: utf8Encode('hello'),
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
      });

      const events = await store.getAllEvents();
      expect(events).toHaveLength(1);
      expect(events[0].eventId).toBe(event.eventId);
    });

    test('emits newEvent', async () => {
      const received = [];
      service.onNewEvent((e) => received.push(e));

      await service.appendEvent({
        type: EventType.MESSAGE,
        payload: utf8Encode('hello'),
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
      });

      expect(received).toHaveLength(1);
      expect(received[0].eventType).toBe(EventType.MESSAGE);
    });
  });

  describe('receiveRemoteEvent()', () => {
    test('stores the event', async () => {
      const remoteEvent = await createTestEvent();
      await service.receiveRemoteEvent(remoteEvent);

      const events = await store.getAllEvents();
      expect(events).toHaveLength(1);
      expect(events[0].eventId).toBe(remoteEvent.eventId);
    });

    test('emits remoteEvent and newEvent', async () => {
      const remoteReceived = [];
      const newReceived = [];
      service.onRemoteEvent((e) => remoteReceived.push(e));
      service.onNewEvent((e) => newReceived.push(e));

      const remoteEvent = await createTestEvent();
      await service.receiveRemoteEvent(remoteEvent);

      expect(remoteReceived).toHaveLength(1);
      expect(newReceived).toHaveLength(1);
    });
  });

  describe('getHistory()', () => {
    test('returns all events', async () => {
      await service.appendEvent({
        type: EventType.MESSAGE,
        payload: utf8Encode('one'),
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
      });
      await service.appendEvent({
        type: EventType.MESSAGE,
        payload: utf8Encode('two'),
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
      });

      const history = await service.getHistory();
      expect(history).toHaveLength(2);
    });
  });

  describe('getHistoryRange()', () => {
    test('filters by date range', async () => {
      const before = new Date();

      await service.appendEvent({
        type: EventType.MESSAGE,
        payload: utf8Encode('in range'),
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
      });

      const after = new Date();

      const inRange = await service.getHistoryRange(before, after);
      expect(inRange.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('getLatestEvent()', () => {
    test('returns null when empty', async () => {
      const latest = await service.getLatestEvent();
      expect(latest).toBeNull();
    });

    test('returns latest event after append', async () => {
      const event = await service.appendEvent({
        type: EventType.MESSAGE,
        payload: utf8Encode('latest'),
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
      });

      const latest = await service.getLatestEvent();
      expect(latest.eventId).toBe(event.eventId);
    });
  });

  describe('validateChain()', () => {
    test('delegates to ChainValidator and returns null for valid chain', async () => {
      await service.appendEvent({
        type: EventType.MESSAGE,
        payload: utf8Encode('test'),
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
      });

      const result = await service.validateChain();
      expect(result).toBeNull();
    });
  });

  describe('event subscriptions', () => {
    test('unsubscribe stops receiving events', async () => {
      const received = [];
      const unsub = service.onNewEvent((e) => received.push(e));

      await service.appendEvent({
        type: EventType.MESSAGE,
        payload: utf8Encode('before'),
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
      });

      expect(received).toHaveLength(1);

      unsub();

      await service.appendEvent({
        type: EventType.MESSAGE,
        payload: utf8Encode('after'),
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
      });

      expect(received).toHaveLength(1);
    });
  });
});
