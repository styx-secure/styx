// test/ledger/event-factory.test.js
import { describe, test, expect, beforeAll } from '@jest/globals';
import { EventFactory } from '../../src/ledger/event-factory.js';
import { EventType } from '../../src/ledger/event.js';
import { Signer } from '../../src/crypto/signer.js';
import { Hasher } from '../../src/crypto/hasher.js';
import { VectorClock } from '../../src/ledger/vector-clock.js';
import { createTestKeyPair } from '../setup.js';
import { utf8Encode } from '../../src/utils.js';

describe('EventFactory', () => {
  let factory;
  let keyPair;

  beforeAll(async () => {
    const signer = new Signer();
    const hasher = new Hasher();
    factory = new EventFactory(signer, hasher);
    keyPair = await createTestKeyPair();
  });

  describe('createGenesisEvent()', () => {
    let genesis;

    beforeAll(async () => {
      genesis = await factory.createGenesisEvent({
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        nodeId: keyPair.publicKey.nodeId,
      });
    });

    test('previousHash is null', () => {
      expect(genesis.previousHash).toBeNull();
    });

    test('has a valid eventHash (hex string)', () => {
      expect(typeof genesis.eventHash).toBe('string');
      expect(genesis.eventHash).toMatch(/^[0-9a-f]{64}$/);
    });

    test('has a valid signature (64 bytes)', () => {
      expect(genesis.signature).toBeInstanceOf(Uint8Array);
      expect(genesis.signature.byteLength).toBe(64);
    });

    test('eventType is CONFIG', () => {
      expect(genesis.eventType).toBe(EventType.CONFIG);
    });

    test('vectorClock is zero', () => {
      expect(genesis.vectorClock.a).toBe(0);
      expect(genesis.vectorClock.b).toBe(0);
    });

    test('has an eventId', () => {
      expect(typeof genesis.eventId).toBe('string');
      expect(genesis.eventId.length).toBeGreaterThan(0);
    });
  });

  describe('createEvent()', () => {
    let genesis;
    let event;

    beforeAll(async () => {
      genesis = await factory.createGenesisEvent({
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        nodeId: keyPair.publicKey.nodeId,
      });

      event = await factory.createEvent({
        type: EventType.MESSAGE,
        payload: utf8Encode('hello world'),
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        previousEvent: genesis,
        currentVectorClock: VectorClock.zero(),
        localPeerRole: 'A',
      });
    });

    test('previousHash points to previous event', () => {
      expect(event.previousHash).toBe(genesis.eventHash);
    });

    test('vector clock is incremented', () => {
      expect(event.vectorClock.a).toBe(1);
      expect(event.vectorClock.b).toBe(0);
    });

    test('has a valid eventHash', () => {
      expect(event.eventHash).toMatch(/^[0-9a-f]{64}$/);
    });

    test('has a valid signature', () => {
      expect(event.signature).toBeInstanceOf(Uint8Array);
      expect(event.signature.byteLength).toBe(64);
    });

    test('eventType matches requested type', () => {
      expect(event.eventType).toBe(EventType.MESSAGE);
    });
  });

  describe('computeHashBytes()', () => {
    test('is deterministic', () => {
      const hasher = new Hasher();
      const signer = new Signer();
      const f = new EventFactory(signer, hasher);

      const params = {
        previousHash: 'abc123',
        eventType: EventType.MESSAGE,
        payload: utf8Encode('test'),
        hlcBytes: utf8Encode('2026-01-01T00:00:00.000Z-0000-node1'),
      };

      const hash1 = f.computeHashBytes(params);
      const hash2 = f.computeHashBytes(params);
      expect(Array.from(hash1)).toEqual(Array.from(hash2));
    });
  });

  describe('sequential chain linkage', () => {
    test('event2.previousHash equals event1.eventHash', async () => {
      const genesis = await factory.createGenesisEvent({
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        nodeId: keyPair.publicKey.nodeId,
      });

      const event1 = await factory.createEvent({
        type: EventType.MESSAGE,
        payload: utf8Encode('first'),
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        previousEvent: genesis,
        currentVectorClock: VectorClock.zero(),
        localPeerRole: 'A',
      });

      const event2 = await factory.createEvent({
        type: EventType.MESSAGE,
        payload: utf8Encode('second'),
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        previousEvent: event1,
        currentVectorClock: event1.vectorClock,
        localPeerRole: 'A',
      });

      expect(event2.previousHash).toBe(event1.eventHash);
    });
  });
});
