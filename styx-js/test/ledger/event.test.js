// test/ledger/event.test.js
import { describe, test, expect, beforeAll } from '@jest/globals';
import {
  EventType,
  LedgerEvent,
  ChainValidationError,
  ChainErrorType,
  PruneReason,
} from '../../src/ledger/event.js';
import { HybridLogicalClock } from '../../src/ledger/hlc.js';
import { VectorClock } from '../../src/ledger/vector-clock.js';
import { createTestEvent, createTestKeyPair } from '../setup.js';

describe('EventType', () => {
  test('has all expected values', () => {
    expect(EventType.TRANSACTION).toBe('transaction');
    expect(EventType.MESSAGE).toBe('message');
    expect(EventType.SOS).toBe('sos');
    expect(EventType.CONFIG).toBe('config');
    expect(EventType.REKEY).toBe('rekey');
    expect(EventType.MERGE).toBe('merge');
    expect(EventType.PRUNE_REQUEST).toBe('pruneRequest');
    expect(EventType.PRUNE_ACK).toBe('pruneAck');
  });

  test('contains exactly 8 values', () => {
    expect(Object.keys(EventType)).toHaveLength(8);
  });
});

describe('LedgerEvent', () => {
  let event;

  beforeAll(async () => {
    event = await createTestEvent();
  });

  test('is frozen after construction', () => {
    expect(Object.isFrozen(event)).toBe(true);
  });

  test('has all required fields', () => {
    expect(event).toHaveProperty('eventId');
    expect(event).toHaveProperty('eventType');
    expect(event).toHaveProperty('payload');
    expect(event).toHaveProperty('previousHash');
    expect(event).toHaveProperty('eventHash');
    expect(event).toHaveProperty('hlc');
    expect(event).toHaveProperty('vectorClock');
    expect(event).toHaveProperty('senderPubkey');
    expect(event).toHaveProperty('signature');
    expect(event).toHaveProperty('createdAt');
    expect(event).toHaveProperty('isPruned');
  });

  test('genesis event has null previousHash', () => {
    expect(event.previousHash).toBeNull();
  });

  test('isPruned defaults to false', () => {
    expect(event.isPruned).toBe(false);
  });
});

describe('LedgerEvent.toPruned()', () => {
  let event;
  let pruned;

  beforeAll(async () => {
    event = await createTestEvent();
    pruned = event.toPruned();
  });

  test('payload is null', () => {
    expect(pruned.payload).toBeNull();
  });

  test('isPruned is true', () => {
    expect(pruned.isPruned).toBe(true);
  });

  test('eventHash is preserved', () => {
    expect(pruned.eventHash).toBe(event.eventHash);
  });

  test('eventId is preserved', () => {
    expect(pruned.eventId).toBe(event.eventId);
  });

  test('pruned event is also frozen', () => {
    expect(Object.isFrozen(pruned)).toBe(true);
  });

  test('original event is unchanged', () => {
    expect(event.payload).not.toBeNull();
    expect(event.isPruned).toBe(false);
  });
});

describe('LedgerEvent.toJSON() / fromJSON() roundtrip', () => {
  let event;
  let restored;

  beforeAll(async () => {
    event = await createTestEvent();
    const json = event.toJSON();
    restored = LedgerEvent.fromJSON(json, HybridLogicalClock, VectorClock);
  });

  test('eventId matches', () => {
    expect(restored.eventId).toBe(event.eventId);
  });

  test('eventType matches', () => {
    expect(restored.eventType).toBe(event.eventType);
  });

  test('eventHash matches', () => {
    expect(restored.eventHash).toBe(event.eventHash);
  });

  test('previousHash matches', () => {
    expect(restored.previousHash).toBe(event.previousHash);
  });

  test('senderPubkey matches', () => {
    expect(restored.senderPubkey).toBe(event.senderPubkey);
  });

  test('payload matches', () => {
    expect(Array.from(restored.payload)).toEqual(Array.from(event.payload));
  });

  test('signature matches', () => {
    expect(Array.from(restored.signature)).toEqual(Array.from(event.signature));
  });

  test('vectorClock matches', () => {
    expect(restored.vectorClock.a).toBe(event.vectorClock.a);
    expect(restored.vectorClock.b).toBe(event.vectorClock.b);
  });

  test('hlc canonical matches', () => {
    expect(restored.hlc.toCanonical()).toBe(event.hlc.toCanonical());
  });

  test('createdAt matches', () => {
    expect(restored.createdAt.toISOString()).toBe(event.createdAt.toISOString());
  });

  test('isPruned matches', () => {
    expect(restored.isPruned).toBe(event.isPruned);
  });

  test('restored event is frozen', () => {
    expect(Object.isFrozen(restored)).toBe(true);
  });
});

describe('ChainValidationError', () => {
  test('stores eventId, errorType, and message', () => {
    const err = new ChainValidationError(
      'evt-123',
      ChainErrorType.HASH_MISMATCH,
      'Hash does not match'
    );
    expect(err.eventId).toBe('evt-123');
    expect(err.errorType).toBe(ChainErrorType.HASH_MISMATCH);
    expect(err.message).toBe('Hash does not match');
  });
});

describe('PruneReason', () => {
  test('has all expected values', () => {
    expect(PruneReason.RETENTION_EXPIRED).toBe('retentionExpired');
    expect(PruneReason.USER_REQUEST).toBe('userRequest');
    expect(PruneReason.GDPR_ARTICLE_17).toBe('gdprArticle17');
  });

  test('contains exactly 3 values', () => {
    expect(Object.keys(PruneReason)).toHaveLength(3);
  });
});

describe('ChainErrorType', () => {
  test('has all expected values', () => {
    expect(ChainErrorType.HASH_MISMATCH).toBe('hashMismatch');
    expect(ChainErrorType.SIGNATURE_INVALID).toBe('signatureInvalid');
    expect(ChainErrorType.PREVIOUS_HASH_MISSING).toBe('previousHashMissing');
    expect(ChainErrorType.HLC_VIOLATION).toBe('hlcViolation');
    expect(ChainErrorType.GENESIS_VIOLATION).toBe('genesisViolation');
  });

  test('contains exactly 5 values', () => {
    expect(Object.keys(ChainErrorType)).toHaveLength(5);
  });
});
