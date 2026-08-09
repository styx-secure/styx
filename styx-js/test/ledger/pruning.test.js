// test/ledger/pruning.test.js
import { describe, test, expect, beforeEach, jest } from '@jest/globals';
import {
  PruneProtocol,
  RetentionManager,
  V1PruningDisabledError,
  V1_PRUNING_DISABLED_CODE,
  V1_PRUNING_DISABLED_MESSAGE,
  V1_PRUNING_DISABLED_RESULT,
} from '../../src/ledger/pruning.js';
import { EventType, LedgerEvent } from '../../src/ledger/event.js';
import { MemoryLedgerStore } from '../../src/storage/memory-store.js';
import { createTestEvent } from '../setup.js';

describe('PruneProtocol', () => {
  let protocol;
  let eventFactory;

  beforeEach(() => {
    eventFactory = { createEvent: jest.fn() };
    protocol = new PruneProtocol(eventFactory);
  });

  test('exports one stable, immutable rejection contract', () => {
    const error = new V1PruningDisabledError();
    expect(error).toBeInstanceOf(Error);
    expect(error.code).toBe(V1_PRUNING_DISABLED_CODE);
    expect(error.message).toBe(V1_PRUNING_DISABLED_MESSAGE);
    expect(typeof error.stack).toBe('string');
    expect(error.stack.length).toBeGreaterThan(0);
    expect(error.stack).toContain(V1_PRUNING_DISABLED_MESSAGE);
    expect(Object.isFrozen(error)).toBe(true);
    expect(V1_PRUNING_DISABLED_RESULT).toEqual({
      accepted: false,
      code: V1_PRUNING_DISABLED_CODE,
      message: V1_PRUNING_DISABLED_MESSAGE,
    });
    expect(Object.isFrozen(V1_PRUNING_DISABLED_RESULT)).toBe(true);
  });

  test('publishes the same containment contract from both public entry points', async () => {
    const ledgerApi = await import('../../src/ledger/index.js');
    const rootApi = await import('../../src/index.js');

    for (const api of [ledgerApi, rootApi]) {
      expect(api.V1PruningDisabledError).toBe(V1PruningDisabledError);
      expect(api.V1_PRUNING_DISABLED_CODE).toBe(V1_PRUNING_DISABLED_CODE);
      expect(api.V1_PRUNING_DISABLED_MESSAGE).toBe(V1_PRUNING_DISABLED_MESSAGE);
      expect(api.V1_PRUNING_DISABLED_RESULT).toBe(V1_PRUNING_DISABLED_RESULT);
    }
  });

  test.each(['requestPrune', 'acknowledgePrune'])(
    '%s rejects before event creation or payload access',
    async (method) => {
      const hostileInput = {};
      Object.defineProperty(hostileInput, 'payload', {
        get: () => {
          throw new Error('payload must not be read');
        },
      });

      await expect(protocol[method]({ pruneRequest: hostileInput })).rejects.toMatchObject({
        name: 'V1PruningDisabledError',
        code: V1_PRUNING_DISABLED_CODE,
        message: V1_PRUNING_DISABLED_MESSAGE,
      });
      expect(eventFactory.createEvent).not.toHaveBeenCalled();
    }
  );

  test.each(['executeBilateralPrune', 'executeUnilateralPrune'])(
    '%s rejects before accessing the store',
    async (method) => {
      const store = { pruneEvent: jest.fn() };

      await expect(protocol[method]('target', store)).rejects.toBeInstanceOf(
        V1PruningDisabledError
      );
      expect(store.pruneEvent).not.toHaveBeenCalled();
    }
  );

  test.each([
    'requestPrune',
    'acknowledgePrune',
    'executeBilateralPrune',
    'executeUnilateralPrune',
  ])('%s rejects with the same contract when called without arguments', async (method) => {
    await expect(protocol[method]()).rejects.toMatchObject({
      name: 'V1PruningDisabledError',
      code: V1_PRUNING_DISABLED_CODE,
      message: V1_PRUNING_DISABLED_MESSAGE,
    });
    expect(eventFactory.createEvent).not.toHaveBeenCalled();
  });

  test('keeps an already-pruned v1 record readable without rewriting it', async () => {
    const store = new MemoryLedgerStore();
    const event = await createTestEvent();
    const existing = event.toPruned();
    await store.appendEvent(existing);

    const readBack = await store.getEventById(existing.eventId);
    expect(readBack).toBe(existing);
    expect(readBack.isPruned).toBe(true);
    expect(readBack.payload).toBeNull();
    expect(readBack.eventHash).toBe(event.eventHash);
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
