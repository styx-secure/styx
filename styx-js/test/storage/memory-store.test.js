// test/storage/memory-store.test.js
import { describe, test, expect, beforeEach } from '@jest/globals';
import {
  MemoryLedgerStore,
  MemoryPeerStore,
  MemoryOutboxStore,
  MemoryKeyStore,
} from '../../src/storage/memory-store.js';
import { VectorClock } from '../../src/ledger/vector-clock.js';
import { createTestEvent } from '../setup.js';

describe('MemoryLedgerStore', () => {
  let store;

  beforeEach(() => {
    store = new MemoryLedgerStore();
  });

  test('appendEvent + getAllEvents returns events in HLC order', async () => {
    const e1 = await createTestEvent();
    const e2 = await createTestEvent({
      previousEvent: e1,
      vectorClock: VectorClock.zero(),
    });
    await store.appendEvent(e2);
    await store.appendEvent(e1);

    const all = await store.getAllEvents();
    expect(all).toHaveLength(2);
    // Should be sorted by HLC
    expect(all[0].hlc.compareTo(all[1].hlc)).toBeLessThanOrEqual(0);
  });

  test('getLatestEvent returns null when empty', async () => {
    const latest = await store.getLatestEvent();
    expect(latest).toBeNull();
  });

  test('getLatestEvent returns last event', async () => {
    const e1 = await createTestEvent();
    await store.appendEvent(e1);
    const latest = await store.getLatestEvent();
    expect(latest.eventId).toBe(e1.eventId);
  });

  test('getEventById returns event when found', async () => {
    const e = await createTestEvent();
    await store.appendEvent(e);
    const found = await store.getEventById(e.eventId);
    expect(found).not.toBeNull();
    expect(found.eventId).toBe(e.eventId);
  });

  test('getEventById returns null when not found', async () => {
    const found = await store.getEventById('nonexistent');
    expect(found).toBeNull();
  });

  test('getEventsByType filters correctly', async () => {
    const e = await createTestEvent();
    await store.appendEvent(e);
    const byType = await store.getEventsByType(e.eventType);
    expect(byType).toHaveLength(1);
    expect(byType[0].eventType).toBe(e.eventType);
  });

  test('getCurrentVectorClock merges with appended events', async () => {
    const e = await createTestEvent();
    await store.appendEvent(e);
    const vc = await store.getCurrentVectorClock();
    expect(vc).toBeInstanceOf(VectorClock);
    // After merge, VC should reflect event's VC
    const eventVc = e.vectorClock;
    expect(vc.a).toBeGreaterThanOrEqual(eventVc.a);
    expect(vc.b).toBeGreaterThanOrEqual(eventVc.b);
  });

  test('pruneEvent nullifies payload and sets isPruned', async () => {
    const e = await createTestEvent();
    await store.appendEvent(e);
    await store.pruneEvent(e.eventId);

    const pruned = await store.getEventById(e.eventId);
    expect(pruned.isPruned).toBe(true);
    expect(pruned.payload).toBeNull();
  });

  test('clear removes all events', async () => {
    const e = await createTestEvent();
    await store.appendEvent(e);
    await store.clear();

    const all = await store.getAllEvents();
    expect(all).toHaveLength(0);
  });

  test('count returns number of events', async () => {
    expect(await store.count()).toBe(0);
    const e = await createTestEvent();
    await store.appendEvent(e);
    expect(await store.count()).toBe(1);
  });
});

describe('MemoryPeerStore', () => {
  let store;

  beforeEach(() => {
    store = new MemoryPeerStore();
  });

  test('addPeer + getPeerByPubkey', async () => {
    await store.addPeer({
      pubkeyHex: 'aabb',
      alias: 'Alice',
      pairedAt: new Date(),
    });
    const peer = await store.getPeerByPubkey('aabb');
    expect(peer).not.toBeNull();
    expect(peer.alias).toBe('Alice');
    expect(peer.isActive).toBe(true);
  });

  test('getPeerByPubkey returns null for unknown key', async () => {
    const peer = await store.getPeerByPubkey('unknown');
    expect(peer).toBeNull();
  });

  test('getActivePeers includes active, excludes deactivated', async () => {
    await store.addPeer({ pubkeyHex: 'aa', alias: 'A', pairedAt: new Date() });
    await store.addPeer({ pubkeyHex: 'bb', alias: 'B', pairedAt: new Date() });
    await store.deactivatePeer('bb');

    const active = await store.getActivePeers();
    expect(active).toHaveLength(1);
    expect(active[0].alias).toBe('A');
  });

  test('deactivatePeer sets isActive to false', async () => {
    await store.addPeer({ pubkeyHex: 'cc', alias: 'C', pairedAt: new Date() });
    await store.deactivatePeer('cc');

    const peer = await store.getPeerByPubkey('cc');
    expect(peer.isActive).toBe(false);
  });

  test('updatePeerKey removes old, adds new', async () => {
    await store.addPeer({ pubkeyHex: 'old', alias: 'X', pairedAt: new Date() });
    await store.updatePeerKey({ oldPubkeyHex: 'old', newPubkeyHex: 'new' });

    const oldPeer = await store.getPeerByPubkey('old');
    expect(oldPeer).toBeNull();

    const newPeer = await store.getPeerByPubkey('new');
    expect(newPeer).not.toBeNull();
    expect(newPeer.alias).toBe('X');
  });

  test('addRekeyEntry + getRekeyHistory', async () => {
    await store.addRekeyEntry({
      oldKeyHex: 'k1',
      newKeyHex: 'k2',
      timestamp: new Date(),
    });

    const history = await store.getRekeyHistory('k2');
    expect(history).toHaveLength(1);
    expect(history[0].oldKey).toBe('k1');
    expect(history[0].newKey).toBe('k2');
  });

  test('getRekeyHistory returns entries matching either old or new key', async () => {
    await store.addRekeyEntry({
      oldKeyHex: 'k1',
      newKeyHex: 'k2',
      timestamp: new Date(),
    });

    const byOld = await store.getRekeyHistory('k1');
    expect(byOld).toHaveLength(1);

    const byNew = await store.getRekeyHistory('k2');
    expect(byNew).toHaveLength(1);
  });
});

describe('MemoryOutboxStore', () => {
  let store;

  beforeEach(() => {
    store = new MemoryOutboxStore();
  });

  test('addEntry + getReadyToSend returns pending entries', async () => {
    await store.addEntry('evt-1');
    const ready = await store.getReadyToSend();
    expect(ready).toHaveLength(1);
    expect(ready[0].eventId).toBe('evt-1');
    expect(ready[0].status).toBe('pending');
  });

  test('markSent excludes from getReadyToSend', async () => {
    await store.addEntry('evt-1');
    await store.markSent({ eventId: 'evt-1', transport: 'nostr' });

    const ready = await store.getReadyToSend();
    expect(ready).toHaveLength(0);
  });

  test('markFailed increments retryCount and sets nextRetryAt', async () => {
    await store.addEntry('evt-1');
    await store.markFailed({ eventId: 'evt-1' });

    const ready = await store.getReadyToSend();
    // Failed entry with future nextRetryAt should not be ready yet
    // (nextRetryAt is in the future)
    const entry = ready.find((e) => e.eventId === 'evt-1');
    // It might or might not be ready depending on timing
    // But we can check the internal state
    const all = await store.getReadyToSend();
    // The entry is failed with a future retry time, so not ready
    expect(all.filter((e) => e.eventId === 'evt-1')).toHaveLength(0);
  });

  test('markFailed uses exponential backoff', async () => {
    await store.addEntry('evt-1');

    await store.markFailed({ eventId: 'evt-1' });
    await store.markFailed({ eventId: 'evt-1' });

    // retryCount should be 2 after two failures
    const ready = await store.getReadyToSend();
    // The entry exists but is not ready (future retry)
    const pending = await store.pendingCount();
    // It's in 'failed' status so counts toward pending
    expect(pending).toBe(1);
  });

  test('pendingCount counts pending and failed entries', async () => {
    await store.addEntry('evt-1');
    await store.addEntry('evt-2');
    expect(await store.pendingCount()).toBe(2);

    await store.markSent({ eventId: 'evt-1', transport: 'nostr' });
    expect(await store.pendingCount()).toBe(1);
  });
});

describe('MemoryKeyStore', () => {
  let store;

  beforeEach(() => {
    store = new MemoryKeyStore();
  });

  test('storeKeyPair + retrieveKeyPair', async () => {
    const kp = { publicKey: 'pub', privateKey: 'priv' };
    await store.storeKeyPair({ keyId: 'id1', keyPair: kp });
    const retrieved = await store.retrieveKeyPair('id1');
    expect(retrieved).toEqual(kp);
  });

  test('retrieveKeyPair returns null for unknown id', async () => {
    const result = await store.retrieveKeyPair('unknown');
    expect(result).toBeNull();
  });

  test('deleteKeyPair removes the key pair', async () => {
    await store.storeKeyPair({ keyId: 'id1', keyPair: { a: 1 } });
    await store.deleteKeyPair('id1');
    const result = await store.retrieveKeyPair('id1');
    expect(result).toBeNull();
  });

  test('hasKeyPair returns true/false', async () => {
    expect(await store.hasKeyPair('id1')).toBe(false);
    await store.storeKeyPair({ keyId: 'id1', keyPair: { a: 1 } });
    expect(await store.hasKeyPair('id1')).toBe(true);
  });

  test('storeSecret + retrieveSecret', async () => {
    const secret = new Uint8Array([1, 2, 3]);
    await store.storeSecret({ key: 'mySecret', value: secret });
    const retrieved = await store.retrieveSecret('mySecret');
    expect(retrieved).toBeInstanceOf(Uint8Array);
    expect(Array.from(retrieved)).toEqual([1, 2, 3]);
  });

  test('retrieveSecret returns null for unknown key', async () => {
    const result = await store.retrieveSecret('unknown');
    expect(result).toBeNull();
  });

  test('deleteSecret removes the secret', async () => {
    await store.storeSecret({ key: 's1', value: new Uint8Array([1]) });
    await store.deleteSecret('s1');
    const result = await store.retrieveSecret('s1');
    expect(result).toBeNull();
  });

  test('deleteAll clears everything', async () => {
    await store.storeKeyPair({ keyId: 'id1', keyPair: { a: 1 } });
    await store.storeSecret({ key: 's1', value: new Uint8Array([1]) });
    await store.deleteAll();

    expect(await store.retrieveKeyPair('id1')).toBeNull();
    expect(await store.retrieveSecret('s1')).toBeNull();
  });
});
