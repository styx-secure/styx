import { describe, test, expect, beforeEach } from '@jest/globals';
import { TransportMessage, TransportState, TransportInterface } from '../../src/transport/transport-interface.js';
import {
  TransportFailover,
  TransportPriority,
  TransportFailoverException,
  OutboxWorker,
} from '../../src/transport/failover.js';
import { MemoryLedgerStore, MemoryOutboxStore } from '../../src/storage/memory-store.js';
import { createTestEvent } from '../setup.js';
import { EventEmitter } from '../../src/utils.js';

// --- Mock Transport ---
class MockTransport extends TransportInterface {
  constructor(available = true) {
    super();
    this._available = available;
    this._state = TransportState.DISCONNECTED;
    this._emitter = new EventEmitter();
    this._sendFn = null;
    this.sentMessages = [];
  }
  get currentState() { return this._state; }
  get isAvailable() { return this._available; }
  onStateChange(cb) { return this._emitter.on('stateChange', cb); }
  onMessage(cb) { return this._emitter.on('message', cb); }
  async connect() {
    this._state = TransportState.CONNECTED;
    this._emitter.emit('stateChange', TransportState.CONNECTED);
  }
  async disconnect() {
    this._state = TransportState.DISCONNECTED;
    this._emitter.emit('stateChange', TransportState.DISCONNECTED);
  }
  async send(message) {
    if (this._sendFn) return this._sendFn(message);
    this.sentMessages.push(message);
  }
  simulateMessage(msg) { this._emitter.emit('message', msg); }
  setSendBehavior(fn) { this._sendFn = fn; }
}

describe('TransportMessage', () => {
  test('construction and immutability', () => {
    const msg = new TransportMessage({
      id: 'msg-1',
      senderPubkey: 'aabb',
      recipientPubkey: 'ccdd',
      payload: new Uint8Array([1, 2, 3]),
      timestamp: new Date('2026-01-01T00:00:00Z'),
    });
    expect(msg.id).toBe('msg-1');
    expect(msg.payload).toEqual(new Uint8Array([1, 2, 3]));
    expect(Object.isFrozen(msg)).toBe(true);
  });

  test('toJSON / fromJSON roundtrip', () => {
    const msg = new TransportMessage({
      id: 'msg-2',
      senderPubkey: 'aabb',
      recipientPubkey: 'ccdd',
      payload: new Uint8Array([10, 20, 30]),
    });
    const json = msg.toJSON();
    const restored = TransportMessage.fromJSON(json);
    expect(restored.id).toBe(msg.id);
    expect(restored.senderPubkey).toBe(msg.senderPubkey);
    expect(restored.payload).toEqual(msg.payload);
  });

  test('default timestamp', () => {
    const before = Date.now();
    const msg = new TransportMessage({
      id: 't', senderPubkey: 'a', recipientPubkey: 'b',
      payload: new Uint8Array([1]),
    });
    expect(msg.timestamp.getTime()).toBeGreaterThanOrEqual(before);
  });
});

describe('TransportInterface', () => {
  test('default state is DISCONNECTED', () => {
    const t = new TransportInterface();
    expect(t.currentState).toBe(TransportState.DISCONNECTED);
    expect(t.isAvailable).toBe(false);
  });

  test('methods throw Not implemented', async () => {
    const t = new TransportInterface();
    await expect(t.connect()).rejects.toThrow('Not implemented');
    await expect(t.disconnect()).rejects.toThrow('Not implemented');
    await expect(t.send({})).rejects.toThrow('Not implemented');
    expect(() => t.onStateChange(() => {})).toThrow('Not implemented');
    expect(() => t.onMessage(() => {})).toThrow('Not implemented');
  });
});

describe('TransportFailover', () => {
  test('connect uses first available transport', async () => {
    const unavailable = new MockTransport(false);
    const available = new MockTransport(true);
    const failover = new TransportFailover([
      new TransportPriority(unavailable, 1, 5000),
      new TransportPriority(available, 1, 5000),
    ]);
    await failover.connect();
    expect(failover.currentState).toBe(TransportState.CONNECTED);
    expect(unavailable.currentState).toBe(TransportState.DISCONNECTED);
    expect(available.currentState).toBe(TransportState.CONNECTED);
  });

  test('connect throws when all transports unavailable', async () => {
    const failover = new TransportFailover([
      new TransportPriority(new MockTransport(false), 1, 5000),
    ]);
    await expect(failover.connect()).rejects.toThrow(TransportFailoverException);
  });

  test('isAvailable checks all transports', () => {
    const failover = new TransportFailover([
      new TransportPriority(new MockTransport(false), 1, 5000),
      new TransportPriority(new MockTransport(true), 1, 5000),
    ]);
    expect(failover.isAvailable).toBe(true);
    expect(failover.anyAvailable).toBe(true);
  });

  test('send delegates to connected transport', async () => {
    const transport = new MockTransport(true);
    const failover = new TransportFailover([
      new TransportPriority(transport, 1, 5000),
    ]);
    await failover.connect();

    const msg = new TransportMessage({
      id: 'x', senderPubkey: 'a', recipientPubkey: 'b',
      payload: new Uint8Array([1]),
    });
    await failover.send(msg);
    expect(transport.sentMessages).toHaveLength(1);
  });

  test('send throws when all transports fail', async () => {
    const transport = new MockTransport(true);
    transport.setSendBehavior(() => { throw new Error('fail'); });
    const failover = new TransportFailover([
      new TransportPriority(transport, 0, 100),
    ]);
    await failover.connect();

    const msg = new TransportMessage({
      id: 'x', senderPubkey: 'a', recipientPubkey: 'b',
      payload: new Uint8Array([1]),
    });
    await expect(failover.send(msg)).rejects.toThrow(TransportFailoverException);
  });

  test('disconnect cleans up', async () => {
    const transport = new MockTransport(true);
    const failover = new TransportFailover([
      new TransportPriority(transport, 1, 5000),
    ]);
    await failover.connect();
    await failover.disconnect();
    expect(failover.currentState).toBe(TransportState.DISCONNECTED);
  });

  test('message forwarding from active transport', async () => {
    const transport = new MockTransport(true);
    const failover = new TransportFailover([
      new TransportPriority(transport, 1, 5000),
    ]);
    await failover.connect();

    const received = [];
    failover.onMessage((msg) => received.push(msg));

    const msg = new TransportMessage({
      id: 'y', senderPubkey: 'a', recipientPubkey: 'b',
      payload: new Uint8Array([99]),
    });
    transport.simulateMessage(msg);
    expect(received).toHaveLength(1);
    expect(received[0].id).toBe('y');
  });

  test('dispose removes all listeners', async () => {
    const transport = new MockTransport(true);
    const failover = new TransportFailover([
      new TransportPriority(transport, 1, 5000),
    ]);
    await failover.connect();
    await failover.dispose();
    expect(failover.currentState).toBe(TransportState.DISCONNECTED);
  });
});

describe('OutboxWorker', () => {
  let ledgerStore, outboxStore, transport, worker;

  beforeEach(() => {
    ledgerStore = new MemoryLedgerStore();
    outboxStore = new MemoryOutboxStore();
    transport = new MockTransport(true);
  });

  test('processBatch sends pending events', async () => {
    await transport.connect();
    const failover = new TransportFailover([
      new TransportPriority(transport, 1, 5000),
    ]);
    await failover.connect();

    worker = new OutboxWorker({
      outboxStore, ledgerStore, transport: failover,
      encryptor: null, localPubkey: 'aabb', peerPubkey: 'ccdd',
    });

    const event = await createTestEvent();
    await ledgerStore.appendEvent(event);
    await outboxStore.addEntry(event.eventId);

    const processed = await worker.processBatch();
    expect(processed).toBe(1);
    expect(worker.sentCount).toBe(1);
  });

  test('processBatch returns 0 when nothing pending', async () => {
    const failover = new TransportFailover([
      new TransportPriority(transport, 1, 5000),
    ]);

    worker = new OutboxWorker({
      outboxStore, ledgerStore, transport: failover,
      encryptor: null, localPubkey: 'aabb', peerPubkey: 'ccdd',
    });

    const processed = await worker.processBatch();
    expect(processed).toBe(0);
  });

  test('processBatch marks failed on send error', async () => {
    transport.setSendBehavior(() => { throw new Error('network error'); });
    await transport.connect();
    const failover = new TransportFailover([
      new TransportPriority(transport, 0, 100),
    ]);
    await failover.connect();

    worker = new OutboxWorker({
      outboxStore, ledgerStore, transport: failover,
      encryptor: null, localPubkey: 'aabb', peerPubkey: 'ccdd',
    });

    const event = await createTestEvent();
    await ledgerStore.appendEvent(event);
    await outboxStore.addEntry(event.eventId);

    await worker.processBatch();
    expect(worker.failedCount).toBe(1);
  });

  test('start and stop', async () => {
    const failover = new TransportFailover([
      new TransportPriority(transport, 1, 5000),
    ]);
    worker = new OutboxWorker({
      outboxStore, ledgerStore, transport: failover,
      encryptor: null, localPubkey: 'a', peerPubkey: 'b',
    });

    expect(worker.isRunning).toBe(false);
    // Start and immediately stop to prevent infinite loop
    const startPromise = worker.start();
    worker.stop();
    await startPromise;
    expect(worker.isRunning).toBe(false);
  });
});
