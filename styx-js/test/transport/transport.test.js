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

describe('TransportFailover shutdown lifecycle regression', () => {
  class CountingTransport extends MockTransport {
    constructor() { super(); this.connectCalls = 0; }
    async connect() { this.connectCalls++; await super.connect(); }
  }
  test.each(['disconnect', 'dispose'])('%s does not reconnect on intentional shutdown', async method => {
    const child = new CountingTransport();
    const f = new TransportFailover([new TransportPriority(child, 0, 1000)]);
    await f.connect();
    await f[method]();
    expect(child.connectCalls).toBe(1);
    expect(child.currentState).toBe(TransportState.DISCONNECTED);
    expect(f.currentState).toBe(TransportState.DISCONNECTED);
  });
  test('late connect completion cannot reactivate after disconnect', async () => {
    const child = new CountingTransport();
    let release;
    const gate = new Promise(resolve => { release = resolve; });
    child.connect = async () => { child.connectCalls++; await gate; await MockTransport.prototype.connect.call(child); };
    const f = new TransportFailover([new TransportPriority(child,0,1000)]);
    const outcome = f.connect().then(() => 'connected', () => 'cancelled');
    await f.disconnect();
    release();
    await outcome;
    expect(f.currentState).toBe(TransportState.DISCONNECTED);
    expect(child.currentState).toBe(TransportState.DISCONNECTED);
  });
  test('explicit reconnect remains possible without duplicate forwarding', async () => {
    const child = new CountingTransport();
    const f = new TransportFailover([new TransportPriority(child,0,1000)]);
    await f.connect(); await f.disconnect(); await f.connect();
    const seen=[]; f.onMessage(x=>seen.push(x)); child.simulateMessage({id:'once'});
    expect(child.connectCalls).toBe(2); expect(seen).toHaveLength(1);
    await f.dispose();
  });
  test('unexpected active loss still reconnects', async () => {
    const child = new CountingTransport();
    const f = new TransportFailover([new TransportPriority(child,0,1000)]);
    await f.connect();
    const ready = new Promise(resolve=>f.onStateChange(s=>{if(s===TransportState.CONNECTED)resolve();}));
    await child.disconnect(); await ready;
    expect(child.connectCalls).toBe(2); expect(f.currentState).toBe(TransportState.CONNECTED);
    await f.dispose();
  });
});

describe('TransportFailover F-01 stale completion ownership', () => {
  test('closes stale A while preserving a different active B', async () => {
    const a = new MockTransport();
    const b = new MockTransport();
    let release;
    const gate = new Promise(resolve => { release = resolve; });
    a.connect = async () => {
      await gate;
      await MockTransport.prototype.connect.call(a);
    };
    const f = new TransportFailover([
      new TransportPriority(a, 0, 1000),
      new TransportPriority(b, 0, 1000),
    ]);
    const oldOutcome = f.connect().then(() => 'fulfilled', error => error.message);
    await f.disconnect();
    a._available = false;
    await f.connect();
    release();
    const outcome = await oldOutcome;
    const observed = {
      outcome,
      a: a.currentState,
      b: b.currentState,
      active: f._activeTransport,
      state: f.currentState,
    };
    await f.dispose();
    expect(observed.outcome).toBe('Connection cancelled');
    expect(observed.a).toBe(TransportState.DISCONNECTED);
    expect(observed.b).toBe(TransportState.CONNECTED);
    expect(observed.active).toBe(b);
    expect(observed.state).toBe(TransportState.CONNECTED);
  });

  test('does not disconnect a valid new activation reusing the same child', async () => {
    const child = new MockTransport();
    let release;
    const gate = new Promise(resolve => { release = resolve; });
    let calls = 0;
    child.connect = async () => {
      if (++calls === 1) await gate;
      await MockTransport.prototype.connect.call(child);
    };
    const f = new TransportFailover([new TransportPriority(child, 0, 1000)]);
    const oldOutcome = f.connect().then(() => 'fulfilled', error => error.message);
    await f.disconnect();
    await f.connect();
    release();
    const outcome = await oldOutcome;
    const seen = [];
    f.onMessage(message => seen.push(message));
    child.simulateMessage({ id: 'same-child-once' });
    const observed = { state: child.currentState, active: f._activeTransport, wrapper: f.currentState };
    await f.dispose();
    expect(outcome).toBe('Connection cancelled');
    expect(calls).toBe(2);
    expect(observed.state).toBe(TransportState.CONNECTED);
    expect(observed.active).toBe(child);
    expect(observed.wrapper).toBe(TransportState.CONNECTED);
    expect(seen).toEqual([{ id: 'same-child-once' }]);
  });
});
