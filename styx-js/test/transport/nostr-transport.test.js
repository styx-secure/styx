import { describe, test, expect, beforeEach, afterEach } from '@jest/globals';
import { RelayPool, NostrTransport } from '../../src/transport/nostr-transport.js';
import { TransportMessage, TransportState } from '../../src/transport/transport-interface.js';
import { StyxEncryptor } from '../../src/crypto/encryption.js';
import { randomBytes, bytesToBase64 } from '../../src/utils.js';

// --- Mock WebSocket ---
const OPEN = 1;
const CLOSED = 3;

class MockWebSocket {
  constructor(url) {
    this.url = url;
    this.readyState = OPEN;
    this._sentMessages = [];
    this.onopen = null;
    this.onclose = null;
    this.onerror = null;
    this.onmessage = null;
    // Auto-connect
    setTimeout(() => this.onopen && this.onopen(), 0);
  }
  send(data) { this._sentMessages.push(data); }
  close() {
    this.readyState = CLOSED;
    if (this.onclose) this.onclose();
  }
}

let originalWebSocket;

beforeEach(() => {
  originalWebSocket = globalThis.WebSocket;
  globalThis.WebSocket = MockWebSocket;
  MockWebSocket.OPEN = OPEN;
});

afterEach(() => {
  globalThis.WebSocket = originalWebSocket;
});

describe('RelayPool', () => {
  test('constructor stores relay URLs', () => {
    const pool = new RelayPool(['wss://r1.example', 'wss://r2.example']);
    expect(pool.relayUrls).toEqual(['wss://r1.example', 'wss://r2.example']);
  });

  test('connectAll connects to relays', async () => {
    const pool = new RelayPool(['wss://r1.example']);
    const count = await pool.connectAll();
    expect(count).toBe(1);
  });

  test('disconnectAll closes connections', async () => {
    const pool = new RelayPool(['wss://r1.example']);
    await pool.connectAll();
    await pool.disconnectAll();
    // connections map should be empty
  });

  test('publish sends to all connected relays', async () => {
    const pool = new RelayPool(['wss://r1.example']);
    await pool.connectAll();
    const sent = pool.publish({ kind: 30078, content: 'test' });
    expect(sent).toBe(1);
  });

  test('subscribe sends REQ to all relays', async () => {
    const pool = new RelayPool(['wss://r1.example']);
    await pool.connectAll();
    pool.subscribe('sub-1', { kinds: [30078] });
    // Verifying no throws
  });

  test('healthCheck returns status per relay', () => {
    const pool = new RelayPool(['wss://r1.example', 'wss://r2.example']);
    const health = pool.healthCheck();
    expect(health).toHaveLength(2);
    expect(health[0].url).toBe('wss://r1.example');
  });

  test('addRelay adds new URL', () => {
    const pool = new RelayPool(['wss://r1.example']);
    pool.addRelay('wss://r3.example');
    expect(pool.relayUrls).toContain('wss://r3.example');
  });

  test('addRelay ignores duplicates', () => {
    const pool = new RelayPool(['wss://r1.example']);
    pool.addRelay('wss://r1.example');
    expect(pool.relayUrls).toHaveLength(1);
  });

  test('removeRelay removes URL', async () => {
    const pool = new RelayPool(['wss://r1.example', 'wss://r2.example']);
    await pool.connectAll();
    await pool.removeRelay('wss://r1.example');
    expect(pool.relayUrls).toEqual(['wss://r2.example']);
  });

  test('dispose cleans up', async () => {
    const pool = new RelayPool(['wss://r1.example']);
    await pool.connectAll();
    await pool.dispose();
  });

  test('publishAndVerify resolves verified when event is returned', async () => {
    const pool = new RelayPool(['wss://r1.example']);
    await pool.connectAll();

    const event = { id: 'abc123', kind: 30078, content: 'test' };

    // Simulate relay returning the event after subscribe
    const origSubscribe = pool.subscribe.bind(pool);
    pool.subscribe = (subId, filter) => {
      origSubscribe(subId, filter);
      // Simulate relay sending back the event
      setTimeout(() => {
        pool.messages.emit('message', {
          relay: 'wss://r1.example',
          data: ['EVENT', subId, { id: 'abc123' }],
        });
      }, 10);
    };

    const result = await pool.publishAndVerify(event, 2000);
    expect(result.sent).toBe(1);
    expect(result.verified).toBe(true);
  });

  test('publishAndVerify times out if event not returned', async () => {
    const pool = new RelayPool(['wss://r1.example']);
    await pool.connectAll();

    const event = { id: 'xyz789', kind: 30078, content: 'test' };
    const result = await pool.publishAndVerify(event, 200); // short timeout
    expect(result.sent).toBe(1);
    expect(result.verified).toBe(false);
  });

  test('publishAndVerify returns sent=0 when no relays connected', async () => {
    const pool = new RelayPool([]);
    const event = { id: 'nope', kind: 30078, content: 'test' };
    const result = await pool.publishAndVerify(event);
    expect(result.sent).toBe(0);
    expect(result.verified).toBe(false);
  });

  test('messages emitter is accessible', () => {
    const pool = new RelayPool(['wss://r1.example']);
    expect(pool.messages).toBeDefined();
  });
});

describe('NostrTransport', () => {
  let pool, encryptor, transport;

  beforeEach(() => {
    pool = new RelayPool(['wss://r1.example']);
    const key = randomBytes(32);
    encryptor = new StyxEncryptor(key, key);
    transport = new NostrTransport(pool, encryptor, 'aabb', 'ccdd');
  });

  test('initial state is DISCONNECTED', () => {
    expect(transport.currentState).toBe(TransportState.DISCONNECTED);
  });

  test('isAvailable checks for WebSocket', () => {
    expect(transport.isAvailable).toBe(true);
  });

  test('connect sets state to CONNECTED', async () => {
    await transport.connect();
    expect(transport.currentState).toBe(TransportState.CONNECTED);
  });

  test('connect throws if no relays connect', async () => {
    // Override with failing WebSocket
    globalThis.WebSocket = class {
      constructor() {
        setTimeout(() => this.onerror && this.onerror(new Error('fail')), 0);
      }
      close() {}
    };
    const pool2 = new RelayPool(['wss://bad.example']);
    const t2 = new NostrTransport(pool2, encryptor, 'aabb', 'ccdd');
    await expect(t2.connect()).rejects.toThrow('Could not connect to any relay');
  });

  test('disconnect sets state to DISCONNECTED', async () => {
    await transport.connect();
    await transport.disconnect();
    expect(transport.currentState).toBe(TransportState.DISCONNECTED);
  });

  test('send publishes encrypted event to relay pool', async () => {
    await transport.connect();
    const msg = new TransportMessage({
      id: 'test-1',
      senderPubkey: 'aabb',
      recipientPubkey: 'ccdd',
      payload: new Uint8Array([1, 2, 3]),
    });
    await transport.send(msg);
    // No throw means success
  });

  test('send throws when not connected', async () => {
    const msg = new TransportMessage({
      id: 'test-1', senderPubkey: 'aabb', recipientPubkey: 'ccdd',
      payload: new Uint8Array([1]),
    });
    await expect(transport.send(msg)).rejects.toThrow('not connected');
  });

  test('onStateChange emits state transitions', async () => {
    const states = [];
    transport.onStateChange((s) => states.push(s));
    await transport.connect();
    expect(states).toContain(TransportState.CONNECTING);
    expect(states).toContain(TransportState.CONNECTED);
  });

  test('onMessage receives decrypted messages', async () => {
    await transport.connect();

    const received = [];
    transport.onMessage((msg) => received.push(msg));

    // Simulate incoming Nostr event from peer
    const innerMsg = new TransportMessage({
      id: 'incoming-1',
      senderPubkey: 'ccdd',
      recipientPubkey: 'aabb',
      payload: new Uint8Array([10, 20]),
    });
    const serialized = new TextEncoder().encode(JSON.stringify(innerMsg.toJSON()));
    const encrypted = encryptor.encrypt(serialized);

    const nostrEvent = {
      pubkey: 'ccdd',
      content: bytesToBase64(encrypted),
      kind: 30078,
    };

    // Emit via relay pool
    pool.messages.emit('message', {
      relay: 'wss://r1.example',
      data: ['EVENT', 'sub-id', nostrEvent],
    });

    expect(received).toHaveLength(1);
    expect(received[0].id).toBe('incoming-1');
  });

  test('_handleRelayMessage ignores non-EVENT messages', async () => {
    await transport.connect();
    const received = [];
    transport.onMessage((msg) => received.push(msg));

    pool.messages.emit('message', {
      relay: 'wss://r1.example',
      data: ['NOTICE', 'some notice'],
    });
    expect(received).toHaveLength(0);
  });

  test('_handleRelayMessage ignores events from non-peer', async () => {
    await transport.connect();
    const received = [];
    transport.onMessage((msg) => received.push(msg));

    pool.messages.emit('message', {
      relay: 'wss://r1.example',
      data: ['EVENT', 'sub-id', { pubkey: 'unknown', content: 'bad' }],
    });
    expect(received).toHaveLength(0);
  });

  test('dispose cleans up', async () => {
    await transport.connect();
    await transport.dispose();
    expect(transport.currentState).toBe(TransportState.DISCONNECTED);
  });
});
