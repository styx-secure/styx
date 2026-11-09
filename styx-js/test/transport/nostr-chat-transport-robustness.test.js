// test/transport/nostr-chat-transport-robustness.test.js
// The reference chat transport must:
//   - report a send that reached no open relay connection as a failure, so the
//     chat never marks such a message as sent;
//   - bound inbound relay frames before JSON parsing, and event contents
//     before the signature check and the base64 decoding;
//   - catch the rejection of an async message handler.
import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import * as chatTransport from '../../src/transport/nostr-chat-transport.js';
import { RelayPool } from '../../src/transport/nostr-transport.js';
import { bytesToHex, utf8Encode } from '../../src/utils.js';

const { NostrChatTransport } = chatTransport;
const KIND = 1059;
const OPEN = 1;
const CLOSED = 3;

class MockWebSocket {
  constructor(url) {
    this.url = url;
    this.readyState = OPEN;
    this.sent = [];
    this.onopen = null;
    this.onclose = null;
    this.onerror = null;
    this.onmessage = null;
    setTimeout(() => this.onopen && this.onopen(), 0);
  }
  send(data) { this.sent.push(data); }
  close() { this.readyState = CLOSED; if (this.onclose) this.onclose(); }
}

let originalWebSocket;
beforeEach(() => {
  originalWebSocket = globalThis.WebSocket;
  globalThis.WebSocket = MockWebSocket;
  MockWebSocket.OPEN = OPEN;
});
afterEach(() => { globalThis.WebSocket = originalWebSocket; });

function signedEvent(sk, pk, toPk, content) {
  const event = {
    kind: KIND, pubkey: pk, created_at: Math.floor(Date.now() / 1000),
    tags: [['p', toPk]], content,
  };
  const id = sha256(utf8Encode(JSON.stringify([
    0, event.pubkey, event.created_at, event.kind, event.tags, event.content,
  ])));
  event.id = bytesToHex(id);
  event.sig = bytesToHex(schnorr.sign(id, sk));
  return event;
}

function transportWith(relays = ['wss://r1.example']) {
  const sk = schnorr.utils.randomPrivateKey();
  const pk = bytesToHex(schnorr.getPublicKey(sk));
  return { t: new NostrChatTransport({ secretKey: sk, pubkey: pk, relays }), sk, pk };
}

const flush = async () => { for (let i = 0; i < 5; i += 1) await new Promise((r) => setTimeout(r, 0)); };

describe('NostrChatTransport.send reports a send that reached no relay', () => {
  test('rejects with NO_OPEN_RELAY when no relay connection is open', async () => {
    const { t } = transportWith();
    // The pool was never connected: zero open sockets.
    await expect(t.send('ab'.repeat(32), utf8Encode('x'))).rejects.toMatchObject({ code: 'NO_OPEN_RELAY' });
  });

  test('rejects when the only socket closed after connecting', async () => {
    const { t } = transportWith();
    await t._pool.connectAll();
    for (const ws of t._pool._connections.values()) ws.readyState = CLOSED;
    await expect(t.send('ab'.repeat(32), utf8Encode('x'))).rejects.toMatchObject({ code: 'NO_OPEN_RELAY' });
    await t._pool.disconnectAll();
  });

  test('resolves with the number of open connections the event was written to', async () => {
    const { t } = transportWith(['wss://r1.example', 'wss://r2.example']);
    await t._pool.connectAll();
    await expect(t.send('ab'.repeat(32), utf8Encode('x'))).resolves.toBe(2);
    const frames = [...t._pool._connections.values()].map((ws) => ws.sent.length);
    expect(frames).toEqual([1, 1]);
    await t._pool.disconnectAll();
  });

  test('exports the error class it throws', () => {
    expect(typeof chatTransport.NoOpenRelayError).toBe('function');
  });
});

describe('NostrChatTransport bounds inbound data before decoding', () => {
  test('drops a correctly signed event whose content exceeds the bound', () => {
    const { t, pk } = transportWith();
    const senderSk = schnorr.utils.randomPrivateKey();
    const senderPk = bytesToHex(schnorr.getPublicKey(senderSk));
    const cb = jest.fn();
    t.onMessage(cb);
    expect(Number.isSafeInteger(chatTransport.MAX_EVENT_CONTENT_LENGTH)).toBe(true);
    const big = 'A'.repeat(chatTransport.MAX_EVENT_CONTENT_LENGTH + 4);
    t._onRelay(['EVENT', 'sub', signedEvent(senderSk, senderPk, pk, big)]);
    expect(cb).not.toHaveBeenCalled();
  });

  test('still delivers a correctly signed event at the bound', () => {
    const { t, pk } = transportWith();
    const senderSk = schnorr.utils.randomPrivateKey();
    const senderPk = bytesToHex(schnorr.getPublicKey(senderSk));
    const cb = jest.fn();
    t.onMessage(cb);
    const atBound = 'A'.repeat(chatTransport.MAX_EVENT_CONTENT_LENGTH);
    t._onRelay(['EVENT', 'sub', signedEvent(senderSk, senderPk, pk, atBound)]);
    expect(cb).toHaveBeenCalledTimes(1);
  });

  test('its relay pool drops an oversized frame before JSON parsing', async () => {
    const { t } = transportWith();
    await t._pool.connectAll();
    const got = [];
    t._pool.messages.on('message', (m) => got.push(m));
    const ws = [...t._pool._connections.values()][0];
    const parse = jest.spyOn(JSON, 'parse');
    try {
      ws.onmessage({ data: `["NOTICE","${'x'.repeat(chatTransport.MAX_RELAY_FRAME_LENGTH)}"]` });
      expect(parse).not.toHaveBeenCalled();
    } finally {
      parse.mockRestore();
    }
    expect(got).toHaveLength(0);
    ws.onmessage({ data: '["NOTICE","small"]' });
    expect(got).toHaveLength(1);
    await t._pool.disconnectAll();
  });
});

describe('RelayPool maxFrameLength option', () => {
  test('unset keeps the unbounded behaviour', async () => {
    const pool = new RelayPool(['wss://r1.example']);
    await pool.connectAll();
    const got = [];
    pool.messages.on('message', (m) => got.push(m));
    [...pool._connections.values()][0].onmessage({ data: JSON.stringify(['NOTICE', 'y'.repeat(5000)]) });
    expect(got).toHaveLength(1);
    await pool.disconnectAll();
  });

  test('set, frames over the bound or not strings are dropped and counted', async () => {
    const pool = new RelayPool(['wss://r1.example'], { maxFrameLength: 100 });
    await pool.connectAll();
    const got = [];
    pool.messages.on('message', (m) => got.push(m));
    const ws = [...pool._connections.values()][0];
    ws.onmessage({ data: JSON.stringify(['NOTICE', 'y'.repeat(200)]) });
    ws.onmessage({ data: new Uint8Array(10) });
    ws.onmessage({ data: JSON.stringify(['NOTICE', 'ok']) });
    expect(got).toHaveLength(1);
    expect(pool.oversizedFrameCount).toBe(2);
    await pool.disconnectAll();
  });

  test('an invalid bound is refused', () => {
    expect(() => new RelayPool([], { maxFrameLength: 0 })).toThrow(TypeError);
    expect(() => new RelayPool([], { maxFrameLength: 1.5 })).toThrow(TypeError);
  });
});

describe('NostrChatTransport catches an async handler rejection', () => {
  test('the rejection is logged, never left unhandled', async () => {
    const { t, pk } = transportWith();
    const senderSk = schnorr.utils.randomPrivateKey();
    const senderPk = bytesToHex(schnorr.getPublicKey(senderSk));
    const unhandled = [];
    const onUnhandled = (reason) => unhandled.push(reason);
    process.on('unhandledRejection', onUnhandled);
    const errors = jest.spyOn(console, 'error').mockImplementation(() => {});
    try {
      t.onMessage(async () => { throw new Error('handler failed'); });
      t._onRelay(['EVENT', 'sub', signedEvent(senderSk, senderPk, pk, 'aGVsbG8=')]);
      await flush();
      expect(unhandled).toHaveLength(0);
      expect(errors).toHaveBeenCalledWith('[NostrChatTransport] handler error:', expect.any(Error));
    } finally {
      errors.mockRestore();
      process.off('unhandledRejection', onUnhandled);
    }
  });
});
