// test/chat/styx-chat-inbound-validation.test.js
// Typed fields of an authenticated inbound payload are validated before anything
// is stored: a payload whose id, text or ts is not of the accepted type and range
// is discarded and counted, and never reaches the message store, the roster or
// the 'message' event. Records stored before this validation existed are
// neutralised when the history is loaded.
import { describe, test, expect, beforeAll, afterEach, jest } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { StyxChat } from '../../src/chat/styx-chat.js';
import { ContactRoster } from '../../src/chat/contact-roster.js';
import { MlsEngine } from '../../src/crypto/mls/mls-engine.js';

const wasmBytes = readFileSync(
  fileURLToPath(new URL('../../vendor/openmls-wasm/openmls_wasm_bg.wasm', import.meta.url)),
);

// The accepted bounds (see src/chat/inbound-payload.js).
const MAX_ID = 128;
const MAX_TEXT = 65_536;
const MAX_TS = 8_640_000_000_000_000;

const PEER = 'b'.repeat(64);
const TS = 1_780_000_000_000;
const poisoned = () => ({ valueOf: 0, toString: 0 });

function memBackend() {
  const values = new Map();
  return {
    async get(key) { return values.has(key) ? values.get(key) : null; },
    async set(key, value) { values.set(key, value); },
    async delete(key) { values.delete(key); },
  };
}

/** A chat with a known contact whose session decrypts to the given plaintext. */
async function harness() {
  const backend = memBackend();
  const roster = new ContactRoster({ backend });
  await roster.load();
  await roster.add({ pubkey: PEER, alias: 'Peer' });
  const sent = [];
  let plaintext = new Uint8Array();
  const session = {
    decrypt: jest.fn(() => ({ kind: 'application', plaintext })),
    encrypt: jest.fn((bytes) => bytes),
  };
  const engine = { session: jest.fn((from) => (from === PEER ? session : null)) };
  const transport = {
    async send(to, bytes) { sent.push({ to, bytes }); },
    onMessage() { return () => {}; },
  };
  const chat = new StyxChat({
    identity: { pubkey: 'a'.repeat(64), alias: 'Me' }, engine, roster, transport,
  });
  const messages = [];
  chat.onMessage((m) => messages.push(m));
  const states = [];
  chat.onMessageState((id, state) => states.push({ id, state }));
  const deliver = async (payload) => {
    plaintext = new TextEncoder().encode(typeof payload === 'string' ? payload : JSON.stringify(payload));
    return chat._processApp(PEER, { t: 'app', ct: 'AAAA' });
  };
  return { chat, roster, sent, messages, states, deliver };
}

const msg = (over = {}) => ({ t: 'msg', id: 'id-1', text: 'ciao', ts: TS, ...over });

describe('inbound payload validation (StyxChat._processApp)', () => {
  beforeAll(async () => { await MlsEngine.initWasm({ wasmBytes }); });
  afterEach(() => { jest.restoreAllMocks(); });

  test('a valid typed message is stored, surfaced and acknowledged', async () => {
    const h = await harness();
    await expect(h.deliver(msg())).resolves.toBe(true);
    expect(await h.chat.listMessages(PEER)).toEqual([
      { id: 'id-1', contactPubkey: PEER, direction: 'in', text: 'ciao', ts: TS, state: 'delivered' },
    ]);
    expect(h.messages).toHaveLength(1);
    expect((await h.roster.get(PEER)).lastTs).toBe(TS);
    expect(h.sent).toHaveLength(1);
  });

  test('a bare-string legacy plaintext is still accepted with a local id and time', async () => {
    const h = await harness();
    const before = Date.now();
    await h.deliver('legacy text');
    const [stored] = await h.chat.listMessages(PEER);
    expect(stored.text).toBe('legacy text');
    expect(typeof stored.id).toBe('string');
    expect(stored.ts).toBeGreaterThanOrEqual(before);
  });

  const discarded = [
    ['an object ts whose conversions are not callable', msg({ ts: poisoned() }), 'invalid-ts'],
    ['a string ts', msg({ ts: String(TS) }), 'invalid-ts'],
    ['a fractional ts', msg({ ts: TS + 0.5 }), 'invalid-ts'],
    ['a zero ts', msg({ ts: 0 }), 'invalid-ts'],
    ['a negative ts', msg({ ts: -1 }), 'invalid-ts'],
    ['a ts beyond the Date range', msg({ ts: MAX_TS + 1e6 }), 'invalid-ts'],
    ['a missing ts', { t: 'msg', id: 'id-1', text: 'ciao' }, 'invalid-ts'],
    ['an object id', msg({ id: { toString: 0 } }), 'invalid-id'],
    ['a numeric id', msg({ id: 7 }), 'invalid-id'],
    ['an empty id', msg({ id: '' }), 'invalid-id'],
    ['an over-long id', msg({ id: 'x'.repeat(MAX_ID + 1) }), 'invalid-id'],
    ['an object text', msg({ text: { toString: 0 } }), 'invalid-text'],
    ['a missing text', { t: 'msg', id: 'id-1', ts: TS }, 'invalid-text'],
    ['an over-long text', msg({ text: 'x'.repeat(MAX_TEXT + 1) }), 'invalid-text'],
    ['an array payload', [msg()], 'malformed-payload'],
    ['an unknown payload type', { ...msg(), t: 'other' }, 'unknown-type'],
    ['a payload without a type', { id: 'id-1', text: 'ciao', ts: TS }, 'unknown-type'],
  ];

  test.each(discarded)('%s is discarded, counted and never stored', async (_label, payload, reason) => {
    const h = await harness();
    await expect(h.deliver(payload)).resolves.toBe(true);
    expect(h.chat._inboundDiscards?.[reason]).toBe(1);
    expect(await h.chat.listMessages(PEER)).toEqual([]);
    expect(h.messages).toEqual([]);
    expect(h.sent).toEqual([]);
    const contact = await h.roster.get(PEER);
    expect(contact.lastTs).toBeNull();
    expect(contact.unread).toBe(0);
    await expect(h.roster.list()).resolves.toHaveLength(1);
  });

  test('a discarded message id is not remembered: a later valid copy is accepted', async () => {
    const h = await harness();
    await h.deliver(msg({ ts: 'bad' }));
    await h.deliver(msg());
    expect(await h.chat.listMessages(PEER)).toEqual([
      { id: 'id-1', contactPubkey: PEER, direction: 'in', text: 'ciao', ts: TS, state: 'delivered' },
    ]);
  });

  test('an over-long legacy plaintext is discarded as invalid text', async () => {
    const h = await harness();
    await h.deliver('x'.repeat(MAX_TEXT + 1));
    expect(h.chat._inboundDiscards?.['invalid-text']).toBe(1);
    expect(await h.chat.listMessages(PEER)).toEqual([]);
  });

  test('receipts need a valid message id and kind; invalid ones are counted', async () => {
    const h = await harness();
    await h.deliver({ t: 'receipt', ref: 'id-9', kind: 'read' });
    await h.deliver({ t: 'receipt', ref: { toString: 0 }, kind: 'read' });
    await h.deliver({ t: 'receipt', ref: 'id-9', kind: 'seen' });
    expect(h.states).toEqual([{ id: 'id-9', state: 'read' }]);
    expect(h.chat._inboundDiscards?.['invalid-receipt']).toBe(2);
  });

  test('an intro whose alias is not a string is counted and changes nothing', async () => {
    const h = await harness();
    await expect(h.deliver({ t: 'intro', alias: { toString: 0 } })).resolves.toBe(true);
    expect(h.chat._inboundDiscards?.['invalid-intro']).toBe(1);
    expect((await h.roster.get(PEER)).alias).toBe('Peer');
    await h.deliver({ t: 'intro', alias: 'Nuovo' });
    expect((await h.roster.get(PEER)).alias).toBe('Nuovo');
  });

  test('sendText refuses a text over the bound before storing anything', async () => {
    const h = await harness();
    await expect(h.chat.sendText(PEER, 'x'.repeat(MAX_TEXT + 1))).rejects.toThrow(RangeError);
    expect(await h.chat.listMessages(PEER)).toEqual([]);
    expect(h.sent).toEqual([]);
  });

  test('an instance assembled without the constructor still discards and counts', async () => {
    const roster = new ContactRoster({ backend: memBackend() });
    await roster.load();
    await roster.add({ pubkey: PEER, alias: 'Peer' });
    const plaintext = new TextEncoder().encode(JSON.stringify(msg({ ts: poisoned() })));
    const stored = [];
    const bare = Object.assign(Object.create(StyxChat.prototype), {
      _engine: { session: () => ({ decrypt: () => ({ kind: 'application', plaintext }) }) },
      _persistMls: async () => {},
      _roster: roster,
      _pending: new Map(),
      _emitter: { emit() {} },
      _seenIncoming: new Set(),
      _store: { append: async (m) => { stored.push(m); } },
      _persistMessages: async () => {},
      _sendReceipt: async () => {},
    });
    await expect(bare._processApp(PEER, { t: 'app', ct: 'AAAA' })).resolves.toBe(true);
    expect(bare._inboundDiscards?.['invalid-ts']).toBe(1);
    expect(stored).toEqual([]);
    expect((await roster.get(PEER)).lastTs).toBeNull();
  });
});

describe('stored history neutralisation at init()', () => {
  beforeAll(async () => { await MlsEngine.initWasm({ wasmBytes }); });

  const good = { id: 'g1', contactPubkey: PEER, direction: 'in', text: 'ok', ts: TS, state: 'delivered' };

  test('a poisoned history and contact index load without throwing', async () => {
    const backend = memBackend();
    const first = new StyxChat();
    await first.init({ password: 'pw', backend, channelName: 'inbound-1', allowInsecureTransport: true, autoStart: false });
    first.destroy();
    await backend.set('msgs', {
      [PEER]: [good, { ...good, id: 'p1', ts: poisoned() }, { ...good, id: { toString: 0 } }],
    });
    await backend.set('styx:contacts', {
      [PEER]: {
        pubkey: PEER, alias: 'Peer', unread: 1, lastPreview: 'ok',
        lastTs: poisoned(), verified: false, verifiedAt: null,
      },
    });

    const again = new StyxChat();
    await again.init({ password: 'pw', backend, channelName: 'inbound-2', allowInsecureTransport: true, autoStart: false });
    try {
      expect(await again.listMessages(PEER)).toEqual([good]);
      expect(again._storedMessagesDropped).toBe(2);
      const contacts = await again.listContacts();
      expect(contacts).toHaveLength(1);
      expect(contacts[0].lastTs).toBeNull();
      expect(contacts[0].unread).toBe(1);
    } finally {
      again.destroy();
    }
  });

  test('history written before the length bounds existed is kept', async () => {
    const backend = memBackend();
    const first = new StyxChat();
    await first.init({ password: 'pw', backend, channelName: 'inbound-3', allowInsecureTransport: true, autoStart: false });
    first.destroy();
    const long = { ...good, id: 'x'.repeat(MAX_ID + 1), text: 'y'.repeat(MAX_TEXT + 1) };
    await backend.set('msgs', { [PEER]: [long] });
    const again = new StyxChat();
    await again.init({ password: 'pw', backend, channelName: 'inbound-4', allowInsecureTransport: true, autoStart: false });
    try {
      expect(await again.listMessages(PEER)).toEqual([long]);
    } finally {
      again.destroy();
    }
  });
});
