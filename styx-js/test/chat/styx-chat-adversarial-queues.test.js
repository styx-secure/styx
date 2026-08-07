import { beforeAll, afterEach, describe, expect, jest, test } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { StyxChat } from '../../src/chat/styx-chat.js';
import { ContactRoster } from '../../src/chat/contact-roster.js';
import { MlsEngine } from '../../src/crypto/mls/mls-engine.js';

const wasmBytes = readFileSync(
  fileURLToPath(new URL('../../vendor/openmls-wasm/openmls_wasm_bg.wasm', import.meta.url)),
);

const encode = (value) => new TextEncoder().encode(JSON.stringify(value));
const decode = (bytes) => JSON.parse(new TextDecoder().decode(bytes));
const appBytes = (ct) => encode({ t: 'app', ct });

function memBackend() {
  const values = new Map();
  return {
    async get(key) { return values.has(key) ? values.get(key) : null; },
    async set(key, value) { values.set(key, value); },
    async delete(key) { values.delete(key); },
    async clear() { values.clear(); },
  };
}

async function harness() {
  const sessions = new Map();
  const engine = {
    session: jest.fn((from) => sessions.get(from) || null),
    keyPackageBytes: jest.fn(() => new Uint8Array([1, 2, 3])),
  };
  const roster = new ContactRoster({ backend: memBackend() });
  await roster.load();
  const transport = {
    async send() {},
    onMessage() { return () => {}; },
    close: jest.fn(),
  };
  const chat = new StyxChat({
    identity: { pubkey: 'local', alias: 'Local' }, engine, roster, transport,
  });
  return { chat, engine, sessions };
}

function pendingEntries(chat) {
  return [...chat._pendingApp.values()].flat();
}

describe('StyxChat adversarial pre-Welcome queues', () => {
  beforeAll(async () => { await MlsEngine.initWasm({ wasmBytes }); });
  afterEach(() => { jest.restoreAllMocks(); });

  test('drops unauthenticated app envelopes when no local invite is active', async () => {
    const { chat } = await harness();
    await chat._onWire('unknown', appBytes('ciphertext'));
    expect(chat._pendingApp.size).toBe(0);
    expect(chat._pendingAppBytes).toBe(0);
  });

  test('enforces per-sender and global count limits with oldest-first eviction', async () => {
    const { chat } = await harness();
    chat._inviteNonce = new Uint8Array([1]);

    for (let i = 0; i < 17; i += 1) {
      await chat._onWire('one-sender', appBytes(`cipher-${i}`));
    }
    expect(chat._pendingApp.get('one-sender')).toHaveLength(16);
    expect(chat._pendingApp.get('one-sender')[0].env.ct).toBe('cipher-1');

    chat._clearPendingApp();
    chat._inviteNonce = new Uint8Array([1]);
    for (let i = 0; i < 65; i += 1) {
      await chat._onWire(`sender-${i}`, appBytes(`cipher-${i}`));
    }
    expect(pendingEntries(chat)).toHaveLength(64);
    expect(chat._pendingApp.has('sender-0')).toBe(false);
    expect(chat._pendingApp.has('sender-64')).toBe(true);
  });

  test('enforces envelope, sender-byte and global-byte limits', async () => {
    const { chat } = await harness();
    chat._inviteNonce = new Uint8Array([1]);

    await chat._onWire('oversized', appBytes('x'.repeat(256 * 1024)));
    expect(chat._pendingApp.has('oversized')).toBe(false);

    const large = 'x'.repeat(240 * 1024);
    for (let i = 0; i < 5; i += 1) await chat._onWire('same', appBytes(`${i}${large}`));
    const senderQueue = chat._pendingApp.get('same');
    expect(senderQueue).toHaveLength(4);
    expect(senderQueue.reduce((sum, entry) => sum + entry.byteLength, 0)).toBeLessThanOrEqual(1024 * 1024);
    expect(senderQueue[0].env.ct.startsWith('1')).toBe(true);

    chat._clearPendingApp();
    chat._inviteNonce = new Uint8Array([1]);
    for (let i = 0; i < 18; i += 1) await chat._onWire(`large-${i}`, appBytes(`${i}${large}`));
    expect(chat._pendingAppBytes).toBeLessThanOrEqual(4 * 1024 * 1024);
    expect(chat._pendingApp.has('large-0')).toBe(false);
    expect(chat._pendingApp.has('large-17')).toBe(true);
  });

  test('expires queued envelopes lazily and never decrypts an expired drain', async () => {
    const { chat, sessions } = await harness();
    const now = jest.spyOn(Date, 'now').mockReturnValue(1_000);
    chat._inviteNonce = new Uint8Array([1]);
    await chat._onWire('old', appBytes('old-cipher'));

    now.mockReturnValue(121_000);
    await chat._onWire('fresh', appBytes('fresh-cipher'));
    expect(chat._pendingApp.has('old')).toBe(false);
    expect(chat._pendingApp.has('fresh')).toBe(true);

    const decrypt = jest.fn();
    sessions.set('fresh', { decrypt });
    now.mockReturnValue(241_000);
    await chat._drainPending('fresh');
    expect(decrypt).not.toHaveBeenCalled();
    expect(chat._pendingApp.size).toBe(0);
    expect(chat._pendingAppBytes).toBe(0);
  });

  test('drops malformed authenticated ciphertext instead of requeueing it', async () => {
    const { chat, sessions } = await harness();
    const decrypt = jest.fn(() => { throw new Error('invalid ciphertext'); });
    sessions.set('peer', { decrypt });
    chat._inviteNonce = new Uint8Array([1]);

    await expect(chat._onWire('peer', appBytes('AQID'))).resolves.toBeUndefined();
    expect(decrypt).toHaveBeenCalledTimes(1);
    expect(chat._pendingApp.size).toBe(0);
  });

  test('clears pending references on invite retirement, destroy and wipe', async () => {
    const { chat } = await harness();
    chat._inviteNonce = new Uint8Array([1]);
    await chat._onWire('peer', appBytes('one'));
    await chat.createQrInvite();
    expect(chat._pendingApp.size).toBe(0);
    expect(chat._pendingAppBytes).toBe(0);
    expect(chat._pendingAppOrder).toBe(0);

    await chat._onWire('peer', appBytes('one-new-invite'));
    await chat._retireInvite();
    expect(chat._pendingApp.size).toBe(0);
    expect(chat._pendingAppBytes).toBe(0);

    chat._inviteNonce = new Uint8Array([2]);
    await chat._onWire('peer', appBytes('two'));
    chat.destroy();
    expect(chat._pendingApp.size).toBe(0);

    chat._inviteNonce = new Uint8Array([3]);
    await chat._onWire('peer', appBytes('three'));
    await chat.wipe();
    expect(chat._pendingApp.size).toBe(0);
    expect(chat._pendingAppBytes).toBe(0);
  });

  test('bounds recent message deduplication to the newest 5000 ids', async () => {
    const { chat } = await harness();
    for (let i = 0; i <= 5000; i += 1) expect(chat._rememberIncoming(`id-${i}`)).toBe(true);
    expect(chat._seenIncoming.size).toBe(5000);
    expect(chat._seenIncoming.has('id-0')).toBe(false);
    expect(chat._seenIncoming.has('id-1')).toBe(true);
    expect(chat._rememberIncoming('id-5000')).toBe(false);
  });

  test('suppresses typing without an authenticated session', async () => {
    const { chat, sessions } = await harness();
    const events = [];
    chat.onTyping((from, on) => events.push({ from, on }));

    await chat._onWire('unknown', encode({ t: 'typing', on: true }));
    await chat._onWire('unknown', encode({ t: 'typing', on: 'true' }));
    expect(events).toEqual([]);

    sessions.set('peer', {});
    await chat._onWire('peer', encode({ t: 'typing', on: true }));
    expect(events).toEqual([{ from: 'peer', on: true }]);
  });

  test('malformed, accessor and prototype envelopes fail closed', async () => {
    const { chat, sessions } = await harness();
    const decrypt = jest.fn();
    sessions.set('peer', { decrypt });
    chat._inviteNonce = new Uint8Array([1]);

    await expect(chat._onWire('peer', new Uint8Array([0xff]))).resolves.toBeUndefined();
    await chat._onWire('peer', encode(null));
    await chat._onWire('peer', encode([]));
    await chat._onWire('peer', encode({ t: 'app', ct: 7 }));

    const accessor = { t: 'app', get ct() { throw new Error('getter ran'); } };
    const inherited = Object.create({ t: 'app', ct: 'ciphertext' });
    await expect(chat._processApp('peer', accessor)).resolves.toBe(false);
    await expect(chat._processApp('peer', inherited)).resolves.toBe(false);
    expect(decrypt).not.toHaveBeenCalled();
    expect(chat._pendingApp.size).toBe(0);
  });

  test('real MLS still delivers app-before-Welcome exactly once', async () => {
    const captured = [];
    const aliceEngine = await MlsEngine.create({ name: 'queue_alice' });
    const bobEngine = await MlsEngine.create({ name: 'queue_bob' });
    const aliceRoster = new ContactRoster({ backend: memBackend() });
    const bobRoster = new ContactRoster({ backend: memBackend() });
    await aliceRoster.load();
    await bobRoster.load();

    const alice = new StyxChat({
      identity: { pubkey: 'queue_alice', alias: 'Alice' },
      engine: aliceEngine,
      roster: aliceRoster,
      transport: {
        async send(to, bytes) { captured.push({ from: 'queue_alice', to, bytes }); },
        onMessage() { return () => {}; },
      },
    });
    const bob = new StyxChat({
      identity: { pubkey: 'queue_bob', alias: 'Bob' },
      engine: bobEngine,
      roster: bobRoster,
      transport: { async send() {}, onMessage() { return () => {}; } },
    });

    const { qr } = await bob.createQrInvite();
    await alice.acceptQrInvite(qr);
    await alice.confirmPairing({ contactPubkey: 'queue_bob', alias: 'Bob' });
    await alice.sendText('queue_bob', 'out of order');

    const welcome = captured.find(({ bytes }) => decode(bytes).t === 'welcome');
    const apps = captured.filter(({ bytes }) => decode(bytes).t === 'app').reverse();
    const messages = [];
    bob.onMessage((message) => messages.push(message));

    for (const frame of apps) await bob._onWire(frame.from, frame.bytes);
    expect(bob._pendingApp.get('queue_alice')).toHaveLength(apps.length);
    await bob._onWire(welcome.from, welcome.bytes);

    expect(messages.map((message) => message.text)).toEqual(['out of order']);
    expect(bob._pendingApp.size).toBe(0);
    await bob._onWire(apps[0].from, apps[0].bytes); // replay cannot be decrypted again
    expect(messages.map((message) => message.text)).toEqual(['out of order']);
    expect(bob._pendingApp.size).toBe(0);
  });
});
