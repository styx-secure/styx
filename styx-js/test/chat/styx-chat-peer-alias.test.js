// test/chat/styx-chat-peer-alias.test.js
// The alias of a contact is the name chosen on this device. The name a peer
// declares for itself in an encrypted introduction is peer-chosen: it is kept
// apart (peerAlias), never replaces the local alias, and never changes the
// verified state, which binds the public key, not a name.
import { describe, test, expect, beforeAll, afterEach, jest } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { StyxChat } from '../../src/chat/styx-chat.js';
import { ContactRoster } from '../../src/chat/contact-roster.js';
import { MlsEngine } from '../../src/crypto/mls/mls-engine.js';

const wasmBytes = readFileSync(
  fileURLToPath(new URL('../../vendor/openmls-wasm/openmls_wasm_bg.wasm', import.meta.url)),
);

const INDEX_KEY = 'styx:contacts';
const PEER = 'c'.repeat(64);

function memBackend(initial = {}) {
  const values = new Map(Object.entries(initial));
  const writes = [];
  return {
    values,
    writes,
    async get(key) { return values.has(key) ? values.get(key) : null; },
    async set(key, value) { writes.push(key); values.set(key, JSON.parse(JSON.stringify(value))); },
    async delete(key) { values.delete(key); },
  };
}

/** A chat whose session with PEER decrypts to the payload handed to deliver(). */
async function harness({ contact = true } = {}) {
  const backend = memBackend();
  const roster = new ContactRoster({ backend });
  await roster.load();
  if (contact) {
    await roster.add({ pubkey: PEER, alias: 'Luca (lavoro)' });
    await roster.setVerified(PEER, true);
  }
  let plaintext = new Uint8Array();
  const session = {
    decrypt: jest.fn(() => ({ kind: 'application', plaintext })),
    encrypt: jest.fn((bytes) => bytes),
  };
  const engine = { session: jest.fn((from) => (from === PEER ? session : null)) };
  const transport = { async send() {}, onMessage() { return () => {}; } };
  const chat = new StyxChat({
    identity: { pubkey: 'a'.repeat(64), alias: 'Me' }, engine, roster, transport,
  });
  const deliver = async (payload) => {
    plaintext = new TextEncoder().encode(JSON.stringify(payload));
    return chat._processApp(PEER, { t: 'app', ct: 'AAAA' });
  };
  return { chat, roster, backend, deliver };
}

describe('peer-declared name for an accepted contact (StyxChat._processApp)', () => {
  beforeAll(async () => { await MlsEngine.initWasm({ wasmBytes }); });
  afterEach(() => { jest.restoreAllMocks(); });

  test('an intro never replaces the local alias and leaves verification as it is', async () => {
    const h = await harness();
    const before = await h.roster.get(PEER);
    expect(before).toMatchObject({ alias: 'Luca (lavoro)', verified: true });
    expect(typeof before.verifiedAt).toBe('number');

    await expect(h.deliver({ t: 'intro', alias: 'Mamma' })).resolves.toBe(true);

    const after = await h.roster.get(PEER);
    expect(after.alias).toBe('Luca (lavoro)');
    expect(after.peerAlias).toBe('Mamma');
    expect(after.verified).toBe(true);
    expect(after.verifiedAt).toBe(before.verifiedAt);
  });

  test('the persisted record keeps the local alias and stores the declared name apart', async () => {
    const h = await harness();
    await h.deliver({ t: 'intro', alias: 'Mamma' });
    const saved = h.backend.values.get(INDEX_KEY)[PEER];
    expect(saved.alias).toBe('Luca (lavoro)');
    expect(saved.peerAlias).toBe('Mamma');
    expect(saved.verified).toBe(true);

    // A fresh roster over the same storage sees the same separation.
    const reloaded = new ContactRoster({ backend: h.backend });
    await reloaded.load();
    expect(await reloaded.get(PEER)).toMatchObject({
      alias: 'Luca (lavoro)', peerAlias: 'Mamma', verified: true,
    });
  });

  test('a changed declared name replaces only the previous declared name', async () => {
    const h = await harness();
    await h.deliver({ t: 'intro', alias: 'Luca' });
    await h.deliver({ t: 'intro', alias: 'Banca' });
    expect(await h.roster.get(PEER)).toMatchObject({
      alias: 'Luca (lavoro)', peerAlias: 'Banca', verified: true,
    });
  });

  test('the same declared name again writes nothing', async () => {
    const h = await harness();
    await h.deliver({ t: 'intro', alias: 'Luca' });
    const writes = h.backend.writes.filter((k) => k === INDEX_KEY).length;
    await h.deliver({ t: 'intro', alias: 'Luca' });
    expect(h.backend.writes.filter((k) => k === INDEX_KEY).length).toBe(writes);
  });

  test('the declared name is sanitized; one with nothing legible changes nothing', async () => {
    const h = await harness();
    await h.deliver({ t: 'intro', alias: '\u202EMamma\u0007' });
    expect((await h.roster.get(PEER)).peerAlias).toBe('Mamma');
    await h.deliver({ t: 'intro', alias: '\u200B\u202E ' });
    expect(await h.roster.get(PEER)).toMatchObject({ alias: 'Luca (lavoro)', peerAlias: 'Mamma' });
  });

  test('before acceptance the declared name stays the default and is kept as peerAlias', async () => {
    const h = await harness({ contact: false });
    await h.deliver({ t: 'intro', alias: 'Alice' });
    await h.chat.confirmPairing({ contactPubkey: PEER });
    expect(await h.roster.get(PEER)).toMatchObject({ alias: 'Alice', peerAlias: 'Alice', verified: false });
  });

  test('a name typed at acceptance is the alias; the declared one stays apart', async () => {
    const h = await harness({ contact: false });
    await h.deliver({ t: 'intro', alias: 'Alice' });
    await h.chat.confirmPairing({ contactPubkey: PEER, alias: 'Alice (lavoro)' });
    expect(await h.roster.get(PEER)).toMatchObject({ alias: 'Alice (lavoro)', peerAlias: 'Alice' });
  });

  test('a contact accepted without any introduction has no peerAlias', async () => {
    const h = await harness({ contact: false });
    await h.chat.confirmPairing({ contactPubkey: PEER, alias: 'Alice' });
    const c = await h.roster.get(PEER);
    expect(c.alias).toBe('Alice');
    expect(Object.prototype.hasOwnProperty.call(c, 'peerAlias')).toBe(false);
  });
});

describe('peer-declared name over a real MLS session', () => {
  beforeAll(async () => { await MlsEngine.initWasm({ wasmBytes }); });

  function makeBus() {
    const handlers = new Map();
    return {
      transportFor(pk) {
        return {
          async send(to, bytes) { const h = handlers.get(to); if (h) queueMicrotask(() => h(pk, bytes)); },
          onMessage(cb) { handlers.set(pk, cb); return () => handlers.delete(pk); },
        };
      },
    };
  }
  const flush = async () => { for (let i = 0; i < 10; i++) await new Promise((r) => setTimeout(r, 0)); };
  async function peer(bus, pubkey, alias) {
    const engine = await MlsEngine.create({ name: pubkey });
    const roster = new ContactRoster({ backend: memBackend() });
    await roster.load();
    const chat = new StyxChat({ identity: { pubkey, alias }, engine, roster, transport: bus.transportFor(pubkey) });
    await chat.start();
    return chat;
  }

  test('a verified contact renamed by the peer keeps the local alias and its verification', async () => {
    const bus = makeBus();
    const bob = await peer(bus, 'bob_pa1', 'Bob');
    const alice = await peer(bus, 'alice_pa1', 'Alice');
    const { qr } = await bob.createQrInvite();
    await alice.acceptQrInvite(qr);
    await flush();
    await bob.confirmPairing({ contactPubkey: 'alice_pa1', alias: 'Alice (lavoro)' });
    await bob.setVerified('alice_pa1', true);

    await alice.setAlias('Mamma');
    await alice._sendIntro('bob_pa1');
    await flush();

    const c = (await bob.listContacts()).find((x) => x.pubkey === 'alice_pa1');
    expect(c).toMatchObject({ alias: 'Alice (lavoro)', peerAlias: 'Mamma', verified: true });
  });
});

describe('ContactRoster.peerAlias', () => {
  const record = (over = {}) => ({
    pubkey: 'aa', alias: 'A', unread: 0, lastPreview: null, lastTs: null,
    verified: true, verifiedAt: 7, ...over,
  });

  test('a record stored before peerAlias existed loads unchanged, with no peerAlias', async () => {
    const backend = memBackend({ [INDEX_KEY]: { aa: record() } });
    const roster = new ContactRoster({ backend });
    await roster.load();
    const c = await roster.get('aa');
    expect(c).toEqual({ ...record(), online: false });
    expect(Object.prototype.hasOwnProperty.call(c, 'peerAlias')).toBe(false);
  });

  test('a stored peerAlias that is a non-empty string is kept and saved again', async () => {
    const backend = memBackend({ [INDEX_KEY]: { aa: record({ peerAlias: 'Mamma' }) } });
    const roster = new ContactRoster({ backend });
    await roster.load();
    expect(await roster.get('aa')).toMatchObject({ alias: 'A', peerAlias: 'Mamma', verified: true });
    await roster.clearUnread('aa');
    expect(backend.values.get(INDEX_KEY).aa.peerAlias).toBe('Mamma');
  });

  test('a stored peerAlias of the wrong type, empty or over the bound is dropped at load', async () => {
    for (const bad of [{ toString: 0 }, 42, '', 'x'.repeat(129), null, ['M']]) {
      const backend = memBackend({ [INDEX_KEY]: { aa: record({ peerAlias: bad }) } });
      const roster = new ContactRoster({ backend });
      await roster.load();
      const c = await roster.get('aa');
      expect(Object.prototype.hasOwnProperty.call(c, 'peerAlias')).toBe(false);
      expect(c).toMatchObject({ alias: 'A', verified: true, verifiedAt: 7 });
    }
  });

  test('setPeerAlias changes neither alias nor verification', async () => {
    const backend = memBackend({ [INDEX_KEY]: { aa: record() } });
    const roster = new ContactRoster({ backend });
    await roster.load();
    const c = await roster.setPeerAlias('aa', 'Mamma');
    expect(c).toMatchObject({ alias: 'A', peerAlias: 'Mamma', verified: true, verifiedAt: 7 });
  });

  test('setPeerAlias refuses an unknown contact and an invalid name', async () => {
    const backend = memBackend({ [INDEX_KEY]: { aa: record() } });
    const roster = new ContactRoster({ backend });
    await roster.load();
    await expect(roster.setPeerAlias('zz', 'X')).rejects.toThrow(/Unknown contact/);
    await expect(roster.setPeerAlias('aa', '')).rejects.toThrow(TypeError);
    await expect(roster.setPeerAlias('aa', { toString: 0 })).rejects.toThrow(TypeError);
    expect(Object.prototype.hasOwnProperty.call(await roster.get('aa'), 'peerAlias')).toBe(false);
  });

  test('re-adding an existing contact keeps its peerAlias unless a new one is given', async () => {
    const backend = memBackend({ [INDEX_KEY]: { aa: record({ peerAlias: 'Mamma' }) } });
    const roster = new ContactRoster({ backend });
    await roster.load();
    expect(await roster.add({ pubkey: 'aa', alias: 'B' })).toMatchObject({ alias: 'B', peerAlias: 'Mamma' });
    expect(await roster.add({ pubkey: 'aa', alias: 'B', peerAlias: 'Zia' })).toMatchObject({ peerAlias: 'Zia' });
  });
});
