// test/chat/styx-chat.test.js
import { describe, test, expect, beforeAll } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { StyxChat } from '../../src/chat/styx-chat.js';
import { MlsEngine } from '../../src/crypto/mls/mls-engine.js';
import { ContactRoster } from '../../src/chat/contact-roster.js';

const wasmBytes = readFileSync(
  fileURLToPath(new URL('../../vendor/openmls-wasm/openmls_wasm_bg.wasm', import.meta.url)),
);

/** In-memory KV backend. */
function memBackend() {
  const m = new Map();
  return {
    async get(k) { return m.has(k) ? m.get(k) : null; },
    async set(k, v) { m.set(k, v); },
    async delete(k) { m.delete(k); },
  };
}

/** In-memory transport bus keyed by pubkey. */
function makeBus() {
  const handlers = new Map();
  return {
    transportFor(selfPubkey) {
      return {
        async send(toPubkey, bytes) {
          const h = handlers.get(toPubkey);
          if (h) queueMicrotask(() => h(selfPubkey, bytes));
        },
        onMessage(cb) { handlers.set(selfPubkey, cb); return () => handlers.delete(selfPubkey); },
      };
    },
  };
}

const flush = async () => { for (let i = 0; i < 5; i++) await new Promise((r) => setTimeout(r, 0)); };

async function makePeer(bus, pubkey, alias) {
  const engine = await MlsEngine.create({ name: pubkey });
  const roster = new ContactRoster({ backend: memBackend() });
  await roster.load();
  const chat = new StyxChat({
    identity: { pubkey, alias },
    engine,
    roster,
    transport: bus.transportFor(pubkey),
  });
  await chat.start();
  return chat;
}

describe('StyxChat orchestrator (in-memory transport, real MLS)', () => {
  beforeAll(async () => { await MlsEngine.initWasm({ wasmBytes }); });

  test('two peers pair via QR invite and exchange an encrypted message', async () => {
    const bus = makeBus();
    const alice = await makePeer(bus, 'alice_pk', 'Alice');
    const bob = await makePeer(bus, 'bob_pk', 'Bob');

    // Bob shows his invite; Alice scans/accepts it.
    const { qr } = await bob.createQrInvite();
    const { contactPubkey } = await alice.acceptQrInvite(qr);
    expect(contactPubkey).toBe('bob_pk');
    await alice.confirmPairing({ contactPubkey, alias: 'Bob' });
    await flush(); // welcome delivered → Bob joins + adds Alice

    // Both sides now have the contact.
    expect((await alice.listContacts()).map((c) => c.pubkey)).toContain('bob_pk');
    expect((await bob.listContacts()).map((c) => c.pubkey)).toContain('alice_pk');

    // Alice -> Bob encrypted message arrives decrypted at Bob.
    const gotAtBob = new Promise((res) => bob.onMessage((m) => res(m)));
    await alice.sendText('bob_pk', 'Ciao Bob 🔐');
    const msg = await gotAtBob;
    expect(msg.text).toBe('Ciao Bob 🔐');
    expect(msg.direction).toBe('in');
    expect(msg.contactPubkey).toBe('alice_pk');
  });

  // Shared paired fixture for the behavioural tests.
  async function pairedPeers() {
    const bus = makeBus();
    const alice = await makePeer(bus, 'a_pk', 'Alice');
    const bob = await makePeer(bus, 'b_pk', 'Bob');
    const { qr } = await bob.createQrInvite();
    await alice.acceptQrInvite(qr);
    await alice.confirmPairing({ contactPubkey: 'b_pk', alias: 'Bob' });
    await flush();
    return { alice, bob };
  }

  test('outgoing message transitions sending → sent and is stored', async () => {
    const { alice } = await pairedPeers();
    const states = [];
    alice.onMessageState((id, s) => states.push(s));
    const out = await alice.sendText('b_pk', 'primo');
    expect(out.direction).toBe('out');
    await flush();
    expect(states).toContain('sent');
    const history = await alice.listMessages('b_pk');
    expect(history.map((m) => m.text)).toContain('primo');
  });

  test('incoming message bumps unread and updates the contact preview', async () => {
    const { alice, bob } = await pairedPeers();
    await alice.sendText('b_pk', 'ciao come va');
    await flush();
    const bobsAlice = (await bob.listContacts()).find((c) => c.pubkey === 'a_pk');
    expect(bobsAlice.unread).toBeGreaterThan(0);
    expect(bobsAlice.lastPreview).toBe('ciao come va');
  });

  test('markRead clears the unread counter', async () => {
    const { alice, bob } = await pairedPeers();
    await alice.sendText('b_pk', 'x');
    await flush();
    await bob.markRead('a_pk');
    const c = (await bob.listContacts()).find((x) => x.pubkey === 'a_pk');
    expect(c.unread).toBe(0);
  });

  test('bidirectional messaging works', async () => {
    const { alice, bob } = await pairedPeers();
    const atAlice = new Promise((res) => alice.onMessage((m) => res(m)));
    await bob.sendText('a_pk', 'risposta di Bob');
    const m = await atAlice;
    expect(m.text).toBe('risposta di Bob');
    expect(m.contactPubkey).toBe('b_pk');
  });

  test('sendText without a session throws', async () => {
    const bus = makeBus();
    const alice = await makePeer(bus, 'solo_pk', 'Solo');
    await expect(alice.sendText('ghost', 'hi')).rejects.toThrow('No MLS session');
  });

  test('typing signal propagates to the peer', async () => {
    const { alice, bob } = await pairedPeers();
    const typed = new Promise((res) => bob.onTyping((pubkey, on) => res({ pubkey, on })));
    await alice.setTyping('b_pk', true);
    const t = await typed;
    expect(t).toEqual({ pubkey: 'a_pk', on: true });
  });
});
