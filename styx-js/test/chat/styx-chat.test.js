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
    await flush(); // welcome delivered → Bob has a pending pairing (A4: no auto-add)
    await bob.confirmPairing({ contactPubkey: 'alice_pk', alias: 'Alice' });

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
    await bob.confirmPairing({ contactPubkey: 'a_pk', alias: 'Alice' }); // A4: explicit
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

  test('an app message that arrives before its Welcome is queued and delivered', async () => {
    // Alice's transport captures what it sends to Bob; we then replay to Bob in
    // reverse (app message first, Welcome second) — the relay-replay reorder case.
    const captured = [];
    const aliceEngine = await MlsEngine.create({ name: 'ax_pk' });
    const bobEngine = await MlsEngine.create({ name: 'bx_pk' });
    const aliceRoster = new ContactRoster({ backend: memBackend() }); await aliceRoster.load();
    const bobRoster = new ContactRoster({ backend: memBackend() }); await bobRoster.load();
    let bobHandler = null;

    const alice = new StyxChat({
      identity: { pubkey: 'ax_pk', alias: 'Alice' }, engine: aliceEngine, roster: aliceRoster,
      transport: { async send(to, bytes) { captured.push({ from: 'ax_pk', bytes }); }, onMessage() { return () => {}; } },
    });
    const bob = new StyxChat({
      identity: { pubkey: 'bx_pk', alias: 'Bob' }, engine: bobEngine, roster: bobRoster,
      transport: { async send() {}, onMessage(cb) { bobHandler = cb; return () => { bobHandler = null; }; } },
    });
    await alice.start(); await bob.start();

    const { qr } = await bob.createQrInvite();
    await alice.acceptQrInvite(qr);            // captures the Welcome
    await alice.confirmPairing({ contactPubkey: 'bx_pk', alias: 'Bob' });
    await alice.sendText('bx_pk', 'fuori ordine'); // captures the app message

    // Deliver to Bob in REVERSE: app message first, then Welcome.
    const gotAtBob = new Promise((res) => bob.onMessage((m) => res(m)));
    for (const { from, bytes } of [...captured].reverse()) bobHandler(from, bytes);

    const msg = await Promise.race([
      gotAtBob,
      new Promise((_, rej) => setTimeout(() => rej(new Error('message dropped')), 3000)),
    ]);
    expect(msg.text).toBe('fuori ordine');
  });

  test('typing signal propagates to the peer', async () => {
    const { alice, bob } = await pairedPeers();
    const typed = new Promise((res) => bob.onTyping((pubkey, on) => res({ pubkey, on })));
    await alice.setTyping('b_pk', true);
    const t = await typed;
    expect(t).toEqual({ pubkey: 'a_pk', on: true });
  });

  test("recipient shows the sender's id and send timestamp, not the receive time", async () => {
    const { alice, bob } = await pairedPeers();
    const gotAtBob = new Promise((res) => bob.onMessage((m) => res(m)));
    const out = await alice.sendText('b_pk', 'orario esatto');
    const inMsg = await gotAtBob;
    expect(inMsg.id).toBe(out.id);
    expect(inMsg.ts).toBe(out.ts);
    expect(inMsg.text).toBe('orario esatto');
  });

  test('outgoing message advances to delivered when the peer auto-acks', async () => {
    const { alice } = await pairedPeers();
    const states = new Map();
    alice.onMessageState((id, s) => states.set(id, s));
    const out = await alice.sendText('b_pk', 'consegna');
    await flush();
    expect(states.get(out.id)).toBe('delivered');
  });

  test('markRead sends a read receipt that advances the sender to read', async () => {
    const { alice, bob } = await pairedPeers();
    const seen = [];
    alice.onMessageState((id, s) => seen.push({ id, s }));
    const out = await alice.sendText('b_pk', 'leggimi');
    await flush();
    await bob.markRead('a_pk');
    await flush();
    expect(seen.filter((x) => x.id === out.id).map((x) => x.s)).toEqual(['sent', 'delivered', 'read']);
  });

  test('receipts never create a message and never loop', async () => {
    const { alice, bob } = await pairedPeers();
    let aliceInbound = 0;
    alice.onMessage((m) => { if (m.direction === 'in') aliceInbound++; });
    await alice.sendText('b_pk', 'no loop');
    await flush();
    await bob.markRead('a_pk');
    await flush();
    // Bob stored exactly one inbound text; the receipts produced no phantom messages.
    expect((await bob.listMessages('a_pk')).filter((m) => m.direction === 'in')).toHaveLength(1);
    expect(aliceInbound).toBe(0); // a receipt must not surface as an inbound message
  });

  test('receipts travel encrypted — the wire never reveals a receipt', async () => {
    const { alice, bob } = await pairedPeers();
    const wire = [];
    const orig = bob._transport.send.bind(bob._transport);
    bob._transport.send = async (to, bytes, opts) => {
      wire.push(new TextDecoder().decode(bytes));
      return orig(to, bytes, opts);
    };
    await alice.sendText('b_pk', 'segreto');
    await flush();
    await bob.markRead('a_pk');
    await flush();
    expect(wire.length).toBeGreaterThan(0); // bob emitted delivered + read receipts
    for (const frame of wire) {
      expect(frame).not.toMatch(/receipt|delivered|read/); // opaque on the wire
      expect(JSON.parse(frame).t).toBe('app'); // indistinguishable from a text message
    }
  });
});
