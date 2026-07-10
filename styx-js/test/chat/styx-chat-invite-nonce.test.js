// test/chat/styx-chat-invite-nonce.test.js
// A2: the welcome must carry an HMAC over the 32-byte nonce that lives only in
// the QR. Someone who never saw the inviter's screen cannot forge it. The nonce
// is single-use, so a captured invite cannot be replayed.
import { describe, test, expect, beforeAll } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { StyxChat } from '../../src/chat/styx-chat.js';
import { MlsEngine } from '../../src/crypto/mls/mls-engine.js';
import { ContactRoster } from '../../src/chat/contact-roster.js';
import { base64ToBytes, utf8Decode } from '../../src/utils.js';

const wasmBytes = readFileSync(
  fileURLToPath(new URL('../../vendor/openmls-wasm/openmls_wasm_bg.wasm', import.meta.url)),
);

function memBackend() {
  const m = new Map();
  return {
    async get(k) { return m.has(k) ? m.get(k) : null; },
    async set(k, v) { m.set(k, v); },
    async delete(k) { m.delete(k); },
  };
}

/** A bus whose per-peer handler can be wrapped, to tamper with frames in flight. */
function makeBus() {
  const handlers = new Map();
  return {
    handlers,
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

const flush = async () => { for (let i = 0; i < 8; i++) await new Promise((r) => setTimeout(r, 0)); };

async function peer(bus, pubkey, alias) {
  const engine = await MlsEngine.create({ name: pubkey });
  const roster = new ContactRoster({ backend: memBackend() });
  await roster.load();
  const chat = new StyxChat({ identity: { pubkey, alias }, engine, roster, transport: bus.transportFor(pubkey) });
  await chat.start();
  return chat;
}

/** Wrap `pubkey`'s inbound handler so each welcome envelope can be mutated. */
function tamperWelcome(bus, pubkey, mutate) {
  const real = bus.handlers.get(pubkey);
  bus.handlers.set(pubkey, (from, bytes) => {
    const env = JSON.parse(utf8Decode(bytes));
    if (env.t === 'welcome') mutate(env);
    real(from, new TextEncoder().encode(JSON.stringify(env)));
  });
}

describe('StyxChat A2 invite nonce binding', () => {
  beforeAll(async () => { await MlsEngine.initWasm({ wasmBytes }); });

  test('the invite embeds a 32-byte nonce', async () => {
    const bus = makeBus();
    const bob = await peer(bus, 'bob_n0', 'Bob');
    const { qr } = await bob.createQrInvite();
    const payload = JSON.parse(utf8Decode(base64ToBytes(qr.replace('styx://invite/', ''))));
    expect(base64ToBytes(payload.nonce)).toHaveLength(32);
  });

  test('a genuine QR invite still pairs (happy path)', async () => {
    const bus = makeBus();
    const bob = await peer(bus, 'bob_n1', 'Bob');
    const alice = await peer(bus, 'alice_n1', 'Alice');
    const { qr } = await bob.createQrInvite();
    await alice.acceptQrInvite(qr);
    await flush();
    expect(bob._engine.session('alice_n1')).toBeTruthy();
  });

  test('a welcome with a stripped HMAC is rejected', async () => {
    const bus = makeBus();
    const bob = await peer(bus, 'bob_n2', 'Bob');
    const alice = await peer(bus, 'alice_n2', 'Alice');
    const { qr } = await bob.createQrInvite();
    tamperWelcome(bus, 'bob_n2', (env) => { delete env.hmac; });
    await alice.acceptQrInvite(qr);
    await flush();
    expect(bob._engine.session('alice_n2')).toBeFalsy();
  });

  test('a welcome with a forged HMAC is rejected', async () => {
    const bus = makeBus();
    const bob = await peer(bus, 'bob_n3', 'Bob');
    const alice = await peer(bus, 'alice_n3', 'Alice');
    const { qr } = await bob.createQrInvite();
    tamperWelcome(bus, 'bob_n3', (env) => { env.hmac = Buffer.alloc(32, 7).toString('base64'); });
    await alice.acceptQrInvite(qr);
    await flush();
    expect(bob._engine.session('alice_n3')).toBeFalsy();
  });

  test('an attacker who never saw the QR cannot pair (no nonce → no valid HMAC)', async () => {
    const bus = makeBus();
    const bob = await peer(bus, 'bob_n4', 'Bob');
    const mallory = await peer(bus, 'mallory_n4', 'Mallory');
    const { qr } = await bob.createQrInvite();
    // Mallory intercepts the invite but the nonce is unknown to her: she must guess.
    const payload = JSON.parse(utf8Decode(base64ToBytes(qr.replace('styx://invite/', ''))));
    const blinded = { ...payload, nonce: Buffer.alloc(32, 0).toString('base64') };
    const forgedQr = 'styx://invite/' + Buffer.from(JSON.stringify(blinded)).toString('base64');
    await mallory.acceptQrInvite(forgedQr);
    await flush();
    expect(bob._engine.session('mallory_n4')).toBeFalsy();
  });

  test('the nonce is single-use: a replayed invite cannot pair a second peer', async () => {
    const bus = makeBus();
    const bob = await peer(bus, 'bob_n5', 'Bob');
    const alice = await peer(bus, 'alice_n5', 'Alice');
    const mallory = await peer(bus, 'mallory_n5', 'Mallory');
    const { qr } = await bob.createQrInvite();

    await alice.acceptQrInvite(qr); // legitimate scan burns the nonce
    await flush();
    expect(bob._engine.session('alice_n5')).toBeTruthy();

    // Mallory photographed the same QR and replays it.
    await mallory.acceptQrInvite(qr);
    await flush();
    expect(bob._engine.session('mallory_n5')).toBeFalsy();
  });

  test('a welcome whose group material was swapped after MAC computation is rejected', async () => {
    const bus = makeBus();
    const bob = await peer(bus, 'bob_n6', 'Bob');
    const alice = await peer(bus, 'alice_n6', 'Alice');
    const mallory = await peer(bus, 'mallory_n6', 'Mallory');
    const { qr } = await bob.createQrInvite();

    // Mallory builds her own group with Bob's KeyPackage and splices her welcome
    // into Alice's envelope, keeping Alice's HMAC. The MAC covers the welcome
    // bytes, so it must not verify.
    const payload = JSON.parse(utf8Decode(base64ToBytes(qr.replace('styx://invite/', ''))));
    const evil = mallory._engine.startSession('bob_n6', base64ToBytes(payload.kp));
    tamperWelcome(bus, 'bob_n6', (env) => {
      env.welcome = Buffer.from(evil.welcome).toString('base64');
      env.tree = Buffer.from(evil.ratchetTree).toString('base64');
    });

    await alice.acceptQrInvite(qr);
    await flush();
    expect(bob._engine.session('alice_n6')).toBeFalsy();
  });
});
