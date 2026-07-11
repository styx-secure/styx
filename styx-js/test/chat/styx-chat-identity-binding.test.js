// test/chat/styx-chat-identity-binding.test.js
//
// N2 — the MLS credential inside a group must match the transport identity that gave
// us the group.
//
// A1 proves an event really came from the key that signed it. A2 proves the sender saw
// our QR. Neither proves that the *group* we are joining actually contains that sender:
// the MLS credential lives inside the Welcome, and until now nobody checked it. So a
// peer could hand us a group built for — or by — somebody else, and we would file the
// conversation under the wrong name. Every downstream guarantee (the safety number, the
// verified badge, "who am I talking to") is built on that name.
import { describe, test, expect, beforeAll } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { StyxChat } from '../../src/chat/styx-chat.js';
import { MlsEngine } from '../../src/crypto/mls/mls-engine.js';
import { ContactRoster } from '../../src/chat/contact-roster.js';
import { bytesToBase64, base64ToBytes, utf8Encode, utf8Decode } from '../../src/utils.js';

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
const flush = async () => { for (let i = 0; i < 8; i++) await new Promise((r) => setTimeout(r, 0)); };

async function peer(bus, pubkey, alias) {
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

const parseInvite = (qr) =>
  JSON.parse(utf8Decode(base64ToBytes(String(qr).replace('styx://invite/', ''))));

/** A QR that claims `pubkey` but carries somebody else's KeyPackage. */
function forgeInvite(pubkey, alias, kpBytes) {
  const payload = {
    pubkey,
    alias,
    kp: bytesToBase64(kpBytes),
    nonce: bytesToBase64(new Uint8Array(32).fill(9)),
  };
  return 'styx://invite/' + bytesToBase64(utf8Encode(JSON.stringify(payload)));
}

describe('StyxChat N2 — scanner side: the QR KeyPackage must belong to the QR pubkey', () => {
  beforeAll(async () => { await MlsEngine.initWasm({ wasmBytes }); });

  test('an invite claiming Alice but carrying Mallory\'s KeyPackage is refused', async () => {
    const bus = makeBus();
    const bob = await peer(bus, 'bob_n2a', 'Bob');
    const mallory = await MlsEngine.create({ name: 'mallory_n2a' });

    // Bob has never met Alice, so A3's "session already exists" guard does not fire.
    // Only the credential binding can catch this.
    const evilQr = forgeInvite('alice_n2a', 'Alice', mallory.keyPackageBytes());

    await expect(bob.acceptQrInvite(evilQr)).rejects.toThrow(/credential|identity|match/i);

    // No session, no group, nothing filed under Alice's name.
    expect(bob._engine.session('alice_n2a')).toBeFalsy();
    expect(bob._groups['alice_n2a']).toBeUndefined();
  });

  test('a genuine invite still pairs, and the group really contains that peer', async () => {
    const bus = makeBus();
    const bob = await peer(bus, 'bob_n2b', 'Bob');
    const alice = await peer(bus, 'alice_n2b', 'Alice');

    const { qr } = await alice.createQrInvite();
    await expect(bob.acceptQrInvite(qr)).resolves.toBeTruthy();

    expect(bob._engine.peerIdentity('alice_n2b')).toBe('alice_n2b');
  });
});

describe('StyxChat N2 — wire side: the Welcome must contain the peer who sent it', () => {
  beforeAll(async () => { await MlsEngine.initWasm({ wasmBytes }); });

  test('a Welcome relayed under a different pubkey is rejected', async () => {
    const bus = makeBus();
    const bob = await peer(bus, 'bob_n2c', 'Bob');

    // Bob shows a QR. Mallory photographs it — so she has both Bob's KeyPackage and
    // the single-use nonce, and can satisfy A2's proof-of-scan MAC.
    const { qr } = await bob.createQrInvite();
    const inv = parseInvite(qr);
    const nonce = base64ToBytes(inv.nonce);

    // But the group is built by Carol, not by Mallory.
    const carol = await MlsEngine.create({ name: 'carol_n2c' });
    const { welcome, ratchetTree, groupId } = carol.startSession('bob_n2c', base64ToBytes(inv.kp));

    // Mallory forwards Carol's Welcome from her own key, with a MAC that verifies.
    const envelope = {
      t: 'welcome',
      from: { pubkey: 'mallory_n2c' },
      welcome: bytesToBase64(welcome),
      tree: bytesToBase64(ratchetTree),
      groupId,
      hmac: bytesToBase64(bob._welcomeMac(nonce, welcome, ratchetTree, groupId)),
    };
    await bus.transportFor('mallory_n2c').send('bob_n2c', utf8Encode(JSON.stringify(envelope)));
    await flush();

    // Bob must not end up with a "Mallory" conversation whose real other member is
    // Carol — that is the whole point of the binding.
    expect(bob._engine.session('mallory_n2c')).toBeFalsy();
    expect(bob._groups['mallory_n2c']).toBeUndefined();
    expect(bob._pending.has('mallory_n2c')).toBe(false);
  });

  test('a rejected Welcome retires the invite (MLS ate the init key) and signals the app', async () => {
    const bus = makeBus();
    const bob = await peer(bus, 'bob_n2d', 'Bob');
    const alice = await peer(bus, 'alice_n2d', 'Alice');

    const rejected = [];
    bob.onInviteRejected((e) => rejected.push(e));

    const { qr } = await bob.createQrInvite();
    const inv = parseInvite(qr);
    const nonce = base64ToBytes(inv.nonce);

    // Mallory relays a group built by Carol under her own pubkey.
    const carol = await MlsEngine.create({ name: 'carol_n2d' });
    const bad = carol.startSession('bob_n2d', base64ToBytes(inv.kp));
    await bus.transportFor('mallory_n2d').send('bob_n2d', utf8Encode(JSON.stringify({
      t: 'welcome',
      from: { pubkey: 'mallory_n2d' },
      welcome: bytesToBase64(bad.welcome),
      tree: bytesToBase64(bad.ratchetTree),
      groupId: bad.groupId,
      hmac: bytesToBase64(bob._welcomeMac(nonce, bad.welcome, bad.ratchetTree, bad.groupId)),
    })));
    await flush();

    expect(bob._engine.session('mallory_n2d')).toBeFalsy();
    expect(rejected).toEqual([{ from: 'mallory_n2d', reason: 'identity-mismatch' }]);

    // The invite is spent, not merely unused: decrypting the Welcome made MLS consume
    // the KeyPackage's private init key, so this QR can never complete a pairing again
    // — not even for Alice, who scanned it legitimately. State must say so.
    expect(bob._inviteNonce).toBeNull();

    // The recovery path is a fresh QR, and it works.
    const second = await bob.createQrInvite();
    await alice.acceptQrInvite(second.qr);
    await flush();

    expect(bob._engine.peerIdentity('alice_n2d')).toBe('alice_n2d');
    expect(bob._pending.has('alice_n2d')).toBe(true);
  });
});
