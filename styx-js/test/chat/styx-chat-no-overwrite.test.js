// test/chat/styx-chat-no-overwrite.test.js
// A3: a welcome must never replace an established MLS session. That overwrite is
// the C2 silent-MITM vector: it hijacks a conversation already in progress.
import { describe, test, expect, beforeAll } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { StyxChat } from '../../src/chat/styx-chat.js';
import { MlsEngine } from '../../src/crypto/mls/mls-engine.js';
import { ContactRoster } from '../../src/chat/contact-roster.js';
import { bytesToBase64, utf8Encode } from '../../src/utils.js';

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
  const chat = new StyxChat({ identity: { pubkey, alias }, engine, roster, transport: bus.transportFor(pubkey) });
  await chat.start();
  return chat;
}
/** Forge a QR invite that claims `pubkey` but carries `kpBytes` (attacker's KeyPackage). */
function forgeInvite(pubkey, alias, kpBytes) {
  const payload = { pubkey, alias, kp: bytesToBase64(kpBytes), nonce: bytesToBase64(new Uint8Array(32).fill(9)) };
  return 'styx://invite/' + bytesToBase64(utf8Encode(JSON.stringify(payload)));
}

describe('MlsEngine A3 no-overwrite', () => {
  beforeAll(async () => { await MlsEngine.initWasm({ wasmBytes }); });

  test('joinSession throws if a session for the contact already exists', async () => {
    const inviter = await MlsEngine.create({ name: 'inviter' });
    const joiner = await MlsEngine.create({ name: 'joiner' });
    const { welcome, ratchetTree } = inviter.startSession('peer', joiner.keyPackageBytes());

    joiner.joinSession('peer', welcome, ratchetTree);
    expect(() => joiner.joinSession('peer', welcome, ratchetTree)).toThrow(/already exists/);
  });

  test('the original session survives a rejected re-join attempt', async () => {
    const inviter = await MlsEngine.create({ name: 'inviter2' });
    const joiner = await MlsEngine.create({ name: 'joiner2' });
    const { session: inviterSession, welcome, ratchetTree } = inviter.startSession('peer', joiner.keyPackageBytes());
    joiner.joinSession('peer', welcome, ratchetTree);
    const original = joiner.session('peer');

    // An attacker replays a welcome for the same contact.
    const attacker = await MlsEngine.create({ name: 'attacker' });
    const evil = attacker.startSession('victim', joiner.keyPackageBytes());
    expect(() => joiner.joinSession('peer', evil.welcome, evil.ratchetTree)).toThrow(/already exists/);

    // Same session object, and it still decrypts traffic from the genuine peer.
    expect(joiner.session('peer')).toBe(original);
    const ct = inviterSession.encrypt(new TextEncoder().encode('still us'));
    expect(new TextDecoder().decode(joiner.session('peer').decrypt(ct).plaintext)).toBe('still us');
  });

  test('startSession also refuses to replace an existing session (scanner side)', async () => {
    const engine = await MlsEngine.create({ name: 'scanner' });
    const alice = await MlsEngine.create({ name: 'alice' });
    engine.startSession('alice_pk', alice.keyPackageBytes());
    const attacker = await MlsEngine.create({ name: 'attacker' });
    expect(() => engine.startSession('alice_pk', attacker.keyPackageBytes())).toThrow(/already exists/);
  });
});

describe('StyxChat A3 scanner-side (acceptQrInvite cannot hijack a verified contact)', () => {
  beforeAll(async () => { await MlsEngine.initWasm({ wasmBytes }); });

  test('a malicious invite reusing an established contact pubkey is refused, session intact', async () => {
    const bus = makeBus();
    const bob = await peer(bus, 'bob_h1', 'Bob');
    const alice = await peer(bus, 'alice_h1', 'Alice');

    // Bob pairs with the real Alice and verifies her.
    const { qr } = await alice.createQrInvite();
    await bob.acceptQrInvite(qr);
    await flush();
    await bob.confirmPairing({ contactPubkey: 'alice_h1', alias: 'Alice' });
    await bob.setVerified('alice_h1', true);
    const genuineSession = bob._engine.session('alice_h1');

    // An attacker gets Bob to open an invite that claims to be Alice but carries
    // the attacker's KeyPackage. This must NOT silently replace Bob↔Alice.
    const mallory = await MlsEngine.create({ name: 'mallory' });
    const evilQr = forgeInvite('alice_h1', 'Alice', mallory.keyPackageBytes());
    await expect(bob.acceptQrInvite(evilQr)).rejects.toThrow(/already exists|remove/i);

    // The genuine session is untouched and the verified badge is still honest.
    expect(bob._engine.session('alice_h1')).toBe(genuineSession);
    const c = (await bob.listContacts()).find((x) => x.pubkey === 'alice_h1');
    expect(c.verified).toBe(true);
  });

  test('removeContact drops the session so a deliberate re-pair is possible', async () => {
    const bus = makeBus();
    const bob = await peer(bus, 'bob_h2', 'Bob');
    const alice = await peer(bus, 'alice_h2', 'Alice');

    const { qr } = await alice.createQrInvite();
    await bob.acceptQrInvite(qr);
    await flush();
    await bob.confirmPairing({ contactPubkey: 'alice_h2', alias: 'Alice' });
    await bob.setVerified('alice_h2', true);

    // Deliberate removal clears the session AND the verification.
    await bob.removeContact('alice_h2');
    expect(bob._engine.session('alice_h2')).toBeFalsy();
    expect(bob._groups['alice_h2']).toBeUndefined();

    // Now a fresh invite for the same pubkey pairs again, unverified.
    const alice2 = await peer(bus, 'alice_h2', 'Alice');
    const again = await alice2.createQrInvite();
    await expect(bob.acceptQrInvite(again.qr)).resolves.toBeTruthy();
  });
});
