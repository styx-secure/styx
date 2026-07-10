// test/chat/styx-chat-safety-number.test.js
// A5: two genuine peers derive the same safety number from their shared MLS
// group secret; anyone in the middle holds a different group and therefore shows
// a different number. This is what makes a MITM detectable (H3).
import { describe, test, expect, beforeAll } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { StyxChat } from '../../src/chat/styx-chat.js';
import { MlsEngine } from '../../src/crypto/mls/mls-engine.js';
import { ContactRoster } from '../../src/chat/contact-roster.js';

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
const flush = async () => { for (let i = 0; i < 10; i++) await new Promise((r) => setTimeout(r, 0)); };

async function peer(bus, pubkey, alias) {
  const engine = await MlsEngine.create({ name: pubkey });
  const roster = new ContactRoster({ backend: memBackend() });
  await roster.load();
  const chat = new StyxChat({ identity: { pubkey, alias }, engine, roster, transport: bus.transportFor(pubkey) });
  await chat.start();
  return chat;
}

describe('StyxChat A5 safety number', () => {
  beforeAll(async () => { await MlsEngine.initWasm({ wasmBytes }); });

  test('both peers derive the same 60-digit number, grouped in fives', async () => {
    const bus = makeBus();
    const bob = await peer(bus, 'bob_sn', 'Bob');
    const alice = await peer(bus, 'alice_sn', 'Alice');
    const { qr } = await bob.createQrInvite();
    await alice.acceptQrInvite(qr);
    await flush();

    const snAlice = alice.safetyNumber('bob_sn');
    const snBob = bob.safetyNumber('alice_sn');
    expect(snAlice).toBe(snBob);
    expect(snAlice.replace(/ /g, '')).toMatch(/^\d{60}$/);
    expect(snAlice.split(' ').every((g) => g.length === 5)).toBe(true);
  });

  test('it is stable across calls and independent of who asks', async () => {
    const bus = makeBus();
    const bob = await peer(bus, 'bob_sn2', 'Bob');
    const alice = await peer(bus, 'alice_sn2', 'Alice');
    const { qr } = await bob.createQrInvite();
    await alice.acceptQrInvite(qr);
    await flush();
    expect(alice.safetyNumber('bob_sn2')).toBe(alice.safetyNumber('bob_sn2'));
  });

  test('a man in the middle produces different numbers on each side', async () => {
    // Mallory pairs separately with Alice and with Bob: two distinct MLS groups,
    // so the number Alice reads aloud cannot match the one Bob reads back.
    const bus = makeBus();
    const alice = await peer(bus, 'alice_sn3', 'Alice');
    const bob = await peer(bus, 'bob_sn3', 'Bob');
    const mallory = await peer(bus, 'mallory_sn3', 'Mallory');

    const aliceInvite = await alice.createQrInvite();
    await mallory.acceptQrInvite(aliceInvite.qr); // Mallory ↔ Alice
    await flush();
    const bobInvite = await bob.createQrInvite();
    await mallory.acceptQrInvite(bobInvite.qr);   // Mallory ↔ Bob
    await flush();

    // What Alice would compare against Bob, if each believed they talked to the other.
    const aliceSideNumber = alice.safetyNumber('mallory_sn3');
    const bobSideNumber = bob.safetyNumber('mallory_sn3');
    expect(aliceSideNumber).not.toBe(bobSideNumber);
  });

  test('safetyNumber throws when there is no session', async () => {
    const bus = makeBus();
    const solo = await peer(bus, 'solo_sn', 'Solo');
    expect(() => solo.safetyNumber('ghost')).toThrow(/session/i);
  });
});

describe('ContactRoster verification state', () => {
  test('a contact starts unverified and can be marked verified', async () => {
    const roster = new ContactRoster({ backend: memBackend() });
    await roster.load();
    await roster.add({ pubkey: 'p1', alias: 'P1' });

    expect((await roster.get('p1')).verified).toBe(false);
    expect((await roster.get('p1')).verifiedAt).toBeNull();

    await roster.setVerified('p1', true);
    const c = await roster.get('p1');
    expect(c.verified).toBe(true);
    expect(typeof c.verifiedAt).toBe('number');
  });

  test('un-verifying clears the timestamp', async () => {
    const roster = new ContactRoster({ backend: memBackend() });
    await roster.load();
    await roster.add({ pubkey: 'p2', alias: 'P2' });
    await roster.setVerified('p2', true);
    await roster.setVerified('p2', false);
    const c = await roster.get('p2');
    expect(c.verified).toBe(false);
    expect(c.verifiedAt).toBeNull();
  });

  test('re-adding an existing contact preserves its verification', async () => {
    const roster = new ContactRoster({ backend: memBackend() });
    await roster.load();
    await roster.add({ pubkey: 'p3', alias: 'P3' });
    await roster.setVerified('p3', true);
    await roster.add({ pubkey: 'p3', alias: 'P3 renamed' });
    expect((await roster.get('p3')).verified).toBe(true);
  });
});
