// test/chat/styx-chat-explicit-pairing.test.js
// A4: an authenticated welcome creates a PENDING pairing, never a contact — the
// user confirms explicitly. The alias no longer rides in the cleartext envelope;
// it arrives as an encrypted intro inside MLS and is sanitized on receipt.
import { describe, test, expect, beforeAll } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { StyxChat, sanitizeAlias } from '../../src/chat/styx-chat.js';
import { MlsEngine } from '../../src/crypto/mls/mls-engine.js';
import { ContactRoster } from '../../src/chat/contact-roster.js';
import { utf8Decode } from '../../src/utils.js';

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

describe('sanitizeAlias', () => {
  const wrap = (cp) => 'a' + String.fromCodePoint(cp) + 'b';

  test('trims and preserves ordinary text', () => {
    expect(sanitizeAlias('  Alice  ')).toBe('Alice');
    expect(sanitizeAlias('Zoë \u{1F510}')).toBe('Zoë \u{1F510}');
  });

  test('strips bidi overrides and isolates used for display spoofing', () => {
    expect(sanitizeAlias(wrap(0x202E))).toBe('ab'); // RLO
    expect(sanitizeAlias(wrap(0x202A))).toBe('ab'); // LRE
    expect(sanitizeAlias(wrap(0x2066))).toBe('ab'); // LRI
    expect(sanitizeAlias(wrap(0x2069))).toBe('ab'); // PDI
  });

  test('strips directional marks (LRM/RLM/ALM)', () => {
    expect(sanitizeAlias(wrap(0x200E))).toBe('ab'); // LRM
    expect(sanitizeAlias(wrap(0x200F))).toBe('ab'); // RLM
    expect(sanitizeAlias(wrap(0x061C))).toBe('ab'); // Arabic letter mark
  });

  test('strips zero-width characters and the BOM', () => {
    expect(sanitizeAlias(wrap(0x200B))).toBe('ab'); // ZWSP
    expect(sanitizeAlias(wrap(0x200D))).toBe('ab'); // ZWJ
    expect(sanitizeAlias(wrap(0x2060))).toBe('ab'); // word joiner
    expect(sanitizeAlias(wrap(0xFEFF))).toBe('ab'); // ZWNBSP / BOM
  });

  test('strips C0/C1 control characters', () => {
    expect(sanitizeAlias(wrap(0x0007))).toBe('ab'); // BEL (C0)
    expect(sanitizeAlias('two\nlines')).toBe('twolines');
    expect(sanitizeAlias(wrap(0x0085))).toBe('ab'); // NEL (C1)
  });

  test('caps the length at 64 code points without splitting astral chars', () => {
    expect([...sanitizeAlias('x'.repeat(200))]).toHaveLength(64);
    const capped = sanitizeAlias('\u{1F600}'.repeat(100)); // astral, 2 UTF-16 units each
    expect([...capped]).toHaveLength(64);
    expect(capped).toBe('\u{1F600}'.repeat(64)); // whole emoji, never a lone surrogate
  });

  test('returns empty string for blank/nullish input', () => {
    expect(sanitizeAlias('   ')).toBe('');
    expect(sanitizeAlias(null)).toBe('');
    expect(sanitizeAlias(undefined)).toBe('');
  });
});


describe('StyxChat A4 explicit pairing + alias inside MLS', () => {
  beforeAll(async () => { await MlsEngine.initWasm({ wasmBytes }); });

  test('an authenticated welcome does not auto-add a contact; it raises a pending pairing', async () => {
    const bus = makeBus();
    const bob = await peer(bus, 'bob_a4', 'Bob');
    const alice = await peer(bus, 'alice_a4', 'Alice');
    const pendings = [];
    bob.onPairing((p) => pendings.push(p));

    const { qr } = await bob.createQrInvite();
    await alice.acceptQrInvite(qr);
    await flush();

    expect(pendings.map((p) => p.pubkey)).toContain('alice_a4');
    expect((await bob.listContacts()).map((c) => c.pubkey)).not.toContain('alice_a4');

    await bob.confirmPairing({ contactPubkey: 'alice_a4' });
    expect((await bob.listContacts()).map((c) => c.pubkey)).toContain('alice_a4');
  });

  test('the introduced alias arrives encrypted and becomes the default on confirm', async () => {
    const bus = makeBus();
    const bob = await peer(bus, 'bob_a4b', 'Bob');
    const alice = await peer(bus, 'alice_a4b', 'Alice');
    const { qr } = await bob.createQrInvite();
    await alice.acceptQrInvite(qr);
    await flush();

    await bob.confirmPairing({ contactPubkey: 'alice_a4b' }); // no alias given
    const c = (await bob.listContacts()).find((x) => x.pubkey === 'alice_a4b');
    expect(c.alias).toBe('Alice');
  });

  test('an explicit alias on confirm wins over the introduced one', async () => {
    const bus = makeBus();
    const bob = await peer(bus, 'bob_a4e', 'Bob');
    const alice = await peer(bus, 'alice_a4e', 'Alice');
    const { qr } = await bob.createQrInvite();
    await alice.acceptQrInvite(qr);
    await flush();

    await bob.confirmPairing({ contactPubkey: 'alice_a4e', alias: 'Alice (lavoro)' });
    const c = (await bob.listContacts()).find((x) => x.pubkey === 'alice_a4e');
    expect(c.alias).toBe('Alice (lavoro)');
  });

  test('the welcome envelope carries no cleartext alias', async () => {
    const bus = makeBus();
    const bob = await peer(bus, 'bob_a4c', 'Bob');
    const alice = await peer(bus, 'alice_a4c', 'Alice');
    const frames = [];
    const orig = alice._transport.send.bind(alice._transport);
    alice._transport.send = async (to, bytes, opts) => {
      frames.push(utf8Decode(bytes));
      return orig(to, bytes, opts);
    };
    const { qr } = await bob.createQrInvite();
    await alice.acceptQrInvite(qr);
    await flush();

    const welcome = frames.map((f) => JSON.parse(f)).find((e) => e.t === 'welcome');
    expect(welcome).toBeTruthy();
    expect(welcome.from?.alias).toBeUndefined();
    expect(JSON.stringify(welcome)).not.toMatch(/Alice/);
  });

  test('an intro with a hostile alias is sanitized before it reaches the roster', async () => {
    const bus = makeBus();
    const bob = await peer(bus, 'bob_a4d', 'Bob');
    const alice = await peer(bus, 'alice_a4d', '‮Admin');
    const { qr } = await bob.createQrInvite();
    await alice.acceptQrInvite(qr);
    await flush();

    await bob.confirmPairing({ contactPubkey: 'alice_a4d' });
    const c = (await bob.listContacts()).find((x) => x.pubkey === 'alice_a4d');
    expect(c.alias).toBe('Admin');
  });

  test('an intro for an established contact updates its alias', async () => {
    const bus = makeBus();
    const bob = await peer(bus, 'bob_a4f', 'Bob');
    const alice = await peer(bus, 'alice_a4f', 'Alice');
    const { qr } = await bob.createQrInvite();
    await alice.acceptQrInvite(qr);
    await flush();
    await bob.confirmPairing({ contactPubkey: 'alice_a4f' });

    await alice.setAlias('Alice Rossi');
    await alice._sendIntro('bob_a4f');
    await flush();

    const c = (await bob.listContacts()).find((x) => x.pubkey === 'alice_a4f');
    expect(c.alias).toBe('Alice Rossi');
  });

  test('the scanner takes the inviter alias from the QR (the in-person channel)', async () => {
    const bus = makeBus();
    const bob = await peer(bus, 'bob_a4g', 'Bob');
    const alice = await peer(bus, 'alice_a4g', 'Alice');
    const { qr } = await bob.createQrInvite();
    await alice.acceptQrInvite(qr);

    await alice.confirmPairing({ contactPubkey: 'bob_a4g' }); // no alias given
    const c = (await alice.listContacts()).find((x) => x.pubkey === 'bob_a4g');
    expect(c.alias).toBe('Bob');
  });

  test('a rejected welcome raises no pending pairing', async () => {
    const bus = makeBus();
    const bob = await peer(bus, 'bob_a4h', 'Bob');
    const mallory = await peer(bus, 'mallory_a4h', 'Mallory');
    const pendings = [];
    bob.onPairing((p) => pendings.push(p));

    await bob.createQrInvite();
    // Mallory never saw the QR: she fabricates an invite with her own nonce.
    const fake = Buffer.from(JSON.stringify({
      pubkey: 'bob_a4h', alias: 'Bob',
      kp: Buffer.from(bob._engine.keyPackageBytes()).toString('base64'),
      nonce: Buffer.alloc(32, 1).toString('base64'),
    })).toString('base64');
    await mallory.acceptQrInvite('styx://invite/' + fake);
    await flush();

    expect(pendings).toHaveLength(0);
    expect((await bob.listContacts())).toHaveLength(0);
  });
});
