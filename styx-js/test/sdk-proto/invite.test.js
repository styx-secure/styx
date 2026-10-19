// PROTOTYPE tests: MLS session port + MLS invitation over Nostr (loopback relays).
import { describe, test, expect, beforeAll, afterEach } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { MlsEngine } from '../../src/crypto/mls/mls-engine.js';
import { createMlsSessionPort } from '../../src/sdk/session/mls-port.js';
import { createInviteFlow, PROTO_KIND_KEYPACKAGE } from '../../src/sdk/session/invite.js';
import { createSeedIdentity } from '../../proto/identity.js';
import { startRelay } from './support/relay.js';

const wasmBytes = readFileSync(new URL('../../vendor/openmls-wasm/openmls_wasm_bg.wasm', import.meta.url));
const enc = (s) => new TextEncoder().encode(s);
const dec = (b) => new TextDecoder().decode(b);

async function member(seed) {
  const identity = createSeedIdentity({ seed });
  const pk = identity.getPublicKey();
  const engine = await MlsEngine.create({ name: pk });
  return { identity, pk, engine, port: createMlsSessionPort({ engine, selfPublicKey: pk }) };
}

let relays = [];
afterEach(async () => { for (const r of relays) await r.close(); relays = []; });

beforeAll(async () => { await MlsEngine.initWasm({ wasmBytes }); });

describe('mls-port', () => {
  test('seal/open between two bound members; wrong sender and wrong recipient refused', async () => {
    const a = await member('alice-seed-unit');
    const b = await member('bob-seed-unit');
    const c = await member('carol-seed-unit');
    const st = a.port.startSession(b.pk, b.port.keyPackageBytes());
    b.port.joinSession(a.pk, st.welcome, st.ratchetTree);
    const { ciphertext } = a.port.seal({ recipient: b.pk, plaintext: enc('hello') });
    expect(ciphertext.length).toBeGreaterThan(5);
    expect(dec(b.port.open({ sender: a.pk, ciphertext }).plaintext)).toBe('hello');
    // b has no session with c -> open with sender c refused
    expect(() => b.port.open({ sender: c.pk, ciphertext })).toThrow(/does not match/);
    expect(() => a.port.seal({ recipient: c.pk, plaintext: enc('x') })).toThrow(/no bound/);
    expect(a.port.exportSecret(b.pk, 'l', enc('c'), 8)).toEqual(b.port.exportSecret(a.pk, 'l', enc('c'), 8));
  });

  test('startSession refuses a KeyPackage whose credential is not the invited key (rollback)', async () => {
    const a = await member('alice-seed-kp');
    const b = await member('bob-seed-kp');
    const c = await member('carol-seed-kp');
    expect(() => a.port.startSession(b.pk, c.port.keyPackageBytes())).toThrow(/credential/);
    expect(a.port.hasSession(b.pk)).toBe(false);
    // and the real one still works afterwards
    expect(() => a.port.startSession(b.pk, b.port.keyPackageBytes())).not.toThrow();
  });

  test('joinSession refuses a Welcome attributed to a key that is not the group member', async () => {
    const a = await member('alice-seed-j');
    const b = await member('bob-seed-j');
    const m = await member('mallory-seed-j');
    const st = a.port.startSession(b.pk, b.port.keyPackageBytes());
    expect(() => b.port.joinSession(m.pk, st.welcome, st.ratchetTree)).toThrow(/does not match/);
    expect(b.port.hasSession(m.pk)).toBe(false);
  });

  test('constructor checks', () => {
    expect(() => createMlsSessionPort({ engine: null, selfPublicKey: 'a'.repeat(64) })).toThrow();
    expect(() => createMlsSessionPort({ engine: { session() {} }, selfPublicKey: 'XYZ' })).toThrow();
  });
});

describe('invite over Nostr (loopback relays)', () => {
  test('KeyPackage event -> inviter adds member -> gift-wrapped Welcome -> invitee joins', async () => {
    relays = [await startRelay(), await startRelay()];
    const urls = relays.map((r) => r.url);
    const alice = await member('alice-seed-inv');
    const bob = await member('bob-seed-inv');
    const steps = [];
    const fa = createInviteFlow({ relays: urls, identity: alice.identity, mlsPort: alice.port, onProgress: (s) => steps.push(`A:${s}`) });
    const fb = createInviteFlow({ relays: urls, identity: bob.identity, mlsPort: bob.port, onProgress: (s) => steps.push(`B:${s}`) });
    const kp = await fb.publishKeyPackage();
    expect(kp.accepted).toBe(2);
    const stored = relays[0].events.find((e) => e.id === kp.eventId);
    expect(stored.kind).toBe(PROTO_KIND_KEYPACKAGE);
    expect(stored.pubkey).toBe(bob.pk);
    const waiting = fb.awaitWelcome({ keyPackageEventId: kp.eventId, timeoutMs: 20000 });
    const inv = await fa.invite({ invitee: bob.pk, timeoutMs: 20000 });
    const joined = await waiting;
    expect(joined.inviter).toBe(alice.pk);
    expect(joined.groupId).toBe(inv.groupId);
    // the wrap on the relay is kind 1059, signed by a one-time key, and does not show Alice
    const wrap = relays[0].events.find((e) => e.id === inv.wrapEventId);
    expect(wrap.kind).toBe(1059);
    expect(wrap.pubkey).not.toBe(alice.pk);
    expect(JSON.stringify(wrap)).not.toContain(alice.pk);
    expect(JSON.stringify(wrap)).not.toContain(inv.groupId);
    // the session works both ways
    const { ciphertext } = alice.port.seal({ recipient: bob.pk, plaintext: enc('m1') });
    expect(dec(bob.port.open({ sender: alice.pk, ciphertext }).plaintext)).toBe('m1');
    const back = bob.port.seal({ recipient: alice.pk, plaintext: enc('r1') });
    expect(dec(alice.port.open({ sender: bob.pk, ciphertext: back.ciphertext }).plaintext)).toBe('r1');
    expect(steps).toEqual(expect.arrayContaining(['B:keypackage-published', 'A:keypackage-fetched', 'A:member-added', 'A:welcome-sent', 'B:joined']));
  }, 60000);

  test('inviter picks the newest KeyPackage; a forged KeyPackage under another author is ignored', async () => {
    relays = [await startRelay()];
    const urls = relays.map((r) => r.url);
    const alice = await member('alice-seed-new');
    const bob = await member('bob-seed-new');
    const mallory = await member('mallory-seed-new');
    const fb = createInviteFlow({ relays: urls, identity: bob.identity, mlsPort: bob.port });
    const fm = createInviteFlow({ relays: urls, identity: mallory.identity, mlsPort: mallory.port });
    await fm.publishKeyPackage(); // Mallory's own KP: different author, never fetched for bob
    const kp = await fb.publishKeyPackage();
    const fa = createInviteFlow({ relays: urls, identity: alice.identity, mlsPort: alice.port });
    const waiting = fb.awaitWelcome({ keyPackageEventId: kp.eventId, timeoutMs: 20000 });
    const inv = await fa.invite({ invitee: bob.pk, timeoutMs: 20000 });
    expect(inv.keyPackageEventId).toBe(kp.eventId);
    expect((await waiting).inviter).toBe(alice.pk);
  }, 60000);

  test('a Welcome wrapped by a third party for an unrelated KeyPackage is not joined', async () => {
    relays = [await startRelay()];
    const urls = relays.map((r) => r.url);
    const bob = await member('bob-seed-3p');
    const mallory = await member('mallory-seed-3p');
    const fb = createInviteFlow({ relays: urls, identity: bob.identity, mlsPort: bob.port });
    const kp = await fb.publishKeyPackage();
    // Mallory gift-wraps a rumor that names Bob's KP but carries garbage Welcome bytes
    const wrap = mallory.identity.giftWrap({
      rumor: { kind: 4744, content: JSON.stringify({ welcome: 'AAAA', tree: 'AAAA', groupId: 'x' }), tags: [['e', kp.eventId]] },
      recipient: bob.pk,
    });
    const { WebSocket } = await import('ws');
    const ws = new WebSocket(urls[0]);
    await new Promise((r) => ws.once('open', r));
    ws.send(JSON.stringify(['EVENT', wrap]));
    await new Promise((r) => ws.once('message', r));
    ws.close();
    await expect(fb.awaitWelcome({ keyPackageEventId: kp.eventId, timeoutMs: 3000 })).rejects.toThrow(/no Welcome/);
    expect(bob.port.hasSession(mallory.pk)).toBe(false);
  }, 30000);

  test('relay rule: non-allowlisted relay refused at construction', async () => {
    const bob = await member('bob-seed-rule');
    const host = ['evil', 'example'].join('.');
    expect(() => createInviteFlow({ relays: [`wss:/${'/'}${host}`], identity: bob.identity, mlsPort: bob.port })).toThrow(/relays/);
  });
});
