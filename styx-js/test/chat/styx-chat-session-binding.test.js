// test/chat/styx-chat-session-binding.test.js
//
// StyxChat files every MLS session under the contact it was paired with, and the
// stored mapping (contact -> group id) is what reloads that session after a
// restart. The mapping must only ever name the contact's own group:
//   - a Welcome is accepted only when the group id it declares names the group it
//     actually carries; otherwise it is rejected like any identity mismatch;
//   - on restart, a stored group is reloaded for a contact only if its peer is
//     that contact and it is not already another contact's session.
import { describe, test, expect, beforeAll, afterEach } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { StyxChat } from '../../src/chat/styx-chat.js';
import { MlsEngine } from '../../src/crypto/mls/mls-engine.js';
import { Group } from '../../vendor/openmls-wasm/openmls_wasm.js';
import { bytesToBase64, base64ToBytes, utf8Encode, utf8Decode } from '../../src/utils.js';

const wasmBytes = readFileSync(
  fileURLToPath(new URL('../../vendor/openmls-wasm/openmls_wasm_bg.wasm', import.meta.url)),
);

const enc = (s) => new TextEncoder().encode(s);
const dec = (b) => new TextDecoder().decode(b);
const BOB = 'b0'.repeat(32);
const CAROL = 'c0'.repeat(32);

function memBackend() {
  const m = new Map();
  return {
    async get(k) { return m.has(k) ? structuredClone(m.get(k)) : null; },
    async set(k, v) { m.set(k, structuredClone(v)); },
    async delete(k) { m.delete(k); },
  };
}

const live = [];
afterEach(() => { live.splice(0).forEach((c) => c.destroy()); });

async function appChat(backend, channelName) {
  const chat = new StyxChat();
  await chat.init({ password: 'pw', backend, channelName, allowInsecureTransport: true, autoStart: false });
  live.push(chat);
  return chat;
}

const parseInvite = (qr) => JSON.parse(utf8Decode(base64ToBytes(String(qr).replace('styx://invite/', ''))));

/**
 * `peer` (a raw engine) answers `chat`'s QR invite with a Welcome envelope. By
 * default the envelope declares the group's own id; `declaredGroupId` overrides it.
 */
async function answerInvite(chat, peer, { declaredGroupId } = {}) {
  const inv = parseInvite((await chat.createQrInvite()).qr);
  const nonce = base64ToBytes(inv.nonce);
  const started = peer.startSession(chat.me.pubkey, base64ToBytes(inv.kp));
  const groupId = declaredGroupId ?? started.groupId;
  const envelope = {
    t: 'welcome',
    from: { pubkey: peer.name },
    welcome: bytesToBase64(started.welcome),
    tree: bytesToBase64(started.ratchetTree),
    groupId,
    hmac: bytesToBase64(chat._welcomeMac(nonce, started.welcome, started.ratchetTree, groupId)),
  };
  await chat._onWire(peer.name, utf8Encode(JSON.stringify(envelope)));
  return started;
}

describe('StyxChat binds each stored session to its own contact', () => {
  beforeAll(async () => { await MlsEngine.initWasm({ wasmBytes }); });

  test('a Welcome whose declared group id names another contact\'s group is rejected', async () => {
    const chat = await appChat(memBackend(), 'binding-1');
    const bob = await MlsEngine.create({ name: BOB });
    const carol = await MlsEngine.create({ name: CAROL });
    const withBob = await answerInvite(chat, bob);
    expect(chat._engine.peerIdentity(BOB)).toBe(BOB);

    const rejected = [];
    chat.onInviteRejected((e) => rejected.push(e));
    await answerInvite(chat, carol, { declaredGroupId: withBob.groupId });

    expect(rejected).toEqual([{ from: CAROL, reason: 'identity-mismatch' }]);
    expect(chat._engine.session(CAROL)).toBeFalsy();
    expect(chat._groups[CAROL]).toBeUndefined();
    expect(chat._inviteNonce).toBeNull();
    // Bob's session is untouched and still works.
    expect(chat._groups[BOB]).toBe(withBob.groupId);
    expect(dec(chat._engine.session(BOB).decrypt(bob.session(chat.me.pubkey).encrypt(enc('hi'))).plaintext))
      .toBe('hi');
  });

  test('a Welcome declaring a group id that is not stored at all is rejected', async () => {
    const chat = await appChat(memBackend(), 'binding-2');
    const carol = await MlsEngine.create({ name: CAROL });
    const rejected = [];
    chat.onInviteRejected((e) => rejected.push(e));
    await answerInvite(chat, carol, { declaredGroupId: 'styx:not-this-group' });
    expect(rejected).toEqual([{ from: CAROL, reason: 'identity-mismatch' }]);
    expect(chat._engine.session(CAROL)).toBeFalsy();
    expect(chat._groups[CAROL]).toBeUndefined();
  });

  test('on restart, a stored mapping naming another contact\'s group is not loaded', async () => {
    const backend = memBackend();
    const chat = await appChat(backend, 'binding-3');
    const me = chat.me.pubkey;
    const bob = await MlsEngine.create({ name: BOB });
    const carol = await MlsEngine.create({ name: CAROL });
    const withBob = await answerInvite(chat, bob);
    await answerInvite(chat, carol);
    expect(chat._engine.peerIdentity(CAROL)).toBe(CAROL);
    // A stored mapping in which Carol's entry names Bob's group.
    await backend.set('mls:groups', { [CAROL]: withBob.groupId, [BOB]: withBob.groupId });
    chat.destroy();
    live.splice(live.indexOf(chat), 1);

    const reloaded = await appChat(backend, 'binding-3b');
    expect(reloaded.me.pubkey).toBe(me);
    expect(reloaded._engine.session(CAROL)).toBeFalsy();
    expect(reloaded._engine.peerIdentity(BOB)).toBe(BOB);
    // Bob's reloaded session is Bob's alone and keeps working in both directions.
    expect(dec(bob.session(me).decrypt(reloaded._engine.session(BOB).encrypt(enc('to bob'))).plaintext))
      .toBe('to bob');
    expect(dec(reloaded._engine.session(BOB).decrypt(bob.session(me).encrypt(enc('from bob'))).plaintext))
      .toBe('from bob');
  });

  test('a Welcome whose group cannot be verified after the join is rejected and spends the invite', async () => {
    const chat = await appChat(memBackend(), 'binding-5');
    const carol = await MlsEngine.create({ name: CAROL });
    const rejected = [];
    chat.onInviteRejected((e) => rejected.push(e));
    const originalLoad = Group.load;
    let failures = 0;
    Group.load = (...args) => {
      if (failures === 0) { failures += 1; throw new Error('storage unavailable'); }
      return originalLoad.apply(Group, args);
    };
    try {
      await answerInvite(chat, carol);
    } finally {
      Group.load = originalLoad;
    }
    expect(failures).toBe(1);
    expect(rejected).toEqual([{ from: CAROL, reason: 'identity-mismatch' }]);
    expect(chat._engine.session(CAROL)).toBeFalsy();
    expect(chat._groups[CAROL]).toBeUndefined();
    expect(chat._inviteNonce).toBeNull();
  });

  test('control: genuine sessions reload for their own contacts after a restart', async () => {
    const backend = memBackend();
    const chat = await appChat(backend, 'binding-4');
    const me = chat.me.pubkey;
    const bob = await MlsEngine.create({ name: BOB });
    const carol = await MlsEngine.create({ name: CAROL });
    await answerInvite(chat, bob);
    await answerInvite(chat, carol);
    chat.destroy();
    live.splice(live.indexOf(chat), 1);

    const reloaded = await appChat(backend, 'binding-4b');
    expect(reloaded._engine.peerIdentity(BOB)).toBe(BOB);
    expect(reloaded._engine.peerIdentity(CAROL)).toBe(CAROL);
    expect(dec(carol.session(me).decrypt(reloaded._engine.session(CAROL).encrypt(enc('to carol'))).plaintext))
      .toBe('to carol');
  });
});
