// test/chat/styx-chat-legacy-robustness.test.js
//
// Robustness of the reference chat (StyxChat), app mode and DI mode:
//   - a message whose event reached no open relay connection is 'failed', not 'sent';
//   - an envelope over MAX_WIRE_ENVELOPE_BYTES is dropped before decoding;
//   - 'read' receipts: only up to the message the caller names, never twice for
//     the same message (across a reload too), and never when turned off;
//   - removing a contact writes the shortened history at once;
//   - the group map has no prototype, so no key collides with Object.prototype.
import { describe, test, expect, beforeAll, afterEach, jest } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { schnorr } from '@noble/curves/secp256k1';
import * as chatModule from '../../src/chat/styx-chat.js';
import { MlsEngine } from '../../src/crypto/mls/mls-engine.js';
import { ContactRoster } from '../../src/chat/contact-roster.js';
import { NostrChatTransport } from '../../src/transport/nostr-chat-transport.js';
import { bytesToBase64, base64ToBytes, bytesToHex, utf8Encode, utf8Decode } from '../../src/utils.js';

const { StyxChat } = chatModule;

const wasmBytes = readFileSync(
  fileURLToPath(new URL('../../vendor/openmls-wasm/openmls_wasm_bg.wasm', import.meta.url)),
);

const BOB = 'b0'.repeat(32);

/** A JSON key-value backend, like LocalStorageBackend. */
function memBackend() {
  const m = new Map();
  return {
    async get(k) { return m.has(k) ? JSON.parse(m.get(k)) : null; },
    async set(k, v) { m.set(k, JSON.stringify(v)); },
    async delete(k) { m.delete(k); },
    async clear() { m.clear(); },
  };
}

const flush = async () => { for (let i = 0; i < 5; i += 1) await new Promise((r) => setTimeout(r, 0)); };

const live = [];
afterEach(() => { live.splice(0).forEach((c) => { try { c.destroy(); } catch { /* gone */ } }); });

async function appChat(backend, channelName) {
  const chat = new StyxChat();
  await chat.init({ password: 'pw', backend, channelName, allowInsecureTransport: true, autoStart: false });
  live.push(chat);
  return chat;
}

const parseInvite = (qr) => JSON.parse(utf8Decode(base64ToBytes(String(qr).replace('styx://invite/', ''))));

/** `peer` (a raw engine named `peerName`) answers `chat`'s QR invite. */
async function answerInvite(chat, peer, peerName) {
  const inv = parseInvite((await chat.createQrInvite()).qr);
  const nonce = base64ToBytes(inv.nonce);
  const started = peer.startSession(chat.me.pubkey, base64ToBytes(inv.kp));
  const envelope = {
    t: 'welcome',
    from: { pubkey: peerName },
    welcome: bytesToBase64(started.welcome),
    tree: bytesToBase64(started.ratchetTree),
    groupId: started.groupId,
    hmac: bytesToBase64(chat._welcomeMac(nonce, started.welcome, started.ratchetTree, started.groupId)),
  };
  await chat._onWire(peerName, utf8Encode(JSON.stringify(envelope)));
  return started;
}

/** The raw peer sends one typed message to `chat`, by default stamped now. */
async function peerSays(chat, peer, peerName, id, text, ts = Date.now()) {
  const ct = peer.session(chat.me.pubkey).encrypt(utf8Encode(JSON.stringify({ t: 'msg', id, text, ts })));
  await chat._onWire(peerName, utf8Encode(JSON.stringify({ t: 'app', ct: bytesToBase64(ct) })));
}

/** Count the 'read' receipts `chat` sends, by message id. */
function countReadReceipts(chat) {
  const reads = [];
  const orig = chat._sendReceipt.bind(chat);
  chat._sendReceipt = async (to, ref, kind) => {
    if (kind === 'read') reads.push(ref);
    return orig(to, ref, kind);
  };
  return reads;
}

async function pairedWithBob(backend, channel) {
  const chat = await appChat(backend, channel);
  const bob = await MlsEngine.create({ name: BOB });
  await answerInvite(chat, bob, BOB);
  await chat.confirmPairing({ contactPubkey: BOB, alias: 'Bob' });
  return { chat, bob };
}

describe('StyxChat legacy robustness', () => {
  beforeAll(async () => { await MlsEngine.initWasm({ wasmBytes }); });

  test('a message whose event reached no open relay connection is failed, not sent', async () => {
    const { chat } = await pairedWithBob(memBackend(), 'c7-sent-1');
    const sk = schnorr.utils.randomPrivateKey();
    chat._transport.close?.(); // release the in-process channel it replaces
    // A real Nostr chat transport whose pool has no open socket (never connected).
    chat._transport = new NostrChatTransport({
      secretKey: sk, pubkey: bytesToHex(schnorr.getPublicKey(sk)), relays: ['wss://relay.invalid'],
    });
    const states = [];
    chat.onMessageState((id, s) => states.push(s));
    const out = await chat.sendText(BOB, 'nessun relay aperto');
    expect(out.state).toBe('failed');
    expect(states).toEqual(['failed']);
    // Other callers keep their behaviour: typing stays best effort, and a pairing
    // welcome that reached no relay is not reported, as before.
    await expect(chat.setTyping(BOB, true)).resolves.toBeUndefined();
    const other = await appChat(memBackend(), 'c7-sent-1b');
    const { qr } = await other.createQrInvite();
    await expect(chat.acceptQrInvite(qr)).resolves.toEqual({ contactPubkey: other.me.pubkey });
    expect(chat._pending.has(other.me.pubkey)).toBe(true);
  });

  test('an envelope over MAX_WIRE_ENVELOPE_BYTES is dropped before decoding', async () => {
    const { chat, bob } = await pairedWithBob(memBackend(), 'c7-bound-1');
    expect(chatModule.MAX_WIRE_ENVELOPE_BYTES).toBe(1024 * 1024);
    const ct = bob.session(chat.me.pubkey).encrypt(utf8Encode(JSON.stringify({ t: 'msg', id: 'big', text: 'x', ts: Date.now() })));
    const json = JSON.stringify({ t: 'app', ct: bytesToBase64(ct) });
    // Valid JSON padded with whitespace past the bound.
    const padded = utf8Encode(json + ' '.repeat(chatModule.MAX_WIRE_ENVELOPE_BYTES - json.length + 1));
    expect(padded.byteLength).toBe(chatModule.MAX_WIRE_ENVELOPE_BYTES + 1);
    const parse = jest.spyOn(JSON, 'parse');
    try {
      await chat._onWire(BOB, padded);
      expect(parse).not.toHaveBeenCalled(); // dropped before any decoding
    } finally {
      parse.mockRestore();
    }
    expect((await chat.listMessages(BOB)).filter((m) => m.direction === 'in')).toHaveLength(0);
  });

  test('an envelope at the bound is still processed', async () => {
    const { chat, bob } = await pairedWithBob(memBackend(), 'c7-bound-2');
    const ct = bob.session(chat.me.pubkey).encrypt(utf8Encode(JSON.stringify({ t: 'msg', id: 'edge', text: 'x', ts: Date.now() })));
    const json = JSON.stringify({ t: 'app', ct: bytesToBase64(ct) });
    const padded = utf8Encode(json + ' '.repeat(chatModule.MAX_WIRE_ENVELOPE_BYTES - json.length));
    expect(padded.byteLength).toBe(chatModule.MAX_WIRE_ENVELOPE_BYTES);
    await chat._onWire(BOB, padded);
    expect((await chat.listMessages(BOB)).map((m) => m.id)).toContain('edge');
  });

  test('markRead with a message id acknowledges only up to that message', async () => {
    const { chat, bob } = await pairedWithBob(memBackend(), 'c7-read-1');
    const t0 = Date.now() - 60_000;
    await peerSays(chat, bob, BOB, 'm1', 'uno', t0);
    await peerSays(chat, bob, BOB, 'm2', 'due', t0 + 2000);
    // Arrives last but was written before m2: on screen it sits before m2.
    await peerSays(chat, bob, BOB, 'm3', 'tre', t0 + 1000);
    const reads = countReadReceipts(chat);
    await chat.markRead(BOB, 'm1');
    expect(reads).toEqual(['m1']);
    await chat.markRead(BOB, 'm2');
    expect(reads).toEqual(['m1', 'm3', 'm2']);
    // The named message counts even beyond the newest 1 000 of the conversation.
    await peerSays(chat, bob, BOB, 'm4', 'quattro', t0 + 2500);
    for (let i = 0; i < 1000; i += 1) {
      await chat._store.append({
        id: `f${i}`, contactPubkey: BOB, direction: 'in', text: 'x', ts: t0 + 3000 + i, state: 'delivered',
      });
    }
    await chat.markRead(BOB, 'm4');
    expect(reads).toEqual(['m1', 'm3', 'm2', 'm4']);
  });

  test('markRead with an id that is not in the conversation acknowledges nothing', async () => {
    const { chat, bob } = await pairedWithBob(memBackend(), 'c7-read-2');
    await peerSays(chat, bob, BOB, 'm1', 'uno');
    const reads = countReadReceipts(chat);
    await chat.markRead(BOB, 'not-a-message');
    expect(reads).toEqual([]);
  });

  test('a message acknowledged before a reload is not acknowledged again after it', async () => {
    const backend = memBackend();
    const { chat, bob } = await pairedWithBob(backend, 'c7-read-3');
    await peerSays(chat, bob, BOB, 'm1', 'uno');
    const before = countReadReceipts(chat);
    await chat.markRead(BOB);
    expect(before).toEqual(['m1']);
    chat.destroy();
    live.splice(live.indexOf(chat), 1);

    const reloaded = await appChat(backend, 'c7-read-3b');
    expect(reloaded._engine.session(BOB)).toBeTruthy();
    const after = countReadReceipts(reloaded);
    await reloaded.markRead(BOB);
    expect(after).toEqual([]);
  });

  test('read receipts can be turned off, and the choice survives a reload', async () => {
    const backend = memBackend();
    const { chat, bob } = await pairedWithBob(backend, 'c7-read-4');
    expect(chat.readReceiptsEnabled).toBe(true);
    await chat.setReadReceipts(false);
    expect(chat.readReceiptsEnabled).toBe(false);
    await peerSays(chat, bob, BOB, 'm1', 'uno');
    const reads = countReadReceipts(chat);
    await chat.markRead(BOB);
    expect(reads).toEqual([]);
    // The unread counter is still cleared.
    expect((await chat.listContacts()).find((c) => c.pubkey === BOB).unread).toBe(0);
    chat.destroy();
    live.splice(live.indexOf(chat), 1);

    const reloaded = await appChat(backend, 'c7-read-4b');
    expect(reloaded.readReceiptsEnabled).toBe(false);
  });

  test('removing a contact writes the shortened history at once', async () => {
    const backend = memBackend();
    const { chat, bob } = await pairedWithBob(backend, 'c7-remove-1');
    await peerSays(chat, bob, BOB, 'm1', 'uno');
    expect(Object.keys((await backend.get('msgs')) || {})).toContain(BOB);
    await chat.removeContact(BOB);
    expect(Object.keys((await backend.get('msgs')) || {})).not.toContain(BOB);
  });

  test('the group map has no prototype, so inherited names are not groups', async () => {
    const chat = await appChat(memBackend(), 'c7-proto-1');
    expect(Object.getPrototypeOf(chat._groups)).toBeNull();
    // A peer whose name is an Object.prototype key can still pair: the
    // "existing session" guard must not see an inherited property as a group.
    const peer = await MlsEngine.create({ name: 'constructor' });
    await answerInvite(chat, peer, 'constructor');
    expect(chat._engine.session('constructor')).toBeTruthy();
    expect(Object.getPrototypeOf(chat._groups)).toBeNull();
  });
});
