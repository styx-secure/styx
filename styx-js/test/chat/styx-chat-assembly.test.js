// test/chat/styx-chat-assembly.test.js — the real assembly path: new StyxChat()
// + init({password}) wiring Ed25519 identity, MLS engine, roster and a real
// BroadcastChannel transport. No injected engine/transport.
import { describe, test, expect, beforeAll, afterEach } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { StyxChat } from '../../src/chat/styx-chat.js';
import { MlsEngine } from '../../src/crypto/mls/mls-engine.js';

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
const flush = async () => { for (let i = 0; i < 6; i++) await new Promise((r) => setTimeout(r, 5)); };

const live = [];
afterEach(() => { live.splice(0).forEach((c) => c.destroy()); });

async function realPeer({ backend, channelName, alias, password = 'pw' }) {
  const chat = new StyxChat();
  await chat.init({ password, backend, channelName, alias });
  live.push(chat);
  return chat;
}

describe('StyxChat assembly (real identity + MLS + BroadcastChannel)', () => {
  beforeAll(async () => { await MlsEngine.initWasm({ wasmBytes }); });

  test('hasIdentity flips false→true; init derives a stable Ed25519 pubkey', async () => {
    const backend = memBackend();
    expect(await StyxChat.hasIdentity({ backend })).toBe(false);
    const chat = await realPeer({ backend, channelName: 'asm-1', alias: 'Neo' });
    expect(chat.me.alias).toBe('Neo');
    expect(chat.me.pubkey).toMatch(/^[0-9a-f]{64}$/);
    expect(await StyxChat.hasIdentity({ backend })).toBe(true);
  });

  test('re-init with the same backend + password recovers the same identity', async () => {
    const backend = memBackend();
    const first = await realPeer({ backend, channelName: 'asm-2a', alias: 'Trinity' });
    const pubkey = first.me.pubkey;
    first.destroy();
    const again = await realPeer({ backend, channelName: 'asm-2b' });
    expect(again.me.pubkey).toBe(pubkey);
    expect(again.me.alias).toBe('Trinity');
  });

  test('wrong password on re-init throws', async () => {
    const backend = memBackend();
    (await realPeer({ backend, channelName: 'asm-3', password: 'right' })).destroy();
    const chat = new StyxChat();
    await expect(chat.init({ password: 'wrong', backend, channelName: 'asm-3' }))
      .rejects.toThrow('Invalid password');
  });

  test('two real peers pair and exchange an encrypted message over BroadcastChannel', async () => {
    const ch = 'asm-e2e';
    const alice = await realPeer({ backend: memBackend(), channelName: ch, alias: 'Alice' });
    const bob = await realPeer({ backend: memBackend(), channelName: ch, alias: 'Bob' });

    const { qr } = await bob.createQrInvite();
    const { contactPubkey } = await alice.acceptQrInvite(qr);
    expect(contactPubkey).toBe(bob.me.pubkey);
    await alice.confirmPairing({ contactPubkey, alias: 'Bob' });
    await flush();

    expect((await alice.listContacts()).map((c) => c.pubkey)).toContain(bob.me.pubkey);
    expect((await bob.listContacts()).map((c) => c.pubkey)).toContain(alice.me.pubkey);

    const gotAtBob = new Promise((res) => bob.onMessage((m) => res(m)));
    await alice.sendText(bob.me.pubkey, 'Ciao Bob, crypto vera 🔐');
    const msg = await gotAtBob;
    expect(msg.text).toBe('Ciao Bob, crypto vera 🔐');
    expect(msg.contactPubkey).toBe(alice.me.pubkey);
  });

  test('an invite still works if the inviter reloads before the peer joins', async () => {
    const ch = 'invite-reload';
    const aBackend = memBackend();
    let a = await realPeer({ backend: aBackend, channelName: ch, alias: 'A' });
    const aPubkey = a.me.pubkey;
    const { qr } = await a.createQrInvite(); // KeyPackage generated — must be persisted

    // A reloads BEFORE the peer accepts the invite.
    a.destroy();
    a = new StyxChat();
    await a.init({ password: 'pw', backend: aBackend, channelName: ch });
    live.push(a);

    // B accepts A's invite → sends the Welcome to A, who must be able to join.
    const b = await realPeer({ backend: memBackend(), channelName: ch, alias: 'B' });
    await b.acceptQrInvite(qr);
    await b.confirmPairing({ contactPubkey: aPubkey, alias: 'A' });
    await flush();

    expect((await a.listContacts()).map((c) => c.pubkey)).toContain(b.me.pubkey);
    const gotAtA = new Promise((res) => a.onMessage((m) => res(m)));
    await b.sendText(aPubkey, 'ciao dopo reload invito');
    const msg = await Promise.race([
      gotAtA,
      new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 6000)),
    ]);
    expect(msg.text).toBe('ciao dopo reload invito');
  });

  test('a used invite cannot be replayed by a second peer after a reload', async () => {
    // The invite nonce is single-use AND persisted: burning it must survive the
    // reload, or a photographed QR would pair an attacker after a refresh.
    const ch = 'invite-replay';
    const aBackend = memBackend();
    let a = await realPeer({ backend: aBackend, channelName: ch, alias: 'A' });
    const aPubkey = a.me.pubkey;
    const { qr } = await a.createQrInvite();

    const b = await realPeer({ backend: memBackend(), channelName: ch, alias: 'B' });
    await b.acceptQrInvite(qr); // legitimate scan burns the nonce
    await flush();
    expect((await a.listContacts()).map((c) => c.pubkey)).toContain(b.me.pubkey);

    // A reloads; the burned nonce must not come back.
    a.destroy();
    a = new StyxChat();
    await a.init({ password: 'pw', backend: aBackend, channelName: ch });
    live.push(a);

    const mallory = await realPeer({ backend: memBackend(), channelName: ch, alias: 'M' });
    await mallory.acceptQrInvite(qr); // replays the same QR
    await flush();
    expect((await a.listContacts()).map((c) => c.pubkey)).not.toContain(mallory.me.pubkey);
    expect(a._engine.session(mallory.me.pubkey)).toBeFalsy();
  });

  test('a peer survives a reload and still receives on the restored MLS session', async () => {
    const ch = 'reload';
    const bobBackend = memBackend();
    const alice = await realPeer({ backend: memBackend(), channelName: ch, alias: 'Alice' });
    let bob = await realPeer({ backend: bobBackend, channelName: ch, alias: 'Bob' });
    const bobPubkey = bob.me.pubkey;

    const { qr } = await bob.createQrInvite();
    const { contactPubkey } = await alice.acceptQrInvite(qr);
    await alice.confirmPairing({ contactPubkey, alias: 'Bob' });
    await flush();
    await alice.sendText(bobPubkey, 'prima del reload');
    await flush();

    // Reload Bob: tear down and re-create from the SAME backend + password.
    bob.destroy();
    bob = new StyxChat();
    await bob.init({ password: 'pw', backend: bobBackend, channelName: ch });
    live.push(bob);

    // Same identity, contact restored, session reloaded.
    expect(bob.me.pubkey).toBe(bobPubkey);
    expect((await bob.listContacts()).map((c) => c.pubkey)).toContain(alice.me.pubkey);
    expect((await bob.listMessages(alice.me.pubkey)).map((m) => m.text)).toContain('prima del reload');

    // A new message from Alice is decrypted by the RESTORED session.
    const gotAfterReload = new Promise((res) => bob.onMessage((m) => res(m)));
    await alice.sendText(bobPubkey, 'dopo il reload');
    const msg = await Promise.race([
      gotAfterReload,
      new Promise((_, rej) => setTimeout(() => rej(new Error('timeout after reload')), 6000)),
    ]);
    expect(msg.text).toBe('dopo il reload');
  });
});
