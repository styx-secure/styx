// test/integration/styx-chat-nostr.test.js
// The full stack over a real strfry relay: two StyxChat peers (real secp256k1
// identities, real MLS) pair via an invite and exchange an encrypted message,
// with the relay as the transport — the shape of a real cross-device test.
//   docker compose -f docker-compose.test.yml up -d
//   NOSTR_RELAY=ws://localhost:17777 node --experimental-vm-modules \
//     node_modules/.bin/jest test/integration/styx-chat-nostr.test.js --forceExit
import { describe, test, expect, beforeAll, afterEach } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { StyxChat } from '../../src/chat/styx-chat.js';
import { MlsEngine } from '../../src/crypto/mls/mls-engine.js';

const RELAY = process.env.NOSTR_RELAY || 'ws://localhost:17777';
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
async function waitUntil(fn, { timeout = 8000, step = 150 } = {}) {
  const t0 = Date.now();
  for (;;) {
    if (await fn()) return true;
    if (Date.now() - t0 > timeout) throw new Error('waitUntil timeout');
    await new Promise((r) => setTimeout(r, step));
  }
}

const live = [];
afterEach(() => { live.splice(0).forEach((c) => c.destroy()); });

async function realPeer(alias) {
  const chat = new StyxChat();
  await chat.init({ password: 'pw', backend: memBackend(), relays: [RELAY], alias });
  live.push(chat);
  return chat;
}

describe('StyxChat over a real Nostr relay', () => {
  beforeAll(async () => { await MlsEngine.initWasm({ wasmBytes }); });

  test('two peers pair and exchange an MLS-encrypted message over the relay', async () => {
    const alice = await realPeer('Alice');
    const bob = await realPeer('Bob');

    const { qr } = await bob.createQrInvite();
    const { contactPubkey } = await alice.acceptQrInvite(qr);
    expect(contactPubkey).toBe(bob.me.pubkey);
    await alice.confirmPairing({ contactPubkey, alias: 'Bob' });

    // Welcome travels over the relay; Bob joins and learns Alice.
    await waitUntil(async () => (await bob.listContacts()).some((c) => c.pubkey === alice.me.pubkey));

    const gotAtBob = new Promise((res) => bob.onMessage((m) => res(m)));
    await alice.sendText(bob.me.pubkey, 'Ciao Bob, via relay Nostr reale 🔐');
    const msg = await Promise.race([
      gotAtBob,
      new Promise((_, rej) => setTimeout(() => rej(new Error('message timeout')), 10000)),
    ]);
    expect(msg.text).toBe('Ciao Bob, via relay Nostr reale 🔐');
    expect(msg.contactPubkey).toBe(alice.me.pubkey);
  }, 30000);
});
