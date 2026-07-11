// test/integration/nostr-chat-transport.test.js
// Integration test against a real strfry relay (Docker).
//   cd styx-js && docker compose -f docker-compose.test.yml up -d
//   NOSTR_RELAY=ws://localhost:17777 node --experimental-vm-modules \
//     node_modules/.bin/jest test/integration/nostr-chat-transport.test.js --forceExit
import { describe, test, expect, afterEach, beforeAll } from '@jest/globals';
import WebSocket from 'ws';
import { schnorr } from '@noble/curves/secp256k1';
import { NostrChatTransport } from '../../src/transport/nostr-chat-transport.js';
import { bytesToHex } from '../../src/utils.js';

const RELAY = process.env.NOSTR_RELAY || 'ws://localhost:17777';

// These tests need a live relay. Where none is reachable (e.g. CI without strfry) they
// skip gracefully instead of failing — same pattern as nostr-relay.test.js.
globalThis.WebSocket = globalThis.WebSocket || WebSocket;
let relayAvailable = false;
beforeAll(async () => {
  relayAvailable = await new Promise((resolve) => {
    const ws = new WebSocket(RELAY);
    const t = setTimeout(() => { try { ws.close(); } catch {} resolve(false); }, 2000);
    ws.on('open', () => { clearTimeout(t); ws.close(); resolve(true); });
    ws.on('error', () => { clearTimeout(t); resolve(false); });
  });
  if (!relayAvailable) {
    console.warn('\n⚠ Nostr relay not available at ' + RELAY + ' — skipping relay integration tests.\n');
  }
}, 10000);
const skipIfNoRelay = () => !relayAvailable;

function newPeer() {
  const sk = schnorr.utils.randomPrivateKey();
  const pk = bytesToHex(schnorr.getPublicKey(sk));
  return { sk, pk };
}

const live = [];
afterEach(() => { live.splice(0).forEach((t) => t.close()); });

function transport({ sk, pk }) {
  const t = new NostrChatTransport({ secretKey: sk, pubkey: pk, relays: [RELAY] });
  live.push(t);
  return t;
}

describe('NostrChatTransport (real strfry relay)', () => {
  test('delivers an addressed message from one peer to another', async () => {
    if (skipIfNoRelay()) return;
    const alice = newPeer();
    const bob = newPeer();
    const at = transport(alice);
    const bt = transport(bob);

    const got = new Promise((resolve) => {
      bt.onMessage((from, bytes) => resolve({ from, text: new TextDecoder().decode(bytes) }));
    });

    await bt.connect();
    await at.connect();
    await new Promise((r) => setTimeout(r, 200));
    await at.send(bob.pk, new TextEncoder().encode('ciao via nostr'));

    const msg = await Promise.race([
      got,
      new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 8000)),
    ]);
    expect(msg.from).toBe(alice.pk);
    expect(msg.text).toBe('ciao via nostr');
  }, 15000);

  test('a peer receives a message stored before it subscribed (offline delivery)', async () => {
    if (skipIfNoRelay()) return;
    const alice = newPeer();
    const bob = newPeer();
    const at = transport(alice);
    await at.connect();
    await at.send(bob.pk, new TextEncoder().encode('messaggio in differita'));
    await new Promise((r) => setTimeout(r, 400)); // let the relay store it

    const bt = transport(bob);
    const got = new Promise((resolve) => {
      bt.onMessage((from, bytes) => resolve(new TextDecoder().decode(bytes)));
    });
    await bt.connect(); // subscription should replay the stored event

    const text = await Promise.race([
      got,
      new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 8000)),
    ]);
    expect(text).toBe('messaggio in differita');
  }, 15000);

  test('multiple messages sent while offline are all stored and delivered', async () => {
    if (skipIfNoRelay()) return;
    const alice = newPeer();
    const bob = newPeer();
    const at = transport(alice);
    await at.connect();
    for (const m of ['uno', 'due', 'tre']) {
      await at.send(bob.pk, new TextEncoder().encode(m));
      await new Promise((r) => setTimeout(r, 60));
    }
    await new Promise((r) => setTimeout(r, 400));

    const bt = transport(bob);
    const received = new Set();
    const done = new Promise((resolve) => {
      bt.onMessage((_from, bytes) => {
        received.add(new TextDecoder().decode(bytes));
        if (received.size === 3) resolve();
      });
    });
    await bt.connect();
    await Promise.race([
      done,
      new Promise((_, rej) => setTimeout(() => rej(new Error(`only got ${[...received]}`)), 8000)),
    ]);
    expect([...received].sort()).toEqual(['due', 'tre', 'uno']);
  }, 15000);

  test('reconnect resumes delivery and does not re-deliver replayed events', async () => {
    if (skipIfNoRelay()) return;
    const alice = newPeer();
    const bob = newPeer();
    const at = transport(alice);
    const bt = transport(bob);
    const got = [];
    bt.onMessage((_from, bytes) => got.push(new TextDecoder().decode(bytes)));
    await bt.connect();
    await at.connect();
    await new Promise((r) => setTimeout(r, 200));

    await at.send(bob.pk, new TextEncoder().encode('m1'));
    await new Promise((r) => setTimeout(r, 400));
    expect(got).toEqual(['m1']);

    // Simulate returning to the foreground: force reconnect (relay replays m1).
    await bt.reconnect();
    await new Promise((r) => setTimeout(r, 400));
    expect(got).toEqual(['m1']); // replayed m1 is deduped, not delivered twice

    // A new message after reconnect still arrives.
    await at.send(bob.pk, new TextEncoder().encode('m2'));
    await new Promise((r) => setTimeout(r, 500));
    expect(got).toEqual(['m1', 'm2']);
  }, 20000);
});
