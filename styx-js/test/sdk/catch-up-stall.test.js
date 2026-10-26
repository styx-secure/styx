// M3-CATCHUP: default timing, two independent loopback relays, no stall detector.
import { describe, test, expect, beforeAll, afterAll, afterEach, jest } from '@jest/globals';
import { WebSocket, WebSocketServer } from 'ws';
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, utf8Encode } from '../../src/utils.js';
import { createStyxClient, SDK_INTERFACE_VERSION } from '../../src/sdk/index.js';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const cleanups = [];
let originalWebSocket;
beforeAll(() => { originalWebSocket = globalThis.WebSocket; globalThis.WebSocket = WebSocket; });
afterAll(() => { globalThis.WebSocket = originalWebSocket; });
afterEach(async () => { for (const cleanup of cleanups.splice(0).reverse()) await cleanup(); });
async function until(predicate, ms = 3000) {
  const end = Date.now() + ms;
  while (!predicate() && Date.now() < end) await sleep(5);
  return predicate();
}
function matches(filter, event) {
  return filter.kinds.includes(event.kind)
    && event.tags.some(([name, value]) => name === 'p' && filter['#p'].includes(value))
    && (filter.since === undefined || event.created_at >= filter.since);
}
async function relay() {
  const server = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await new Promise((resolve) => server.once('listening', resolve));
  const peers = new Map();
  const events = new Map();
  const stalled = new Set();
  const requests = [];
  const send = (socket, frame) => {
    if (!stalled.has(peers.get(socket)?.key) && socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify(frame));
  };
  server.on('connection', (socket) => {
    const peer = { key: null, subscriptions: new Map() };
    peers.set(socket, peer);
    socket.on('close', () => peers.delete(socket));
    socket.on('message', (raw) => {
      const [type, value, filter] = JSON.parse(String(raw));
      if (type === 'REQ') {
        peer.key = filter['#p'][0];
        requests.push({ key: peer.key, id: value, filter, dropped: stalled.has(peer.key) });
      }
      // Both directions are dropped, without closing the socket. In particular
      // an initial dropped REQ installs no active subscription or EOSE.
      if (stalled.has(peer.key)) return;
      if (type === 'REQ') {
        peer.subscriptions.set(value, filter);
        for (const event of events.values()) if (matches(filter, event)) send(socket, ['EVENT', value, event]);
        send(socket, ['EOSE', value]);
      } else if (type === 'EVENT') {
        const event = value;
        const id = bytesToHex(sha256(utf8Encode(JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content]))));
        if (id !== event.id) { send(socket, ['OK', event.id, false, 'invalid id']); return; }
        events.set(event.id, event);
        send(socket, ['OK', event.id, true, 'saved']);
        for (const [other, state] of peers) for (const [sub, f] of state.subscriptions) {
          if (matches(f, event)) send(other, ['EVENT', sub, event]);
        }
      } else if (type === 'CLOSE') peer.subscriptions.delete(value);
    });
  });
  cleanups.push(async () => {
    for (const socket of server.clients) socket.terminate();
    await new Promise((resolve) => server.close(resolve));
  });
  return { url: `ws://127.0.0.1:${server.address().port}`, events, stalled, requests };
}
function makeClient(urls) {
  const key = schnorr.utils.randomPrivateKey();
  const pub = bytesToHex(schnorr.getPublicKey(key));
  const open = jest.fn(({ ciphertext }) => ({ plaintext: ciphertext }));
  const made = createStyxClient({
    interfaceVersion: SDK_INTERFACE_VERSION,
    relays: urls,
    ports: {
      storage: { put: () => true, get: () => null, update: () => true, remove: () => true, list: () => [] },
      session: { seal: ({ plaintext }) => ({ ciphertext: plaintext }), open },
      identity: { getPublicKey: () => pub, sign: ({ digest }) => schnorr.sign(digest, key) },
    },
    // All numeric delivery parameters and the clock retain their defaults.
    delivery: { receiptMode: 'RECIPIENT_RECEIPT' },
  });
  expect(made.ok).toBe(true);
  const client = made.value;
  cleanups.push(() => client.shutdown());
  return { client, pub, open, events: [] };
}
async function send(b, a, byte) {
  const sent = await b.client.send({ recipient: a.pub, payload: new Uint8Array([byte]) });
  expect(sent.ok).toBe(true);
  return sent.value.deliveryId;
}
const received = (h) => h.events.filter((e) => e.kind === 'MESSAGE_RECEIVED');
const acknowledged = (b, id) => b.events.some((e) => e.deliveryId === id && e.state === 'RECIPIENT_RECEIPT_RECEIVED');

describe('catch-up after an open-socket stall (default delivery)', () => {
  test.each(['reply 2', 'first inbound message', 'lost initial EOSE'])('%s', async (scenario) => {
    const relays = [await relay(), await relay()];
    const urls = relays.map((r) => r.url);
    const a = makeClient(urls);
    const b = makeClient(urls);
    if (scenario === 'lost initial EOSE') for (const r of relays) r.stalled.add(a.pub);
    for (const h of [a, b]) await h.client.onEvent((event) => h.events.push(event));
    const started = await Promise.all([a.client.start(), b.client.start()]);
    expect(started.every((r) => r.ok && r.value.connectedRelays === 2)).toBe(true);
    expect(relays.every((r) => r.requests.find((q) => q.key === a.pub)?.filter.since === undefined)).toBe(true);
    let expected = 1;
    if (scenario === 'reply 2') {
      const first = await send(b, a, 1);
      expect(await until(() => acknowledged(b, first))).toBe(true);
      expect(received(a)).toHaveLength(1);
      expected = 2;
    }
    for (const r of relays) r.stalled.add(a.pub);
    const id = await send(b, a, expected);
    expect(await until(() => relays.every((r) => [...r.events.values()].some((e) => e.kind === 4741 && e.content === (expected === 1 ? 'AQ==' : 'Ag=='))))).toBe(true);
    expect(received(a)).toHaveLength(expected - 1);
    const before = relays.map((r) => r.requests.filter((q) => q.key === a.pub).length);
    const restoredAt = Date.now();
    for (const r of relays) r.stalled.delete(a.pub);
    expect(await until(() => received(a).length === expected && acknowledged(b, id), 22000)).toBe(true);
    expect(Date.now() - restoredAt).toBeLessThanOrEqual(22000);
    for (const [i, r] of relays.entries()) {
      const req = r.requests.filter((q) => q.key === a.pub)[before[i]];
      expect(req).toBeDefined();
      expect(req.id).toBe(r.requests.find((q) => q.key === a.pub).id);
      if (scenario === 'lost initial EOSE') expect(req.filter).not.toHaveProperty('since');
      else expect(Number.isSafeInteger(req.filter.since)).toBe(true);
    }
    // A further re-request replays all these ids inside the unchanged window.
    const recoveredCounts = relays.map((r) => r.requests.filter((q) => q.key === a.pub).length);
    const receiptCounts = relays.map((r) => [...r.events.values()].filter((e) => e.kind === 4742 && e.pubkey === a.pub).length);
    expect(await until(() => relays.every((r, i) => r.requests.filter((q) => q.key === a.pub).length > recoveredCounts[i]), 11000)).toBe(true);
    await sleep(50);
    expect(a.open).toHaveBeenCalledTimes(expected);
    expect(received(a)).toHaveLength(expected);
    for (const [i, r] of relays.entries()) expect([...r.events.values()].filter((e) => e.kind === 4742 && e.pubkey === a.pub)).toHaveLength(receiptCounts[i]);
  }, 90000);
});
