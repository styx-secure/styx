// Real immutable vendored engine; the test gift wrap DOES NOT ENCRYPT.
// Only this file has the owner-authorized MlsEngine/node:fs import exception.
import { describe, test, expect, beforeAll, afterAll, afterEach } from '@jest/globals';
import { MlsEngine } from '../../src/crypto/mls/mls-engine.js';
import { readFileSync } from 'node:fs';
import { WebSocket, WebSocketServer } from 'ws';
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, utf8Encode } from '../../src/utils.js';
import { createStyxClient, SDK_INTERFACE_VERSION } from '../../src/sdk/index.js';

const cleanup = [];
let originalWebSocket;
beforeAll(async () => {
  originalWebSocket = globalThis.WebSocket; globalThis.WebSocket = WebSocket;
  await MlsEngine.initWasm({ wasmBytes: readFileSync(new URL('../../vendor/openmls-wasm/openmls_wasm_bg.wasm', import.meta.url)) });
});
afterAll(() => { globalThis.WebSocket = originalWebSocket; });
afterEach(async () => { while (cleanup.length) await cleanup.pop()(); });
const hash = (e) => bytesToHex(sha256(utf8Encode(JSON.stringify([0, e.pubkey, e.created_at, e.kind, e.tags, e.content]))));
function signed(e, key) { const id = hash(e); return { ...e, id, sig: bytesToHex(schnorr.sign(hexToBytes(id), key)) }; }
function identity() {
  const key = schnorr.utils.randomPrivateKey(), pk = bytesToHex(schnorr.getPublicKey(key));
  return { pk, getPublicKey: () => pk, sign: ({ digest }) => schnorr.sign(digest, key),
    giftWrap: ({ rumor, recipient }) => {
      const seal = signed({ pubkey: pk, created_at: rumor.created_at, kind: 13, tags: [], content: JSON.stringify(rumor) }, key);
      const fresh = schnorr.utils.randomPrivateKey();
      return signed({ pubkey: bytesToHex(schnorr.getPublicKey(fresh)), created_at: rumor.created_at,
        kind: 1059, tags: [['p', recipient]], content: JSON.stringify(seal) }, fresh);
    },
    unwrapGift: ({ event }) => {
      const seal = JSON.parse(event.content);
      if (seal.kind !== 13 || seal.id !== hash(seal)
          || !schnorr.verify(hexToBytes(seal.sig), hexToBytes(seal.id), hexToBytes(seal.pubkey))) throw Error('seal');
      return { rumor: JSON.parse(seal.content), sealSigner: seal.pubkey };
    },
  };
}
async function adapter(id) {
  const engine = await MlsEngine.create({ name: id.pk });
  const bindings = new Set();
  const port = {
    createKeyPackage: () => engine.keyPackageBytes(),
    startSession: async ({ peer, keyPackage }) => {
      if (bindings.has(peer)) throw Error('existing');
      // Validate credentials on an isolated, throwaway real engine before mutating this engine.
      const probe = await MlsEngine.create({ name: id.pk });
      probe.startSession(peer, keyPackage);
      if (probe.peerIdentity(peer) !== peer) throw Error('wrong KeyPackage credential');
      const result = engine.startSession(peer, keyPackage);
      bindings.add(peer);
      return { welcome: result.welcome, ratchetTree: result.ratchetTree };
    },
    joinSession: async ({ peer, welcome, ratchetTree }) => {
      if (bindings.has(peer)) throw Error('existing');
      // A clone checks membership; the live caller state changes only after validation.
      const clone = await MlsEngine.restore({ name: id.pk, stateBytes: engine.serializeState(), identityPubKey: engine.identityPublicKey() });
      clone.joinSession(peer, welcome, ratchetTree);
      if (clone.peerIdentity(peer) !== peer) throw Error('wrong Welcome credential');
      engine.joinSession(peer, welcome, ratchetTree); bindings.add(peer); return true;
    },
    seal: ({ recipient, plaintext }) => ({ ciphertext: engine.session(recipient).encrypt(plaintext) }),
    open: ({ sender, ciphertext }) => {
      const result = engine.session(sender).decrypt(ciphertext);
      if (result.kind !== 'application') throw Error('not an application message');
      return { plaintext: result.plaintext };
    },
  };
  return { engine, port };
}
async function relay() {
  const server = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await new Promise((resolve) => server.once('listening', resolve));
  const events = [], subscriptions = new Map();
  function matches(f, e) { return (!f.kinds || f.kinds.includes(e.kind)) && (!f.authors || f.authors.includes(e.pubkey))
    && (!f['#p'] || e.tags.some((t) => t[0] === 'p' && f['#p'].includes(t[1]))); }
  server.on('connection', (socket) => {
    subscriptions.set(socket, new Map()); socket.on('close', () => subscriptions.delete(socket));
    socket.on('message', (raw) => {
      const f = JSON.parse(String(raw));
      if (f[0] === 'REQ') {
        subscriptions.get(socket).set(f[1], f[2]);
        for (const e of events) if (matches(f[2], e)) socket.send(JSON.stringify(['EVENT', f[1], e]));
        socket.send(JSON.stringify(['EOSE', f[1]]));
      }
      if (f[0] === 'EVENT') {
        const event = f[1]; events.push(event); socket.send(JSON.stringify(['OK', event.id, true, 'test']));
        for (const [s, subs] of subscriptions) for (const [sub, filter] of subs)
          if (s.readyState === WebSocket.OPEN && matches(filter, event)) s.send(JSON.stringify(['EVENT', sub, event]));
      }
      if (f[0] === 'CLOSE') subscriptions.get(socket).delete(f[1]);
    });
  });
  cleanup.push(async () => { for (const socket of server.clients) socket.terminate(); await new Promise((resolve) => server.close(resolve)); });
  return { events, url: 'ws' + '://' + '127.0.0.1:' + server.address().port };
}
async function client(relays) {
  const id = identity(), session = await adapter(id), records = new Map();
  const origin = Date.now();
  const made = createStyxClient({ interfaceVersion: SDK_INTERFACE_VERSION, relays: relays.map((r) => r.url),
    clock: { now: () => origin + (Date.now() - origin) * 10, setTimer: (f, ms) => setTimeout(f, ms / 10), clearTimer: clearTimeout },
    delivery: { perRelayTimeoutMs: 11000, deadlineMs: 60000 },
    ports: { identity: id, session: session.port, storage: {
      put: (record) => { records.set(record.deliveryId, record); return true; },
      get: (key) => records.get(key) || null, update: (key, record) => { records.set(key, record); return true; },
      remove: (key) => records.delete(key), list: () => [...records.values()],
    } } });
  expect(made.ok).toBe(true); cleanup.push(() => made.value.shutdown());
  expect((await made.value.start()).ok).toBe(true);
  return { ...session, id, client: made.value };
}
async function flow(a, b) {
  const kp = await b.client.publishKeyPackage(); expect(kp.ok).toBe(true);
  const pending = b.client.acceptInvite({ inviter: a.id.pk, keyPackageEventId: kp.value.keyPackageEventId });
  const sent = await a.client.invite({ invitee: b.id.pk });
  return { kp, sent, accepted: await pending };
}
describe('M3-INVITE real MlsEngine, isolated loopback', () => {
  test('two-member flow, equal exporter, bidirectional seal/open; wrong credential rejected before session creation', async () => {
    const relays = [await relay(), await relay()];
    const [a, b] = await Promise.all([client(relays), client(relays)]);
    const third = await MlsEngine.create({ name: 'c'.repeat(64) });
    await expect(a.port.startSession({ peer: b.id.pk, keyPackage: third.keyPackageBytes() })).rejects.toThrow('credential');
    expect(a.engine.session(b.id.pk)).toBeUndefined();
    const result = await flow(a, b);
    expect(result.sent.ok).toBe(true);
    expect(result.accepted).toEqual({ ok: true, value: { inviter: a.id.pk } });
    expect(a.engine.peerIdentity(b.id.pk)).toBe(b.id.pk); expect(b.engine.peerIdentity(a.id.pk)).toBe(a.id.pk);
    const label = 'styx-invite-test', context = new Uint8Array([1, 2]);
    expect(a.engine.session(b.id.pk).exportSecret(label, context, 32)).toEqual(b.engine.session(a.id.pk).exportSecret(label, context, 32));
    for (const [sender, receiver] of [[a, b], [b, a]]) {
      const plaintext = new Uint8Array([7, 4, 3]);
      const sealed = sender.port.seal({ recipient: receiver.id.pk, plaintext });
      expect(receiver.port.open({ sender: sender.id.pk, ciphertext: sealed.ciphertext })).toEqual({ plaintext });
    }
  });
  test('refused Welcome => session failed; same inviter state fails, fresh engines/ports/clients succeed', async () => {
    const relays = [await relay()]; const [a, b] = await Promise.all([client(relays), client(relays)]);
    const originalJoin = b.port.joinSession;
    b.port.joinSession = () => { throw Error('refused Welcome'); };
    const first = await flow(a, b);
    expect(first.sent.ok).toBe(true); expect(first.accepted).toEqual({ ok: false, code: 'E_SDK_SESSION_FAILED' });
    b.port.joinSession = originalJoin;
    expect(await a.client.invite({ invitee: b.id.pk })).toEqual({ ok: false, code: 'E_SDK_SESSION_FAILED' });
    await a.client.shutdown(); await b.client.shutdown();
    const [freshA, freshB] = await Promise.all([client(relays), client(relays)]);
    const fresh = await flow(freshA, freshB);
    expect(fresh.sent.ok).toBe(true); expect(fresh.accepted.ok).toBe(true);
  });
});
