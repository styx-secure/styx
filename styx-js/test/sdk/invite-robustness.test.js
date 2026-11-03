// Loopback-only invitation robustness tests. Test wrapping signs layers but DOES NOT ENCRYPT.
import { describe, test, expect, beforeAll, afterAll, afterEach } from '@jest/globals';
import { WebSocket, WebSocketServer } from 'ws';
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, utf8Encode, utf8Decode, bytesToBase64 } from '../../src/utils.js';
import { createStyxClient, SDK_INTERFACE_VERSION, SDK_WIRE_VERSION } from '../../src/sdk/index.js';

const V = SDK_WIRE_VERSION;
const cleanup = [];
let originalWebSocket;
beforeAll(() => { originalWebSocket = globalThis.WebSocket; globalThis.WebSocket = WebSocket; });
afterAll(() => { globalThis.WebSocket = originalWebSocket; });
afterEach(async () => { while (cleanup.length) await cleanup.pop()(); });
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function until(predicate, ms = 20000) {
  const end = Date.now() + ms;
  while (!predicate()) { if (Date.now() > end) throw Error('timeout'); await sleep(5); }
}
const hash = (event) => bytesToHex(sha256(utf8Encode(JSON.stringify([
  0, event.pubkey, event.created_at, event.kind, event.tags, event.content,
]))));
function signed(event, key) {
  const id = hash(event);
  return { ...event, id, sig: bytesToHex(schnorr.sign(hexToBytes(id), key)) };
}
function identity(key = schnorr.utils.randomPrivateKey()) {
  const pk = bytesToHex(schnorr.getPublicKey(key));
  return { pk, key, getPublicKey: () => pk, sign: ({ digest }) => schnorr.sign(digest, key),
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
function testSession(pk) {
  const peers = new Set();
  return { seal: ({ plaintext }) => ({ ciphertext: plaintext }), open: ({ ciphertext }) => ({ plaintext: ciphertext }),
    createKeyPackage: () => utf8Encode(pk),
    startSession: ({ peer, keyPackage }) => {
      if (peers.has(peer) || utf8Decode(keyPackage) !== peer) throw Error('credential/existing');
      peers.add(peer);
      return { welcome: utf8Encode(pk + ':' + peer), ratchetTree: new Uint8Array([1]) };
    },
    joinSession: ({ peer, welcome }) => {
      if (peers.has(peer) || utf8Decode(welcome) !== peer + ':' + pk) throw Error('welcome/existing');
      peers.add(peer); return true;
    },
  };
}
function clock(speed = 20) {
  const origin = Date.now();
  return { now: () => origin + (Date.now() - origin) * speed,
    setTimer: (f, ms) => setTimeout(f, ms / speed), clearTimer: clearTimeout };
}
// A loopback relay; `onReq(socket, subscriptionId, filter)` returning false skips replay and EOSE.
async function relay() {
  const server = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await new Promise((resolve) => server.once('listening', resolve));
  const events = [], subscriptions = new Map();
  const state = { events, server, onReq: null };
  const matches = (filter, event) => (!filter.kinds || filter.kinds.includes(event.kind))
    && (!filter.authors || filter.authors.includes(event.pubkey))
    && (!filter['#p'] || event.tags.some((t) => t[0] === 'p' && filter['#p'].includes(t[1])));
  server.on('connection', (socket) => {
    subscriptions.set(socket, new Map());
    socket.on('close', () => subscriptions.delete(socket));
    socket.on('message', (raw) => {
      const f = JSON.parse(String(raw));
      if (f[0] === 'REQ') {
        subscriptions.get(socket).set(f[1], f[2]);
        if (state.onReq?.(socket, f[1], f[2]) === false) return;
        for (const event of events) if (matches(f[2], event)) socket.send(JSON.stringify(['EVENT', f[1], event]));
        socket.send(JSON.stringify(['EOSE', f[1]]));
      }
      if (f[0] === 'EVENT') {
        socket.send(JSON.stringify(['OK', f[1].id, true, 'test']));
        events.push(f[1]);
        for (const [s, subs] of subscriptions) for (const [id, filter] of subs)
          if (s.readyState === WebSocket.OPEN && matches(filter, f[1])) s.send(JSON.stringify(['EVENT', id, f[1]]));
      }
      if (f[0] === 'CLOSE') subscriptions.get(socket).delete(f[1]);
    });
  });
  cleanup.push(async () => { for (const socket of server.clients) socket.terminate(); await new Promise((resolve) => server.close(resolve)); });
  state.url = 'ws' + '://' + '127.0.0.1:' + server.address().port;
  return state;
}
async function started(relays, { id = identity(), time = clock() } = {}) {
  const records = new Map();
  const session = testSession(id.pk);
  const config = { interfaceVersion: SDK_INTERFACE_VERSION, relays: relays.map((r) => r.url), clock: time,
    delivery: { perRelayTimeoutMs: 11000, deadlineMs: 30000 },
    ports: { identity: id, session, storage: {
      list: () => [...records.values()], get: (key) => records.get(key),
      put: (record) => { records.set(record.deliveryId, record); return true; },
      update: (key, value) => { records.set(key, value); return true; }, remove: (key) => records.delete(key),
    } } };
  const created = createStyxClient(config);
  expect(created.ok).toBe(true);
  cleanup.push(() => created.value.shutdown());
  expect((await created.value.start()).ok).toBe(true);
  return { client: created.value, id, session, config };
}
// A signed kind-1059 wrap for `recipient` whose content no unwrap accepts.
function junkWrap(recipient, label, key = schnorr.utils.randomPrivateKey()) {
  return signed({ pubkey: bytesToHex(schnorr.getPublicKey(key)), created_at: Math.floor(Date.now() / 1000),
    kind: 1059, tags: [['p', recipient]], content: JSON.stringify({ junk: label }) }, key);
}

describe('C-DLV section 7.1 -- invitation candidates examined once and bounded', () => {
  test('repeated copies of one wrap are unwrapped once; the genuine Welcome is then reached', async () => {
    const r = await relay(); const a = await started([r]), b = await started([r]);
    const kp = await b.client.publishKeyPackage(); expect(kp.ok).toBe(true);
    expect((await a.client.invite({ invitee: b.id.pk })).ok).toBe(true);
    const genuine = r.events.find((e) => e.kind === 1059);
    const invalid = junkWrap(b.id.pk, 'repeated');
    r.events.splice(0, r.events.length, ...Array.from({ length: 20 }, () => ({ ...invalid })), genuine);
    const unwrap = b.id.unwrapGift; const seen = [];
    // 120 ms per unwrap: twenty-one serial unwraps outlast the 1.5 s (real) accept deadline.
    b.id.unwrapGift = async (argument) => { seen.push(argument.event.id); await sleep(120); return unwrap(argument); };
    const accepted = await b.client.acceptInvite({ inviter: a.id.pk, keyPackageEventId: kp.value.keyPackageEventId });
    expect(accepted).toEqual({ ok: true, value: { inviter: a.id.pk } });
    expect(seen).toEqual([invalid.id, genuine.id]);
  });

  test('a re-signed copy under the same wrap key is not unwrapped again', async () => {
    const r = await relay(); const a = await started([r]), b = await started([r]);
    const kp = await b.client.publishKeyPackage();
    expect((await a.client.invite({ invitee: b.id.pk })).ok).toBe(true);
    const genuine = r.events.find((e) => e.kind === 1059);
    const key = schnorr.utils.randomPrivateKey();
    const first = junkWrap(b.id.pk, 'same', key);
    const later = signed({ ...first, created_at: first.created_at - 1 }, key);
    expect(later.id).not.toBe(first.id);
    r.events.splice(0, r.events.length, first, later, genuine);
    const unwrap = b.id.unwrapGift; const seen = [];
    b.id.unwrapGift = (argument) => { seen.push(argument.event.id); return unwrap(argument); };
    expect((await b.client.acceptInvite({ inviter: a.id.pk, keyPackageEventId: kp.value.keyPackageEventId })).ok).toBe(true);
    expect(seen).toEqual([first.id, genuine.id]);
  });

  test('the same content under another wrap key does not suppress the genuine wrap', async () => {
    const r = await relay(); const a = await started([r]), b = await started([r]);
    const kp = await b.client.publishKeyPackage();
    expect((await a.client.invite({ invitee: b.id.pk })).ok).toBe(true);
    const genuine = r.events.find((e) => e.kind === 1059);
    const other = schnorr.utils.randomPrivateKey();
    const copy = signed({ ...genuine, pubkey: bytesToHex(schnorr.getPublicKey(other)) }, other);
    r.events.splice(0, r.events.length, copy, genuine);
    // Like NIP-44, the unwrap depends on the wrap key: only the genuine key opens it.
    const unwrap = b.id.unwrapGift; const seen = [];
    b.id.unwrapGift = (argument) => {
      seen.push(argument.event.id);
      if (argument.event.pubkey !== genuine.pubkey) throw Error('wrong conversation key');
      return unwrap(argument);
    };
    expect(await b.client.acceptInvite({ inviter: a.id.pk, keyPackageEventId: kp.value.keyPackageEventId }))
      .toEqual({ ok: true, value: { inviter: a.id.pk } });
    expect(seen).toEqual([copy.id, genuine.id]);
  });

  test('at most 1 024 unexamined candidates wait while an unwrap is in progress', async () => {
    const r = await relay(); const b = await started([r], { time: clock(1) }); const inviter = identity();
    const kp = await b.client.publishKeyPackage();
    const head = junkWrap(b.id.pk, 'head');
    const flood = Array.from({ length: 1100 }, (_, i) => junkWrap(b.id.pk, 'flood-' + i));
    let release; const held = new Promise((resolve) => { release = resolve; });
    const seen = [];
    b.id.unwrapGift = async ({ event }) => {
      seen.push(event.id);
      if (event.id === head.id) await held;
      throw Error('junk');
    };
    let socket = null, sid = null;
    r.onReq = (s, id, filter) => {
      if (!filter.kinds?.includes(1059)) return undefined;
      socket = s; sid = id; s.send(JSON.stringify(['EVENT', id, head])); return false;
    };
    const accepting = b.client.acceptInvite({ inviter: inviter.pk, keyPackageEventId: kp.value.keyPackageEventId });
    await until(() => seen.length === 1);
    for (const event of flood) socket.send(JSON.stringify(['EVENT', sid, event]));
    socket.send(JSON.stringify(['EOSE', sid]));
    await sleep(300);
    release();
    await until(() => seen.length >= 1025);
    await sleep(300);
    expect(seen.length).toBe(1025);
    expect(seen.slice(1)).toEqual(flood.slice(0, 1024).map((e) => e.id));
    await b.client.shutdown();
    expect(await accepting).toEqual({ ok: false, code: 'E_SDK_CLIENT_STOPPED' });
  }, 60000);
});

describe('C-DLV section 6.5 -- a KeyPackage may not lead the local clock beyond the bound', () => {
  function keyPackageEvent(owner, createdAt) {
    return signed({ pubkey: owner.pk, created_at: createdAt, kind: 4743,
      tags: [['v', V], ['expiration', String(createdAt + 3600)]], content: bytesToBase64(utf8Encode(owner.pk)) }, owner.key);
  }

  test('a KeyPackage dated a day ahead is not selected over the current one', async () => {
    const r = await relay(); const a = await started([r]), b = await started([r]);
    const kp = await b.client.publishKeyPackage(); expect(kp.ok).toBe(true);
    const future = keyPackageEvent(b.id, Math.floor(a.config.clock.now() / 1000) + 86400);
    r.events.push(future);
    const sent = await a.client.invite({ invitee: b.id.pk });
    expect(sent.ok).toBe(true);
    expect(sent.value.keyPackageEventId).toBe(kp.value.keyPackageEventId);
  });

  test('only future KeyPackages: none is selected', async () => {
    const r = await relay(); const a = await started([r]), b = identity();
    r.events.push(keyPackageEvent(b, Math.floor(a.config.clock.now() / 1000) + 3600));
    expect(await a.client.invite({ invitee: b.pk })).toEqual({ ok: false, code: 'E_SDK_KEYPACKAGE_NOT_FOUND' });
  });

  test('a KeyPackage within the bound remains the newest valid choice', async () => {
    const r = await relay(); const a = await started([r]), b = await started([r]);
    const kp = await b.client.publishKeyPackage(); expect(kp.ok).toBe(true);
    const ahead = keyPackageEvent(b.id, Math.floor(a.config.clock.now() / 1000) + 300);
    r.events.push(ahead);
    const sent = await a.client.invite({ invitee: b.id.pk });
    expect(sent.ok).toBe(true);
    expect(sent.value.keyPackageEventId).toBe(ahead.id);
  });
});
