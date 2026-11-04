// M3-RECEIVE-1: the 0.4.0 client with and without `ports.receiveState`, over
// loopback relays started inside the test, with deterministic fake ports: an
// in-memory durable store shared by successive client instances (a simulated
// crash makes one instance's view dead), a cleartext session port with a fake
// candidate/commit coordinator, and an accelerated caller clock.
import { describe, test, expect, beforeAll, afterAll, afterEach } from '@jest/globals';
import { WebSocket, WebSocketServer } from 'ws';
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, utf8Encode, utf8Decode } from '../../src/utils.js';
import { createStyxClient, SDK_INTERFACE_VERSION, SDK_WIRE_VERSION } from '../../src/sdk/index.js';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const cleanups = [];
let originalWebSocket;
beforeAll(() => { originalWebSocket = globalThis.WebSocket; globalThis.WebSocket = WebSocket; });
afterAll(() => { globalThis.WebSocket = originalWebSocket; });
afterEach(async () => { for (const cleanup of cleanups.splice(0).reverse()) await cleanup(); });
async function until(predicate, ms = 8000) {
  const end = Date.now() + ms;
  while (!predicate() && Date.now() < end) await sleep(5);
  return predicate();
}
const SCHEMA = 'styx-m3-receive-state/v1';
const SCOPE = 'styx-m3-delivery/4741/wire-0.3.0';
const NEVER = new Promise(() => {});

/** An accelerated caller clock: time and timers both run `factor` times faster. */
function fastClock(factor = 50) {
  const origin = Date.now();
  return {
    now: () => origin + (Date.now() - origin) * factor,
    setTimer: (callback, delay) => setTimeout(callback, Math.max(0, Math.floor(delay / factor))),
    clearTimer: (handle) => clearTimeout(handle),
  };
}

function matches(filter, event) {
  return (!filter.kinds || filter.kinds.includes(event.kind))
    && (!filter.authors || filter.authors.includes(event.pubkey))
    && (!filter.ids || filter.ids.includes(event.id))
    && (!filter['#p'] || event.tags.some(([name, value]) => name === 'p' && filter['#p'].includes(value)))
    && (filter.since === undefined || event.created_at >= filter.since);
}

/** A NIP-01 loopback relay: stores events, serves REQ with since, EOSE, live events. */
async function relay({ delayMs = 0 } = {}) {
  const server = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await new Promise((resolve) => server.once('listening', resolve));
  const peers = new Map();
  const events = new Map();
  const requests = [];
  const state = { delayMs, mute: new Set() };
  const send = (socket, frame) => {
    const go = () => { if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify(frame)); };
    if (state.delayMs > 0 && frame[0] === 'EVENT') setTimeout(go, state.delayMs); else go();
  };
  server.on('connection', (socket) => {
    const peer = { key: null, subscriptions: new Map() };
    peers.set(socket, peer);
    socket.on('close', () => peers.delete(socket));
    socket.on('message', (raw) => {
      const [type, value, filter] = JSON.parse(String(raw));
      if (type === 'REQ') {
        if (filter['#p'] !== undefined) peer.key = filter['#p'][0];
        requests.push({ key: peer.key, id: value, filter });
        peer.subscriptions.set(value, filter);
        for (const event of events.values()) if (matches(filter, event)) send(socket, ['EVENT', value, event]);
        if (state.delayMs > 0) setTimeout(() => send(socket, ['EOSE', value]), state.delayMs + 5);
        else send(socket, ['EOSE', value]);
      } else if (type === 'EVENT') {
        const event = value;
        const id = bytesToHex(sha256(utf8Encode(JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content]))));
        if (id !== event.id) { send(socket, ['OK', event.id, false, 'invalid id']); return; }
        events.set(event.id, event);
        send(socket, ['OK', event.id, true, 'saved']);
        for (const [other, entry] of peers) {
          if (state.mute.has(entry.key)) continue;
          for (const [sub, f] of entry.subscriptions) if (matches(f, event)) send(other, ['EVENT', sub, event]);
        }
      } else if (type === 'CLOSE') peer.subscriptions.delete(value);
    });
  });
  cleanups.push(async () => {
    for (const socket of server.clients) socket.terminate();
    await new Promise((resolve) => server.close(resolve));
  });
  return { url: `ws://127.0.0.1:${server.address().port}`, events, requests, state };
}

/** The durable store of one identity. `view()` is one process's port; `crash()` kills that view. */
function durableDisk(publicKey) {
  const disk = {
    revision: 0, seen: [], pending: [], ready: [], acknowledged: [], receiptsDue: [], cursors: [],
    resolutions: new Map(), mlsCommitted: 0, loads: 0, provider: 0,
  };
  const bytes = () => 100 + 32 * disk.seen.length + disk.pending.reduce((n, e) => n + e.ciphertext.length, 0)
    + disk.ready.reduce((n, e) => n + e.payload.length, 0);
  const ok = () => Object.freeze({ revision: disk.revision, storedBytes: bytes() });
  function view() {
    const self = { dead: false, crashAt: null, calls: [] };
    // A crash point: { method, when: 'before' | 'after' } on the next matching call.
    const gate = async (method, apply) => {
      if (self.dead) return NEVER;
      self.calls.push(method);
      const point = self.crashAt !== null && self.crashAt.method === method ? self.crashAt : null;
      if (point !== null && point.when === 'before') { self.dead = true; return NEVER; }
      const value = apply();
      if (point !== null && point.when === 'after') { self.dead = true; return NEVER; }
      return value;
    };
    const write = (method, argument, change) => gate(method, () => {
      if (argument.revision !== disk.revision) return Object.freeze({ code: 'E_SDK_RECEIVE_STATE_CONFLICT' });
      change();
      disk.revision += 1;
      return ok();
    });
    self.port = {
      load: (argument) => gate('load', () => {
        disk.loads += 1;
        if (argument.identity !== publicKey || argument.scope !== SCOPE) return Object.freeze({ code: 'E_SDK_RECEIVE_STATE_INCOMPATIBLE' });
        if (disk.torn) return Object.freeze({ code: 'E_SDK_RECEIVE_STATE_INCOMPATIBLE' });
        return {
          schema: SCHEMA, identity: publicKey, scope: SCOPE, revision: disk.revision, storedBytes: bytes(),
          cursors: disk.cursors.map((c) => ({ ...c })),
          pending: disk.pending.map((e) => ({ ...e, ciphertext: new Uint8Array(e.ciphertext) })),
          ready: disk.ready.map((e) => ({ ...e, payload: new Uint8Array(e.payload) })),
          acknowledged: [...disk.acknowledged], receiptsDue: disk.receiptsDue.map((e) => ({ ...e })), seen: [...disk.seen],
        };
      }),
      stage: (a) => write('stage', a, () => {
        if (!disk.seen.includes(a.event.eventId)) {
          disk.seen.push(a.event.eventId);
          disk.pending.push({ ...a.event, ciphertext: new Uint8Array(a.event.ciphertext) });
        }
      }),
      commit: (a) => write('commit', a, () => {
        disk.pending = disk.pending.filter((e) => e.eventId !== a.eventId);
        if (a.result.type === 'application') {
          disk.ready.push({ eventId: a.eventId, sender: a.result.sender, payload: new Uint8Array(a.result.payload),
            receiptDue: a.result.receiptDue });
          if (a.result.receiptDue) disk.receiptsDue.push({ eventId: a.eventId, sender: a.result.sender });
        }
        disk.mlsCommitted = a.ticket.generation;
        disk.resolutions.set(a.operationId, a.result);
      }),
      ack: (a) => write('ack', a, () => {
        disk.ready = disk.ready.filter((e) => e.eventId !== a.eventId);
        disk.acknowledged.push(a.eventId);
      }),
      receiptDone: (a) => write('receiptDone', a, () => {
        disk.receiptsDue = disk.receiptsDue.filter((e) => e.eventId !== a.eventId);
      }),
      commitCursor: (a) => write('commitCursor', a, () => {
        disk.cursors = disk.cursors.filter((c) => c.relay !== a.relay);
        disk.cursors.push({ relay: a.relay, syncedUntil: a.syncedUntil });
      }),
      resolve: (a) => gate('resolve', () => {
        const result = disk.resolutions.get(a.operationId);
        return result !== undefined
          ? { status: 'committed', revision: disk.revision, storedBytes: bytes(), result }
          : { status: 'aborted', revision: disk.revision };
      }),
    };
    self.crash = () => { self.dead = true; };
    return self;
  }
  return { disk, view };
}

/** A cleartext session port over a fake MLS provider generation, with candidate semantics. */
function cleartextSession(disk, view, known, invitations = null) {
  const trace = { opens: [], candidates: [], seals: 0, outcomes: [], mutations: [] };
  const session = {
    seal: ({ plaintext }) => {
      trace.seals += 1;
      trace.mutations.push('seal');
      if (disk !== null) disk.provider += 1;
      return { ciphertext: new Uint8Array(plaintext) };
    },
    open: ({ ciphertext }) => ({ plaintext: new Uint8Array(ciphertext) }),
    openCandidate: ({ sender, ciphertext }) => {
      if (view !== null && view.dead) return NEVER;
      trace.opens.push(bytesToHex(ciphertext));
      if (view !== null && view.crashAt?.method === 'openCandidate') { view.dead = true; return NEVER; }
      const plan = trace.outcomes.length > 0 ? trace.outcomes.shift() : 'application';
      if (plan === 'retry') return { receiveOutcome: 'retry', ticket: null };
      const generation = (disk?.mlsCommitted ?? 0) + 1;
      trace.candidates.push(generation);
      return { receiveOutcome: 'application', plaintext: new Uint8Array(ciphertext), ticket: { sender, generation } };
    },
    isKnownSender: ({ sender }) => known.has(sender),
  };
  if (invitations !== null) {
    session.createKeyPackage = () => utf8Encode(invitations.pub);
    session.startSession = ({ peer, keyPackage }) => {
      if (known.has(peer) || utf8Decode(keyPackage) !== peer) throw Error('credential/existing');
      known.add(peer);
      trace.mutations.push('startSession');
      return { welcome: utf8Encode(invitations.pub + ':' + peer), ratchetTree: new Uint8Array([1]) };
    };
    session.joinSession = async ({ peer, welcome }) => {
      if (known.has(peer) || utf8Decode(welcome) !== peer + ':' + invitations.pub) throw Error('welcome/existing');
      if (invitations.joinGate) await invitations.joinGate;
      known.add(peer);
      trace.mutations.push('joinSession');
      return true;
    };
  }
  return { session, trace };
}

function identity() {
  const secret = schnorr.utils.randomPrivateKey();
  return { secret, pub: bytesToHex(schnorr.getPublicKey(secret)) };
}

/* Test gift wrapping signs layers but DOES NOT ENCRYPT (as invite.test.js). */
const eventHash = (event) => bytesToHex(sha256(utf8Encode(JSON.stringify([
  0, event.pubkey, event.created_at, event.kind, event.tags, event.content,
]))));
function signedEvent(event, secret) {
  const id = eventHash(event);
  return { ...event, id, sig: bytesToHex(schnorr.sign(hexToBytes(id), secret)) };
}
function wrapping(key) {
  return {
    giftWrap: ({ rumor, recipient }) => {
      const seal = signedEvent({ pubkey: key.pub, created_at: rumor.created_at, kind: 13, tags: [],
        content: JSON.stringify(rumor) }, key.secret);
      const fresh = schnorr.utils.randomPrivateKey();
      return signedEvent({ pubkey: bytesToHex(schnorr.getPublicKey(fresh)), created_at: rumor.created_at,
        kind: 1059, tags: [['p', recipient]], content: JSON.stringify(seal) }, fresh);
    },
    unwrapGift: ({ event }) => {
      const seal = JSON.parse(event.content);
      if (seal.kind !== 13 || seal.id !== eventHash(seal)
          || !schnorr.verify(hexToBytes(seal.sig), hexToBytes(seal.id), hexToBytes(seal.pubkey))) throw Error('seal');
      return { rumor: JSON.parse(seal.content), sealSigner: seal.pubkey };
    },
  };
}

function makeClient(urls, { key = identity(), disk = null, known = new Set(), clock = fastClock(), receiptMode = 'RECIPIENT_RECEIPT', receive, invitations = false, joinGate = null } = {}) {
  const view = disk === null ? null : disk.view();
  const { session, trace } = cleartextSession(disk?.disk ?? null, view, known,
    invitations ? { pub: key.pub, joinGate } : null);
  const records = new Map();
  const ports = {
    storage: {
      list: () => [...records.values()], get: (k) => records.get(k) ?? null,
      put: (record) => { records.set(record.deliveryId, record); return true; },
      update: (k, value) => { records.set(k, value); return true; }, remove: (k) => records.delete(k),
    },
    session,
    identity: { getPublicKey: () => key.pub, sign: ({ digest }) => schnorr.sign(digest, key.secret),
      ...(invitations ? wrapping(key) : {}) },
  };
  if (view !== null) ports.receiveState = view.port;
  const config = { interfaceVersion: SDK_INTERFACE_VERSION, relays: urls, ports, clock, delivery: { receiptMode } };
  if (receive !== undefined) config.receive = receive;
  const made = createStyxClient(config);
  expect(made.ok).toBe(true);
  const client = made.value;
  const events = [];
  cleanups.push(() => client.shutdown());
  return { client, key, pub: key.pub, events, trace, view, config,
    messages: () => events.filter((e) => e.kind === 'MESSAGE_RECEIVED') };
}

async function started(h, listen = true) {
  if (listen) await h.client.onEvent((event) => h.events.push(event));
  const result = await h.client.start();
  expect(result.ok).toBe(true);
  return h;
}

const fail = (code) => ({ ok: false, code });

describe('M3-RECEIVE-1 configuration and surface', () => {
  test('interface 0.4.0 only; receiveState all seven methods or none, with the two session methods; receive only with the port', async () => {
    const r = await relay();
    const disk = durableDisk('a'.repeat(64));
    const h = makeClient([r.url], { disk });
    expect(SDK_INTERFACE_VERSION).toBe('styx-m3-sdk/0.4.0-experimental');
    expect(SDK_WIRE_VERSION).toBe('styx-m3-sdk/0.3.0-experimental');
    expect(createStyxClient({ ...h.config, interfaceVersion: 'styx-m3-sdk/0.3.1-experimental' })).toEqual(fail('E_SDK_UNSUPPORTED_VERSION'));
    for (const method of ['load', 'stage', 'commit', 'ack', 'receiptDone', 'commitCursor', 'resolve']) {
      const receiveState = { ...h.config.ports.receiveState };
      delete receiveState[method];
      expect(createStyxClient({ ...h.config, ports: { ...h.config.ports, receiveState } })).toEqual(fail('E_SDK_INVALID_CONFIG'));
    }
    for (const method of ['openCandidate', 'isKnownSender']) {
      const session = { ...h.config.ports.session };
      delete session[method];
      expect(createStyxClient({ ...h.config, ports: { ...h.config.ports, session } })).toEqual(fail('E_SDK_INVALID_CONFIG'));
    }
    const { receiveState, ...without } = h.config.ports;
    expect(receiveState).toBeDefined();
    expect(createStyxClient({ ...h.config, ports: without, receive: { maxPending: 1 } })).toEqual(fail('E_SDK_INVALID_CONFIG'));
    for (const receive of [{ maxPending: 0 }, { maxPending: 65537 }, { maxSeen: 16777217 }, { maxStoredBytes: 4294967297 },
      { maxUnacknowledged: 2.5 }, { other: 1 }, null]) {
      expect(createStyxClient({ ...h.config, receive })).toEqual(fail('E_SDK_INVALID_CONFIG'));
    }
    expect(createStyxClient({ ...h.config, receive: { maxPending: 65536, maxUnacknowledged: 1, maxSeen: 16777216,
      maxStoredBytes: 4294967296 } }).ok).toBe(true);
    expect(createStyxClient({ ...h.config, ports: { ...h.config.ports, receiveState: null } })).toEqual(fail('E_SDK_INVALID_CONFIG'));
  });

  test('without the port: MESSAGE_RECEIVED carries the event id; acknowledgeMessage is NOT_STARTED, NOT_CONFIGURED, CLIENT_STOPPED', async () => {
    const r = await relay();
    const a = makeClient([r.url]);
    const b = makeClient([r.url]);
    expect(await a.client.acknowledgeMessage({ eventId: 'f'.repeat(64) })).toEqual(fail('E_SDK_NOT_STARTED'));
    await started(a);
    await started(b);
    expect((await b.client.send({ recipient: a.pub, payload: new Uint8Array([1, 2]) })).ok).toBe(true);
    expect(await until(() => a.messages().length === 1)).toBe(true);
    const [message] = a.messages();
    const stored = [...r.events.values()].find((e) => e.kind === 4741);
    expect(message).toEqual({ kind: 'MESSAGE_RECEIVED', sender: b.pub, payload: new Uint8Array([1, 2]), eventId: stored.id });
    expect(await a.client.acknowledgeMessage({ eventId: stored.id })).toEqual(fail('E_SDK_NOT_CONFIGURED'));
    expect(await a.client.acknowledgeMessage({ eventId: 'X' })).toEqual(fail('E_SDK_NOT_CONFIGURED'));
    await a.client.shutdown();
    expect(await a.client.acknowledgeMessage({ eventId: stored.id })).toEqual(fail('E_SDK_CLIENT_STOPPED'));
  });
});

describe('M3-RECEIVE-1 end-to-end with the port (criteria 1, 2, 10)', () => {
  test('0.4.0 with the port and without it interoperate both ways on wire 0.3.0: messages and receipts', async () => {
    const r = await relay();
    const alice = makeClient([r.url]);
    const bobKey = identity();
    const disk = durableDisk(bobKey.pub);
    const bob = makeClient([r.url], { key: bobKey, disk, known: new Set([alice.pub]) });
    await started(alice);
    await started(bob);
    const sent = await alice.client.send({ recipient: bob.pub, payload: utf8Encode('to bob') });
    expect(await until(() => bob.messages().length === 1)).toBe(true);
    const [message] = bob.messages();
    expect(message.sender).toBe(alice.pub);
    expect(message.eventId).toMatch(/^[0-9a-f]{64}$/);
    expect(await until(() => alice.events.some((e) => e.deliveryId === sent.value.deliveryId
      && e.state === 'RECIPIENT_RECEIPT_RECEIVED'))).toBe(true);
    expect(await until(() => disk.disk.receiptsDue.length === 0)).toBe(true);
    expect(await bob.client.acknowledgeMessage({ eventId: 'z' })).toEqual(fail('E_SDK_INVALID_ARGUMENT'));
    expect(await bob.client.acknowledgeMessage({ eventId: message.eventId, more: 1 })).toEqual(fail('E_SDK_INVALID_ARGUMENT'));
    expect(await bob.client.acknowledgeMessage({ eventId: 'f'.repeat(64) })).toEqual(fail('E_SDK_UNKNOWN_MESSAGE'));
    expect(await bob.client.acknowledgeMessage({ eventId: message.eventId })).toEqual({ ok: true, value: { eventId: message.eventId } });
    expect(await bob.client.acknowledgeMessage({ eventId: message.eventId })).toEqual({ ok: true, value: { eventId: message.eventId } });
    expect(disk.disk.acknowledged).toEqual([message.eventId]);
    const back = await bob.client.send({ recipient: alice.pub, payload: utf8Encode('to alice') });
    expect(await until(() => alice.messages().length === 1)).toBe(true);
    expect(await until(() => bob.events.some((e) => e.deliveryId === back.value.deliveryId
      && e.state === 'RECIPIENT_RECEIPT_RECEIVED'))).toBe(true);
    const kinds = [...r.events.values()].map((e) => [e.kind, e.tags.map(([t]) => t).join(','), e.tags.find(([t]) => t === 'v')[1]]);
    expect(kinds).toEqual(expect.arrayContaining([[4741, 'p,v,n,r', SDK_WIRE_VERSION], [4742, 'p,e,v,n', SDK_WIRE_VERSION]]));
    expect(bob.trace.opens).toHaveLength(1);
  });

  test('a READY entry is emitted to a listener registered after start and redelivered until acknowledged', async () => {
    const r = await relay();
    const alice = await started(makeClient([r.url]));
    const bobKey = identity();
    const bob = makeClient([r.url], { key: bobKey, disk: durableDisk(bobKey.pub), known: new Set([alice.pub]) });
    await started(bob, false);
    await alice.client.send({ recipient: bob.pub, payload: utf8Encode('later') });
    expect(await until(() => bob.trace.candidates.length === 1)).toBe(true);
    await sleep(100);
    expect([...r.events.values()].filter((e) => e.kind === 4742)).toHaveLength(0);
    let throwing = true;
    await bob.client.onEvent((event) => { bob.events.push(event); if (throwing) throw new Error('listener'); });
    expect(await until(() => bob.messages().length === 1)).toBe(true);
    expect(await until(() => [...r.events.values()].some((e) => e.kind === 4742))).toBe(true);
    // The redelivery pass (60 000 ms of the accelerated clock) delivers it again.
    expect(await until(() => bob.messages().length === 2, 6000)).toBe(true);
    throwing = false;
    expect((await bob.client.acknowledgeMessage({ eventId: bob.messages()[0].eventId })).ok).toBe(true);
    const count = bob.messages().length;
    await sleep(2600);
    expect(bob.messages()).toHaveLength(count);
  });
});

describe('M3-RECEIVE-1 H17 with the port and no restart (criterion 13)', () => {
  test('(a) a retry, then the copy from a second relay: retried, delivered exactly once, one stage', async () => {
    const r1 = await relay();
    const r2 = await relay({ delayMs: 150 });
    const alice = await started(makeClient([r1.url, r2.url]));
    const bobKey = identity();
    const disk = durableDisk(bobKey.pub);
    const bob = makeClient([r1.url, r2.url], { key: bobKey, disk, known: new Set([alice.pub]),
      clock: fastClock(1) });
    bob.trace.outcomes.push('retry');
    await started(bob);
    await alice.client.send({ recipient: bob.pub, payload: utf8Encode('h17') });
    expect(await until(() => bob.messages().length === 1, 4000)).toBe(true);
    expect(bob.trace.opens).toHaveLength(2);
    expect(bob.view.calls.filter((m) => m === 'stage')).toHaveLength(1);
    await sleep(300);
    expect(bob.messages()).toHaveLength(1);
  }, 40000);

  test('(b) without any copy: the periodic pass retries it within one catch-up interval', async () => {
    const r = await relay();
    const alice = await started(makeClient([r.url]));
    const bobKey = identity();
    const bob = makeClient([r.url], { key: bobKey, disk: durableDisk(bobKey.pub), known: new Set([alice.pub]) });
    bob.trace.outcomes.push('retry');
    await started(bob);
    await alice.client.send({ recipient: bob.pub, payload: utf8Encode('periodic') });
    expect(await until(() => bob.trace.opens.length === 1)).toBe(true);
    // 10 000 ms on the accelerated clock (factor 50) is 200 ms of host time.
    expect(await until(() => bob.messages().length === 1, 3000)).toBe(true);
    expect(bob.trace.opens).toHaveLength(2);
  });
});

describe('M3-RECEIVE-1 restart: cursor, recovery and admission (criteria 4, 6, 10)', () => {
  test('restart replays from the committed cursor; committed ids never reach openCandidate again', async () => {
    const r = await relay();
    const alice = await started(makeClient([r.url]));
    const bobKey = identity();
    const disk = durableDisk(bobKey.pub);
    const first = await started(makeClient([r.url], { key: bobKey, disk, known: new Set([alice.pub]) }));
    for (let i = 1; i <= 3; i += 1) await alice.client.send({ recipient: bobKey.pub, payload: utf8Encode(`m${i}`) });
    expect(await until(() => first.messages().length === 3)).toBe(true);
    for (const message of first.messages()) expect((await first.client.acknowledgeMessage({ eventId: message.eventId })).ok).toBe(true);
    expect(await until(() => disk.disk.cursors.length === 1)).toBe(true);
    await first.client.shutdown();
    const committed = disk.disk.cursors[0].syncedUntil;
    await alice.client.send({ recipient: bobKey.pub, payload: utf8Encode('m4') });
    const before = r.requests.length;
    const second = await started(makeClient([r.url], { key: bobKey, disk, known: new Set([alice.pub]) }));
    expect(await until(() => second.messages().length === 1)).toBe(true);
    expect(second.messages()[0].payload).toEqual(utf8Encode('m4'));
    const firstRequest = r.requests.slice(before).find((q) => q.key === bobKey.pub);
    expect(firstRequest.filter.since).toBe(committed - 120);
    expect(second.trace.opens).toHaveLength(1);
    await sleep(300);
    expect(second.messages()).toHaveLength(1);
  });

  test('an id excluded as unknown is admitted on a later replay once its session is known', async () => {
    const r = await relay();
    const alice = await started(makeClient([r.url]));
    const bobKey = identity();
    const disk = durableDisk(bobKey.pub);
    const known = new Set();
    const first = await started(makeClient([r.url], { key: bobKey, disk, known }));
    await alice.client.send({ recipient: bobKey.pub, payload: utf8Encode('early') });
    expect(await until(() => [...r.events.values()].some((e) => e.kind === 4741))).toBe(true);
    await sleep(200);
    expect(first.trace.opens).toHaveLength(0);
    expect(disk.disk.seen).toHaveLength(0);
    known.add(alice.pub);
    // The next periodic re-request replays it (no cursor passed it: not admitted is accounted).
    await first.client.shutdown();
    const second = await started(makeClient([r.url], { key: bobKey, disk, known }));
    expect(await until(() => second.messages().length === 1)).toBe(true);
  });
});

/** The joint oracle of criterion 3 after a restart. */
function oracle(disk, stagedIds) {
  const seen = new Set(disk.disk.seen);
  for (const id of stagedIds) expect(seen.has(id)).toBe(true);
  const pending = disk.disk.pending.map((e) => e.eventId);
  const ready = disk.disk.ready.map((e) => e.eventId);
  const all = [...pending, ...ready, ...disk.disk.acknowledged];
  expect(new Set(all).size).toBe(all.length);
  for (const id of all) expect(seen.has(id)).toBe(true);
  for (const r of disk.disk.receiptsDue) expect([...ready, ...disk.disk.acknowledged]).toContain(r.eventId);
}

describe('M3-RECEIVE-1 crash matrix with two client instances (criterion 3, fake ports)', () => {
  test.each([
    ['before stage', { method: 'stage', when: 'before' }],
    ['lost result of stage', { method: 'stage', when: 'after' }],
    ['during openCandidate', { method: 'openCandidate', when: 'before' }],
    ['during commit, not written (resolve aborted)', { method: 'commit', when: 'before' }],
    ['during commit, written (resolve committed)', { method: 'commit', when: 'after' }],
    ['after the application effect, before ack', { method: 'ack', when: 'before' }],
    ['lost result of ack', { method: 'ack', when: 'after' }],
    ['after receipt publication, before receiptDone', { method: 'receiptDone', when: 'before' }],
    ['lost result of receiptDone', { method: 'receiptDone', when: 'after' }],
    ['lost result of commitCursor', { method: 'commitCursor', when: 'after' }],
  ])('%s: no staged event lost, no committed id opened again, delivered after restart', async (_name, point) => {
    const r = await relay();
    const alice = await started(makeClient([r.url]));
    const bobKey = identity();
    const disk = durableDisk(bobKey.pub);
    const first = makeClient([r.url], { key: bobKey, disk, known: new Set([alice.pub]) });
    await first.client.onEvent((event) => {
      first.events.push(event);
      if (event.kind === 'MESSAGE_RECEIVED') first.client.acknowledgeMessage({ eventId: event.eventId });
    });
    expect((await first.client.start()).ok).toBe(true);
    first.view.crashAt = point;
    await alice.client.send({ recipient: bobKey.pub, payload: utf8Encode('crash') });
    expect(await until(() => first.view.dead, 6000)).toBe(true);
    const stagedBefore = [...disk.disk.seen];
    const committedBefore = [...disk.disk.ready.map((e) => e.eventId), ...disk.disk.acknowledged];
    // A new instance on the same durable store; the dead one stays silent.
    const second = await started(makeClient([r.url], { key: bobKey, disk, known: new Set([alice.pub]) }));
    expect(await until(() => disk.disk.ready.length + disk.disk.acknowledged.length === 1)).toBe(true);
    oracle(disk, stagedBefore);
    const delivered = [...first.messages(), ...second.messages()].map((e) => e.eventId);
    expect(new Set(delivered).size).toBe(1);
    const opened = second.trace.opens.length;
    if (committedBefore.length > 0) expect(opened).toBe(0);
    if (!disk.disk.acknowledged.includes(delivered[0])) {
      expect(await until(() => second.messages().length >= 1)).toBe(true);
      expect((await second.client.acknowledgeMessage({ eventId: delivered[0] })).ok).toBe(true);
    }
    expect(await until(() => disk.disk.receiptsDue.length === 0)).toBe(true);
    expect(disk.disk.mlsCommitted).toBe(1);
    await sleep(200);
    expect(second.trace.opens.length).toBe(opened);
  }, 30000);

  test('torn or incompatible snapshot: start fails before any network activity, nothing is reset', async () => {
    const r = await relay();
    const bobKey = identity();
    const disk = durableDisk(bobKey.pub);
    disk.disk.torn = true;
    const bob = makeClient([r.url], { key: bobKey, disk });
    expect(await bob.client.start()).toEqual(fail('E_SDK_RECEIVE_STATE_INCOMPATIBLE'));
    expect(r.requests).toEqual([]);
    const other = makeClient([r.url], { disk: durableDisk(bobKey.pub) });
    expect(await other.client.start()).toEqual(fail('E_SDK_RECEIVE_STATE_INCOMPATIBLE'));
    expect(r.requests).toEqual([]);
  });

  test('shutdown during openCandidate, then a new instance: the entry stays PENDING and is delivered once', async () => {
    const r = await relay();
    const alice = await started(makeClient([r.url]));
    const bobKey = identity();
    const disk = durableDisk(bobKey.pub);
    const first = makeClient([r.url], { key: bobKey, disk, known: new Set([alice.pub]) });
    let release;
    const original = first.config.ports.session.openCandidate;
    first.config.ports.session.openCandidate = async (argument) => {
      await new Promise((resolve) => { release = resolve; });
      return original(argument);
    };
    await started(first);
    await alice.client.send({ recipient: bobKey.pub, payload: utf8Encode('held') });
    expect(await until(() => release !== undefined)).toBe(true);
    const stopping = first.client.shutdown();
    release();
    expect((await stopping).ok).toBe(true);
    expect(disk.disk.pending).toHaveLength(1);
    expect(disk.disk.ready).toHaveLength(0);
    const second = await started(makeClient([r.url], { key: bobKey, disk, known: new Set([alice.pub]) }));
    expect(await until(() => second.messages().length === 1)).toBe(true);
  });
});

describe('M3-RECEIVE-1 fail-stop gates provider mutations (criterion 9)', () => {
  test('a frozen receive state: send and invitation methods fail E_SDK_RECEIVE_STATE_FAILED before any port call', async () => {
    const r = await relay();
    const alice = await started(makeClient([r.url]));
    const bobKey = identity();
    const disk = durableDisk(bobKey.pub);
    const bob = makeClient([r.url], { key: bobKey, disk, known: new Set([alice.pub]) });
    const conflicting = bob.config.ports.receiveState.stage;
    bob.config.ports.receiveState.stage = (argument) => conflicting({ ...argument, revision: -1 });
    await started(bob);
    await alice.client.send({ recipient: bobKey.pub, payload: utf8Encode('x') });
    expect(await until(() => bob.events.some((e) => e.kind === 'RECEIVE_STATE_FAILED'))).toBe(true);
    expect(bob.events.find((e) => e.kind === 'RECEIVE_STATE_FAILED')).toEqual({ kind: 'RECEIVE_STATE_FAILED',
      code: 'E_SDK_RECEIVE_STATE_CONFLICT' });
    const seals = bob.trace.seals;
    expect(await bob.client.send({ recipient: alice.pub, payload: new Uint8Array([1]) })).toEqual(fail('E_SDK_RECEIVE_STATE_FAILED'));
    expect(bob.trace.seals).toBe(seals);
    expect(await bob.client.publishKeyPackage()).toEqual(fail('E_SDK_NOT_CONFIGURED'));
    expect(disk.disk.seen).toEqual([]);
    expect(bob.trace.opens).toEqual([]);
    expect(bob.messages()).toEqual([]);
  });
});

async function invited(inviter, invitee) {
  const kp = await invitee.client.publishKeyPackage();
  expect(kp.ok).toBe(true);
  const accepting = invitee.client.acceptInvite({ inviter: inviter.pub, keyPackageEventId: kp.value.keyPackageEventId });
  const invitation = await inviter.client.invite({ invitee: invitee.pub });
  expect(invitation.ok).toBe(true);
  expect(await accepting).toEqual({ ok: true, value: { inviter: inviter.pub } });
}

describe('M3-RECEIVE-1 interoperability with invitations (criteria 2 and 6)', () => {
  test.each([['the client with the port invites', true], ['the client without the port invites', false]])(
    '%s: KeyPackage, Welcome, messages and receipts both ways on wire 0.3.0', async (_name, portInvites) => {
      const r = await relay();
      const bobKey = identity();
      const disk = durableDisk(bobKey.pub);
      const bob = await started(makeClient([r.url], { key: bobKey, disk, invitations: true }));
      const alice = await started(makeClient([r.url], { invitations: true }));
      if (portInvites) await invited(bob, alice); else await invited(alice, bob);
      expect([...r.events.values()].map((e) => e.kind)).toEqual(expect.arrayContaining([4743, 1059]));
      const toBob = await alice.client.send({ recipient: bob.pub, payload: utf8Encode('hello bob') });
      expect(await until(() => bob.messages().length === 1)).toBe(true);
      expect(bob.messages()[0].payload).toEqual(utf8Encode('hello bob'));
      expect(await until(() => alice.events.some((e) => e.deliveryId === toBob.value.deliveryId
        && e.state === 'RECIPIENT_RECEIPT_RECEIVED'))).toBe(true);
      const toAlice = await bob.client.send({ recipient: alice.pub, payload: utf8Encode('hello alice') });
      expect(await until(() => alice.messages().length === 1)).toBe(true);
      expect(await until(() => bob.events.some((e) => e.deliveryId === toAlice.value.deliveryId
        && e.state === 'RECIPIENT_RECEIPT_RECEIVED'))).toBe(true);
      expect(disk.disk.ready.map((e) => e.eventId)).toEqual([bob.messages()[0].eventId]);
      for (const event of r.events.values()) {
        if (event.kind === 4741 || event.kind === 4742) expect(event.tags.find(([t]) => t === 'v')[1]).toBe(SDK_WIRE_VERSION);
      }
    });

  test('a message of the new peer arriving before the join completes is admitted by the post-operation generation', async () => {
    const r = await relay();
    const bobKey = identity();
    const disk = durableDisk(bobKey.pub);
    let open;
    const joinGate = new Promise((resolve) => { open = resolve; });
    const bob = await started(makeClient([r.url], { key: bobKey, disk, invitations: true, joinGate }));
    const alice = await started(makeClient([r.url], { invitations: true }));
    expect(await until(() => disk.disk.cursors.length === 1)).toBe(true);
    const kp = await bob.client.publishKeyPackage();
    const preOperation = JSON.stringify(disk.disk.cursors);
    const commitsBefore = bob.view.calls.filter((m) => m === 'commitCursor').length;
    const accepting = bob.client.acceptInvite({ inviter: alice.pub, keyPackageEventId: kp.value.keyPackageEventId });
    expect((await alice.client.invite({ invitee: bob.pub })).ok).toBe(true);
    await alice.client.send({ recipient: bob.pub, payload: utf8Encode('early') });
    expect(await until(() => [...r.events.values()].some((e) => e.kind === 4741))).toBe(true);
    await sleep(150);
    expect(bob.trace.opens).toEqual([]);
    expect(disk.disk.seen).toEqual([]);
    // While the invitation is active no delivery cursor is committed: the pre-operation cursor stays.
    await sleep(600);
    expect(JSON.stringify(disk.disk.cursors)).toBe(preOperation);
    expect(bob.view.calls.filter((m) => m === 'commitCursor')).toHaveLength(commitsBefore);
    open();
    expect((await accepting).ok).toBe(true);
    // The periodic re-request after the operation ended replays it from the pre-operation cursor.
    expect(await until(() => bob.messages().length === 1, 6000)).toBe(true);
    expect(bob.messages()[0].payload).toEqual(utf8Encode('early'));
  });
});

describe('M3-RECEIVE-1 provider mutations during a candidate (criteria 3 and 12, SDK side with a fake coordinator)', () => {
  test('a seal completed while a candidate is open survives an aborted commit; the entry is delivered once later', async () => {
    const r = await relay();
    const alice = await started(makeClient([r.url]));
    const bobKey = identity();
    const disk = durableDisk(bobKey.pub);
    const bob = makeClient([r.url], { key: bobKey, disk, known: new Set([alice.pub]) });
    let release;
    const original = bob.config.ports.session.openCandidate;
    bob.config.ports.session.openCandidate = async (argument) => {
      await new Promise((resolve) => { release = resolve; });
      return original(argument);
    };
    const commit = bob.config.ports.receiveState.commit;
    let failOnce = true;
    bob.config.ports.receiveState.commit = (argument) => {
      if (failOnce) { failOnce = false; throw new Error('uncertain, not written'); }
      return commit(argument);
    };
    await started(bob);
    await alice.client.send({ recipient: bobKey.pub, payload: utf8Encode('during') });
    expect(await until(() => release !== undefined)).toBe(true);
    const sent = await bob.client.send({ recipient: alice.pub, payload: utf8Encode('sealed meanwhile') });
    expect(sent.ok).toBe(true);
    expect(disk.disk.provider).toBe(1);
    release();
    expect(await until(() => bob.events.some((e) => e.kind === 'RECEIVE_STATE_FAILED'))).toBe(true);
    expect(await until(() => alice.messages().length === 1)).toBe(true);
    // resolve answered aborted: the entry stays PENDING, the seal mutation is not rolled back.
    expect(disk.disk.pending).toHaveLength(1);
    expect(disk.disk.provider).toBe(1);
    bob.config.ports.session.openCandidate = original;
    expect(await until(() => bob.messages().length === 1, 6000)).toBe(true);
    expect(disk.disk.ready.length + disk.disk.acknowledged.length).toBe(1);
    expect(disk.disk.mlsCommitted).toBe(1);
  });
});

describe('M3-RECEIVE-1 cursors across restart with a reordered relay list (criterion 5)', () => {
  test('cursors are keyed by the exact relay string; an event older than the overlap served again is dropped as seen', async () => {
    const r1 = await relay();
    const r2 = await relay();
    const alice = await started(makeClient([r1.url, r2.url]));
    const bobKey = identity();
    const disk = durableDisk(bobKey.pub);
    const first = await started(makeClient([r1.url, r2.url], { key: bobKey, disk, known: new Set([alice.pub]) }));
    await alice.client.send({ recipient: bobKey.pub, payload: utf8Encode('old') });
    expect(await until(() => first.messages().length === 1)).toBe(true);
    expect((await first.client.acknowledgeMessage({ eventId: first.messages()[0].eventId })).ok).toBe(true);
    expect(await until(() => disk.disk.cursors.length === 2)).toBe(true);
    await first.client.shutdown();
    const cursors = Object.fromEntries(disk.disk.cursors.map((c) => [c.relay, c.syncedUntil]));
    const before = [r1.requests.length, r2.requests.length];
    const second = await started(makeClient([r2.url, r1.url], { key: bobKey, disk, known: new Set([alice.pub]) }));
    expect(await until(() => r1.requests.length > before[0] && r2.requests.length > before[1])).toBe(true);
    expect(r1.requests[before[0]].filter.since).toBe(cursors[r1.url] - 120);
    expect(r2.requests[before[1]].filter.since).toBe(cursors[r2.url] - 120);
    // The loopback relays serve the stored event again (its created_at is inside the overlap): seen, not opened.
    await sleep(300);
    expect(second.trace.opens).toEqual([]);
    expect(second.messages()).toEqual([]);
  });
});
