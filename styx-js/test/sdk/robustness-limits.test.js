// Loopback-only tests of the declared limits and the KeyPackage expiration rule of
// M3-ROBUSTNESS-LOW. Test wrapping signs layers but DOES NOT ENCRYPT.
import { describe, test, expect, beforeAll, afterAll, afterEach } from '@jest/globals';
import { WebSocket, WebSocketServer } from 'ws';
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, utf8Encode, utf8Decode, bytesToBase64 } from '../../src/utils.js';
import { createStyxClient, SDK_INTERFACE_VERSION, SDK_WIRE_VERSION } from '../../src/sdk/index.js';

const V = SDK_WIRE_VERSION;
const SPEED = 20;
const PER_RELAY_TIMEOUT_MS = 11000;
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
// Every session port call is logged by name; the bytes are cleartext test values.
function testSession(pk, calls) {
  const peers = new Set();
  return { seal: ({ plaintext }) => ({ ciphertext: plaintext }),
    open: ({ ciphertext }) => { calls.push('open'); return { plaintext: ciphertext }; },
    createKeyPackage: () => { calls.push('createKeyPackage'); return utf8Encode(pk); },
    startSession: ({ peer, keyPackage }) => {
      calls.push('startSession');
      if (peers.has(peer) || utf8Decode(keyPackage) !== peer) throw Error('credential/existing');
      peers.add(peer);
      return { welcome: utf8Encode(pk + ':' + peer), ratchetTree: new Uint8Array([1]) };
    },
    joinSession: ({ peer, welcome }) => {
      calls.push('joinSession');
      if (peers.has(peer) || utf8Decode(welcome) !== peer + ':' + pk) throw Error('welcome/existing');
      peers.add(peer); return true;
    },
  };
}
// A caller clock SPEED times faster than host time; `shifts.get(port).by` moves only its readings.
const shifts = new WeakMap();
function clock(speed = SPEED) {
  const origin = Date.now(); const shift = { by: 0 };
  const port = { now: () => origin + (Date.now() - origin) * speed + shift.by,
    setTimer: (f, ms) => setTimeout(f, ms / speed), clearTimer: clearTimeout };
  shifts.set(port, shift);
  return port;
}
const shiftTo = (time, reading) => { shifts.get(time).by += reading - time.now(); };
// A loopback relay; `onReq(socket, subscriptionId, filter)` returning false skips replay and EOSE.
async function relay() {
  const server = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await new Promise((resolve) => server.once('listening', resolve));
  const events = [], subscriptions = new Map();
  const matches = (filter, event) => (!filter.kinds || filter.kinds.includes(event.kind))
    && (!filter.authors || filter.authors.includes(event.pubkey))
    && (!filter['#p'] || event.tags.some((t) => t[0] === 'p' && filter['#p'].includes(t[1])));
  const emit = (event) => {
    for (const [s, subs] of subscriptions) for (const [id, filter] of subs)
      if (s.readyState === WebSocket.OPEN && matches(filter, event)) s.send(JSON.stringify(['EVENT', id, event]));
  };
  const state = { events, server, onReq: null, emit };
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
        emit(f[1]);
      }
      if (f[0] === 'CLOSE') subscriptions.get(socket).delete(f[1]);
    });
  });
  cleanup.push(async () => { for (const socket of server.clients) socket.terminate(); await new Promise((resolve) => server.close(resolve)); });
  state.url = 'ws' + '://' + '127.0.0.1:' + server.address().port;
  return state;
}
function memoryStorage(records = new Map()) {
  return { list: () => [...records.values()], get: (key) => records.get(key),
    put: (record) => { records.set(record.deliveryId, record); return true; },
    update: (key, value) => { records.set(key, value); return true; }, remove: (key) => records.delete(key) };
}
async function started(relays, { id = identity(), time = clock(), storage = memoryStorage(), start = true } = {}) {
  const calls = [];
  const session = testSession(id.pk, calls);
  const events = [];
  const config = { interfaceVersion: SDK_INTERFACE_VERSION, relays: relays.map((r) => r.url), clock: time,
    delivery: { perRelayTimeoutMs: PER_RELAY_TIMEOUT_MS, deadlineMs: 30000 },
    ports: { identity: id, session, storage } };
  const created = createStyxClient(config);
  expect(created).toMatchObject({ ok: true });
  cleanup.push(() => created.value.shutdown());
  if (start) expect((await created.value.start()).ok).toBe(true);
  return { client: created.value, id, session, calls, config, time, events };
}
function keyPackageEvent(owner, createdAt) {
  return signed({ pubkey: owner.pk, created_at: createdAt, kind: 4743,
    tags: [['v', V], ['expiration', String(createdAt + 3600)]], content: bytesToBase64(utf8Encode(owner.pk)) }, owner.key);
}
const seconds = (time) => Math.floor(time.now() / 1000);

describe('C-DLV section 5.5 -- the KeyPackage fetch waits for every connected relay\'s EOSE or one perRelayTimeoutMs', () => {
  // r1 answers at once with an older KeyPackage; r2 holds the newer one and is the relay under test.
  async function fetchCase(r2Answer) {
    const r1 = await relay(), r2 = await relay();
    const a = await started([r1, r2]); const b = identity();
    const now = seconds(a.time);
    const older = keyPackageEvent(b, now - 120), newer = keyPackageEvent(b, now - 60);
    r1.events.push(older);
    r2.onReq = (socket, sid, filter) => {
      if (!filter.kinds?.includes(4743)) return undefined;
      r2Answer(() => {
        if (socket.readyState !== WebSocket.OPEN) return;
        socket.send(JSON.stringify(['EVENT', sid, newer])); socket.send(JSON.stringify(['EOSE', sid]));
      });
      return false;
    };
    const begun = Date.now();
    const sent = await a.client.invite({ invitee: b.pk });
    return { sent, elapsed: Date.now() - begun, older, newer };
  }

  test('a relay whose newer KeyPackage and EOSE arrive within the wait contributes: the newest valid one is chosen', async () => {
    // 150 ms of host time is 3 000 ms of caller time, well inside the 11 000 ms wait.
    const { sent, newer } = await fetchCase((answer) => setTimeout(answer, 150));
    expect(sent.ok).toBe(true);
    expect(sent.value.keyPackageEventId).toBe(newer.id);
  });

  test('declared limit: a connected relay silent for the whole wait does not contribute; the newest received is chosen after the full wait', async () => {
    const { sent, older, elapsed } = await fetchCase(() => {});
    expect(sent.ok).toBe(true);
    expect(sent.value.keyPackageEventId).toBe(older.id);
    // The fetch waited for the silent relay up to one perRelayTimeoutMs (550 ms of host time here).
    expect(elapsed).toBeGreaterThanOrEqual(PER_RELAY_TIMEOUT_MS / SPEED - 50);
  });

  test('declared limit: an answer that arrives only after the wait does not change the choice', async () => {
    const { sent, older } = await fetchCase((answer) => setTimeout(answer, 1500));
    expect(sent.ok).toBe(true);
    expect(sent.value.keyPackageEventId).toBe(older.id);
  });
});

describe('C-DLV section 6.5 -- a Welcome is joined only while its own KeyPackage is unexpired', () => {
  async function invited() {
    const r = await relay(); const a = await started([r]), b = await started([r]);
    const kp = await b.client.publishKeyPackage(); expect(kp.ok).toBe(true);
    const expiration = Number(r.events.find((e) => e.id === kp.value.keyPackageEventId).tags[1][1]);
    expect((await a.client.invite({ invitee: b.id.pk })).ok).toBe(true);
    return { r, a, b, kp, expiration };
  }

  test('after the KeyPackage expiration the Welcome is ignored: E_SDK_INVITE_TIMEOUT and no joinSession', async () => {
    const { a, b, kp } = await invited();
    shifts.get(b.time).by = 3601 * 1000;
    expect(await b.client.acceptInvite({ inviter: a.id.pk, keyPackageEventId: kp.value.keyPackageEventId }))
      .toEqual({ ok: false, code: 'E_SDK_INVITE_TIMEOUT' });
    expect(b.calls.filter((c) => c === 'joinSession')).toHaveLength(0);
  });

  test('from the expiration reading on, the Welcome is ignored', async () => {
    const { a, b, kp, expiration } = await invited();
    // Shift so that the clock already reads the expiration second when the acceptance starts.
    shiftTo(b.time, expiration * 1000);
    expect(await b.client.acceptInvite({ inviter: a.id.pk, keyPackageEventId: kp.value.keyPackageEventId }))
      .toEqual({ ok: false, code: 'E_SDK_INVITE_TIMEOUT' });
    expect(b.calls.filter((c) => c === 'joinSession')).toHaveLength(0);
  });

  test('a Welcome read before the expiration is joined as before', async () => {
    const { a, b, kp, expiration } = await invited();
    // 60 s of caller time before the expiration is 3 s of host time.
    shiftTo(b.time, (expiration - 60) * 1000);
    expect(await b.client.acceptInvite({ inviter: a.id.pk, keyPackageEventId: kp.value.keyPackageEventId }))
      .toEqual({ ok: true, value: { inviter: a.id.pk } });
    expect(b.calls.filter((c) => c === 'joinSession')).toHaveLength(1);
  });

  test('a Welcome that arrives after the expiration, within the acceptance deadline, is ignored', async () => {
    const { r, a, b, kp, expiration } = await invited();
    const wrap = r.events.find((e) => e.kind === 1059);
    r.onReq = (socket, sid, filter) => {
      if (!filter.kinds?.includes(1059)) return undefined;
      // 600 ms of host time is 12 s of caller time: past the expiration, before the 30 s deadline.
      setTimeout(() => {
        if (socket.readyState !== WebSocket.OPEN) return;
        socket.send(JSON.stringify(['EVENT', sid, wrap])); socket.send(JSON.stringify(['EOSE', sid]));
      }, 600);
      return false;
    };
    shiftTo(b.time, (expiration - 5) * 1000);
    const seen = []; const unwrap = b.id.unwrapGift;
    b.id.unwrapGift = (argument) => { seen.push(argument.event.id); return unwrap(argument); };
    expect(await b.client.acceptInvite({ inviter: a.id.pk, keyPackageEventId: kp.value.keyPackageEventId }))
      .toEqual({ ok: false, code: 'E_SDK_INVITE_TIMEOUT' });
    expect(seen).toEqual([wrap.id]);
    expect(b.calls.filter((c) => c === 'joinSession')).toHaveLength(0);
  });
});

describe('C-DLV section 7.1 -- declared limit: the first passing Welcome ends the acceptance', () => {
  test('an authentic Welcome that joinSession refuses is E_SDK_SESSION_FAILED; a later valid one is not examined', async () => {
    const r = await relay(); const a = await started([r]), b = await started([r]);
    const kp = await b.client.publishKeyPackage();
    expect((await a.client.invite({ invitee: b.id.pk })).ok).toBe(true);
    const genuine = r.events.find((e) => e.kind === 1059);
    const rumor = { pubkey: a.id.pk, created_at: seconds(a.time), kind: 4744,
      tags: [['e', kp.value.keyPackageEventId], ['v', V]],
      content: JSON.stringify({ welcome: bytesToBase64(utf8Encode('for another KeyPackage')), ratchetTree: bytesToBase64(new Uint8Array([1])) }) };
    const first = a.id.giftWrap({ rumor, recipient: b.id.pk });
    r.events.splice(0, r.events.length, first, genuine);
    const seen = []; const unwrap = b.id.unwrapGift;
    b.id.unwrapGift = (argument) => { seen.push(argument.event.id); return unwrap(argument); };
    expect(await b.client.acceptInvite({ inviter: a.id.pk, keyPackageEventId: kp.value.keyPackageEventId }))
      .toEqual({ ok: false, code: 'E_SDK_SESSION_FAILED' });
    expect(seen).toEqual([first.id]);
    expect(b.calls.filter((c) => c === 'joinSession')).toHaveLength(1);
  });
});

describe('interface section 4.2 -- declared limit: a failed startSession is not rolled back', () => {
  test('startSession failing is E_SDK_SESSION_FAILED, with no further session call and no Welcome published', async () => {
    const r = await relay(); const a = await started([r]); const b = identity();
    // The content is not the invitee's credential, so the test session refuses it.
    r.events.push(signed({ pubkey: b.pk, created_at: seconds(a.time), kind: 4743,
      tags: [['v', V], ['expiration', String(seconds(a.time) + 3600)]], content: bytesToBase64(new Uint8Array([1, 2, 3])) }, b.key));
    expect(await a.client.invite({ invitee: b.pk })).toEqual({ ok: false, code: 'E_SDK_SESSION_FAILED' });
    expect(a.calls).toEqual(['startSession']);
    expect(r.events.filter((e) => e.kind === 1059)).toHaveLength(0);
  });
});

describe('C-DLV section 8 -- declared limit: a failed open remains processed', () => {
  test('a copy from a second relay is not opened again after a failed open; a fresh message still is', async () => {
    const r1 = await relay(), r2 = await relay();
    const b = await started([r1, r2]); const sender = identity();
    const open = b.session.open; let opens = 0;
    b.session.open = (argument) => { opens++; if (opens === 1) throw Error('transient'); return open(argument); };
    expect((await b.client.onEvent((event) => b.events.push(event))).ok).toBe(true);
    const message = (text) => signed({ pubkey: sender.pk, created_at: seconds(b.time), kind: 4741,
      tags: [['p', b.id.pk], ['v', V], ['n', bytesToHex(sha256(utf8Encode(text))).slice(0, 32)]],
      content: bytesToBase64(utf8Encode(text)) }, sender.key);
    const first = message('first');
    r1.emit(first);
    await until(() => b.events.length === 1);
    expect(b.events[0]).toMatchObject({ kind: 'INBOUND_DISCARDED', code: 'E_SDK_SESSION_FAILED' });
    r2.emit(first);
    await sleep(200);
    expect(opens).toBe(1);
    expect(b.events).toHaveLength(1);
    r2.emit(message('fresh'));
    await until(() => b.events.length === 2);
    expect(opens).toBe(2);
    expect(b.events[1].kind).toBe('MESSAGE_RECEIVED');
    expect(utf8Decode(b.events[1].payload)).toBe('fresh');
  });
});

describe('C-DLV section 5.2 -- declared limit: start() inspects every listed record in one pass', () => {
  const template = (i, state = 'RELAY_ACCEPTED') => ({ deliveryId: 'd' + (i + 1), recipient: 'a'.repeat(64),
    receiptMode: 'RELAY_ACCEPTANCE_ONLY', state, attempts: 1, createdAt: 0, deadlineAt: 120000, lastCode: null,
    relayOutcomes: [{ relayIndex: 0, outcome: 'ACCEPTED' }], ciphertext: null, event: null });
  async function inspect(records) {
    const r = await relay(); let lists = 0;
    const storage = { ...memoryStorage(), list: () => { lists++; return records; } };
    const c = await started([r], { storage, start: false });
    const result = await c.client.start();
    return { result, lists };
  }
  function counted(n) {
    const reads = new Array(n).fill(0);
    const traps = (i) => Object.fromEntries(['get', 'getOwnPropertyDescriptor', 'ownKeys', 'has', 'getPrototypeOf']
      .map((name) => [name, (...args) => { reads[i]++; return Reflect[name](...args); }]));
    return { reads, records: Array.from({ length: n }, (_, i) => new Proxy(template(i), traps(i))) };
  }

  test('every record costs the same work: 100 and 10 000 records, one list call, E_SDK_STORAGE_NOT_EMPTY', async () => {
    const small = counted(100), large = counted(10000);
    const a = await inspect(small.records), b = await inspect(large.records);
    expect(a).toEqual({ result: { ok: false, code: 'E_SDK_STORAGE_NOT_EMPTY' }, lists: 1 });
    expect(b).toEqual({ result: { ok: false, code: 'E_SDK_STORAGE_NOT_EMPTY' }, lists: 1 });
    const perRecord = small.reads[0];
    expect(perRecord).toBeGreaterThan(0);
    expect(new Set([...small.reads, ...large.reads])).toEqual(new Set([perRecord]));
  }, 60000);

  test('an out-of-set state in the last of 10 000 records is still E_SDK_UNKNOWN_CODE', async () => {
    const records = Array.from({ length: 10000 }, (_, i) => template(i));
    records[9999] = template(9999, 'NOT_A_STATE');
    expect((await inspect(records)).result).toEqual({ ok: false, code: 'E_SDK_UNKNOWN_CODE' });
  }, 60000);
});
