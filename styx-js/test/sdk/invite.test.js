// Loopback-only invitation tests. Test wrapping signs layers but DOES NOT ENCRYPT.
import { describe, test, expect, beforeAll, afterAll, afterEach, jest } from '@jest/globals';
import { WebSocket, WebSocketServer } from 'ws';
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, utf8Encode, utf8Decode, bytesToBase64 } from '../../src/utils.js';
import { createStyxClient, SDK_INTERFACE_VERSION, SDK_WIRE_VERSION, SdkResultCode } from '../../src/sdk/index.js';
import { createRelaySet as originalRelaySet } from '../../src/sdk/delivery/relay-pool.js';

const V = SDK_WIRE_VERSION;
const cleanup = [];
let originalWebSocket;
beforeAll(() => { originalWebSocket = globalThis.WebSocket; globalThis.WebSocket = WebSocket; });
afterAll(() => { globalThis.WebSocket = originalWebSocket; });
afterEach(async () => { while (cleanup.length) await cleanup.pop()(); });
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const fail = (code) => ({ ok: false, code });
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
function clock() {
  const origin = Date.now();
  return { now: () => origin + (Date.now() - origin) * 20,
    setTimer: (f, ms) => setTimeout(f, ms / 20), clearTimer: clearTimeout };
}
async function relay({ accept = true } = {}) {
  const server = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await new Promise((resolve) => server.once('listening', resolve));
  const events = [], subscriptions = new Map();
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
        for (const event of events) if (matches(f[2], event)) socket.send(JSON.stringify(['EVENT', f[1], event]));
        socket.send(JSON.stringify(['EOSE', f[1]]));
      }
      if (f[0] === 'EVENT') {
        socket.send(JSON.stringify(['OK', f[1].id, accept, 'test']));
        if (accept) { events.push(f[1]); broadcast(f[1]); }
      }
      if (f[0] === 'CLOSE') subscriptions.get(socket).delete(f[1]);
    });
  });
  function broadcast(event) {
    for (const [socket, subs] of subscriptions) for (const [id, filter] of subs)
      if (socket.readyState === WebSocket.OPEN && matches(filter, event)) socket.send(JSON.stringify(['EVENT', id, event]));
  }
  cleanup.push(async () => { for (const socket of server.clients) socket.terminate(); await new Promise((resolve) => server.close(resolve)); });
  return { events, broadcast, server, url: 'ws' + '://' + '127.0.0.1:' + server.address().port };
}
function make(relays, { id = identity(), session = null, configured = true, time = clock(), factory = createStyxClient } = {}) {
  const records = new Map();
  const s = session || testSession(id.pk);
  if (!configured) { delete s.createKeyPackage; delete s.startSession; delete s.joinSession; delete id.giftWrap; delete id.unwrapGift; }
  const config = { interfaceVersion: SDK_INTERFACE_VERSION, relays: relays.map((r) => r.url), clock: time,
    delivery: { perRelayTimeoutMs: 11000, deadlineMs: 30000 },
    ports: { identity: id, session: s, storage: {
      list: () => [...records.values()], get: (key) => records.get(key),
      put: (record) => { records.set(record.deliveryId, record); return true; },
      update: (key, value) => { records.set(key, value); return true; }, remove: (key) => records.delete(key),
    } } };
  const created = factory(config);
  expect(created.ok).toBe(true);
  cleanup.push(() => created.value.shutdown());
  return { client: created.value, id, session: s, config };
}
async function started(relays, options) {
  const made = make(relays, options);
  expect((await made.client.start()).ok).toBe(true);
  return made;
}
async function flow(a, b) {
  const kp = await b.client.publishKeyPackage(); expect(kp.ok).toBe(true);
  const accepting = b.client.acceptInvite({ inviter: a.id.pk, keyPackageEventId: kp.value.keyPackageEventId });
  const invitation = await a.client.invite({ invitee: b.id.pk }); expect(invitation.ok).toBe(true);
  expect(await accepting).toEqual({ ok: true, value: { inviter: a.id.pk } });
  return { kp, invitation };
}

describe('M3-INVITE, caller ports over loopback only', () => {
  test('0.2.0 rejected, exactly nine members and 22 codes; partial groups invalid', async () => {
    const r = await relay(); const a = make([r]);
    expect(createStyxClient({ ...a.config, interfaceVersion: 'styx-m3-sdk/0.2.0-experimental' })).toEqual(fail('E_SDK_UNSUPPORTED_VERSION'));
    expect(Reflect.ownKeys(a.client).sort()).toEqual(['start', 'send', 'getDelivery', 'cancel', 'onEvent', 'shutdown', 'publishKeyPackage', 'invite', 'acceptInvite'].sort());
    expect(Reflect.ownKeys(SdkResultCode)).toHaveLength(22);
    for (const name of ['createKeyPackage', 'startSession', 'joinSession']) {
      const session = { ...a.config.ports.session }; delete session[name];
      expect(createStyxClient({ ...a.config, ports: { ...a.config.ports, session } })).toEqual(fail('E_SDK_INVALID_CONFIG'));
    }
  });
  test('CREATED/STOPPED state and unconfigured ports take precedence without calls', async () => {
    const r = await relay(); const a = make([r], { configured: false });
    for (const method of ['publishKeyPackage', 'invite', 'acceptInvite']) expect(await a.client[method]()).toEqual(fail('E_SDK_NOT_STARTED'));
    expect((await a.client.start()).ok).toBe(true);
    for (const method of ['publishKeyPackage', 'invite', 'acceptInvite']) expect(await a.client[method]()).toEqual(fail('E_SDK_NOT_CONFIGURED'));
    await a.client.shutdown();
    for (const method of ['publishKeyPackage', 'invite', 'acceptInvite']) expect(await a.client[method]()).toEqual(fail('E_SDK_CLIENT_STOPPED'));
  });
  test('two clients, two relays, wrap in clear; subsequent messages both ways', async () => {
    const rs = [await relay(), await relay()];
    const [a, b] = await Promise.all([started(rs), started(rs)]);
    const { kp, invitation } = await flow(a, b);
    expect(kp.value.acceptedRelays).toEqual([0, 1]);
    expect(invitation.value.acceptedRelays).toEqual([0, 1]);
    expect(Object.isFrozen(invitation.value.acceptedRelays)).toBe(true);
    const receivedA = [], receivedB = [];
    await a.client.onEvent((event) => receivedA.push(event)); await b.client.onEvent((event) => receivedB.push(event));
    expect((await a.client.send({ recipient: b.id.pk, payload: new Uint8Array([4]) })).ok).toBe(true);
    expect((await b.client.send({ recipient: a.id.pk, payload: new Uint8Array([5]) })).ok).toBe(true);
    for (let i = 0; i < 100 && (!receivedA.some((e) => e.kind === 'MESSAGE_RECEIVED') || !receivedB.some((e) => e.kind === 'MESSAGE_RECEIVED')); i++) await sleep(10);
    expect(receivedA.find((e) => e.kind === 'MESSAGE_RECEIVED')?.payload).toEqual(new Uint8Array([5]));
    expect(receivedB.find((e) => e.kind === 'MESSAGE_RECEIVED')?.payload).toEqual(new Uint8Array([4]));
  });
  test('bad keys, own keys, unpublished ids and extra argument keys', async () => {
    const r = await relay(); const a = await started([r]);
    for (const invitee of [null, '', 'A'.repeat(64), a.id.pk]) expect(await a.client.invite({ invitee })).toEqual(fail('E_SDK_INVALID_ARGUMENT'));
    expect(await a.client.invite({ invitee: 'a'.repeat(64), extra: 1 })).toEqual(fail('E_SDK_INVALID_ARGUMENT'));
    expect(await a.client.acceptInvite({ inviter: 'a'.repeat(64), keyPackageEventId: 'b'.repeat(64) })).toEqual(fail('E_SDK_INVALID_ARGUMENT'));
  });
  test('publish not accepted and no valid KeyPackage', async () => {
    const r = await relay({ accept: false }); const a = await started([r]);
    expect(await a.client.publishKeyPackage()).toEqual(fail('E_SDK_PUBLISH_NOT_ACCEPTED'));
    expect(await a.client.invite({ invitee: 'a'.repeat(64) })).toEqual(fail('E_SDK_KEYPACKAGE_NOT_FOUND'));
  });
  test.each(['throw', 'reject', 'never', 'malformed', 'unknown'])('createKeyPackage Model B %s', async (fault) => {
    const r = await relay(); const id = identity(); const session = testSession(id.pk);
    session.createKeyPackage = () => {
      if (fault === 'throw') throw Error('fault');
      if (fault === 'reject') return Promise.reject(Error('fault'));
      if (fault === 'never') return new Promise(() => {});
      return fault === 'unknown' ? { code: 'OUTSIDE_CLOSED_SET' } : new Uint8Array(65537);
    };
    const a = await started([r], { id, session });
    expect(await a.client.publishKeyPackage()).toEqual(fail(fault === 'unknown' ? 'E_SDK_UNKNOWN_CODE' : 'E_SDK_SESSION_FAILED'));
    expect(r.events).toHaveLength(0);
    expect((await a.client.shutdown()).ok).toBe(true);
  });
  test('start failure and malformed wrap publish no Welcome; join failure ends accept', async () => {
    const r = await relay(); const a = await started([r]); const b = await started([r]);
    const kp = await b.client.publishKeyPackage();
    a.session.startSession = () => { throw Error('session'); };
    expect(await a.client.invite({ invitee: b.id.pk })).toEqual(fail('E_SDK_SESSION_FAILED'));
    a.session.startSession = () => ({ welcome: new Uint8Array([1]), ratchetTree: new Uint8Array([2]) });
    a.id.giftWrap = () => ({ kind: 1059 });
    expect(await a.client.invite({ invitee: b.id.pk })).toEqual(fail('E_SDK_IDENTITY_FAILED'));
    expect(r.events.filter((e) => e.kind === 1059)).toHaveLength(0);
    a.id.giftWrap = identity(a.id.key).giftWrap;
    b.session.joinSession = () => false;
    const pending = b.client.acceptInvite({ inviter: a.id.pk, keyPackageEventId: kp.value.keyPackageEventId });
    expect((await a.client.invite({ invitee: b.id.pk })).ok).toBe(true);
    expect(await pending).toEqual(fail('E_SDK_SESSION_FAILED'));
  });
  test.each(['author', 'id', 'signature', 'tags', 'version', 'expiration', 'size', 'base64', 'kind', 'extra'])
  ('invalid KeyPackage %s ignored; later valid candidate chosen without discard', async (fault) => {
    const r = await relay(); const a = await started([r]); const b = await started([r]);
    const kp = await b.client.publishKeyPackage(); expect(kp.ok).toBe(true);
    const valid = r.events.find((e) => e.id === kp.value.keyPackageEventId);
    let bad = { ...valid, tags: valid.tags.map((t) => [...t]), created_at: valid.created_at + 100 };
    bad.tags[1][1] = String(bad.created_at + 3600);
    if (fault === 'author') bad.pubkey = 'd'.repeat(64);
    if (fault === 'tags') bad.tags.push(['relays', 'not-allowed']);
    if (fault === 'version') bad.tags[0][1] = 'styx-m3-sdk/0.2.0-experimental';
    if (fault === 'expiration') { bad.created_at = 0; bad.tags[1][1] = '3600'; }
    if (fault === 'size') bad.content = bytesToBase64(new Uint8Array(65537));
    if (fault === 'base64') bad.content = 'AB==';
    if (fault === 'kind') bad.kind = 4744;
    if (fault === 'extra') bad.extra = true;
    bad = signed(bad, b.id.key);
    if (fault === 'id') bad.id = '0'.repeat(64);
    if (fault === 'signature') bad.sig = '0'.repeat(128);
    r.events.unshift(bad);
    let chosen;
    const original = a.session.startSession;
    a.session.startSession = (argument) => { chosen = argument.keyPackage; return original(argument); };
    const seen = []; await a.client.onEvent((e) => seen.push(e));
    const invited = await a.client.invite({ invitee: b.id.pk });
    expect(invited.ok).toBe(true); expect(invited.value.keyPackageEventId).toBe(valid.id);
    expect(utf8Decode(chosen)).toBe(b.id.pk);
    expect(seen.some((e) => e.kind === 'INBOUND_DISCARDED')).toBe(false);
  });
  test('newest KeyPackage, lowest id on tie, exact acceptedRelays with one refusal', async () => {
    const rs = [await relay(), await relay({ accept: false })];
    const a = await started(rs), b = await started(rs);
    const kp = await b.client.publishKeyPackage(); expect(kp.value.acceptedRelays).toEqual([0]);
    const original = rs[0].events.find((e) => e.id === kp.value.keyPackageEventId);
    const created_at = original.created_at + 1;
    const newer = [0, 1].map((n) => signed({ pubkey: b.id.pk, created_at, kind: 4743,
      tags: [['v', V], ['expiration', String(created_at + 3600)]], content: bytesToBase64(utf8Encode(b.id.pk + (n ? ' ' : ''))) }, b.id.key));
    a.session.startSession = () => ({ welcome: new Uint8Array([1]), ratchetTree: new Uint8Array([1]) });
    rs[0].events.push(...newer);
    const expected = newer.map((e) => e.id).sort()[0];
    const sent = await a.client.invite({ invitee: b.id.pk }); expect(sent.ok).toBe(true);
    expect(sent.value.keyPackageEventId).toBe(expected); expect(sent.value.acceptedRelays).toEqual([0]);
  });
  test.each(['wrap-id', 'wrap-signature', 'p', 'wrap-size', 'unwrap-throw', 'unwrap-reject', 'unwrap-malformed',
    'e', 'version', 'tags', 'welcome-size', 'tree-size', 'sealSigner', 'pubkey', 'third-client'])
  ('invalid Welcome %s ignored and a later valid Welcome succeeds', async (fault) => {
    const r = await relay(); const a = await started([r]), b = await started([r]);
    const kp = await b.client.publishKeyPackage();
    const now = Math.floor(b.config.clock.now() / 1000);
    const rumor = { pubkey: a.id.pk, created_at: now, kind: 4744, tags: [['e', kp.value.keyPackageEventId], ['v', V]],
      content: JSON.stringify({ welcome: bytesToBase64(utf8Encode(a.id.pk + ':' + b.id.pk)), ratchetTree: 'AQ==' }) };
    if (fault === 'e') rumor.tags[0][1] = 'f'.repeat(64);
    if (fault === 'version') rumor.tags[1][1] = 'styx-m3-sdk/0.2.0-experimental';
    if (fault === 'tags') rumor.tags.push(['relays', 'forbidden']);
    if (fault === 'pubkey') rumor.pubkey = 'f'.repeat(64);
    if (fault === 'welcome-size' || fault === 'tree-size') {
      const content = JSON.parse(rumor.content); content[fault === 'welcome-size' ? 'welcome' : 'ratchetTree'] = bytesToBase64(new Uint8Array(262145));
      rumor.content = JSON.stringify(content);
    }
    let bad = (fault === 'third-client' ? identity() : a.id).giftWrap({ rumor, recipient: b.id.pk });
    if (fault === 'wrap-id') bad.id = '0'.repeat(64);
    if (fault === 'wrap-signature') bad.sig = '0'.repeat(128);
    if (fault === 'p' || fault === 'wrap-size') {
      const fresh = schnorr.utils.randomPrivateKey();
      bad = signed({ ...bad, pubkey: bytesToHex(schnorr.getPublicKey(fresh)),
        tags: [['p', fault === 'p' ? 'f'.repeat(64) : b.id.pk]],
        content: fault === 'wrap-size' ? 'x'.repeat(1048577) : bad.content }, fresh);
    }
    const unwrap = b.id.unwrapGift;
    b.id.unwrapGift = (argument) => {
      if (argument.event.id === bad.id) {
        if (fault === 'unwrap-throw') throw Error('bad');
        if (fault === 'unwrap-reject') return Promise.reject(Error('bad'));
        if (fault === 'unwrap-malformed') return { rumor: null };
        if (fault === 'sealSigner') return { rumor, sealSigner: 'f'.repeat(64) };
      }
      return unwrap(argument);
    };
    r.events.push(bad);
    const seen = []; await b.client.onEvent((e) => seen.push(e));
    const pending = b.client.acceptInvite({ inviter: a.id.pk, keyPackageEventId: kp.value.keyPackageEventId });
    const sent = await a.client.invite({ invitee: b.id.pk }); expect(sent.ok).toBe(true);
    expect(await pending).toEqual({ ok: true, value: { inviter: a.id.pk } });
    expect(seen.some((e) => e.kind === 'INBOUND_DISCARDED')).toBe(false);
  });
  test.each(['startSession', 'giftWrap', 'joinSession', 'sign'].flatMap((method) =>
    ['throw', 'reject', 'never', 'malformed', 'unknown'].map((fault) => [method, fault])))
  ('Model B %s / %s disposes and bounds shutdown', async (method, fault) => {
    const r = await relay();
      const a = await started([r]), b = await started([r]);
      const kp = await b.client.publishKeyPackage();
      const target = method === 'joinSession' ? b.session : method === 'startSession' ? a.session : a.id;
      const failing = () => {
        if (fault === 'throw') throw Error('fault');
        if (fault === 'reject') return Promise.reject(Error('fault'));
        if (fault === 'never') return new Promise(() => {});
        return fault === 'unknown' ? { code: 'OUT_OF_SET' } : null;
      };
      target[method] = failing;
      const code = fault === 'unknown' ? 'E_SDK_UNKNOWN_CODE' : ['sign', 'giftWrap'].includes(method) ? 'E_SDK_IDENTITY_FAILED' : 'E_SDK_SESSION_FAILED';
      if (method === 'sign') {
        expect(await a.client.publishKeyPackage()).toEqual(fail(code));
      } else if (method === 'joinSession') {
        const pending = b.client.acceptInvite({ inviter: a.id.pk, keyPackageEventId: kp.value.keyPackageEventId });
        expect((await a.client.invite({ invitee: b.id.pk })).ok).toBe(true);
        expect(await pending).toEqual(fail(code));
      } else expect(await a.client.invite({ invitee: b.id.pk })).toEqual(fail(code));
      await a.client.shutdown(); await b.client.shutdown();
  });
  test('accept deadline host backstop works when caller clock timers never fire', async () => {
    const r = await relay(); const a = await started([r]);
    const kp = await a.client.publishKeyPackage();
    const realTimer = setTimeout;
    const fixed = a.config.clock.now();
    a.config.clock.now = () => fixed;
    a.config.clock.setTimer = () => Symbol('never-fires');
    a.config.clock.clearTimer = () => undefined;
    jest.useFakeTimers({ doNotFake: ['nextTick', 'setImmediate', 'queueMicrotask'] });
    try {
      const pending = a.client.acceptInvite({ inviter: 'f'.repeat(64), keyPackageEventId: kp.value.keyPackageEventId });
      await new Promise((resolve) => realTimer(resolve, 50));
      await jest.advanceTimersByTimeAsync(11000);
      await jest.advanceTimersByTimeAsync(20000);
      expect(await pending).toEqual(fail('E_SDK_INVITE_TIMEOUT'));
      const closing = a.client.shutdown();
      await jest.runOnlyPendingTimersAsync(); await closing;
    } finally { jest.useRealTimers(); }
  });
  test('shutdown during invitation connection remains bounded and disposes method sets', async () => {
    const r = await relay(); const a = await started([r]);
    const pending = a.client.invite({ invitee: 'b'.repeat(64) });
    await sleep(20);
    const stop = a.client.shutdown();
    expect(await pending).toEqual(fail('E_SDK_CLIENT_STOPPED'));
    expect((await stop).ok).toBe(true);
  });

  test('all five optional members are all-or-none; new closed codes are malformed session returns', async () => {
    const r = await relay(); const a = make([r]);
    for (const [group, name] of [['identity', 'giftWrap'], ['identity', 'unwrapGift']]) {
      const ports = { ...a.config.ports, [group]: { ...a.config.ports[group] } }; delete ports[group][name];
      expect(createStyxClient({ ...a.config, ports })).toEqual(fail('E_SDK_INVALID_CONFIG'));
    }
    expect((await a.client.start()).ok).toBe(true);
    for (const code of ['E_SDK_NOT_CONFIGURED', 'E_SDK_PUBLISH_NOT_ACCEPTED', 'E_SDK_KEYPACKAGE_NOT_FOUND', 'E_SDK_INVITE_TIMEOUT']) {
      a.session.createKeyPackage = () => ({ ok: false, code });
      expect(await a.client.publishKeyPackage()).toEqual(fail('E_SDK_SESSION_FAILED'));
    }
  });
  test.each(['wrap-extra', 'wrap-kind', 'wrap-tags', 'wrap-pubkey', 'rumor-extra', 'rumor-kind', 'rumor-time', 'payload-extra', 'payload-base64', 'unwrap-unknown', 'unwrap-never'])
  ('additional closed wire/port rejection %s then valid Welcome succeeds', async (fault) => {
    const r = await relay(); const a = await started([r]);
    const b = await started([r], { time: { ...clock(), now: Date.now } });
    const kp = await b.client.publishKeyPackage();
    const rumor = { pubkey: a.id.pk, created_at: Math.floor(Date.now() / 1000), kind: 4744,
      tags: [['e', kp.value.keyPackageEventId], ['v', V]],
      content: JSON.stringify({ welcome: bytesToBase64(utf8Encode(a.id.pk + ':' + b.id.pk)), ratchetTree: 'AQ==' }) };
    if (fault === 'rumor-extra') rumor.extra = true;
    if (fault === 'rumor-kind') rumor.kind = 4743;
    if (fault === 'rumor-time') rumor.created_at = -1;
    if (fault.startsWith('payload-')) {
      const payload = JSON.parse(rumor.content);
      if (fault === 'payload-extra') payload.extra = true; else payload.welcome = 'AB==';
      rumor.content = JSON.stringify(payload);
    }
    let bad = a.id.giftWrap({ rumor, recipient: b.id.pk });
    if (fault === 'wrap-extra') bad.extra = true;
    if (fault === 'wrap-kind') bad.kind = 13;
    if (fault === 'wrap-tags') bad.tags.push(['e', kp.value.keyPackageEventId]);
    if (fault === 'wrap-pubkey') bad.pubkey = 'G'.repeat(64);
    const unwrap = b.id.unwrapGift;
    b.id.unwrapGift = (arg) => {
      if (arg.event.id === bad.id && fault === 'unwrap-unknown') return { code: 'OUTSIDE_CLOSED_SET' };
      if (arg.event.id === bad.id && fault === 'unwrap-never') return new Promise(() => {});
      return unwrap(arg);
    };
    r.events.push(bad); const seen = []; await b.client.onEvent((e) => seen.push(e));
    const pending = b.client.acceptInvite({ inviter: a.id.pk, keyPackageEventId: kp.value.keyPackageEventId });
    expect((await a.client.invite({ invitee: b.id.pk })).ok).toBe(true);
    expect(await pending).toEqual({ ok: true, value: { inviter: a.id.pk } });
    expect(seen.filter((e) => e.kind === 'INBOUND_DISCARDED')).toHaveLength(0);
  });
  test.each(['connection', 'held-port', 'waiting-frame'])
  ('shutdown ordering with nonterminal outbound item and invitation %s', async (phase) => {
    const r = await relay(); const a = await started([r]);
    const trace = []; let stopping = false;
    const clear = a.config.clock.clearTimer;
    a.config.clock.clearTimer = (h) => { if (stopping) trace.push('clear'); return clear(h); };
    const close = WebSocket.prototype.close;
    WebSocket.prototype.close = function (...args) { if (stopping) trace.push('close'); return close.apply(this, args); };
    try {
      await a.client.onEvent((e) => { if (e.kind === 'DELIVERY_STATE_CHANGED' && e.state === 'LOST_ON_SHUTDOWN') trace.push('lost'); });
      // A failed relay acknowledgement would terminate quickly; hold signing instead.
      let releaseSign;
      a.id.sign = () => new Promise((resolve) => { releaseSign = resolve; });
      const sent = await a.client.send({ recipient: 'b'.repeat(64), payload: new Uint8Array([1]) });
      expect(sent.ok).toBe(true);
      await sleep(10);
      let pending;
      if (phase === 'held-port') {
        a.session.createKeyPackage = () => new Promise(() => {});
        pending = a.client.publishKeyPackage();
      } else if (phase === 'waiting-frame') {
        // Release the signing seam for a successful KeyPackage publication first.
        a.id.sign = identity(a.id.key).sign;
        const kp = await a.client.publishKeyPackage(); expect(kp.ok).toBe(true);
        pending = a.client.acceptInvite({ inviter: 'b'.repeat(64), keyPackageEventId: kp.value.keyPackageEventId });
        await sleep(600);
      } else pending = a.client.invite({ invitee: 'b'.repeat(64) });
      await sleep(5); stopping = true; const began = Date.now(); const stop = a.client.shutdown();
      // Existing pending signing call is bounded independently, never new work.
      if (releaseSign) releaseSign(new Uint8Array(64));
      expect(await pending).toEqual(fail('E_SDK_CLIENT_STOPPED'));
      expect((await stop).ok).toBe(true);
      expect(Date.now() - began).toBeLessThan(4 * 5500 + 10000 + 5500 + 11000 + 5500);
      expect(trace).toContain('lost'); expect(trace).toContain('close');
      expect(trace.indexOf('lost')).toBeLessThan(trace.indexOf('close'));
      if (trace.includes('clear')) expect(trace.indexOf('lost')).toBeLessThan(trace.indexOf('clear'));
      expect((await a.client.getDelivery({ deliveryId: sent.value.deliveryId })).value.state).toBe('LOST_ON_SHUTDOWN');
    } finally { stopping = false; WebSocket.prototype.close = close; }
  });
});

// Kimi correction cycle: literal counterexamples, real loopback sets with one faulty seam.
describe('Kimi R8 counterexamples', () => {
  async function seam() {
    jest.resetModules();
    let fault = null;
    let afterStart = null;
    const trace = [];
    jest.unstable_mockModule('../../src/sdk/delivery/relay-pool.js', () => ({
      createRelaySet: (options) => {
        const set = originalRelaySet(options);
        if (![4743, 1059].includes(options.filter.kinds[0])) return set;
        const captured = fault;
        const start = set.start;
        set.start = async () => { const result = await start(); afterStart?.(); return result; };
        const dispose = set.dispose;
        set.dispose = async () => {
          await dispose();
          trace.push('disposed');
          if (captured === 'throw') throw Error('dispose fault');
          if (captured === 'reject') return Promise.reject(Error('dispose fault'));
          if (captured === 'never') return new Promise(() => {});
          if (captured === 'malformed') return { unexpected: true };
          if (captured === 'unknown') return { code: 'OUTSIDE_CLOSED_SET' };
          return undefined;
        };
        return set;
      },
    }));
    const fresh = await import('../../src/sdk/index.js');
    cleanup.push(() => { jest.unstable_mockModule('../../src/sdk/delivery/relay-pool.js', () => ({ createRelaySet: originalRelaySet })); jest.resetModules(); });
    return { factory: fresh.createStyxClient, trace,
      setFault: (value) => { fault = value; }, setAfterStart: (fn) => { afterStart = fn; } };
  }
  test.each(['publishKeyPackage', 'invite', 'acceptInvite'].flatMap((method) =>
    ['throw', 'reject', 'never', 'malformed', 'unknown'].map((fault) => [method, fault])))
  ('H1 %s disposal %s cannot preserve success', async (method, fault) => {
    const s = await seam(); const r = await relay();
    const a = await started([r], { factory: s.factory });
    const b = await started([r], { factory: s.factory });
    let kp;
    if (method !== 'publishKeyPackage') { kp = await b.client.publishKeyPackage(); expect(kp.ok).toBe(true); }
    s.setFault(fault);
    const began = Date.now(); let pending;
    if (method === 'publishKeyPackage') pending = a.client.publishKeyPackage();
    else if (method === 'invite') pending = a.client.invite({ invitee: b.id.pk });
    else {
      pending = b.client.acceptInvite({ inviter: a.id.pk, keyPackageEventId: kp.value.keyPackageEventId });
      // The inviter's independent disposal is not the one under test.
      s.setFault(null);
      expect((await a.client.invite({ invitee: b.id.pk })).ok).toBe(true);
    }
    expect(await pending).toEqual(fail(fault === 'unknown' ? 'E_SDK_UNKNOWN_CODE' : 'E_SDK_INTERNAL'));
    expect(Date.now() - began).toBeLessThan(20000);
    expect(s.trace).toContain('disposed');
    expect((await a.client.shutdown()).ok).toBe(true);
    expect((await b.client.shutdown()).ok).toBe(true);
    for (let i = 0; i < 100 && r.server.clients.size; i++) await sleep(10);
    expect(r.server.clients.size).toBe(0);
  });
  test.each(['throw', 'reject', 'never', 'malformed', 'unknown'])
  ('H1 shutdown preserves CLIENT_STOPPED despite disposal %s', async (fault) => {
    const s = await seam(); const r = await relay();
    const a = await started([r], { factory: s.factory });
    const b = await started([r], { factory: s.factory });
    expect((await b.client.publishKeyPackage()).ok).toBe(true);
    let release; let entered = false;
    a.session.startSession = () => { entered = true; return new Promise((resolve) => { release = resolve; }); };
    s.setFault(fault);
    const pending = a.client.invite({ invitee: b.id.pk });
    for (let i = 0; i < 300 && !entered; i++) await sleep(10);
    expect(entered).toBe(true);
    const began = Date.now(); const stopping = a.client.shutdown();
    release({ welcome: new Uint8Array([1]), ratchetTree: new Uint8Array([1]) });
    expect(await pending).toEqual(fail('E_SDK_CLIENT_STOPPED'));
    expect((await stopping).ok).toBe(true);
    expect(Date.now() - began).toBeLessThan(20000);
    expect(r.events.filter((event) => event.kind === 1059)).toHaveLength(0);
  });
  test.each(['throw', 'unknown', 'malformed', 'reject', 'never'])
  ('H2 candidate expiration clock %s is a local fault, not not-found', async (fault) => {
    const s = await seam(); const r = await relay();
    const a = await started([r], { factory: s.factory });
    const b = await started([r], { factory: s.factory });
    expect((await b.client.publishKeyPackage()).ok).toBe(true);
    expect(r.events.some((e) => e.kind === 4743 && e.pubkey === b.id.pk)).toBe(true);
    let reads = 0;
    s.setAfterStart(() => {
      a.config.clock.now = () => {
        reads++;
        if (fault === 'throw') throw Error('expiration clock fault');
        if (fault === 'unknown') return { code: 'OUTSIDE_CLOSED_SET' };
        if (fault === 'reject') return Promise.reject(Error('expiration clock fault'));
        if (fault === 'never') return new Promise(() => {});
        return null;
      };
    });
    expect(await a.client.invite({ invitee: b.id.pk })).toEqual(fail(fault === 'unknown' ? 'E_SDK_UNKNOWN_CODE' : 'E_SDK_INTERNAL'));
    expect(reads).toBeGreaterThan(0);
    expect(r.events.filter((e) => e.kind === 1059)).toHaveLength(0);
  });
  test.each([0, 1, 3599, 3600, 3601])
  ('M1 timestamp MAX_SAFE_INTEGER minus %s keeps expiration safe before signing', async (offset) => {
    const r = await relay(); const a = await started([r]);
    const created_at = Number.MAX_SAFE_INTEGER - offset;
    a.config.clock.now = () => created_at * 1000;
    expect(Math.floor(a.config.clock.now() / 1000)).toBe(created_at);
    const sign = jest.fn(a.id.sign); a.id.sign = sign;
    const result = await a.client.publishKeyPackage();
    if (offset < 3600) {
      expect(result).toEqual(fail('E_SDK_INTERNAL'));
      expect(sign).not.toHaveBeenCalled(); expect(r.events).toHaveLength(0);
    } else {
      expect(result.ok).toBe(true);
      expect(sign).toHaveBeenCalledTimes(1);
      expect(r.events[0].tags[1]).toEqual(['expiration', String(created_at + 3600)]);
      expect(Number.isSafeInteger(Number(r.events[0].tags[1][1]))).toBe(true);
    }
  });
});

// Second and final correction cycle: local seam faults, never hostile getters.
describe('Kimi R9 counterexamples', () => {
  const faults = ['throw', 'reject', 'never', 'malformed', 'unknown'];
  const bad = (fault, malformed = null) => {
    if (fault === 'throw') throw Error('R9 literal fault');
    if (fault === 'reject') return Promise.reject(Error('R9 literal fault'));
    if (fault === 'never') return new Promise(() => {});
    return fault === 'unknown' ? { code: 'OUTSIDE_CLOSED_SET' } : malformed;
  };
  async function seam() {
    jest.resetModules();
    let active = null;
    const trace = [];
    jest.unstable_mockModule('../../src/sdk/delivery/relay-pool.js', () => ({
      createRelaySet: (options) => {
        // Keep the unchanged lane's own clock conforming. Only the added
        // invitation orchestration consumes the injected faulty clock.
        const set = originalRelaySet({ ...options, clock: { ...options.clock } });
        if (![4743, 1059].includes(options.filter.kinds[0])) return set;
        const captured = active;
        const dispose = set.dispose;
        set.dispose = async () => { await dispose(); trace.push('disposed'); };
        if (!captured) return set;
        if (captured.port === 'factory') { void dispose(); trace.push('disposed'); return bad(captured.fault); }
        if (captured.port === 'freeze') {
          const freeze = set.freeze;
          set.freeze = () => { freeze(); trace.push('frozen'); return bad(captured.fault); };
        }
        const start = set.start;
        set.start = async () => {
          const value = await start();
          if (captured.port === 'start') return bad(captured.fault);
          if (['setTimer', 'clearTimer'].includes(captured.port)) {
            options.clock[captured.port] = () => { trace.push(captured.port); return bad(captured.fault); };
          }
          return value;
        };
        if (captured.port === 'onFrame') {
          const subscribe = set.onFrame;
          set.onFrame = (listener) => { subscribe(listener); return bad(captured.fault); };
        }
        if (captured.port === 'frame' || captured.port === 'frame-top') {
          const subscribe = set.onFrame;
          set.onFrame = (listener) => subscribe((frame) => listener(captured.port === 'frame-top'
            ? { ...frame, code: 'OUTSIDE_CLOSED_SET' }
            : { ...frame, relayIndex: captured.fault === 'unknown' ? { code: 'OUTSIDE_CLOSED_SET' } : -1 }));
        }
        const publish = set.publish;
        set.publish = (...args) => {
          if (captured.port === 'publish') return bad(captured.fault);
          const attempt = publish(...args);
          if (!['isSettled', 'outcomes', 'onSettled'].includes(captured.port)) return attempt;
          let armed = false;
          const descriptors = Object.getOwnPropertyDescriptors(attempt);
          descriptors.onSettled = { value: (listener) => {
            armed = true;
            const unsubscribe = attempt.onSettled(listener);
            return captured.port === 'onSettled' ? bad(captured.fault) : unsubscribe;
          }, enumerable: true };
          if (captured.port === 'isSettled') descriptors.isSettled = { value: () => {
            trace.push('isSettled'); return bad(captured.fault);
          }, enumerable: true };
          // A normal, side-effect-free accessor is used only to supply the final
          // snapshot; checkAttempt requires a data member, so expose a live array
          // whose elements are changed after the initial shape check instead.
          if (captured.port === 'outcomes') {
            const outcomes = [...attempt.outcomes];
            descriptors.outcomes = { value: outcomes, enumerable: true };
            descriptors.isSettled = { value: () => {
              if (armed) {
                trace.push('outcomes');
                outcomes[0] = 'ACCEPTED';
                if (captured.fault === 'unknown') outcomes[1] = 'OUTSIDE_CLOSED_SET';
                else if (captured.fault === 'known-slot') outcomes[1] = { code: 'E_SDK_INTERNAL' };
                else if (captured.fault === 'sparse') delete outcomes[1];
                else outcomes.length = 1;
              }
              return true;
            }, enumerable: true };
          }
          return Object.create(null, descriptors);
        };
        return set;
      },
    }));
    const fresh = await import('../../src/sdk/index.js');
    cleanup.push(() => { jest.unstable_mockModule('../../src/sdk/delivery/relay-pool.js', () => ({ createRelaySet: originalRelaySet })); jest.resetModules(); });
    return { factory: fresh.createStyxClient, trace, activate: (port, fault) => { active = { port, fault }; }, clear: () => { active = null; } };
  }
  async function run(method, port, fault) {
    const s = await seam(); const rs = [await relay(), await relay()];
    const a = await started(rs, { factory: s.factory });
    const b = await started(rs, { factory: s.factory });
    let kp;
    if (method !== 'publishKeyPackage') { kp = await b.client.publishKeyPackage(); expect(kp.ok).toBe(true); }
    s.activate(port, fault);
    const began = Date.now(); let pending;
    if (method === 'publishKeyPackage') pending = a.client.publishKeyPackage();
    else if (method === 'invite') pending = a.client.invite({ invitee: b.id.pk });
    else {
      pending = b.client.acceptInvite({ inviter: a.id.pk, keyPackageEventId: kp.value.keyPackageEventId });
      s.clear();
      // Ensure the acceptance waits for a later frame, rather than finding a
      // Welcome already in its initial buffer.
      await sleep(700);
      expect((await a.client.invite({ invitee: b.id.pk })).ok).toBe(true);
    }
    const expected = fault === 'unknown' ? 'E_SDK_UNKNOWN_CODE' : 'E_SDK_INTERNAL';
    const result = await pending;
    // Restore caller clocks before independent delivery shutdown. The method's
    // disposal already happened and must not depend on this fixture cleanup.
    a.config.clock.setTimer = clock().setTimer; a.config.clock.clearTimer = clearTimeout;
    b.config.clock.setTimer = clock().setTimer; b.config.clock.clearTimer = clearTimeout;
    expect(result).toEqual(fail(expected));
    expect(Date.now() - began).toBeLessThan(20000);
    expect(s.trace).toContain('disposed');
    expect((await a.client.shutdown()).ok).toBe(true);
    expect((await b.client.shutdown()).ok).toBe(true);
    for (let i = 0; i < 100 && rs.some((r) => r.server.clients.size); i++) await sleep(10);
    expect(rs.map((r) => r.server.clients.size)).toEqual([0, 0]);
  }
  test.each(['publishKeyPackage', 'invite', 'acceptInvite'].flatMap((method) =>
    ['setTimer', 'clearTimer'].flatMap((port) => faults.map((fault) => [method, port, fault]))))
  ('N1 %s %s %s cannot preserve success', run);
  test.each(faults.map((fault) => ['publishKeyPackage', 'isSettled', fault]))
  ('N2 %s %s %s cannot use a non-boolean predicate', run);
  test.each(['unknown', 'malformed', 'sparse', 'known-slot'].map((fault) => ['publishKeyPackage', 'outcomes', fault]))
  ('N2 %s final %s %s cannot preserve ACCEPTED beside invalid entries', run);
  test.each(['factory', 'onFrame', 'start', 'publish', 'onSettled'].flatMap((port) => faults.map((fault) => ['publishKeyPackage', port, fault])))
  ('sweep %s %s %s checks every registration and connection result', run);
  test.each([['publishKeyPackage', 'frame', 'unknown'], ['publishKeyPackage', 'frame', 'malformed'], ['publishKeyPackage', 'frame-top', 'unknown']])
  ('sweep %s callback %s %s checks local relay metadata', run);
  test.each(['clearTimer', 'freeze'].flatMap((port) => faults.map((fault) => [port, fault])))
  ('sweep shutdown preserves CLIENT_STOPPED with %s %s', async (port, fault) => {
    const s = await seam(); const r = await relay();
    const a = await started([r], { factory: s.factory });
    const b = await started([r], { factory: s.factory });
    const kp = await b.client.publishKeyPackage(); expect(kp.ok).toBe(true);
    s.activate(port, fault);
    const pending = b.client.acceptInvite({ inviter: a.id.pk, keyPackageEventId: kp.value.keyPackageEventId });
    await sleep(700);
    const began = Date.now(); const closing = b.client.shutdown();
    expect(await pending).toEqual(fail('E_SDK_CLIENT_STOPPED'));
    expect((await closing).ok).toBe(true);
    expect(Date.now() - began).toBeLessThan(20000);
    expect(s.trace).toContain('disposed');
  });
  test.each(['createKeyPackage', 'sign', 'startSession', 'giftWrap', 'joinSession'])
  ('sweep absent runtime member %s is a bounded port failure', async (name) => {
    const r = await relay(); const a = await started([r]); const b = await started([r]);
    const kp = await b.client.publishKeyPackage(); expect(kp.ok).toBe(true);
    const target = name === 'joinSession' ? b.session : ['createKeyPackage', 'startSession'].includes(name) ? a.session : a.id;
    delete target[name];
    const expected = ['sign', 'giftWrap'].includes(name) ? 'E_SDK_IDENTITY_FAILED' : 'E_SDK_SESSION_FAILED';
    let result;
    if (name === 'joinSession') {
      const pending = b.client.acceptInvite({ inviter: a.id.pk, keyPackageEventId: kp.value.keyPackageEventId });
      expect((await a.client.invite({ invitee: b.id.pk })).ok).toBe(true); result = await pending;
    } else result = name === 'createKeyPackage' || name === 'sign' ? await a.client.publishKeyPackage() : await a.client.invite({ invitee: b.id.pk });
    expect(result).toEqual(fail(expected));
  });
});
