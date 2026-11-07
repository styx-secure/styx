// C-DLV section 5.5: the KeyPackage fetch waits for the EOSE of every relay
// counted connected at the end of the operation's connection phase, by
// identity, and an invitation publication ends at the first ACCEPTED.
// In-process WebSocket double only: scripted relays, no socket is opened.
// Test wrapping signs layers but DOES NOT ENCRYPT.
import { describe, test, expect, beforeAll, afterAll, afterEach, jest } from '@jest/globals';
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, utf8Encode, utf8Decode, bytesToBase64 } from '../../src/utils.js';
import { createStyxClient, SDK_INTERFACE_VERSION, SDK_WIRE_VERSION } from '../../src/sdk/index.js';
import { createRelaySet } from '../../src/sdk/delivery/relay-pool.js';

const V = SDK_WIRE_VERSION;
// The caller clock runs SPEED times faster than host time, so one
// perRelayTimeoutMs of 11 000 ms is 550 ms of host time.
const SPEED = 20;
const T = 11000;
const PHASE_MS = T / SPEED;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const url = (port) => 'ws' + '://' + '127.0.0.1:' + port;
const A = url(7101);
const B = url(7102);
const hash = (e) => bytesToHex(sha256(utf8Encode(JSON.stringify([0, e.pubkey, e.created_at, e.kind, e.tags, e.content]))));
const signed = (e, key) => { const id = hash(e); return { ...e, id, sig: bytesToHex(schnorr.sign(hexToBytes(id), key)) }; };

function identity(key = schnorr.utils.randomPrivateKey()) {
  const pk = bytesToHex(schnorr.getPublicKey(key));
  return { pk, key, getPublicKey: () => pk, sign: ({ digest }) => schnorr.sign(digest, key),
    giftWrap: ({ rumor, recipient }) => {
      const seal = signed({ pubkey: pk, created_at: rumor.created_at, kind: 13, tags: [], content: JSON.stringify(rumor) }, key);
      const fresh = schnorr.utils.randomPrivateKey();
      return signed({ pubkey: bytesToHex(schnorr.getPublicKey(fresh)), created_at: rumor.created_at,
        kind: 1059, tags: [['p', recipient]], content: JSON.stringify(seal) }, fresh);
    },
    unwrapGift: () => { throw Error('unused'); } };
}
function session(pk) {
  return { seal: ({ plaintext }) => ({ ciphertext: plaintext }), open: ({ ciphertext }) => ({ plaintext: ciphertext }),
    createKeyPackage: () => utf8Encode(pk),
    startSession: ({ peer, keyPackage }) => {
      if (utf8Decode(keyPackage) !== peer) throw Error('credential');
      return { welcome: utf8Encode(pk + ':' + peer), ratchetTree: new Uint8Array([1]) };
    },
    joinSession: () => true };
}

// In-process WebSocket double. `scenario.openDelay(url)` gives the host delay
// before a socket opens; `scenario.onSend(ws, frame)` answers each frame.
let scenario;
const sockets = new Set();
class ScriptedSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;
  constructor(target) {
    this.url = target;
    this.readyState = 0;
    sockets.add(this);
    const delay = scenario.openDelay ? scenario.openDelay(target) : 5;
    setTimeout(() => {
      if (this.readyState !== 0) return;
      this.readyState = 1;
      if (this.onopen) this.onopen();
    }, delay);
  }
  deliver(frame, delay = 0) {
    setTimeout(() => {
      if (this.readyState === 1 && this.onmessage) this.onmessage({ data: JSON.stringify(frame) });
    }, delay);
  }
  send(raw) { scenario.onSend(this, JSON.parse(raw)); }
  close() {
    if (this.readyState === 3) return;
    this.readyState = 3;
    sockets.delete(this);
    setTimeout(() => { if (this.onclose) this.onclose({}); }, 0);
  }
}

let originalWebSocket;
const cleanup = [];
beforeAll(() => { originalWebSocket = globalThis.WebSocket; globalThis.WebSocket = ScriptedSocket; });
afterAll(() => { globalThis.WebSocket = originalWebSocket; });
afterEach(async () => {
  while (cleanup.length) await cleanup.pop()();
  for (let i = 0; i < 100 && sockets.size; i++) await sleep(10);
  expect(sockets.size).toBe(0);
  scenario = undefined;
});

function clock() {
  const origin = Date.now();
  return { now: () => origin + (Date.now() - origin) * SPEED,
    setTimer: (f, ms) => setTimeout(f, ms / SPEED), clearTimer: clearTimeout };
}
async function client(id = identity()) {
  const records = new Map();
  const time = clock();
  const created = createStyxClient({ interfaceVersion: SDK_INTERFACE_VERSION, relays: [A, B], clock: time,
    delivery: { perRelayTimeoutMs: T, deadlineMs: 30000 },
    ports: { identity: id, session: session(id.pk), storage: {
      list: () => [...records.values()], get: (k) => records.get(k),
      put: (r) => { records.set(r.deliveryId, r); return true; },
      update: (k, v) => { records.set(k, v); return true; }, remove: (k) => records.delete(k) } } });
  expect(created.ok).toBe(true);
  cleanup.push(() => created.value.shutdown());
  expect((await created.value.start()).ok).toBe(true);
  return { client: created.value, id, clock: time };
}
function keyPackageOf(invitee, time) {
  const created_at = Math.floor(time.now() / 1000);
  return signed({ pubkey: invitee.pk, created_at, kind: 4743,
    tags: [['v', V], ['expiration', String(created_at + 3600)]], content: bytesToBase64(utf8Encode(invitee.pk)) }, invitee.key);
}
const isFetch = (frame) => frame[0] === 'REQ' && Array.isArray(frame[2].kinds) && frame[2].kinds.includes(4743);

describe('C-DLV 5.5 KeyPackage fetch waits for the EOSE of every phase-end relay, by identity', () => {
  test('an EOSE from a relay that left before the phase end does not end the wait; the phase-end relay answer is chosen', async () => {
    const invitee = identity();
    let kp = null;
    const log = [];
    scenario = { onSend(ws, f) {
      if (f[0] === 'EVENT') { ws.deliver(['OK', f[1].id, true, '']); return; }
      if (f[0] !== 'REQ') return;
      if (!isFetch(f)) { ws.deliver(['EOSE', f[1]]); return; }
      if (ws.url === A) {
        ws.deliver(['EOSE', f[1]]);
        // A leaves 60 ms after its EOSE, well before the 550 ms phase end.
        setTimeout(() => { log.push('A-left'); ws.close(); }, 60);
      } else {
        // B is connected at the phase end and answers 700 ms after its REQ,
        // after the phase and inside the 550 ms fetch wait that follows.
        setTimeout(() => { log.push('B-answer'); ws.deliver(['EVENT', f[1], kp]); ws.deliver(['EOSE', f[1]]); }, 700);
      }
    } };
    const inviter = await client();
    kp = keyPackageOf(invitee, inviter.clock);
    const result = await inviter.client.invite({ invitee: invitee.pk });
    expect(result.ok ? 'ok' : result.code).toBe('ok');
    // A's replacement pool may connect and leave again during the wait.
    expect(log[0]).toBe('A-left');
    expect(log.filter((entry) => entry === 'B-answer')).toHaveLength(1);
    expect(result.ok).toBe(true);
    expect(result.value.keyPackageEventId).toBe(kp.id);
  });

  test('an EOSE from a relay that connected only after the phase end does not end the wait', async () => {
    const invitee = identity();
    let kp = null;
    let late = false;
    const log = [];
    scenario = {
      // During the invitation, A opens 700 ms after its socket is created,
      // after the 550 ms connection phase of the operation.
      openDelay: (target) => (late && target === A ? 700 : 5),
      onSend(ws, f) {
        if (f[0] === 'EVENT') { ws.deliver(['OK', f[1].id, true, '']); return; }
        if (f[0] !== 'REQ') return;
        if (!isFetch(f)) { ws.deliver(['EOSE', f[1]]); return; }
        if (ws.url === A) { log.push('A-eose'); ws.deliver(['EOSE', f[1]]); return; }
        setTimeout(() => { log.push('B-answer'); ws.deliver(['EVENT', f[1], kp]); ws.deliver(['EOSE', f[1]]); }, 950);
      },
    };
    const inviter = await client();
    kp = keyPackageOf(invitee, inviter.clock);
    late = true;
    const result = await inviter.client.invite({ invitee: invitee.pk });
    expect(result.ok ? 'ok' : result.code).toBe('ok');
    expect(log[0]).toBe('A-eose');
    expect(log.filter((entry) => entry === 'B-answer')).toHaveLength(1);
    expect(result.ok).toBe(true);
    expect(result.value.keyPackageEventId).toBe(kp.id);
  });

  test('control: when every phase-end relay has sent EOSE the fetch ends before the wait', async () => {
    const invitee = identity();
    let kp = null;
    scenario = { onSend(ws, f) {
      if (f[0] === 'EVENT') { ws.deliver(['OK', f[1].id, true, '']); return; }
      if (f[0] !== 'REQ') return;
      if (isFetch(f) && ws.url === A) ws.deliver(['EVENT', f[1], kp]);
      ws.deliver(['EOSE', f[1]]);
    } };
    const inviter = await client();
    kp = keyPackageOf(invitee, inviter.clock);
    const began = Date.now();
    const result = await inviter.client.invite({ invitee: invitee.pk });
    expect(result.ok).toBe(true);
    expect(result.value.keyPackageEventId).toBe(kp.id);
    // The connection phase always lasts one perRelayTimeoutMs; the fetch wait
    // after it ended at the second EOSE, not at its own 550 ms bound.
    expect(Date.now() - began).toBeLessThan(2 * PHASE_MS - 100);
  });

  test('control: a phase-end relay that stays silent does not contribute and the wait runs to its bound', async () => {
    const invitee = identity();
    let kp = null;
    scenario = { onSend(ws, f) {
      if (f[0] === 'EVENT') { ws.deliver(['OK', f[1].id, true, '']); return; }
      if (f[0] !== 'REQ') return;
      if (!isFetch(f)) { ws.deliver(['EOSE', f[1]]); return; }
      if (ws.url === A) { ws.deliver(['EVENT', f[1], kp]); ws.deliver(['EOSE', f[1]]); }
    } };
    const inviter = await client();
    kp = keyPackageOf(invitee, inviter.clock);
    const began = Date.now();
    const result = await inviter.client.invite({ invitee: invitee.pk });
    expect(result.ok).toBe(true);
    expect(result.value.keyPackageEventId).toBe(kp.id);
    expect(Date.now() - began).toBeGreaterThanOrEqual(2 * PHASE_MS - 20);
  });
});

describe('C-DLV 5.5 invitation publication ends at the first ACCEPTED', () => {
  // `answers[url]` gives, per kind of the published event, either
  // ['OK', accepted, hostDelayMs] or null for a relay that never answers.
  function publishing(answers, kp) {
    return { onSend(ws, f) {
      if (f[0] === 'EVENT') {
        const answer = answers[ws.url](f[1].kind);
        if (answer) ws.deliver(['OK', f[1].id, answer[0], ''], answer[1]);
        return;
      }
      if (f[0] !== 'REQ') return;
      if (isFetch(f) && kp.event) ws.deliver(['EVENT', f[1], kp.event]);
      ws.deliver(['EOSE', f[1]]);
    } };
  }
  const invitation = (kind) => kind === 4743 || kind === 1059;

  test('a slower accepting relay is not waited for: publishKeyPackage and invite report the first acceptance', async () => {
    const invitee = identity();
    const kp = { event: null };
    scenario = publishing({
      [A]: (kind) => (invitation(kind) ? [true, 0] : [true, 0]),
      // B accepts 150 ms after the publication, inside the 550 ms attempt timeout.
      [B]: (kind) => (invitation(kind) ? [true, 150] : [true, 0]),
    }, kp);
    const own = await client();
    const published = await own.client.publishKeyPackage();
    expect(published.ok).toBe(true);
    expect(published.value.acceptedRelays).toEqual([0]);
    expect(Object.isFrozen(published.value.acceptedRelays)).toBe(true);
    kp.event = keyPackageOf(invitee, own.clock);
    const sent = await own.client.invite({ invitee: invitee.pk });
    expect(sent.ok).toBe(true);
    expect(sent.value.keyPackageEventId).toBe(kp.event.id);
    expect(sent.value.acceptedRelays).toEqual([0]);
    expect(Object.isFrozen(sent.value.acceptedRelays)).toBe(true);
  });

  test('control: a refusal does not end the publication; the later first acceptance does', async () => {
    const invitee = identity();
    const kp = { event: null };
    scenario = publishing({
      [A]: (kind) => (invitation(kind) ? [false, 0] : [true, 0]),
      [B]: (kind) => (invitation(kind) ? [true, 150] : [true, 0]),
    }, kp);
    const own = await client();
    const published = await own.client.publishKeyPackage();
    expect(published.ok).toBe(true);
    expect(published.value.acceptedRelays).toEqual([1]);
    kp.event = keyPackageOf(invitee, own.clock);
    const sent = await own.client.invite({ invitee: invitee.pk });
    expect(sent.ok).toBe(true);
    expect(sent.value.acceptedRelays).toEqual([1]);
  });

  test('control: with no acceptance before the attempt timeout the publication is not accepted', async () => {
    const kp = { event: null };
    scenario = publishing({
      [A]: (kind) => (invitation(kind) ? [false, 0] : [true, 0]),
      [B]: (kind) => (invitation(kind) ? null : [true, 0]),
    }, kp);
    const own = await client();
    const began = Date.now();
    expect(await own.client.publishKeyPackage()).toEqual({ ok: false, code: 'E_SDK_PUBLISH_NOT_ACCEPTED' });
    expect(Date.now() - began).toBeGreaterThanOrEqual(2 * PHASE_MS - 20);
  });
});

describe('C-DLV 5.5 S9 relay-set option onPhaseConnected', () => {
  const random = { nextUint32: () => 0 };
  function set(onPhaseConnected) {
    const made = createRelaySet({ relays: [A, B], clock: clock(), random, perRelayTimeoutMs: T,
      subscriptionId: 's' + '0'.repeat(32), filter: { kinds: [4743] }, onPhaseConnected });
    cleanup.push(() => made.dispose());
    return made;
  }
  const quiet = { onSend() {} };

  test('called once at the phase end with exactly the counted relays, ascending and frozen, before start resolves', async () => {
    // B opens only after the 550 ms phase: it is not counted.
    scenario = { ...quiet, openDelay: (target) => (target === B ? PHASE_MS + 150 : 5) };
    const calls = [];
    const relaySet = set((indices) => calls.push(indices));
    const result = await relaySet.start();
    expect(result).toEqual({ connectedRelays: 1 });
    expect(calls).toEqual([[0]]);
    expect(Object.isFrozen(calls[0])).toBe(true);
    await sleep(300);
    expect(relaySet.connectedRelays).toBe(2);
    expect(calls).toHaveLength(1);
  });

  test('a relay that left before the phase end is not counted', async () => {
    scenario = { onSend(ws) { if (ws.url === A) setTimeout(() => ws.close(), 30); } };
    const calls = [];
    const relaySet = set((indices) => calls.push(indices));
    expect(await relaySet.start()).toEqual({ connectedRelays: 1 });
    expect(calls).toEqual([[1]]);
  });

  test('not called when no relay is connected at the phase end; a throwing observer changes nothing', async () => {
    scenario = { ...quiet, openDelay: () => PHASE_MS + 150 };
    const calls = [];
    expect(await set((indices) => calls.push(indices)).start()).toEqual({ connectedRelays: 0 });
    expect(calls).toEqual([]);
    scenario = { ...quiet };
    const throwing = set(() => { throw Error('observer'); });
    expect(await throwing.start()).toEqual({ connectedRelays: 2 });
  });
});

// Kimi review cycle 1: the S9 set an invitation receives must be dense, ascending and
// exactly `connectedRelays` long, or the operation fails closed with E_SDK_INTERNAL.
describe('C-DLV 5.5 an inconsistent S9 report is E_SDK_INTERNAL', () => {
  async function seam(report) {
    jest.resetModules();
    jest.unstable_mockModule('../../src/sdk/delivery/relay-pool.js', () => ({
      createRelaySet: (options) => {
        if (![4743, 1059].includes(options.filter.kinds[0])) return createRelaySet(options);
        // The real set reports nothing; the faulty one reports `report(connectedRelays)`, or nothing.
        const set = createRelaySet({ ...options, onPhaseConnected: undefined });
        const start = set.start;
        set.start = async () => {
          const result = await start();
          const value = report(result.connectedRelays);
          if (value !== undefined) options.onPhaseConnected(value);
          return result;
        };
        return set;
      },
    }));
    const fresh = await import('../../src/sdk/index.js');
    cleanup.push(() => { jest.unstable_mockModule('../../src/sdk/delivery/relay-pool.js', () => ({ createRelaySet: createRelaySet })); jest.resetModules(); });
    return fresh.createStyxClient;
  }
  async function seamClient(factory) {
    const id = identity();
    const records = new Map();
    const time = clock();
    const created = factory({ interfaceVersion: SDK_INTERFACE_VERSION, relays: [A, B], clock: time,
      delivery: { perRelayTimeoutMs: T, deadlineMs: 30000 },
      ports: { identity: id, session: session(id.pk), storage: {
        list: () => [...records.values()], get: (k) => records.get(k),
        put: (r) => { records.set(r.deliveryId, r); return true; },
        update: (k, v) => { records.set(k, v); return true; }, remove: (k) => records.delete(k) } } });
    expect(created.ok).toBe(true);
    cleanup.push(() => created.value.shutdown());
    expect((await created.value.start()).ok).toBe(true);
    return { client: created.value, clock: time };
  }
  const reports = {
    sparse: (n) => Object.freeze(new Array(n)),
    'sparse-tail': (n) => { const a = new Array(n); a[0] = 0; return Object.freeze(a); },
    absent: () => undefined,
    short: (n) => Object.freeze([...Array(n - 1).keys()]),
    descending: (n) => Object.freeze([...Array(n).keys()].reverse()),
    'out-of-range': (n) => Object.freeze([...Array(n).keys()].map((i) => i + 5)),
    'non-integer': (n) => Object.freeze([...Array(n).keys()].map((i) => i + 0.5)),
  };
  test.each(Object.keys(reports))('S9 report %s: publishKeyPackage and invite end with E_SDK_INTERNAL', async (name) => {
    const invitee = identity();
    let kp = null;
    // Both relays connect at once; the KeyPackage arrives 300 ms after the fetch REQ,
    // so a fetch whose wait ended at once would miss it.
    scenario = { onSend(ws, f) {
      if (f[0] === 'EVENT') { ws.deliver(['OK', f[1].id, true, '']); return; }
      if (f[0] !== 'REQ') return;
      if (!isFetch(f)) { ws.deliver(['EOSE', f[1]]); return; }
      setTimeout(() => { if (kp) ws.deliver(['EVENT', f[1], kp]); ws.deliver(['EOSE', f[1]]); }, 300);
    } };
    const own = await seamClient(await seam(reports[name]));
    expect(await own.client.publishKeyPackage()).toEqual({ ok: false, code: 'E_SDK_INTERNAL' });
    kp = keyPackageOf(invitee, own.clock);
    expect(await own.client.invite({ invitee: invitee.pk })).toEqual({ ok: false, code: 'E_SDK_INTERNAL' });
  });
});
