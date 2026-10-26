// M3-SHUTDOWN-DRAIN: socket writes only, over independent loopback relays.
import { describe, test, expect, beforeAll, afterAll, afterEach, jest } from '@jest/globals';
import { WebSocket, WebSocketServer } from 'ws';
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, utf8Encode } from '../../src/utils.js';
import { createStyxClient, SDK_INTERFACE_VERSION } from '../../src/sdk/index.js';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const trace = [];
const cleanups = [];
const relayByUrl = new Map();
let originalWebSocket;
class RecordingSocket extends WebSocket {
  constructor(...args) {
    super(...args);
    this.inboundMessages = 0;
    trace.push({ type: 'open', socket: this });
    this.on('message', (raw) => {
      const frame = JSON.parse(String(raw));
      if (frame[0] === 'EVENT' && frame[2]?.kind === 4741) this.inboundMessages += 1;
    });
  }
  send(data, ...args) {
    const frame = JSON.parse(String(data));
    if (frame[0] === 'EVENT') trace.push({ type: 'write', kind: frame[1].kind, socket: this, closed: this.closing === true });
    return super.send(data, ...args);
  }
  close(...args) {
    this.closing = true;
    trace.push({ type: 'close', socket: this });
    return super.close(...args);
  }
}
beforeAll(() => { originalWebSocket = globalThis.WebSocket; globalThis.WebSocket = RecordingSocket; });
afterAll(() => { globalThis.WebSocket = originalWebSocket; });
afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
  trace.length = 0;
  relayByUrl.clear();
});
async function until(predicate, ms = 3000) {
  const end = Date.now() + ms;
  while (!predicate() && Date.now() < end) await sleep(2);
  return predicate();
}
function clock() {
  let now = 12000;
  let id = 0;
  const timers = new Map();
  return {
    now: () => now,
    setTimer(fn, ms) { timers.set(++id, { fn, at: now + ms }); return id; },
    clearTimer(handle) { trace.push({ type: 'clearTimer' }); timers.delete(handle); },
    advance(ms) {
      now += ms;
      for (const [key, timer] of [...timers]) {
        if (timer.at <= now && timers.delete(key)) timer.fn();
      }
    },
  };
}
function matches(filter, event) {
  return (!filter.kinds || filter.kinds.includes(event.kind))
    && (!filter['#p'] || event.tags.some(([name, value]) => name === 'p' && filter['#p'].includes(value)));
}
async function relay() {
  const server = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await new Promise((resolve) => server.once('listening', resolve));
  const subscriptions = new Map();
  const events = [];
  let reqs = 0;
  server.on('connection', (socket) => {
    subscriptions.set(socket, new Map());
    socket.on('close', () => subscriptions.delete(socket));
    socket.on('message', (raw) => {
      const [type, value, ...rest] = JSON.parse(String(raw));
      if (type === 'REQ') {
        reqs += 1;
        subscriptions.get(socket).set(value, rest);
        for (const event of events) if (rest.some((filter) => matches(filter, event))) socket.send(JSON.stringify(['EVENT', value, event]));
        socket.send(JSON.stringify(['EOSE', value]));
      } else if (type === 'EVENT') {
        const event = value;
        const id = bytesToHex(sha256(utf8Encode(JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content]))));
        if (id !== event.id) { socket.send(JSON.stringify(['OK', event.id, false, 'invalid id'])); return; }
        events.push(event);
        socket.send(JSON.stringify(['OK', event.id, true, 'saved']));
        for (const [peer, subs] of subscriptions) for (const [sub, filters] of subs) {
          if (peer.readyState === WebSocket.OPEN && filters.some((filter) => matches(filter, event))) peer.send(JSON.stringify(['EVENT', sub, event]));
        }
      } else if (type === 'CLOSE') subscriptions.get(socket).delete(value);
    });
  });
  cleanups.push(async () => {
    for (const socket of server.clients) socket.terminate();
    await new Promise((resolve) => server.close(resolve));
  });
  const result = { url: `ws://127.0.0.1:${server.address().port}`, events, get reqs() { return reqs; } };
  relayByUrl.set(result.url, result);
  return result;
}
function makeClient(urls, { sign, open, factory = createStyxClient, receiptMode = 'RECIPIENT_RECEIPT' } = {}) {
  const key = schnorr.utils.randomPrivateKey();
  const pub = bytesToHex(schnorr.getPublicKey(key));
  const time = clock();
  const config = {
    interfaceVersion: SDK_INTERFACE_VERSION,
    relays: urls,
    clock: { now: time.now, setTimer: time.setTimer, clearTimer: time.clearTimer },
    ports: {
      storage: { put: () => true, get: () => null, update: () => true, remove: () => true, list: () => [] },
      session: { seal: ({ plaintext }) => ({ ciphertext: plaintext }), open: open || (({ ciphertext }) => ({ plaintext: ciphertext })) },
      identity: { getPublicKey: () => pub, sign: sign ? (arg) => sign(arg, key) : ({ digest }) => schnorr.sign(digest, key) },
    },
    delivery: { maxAttempts: 1, deadlineMs: 30000, perRelayTimeoutMs: 11000, receiptMode },
  };
  const made = factory(config);
  expect(made.ok).toBe(true);
  const client = made.value;
  const events = [];
  cleanups.push(() => client.shutdown());
  return { client, time, pub, events, config };
}
async function start(h) {
  await h.client.onEvent((event) => { h.events.push(event); if (event.state === 'LOST_ON_SHUTDOWN') trace.push({ type: 'lost' }); });
  const relays = h.config.relays.map((url) => relayByUrl.get(url));
  const baseline = relays.map((r) => r.reqs);
  const socketsBefore = new Set(trace.filter((e) => e.type === 'open').map((e) => e.socket));
  const starting = h.client.start();
  expect(await until(() => relays.every((r, i) => r.reqs > baseline[i]))).toBe(true);
  await sleep(5);
  h.time.advance(11000);
  expect((await starting).ok).toBe(true);
  h.sockets = trace.filter((e) => e.type === 'open' && !socketsBefore.has(e.socket)).map((e) => e.socket);
}
async function setup(options = {}) {
  const relays = [await relay(), await relay()];
  const urls = relays.map((r) => r.url);
  const a = makeClient(urls, options);
  const b = makeClient(urls);
  await start(a); await start(b);
  return { a, b, relays };
}
async function snapshot(h, id) { return (await h.client.getDelivery({ deliveryId: id })).value; }

describe('owed receipt drain', () => {
  test('main: shutdown in MESSAGE_RECEIVED reaches RECIPIENT_RECEIPT_RECEIVED on two relays', async () => {
    const { a, b, relays } = await setup();
    let stopping;
    await a.client.onEvent((event) => { if (event.kind === 'MESSAGE_RECEIVED') stopping = a.client.shutdown(); });
    const sent = await b.client.send({ recipient: a.pub, payload: new Uint8Array([1, 2, 3]) });
    expect(sent.ok).toBe(true);
    expect(await until(() => b.events.some((event) => event.state === 'RELAY_ACCEPTED_AWAITING_RECEIPT'))).toBe(true);
    await until(() => b.events.some((event) => event.state === 'RECIPIENT_RECEIPT_RECEIVED'), 6500);
    const beforeDeadline = (await snapshot(b, sent.value.deliveryId)).state;
    if (beforeDeadline !== 'RECIPIENT_RECEIPT_RECEIVED') {
      // Failure diagnostics only: the same file must be red against the base.
      // No assertion accepts the failure state as a successful run.
      expect(beforeDeadline).toBe('RELAY_ACCEPTED_AWAITING_RECEIPT');
      b.time.advance(30000);
      console.info('red-before diagnostic', beforeDeadline, (await snapshot(b, sent.value.deliveryId)).state);
    }
    expect((await snapshot(b, sent.value.deliveryId)).state).toBe('RECIPIENT_RECEIPT_RECEIVED');
    await stopping;
    expect(await until(() => relays.every((r) => r.events.filter((event) => event.kind === 4742).length === 1))).toBe(true);
    expect(trace.filter((entry) => entry.type === 'write' && entry.kind === 4742)).toHaveLength(2);
    expect(trace.filter((entry) => entry.type === 'write').every((entry) => !entry.closed)).toBe(true);
    b.time.advance(30000);
  }, 12000);

  test('a held signature drains once before socket close and after LOST listeners', async () => {
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    const { a, b, relays } = await setup({ sign: ({ digest }, key) => gate.then(() => schnorr.sign(digest, key)) });
    // Keep an outbound item so shutdown has a real LOST event.
    await a.client.send({ recipient: b.pub, payload: new Uint8Array([8]) });
    let stopping;
    let resolved = false;
    await a.client.onEvent((event) => {
      if (event.kind === 'MESSAGE_RECEIVED') {
        trace.length = 0;
        stopping = a.client.shutdown().then(() => { resolved = true; });
      }
    });
    await b.client.send({ recipient: a.pub, payload: new Uint8Array([2]) });
    expect(await until(() => stopping !== undefined)).toBe(true);
    expect(resolved).toBe(false);
    release();
    await stopping;
    expect(await until(() => relays.every((r) => r.events.some((e) => e.kind === 4742 && e.pubkey === a.pub)))).toBe(true);
    const lost = trace.findIndex((entry) => entry.type === 'lost');
    expect(lost).toBeGreaterThanOrEqual(0);
    expect(trace.findIndex((entry) => entry.type === 'clearTimer')).toBeGreaterThan(lost);
    expect(trace.findIndex((entry) => entry.type === 'close')).toBeGreaterThan(lost);
    for (const entry of trace.filter((e) => e.type === 'write' && e.kind === 4742 && e.socket.closing)) {
      expect(trace.indexOf(entry)).toBeLessThan(trace.findIndex((e) => e.type === 'close' && e.socket === entry.socket));
    }
  });

  test.each(['throw', 'reject', 'never', 'malformed', 'unknown'])(
    'model B owed identity.sign: %s', async (fault) => {
      let release;
      const gate = new Promise((resolve) => { release = resolve; });
      const { a, b, relays } = await setup({ sign: () => {
        if (fault === 'throw') throw new Error('sign fault');
        if (fault === 'reject') return Promise.reject(new Error('sign fault'));
        if (fault === 'never') return gate;
        if (fault === 'unknown') return { code: 'E_FUTURE_RESULT' };
        return new Uint8Array(63);
      } });
      let stopping;
      let at;
      await a.client.onEvent((event) => { if (event.kind === 'MESSAGE_RECEIVED') { at = Date.now(); stopping = a.client.shutdown(); } });
      await b.client.send({ recipient: a.pub, payload: new Uint8Array([3]) });
      expect(await until(() => stopping !== undefined)).toBe(true);
      await stopping;
      expect(Date.now() - at).toBeLessThan(6500);
      expect(relays.flatMap((r) => r.events).filter((e) => e.kind === 4742)).toEqual([]);
      if (fault === 'unknown') {
        const discard = a.events.findIndex((e) => e.kind === 'INBOUND_DISCARDED' && e.code === 'E_SDK_UNKNOWN_CODE');
        expect(discard).toBeGreaterThanOrEqual(0);
        expect(a.events.findIndex((e) => e.clientState === 'STOPPED')).toBeGreaterThan(discard);
      }
      release(new Uint8Array(64));
      await sleep(5);
      expect(trace.some((e) => e.type === 'write' && e.closed)).toBe(false);
    }, 12000,
  );

  test('two relay copies recorded before the stop owe exactly one signed receipt', async () => {
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    let signs = 0;
    const { a, b, relays } = await setup({
      open: () => gate,
      sign: ({ digest }, key) => { signs += 1; return schnorr.sign(digest, key); },
    });
    let stopping;
    await a.client.onEvent((event) => { if (event.kind === 'MESSAGE_RECEIVED') stopping = a.client.shutdown(); });
    await b.client.send({ recipient: a.pub, payload: new Uint8Array([10]) });
    expect(await until(() => a.sockets.reduce((n, socket) => n + socket.inboundMessages, 0) === 2)).toBe(true);
    release({ plaintext: new Uint8Array([10]) });
    expect(await until(() => stopping !== undefined)).toBe(true);
    await stopping;
    expect(signs).toBe(1);
    expect(a.events.filter((e) => e.kind === 'MESSAGE_RECEIVED')).toHaveLength(1);
    expect(await until(() => relays.every((r) => r.events.filter((e) => e.kind === 4742).length === 1))).toBe(true);
  });

  test('no r tag owes no receipt', async () => {
    const { a, b, relays } = await setup();
    // Use a separate sender configured without r; its signature key remains valid.
    const c = makeClient(relays.map((r) => r.url), { receiptMode: 'RELAY_ACCEPTANCE_ONLY' });
    await start(c);
    let stopping;
    await a.client.onEvent((event) => { if (event.kind === 'MESSAGE_RECEIVED') stopping = a.client.shutdown(); });
    await c.client.send({ recipient: a.pub, payload: new Uint8Array([4]) });
    expect(await until(() => stopping !== undefined)).toBe(true);
    await stopping;
    expect(a.events.filter((e) => e.kind === 'MESSAGE_RECEIVED')).toHaveLength(1);
    expect(relays.flatMap((r) => r.events).filter((e) => e.kind === 4742)).toEqual([]);
  });

  test.each(['throw', 'reject', 'never', 'malformed', 'unknown'])(
    'model B publishDrain: %s', async (fault) => {
      jest.resetModules();
      let calls = 0;
      let forward;
      jest.unstable_mockModule('../../src/sdk/delivery/relay-pool.js', () => ({
        createRelaySet: () => ({
          start: async () => ({ connectedRelays: 1 }),
          onFrame: (listener) => { forward = listener; return () => {}; },
          freeze() {},
          dispose: async () => {},
          publishDrain: () => {
            calls += 1;
            if (fault === 'throw') throw new Error('publishDrain fault');
            if (fault === 'reject') return Promise.reject(new Error('publishDrain fault'));
            if (fault === 'never') return new Promise(() => {});
            if (fault === 'unknown') return { code: 'E_FUTURE_RESULT' };
            return { ok: true };
          },
        }),
      }));
      const module = await import('../../src/sdk/index.js');
      const relays = [await relay(), await relay()];
      const urls = relays.map((r) => r.url);
      const a = makeClient(urls, { factory: module.createStyxClient });
      const b = makeClient(urls);
      await a.client.onEvent((event) => a.events.push(event));
      expect((await a.client.start()).ok).toBe(true);
      await start(b);
      let stopping;
      let at;
      await a.client.onEvent((event) => { if (event.kind === 'MESSAGE_RECEIVED') { at = Date.now(); stopping = a.client.shutdown(); } });
      await b.client.send({ recipient: a.pub, payload: new Uint8Array([7]) });
      expect(await until(() => relays[0].events.some((e) => e.kind === 4741))).toBe(true);
      forward({ relayIndex: 0, relay: relays[0].url, data: ['EVENT', 'sub', relays[0].events.find((e) => e.kind === 4741)] });
      expect(await until(() => stopping !== undefined)).toBe(true);
      expect((await stopping).ok).toBe(true);
      expect(Date.now() - at).toBeLessThan(6500);
      expect(calls).toBe(1);
      expect(relays.flatMap((r) => r.events).filter((e) => e.kind === 4742)).toEqual([]);
      expect(a.events.filter((e) => e.kind === 'MESSAGE_RECEIVED')).toHaveLength(1);
      if (fault === 'unknown') {
        const discarded = a.events.findIndex((e) => e.code === 'E_SDK_UNKNOWN_CODE');
        expect(discarded).toBeGreaterThanOrEqual(0);
        expect(a.events.findIndex((e) => e.clientState === 'STOPPED')).toBeGreaterThan(discarded);
      }
    },
  );

  test('an open held at shutdown and later network frames owe nothing', async () => {
    let release;
    let opened = false;
    const gate = new Promise((resolve) => { release = resolve; });
    const { a, b, relays } = await setup({ open: () => { opened = true; return gate; } });
    await b.client.send({ recipient: a.pub, payload: new Uint8Array([5]) });
    expect(await until(() => opened)).toBe(true);
    const stopping = a.client.shutdown();
    release({ plaintext: new Uint8Array([5]) });
    await stopping;
    await b.client.send({ recipient: a.pub, payload: new Uint8Array([6]) });
    await sleep(10);
    expect(a.events.filter((e) => e.kind === 'MESSAGE_RECEIVED')).toEqual([]);
    expect(relays.flatMap((r) => r.events).filter((e) => e.kind === 4742)).toEqual([]);
  });
});
