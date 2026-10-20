// Tests of the early-lane SDK client (card I-SDK): the public surface of
// C-SDK, the configuration rules, the client state machine, start, send,
// getDelivery, cancel, events, the fail-closed result check and the orderly
// stop. Every relay is a loopback relay started inside this file with
// `WebSocketServer` on 127.0.0.1 and an ephemeral port; `ws` provides the
// global `WebSocket` for the test (C-DLV section 10).
import { describe, test, expect, beforeAll, afterAll, beforeEach, afterEach, jest } from '@jest/globals';
import { WebSocket, WebSocketServer } from 'ws';
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, utf8Encode } from '../../src/utils.js';
import * as sdk from '../../src/sdk/index.js';
import * as clientModule from '../../src/sdk/client.js';

const {
  SDK_INTERFACE_VERSION, SdkResultCode, DeliveryState, RelayOutcome, ClientState, SdkEventKind,
  isKnownResultCode, createStyxClient,
} = sdk;

const EIGHT_NAMES = [
  'SDK_INTERFACE_VERSION', 'SdkResultCode', 'DeliveryState', 'RelayOutcome', 'ClientState', 'SdkEventKind',
  'isKnownResultCode', 'createStyxClient',
];
const PER_RELAY_MS = 11000;
const PORT_CALL_MS = Math.floor(PER_RELAY_MS / 2);
const SEP = ':' + '/' + '/';

/* ------------------------------------------------------------------------- *
 * Harness: sockets, relays, clock, ports.
 * ------------------------------------------------------------------------- */

const socketLog = [];
const openedSockets = new Set();
let originalWebSocket;

/** The global WebSocket of the test: `ws`, with every client close recorded. */
class RecordingWebSocket extends WebSocket {
  constructor(...args) {
    super(...args);
    openedSockets.add(this);
    this.closeCalled = false;
  }

  close(...args) {
    this.closeCalled = true;
    socketLog.push({ type: 'close' });
    return super.close(...args);
  }
}

beforeAll(() => {
  originalWebSocket = globalThis.WebSocket;
  globalThis.WebSocket = RecordingWebSocket;
});

afterAll(() => {
  globalThis.WebSocket = originalWebSocket;
});

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const flushMicrotasks = async () => {
  for (let i = 0; i < 20; i += 1) await Promise.resolve();
};

async function waitFor(predicate, { clock = null, ms = 15000 } = {}) {
  const started = Date.now();
  while (!predicate()) {
    if (Date.now() - started > ms) throw new Error('waitFor: condition not reached');
    if (clock !== null) clock.advance(0);
    await sleep(10);
  }
}

let cleanups = [];
afterEach(async () => {
  const pending = cleanups.reverse();
  cleanups = [];
  for (const cleanup of pending) {
    try {
      await cleanup();
    } catch {
      // teardown continues
    }
  }
  openedSockets.clear();
  socketLog.length = 0;
});

function matchesFilter(filter, event) {
  if (Array.isArray(filter.kinds) && !filter.kinds.includes(event.kind)) return false;
  for (const key of Object.keys(filter)) {
    if (key[0] !== '#') continue;
    const values = filter[key];
    if (!event.tags.some((tag) => tag[0] === key.slice(1) && values.includes(tag[1]))) return false;
  }
  return true;
}

/**
 * A loopback relay: stores events, answers `OK`, serves `REQ` with `EOSE` and
 * pushes live events. `hung` accepts connections and never answers anything;
 * `rejectFor` answers `OK false` to events tagged for those keys; `holdFor`
 * never answers events tagged for those keys.
 */
async function startRelay({ hung = false, rejectFor = [], holdFor = [], port = 0 } = {}) {
  const server = new WebSocketServer({ host: '127.0.0.1', port });
  await new Promise((resolve) => server.once('listening', resolve));
  const relay = {
    url: `ws${SEP}127.0.0.1:${server.address().port}`,
    port: server.address().port,
    events: [],
    connections: 0,
    reqs: 0,
    kindCounts: new Map(),
    sockets: new Set(),
    closedByClient: 0,
  };
  const subscriptions = new Map();
  server.on('connection', (socket) => {
    relay.connections += 1;
    relay.sockets.add(socket);
    subscriptions.set(socket, new Map());
    socket.on('close', () => {
      relay.sockets.delete(socket);
      relay.closedByClient += 1;
      subscriptions.delete(socket);
    });
    socket.on('message', (raw) => {
      if (hung) return;
      let frame;
      try {
        frame = JSON.parse(String(raw));
      } catch {
        return;
      }
      if (frame[0] === 'EVENT') {
        const event = frame[1];
        relay.kindCounts.set(event.kind, (relay.kindCounts.get(event.kind) ?? 0) + 1);
        const tagged = event.tags.filter((tag) => tag[0] === 'p').map((tag) => tag[1]);
        if (tagged.some((key) => holdFor.includes(key))) return;
        if (tagged.some((key) => rejectFor.includes(key))) {
          socket.send(JSON.stringify(['OK', event.id, false, 'blocked: test']));
          return;
        }
        if (!relay.events.some((stored) => stored.id === event.id)) relay.events.push(event);
        socket.send(JSON.stringify(['OK', event.id, true, '']));
        for (const [peer, subs] of subscriptions) {
          for (const [id, filters] of subs) {
            if (filters.some((filter) => matchesFilter(filter, event))) {
              peer.send(JSON.stringify(['EVENT', id, event]));
            }
          }
        }
      } else if (frame[0] === 'REQ') {
        const [, id, ...filters] = frame;
        relay.reqs += 1;
        subscriptions.get(socket).set(id, filters);
        for (const event of relay.events) {
          if (filters.some((filter) => matchesFilter(filter, event))) {
            socket.send(JSON.stringify(['EVENT', id, event]));
          }
        }
        socket.send(JSON.stringify(['EOSE', id]));
      } else if (frame[0] === 'CLOSE') {
        subscriptions.get(socket)?.delete(frame[1]);
      }
    });
  });
  relay.waitForClientsClosed = async (ms = 5000) => {
    const started = Date.now();
    while (relay.sockets.size > 0 && Date.now() - started < ms) await sleep(10);
    // A socket still open at the bound is a failure of the caller's test, never a silent pass.
    if (relay.sockets.size > 0) throw new Error(`waitForClientsClosed: ${relay.sockets.size} socket(s) still open`);
  };
  relay.close = async () => {
    for (const socket of relay.sockets) socket.terminate();
    await new Promise((resolve) => server.close(() => resolve()));
  };
  cleanups.push(() => relay.close());
  return relay;
}

/** A loopback port with no listener: open a server, read its port, close it. */
async function freeLoopbackPort() {
  const server = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await new Promise((resolve) => server.once('listening', resolve));
  const port = server.address().port;
  await new Promise((resolve) => server.close(() => resolve()));
  return port;
}

/**
 * An injected clock with manual time. `clock` is the closed object handed to
 * the client; `advance(ms)` fires every due timer in order.
 */
function manualClock(log = []) {
  let now = 1700000000000;
  let sequence = 0;
  const timers = new Map();
  const clock = {
    now: () => now,
    setTimer: (callback, delayMs) => {
      sequence += 1;
      timers.set(sequence, { callback, at: now + Math.max(0, Number(delayMs) || 0) });
      log.push({ type: 'setTimer', id: sequence });
      return sequence;
    },
    clearTimer: (handle) => {
      log.push({ type: 'clearTimer', id: handle });
      timers.delete(handle);
    },
  };
  const advance = (ms) => {
    const target = now + ms;
    for (;;) {
      let nextId = null;
      let next = null;
      for (const [id, timer] of timers) {
        if (timer.at <= target && (next === null || timer.at < next.at)) {
          nextId = id;
          next = timer;
        }
      }
      if (next === null) break;
      timers.delete(nextId);
      now = Math.max(now, next.at);
      try {
        next.callback();
      } catch {
        // a callback fault is the module's concern
      }
    }
    now = target;
  };
  return { clock, advance, timers, log, get now() { return now; } };
}

function identityPort() {
  const secretKey = schnorr.utils.randomPrivateKey();
  const publicKey = bytesToHex(schnorr.getPublicKey(secretKey));
  const calls = { getPublicKey: 0, sign: 0, signThis: [] };
  const port = {
    getPublicKey() {
      calls.getPublicKey += 1;
      return publicKey;
    },
    sign({ digest }) {
      calls.sign += 1;
      calls.signThis.push(this);
      return schnorr.sign(digest, secretKey);
    },
  };
  return { port, publicKey, calls };
}

function sessionPort() {
  return {
    seal: ({ plaintext }) => ({ ciphertext: new Uint8Array(plaintext) }),
    open: ({ ciphertext }) => ({ plaintext: new Uint8Array(ciphertext) }),
  };
}

function storagePort() {
  const records = new Map();
  return {
    records,
    put: (record) => {
      records.set(record.deliveryId, record);
      return true;
    },
    get: (id) => records.get(id) ?? null,
    update: (id, record) => {
      if (!records.has(id)) return false;
      records.set(id, record);
      return true;
    },
    remove: (id) => records.delete(id),
    list: () => [...records.values()],
  };
}

function makeConfig({ relays, identity = identityPort().port, storage = storagePort(), session = sessionPort(),
  clock = undefined, random = undefined, delivery = { perRelayTimeoutMs: PER_RELAY_MS } } = {}) {
  const config = {
    interfaceVersion: SDK_INTERFACE_VERSION,
    relays,
    ports: { storage, session, identity },
  };
  if (clock !== undefined) config.clock = clock;
  if (random !== undefined) config.random = random;
  if (delivery !== undefined) config.delivery = delivery;
  return config;
}

function createClient(config) {
  const created = createStyxClient(config);
  expect(created.ok).toBe(true);
  const client = created.value;
  cleanups.push(() => client.shutdown());
  return client;
}

/** Start a client: wait until each relay has the subscription, then end the phase. */
async function startOnLoopback(client, manual, relays, { expectReqs = null } = {}) {
  const baseline = relays.map((relay) => relay.reqs);
  const started = client.start();
  await waitFor(() => relays.every((relay, i) => relay.reqs >= (expectReqs ?? baseline[i] + 1)));
  await sleep(20);
  manual.advance(PER_RELAY_MS);
  return started;
}

/** A started member with its own manual clock and recorded events. */
async function startMember(relays, { delivery = {}, identity = identityPort(), storage = storagePort(),
  session = sessionPort(), log = [] } = {}) {
  const manual = manualClock(log);
  const client = createClient(makeConfig({
    relays: relays.map((relay) => relay.url),
    identity: identity.port,
    storage,
    session,
    clock: manual.clock,
    delivery: { perRelayTimeoutMs: PER_RELAY_MS, ...delivery },
  }));
  const events = [];
  await client.onEvent((event) => events.push(event));
  const started = await startOnLoopback(client, manual, relays);
  expect(started).toEqual({ ok: true, value: { clientState: 'RUNNING', connectedRelays: relays.length } });
  return { client, manual, identity, storage, events };
}

const deliveryEvents = (events, id) => events.filter(
  (event) => event.kind === 'DELIVERY_STATE_CHANGED' && event.deliveryId === id,
);

/* ------------------------------------------------------------------------- *
 * Surface.
 * ------------------------------------------------------------------------- */

describe('surface', () => {
  test('index.js re-exports exactly the eight names, identical to client.js', () => {
    expect(Object.keys(sdk).sort()).toEqual([...EIGHT_NAMES].sort());
    expect(Object.keys(clientModule).sort()).toEqual([...EIGHT_NAMES].sort());
    for (const name of EIGHT_NAMES) expect(sdk[name]).toBe(clientModule[name]);
  });

  test('the interface version string', () => {
    expect(SDK_INTERFACE_VERSION).toBe('styx-m3-sdk/0.1.0-experimental');
  });

  test('the five enumerations are frozen, closed and self-mapped', () => {
    const expected = [
      [SdkResultCode, [
        'E_SDK_UNSUPPORTED_VERSION', 'E_SDK_INVALID_CONFIG', 'E_SDK_INVALID_ARGUMENT', 'E_SDK_PAYLOAD_TOO_LARGE',
        'E_SDK_NOT_STARTED', 'E_SDK_ALREADY_STARTED', 'E_SDK_CLIENT_STOPPED', 'E_SDK_STORAGE_NOT_EMPTY',
        'E_SDK_NO_RELAY_AVAILABLE', 'E_SDK_QUEUE_FULL', 'E_SDK_UNKNOWN_DELIVERY', 'E_SDK_DELIVERY_TERMINAL',
        'E_SDK_STORAGE_FAILED', 'E_SDK_SESSION_FAILED', 'E_SDK_IDENTITY_FAILED', 'E_SDK_INBOUND_INVALID',
        'E_SDK_INTERNAL', 'E_SDK_UNKNOWN_CODE',
      ]],
      [DeliveryState, [
        'QUEUED', 'IN_FLIGHT', 'RELAY_ACCEPTED_AWAITING_RECEIPT', 'RELAY_ACCEPTED', 'RECIPIENT_RECEIPT_RECEIVED',
        'FAILED_NOT_ACCEPTED', 'FAILED_NO_RECEIPT', 'CANCELLED', 'LOST_ON_SHUTDOWN',
      ]],
      [RelayOutcome, ['PENDING', 'ACCEPTED', 'REJECTED', 'TIMED_OUT', 'UNREACHABLE']],
      [ClientState, ['CREATED', 'RUNNING', 'STOPPED']],
      [SdkEventKind, ['CLIENT_STATE_CHANGED', 'DELIVERY_STATE_CHANGED', 'MESSAGE_RECEIVED', 'INBOUND_DISCARDED']],
    ];
    for (const [enumeration, members] of expected) {
      expect(Object.isFrozen(enumeration)).toBe(true);
      expect(Object.getPrototypeOf(enumeration)).toBe(Object.prototype);
      expect(Reflect.ownKeys(enumeration)).toEqual(members);
      for (const member of members) expect(enumeration[member]).toBe(member);
    }
  });

  test('isKnownResultCode', () => {
    for (const code of Object.keys(SdkResultCode)) expect(isKnownResultCode(code)).toBe(true);
    let trapCalls = 0;
    const trapping = new Proxy({}, new Proxy({}, {
      get() {
        trapCalls += 1;
        return () => {
          throw new Error('trap');
        };
      },
    }));
    for (const value of ['toString', '__proto__', 'constructor', 'hasOwnProperty', 'E_SDK_FOO', '', undefined, null,
      7, {}, Symbol('E_SDK_INTERNAL'), trapping, ['E_SDK_INTERNAL'], new String('E_SDK_INTERNAL')]) {
      expect(() => isKnownResultCode(value)).not.toThrow();
      expect(isKnownResultCode(value)).toBe(false);
    }
    expect(trapCalls).toBe(0);
  });
});

/* ------------------------------------------------------------------------- *
 * createStyxClient.
 * ------------------------------------------------------------------------- */

describe('createStyxClient', () => {
  const RELAY = `ws${SEP}127.0.0.1:7000`;
  const config = (overrides = {}) => ({ ...makeConfig({ relays: [RELAY] }), ...overrides });
  const code = (value) => createStyxClient(value).code;

  test('a valid configuration gives a frozen client in CREATED with exactly six methods', () => {
    const created = createStyxClient(config());
    expect(Object.isFrozen(created)).toBe(true);
    expect(created.ok).toBe(true);
    expect(Object.isFrozen(created.value)).toBe(true);
    expect(Reflect.ownKeys(created.value).sort()).toEqual(
      ['cancel', 'getDelivery', 'onEvent', 'send', 'shutdown', 'start'],
    );
  });

  test('the version is checked first, also with an unknown field', () => {
    expect(createStyxClient({ ...config(), interfaceVersion: 'styx-m3-sdk/0.0.0', bogus: 1 }))
      .toEqual({ ok: false, code: 'E_SDK_UNSUPPORTED_VERSION' });
    const absent = config();
    delete absent.interfaceVersion;
    expect(code(absent)).toBe('E_SDK_UNSUPPORTED_VERSION');
    expect(code({ ...config(), interfaceVersion: 7 })).toBe('E_SDK_UNSUPPORTED_VERSION');
  });

  test('non-plain configurations are E_SDK_INVALID_CONFIG', () => {
    class Holder {
      constructor() {
        Object.assign(this, config());
      }
    }
    const throwing = new Proxy(config(), {
      getPrototypeOf() { throw new Error('trap'); },
      ownKeys() { throw new Error('trap'); },
      getOwnPropertyDescriptor() { throw new Error('trap'); },
      get() { throw new Error('trap'); },
    });
    for (const value of [undefined, null, 1, 'config', [], () => {}, new Holder(), throwing]) {
      expect(createStyxClient(value)).toEqual({ ok: false, code: 'E_SDK_INVALID_CONFIG' });
    }
  });

  test('a getter during validation is E_SDK_INVALID_CONFIG', () => {
    const withGetter = config();
    Object.defineProperty(withGetter, 'relays', { get: () => [RELAY], enumerable: true });
    expect(code(withGetter)).toBe('E_SDK_INVALID_CONFIG');
    const versionGetter = config();
    Object.defineProperty(versionGetter, 'interfaceVersion', { get: () => SDK_INTERFACE_VERSION, enumerable: true });
    expect(code(versionGetter)).toBe('E_SDK_INVALID_CONFIG');
  });

  test('each configuration value is read once, as a data value; a port-method getter is never invoked', () => {
    const reads = new Map();
    const counted = (target) => new Proxy(target, {
      getOwnPropertyDescriptor(object, key) {
        reads.set(key, (reads.get(key) ?? 0) + 1);
        return Reflect.getOwnPropertyDescriptor(object, key);
      },
    });
    expect(createStyxClient(counted(config())).ok).toBe(true);
    for (const key of ['interfaceVersion', 'relays', 'ports']) expect(reads.get(key)).toBe(1);

    let getterCalls = 0;
    for (const [port, method] of [['storage', 'list'], ['session', 'open'], ['identity', 'getPublicKey']]) {
      const own = config();
      Object.defineProperty(own.ports[port], method, {
        enumerable: true,
        get: () => { getterCalls += 1; return () => undefined; },
      });
      expect(code(own)).toBe('E_SDK_INVALID_CONFIG');
      const inherited = config();
      const proto = {};
      Object.defineProperty(proto, method, { get: () => { getterCalls += 1; return () => undefined; } });
      const holder = Object.create(proto);
      for (const [name, fn] of Object.entries(inherited.ports[port])) {
        if (name !== method) holder[name] = fn;
      }
      inherited.ports[port] = holder;
      expect(code(inherited)).toBe('E_SDK_INVALID_CONFIG');
    }
    expect(getterCalls).toBe(0);
  });

  test('a Proxy trap that throws at any later step of validation is E_SDK_INVALID_CONFIG', () => {
    const traps = ['ownKeys', 'getOwnPropertyDescriptor', 'getPrototypeOf'];
    const throwingAfter = (target, trap, after, state) => new Proxy(target, {
      [trap](...args) {
        state.calls += 1;
        if (state.calls > after) {
          state.threw = true;
          throw new Error('trap');
        }
        return Reflect[trap](...args);
      },
    });
    // A trap that throws at its (after + 1)-th call: whenever it did throw, the result is
    // E_SDK_INVALID_CONFIG, never success; a trap reached fewer times leaves a valid configuration.
    const check = (build) => {
      let threwOnce = false;
      for (const after of [0, 1, 2, 3]) {
        const state = { calls: 0, threw: false };
        const result = createStyxClient(build(after, state));
        if (state.threw) {
          threwOnce = true;
          expect(result).toEqual({ ok: false, code: 'E_SDK_INVALID_CONFIG' });
        } else {
          expect(result.ok).toBe(true);
        }
      }
      expect(threwOnce).toBe(true);
    };
    for (const trap of traps) {
      check((after, state) => throwingAfter(config(), trap, after, state));
      check((after, state) => {
        const c = config();
        c.ports = throwingAfter(c.ports, trap, after, state);
        return c;
      });
      check((after, state) => {
        const d = config({ delivery: { maxAttempts: 5 } });
        d.delivery = throwingAfter(d.delivery, trap, after, state);
        return d;
      });
    }
    check((after, state) => {
      const p = config();
      p.ports.session = throwingAfter(sessionPort(), 'getOwnPropertyDescriptor', after, state);
      return p;
    });
  });

  test('required fields', () => {
    for (const field of ['relays', 'ports']) {
      const missing = config();
      delete missing[field];
      expect(code(missing)).toBe('E_SDK_INVALID_CONFIG');
    }
  });

  test('an unknown non-enumerable key and an own symbol key are rejected on every closed object', () => {
    const manual = manualClock();
    const holders = [
      (c) => c,
      (c) => c.ports,
      (c) => c.clock,
      (c) => c.random,
      (c) => c.delivery,
    ];
    for (const holderOf of holders) {
      for (const add of [
        (holder) => Object.defineProperty(holder, 'hidden', { value: 1, enumerable: false }),
        (holder) => { holder[Symbol('extra')] = 1; },
        (holder) => { holder.extra = 1; },
      ]) {
        const c = config({
          clock: { ...manual.clock },
          random: { nextUint32: () => 1 },
          delivery: { maxAttempts: 5 },
        });
        expect(createStyxClient(c).ok).toBe(true);
        add(holderOf(c));
        expect(code(c)).toBe('E_SDK_INVALID_CONFIG');
      }
    }
  });

  test('ports: each one an object or function exposing every method', () => {
    for (const [port, method] of [['storage', 'put'], ['storage', 'get'], ['storage', 'update'],
      ['storage', 'remove'], ['storage', 'list'], ['session', 'seal'], ['session', 'open'],
      ['identity', 'getPublicKey'], ['identity', 'sign']]) {
      const c = config();
      c.ports[port] = { ...c.ports[port], [method]: 'not a function' };
      expect(code(c)).toBe('E_SDK_INVALID_CONFIG');
    }
    for (const value of [null, undefined, 1, 'port']) {
      const c = config();
      c.ports.session = value;
      expect(code(c)).toBe('E_SDK_INVALID_CONFIG');
    }
    const functionPort = config();
    const sealFn = Object.assign(() => {}, sessionPort());
    functionPort.ports.session = sealFn;
    expect(createStyxClient(functionPort).ok).toBe(true);
    const inherited = config();
    inherited.ports.storage = Object.create(storagePort());
    expect(createStyxClient(inherited).ok).toBe(true);
    const missing = config();
    delete missing.ports.identity;
    expect(code(missing)).toBe('E_SDK_INVALID_CONFIG');
  });

  test('clock and random', () => {
    const manual = manualClock();
    expect(createStyxClient(config({ clock: manual.clock })).ok).toBe(true);
    expect(code(config({ clock: { now: () => 1, setTimer: () => 1 } }))).toBe('E_SDK_INVALID_CONFIG');
    expect(code(config({ clock: { ...manual.clock, now: 1 } }))).toBe('E_SDK_INVALID_CONFIG');
    expect(code(config({ clock: null }))).toBe('E_SDK_INVALID_CONFIG');
    expect(createStyxClient(config({ random: { nextUint32: () => 1 } })).ok).toBe(true);
    expect(code(config({ random: { nextUint32: 1 } }))).toBe('E_SDK_INVALID_CONFIG');
    expect(code(config({ random: {} }))).toBe('E_SDK_INVALID_CONFIG');
  });

  test('delivery fields: bounds, types and receipt mode', () => {
    const bounds = { maxAttempts: [1, 10], deadlineMs: [30000, 600000], perRelayTimeoutMs: [11000, 30000] };
    for (const [field, [minimum, maximum]] of Object.entries(bounds)) {
      for (const value of [minimum, maximum]) {
        expect(createStyxClient(config({ delivery: { [field]: value } })).ok).toBe(true);
      }
      for (const value of [minimum - 1, maximum + 1, 0, -1, 1.5, NaN, Infinity, String(minimum)]) {
        expect(code(config({ delivery: { [field]: value } }))).toBe('E_SDK_INVALID_CONFIG');
      }
    }
    expect(createStyxClient(config({ delivery: {} })).ok).toBe(true);
    expect(createStyxClient(config({ delivery: { receiptMode: 'RECIPIENT_RECEIPT' } })).ok).toBe(true);
    expect(createStyxClient(config({ delivery: { receiptMode: 'RELAY_ACCEPTANCE_ONLY' } })).ok).toBe(true);
    for (const mode of ['recipient_receipt', 'NONE', null, 1]) {
      expect(code(config({ delivery: { receiptMode: mode } }))).toBe('E_SDK_INVALID_CONFIG');
    }
  });

  test('relay count: 0, 1, 16, 17 and a duplicate', () => {
    const relays = (n) => Array.from({ length: n }, (_, i) => `ws${SEP}127.0.0.1:${7000 + i}`);
    expect(code(config({ relays: [] }))).toBe('E_SDK_INVALID_CONFIG');
    expect(createStyxClient(config({ relays: relays(1) })).ok).toBe(true);
    expect(createStyxClient(config({ relays: relays(16) })).ok).toBe(true);
    expect(code(config({ relays: relays(17) }))).toBe('E_SDK_INVALID_CONFIG');
    expect(code(config({ relays: [RELAY, RELAY] }))).toBe('E_SDK_INVALID_CONFIG');
    expect(code(config({ relays: RELAY }))).toBe('E_SDK_INVALID_CONFIG');
    expect(code(config({ relays: [RELAY, 7] }))).toBe('E_SDK_INVALID_CONFIG');
    expect(code(config({ relays: [RELAY, , `ws${SEP}127.0.0.2`] }))).toBe('E_SDK_INVALID_CONFIG');
  });

  test('relay strings accepted', () => {
    const accepted = [
      `ws${SEP}127.0.0.1:7000`, `wss${SEP}127.255.255.254/x?y=1`, `WS${SEP}127.0.0.1`, `ws${SEP}127.0.0.1:080`,
      `ws${SEP}127.0.0.1:`, `ws${SEP}[::1]:1`, `ws${SEP}[0:0:0:0:0:0:0:1]`, `ws${SEP}[::0001]/`,
      `ws${SEP}[::0.0.0.1]`, `wSs${SEP}127.0.0.1/a/b%20c?q=1&r=%2F`, `ws${SEP}127.0.0.1:99999`,
    ];
    for (const url of accepted) {
      expect([url, createStyxClient(config({ relays: [url] })).ok]).toEqual([url, true]);
    }
  });

  test('relay strings rejected (non-loopback hosts are assembled at run time)', () => {
    const ws = (host) => ['ws', SEP, host].join('');
    const rejected = [
      ws('localhost'), ws('128.0.0.1'), ws('10.0.0.1'), ws('127.0.0.01'), ws('127.1'),
      ws('[::ffff:127.0.0.1]'), ws('[v1.x]'), ws('[::1%25lo]'), ws(['u', '@', '127.0.0.1'].join('')),
      ws('127.0.0.1#f'), ws('127.0.0.1/%zz'), ws('127.0.0.1/%2'), ws('127.0.0.1/a b'), ws('127.0.0.1/a\\b'),
      ['http', SEP, '127.0.0.1'].join(''), '', ws(''), ws('[::2]'), ws('[1::1]'), ws('[::1'),
      ws('127.0.0.1:x'), ws('127.0.0.1 '), ['ws', ':', '127.0.0.1'].join(''), ws('256.0.0.1'),
      ws('[::1:2:3:4:5:6:7:8]'), ws('[::1]x'),
    ];
    for (const url of rejected) {
      expect([url, code(config({ relays: [url] }))]).toEqual([url, 'E_SDK_INVALID_CONFIG']);
    }
  });

  test('no port, clock or random function is called', () => {
    const calls = [];
    const spy = (name) => (...args) => {
      calls.push(name);
      return args;
    };
    const ports = {
      storage: { put: spy('put'), get: spy('get'), update: spy('update'), remove: spy('remove'), list: spy('list') },
      session: { seal: spy('seal'), open: spy('open') },
      identity: { getPublicKey: spy('getPublicKey'), sign: spy('sign') },
    };
    const created = createStyxClient({
      interfaceVersion: SDK_INTERFACE_VERSION,
      relays: [RELAY],
      ports,
      clock: { now: spy('now'), setTimer: spy('setTimer'), clearTimer: spy('clearTimer') },
      random: { nextUint32: spy('nextUint32') },
    });
    expect(created.ok).toBe(true);
    expect(calls).toEqual([]);
  });

  test('later changes to config, its relays and its ports holder change nothing the client uses', async () => {
    const relay = await startRelay();
    const other = await startRelay();
    const manual = manualClock();
    const identity = identityPort();
    const session = sessionPort();
    let replacedSessionCalls = 0;
    const c = makeConfig({
      relays: [relay.url], identity: identity.port, session, clock: manual.clock,
      delivery: { perRelayTimeoutMs: PER_RELAY_MS, maxAttempts: 2 },
    });
    const client = createClient(c);
    c.relays[0] = other.url;
    c.delivery.maxAttempts = 9;
    c.ports.session = { seal: () => { replacedSessionCalls += 1; }, open: () => { replacedSessionCalls += 1; } };
    const started = await startOnLoopback(client, manual, [relay]);
    expect(started.ok).toBe(true);
    expect(other.connections).toBe(0);
    const sent = await client.send({ recipient: identity.publicKey, payload: new Uint8Array([1]) });
    expect(sent.ok).toBe(true);
    expect(replacedSessionCalls).toBe(0);
    const snapshot = await client.getDelivery({ deliveryId: sent.value.deliveryId });
    expect(snapshot.ok).toBe(true);
    // The delivery values are the ones of the call: maxAttempts stays 2.
    const rejecting = await startRelay({ rejectFor: [identity.publicKey] });
    const manual2 = manualClock();
    const c2 = makeConfig({
      relays: [rejecting.url], identity: identity.port, clock: manual2.clock,
      delivery: { perRelayTimeoutMs: PER_RELAY_MS, maxAttempts: 2 },
    });
    const client2 = createClient(c2);
    c2.delivery.maxAttempts = 9;
    expect((await startOnLoopback(client2, manual2, [rejecting])).ok).toBe(true);
    const failed = await client2.send({ recipient: identity.publicKey, payload: new Uint8Array([2]) });
    for (let i = 0; i < 40; i += 1) {
      manual2.advance(40000);
      await sleep(10);
      const s = await client2.getDelivery({ deliveryId: failed.value.deliveryId });
      if (s.value.terminal) break;
    }
    const final = await client2.getDelivery({ deliveryId: failed.value.deliveryId });
    expect(final.value.state).toBe('FAILED_NOT_ACCEPTED');
    expect(final.value.attempts).toBe(2);
  }, 30000);
});

/* ------------------------------------------------------------------------- *
 * The counterexamples of the round-3 review (third correction cycle). Only the
 * relay set, and in one case the outbox, is a double; the other lane modules
 * are the real ones. They run before the doubles below, whose module mocks
 * stay registered for the rest of the file.
 * ------------------------------------------------------------------------- */

/* --- review probes r1 to r4, real lane modules (cycle 4) --- */
describe('review probe r1: probe-relay-results (regression)', () => {

  const VERSION = 'styx-m3-sdk/0.1.0-experimental';

  function config() {
    const records = new Map();
    return {
      interfaceVersion: VERSION,
      relays: ['ws://127.0.0.1:7000'],
      ports: {
        storage: {
          put(record) {
            records.set(record.deliveryId, record);
            return true;
          },
          get(id) {
            return records.get(id) ?? null;
          },
          update(id, record) {
            records.set(id, record);
            return true;
          },
          remove(id) {
            return records.delete(id);
          },
          list() {
            return [...records.values()];
          },
        },
        session: {
          seal({ plaintext }) {
            return { ciphertext: new Uint8Array(plaintext) };
          },
          open({ ciphertext }) {
            return { plaintext: new Uint8Array(ciphertext) };
          },
        },
        identity: {
          getPublicKey() {
            return 'a'.repeat(64);
          },
          sign() {
            return new Uint8Array(64);
          },
        },
      },
    };
  }

  function unknownAttempt(event) {
    let acceptGate = null;
    let latePublishGate = null;
    const attempt = {
      index: 1,
      event,
      outcomes: Object.freeze(['ACCEPTED']),
      publishedOnce: Object.freeze([true]),
      acceptedIndex: 0,
      isSettled: () => true,
      onOutcome(listener) {
        listener(0, 'ACCEPTED');
        return () => {};
      },
      onSettled(listener) {
        listener();
        return () => {};
      },
      ignoreAcks() {},
      get acceptGate() {
        return acceptGate;
      },
      set acceptGate(value) {
        acceptGate = value;
      },
      get latePublishGate() {
        return latePublishGate;
      },
      set latePublishGate(value) {
        latePublishGate = value;
      },
      code: 'E_SDK_NEW',
    };
    Object.setPrototypeOf(attempt, null);
    return Object.freeze(attempt);
  }

  async function loadClient(startResult = { connectedRelays: 1 }) {
    jest.resetModules();
    jest.unstable_mockModule('../../src/sdk/delivery/relay-pool.js', () => ({
      createRelaySet: () => ({
        start: async () => startResult,
        onFrame: () => () => {},
        publish: unknownAttempt,
        freeze() {},
        dispose: async () => undefined,
      }),
    }));
    return import('../../src/sdk/client.js');
  }

  test('an unknown closed slot on a relay attempt cannot yield acceptance', async () => {
    const { createStyxClient } = await loadClient();
    const created = createStyxClient(config());
    expect(created.ok).toBe(true);
    const client = created.value;

    try {
      expect((await client.start()).ok).toBe(true);
      const sent = await client.send({
        recipient: 'b'.repeat(64),
        payload: new Uint8Array([1]),
      });
      expect(sent.ok).toBe(true);

      for (let turn = 0; turn < 100; turn += 1) await Promise.resolve();

      const snapshot = await client.getDelivery({
        deliveryId: sent.value.deliveryId,
      });
      expect(snapshot.ok).toBe(true);

      // Expected at this head: RELAY_ACCEPTED, lastCode null.
      expect(snapshot.value).toMatchObject({
        state: 'FAILED_NOT_ACCEPTED',
        terminal: true,
        lastCode: 'E_SDK_UNKNOWN_CODE',
      });
    } finally {
      await client.shutdown();
    }
  });

  test('an unknown slot on relaySet.start precedes its malformed shape', async () => {
    const { createStyxClient } = await loadClient({
      connectedRelays: 1,
      code: 'E_SDK_NEW',
    });
    const created = createStyxClient(config());
    expect(created.ok).toBe(true);
    const client = created.value;

    try {
      // Expected at this head: E_SDK_NO_RELAY_AVAILABLE.
      expect(await client.start()).toEqual({
        ok: false,
        code: 'E_SDK_UNKNOWN_CODE',
      });
    } finally {
      await client.shutdown();
    }
  });
});

describe('review probe r1: probe-stop-reentrancy (regression)', () => {
  const { createStyxClient, SDK_INTERFACE_VERSION } = sdk;


  const PER_RELAY_MS = 11000;
  const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  async function until(predicate) {
    const end = Date.now() + 5000;
    while (!predicate()) {
      if (Date.now() >= end) throw new Error('Probe condition timed out');
      await pause(1);
    }
  }

  function makePorts() {
    const records = new Map();
    return {
      storage: {
        put(record) {
          records.set(record.deliveryId, record);
          return true;
        },
        get(id) {
          return records.get(id) ?? null;
        },
        update(id, record) {
          records.set(id, record);
          return true;
        },
        remove(id) {
          return records.delete(id);
        },
        list() {
          return [...records.values()];
        },
      },
      session: {
        seal({ plaintext }) {
          return { ciphertext: new Uint8Array(plaintext) };
        },
        open({ ciphertext }) {
          return { plaintext: new Uint8Array(ciphertext) };
        },
      },
      identity: {
        getPublicKey() {
          return 'a'.repeat(64);
        },
        sign() {
          return new Uint8Array(64);
        },
      },
    };
  }

  async function withRelay(body) {
    const server = new WebSocketServer({ host: '127.0.0.1', port: 0 });
    await new Promise((resolve, reject) => {
      server.once('listening', resolve);
      server.once('error', reject);
    });

    const previousWebSocket = globalThis.WebSocket;
    const sockets = [];
    const timers = new Set();
    const context = {
      stopCalled: false,
      stopPromise: null,
      connectionsAfterStop: 0,
      publicationsAfterStop: 0,
      phaseTimer: null,
      onArm: () => {},
      client: null,
    };

    class ObservedWebSocket extends WebSocket {
      constructor(...args) {
        super(...args);
        this.on('error', () => {});
        sockets.push(this);
        if (context.stopCalled) context.connectionsAfterStop += 1;
      }

      send(data, ...args) {
        const frame = JSON.parse(String(data));
        if (context.stopCalled && frame[0] === 'EVENT') {
          context.publicationsAfterStop += 1;
        }
        return super.send(data, ...args);
      }
    }

    globalThis.WebSocket = ObservedWebSocket;

    const clock = {
      now: () => 1700000000000,
      setTimer(callback, delayMs) {
        const handle = { callback, delayMs };
        timers.add(handle);
        if (delayMs === PER_RELAY_MS && context.phaseTimer === null) {
          context.phaseTimer = handle;
        }
        context.onArm(delayMs);
        return handle;
      },
      clearTimer(handle) {
        timers.delete(handle);
      },
    };

    const created = createStyxClient({
      interfaceVersion: SDK_INTERFACE_VERSION,
      relays: [`ws://127.0.0.1:${server.address().port}`],
      ports: makePorts(),
      clock,
      delivery: { perRelayTimeoutMs: PER_RELAY_MS },
    });
    expect(created.ok).toBe(true);
    context.client = created.value;

    context.stop = () => {
      if (context.stopPromise !== null) return;
      context.stopCalled = true;
      context.stopPromise = context.client.shutdown();
    };

    context.startNormally = async () => {
      const starting = context.client.start();
      await until(() => context.phaseTimer !== null);
      await until(() => sockets.some((socket) => socket.readyState === WebSocket.OPEN));
      await pause(0);
      context.phaseTimer.callback();
      expect(await starting).toEqual({
        ok: true,
        value: { clientState: 'RUNNING', connectedRelays: 1 },
      });
    };

    try {
      await body(context);
    } finally {
      if (context.stopPromise !== null) {
        await context.stopPromise;
      } else {
        await context.client.shutdown();
      }
      for (const socket of sockets) {
        if (socket.readyState !== WebSocket.CLOSED) socket.terminate();
      }
      for (const socket of server.clients) socket.terminate();
      await new Promise((resolve) => server.close(resolve));
      globalThis.WebSocket = previousWebSocket;
    }
  }

  test('no connection starts after shutdown reenters phase-timer arming', async () => {
    await withRelay(async (context) => {
      context.onArm = (delayMs) => {
        if (delayMs === PER_RELAY_MS) context.stop();
      };

      const starting = context.client.start();
      await until(() => context.phaseTimer !== null);
      context.phaseTimer.callback();

      expect(await starting).toEqual({
        ok: false,
        code: 'E_SDK_CLIENT_STOPPED',
      });
      await context.stopPromise;

      // Expected at this head: received 1.
      expect(context.connectionsAfterStop).toBe(0);
    });
  }, 20000);

  test('no publication follows shutdown reentering attempt-timer arming', async () => {
    await withRelay(async (context) => {
      await context.startNormally();
      context.onArm = (delayMs) => {
        if (delayMs === PER_RELAY_MS) context.stop();
      };

      const sending = context.client.send({
        recipient: 'b'.repeat(64),
        payload: new Uint8Array([1]),
      });
      await until(() => context.stopPromise !== null);
      await sending;
      await context.stopPromise;

      // Expected at this head: received 1.
      expect(context.publicationsAfterStop).toBe(0);
    });
  }, 20000);

  test('identity lookup cannot invoke a method after its getter stops the client', async () => {
    const ports = makePorts();
    const created = createStyxClient({
      interfaceVersion: SDK_INTERFACE_VERSION,
      relays: ['ws://127.0.0.1:7000'],
      ports,
      delivery: { perRelayTimeoutMs: PER_RELAY_MS },
    });
    expect(created.ok).toBe(true);

    const client = created.value;
    let stopping = null;
    let invocations = 0;

    // Installed after validation: port objects must remain live references.
    Object.defineProperty(ports.identity, 'getPublicKey', {
      configurable: true,
      get() {
        stopping = client.shutdown();
        return function getPublicKey() {
          invocations += 1;
          return 'a'.repeat(64);
        };
      },
    });

    try {
      expect(await client.start()).toEqual({
        ok: false,
        code: 'E_SDK_CLIENT_STOPPED',
      });
      expect(stopping).not.toBeNull();
      await stopping;

      // Expected at this head: received 1.
      expect(invocations).toBe(0);
    } finally {
      if (stopping !== null) await stopping;
      else await client.shutdown();
    }
  });
});

describe('review probe r2: probe-r2-attempt-validation (regression)', () => {

  function config() {
    const records = new Map();
    return {
      interfaceVersion: 'styx-m3-sdk/0.1.0-experimental',
      relays: ['ws://127.0.0.1:7000'],
      ports: {
        storage: {
          put(record) {
            records.set(record.deliveryId, record);
            return true;
          },
          get(id) {
            return records.get(id) ?? null;
          },
          update(id, record) {
            records.set(id, record);
            return true;
          },
          remove(id) {
            return records.delete(id);
          },
          list() {
            return [...records.values()];
          },
        },
        session: {
          seal: ({ plaintext }) => ({
            ciphertext: new Uint8Array(plaintext),
          }),
          open: ({ ciphertext }) => ({
            plaintext: new Uint8Array(ciphertext),
          }),
        },
        identity: {
          getPublicKey: () => 'a'.repeat(64),
          sign: () => new Uint8Array(64),
        },
      },
    };
  }

  function acceptingAttempt(event, mode) {
    let acceptGate = null;
    let latePublishGate = null;

    const onOutcome = (listener) => {
      listener(0, 'ACCEPTED');
      return () => undefined;
    };
    if (mode === 'callable-code') {
      Object.defineProperty(onOutcome, 'code', {
        value: 'E_SDK_NEW',
        enumerable: false,
      });
    }

    let outcomes = ['ACCEPTED'];
    if (mode === 'extra-and-outcome') outcomes = ['UNLISTED_OUTCOME'];
    if (mode === 'length-and-outcome') {
      outcomes = ['ACCEPTED', 'UNLISTED_OUTCOME'];
    }

    const attempt = {
      index: mode === 'bad-index' ? 'not-an-index' : 1,
      event,
      outcomes: Object.freeze(outcomes),
      publishedOnce: Object.freeze([true]),
      get acceptedIndex() {
        return 0;
      },
      isSettled: () => true,
      onOutcome,
      onSettled(listener) {
        listener();
        return () => undefined;
      },
      ignoreAcks() {},
      get acceptGate() {
        return acceptGate;
      },
      set acceptGate(value) {
        acceptGate = value;
      },
      get latePublishGate() {
        return latePublishGate;
      },
      set latePublishGate(value) {
        latePublishGate = value;
      },
    };

    if (mode === 'extra-and-outcome') attempt.extra = 1;
    Object.setPrototypeOf(attempt, null);
    return Object.freeze(attempt);
  }

  test.each([
    ['valid control', 'valid', null],
    ['unknown code on callable member', 'callable-code', 'E_SDK_UNKNOWN_CODE'],
    ['extra key hides unknown outcome', 'extra-and-outcome', 'E_SDK_UNKNOWN_CODE'],
    ['wrong length hides unknown outcome', 'length-and-outcome', 'E_SDK_UNKNOWN_CODE'],
    ['invalid index is malformed', 'bad-index', 'E_SDK_INTERNAL'],
  ])('%s', async (_title, mode, expectedCode) => {
    jest.resetModules();
    jest.unstable_mockModule('../../src/sdk/delivery/relay-pool.js', () => ({
      createRelaySet: () => ({
        start: async () => ({ connectedRelays: 1 }),
        onFrame: () => () => undefined,
        publish: (event) => acceptingAttempt(event, mode),
        freeze() {},
        dispose: async () => undefined,
      }),
    }));

    // The outbox and inbound processor are real.
    const { createStyxClient } = await import('../../src/sdk/client.js');
    const created = createStyxClient(config());
    expect(created.ok).toBe(true);
    const client = created.value;

    try {
      expect((await client.start()).ok).toBe(true);
      const sent = await client.send({
        recipient: 'b'.repeat(64),
        payload: new Uint8Array([1]),
      });
      expect(sent.ok).toBe(true);

      for (let turn = 0; turn < 100; turn += 1) await Promise.resolve();

      const snapshot = await client.getDelivery({
        deliveryId: sent.value.deliveryId,
      });
      expect(snapshot.ok).toBe(true);

      expect(snapshot.value).toMatchObject(
        expectedCode === null
          ? {
              state: 'RELAY_ACCEPTED',
              terminal: true,
              lastCode: null,
            }
          : {
              state: 'FAILED_NOT_ACCEPTED',
              terminal: true,
              lastCode: expectedCode,
            },
      );
    } finally {
      await client.shutdown();
    }
  });
});

describe('review probe r3: probe-r3-inbound-drain (regression)', () => {

  test('shutdown waits for an open that synchronously initiated the stop', async () => {
    jest.resetModules();

    let inbound = null;
    jest.unstable_mockModule('../../src/sdk/delivery/relay-pool.js', () => ({
      createRelaySet: () => ({
        start: async () => ({ connectedRelays: 1 }),
        onFrame(listener) {
          inbound = listener;
          return () => undefined;
        },
        freeze() {},
        dispose: async () => undefined,
      }),
    }));

    const { createStyxClient } = await import('../../src/sdk/client.js');
    const owner = 'a'.repeat(64);

    let releaseOpen;
    const heldOpen = new Promise((resolve) => {
      releaseOpen = resolve;
    });

    let client;
    let opened = false;
    let stopping = null;
    let stopResolved = false;

    const created = createStyxClient({
      interfaceVersion: 'styx-m3-sdk/0.1.0-experimental',
      relays: ['ws://127.0.0.1:7000'],
      delivery: { perRelayTimeoutMs: 11000 },
      ports: {
        storage: {
          put: () => true,
          get: () => null,
          update: () => true,
          remove: () => true,
          list: () => [],
        },
        session: {
          seal: ({ plaintext }) => ({ ciphertext: plaintext }),
          open() {
            opened = true;
            stopping = client.shutdown().then((result) => {
              stopResolved = true;
              return result;
            });
            return heldOpen;
          },
        },
        identity: {
          getPublicKey: () => owner,
          sign: () => new Uint8Array(64),
        },
      },
    });

    expect(created.ok).toBe(true);
    client = created.value;

    try {
      expect((await client.start()).ok).toBe(true);

      const secret = new Uint8Array(32);
      secret[31] = 1;
      const pubkey = bytesToHex(schnorr.getPublicKey(secret));
      const createdAt = 12;
      const kind = 4741;
      const tags = [
        ['p', owner],
        ['v', 'styx-m3-sdk/0.1.0-experimental'],
        ['n', '0'.repeat(32)],
      ];
      const content = 'AQ==';
      const id = bytesToHex(sha256(utf8Encode(JSON.stringify([
        0, pubkey, createdAt, kind, tags, content,
      ]))));
      const event = {
        id,
        pubkey,
        created_at: createdAt,
        kind,
        tags,
        content,
        sig: bytesToHex(schnorr.sign(hexToBytes(id), secret)),
      };

      inbound({
        relayIndex: 0,
        relay: 'ws://127.0.0.1:7000',
        data: ['EVENT', 'sub', event],
      });

      for (let turn = 0; turn < 200; turn += 1) {
        await Promise.resolve();
      }

      expect(opened).toBe(true);
      expect(stopping).not.toBeNull();

      // Predicted at this head: true, while heldOpen remains unresolved.
      expect(stopResolved).toBe(false);
    } finally {
      releaseOpen({ plaintext: new Uint8Array([7]) });
      if (stopping !== null) await stopping;
      else await client.shutdown();
    }
  });
});

describe('review probe r3: probe-r3-unknown-precedence, real lanes (regression)', () => {

  const ok = (value) => Object.freeze({
    ok: true,
    value: Object.freeze(value),
  });

  function config() {
    const records = new Map();
    return {
      interfaceVersion: 'styx-m3-sdk/0.1.0-experimental',
      relays: [
        'ws://127.0.0.1:7000',
        'ws://127.0.0.1:7001',
      ],
      delivery: { perRelayTimeoutMs: 11000 },
      ports: {
        storage: {
          put(record) {
            records.set(record.deliveryId, record);
            return true;
          },
          get: (id) => records.get(id) ?? null,
          update(id, record) {
            records.set(id, record);
            return true;
          },
          remove: (id) => records.delete(id),
          list: () => [...records.values()],
        },
        session: {
          seal: ({ plaintext }) => ({
            ciphertext: new Uint8Array(plaintext),
          }),
          open: ({ ciphertext }) => ({
            plaintext: new Uint8Array(ciphertext),
          }),
        },
        identity: {
          getPublicKey: () => 'a'.repeat(64),
          sign: () => new Uint8Array(64),
        },
      },
    };
  }

  function attemptFor(event, mode) {
    if (mode === 'callable-root') {
      return Object.freeze(Object.assign(
        () => undefined,
        { code: 'E_SDK_NEW' },
      ));
    }

    let acceptGate = null;
    let latePublishGate = null;
    const valid = mode === 'valid';

    const outcomes = valid
      ? Object.freeze(['ACCEPTED', 'ACCEPTED'])
      : new Proxy(Object.freeze(['PENDING', 'UNLISTED_OUTCOME']), {
        getOwnPropertyDescriptor(target, key) {
          if (key === '0') throw new Error('unreadable first descriptor');
          return Reflect.getOwnPropertyDescriptor(target, key);
        },
      });

    const attempt = {
      index: 1,
      event,
      outcomes,
      publishedOnce: Object.freeze([valid, valid]),
      get acceptedIndex() {
        return valid ? 0 : -1;
      },
      isSettled: () => valid,
      onOutcome(listener) {
        if (valid) {
          listener(0, 'ACCEPTED');
          listener(1, 'ACCEPTED');
        }
        return () => undefined;
      },
      onSettled(listener) {
        if (valid) listener();
        return () => undefined;
      },
      ignoreAcks() {},
      get acceptGate() {
        return acceptGate;
      },
      set acceptGate(value) {
        acceptGate = value;
      },
      get latePublishGate() {
        return latePublishGate;
      },
      set latePublishGate(value) {
        latePublishGate = value;
      },
    };

    Object.setPrototypeOf(attempt, null);
    return Object.freeze(attempt);
  }

  function mockRelay(mode) {
    jest.unstable_mockModule('../../src/sdk/delivery/relay-pool.js', () => ({
      createRelaySet: () => ({
        start: async () => ({ connectedRelays: 2 }),
        onFrame: () => () => undefined,
        publish: (event) => attemptFor(event, mode),
        freeze() {},
        dispose: async () => undefined,
      }),
    }));
  }

  test.each([
    ['valid control', 'valid', null],
    [
      'a descriptor fault cannot hide a later unknown outcome',
      'descriptor-fault',
      'E_SDK_UNKNOWN_CODE',
    ],
    [
      'an unknown slot on a root function precedes attempt shape',
      'callable-root',
      'E_SDK_UNKNOWN_CODE',
    ],
  ])('%s', async (_title, mode, expectedCode) => {
    jest.resetModules();
    mockRelay(mode);

    // Outbox and inbound processor are real in these three cases.
    const { createStyxClient } = await import('../../src/sdk/client.js');
    const created = createStyxClient(config());
    expect(created.ok).toBe(true);
    const client = created.value;

    try {
      expect((await client.start()).ok).toBe(true);

      const sent = await client.send({
        recipient: 'b'.repeat(64),
        payload: new Uint8Array([1]),
      });
      expect(sent.ok).toBe(true);

      for (let turn = 0; turn < 200; turn += 1) {
        await Promise.resolve();
      }

      const snapshot = await client.getDelivery({
        deliveryId: sent.value.deliveryId,
      });
      expect(snapshot.ok).toBe(true);

      // Both non-control cases are predicted to have E_SDK_INTERNAL.
      expect(snapshot.value).toMatchObject(
        expectedCode === null
          ? {
            state: 'RELAY_ACCEPTED',
            terminal: true,
            lastCode: null,
          }
          : {
            state: 'FAILED_NOT_ACCEPTED',
            terminal: true,
            lastCode: expectedCode,
          },
      );
    } finally {
      await client.shutdown();
    }
  });
});

describe('review probe r4: probe-r4-callable-outcomes (regression)', () => {

  function config() {
    const records = new Map();

    return {
      interfaceVersion: 'styx-m3-sdk/0.1.0-experimental',
      relays: ['ws://127.0.0.1:7000'],
      delivery: { perRelayTimeoutMs: 11000 },
      ports: {
        storage: {
          put(record) {
            records.set(record.deliveryId, record);
            return true;
          },
          get: (id) => records.get(id) ?? null,
          update(id, record) {
            records.set(id, record);
            return true;
          },
          remove: (id) => records.delete(id),
          list: () => [...records.values()],
        },
        session: {
          seal: ({ plaintext }) => ({
            ciphertext: new Uint8Array(plaintext),
          }),
          open: ({ ciphertext }) => ({
            plaintext: new Uint8Array(ciphertext),
          }),
        },
        identity: {
          getPublicKey: () => 'a'.repeat(64),
          sign: () => new Uint8Array(64),
        },
      },
    };
  }

  function validAttempt(event) {
    let acceptGate = null;
    let latePublishGate = null;

    const attempt = {
      index: 1,
      event,
      outcomes: Object.freeze(['ACCEPTED']),
      publishedOnce: Object.freeze([true]),
      get acceptedIndex() {
        return 0;
      },
      isSettled: () => true,
      onOutcome(listener) {
        listener(0, 'ACCEPTED');
        return () => undefined;
      },
      onSettled(listener) {
        listener();
        return () => undefined;
      },
      ignoreAcks() {},
      get acceptGate() {
        return acceptGate;
      },
      set acceptGate(value) {
        acceptGate = value;
      },
      get latePublishGate() {
        return latePublishGate;
      },
      set latePublishGate(value) {
        latePublishGate = value;
      },
    };

    Object.setPrototypeOf(attempt, null);
    return Object.freeze(attempt);
  }

  test.each([
    ['valid control', false],
    ['a callable root cannot hide an unknown outcome', true],
  ])('%s', async (_title, callable) => {
    jest.resetModules();

    jest.unstable_mockModule('../../src/sdk/delivery/relay-pool.js', () => ({
      createRelaySet: () => ({
        start: async () => ({ connectedRelays: 1 }),
        onFrame: () => () => undefined,
        publish(event) {
          if (!callable) return validAttempt(event);

          return Object.freeze(Object.assign(() => undefined, {
            outcomes: Object.freeze(['UNLISTED_OUTCOME']),
          }));
        },
        freeze() {},
        dispose: async () => undefined,
      }),
    }));

    // The client, outbox and inbound processor are real.
    const { createStyxClient } = await import('../../src/sdk/client.js');
    const created = createStyxClient(config());
    expect(created.ok).toBe(true);
    const client = created.value;

    try {
      expect((await client.start()).ok).toBe(true);

      const sent = await client.send({
        recipient: 'b'.repeat(64),
        payload: new Uint8Array([1]),
      });
      expect(sent.ok).toBe(true);

      for (let turn = 0; turn < 200; turn += 1) {
        await Promise.resolve();
      }

      const snapshot = await client.getDelivery({
        deliveryId: sent.value.deliveryId,
      });
      expect(snapshot.ok).toBe(true);

      expect(snapshot.value).toMatchObject(callable
        ? {
          state: 'FAILED_NOT_ACCEPTED',
          terminal: true,
          lastCode: 'E_SDK_UNKNOWN_CODE',
        }
        : {
          state: 'RELAY_ACCEPTED',
          terminal: true,
          lastCode: null,
        });
    } finally {
      await client.shutdown();
    }
  }, 30000);
});

describe('review probe r4: probe-r4-identity-precedence (regression)', () => {
  const { createStyxClient } = clientModule;


  test.each([
    ['an observed unknown survives a later descriptor fault', 'code', 'state'],
    ['an earlier descriptor fault cannot hide an unknown state', 'state', 'code'],
    ['control: an unknown without a descriptor fault', 'code', null],
  ])('%s', async (_title, unknownSlot, faultSlot) => {
    const target = Object.freeze({
      [unknownSlot]: unknownSlot === 'code'
        ? 'E_SDK_R4_FUTURE'
        : 'R4_FUTURE_STATE',
    });

    const key = new Proxy(target, {
      getOwnPropertyDescriptor(object, name) {
        if (name === faultSlot) {
          throw new Error('descriptor inspection fault');
        }
        return Reflect.getOwnPropertyDescriptor(object, name);
      },
    });

    const created = createStyxClient({
      interfaceVersion: 'styx-m3-sdk/0.1.0-experimental',
      relays: ['ws://127.0.0.1:7000'],
      delivery: { perRelayTimeoutMs: 11000 },
      ports: {
        storage: {
          put: () => true,
          get: () => null,
          update: () => true,
          remove: () => false,
          list: () => [],
        },
        session: {
          seal: ({ plaintext }) => ({ ciphertext: plaintext }),
          open: ({ ciphertext }) => ({ plaintext: ciphertext }),
        },
        identity: {
          getPublicKey: () => key,
          sign: () => new Uint8Array(64),
        },
      },
    });

    expect(created.ok).toBe(true);
    const client = created.value;

    try {
      // No connection phase is reached.
      expect(await client.start()).toEqual({
        ok: false,
        code: 'E_SDK_UNKNOWN_CODE',
      });
    } finally {
      await client.shutdown();
    }
  });
});

describe('round-3 counterexamples', () => {
  const V = 'styx-m3-sdk/0.1.0-experimental';
  const R0 = 'ws' + SEP + '127.0.0.1:7000';
  const R1 = 'ws' + SEP + '127.0.0.1:7001';
  const frozenValue = (value) => Object.freeze({ ok: true, value: Object.freeze(value) });
  const flushTurns = async (turns = 200) => {
    for (let turn = 0; turn < turns; turn += 1) await Promise.resolve();
  };

  function lanePorts(session) {
    const records = new Map();
    return {
      storage: {
        put(record) {
          records.set(record.deliveryId, record);
          return true;
        },
        get: (id) => records.get(id) ?? null,
        update(id, record) {
          records.set(id, record);
          return true;
        },
        remove: (id) => records.delete(id),
        list: () => [...records.values()],
      },
      session: session ?? {
        seal: ({ plaintext }) => ({ ciphertext: new Uint8Array(plaintext) }),
        open: ({ ciphertext }) => ({ plaintext: new Uint8Array(ciphertext) }),
      },
      identity: {
        getPublicKey: () => 'a'.repeat(64),
        sign: () => new Uint8Array(64),
      },
    };
  }

  test('the stop waits for a session.open that synchronously started it (r3-H1)', async () => {
    jest.resetModules();
    let inbound = null;
    jest.unstable_mockModule('../../src/sdk/delivery/relay-pool.js', () => ({
      createRelaySet: () => ({
        start: async () => ({ connectedRelays: 1 }),
        onFrame(listener) {
          inbound = listener;
          return () => undefined;
        },
        freeze() {},
        dispose: async () => undefined,
      }),
    }));
    const { createStyxClient: create } = await import('../../src/sdk/client.js');
    const owner = 'a'.repeat(64);
    let releaseOpen;
    const heldOpen = new Promise((resolve) => {
      releaseOpen = resolve;
    });
    let client;
    let opened = false;
    let stopping = null;
    let stopResolved = false;
    const created = create({
      interfaceVersion: V,
      relays: [R0],
      delivery: { perRelayTimeoutMs: PER_RELAY_MS },
      ports: lanePorts({
        seal: ({ plaintext }) => ({ ciphertext: plaintext }),
        open() {
          opened = true;
          stopping = client.shutdown().then((result) => {
            stopResolved = true;
            return result;
          });
          return heldOpen;
        },
      }),
    });
    expect(created.ok).toBe(true);
    client = created.value;
    try {
      expect((await client.start()).ok).toBe(true);
      const secret = new Uint8Array(32);
      secret[31] = 1;
      const pubkey = bytesToHex(schnorr.getPublicKey(secret));
      const createdAt = 12;
      const kind = 4741;
      const tags = [['p', owner], ['v', V], ['n', '0'.repeat(32)]];
      const content = 'AQ==';
      const id = bytesToHex(sha256(new TextEncoder().encode(JSON.stringify([0, pubkey, createdAt, kind, tags, content]))));
      const event = {
        id, pubkey, created_at: createdAt, kind, tags, content,
        sig: bytesToHex(schnorr.sign(id, secret)),
      };
      inbound({ relayIndex: 0, relay: R0, data: ['EVENT', 'sub', event] });
      await flushTurns();
      expect(opened).toBe(true);
      expect(stopping).not.toBeNull();
      expect(stopResolved).toBe(false);
    } finally {
      releaseOpen({ plaintext: new Uint8Array([7]) });
      if (stopping !== null) await stopping;
      else await client.shutdown();
    }
    expect(stopResolved).toBe(true);
  }, 30000);

  function attemptFor(event, mode) {
    if (mode === 'callable-root') {
      return Object.freeze(Object.assign(() => undefined, { code: 'E_SDK_NEW' }));
    }
    let acceptGate = null;
    let latePublishGate = null;
    const valid = mode === 'valid';
    const outcomes = valid
      ? Object.freeze(['ACCEPTED', 'ACCEPTED'])
      : new Proxy(Object.freeze(['PENDING', 'UNLISTED_OUTCOME']), {
        getOwnPropertyDescriptor(target, key) {
          if (key === '0') throw new Error('unreadable first descriptor');
          return Reflect.getOwnPropertyDescriptor(target, key);
        },
      });
    const attempt = {
      index: 1,
      event,
      outcomes,
      publishedOnce: Object.freeze([valid, valid]),
      get acceptedIndex() {
        return valid ? 0 : -1;
      },
      isSettled: () => valid,
      onOutcome(listener) {
        if (valid) {
          listener(0, 'ACCEPTED');
          listener(1, 'ACCEPTED');
        }
        return () => undefined;
      },
      onSettled(listener) {
        if (valid) listener();
        return () => undefined;
      },
      ignoreAcks() {},
      get acceptGate() {
        return acceptGate;
      },
      set acceptGate(value) {
        acceptGate = value;
      },
      get latePublishGate() {
        return latePublishGate;
      },
      set latePublishGate(value) {
        latePublishGate = value;
      },
    };
    Object.setPrototypeOf(attempt, null);
    return Object.freeze(attempt);
  }

  function mockRelaySet(mode) {
    jest.unstable_mockModule('../../src/sdk/delivery/relay-pool.js', () => ({
      createRelaySet: () => ({
        start: async () => ({ connectedRelays: 2 }),
        onFrame: () => () => undefined,
        publish: (event) => attemptFor(event, mode),
        freeze() {},
        dispose: async () => undefined,
      }),
    }));
  }

  test.each([
    ['valid control', 'valid', null],
    ['a descriptor fault cannot hide a later unknown outcome (r3-H2)', 'descriptor-fault', 'E_SDK_UNKNOWN_CODE'],
    ['an unknown slot on a root function precedes the attempt shape (r3-H2)', 'callable-root', 'E_SDK_UNKNOWN_CODE'],
  ])('%s', async (_title, mode, expectedCode) => {
    jest.resetModules();
    mockRelaySet(mode);
    const { createStyxClient: create } = await import('../../src/sdk/client.js');
    const created = create({
      interfaceVersion: V, relays: [R0, R1], delivery: { perRelayTimeoutMs: PER_RELAY_MS }, ports: lanePorts(),
    });
    expect(created.ok).toBe(true);
    const client = created.value;
    try {
      expect((await client.start()).ok).toBe(true);
      const sent = await client.send({ recipient: 'b'.repeat(64), payload: new Uint8Array([1]) });
      expect(sent.ok).toBe(true);
      await flushTurns();
      const snapshot = await client.getDelivery({ deliveryId: sent.value.deliveryId });
      expect(snapshot.ok).toBe(true);
      expect(snapshot.value).toMatchObject(expectedCode === null
        ? { state: 'RELAY_ACCEPTED', terminal: true, lastCode: null }
        : { state: 'FAILED_NOT_ACCEPTED', terminal: true, lastCode: expectedCode });
    } finally {
      await client.shutdown();
    }
  }, 30000);

  test('an unknown slot on a root callable envelope fails its item closed (r3-H2)', async () => {
    jest.resetModules();
    mockRelaySet('valid');
    const failClosedIds = [];
    const returned = Object.freeze(Object.assign(() => undefined, {
      ok: true,
      value: Object.freeze({ deliveryId: 'd1', state: 'QUEUED' }),
      code: 'E_SDK_NEW',
    }));
    jest.unstable_mockModule('../../src/sdk/delivery/outbox.js', () => ({
      createOutbox: () => ({
        inspectStore: async () => frozenValue({ empty: true }),
        adoptPublicKey: () => frozenValue({ adopted: true }),
        send: async () => returned,
        acceptReceipt: async () => frozenValue({ accepted: false }),
        failClosed({ deliveryId }) {
          failClosedIds.push(deliveryId);
          return frozenValue({ deliveryId, state: 'FAILED_NOT_ACCEPTED' });
        },
        shutdown: async () => frozenValue({ clientState: 'STOPPED', lost: 0 }),
      }),
    }));
    const { createStyxClient: create } = await import('../../src/sdk/client.js');
    const created = create({
      interfaceVersion: V, relays: [R0, R1], delivery: { perRelayTimeoutMs: PER_RELAY_MS }, ports: lanePorts(),
    });
    expect(created.ok).toBe(true);
    const client = created.value;
    try {
      expect((await client.start()).ok).toBe(true);
      const result = await client.send({ recipient: 'b'.repeat(64), payload: new Uint8Array([1]) });
      expect({ result, failClosedIds }).toEqual({
        result: { ok: false, code: 'E_SDK_UNKNOWN_CODE' },
        failClosedIds: ['d1'],
      });
    } finally {
      await client.shutdown();
    }
  }, 30000);
});

/* ------------------------------------------------------------------------- *
 * Lane modules replaced by doubles (jest.unstable_mockModule).
 * ------------------------------------------------------------------------- */

const frozenOk = (value) => Object.freeze({ ok: true, value: Object.freeze(value) });
const frozenFail = (code) => Object.freeze({ ok: false, code });
/** Freeze `value` and every object reachable from it. */
function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const key of Reflect.ownKeys(value)) deepFreeze(value[key]);
    Object.freeze(value);
  }
  return value;
}
const HEX_A = 'a'.repeat(64);
const HEX_B = 'b'.repeat(64);

function goodSnapshot(id, overrides = {}) {
  return {
    deliveryId: id,
    recipient: HEX_B,
    state: 'QUEUED',
    terminal: false,
    attempts: 0,
    createdAt: 1,
    deadlineAt: 2,
    lastCode: null,
    relayOutcomes: [{ relayIndex: 0, outcome: 'PENDING' }],
    ...overrides,
  };
}

/** Doubles of the three seam modules, with recorded calls and the client's sinks. */
function makeDoubles() {
  const doubles = {
    calls: [],
    failClosedIds: [],
    outboxSink: null,
    receiptsSink: null,
    frameListener: null,
    relayStart: () => Promise.resolve({ connectedRelays: 1 }),
    outbox: {
      inspectStore: async () => frozenOk({ empty: true }),
      adoptPublicKey: () => frozenOk({ adopted: true }),
      send: async () => frozenOk({ deliveryId: 'd1', state: 'QUEUED' }),
      cancel: async ({ deliveryId }) => frozenOk({ deliveryId, state: 'CANCELLED' }),
      getDelivery: async ({ deliveryId }) => frozenOk(goodSnapshot(deliveryId)),
      acceptReceipt: async () => frozenOk({}),
      failClosed: ({ deliveryId }) => {
        doubles.failClosedIds.push(deliveryId);
        return frozenOk({ deliveryId, state: 'FAILED_NOT_ACCEPTED' });
      },
      shutdown: async () => frozenOk({ clientState: 'STOPPED', lost: 0 }),
    },
    receipts: {
      ingest: () => frozenOk({ queued: true }),
      shutdown: () => frozenOk({ dropped: 0 }),
      settled: async () => undefined,
    },
    relaySet: {
      start: () => doubles.relayStart(),
      publish: () => ({ ignoreAcks() {}, acceptGate: null, latePublishGate: null }),
      onFrame: (listener) => {
        doubles.frameListener = listener;
        return () => {};
      },
      freeze: () => doubles.calls.push('freeze'),
      dispose: async () => doubles.calls.push('dispose'),
    },
  };
  return doubles;
}

async function loadClientWith(doubles) {
  jest.resetModules();
  jest.unstable_mockModule('../../src/sdk/delivery/outbox.js', () => ({
    createOutbox: (options) => {
      doubles.calls.push('createOutbox');
      doubles.outboxSink = options.onEvent;
      doubles.outboxOptions = options;
      return doubles.outbox;
    },
  }));
  jest.unstable_mockModule('../../src/sdk/delivery/receipts.js', () => ({
    createReceipts: (options) => {
      doubles.calls.push('createReceipts');
      doubles.receiptsSink = options.onEvent;
      doubles.receiptsOptions = options;
      return doubles.receipts;
    },
  }));
  jest.unstable_mockModule('../../src/sdk/delivery/relay-pool.js', () => ({
    createRelaySet: (options) => {
      doubles.calls.push('createRelaySet');
      doubles.relayOptions = options;
      return doubles.relaySet;
    },
  }));
  return import('../../src/sdk/client.js');
}

async function startedWithDoubles(doubles, { listener = null } = {}) {
  const module = await loadClientWith(doubles);
  const identity = identityPort();
  const created = module.createStyxClient(makeConfig({ relays: [`ws${SEP}127.0.0.1:7000`], identity: identity.port }));
  const client = created.value;
  cleanups.push(() => client.shutdown());
  const events = [];
  await client.onEvent(listener ?? ((event) => events.push(event)));
  const started = await client.start();
  expect(started.ok).toBe(true);
  return { client, events, identity };
}

describe('result check and events with lane doubles', () => {
  test('start wires the modules as the contract states', async () => {
    const doubles = makeDoubles();
    const { identity } = await startedWithDoubles(doubles);
    expect(doubles.calls.slice(0, 3)).toEqual(['createOutbox', 'createRelaySet', 'createReceipts']);
    expect(doubles.relayOptions.filter).toEqual({ kinds: [4741, 4742], '#p': [identity.publicKey] });
    expect(doubles.relayOptions.subscriptionId).toMatch(/^s[0-9a-f]{32}$/);
    expect(doubles.relayOptions.transport).toBeUndefined();
    expect(doubles.relayOptions.perRelayTimeoutMs).toBe(PER_RELAY_MS);
    expect(doubles.receiptsOptions.publicKey).toBe(identity.publicKey);
    expect(doubles.receiptsOptions.acceptReceipt).toBe(doubles.outbox.acceptReceipt);
    expect(doubles.receiptsOptions.identity).toBe(identity.port);
  });

  test('publishReceipt ignores acknowledgements and gates every later publication', async () => {
    const doubles = makeDoubles();
    const attempts = [];
    doubles.relaySet.publish = (event) => {
      const attempt = {
        event,
        ignored: 0,
        acceptGate: null,
        latePublishGate: null,
        ignoreAcks() { attempt.ignored += 1; },
      };
      attempts.push(attempt);
      return attempt;
    };
    await startedWithDoubles(doubles);
    expect(doubles.receiptsOptions.publishReceipt({ id: 'r' })).toBeUndefined();
    expect(attempts).toHaveLength(1);
    expect(attempts[0].ignored).toBe(1);
    expect(attempts[0].acceptGate()).toBe(false);
    expect(attempts[0].latePublishGate()).toBe(false);
    doubles.relaySet.publish = () => { throw new Error('refused'); };
    expect(() => doubles.receiptsOptions.publishReceipt({ id: 'r2' })).not.toThrow();
  });

  test('send: payload checks precede the copy and the outbox', async () => {
    const doubles = makeDoubles();
    let sends = 0;
    doubles.outbox.send = async () => {
      sends += 1;
      return frozenOk({ deliveryId: 'd1', state: 'QUEUED' });
    };
    const { client } = await startedWithDoubles(doubles);
    for (const payload of [undefined, null, 'x', [1], new Uint8Array(0), new ArrayBuffer(2)]) {
      expect(await client.send({ recipient: HEX_B, payload })).toEqual({ ok: false, code: 'E_SDK_INVALID_ARGUMENT' });
    }
    expect(await client.send({ recipient: HEX_B, payload: new Uint8Array(65537) }))
      .toEqual({ ok: false, code: 'E_SDK_PAYLOAD_TOO_LARGE' });
    for (const argument of [undefined, null, { recipient: HEX_B }, { payload: new Uint8Array(1) },
      { recipient: HEX_B, payload: new Uint8Array(1), extra: 1 }]) {
      expect(await client.send(argument)).toEqual({ ok: false, code: 'E_SDK_INVALID_ARGUMENT' });
    }
    expect(sends).toBe(0);
    expect(await client.send({ recipient: HEX_B, payload: new Uint8Array(65536) }))
      .toEqual({ ok: true, value: { deliveryId: 'd1', state: 'QUEUED' } });
    expect(sends).toBe(1);
    // The byte count is the array's own, whatever its prototype reports.
    const oversized = new Uint8Array(65537);
    Object.setPrototypeOf(oversized, Object.create(Uint8Array.prototype, { length: { get: () => 1 } }));
    expect(oversized.length).toBe(1);
    expect(await client.send({ recipient: HEX_B, payload: oversized }))
      .toEqual({ ok: false, code: 'E_SDK_PAYLOAD_TOO_LARGE' });
    const hidden = new Uint8Array(4);
    Object.setPrototypeOf(hidden, Object.create(Uint8Array.prototype, { length: { get: () => 0 } }));
    let trapCalls = 0;
    const trapping = new Uint8Array(4);
    Object.setPrototypeOf(trapping, new Proxy(Uint8Array.prototype, {
      get: (...args) => { trapCalls += 1; return Reflect.get(...args); },
      getPrototypeOf: (target) => { trapCalls += 1; return Reflect.getPrototypeOf(target); },
    }));
    class Bytes extends Uint8Array {}
    for (const payload of [hidden, trapping, new Bytes([1, 2])]) {
      expect(await client.send({ recipient: HEX_B, payload })).toEqual({ ok: true, value: { deliveryId: 'd1', state: 'QUEUED' } });
    }
    expect(trapCalls).toBe(0);
    for (const payload of [new Proxy(new Uint8Array(4), {}), new Uint16Array(2), new DataView(new ArrayBuffer(2))]) {
      expect(await client.send({ recipient: HEX_B, payload })).toEqual({ ok: false, code: 'E_SDK_INVALID_ARGUMENT' });
    }
    expect(sends).toBe(4);
  });

  test('send and cancel: an argument whose reading stops the client reaches no module', async () => {
    const doubles = makeDoubles();
    let sends = 0;
    let cancels = 0;
    doubles.outbox.send = async () => { sends += 1; return frozenOk({ deliveryId: 'd1', state: 'QUEUED' }); };
    doubles.outbox.cancel = async ({ deliveryId }) => { cancels += 1; return frozenOk({ deliveryId, state: 'CANCELLED' }); };
    const { client } = await startedWithDoubles(doubles);
    let stopping = null;
    const stoppingProxy = (target) => new Proxy(target, {
      ownKeys: (object) => {
        if (stopping === null) stopping = client.shutdown();
        return Reflect.ownKeys(object);
      },
    });
    expect(await client.send(stoppingProxy({ recipient: HEX_B, payload: new Uint8Array(1) })))
      .toEqual({ ok: false, code: 'E_SDK_CLIENT_STOPPED' });
    expect(sends).toBe(0);
    expect((await stopping).ok).toBe(true);

    const second = makeDoubles();
    second.outbox.cancel = doubles.outbox.cancel;
    const other = await startedWithDoubles(second);
    stopping = null;
    const cancelProxy = new Proxy({ deliveryId: 'd1' }, {
      ownKeys: (object) => {
        if (stopping === null) stopping = other.client.shutdown();
        return Reflect.ownKeys(object);
      },
    });
    expect(await other.client.cancel(cancelProxy)).toEqual({ ok: false, code: 'E_SDK_CLIENT_STOPPED' });
    expect(cancels).toBe(0);
    expect((await stopping).ok).toBe(true);
  });

  test('send: unknown code, unknown state, malformed value and a throw', async () => {
    const doubles = makeDoubles();
    const { client } = await startedWithDoubles(doubles);
    const payload = new Uint8Array([1]);
    const frozen = (envelope) => async () => deepFreeze(envelope);
    const withAccessor = () => {
      const unrelated = {};
      Object.defineProperty(unrelated, 'accessor', { enumerable: true, get: () => { throw new Error('read'); } });
      return Object.freeze({ ok: true, unrelated, value: Object.freeze({ deliveryId: 'd9', state: 'UNLISTED' }) });
    };
    const deep = () => {
      let unrelated = null;
      for (let depth = 0; depth < 64; depth += 1) unrelated = { child: unrelated };
      return deepFreeze({ ok: true, unrelated, value: { deliveryId: 'd10', state: 'UNLISTED' } });
    };
    const typedSlot = () => {
      const bytes = new Uint8Array([1]);
      Object.defineProperty(bytes, 'code', { value: 'E_SDK_NEW', enumerable: false });
      return Object.freeze({ ok: true, value: Object.freeze({ deliveryId: 'd11', state: 'QUEUED', bytes }) });
    };
    const functionSlot = () => {
      const carrier = Object.assign(() => undefined, { inner: Object.freeze({ state: 'UNLISTED' }) });
      return Object.freeze({ ok: true, value: Object.freeze({ deliveryId: 'd13', state: 'QUEUED', carrier }) });
    };
    const trappedTypedArray = () => {
      let trapCalls = 0;
      const bytes = new Uint8Array([1]);
      Object.defineProperty(bytes, 'code', { value: 'E_SDK_NEW', enumerable: true });
      Object.setPrototypeOf(bytes, new Proxy(Uint8Array.prototype, {
        getPrototypeOf() { trapCalls += 1; throw new Error('trap'); },
      }));
      trappedTypedArray.calls = () => trapCalls;
      return Object.freeze({ ok: true, value: Object.freeze({ deliveryId: 'd14', state: 'QUEUED', bytes }) });
    };
    // [send double, expected code, failClosed calls expected for this case]
    const cases = [
      [frozen({ ok: false, code: 'E_SDK_NEW' }), 'E_SDK_UNKNOWN_CODE', []],
      [frozen({ ok: true, value: { deliveryId: 'd7', state: 'WEIRD' } }), 'E_SDK_UNKNOWN_CODE', ['d7']],
      // At most once per item: the second unknown d7 calls nothing.
      [frozen({ ok: true, value: { deliveryId: 'd7', state: 'WEIRD' } }), 'E_SDK_UNKNOWN_CODE', []],
      // The unknown slot takes precedence over an accessor, a deep nesting and a typed array around it.
      [async () => withAccessor(), 'E_SDK_UNKNOWN_CODE', ['d9']],
      [async () => deep(), 'E_SDK_UNKNOWN_CODE', ['d10']],
      [async () => typedSlot(), 'E_SDK_UNKNOWN_CODE', ['d11']],
      // ... inside a function, and on a typed array whose prototype chain traps.
      [async () => functionSlot(), 'E_SDK_UNKNOWN_CODE', ['d13']],
      [async () => trappedTypedArray(), 'E_SDK_UNKNOWN_CODE', ['d14']],
      // ... and over a missing freeze.
      [async () => ({ ok: true, value: { deliveryId: 'd12', state: 'WEIRD' } }), 'E_SDK_UNKNOWN_CODE', ['d12']],
      [frozen({ ok: true, value: { deliveryId: 'd8', state: 'IN_FLIGHT' } }), 'E_SDK_INTERNAL', []],
      [frozen({ ok: true, value: { deliveryId: 'd8' } }), 'E_SDK_INTERNAL', []],
      [frozen({ ok: false, code: 'E_SDK_DELIVERY_TERMINAL' }), 'E_SDK_INTERNAL', []],
      // A known code that C-SDK section 11 does not list for send.
      [frozen({ ok: false, code: 'E_SDK_IDENTITY_FAILED' }), 'E_SDK_INTERNAL', []],
      [frozen({ ok: 'yes', value: { deliveryId: 'd8', state: 'QUEUED' } }), 'E_SDK_INTERNAL', []],
      // Envelopes that are not frozen (C-SDK section 5.1).
      [async () => ({ ok: true, value: { deliveryId: 'd8', state: 'QUEUED' } }), 'E_SDK_INTERNAL', []],
      [async () => Object.freeze({ ok: true, value: { deliveryId: 'd8', state: 'QUEUED' } }), 'E_SDK_INTERNAL', []],
      [async () => ({ ok: false, code: 'E_SDK_QUEUE_FULL' }), 'E_SDK_INTERNAL', []],
      [async () => { throw new Error('fault'); }, 'E_SDK_INTERNAL', []],
      [() => { throw new Error('fault'); }, 'E_SDK_INTERNAL', []],
    ];
    for (const [behaviour, expected, failClosed] of cases) {
      doubles.failClosedIds.length = 0;
      doubles.outbox.send = behaviour;
      const result = await client.send({ recipient: HEX_B, payload });
      expect(result).toEqual({ ok: false, code: expected });
      expect(Object.isFrozen(result)).toBe(true);
      expect(doubles.failClosedIds).toEqual(failClosed);
    }
    expect(await client.send({ recipient: HEX_B, payload: new Uint8Array([1]) })).toEqual(
      { ok: false, code: 'E_SDK_INTERNAL' },
    );
  });

  test('getDelivery and cancel: unknown values fail the item closed once', async () => {
    const doubles = makeDoubles();
    const { client } = await startedWithDoubles(doubles);
    doubles.outbox.getDelivery = async ({ deliveryId }) => deepFreeze({ ok: true, value: goodSnapshot(deliveryId, { state: 'MAYBE' }) });
    expect(await client.getDelivery({ deliveryId: 'd1' })).toEqual({ ok: false, code: 'E_SDK_UNKNOWN_CODE' });
    expect(doubles.failClosedIds).toEqual(['d1']);
    doubles.outbox.getDelivery = async ({ deliveryId }) => deepFreeze({
      ok: true, value: goodSnapshot(deliveryId, { relayOutcomes: [{ relayIndex: 0, outcome: 'LOST' }] }),
    });
    expect(await client.getDelivery({ deliveryId: 'd2' })).toEqual({ ok: false, code: 'E_SDK_UNKNOWN_CODE' });
    expect(await client.getDelivery({ deliveryId: 'd2' })).toEqual({ ok: false, code: 'E_SDK_UNKNOWN_CODE' });
    expect(doubles.failClosedIds).toEqual(['d1', 'd2']);
    for (const malformed of [
      goodSnapshot('d3', { terminal: true }),
      goodSnapshot('d3', { attempts: 6 }),
      goodSnapshot('d3', { recipient: HEX_B.toUpperCase() }),
      goodSnapshot('d3', { relayOutcomes: [] }),
      goodSnapshot('d3', { relayOutcomes: [{ relayIndex: 1, outcome: 'PENDING' }] }),
      goodSnapshot('d3', { createdAt: Infinity }),
      { ...goodSnapshot('d3'), payload: new Uint8Array(1) },
    ]) {
      doubles.outbox.getDelivery = async () => deepFreeze({ ok: true, value: malformed });
      expect(await client.getDelivery({ deliveryId: 'd3' })).toEqual({ ok: false, code: 'E_SDK_INTERNAL' });
    }
    // Not frozen (C-SDK section 5.1), otherwise well formed.
    doubles.outbox.getDelivery = async () => ({ ok: true, value: goodSnapshot('d3') });
    expect(await client.getDelivery({ deliveryId: 'd3' })).toEqual({ ok: false, code: 'E_SDK_INTERNAL' });
    // A known code C-SDK section 11 does not list for getDelivery.
    doubles.outbox.getDelivery = async () => frozenFail('E_SDK_CLIENT_STOPPED');
    expect(await client.getDelivery({ deliveryId: 'd3' })).toEqual({ ok: false, code: 'E_SDK_INTERNAL' });
    doubles.outbox.getDelivery = async () => frozenFail('E_SDK_STORAGE_FAILED');
    expect(await client.getDelivery({ deliveryId: 'd3' })).toEqual({ ok: false, code: 'E_SDK_STORAGE_FAILED' });
    doubles.outbox.getDelivery = async () => { throw new Error('fault'); };
    expect(await client.getDelivery({ deliveryId: 'd3' })).toEqual({ ok: false, code: 'E_SDK_INTERNAL' });
    expect(doubles.failClosedIds).toEqual(['d1', 'd2']);
    doubles.outbox.getDelivery = async ({ deliveryId }) => deepFreeze({ ok: true, value: goodSnapshot(deliveryId) });
    const snapshot = await client.getDelivery({ deliveryId: 'd4' });
    expect(snapshot).toEqual({ ok: true, value: goodSnapshot('d4') });
    expect(Object.isFrozen(snapshot.value)).toBe(true);
    expect(Object.isFrozen(snapshot.value.relayOutcomes)).toBe(true);
    expect(Object.isFrozen(snapshot.value.relayOutcomes[0])).toBe(true);
    for (const argument of [undefined, {}, { deliveryId: 1 }, { deliveryId: 'd1', x: 1 }]) {
      expect(await client.getDelivery(argument)).toEqual({ ok: false, code: 'E_SDK_INVALID_ARGUMENT' });
      expect(await client.cancel(argument)).toEqual({ ok: false, code: 'E_SDK_INVALID_ARGUMENT' });
    }
    doubles.outbox.cancel = async ({ deliveryId }) => deepFreeze({ ok: true, value: { deliveryId, state: 'GONE' } });
    expect(await client.cancel({ deliveryId: 'd5' })).toEqual({ ok: false, code: 'E_SDK_UNKNOWN_CODE' });
    expect(doubles.failClosedIds).toEqual(['d1', 'd2', 'd5']);
    doubles.outbox.cancel = async ({ deliveryId }) => deepFreeze({ ok: true, value: { deliveryId, state: 'QUEUED' } });
    expect(await client.cancel({ deliveryId: 'd6' })).toEqual({ ok: false, code: 'E_SDK_INTERNAL' });
    doubles.outbox.cancel = async () => frozenFail('E_SDK_DELIVERY_TERMINAL');
    expect(await client.cancel({ deliveryId: 'd6' })).toEqual({ ok: false, code: 'E_SDK_DELIVERY_TERMINAL' });
    doubles.outbox.cancel = async () => frozenFail('E_SDK_QUEUE_FULL');
    expect(await client.cancel({ deliveryId: 'd6' })).toEqual({ ok: false, code: 'E_SDK_INTERNAL' });
    // Not frozen (C-SDK section 5.1), otherwise well formed.
    doubles.outbox.cancel = async () => ({ ok: false, code: 'E_SDK_DELIVERY_TERMINAL' });
    expect(await client.cancel({ deliveryId: 'd6' })).toEqual({ ok: false, code: 'E_SDK_INTERNAL' });
    doubles.outbox.cancel = async ({ deliveryId }) => Object.freeze({ ok: true, value: { deliveryId, state: 'CANCELLED' } });
    expect(await client.cancel({ deliveryId: 'd6' })).toEqual({ ok: false, code: 'E_SDK_INTERNAL' });
    expect(doubles.failClosedIds).toEqual(['d1', 'd2', 'd5']);
  });

  test('events with an unknown kind, an unknown state or a wrong field set are never forwarded', async () => {
    const doubles = makeDoubles();
    const { client, events } = await startedWithDoubles(doubles);
    await flushMicrotasks();
    events.length = 0;
    const sink = doubles.outboxSink;
    sink({ kind: 'DELIVERY_REVOKED', deliveryId: 'e1', state: 'QUEUED', terminal: false, lastCode: null });
    sink({ kind: 'DELIVERY_STATE_CHANGED', deliveryId: 'e2', state: 'HALF', terminal: false, lastCode: null });
    sink({ kind: 'DELIVERY_STATE_CHANGED', deliveryId: 'e3', state: 'QUEUED', terminal: false, lastCode: 'E_X' });
    sink({ kind: 'DELIVERY_STATE_CHANGED', deliveryId: 'e4', state: 'QUEUED', terminal: false });
    sink({ kind: 'DELIVERY_STATE_CHANGED', deliveryId: 'e5', state: 'QUEUED', terminal: true, lastCode: null });
    sink({ kind: 'DELIVERY_STATE_CHANGED', deliveryId: 'e6', state: 'QUEUED', terminal: false, lastCode: null, x: 1 });
    sink({ kind: 'DELIVERY_STATE_CHANGED', deliveryId: 7, state: 'QUEUED', terminal: false, lastCode: null });
    sink({ kind: 'CLIENT_STATE_CHANGED', clientState: 'RUNNING' });
    sink(null);
    doubles.receiptsSink({ kind: 'MESSAGE_RECEIVED', sender: HEX_A, payload: [1] });
    doubles.receiptsSink({ kind: 'MESSAGE_RECEIVED', sender: HEX_A.toUpperCase(), payload: new Uint8Array(1) });
    doubles.receiptsSink({ kind: 'INBOUND_DISCARDED', code: 'E_SDK_INTERNAL' });
    doubles.receiptsSink({ kind: 'INBOUND_DISCARDED', code: 'E_SDK_SOMETHING' });
    doubles.receiptsSink({ kind: 'INBOUND_DISCARDED', code: 'E_SDK_INBOUND_INVALID', relay: 'x' });
    await flushMicrotasks();
    expect(events).toEqual([]);
    expect(doubles.failClosedIds).toEqual(['e1', 'e2', 'e3', 'e4', 'e5', 'e6']);
    sink({ kind: 'DELIVERY_STATE_CHANGED', deliveryId: 'e9', state: 'QUEUED', terminal: false, lastCode: null });
    doubles.receiptsSink({ kind: 'INBOUND_DISCARDED', code: 'E_SDK_SESSION_FAILED' });
    await flushMicrotasks();
    expect(events).toEqual([
      { kind: 'DELIVERY_STATE_CHANGED', deliveryId: 'e9', state: 'QUEUED', terminal: false, lastCode: null },
      { kind: 'INBOUND_DISCARDED', code: 'E_SDK_SESSION_FAILED' },
    ]);
    for (const event of events) expect(Object.isFrozen(event)).toBe(true);
    await client.shutdown();
  });

  test('a deviating ingest return: an unknown slot records INBOUND_DISCARDED, any other records nothing', async () => {
    const doubles = makeDoubles();
    const { events } = await startedWithDoubles(doubles);
    await flushMicrotasks();
    events.length = 0;
    doubles.receipts.ingest = () => ({ ok: false, code: 'E_SDK_SOMETHING' });
    expect(doubles.frameListener({ data: [] })).toBeUndefined();
    doubles.receipts.ingest = () => ({ ok: true, value: { queued: 'yes' } });
    doubles.frameListener({ data: [] });
    doubles.receipts.ingest = () => { throw new Error('fault'); };
    doubles.frameListener({ data: [] });
    doubles.receipts.ingest = () => frozenOk({ queued: true, state: 'ODD' });
    doubles.frameListener({ data: [] });
    await flushMicrotasks();
    expect(events).toEqual([
      { kind: 'INBOUND_DISCARDED', code: 'E_SDK_UNKNOWN_CODE' },
      { kind: 'INBOUND_DISCARDED', code: 'E_SDK_UNKNOWN_CODE' },
    ]);
  });

  test('start: inspectStore, adoptPublicKey and relaySet.start deviations', async () => {
    const cases = [
      [(d) => { d.outbox.inspectStore = async () => frozenFail('E_SDK_STORAGE_FAILED'); }, 'E_SDK_STORAGE_FAILED'],
      [(d) => { d.outbox.inspectStore = async () => ({ ok: false, code: 'E_SDK_X' }); }, 'E_SDK_UNKNOWN_CODE'],
      [(d) => { d.outbox.inspectStore = async () => ({ ok: true, value: { empty: true } }); }, 'E_SDK_INTERNAL'],
      [(d) => { d.outbox.inspectStore = async () => frozenFail('E_SDK_QUEUE_FULL'); }, 'E_SDK_INTERNAL'],
      [(d) => { d.outbox.adoptPublicKey = () => frozenFail('E_SDK_INVALID_ARGUMENT'); }, 'E_SDK_INTERNAL'],
      [(d) => { d.outbox.adoptPublicKey = () => { throw new Error('x'); }; }, 'E_SDK_INTERNAL'],
      [(d) => { d.outbox.adoptPublicKey = () => ({ ok: true, value: { adopted: true } }); }, 'E_SDK_INTERNAL'],
      // An out-of-set slot of the adoption result precedes its shape (choice 1 of the card).
      [(d) => { d.outbox.adoptPublicKey = () => frozenFail('E_SDK_NEW'); }, 'E_SDK_UNKNOWN_CODE'],
      [(d) => { d.outbox.adoptPublicKey = () => ({ ok: true, value: { adopted: false, state: 'NEW' } }); },
        'E_SDK_UNKNOWN_CODE'],
      [(d) => { d.relayStart = () => Promise.reject(new Error('x')); }, 'E_SDK_NO_RELAY_AVAILABLE'],
      [(d) => { d.relayStart = async () => ({ connectedRelays: 2 }); }, 'E_SDK_NO_RELAY_AVAILABLE'],
      [(d) => { d.relayStart = async () => ({ connectedRelays: '1' }); }, 'E_SDK_NO_RELAY_AVAILABLE'],
      [(d) => { d.relayStart = async () => ({ connectedRelays: 0 }); }, 'E_SDK_NO_RELAY_AVAILABLE'],
      // relaySet.start(): an out-of-set slot anywhere precedes its malformed shape.
      [(d) => { d.relayStart = async () => ({ connectedRelays: 1, code: 'E_SDK_NEW' }); }, 'E_SDK_UNKNOWN_CODE'],
      [(d) => { d.relayStart = async () => ({ connectedRelays: 1, detail: { relay: { outcome: 'LOST' } } }); },
        'E_SDK_UNKNOWN_CODE'],
    ];
    for (const [arrange, expected] of cases) {
      const doubles = makeDoubles();
      arrange(doubles);
      const module = await loadClientWith(doubles);
      const client = module.createStyxClient(makeConfig({ relays: [`ws${SEP}127.0.0.1:7000`] })).value;
      expect(await client.start()).toEqual({ ok: false, code: expected });
      expect(await client.shutdown()).toEqual({ ok: true, value: { clientState: 'STOPPED', lost: 0 } });
    }
  });

  test('default clock and random: private per client, built on the host; caller ones stay live references', async () => {
    const first = makeDoubles();
    await startedWithDoubles(first);
    const second = makeDoubles();
    await startedWithDoubles(second);
    for (const doubles of [first, second]) {
      // The same private objects reach every module.
      expect(doubles.relayOptions.clock).toBe(doubles.outboxOptions.clock);
      expect(doubles.relayOptions.random).toBe(doubles.outboxOptions.random);
      expect(doubles.receiptsOptions.clock).toBe(doubles.outboxOptions.clock);
      expect(Object.keys(doubles.relayOptions.clock).sort()).toEqual(['clearTimer', 'now', 'setTimer']);
      expect(Object.keys(doubles.relayOptions.random)).toEqual(['nextUint32']);
    }
    expect(first.relayOptions.clock).not.toBe(second.relayOptions.clock);
    expect(first.relayOptions.random).not.toBe(second.relayOptions.random);

    const { clock, random } = first.relayOptions;
    const before = Date.now();
    const now = clock.now();
    expect(now).toBeGreaterThanOrEqual(before);
    expect(now).toBeLessThanOrEqual(Date.now());
    let fired = 0;
    const handle = clock.setTimer(() => { fired += 1; }, 5);
    clock.clearTimer(handle);
    const kept = clock.setTimer(() => { fired += 10; }, 5);
    await sleep(40);
    expect(fired).toBe(10);
    clock.clearTimer(kept);

    // b0 * 2^24 + b1 * 2^16 + b2 * 2^8 + b3 over a 4-byte Uint8Array filled by crypto.getRandomValues.
    const spy = jest.spyOn(globalThis.crypto, 'getRandomValues').mockImplementation((bytes) => {
      expect(bytes).toBeInstanceOf(Uint8Array);
      expect(bytes.length).toBe(4);
      bytes.set([0xfe, 0x01, 0x80, 0x7f]);
      return bytes;
    });
    try {
      expect(random.nextUint32()).toBe(0xfe * 2 ** 24 + 0x01 * 2 ** 16 + 0x80 * 2 ** 8 + 0x7f);
      expect(spy).toHaveBeenCalledTimes(1);
    } finally {
      spy.mockRestore();
    }

    // Caller clock and random objects are handed on as they are, so a later change to a method is seen.
    const callerDoubles = makeDoubles();
    const module = await loadClientWith(callerDoubles);
    const manual = manualClock();
    const callerRandom = { nextUint32: () => 1 };
    const created = module.createStyxClient(makeConfig({
      relays: [`ws${SEP}127.0.0.1:7000`], clock: manual.clock, random: callerRandom,
    }));
    const client = created.value;
    cleanups.push(() => client.shutdown());
    expect((await client.start()).ok).toBe(true);
    expect(callerDoubles.relayOptions.clock).toBe(manual.clock);
    expect(callerDoubles.outboxOptions.clock).toBe(manual.clock);
    expect(callerDoubles.relayOptions.random).toBe(callerRandom);
    callerRandom.nextUint32 = () => 7;
    expect(callerDoubles.relayOptions.random.nextUint32()).toBe(7);
    expect(Object.isFrozen(manual.clock)).toBe(false);
  });

  test('getDelivery: every call returns a fresh frozen snapshot, array and entries', async () => {
    const doubles = makeDoubles();
    // The double hands out one and the same frozen envelope every time.
    const same = deepFreeze({ ok: true, value: goodSnapshot('d1') });
    doubles.outbox.getDelivery = async () => same;
    const { client } = await startedWithDoubles(doubles);
    const one = await client.getDelivery({ deliveryId: 'd1' });
    const two = await client.getDelivery({ deliveryId: 'd1' });
    expect(one).toEqual(two);
    expect(one.value).toEqual(same.value);
    for (const result of [one, two]) {
      expect(result.value).not.toBe(same.value);
      expect(result.value.relayOutcomes).not.toBe(same.value.relayOutcomes);
      expect(result.value.relayOutcomes[0]).not.toBe(same.value.relayOutcomes[0]);
    }
    expect(one.value).not.toBe(two.value);
    expect(one.value.relayOutcomes).not.toBe(two.value.relayOutcomes);
    expect(one.value.relayOutcomes[0]).not.toBe(two.value.relayOutcomes[0]);
    for (const snapshot of [one.value, two.value]) {
      expect(Object.isFrozen(snapshot)).toBe(true);
      expect(Object.isFrozen(snapshot.relayOutcomes)).toBe(true);
      expect(Object.isFrozen(snapshot.relayOutcomes[0])).toBe(true);
    }
  });

  test('relaySet.publish: an attempt is checked before the outbox sees it', async () => {
    const doubles = makeDoubles();
    let relayAttempt = null;
    doubles.relaySet.publish = (event) => relayAttempt(event);
    await startedWithDoubles(doubles);
    const publish = doubles.outboxOptions.publish;
    const event = Object.freeze({ id: 'e'.repeat(64), kind: 4741, tags: Object.freeze([]) });
    let ignored = 0;
    const attempt = (extra = {}, outcomes = ['PENDING']) => {
      let acceptGate = null;
      let latePublishGate = null;
      const value = Object.create(null, {
        index: { value: 1, enumerable: true },
        event: { value: event, enumerable: true },
        outcomes: { value: Object.freeze([...outcomes]), enumerable: true },
        publishedOnce: { value: Object.freeze([true]), enumerable: true },
        acceptedIndex: { get: () => -1, enumerable: true },
        isSettled: { value: () => false, enumerable: true },
        onOutcome: { value: () => () => {}, enumerable: true },
        onSettled: { value: () => () => {}, enumerable: true },
        ignoreAcks: { value: () => { ignored += 1; }, enumerable: true },
        acceptGate: { get: () => acceptGate, set: (gate) => { acceptGate = gate; }, enumerable: true },
        latePublishGate: { get: () => latePublishGate, set: (gate) => { latePublishGate = gate; }, enumerable: true },
        ...extra,
      });
      return Object.freeze(value);
    };

    // The I-RELAY attempt itself reaches the outbox unchanged.
    const good = attempt();
    relayAttempt = () => good;
    expect(publish(event)).toBe(good);

    // An out-of-set slot anywhere, or an out-of-set outcome: the outbox gets an inert attempt whose every
    // outcome is out of set (its unknown-value rule then fails the item with E_SDK_UNKNOWN_CODE), and the
    // relay-set attempt ignores acknowledgements from then on.
    for (const unknown of [
      attempt({ code: { value: 'E_SDK_NEW', enumerable: true } }),
      attempt({ detail: { value: Object.freeze({ inner: Object.freeze({ state: 'NEW' }) }), enumerable: true } }),
      attempt({}, ['ACCEPTED_SOON']),
      // An unknown slot carried by a function member.
      attempt({ onOutcome: { value: Object.assign(() => () => {}, { code: 'E_SDK_NEW' }), enumerable: true } }),
      // An unknown outcome next to a malformed part: an extra member, a wrong length, an accessor.
      attempt({ extra: { value: 1, enumerable: true } }, ['LOST']),
      attempt({}, ['PENDING', 'LOST']),
      attempt({ index: { get: () => 1, enumerable: true } }, ['LOST']),
    ]) {
      ignored = 0;
      relayAttempt = () => unknown;
      const handed = publish(event);
      expect(handed).not.toBe(unknown);
      expect([...handed.outcomes]).toEqual(['UNKNOWN']);
      expect(handed.outcomes.every((outcome) => !Object.hasOwn(RelayOutcome, outcome))).toBe(true);
      expect(handed.isSettled()).toBe(true);
      handed.acceptGate = () => true;
      handed.latePublishGate = () => true;
      let listened = 0;
      handed.onOutcome(() => { listened += 1; });
      handed.onSettled(() => { listened += 1; });
      expect(listened).toBe(0);
      expect(ignored).toBe(1);
    }

    // Any other deviation from the I-RELAY attempt throws, which the outbox handles as an internal fault.
    let getterCalls = 0;
    for (const malformed of [
      null,
      { ignoreAcks() {}, acceptGate: null, latePublishGate: null },
      attempt({ extra: { value: 1, enumerable: true } }),
      attempt({}, ['PENDING', 'PENDING']),
      attempt({ onOutcome: { value: 1, enumerable: true } }),
      attempt({ acceptGate: { value: null, writable: false, enumerable: true } }),
      attempt({ index: { value: 'not-an-index', enumerable: true } }),
      attempt({ index: { value: 0, enumerable: true } }),
      attempt({ index: { get: () => { getterCalls += 1; return 1; }, enumerable: true } }),
      attempt({ event: { value: { ...event }, enumerable: true } }),
      attempt({ publishedOnce: { value: Object.freeze(['yes']), enumerable: true } }),
      attempt({ publishedOnce: { value: Object.freeze([true, false]), enumerable: true } }),
      attempt({ acceptedIndex: { value: 1, enumerable: true } }),
      attempt({ acceptedIndex: { value: -2, enumerable: true } }),
      attempt({ detail: { value: { get inner() { getterCalls += 1; return 1; } }, enumerable: true } }),
    ]) {
      relayAttempt = () => malformed;
      expect(() => publish(event)).toThrow();
    }
    expect(getterCalls).toBe(0);
  });

  test('a module event is dispatched after the call that caused it has returned its promise', async () => {
    const doubles = makeDoubles();
    const order = [];
    doubles.outbox.send = async () => {
      doubles.outboxSink({ kind: 'DELIVERY_STATE_CHANGED', deliveryId: 'd1', state: 'IN_FLIGHT', terminal: false, lastCode: null });
      order.push('module returned');
      return frozenOk({ deliveryId: 'd1', state: 'QUEUED' });
    };
    const { client } = await startedWithDoubles(doubles, {
      listener: (event) => order.push(`listener ${event.kind}`),
    });
    await flushMicrotasks();
    order.length = 0;
    const promise = client.send({ recipient: HEX_B, payload: new Uint8Array(1) });
    order.push('call returned');
    await promise;
    await flushMicrotasks();
    expect(order).toEqual(['module returned', 'call returned', 'listener DELIVERY_STATE_CHANGED']);
  });
});

/* ------------------------------------------------------------------------- *
 * Events.
 * ------------------------------------------------------------------------- */

describe('events', () => {
  test('listeners run after the call returned, in registration order, isolated from faults', async () => {
    const created = createStyxClient(makeConfig({ relays: [`ws${SEP}127.0.0.1:7000`] }));
    const client = created.value;
    const order = [];
    expect(await client.onEvent(() => { order.push('a'); throw new Error('listener fault'); })).toMatchObject({ ok: true });
    await client.onEvent(() => { order.push('b'); return Promise.reject(new Error('rejecting listener')); });
    await client.onEvent(() => { order.push('c'); });
    const promise = client.shutdown();
    expect(order).toEqual([]);
    const result = await promise;
    expect(result).toEqual({ ok: true, value: { clientState: 'STOPPED', lost: 0 } });
    expect(order).toEqual(['a', 'b', 'c']);
  });

  test('onEvent: argument, envelope, unsubscribe', async () => {
    const client = createStyxClient(makeConfig({ relays: [`ws${SEP}127.0.0.1:7000`] })).value;
    for (const value of [undefined, null, 1, {}, 'f']) {
      expect(await client.onEvent(value)).toEqual({ ok: false, code: 'E_SDK_INVALID_ARGUMENT' });
    }
    const seen = [];
    const listener = (event) => seen.push(event.kind);
    const first = await client.onEvent(listener);
    const second = await client.onEvent(listener);
    expect(Object.isFrozen(first)).toBe(true);
    expect(Object.isFrozen(first.value)).toBe(true);
    expect(Reflect.ownKeys(first.value)).toEqual(['unsubscribe']);
    expect(first.value.unsubscribe()).toBeUndefined();
    expect(first.value.unsubscribe()).toBeUndefined();
    await client.shutdown();
    expect(seen).toEqual(['CLIENT_STATE_CHANGED']);
    expect(second.value.unsubscribe()).toBeUndefined();
    // onEvent stays allowed after the stop.
    expect((await client.onEvent(listener)).ok).toBe(true);
  });

  test('unsubscribe stops an event recorded but not yet dispatched; a later listener gets nothing', async () => {
    const doubles = makeDoubles();
    const seen = [];
    const { client } = await startedWithDoubles(doubles, { listener: (event) => seen.push(['first', event.kind]) });
    await flushMicrotasks();
    seen.length = 0;
    const second = await client.onEvent((event) => seen.push(['second', event.kind]));
    doubles.outboxSink({ kind: 'DELIVERY_STATE_CHANGED', deliveryId: 'd1', state: 'IN_FLIGHT', terminal: false, lastCode: null });
    second.value.unsubscribe();
    await client.onEvent((event) => seen.push(['late', event.kind]));
    await flushMicrotasks();
    expect(seen).toEqual([['first', 'DELIVERY_STATE_CHANGED']]);
  });

  test('two listeners of one MESSAGE_RECEIVED receive distinct payload copies', async () => {
    const doubles = makeDoubles();
    const payloads = [];
    const { client } = await startedWithDoubles(doubles, { listener: (event) => {
      if (event.kind === 'MESSAGE_RECEIVED') {
        payloads.push(event.payload);
        event.payload[0] = 99;
      }
    } });
    await client.onEvent((event) => {
      if (event.kind === 'MESSAGE_RECEIVED') payloads.push(event.payload);
    });
    const source = new Uint8Array([1, 2, 3]);
    doubles.receiptsSink({ kind: 'MESSAGE_RECEIVED', sender: HEX_A, payload: source });
    source[1] = 42;
    await flushMicrotasks();
    expect(payloads).toHaveLength(2);
    expect(payloads[0]).not.toBe(payloads[1]);
    expect([...payloads[1]]).toEqual([1, 2, 3]);
    expect([...payloads[0]]).toEqual([99, 2, 3]);
  });
});

/* ------------------------------------------------------------------------- *
 * State machine.
 * ------------------------------------------------------------------------- */

describe('state machine', () => {
  const RELAY = `ws${SEP}127.0.0.1:7000`;
  const ID = { deliveryId: 'd1' };
  const SEND = { recipient: HEX_B, payload: new Uint8Array([1]) };

  test('CREATED', async () => {
    const client = createStyxClient(makeConfig({ relays: [RELAY] })).value;
    expect(await client.send(SEND)).toEqual({ ok: false, code: 'E_SDK_NOT_STARTED' });
    expect(await client.cancel(ID)).toEqual({ ok: false, code: 'E_SDK_NOT_STARTED' });
    expect(await client.getDelivery(ID)).toEqual({ ok: false, code: 'E_SDK_NOT_STARTED' });
    await client.shutdown();
  });

  test('during a start() in progress the client is CREATED; a second start shares it', async () => {
    const doubles = makeDoubles();
    let release;
    doubles.relayStart = () => new Promise((resolve) => { release = () => resolve({ connectedRelays: 1 }); });
    const module = await loadClientWith(doubles);
    const client = module.createStyxClient(makeConfig({ relays: [RELAY] })).value;
    cleanups.push(() => client.shutdown());
    const first = client.start();
    await waitFor(() => release !== undefined);
    const second = client.start();
    expect(await client.send(SEND)).toEqual({ ok: false, code: 'E_SDK_NOT_STARTED' });
    expect(await client.cancel(ID)).toEqual({ ok: false, code: 'E_SDK_NOT_STARTED' });
    expect(await client.getDelivery(ID)).toEqual({ ok: false, code: 'E_SDK_NOT_STARTED' });
    release();
    const [a, b] = await Promise.all([first, second]);
    expect(a).toEqual({ ok: true, value: { clientState: 'RUNNING', connectedRelays: 1 } });
    expect(b).toEqual(a);
    expect(b).not.toBe(a);
    expect(Object.isFrozen(b)).toBe(true);
    expect(doubles.calls.filter((call) => call === 'createRelaySet')).toHaveLength(1);
  });

  test('RUNNING', async () => {
    const doubles = makeDoubles();
    const { client } = await startedWithDoubles(doubles);
    expect(await client.start()).toEqual({ ok: false, code: 'E_SDK_ALREADY_STARTED' });
  });

  test('a deviating outbox stop result: lost is the number of LOST_ON_SHUTDOWN events the sink received', async () => {
    const lostEvent = (deliveryId) => Object.freeze({
      kind: 'DELIVERY_STATE_CHANGED', deliveryId, state: 'LOST_ON_SHUTDOWN', terminal: true, lastCode: null,
    });
    for (const stopResult of [
      Object.freeze({ ok: true, value: Object.freeze({ clientState: 'STOPPED', lost: -1 }) }),
      Object.freeze({ ok: true, value: Object.freeze({ clientState: 'STOPPED', lost: 1.5 }) }),
      Object.freeze({ ok: true, value: Object.freeze({ clientState: 'RUNNING', lost: 2 }) }),
      Object.freeze({ ok: true, value: Object.freeze({ clientState: 'STOPPED', lost: 2, extra: 1 }) }),
      Object.freeze({ ok: true, value: Object.freeze({ clientState: 'PAUSED', lost: 2 }) }),
      { ok: true, value: { clientState: 'STOPPED', lost: 7 } },
      frozenFail('E_SDK_INTERNAL'),
      null,
      'rejects',
    ]) {
      const doubles = makeDoubles();
      doubles.outbox.shutdown = () => {
        // Step (1) of the outbox stop records two LOST_ON_SHUTDOWN events through the sink.
        doubles.outboxSink(lostEvent('d1'));
        doubles.outboxSink(lostEvent('d2'));
        return stopResult === 'rejects' ? Promise.reject(new Error('fault')) : Promise.resolve(stopResult);
      };
      const { client, events } = await startedWithDoubles(doubles);
      expect(await client.shutdown()).toEqual({ ok: true, value: { clientState: 'STOPPED', lost: 2 } });
      expect(events.filter((event) => event.state === 'LOST_ON_SHUTDOWN')).toHaveLength(2);
      expect(doubles.calls).toContain('dispose');
    }
    // A well-formed result gives its own lost.
    const doubles = makeDoubles();
    doubles.outbox.shutdown = async () => frozenOk({ clientState: 'STOPPED', lost: 5 });
    const { client } = await startedWithDoubles(doubles);
    expect(await client.shutdown()).toEqual({ ok: true, value: { clientState: 'STOPPED', lost: 5 } });
  });

  test('during a shutdown() in progress and after it', async () => {
    const doubles = makeDoubles();
    let release;
    doubles.outbox.shutdown = () => new Promise((resolve) => {
      release = () => resolve(frozenOk({ clientState: 'STOPPED', lost: 0 }));
    });
    doubles.outbox.getDelivery = async ({ deliveryId }) => frozenOk(goodSnapshot(deliveryId));
    const { client } = await startedWithDoubles(doubles);
    const stopping = client.shutdown();
    for (const result of [await client.start(), await client.send(SEND), await client.cancel(ID),
      await client.shutdown()]) {
      expect(result).toEqual({ ok: false, code: 'E_SDK_CLIENT_STOPPED' });
    }
    expect((await client.getDelivery(ID)).ok).toBe(true);
    expect((await client.onEvent(() => {})).ok).toBe(true);
    release();
    expect(await stopping).toEqual({ ok: true, value: { clientState: 'STOPPED', lost: 0 } });
    for (const result of [await client.start(), await client.send(SEND), await client.cancel(ID),
      await client.shutdown()]) {
      expect(result).toEqual({ ok: false, code: 'E_SDK_CLIENT_STOPPED' });
    }
    expect((await client.getDelivery(ID)).ok).toBe(true);
    expect(doubles.calls).toContain('freeze');
    expect(doubles.calls).toContain('dispose');
  });

  test('a STOPPED client that never ran: every string id is unknown', async () => {
    const client = createStyxClient(makeConfig({ relays: [RELAY] })).value;
    await client.shutdown();
    expect(await client.getDelivery(ID)).toEqual({ ok: false, code: 'E_SDK_UNKNOWN_DELIVERY' });
    expect(await client.getDelivery({ deliveryId: 1 })).toEqual({ ok: false, code: 'E_SDK_INVALID_ARGUMENT' });
  });

  test('a second start() during the first opens no second connection on a loopback relay', async () => {
    const relay = await startRelay();
    const manual = manualClock();
    const client = createClient(makeConfig({ relays: [relay.url], clock: manual.clock }));
    const first = client.start();
    const second = client.start();
    await waitFor(() => relay.reqs >= 1);
    await sleep(20);
    manual.advance(PER_RELAY_MS);
    const [a, b] = await Promise.all([first, second]);
    expect(a).toEqual({ ok: true, value: { clientState: 'RUNNING', connectedRelays: 1 } });
    expect(b).toEqual(a);
    expect(b).not.toBe(a);
    expect(relay.connections).toBe(1);
  });
});

/* ------------------------------------------------------------------------- *
 * start() failures.
 * ------------------------------------------------------------------------- */

describe('start() failures leave nothing behind', () => {
  /** Run a failing start, check the cleanup, then a successful start. */
  async function failingThenWorking({ storage = storagePort(), identity = identityPort(), relaysFor = null,
    expected, timeoutWait = false }) {
    const relay = await startRelay();
    const manual = manualClock();
    const getPublicKeyCalls = () => identity.calls.getPublicKey;
    const relays = relaysFor !== null ? await relaysFor(relay) : [relay.url];
    const config = makeConfig({ relays, storage, identity: identity.port, clock: manual.clock });
    const client = createClient(config);
    const started = Date.now();
    const pending = client.start();
    if (relaysFor !== null) {
      await sleep(200);
      manual.advance(PER_RELAY_MS);
    }
    const result = await pending;
    expect(result).toEqual({ ok: false, code: expected });
    if (timeoutWait) expect(Date.now() - started).toBeLessThan(PORT_CALL_MS + 2000);
    await flushMicrotasks();
    expect(manual.timers.size).toBe(0);
    for (const socket of openedSockets) {
      expect(socket.readyState === WebSocket.CLOSED || socket.readyState === WebSocket.CLOSING
        || socket.closeCalled).toBe(true);
    }
    await relay.waitForClientsClosed();
    expect(relay.sockets.size).toBe(0);
    return { client, relay, manual, getPublicKeyCalls };
  }

  /** A later start() on the same client against a working relay. */
  async function thenSucceeds(context, { fixStorage = null, fixIdentity = null } = {}) {
    if (fixStorage !== null) fixStorage();
    if (fixIdentity !== null) fixIdentity();
    const before = context.getPublicKeyCalls();
    const started = await startOnLoopback(context.client, context.manual, [context.relay],
      { expectReqs: context.relay.reqs + 1 });
    expect(started.ok).toBe(true);
    expect(context.getPublicKeyCalls() - before).toBe(1);
  }

  test('list() returns a non-array: E_SDK_STORAGE_FAILED', async () => {
    const storage = storagePort();
    const list = storage.list;
    storage.list = () => 'nothing';
    const context = await failingThenWorking({ storage, expected: 'E_SDK_STORAGE_FAILED' });
    await thenSucceeds(context, { fixStorage: () => { storage.list = list; } });
  }, 30000);

  test('list(): an out-of-set closed slot is E_SDK_UNKNOWN_CODE even next to a malformed element', async () => {
    const storage = storagePort();
    const list = storage.list;
    storage.list = () => [{ broken: true }, { deliveryId: 'd1', state: 'ZOMBIE' }];
    const context = await failingThenWorking({ storage, expected: 'E_SDK_UNKNOWN_CODE' });
    await thenSucceeds(context, { fixStorage: () => { storage.list = list; } });
  }, 30000);

  test('list(): a malformed element is E_SDK_STORAGE_FAILED', async () => {
    const storage = storagePort();
    const list = storage.list;
    storage.list = () => [{ broken: true }];
    const context = await failingThenWorking({ storage, expected: 'E_SDK_STORAGE_FAILED' });
    await thenSucceeds(context, { fixStorage: () => { storage.list = list; } });
  }, 30000);

  test('a non-empty well-formed store is E_SDK_STORAGE_NOT_EMPTY', async () => {
    // A record written by a first client, then offered to a new one.
    const relay = await startRelay();
    const storage = storagePort();
    const first = await startMember([relay], { storage });
    await first.client.send({ recipient: HEX_B, payload: new Uint8Array([1]) });
    const kept = [...storage.records.values()];
    await first.client.shutdown();
    const second = storagePort();
    for (const record of kept) second.records.set(record.deliveryId, record);
    const context = await failingThenWorking({ storage: second, expected: 'E_SDK_STORAGE_NOT_EMPTY' });
    await thenSucceeds(context, { fixStorage: () => second.records.clear() });
  }, 30000);

  test('a list() that never settles resolves within one port-call timeout of host time', async () => {
    const storage = storagePort();
    const list = storage.list;
    storage.list = () => new Promise(() => {});
    const context = await failingThenWorking({ storage, expected: 'E_SDK_STORAGE_FAILED', timeoutWait: true });
    await thenSucceeds(context, { fixStorage: () => { storage.list = list; } });
  }, 30000);

  test.each([
    ['throws', () => { throw new Error('identity fault'); }, 'E_SDK_IDENTITY_FAILED'],
    ['rejects', () => Promise.reject(new Error('identity fault')), 'E_SDK_IDENTITY_FAILED'],
    ['returns uppercase hex', () => 'A'.repeat(64), 'E_SDK_IDENTITY_FAILED'],
    ['returns 63 hex digits', () => 'a'.repeat(63), 'E_SDK_IDENTITY_FAILED'],
    ['returns 65 hex digits', () => 'a'.repeat(65), 'E_SDK_IDENTITY_FAILED'],
    ['returns an object with an out-of-set code', () => ({ code: 'E_SDK_SOMETHING' }), 'E_SDK_UNKNOWN_CODE'],
    ['returns an object with an out-of-set state', () => ({ state: 'SOMEWHERE' }), 'E_SDK_UNKNOWN_CODE'],
    ['returns an object with known slots', () => ({ code: 'E_SDK_INTERNAL' }), 'E_SDK_IDENTITY_FAILED'],
  ])('getPublicKey %s', async (_, behaviour, expected) => {
    const identity = identityPort();
    const original = identity.port.getPublicKey;
    identity.port.getPublicKey = function getPublicKey() {
      identity.calls.getPublicKey += 1;
      return behaviour();
    };
    const context = await failingThenWorking({ identity, expected });
    await thenSucceeds(context, { fixIdentity: () => { identity.port.getPublicKey = original; } });
  }, 30000);

  test('getPublicKey never settles: E_SDK_IDENTITY_FAILED within one port-call timeout', async () => {
    const identity = identityPort();
    const original = identity.port.getPublicKey;
    identity.port.getPublicKey = () => {
      identity.calls.getPublicKey += 1;
      return new Promise(() => {});
    };
    const context = await failingThenWorking({ identity, expected: 'E_SDK_IDENTITY_FAILED', timeoutWait: true });
    await thenSucceeds(context, { fixIdentity: () => { identity.port.getPublicKey = original; } });
  }, 30000);

  test('the only relay is a loopback port with no listener: E_SDK_NO_RELAY_AVAILABLE', async () => {
    const port = await freeLoopbackPort();
    const context = await failingThenWorking({
      relaysFor: async () => [`ws${SEP}127.0.0.1:${port}`],
      expected: 'E_SDK_NO_RELAY_AVAILABLE',
    });
    expect(context.relay.connections).toBe(0);
    // A relay now listens on that port: the same client starts there.
    const working = await startRelay({ port });
    await thenSucceeds({ ...context, relay: working });
  }, 30000);

  test('a frame delivered during a connection phase that fails produces its MESSAGE_RECEIVED only', async () => {
    const relay = await startRelay();
    const sender = await startMember([relay]);
    const recipient = identityPort();
    const payload = new Uint8Array([7, 7, 7]);
    const sent = await sender.client.send({ recipient: recipient.publicKey, payload });
    await waitFor(() => relay.events.length === 1, { clock: sender.manual });
    // The recipient's start: its first relay holds the message, its second
    // never connects; a shutdown() during the phase makes the start fail.
    const manual = manualClock();
    const deadPort = await freeLoopbackPort();
    const client = createClient(makeConfig({
      relays: [relay.url, `ws${SEP}127.0.0.1:${deadPort}`], identity: recipient.port, clock: manual.clock,
    }));
    const events = [];
    await client.onEvent((event) => events.push(event));
    const pending = client.start();
    await waitFor(() => events.some((event) => event.kind === 'MESSAGE_RECEIVED'));
    // Shut the client down during the phase: start fails with E_SDK_CLIENT_STOPPED.
    const stopped = client.shutdown();
    manual.advance(PER_RELAY_MS);
    expect(await pending).toEqual({ ok: false, code: 'E_SDK_CLIENT_STOPPED' });
    await stopped;
    const received = events.filter((event) => event.kind === 'MESSAGE_RECEIVED');
    expect(received).toHaveLength(1);
    expect([...received[0].payload]).toEqual([7, 7, 7]);
    expect(events.map((event) => event.kind)).toEqual(['MESSAGE_RECEIVED', 'CLIENT_STATE_CHANGED']);
    expect(sent.ok).toBe(true);
  }, 30000);
});

/* ------------------------------------------------------------------------- *
 * End to end on loopback relays.
 * ------------------------------------------------------------------------- */

describe('end to end on loopback relays', () => {
  test('RELAY_ACCEPTANCE_ONLY: RELAY_ACCEPTED and MESSAGE_RECEIVED with the exact bytes', async () => {
    const r1 = await startRelay();
    const r2 = await startRelay();
    const alice = await startMember([r1, r2]);
    const bob = await startMember([r1, r2]);
    const payload = new Uint8Array([10, 20, 30, 40]);
    const sent = await alice.client.send({ recipient: bob.identity.publicKey, payload });
    expect(sent).toEqual({ ok: true, value: { deliveryId: expect.any(String), state: 'QUEUED' } });
    const id = sent.value.deliveryId;
    await waitFor(() => deliveryEvents(alice.events, id).some((event) => event.terminal), { clock: alice.manual });
    await waitFor(() => bob.events.some((event) => event.kind === 'MESSAGE_RECEIVED'));
    const final = deliveryEvents(alice.events, id).at(-1);
    expect(final).toEqual({ kind: 'DELIVERY_STATE_CHANGED', deliveryId: id, state: 'RELAY_ACCEPTED', terminal: true, lastCode: null });
    const received = bob.events.find((event) => event.kind === 'MESSAGE_RECEIVED');
    expect(received.sender).toBe(alice.identity.publicKey);
    expect([...received.payload]).toEqual([10, 20, 30, 40]);
    const snapshot = await alice.client.getDelivery({ deliveryId: id });
    expect(snapshot.ok).toBe(true);
    expect(Object.isFrozen(snapshot.value)).toBe(true);
    expect(Reflect.ownKeys(snapshot.value).sort()).toEqual([
      'attempts', 'createdAt', 'deadlineAt', 'deliveryId', 'lastCode', 'recipient', 'relayOutcomes', 'state', 'terminal',
    ]);
    expect(snapshot.value.relayOutcomes).toHaveLength(2);
    expect(Object.isFrozen(snapshot.value.relayOutcomes)).toBe(true);
    snapshot.value.relayOutcomes.forEach((entry, index) => {
      expect(Object.isFrozen(entry)).toBe(true);
      expect(entry.relayIndex).toBe(index);
    });
    expect(snapshot.value.recipient).toBe(bob.identity.publicKey);
    expect(await alice.client.cancel({ deliveryId: id })).toEqual({ ok: false, code: 'E_SDK_DELIVERY_TERMINAL' });
  }, 30000);

  test('RECIPIENT_RECEIPT: awaiting, then RECIPIENT_RECEIPT_RECEIVED, one event per transition', async () => {
    const relay = await startRelay();
    const alice = await startMember([relay], { delivery: { receiptMode: 'RECIPIENT_RECEIPT' } });
    const bob = await startMember([relay]);
    const sent = await alice.client.send({ recipient: bob.identity.publicKey, payload: new Uint8Array([5]) });
    const id = sent.value.deliveryId;
    await waitFor(() => deliveryEvents(alice.events, id).some((event) => event.terminal), { clock: alice.manual });
    const states = deliveryEvents(alice.events, id).map((event) => event.state);
    expect(states).toEqual(['IN_FLIGHT', 'RELAY_ACCEPTED_AWAITING_RECEIPT', 'RECIPIENT_RECEIPT_RECEIVED']);
    expect(relay.kindCounts.get(4742)).toBe(1);
  }, 30000);

  test('a payload mutated right after send, with seal held, arrives with the bytes of the call', async () => {
    const relay = await startRelay();
    let releaseSeal;
    const session = sessionPort();
    const holdingSession = {
      seal: (argument) => new Promise((resolve) => { releaseSeal = () => resolve(session.seal(argument)); }),
      open: session.open,
    };
    const alice = await startMember([relay], { session: holdingSession });
    const bob = await startMember([relay]);
    const payload = new Uint8Array([1, 2, 3]);
    const pending = alice.client.send({ recipient: bob.identity.publicKey, payload });
    payload[0] = 9;
    payload[2] = 9;
    await waitFor(() => releaseSeal !== undefined);
    releaseSeal();
    expect((await pending).ok).toBe(true);
    await waitFor(() => bob.events.some((event) => event.kind === 'MESSAGE_RECEIVED'), { clock: alice.manual });
    expect([...bob.events.find((event) => event.kind === 'MESSAGE_RECEIVED').payload]).toEqual([1, 2, 3]);
  }, 30000);

  test('cancel of a queued item gives CANCELLED', async () => {
    const relay = await startRelay({ rejectFor: [HEX_B] });
    const alice = await startMember([relay]);
    const sent = await alice.client.send({ recipient: HEX_B, payload: new Uint8Array([1]) });
    const id = sent.value.deliveryId;
    await waitFor(() => deliveryEvents(alice.events, id).some((event) => event.state === 'QUEUED'));
    expect(await alice.client.cancel({ deliveryId: id })).toEqual({ ok: true, value: { deliveryId: id, state: 'CANCELLED' } });
    expect(await alice.client.cancel({ deliveryId: id })).toEqual({ ok: false, code: 'E_SDK_DELIVERY_TERMINAL' });
    expect(await alice.client.cancel({ deliveryId: 'd999' })).toEqual({ ok: false, code: 'E_SDK_UNKNOWN_DELIVERY' });
  }, 30000);

  test('a hung relay next to a normal one: accepted through the normal relay, the hung one TIMED_OUT', async () => {
    const normal = await startRelay();
    const hung = await startRelay({ hung: true });
    const manual = manualClock();
    const identity = identityPort();
    const client = createClient(makeConfig({ relays: [hung.url, normal.url], identity: identity.port, clock: manual.clock }));
    const events = [];
    await client.onEvent((event) => events.push(event));
    const pending = client.start();
    await waitFor(() => normal.reqs >= 1 && hung.connections >= 1);
    await sleep(50);
    manual.advance(PER_RELAY_MS);
    expect(await pending).toEqual({ ok: true, value: { clientState: 'RUNNING', connectedRelays: 2 } });
    const sent = await client.send({ recipient: HEX_B, payload: new Uint8Array([3]) });
    const id = sent.value.deliveryId;
    await waitFor(() => deliveryEvents(events, id).some((event) => event.state === 'RELAY_ACCEPTED'));
    let snapshot = await client.getDelivery({ deliveryId: id });
    expect(snapshot.value.relayOutcomes).toEqual([
      { relayIndex: 0, outcome: 'PENDING' }, { relayIndex: 1, outcome: 'ACCEPTED' },
    ]);
    manual.advance(PER_RELAY_MS);
    await flushMicrotasks();
    snapshot = await client.getDelivery({ deliveryId: id });
    expect(snapshot.value.relayOutcomes).toEqual([
      { relayIndex: 0, outcome: 'TIMED_OUT' }, { relayIndex: 1, outcome: 'ACCEPTED' },
    ]);
    expect(snapshot.value.state).toBe('RELAY_ACCEPTED');
  }, 30000);

  test('a receipt is published once per relay connected at that instant, not on one that connects later', async () => {
    const r1 = await startRelay();
    const latePort = await freeLoopbackPort();
    const alice = await startMember([r1], { delivery: { receiptMode: 'RECIPIENT_RECEIPT' } });
    // Bob's second relay has no listener at his start.
    const bobIdentity = identityPort();
    const bobClock = manualClock();
    const bob = createClient(makeConfig({
      relays: [r1.url, `ws${SEP}127.0.0.1:${latePort}`], identity: bobIdentity.port, clock: bobClock.clock,
    }));
    const bobEvents = [];
    await bob.onEvent((event) => bobEvents.push(event));
    const pending = bob.start();
    await waitFor(() => r1.reqs >= 2);
    await sleep(100);
    bobClock.advance(PER_RELAY_MS);
    expect(await pending).toEqual({ ok: true, value: { clientState: 'RUNNING', connectedRelays: 1 } });
    const sent = await alice.client.send({ recipient: bobIdentity.publicKey, payload: new Uint8Array([4]) });
    await waitFor(() => deliveryEvents(alice.events, sent.value.deliveryId).some((event) => event.terminal),
      { clock: alice.manual });
    expect(r1.kindCounts.get(4742)).toBe(1);
    // The late relay starts listening and Bob reconnects to it.
    const late = await startRelay({ port: latePort });
    for (let i = 0; i < 100 && late.reqs < 1; i += 1) {
      bobClock.advance(1000);
      await sleep(20);
    }
    expect(late.reqs).toBeGreaterThanOrEqual(1);
    await sleep(100);
    expect(late.kindCounts.get(4742) ?? 0).toBe(0);
    expect(r1.kindCounts.get(4742)).toBe(1);
  }, 30000);

  test('the public key is read once and every sign call reaches the caller port as a method', async () => {
    const relay = await startRelay();
    const alice = await startMember([relay]);
    // Bob asks for a recipient receipt, so Alice signs one for his message.
    const bob = await startMember([relay], { delivery: { receiptMode: 'RECIPIENT_RECEIPT' } });
    for (const byte of [1, 2]) {
      expect((await alice.client.send({ recipient: bob.identity.publicKey, payload: new Uint8Array([byte]) })).ok).toBe(true);
    }
    // An inbound message whose receipt Alice signs.
    expect((await bob.client.send({ recipient: alice.identity.publicKey, payload: new Uint8Array([3]) })).ok).toBe(true);
    await waitFor(() => alice.events.some((event) => event.kind === 'MESSAGE_RECEIVED'), { clock: alice.manual });
    await waitFor(() => relay.kindCounts.get(4742) >= 1);
    await alice.client.shutdown();
    expect(alice.identity.calls.getPublicKey).toBe(1);
    expect(alice.identity.calls.sign).toBeGreaterThanOrEqual(3);
    for (const self of alice.identity.calls.signThis) expect(self).toBe(alice.identity.port);
  }, 30000);
});

/* ------------------------------------------------------------------------- *
 * shutdown().
 * ------------------------------------------------------------------------- */

describe('shutdown()', () => {
  test('in CREATED: STOPPED, lost 0, one event to the earlier listeners, no port call', async () => {
    const calls = [];
    const spy = (name) => () => { calls.push(name); };
    const client = createStyxClient({
      interfaceVersion: SDK_INTERFACE_VERSION,
      relays: [`ws${SEP}127.0.0.1:7000`],
      ports: {
        storage: { put: spy('put'), get: spy('get'), update: spy('update'), remove: spy('remove'), list: spy('list') },
        session: { seal: spy('seal'), open: spy('open') },
        identity: { getPublicKey: spy('getPublicKey'), sign: spy('sign') },
      },
    }).value;
    const events = [];
    await client.onEvent((event) => events.push(event));
    const result = await client.shutdown();
    expect(result).toEqual({ ok: true, value: { clientState: 'STOPPED', lost: 0 } });
    expect(Object.isFrozen(result.value)).toBe(true);
    expect(events).toEqual([{ kind: 'CLIENT_STATE_CHANGED', clientState: 'STOPPED' }]);
    expect(calls).toEqual([]);
    expect(await client.shutdown()).toEqual({ ok: false, code: 'E_SDK_CLIENT_STOPPED' });
  });

  test('in RUNNING with QUEUED, IN_FLIGHT and awaiting items: lost, ordering and released sockets', async () => {
    const QUEUED_KEY = 'c'.repeat(64);
    const HELD_KEY = 'd'.repeat(64);
    const AWAIT_KEY = 'e'.repeat(64);
    const relay = await startRelay({ rejectFor: [QUEUED_KEY], holdFor: [HELD_KEY] });
    const log = [];
    const alice = await startMember([relay], { delivery: { receiptMode: 'RECIPIENT_RECEIPT' }, log });
    const ids = {};
    for (const [name, key] of [['queued', QUEUED_KEY], ['inFlight', HELD_KEY], ['awaiting', AWAIT_KEY]]) {
      ids[name] = (await alice.client.send({ recipient: key, payload: new Uint8Array([1]) })).value.deliveryId;
    }
    await waitFor(() => deliveryEvents(alice.events, ids.queued).some((event) => event.state === 'QUEUED')
      && deliveryEvents(alice.events, ids.awaiting).some((event) => event.state === 'RELAY_ACCEPTED_AWAITING_RECEIPT')
      && deliveryEvents(alice.events, ids.inFlight).some((event) => event.state === 'IN_FLIGHT'));
    await flushMicrotasks();
    const before = {};
    for (const [name, id] of Object.entries(ids)) before[name] = (await alice.client.getDelivery({ deliveryId: id })).value;
    expect(before.queued.state).toBe('QUEUED');
    expect(before.inFlight.state).toBe('IN_FLIGHT');
    const order = [];
    const early = [];
    await alice.client.onEvent((event) => {
      early.push(event);
      if (event.kind === 'DELIVERY_STATE_CHANGED' && event.state === 'LOST_ON_SHUTDOWN') {
        log.push({ type: 'lost' });
        socketLog.push({ type: 'lost' });
      }
    });
    const mark = log.length;
    const socketMark = socketLog.length;
    const stopping = alice.client.shutdown();
    const late = [];
    await alice.client.onEvent((event) => late.push(event));
    const result = await stopping;
    expect(result).toEqual({ ok: true, value: { clientState: 'STOPPED', lost: 3 } });
    expect(late).toEqual([]);
    const lostEvents = early.filter((event) => event.state === 'LOST_ON_SHUTDOWN');
    expect(lostEvents.map((event) => event.deliveryId).sort()).toEqual(Object.values(ids).sort());
    for (const event of lostEvents) expect(event.lastCode).toBeNull();
    expect(early.at(-1)).toEqual({ kind: 'CLIENT_STATE_CHANGED', clientState: 'STOPPED' });
    expect(alice.events.at(-1)).toEqual({ kind: 'CLIENT_STATE_CHANGED', clientState: 'STOPPED' });
    // Every LOST_ON_SHUTDOWN listener call precedes the first clearTimer and the first socket close().
    const afterMark = log.slice(mark);
    const firstClear = afterMark.findIndex((entry) => entry.type === 'clearTimer');
    const lastLost = afterMark.map((entry) => entry.type).lastIndexOf('lost');
    expect(lastLost).toBeGreaterThanOrEqual(0);
    expect(firstClear).toBeGreaterThan(lastLost);
    const afterSocketMark = socketLog.slice(socketMark);
    const firstClose = afterSocketMark.findIndex((entry) => entry.type === 'close');
    expect(firstClose).toBeGreaterThan(afterSocketMark.map((entry) => entry.type).lastIndexOf('lost'));
    // Snapshots after the stop.
    for (const [name, id] of Object.entries(ids)) {
      const snapshot = await alice.client.getDelivery({ deliveryId: id });
      expect(snapshot.value.state).toBe('LOST_ON_SHUTDOWN');
      expect(snapshot.value.lastCode).toBeNull();
      expect(snapshot.value.relayOutcomes).toEqual(before[name].relayOutcomes);
    }
    // Every socket the client opened was closed.
    for (const socket of openedSockets) expect(socket.closeCalled).toBe(true);
    await relay.waitForClientsClosed();
    expect(alice.manual.timers.size).toBe(0);
    for (const call of [alice.client.start(), alice.client.send({ recipient: HEX_B, payload: new Uint8Array(1) }),
      alice.client.cancel({ deliveryId: ids.queued }), alice.client.shutdown()]) {
      expect(await call).toEqual({ ok: false, code: 'E_SDK_CLIENT_STOPPED' });
    }
    expect((await alice.client.onEvent(() => {})).ok).toBe(true);
  }, 30000);

  test('waits for a held put and a held inbound open', async () => {
    const relay = await startRelay();
    let releasePut;
    let releaseOpen;
    let openStarted = false;
    const storage = storagePort();
    const put = storage.put;
    const session = sessionPort();
    const holdingSession = {
      seal: session.seal,
      open: (argument) => {
        openStarted = true;
        return new Promise((resolve) => { releaseOpen = () => resolve(session.open(argument)); });
      },
    };
    const alice = await startMember([relay], { storage, session: holdingSession });
    const bob = await startMember([relay]);
    await bob.client.send({ recipient: alice.identity.publicKey, payload: new Uint8Array([1]) });
    await waitFor(() => openStarted, { clock: bob.manual });
    storage.put = (record) => new Promise((resolve) => { releasePut = () => resolve(put(record)); });
    const sending = alice.client.send({ recipient: HEX_B, payload: new Uint8Array([2]) });
    await waitFor(() => releasePut !== undefined);
    let resolved = false;
    const stopping = alice.client.shutdown().then((result) => {
      resolved = true;
      return result;
    });
    await sleep(100);
    expect(resolved).toBe(false);
    releasePut();
    await sleep(50);
    expect(resolved).toBe(false);
    releaseOpen();
    const result = await stopping;
    expect(result.ok).toBe(true);
    expect((await sending).ok).toBe(true);
    expect(result.value.lost).toBe(1);
  }, 30000);

  test('a shutdown() during a start() in progress makes it resolve E_SDK_CLIENT_STOPPED', async () => {
    const relay = await startRelay();
    const manual = manualClock();
    const client = createClient(makeConfig({ relays: [relay.url], clock: manual.clock }));
    const starting = client.start();
    await waitFor(() => relay.reqs >= 1);
    const stopping = client.shutdown();
    manual.advance(PER_RELAY_MS);
    expect(await starting).toEqual({ ok: false, code: 'E_SDK_CLIENT_STOPPED' });
    expect(await stopping).toEqual({ ok: true, value: { clientState: 'STOPPED', lost: 0 } });
    await relay.waitForClientsClosed();
    expect(relay.sockets.size).toBe(0);
    expect(manual.timers.size).toBe(0);
  }, 30000);

  test('a shutdown() reentering from the clock while the connection phase arms opens no connection', async () => {
    const relay = await startRelay();
    const manual = manualClock();
    let client = null;
    let stopping = null;
    const clock = {
      now: () => manual.clock.now(),
      setTimer: (callback, delayMs) => {
        const handle = manual.clock.setTimer(callback, delayMs);
        if (stopping === null && delayMs === PER_RELAY_MS) stopping = client.shutdown();
        return handle;
      },
      clearTimer: (handle) => manual.clock.clearTimer(handle),
    };
    client = createClient(makeConfig({ relays: [relay.url], clock }));
    const starting = client.start();
    await waitFor(() => stopping !== null);
    manual.advance(PER_RELAY_MS);
    expect(await starting).toEqual({ ok: false, code: 'E_SDK_CLIENT_STOPPED' });
    expect(await stopping).toEqual({ ok: true, value: { clientState: 'STOPPED', lost: 0 } });
    await sleep(100);
    expect(relay.connections).toBe(0);
    expect(openedSockets.size).toBe(0);
    expect(manual.timers.size).toBe(0);
  }, 30000);

  test('a shutdown() reentering from the clock while an attempt timer arms publishes nothing', async () => {
    const relay = await startRelay({ holdFor: [HEX_B] });
    const manual = manualClock();
    let client = null;
    let armed = false;
    let stopping = null;
    const clock = {
      now: () => manual.clock.now(),
      setTimer: (callback, delayMs) => {
        const handle = manual.clock.setTimer(callback, delayMs);
        if (armed && stopping === null && delayMs === PER_RELAY_MS) stopping = client.shutdown();
        return handle;
      },
      clearTimer: (handle) => manual.clock.clearTimer(handle),
    };
    client = createClient(makeConfig({ relays: [relay.url], clock }));
    const events = [];
    await client.onEvent((event) => events.push(event));
    expect(await startOnLoopback(client, manual, [relay])).toEqual(
      { ok: true, value: { clientState: 'RUNNING', connectedRelays: 1 } },
    );
    armed = true;
    const sent = await client.send({ recipient: HEX_B, payload: new Uint8Array([1]) });
    expect(sent.ok).toBe(true);
    await waitFor(() => stopping !== null);
    expect(await stopping).toEqual({ ok: true, value: { clientState: 'STOPPED', lost: 1 } });
    await sleep(100);
    expect(relay.kindCounts.get(4741) ?? 0).toBe(0);
    expect(deliveryEvents(events, sent.value.deliveryId).at(-1)).toMatchObject({ state: 'LOST_ON_SHUTDOWN' });
    expect(manual.timers.size).toBe(0);
  }, 30000);

  test('an identity-method getter that stops the client: the method is never invoked', async () => {
    const identity = identityPort();
    const client = createClient(makeConfig({ relays: [`ws${SEP}127.0.0.1:${await freeLoopbackPort()}`],
      identity: identity.port }));
    let stopping = null;
    let invoked = 0;
    // Installed after validation: the port is a live reference.
    Object.defineProperty(identity.port, 'getPublicKey', {
      configurable: true,
      get: () => {
        stopping = client.shutdown();
        return () => { invoked += 1; return identity.publicKey; };
      },
    });
    expect(await client.start()).toEqual({ ok: false, code: 'E_SDK_CLIENT_STOPPED' });
    expect(await stopping).toEqual({ ok: true, value: { clientState: 'STOPPED', lost: 0 } });
    expect(invoked).toBe(0);
  }, 30000);

  test('a storage port whose update throws and a listener that throws do not prevent success', async () => {
    const relay = await startRelay({ holdFor: [HEX_B] });
    const storage = storagePort();
    const alice = await startMember([relay], { storage });
    await alice.client.send({ recipient: HEX_B, payload: new Uint8Array([1]) });
    storage.update = () => { throw new Error('storage fault'); };
    await alice.client.onEvent(() => { throw new Error('listener fault'); });
    const result = await alice.client.shutdown();
    expect(result).toEqual({ ok: true, value: { clientState: 'STOPPED', lost: 1 } });
  }, 30000);

  test('a new client with a new empty store does not see the old items', async () => {
    const relay = await startRelay({ holdFor: [HEX_B] });
    const alice = await startMember([relay]);
    const sent = await alice.client.send({ recipient: HEX_B, payload: new Uint8Array([1]) });
    await alice.client.shutdown();
    const again = await startMember([relay]);
    expect(await again.client.getDelivery({ deliveryId: sent.value.deliveryId }))
      .toEqual({ ok: false, code: 'E_SDK_UNKNOWN_DELIVERY' });
  }, 30000);
});

// The digest helper is used by the identity ports above through schnorr; this
// check keeps the declared sha256 import meaningful for the receipt digest.
describe('test harness', () => {
  test('sha256 digests are 32 bytes', () => {
    expect(sha256(new Uint8Array([1]))).toHaveLength(32);
  });
});

/* --- review probes r1 to r4, lane doubles (cycle 4) --- */
describe('review probe r1: probe-result-check (regression)', () => {

  const VERSION = 'styx-m3-sdk/0.1.0-experimental';
  const ok = (value) => Object.freeze({
    ok: true,
    value: Object.freeze(value),
  });

  async function makeClient(sendResult) {
    jest.resetModules();
    const failClosedIds = [];

    const outbox = {
      inspectStore: async () => ok({ empty: true }),
      adoptPublicKey: () => ok({ adopted: true }),
      send: async () => sendResult,
      getDelivery: async () => Object.freeze({
        ok: false,
        code: 'E_SDK_UNKNOWN_DELIVERY',
      }),
      cancel: async ({ deliveryId }) => ok({
        deliveryId,
        state: 'CANCELLED',
      }),
      acceptReceipt: async () => ok({ accepted: false }),
      failClosed({ deliveryId }) {
        failClosedIds.push(deliveryId);
        return ok({ deliveryId, state: 'FAILED_NOT_ACCEPTED' });
      },
      shutdown: async () => ok({ clientState: 'STOPPED', lost: 0 }),
    };

    jest.unstable_mockModule('../../src/sdk/delivery/outbox.js', () => ({
      createOutbox: () => outbox,
    }));
    jest.unstable_mockModule('../../src/sdk/delivery/receipts.js', () => ({
      createReceipts: () => ({
        ingest: () => ok({ queued: true }),
        shutdown: () => ok({ dropped: 0 }),
        settled: async () => undefined,
      }),
    }));
    jest.unstable_mockModule('../../src/sdk/delivery/relay-pool.js', () => ({
      createRelaySet: () => ({
        start: async () => ({ connectedRelays: 1 }),
        onFrame: () => () => {},
        publish: () => {
          throw new Error('This double must not publish');
        },
        freeze() {},
        dispose: async () => undefined,
      }),
    }));

    const { createStyxClient } = await import('../../src/sdk/client.js');
    const created = createStyxClient({
      interfaceVersion: VERSION,
      relays: ['ws://127.0.0.1:7000'],
      ports: {
        storage: {
          put: () => true,
          get: () => null,
          update: () => true,
          remove: () => true,
          list: () => [],
        },
        session: {
          seal: ({ plaintext }) => ({
            ciphertext: new Uint8Array(plaintext),
          }),
          open: ({ ciphertext }) => ({
            plaintext: new Uint8Array(ciphertext),
          }),
        },
        identity: {
          getPublicKey: () => 'a'.repeat(64),
          sign: () => new Uint8Array(64),
        },
      },
    });
    expect(created.ok).toBe(true);
    const client = created.value;
    expect((await client.start()).ok).toBe(true);
    return { client, failClosedIds };
  }

  function responseWithAccessorBeforeUnknown() {
    const unrelated = {};
    Object.defineProperty(unrelated, 'accessor', {
      enumerable: true,
      get() {
        throw new Error('The checker must not invoke this getter');
      },
    });
    return Object.freeze({
      ok: true,
      unrelated,
      value: Object.freeze({
        deliveryId: 'd1',
        state: 'UNLISTED_STATE',
      }),
    });
  }

  function responseWithDeepFieldBeforeUnknown() {
    let unrelated = null;
    for (let depth = 0; depth < 12; depth += 1) {
      unrelated = { child: unrelated };
    }
    return Object.freeze({
      ok: true,
      unrelated,
      value: Object.freeze({
        deliveryId: 'd1',
        state: 'UNLISTED_STATE',
      }),
    });
  }

  function responseWithUnknownOnTypedArray() {
    const bytes = new Uint8Array([1]);
    Object.defineProperty(bytes, 'code', {
      value: 'E_SDK_NEW',
      enumerable: false,
    });
    return ok({
      deliveryId: 'd1',
      state: 'QUEUED',
      bytes,
    });
  }

  test.each([
    ['accessor before unknown state', responseWithAccessorBeforeUnknown],
    ['deep field before unknown state', responseWithDeepFieldBeforeUnknown],
    ['unknown custom slot on a typed array', responseWithUnknownOnTypedArray],
  ])('unknown precedence: %s', async (_name, makeResponse) => {
    const { client, failClosedIds } = await makeClient(makeResponse());
    try {
      const result = await client.send({
        recipient: 'b'.repeat(64),
        payload: new Uint8Array([1]),
      });

      // Expected at this head: E_SDK_INTERNAL and [].
      expect({ result, failClosedIds }).toEqual({
        result: { ok: false, code: 'E_SDK_UNKNOWN_CODE' },
        failClosedIds: ['d1'],
      });
    } finally {
      await client.shutdown();
    }
  });

  test('an unfrozen outbox success envelope is a contract deviation', async () => {
    const { client } = await makeClient({
      ok: true,
      value: { deliveryId: 'd1', state: 'QUEUED' },
    });
    try {
      // Expected at this head: success with d1 / QUEUED.
      expect(await client.send({
        recipient: 'b'.repeat(64),
        payload: new Uint8Array([1]),
      })).toEqual({
        ok: false,
        code: 'E_SDK_INTERNAL',
      });
    } finally {
      await client.shutdown();
    }
  });

  test('send cannot forward the known but forbidden identity-failure code', async () => {
    const { client } = await makeClient(Object.freeze({
      ok: false,
      code: 'E_SDK_IDENTITY_FAILED',
    }));
    try {
      // Expected at this head: E_SDK_IDENTITY_FAILED.
      expect(await client.send({
        recipient: 'b'.repeat(64),
        payload: new Uint8Array([1]),
      })).toEqual({
        ok: false,
        code: 'E_SDK_INTERNAL',
      });
    } finally {
      await client.shutdown();
    }
  });
});

describe('review probe r2: probe-r2-slot-scan (regression)', () => {

  const ok = (value) => Object.freeze({
    ok: true,
    value: Object.freeze(value),
  });

  async function makeClient(sendResult) {
    jest.resetModules();
    const failClosedIds = [];

    jest.unstable_mockModule('../../src/sdk/delivery/outbox.js', () => ({
      createOutbox: () => ({
        inspectStore: async () => ok({ empty: true }),
        adoptPublicKey: () => ok({ adopted: true }),
        send: async () => sendResult,
        acceptReceipt: async () => ok({ accepted: false }),
        failClosed({ deliveryId }) {
          failClosedIds.push(deliveryId);
          return ok({ deliveryId, state: 'FAILED_NOT_ACCEPTED' });
        },
        shutdown: async () => ok({ clientState: 'STOPPED', lost: 0 }),
      }),
    }));
    jest.unstable_mockModule('../../src/sdk/delivery/receipts.js', () => ({
      createReceipts: () => ({
        ingest: () => ok({ queued: true }),
        shutdown: () => ok({ dropped: 0 }),
        settled: async () => undefined,
      }),
    }));
    jest.unstable_mockModule('../../src/sdk/delivery/relay-pool.js', () => ({
      createRelaySet: () => ({
        start: async () => ({ connectedRelays: 1 }),
        onFrame: () => () => undefined,
        freeze() {},
        dispose: async () => undefined,
      }),
    }));

    const { createStyxClient } = await import('../../src/sdk/client.js');
    const created = createStyxClient({
      interfaceVersion: 'styx-m3-sdk/0.1.0-experimental',
      relays: ['ws://127.0.0.1:7000'],
      ports: {
        storage: {
          put: () => true,
          get: () => null,
          update: () => true,
          remove: () => true,
          list: () => [],
        },
        session: {
          seal: ({ plaintext }) => ({ ciphertext: plaintext }),
          open: ({ ciphertext }) => ({ plaintext: ciphertext }),
        },
        identity: {
          getPublicKey: () => 'a'.repeat(64),
          sign: () => new Uint8Array(64),
        },
      },
    });
    expect(created.ok).toBe(true);
    expect((await created.value.start()).ok).toBe(true);
    return { client: created.value, failClosedIds };
  }

  function unknownInsideFunction() {
    const nested = () => undefined;
    Object.defineProperty(nested, 'code', {
      value: 'E_SDK_NEW',
      enumerable: false,
    });
    return ok({ deliveryId: 'd1', state: 'QUEUED', nested });
  }

  function unknownOnTypedArrayWithThrowingPrototype() {
    const bytes = new Uint8Array([1]);
    Object.defineProperty(bytes, 'code', {
      value: 'E_SDK_NEW',
      enumerable: false,
    });

    Object.setPrototypeOf(bytes, new Proxy(Object.create(null), {
      getPrototypeOf() {
        throw new Error('own-slot inspection need not traverse this prototype');
      },
    }));

    return ok({ deliveryId: 'd1', state: 'QUEUED', bytes });
  }

  test.each([
    ['unknown slot inside a function', unknownInsideFunction],
    ['typed-array prototype fault cannot hide its own code',
      unknownOnTypedArrayWithThrowingPrototype],
  ])('%s', async (_title, makeResult) => {
    const { client, failClosedIds } = await makeClient(makeResult());
    try {
      const result = await client.send({
        recipient: 'b'.repeat(64),
        payload: new Uint8Array([1]),
      });

      // Both predicted: E_SDK_INTERNAL and [].
      expect({ result, failClosedIds }).toEqual({
        result: { ok: false, code: 'E_SDK_UNKNOWN_CODE' },
        failClosedIds: ['d1'],
      });
    } finally {
      await client.shutdown();
    }
  });
});

describe('review probe r3: probe-r3-unknown-precedence, lane doubles (regression)', () => {

  const ok = (value) => Object.freeze({
    ok: true,
    value: Object.freeze(value),
  });

  function config() {
    const records = new Map();
    return {
      interfaceVersion: 'styx-m3-sdk/0.1.0-experimental',
      relays: [
        'ws://127.0.0.1:7000',
        'ws://127.0.0.1:7001',
      ],
      delivery: { perRelayTimeoutMs: 11000 },
      ports: {
        storage: {
          put(record) {
            records.set(record.deliveryId, record);
            return true;
          },
          get: (id) => records.get(id) ?? null,
          update(id, record) {
            records.set(id, record);
            return true;
          },
          remove: (id) => records.delete(id),
          list: () => [...records.values()],
        },
        session: {
          seal: ({ plaintext }) => ({
            ciphertext: new Uint8Array(plaintext),
          }),
          open: ({ ciphertext }) => ({
            plaintext: new Uint8Array(ciphertext),
          }),
        },
        identity: {
          getPublicKey: () => 'a'.repeat(64),
          sign: () => new Uint8Array(64),
        },
      },
    };
  }

  function attemptFor(event, mode) {
    if (mode === 'callable-root') {
      return Object.freeze(Object.assign(
        () => undefined,
        { code: 'E_SDK_NEW' },
      ));
    }

    let acceptGate = null;
    let latePublishGate = null;
    const valid = mode === 'valid';

    const outcomes = valid
      ? Object.freeze(['ACCEPTED', 'ACCEPTED'])
      : new Proxy(Object.freeze(['PENDING', 'UNLISTED_OUTCOME']), {
        getOwnPropertyDescriptor(target, key) {
          if (key === '0') throw new Error('unreadable first descriptor');
          return Reflect.getOwnPropertyDescriptor(target, key);
        },
      });

    const attempt = {
      index: 1,
      event,
      outcomes,
      publishedOnce: Object.freeze([valid, valid]),
      get acceptedIndex() {
        return valid ? 0 : -1;
      },
      isSettled: () => valid,
      onOutcome(listener) {
        if (valid) {
          listener(0, 'ACCEPTED');
          listener(1, 'ACCEPTED');
        }
        return () => undefined;
      },
      onSettled(listener) {
        if (valid) listener();
        return () => undefined;
      },
      ignoreAcks() {},
      get acceptGate() {
        return acceptGate;
      },
      set acceptGate(value) {
        acceptGate = value;
      },
      get latePublishGate() {
        return latePublishGate;
      },
      set latePublishGate(value) {
        latePublishGate = value;
      },
    };

    Object.setPrototypeOf(attempt, null);
    return Object.freeze(attempt);
  }

  function mockRelay(mode) {
    jest.unstable_mockModule('../../src/sdk/delivery/relay-pool.js', () => ({
      createRelaySet: () => ({
        start: async () => ({ connectedRelays: 2 }),
        onFrame: () => () => undefined,
        publish: (event) => attemptFor(event, mode),
        freeze() {},
        dispose: async () => undefined,
      }),
    }));
  }

  test('an unknown slot on a root callable envelope also fails its item closed', async () => {
    jest.resetModules();
    mockRelay('valid');

    const failClosedIds = [];
    const returned = Object.freeze(Object.assign(
      () => undefined,
      {
        ok: true,
        value: Object.freeze({ deliveryId: 'd1', state: 'QUEUED' }),
        code: 'E_SDK_NEW',
      },
    ));

    jest.unstable_mockModule('../../src/sdk/delivery/outbox.js', () => ({
      createOutbox: () => ({
        inspectStore: async () => ok({ empty: true }),
        adoptPublicKey: () => ok({ adopted: true }),
        send: async () => returned,
        acceptReceipt: async () => ok({ accepted: false }),
        failClosed({ deliveryId }) {
          failClosedIds.push(deliveryId);
          return ok({ deliveryId, state: 'FAILED_NOT_ACCEPTED' });
        },
        shutdown: async () => ok({ clientState: 'STOPPED', lost: 0 }),
      }),
    }));

    const { createStyxClient } = await import('../../src/sdk/client.js');
    const created = createStyxClient(config());
    expect(created.ok).toBe(true);
    const client = created.value;

    try {
      expect((await client.start()).ok).toBe(true);
      const result = await client.send({
        recipient: 'b'.repeat(64),
        payload: new Uint8Array([1]),
      });

      // Predicted: E_SDK_INTERNAL and [].
      expect({ result, failClosedIds }).toEqual({
        result: { ok: false, code: 'E_SDK_UNKNOWN_CODE' },
        failClosedIds: ['d1'],
      });
    } finally {
      await client.shutdown();
    }
  });
});

/* --- port boundary: systematic table (cycle 4) --- */

describe('port boundary: identity port at the client (table)', () => {
  const R = `ws${SEP}127.0.0.1:7000`;
  const turns = async (count = 50) => {
    for (let turn = 0; turn < count; turn += 1) await Promise.resolve();
  };
  const unknownState = new Proxy(Object.freeze({ state: 'R4_FUTURE_STATE' }), {
    getOwnPropertyDescriptor(target, name) {
      if (name === 'code') throw new Error('descriptor fault');
      return Reflect.getOwnPropertyDescriptor(target, name);
    },
  });
  const throwingTraps = new Proxy({}, {
    get() { throw new Error('get'); },
    getOwnPropertyDescriptor() { throw new Error('descriptor'); },
    ownKeys() { throw new Error('keys'); },
    getPrototypeOf() { throw new Error('prototype'); },
    has() { throw new Error('has'); },
  });

  // [row, how the method is replaced after createStyxClient, expected code]
  const rows = [
    ['lookup throws', (port) => Object.defineProperty(port, 'getPublicKey', {
      get() { throw new Error('lookup'); }, configurable: true,
    }), 'E_SDK_IDENTITY_FAILED'],
    ['absent', (port) => { delete port.getPublicKey; }, 'E_SDK_IDENTITY_FAILED'],
    ['not a function', (port) => { port.getPublicKey = 7; }, 'E_SDK_IDENTITY_FAILED'],
    ['synchronous throw', (port) => { port.getPublicKey = () => { throw new Error('sync'); }; }, 'E_SDK_IDENTITY_FAILED'],
    ['rejection', (port) => { port.getPublicKey = () => Promise.reject(new Error('rejected')); }, 'E_SDK_IDENTITY_FAILED'],
    ['thenable whose then throws', (port) => {
      port.getPublicKey = () => ({ get then() { throw new Error('then'); } });
    }, 'E_SDK_IDENTITY_FAILED'],
    ['returns a function', (port) => { port.getPublicKey = () => () => 'a'.repeat(64); }, 'E_SDK_IDENTITY_FAILED'],
    ['returns a proxy whose traps throw', (port) => { port.getPublicKey = () => throwingTraps; }, 'E_SDK_IDENTITY_FAILED'],
    ['returns an object with a throwing getter', (port) => {
      port.getPublicKey = () => ({ get code() { throw new Error('getter'); } });
    }, 'E_SDK_IDENTITY_FAILED'],
    ['returns an unfrozen object', (port) => { port.getPublicKey = () => ({ key: 'a'.repeat(64) }); }, 'E_SDK_IDENTITY_FAILED'],
    ['returns an unknown code', (port) => { port.getPublicKey = () => Object.freeze({ code: 'E_SDK_FUTURE' }); }, 'E_SDK_UNKNOWN_CODE'],
    ['returns an unknown state behind a descriptor fault', (port) => { port.getPublicKey = () => unknownState; }, 'E_SDK_UNKNOWN_CODE'],
    ['returns a function carrying an unknown code', (port) => {
      port.getPublicKey = () => Object.freeze(Object.assign(() => undefined, { code: 'E_SDK_FUTURE' }));
    }, 'E_SDK_UNKNOWN_CODE'],
  ];

  function countedPorts() {
    const calls = [];
    const identity = identityPort();
    const storage = storagePort();
    const session = sessionPort();
    const counted = (port, names) => {
      const wrapped = {};
      for (const name of names) {
        const original = port[name];
        wrapped[name] = function counting(...args) {
          calls.push(name);
          return Reflect.apply(original, port, args);
        };
      }
      return wrapped;
    };
    return {
      calls,
      identity: counted(identity.port, ['getPublicKey', 'sign']),
      storage: counted(storage, ['put', 'get', 'update', 'remove', 'list']),
      session: counted(session, ['seal', 'open']),
    };
  }

  test.each(rows)('%s', async (_row, replace, code) => {
    const ports = countedPorts();
    const client = clientModule.createStyxClient(makeConfig({
      relays: [R], identity: ports.identity, storage: ports.storage, session: ports.session,
    })).value;
    replace(ports.identity);
    const started = await client.start();
    expect(started).toEqual({ ok: false, code });
    expect(Object.isFrozen(started)).toBe(true);
    expect(openedSockets.size).toBe(0);
    const stopped = await client.shutdown();
    expect(stopped).toEqual({ ok: true, value: { clientState: 'STOPPED', lost: 0 } });
    const after = ports.calls.length;
    await turns();
    expect(ports.calls.length).toBe(after);
    expect(ports.calls.filter((name) => name === 'sign' || name === 'seal' || name === 'open')).toEqual([]);
  });

  test('a call that never settles is bounded by the port-call timeout', async () => {
    const ports = countedPorts();
    const client = clientModule.createStyxClient(makeConfig({
      relays: [R], identity: ports.identity, storage: ports.storage, session: ports.session,
    })).value;
    ports.identity.getPublicKey = () => new Promise(() => undefined);
    const begun = Date.now();
    expect(await client.start()).toEqual({ ok: false, code: 'E_SDK_IDENTITY_FAILED' });
    expect(Date.now() - begun).toBeGreaterThanOrEqual(Math.floor(PER_RELAY_MS / 2) - 50);
    expect((await client.shutdown()).ok).toBe(true);
  }, 30000);

  test('re-entry: a lookup that stops the client invokes no method', async () => {
    const ports = countedPorts();
    let invoked = false;
    const client = clientModule.createStyxClient(makeConfig({
      relays: [R], identity: ports.identity, storage: ports.storage, session: ports.session,
    })).value;
    let stopping = null;
    Object.defineProperty(ports.identity, 'getPublicKey', {
      get() {
        stopping = client.shutdown();
        return () => {
          invoked = true;
          return 'a'.repeat(64);
        };
      },
      configurable: true,
    });
    expect(await client.start()).toEqual({ ok: false, code: 'E_SDK_CLIENT_STOPPED' });
    expect(invoked).toBe(false);
    expect((await stopping).ok).toBe(true);
    expect(openedSockets.size).toBe(0);
  });

  test('re-entry: a method that stops the client is waited for, and nothing follows it', async () => {
    const ports = countedPorts();
    const client = clientModule.createStyxClient(makeConfig({
      relays: [R], identity: ports.identity, storage: ports.storage, session: ports.session,
    })).value;
    let release;
    let stopping = null;
    let stopResolved = false;
    ports.identity.getPublicKey = () => {
      stopping = client.shutdown().then((result) => {
        stopResolved = true;
        return result;
      });
      return new Promise((resolve) => {
        release = resolve;
      });
    };
    const starting = client.start();
    await turns(100);
    expect(stopping).not.toBeNull();
    expect(stopResolved).toBe(false);
    const before = ports.calls.length;
    release('a'.repeat(64));
    expect(await starting).toEqual({ ok: false, code: 'E_SDK_CLIENT_STOPPED' });
    expect((await stopping).ok).toBe(true);
    expect(ports.calls.slice(before)).toEqual([]);
    expect(openedSockets.size).toBe(0);
  });
});

describe('port boundary: delivery seams (table)', () => {
  const turns = async (count = 100) => {
    for (let turn = 0; turn < count; turn += 1) await Promise.resolve();
  };
  const unhandled = [];
  const onUnhandled = (reason) => unhandled.push(reason);
  beforeEach(() => {
    unhandled.length = 0;
    process.on('unhandledRejection', onUnhandled);
  });
  afterEach(async () => {
    await new Promise((resolve) => setTimeout(resolve, 0));
    process.off('unhandledRejection', onUnhandled);
    expect(unhandled).toEqual([]);
  });

  const throwingTraps = () => new Proxy({}, {
    get() { throw new Error('get'); },
    getOwnPropertyDescriptor() { throw new Error('descriptor'); },
    ownKeys() { throw new Error('keys'); },
    getPrototypeOf() { throw new Error('prototype'); },
    has() { throw new Error('has'); },
  });

  // Each fault: its class and how it replaces member `name` of `holder`.
  // `valid` is the member's own valid return, `unknown` a return carrying an
  // out-of-set closed slot about the same item.
  const FAULTS = [
    ['lookup throws', 'call', (holder, name) => Object.defineProperty(holder, name, {
      get() { throw new Error('lookup'); }, configurable: true,
    })],
    ['absent', 'call', (holder, name) => { delete holder[name]; }],
    ['not a function', 'call', (holder, name) => { holder[name] = 7; }],
    ['synchronous throw', 'call', (holder, name) => { holder[name] = () => { throw new Error('sync'); }; }],
    ['rejection', 'thenable', (holder, name) => { holder[name] = () => Promise.reject(new Error('rejected')); }],
    ['thenable whose then throws', 'thenable', (holder, name) => {
      holder[name] = () => ({ get then() { throw new Error('then'); } });
    }],
    ['returns a function', 'malformed', (holder, name, member) => {
      holder[name] = () => Object.freeze(Object.assign(() => undefined, member.valid()));
    }],
    ['returns a proxy whose traps throw', 'malformed', (holder, name) => { holder[name] = () => throwingTraps(); }],
    ['returns an unfrozen value', 'unfrozen', (holder, name, member) => { holder[name] = () => member.unfrozen(); }],
    ['returns an unknown closed slot', 'unknown', (holder, name, member) => { holder[name] = () => member.unknown(); }],
    ['returns a function carrying an unknown closed slot', 'unknown', (holder, name, member) => {
      holder[name] = () => Object.freeze(Object.assign(() => undefined, member.unknown()));
    }],
  ];

  const okEnvelope = (value) => Object.freeze({ ok: true, value: Object.freeze(value) });
  const unfrozenEnvelope = (value) => ({ ok: true, value: { ...value } });
  const unknownItem = (id) => okEnvelope({ deliveryId: id, state: 'R5_FUTURE_STATE' });

  async function startWith(doubles) {
    const module = await loadClientWith(doubles);
    const created = module.createStyxClient(makeConfig({ relays: [`ws${SEP}127.0.0.1:7000`] }));
    const client = created.value;
    const events = [];
    await client.onEvent((event) => events.push(event));
    return { client, events, started: await client.start() };
  }

  async function stopChecked(client) {
    const stopped = await client.shutdown();
    expect(stopped.ok).toBe(true);
    expect(stopped.value.clientState).toBe('STOPPED');
    expect(Number.isSafeInteger(stopped.value.lost) && stopped.value.lost >= 0).toBe(true);
    expect(await client.shutdown()).toEqual({ ok: false, code: 'E_SDK_CLIENT_STOPPED' });
  }

  /** The start-phase members: the result of `start()` for each fault class. */
  const START_MEMBERS = [
    ['outbox', 'inspectStore', {
      valid: () => okEnvelope({ empty: true }),
      unfrozen: () => unfrozenEnvelope({ empty: true }),
      unknown: () => Object.freeze({ ok: false, code: 'E_SDK_R5_FUTURE' }),
      expect: {
        call: 'E_SDK_INTERNAL', thenable: 'E_SDK_INTERNAL', malformed: 'E_SDK_INTERNAL', unfrozen: 'E_SDK_INTERNAL',
        unknown: 'E_SDK_UNKNOWN_CODE',
      },
    }],
    ['outbox', 'adoptPublicKey', {
      valid: () => okEnvelope({ adopted: true }),
      unfrozen: () => unfrozenEnvelope({ adopted: true }),
      unknown: () => Object.freeze({ ok: false, code: 'E_SDK_R5_FUTURE' }),
      expect: {
        call: 'E_SDK_INTERNAL', thenable: 'E_SDK_INTERNAL', malformed: 'E_SDK_INTERNAL', unfrozen: 'E_SDK_INTERNAL',
        unknown: 'E_SDK_UNKNOWN_CODE',
      },
    }],
    ['relaySet', 'start', {
      valid: () => ({ connectedRelays: 1 }),
      unfrozen: () => ({ connectedRelays: 1 }),
      unknown: () => Object.freeze({ connectedRelays: 1, code: 'E_SDK_R5_FUTURE' }),
      // A plain object is the contract's shape: an unfrozen one is valid.
      expect: {
        call: 'E_SDK_NO_RELAY_AVAILABLE', thenable: 'E_SDK_NO_RELAY_AVAILABLE', malformed: 'E_SDK_NO_RELAY_AVAILABLE',
        unfrozen: null, unknown: 'E_SDK_UNKNOWN_CODE',
      },
    }],
    ['relaySet', 'onFrame', {
      valid: () => () => undefined,
      unfrozen: () => () => undefined,
      unknown: () => Object.freeze({ code: 'E_SDK_R5_FUTURE' }),
      // Its return is not a lane result, but a failed call fails `start()`:
      // a throw, a rejection, and a returned thenable that fails (model B).
      // A proxy whose traps throw fails the adoption of the return.
      expect: { call: 'E_SDK_INTERNAL', thenable: 'E_SDK_INTERNAL', malformed: null, unfrozen: null, unknown: null },
      expectByFault: { 'returns a proxy whose traps throw': 'E_SDK_INTERNAL' },
    }],
  ];

  for (const [moduleName, name, member] of START_MEMBERS) {
    describe(`${moduleName}.${name} during start()`, () => {
      test.each(FAULTS)('%s', async (fault, kind, inject) => {
        const doubles = makeDoubles();
        inject(doubles[moduleName], name, member);
        const { client, started } = await startWith(doubles);
        const byFault = member.expectByFault || {};
        const code = Object.prototype.hasOwnProperty.call(byFault, fault) ? byFault[fault] : member.expect[kind];
        if (code === null) {
          expect(started.ok).toBe(true);
        } else {
          expect(started).toEqual({ ok: false, code });
        }
        expect(Object.isFrozen(started)).toBe(true);
        await stopChecked(client);
      });

      test('re-entry: the member stops the client', async () => {
        const doubles = makeDoubles();
        let client = null;
        let stopping = null;
        const holder = doubles[moduleName];
        const original = holder[name];
        let callsAtStop = null;
        doubles.relayStart = () => {
          doubles.calls.push('relayStart');
          return Promise.resolve({ connectedRelays: 1 });
        };
        holder[name] = (...args) => {
          stopping = client.shutdown();
          callsAtStop = doubles.calls.length;
          return Reflect.apply(original, holder, args);
        };
        const module = await loadClientWith(doubles);
        client = module.createStyxClient(makeConfig({ relays: [`ws${SEP}127.0.0.1:7000`] })).value;
        expect(await client.start()).toEqual({ ok: false, code: 'E_SDK_CLIENT_STOPPED' });
        const stopped = await stopping;
        expect(stopped.ok).toBe(true);
        expect(stopped.value.clientState).toBe('STOPPED');
        // After the stop began, no module is created and no connection phase
        // starts: only the stop's own calls follow.
        const later = doubles.calls.slice(callsAtStop).filter((entry) => entry !== 'freeze' && entry !== 'dispose');
        // The member's own call is the only connection phase.
        expect(later).toEqual(name === 'start' ? ['relayStart'] : []);
      });
    });
  }

  /** The item members: the result of the public method and the items failed closed. */
  const ITEM_MEMBERS = [
    ['send', (client) => client.send({ recipient: HEX_B, payload: new Uint8Array([1]) }), 'd1', {
      valid: () => okEnvelope({ deliveryId: 'd1', state: 'QUEUED' }),
      unfrozen: () => unfrozenEnvelope({ deliveryId: 'd1', state: 'QUEUED' }),
      unknown: () => unknownItem('d1'),
    }],
    ['cancel', (client) => client.cancel({ deliveryId: 'd2' }), 'd2', {
      valid: () => okEnvelope({ deliveryId: 'd2', state: 'CANCELLED' }),
      unfrozen: () => unfrozenEnvelope({ deliveryId: 'd2', state: 'CANCELLED' }),
      unknown: () => unknownItem('d2'),
    }],
    ['getDelivery', (client) => client.getDelivery({ deliveryId: 'd3' }), 'd3', {
      valid: () => okEnvelope(goodSnapshot('d3')),
      unfrozen: () => unfrozenEnvelope(goodSnapshot('d3')),
      unknown: () => okEnvelope(goodSnapshot('d3', { lastCode: 'E_SDK_R5_FUTURE' })),
    }],
  ];

  for (const [name, call, id, member] of ITEM_MEMBERS) {
    describe(`outbox.${name} through ${name}()`, () => {
      test.each(FAULTS)('%s', async (_fault, kind, inject) => {
        const doubles = makeDoubles();
        const { client, started } = await startWith(doubles);
        expect(started.ok).toBe(true);
        inject(doubles.outbox, name, member);
        const result = await call(client);
        expect(Object.isFrozen(result)).toBe(true);
        if (kind === 'unknown') {
          expect(result).toEqual({ ok: false, code: 'E_SDK_UNKNOWN_CODE' });
          expect(doubles.failClosedIds).toEqual([id]);
        } else {
          expect(result).toEqual({ ok: false, code: 'E_SDK_INTERNAL' });
          expect(doubles.failClosedIds).toEqual([]);
        }
        await stopChecked(client);
      });

      test('re-entry: the member stops the client', async () => {
        const doubles = makeDoubles();
        const { client, started } = await startWith(doubles);
        expect(started.ok).toBe(true);
        let stopping = null;
        const original = doubles.outbox[name];
        doubles.outbox[name] = (...args) => {
          stopping = client.shutdown();
          return Reflect.apply(original, doubles.outbox, args);
        };
        const result = await call(client);
        expect(Object.isFrozen(result)).toBe(true);
        expect(result.ok === true || clientModule.isKnownResultCode(result.code)).toBe(true);
        const stopped = await stopping;
        expect(stopped.ok).toBe(true);
        expect(await client.send({ recipient: HEX_B, payload: new Uint8Array([1]) }))
          .toEqual({ ok: false, code: 'E_SDK_CLIENT_STOPPED' });
      });
    });
  }

  describe('relaySet.publish through the outbound seam', () => {
    const attemptMember = {
      valid: () => ({ outcomes: Object.freeze(['PENDING']) }),
      unfrozen: () => ({ outcomes: ['PENDING'] }),
      unknown: () => ({ outcomes: Object.freeze(['R5_FUTURE_OUTCOME']) }),
    };
    test.each(FAULTS)('%s', async (_fault, kind, inject) => {
      const doubles = makeDoubles();
      const { client, started } = await startWith(doubles);
      expect(started.ok).toBe(true);
      inject(doubles.relaySet, 'publish', attemptMember);
      const event = Object.freeze({ id: 'e'.repeat(64) });
      if (kind === 'unknown') {
        const inert = doubles.outboxOptions.publish(event);
        expect([...inert.outcomes]).toEqual(['UNKNOWN']);
        expect(inert.acceptedIndex).toBe(-1);
        expect(inert.isSettled()).toBe(true);
      } else {
        expect(() => doubles.outboxOptions.publish(event)).toThrow(TypeError);
      }
      await stopChecked(client);
    });
  });

  describe('receipts.ingest through the inbound listener', () => {
    const ingestMember = {
      valid: () => okEnvelope({ queued: true }),
      unfrozen: () => unfrozenEnvelope({ queued: true }),
      unknown: () => Object.freeze({ ok: false, code: 'E_SDK_R5_FUTURE' }),
    };
    test.each(FAULTS)('%s', async (_fault, kind, inject) => {
      const doubles = makeDoubles();
      const { client, events, started } = await startWith(doubles);
      expect(started.ok).toBe(true);
      await turns();
      events.length = 0;
      inject(doubles.receipts, 'ingest', ingestMember);
      expect(doubles.frameListener({ relayIndex: 0, data: ['EVENT', 's', {}] })).toBeUndefined();
      await turns();
      expect(events).toEqual(kind === 'unknown' ? [{ kind: 'INBOUND_DISCARDED', code: 'E_SDK_UNKNOWN_CODE' }] : []);
      await stopChecked(client);
    });
  });

  describe('outbox.failClosed through the event sink', () => {
    const failMember = {
      valid: () => okEnvelope({ deliveryId: 'd9', state: 'FAILED_NOT_ACCEPTED' }),
      unfrozen: () => unfrozenEnvelope({ deliveryId: 'd9', state: 'FAILED_NOT_ACCEPTED' }),
      unknown: () => unknownItem('d9'),
    };
    test.each(FAULTS)('%s', async (_fault, _kind, inject) => {
      const doubles = makeDoubles();
      const { client, events, started } = await startWith(doubles);
      expect(started.ok).toBe(true);
      await turns();
      events.length = 0;
      inject(doubles.outbox, 'failClosed', failMember);
      const invalid = Object.freeze({
        kind: 'DELIVERY_STATE_CHANGED', deliveryId: 'd9', state: 'R5_FUTURE_STATE', terminal: false, lastCode: null,
      });
      expect(doubles.outboxSink(invalid)).toBeUndefined();
      expect(doubles.outboxSink(invalid)).toBeUndefined();
      await turns();
      expect(events).toEqual([]);
      await stopChecked(client);
    });
  });

  /** The stop members: `shutdown()` resolves success whatever each does. */
  const STOP_MEMBERS = [
    ['receipts', 'shutdown', () => okEnvelope({ dropped: 0 })],
    ['relaySet', 'freeze', () => undefined],
    ['outbox', 'shutdown', () => okEnvelope({ clientState: 'STOPPED', lost: 0 })],
    ['receipts', 'settled', () => undefined],
    ['relaySet', 'dispose', () => undefined],
  ];

  for (const [moduleName, name, validValue] of STOP_MEMBERS) {
    describe(`${moduleName}.${name} during shutdown()`, () => {
      const member = {
        valid: () => Object.freeze({ value: validValue() }),
        unfrozen: () => ({ value: validValue() }),
        unknown: () => Object.freeze({ ok: false, code: 'E_SDK_R5_FUTURE' }),
      };
      test.each(FAULTS)('%s', async (_fault, _kind, inject) => {
        const doubles = makeDoubles();
        const { client, started } = await startWith(doubles);
        expect(started.ok).toBe(true);
        inject(doubles[moduleName], name, member);
        await stopChecked(client);
        expect(doubles.calls.filter((entry) => entry === 'dispose').length).toBeLessThanOrEqual(1);
      });

      test('re-entry: the member calls shutdown() again', async () => {
        const doubles = makeDoubles();
        const { client, started } = await startWith(doubles);
        expect(started.ok).toBe(true);
        const holder = doubles[moduleName];
        const original = holder[name];
        let second = null;
        holder[name] = (...args) => {
          second = client.shutdown();
          return Reflect.apply(original, holder, args);
        };
        const stopped = await client.shutdown();
        expect(stopped.ok).toBe(true);
        expect(await second).toEqual({ ok: false, code: 'E_SDK_CLIENT_STOPPED' });
      });
    });
  }
});

/* --- review probes r5 within threat model B, lane doubles (cycle 5) --- */
describe('review probe r5: probe-r5-client-boundary, bounded shutdown waits (regression)', () => {
  const VERSION = 'styx-m3-sdk/0.1.0-experimental';
  const KEY = 'a'.repeat(64);
  const ok = (value) =>
    Object.freeze({ ok: true, value: Object.freeze(value) });

  async function turns(n = 100) {
    for (let i = 0; i < n; i += 1) await Promise.resolve();
  }

  async function harness() {
    jest.resetModules();

    const h = {
      hooks: {},
      calls: [],
      failClosedIds: [],
      options: null,
    };

    h.outbox = {
      inspectStore() {
        h.calls.push('inspectStore');
        return ok({ empty: true });
      },
      adoptPublicKey: () => ok({ adopted: true }),
      acceptReceipt: () => ok({}),
      send: () => ok({ deliveryId: 'd1', state: 'QUEUED' }),
      cancel: () => ok({ deliveryId: 'd1', state: 'CANCELLED' }),
      getDelivery: () =>
        Object.freeze({ ok: false, code: 'E_SDK_UNKNOWN_DELIVERY' }),
      failClosed({ deliveryId }) {
        h.failClosedIds.push(deliveryId);
        return ok({ deliveryId, state: 'FAILED_NOT_ACCEPTED' });
      },
      shutdown: () => ok({ clientState: 'STOPPED', lost: 0 }),
    };

    h.receipts = {
      ingest: () => ok({ queued: true }),
      shutdown: () => ok({ dropped: 0 }),
      settled: async () => undefined,
    };

    h.relaySet = {
      start: async () => ({ connectedRelays: 1 }),
      onFrame() {
        h.calls.push('onFrame');
        return () => undefined;
      },
      publish: () => ({}),
      freeze() {},
      dispose: async () => undefined,
    };

    jest.unstable_mockModule('../../src/sdk/delivery/outbox.js', () => ({
      createOutbox(options) {
        h.options = options;
        h.hooks.createOutbox?.();
        return h.outbox;
      },
    }));
    jest.unstable_mockModule('../../src/sdk/delivery/receipts.js', () => ({
      createReceipts() {
        h.calls.push('createReceipts');
        return h.receipts;
      },
    }));
    jest.unstable_mockModule('../../src/sdk/delivery/relay-pool.js', () => ({
      createRelaySet: () => h.relaySet,
    }));

    const { createStyxClient } = await import('../../src/sdk/client.js');
    const created = createStyxClient({
      interfaceVersion: VERSION,
      relays: ['ws://127.0.0.1:7000'],
      delivery: { perRelayTimeoutMs: 11000 },
      ports: {
        storage: {
          put: () => true,
          get: () => null,
          update: () => true,
          remove: () => true,
          list: () => [],
        },
        session: {
          seal: ({ plaintext }) => ({ ciphertext: plaintext }),
          open: ({ ciphertext }) => ({ plaintext: ciphertext }),
        },
        identity: {
          getPublicKey: () => KEY,
          sign: () => new Uint8Array(64),
        },
      },
    });
    expect(created.ok).toBe(true);
    h.client = created.value;
    return h;
  }

  test.each([
    ['receipts', 'settled'],
    ['outbox', 'shutdown'],
    ['relaySet', 'dispose'],
  ])(
    'r5-C1: an unresolved %s.%s must not hold shutdown indefinitely',
    async (holder, name) => {
      const h = await harness();
      expect((await h.client.start()).ok).toBe(true);
      let release;
      const pending = new Promise((resolve) => { release = resolve; });
      h[holder][name] = () => pending;
      jest.useFakeTimers();
      let finished = false;
      const stopping = h.client.shutdown().then((result) => {
        finished = true;
        return result;
      });
      try {
        // Far beyond the 5500 ms port-call timeout and the documented
        // shutdown budget; there are no real connection attempts here.
        await jest.advanceTimersByTimeAsync(60000);
        expect(finished).toBe(true);
      } finally {
        release(ok({ clientState: 'STOPPED', lost: 0 }));
        await stopping;
        jest.useRealTimers();
      }
    },
  );

  test('model B: shutdown is bounded when settled, the outbox stop and the disposal all never settle', async () => {
    const h = await harness();
    expect((await h.client.start()).ok).toBe(true);
    const never = new Promise(() => undefined);
    h.receipts.settled = () => never;
    h.outbox.shutdown = () => never;
    h.relaySet.dispose = () => never;
    jest.useFakeTimers();
    let result = null;
    const stopping = h.client.shutdown().then((value) => {
      result = value;
      return value;
    });
    try {
      // Three waits, each bounded by its backstop: settled 2P, the outbox stop
      // 5P and the disposal R + P (P = 5500 ms, R = 11 000 ms here).
      await jest.advanceTimersByTimeAsync(2 * 5500 + 5 * 5500 + 11000 + 5500 + 1);
      expect(result).toEqual({ ok: true, value: { clientState: 'STOPPED', lost: 0 } });
      expect(jest.getTimerCount()).toBe(0);
    } finally {
      await stopping;
      jest.useRealTimers();
    }
  });

  test.each([
    ['receipts', 'settled'],
    ['outbox', 'shutdown'],
    ['relaySet', 'dispose'],
  ])('model B: a failed start() is bounded when %s.%s never settles', async (holder, name) => {
    const h = await harness();
    h.relaySet.start = async () => ({ connectedRelays: 0 });
    h[holder][name] = () => new Promise(() => undefined);
    jest.useFakeTimers();
    let result = null;
    const starting = h.client.start().then((value) => {
      result = value;
      return value;
    });
    try {
      // The stuck wait's backstop: at most 5P (the outbox stop).
      await jest.advanceTimersByTimeAsync(5 * 5500 + 1);
      expect(result).toEqual({ ok: false, code: 'E_SDK_NO_RELAY_AVAILABLE' });
      expect(jest.getTimerCount()).toBe(0);
    } finally {
      await starting;
      jest.useRealTimers();
      await h.client.shutdown();
    }
  });
});

/* --- review probes r6 within threat model B, lane doubles and the real outbox (cycle 6) --- */
describe('review probe r6 (Sol): probe-r6-model-b (regression, bounded-wait advance adapted)', () => {

  const VERSION = 'styx-m3-sdk/0.1.0-experimental';
  const KEY = 'a'.repeat(64);
  const P = 5500;

  const ok = (value) =>
    Object.freeze({ ok: true, value: Object.freeze(value) });

  const fail = (code) => Object.freeze({ ok: false, code });

  async function turns(n = 100) {
    for (let i = 0; i < n; i += 1) await Promise.resolve();
  }

  async function harness({ realOutbox = false } = {}) {
    jest.resetModules();

    const h = {
      events: [],
      storage: {
        put: () => true,
        get: () => null,
        update: () => true,
        remove: () => true,
        list: () => [],
      },
      identity: {
        getPublicKey: () => KEY,
        sign: () => new Uint8Array(64),
      },
    };

    h.outbox = {
      inspectStore: () => ok({ empty: true }),
      adoptPublicKey: () => ok({ adopted: true }),
      acceptReceipt: () => ok({}),
      send: () => ok({ deliveryId: 'd1', state: 'QUEUED' }),
      cancel: () => ok({ deliveryId: 'd1', state: 'CANCELLED' }),
      getDelivery: () => fail('E_SDK_UNKNOWN_DELIVERY'),
      failClosed: ({ deliveryId }) =>
        ok({ deliveryId, state: 'FAILED_NOT_ACCEPTED' }),
      shutdown: () => ok({ clientState: 'STOPPED', lost: 0 }),
    };

    h.receipts = {
      ingest: () => ok({ queued: true }),
      shutdown: () => ok({ dropped: 0 }),
      settled: async () => undefined,
    };
    h.receiptFactory = () => h.receipts;

    h.relaySet = {
      start: async () => ({ connectedRelays: 1 }),
      onFrame: () => () => undefined,
      publish: () => ({}),
      freeze() {},
      dispose: async () => undefined,
    };

    jest.unstable_mockModule('../../src/sdk/delivery/outbox.js', () => ({
      createOutbox(options) {
        return h.outbox;
      },
    }));
    jest.unstable_mockModule('../../src/sdk/delivery/receipts.js', () => ({
      createReceipts: (...args) => h.receiptFactory(...args),
    }));
    jest.unstable_mockModule('../../src/sdk/delivery/relay-pool.js', () => ({
      createRelaySet: () => h.relaySet,
    }));

    const { createStyxClient } = await import('../../src/sdk/client.js');
    const created = createStyxClient({
      interfaceVersion: VERSION,
      relays: ['ws://127.0.0.1:7000'],
      delivery: { perRelayTimeoutMs: 11000 },
      ports: {
        storage: h.storage,
        session: {
          seal: ({ plaintext }) => ({ ciphertext: plaintext }),
          open: ({ ciphertext }) => ({ plaintext: ciphertext }),
        },
        identity: h.identity,
      },
    });
    expect(created.ok).toBe(true);
    h.client = created.value;
    return h;
  }

  const WAITS = [
    ['outbox', 'inspectStore', ok({ empty: true }), 'E_SDK_INTERNAL'],
    ['relaySet', 'start', { connectedRelays: 1 },
      'E_SDK_NO_RELAY_AVAILABLE'],
    ['outbox', 'send', ok({ deliveryId: 'd1', state: 'QUEUED' }),
      'E_SDK_INTERNAL'],
    ['outbox', 'cancel', ok({ deliveryId: 'd1', state: 'CANCELLED' }),
      'E_SDK_INTERNAL'],
    ['outbox', 'getDelivery', fail('E_SDK_UNKNOWN_DELIVERY'),
      'E_SDK_INTERNAL'],
  ];

  test.each(WAITS)(
    'model B: unresolved %s.%s must be bounded',
    async (holder, method, lateValue, expectedCode) => {
      jest.useFakeTimers({ doNotFake: ['queueMicrotask'] });
      let h;
      let release = () => undefined;
      let operation;
      try {
        h = await harness();
        const duringStart = method === 'inspectStore' || method === 'start';
        if (!duringStart) {
          expect((await h.client.start()).ok).toBe(true);
        }

        const pending = new Promise((resolve) => { release = resolve; });
        h[holder][method] = () => pending;

        let result = null;
        const args = method === 'send'
          ? [{ recipient: KEY, payload: new Uint8Array([1]) }]
          : method === 'cancel' || method === 'getDelivery'
            ? [{ deliveryId: 'd1' }]
            : [];

        operation = (
          duringStart ? h.client.start() : h.client[method](...args)
        ).then((value) => { result = value; return value; });

        await turns();
        // Adapted (cycle 6): each wait has its own C-DLV backstop; the largest here is send's, 4P.
        await jest.advanceTimersByTimeAsync(4 * P + 1);
        expect(result).toEqual({ ok: false, code: expectedCode });
      } finally {
        release(lateValue);
        if (operation) await operation;
        if (h) await h.client.shutdown();
        jest.useRealTimers();
      }
    },
  );

  test.each([
    ['outbox', 'inspectStore', ok({ empty: true })],
    ['relaySet', 'start', { connectedRelays: 1 }],
  ])(
    'model B: shutdown must finish while start waits on %s.%s',
    async (holder, method, lateValue) => {
      jest.useFakeTimers({ doNotFake: ['queueMicrotask'] });
      let h;
      let release = () => undefined;
      let starting;
      let stopping;
      try {
        h = await harness();
        const pending = new Promise((resolve) => { release = resolve; });
        h[holder][method] = () => pending;

        starting = h.client.start();
        await turns();

        let result = null;
        stopping = h.client.shutdown().then((value) => {
          result = value;
          return value;
        });

        await jest.advanceTimersByTimeAsync(60000);
        expect(result).toEqual({
          ok: true,
          value: { clientState: 'STOPPED', lost: 0 },
        });
      } finally {
        release(lateValue);
        if (starting) await starting;
        if (stopping) await stopping;
        if (h) await h.client.shutdown();
        jest.useRealTimers();
      }
    },
  );

  test.each(['receipts rejection', 'onFrame rejection', 'null receipts'])(
    'model B: startup must reject %s',
    async (fault) => {
      const h = await harness();
      if (fault === 'receipts rejection') {
        h.receiptFactory = () => Promise.reject(new Error('receipt fault'));
      } else if (fault === 'onFrame rejection') {
        h.relaySet.onFrame = () => Promise.reject(new Error('subscribe fault'));
      } else {
        h.receiptFactory = () => null;
      }

      try {
        expect(await h.client.start()).toEqual({
          ok: false,
          code: 'E_SDK_INTERNAL',
        });
      } finally {
        await h.client.shutdown();
      }
    },
  );

  test('author r6-B: shutdown awaits an outbox stop that takes the C-DLV maximum', async () => {
    jest.useFakeTimers({ doNotFake: ['queueMicrotask'] });
    let h;
    try {
      h = await harness();
      expect((await h.client.start()).ok).toBe(true);
      const order = [];
      // A conforming outbox may take four port-call timeouts to stop (C-DLV section 5.5).
      h.outbox.shutdown = () => new Promise((resolve) => {
        setTimeout(() => {
          order.push('outbox stopped');
          resolve(ok({ clientState: 'STOPPED', lost: 3 }));
        }, 4 * P);
      });
      h.relaySet.dispose = async () => { order.push('dispose'); };
      let result = null;
      const stopping = h.client.shutdown().then((value) => { result = value; return value; });
      await jest.advanceTimersByTimeAsync(4 * P - 1);
      expect(result).toBe(null);
      await jest.advanceTimersByTimeAsync(2);
      await stopping;
      expect(result).toEqual({ ok: true, value: { clientState: 'STOPPED', lost: 3 } });
      expect(order).toEqual(['outbox stopped', 'dispose']);
      expect(jest.getTimerCount()).toBe(0);
    } finally {
      jest.useRealTimers();
    }
  });
});

describe('review probe r6 (Muse): probe-r6-unbounded-seam (regression)', () => {

  const VERSION = 'styx-m3-sdk/0.1.0-experimental';
  const KEY = 'a'.repeat(64);
  const ok = (v) => Object.freeze({ ok: true, value: Object.freeze(v) });

  async function harness(overrides = {}) {
    jest.resetModules();
    const h = { calls: [] };
    h.outbox = {
      inspectStore: () => ok({ empty: true }),
      adoptPublicKey: () => ok({ adopted: true }),
      acceptReceipt: () => ok({}),
      send: () => ok({ deliveryId: 'd1', state: 'QUEUED' }),
      cancel: () => ok({ deliveryId: 'd1', state: 'CANCELLED' }),
      getDelivery: () => Object.freeze({ ok: false, code: 'E_SDK_UNKNOWN_DELIVERY' }),
      failClosed: ({ deliveryId }) => ok({ deliveryId, state: 'FAILED_NOT_ACCEPTED' }),
      shutdown: () => ok({ clientState: 'STOPPED', lost: 0 }),
      ...overrides.outbox,
    };
    h.receipts = {
      ingest: () => ok({ queued: true }),
      shutdown: () => ok({ dropped: 0 }),
      settled: async () => undefined,
      ...overrides.receipts,
    };
    h.relaySet = {
      start: async () => ({ connectedRelays: 1 }),
      onFrame: () => () => undefined,
      publish: () => ({}),
      freeze() {},
      dispose: async () => undefined,
      ...overrides.relaySet,
    };
    jest.unstable_mockModule('../../src/sdk/delivery/outbox.js', () => ({
      createOutbox: () => h.outbox,
    }));
    jest.unstable_mockModule('../../src/sdk/delivery/receipts.js', () => ({
      createReceipts: () => h.receipts,
    }));
    jest.unstable_mockModule('../../src/sdk/delivery/relay-pool.js', () => ({
      createRelaySet: () => h.relaySet,
    }));
    const { createStyxClient } = await import('../../src/sdk/client.js');
    const created = createStyxClient({
      interfaceVersion: VERSION,
      relays: ['ws://127.0.0.1:7000'],
      delivery: { perRelayTimeoutMs: 11000 },
      ports: {
        storage: { put: () => true, get: () => null, update: () => true, remove: () => true, list: () => [] },
        session: { seal: ({ plaintext }) => ({ ciphertext: plaintext }), open: ({ ciphertext }) => ({ plaintext: ciphertext }) },
        identity: { getPublicKey: () => KEY, sign: () => new Uint8Array(64) },
      },
    });
    expect(created.ok).toBe(true);
    h.client = created.value;
    return h;
  }

  test('r6-H1: relaySet.start never settling must not hold start() open', async () => {
    const h = await harness({ relaySet: { start: () => new Promise(() => undefined) } });
    jest.useFakeTimers();
    let finished = false;
    let result = null;
    const p = h.client.start().then((v) => { finished = true; result = v; return v; });
    try {
      await jest.advanceTimersByTimeAsync(60000);
      expect(finished).toBe(true);
      expect(result.ok).toBe(false);
    } finally {
      jest.useRealTimers();
      // release to avoid hanging the worker; failure already recorded above
      h.relaySet.start = async () => ({ connectedRelays: 0 });
      await p.catch(() => undefined);
      await h.client.shutdown().catch(() => undefined);
    }
  });

  test('r6-H2: outbox.send never settling must not hold send() open', async () => {
    const h = await harness();
    expect((await h.client.start()).ok).toBe(true);
    h.outbox.send = () => new Promise(() => undefined);
    jest.useFakeTimers();
    let finished = false;
    const p = h.client.send({ recipient: KEY, payload: new Uint8Array([1]) }).then((v) => { finished = true; return v; });
    try {
      await jest.advanceTimersByTimeAsync(60000);
      expect(finished).toBe(true);
    } finally {
      jest.useRealTimers();
      await p.catch(() => undefined);
      await h.client.shutdown().catch(() => undefined);
    }
  });

  test('r6-H3: hanging start() must not hold shutdown() open', async () => {
    const h = await harness({ relaySet: { start: () => new Promise(() => undefined) } });
    jest.useFakeTimers();
    let startFinished = false;
    let stopFinished = false;
    const sp = h.client.start().then((v) => { startFinished = true; return v; });
    const qp = h.client.shutdown().then((v) => { stopFinished = true; return v; });
    try {
      await jest.advanceTimersByTimeAsync(60000);
      expect(startFinished).toBe(true);
      expect(stopFinished).toBe(true);
    } finally {
      jest.useRealTimers();
      await sp.catch(() => undefined);
      await qp.catch(() => undefined);
    }
  });
});

describe('review probe r6 (author): shutdown during a stuck start (regression)', () => {

  // Author probe (cycle 5 verification of Muse r6-H3): shutdown() called while start() is stuck in a lane call that
  // never settles. Model B: shutdown() must resolve within a bound anyway.
  const VERSION = 'styx-m3-sdk/0.1.0-experimental';
  const KEY = 'a'.repeat(64);
  const ok = (v) => Object.freeze({ ok: true, value: Object.freeze(v) });

  async function harness(overrides = {}) {
    jest.resetModules();
    const h = {};
    h.outbox = {
      inspectStore: () => ok({ empty: true }),
      adoptPublicKey: () => ok({ adopted: true }),
      acceptReceipt: () => ok({}),
      send: () => ok({ deliveryId: 'd1', state: 'QUEUED' }),
      cancel: () => ok({ deliveryId: 'd1', state: 'CANCELLED' }),
      getDelivery: () => Object.freeze({ ok: false, code: 'E_SDK_UNKNOWN_DELIVERY' }),
      failClosed: ({ deliveryId }) => ok({ deliveryId, state: 'FAILED_NOT_ACCEPTED' }),
      shutdown: () => ok({ clientState: 'STOPPED', lost: 0 }),
      ...overrides.outbox,
    };
    h.receipts = {
      ingest: () => ok({ queued: true }),
      shutdown: () => ok({ dropped: 0 }),
      settled: async () => undefined,
      ...overrides.receipts,
    };
    h.relaySet = {
      start: async () => ({ connectedRelays: 1 }),
      onFrame: () => () => undefined,
      publish: () => ({}),
      freeze() {},
      dispose: async () => undefined,
      ...overrides.relaySet,
    };
    jest.unstable_mockModule('../../src/sdk/delivery/outbox.js', () => ({ createOutbox: () => h.outbox }));
    jest.unstable_mockModule('../../src/sdk/delivery/receipts.js', () => ({ createReceipts: () => h.receipts }));
    jest.unstable_mockModule('../../src/sdk/delivery/relay-pool.js', () => ({ createRelaySet: () => h.relaySet }));
    const { createStyxClient } = await import('../../src/sdk/client.js');
    const created = createStyxClient({
      interfaceVersion: VERSION,
      relays: ['ws://127.0.0.1:7000'],
      delivery: { perRelayTimeoutMs: 11000 },
      ports: {
        storage: { put: () => true, get: () => null, update: () => true, remove: () => true, list: () => [] },
        session: { seal: ({ plaintext }) => ({ ciphertext: plaintext }), open: ({ ciphertext }) => ({ plaintext: ciphertext }) },
        identity: { getPublicKey: () => KEY, sign: () => new Uint8Array(64) },
      },
    });
    expect(created.ok).toBe(true);
    h.client = created.value;
    return h;
  }

  const turns = async () => { for (let i = 0; i < 50; i += 1) await Promise.resolve(); };

  test.each([
    ['relaySet.start', { relaySet: { start: () => new Promise(() => undefined) } }],
    ['outbox.inspectStore', { outbox: { inspectStore: () => new Promise(() => undefined) } }],
  ])('author r6-H3b: shutdown() during a start() stuck in %s resolves within a bound', async (_name, overrides) => {
    const h = await harness(overrides);
    jest.useFakeTimers();
    let stopped = null;
    try {
      h.client.start();
      await turns();
      const stopping = h.client.shutdown().then((v) => { stopped = v; return v; });
      await jest.advanceTimersByTimeAsync(120000);
      expect(stopped).toEqual({ ok: true, value: { clientState: 'STOPPED', lost: 0 } });
      expect(jest.getTimerCount()).toBe(0);
      await stopping;
    } finally {
      jest.useRealTimers();
    }
  });
});
