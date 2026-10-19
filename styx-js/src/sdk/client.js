/**
 * I-SDK client -- PROTOTYPE (branch proto/sdk-demo-2026-10, not for merge).
 *
 * Assembles the merged M3 delivery layer (outbox, receipts, relay set, retry)
 * behind the C-SDK interface (docs/architecture/m3/sdk-interface.md). It
 * follows the I-SDK contract draft as closely as practical for a prototype;
 * the deliberate departures are listed in PROTOTYPE_DEPARTURES below and in
 * the prototype's RESULTS.md. The merged lane modules are used unchanged
 * (no S1-S5 seams): the identity port is wrapped so the key is read once.
 *
 * Every method resolves a frozen result envelope and never throws or rejects.
 */

import { createOutbox } from './delivery/outbox.js';
import { createReceipts } from './delivery/receipts.js';
import { createRelaySet } from './delivery/relay-pool.js';
import { retryDelayMs } from './delivery/retry.js';
import { bytesToHex, randomBytes } from '../utils.js';
import { relayUrlAllowed } from './relay-url.js';

export const SDK_INTERFACE_VERSION = 'styx-m3-sdk/0.1.0-experimental';

const enumOf = (names) => Object.freeze(Object.fromEntries(names.map((n) => [n, n])));

export const SdkResultCode = enumOf([
  'E_SDK_UNSUPPORTED_VERSION', 'E_SDK_INVALID_CONFIG', 'E_SDK_INVALID_ARGUMENT',
  'E_SDK_PAYLOAD_TOO_LARGE', 'E_SDK_NOT_STARTED', 'E_SDK_ALREADY_STARTED',
  'E_SDK_CLIENT_STOPPED', 'E_SDK_STORAGE_NOT_EMPTY', 'E_SDK_NO_RELAY_AVAILABLE',
  'E_SDK_QUEUE_FULL', 'E_SDK_UNKNOWN_DELIVERY', 'E_SDK_DELIVERY_TERMINAL',
  'E_SDK_STORAGE_FAILED', 'E_SDK_SESSION_FAILED', 'E_SDK_IDENTITY_FAILED',
  'E_SDK_INBOUND_INVALID', 'E_SDK_INTERNAL', 'E_SDK_UNKNOWN_CODE',
]);

export const DeliveryState = enumOf([
  'QUEUED', 'IN_FLIGHT', 'RELAY_ACCEPTED_AWAITING_RECEIPT', 'RELAY_ACCEPTED',
  'RECIPIENT_RECEIPT_RECEIVED', 'FAILED_NOT_ACCEPTED', 'FAILED_NO_RECEIPT',
  'CANCELLED', 'LOST_ON_SHUTDOWN',
]);

export const RelayOutcome = enumOf(['PENDING', 'ACCEPTED', 'REJECTED', 'TIMED_OUT', 'UNREACHABLE']);

export const ClientState = enumOf(['CREATED', 'RUNNING', 'STOPPED']);

export const SdkEventKind = enumOf([
  'CLIENT_STATE_CHANGED', 'DELIVERY_STATE_CHANGED', 'MESSAGE_RECEIVED', 'INBOUND_DISCARDED',
]);

const hasOwn = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

/** True only for a member of SdkResultCode; no coercion, no property access on `value`. */
export function isKnownResultCode(value) {
  try {
    return typeof value === 'string' && hasOwn(SdkResultCode, value);
  } catch {
    return false;
  }
}

/* ------------------------------------------------------------------------ */

const TERMINAL = new Set([
  'RELAY_ACCEPTED', 'RECIPIENT_RECEIPT_RECEIVED', 'FAILED_NOT_ACCEPTED',
  'FAILED_NO_RECEIPT', 'CANCELLED', 'LOST_ON_SHUTDOWN',
]);
const DISCARD_CODES = new Set(['E_SDK_INBOUND_INVALID', 'E_SDK_SESSION_FAILED', 'E_SDK_UNKNOWN_CODE']);
const DEFAULTS = Object.freeze({
  maxAttempts: 5, deadlineMs: 120000, perRelayTimeoutMs: 12000, receiptMode: 'RELAY_ACCEPTANCE_ONLY',
});
const BOUNDS = Object.freeze({
  maxAttempts: [1, 10], deadlineMs: [30000, 600000], perRelayTimeoutMs: [11000, 30000],
});
const PAYLOAD_MAX_BYTES = 65536;
const HEX64 = /^[0-9a-f]{64}$/;

const ok = (value) => Object.freeze({ ok: true, value });
const fail = (code) => Object.freeze({ ok: false, code });

function isPlain(o) {
  if (o === null || typeof o !== 'object' || Array.isArray(o)) return false;
  const p = Object.getPrototypeOf(o);
  return p === Object.prototype || p === null;
}

/** Closed object: exact own-key set (strings only), required keys present, data values. */
function readClosed(o, required, optional = []) {
  if (!isPlain(o)) return null;
  const keys = Reflect.ownKeys(o);
  const allowed = new Set([...required, ...optional]);
  for (const k of keys) if (typeof k !== 'string' || !allowed.has(k)) return null;
  for (const k of required) if (!keys.includes(k)) return null;
  const out = {};
  for (const k of keys) {
    const d = Object.getOwnPropertyDescriptor(o, k);
    if (!d || !hasOwn(d, 'value')) return null;
    out[k] = d.value;
  }
  return out;
}

function validateConfig(config) {
  let c;
  try {
    if (!isPlain(config)) return fail('E_SDK_INVALID_CONFIG');
    const vd = Object.getOwnPropertyDescriptor(config, 'interfaceVersion');
    if (!vd || !hasOwn(vd, 'value') || vd.value !== SDK_INTERFACE_VERSION) return fail('E_SDK_UNSUPPORTED_VERSION');
    c = readClosed(config, ['interfaceVersion', 'relays', 'ports'], ['clock', 'random', 'delivery']);
    if (!c) return fail('E_SDK_INVALID_CONFIG');
    const relays = c.relays;
    if (!Array.isArray(relays) || relays.length < 1 || relays.length > 16) return fail('E_SDK_INVALID_CONFIG');
    const rl = [];
    for (let i = 0; i < relays.length; i += 1) {
      const d = Object.getOwnPropertyDescriptor(relays, i);
      if (!d || !hasOwn(d, 'value') || !relayUrlAllowed(d.value)) return fail('E_SDK_INVALID_CONFIG');
      rl.push(d.value);
    }
    if (new Set(rl).size !== rl.length) return fail('E_SDK_INVALID_CONFIG');
    const ports = readClosed(c.ports, ['storage', 'session', 'identity']);
    if (!ports) return fail('E_SDK_INVALID_CONFIG');
    const need = { storage: ['put', 'get', 'update', 'remove', 'list'], session: ['seal', 'open'], identity: ['getPublicKey', 'sign'] };
    for (const [p, methods] of Object.entries(need)) {
      const port = ports[p];
      if (port === null || (typeof port !== 'object' && typeof port !== 'function')) return fail('E_SDK_INVALID_CONFIG');
      for (const m of methods) if (typeof port[m] !== 'function') return fail('E_SDK_INVALID_CONFIG');
    }
    let clock = null;
    if (hasOwn(c, 'clock')) {
      clock = readClosed(c.clock, ['now', 'setTimer', 'clearTimer']);
      if (!clock || ![clock.now, clock.setTimer, clock.clearTimer].every((f) => typeof f === 'function')) return fail('E_SDK_INVALID_CONFIG');
      clock = Object.freeze(clock);
    }
    let random = null;
    if (hasOwn(c, 'random')) {
      random = readClosed(c.random, ['nextUint32']);
      if (!random || typeof random.nextUint32 !== 'function') return fail('E_SDK_INVALID_CONFIG');
      random = Object.freeze(random);
    }
    const delivery = { ...DEFAULTS };
    if (hasOwn(c, 'delivery')) {
      const d = readClosed(c.delivery, [], ['maxAttempts', 'deadlineMs', 'perRelayTimeoutMs', 'receiptMode']);
      if (!d) return fail('E_SDK_INVALID_CONFIG');
      for (const [k, [lo, hi]] of Object.entries(BOUNDS)) {
        if (!hasOwn(d, k)) continue;
        if (!Number.isSafeInteger(d[k]) || d[k] < lo || d[k] > hi) return fail('E_SDK_INVALID_CONFIG');
        delivery[k] = d[k];
      }
      if (hasOwn(d, 'receiptMode')) {
        if (d.receiptMode !== 'RECIPIENT_RECEIPT' && d.receiptMode !== 'RELAY_ACCEPTANCE_ONLY') return fail('E_SDK_INVALID_CONFIG');
        delivery.receiptMode = d.receiptMode;
      }
    }
    return ok(Object.freeze({
      relays: Object.freeze(rl), storage: ports.storage, session: ports.session, identity: ports.identity,
      clock, random, delivery: Object.freeze(delivery),
    }));
  } catch {
    return fail('E_SDK_INVALID_CONFIG');
  }
}

/* --- result checks ------------------------------------------------------- */

function closedSlotsOk(v, depth = 0) {
  if (v === null || typeof v !== 'object' || depth > 3) return true;
  const checks = {
    code: (x) => isKnownResultCode(x),
    lastCode: (x) => x === null || isKnownResultCode(x),
    state: (x) => hasOwn(DeliveryState, x),
    clientState: (x) => hasOwn(ClientState, x),
    outcome: (x) => hasOwn(RelayOutcome, x),
    receiptMode: (x) => x === 'RECIPIENT_RECEIPT' || x === 'RELAY_ACCEPTANCE_ONLY',
  };
  for (const k of Reflect.ownKeys(v)) {
    const d = Object.getOwnPropertyDescriptor(v, k);
    if (!d || !hasOwn(d, 'value')) return false;
    if (typeof k === 'string' && hasOwn(checks, k) && !checks[k](d.value)) return false;
    if (d.value && typeof d.value === 'object' && !(d.value instanceof Uint8Array) && !closedSlotsOk(d.value, depth + 1)) return false;
  }
  return true;
}

/** Fail-closed check of a lane-module envelope; returns a frozen envelope. */
function checkEnvelope(r, shapeOk, allowedCodes) {
  try {
    if (r === null || typeof r !== 'object') return fail('E_SDK_INTERNAL');
    if (!closedSlotsOk(r)) return fail('E_SDK_UNKNOWN_CODE');
    if (r.ok === true) return shapeOk(r.value) ? ok(r.value) : fail('E_SDK_INTERNAL');
    if (r.ok === false) {
      if (!isKnownResultCode(r.code)) return fail('E_SDK_UNKNOWN_CODE');
      return allowedCodes.has(r.code) ? fail(r.code) : fail('E_SDK_INTERNAL');
    }
    return fail('E_SDK_INTERNAL');
  } catch {
    return fail('E_SDK_INTERNAL');
  }
}

const isStr = (x) => typeof x === 'string';

function snapshotOk(relayCount, maxAttempts) {
  return (s) => {
    if (!s || typeof s !== 'object') return false;
    const keys = Object.keys(s).sort().join(',');
    if (keys !== 'attempts,createdAt,deadlineAt,deliveryId,lastCode,recipient,relayOutcomes,state,terminal') return false;
    if (!isStr(s.deliveryId) || !HEX64.test(s.recipient) || !hasOwn(DeliveryState, s.state)) return false;
    if (s.terminal !== TERMINAL.has(s.state)) return false;
    if (!Number.isInteger(s.attempts) || s.attempts < 0 || s.attempts > maxAttempts) return false;
    if (!Number.isFinite(s.createdAt) || !Number.isFinite(s.deadlineAt)) return false;
    if (!Array.isArray(s.relayOutcomes) || s.relayOutcomes.length !== relayCount) return false;
    return s.relayOutcomes.every((o, i) => o && o.relayIndex === i && hasOwn(RelayOutcome, o.outcome));
  };
}

/** Bound a possibly-async port call with the host setTimeout. */
function bounded(fn, ms) {
  return new Promise((resolve) => {
    let done = false;
    const t = setTimeout(() => { if (!done) { done = true; resolve({ timeout: true }); } }, ms);
    const finish = (r) => { if (!done) { done = true; clearTimeout(t); resolve(r); } };
    try {
      Promise.resolve(fn()).then((value) => finish({ value }), () => finish({ error: true }));
    } catch {
      finish({ error: true });
    }
  });
}

/* --- the client ---------------------------------------------------------- */

export function createStyxClient(config) {
  const v = validateConfig(config);
  if (!v.ok) return v;
  const cfg = v.value;
  const relayCount = cfg.relays.length;
  const clock = cfg.clock ?? Object.freeze({
    now: () => Date.now(),
    setTimer: (cb, ms) => setTimeout(cb, ms),
    clearTimer: (h) => clearTimeout(h),
  });
  const random = cfg.random ?? Object.freeze({
    nextUint32: () => {
      const b = new Uint8Array(4);
      crypto.getRandomValues(b);
      return b[0] * 2 ** 24 + b[1] * 2 ** 16 + b[2] * 2 ** 8 + b[3];
    },
  });
  const portTimeoutMs = Math.floor(cfg.delivery.perRelayTimeoutMs / 2);

  let state = 'CREATED';
  let stopping = false;
  let startPromise = null;
  let mods = null; // { outbox, receipts, relaySet, unFrame, disposeP }
  const listeners = []; // { fn, live }

  const dispatch = (ev, audience) => {
    const targets = audience ?? listeners.slice();
    queueMicrotask(() => {
      for (const reg of targets) {
        if (!reg.live) continue;
        let copy = ev;
        if (ev.kind === 'MESSAGE_RECEIVED') copy = Object.freeze({ kind: ev.kind, sender: ev.sender, payload: new Uint8Array(ev.payload) });
        try {
          const r = reg.fn(copy);
          if (r && typeof r.then === 'function') r.then(undefined, () => {});
        } catch { /* a listener fault changes nothing */ }
      }
    });
  };
  let shutdownAudience = null;
  const emit = (ev) => dispatch(ev, shutdownAudience ?? undefined);

  /** The sink of the lane modules: check, then record and dispatch. */
  const sink = (ev) => {
    try {
      if (!ev || typeof ev !== 'object') return;
      const kind = ev.kind;
      const keys = Object.keys(ev).sort().join(',');
      if (kind === 'DELIVERY_STATE_CHANGED') {
        const good = hasOwn(DeliveryState, ev.state) && (ev.lastCode === null || isKnownResultCode(ev.lastCode))
          && keys === 'deliveryId,kind,lastCode,state,terminal' && isStr(ev.deliveryId) && ev.terminal === TERMINAL.has(ev.state);
        if (!good) return;
        emit(Object.freeze({ kind, deliveryId: ev.deliveryId, state: ev.state, terminal: ev.terminal, lastCode: ev.lastCode }));
      } else if (kind === 'MESSAGE_RECEIVED') {
        if (keys !== 'kind,payload,sender' || !HEX64.test(ev.sender) || !(ev.payload instanceof Uint8Array)) return;
        emit(Object.freeze({ kind, sender: ev.sender, payload: new Uint8Array(ev.payload) }));
      } else if (kind === 'INBOUND_DISCARDED') {
        if (keys !== 'code,kind' || !DISCARD_CODES.has(ev.code)) return;
        emit(Object.freeze({ kind, code: ev.code }));
      }
      // any other kind is never forwarded (C-SDK 5.3)
    } catch { /* never forwarded */ }
  };

  const setState = (s) => {
    state = s;
    emit(Object.freeze({ kind: 'CLIENT_STATE_CHANGED', clientState: s }));
  };

  const teardown = async (m) => {
    if (!m) return;
    try { m.receipts?.shutdown(); } catch { /* ignore */ }
    try { if (m.outbox) await m.outbox.shutdown(); } catch { /* ignore */ }
    try { m.unFrame?.(); } catch { /* ignore */ }
    if (m.relaySet) {
      if (!m.disposeP) m.disposeP = Promise.resolve().then(() => m.relaySet.dispose()).catch(() => {});
      await m.disposeP;
    }
  };

  const runStart = async () => {
    const m = {};
    // (1) outbox -- with a wrapped identity port so the key is read once (prototype stand-in for seam S1)
    let cachedKey = null;
    const identity = cfg.identity;
    const idWrap = Object.freeze({
      getPublicKey: () => cachedKey,
      sign: (a) => identity.sign(a),
    });
    try {
      m.outbox = createOutbox({
        delivery: cfg.delivery, relayCount, storage: cfg.storage, session: cfg.session,
        identity: idWrap, clock, random, publish: (event) => m.relaySet.publish(event), onEvent: sink,
      });
    } catch { return fail('E_SDK_INTERNAL'); }
    // (2) store must be empty
    let insp;
    try { insp = await m.outbox.inspectStore(); } catch { insp = null; }
    const ic = checkEnvelope(insp, (x) => x && x.empty === true,
      new Set(['E_SDK_STORAGE_FAILED', 'E_SDK_STORAGE_NOT_EMPTY', 'E_SDK_UNKNOWN_CODE', 'E_SDK_INTERNAL']));
    if (!ic.ok) { await teardown(m); return ic; }
    if (stopping) { await teardown(m); return fail('E_SDK_CLIENT_STOPPED'); }
    // (3) public key, once, bounded
    const r = await bounded(() => identity.getPublicKey(), portTimeoutMs);
    if (r.timeout || r.error) { await teardown(m); return fail('E_SDK_IDENTITY_FAILED'); }
    if (r.value && typeof r.value === 'object' && !closedSlotsOk(r.value)) { await teardown(m); return fail('E_SDK_UNKNOWN_CODE'); }
    if (typeof r.value !== 'string' || !HEX64.test(r.value)) { await teardown(m); return fail('E_SDK_IDENTITY_FAILED'); }
    cachedKey = r.value;
    if (stopping) { await teardown(m); return fail('E_SDK_CLIENT_STOPPED'); }
    // (4) relay set
    try {
      m.relaySet = createRelaySet({
        relays: [...cfg.relays], clock, random, perRelayTimeoutMs: cfg.delivery.perRelayTimeoutMs,
        subscriptionId: 's' + bytesToHex(randomBytes(16)),
        filter: { kinds: [4741, 4742], '#p': [cachedKey] }, reconnectDelay: retryDelayMs,
      });
    } catch { await teardown(m); return fail('E_SDK_INTERNAL'); }
    // (5) inbound processor
    try {
      m.receipts = createReceipts({
        identity: idWrap, session: cfg.session, clock, perRelayTimeoutMs: cfg.delivery.perRelayTimeoutMs,
        publishReceipt: (receipt) => {
          try {
            const a = m.relaySet.publish(receipt);
            a.ignoreAcks(); a.acceptGate = () => false; a.latePublishGate = () => false;
          } catch { /* changes nothing */ }
        },
        acceptReceipt: (x) => m.outbox.acceptReceipt(x),
        onEvent: sink,
      });
      m.unFrame = m.relaySet.onFrame((frame) => { try { m.receipts.ingest(frame); } catch { /* ignore */ } });
    } catch { await teardown(m); return fail('E_SDK_INTERNAL'); }
    // (6) connect
    let started;
    try { started = await m.relaySet.start(); } catch { started = null; }
    const n = started && Number.isInteger(started.connectedRelays) ? started.connectedRelays : 0;
    if (stopping) { await teardown(m); return fail('E_SDK_CLIENT_STOPPED'); }
    if (n < 1 || n > relayCount) { await teardown(m); return fail('E_SDK_NO_RELAY_AVAILABLE'); }
    mods = m;
    setState('RUNNING');
    return ok(Object.freeze({ clientState: 'RUNNING', connectedRelays: n }));
  };

  const guard = (allowed) => {
    if (stopping || state === 'STOPPED') return allowed.includes('STOPPED') ? null : fail('E_SDK_CLIENT_STOPPED');
    if (!allowed.includes(state)) return state === 'CREATED' ? fail('E_SDK_NOT_STARTED') : fail('E_SDK_INTERNAL');
    return null;
  };

  const safe = (fn) => async (...a) => { try { return await fn(...a); } catch { return fail('E_SDK_INTERNAL'); } };
  const idArg = (arg) => { const a = readClosed(arg, ['deliveryId']); return a && isStr(a.deliveryId) ? a : null; };

  const client = {
    start: safe(async () => {
      if (stopping || state === 'STOPPED') return fail('E_SDK_CLIENT_STOPPED');
      if (state === 'RUNNING') return fail('E_SDK_ALREADY_STARTED');
      if (!startPromise) startPromise = runStart().finally(() => { startPromise = null; });
      const r = await startPromise;
      return r.ok ? ok(r.value) : fail(r.code);
    }),

    send: safe(async (arg) => {
      const g = guard(['RUNNING']); if (g) return g;
      const a = readClosed(arg, ['recipient', 'payload']);
      if (!a || !(a.payload instanceof Uint8Array) || a.payload.length === 0) return fail('E_SDK_INVALID_ARGUMENT');
      if (a.payload.length > PAYLOAD_MAX_BYTES) return fail('E_SDK_PAYLOAD_TOO_LARGE');
      if (typeof a.recipient !== 'string' || !HEX64.test(a.recipient)) return fail('E_SDK_INVALID_ARGUMENT');
      const copy = new Uint8Array(a.payload);
      const r = await mods.outbox.send({ recipient: a.recipient, plaintext: copy });
      return checkEnvelope(r, (x) => x && isStr(x.deliveryId) && x.state === 'QUEUED',
        new Set(['E_SDK_INVALID_ARGUMENT', 'E_SDK_PAYLOAD_TOO_LARGE', 'E_SDK_QUEUE_FULL', 'E_SDK_STORAGE_FAILED',
          'E_SDK_SESSION_FAILED', 'E_SDK_IDENTITY_FAILED', 'E_SDK_CLIENT_STOPPED', 'E_SDK_INTERNAL', 'E_SDK_UNKNOWN_CODE']));
    }),

    getDelivery: safe(async (arg) => {
      if (state === 'CREATED' && !stopping) return fail('E_SDK_NOT_STARTED');
      const a = idArg(arg); if (!a) return fail('E_SDK_INVALID_ARGUMENT');
      if (!mods) return fail('E_SDK_UNKNOWN_DELIVERY');
      const r = await mods.outbox.getDelivery({ deliveryId: a.deliveryId });
      return checkEnvelope(r, snapshotOk(relayCount, cfg.delivery.maxAttempts),
        new Set(['E_SDK_UNKNOWN_DELIVERY', 'E_SDK_INVALID_ARGUMENT', 'E_SDK_INTERNAL']));
    }),

    cancel: safe(async (arg) => {
      const g = guard(['RUNNING']); if (g) return g;
      const a = idArg(arg); if (!a) return fail('E_SDK_INVALID_ARGUMENT');
      const r = await mods.outbox.cancel({ deliveryId: a.deliveryId });
      return checkEnvelope(r, (x) => x && isStr(x.deliveryId) && x.state === 'CANCELLED',
        new Set(['E_SDK_UNKNOWN_DELIVERY', 'E_SDK_DELIVERY_TERMINAL', 'E_SDK_INVALID_ARGUMENT', 'E_SDK_CLIENT_STOPPED',
          'E_SDK_STORAGE_FAILED', 'E_SDK_INTERNAL']));
    }),

    onEvent: safe(async (listener) => {
      if (typeof listener !== 'function') return fail('E_SDK_INVALID_ARGUMENT');
      const reg = { fn: listener, live: true };
      listeners.push(reg);
      const unsubscribe = () => {
        reg.live = false;
        const i = listeners.indexOf(reg);
        if (i >= 0) listeners.splice(i, 1);
        return undefined;
      };
      return ok(Object.freeze({ unsubscribe }));
    }),

    shutdown: safe(async () => {
      if (stopping || state === 'STOPPED') return fail('E_SDK_CLIENT_STOPPED');
      // step 1 (synchronous): stop admission, fix the audience, stop the modules
      stopping = true;
      shutdownAudience = listeners.slice();
      const m = mods;
      let lost = 0;
      let outboxStop = null;
      if (m) {
        try { m.receipts.shutdown(); } catch { /* ignore */ }
        try { outboxStop = m.outbox.shutdown(); } catch { outboxStop = null; }
      }
      // step 2: a start() in progress resolves (it sees `stopping` and cleans up)
      if (startPromise) { try { await startPromise; } catch { /* ignore */ } }
      // step 3/4: outbox remainder (LOST_ON_SHUTDOWN events go through the sink)
      if (outboxStop) {
        try {
          const r = await outboxStop;
          if (r && r.ok === true && Number.isSafeInteger(r.value?.lost)) lost = r.value.lost;
        } catch { /* ignore */ }
      }
      // let the queued LOST_ON_SHUTDOWN dispatches run before the sockets close
      await new Promise((res) => queueMicrotask(res));
      if (m) {
        try { m.unFrame?.(); } catch { /* ignore */ }
        if (!m.disposeP) m.disposeP = Promise.resolve().then(() => m.relaySet.dispose()).catch(() => {});
        await m.disposeP;
      }
      state = 'STOPPED';
      emit(Object.freeze({ kind: 'CLIENT_STATE_CHANGED', clientState: 'STOPPED' }));
      await new Promise((res) => queueMicrotask(res));
      // release the audience after its last event has been dispatched
      queueMicrotask(() => { for (const reg of shutdownAudience) reg.live = false; });
      return ok(Object.freeze({ clientState: 'STOPPED', lost }));
    }),
  };
  return ok(Object.freeze(client));
}
