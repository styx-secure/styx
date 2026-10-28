// T-RELAY: test-only real loopback infrastructure; no production seam doubles.
import { expect } from '@jest/globals';
import { WebSocket, WebSocketServer } from 'ws';
import { createServer } from 'node:http';
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, utf8Encode } from '../../../src/utils.js';
import { createStyxClient, SDK_INTERFACE_VERSION } from '../../../src/sdk/index.js';

let observationSequence = 0;
function stamp(row) { return { ...row, hostSequence: observationSequence++, hostAt: Date.now() }; }

export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
export async function settle() { for (let i = 0; i < 40; i += 1) await Promise.resolve(); }
export async function waitFor(predicate, label, ms = 4000) {
  const end = Date.now() + ms;
  while (!(await predicate())) {
    if (Date.now() >= end) throw new Error(`T-RELAY barrier: ${label}`);
    await sleep(2);
  }
  await settle();
}
export function deferred() {
  let resolve; let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
export function eventId(e) {
  return bytesToHex(sha256(utf8Encode(JSON.stringify([0, e.pubkey, e.created_at, e.kind, e.tags, e.content]))));
}
export function matches(filter, event) {
  if (filter.ids && !filter.ids.includes(event.id)) return false;
  if (filter.kinds && !filter.kinds.includes(event.kind)) return false;
  if (filter.since !== undefined && event.created_at < filter.since) return false;
  return Object.entries(filter).every(([key, values]) => key[0] !== '#' ||
    event.tags.some((t) => t[0] === key.slice(1) && values.includes(t[1])));
}
export function manualClock(trace = []) {
  let now = 0; let id = 0;
  const timers = new Map(); const captured = new Map();
  const clock = {
    now: () => now,
    setTimer(callback, delay) {
      const handle = ++id; const timer = { callback, at: now + delay, delay };
      timers.set(handle, timer); captured.set(handle, timer);
      trace.push(stamp({ type: 'arm', at: now, handle, due: timer.at, delay })); return handle;
    },
    clearTimer(handle) { trace.push(stamp({ type: 'clear', at: now, handle })); timers.delete(handle); },
  };
  const to = async (target) => {
    if (target < now) throw new Error('clock reversal');
    for (let steps = 0; ; steps += 1) {
      if (steps > 20000) throw new Error('clock runaway');
      const next = [...timers].filter(([, t]) => t.at <= target).sort((a, b) => a[1].at - b[1].at || a[0] - b[0])[0];
      if (!next) break;
      const [handle, t] = next; timers.delete(handle); now = Math.max(now, t.at);
      trace.push(stamp({ type: 'fire', at: now, handle })); t.callback(); await settle();
    }
    now = target; await settle();
  };
  return { clock, timers, captured, trace, to, setNow(value) { now = value; }, get now() { return now; } };
}
function portCalls(port) {
  const calls = []; const observations = [];
  const record = (method, args = []) => { observations.push(stamp({ type: 'port', port, method })); calls.push(args.length ? [method, ...args] : method); };
  return { calls, observations, record };
}
export function identity() {
  const key = schnorr.utils.randomPrivateKey(); const publicKey = bytesToHex(schnorr.getPublicKey(key));
  const log = portCalls('identity');
  const port = { getPublicKey() { log.record('getPublicKey'); return publicKey; },
    sign({ digest }) { log.record('sign'); return schnorr.sign(digest, key); } };
  return { port, publicKey, calls: log.calls, observations: log.observations };
}
export function storage() {
  const records = new Map(); const log = portCalls('storage'); const control = { update: null };
  return { records, calls: log.calls, observations: log.observations, control,
    put(r) { log.record('put', [r.deliveryId]); records.set(r.deliveryId, r); return true; },
    get(id) { log.record('get', [id]); return records.get(id) ?? null; },
    update(id, r) {
      log.record('update', [id, r]);
      const apply = () => { if (!records.has(id)) return false; records.set(id, r); return true; };
      return control.update ? control.update(id, r, apply) : apply();
    },
    remove(id) { log.record('remove', [id]); return records.delete(id); },
    list() { log.record('list'); return [...records.values()]; },
  };
}
export function session() {
  const log = portCalls('session');
  return { calls: log.calls, observations: log.observations,
    seal({ plaintext }) { log.record('seal'); return { ciphertext: new Uint8Array(plaintext) }; },
    open({ ciphertext }) { log.record('open'); return { plaintext: new Uint8Array(ciphertext) }; },
  };
}
export function assertSixHandles(trace, handles) {
  expect(handles).toHaveLength(6); expect(new Set(handles).size).toBe(6);
  const lost = trace.map((t, i) => [t, i]).filter(([t]) => t.type === 'event' && t.event.state === 'LOST_ON_SHUTDOWN');
  expect(lost).toHaveLength(2);
  const stopped = trace.findIndex((t) => t.type === 'event' && t.event.clientState === 'STOPPED');
  expect(stopped).toBeGreaterThan(lost[1][1]);
  const cleared = trace.map((t, i) => [t, i]).filter(([t]) => t.type === 'clear' && handles.includes(t.handle));
  expect(cleared).toHaveLength(6);
  expect(cleared.map(([t]) => t.handle).sort((a, b) => a - b)).toEqual([...handles].sort((a, b) => a - b));
  for (const [, i] of cleared) { expect(i).toBeGreaterThan(lost[1][1]); expect(i).toBeLessThan(stopped); }
}

export function assertWirePublication(observation, eventIdValue, relayIndex) {
  expect(observation.relayIndex).toBe(relayIndex);
  expect(observation.row.type).toBe('in');
  expect(observation.row.frame[0]).toBe('EVENT');
  expect(observation.row.frame[1].id).toBe(eventIdValue);
}
export function assertDedupCounts({ opens, messages, receipts, unique }) {
  expect(opens).toBe(unique); expect(messages).toBe(unique); expect(receipts).toBe(unique);
}
export function assertReceiptBoundary({ at, deadline, successful }) {
  expect(successful).toBe(at < deadline);
}
export function assertAcceptanceDistinct(snapshot) {
  expect(snapshot.state).toBe('RELAY_ACCEPTED_AWAITING_RECEIPT'); expect(snapshot.terminal).toBe(false);
}
export function assertNoForbiddenPublish(frames) { expect(frames).toHaveLength(0); }
export function assertClosed({ sockets, tcp }) { expect(sockets).toBe(0); expect(tcp).toBe(0); }
export function assertFrozen(actual, previous) { expect(actual).toEqual(previous); }
// Compare every normative item field, with generated identifiers mapped by role.
export function assertItem(actual, { id, recipient, state, attempts = 1, outcomes }) {
  // The role key must come from send(), never from the observed snapshot.
  expect(recipient).toMatch(/^[0-9a-f]{64}$/);
  expect(actual).toEqual({ deliveryId: id, recipient, state, terminal: true, attempts,
    createdAt: 12000, deadlineAt: 132000, lastCode: null,
    relayOutcomes: outcomes.map((outcome, relayIndex) => ({ relayIndex, outcome })) });
}
export function assertDeliveryTimeline(trace, id, expected) {
  expect(trace.filter((r) => r.type === 'event' && r.event.deliveryId === id)
    .map((r) => [r.at, r.event.state, r.event.terminal, r.event.lastCode])).toEqual(
    expected.map(([at, state]) => [at, state, !['IN_FLIGHT', 'QUEUED', 'RELAY_ACCEPTED_AWAITING_RECEIPT'].includes(state), null]));
}

export async function relay({ mode = 'normal', clock = null, holdUpgrade = false, dropAfter = 1,
  holdFrames = false, duplicate = false, reverse = false, delayMs = 0 } = {}) {
  const host = '127.0.0.1';
  const server = createServer(); const ws = new WebSocketServer({ noServer: true });
  const sockets = new Set(); const tcp = new Set(); const history = []; const events = new Map();
  const subscriptions = new Map(); const upgrades = []; const queued = []; const delays = new Set();
  let connectionId = 0; let eventFrames = 0;
  const record = (entry) => { const row = stamp({ sequence: history.length, at: clock?.now ?? 0, ...entry }); history.push(row); return row; };
  const send = (socket, frame) => {
    if (socket.readyState !== WebSocket.OPEN) return;
    record({ type: 'out', connection: socket.connectionId, frame }); socket.send(JSON.stringify(frame));
  };
  const outgoing = (socket, frame) => {
    if (mode === 'neverAnswering') return;
    if (holdFrames) { queued.push({ socket, frame }); return; }
    if (delayMs) { const timer = setTimeout(() => { delays.delete(timer); send(socket, frame); }, delayMs); delays.add(timer); }
    else send(socket, frame);
  };
  const deliver = (socket, sub, event) => {
    outgoing(socket, ['EVENT', sub, event]); if (duplicate) outgoing(socket, ['EVENT', sub, event]);
  };
  server.on('connection', (socket) => {
    tcp.add(socket);
    socket.on('end', () => { record({ type: 'tcp-end' }); socket.end(); });
    socket.on('close', () => { record({ type: 'tcp-close' }); tcp.delete(socket); });
  });
  server.on('upgrade', (request, socket, head) => {
    const accept = () => { if (!socket.destroyed) ws.handleUpgrade(request, socket, head, (s) => ws.emit('connection', s)); };
    record({ type: 'upgrade' });
    if (holdUpgrade || mode === 'stalledHandshake') {
      // A held HTTP upgrade must still consume TCP EOF; otherwise a paused
      // server socket conceals the client's completed handshake abort.
      socket.resume(); upgrades.push(accept);
    } else accept();
  });
  ws.on('connection', (socket) => {
    socket.connectionId = ++connectionId; sockets.add(socket); subscriptions.set(socket, new Map());
    record({ type: 'open', connection: socket.connectionId });
    socket.on('error', (e) => record({ type: 'socket-error', message: e.message }));
    socket.on('close', () => { record({ type: 'close', connection: socket.connectionId }); sockets.delete(socket); subscriptions.delete(socket); });
    socket.on('message', (raw) => {
      let frame;
      try { frame = JSON.parse(String(raw)); } catch { record({ type: 'malformed' }); return; }
      record({ type: 'in', connection: socket.connectionId, frame });
      if (mode === 'neverAnswering') return;
      if (frame[0] === 'EVENT') {
        const e = frame[1]; eventFrames += 1;
        const valid = e && e.id === eventId(e); const accepted = valid && mode !== 'rejectAll';
        const known = events.has(e.id);
        if (accepted) events.set(e.id, e);
        if (mode === 'dropAfterFrames' && eventFrames === dropAfter) { socket.close(); return; }
        outgoing(socket, ['OK', e.id, accepted, accepted ? (known ? 'duplicate: already have this event' : 'saved') : 'invalid: id or rejected']);
        if (accepted) for (const [other, subs] of subscriptions) for (const [id, filters] of subs) {
          if (filters.some((f) => matches(f, e))) deliver(other, id, e);
        }
      } else if (frame[0] === 'REQ') {
        const filters = frame.slice(2); subscriptions.get(socket).set(frame[1], filters);
        let replay = [...events.values()].filter((e) => filters.some((f) => matches(f, e)));
        if (reverse) replay = replay.reverse();
        for (const e of replay) deliver(socket, frame[1], e);
        outgoing(socket, ['EOSE', frame[1]]);
      } else if (frame[0] === 'CLOSE') subscriptions.get(socket).delete(frame[1]);
    });
  });
  server.listen(0, host); await new Promise((resolve, reject) => { server.once('listening', resolve); server.once('error', reject); });
  const urlHost = host.includes(':') ? `[${host}]` : host;
  return { url: `ws://${urlHost}:${server.address().port}`, history, sockets, tcp, events, queued, upgrades, subscriptions,
    get delayedTimers() { return delays.size; },
    get connections() { return connectionId; },
    reqs() { return history.filter((h) => h.type === 'in' && h.frame[0] === 'REQ'); },
    published() { return history.filter((h) => h.type === 'in' && h.frame[0] === 'EVENT'); },
    releaseUpgrade() { const f = upgrades.shift(); if (!f) throw new Error('no held upgrade'); f(); },
    release(predicate = () => true) { for (let i = 0; i < queued.length;) { const q = queued[i]; if (predicate(q.frame, q.socket)) { queued.splice(i, 1); send(q.socket, q.frame); } else i += 1; } },
    setHoldUpgrade(value) { holdUpgrade = value; },
    setHold(value) { holdFrames = value; },
    setMode(value) { mode = value; },
    sendRaw(socket, frame) { send(socket, frame); },
    async cleanup() {
      for (const timer of delays) clearTimeout(timer); delays.clear();
      for (const socket of sockets) socket.terminate(); for (const socket of tcp) socket.destroy();
      await new Promise((resolve) => ws.close(resolve)); await new Promise((resolve) => server.close(resolve));
    },
  };
}

export async function probe(url) {
  const socket = new WebSocket(url); const frames = [];
  socket.on('message', (raw) => frames.push(JSON.parse(String(raw))));
  socket.on('error', () => {});
  await waitFor(() => socket.readyState === WebSocket.OPEN, 'harness control real socket open');
  return { frames, send(frame) { socket.send(JSON.stringify(frame)); },
    async close() { socket.close(); await waitFor(() => socket.readyState === WebSocket.CLOSED, 'harness control socket closed'); } };
}

export function rig() {
  const original = globalThis.WebSocket; globalThis.WebSocket = WebSocket;
  const trace = []; const manual = manualClock(trace); const relays = []; const members = [];
  const addRelay = async (options = {}) => { const r = await relay({ clock: manual, ...options }); relays.push(r); return r; };
  const member = ({ identity: id = identity(), storage: store = storage(), session: sess = session(),
    delivery = {}, randomValues = [] } = {}) => {
    const draws = [];
    const random = { nextUint32() { if (draws.length >= randomValues.length) throw new Error('unexpected random draw'); const u = randomValues[draws.length]; draws.push(u); return u; } };
    const created = createStyxClient({ interfaceVersion: SDK_INTERFACE_VERSION, relays: relays.map((r) => r.url),
      ports: { identity: id.port, storage: store, session: sess }, clock: manual.clock, random,
      delivery: { perRelayTimeoutMs: 12000, ...delivery } });
    expect(created.ok).toBe(true);
    const m = { client: created.value, identity: id, storage: store, session: sess, events: [], draws };
    members.push(m); return m;
  };
  const listen = async (m) => { expect((await m.client.onEvent((event) => { m.events.push(event); trace.push(stamp({ type: 'event', at: manual.now, event })); })).ok).toBe(true); };
  const start = async (m, { held = [] } = {}) => {
    await listen(m); const baselines = relays.map((r) => r.reqs().length); const p = m.client.start();
    await waitFor(() => relays.every((r, i) => held.includes(i) ? r.upgrades.length > 0 : r.reqs().length > baselines[i]), 'subscriptions or held upgrades');
    await manual.to(manual.now + 12000); return p;
  };
  const snapshot = async (m, id) => { const result = await m.client.getDelivery({ deliveryId: id }); expect(result.ok).toBe(true); const value = structuredClone(result.value); trace.push(stamp({ type: 'snapshot', at: manual.now, value })); return value; };
  const stop = async () => {
    const failures = [];
    for (const m of members) { try { await m.client.shutdown(); } catch (e) { failures.push(e); } }
    await waitFor(() => relays.every((r) => r.sockets.size === 0 && r.tcp.size === 0 && r.delayedTimers === 0), 'SDK closes every socket and TCP connection; host frame delays drained').catch((e) => failures.push(e));
    for (const r of relays) { try { assertClosed({ sockets: r.sockets.size, tcp: r.tcp.size }); } catch (e) { failures.push(e); } }
    if (manual.timers.size) failures.push(new Error(`clock handles leaked: ${manual.timers.size}`));
    console.log(JSON.stringify({ schema: 't-relay-trace-v1', trace,
      relays: relays.map((r) => ({ url: r.url, history: r.history, sockets: r.sockets.size, tcp: r.tcp.size })),
      ports: members.map((m) => ({ identity: m.identity.calls, session: m.session.calls, storage: m.storage.calls, draws: m.draws,
        observations: [...(m.identity.observations ?? []), ...(m.session.observations ?? []), ...(m.storage.observations ?? [])].sort((a, b) => a.hostSequence - b.hostSequence) })),
      resourceVerdict: failures.length ? 'FAIL' : 'PASS' }));
    try { for (const r of relays) await r.cleanup(); } finally { globalThis.WebSocket = original; }
    if (failures.length) throw new AggregateError(failures, 'T-RELAY teardown');
  };
  return { trace, manual, relays, members, addRelay, member, listen, start, snapshot, stop };
}
