// M3-RECEIVE-2 test helpers: temporary archive directories, keys, and a pair
// of reference receivers joined into one real MLS 1:1 group.
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { WebSocket, WebSocketServer } from 'ws';
import { MlsEngine } from '../../src/crypto/mls/mls-engine.js';
import { bytesToHex, hexToBytes, utf8Encode } from '../../src/utils.js';
import { createStyxClient, SDK_INTERFACE_VERSION } from '../../src/sdk/index.js';
import { createReferenceReceiver } from '../../reference/receive-state/index.js';

export const SCOPE = 'styx-m3-delivery/4741/wire-0.3.0';
export const WASM = readFileSync(new URL('../../vendor/openmls-wasm/openmls_wasm_bg.wasm', import.meta.url));

export async function initWasm() {
  await MlsEngine.initWasm({ wasmBytes: WASM });
}

const directories = [];
export function tempRoot() {
  const root = mkdtempSync(join(tmpdir(), 'styx-rs-'));
  directories.push(root);
  return root;
}
export function removeTempRoots() {
  for (const root of directories.splice(0)) rmSync(root, { recursive: true, force: true });
}

export function newKeys() {
  const secret = schnorr.utils.randomPrivateKey();
  return { secret, publicKey: bytesToHex(schnorr.getPublicKey(secret)) };
}

let opCounter = 0;
export function opId() {
  opCounter += 1;
  return randomBytes(12).toString('hex') + opCounter.toString(16).padStart(8, '0');
}

export function eventId() {
  return randomBytes(32).toString('hex');
}

/** One party: an identity, an archive directory and a key, with `open()` for each process run. */
export function party(root, name, overrides = {}) {
  const keys = newKeys();
  const directory = join(root, name);
  const atRestKey = new Uint8Array(randomBytes(32));
  let first = true;
  return {
    keys, directory, atRestKey, identity: keys.publicKey,
    /** A new receiver instance (a new process run): 'create' the first time, then 'open'. */
    instance(extra = {}) {
      const mode = first ? 'create' : 'open';
      first = false;
      return createReferenceReceiver({
        directory, atRestKey, identity: keys.publicKey, mode, wasmBytes: WASM, ...overrides, ...extra,
      });
    },
  };
}

export async function loaded(receiver, identity) {
  const snapshot = await receiver.receiveState.load({ identity, scope: SCOPE });
  if (snapshot.code !== undefined) throw new Error(`load failed: ${snapshot.code}`);
  return snapshot;
}

/** Alice invites Bob (directly through the ports): Alice's binding is complete, Bob's is an invitee binding. */
export async function invite(alice, aliceReceiver, bob, bobReceiver) {
  const keyPackage = await bobReceiver.session.createKeyPackage();
  const { welcome, ratchetTree } = await aliceReceiver.session.startSession({ peer: bob.identity, keyPackage });
  await bobReceiver.session.joinSession({ peer: alice.identity, welcome, ratchetTree });
}

export const text = (value) => new TextEncoder().encode(value);
export const untext = (bytes) => new TextDecoder().decode(bytes);

/* --- loopback relay and SDK clients ------------------------------------------ */

export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
export async function until(predicate, ms = 15_000) {
  const end = Date.now() + ms;
  while (!predicate() && Date.now() < end) await sleep(5);
  return predicate();
}

/** An accelerated caller clock: time and timers both run `factor` times faster. */
export function fastClock(factor = 50) {
  const origin = Date.now();
  return {
    now: () => origin + (Date.now() - origin) * factor,
    setTimer: (callback, delay) => setTimeout(callback, Math.max(0, Math.floor(delay / factor))),
    clearTimer: (handle) => clearTimeout(handle),
  };
}

const eventHash = (event) => bytesToHex(sha256(utf8Encode(JSON.stringify([
  0, event.pubkey, event.created_at, event.kind, event.tags, event.content,
]))));

function matches(filter, event) {
  return (!filter.kinds || filter.kinds.includes(event.kind))
    && (!filter.authors || filter.authors.includes(event.pubkey))
    && (!filter.ids || filter.ids.includes(event.id))
    && (!filter['#p'] || event.tags.some(([name, value]) => name === 'p' && filter['#p'].includes(value)))
    && (filter.since === undefined || event.created_at >= filter.since);
}

/**
 * A NIP-01 loopback relay: stores events, serves REQ (with `since`) then EOSE,
 * forwards live events. `state.delayMs` holds every EVENT frame it sends;
 * `state.silent` stops live forwarding (stored events are still served);
 * `replay(id)` sends a stored event again to every matching subscription.
 */
export async function relay({ delayMs = 0, port = 0 } = {}) {
  const server = new WebSocketServer({ host: '127.0.0.1', port });
  await new Promise((resolve) => server.once('listening', resolve));
  const peers = new Map();
  const events = new Map();
  const requests = [];
  const state = { delayMs, silent: false };
  const send = (socket, frame) => {
    const go = () => { if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify(frame)); };
    if (state.delayMs > 0 && frame[0] === 'EVENT') setTimeout(go, state.delayMs); else go();
  };
  server.on('connection', (socket) => {
    const subscriptions = new Map();
    peers.set(socket, subscriptions);
    socket.on('close', () => peers.delete(socket));
    socket.on('message', (raw) => {
      let frame;
      try { frame = JSON.parse(String(raw)); } catch { return; }
      const [type, value, filter] = frame;
      if (type === 'REQ') {
        requests.push({ id: value, filter });
        subscriptions.set(value, filter);
        for (const event of events.values()) if (matches(filter, event)) send(socket, ['EVENT', value, event]);
        if (state.delayMs > 0) setTimeout(() => send(socket, ['EOSE', value]), state.delayMs + 5);
        else send(socket, ['EOSE', value]);
      } else if (type === 'EVENT') {
        const event = value;
        if (eventHash(event) !== event.id) { send(socket, ['OK', event.id, false, 'invalid: id']); return; }
        events.set(event.id, event);
        send(socket, ['OK', event.id, true, '']);
        if (state.silent) return;
        for (const [other, subs] of peers) for (const [sub, f] of subs) if (matches(f, event)) send(other, ['EVENT', sub, event]);
      } else if (type === 'CLOSE') subscriptions.delete(value);
    });
  });
  const handle = {
    url: 'ws' + '://' + '127.0.0.1:' + server.address().port, port: server.address().port, events, requests, state,
    replay(id) {
      const event = events.get(id);
      for (const [other, subs] of peers) for (const [sub, f] of subs) if (matches(f, event)) send(other, ['EVENT', sub, event]);
    },
    async close() {
      for (const socket of server.clients) socket.terminate();
      await new Promise((resolve) => server.close(resolve));
    },
  };
  return handle;
}

function signedEvent(event, secret) {
  const id = eventHash(event);
  return { ...event, id, sig: bytesToHex(schnorr.sign(hexToBytes(id), secret)) };
}

/** Identity port with a test gift wrap that signs its layers and DOES NOT ENCRYPT. */
export function identityPort(keys) {
  return {
    getPublicKey: () => keys.publicKey,
    sign: ({ digest }) => schnorr.sign(digest, keys.secret),
    giftWrap: ({ rumor, recipient }) => {
      const seal = signedEvent({ pubkey: keys.publicKey, created_at: rumor.created_at, kind: 13, tags: [],
        content: JSON.stringify(rumor) }, keys.secret);
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

/** Wrap the reference ports to count calls: `calls.stage`, `calls.open` (by ciphertext hex) and so on. */
export function counted(receiver) {
  const calls = { stage: [], open: [], commit: [], ack: [], receiptDone: [], commitCursor: [], resolve: [] };
  const receiveState = { ...receiver.receiveState };
  for (const name of ['stage', 'commit', 'ack', 'receiptDone', 'commitCursor', 'resolve']) {
    const inner = receiver.receiveState[name];
    receiveState[name] = (argument) => { calls[name].push(argument); return inner(argument); };
  }
  const session = { ...receiver.session };
  session.openCandidate = (argument) => {
    calls.open.push(bytesToHex(argument.ciphertext));
    return receiver.session.openCandidate(argument);
  };
  return { receiveState, session, calls };
}

/** An SDK client over the reference ports, with an in-memory outbox store. */
export function makeClient({ urls, keys, ports, clock = fastClock(), receiptMode = 'RECIPIENT_RECEIPT', receive, delivery = {} }) {
  const records = new Map();
  const config = {
    interfaceVersion: SDK_INTERFACE_VERSION, relays: urls, clock, delivery: { receiptMode, ...delivery },
    ports: {
      storage: {
        list: () => [...records.values()], get: (k) => records.get(k) ?? null,
        put: (record) => { records.set(record.deliveryId, record); return true; },
        update: (k, value) => { records.set(k, value); return true; }, remove: (k) => records.delete(k),
      },
      session: ports.session, identity: identityPort(keys), receiveState: ports.receiveState,
    },
  };
  if (receive !== undefined) config.receive = receive;
  const made = createStyxClient(config);
  if (!made.ok) throw new Error(`createStyxClient: ${made.code}`);
  const client = made.value;
  const events = [];
  return {
    client, events,
    messages: () => events.filter((event) => event.kind === 'MESSAGE_RECEIVED'),
    async start({ listen = true, onMessage } = {}) {
      if (listen) {
        await client.onEvent((event) => {
          events.push(event);
          if (onMessage && event.kind === 'MESSAGE_RECEIVED') return onMessage(event);
          return undefined;
        });
      }
      return client.start();
    },
  };
}
