/** Experimental invitation orchestration; all session and wrap semantics belong to caller ports. */
import { createRelaySet } from './delivery/relay-pool.js';
import { retryDelayMs } from './delivery/retry.js';
import { sha256 } from '@noble/hashes/sha256';
import { schnorr } from '@noble/curves/secp256k1';
import { bytesToHex, hexToBytes, utf8Encode, bytesToBase64, base64ToBytes, randomBytes } from '../utils.js';

import { SDK_WIRE_VERSION as VERSION } from './wire-version.js';
const HEX = /^[0-9a-f]{64}$/;
const SIGNATURE = /^[0-9a-f]{128}$/;
// C-DLV section 3: unexamined candidate events one invitation operation keeps.
const CANDIDATE_PENDING_BOUND = 1024;
// C-DLV section 7.1: wrap key/content pairs remembered per accept, FIFO.
const EXAMINED_WINDOW = 4096;
// C-DLV section 6.5: a KeyPackage created_at may lead the local clock by at most this.
const KEY_PACKAGE_MAX_FUTURE_SECONDS = 600;
const EVENT_KEYS = ['id', 'pubkey', 'created_at', 'kind', 'tags', 'content', 'sig'];
const RUMOR_KEYS = ['pubkey', 'created_at', 'kind', 'tags', 'content'];
const ok = (value) => Object.freeze({ ok: true, value: Object.freeze(value) });
const fail = (code) => Object.freeze({ ok: false, code });
const exact = (v, keys) => v !== null && typeof v === 'object' && !Array.isArray(v)
  && Reflect.ownKeys(v).length === keys.length && keys.every((k) => Object.hasOwn(v, k));
const tagsEqual = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const digest = (event) => bytesToHex(sha256(utf8Encode(JSON.stringify([
  0, event.pubkey, event.created_at, event.kind, event.tags, event.content,
]))));
const bytes = (value, max) => value instanceof Uint8Array && value.length >= 1 && value.length <= max;
function decode(value, max) {
  if (typeof value !== 'string' || value.length > 4 * Math.ceil(max / 3)
      || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) return null;
  try {
    const result = base64ToBytes(value);
    return bytes(result, max) && bytesToBase64(result) === value ? result : null;
  } catch { return null; }
}
function shape(event, kind, limit) {
  return exact(event, EVENT_KEYS) && HEX.test(event.id) && HEX.test(event.pubkey)
    && SIGNATURE.test(event.sig) && Number.isSafeInteger(event.created_at) && event.created_at >= 0
    && event.kind === kind && Array.isArray(event.tags) && typeof event.content === 'string'
    && event.content.length <= limit;
}
function signed(event) {
  try { return digest(event) === event.id && schnorr.verify(hexToBytes(event.sig), hexToBytes(event.id), hexToBytes(event.pubkey)); }
  catch { return false; }
}

/** Private per-client manager. Boundary functions are supplied by the owning client. */
export function createInvitations(options) {
  const { relays, delivery, identity, session, clock, random, publicKey, call, scan, checkAttempt } = options;
  const P = Math.floor(delivery.perRelayTimeoutMs / 2);
  const T = delivery.perRelayTimeoutMs;
  const operations = new Set();
  const published = new Set();
  let stopped = false;
  let releaseDisposal;
  const disposalAllowed = new Promise((resolve) => { releaseDisposal = resolve; });
  const error = (code) => { throw { invitationCode: code }; };
  const running = () => { if (stopped) error('E_SDK_CLIENT_STOPPED'); };
  function now() {
    running();
    let value;
    try { value = clock.now(); } catch { error('E_SDK_INTERNAL'); }
    Promise.resolve(value).catch(() => {});
    const checked = scan(value);
    if (checked.unknown) error('E_SDK_UNKNOWN_CODE');
    if (checked.malformed) error('E_SDK_INTERNAL');
    if (typeof value !== 'number' || !Number.isFinite(value)) error('E_SDK_INTERNAL');
    return value;
  }
  async function boundary(holder, name, args, code, timeout = P) {
    running();
    const result = await call(holder, name, args, timeout);
    running();
    if (result.settled !== 'value') error(code);
    const checked = scan(result.value);
    if (checked.unknown) error('E_SDK_UNKNOWN_CODE');
    if (checked.malformed) error(code);
    return result.value;
  }
  // Synchronous clock/accessor results are not awaited: a promise is a wrong
  // value, even if it eventually resolves. Observe rejections without using them.
  function syncResult(holder, name, args, valid) {
    let value;
    try { value = holder[name](...args); } catch { error('E_SDK_INTERNAL'); }
    Promise.resolve(value).catch(() => {});
    const checked = scan(value);
    if (checked.unknown) error('E_SDK_UNKNOWN_CODE');
    if (checked.malformed || (value !== null && typeof value?.then === 'function') || !valid(value)) error('E_SDK_INTERNAL');
    return value;
  }
  const handleShape = (value) => value !== null && value !== undefined
    && !['boolean', 'function'].includes(typeof value);
  const healthy = (op) => { running(); if (op.fault) error(op.fault); };
  const remember = (op, e) => {
    if (op.fault !== 'E_SDK_UNKNOWN_CODE') op.fault = e?.invitationCode || 'E_SDK_INTERNAL';
  };
  // Every wait has both a caller-clock timer and a host backstop. Freezing never
  // clears either until shutdown step (4). Callback faults reject THIS wait;
  // throwing into a relay listener would otherwise be swallowed by the lane.
  function wait(op, delay, predicate, hostDelay = delay) {
    return new Promise((resolve, reject) => {
      let done = false;
      let clockHandle;
      let armed = false;
      let hostHandle;
      const finish = () => {
        if (done) return;
        done = true;
        op.wake = null;
        const clear = () => {
          clearTimeout(hostHandle);
          if (armed) {
            try { syncResult(clock, 'clearTimer', [clockHandle], (v) => v === undefined); }
            catch (e) { remember(op, e); }
          }
        };
        if (stopped) op.deferredClear.push(clear); else clear();
        if (!stopped && op.fault) reject({ invitationCode: op.fault }); else resolve();
      };
      op.wake = () => {
        if (stopped || op.fault) { finish(); return; }
        try { if (predicate()) finish(); } catch (e) { remember(op, e); finish(); }
      };
      hostHandle = setTimeout(finish, hostDelay);
      try { clockHandle = syncResult(clock, 'setTimer', [finish, delay], handleShape); armed = true; }
      catch (e) { remember(op, e); finish(); }
      op.wake?.();
    });
  }
  async function connect(op, filter) {
    running();
    const subscriptionId = 'i' + bytesToHex(randomBytes(16));
    let set;
    try { set = createRelaySet({ relays: [...relays], clock, random, perRelayTimeoutMs: T, subscriptionId, filter, reconnectDelay: retryDelayMs }); }
    catch { error('E_SDK_INTERNAL'); }
    op.set = set;
    Promise.resolve(set).catch(() => {});
    const setCheck = scan(set, new Set(['relayCount', 'connectedRelays', 'stopped', 'running']));
    if (setCheck.unknown) error('E_SDK_UNKNOWN_CODE');
    if (setCheck.malformed || !set || typeof set.then === 'function'
        || !['onFrame', 'start', 'publish', 'freeze', 'dispose'].every((n) => typeof set[n] === 'function')) error('E_SDK_INTERNAL');
    const unsubscribe = await boundary(set, 'onFrame', [(frame) => {
      if (stopped) { op.wake?.(); return; }
      // Frame data is untrusted network input; inspect only the local envelope.
      try {
        const local = Object.fromEntries(Reflect.ownKeys(frame).filter((key) => key !== 'data')
          .map((key) => [key, frame[key]]));
        const metadata = scan(local);
        if (metadata.unknown) error('E_SDK_UNKNOWN_CODE');
        if (!exact(frame, ['relayIndex', 'relay', 'data']) || metadata.malformed
            || !Number.isInteger(frame.relayIndex) || frame.relayIndex < 0
            || frame.relayIndex >= relays.length || frame.relay !== relays[frame.relayIndex]) error('E_SDK_INTERNAL');
        const data = frame.data;
        if (!Array.isArray(data)) return;
        if (data[0] === 'EOSE' && data[1] === subscriptionId) op.eose.add(frame.relayIndex);
        if (data[0] === 'EVENT' && data[1] === subscriptionId && op.events.length < CANDIDATE_PENDING_BOUND) {
          op.events.push(data[2]);
        }
      } catch (e) { remember(op, e); }
      op.wake?.();
    }], 'E_SDK_INTERNAL');
    if (typeof unsubscribe !== 'function') error('E_SDK_INTERNAL');
    const result = await boundary(set, 'start', [], 'E_SDK_INTERNAL', T + P);
    healthy(op);
    if (!exact(result, ['connectedRelays']) || !Number.isInteger(result.connectedRelays)
        || result.connectedRelays < 0 || result.connectedRelays > relays.length) error('E_SDK_INTERNAL');
    if (!result.connectedRelays) error('E_SDK_NO_RELAY_AVAILABLE');
    return result.connectedRelays;
  }
  async function publish(op, event) {
    running();
    const returned = await call(op.set, 'publish', [event], P);
    running();
    if (returned.settled !== 'value') error('E_SDK_INTERNAL');
    const attempt = returned.value;
    const validateAttempt = (initial = false) => {
      if (!initial) {
        const outcomes = attempt.outcomes;
        const checked = scan(outcomes);
        if (checked.unknown) error('E_SDK_UNKNOWN_CODE');
        if (checked.malformed || !Array.isArray(outcomes) || outcomes.length !== relays.length) error('E_SDK_INTERNAL');
        for (let i = 0; i < relays.length; i++) {
          if (!Object.hasOwn(outcomes, i) || typeof outcomes[i] !== 'string') error('E_SDK_INTERNAL');
        }
      }
      const verdict = checkAttempt(attempt, event);
      if (verdict !== 'ok') error(verdict === 'unknown' ? 'E_SDK_UNKNOWN_CODE' : 'E_SDK_INTERNAL');
    };
    validateAttempt(true);
    const origin = now();
    const finishPublication = () => {
      healthy(op);
      const settled = syncResult(attempt, 'isSettled', [], (v) => typeof v === 'boolean');
      validateAttempt();
      return settled;
    };
    const unsubscribe = await boundary(attempt, 'onSettled', [() => op.wake?.()], 'E_SDK_INTERNAL');
    if (typeof unsubscribe !== 'function') error('E_SDK_INTERNAL');
    await wait(op, Math.max(0, T - (now() - origin)), finishPublication);
    healthy(op);
    validateAttempt();
    const acceptedRelays = Object.freeze(attempt.outcomes.flatMap((outcome, index) => outcome === 'ACCEPTED' ? [index] : []));
    if (!acceptedRelays.length) error('E_SDK_PUBLISH_NOT_ACCEPTED');
    return acceptedRelays;
  }
  async function sign(event) {
    const id = digest(event);
    const signature = await boundary(identity, 'sign', [ { digest: hexToBytes(id) } ], 'E_SDK_IDENTITY_FAILED');
    if (!(signature instanceof Uint8Array) || signature.length !== 64) error('E_SDK_IDENTITY_FAILED');
    return { ...event, id, sig: bytesToHex(signature) };
  }
  function timestamp() {
    const value = Math.floor(now() / 1000);
    if (!Number.isSafeInteger(value) || value < 0) error('E_SDK_INTERNAL');
    return value;
  }
  function operation(body) {
    const op = { set: null, eose: new Set(), events: [], wake: null, deferredClear: [], done: null };
    operations.add(op);
    op.done = (async () => {
      let result;
      try { result = await body(op); healthy(op); }
      catch (e) { result = fail(e?.invitationCode || 'E_SDK_INTERNAL'); }
      finally {
        if (stopped) await disposalAllowed;
        for (const clear of op.deferredClear) clear();
        if (op.set) {
          const disposed = await call(op.set, 'dispose', [], T + P);
          const checked = disposed.settled === 'value' ? scan(disposed.value) : null;
          if (checked?.unknown) result = fail('E_SDK_UNKNOWN_CODE');
          else if (disposed.settled !== 'value' || checked.malformed || disposed.value !== undefined) {
            if (result.ok) result = fail('E_SDK_INTERNAL');
          }
        }
        operations.delete(op);
      }
      return stopped ? fail('E_SDK_CLIENT_STOPPED') : result;
    })();
    return op.done;
  }
  function peerArgument(argument, keys, peerName) {
    if (!exact(argument, keys) || typeof argument[peerName] !== 'string'
        || !HEX.test(argument[peerName]) || argument[peerName] === publicKey) error('E_SDK_INVALID_ARGUMENT');
    return argument[peerName];
  }
  function keyPackage(event, invitee) {
    try {
      if (!shape(event, 4743, 4 * Math.ceil(65536 / 3)) || event.pubkey !== invitee) return null;
      const expiration = event.created_at + 3600;
      if (!Number.isSafeInteger(expiration)
          || !tagsEqual(event.tags, [['v', VERSION], ['expiration', String(expiration)]])) return null;
      const value = decode(event.content, 65536);
      if (!value) return null;
      const current = now();
      if (expiration * 1000 <= current
          || event.created_at > Math.floor(current / 1000) + KEY_PACKAGE_MAX_FUTURE_SECONDS || !signed(event)) return null;
      return value;
    } catch (e) {
      // A local clock fault is not an invalid network candidate.
      if (e?.invitationCode) throw e;
      return null;
    }
  }
  return {
    publishKeyPackage: () => operation(async (op) => {
      const keyPackage = await boundary(session, 'createKeyPackage', [], 'E_SDK_SESSION_FAILED');
      if (!bytes(keyPackage, 65536)) error('E_SDK_SESSION_FAILED');
      const created_at = timestamp();
      const expiration = created_at + 3600;
      if (!Number.isSafeInteger(expiration)) error('E_SDK_INTERNAL');
      const event = await sign({ pubkey: publicKey, created_at, kind: 4743,
        tags: [['v', VERSION], ['expiration', String(expiration)]], content: bytesToBase64(keyPackage) });
      await connect(op, { kinds: [4743], authors: [publicKey] });
      const acceptedRelays = await publish(op, event);
      published.add(event.id);
      return ok({ keyPackageEventId: event.id, acceptedRelays });
    }),
    invite: (argument) => operation(async (op) => {
      const invitee = peerArgument(argument, ['invitee'], 'invitee');
      const connected = await connect(op, { kinds: [4743], authors: [invitee] });
      await wait(op, T, () => op.eose.size >= connected);
      running();
      const candidates = op.events.map((event) => ({ event, value: keyPackage(event, invitee) })).filter((c) => c.value);
      candidates.sort((a, b) => b.event.created_at - a.event.created_at || (a.event.id < b.event.id ? -1 : a.event.id > b.event.id ? 1 : 0));
      if (!candidates.length) error('E_SDK_KEYPACKAGE_NOT_FOUND');
      const chosen = candidates[0];
      // Examined candidates are not retained (C-DLV section 7.1).
      op.events.length = 0;
      candidates.length = 0;
      const started = await boundary(session, 'startSession', [{ peer: invitee, keyPackage: chosen.value }], 'E_SDK_SESSION_FAILED');
      if (!exact(started, ['welcome', 'ratchetTree']) || !bytes(started.welcome, 262144)
          || !bytes(started.ratchetTree, 262144)) error('E_SDK_SESSION_FAILED');
      const rumor = { pubkey: publicKey, created_at: timestamp(), kind: 4744,
        tags: [['e', chosen.event.id], ['v', VERSION]],
        content: JSON.stringify({ welcome: bytesToBase64(started.welcome), ratchetTree: bytesToBase64(started.ratchetTree) }) };
      const event = await boundary(identity, 'giftWrap', [{ rumor, recipient: invitee }], 'E_SDK_IDENTITY_FAILED');
      if (!shape(event, 1059, 1048576) || !tagsEqual(event.tags, [['p', invitee]])) error('E_SDK_IDENTITY_FAILED');
      const acceptedRelays = await publish(op, event);
      return ok({ keyPackageEventId: chosen.event.id, welcomeEventId: event.id, acceptedRelays });
    }),
    acceptInvite: (argument) => operation(async (op) => {
      const inviter = peerArgument(argument, ['inviter', 'keyPackageEventId'], 'inviter');
      const id = argument.keyPackageEventId;
      if (typeof id !== 'string' || !HEX.test(id) || !published.has(id)) error('E_SDK_INVALID_ARGUMENT');
      const admitted = now();
      const deadline = admitted + delivery.deadlineMs;
      const hostDeadline = Date.now() + delivery.deadlineMs + 1000;
      await connect(op, { kinds: [1059], '#p': [publicKey] });
      // Candidates whose unwrap was already attempted in this operation.
      const examined = new Set();
      while (Date.now() < hostDeadline && now() < deadline) {
          if (op.events.length === 0) {
            await wait(op, Math.max(0, deadline - now()), () => op.events.length > 0,
              Math.max(0, hostDeadline - Date.now()));
            running();
            continue;
          }
          // Examined candidates are not retained (C-DLV section 7.1).
          const event = op.events.shift();
          if (!shape(event, 1059, 1048576) || !tagsEqual(event.tags, [['p', publicKey]])) continue;
          // The unwrap depends only on the wrap key and content: one attempt each.
          const candidate = bytesToHex(sha256(utf8Encode(JSON.stringify([event.pubkey, event.content]))));
          if (examined.has(candidate) || !signed(event)) continue;
          if (examined.size >= EXAMINED_WINDOW) examined.delete(examined.values().next().value);
          examined.add(candidate);
          let unwrapped;
          try { unwrapped = await boundary(identity, 'unwrapGift', [{ event }], 'E_SDK_IDENTITY_FAILED'); }
          catch { running(); continue; }
          if (!exact(unwrapped, ['rumor', 'sealSigner']) || unwrapped.sealSigner !== inviter) continue;
          const rumor = unwrapped.rumor;
          if (!exact(rumor, RUMOR_KEYS) || rumor.pubkey !== inviter || rumor.kind !== 4744
              || !Number.isSafeInteger(rumor.created_at) || rumor.created_at < 0
              || !tagsEqual(rumor.tags, [['e', id], ['v', VERSION]])
              || typeof rumor.content !== 'string' || rumor.content.length > 700000) continue;
          let payload;
          try { payload = JSON.parse(rumor.content); } catch { continue; }
          if (!exact(payload, ['welcome', 'ratchetTree'])) continue;
          const welcome = decode(payload.welcome, 262144);
          const ratchetTree = decode(payload.ratchetTree, 262144);
          if (!welcome || !ratchetTree || Date.now() >= hostDeadline || now() >= deadline) continue;
          const joined = await boundary(session, 'joinSession', [{ peer: inviter, welcome, ratchetTree }], 'E_SDK_SESSION_FAILED');
          if (joined !== true) error('E_SDK_SESSION_FAILED');
          return ok({ inviter });
        }
      error('E_SDK_INVITE_TIMEOUT');
    }),
    freeze: () => {
      stopped = true;
      for (const op of operations) {
        try { Promise.resolve(op.set?.freeze()).catch(() => {}); } catch { /* independent sets */ }
      }
    },
    dispose: async () => {
      releaseDisposal();
      for (const op of operations) op.wake?.();
      await Promise.all([...operations].map((op) => op.done));
    },
  };
}
