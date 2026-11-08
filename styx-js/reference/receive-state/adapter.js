// Experimental Node reference implementation of the M3-RECEIVE ports:
// `ports.receiveState` (C-SDK §8.5) and the session port with the receive
// methods `openCandidate` and `isKnownSender` (C-SDK §8.2), over the unchanged
// MlsEngine and the immutable vendored WASM. Not imported by the SDK lane.
//
// Design (owner technical gate of M3-RECEIVE-2, G1-G3):
// - one exclusive coordinator per provider serialises every port call that
//   reads or mutates MLS or durable state;
// - candidate-copy strategy: `openCandidate` opens on a copy of the
//   authoritative engine restored from its serialized state; the
//   authoritative engine changes only after the commit is durable;
// - every provider mutation (`seal`, `createKeyPackage`, `startSession`,
//   `joinSession`, an installed commit) is made durable by an atomic snapshot
//   rewrite before its effect leaves the coordinator;
// - the peer-binding manifest maps each peer to its group; an invitee binding
//   starts without a group id and is completed by the exporter test of §12.
import { readFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { timingSafeEqual } from 'node:crypto';
import { MlsEngine, MlsBindingError } from '../../src/crypto/mls/mls-engine.js';
import { isMlsApplicationMessage } from '../../src/crypto/mls/mls-session.js';
import { Group } from '../../vendor/openmls-wasm/openmls_wasm.js';
import {
  BOUNDS, SCHEMA, SCOPE, SnapshotFormatError, emptyState, openSnapshot, sealSnapshot, storedBytesOf,
} from './format.js';
import {
  ArchiveLayoutError, UncertainWriteError, createDirectory, readSnapshot, removeOrphans, writeSnapshot,
} from './store.js';

export const BINDING_LABEL = 'styx/m3-receive/invitee-binding/v1';
export const BINDING_LENGTH = 32;
export const DEFAULT_MAX_STORED_BYTES = 536_870_912;
export const MAX_CURSORS = BOUNDS.cursors;

const FAILED = 'E_SDK_RECEIVE_STATE_FAILED';
const INCOMPATIBLE = 'E_SDK_RECEIVE_STATE_INCOMPATIBLE';
const CONFLICT = 'E_SDK_RECEIVE_STATE_CONFLICT';
const CAPACITY = 'E_SDK_RECEIVE_STATE_CAPACITY';
const HEX64 = /^[0-9a-f]{64}$/;
const HEX32 = /^[0-9a-f]{32}$/;
const utf8 = new TextEncoder();
const strictUtf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const DEFAULT_WASM = new URL('../../vendor/openmls-wasm/openmls_wasm_bg.wasm', import.meta.url);

const code = (value) => Object.freeze({ code: value });
const isBytes = (value) => value instanceof Uint8Array;
const copy = (bytes) => new Uint8Array(bytes);

/* --- MLS header ---------------------------------------------------------- */

/** RFC 9420 §2.1.2 variable-length integer with minimal encoding, or null. */
function readVarint(bytes, offset) {
  if (offset >= bytes.length) return null;
  const first = bytes[offset];
  const prefix = first >> 6;
  if (prefix === 0) return { value: first & 0x3f, next: offset + 1 };
  if (prefix === 1) {
    if (offset + 2 > bytes.length) return null;
    const value = ((first & 0x3f) << 8) | bytes[offset + 1];
    return value < 0x40 ? null : { value, next: offset + 2 };
  }
  if (prefix === 2) {
    if (offset + 4 > bytes.length) return null;
    const value = (first & 0x3f) * 0x1000000 + (bytes[offset + 1] << 16) + (bytes[offset + 2] << 8) + bytes[offset + 3];
    return value < 0x4000 ? null : { value, next: offset + 4 };
  }
  return null;
}

/**
 * Read the cleartext `group_id` of an MLS application PrivateMessage (RFC
 * 9420 §6.3.1). Returns `{ groupId }` for a strict canonical UTF-8 id,
 * `{ malformed: true }` for a ciphertext that is not a well-formed application
 * PrivateMessage or whose id is empty or not canonical UTF-8, and
 * `{ oversized: true }` for a well-formed id longer than the adapter stores
 * (BOUNDS.groupId), which is not a permanent property of the message.
 */
export function readHeaderGroupId(ciphertext) {
  if (!isBytes(ciphertext) || !isMlsApplicationMessage(ciphertext)) return { malformed: true };
  const length = readVarint(ciphertext, 4);
  if (length === null || length.value === 0 || length.next + length.value > ciphertext.length) return { malformed: true };
  const raw = ciphertext.subarray(length.next, length.next + length.value);
  let value;
  try {
    value = strictUtf8.decode(raw);
  } catch {
    return { malformed: true };
  }
  const again = utf8.encode(value);
  if (again.length !== raw.length) return { malformed: true };
  for (let i = 0; i < raw.length; i += 1) if (again[i] !== raw[i]) return { malformed: true };
  if (raw.length > BOUNDS.groupId) return { oversized: true };
  return { groupId: value };
}

/** The header group id as a string, or `null` when `readHeaderGroupId` finds none. */
export function headerGroupId(ciphertext) {
  return readHeaderGroupId(ciphertext).groupId ?? null;
}

/* --- canonical comparison of two serialized provider states -------------- */

/**
 * The provider serializes its storage map in hash order, so two equal states
 * may differ byte for byte. This compares the decoded entries as a set:
 * `u64 count || (u64 keyLength || u64 valueLength || key || value)*`.
 */
export function sameProviderState(a, b) {
  const entries = (bytes) => {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const read = (offset) => {
      if (offset + 8 > bytes.length) throw new RangeError('truncated');
      const value = view.getUint32(offset) * 0x1_0000_0000 + view.getUint32(offset + 4);
      if (!Number.isSafeInteger(value)) throw new RangeError('length');
      return value;
    };
    const count = read(0);
    let offset = 8;
    const map = new Map();
    for (let i = 0; i < count; i += 1) {
      const keyLength = read(offset);
      const valueLength = read(offset + 8);
      offset += 16;
      if (keyLength + valueLength > bytes.length - offset) throw new RangeError('truncated');
      const key = Buffer.from(bytes.subarray(offset, offset + keyLength)).toString('hex');
      map.set(key, bytes.subarray(offset + keyLength, offset + keyLength + valueLength));
      offset += keyLength + valueLength;
    }
    if (offset !== bytes.length) throw new RangeError('trailing');
    return map;
  };
  try {
    const left = entries(a);
    const right = entries(b);
    if (left.size !== right.size) return false;
    for (const [key, value] of left) {
      const other = right.get(key);
      if (other === undefined || other.length !== value.length || !Buffer.from(value).equals(Buffer.from(other))) return false;
    }
    return true;
  } catch {
    return false;
  }
}

/* --- the reference receiver ---------------------------------------------- */

/**
 * Create the reference ports for one identity and one archive directory.
 *
 * @param {object} options
 * @param {string} options.directory the archive directory (created when `mode` is `'create'`)
 * @param {Uint8Array} options.atRestKey exactly 32 random bytes kept apart from the archive
 * @param {string} options.identity own public key, 64 lowercase hex (also the MLS credential)
 * @param {'create' | 'open'} options.mode `'create'` makes a new empty archive at the first `load`
 *   and fails if one exists; `'open'` requires an existing archive
 * @param {number} [options.maxStoredBytes] the adapter's own bound on `storedBytes`; it must be at
 *   least the SDK's `receive.maxStoredBytes` plus one inbound event and one MLS checkpoint
 * @param {Uint8Array} [options.wasmBytes] the vendored WASM bytes (read from the vendored file when absent)
 * @param {object} [options.hooks] test hooks (fault injection only; a throw is a fault): `beforeStep(step,
 *   operation)` before each step of a snapshot rewrite; `beforeCandidate({ sender })` inside
 *   `openCandidate` before the copy is restored; `beforeVerification(step)` before `group-load`,
 *   `export-key` and `load-session` of the invitee verification; `afterExport(value)` may replace the
 *   exporter value; `beforeReapply()` and `beforeSwap()` inside the installation after a commit
 * @returns {{ receiveState: object, session: object, inspect: () => object }}
 */
export function createReferenceReceiver(options) {
  if (options === null || typeof options !== 'object') throw new TypeError('options required');
  const { directory, atRestKey, identity, mode } = options;
  if (typeof directory !== 'string' || directory.length === 0) throw new TypeError('directory required');
  if (!isBytes(atRestKey) || atRestKey.length !== 32) {
    throw new TypeError('atRestKey must be exactly 32 bytes supplied by the caller');
  }
  if (typeof identity !== 'string' || !HEX64.test(identity)) throw new TypeError('identity must be 64 lowercase hex');
  if (mode !== 'create' && mode !== 'open') throw new TypeError("mode must be 'create' or 'open'");
  const maxStoredBytes = options.maxStoredBytes ?? DEFAULT_MAX_STORED_BYTES;
  if (!Number.isSafeInteger(maxStoredBytes) || maxStoredBytes <= 0) throw new TypeError('maxStoredBytes');
  const maxFileBytes = 2 * maxStoredBytes + 1_048_576;
  const hooks = options.hooks ?? {};
  const key = copy(atRestKey);

  /** The durable state as last written (or loaded); null before `load`. */
  let state = null;
  /** The authoritative engine; it never runs ahead of `state` outside the coordinator. */
  let engine = null;
  let mlsIdentityKey = null;
  /** Incremented by every authoritative provider mutation. */
  let generation = 0;
  /** True after a write whose outcome on disk is unknown: every later call fails until `load`. */
  let poisoned = false;
  /** The single open candidate (one open unit at a time). */
  let candidate = null;
  let ticketCounter = 0;
  const deadOperations = new Set();
  /** The resolution record found by the last load (diagnostics only; never answered after a load). */
  let loadedResolution = null;
  let createdArchive = false;
  let writes = 0;
  let swaps = 0;

  /* --- the exclusive coordinator ---------------------------------------- */

  // Two FIFO locks, always taken in this order: the provider lock serialises
  // every operation that reads or mutates MLS state (openCandidate, commit,
  // seal, createKeyPackage, startSession, joinSession, load); the file lock
  // serialises every snapshot rewrite and every read of the durable state
  // that must not interleave with one (all port writes, resolve, load). A
  // slow candidate therefore never delays a plain receive-state write.
  function mutex() {
    let chain = Promise.resolve();
    return (task) => {
      const run = chain.then(task);
      chain = run.then(() => undefined, () => undefined);
      return run;
    };
  }
  const withProvider = mutex();
  const withFile = mutex();

  async function wasm() {
    const bytes = options.wasmBytes ?? await readFile(DEFAULT_WASM);
    await MlsEngine.initWasm({ wasmBytes: bytes });
  }

  async function restoreEngine(stateBytes) {
    return MlsEngine.restore({ name: identity, stateBytes, identityPubKey: mlsIdentityKey });
  }

  /**
   * Rewrite the snapshot with `next`. Resolves 'ok' (adopted), 'failed' (the
   * authoritative file is unchanged) or 'uncertain' (poisoned).
   */
  async function persist(next, operation) {
    let bytes;
    try {
      bytes = sealSnapshot(next, key);
    } catch {
      return 'failed';
    }
    try {
      await writeSnapshot(directory, bytes, (step) => (hooks.beforeStep ? hooks.beforeStep(step, operation) : undefined));
    } catch (error) {
      if (error instanceof UncertainWriteError) {
        poisoned = true;
        return 'uncertain';
      }
      return 'failed';
    } finally {
      bytes.fill(0);
    }
    writes += 1;
    state = next;
    return 'ok';
  }

  function successOf(current) {
    return Object.freeze({ revision: current.revision, storedBytes: storedBytesOf(current) });
  }

  function binding(peer) {
    return state.bindings.find((entry) => entry.peer === peer) ?? null;
  }

  function withState(change) {
    return {
      ...state,
      bindings: state.bindings.slice(), cursors: state.cursors.slice(), seen: state.seen.slice(),
      pending: state.pending.slice(), ready: state.ready.slice(), acknowledged: state.acknowledged.slice(),
      receiptsDue: state.receiptsDue.slice(), ...change,
    };
  }

  /** The authoritative session of a peer, loading a complete binding on demand. */
  function authoritativeSession(peer) {
    const existing = engine.session(peer);
    if (existing !== undefined) return existing;
    const bound = binding(peer);
    if (bound === null || bound.groupId === null) return null;
    return engine.loadSession(peer, bound.groupId, { expectedPeer: peer });
  }

  /**
   * Checkpoint the authoritative engine after a provider mutation (called
   * under the provider lock); `build(state)` returns the other changes and is
   * evaluated under the file lock against the current durable state.
   */
  async function checkpoint(build, operation) {
    generation += 1;
    return withFile(() => {
      if (!usable()) return 'failed';
      return persist(withState({ ...build(state), mlsState: engine.serializeState() }), operation);
    });
  }

  function usable() {
    return state !== null && !poisoned;
  }

  /* --- receiveState: load ----------------------------------------------- */

  async function loadUnit(argument) {
    if (argument === null || typeof argument !== 'object' || argument.identity !== identity || argument.scope !== SCOPE) {
      return code(INCOMPATIBLE);
    }
    state = null;
    engine = null;
    poisoned = false;
    candidate = null;
    deadOperations.clear();
    try {
      await wasm();
    } catch {
      return code(FAILED);
    }
    let fileBytes;
    try {
      if (mode === 'create' && !createdArchive) {
        await createDirectory(directory, dirname(directory));
        const fresh = await MlsEngine.create({ name: identity });
        mlsIdentityKey = copy(fresh.identityPublicKey());
        const initial = emptyState({ identity, mlsState: fresh.serializeState(), mlsIdentityKey });
        const written = await persist(initial, 'create');
        if (written !== 'ok') return code(FAILED);
        createdArchive = true;
      }
      await removeOrphans(directory);
      fileBytes = await readSnapshot(directory, maxFileBytes);
    } catch (error) {
      if (error instanceof ArchiveLayoutError) return code(INCOMPATIBLE);
      return code(FAILED);
    }
    if (fileBytes === null) return code(INCOMPATIBLE); // a missing archive is never an empty state
    let loaded;
    try {
      loaded = openSnapshot(fileBytes, key, identity, maxFileBytes);
    } catch (error) {
      return code(error instanceof SnapshotFormatError ? INCOMPATIBLE : FAILED);
    } finally {
      fileBytes.fill(0);
    }
    mlsIdentityKey = loaded.mlsIdentityKey;
    let restored;
    try {
      restored = await restoreEngine(loaded.mlsState);
      for (const entry of loaded.bindings) {
        if (entry.groupId === null) continue;
        const session = restored.loadSession(entry.peer, entry.groupId, { expectedPeer: entry.peer });
        if (session === null) return code(INCOMPATIBLE);
      }
    } catch {
      return code(INCOMPATIBLE);
    }
    // The resolution record is retained until this load (C-SDK §8.5); the next write drops it.
    state = { ...loaded, lastCommit: null };
    loadedResolution = loaded.lastCommit;
    engine = restored;
    generation += 1;
    return {
      schema: SCHEMA, identity, scope: SCOPE, revision: state.revision, storedBytes: storedBytesOf(state),
      cursors: state.cursors.map((entry) => ({ relay: entry.relay, syncedUntil: entry.syncedUntil })),
      pending: state.pending.map((entry) => ({
        eventId: entry.eventId, sender: entry.sender, ciphertext: copy(entry.ciphertext), receiptRequested: entry.receiptRequested,
      })),
      ready: state.ready.map((entry) => ({
        eventId: entry.eventId, sender: entry.sender, payload: copy(entry.payload), receiptDue: entry.receiptDue,
      })),
      acknowledged: state.acknowledged.slice(),
      receiptsDue: state.receiptsDue.map((entry) => ({ eventId: entry.eventId, sender: entry.sender })),
      seen: state.seen.slice(),
    };
  }

  /* --- receiveState: writes ---------------------------------------------- */

  /** Common checks of a write: `null` to proceed, or the refusal. */
  function writeGate(argument) {
    if (!usable()) return code(FAILED);
    if (argument === null || typeof argument !== 'object' || !HEX32.test(argument.operationId)) return code(FAILED);
    if (argument.revision !== state.revision) return code(CONFLICT);
    return null;
  }

  async function plainWrite(next, operation) {
    if (storedBytesOf(next) > maxStoredBytes) return code(FAILED);
    const written = await persist(next, operation);
    if (written === 'ok') return successOf(state);
    if (written === 'failed') return code(FAILED);
    throw new UncertainWriteError(`${operation}: outcome unknown`);
  }

  async function stageUnit(argument) {
    const refused = writeGate(argument);
    if (refused !== null) return refused;
    const event = argument.event;
    if (event === null || typeof event !== 'object' || !HEX64.test(event.eventId) || !HEX64.test(event.sender)
      || typeof event.receiptRequested !== 'boolean' || !isBytes(event.ciphertext)
      || event.ciphertext.length === 0 || event.ciphertext.length > BOUNDS.ciphertext) {
      return code(FAILED);
    }
    if (state.seen.includes(event.eventId)) return successOf(state); // idempotent per id
    const entry = {
      eventId: event.eventId, sender: event.sender, receiptRequested: event.receiptRequested, ciphertext: copy(event.ciphertext),
    };
    const next = withState({ revision: state.revision + 1 });
    next.seen.push(entry.eventId);
    next.pending.push(entry);
    return plainWrite(next, 'stage');
  }

  async function ackUnit(argument) {
    const refused = writeGate(argument);
    if (refused !== null) return refused;
    const index = state.ready.findIndex((entry) => entry.eventId === argument.eventId);
    if (index < 0) return code(FAILED);
    const next = withState({ revision: state.revision + 1 });
    next.ready.splice(index, 1);
    next.acknowledged.push(argument.eventId);
    const result = await plainWrite(next, 'ack');
    return result;
  }

  async function receiptDoneUnit(argument) {
    const refused = writeGate(argument);
    if (refused !== null) return refused;
    const index = state.receiptsDue.findIndex((entry) => entry.eventId === argument.eventId);
    if (index < 0) return code(FAILED);
    const next = withState({ revision: state.revision + 1 });
    next.receiptsDue.splice(index, 1);
    return plainWrite(next, 'receiptDone');
  }

  async function commitCursorUnit(argument) {
    const refused = writeGate(argument);
    if (refused !== null) return refused;
    const { relay, syncedUntil } = argument;
    if (typeof relay !== 'string' || relay.length === 0 || utf8.encode(relay).length > BOUNDS.relay
      || !Number.isSafeInteger(syncedUntil) || syncedUntil < 0) {
      return code(FAILED);
    }
    const next = withState({ revision: state.revision + 1 });
    // The most recently committed cursor goes last; beyond MAX_CURSORS the
    // oldest is dropped (a missing cursor only means a full catch-up).
    next.cursors = next.cursors.filter((entry) => entry.relay !== relay);
    next.cursors.push({ relay, syncedUntil });
    while (next.cursors.length > MAX_CURSORS) next.cursors.shift();
    return plainWrite(next, 'commitCursor');
  }

  /* --- session: the candidate ------------------------------------------- */

  /**
   * Open `ciphertext` from `sender` on a fresh copy of the authoritative
   * engine. Returns `{ outcome: 'application', plaintext, stateBytes, groupId }`,
   * `{ outcome: 'reject' }` or `{ outcome: 'retry' }`; never changes the
   * authoritative engine or the durable state.
   */
  async function classify(sender, ciphertext) {
    const bound = binding(sender);
    if (bound === null) return { outcome: 'retry' };
    const header = readHeaderGroupId(ciphertext);
    if (header.malformed) return { outcome: 'reject' };
    if (header.oversized) {
      // A bound group id is at most BOUNDS.groupId bytes, so a longer one differs from it: reject. For an
      // invitee binding the length is only this adapter's bound, not a property of the message: retry.
      return { outcome: bound.groupId !== null ? 'reject' : 'retry' };
    }
    const { groupId } = header;
    if (bound.groupId !== null && groupId !== bound.groupId) return { outcome: 'reject' };
    let scratch;
    try {
      if (hooks.beforeCandidate) await hooks.beforeCandidate({ sender });
      scratch = await restoreEngine(engine.serializeState());
    } catch {
      return { outcome: 'retry' };
    }
    if (bound.groupId === null) {
      // §12 step 2/4: the header names a candidate; only the exporter value
      // of the stored group proves that it is the group joined for `sender`.
      let handle;
      try {
        if (hooks.beforeVerification) await hooks.beforeVerification('group-load');
        handle = Group.load(scratch.provider, groupId);
      } catch {
        return { outcome: 'retry' };
      }
      if (handle === undefined) return { outcome: 'reject' };
      let value;
      try {
        if (hooks.beforeVerification) await hooks.beforeVerification('export-key');
        value = handle.export_key(scratch.provider, BINDING_LABEL, utf8.encode(sender), BINDING_LENGTH);
        if (hooks.afterExport) value = await hooks.afterExport(value);
      } catch {
        return { outcome: 'retry' };
      } finally {
        try { handle.free(); } catch { /* already released */ }
      }
      if (!isBytes(value) || value.length !== BINDING_LENGTH) return { outcome: 'retry' };
      if (!timingSafeEqual(value, bound.bindingValue)) return { outcome: 'reject' };
    }
    let session;
    try {
      if (hooks.beforeVerification) await hooks.beforeVerification('load-session');
      session = scratch.loadSession(sender, groupId, { expectedPeer: sender });
    } catch {
      return { outcome: 'retry' };
    }
    if (session === null) return { outcome: 'retry' };
    let opened;
    try {
      opened = session.decrypt(ciphertext);
    } catch (error) {
      if (!(error instanceof MlsBindingError) && /no application plaintext from the peer/.test(String(error && error.message))) {
        return { outcome: 'reject' };
      }
      return { outcome: 'retry' };
    }
    let stateBytes;
    try {
      stateBytes = scratch.serializeState();
    } catch {
      return { outcome: 'retry' };
    }
    return { outcome: 'application', plaintext: copy(opened.plaintext), stateBytes, groupId };
  }

  async function openCandidateUnit(argument) {
    candidate = null;
    if (!usable()) throw new Error('reference receiver not usable');
    if (argument === null || typeof argument !== 'object' || !HEX64.test(argument.sender)
      || !isBytes(argument.ciphertext) || argument.ciphertext.length === 0) {
      throw new TypeError('openCandidate: malformed argument');
    }
    const ciphertext = copy(argument.ciphertext);
    const found = await classify(argument.sender, ciphertext);
    ticketCounter += 1;
    const ticket = `ticket-${ticketCounter}`;
    if (found.outcome === 'retry') return Object.freeze({ receiveOutcome: 'retry', ticket });
    candidate = { ticket, generation, sender: argument.sender, ciphertext, ...found };
    if (found.outcome === 'reject') return Object.freeze({ receiveOutcome: 'reject', ticket });
    return Object.freeze({ receiveOutcome: 'application', ticket, plaintext: copy(found.plaintext) });
  }

  function sameBytes(a, b) {
    return isBytes(a) && isBytes(b) && a.length === b.length && Buffer.from(a).equals(Buffer.from(b));
  }

  /** Make the authoritative engine equal to the committed candidate state. */
  async function install(chosen) {
    generation += 1;
    if (chosen.outcome !== 'application') return;
    try {
      if (hooks.beforeReapply) await hooks.beforeReapply();
      const session = authoritativeSession(chosen.sender)
        ?? engine.loadSession(chosen.sender, chosen.groupId, { expectedPeer: chosen.sender });
      const opened = session.decrypt(chosen.ciphertext);
      if (sameBytes(opened.plaintext, chosen.plaintext) && sameProviderState(engine.serializeState(), chosen.stateBytes)) return;
    } catch {
      // fall through to the swap below
    }
    // The re-applied state differs: the committed bytes are authoritative.
    swaps += 1;
    try {
      if (hooks.beforeSwap) await hooks.beforeSwap();
      engine = await restoreEngine(chosen.stateBytes);
    } catch {
      // The archive holds the commit but no engine equals it: stop every later call until a new load.
      poisoned = true;
    }
  }

  async function commitUnit(argument) {
    if (!usable()) return code(FAILED);
    if (argument === null || typeof argument !== 'object' || !HEX32.test(argument.operationId)) return code(FAILED);
    const { eventId, ticket, result } = argument;
    const entry = state.pending.find((item) => item.eventId === eventId);
    if (entry === undefined || candidate === null || candidate.ticket !== ticket || result === null || typeof result !== 'object') {
      return code(FAILED); // another ticket's candidate is left as it is
    }
    let chosen = candidate;
    candidate = null;
    if (chosen.sender !== entry.sender || !sameBytes(chosen.ciphertext, entry.ciphertext)) return code(FAILED);
    if (chosen.generation !== generation) {
      // A provider mutation happened after the candidate was made: open again
      // on the current authoritative state so that no mutation is lost.
      const again = await classify(entry.sender, entry.ciphertext);
      if (again.outcome !== chosen.outcome
        || (again.outcome === 'application' && !sameBytes(again.plaintext, chosen.plaintext))) {
        return code(FAILED);
      }
      chosen = { ...chosen, ...again };
    }
    if (chosen.outcome === 'application') {
      if (result.type !== 'application' || result.sender !== entry.sender || result.receiptDue !== entry.receiptRequested
        || !sameBytes(result.payload, chosen.plaintext)) {
        return code(FAILED);
      }
    } else if (result.type !== 'rejected' || Object.keys(result).length !== 1) {
      return code(FAILED);
    }
    const written = await withFile(async () => {
      const refused = writeGate(argument);
      if (refused !== null) return refused;
      if (deadOperations.has(argument.operationId)) return code(FAILED);
      const index = state.pending.findIndex((item) => item.eventId === eventId);
      if (index < 0) return code(FAILED);
      const resolution = chosen.outcome === 'application'
        ? { type: 'application', sender: entry.sender, receiptDue: entry.receiptRequested, payload: copy(chosen.plaintext) }
        : { type: 'rejected' };
      const next = withState({ revision: state.revision + 1, lastCommit: { operationId: argument.operationId, eventId, result: resolution } });
      next.pending.splice(index, 1);
      if (chosen.outcome === 'application') {
        next.ready.push({ eventId, sender: entry.sender, receiptDue: entry.receiptRequested, payload: copy(chosen.plaintext) });
        if (entry.receiptRequested) next.receiptsDue.push({ eventId, sender: entry.sender });
        next.mlsState = chosen.stateBytes;
        next.bindings = next.bindings.map((item) => (item.peer === entry.sender && item.groupId === null
          ? { peer: item.peer, groupId: chosen.groupId, bindingValue: null } : item));
      }
      if (storedBytesOf(next) > maxStoredBytes) return code(CAPACITY);
      const outcome = await persist(next, 'commit');
      if (outcome === 'failed') return code(FAILED);
      if (outcome === 'uncertain') throw new UncertainWriteError('commit: outcome unknown');
      return successOf(state);
    });
    if (written.code === undefined) {
      await install(chosen);
      if (poisoned) throw new UncertainWriteError('commit: written, but the authoritative engine could not be installed');
    }
    return written;
  }

  async function resolveUnit(argument) {
    if (argument === null || typeof argument !== 'object' || !HEX32.test(argument.operationId)) return code(FAILED);
    if (state === null || poisoned) return code(FAILED);
    const last = state.lastCommit;
    if (last !== null && last.operationId === argument.operationId) {
      const result = last.result.type === 'application'
        ? Object.freeze({ type: 'application', sender: last.result.sender, payload: copy(last.result.payload), receiptDue: last.result.receiptDue })
        : Object.freeze({ type: 'rejected' });
      return Object.freeze({ status: 'committed', revision: state.revision, storedBytes: storedBytesOf(state), result });
    }
    // Not the last durable commit: it never took effect, and from now on it
    // never can (a late call with this id is refused).
    deadOperations.add(argument.operationId); // kept for the rest of the run, never evicted
    return Object.freeze({ status: 'aborted', revision: state.revision, storedBytes: storedBytesOf(state) });
  }

  /* --- session: provider mutations --------------------------------------- */

  function requireUsable() {
    if (!usable()) throw new Error('reference receiver not usable (not loaded, or a write outcome is unknown)');
  }

  async function sealUnit(argument) {
    requireUsable();
    if (argument === null || typeof argument !== 'object' || !HEX64.test(argument.recipient)
      || !isBytes(argument.plaintext) || argument.plaintext.length === 0) {
      throw new TypeError('seal: malformed argument');
    }
    const session = authoritativeSession(argument.recipient);
    if (session === null) {
      throw new Error('seal: no usable session for this peer (an invitee binding completes with the first inbound message)');
    }
    const ciphertext = session.encrypt(copy(argument.plaintext));
    const written = await checkpoint(() => ({}), 'seal');
    if (written !== 'ok') throw new Error('seal: the MLS checkpoint was not written');
    return Object.freeze({ ciphertext });
  }

  async function createKeyPackageUnit() {
    requireUsable();
    const bytes = engine.keyPackageBytes();
    const written = await checkpoint(() => ({}), 'createKeyPackage');
    if (written !== 'ok') throw new Error('createKeyPackage: the MLS checkpoint was not written');
    return bytes;
  }

  async function startSessionUnit(argument) {
    requireUsable();
    const { peer, keyPackage } = argument ?? {};
    if (!HEX64.test(peer) || peer === identity || !isBytes(keyPackage)) throw new TypeError('startSession: malformed argument');
    if (binding(peer) !== null || engine.session(peer) !== undefined) throw new Error('startSession: a session for this peer exists');
    // The credential is checked on a throwaway engine first, so a refused
    // KeyPackage leaves no group behind in the authoritative provider.
    const probe = await MlsEngine.create({ name: identity });
    probe.startSession(peer, keyPackage, { expectedPeer: peer });
    const started = engine.startSession(peer, keyPackage, { expectedPeer: peer });
    const added = { peer, groupId: started.groupId, bindingValue: null };
    const written = await checkpoint((current) => ({ bindings: current.bindings.concat([added]) }), 'startSession');
    if (written !== 'ok') {
      engine.removeSession(peer);
      throw new Error('startSession: the MLS checkpoint was not written');
    }
    return Object.freeze({ welcome: started.welcome, ratchetTree: started.ratchetTree });
  }

  async function joinSessionUnit(argument) {
    requireUsable();
    const { peer, welcome, ratchetTree } = argument ?? {};
    if (!HEX64.test(peer) || peer === identity || !isBytes(welcome) || !isBytes(ratchetTree)) {
      throw new TypeError('joinSession: malformed argument');
    }
    if (binding(peer) !== null || engine.session(peer) !== undefined) throw new Error('joinSession: a session for this peer exists');
    // Membership is checked on a copy first; the authoritative engine joins
    // only a Welcome that the copy accepted.
    const probe = await restoreEngine(engine.serializeState());
    probe.joinSession(peer, welcome, ratchetTree, { expectedPeer: peer });
    const session = engine.joinSession(peer, welcome, ratchetTree, { expectedPeer: peer });
    let bindingValue;
    try {
      bindingValue = copy(session.exportSecret(BINDING_LABEL, utf8.encode(peer), BINDING_LENGTH));
    } catch (error) {
      engine.removeSession(peer);
      throw error;
    }
    if (bindingValue.length !== BINDING_LENGTH) {
      engine.removeSession(peer);
      throw new Error('joinSession: unexpected binding value length');
    }
    const added = { peer, groupId: null, bindingValue };
    const written = await checkpoint((current) => ({ bindings: current.bindings.concat([added]) }), 'joinSession');
    if (written !== 'ok') {
      engine.removeSession(peer);
      throw new Error('joinSession: the MLS checkpoint was not written');
    }
    return true;
  }

  /* --- the ports ---------------------------------------------------------- */

  const receiveState = Object.freeze({
    load: (argument) => withProvider(() => withFile(() => loadUnit(argument))),
    stage: (argument) => withFile(() => stageUnit(argument)),
    commit: (argument) => withProvider(() => commitUnit(argument)),
    ack: (argument) => withFile(() => ackUnit(argument)),
    receiptDone: (argument) => withFile(() => receiptDoneUnit(argument)),
    commitCursor: (argument) => withFile(() => commitCursorUnit(argument)),
    resolve: (argument) => withProvider(() => withFile(() => resolveUnit(argument))),
  });

  const session = Object.freeze({
    seal: (argument) => withProvider(() => sealUnit(argument)),
    open: () => {
      throw new Error('open: the reference receiver is used only with ports.receiveState (openCandidate)');
    },
    openCandidate: (argument) => withProvider(() => openCandidateUnit(argument)),
    // Reads only the durable binding manifest: no lock is needed.
    isKnownSender: async (argument) => {
      requireUsable();
      if (argument === null || typeof argument !== 'object' || !HEX64.test(argument.sender)) {
        throw new TypeError('isKnownSender: malformed argument');
      }
      return binding(argument.sender) !== null;
    },
    createKeyPackage: () => withProvider(() => createKeyPackageUnit()),
    startSession: (argument) => withProvider(() => startSessionUnit(argument)),
    joinSession: (argument) => withProvider(() => joinSessionUnit(argument)),
  });

  /** Read-only diagnostics for tests and the crash oracle. */
  function inspect() {
    return {
      loaded: state !== null, poisoned, generation, writes, swaps, loadedResolution: loadedResolution !== null,
      revision: state === null ? null : state.revision,
      bindings: state === null ? [] : state.bindings.map((entry) => ({ peer: entry.peer, groupId: entry.groupId })),
      pending: state === null ? [] : state.pending.map((entry) => entry.eventId),
      ready: state === null ? [] : state.ready.map((entry) => entry.eventId),
      acknowledged: state === null ? [] : state.acknowledged.slice(),
      receiptsDue: state === null ? [] : state.receiptsDue.map((entry) => entry.eventId),
      engine,
    };
  }

  return { receiveState, session, inspect };
}
