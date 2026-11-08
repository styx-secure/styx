// Experimental Node reference implementation of the M3-RECEIVE receive-state
// port: the encrypted snapshot format (owner technical gate G1/G2 of
// M3-RECEIVE-2). Not imported by the SDK lane.
//
// One authoritative file holds the whole state. Its bytes are
//
//   header  = MAGIC (8) || formatVersion (u16) || salt (32) || nonce (12) || bodyLength (u64)
//   payload = AES-256-GCM(subkey, nonce, aad, body) || tag (16)
//
// with subkey = HKDF-SHA256(atRestKey, salt, SUBKEY_INFO, 32) and
// aad = lp(AAD_LABEL) || lp(header) || lp(identity) || lp(scope), where lp()
// is a u32 big-endian length prefix. A fresh random salt (and so a fresh
// subkey) and a fresh random nonce are drawn for every rewrite, so each
// subkey encrypts exactly one body. The body is the canonical binary encoding
// below; every length is checked against the remaining bytes and its own
// bound before any allocation, and trailing bytes are refused.
import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto';

export const MAGIC = Uint8Array.from([0x53, 0x54, 0x59, 0x58, 0x52, 0x43, 0x56, 0x31]); // "STYXRCV1"
export const FORMAT_VERSION = 1;
export const BODY_VERSION = 1;
export const HEADER_LENGTH = 8 + 2 + 32 + 12 + 8;
export const TAG_LENGTH = 16;
export const SUBKEY_INFO = 'styx/m3-receive/reference-snapshot-key/v1';
export const AAD_LABEL = 'styx/m3-receive/reference-snapshot/v1';
export const SCHEMA = 'styx-m3-receive-state/v1';
export const SCOPE = 'styx-m3-delivery/4741/wire-0.3.0';

/** Bounds checked before allocation (bytes unless stated). */
export const BOUNDS = Object.freeze({
  /** Largest ciphertext an inbound kind-4741 event can carry (C-DLV §3: 349 528 base64 characters). */
  ciphertext: 262_146,
  /** A plaintext never exceeds its ciphertext. */
  payload: 262_146,
  relay: 2_048,
  groupId: 255,
  mlsIdentityKey: 1_024,
  mlsState: 1_073_741_824,
  records: 16_777_216,
  cursors: 16,
  bindings: 1_048_576,
});

const HEX64 = /^[0-9a-f]{64}$/;
const HEX32 = /^[0-9a-f]{32}$/;

/** The error of a snapshot that cannot be read: maps to E_SDK_RECEIVE_STATE_INCOMPATIBLE. */
export class SnapshotFormatError extends Error {
  constructor(message) {
    super(message);
    this.name = 'SnapshotFormatError';
  }
}

const utf8 = new TextEncoder();
const strictUtf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

function lp(bytes) {
  const out = new Uint8Array(4 + bytes.length);
  new DataView(out.buffer).setUint32(0, bytes.length);
  out.set(bytes, 4);
  return out;
}

function concat(parts) {
  let length = 0;
  for (const part of parts) length += part.length;
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function aadFor(header, identity, scope) {
  return concat([lp(utf8.encode(AAD_LABEL)), lp(header), lp(utf8.encode(identity)), lp(utf8.encode(scope))]);
}

export function subkeyFor(atRestKey, salt) {
  return new Uint8Array(hkdfSync('sha256', atRestKey, salt, utf8.encode(SUBKEY_INFO), 32));
}

/* --- body writer --------------------------------------------------------- */

class Writer {
  constructor() {
    this.parts = [];
  }

  u8(value) {
    this.parts.push(Uint8Array.of(value));
  }

  u32(value) {
    const out = new Uint8Array(4);
    new DataView(out.buffer).setUint32(0, value);
    this.parts.push(out);
  }

  u64(value) {
    if (!Number.isSafeInteger(value) || value < 0) throw new RangeError('u64 out of range');
    const out = new Uint8Array(8);
    const view = new DataView(out.buffer);
    view.setUint32(0, Math.floor(value / 0x1_0000_0000));
    view.setUint32(4, value % 0x1_0000_0000);
    this.parts.push(out);
  }

  bytes(value) {
    this.u32(value.length);
    this.parts.push(value);
  }

  text(value) {
    this.bytes(utf8.encode(value));
  }

  hex(value, length) {
    const out = new Uint8Array(length);
    for (let i = 0; i < length; i += 1) out[i] = parseInt(value.slice(2 * i, 2 * i + 2), 16);
    this.parts.push(out);
  }

  finish() {
    return concat(this.parts);
  }
}

/* --- body reader --------------------------------------------------------- */

class Reader {
  constructor(bytes) {
    this.bytes = bytes;
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    this.offset = 0;
  }

  need(length) {
    if (!Number.isSafeInteger(length) || length < 0 || length > this.bytes.length - this.offset) {
      throw new SnapshotFormatError('truncated or oversized field');
    }
  }

  u8() {
    this.need(1);
    const value = this.bytes[this.offset];
    this.offset += 1;
    return value;
  }

  bool() {
    const value = this.u8();
    if (value > 1) throw new SnapshotFormatError('invalid flag');
    return value === 1;
  }

  u32() {
    this.need(4);
    const value = this.view.getUint32(this.offset);
    this.offset += 4;
    return value;
  }

  u64() {
    this.need(8);
    const high = this.view.getUint32(this.offset);
    const low = this.view.getUint32(this.offset + 4);
    this.offset += 8;
    const value = high * 0x1_0000_0000 + low;
    if (!Number.isSafeInteger(value)) throw new SnapshotFormatError('integer out of range');
    return value;
  }

  count(bound) {
    const value = this.u32();
    if (value > bound) throw new SnapshotFormatError('count over its bound');
    return value;
  }

  bytesField(bound, { nonEmpty = false } = {}) {
    const length = this.u32();
    if (length > bound || (nonEmpty && length === 0)) throw new SnapshotFormatError('byte field over its bound');
    this.need(length);
    const out = this.bytes.slice(this.offset, this.offset + length);
    this.offset += length;
    return out;
  }

  text(bound) {
    const raw = this.bytesField(bound);
    let value;
    try {
      value = strictUtf8.decode(raw);
    } catch {
      throw new SnapshotFormatError('invalid UTF-8');
    }
    const again = utf8.encode(value);
    if (again.length !== raw.length || again.some((byte, i) => byte !== raw[i])) {
      throw new SnapshotFormatError('non-canonical UTF-8');
    }
    return value;
  }

  hex(length) {
    this.need(length);
    let out = '';
    for (let i = 0; i < length; i += 1) out += this.bytes[this.offset + i].toString(16).padStart(2, '0');
    this.offset += length;
    return out;
  }

  done() {
    if (this.offset !== this.bytes.length) throw new SnapshotFormatError('trailing bytes');
  }
}

/* --- the state ----------------------------------------------------------- */

/**
 * The logical size of the active state (C-SDK §8.5 `storedBytes`), a fixed
 * formula independent of the physical file: 65 bytes plus the ciphertext per
 * PENDING entry, 65 plus the payload per READY entry, 32 per seen and per
 * acknowledged id, 64 per receipt obligation, the relay length plus 8 per
 * cursor, the MLS checkpoint length, and 96 plus the group id length per peer
 * binding.
 */
export function storedBytesOf(state) {
  let total = state.mlsState.length;
  for (const entry of state.pending) total += 65 + entry.ciphertext.length;
  for (const entry of state.ready) total += 65 + entry.payload.length;
  total += 32 * state.seen.length + 32 * state.acknowledged.length + 64 * state.receiptsDue.length;
  for (const cursor of state.cursors) total += utf8.encode(cursor.relay).length + 8;
  for (const binding of state.bindings) total += 96 + (binding.groupId === null ? 0 : utf8.encode(binding.groupId).length);
  return total;
}

/** The empty state of a new archive. */
export function emptyState({ identity, mlsState, mlsIdentityKey }) {
  return {
    identity, scope: SCOPE, revision: 0, mlsState, mlsIdentityKey,
    bindings: [], cursors: [], seen: [], pending: [], ready: [], acknowledged: [], receiptsDue: [], lastCommit: null,
  };
}

/** Structural invariants shared by encoding and decoding (throws SnapshotFormatError). */
export function checkState(state) {
  const fail = (message) => { throw new SnapshotFormatError(message); };
  if (!HEX64.test(state.identity) || state.scope !== SCOPE) fail('identity or scope');
  if (!Number.isSafeInteger(state.revision) || state.revision < 0) fail('revision');
  const seen = new Set(state.seen);
  if (seen.size !== state.seen.length) fail('duplicate seen id');
  const owned = new Set();
  const own = (id) => {
    if (!seen.has(id) || owned.has(id)) fail('pending, ready and acknowledged must be disjoint subsets of seen');
    owned.add(id);
  };
  for (const entry of state.pending) own(entry.eventId);
  const readyById = new Map();
  for (const entry of state.ready) {
    own(entry.eventId);
    readyById.set(entry.eventId, entry);
  }
  const acknowledged = new Set();
  for (const id of state.acknowledged) {
    own(id);
    acknowledged.add(id);
  }
  const due = new Set();
  for (const entry of state.receiptsDue) {
    if (due.has(entry.eventId)) fail('duplicate receipt obligation');
    due.add(entry.eventId);
    const ready = readyById.get(entry.eventId);
    const ok = (ready !== undefined && ready.receiptDue && ready.sender === entry.sender) || acknowledged.has(entry.eventId);
    if (!ok) fail('receipt obligation without its entry');
  }
  const relays = new Set();
  for (const cursor of state.cursors) {
    if (relays.has(cursor.relay)) fail('duplicate cursor');
    relays.add(cursor.relay);
  }
  const peers = new Set();
  const groups = new Set();
  for (const binding of state.bindings) {
    if (!HEX64.test(binding.peer) || peers.has(binding.peer) || binding.peer === state.identity) fail('peer binding');
    peers.add(binding.peer);
    if (binding.groupId === null) {
      if (!(binding.bindingValue instanceof Uint8Array) || binding.bindingValue.length !== 32) fail('invitee binding');
    } else {
      if (binding.bindingValue !== null || groups.has(binding.groupId)) fail('established binding');
      groups.add(binding.groupId);
    }
  }
  if (state.lastCommit !== null) {
    const last = state.lastCommit;
    if (!HEX32.test(last.operationId) || !seen.has(last.eventId)) fail('last commit');
    if (state.pending.some((entry) => entry.eventId === last.eventId)) fail('last commit still pending');
  }
}

export function encodeBody(state) {
  checkState(state);
  const w = new Writer();
  w.u32(BODY_VERSION);
  w.text(state.identity);
  w.text(state.scope);
  w.u64(state.revision);
  w.bytes(state.mlsIdentityKey);
  w.bytes(state.mlsState);
  w.u32(state.bindings.length);
  for (const binding of state.bindings) {
    w.hex(binding.peer, 32);
    if (binding.groupId === null) {
      w.u8(2);
      w.parts.push(binding.bindingValue);
    } else {
      w.u8(1);
      w.text(binding.groupId);
    }
  }
  w.u32(state.cursors.length);
  for (const cursor of state.cursors) {
    w.text(cursor.relay);
    w.u64(cursor.syncedUntil);
  }
  w.u32(state.seen.length);
  for (const id of state.seen) w.hex(id, 32);
  w.u32(state.pending.length);
  for (const entry of state.pending) {
    w.hex(entry.eventId, 32);
    w.hex(entry.sender, 32);
    w.u8(entry.receiptRequested ? 1 : 0);
    w.bytes(entry.ciphertext);
  }
  w.u32(state.ready.length);
  for (const entry of state.ready) {
    w.hex(entry.eventId, 32);
    w.hex(entry.sender, 32);
    w.u8(entry.receiptDue ? 1 : 0);
    w.bytes(entry.payload);
  }
  w.u32(state.acknowledged.length);
  for (const id of state.acknowledged) w.hex(id, 32);
  w.u32(state.receiptsDue.length);
  for (const entry of state.receiptsDue) {
    w.hex(entry.eventId, 32);
    w.hex(entry.sender, 32);
  }
  if (state.lastCommit === null) {
    w.u8(0);
  } else {
    w.u8(1);
    w.hex(state.lastCommit.operationId, 16);
    w.hex(state.lastCommit.eventId, 32);
  }
  return w.finish();
}

export function decodeBody(bytes) {
  const r = new Reader(bytes);
  if (r.u32() !== BODY_VERSION) throw new SnapshotFormatError('unknown body version');
  const state = {};
  state.identity = r.text(64);
  state.scope = r.text(64);
  state.revision = r.u64();
  state.mlsIdentityKey = r.bytesField(BOUNDS.mlsIdentityKey, { nonEmpty: true });
  state.mlsState = r.bytesField(BOUNDS.mlsState, { nonEmpty: true });
  const bindings = r.count(BOUNDS.bindings);
  state.bindings = [];
  for (let i = 0; i < bindings; i += 1) {
    const peer = r.hex(32);
    const kind = r.u8();
    if (kind === 1) state.bindings.push({ peer, groupId: r.text(BOUNDS.groupId), bindingValue: null });
    else if (kind === 2) {
      r.need(32);
      const bindingValue = bytes.slice(r.offset, r.offset + 32);
      r.offset += 32;
      state.bindings.push({ peer, groupId: null, bindingValue });
    } else throw new SnapshotFormatError('unknown binding kind');
  }
  const cursors = r.count(BOUNDS.cursors);
  state.cursors = [];
  for (let i = 0; i < cursors; i += 1) state.cursors.push({ relay: r.text(BOUNDS.relay), syncedUntil: r.u64() });
  const seen = r.count(BOUNDS.records);
  r.need(32 * seen);
  state.seen = [];
  for (let i = 0; i < seen; i += 1) state.seen.push(r.hex(32));
  const pending = r.count(BOUNDS.records);
  state.pending = [];
  for (let i = 0; i < pending; i += 1) {
    const eventId = r.hex(32);
    const sender = r.hex(32);
    const receiptRequested = r.bool();
    state.pending.push({ eventId, sender, receiptRequested, ciphertext: r.bytesField(BOUNDS.ciphertext, { nonEmpty: true }) });
  }
  const ready = r.count(BOUNDS.records);
  state.ready = [];
  for (let i = 0; i < ready; i += 1) {
    const eventId = r.hex(32);
    const sender = r.hex(32);
    const receiptDue = r.bool();
    state.ready.push({ eventId, sender, receiptDue, payload: r.bytesField(BOUNDS.payload) });
  }
  const acknowledged = r.count(BOUNDS.records);
  r.need(32 * acknowledged);
  state.acknowledged = [];
  for (let i = 0; i < acknowledged; i += 1) state.acknowledged.push(r.hex(32));
  const due = r.count(BOUNDS.records);
  r.need(64 * due);
  state.receiptsDue = [];
  for (let i = 0; i < due; i += 1) state.receiptsDue.push({ eventId: r.hex(32), sender: r.hex(32) });
  const hasLast = r.u8();
  if (hasLast === 0) state.lastCommit = null;
  else if (hasLast === 1) state.lastCommit = { operationId: r.hex(16), eventId: r.hex(32) };
  else throw new SnapshotFormatError('invalid last-commit flag');
  r.done();
  checkState(state);
  return state;
}

/* --- the file ------------------------------------------------------------ */

function headerBytes(salt, nonce, bodyLength) {
  const header = new Uint8Array(HEADER_LENGTH);
  const view = new DataView(header.buffer);
  header.set(MAGIC, 0);
  view.setUint16(8, FORMAT_VERSION);
  header.set(salt, 10);
  header.set(nonce, 42);
  view.setUint32(54, Math.floor(bodyLength / 0x1_0000_0000));
  view.setUint32(58, bodyLength % 0x1_0000_0000);
  return header;
}

/**
 * Encrypt a state into the bytes of one snapshot file. The plaintext body is
 * zeroed after use (best effort: JavaScript gives no erasure guarantee).
 */
export function sealSnapshot(state, atRestKey) {
  const body = encodeBody(state);
  const salt = new Uint8Array(randomBytes(32));
  const nonce = new Uint8Array(randomBytes(12));
  const header = headerBytes(salt, nonce, body.length);
  const subkey = subkeyFor(atRestKey, salt);
  try {
    const cipher = createCipheriv('aes-256-gcm', subkey, nonce, { authTagLength: TAG_LENGTH });
    cipher.setAAD(aadFor(header, state.identity, state.scope));
    const encrypted = cipher.update(body);
    const final = cipher.final();
    const tag = cipher.getAuthTag();
    return concat([header, encrypted, final, tag]);
  } finally {
    body.fill(0);
    subkey.fill(0);
  }
}

/**
 * Decrypt and decode the bytes of one snapshot file for `identity`. Every
 * failure — wrong magic, version or length, a wrong key, a modified byte, a
 * malformed body or a broken invariant — is a SnapshotFormatError. The tag is
 * verified before the body is parsed.
 */
export function openSnapshot(fileBytes, atRestKey, identity, maxBodyLength) {
  if (!(fileBytes instanceof Uint8Array) || fileBytes.length < HEADER_LENGTH + TAG_LENGTH) {
    throw new SnapshotFormatError('snapshot too short');
  }
  const header = fileBytes.subarray(0, HEADER_LENGTH);
  for (let i = 0; i < MAGIC.length; i += 1) if (header[i] !== MAGIC[i]) throw new SnapshotFormatError('not a snapshot');
  const view = new DataView(header.buffer, header.byteOffset, header.byteLength);
  if (view.getUint16(8) !== FORMAT_VERSION) throw new SnapshotFormatError('unknown format version');
  const bodyLength = view.getUint32(54) * 0x1_0000_0000 + view.getUint32(58);
  if (!Number.isSafeInteger(bodyLength) || bodyLength > maxBodyLength
    || fileBytes.length !== HEADER_LENGTH + bodyLength + TAG_LENGTH) {
    throw new SnapshotFormatError('snapshot length');
  }
  const salt = header.slice(10, 42);
  const nonce = header.slice(42, 54);
  const subkey = subkeyFor(atRestKey, salt);
  let body;
  try {
    const decipher = createDecipheriv('aes-256-gcm', subkey, nonce, { authTagLength: TAG_LENGTH });
    decipher.setAAD(aadFor(header, identity, SCOPE));
    decipher.setAuthTag(fileBytes.subarray(HEADER_LENGTH + bodyLength));
    const part = decipher.update(fileBytes.subarray(HEADER_LENGTH, HEADER_LENGTH + bodyLength));
    const final = decipher.final(); // throws on a wrong key or any modified byte
    body = new Uint8Array(part.length + final.length);
    body.set(part, 0);
    body.set(final, part.length);
    part.fill(0);
  } catch (error) {
    if (error instanceof SnapshotFormatError) throw error;
    throw new SnapshotFormatError('snapshot not authentic under this key');
  } finally {
    subkey.fill(0);
  }
  try {
    const state = decodeBody(body);
    if (state.identity !== identity) throw new SnapshotFormatError('identity');
    return state;
  } finally {
    body.fill(0);
  }
}
