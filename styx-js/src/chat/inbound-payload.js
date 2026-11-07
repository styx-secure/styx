// styx-js/src/chat/inbound-payload.js
// Validation of the typed chat payloads a peer sends inside MLS, and of the
// chat records restored from local storage.
//
// A payload is authenticated (it decrypted under the peer's MLS session) but its
// content is still chosen by the peer. Every field that is stored or rendered is
// checked for type and bound here, before anything is saved: a frame that fails
// is discarded and counted, and never reaches the message store, the roster or
// the UI. The same predicates neutralise records that an older version stored
// without these checks.

/** Largest message id accepted (a UUID has 36 characters). */
export const MAX_MESSAGE_ID_LENGTH = 128;
/** Largest message text accepted, in UTF-16 code units. */
export const MAX_MESSAGE_TEXT_LENGTH = 65_536;
/** Smallest accepted timestamp, in milliseconds since the epoch. */
export const MIN_MESSAGE_TS = 1;
/** Largest accepted timestamp: the end of the ECMAScript Date range. */
export const MAX_MESSAGE_TS = 8_640_000_000_000_000;

/** Reasons an inbound payload is discarded; each has its own counter. */
export const INBOUND_DISCARD_REASONS = Object.freeze([
  'malformed-payload',
  'unknown-type',
  'invalid-id',
  'invalid-text',
  'invalid-ts',
  'invalid-receipt',
  'invalid-intro',
]);

const RECEIPT_KINDS = new Set(['delivered', 'read']);

/**
 * Own data property of a plain object, read without invoking getters, or
 * undefined. Arrays and objects with another prototype yield undefined.
 * @param {unknown} value
 * @param {string} key
 * @returns {unknown}
 */
export function ownDataProperty(value, key) {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) return undefined;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined;
  } catch {
    return undefined;
  }
}

/** True for a plain (non-array) object whose prototype is Object.prototype or null. */
export function isPlainObject(value) {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
    const proto = Object.getPrototypeOf(value);
    return proto === Object.prototype || proto === null;
  } catch {
    return false;
  }
}

/** A timestamp the chat stores: a safe integer in [MIN_MESSAGE_TS, MAX_MESSAGE_TS]. */
export function isValidMessageTs(ts) {
  return Number.isSafeInteger(ts) && ts >= MIN_MESSAGE_TS && ts <= MAX_MESSAGE_TS;
}

/** A message id the chat stores: a non-empty string of at most MAX_MESSAGE_ID_LENGTH. */
export function isValidMessageId(id) {
  return typeof id === 'string' && id.length > 0 && id.length <= MAX_MESSAGE_ID_LENGTH;
}

/** A message text the chat stores: a string of at most MAX_MESSAGE_TEXT_LENGTH. */
export function isValidMessageText(text) {
  return typeof text === 'string' && text.length <= MAX_MESSAGE_TEXT_LENGTH;
}

/**
 * Classify one decoded inbound payload.
 * @param {unknown} payload the JSON value decoded from the MLS plaintext
 * @returns {{kind:'msg', id:string, text:string, ts:number}
 *   | {kind:'intro', alias:string}
 *   | {kind:'receipt', ref:string, receipt:'delivered'|'read'}
 *   | {kind:'discard', reason:string}}
 */
export function classifyInboundPayload(payload) {
  if (!isPlainObject(payload)) return { kind: 'discard', reason: 'malformed-payload' };
  const type = ownDataProperty(payload, 't');

  if (type === 'intro') {
    const alias = ownDataProperty(payload, 'alias');
    if (typeof alias !== 'string') return { kind: 'discard', reason: 'invalid-intro' };
    return { kind: 'intro', alias };
  }

  if (type === 'receipt') {
    const ref = ownDataProperty(payload, 'ref');
    const receipt = ownDataProperty(payload, 'kind');
    if (!isValidMessageId(ref) || !RECEIPT_KINDS.has(receipt)) {
      return { kind: 'discard', reason: 'invalid-receipt' };
    }
    return { kind: 'receipt', ref, receipt };
  }

  if (type !== 'msg') return { kind: 'discard', reason: 'unknown-type' };
  const id = ownDataProperty(payload, 'id');
  if (!isValidMessageId(id)) return { kind: 'discard', reason: 'invalid-id' };
  const text = ownDataProperty(payload, 'text');
  if (!isValidMessageText(text)) return { kind: 'discard', reason: 'invalid-text' };
  const ts = ownDataProperty(payload, 'ts');
  if (!isValidMessageTs(ts)) return { kind: 'discard', reason: 'invalid-ts' };
  return { kind: 'msg', id, text, ts };
}

/**
 * A stored chat message as restored from local storage, or null when it cannot
 * be shown safely: id not a non-empty string, text not a string, ts outside the
 * accepted range, or contact/direction missing. Lengths are not re-checked here
 * so that history written by this device before the bounds existed survives.
 * Only the fields the chat writes are kept.
 * @param {unknown} raw
 * @returns {object|null}
 */
export function normalizeStoredMessage(raw) {
  if (!isPlainObject(raw)) return null;
  const id = ownDataProperty(raw, 'id');
  const text = ownDataProperty(raw, 'text');
  const ts = ownDataProperty(raw, 'ts');
  const contactPubkey = ownDataProperty(raw, 'contactPubkey');
  const direction = ownDataProperty(raw, 'direction');
  const state = ownDataProperty(raw, 'state');
  if (typeof id !== 'string' || id.length === 0) return null;
  if (typeof text !== 'string' || !isValidMessageTs(ts)) return null;
  if (typeof contactPubkey !== 'string' || (direction !== 'in' && direction !== 'out')) return null;
  return {
    id,
    contactPubkey,
    direction,
    text,
    ts,
    state: typeof state === 'string' ? state : null,
  };
}

/**
 * Clean a stored message-history snapshot ({ contactPubkey: message[] }) before
 * it is loaded: every message that normalizeStoredMessage refuses, or that is
 * filed under another contact, is dropped. Absent or malformed snapshots load as
 * an empty history, as an absent one always has.
 * @param {unknown} snapshot
 * @returns {{messages: Record<string, object[]>, dropped: number}}
 */
export function normalizeStoredMessages(snapshot) {
  const messages = {};
  let dropped = 0;
  if (!isPlainObject(snapshot)) return { messages, dropped };
  for (const key of Object.keys(snapshot)) {
    const list = ownDataProperty(snapshot, key);
    if (!Array.isArray(list)) continue;
    const kept = [];
    for (const raw of list) {
      const msg = normalizeStoredMessage(raw);
      if (msg && msg.contactPubkey === key) kept.push(msg);
      else dropped += 1;
    }
    if (kept.length) messages[key] = kept;
  }
  return { messages, dropped };
}
