/**
 * The early-lane SDK client (card I-SDK): the assembly of the delivery layer
 * behind the public interface of C-SDK (docs/architecture/m3/sdk-interface.md).
 *
 * The four lane modules keep every delivery rule: `outbox.js` the item
 * lifecycle of C-DLV section 4, `relay-pool.js` the relays of C-DLV section 5,
 * `receipts.js` the inbound side of C-DLV sections 6.1, 6.3, 7 and 8, and
 * `retry.js` the schedule of C-DLV section 4.3. This module builds them,
 * connects their seams, owns the client state machine of C-SDK section 4.2,
 * validates the configuration of C-SDK section 4.1, dispatches the events of
 * C-SDK section 7 and fails closed on any value outside the closed sets of
 * C-SDK section 5.3. It adds no bound, state, code, event kind, port method,
 * transition or ordering rule.
 *
 * Consumers import `index.js`, never this file.
 */

import { createOutbox } from './delivery/outbox.js';
import { createReceipts } from './delivery/receipts.js';
import { createRelaySet } from './delivery/relay-pool.js';
import { retryDelayMs } from './delivery/retry.js';
import { bytesToHex, randomBytes } from '../utils.js';

/* ------------------------------------------------------------------------- *
 * Public constants (C-SDK sections 3 to 7).
 * ------------------------------------------------------------------------- */

/** The interface version string of C-SDK section 3. */
export const SDK_INTERFACE_VERSION = 'styx-m3-sdk/0.1.0-experimental';

/**
 * A frozen enumeration whose members map to their own names, with prototype
 * `Object.prototype`.
 *
 * @param {string[]} names
 * @returns {Readonly<Record<string, string>>}
 */
function enumeration(names) {
  const members = {};
  for (const name of names) members[name] = name;
  return Object.freeze(members);
}

/** The closed code set of C-SDK section 5.2 (18 codes). */
export const SdkResultCode = enumeration([
  'E_SDK_UNSUPPORTED_VERSION',
  'E_SDK_INVALID_CONFIG',
  'E_SDK_INVALID_ARGUMENT',
  'E_SDK_PAYLOAD_TOO_LARGE',
  'E_SDK_NOT_STARTED',
  'E_SDK_ALREADY_STARTED',
  'E_SDK_CLIENT_STOPPED',
  'E_SDK_STORAGE_NOT_EMPTY',
  'E_SDK_NO_RELAY_AVAILABLE',
  'E_SDK_QUEUE_FULL',
  'E_SDK_UNKNOWN_DELIVERY',
  'E_SDK_DELIVERY_TERMINAL',
  'E_SDK_STORAGE_FAILED',
  'E_SDK_SESSION_FAILED',
  'E_SDK_IDENTITY_FAILED',
  'E_SDK_INBOUND_INVALID',
  'E_SDK_INTERNAL',
  'E_SDK_UNKNOWN_CODE',
]);

/** The closed delivery-state set of C-SDK section 6.1 (9 states). */
export const DeliveryState = enumeration([
  'QUEUED',
  'IN_FLIGHT',
  'RELAY_ACCEPTED_AWAITING_RECEIPT',
  'RELAY_ACCEPTED',
  'RECIPIENT_RECEIPT_RECEIVED',
  'FAILED_NOT_ACCEPTED',
  'FAILED_NO_RECEIPT',
  'CANCELLED',
  'LOST_ON_SHUTDOWN',
]);

/** The closed per-relay outcome set of C-SDK section 6.3 (5 outcomes). */
export const RelayOutcome = enumeration(['PENDING', 'ACCEPTED', 'REJECTED', 'TIMED_OUT', 'UNREACHABLE']);

/** The client states of C-SDK section 4. */
export const ClientState = enumeration(['CREATED', 'RUNNING', 'STOPPED']);

/** The closed event-kind set of C-SDK section 7 (4 kinds). */
export const SdkEventKind = enumeration([
  'CLIENT_STATE_CHANGED',
  'DELIVERY_STATE_CHANGED',
  'MESSAGE_RECEIVED',
  'INBOUND_DISCARDED',
]);

const hasOwn = (object, key) => Object.prototype.hasOwnProperty.call(object, key);

/**
 * True only for a member of `SdkResultCode`. It performs no property access on
 * `value` and no coercion of it, and never throws.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
export function isKnownResultCode(value) {
  return typeof value === 'string' && hasOwn(SdkResultCode, value);
}

/* ------------------------------------------------------------------------- *
 * Values fixed by C-SDK and C-DLV.
 * ------------------------------------------------------------------------- */

const TERMINAL_STATES = new Set([
  'RELAY_ACCEPTED',
  'RECIPIENT_RECEIPT_RECEIVED',
  'FAILED_NOT_ACCEPTED',
  'FAILED_NO_RECEIPT',
  'CANCELLED',
  'LOST_ON_SHUTDOWN',
]);
const FAILED_STATES = new Set(['FAILED_NOT_ACCEPTED', 'FAILED_NO_RECEIPT']);
const RECEIPT_MODES = new Set(['RECIPIENT_RECEIPT', 'RELAY_ACCEPTANCE_ONLY']);
/** C-SDK section 5.2: the only codes of `INBOUND_DISCARDED`. */
const DISCARD_CODES = new Set(['E_SDK_INBOUND_INVALID', 'E_SDK_SESSION_FAILED', 'E_SDK_UNKNOWN_CODE']);

/** C-DLV section 3: bounds and defaults of the delivery configuration. */
const DELIVERY_BOUNDS = Object.freeze({
  maxAttempts: Object.freeze([1, 10]),
  deadlineMs: Object.freeze([30000, 600000]),
  perRelayTimeoutMs: Object.freeze([11000, 30000]),
});
const DELIVERY_DEFAULTS = Object.freeze({
  maxAttempts: 5,
  deadlineMs: 120000,
  perRelayTimeoutMs: 12000,
  receiptMode: 'RELAY_ACCEPTANCE_ONLY',
});
/** C-DLV section 3: the payload maximum in bytes. */
const PAYLOAD_MAX_BYTES = 65536;
/** C-DLV section 3: at most 16 configured relays. */
const RELAY_COUNT_MAX = 16;
/** C-DLV sections 6.2 and 6.3: the kinds the client subscribes to. */
const SUBSCRIBED_KINDS = Object.freeze([4741, 4742]);

const PORT_METHODS = Object.freeze({
  storage: Object.freeze(['put', 'get', 'update', 'remove', 'list']),
  session: Object.freeze(['seal', 'open']),
  identity: Object.freeze(['getPublicKey', 'sign']),
});

const HEX64 = /^[0-9a-f]{64}$/;

/**
 * Codes each lane operation may return: for the internal operations their
 * module contracts, for the public ones exactly the `codes` list of their
 * C-SDK section 11 row.
 */
const CODES = Object.freeze({
  inspectStore: new Set(['E_SDK_STORAGE_FAILED', 'E_SDK_STORAGE_NOT_EMPTY', 'E_SDK_UNKNOWN_CODE', 'E_SDK_INTERNAL']),
  adoptPublicKey: new Set(['E_SDK_INVALID_ARGUMENT']),
  failClosed: new Set([
    'E_SDK_CLIENT_STOPPED', 'E_SDK_INVALID_ARGUMENT', 'E_SDK_UNKNOWN_DELIVERY',
    'E_SDK_DELIVERY_TERMINAL', 'E_SDK_INTERNAL',
  ]),
  outboxShutdown: new Set(['E_SDK_CLIENT_STOPPED', 'E_SDK_INTERNAL']),
  ingest: new Set(['E_SDK_CLIENT_STOPPED']),
  send: new Set([
    'E_SDK_NOT_STARTED', 'E_SDK_CLIENT_STOPPED', 'E_SDK_INVALID_ARGUMENT', 'E_SDK_PAYLOAD_TOO_LARGE',
    'E_SDK_QUEUE_FULL', 'E_SDK_STORAGE_FAILED', 'E_SDK_SESSION_FAILED', 'E_SDK_INTERNAL',
    'E_SDK_UNKNOWN_CODE',
  ]),
  cancel: new Set([
    'E_SDK_NOT_STARTED', 'E_SDK_CLIENT_STOPPED', 'E_SDK_INVALID_ARGUMENT', 'E_SDK_UNKNOWN_DELIVERY',
    'E_SDK_DELIVERY_TERMINAL', 'E_SDK_STORAGE_FAILED', 'E_SDK_INTERNAL', 'E_SDK_UNKNOWN_CODE',
  ]),
  getDelivery: new Set([
    'E_SDK_NOT_STARTED', 'E_SDK_INVALID_ARGUMENT', 'E_SDK_UNKNOWN_DELIVERY', 'E_SDK_STORAGE_FAILED',
    'E_SDK_INTERNAL', 'E_SDK_UNKNOWN_CODE',
  ]),
});

/** The own members of a relay attempt, as card I-RELAY fixes them. */
const ATTEMPT_MEMBERS = Object.freeze([
  'index', 'event', 'outcomes', 'publishedOnce', 'acceptedIndex', 'isSettled', 'onOutcome', 'onSettled',
  'ignoreAcks', 'acceptGate', 'latePublishGate',
]);
/** The attempt members I-RELAY fixes as accessors (never invoked by the check). */
const ATTEMPT_ACCESSORS = Object.freeze(new Set(['acceptedIndex', 'acceptGate', 'latePublishGate']));

const SNAPSHOT_FIELDS = Object.freeze([
  'deliveryId', 'recipient', 'state', 'terminal', 'attempts', 'createdAt', 'deadlineAt', 'lastCode',
  'relayOutcomes',
]);

/* ------------------------------------------------------------------------- *
 * Envelopes and closed objects.
 * ------------------------------------------------------------------------- */

const success = (value) => Object.freeze({ ok: true, value });
const failure = (code) => Object.freeze({ ok: false, code });

/**
 * A plain object: prototype `Object.prototype` or `null`, not an array.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
function isPlainObject(value) {
  if (value === null || typeof value !== 'object') return false;
  if (Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/**
 * Read a closed object: a plain object whose complete own-key set
 * (`Reflect.ownKeys`, enumerable or not, string or symbol) is exactly a subset
 * of the allowed string keys containing every required one, each read once as
 * a data value. Returns a null-prototype copy of the values, or `null`. It may
 * throw (a `Proxy` trap); callers catch.
 *
 * @param {unknown} value
 * @param {readonly string[]} required
 * @param {readonly string[]} [optional]
 * @param {Record<string, PropertyDescriptor>} [alreadyRead] descriptors the
 *   caller has read already, so that each property is read only once
 * @returns {Record<string, unknown> | null}
 */
function readClosed(value, required, optional = [], alreadyRead = null) {
  if (!isPlainObject(value)) return null;
  const keys = Reflect.ownKeys(value);
  const allowed = new Set([...required, ...optional]);
  const values = Object.create(null);
  for (const key of keys) {
    if (typeof key !== 'string' || !allowed.has(key) || hasOwn(values, key)) return null;
    const descriptor = alreadyRead !== null && hasOwn(alreadyRead, key)
      ? alreadyRead[key]
      : Reflect.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !hasOwn(descriptor, 'value')) return null;
    values[key] = descriptor.value;
  }
  for (const key of required) if (!hasOwn(values, key)) return null;
  return values;
}

/* ------------------------------------------------------------------------- *
 * Relay URL rule (C-SDK section 4.1, RFC 3986 as RFC 6455 section 3 uses it).
 * ------------------------------------------------------------------------- */

const SCHEME_SEPARATOR = ':' + '/' + '/';
const PCHAR_CLASS = "A-Za-z0-9\\-._~!$&'()*+,;=:@";
const PATH_ABEMPTY = new RegExp(`^(?:/(?:[${PCHAR_CLASS}]|%[0-9A-Fa-f]{2})*)*$`);
const QUERY = new RegExp(`^(?:[${PCHAR_CLASS}/?]|%[0-9A-Fa-f]{2})*$`);
const DEC_OCTET = /^(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/;
const H16 = /^[0-9A-Fa-f]{1,4}$/;

/**
 * The four octets of an RFC 3986 `IPv4address`, or `null`.
 *
 * @param {string} text
 * @returns {number[] | null}
 */
function ipv4Octets(text) {
  const parts = text.split('.');
  if (parts.length !== 4) return null;
  for (const part of parts) if (!DEC_OCTET.test(part)) return null;
  return parts.map((part) => Number(part));
}

/**
 * The eight 16-bit groups of an RFC 3986 `IPv6address`, or `null`.
 *
 * @param {string} text
 * @returns {number[] | null}
 */
function ipv6Groups(text) {
  let head = text;
  let tail = [];
  const lastColon = text.lastIndexOf(':');
  if (lastColon < 0) return null;
  const last = text.slice(lastColon + 1);
  if (last.includes('.')) {
    const octets = ipv4Octets(last);
    if (octets === null) return null;
    tail = [octets[0] * 256 + octets[1], octets[2] * 256 + octets[3]];
    head = text.slice(0, lastColon + 1);
    // `x:` before the IPv4 tail loses its separator; `::` keeps it.
    if (!head.endsWith('::')) head = head.slice(0, -1);
  }
  const wanted = 8 - tail.length;
  const halves = head.split('::');
  if (halves.length > 2) return null;
  const groupsOf = (part) => (part === '' ? [] : part.split(':'));
  const before = groupsOf(halves[0]);
  const after = halves.length === 2 ? groupsOf(halves[1]) : [];
  for (const group of [...before, ...after]) if (!H16.test(group)) return null;
  let groups;
  if (halves.length === 2) {
    const elided = wanted - before.length - after.length;
    if (elided < 1) return null;
    groups = [...before, ...new Array(elided).fill('0'), ...after];
  } else {
    if (before.length !== wanted) return null;
    groups = before;
  }
  return [...groups.map((group) => Number.parseInt(group, 16)), ...tail];
}

/**
 * True when `url` is an absolute `ws:` or `wss:` URL, with no userinfo and no
 * fragment, whose host is a loopback IP address literal.
 *
 * @param {unknown} url
 * @returns {boolean}
 */
function isAllowedRelayUrl(url) {
  if (typeof url !== 'string') return false;
  if (url.includes('#')) return false;
  const separator = url.indexOf(SCHEME_SEPARATOR);
  if (separator < 0) return false;
  const scheme = url.slice(0, separator).toLowerCase();
  if (scheme !== 'ws' && scheme !== 'wss') return false;
  const rest = url.slice(separator + SCHEME_SEPARATOR.length);
  let authorityEnd = rest.length;
  for (const mark of ['/', '?']) {
    const at = rest.indexOf(mark);
    if (at >= 0 && at < authorityEnd) authorityEnd = at;
  }
  const authority = rest.slice(0, authorityEnd);
  let remainder = rest.slice(authorityEnd);
  let query = null;
  const questionMark = remainder.indexOf('?');
  if (questionMark >= 0) {
    query = remainder.slice(questionMark + 1);
    remainder = remainder.slice(0, questionMark);
  }
  if (!PATH_ABEMPTY.test(remainder)) return false;
  if (query !== null && !QUERY.test(query)) return false;
  if (authority.includes('@')) return false;

  let host;
  let port;
  if (authority.startsWith('[')) {
    const close = authority.indexOf(']');
    if (close < 0) return false;
    host = authority.slice(1, close);
    port = authority.slice(close + 1);
    if (port !== '' && !/^:[0-9]*$/.test(port)) return false;
    // An IPvFuture literal and a zone identifier are rejected.
    if (/^[vV]/.test(host) || host.includes('%')) return false;
    const groups = ipv6Groups(host);
    if (groups === null || groups.length !== 8) return false;
    for (let i = 0; i < 7; i += 1) if (groups[i] !== 0) return false;
    return groups[7] === 1;
  }
  const colon = authority.indexOf(':');
  host = colon >= 0 ? authority.slice(0, colon) : authority;
  port = colon >= 0 ? authority.slice(colon) : '';
  if (port !== '' && !/^:[0-9]*$/.test(port)) return false;
  const octets = ipv4Octets(host);
  return octets !== null && octets[0] === 127;
}

/* ------------------------------------------------------------------------- *
 * Configuration (C-SDK section 4.1).
 * ------------------------------------------------------------------------- */

/**
 * Validate `config` in the order of C-SDK section 4.1. Returns
 * `{ ok: true, value }` with the private copies, or a failure envelope. It
 * never throws and calls no port, clock or random function.
 *
 * @param {unknown} config
 * @returns {object}
 */
function validateConfig(config) {
  const invalid = failure(SdkResultCode.E_SDK_INVALID_CONFIG);
  try {
    if (!isPlainObject(config)) return invalid;
    const versionDescriptor = Reflect.getOwnPropertyDescriptor(config, 'interfaceVersion');
    if (descriptorIsAccessor(versionDescriptor)) return invalid;
    if (versionDescriptor === undefined || versionDescriptor.value !== SDK_INTERFACE_VERSION) {
      return failure(SdkResultCode.E_SDK_UNSUPPORTED_VERSION);
    }
    const alreadyRead = Object.create(null);
    alreadyRead.interfaceVersion = versionDescriptor;
    const top = readClosed(
      config, ['interfaceVersion', 'relays', 'ports'], ['clock', 'random', 'delivery'], alreadyRead,
    );
    if (top === null) return invalid;

    // relays: 1 to 16 pairwise distinct strings, each an allowed relay URL.
    const relaysSource = top.relays;
    if (!Array.isArray(relaysSource)) return invalid;
    const lengthDescriptor = Reflect.getOwnPropertyDescriptor(relaysSource, 'length');
    if (lengthDescriptor === undefined || !hasOwn(lengthDescriptor, 'value')) return invalid;
    const relayCount = lengthDescriptor.value;
    if (!Number.isSafeInteger(relayCount) || relayCount < 1 || relayCount > RELAY_COUNT_MAX) return invalid;
    const relays = [];
    for (let i = 0; i < relayCount; i += 1) {
      const descriptor = Reflect.getOwnPropertyDescriptor(relaysSource, String(i));
      if (descriptor === undefined || !hasOwn(descriptor, 'value')) return invalid;
      if (!isAllowedRelayUrl(descriptor.value)) return invalid;
      if (relays.includes(descriptor.value)) return invalid;
      relays.push(descriptor.value);
    }

    // ports: a closed object over the three ports, each exposing its methods.
    const ports = readClosed(top.ports, ['storage', 'session', 'identity']);
    if (ports === null) return invalid;
    for (const name of ['storage', 'session', 'identity']) {
      const port = ports[name];
      if (port === null || (typeof port !== 'object' && typeof port !== 'function')) return invalid;
      for (const method of PORT_METHODS[name]) {
        if (!methodReadsAsFunction(port, method)) return invalid;
      }
    }

    // clock and random, when present: the caller's own objects, kept by reference.
    let clock = null;
    if (hasOwn(top, 'clock')) {
      const fields = readClosed(top.clock, ['now', 'setTimer', 'clearTimer']);
      if (fields === null) return invalid;
      for (const name of ['now', 'setTimer', 'clearTimer']) {
        if (typeof fields[name] !== 'function') return invalid;
      }
      clock = top.clock;
    }
    let random = null;
    if (hasOwn(top, 'random')) {
      const fields = readClosed(top.random, ['nextUint32']);
      if (fields === null || typeof fields.nextUint32 !== 'function') return invalid;
      random = top.random;
    }

    // delivery: a subset of the four fields, each inside its bounds.
    const delivery = { ...DELIVERY_DEFAULTS };
    if (hasOwn(top, 'delivery')) {
      const fields = readClosed(top.delivery, [], ['maxAttempts', 'deadlineMs', 'perRelayTimeoutMs', 'receiptMode']);
      if (fields === null) return invalid;
      for (const name of ['maxAttempts', 'deadlineMs', 'perRelayTimeoutMs']) {
        if (!hasOwn(fields, name)) continue;
        const value = fields[name];
        const [minimum, maximum] = DELIVERY_BOUNDS[name];
        if (!Number.isSafeInteger(value) || value < minimum || value > maximum) return invalid;
        delivery[name] = value;
      }
      if (hasOwn(fields, 'receiptMode')) {
        if (!RECEIPT_MODES.has(fields.receiptMode)) return invalid;
        delivery.receiptMode = fields.receiptMode;
      }
    }

    return success({
      relays: Object.freeze(relays),
      storage: ports.storage,
      session: ports.session,
      identity: ports.identity,
      clock,
      random,
      delivery: Object.freeze(delivery),
    });
  } catch {
    return invalid;
  }
}

/**
 * @param {PropertyDescriptor | undefined} descriptor
 * @returns {boolean}
 */
function descriptorIsAccessor(descriptor) {
  return descriptor !== undefined && !hasOwn(descriptor, 'value');
}

/**
 * True when `name` reads as a function on `port`, own or inherited, as a data
 * property. A getter on the way is never invoked: it is a validation fault
 * (C-SDK section 5.3), so the method does not read as a function. It may throw
 * (a `Proxy` trap); the caller catches.
 *
 * @param {object | Function} port
 * @param {string} name
 * @returns {boolean}
 */
function methodReadsAsFunction(port, name) {
  const visited = new Set();
  let holder = port;
  while (holder !== null && !visited.has(holder)) {
    visited.add(holder);
    const descriptor = Reflect.getOwnPropertyDescriptor(holder, name);
    if (descriptor !== undefined) return hasOwn(descriptor, 'value') && typeof descriptor.value === 'function';
    holder = Reflect.getPrototypeOf(holder);
  }
  return false;
}

/* ------------------------------------------------------------------------- *
 * Result check (fail closed, C-SDK section 5.3).
 * ------------------------------------------------------------------------- */

/** The `length` getter of every typed array, read once from the intrinsic. */
const typedArrayLength = Reflect.getOwnPropertyDescriptor(
  Reflect.getPrototypeOf(Uint8Array.prototype), 'length',
).get;

/**
 * The element count of `value` when it is a genuine typed array, otherwise
 * -1. The intrinsic `length` getter is a brand check: it reads no property of
 * the value and walks no prototype, so no `Proxy` trap of the value or of its
 * prototype chain runs.
 *
 * @param {object} value
 * @returns {number}
 */
function typedArrayElementCount(value) {
  try {
    return Reflect.apply(typedArrayLength, value, []);
  } catch {
    return -1;
  }
}

/** The `Symbol.toStringTag` getter of every typed array, read once from the intrinsic. */
const typedArrayTag = Reflect.getOwnPropertyDescriptor(
  Reflect.getPrototypeOf(Uint8Array.prototype), Symbol.toStringTag,
).get;

/**
 * The byte count of `value` when it is a genuine `Uint8Array` (a subclass
 * included), otherwise -1. Both reads are intrinsic brand checks on internal
 * slots: no property of the value is read and no prototype is walked, so a
 * replaced prototype or a `Proxy` can neither run code here nor report a
 * length other than the bytes a copy of the value takes.
 *
 * @param {unknown} value
 * @returns {number}
 */
function uint8ArrayByteCount(value) {
  try {
    if (Reflect.apply(typedArrayTag, value, []) !== 'Uint8Array') return -1;
    return Reflect.apply(typedArrayLength, value, []);
  } catch {
    return -1;
  }
}

/**
 * Inspect every closed slot (`code`, `lastCode`, `state`, `clientState`,
 * `outcome`, `receiptMode`) present anywhere in `value`: every own property,
 * string or symbol keyed, enumerable or not, of every object and function
 * reachable through own data properties, with no depth limit (an explicit work
 * list, each object visited once, so a cycle ends). Only data properties are
 * read: an accessor is never invoked and makes the value malformed (except
 * the root keys listed in `rootAccessors`, which the caller's contract fixes as
 * accessors), and so does any other fault while reading one object (a `Proxy`
 * trap that throws); either is remembered and the inspection continues with
 * every other key and object, so a malformed part never hides an out-of-set
 * slot elsewhere (C-SDK section 5.3). The indexed elements of a typed array
 * are numbers and are skipped; its other own properties are inspected like
 * those of any object.
 *
 * @param {unknown} value
 * @param {ReadonlySet<string>} [rootAccessors]
 * @returns {{ unknown: boolean, malformed: boolean }}
 */
function scanClosedSlots(value, rootAccessors = EMPTY_SET) {
  const result = { unknown: false, malformed: false };
  if (!isTraversable(value)) return result;
  const seen = new Set([value]);
  const work = [value];
  while (work.length > 0) {
    const current = work.pop();
    const indexedLength = typedArrayElementCount(current);
    let keys;
    try {
      keys = Reflect.ownKeys(current);
    } catch {
      result.malformed = true;
      continue;
    }
    for (const key of keys) {
      if (indexedLength >= 0 && typeof key === 'string' && isArrayIndexBelow(key, indexedLength)) continue;
      let descriptor;
      try {
        descriptor = Reflect.getOwnPropertyDescriptor(current, key);
      } catch {
        result.malformed = true;
        continue;
      }
      if (descriptor === undefined) continue;
      if (!hasOwn(descriptor, 'value')) {
        if (!(current === value && typeof key === 'string' && rootAccessors.has(key))) result.malformed = true;
        continue;
      }
      const slot = descriptor.value;
      if (typeof key === 'string' && !closedSlotKnown(key, slot)) result.unknown = true;
      if (isTraversable(slot) && !seen.has(slot)) {
        seen.add(slot);
        work.push(slot);
      }
    }
  }
  return result;
}

const EMPTY_SET = Object.freeze(new Set());

/** The closed slots `start()` inspects on an object `getPublicKey` returned. */
const KEY_SLOTS = Object.freeze(['code', 'state', 'outcome', 'lastCode', 'receiptMode']);

/**
 * True when `value` carries, among the given closed slots, an own data
 * property outside its closed set. Each slot is read on its own: a fault while
 * reading one (a `Proxy` trap) skips that slot only. Never throws.
 *
 * @param {object} value
 * @param {readonly string[]} slots
 * @returns {boolean}
 */
function ownSlotsUnknown(value, slots) {
  let unknown = false;
  for (const slot of slots) {
    try {
      const descriptor = Reflect.getOwnPropertyDescriptor(value, slot);
      if (descriptor !== undefined && hasOwn(descriptor, 'value') && !closedSlotKnown(slot, descriptor.value)) {
        unknown = true;
      }
    } catch {
      // This slot is not inspectable; the others still are.
    }
  }
  return unknown;
}

/** True for an object or a function: a value that can carry own properties. */
function isTraversable(value) {
  return value !== null && (typeof value === 'object' || typeof value === 'function');
}

/**
 * True when `key` is the canonical decimal form of an integer below `length`.
 *
 * @param {string} key
 * @param {number} length
 * @returns {boolean}
 */
function isArrayIndexBelow(key, length) {
  if (!/^(0|[1-9][0-9]*)$/.test(key)) return false;
  return Number(key) < length;
}

/**
 * True when every closed slot present anywhere in `value` is inside its
 * closed set and nothing in it is malformed (see `scanClosedSlots`).
 *
 * @param {unknown} value
 * @returns {boolean}
 */
function closedSlotsKnown(value) {
  const scan = scanClosedSlots(value);
  return !scan.unknown && !scan.malformed;
}

/**
 * @param {string} key
 * @param {unknown} slot
 * @returns {boolean}
 */
function closedSlotKnown(key, slot) {
  switch (key) {
    case 'code':
      return isKnownResultCode(slot);
    case 'lastCode':
      return slot === null || isKnownResultCode(slot);
    case 'state':
      return typeof slot === 'string' && hasOwn(DeliveryState, slot);
    case 'clientState':
      return typeof slot === 'string' && hasOwn(ClientState, slot);
    case 'outcome':
      return typeof slot === 'string' && hasOwn(RelayOutcome, slot);
    case 'receiptMode':
      return typeof slot === 'string' && RECEIPT_MODES.has(slot);
    default:
      return true;
  }
}

/**
 * The own data properties of `value`, exactly the given keys, or `null`.
 *
 * @param {unknown} value
 * @param {readonly string[]} keys
 * @returns {Record<string, unknown> | null}
 */
function exactFields(value, keys) {
  if (value === null || typeof value !== 'object') return null;
  const own = Reflect.ownKeys(value);
  if (own.length !== keys.length) return null;
  const fields = Object.create(null);
  for (const key of own) {
    if (typeof key !== 'string' || !keys.includes(key)) return null;
    const descriptor = Reflect.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !hasOwn(descriptor, 'value')) return null;
    fields[key] = descriptor.value;
  }
  return fields;
}

/**
 * Check one envelope a lane operation returned. Returns
 * `{ verdict: 'ok', value }`, `{ verdict: 'fail', code }` for a failure the
 * operation may return, `{ verdict: 'unknown' }` for an out-of-set closed slot,
 * or `{ verdict: 'malformed' }` for every other deviation. Never throws.
 *
 * @param {unknown} returned
 * @param {(value: unknown) => unknown} readValue returns the checked value or `null`
 * @param {Set<string>} codes
 * @param {boolean} frozen whether the envelope and its value must be frozen
 * @returns {{ verdict: string, value?: unknown, code?: string }}
 */
function checkEnvelope(returned, readValue, codes, frozen) {
  try {
    // Closed slots first: an out-of-set value anywhere takes precedence over
    // every other deviation, a malformed part and a root that is not a plain
    // object (a function, for one) included (C-SDK section 5.3).
    const scan = scanClosedSlots(returned);
    if (scan.unknown) return { verdict: 'unknown' };
    if (returned === null || typeof returned !== 'object') return { verdict: 'malformed' };
    if (scan.malformed) return { verdict: 'malformed' };
    if (frozen && !Object.isFrozen(returned)) return { verdict: 'malformed' };
    const okDescriptor = Reflect.getOwnPropertyDescriptor(returned, 'ok');
    if (okDescriptor === undefined || !hasOwn(okDescriptor, 'value')) return { verdict: 'malformed' };
    if (okDescriptor.value === true) {
      const fields = exactFields(returned, ['ok', 'value']);
      if (fields === null) return { verdict: 'malformed' };
      if (frozen && fields.value !== null && typeof fields.value === 'object' && !Object.isFrozen(fields.value)) {
        return { verdict: 'malformed' };
      }
      const value = readValue(fields.value);
      return value === null ? { verdict: 'malformed' } : { verdict: 'ok', value };
    }
    if (okDescriptor.value === false) {
      const fields = exactFields(returned, ['ok', 'code']);
      if (fields === null || !codes.has(fields.code)) return { verdict: 'malformed' };
      return { verdict: 'fail', code: fields.code };
    }
    return { verdict: 'malformed' };
  } catch {
    return { verdict: 'malformed' };
  }
}

/** The client-facing failure code of a verdict that is not `ok`. */
function verdictCode(checked) {
  if (checked.verdict === 'fail') return checked.code;
  if (checked.verdict === 'unknown') return SdkResultCode.E_SDK_UNKNOWN_CODE;
  return SdkResultCode.E_SDK_INTERNAL;
}

/**
 * The `deliveryId` of a value about one item, when it carries a string one as
 * an own data property; otherwise `null`. Never throws.
 *
 * @param {unknown} value
 * @returns {string | null}
 */
function deliveryIdOf(value) {
  try {
    if (!isTraversable(value)) return null;
    const descriptor = Reflect.getOwnPropertyDescriptor(value, 'deliveryId');
    if (descriptor === undefined || !hasOwn(descriptor, 'value')) return null;
    return typeof descriptor.value === 'string' ? descriptor.value : null;
  } catch {
    return null;
  }
}

/**
 * `{ deliveryId, state }` with a string id and one of the given states.
 *
 * @param {Set<string>} states
 * @returns {(value: unknown) => object | null}
 */
function readItemResult(states) {
  return (value) => {
    const fields = exactFields(value, ['deliveryId', 'state']);
    if (fields === null || typeof fields.deliveryId !== 'string' || !states.has(fields.state)) return null;
    return { deliveryId: fields.deliveryId, state: fields.state };
  };
}

/**
 * A delivery snapshot of exactly the nine fields of C-SDK section 6.2, copied
 * into a fresh frozen object with a fresh frozen `relayOutcomes` array.
 *
 * @param {number} relayCount
 * @param {number} maxAttempts
 * @returns {(value: unknown) => object | null}
 */
function readSnapshot(relayCount, maxAttempts) {
  return (value) => {
    const fields = exactFields(value, SNAPSHOT_FIELDS);
    if (fields === null) return null;
    if (typeof fields.deliveryId !== 'string') return null;
    if (typeof fields.recipient !== 'string' || !HEX64.test(fields.recipient)) return null;
    if (typeof fields.state !== 'string' || !hasOwn(DeliveryState, fields.state)) return null;
    if (fields.terminal !== TERMINAL_STATES.has(fields.state)) return null;
    if (!Number.isInteger(fields.attempts) || fields.attempts < 0 || fields.attempts > maxAttempts) return null;
    if (typeof fields.createdAt !== 'number' || !Number.isFinite(fields.createdAt)) return null;
    if (typeof fields.deadlineAt !== 'number' || !Number.isFinite(fields.deadlineAt)) return null;
    if (fields.lastCode !== null && !isKnownResultCode(fields.lastCode)) return null;
    const outcomes = fields.relayOutcomes;
    if (!Array.isArray(outcomes)) return null;
    const lengthDescriptor = Reflect.getOwnPropertyDescriptor(outcomes, 'length');
    if (lengthDescriptor === undefined || lengthDescriptor.value !== relayCount) return null;
    const relayOutcomes = [];
    for (let i = 0; i < relayCount; i += 1) {
      const descriptor = Reflect.getOwnPropertyDescriptor(outcomes, String(i));
      if (descriptor === undefined || !hasOwn(descriptor, 'value')) return null;
      const entry = exactFields(descriptor.value, ['relayIndex', 'outcome']);
      if (entry === null || entry.relayIndex !== i) return null;
      if (typeof entry.outcome !== 'string' || !hasOwn(RelayOutcome, entry.outcome)) return null;
      relayOutcomes.push(Object.freeze({ relayIndex: i, outcome: entry.outcome }));
    }
    return Object.freeze({
      deliveryId: fields.deliveryId,
      recipient: fields.recipient,
      state: fields.state,
      terminal: fields.terminal,
      attempts: fields.attempts,
      createdAt: fields.createdAt,
      deadlineAt: fields.deadlineAt,
      lastCode: fields.lastCode,
      relayOutcomes: Object.freeze(relayOutcomes),
    });
  };
}

/* ------------------------------------------------------------------------- *
 * Host helpers.
 * ------------------------------------------------------------------------- */

/* ------------------------------------------------------------------------- *
 * The port boundary (C-SDK sections 5.3 and 8.4, C-DLV sections 4.5 and 4.6).
 *
 * Every call this module makes into code it does not own goes through the
 * three functions below and nowhere else: the caller's identity port, the
 * caller's event listeners, and the delivery seams, that is the factories and
 * members of the three lane modules (which carry the caller's storage,
 * session, identity, clock and random ports) and the members of a relay-set
 * attempt. One boundary handles, in one place:
 * - a method lookup that throws (a getter or a `Proxy` trap) or re-enters the
 *   client (the caller's `halted` is read after the lookup, before the
 *   invocation);
 * - a method that is absent or not a function;
 * - a synchronous throw, a rejection, a returned thenable whose `then` throws;
 * - a call that never settles (`timeoutMs`, on the host `setTimeout`);
 * - a call that re-enters the client while it runs: a tracked call is
 *   registered before the lookup and ends once it settles or times out, so a
 *   stop started from inside the call waits for it.
 * What a call returns is inspected by the result check further below, closed
 * slots first, before any shape check (`scanClosedSlots`), with the same
 * precedence for every root type; a call that does not return a value never
 * reaches it. None of the three ever throws or rejects.
 *
 * Threat model: ports and seams are faulty, not adversarial. The guaranteed
 * cases are a synchronous throw, a rejection, a call that never settles and a
 * wrong returned value or code (out-of-set closed slots give
 * `E_SDK_UNKNOWN_CODE` and fail the item closed); every wait on a lane module
 * has a host-time backstop no shorter than what C-DLV lets that operation
 * take (`BOUND` in `buildClient`), so `start()`, every method and `shutdown()`
 * settle even when a module never does.
 * Throwing or side-effecting getters and `Proxy` traps, tampered promises and
 * synchronous re-entry into the client are handled on a best-effort basis
 * only, and a synchronous callback that never returns cannot be bounded in
 * this process.
 * ------------------------------------------------------------------------- */

const CALL_ERROR = Object.freeze({ settled: 'error' });
const CALL_HALTED = Object.freeze({ settled: 'halted' });
const CALL_TIMEOUT = Object.freeze({ settled: 'timeout' });
const never = () => false;
const noTracking = () => () => undefined;

/**
 * Read `name` of `holder` for a call. With `ownData`, only an own data
 * property is read and no getter or inherited member is ever invoked (the
 * members of a relay-set attempt); otherwise an ordinary property read, which
 * runs a getter. Throws when the read throws.
 *
 * @param {unknown} holder
 * @param {string} name
 * @param {boolean} ownData
 * @returns {unknown}
 */
function lookUpMember(holder, name, ownData) {
  if (!isTraversable(holder)) return undefined;
  if (!ownData) return holder[name];
  const descriptor = Reflect.getOwnPropertyDescriptor(holder, name);
  return descriptor !== undefined && hasOwn(descriptor, 'value') ? descriptor.value : undefined;
}

/**
 * Call `fn` with `thisArg` and `args`, synchronously. Resolves to
 * `{ settled: 'value', value }` or `{ settled: 'error' }`; never throws. The
 * value is returned as is: a thenable is not adopted here.
 *
 * @param {unknown} fn
 * @param {unknown} thisArg
 * @param {unknown[]} args
 * @returns {object}
 */
function crossCall(fn, thisArg, args) {
  if (typeof fn !== 'function') return CALL_ERROR;
  let value;
  try {
    value = Reflect.apply(fn, thisArg, args);
  } catch {
    return CALL_ERROR;
  }
  consumeRejection(value);
  return { settled: 'value', value };
}

/** `Promise.prototype.then`, read once from the intrinsic. */
const nativeThen = Promise.prototype.then;

/**
 * When `value` is a native promise, attach a handler that ignores its
 * rejection, so a promise a call returned where none belongs (or one the
 * client does not wait for) never becomes an unhandled rejection. The brand
 * check comes first: for any other value no property is read and no caller
 * code runs. Never throws.
 *
 * @param {unknown} value
 */
function consumeRejection(value) {
  if (!isTraversable(value)) return;
  try {
    Reflect.apply(nativeThen, value, [undefined, () => undefined]);
  } catch {
    // Not a native promise: nothing to consume.
  }
}

/**
 * Call member `name` of `holder` as a method, synchronously: the lookup, the
 * `halted` read, then the invocation. Returns `{ settled: 'value', value }`,
 * `{ settled: 'error' }` or `{ settled: 'halted' }`; never throws.
 *
 * @param {unknown} holder
 * @param {string} name
 * @param {unknown[]} args
 * @param {{ halted?: () => boolean, ownData?: boolean }} [options]
 * @returns {object}
 */
function crossBoundary(holder, name, args, options = {}) {
  const halted = options.halted || never;
  let method;
  try {
    method = lookUpMember(holder, name, options.ownData === true);
  } catch {
    return CALL_ERROR;
  }
  try {
    if (halted()) return CALL_HALTED;
  } catch {
    return CALL_HALTED;
  }
  return crossCall(method, holder, args);
}

/**
 * `crossBoundary`, then the adoption of what it returned. Resolves to
 * `{ settled: 'value', value }`, `{ settled: 'error' }`,
 * `{ settled: 'halted' }` or `{ settled: 'timeout' }`; never rejects. With
 * `timeoutMs`, the call settles `timeout` at that bound on the host
 * `setTimeout`. With `track`, the call is registered by `track()` before the
 * lookup and the function it returns is called once, when the call settles.
 *
 * @param {unknown} holder
 * @param {string} name
 * @param {unknown[]} args
 * @param {{ halted?: () => boolean, timeoutMs?: number, track?: () => () => void }} [options]
 * @returns {Promise<object>}
 */
function crossBoundaryAsync(holder, name, args, options = {}) {
  return settleCall(() => crossBoundary(holder, name, args, options), options);
}

/**
 * The adoption of a value a call already returned (a promise a synchronous
 * call handed back): resolves as `crossBoundaryAsync` does; never rejects.
 * With `timeoutMs`, it settles `timeout` at that bound on the host
 * `setTimeout`.
 *
 * @param {unknown} value
 * @param {{ timeoutMs?: number }} [options]
 * @returns {Promise<object>}
 */
function adoptReturned(value, options = {}) {
  return settleCall(() => ({ settled: 'value', value }), options);
}

/**
 * Register (with `options.track`), arm the bound (with `options.timeoutMs`),
 * run `invoke` synchronously, then adopt the value it returned.
 *
 * @param {() => object} invoke
 * @param {{ timeoutMs?: number, track?: () => () => void }} options
 * @returns {Promise<object>}
 */
function settleCall(invoke, options) {
  const track = options.track || noTracking;
  let end = () => undefined;
  try {
    end = track();
  } catch {
    end = () => undefined;
  }
  return new Promise((resolve) => {
    let done = false;
    let handle = null;
    const finish = (outcome) => {
      if (done) return;
      done = true;
      if (handle !== null) clearTimeout(handle);
      try {
        end();
      } catch {
        // The registration ends whatever its owner does.
      }
      resolve(outcome);
    };
    if (Number.isInteger(options.timeoutMs)) handle = setTimeout(() => finish(CALL_TIMEOUT), options.timeoutMs);
    const call = invoke();
    if (call.settled !== 'value') {
      finish(call);
      return;
    }
    try {
      // `Promise.resolve` reads `then` and, for a native promise, its
      // `constructor`: either read may run caller code and throw.
      Promise.resolve(call.value).then(
        (value) => finish({ settled: 'value', value }),
        () => finish(CALL_ERROR),
      );
    } catch {
      finish(CALL_ERROR);
    }
  });
}

/**
 * Write `value` into slot `name` of `holder` when the slot is an own writable
 * data property or an own accessor with a setter (the setter runs here, as a
 * call across the boundary), never through a getter; a fault changes nothing.
 * Returns whether the write ran without a fault.
 *
 * @param {unknown} holder
 * @param {string} name
 * @param {unknown} value
 * @returns {boolean}
 */
function setThroughBoundary(holder, name, value) {
  try {
    if (!isTraversable(holder)) return false;
    const descriptor = Reflect.getOwnPropertyDescriptor(holder, name);
    if (descriptor === undefined) return false;
    if (hasOwn(descriptor, 'value')) return descriptor.writable === true && Reflect.set(holder, name, value);
    return crossCall(descriptor.set, holder, [value]).settled === 'value';
  } catch {
    return false;
  }
}

/** The value of a call that returned one, otherwise `null`. */
const valueOfCall = (call) => (call.settled === 'value' ? call.value : null);

/**
 * Whether `value` is a native promise: a brand check on the intrinsic `then`
 * that reads no property of `value` (the handlers it attaches ignore the
 * outcome). Never throws.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
function isNativePromise(value) {
  if (!isTraversable(value)) return false;
  try {
    Reflect.apply(nativeThen, value, [undefined, () => undefined]);
    return true;
  } catch {
    return false;
  }
}

/**
 * Whether a lane factory call returned a module object: a call that returned
 * a value that is a non-null object or a function and not a promise (a
 * factory of C-DLV is synchronous).
 *
 * @param {object} call
 * @returns {boolean}
 */
const isModuleCall = (call) => call.settled === 'value' && isTraversable(call.value) && !isNativePromise(call.value);

/** The default clock of C-SDK section 8.4, one per client. */
function createDefaultClock() {
  return {
    now: () => Date.now(),
    setTimer: (callback, delayMs) => setTimeout(callback, delayMs),
    clearTimer: (handle) => clearTimeout(handle),
  };
}

/** The default random object of C-SDK section 8.4, one per client. */
function createDefaultRandom() {
  return {
    nextUint32: () => {
      const bytes = new Uint8Array(4);
      crypto.getRandomValues(bytes);
      return bytes[0] * 2 ** 24 + bytes[1] * 2 ** 16 + bytes[2] * 2 ** 8 + bytes[3];
    },
  };
}

/** One turn of the microtask queue. */
const microtaskTurn = () => new Promise((resolve) => queueMicrotask(resolve));

/* ------------------------------------------------------------------------- *
 * The client.
 * ------------------------------------------------------------------------- */

/**
 * Create a client (C-SDK section 4.1). Synchronous; calls no port and no lane
 * module; returns a frozen envelope for every input and never throws.
 *
 * @param {unknown} config
 * @returns {object}
 */
export function createStyxClient(config) {
  const validated = validateConfig(config);
  if (validated.ok !== true) return validated;
  try {
    return success(buildClient(validated.value));
  } catch {
    return failure(SdkResultCode.E_SDK_INVALID_CONFIG);
  }
}

/**
 * @param {object} settings the private copies made by `validateConfig`
 * @returns {object} the frozen client
 */
function buildClient(settings) {
  const relays = settings.relays;
  const relayCount = relays.length;
  const delivery = settings.delivery;
  const portCallTimeoutMs = Math.floor(delivery.perRelayTimeoutMs / 2);
  // Host-time backstops of the waits on the lane modules (threat model B, see
  // the port boundary): each is the longest time C-DLV lets that operation of
  // a module that keeps its contract take, plus one port-call timeout of
  // margin, so a conforming module is never cut short and one that never
  // settles cannot hold a method, `start()` or `shutdown()` open.
  const P = portCallTimeoutMs;
  const BOUND = Object.freeze({
    inspectStore: 2 * P, // one `storage.list` (C-DLV section 5.2)
    relayStart: delivery.perRelayTimeoutMs + P, // the connection phase (C-DLV section 5.2)
    onFrame: P, // synchronous in I-RELAY
    send: 4 * P, // `seal`, `put` and, after a failed `put`, `remove` (C-DLV section 4.2)
    cancel: 3 * P, // a write in progress, then the `update` (C-DLV section 4.6)
    getDelivery: P, // in memory
    settled: 2 * P, // S3: one port-call timeout
    outboxStop: 5 * P, // four port-call timeouts (C-DLV section 5.5)
    dispose: delivery.perRelayTimeoutMs + P, // connection attempts settle within 10 000 ms (C-DLV section 5.5)
  });
  const ports = { storage: settings.storage, session: settings.session, identity: settings.identity };
  let clock = settings.clock !== null ? settings.clock : createDefaultClock();
  let random = settings.random !== null ? settings.random : createDefaultRandom();
  const readSendResult = readItemResult(new Set(['QUEUED']));
  const readCancelResult = readItemResult(new Set(['CANCELLED']));
  const readFailClosedResult = readItemResult(FAILED_STATES);
  const readDeliverySnapshot = readSnapshot(relayCount, delivery.maxAttempts);

  /** @type {'CREATED' | 'RUNNING' | 'STOPPED'} */
  let clientState = 'CREATED';
  let stopping = false;
  let startInProgress = null;
  /** The modules of the running client (or of the `start()` in progress). */
  let modules = null;
  /** The outbox kept after a run, for the retained snapshots of `getDelivery`. */
  let retainedOutbox = null;
  const failClosedIds = new Set();
  /** The port calls of this module in progress (see the port boundary). */
  const portCalls = new Set();

  /** Register one port call before its lookup; returns its end. */
  function trackPortCall() {
    let end = () => undefined;
    const pending = new Promise((resolve) => {
      end = () => resolve(undefined);
    });
    portCalls.add(pending);
    pending.then(() => portCalls.delete(pending));
    return end;
  }

  /** Resolves once every port call registered now has settled or timed out. */
  function portCallsSettled() {
    return Promise.all([...portCalls]).then(() => undefined);
  }

  /* --- events (C-SDK section 7) ---------------------------------------- */

  /** @type {{ listener: Function, live: boolean }[]} */
  let registrations = [];
  let shutdownAudience = null;
  let pendingDispatches = 0;
  let lostEventsDuringShutdown = 0;

  /**
   * Record one checked event: schedule its dispatch with `queueMicrotask` to
   * the registrations present now (after `shutdown()`: to the shutdown
   * audience) that are still present at dispatch, in registration order.
   *
   * @param {() => object} makeEvent builds a fresh frozen event per listener
   */
  function record(makeEvent) {
    const audience = (shutdownAudience !== null ? shutdownAudience : registrations).slice();
    pendingDispatches += 1;
    queueMicrotask(() => {
      try {
        for (const registration of audience) {
          if (!registration.live) continue;
          // A listener fault changes nothing (C-SDK section 7): a throw, and a
          // returned thenable that rejects or whose `then` throws.
          const called = crossCall(registration.listener, undefined, [makeEvent()]);
          if (called.settled === 'value' && isTraversable(called.value)) {
            crossBoundaryAsync(called.value, 'then', [undefined, () => undefined]);
          }
        }
      } finally {
        pendingDispatches -= 1;
      }
    });
  }

  /** Wait until every dispatch already scheduled has run. */
  async function dispatchQueueEmpty() {
    for (let turns = 0; pendingDispatches > 0 && turns < 1000; turns += 1) {
      await microtaskTurn();
    }
  }

  /**
   * Ask the outbox to fail one item closed (S4), at most once per item.
   *
   * @param {string} deliveryId
   */
  function failItemClosed(deliveryId) {
    if (failClosedIds.has(deliveryId)) return;
    failClosedIds.add(deliveryId);
    const outbox = modules !== null ? modules.outbox : retainedOutbox;
    if (outbox === null || outbox === undefined) return;
    // Its result concerns the same item, already handled once: it is
    // checked and nothing further follows.
    checkEnvelope(valueOfCall(crossBoundary(outbox, 'failClosed', [{ deliveryId }])),
      readFailClosedResult, CODES.failClosed, true);
  }

  /**
   * The sink of the outbox and of the inbound processor: check, then record.
   *
   * @param {unknown} event
   */
  function sink(event) {
    let accepted = null;
    try {
      accepted = checkEvent(event);
    } catch {
      accepted = null;
    }
    if (accepted === null) {
      const deliveryId = deliveryIdOf(event);
      if (deliveryId !== null) failItemClosed(deliveryId);
      return;
    }
    if (stopping && accepted.kind === 'DELIVERY_STATE_CHANGED' && accepted.state === 'LOST_ON_SHUTDOWN') {
      lostEventsDuringShutdown += 1;
    }
    if (accepted.kind === 'MESSAGE_RECEIVED') {
      const sender = accepted.sender;
      const payload = new Uint8Array(accepted.payload);
      record(() => Object.freeze({ kind: 'MESSAGE_RECEIVED', sender, payload: new Uint8Array(payload) }));
      return;
    }
    const frozen = Object.freeze(accepted);
    record(() => Object.freeze({ ...frozen }));
  }

  /**
   * Check one event a module handed to the sink; returns its fields or `null`.
   * Closed slots are inspected before the shape.
   *
   * @param {unknown} event
   * @returns {object | null}
   */
  function checkEvent(event) {
    if (event === null || typeof event !== 'object') return null;
    const kindDescriptor = Reflect.getOwnPropertyDescriptor(event, 'kind');
    if (kindDescriptor === undefined || !hasOwn(kindDescriptor, 'value')) return null;
    const kind = kindDescriptor.value;
    if (typeof kind !== 'string' || !hasOwn(SdkEventKind, kind)) return null;
    if (!closedSlotsKnown(event)) return null;
    if (kind === 'DELIVERY_STATE_CHANGED') {
      const fields = exactFields(event, ['kind', 'deliveryId', 'state', 'terminal', 'lastCode']);
      if (fields === null || typeof fields.deliveryId !== 'string') return null;
      if (fields.terminal !== TERMINAL_STATES.has(fields.state)) return null;
      return {
        kind, deliveryId: fields.deliveryId, state: fields.state, terminal: fields.terminal,
        lastCode: fields.lastCode,
      };
    }
    if (kind === 'MESSAGE_RECEIVED') {
      const fields = exactFields(event, ['kind', 'sender', 'payload']);
      if (fields === null || typeof fields.sender !== 'string' || !HEX64.test(fields.sender)) return null;
      if (uint8ArrayByteCount(fields.payload) < 0) return null;
      return { kind, sender: fields.sender, payload: fields.payload };
    }
    if (kind === 'INBOUND_DISCARDED') {
      const fields = exactFields(event, ['kind', 'code']);
      if (fields === null || !DISCARD_CODES.has(fields.code)) return null;
      return { kind, code: fields.code };
    }
    // The client is the only emitter of CLIENT_STATE_CHANGED.
    return null;
  }

  /** Record `CLIENT_STATE_CHANGED`. */
  function recordClientState(state) {
    record(() => Object.freeze({ kind: 'CLIENT_STATE_CHANGED', clientState: state }));
  }

  /* --- modules ----------------------------------------------------------- */

  /**
   * The one relay-set disposal of this client: the first call stores its
   * promise, every later need awaits it.
   *
   * @param {object} held
   * @returns {Promise<void>}
   */
  function disposeRelaySet(held) {
    if (held.relaySet === null) return Promise.resolve();
    if (held.disposal === null) {
      // A disposal fault leaves nothing further to do here.
      // Bounded by its host-time backstop (`BOUND.dispose`), so a disposal
      // that never settles cannot hold the stop open.
      held.disposal = crossBoundaryAsync(held.relaySet, 'dispose', [], { timeoutMs: BOUND.dispose })
        .then(() => undefined);
    }
    return held.disposal;
  }

  /**
   * Clean up the modules a failed `start()` created, in the contract's order.
   *
   * @param {object} held
   */
  async function cleanUpFailedStart(held) {
    // Cleanup faults never change the code. Each wait has its host-time
    // backstop (`BOUND`).
    if (held.receipts !== null) {
      crossBoundary(held.receipts, 'shutdown', []);
      await crossBoundaryAsync(held.receipts, 'settled', [], { timeoutMs: BOUND.settled });
    }
    if (held.outbox !== null) {
      await crossBoundaryAsync(held.outbox, 'shutdown', [], { timeoutMs: BOUND.outboxStop });
    }
    await disposeRelaySet(held);
  }

  /**
   * The outbound seam: one relay-set attempt per outbox attempt. The attempt
   * is checked before the outbox uses it (C-SDK section 5.3): closed slots
   * first, anywhere in it, then the shape the I-RELAY contract fixes. An
   * out-of-set value never reaches the outbox: the outbox receives instead an
   * inert attempt of the same shape whose relay outcomes are all out of set,
   * so its own unknown-value rule (C-DLV section 4.5) fails the item it
   * is publishing with `E_SDK_UNKNOWN_CODE` before any acceptance can be
   * recorded; the relay-set attempt is told to ignore acknowledgements. Any
   * other deviation is thrown, which the outbox handles as an internal fault
   * of that item.
   *
   * @param {object} held
   */
  const publishSeam = (held) => (event) => {
    const published = crossBoundary(held.relaySet, 'publish', [event]);
    if (published.settled !== 'value') throw new TypeError('relay-set publication failed');
    const attempt = published.value;
    const verdict = checkAttempt(attempt, event);
    if (verdict === 'ok') return attempt;
    if (verdict === 'unknown') {
      // The inert attempt below already keeps every acceptance out, whatever
      // this call does.
      crossBoundary(attempt, 'ignoreAcks', [], { ownData: true });
      return unknownAttempt(event);
    }
    throw new TypeError('relay attempt outside the I-RELAY contract');
  };

  /**
   * Check one relay-set attempt for the event `event`. Every unknown value is
   * collected before any shape verdict, so a malformed part never hides one:
   * an out-of-set closed slot anywhere in the attempt (its functions
   * included), or an entry of `outcomes` outside `RelayOutcome` (each own
   * element read, whatever the array length), is `'unknown'`. Then the
   * I-RELAY attempt, member by member: exactly the eleven members; `index` a
   * positive safe integer; `event` the event published; `outcomes` and
   * `publishedOnce` arrays of exactly one entry per configured relay, of
   * relay outcomes and booleans; `acceptedIndex` an integer from -1 to the
   * relay count less one, or a getter (not invoked); the four methods
   * functions; the two gates writable data slots or accessors with a setter
   * (not invoked); no other accessor anywhere. Any deviation is `'malformed'`.
   *
   * @param {unknown} attempt
   * @param {unknown} event
   * @returns {'ok' | 'unknown' | 'malformed'}
   */
  function checkAttempt(attempt, event) {
    let malformed = false;
    let unknown = false;
    // (1) Every unknown value, whatever else is wrong, a root that is not a
    // plain object (a function, for one) included.
    const scan = scanClosedSlots(attempt, ATTEMPT_ACCESSORS);
    unknown = scan.unknown;
    malformed = scan.malformed;
    if (!isTraversable(attempt)) return unknown ? 'unknown' : 'malformed';
    // A root that is not a plain object (a function, for one) is malformed,
    // but only once its relay outcomes, too, have been inspected below.
    if (typeof attempt !== 'object') malformed = true;
    const fields = Object.create(null);
    let own = [];
    try {
      own = Reflect.ownKeys(attempt);
    } catch {
      return unknown ? 'unknown' : 'malformed';
    }
    for (const key of own) {
      try {
        const descriptor = Reflect.getOwnPropertyDescriptor(attempt, key);
        if (typeof key === 'string' && ATTEMPT_MEMBERS.includes(key) && descriptor !== undefined) {
          fields[key] = descriptor;
        } else {
          malformed = true;
        }
      } catch {
        malformed = true;
      }
    }
    const dataOf = (name) => (fields[name] !== undefined && hasOwn(fields[name], 'value') ? fields[name].value : undefined);
    const elements = (array, accept) => {
      // Every own element is read as a data value; the length is checked apart.
      // Each read is guarded on its own, so a fault on one element never stops
      // the inspection of the others.
      let valid = true;
      let elementUnknown = false;
      let keys;
      try {
        if (!Array.isArray(array)) return { valid: false, unknown: false };
        keys = Reflect.ownKeys(array);
      } catch {
        return { valid: false, unknown: false };
      }
      try {
        const length = Reflect.getOwnPropertyDescriptor(array, 'length');
        if (length === undefined || length.value !== relayCount) valid = false;
      } catch {
        valid = false;
      }
      for (const key of keys) {
        if (key === 'length') continue;
        if (typeof key !== 'string' || !/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= relayCount) valid = false;
        let entry;
        try {
          entry = Reflect.getOwnPropertyDescriptor(array, key);
        } catch {
          valid = false;
          continue;
        }
        if (entry === undefined || !hasOwn(entry, 'value')) {
          valid = false;
          continue;
        }
        let verdict;
        try {
          verdict = accept(entry.value);
        } catch {
          verdict = 'bad';
        }
        if (verdict === 'unknown') elementUnknown = true;
        else if (verdict !== 'ok') valid = false;
      }
      for (let index = 0; index < relayCount; index += 1) {
        try {
          if (!hasOwn(array, String(index))) valid = false;
        } catch {
          valid = false;
        }
      }
      return { valid, unknown: elementUnknown };
    };
    const outcomes = elements(dataOf('outcomes'),
      (value) => (typeof value === 'string' && hasOwn(RelayOutcome, value) ? 'ok' : 'unknown'));
    if (unknown || outcomes.unknown) return 'unknown';
    // (2) The shape.
    if (malformed || !outcomes.valid) return 'malformed';
    if (ATTEMPT_MEMBERS.some((name) => fields[name] === undefined)) return 'malformed';
    const index = dataOf('index');
    if (!Number.isSafeInteger(index) || index < 1) return 'malformed';
    if (!hasOwn(fields.event, 'value') || fields.event.value !== event) return 'malformed';
    if (!elements(dataOf('publishedOnce'), (value) => (typeof value === 'boolean' ? 'ok' : 'bad')).valid) return 'malformed';
    const accepted = fields.acceptedIndex;
    if (hasOwn(accepted, 'value')) {
      if (!Number.isInteger(accepted.value) || accepted.value < -1 || accepted.value >= relayCount) return 'malformed';
    } else if (typeof accepted.get !== 'function') {
      return 'malformed';
    }
    for (const name of ['isSettled', 'onOutcome', 'onSettled', 'ignoreAcks']) {
      if (typeof dataOf(name) !== 'function') return 'malformed';
    }
    for (const name of ['acceptGate', 'latePublishGate']) {
      const descriptor = fields[name];
      const writable = hasOwn(descriptor, 'value') ? descriptor.writable === true : typeof descriptor.set === 'function';
      if (!writable) return 'malformed';
    }
    return 'ok';
  }

  /**
   * The inert attempt the outbox receives in place of a relay-set attempt that
   * carried an out-of-set value: every relay outcome is outside the closed set
   * of C-SDK section 6.3, nothing is published, no listener is ever called.
   * Only its two gate slots are writable, as the outbox sets them.
   *
   * @param {unknown} event
   * @returns {object}
   */
  function unknownAttempt(event) {
    const none = () => undefined;
    const fixed = (value) => ({ __proto__: null, value, enumerable: true, writable: false, configurable: false });
    const slot = { __proto__: null, value: null, enumerable: true, writable: true, configurable: false };
    const inert = Object.create(null, {
      __proto__: null,
      index: fixed(0),
      event: fixed(event),
      outcomes: fixed(Object.freeze(new Array(relayCount).fill('UNKNOWN'))),
      publishedOnce: fixed(Object.freeze(new Array(relayCount).fill(false))),
      acceptedIndex: fixed(-1),
      isSettled: fixed(() => true),
      onOutcome: fixed(() => none),
      onSettled: fixed(() => none),
      ignoreAcks: fixed(none),
      acceptGate: { ...slot },
      latePublishGate: { ...slot },
    });
    return Object.preventExtensions(inert);
  }

  /**
   * The receipt seam: published once on every relay connected now, with no
   * outcome recorded or reported (C-DLV section 7.2). The client reads no
   * value from this attempt and records nothing from it (there is no item and
   * no method in progress); it only neutralises it: acknowledgements ignored
   * and both gates refusing, each through an own data function or a writable
   * slot or setter, never through a getter.
   *
   * @param {object} held
   */
  const publishReceiptSeam = (held) => (receipt) => {
    if (stopping) {
      // S6 is synchronous and void: never create an attempt during the drain.
      const drained = crossBoundary(held.relaySet, 'publishDrain', [receipt]);
      if (drained.settled !== 'value') return undefined;
      const scan = scanClosedSlots(drained.value);
      if (scan.unknown) sink({ kind: 'INBOUND_DISCARDED', code: SdkResultCode.E_SDK_UNKNOWN_CODE });
      // Any other non-void value (including a promise) is a failed publication,
      // not an acknowledgement; crossBoundary consumes promise rejections.
      return undefined;
    }
    const published = crossBoundary(held.relaySet, 'publish', [receipt]);
    if (published.settled !== 'value') return undefined;
    const attempt = published.value;
    if (attempt === null || typeof attempt !== 'object') return undefined;
    // A fault here changes nothing.
    crossBoundary(attempt, 'ignoreAcks', [], { ownData: true });
    for (const gate of ['acceptGate', 'latePublishGate']) setThroughBoundary(attempt, gate, () => false);
    return undefined;
  };

  /**
   * One inbound frame: hand it to the inbound processor and check its return.
   *
   * @param {object} held
   * @param {unknown} frame
   */
  function onInboundFrame(held, frame) {
    try {
      const returned = valueOfCall(crossBoundary(held.receipts, 'ingest', [frame]));
      const checked = checkEnvelope(returned, (value) => {
        const fields = exactFields(value, ['queued']);
        return fields !== null && typeof fields.queued === 'boolean' ? fields : null;
      }, CODES.ingest, true);
      if (checked.verdict === 'unknown') {
        sink({ kind: 'INBOUND_DISCARDED', code: SdkResultCode.E_SDK_UNKNOWN_CODE });
      }
    } catch {
      // A fault on the inbound path records nothing.
    }
    return undefined;
  }

  /**
   * `start()` of C-SDK section 4.2 and C-DLV section 5.2, steps (1) to (6).
   *
   * @returns {Promise<object>} a frozen envelope
   */
  async function runStart() {
    const held = {
      outbox: null, receipts: null, relaySet: null, disposal: null, publicKey: null,
    };
    modules = held;
    const fail = async (code) => {
      await cleanUpFailedStart(held);
      if (modules === held) modules = null;
      held.publicKey = null;
      return failure(stopping ? SdkResultCode.E_SDK_CLIENT_STOPPED : code);
    };

    // (1) The outbox, with the caller's port objects themselves.
    const createdOutbox = crossCall(createOutbox, undefined, [{
      delivery,
      relayCount,
      storage: ports.storage,
      session: ports.session,
      identity: ports.identity,
      clock,
      random,
      publish: publishSeam(held),
      onEvent: sink,
    }]);
    if (!isModuleCall(createdOutbox)) return fail(SdkResultCode.E_SDK_INTERNAL);
    held.outbox = createdOutbox.value;

    // (2) The store must hold no item.
    const inspected = valueOfCall(await crossBoundaryAsync(held.outbox, 'inspectStore', [], {
      timeoutMs: BOUND.inspectStore,
    }));
    const inspection = checkEnvelope(inspected, (value) => {
      const fields = exactFields(value, ['empty']);
      return fields !== null && fields.empty === true ? fields : null;
    }, CODES.inspectStore, true);
    if (inspection.verdict !== 'ok') return fail(verdictCode(inspection));
    if (stopping) return fail(SdkResultCode.E_SDK_CLIENT_STOPPED);

    // (3) The public key, read once, as a method of the caller's identity port.
    const reading = await crossBoundaryAsync(ports.identity, 'getPublicKey', [], {
      timeoutMs: portCallTimeoutMs, halted: () => stopping, track: trackPortCall,
    });
    if (reading.settled === 'halted') return fail(SdkResultCode.E_SDK_CLIENT_STOPPED);
    if (reading.settled !== 'value') return fail(SdkResultCode.E_SDK_IDENTITY_FAILED);
    const key = reading.value;
    // Checked first: an object (a function included) carrying an own `code`,
    // `state`, `outcome`, `lastCode` or `receiptMode` data property outside
    // its closed set (C-DLV section 4.5). Each slot is read on its own, so a
    // fault while reading one never hides an out-of-set value in another.
    if (isTraversable(key) && ownSlotsUnknown(key, KEY_SLOTS)) {
      return fail(SdkResultCode.E_SDK_UNKNOWN_CODE);
    }
    if (typeof key !== 'string' || !HEX64.test(key)) return fail(SdkResultCode.E_SDK_IDENTITY_FAILED);
    if (stopping) return fail(SdkResultCode.E_SDK_CLIENT_STOPPED);
    held.publicKey = key;
    const adopted = valueOfCall(crossBoundary(held.outbox, 'adoptPublicKey', [key]));
    const adoption = checkEnvelope(adopted, (value) => {
      const fields = exactFields(value, ['adopted']);
      return fields !== null && fields.adopted === true ? fields : null;
    }, CODES.adoptPublicKey, true);
    if (adoption.verdict !== 'ok') {
      return fail(adoption.verdict === 'unknown' ? SdkResultCode.E_SDK_UNKNOWN_CODE : SdkResultCode.E_SDK_INTERNAL);
    }
    // Every call across the boundary may have re-entered the stop: from then
    // on no further module is created and no connection is opened.
    if (stopping) return fail(SdkResultCode.E_SDK_CLIENT_STOPPED);

    // (4) The relay set.
    let subscriptionId;
    try {
      subscriptionId = 's' + bytesToHex(randomBytes(16));
    } catch {
      return fail(SdkResultCode.E_SDK_INTERNAL);
    }
    const createdSet = crossCall(createRelaySet, undefined, [{
      relays: [...relays],
      clock,
      random,
      perRelayTimeoutMs: delivery.perRelayTimeoutMs,
      subscriptionId,
      filter: { kinds: [...SUBSCRIBED_KINDS], '#p': [key] },
      reconnectDelay: retryDelayMs,
    }]);
    if (!isModuleCall(createdSet) || typeof createdSet.value !== 'object') {
      return fail(SdkResultCode.E_SDK_INTERNAL);
    }
    held.relaySet = createdSet.value;
    if (stopping) return fail(SdkResultCode.E_SDK_CLIENT_STOPPED);

    // (5) The inbound processor, registered before the connection phase.
    let acceptReceipt;
    try {
      acceptReceipt = held.outbox.acceptReceipt;
    } catch {
      return fail(SdkResultCode.E_SDK_INTERNAL);
    }
    const createdReceipts = crossCall(createReceipts, undefined, [{
      identity: ports.identity,
      session: ports.session,
      clock,
      perRelayTimeoutMs: delivery.perRelayTimeoutMs,
      publicKey: key,
      publishReceipt: publishReceiptSeam(held),
      acceptReceipt,
      onEvent: sink,
    }]);
    if (!isModuleCall(createdReceipts)) return fail(SdkResultCode.E_SDK_INTERNAL);
    held.receipts = createdReceipts.value;
    // A rejection (or a returned thenable that fails) is a failed call, as for
    // every other seam call; the value itself is not a lane result.
    const subscribed = await crossBoundaryAsync(held.relaySet, 'onFrame', [(frame) => onInboundFrame(held, frame)], {
      timeoutMs: BOUND.onFrame,
    });
    if (subscribed.settled !== 'value') return fail(SdkResultCode.E_SDK_INTERNAL);
    if (stopping) return fail(SdkResultCode.E_SDK_CLIENT_STOPPED);

    // (6) The connection phase. An out-of-set closed slot anywhere in the
    // resolved value is `E_SDK_UNKNOWN_CODE` (C-SDK section 5.3, checked
    // first); a rejection, a throw or any other value that is not
    // `{ connectedRelays }` with an integer from 0 to the relay count is
    // `{ connectedRelays: 0 }`, a failed connection phase.
    let connectedRelays = 0;
    let startCode = null;
    try {
      const started = valueOfCall(await crossBoundaryAsync(held.relaySet, 'start', [], { timeoutMs: BOUND.relayStart }));
      const scan = scanClosedSlots(started);
      if (scan.unknown) {
        startCode = SdkResultCode.E_SDK_UNKNOWN_CODE;
      } else {
        const fields = !scan.malformed && isPlainObject(started) ? exactFields(started, ['connectedRelays']) : null;
        if (fields !== null && Number.isInteger(fields.connectedRelays)
          && fields.connectedRelays >= 0 && fields.connectedRelays <= relayCount) {
          connectedRelays = fields.connectedRelays;
        }
      }
    } catch {
      connectedRelays = 0;
    }
    if (stopping) return fail(SdkResultCode.E_SDK_CLIENT_STOPPED);
    if (startCode !== null) return fail(startCode);
    if (connectedRelays < 1) return fail(SdkResultCode.E_SDK_NO_RELAY_AVAILABLE);
    clientState = 'RUNNING';
    retainedOutbox = held.outbox;
    recordClientState('RUNNING');
    return success(Object.freeze({ clientState: 'RUNNING', connectedRelays }));
  }

  /* --- methods (C-SDK section 4.2) --------------------------------------- */

  /**
   * The client-state rule of C-SDK section 4.2 for a method that needs
   * `RUNNING`; returns a failure envelope or `null`.
   */
  function admitRunningCall() {
    if (stopping || clientState === 'STOPPED') return failure(SdkResultCode.E_SDK_CLIENT_STOPPED);
    if (clientState !== 'RUNNING') return failure(SdkResultCode.E_SDK_NOT_STARTED);
    return null;
  }

  /**
   * Read `{ deliveryId }` as a closed object with a string id, or `null`.
   *
   * @param {unknown} argument
   * @returns {string | null}
   */
  function readDeliveryIdArgument(argument) {
    try {
      const fields = readClosed(argument, ['deliveryId']);
      if (fields === null || typeof fields.deliveryId !== 'string') return null;
      return fields.deliveryId;
    } catch {
      return null;
    }
  }

  /**
   * The result of one public operation about an item, after the result check.
   *
   * @param {object} checked
   * @param {string | null} itemId the item the value is about, when known
   * @returns {object}
   */
  function publicResult(checked, itemId) {
    if (checked.verdict === 'ok') return success(Object.freeze({ ...checked.value }));
    if (checked.verdict === 'unknown' && itemId !== null) failItemClosed(itemId);
    return failure(verdictCode(checked));
  }

  async function start() {
    try {
      if (stopping || clientState === 'STOPPED') return failure(SdkResultCode.E_SDK_CLIENT_STOPPED);
      if (clientState === 'RUNNING') return failure(SdkResultCode.E_SDK_ALREADY_STARTED);
      if (startInProgress === null) {
        const operation = runStart().catch(() => failure(SdkResultCode.E_SDK_INTERNAL));
        startInProgress = operation;
        operation.then(() => {
          if (startInProgress === operation) startInProgress = null;
        });
      }
      const result = await startInProgress;
      return result.ok === true ? success(Object.freeze({ ...result.value })) : failure(result.code);
    } catch {
      return failure(SdkResultCode.E_SDK_INTERNAL);
    }
  }

  async function send(argument) {
    try {
      const refused = admitRunningCall();
      if (refused !== null) return refused;
      let fields;
      try {
        fields = readClosed(argument, ['recipient', 'payload']);
      } catch {
        fields = null;
      }
      if (fields === null) return failure(SdkResultCode.E_SDK_INVALID_ARGUMENT);
      // Reading the argument may have run caller code (a `Proxy` trap) that
      // stopped the client: the state rule is read again.
      const stoppedMeanwhile = admitRunningCall();
      if (stoppedMeanwhile !== null) return stoppedMeanwhile;
      const payload = fields.payload;
      // The byte count through the intrinsic brand check, never through the
      // value's own or inherited `length`, which a replaced prototype could
      // report smaller than the bytes the copy below takes.
      const byteCount = uint8ArrayByteCount(payload);
      if (byteCount <= 0) return failure(SdkResultCode.E_SDK_INVALID_ARGUMENT);
      if (byteCount > PAYLOAD_MAX_BYTES) return failure(SdkResultCode.E_SDK_PAYLOAD_TOO_LARGE);
      // C-SDK section 4.2: the bytes are copied at the call.
      const plaintext = new Uint8Array(payload);
      if (plaintext.length !== byteCount) return failure(SdkResultCode.E_SDK_INTERNAL);
      const outbox = modules.outbox;
      const returned = valueOfCall(await crossBoundaryAsync(outbox, 'send', [{ recipient: fields.recipient, plaintext }], {
        timeoutMs: BOUND.send,
      }));
      const checked = checkEnvelope(returned, readSendResult, CODES.send, true);
      let itemId = null;
      if (checked.verdict === 'unknown') {
        try {
          itemId = deliveryIdOf(returned.value);
        } catch {
          itemId = null;
        }
      }
      return publicResult(checked, itemId);
    } catch {
      return failure(SdkResultCode.E_SDK_INTERNAL);
    }
  }

  async function getDelivery(argument) {
    try {
      if (clientState === 'CREATED' && !stopping) return failure(SdkResultCode.E_SDK_NOT_STARTED);
      const deliveryId = readDeliveryIdArgument(argument);
      if (deliveryId === null) return failure(SdkResultCode.E_SDK_INVALID_ARGUMENT);
      const outbox = retainedOutbox;
      if (outbox === null) return failure(SdkResultCode.E_SDK_UNKNOWN_DELIVERY);
      const returned = valueOfCall(await crossBoundaryAsync(outbox, 'getDelivery', [{ deliveryId }], {
        timeoutMs: BOUND.getDelivery,
      }));
      const checked = checkEnvelope(returned, readDeliverySnapshot, CODES.getDelivery, true);
      if (checked.verdict === 'ok') return success(checked.value);
      return publicResult(checked, deliveryId);
    } catch {
      return failure(SdkResultCode.E_SDK_INTERNAL);
    }
  }

  async function cancel(argument) {
    try {
      const refused = admitRunningCall();
      if (refused !== null) return refused;
      const deliveryId = readDeliveryIdArgument(argument);
      if (deliveryId === null) return failure(SdkResultCode.E_SDK_INVALID_ARGUMENT);
      // Reading the argument may have run caller code that stopped the client.
      const stoppedMeanwhile = admitRunningCall();
      if (stoppedMeanwhile !== null) return stoppedMeanwhile;
      const outbox = modules.outbox;
      const returned = valueOfCall(await crossBoundaryAsync(outbox, 'cancel', [{ deliveryId }], {
        timeoutMs: BOUND.cancel,
      }));
      return publicResult(checkEnvelope(returned, readCancelResult, CODES.cancel, true), deliveryId);
    } catch {
      return failure(SdkResultCode.E_SDK_INTERNAL);
    }
  }

  async function onEvent(listener) {
    try {
      if (typeof listener !== 'function') return failure(SdkResultCode.E_SDK_INVALID_ARGUMENT);
      const registration = { listener, live: true };
      registrations.push(registration);
      const unsubscribe = () => {
        try {
          if (!registration.live) return undefined;
          registration.live = false;
          registrations = registrations.filter((entry) => entry !== registration);
        } catch {
          // never throws
        }
        return undefined;
      };
      return success(Object.freeze({ unsubscribe }));
    } catch {
      return failure(SdkResultCode.E_SDK_INTERNAL);
    }
  }

  async function shutdown() {
    if (stopping || clientState === 'STOPPED') return failure(SdkResultCode.E_SDK_CLIENT_STOPPED);
    // Step (1), synchronous at the call.
    stopping = true;
    let audience = [];
    try {
      audience = registrations.slice();
    } catch {
      audience = [];
    }
    shutdownAudience = audience;
    const held = modules;
    let outboxStop = null;
    if (held !== null) {
      // Each call is synchronous at the call; a fault in one never prevents
      // the next (C-SDK section 4.2).
      if (held.receipts !== null) crossBoundary(held.receipts, 'shutdown', []);
      if (held.relaySet !== null) crossBoundary(held.relaySet, 'freeze', []);
      if (held.outbox !== null) {
        const stop = crossBoundary(held.outbox, 'shutdown', []);
        outboxStop = stop.settled === 'value' ? stop.value : null;
      }
    }

    let lost = null;
    try {
      // Step (2): a start() in progress resolves first.
      if (startInProgress !== null) {
        try {
          await startInProgress;
        } catch {
          // ignored
        }
      }
      // Steps (3) and (4): inbound drain, the rest of the outbox stop, then
      // the relay-set disposal once every LOST_ON_SHUTDOWN dispatch has run.
      // Each wait on a seam has its host-time backstop (`BOUND`): a seam that
      // never settles cannot hold the stop open.
      if (held !== null && held.receipts !== null) {
        // Concurrent under the same host backstop. drained() itself uses the
        // one drain bound armed synchronously by receipts.shutdown().
        const waits = await Promise.all([
          crossBoundaryAsync(held.receipts, 'settled', [], { timeoutMs: BOUND.settled }),
          crossBoundaryAsync(held.receipts, 'drained', [], { timeoutMs: BOUND.settled }),
        ]);
        const drained = waits[1];
        if (drained.settled === 'value' && scanClosedSlots(drained.value).unknown) {
          sink({ kind: 'INBOUND_DISCARDED', code: SdkResultCode.E_SDK_UNKNOWN_CODE });
        }
      }
      if (outboxStop !== null) {
        const stopped = valueOfCall(await adoptReturned(outboxStop, { timeoutMs: BOUND.outboxStop }));
        const checked = checkEnvelope(stopped, (value) => {
          const fields = exactFields(value, ['clientState', 'lost']);
          if (fields === null || fields.clientState !== 'STOPPED') return null;
          if (!Number.isSafeInteger(fields.lost) || fields.lost < 0) return null;
          return fields;
        }, CODES.outboxShutdown, true);
        if (checked.verdict === 'ok') lost = checked.value.lost;
      }
      // Every port call still registered at the boundary, each bounded by the
      // port-call timeout, has settled before the relay set is disposed.
      await portCallsSettled();
      await dispatchQueueEmpty();
      if (held !== null) await disposeRelaySet(held);
    } catch {
      // Faults never prevent the effects of the stop (C-SDK section 4.2).
    }

    // Step (5).
    if (lost === null) lost = held !== null && held.outbox !== null ? lostEventsDuringShutdown : 0;
    clientState = 'STOPPED';
    try {
      recordClientState('STOPPED');
      await dispatchQueueEmpty();
    } catch {
      // ignored
    }
    for (const registration of audience) registration.live = false;
    registrations = registrations.filter((registration) => registration.live);
    if (held !== null) {
      held.relaySet = null;
      held.receipts = null;
    }
    modules = null;
    ports.storage = null;
    ports.session = null;
    ports.identity = null;
    clock = null;
    random = null;
    return success(Object.freeze({ clientState: 'STOPPED', lost }));
  }

  return Object.freeze({ start, send, getDelivery, cancel, onEvent, shutdown });
}
