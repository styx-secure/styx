/**
 * I-ACK -- inbound delivery receipts, acknowledgements and duplicate handling
 * of the M3 early-lane delivery layer (C-DLV sections 6.1, 6.3, 7 and 8),
 * behind the injected ports of C-SDK section 8.
 *
 * This module is SDK-internal (C-DLV section 9). It owns the inbound side: the
 * common structure rules of section 6.1 as applied to inbound events, the
 * receipt of section 6.3, the inbound validation of section 7 and the
 * duplicate handling of section 8. It owns no item and no relay: the item-side
 * conditions of section 7.3 are handed to the caller's acknowledgement seam,
 * which is card I-QUEUE's `acceptReceipt`, and the receipt of section 7.2 is
 * handed to the caller's publication seam, used only through its public
 * export. It adds no bound, no state, no ordering rule and no code of its own:
 * every value below is the one C-DLV fixes (inbound pending bound 1 024,
 * inbound duplicate window 4 096), a member of a closed set of C-SDK (section
 * 5.2 codes, section 5.1 envelope, section 6.1 states, section 4.1 receipt
 * modes, section 7 event kinds and fields), the interface version string, or a
 * value C-DLV fixes in its text.
 *
 * Nothing a caller supplies escapes as an exception. Every read of an injected
 * port happens inside a guarded path, so a port that is absent, is not a
 * function, throws when read or throws when called, and a value that does not
 * settle within its port-call timeout, are all mapped to the closed-set code
 * C-DLV and C-SDK fix for them. C-SDK section 5.2 closes `INBOUND_DISCARDED` to
 * three members -- `E_SDK_INBOUND_INVALID`, `E_SDK_SESSION_FAILED` and
 * `E_SDK_UNKNOWN_CODE` -- so the inbound path has no `E_SDK_INTERNAL` surface;
 * the two port faults that carry no code at all are the receipt's clock
 * reading and its signature, which C-DLV section 6.1 and section 7.2 settle as
 * "no receipt is sent".
 *
 * The public objects this module returns and the events it hands out are
 * frozen and carry exactly the members this card's contract lists. A receipt
 * is a fresh frozen copy, so no caller can watch an internal value change or
 * forge one.
 */

import { sha256 } from '@noble/hashes/sha256';
import { schnorr } from '@noble/curves/secp256k1';

import { base64ToBytes, bytesToHex, hexToBytes, randomBytes, utf8Encode } from '../../utils.js';

/* ------------------------------------------------------------------------- *
 * Fixed values and closed sets, all from C-DLV section 3, C-DLV sections 6.1
 * to 6.3, C-SDK section 4.1, C-SDK section 5.2 and C-SDK section 7. They are
 * carried, not invented.
 * ------------------------------------------------------------------------- */

/** C-DLV section 3: the inbound pending bound, 1 024 frames per client. */
const INBOUND_PENDING_BOUND = 1024;

/** C-DLV section 3: the inbound duplicate window, 4 096 event ids per client. */
const INBOUND_DUPLICATE_WINDOW = 4096;

/** C-DLV section 6.1: the message event kind. */
const EVENT_KIND_MESSAGE = 4741;

/** C-DLV section 6.3: the receipt event kind. */
const EVENT_KIND_RECEIPT = 4742;

/** C-DLV section 6.1/6.2/6.3: the interface version string of the `v` tag. */
const INTERFACE_VERSION = 'styx-m3-sdk/0.1.0-experimental';

/** C-DLV section 6.1: the seven keys of every SDK-internal event, in no order. */
const EVENT_KEYS = Object.freeze(['id', 'pubkey', 'created_at', 'kind', 'tags', 'content', 'sig']);

/** C-DLV section 7.1: the frames this module queues, on the decoded array. */
const FRAME_KIND_EVENT = 'EVENT';

/** C-SDK section 7: the two event kinds this module emits. */
const EVENT_KIND_MESSAGE_RECEIVED = 'MESSAGE_RECEIVED';
const EVENT_KIND_INBOUND_DISCARDED = 'INBOUND_DISCARDED';

/** C-SDK section 5.2: the three codes admitted in `INBOUND_DISCARDED`. */
const INBOUND_DISCARD_CODES = Object.freeze([
  'E_SDK_INBOUND_INVALID',
  'E_SDK_SESSION_FAILED',
  'E_SDK_UNKNOWN_CODE',
]);
const DISCARD_INVALID = 'E_SDK_INBOUND_INVALID';
const DISCARD_SESSION_FAILED = 'E_SDK_SESSION_FAILED';
const DISCARD_UNKNOWN_CODE = 'E_SDK_UNKNOWN_CODE';

/**
 * C-SDK section 5.2: the closed result-code set. A code a lane module yields
 * outside this set is `E_SDK_UNKNOWN_CODE` (C-DLV section 4.5); a code inside
 * it is the module's own answer and is not an unknown value.
 */
const SDK_RESULT_CODES = new Set([
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

/**
 * C-SDK section 6.1: the closed delivery-state enumeration, read only as a
 * slot of a port return this module inspects.
 */
const DELIVERY_STATES = new Set([
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

/** C-SDK section 6.1: the closed relay-outcome enumeration. */
const RELAY_OUTCOMES = new Set(['PENDING', 'ACCEPTED', 'REJECTED', 'TIMED_OUT', 'UNREACHABLE']);

/** C-SDK section 4.1: the closed receipt-mode set. */
const RECEIPT_MODES = new Set(['RELAY_ACCEPTANCE_ONLY', 'RECIPIENT_RECEIPT']);

/**
 * C-DLV section 4.5: the `lastCode` values a lane decision or an item failure
 * carries — the `null` of exhaustion or of the deadline, and the four codes the
 * document fixes.
 */
const ITEM_LAST_CODES = new Set([
  null,
  'E_SDK_STORAGE_FAILED',
  'E_SDK_IDENTITY_FAILED',
  'E_SDK_INTERNAL',
  'E_SDK_UNKNOWN_CODE',
]);

/**
 * C-DLV section 4.5 and C-SDK section 5.3: the closed slots of a PORT RETURN.
 * The five slots the card's contract names -- `code`, `state`, `outcome`,
 * `lastCode` and `receiptMode` -- are each read on ANY object return, plain or
 * not: a `Uint8Array` signature that carries one violates its closed slot
 * exactly as a plain return does. A return that carries one of them outside its
 * closed set is an unknown value and is `E_SDK_UNKNOWN_CODE`, ahead of every
 * other code the caller could fix for the same call. Card I-QUEUE's
 * `closedSlotViolation` is the model.
 *
 * @param {unknown} value
 * @returns {string|null} the name of the violated slot, or null
 */
function closedSlotViolation(value) {
  if (value === null || typeof value !== 'object') return null;
  for (const [name, allowed] of [
    ['code', SDK_RESULT_CODES],
    ['state', DELIVERY_STATES],
    ['outcome', RELAY_OUTCOMES],
    ['lastCode', ITEM_LAST_CODES],
    ['receiptMode', RECEIPT_MODES],
  ]) {
    let present;
    try {
      present = Object.prototype.hasOwnProperty.call(value, name);
    } catch {
      return name;
    }
    if (!present) continue;
    let slot;
    try {
      slot = value[name];
    } catch {
      return name;
    }
    if (!allowed.has(slot)) return name;
  }
  return null;
}

/**
 * C-SDK section 7: a promise returned by a sink or a seam that rejects is
 * caught and ignored exactly as a thrown exception is, so the rejection is
 * consumed instead of surfacing as an unhandled rejection.
 *
 * @param {Promise<unknown>} returned
 */
function consume(returned) {
  returned.then(undefined, () => {
    // The rejection is caught and ignored (C-SDK section 7).
  });
}

/** C-SDK section 5.2: the one code a second `shutdown()` returns. */
const CODE_CLIENT_STOPPED = 'E_SDK_CLIENT_STOPPED';

/** C-DLV section 7.1: the fixed shapes of the tags of sections 6.2 and 6.3. */
const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;
const HEX32 = /^[0-9a-f]{32}$/;

/** C-DLV section 6.3: the receipt's `e` tag names the original message id. */
const TAG_P = 'p';
const TAG_V = 'v';
const TAG_N = 'n';
const TAG_E = 'e';
const TAG_R = 'r';

/* ------------------------------------------------------------------------- *
 * Guarded helpers. A port read, a port call and a value that does not settle
 * within its bound never escape (C-SDK section 8, C-DLV section 4.5).
 * ------------------------------------------------------------------------- */

/** @returns {boolean} whether `value` is a thenable, without trusting it. */
function isThenable(value) {
  if (value === null || typeof value !== 'object') return false;
  let then;
  try {
    then = value.then;
  } catch {
    return true;
  }
  return typeof then === 'function';
}

/**
 * Settle `value` within `timeoutMs` of host time (C-SDK section 8: the
 * port-call timeout uses the host `setTimeout`, never the clock port).
 *
 * @param {unknown} value
 * @param {number} timeoutMs
 * @returns {Promise<{ settled: boolean, rejected: boolean, value?: unknown }>}
 */
function settleWithin(value, timeoutMs) {
  if (!isThenable(value)) {
    return Promise.resolve({ settled: true, rejected: false, value });
  }
  return new Promise((resolve) => {
    let done = false;
    const timer = setTimeout(() => {
      if (done) return;
      done = true;
      resolve({ settled: false, rejected: false });
    }, timeoutMs);
    Promise.resolve(value).then(
      (settled) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        resolve({ settled: true, rejected: false, value: settled });
      },
      () => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        resolve({ settled: true, rejected: true });
      },
    );
  });
}

/**
 * Read and call one method of an injected port (C-SDK section 8): an absent
 * port, a non-function, a getter that throws, a method that throws and a value
 * that does not settle within the port-call timeout are all reported the same
 * way and never escape.
 *
 * @param {unknown} port
 * @param {string} name
 * @param {unknown[]} args
 * @param {number} timeoutMs
 * @param {() => boolean} [isStopped] the terminal-stop predicate of C-DLV
 *   section 4.6 step (1)
 * @returns {Promise<{ ok: true, value: unknown } | { ok: false, stopped?: boolean }>}
 */
async function callPort(port, name, args, timeoutMs, isStopped) {
  let method;
  try {
    method = port === null || port === undefined ? undefined : port[name];
  } catch {
    return { ok: false };
  }
  /* C-DLV section 4.6 step (1): the lookup is itself untrusted -- a getter
   * may have called `shutdown()` -- so no invocation begins after the stop. */
  if (typeof isStopped === 'function' && isStopped() === true) return { ok: false, stopped: true };
  if (typeof method !== 'function') return { ok: false };
  let returned;
  try {
    returned = method.apply(port, args);
  } catch {
    return { ok: false };
  }
  const settled = await settleWithin(returned, timeoutMs);
  if (!settled.settled || settled.rejected) return { ok: false };
  return { ok: true, value: settled.value };
}

/**
 * Read and call one method of an injected port synchronously (C-SDK section
 * 8.4: clock and random methods are called synchronously, and a promise or
 * other non-synchronous return is an invalid value).
 *
 * @param {unknown} port
 * @param {string} name
 * @param {unknown[]} [args]
 * @returns {{ ok: true, value: unknown } | { ok: false }}
 */
function callSyncPort(port, name, args = []) {
  let method;
  try {
    method = port === null || port === undefined ? undefined : port[name];
  } catch {
    return { ok: false };
  }
  if (typeof method !== 'function') return { ok: false };
  let value;
  try {
    value = method.apply(port, args);
  } catch {
    return { ok: false };
  }
  let thenable;
  try {
    thenable = isThenable(value);
  } catch {
    return { ok: false };
  }
  if (thenable) {
    /* C-SDK section 8.4: a promise from a synchronous port is an invalid
     * value, and the rejection it carries is consumed, never left
     * unhandled (C-SDK section 7). */
    try {
      consume(Promise.resolve(value));
    } catch {
      // The invalid return is a failure; its rejection never surfaces.
    }
    return { ok: false };
  }
  return { ok: true, value };
}

/**
 * C-DLV section 7.1 step 1: a plain object. A JSON-decoded object has
 * `Object.prototype`; a null-prototype object is accepted too, as the record
 * of card I-RELAY is built that way.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  try {
    const proto = Object.getPrototypeOf(value);
    return proto === Object.prototype || proto === null;
  } catch {
    return false;
  }
}

/**
 * C-DLV section 7.1 step 1: a plain object with exactly the seven keys of
 * section 6.1.
 *
 * @param {object} value
 * @returns {boolean}
 */
function hasExactlyEventKeys(value) {
  let keys;
  try {
    keys = Object.keys(value);
  } catch {
    return false;
  }
  if (keys.length !== EVENT_KEYS.length) return false;
  for (const key of EVENT_KEYS) if (!Object.prototype.hasOwnProperty.call(value, key)) return false;
  return true;
}

/**
 * C-DLV section 7.1 step 1: the value of one field, read guarded, so an accessor
 * that throws fails validation instead of escaping.
 *
 * @param {object} source
 * @param {string} name
 * @returns {{ ok: true, value: unknown } | { ok: false }}
 */
function readField(source, name) {
  try {
    return { ok: true, value: source[name] };
  } catch {
    return { ok: false };
  }
}

/**
 * C-DLV section 7.1 step 1: `tags` is an array of arrays of strings.
 *
 * @param {unknown} tags
 * @returns {boolean}
 */
function isTagList(tags) {
  if (!Array.isArray(tags)) return false;
  for (const tag of tags) {
    if (!Array.isArray(tag)) return false;
    for (const part of tag) if (typeof part !== 'string') return false;
  }
  return true;
}

/* ------------------------------------------------------------------------- *
 * The inbound processor.
 * ------------------------------------------------------------------------- */

/**
 * Build the inbound processor of one client.
 *
 * `options` is exactly: `identity` -- the signing and identity port of C-SDK
 * section 8.3; `session` -- the session port of C-SDK section 8.2; `clock` --
 * the clock port of C-SDK section 8.4, read only for the `created_at` of the
 * receipt of section 6.3; `perRelayTimeoutMs` -- the effective per-relay
 * timeout of C-SDK section 4.1, whose port-call timeout is
 * `floor(perRelayTimeoutMs / 2)`; `publishReceipt` -- the inbound publication
 * seam of C-DLV section 7.2; `acceptReceipt` -- the item-side seam of C-DLV
 * section 7.3, which is card I-QUEUE's `acceptReceipt`; and `onEvent` -- the
 * sink for the frozen `MESSAGE_RECEIVED` and `INBOUND_DISCARDED` events of
 * C-SDK section 7.
 *
 * This function never throws, for any `options`: a fault while reading them is
 * remembered as an internal fault, and every operation then answers as if the
 * affected port were absent.
 *
 * @param {object} options
 * @returns {{ ingest: Function, shutdown: Function }}
 */
export function createReceipts(options) {
  /* --- options, read once, guarded ------------------------------------- */
  let read = null;
  try {
    const source = options === null || options === undefined ? {} : options;
    read = {
      identity: source.identity,
      session: source.session,
      clock: source.clock,
      perRelayTimeoutMs: source.perRelayTimeoutMs,
      publishReceipt: source.publishReceipt,
      acceptReceipt: source.acceptReceipt,
      onEvent: source.onEvent,
    };
  } catch {
    read = null;
  }

  /** C-DLV section 3: the port-call timeout of this module. */
  const portCallTimeoutMs = (() => {
    if (read === null) return 0;
    let value;
    try {
      value = read.perRelayTimeoutMs;
    } catch {
      return 0;
    }
    if (!Number.isSafeInteger(value) || value < 1) return 0;
    return Math.floor(value / 2);
  })();

  const queue = [];
  const windowIds = new Set();
  const windowOrder = [];
  let processing = false;
  let stopped = false;
  let publicKeyRead = false;
  let publicKey = null;
  let publicKeyUnknown = false;

  const failure = (code) => Object.freeze({ ok: false, code });
  const success = (value) => Object.freeze({ ok: true, value: Object.freeze(value) });

  /* --- events to the caller -------------------------------------------- */

  /**
   * C-SDK section 7: hand one frozen event to the sink. A sink that is absent,
   * is not a function or throws changes nothing.
   *
   * @param {object} event
   */
  function emit(event) {
    let sink;
    try {
      sink = read === null ? undefined : read.onEvent;
    } catch {
      return;
    }
    if (typeof sink !== 'function') return;
    try {
      const returned = sink(Object.freeze(event));
      if (isThenable(returned)) consume(returned);
    } catch {
      // C-SDK section 7: a listener fault is caught and ignored.
    }
  }

  /** C-SDK section 7: `INBOUND_DISCARDED` with one of the three admitted codes. */
  function discard(code) {
    emit({ kind: EVENT_KIND_INBOUND_DISCARDED, code });
  }

  /* --- the module-mandated identity key reading ------------------------ */

  /**
   * C-DLV section 7.1 step 3: the `p` tag equals the client's own public key.
   * The reading is taken at most once for this module's lifetime and shared
   * across concurrent validations, exactly as card I-QUEUE R1 (c) fixes it;
   * card I-SDK replaces it with the value `start()` caches for the client's
   * lifetime (C-SDK section 8.3). A return carrying a closed slot outside its
   * closed set is `E_SDK_UNKNOWN_CODE` ahead of every other code (C-DLV
   * section 4.5); a reading that faults, never settles or is a well-formed
   * value that is not a lowercase 64-hex string is remembered as an absent
   * key, so no `p` tag can equal it and every frame fails step 3.
   *
   * @returns {Promise<{ key: string|null, unknown: boolean }>}
   */
  async function ownPublicKey() {
    if (publicKeyRead) return { key: publicKey, unknown: publicKeyUnknown };
    publicKeyRead = true;
    const called = await callPort(read === null ? null : read.identity, 'getPublicKey', [],
      portCallTimeoutMs, () => stopped);
    if (!called.ok) {
      publicKey = null;
      publicKeyUnknown = false;
      return { key: null, unknown: false };
    }
    /* C-DLV section 4.5, ahead of every other code: a return that carries a
     * closed slot outside its closed set is an unknown value, not a malformed
     * key (C-SDK section 5.3). */
    if (closedSlotViolation(called.value) !== null) {
      publicKey = null;
      publicKeyUnknown = true;
      return { key: null, unknown: true };
    }
    if (typeof called.value !== 'string' || !HEX64.test(called.value)) {
      publicKey = null;
      publicKeyUnknown = false;
      return { key: null, unknown: false };
    }
    publicKey = called.value;
    publicKeyUnknown = false;
    return { key: publicKey, unknown: false };
  }

  /* --- C-DLV section 7.1: validation ----------------------------------- */

  /**
   * C-DLV section 7.1: validate one decoded frame against the five steps, in
   * their order. The first failure is `E_SDK_INBOUND_INVALID`.
   *
   * @param {unknown} data the decoded frame array
   * @returns {Promise<{ ok: true, kind: number, event: object }
   *   | { ok: false, unknown?: boolean }>} `unknown: true` when the failure is
   *   an unknown closed slot of C-DLV section 4.5 rather than a bad structure
   */
  async function validateEvent(data) {
    /* Step 1: a plain object with exactly the seven keys of section 6.1. */
    if (!isPlainObject(data) || !hasExactlyEventKeys(data)) return { ok: false };
    const id = readField(data, 'id');
    const pubkey = readField(data, 'pubkey');
    const createdAt = readField(data, 'created_at');
    const kind = readField(data, 'kind');
    const tagsField = readField(data, 'tags');
    const content = readField(data, 'content');
    const sig = readField(data, 'sig');
    if (!id.ok || !pubkey.ok || !createdAt.ok || !kind.ok || !tagsField.ok || !content.ok || !sig.ok) {
      return { ok: false };
    }
    if (typeof id.value !== 'string' || !HEX64.test(id.value)) return { ok: false };
    if (typeof sig.value !== 'string' || !HEX128.test(sig.value)) return { ok: false };
    if (typeof pubkey.value !== 'string' || !HEX64.test(pubkey.value)) return { ok: false };
    if (!Number.isSafeInteger(createdAt.value) || createdAt.value < 0) return { ok: false };
    if (!Number.isSafeInteger(kind.value)) return { ok: false };
    if (!isTagList(tagsField.value)) return { ok: false };
    if (typeof content.value !== 'string') return { ok: false };

    /* Step 2: `kind` is 4741 or 4742 (C-DLV section 7.1 step 2). */
    if (kind.value !== EVENT_KIND_MESSAGE && kind.value !== EVENT_KIND_RECEIPT) return { ok: false };

    /* C-DLV section 7.1 step 3 reads the tags several times across awaited
     * boundaries, and section 7.3 hands `eventId` on afterwards, so the inbound
     * array is copied once, here, and never read again: a caller that mutates
     * its frame after `ingest` cannot move a value this module decides on. */
    let safeTags;
    try {
      safeTags = tagsField.value.map((tag) => Object.freeze(tag.slice()));
    } catch {
      return { ok: false };
    }

    /* Step 3: the tags are exactly the closed tag list of section 6.2 or 6.3,
     * with every value in the form given there, the `p` tag equal to the
     * client's own public key, the `v` tag equal to the version string, and,
     * for kind 4742, `content` the empty string. */
    const reading = await ownPublicKey();
    const own = reading.key;
    const tags = safeTags;
    if (own === null) return { ok: false, unknown: reading.unknown };
    if (kind.value === EVENT_KIND_MESSAGE) {
      if (tags.length !== 3 && tags.length !== 4) return { ok: false };
      if (!tagIs(tags[0], TAG_P, own)) return { ok: false };
      if (!tagIs(tags[1], TAG_V, INTERFACE_VERSION)) return { ok: false };
      if (!namedPair(tags[2], TAG_N) || !HEX32.test(tags[2][1])) return { ok: false };
      if (tags.length === 4) {
        if (!namedPair(tags[3], TAG_R) || tags[3][1] !== '1') return { ok: false };
      }
    } else {
      if (tags.length !== 4) return { ok: false };
      if (!tagIs(tags[0], TAG_P, own)) return { ok: false };
      if (!namedPair(tags[1], TAG_E) || !HEX64.test(tags[1][1])) return { ok: false };
      if (!tagIs(tags[2], TAG_V, INTERFACE_VERSION)) return { ok: false };
      if (!namedPair(tags[3], TAG_N) || !HEX32.test(tags[3][1])) return { ok: false };
      if (content.value !== '') return { ok: false };
    }

    /* Step 4: `id` equals the recomputed id of section 6.1. */
    const recomputed = recomputeId(pubkey.value, createdAt.value, kind.value, tags, content.value);
    if (recomputed === null || recomputed !== id.value) return { ok: false };

    /* Step 5: the signature verifies over the id (BIP-340, C-DLV section 6.1). */
    if (!verifySignature(sig.value, id.value, pubkey.value)) return { ok: false };

    return {
      ok: true,
      kind: kind.value,
      event: {
        id: id.value,
        pubkey: pubkey.value,
        createdAt: createdAt.value,
        tags,
        content: content.value,
      },
    };
  }

  /* --- C-DLV section 8: the duplicate window --------------------------- */

  /** @param {string} id @returns {boolean} whether the id is in the window. */
  function isDuplicate(id) {
    return windowIds.has(id);
  }

  /** C-DLV section 8: insert one valid id, first in, first out, window 4096. */
  function remember(id) {
    windowIds.add(id);
    windowOrder.push(id);
    while (windowOrder.length > INBOUND_DUPLICATE_WINDOW) {
      const evicted = windowOrder.shift();
      windowIds.delete(evicted);
    }
  }

  /* --- C-DLV sections 6.1, 6.3, 7.2: the receipt ------------------------ */

  /**
   * C-DLV section 6.1: the id of an event is the lowercase hex of
   * `sha256(utf8Encode(JSON.stringify([0, pubkey, created_at, kind, tags,
   * content])))`. A value the digest cannot cover is `null`.
   *
   * @returns {string|null}
   */
  function recomputeId(pubkey, createdAt, kind, tags, content) {
    try {
      const digest = sha256(utf8Encode(JSON.stringify([0, pubkey, createdAt, kind, tags, content])));
      return bytesToHex(digest);
    } catch {
      return null;
    }
  }

  /**
   * C-DLV section 7.1 step 5: `schnorr.verify` over the digest, never throwing.
   *
   * @returns {boolean}
   */
  function verifySignature(sig, id, pubkey) {
    try {
      return schnorr.verify(hexToBytes(sig), hexToBytes(id), hexToBytes(pubkey)) === true;
    } catch {
      return false;
    }
  }

  /**
   * C-DLV section 6.3: build and sign the receipt of one message event. The
   * clock reading fixes `created_at` as `floor(clock.now() / 1000)`; a reading
   * that faults or is negative or not a safe integer after the division means
   * the structure cannot be built (C-DLV section 6.1) and no receipt is sent.
   * A signature that is not a 64-byte `Uint8Array` or a fault means no receipt
   * either (C-DLV section 7.2).
   *
   * @param {{ sender: string, eventId: string }} message
   * @param {string} own the client's own public key
   * @returns {Promise<object|null>}
   */
  async function buildAndSignReceipt(message, own) {
    const reading = callSyncPort(read === null ? null : read.clock, 'now');
    if (!reading.ok) return { ok: false };
    /* C-DLV section 4.5 ahead of the number, finite, negative and safe-integer
     * checks: a clock return that carries a closed slot outside its closed set
     * is an unknown value, not a bad reading (C-SDK section 5.3). */
    if (closedSlotViolation(reading.value) !== null) return { ok: false, unknown: true };
    if (typeof reading.value !== 'number' || !Number.isFinite(reading.value)) return { ok: false };
    /* C-DLV section 6.1: a negative reading builds no structure, whatever the
     * division of C-SDK section 8.4 would make of it. */
    if (reading.value < 0) return { ok: false };
    /* C-SDK section 8.4: `now()` reads milliseconds and may be fractional. */
    const createdAt = Math.floor(reading.value / 1000);
    if (!Number.isSafeInteger(createdAt) || createdAt < 0) return { ok: false };

    let nonce;
    try {
      nonce = bytesToHex(randomBytes(16));
    } catch {
      return { ok: false };
    }
    if (!HEX32.test(nonce)) return { ok: false };

    const tags = Object.freeze([
      Object.freeze([TAG_P, message.sender]),
      Object.freeze([TAG_E, message.eventId]),
      Object.freeze([TAG_V, INTERFACE_VERSION]),
      Object.freeze([TAG_N, nonce]),
    ]);
    const content = '';
    const id = recomputeId(own, createdAt, EVENT_KIND_RECEIPT, tags, content);
    if (id === null) return { ok: false };
    /* C-DLV section 4.6 step (1): no port call starts after the stop. */
    if (stopped) return { ok: false };
    const signed = await callPort(read === null ? null : read.identity, 'sign',
      [{ digest: hexToBytes(id) }], portCallTimeoutMs, () => stopped);
    if (!signed.ok) return { ok: false };
    /* C-DLV section 4.5 ahead of every other code: a signature return that
     * carries a closed slot outside its closed set is an unknown value, not a
     * bad signature (C-SDK section 5.3). */
    if (closedSlotViolation(signed.value) !== null) return { ok: false, unknown: true };
    if (!(signed.value instanceof Uint8Array) || signed.value.length !== 64) return { ok: false };
    return { ok: true, receipt: Object.freeze({
      id,
      pubkey: own,
      created_at: createdAt,
      kind: EVENT_KIND_RECEIPT,
      tags,
      content,
      sig: bytesToHex(signed.value),
    }) };
  }

  /**
   * C-DLV section 7.2: publish one receipt on every connected current pool
   * through the caller's seam. A fault changes nothing and no code follows.
   *
   * @param {object} receipt
   */
  function publishReceipt(receipt) {
    let seam;
    try {
      seam = read === null ? undefined : read.publishReceipt;
    } catch {
      return;
    }
    if (typeof seam !== 'function') return;
    try {
      const returned = seam(receipt);
      if (isThenable(returned)) consume(returned);
    } catch {
      // Receipt publication is best effort (C-DLV section 7.2).
    }
  }

  /* --- C-DLV sections 7.1 and 7.2: one frame ---------------------------- */

  /**
   * C-DLV section 7.2: decode the content with `base64ToBytes`. A decoding
   * failure and an empty result are `E_SDK_INBOUND_INVALID`.
   *
   * @param {string} content
   * @returns {Uint8Array|null}
   */
  function decodeContent(content) {
    let bytes;
    try {
      bytes = base64ToBytes(content);
    } catch {
      return null;
    }
    if (!(bytes instanceof Uint8Array) || bytes.length === 0) return null;
    return bytes;
  }

  /**
   * C-DLV section 7.2: decode the content and open it through the session
   * port. A decoding failure or an empty result is `E_SDK_INBOUND_INVALID`; a
   * failure or a malformed return of the port is `E_SDK_SESSION_FAILED`.
   * Success emits `MESSAGE_RECEIVED` with a fresh copy of the plaintext.
   *
   * @param {object} event the validated kind-4741 event
   * @returns {Promise<string|null>} the message's sender, or null
   */
  async function openMessage(event) {
    const ciphertext = decodeContent(event.content);
    if (ciphertext === null) {
      discard(DISCARD_INVALID);
      return null;
    }
    /* C-DLV section 4.6 step (1): no port call starts after the stop. */
    if (stopped) return null;
    const opened = await callPort(read === null ? null : read.session, 'open',
      [{ sender: event.pubkey, ciphertext }], portCallTimeoutMs, () => stopped);
    /* ... and no event follows it either. */
    if (stopped) return null;
    if (!opened.ok) {
      discard(DISCARD_SESSION_FAILED);
      return null;
    }
    /* C-DLV section 4.5, as C-DLV section 7.2's "(subject to section 4.5)"
     * requires: the unknown-value rule runs first and takes precedence over
     * every other code this module could fix for the same frame. */
    if (closedSlotViolation(opened.value) !== null) {
      /* C-DLV section 4.6 step (1): the read above is untrusted, so the stop
       * is re-checked before the event of this structure is emitted. */
      if (stopped) return null;
      discard(DISCARD_UNKNOWN_CODE);
      return null;
    }
    /* C-SDK section 8: the exact success shape is the single key `plaintext`. */
    let owned;
    try {
      owned = isPlainObject(opened.value) ? Object.keys(opened.value) : null;
    } catch {
      owned = null;
    }
    if (owned === null || owned.length !== 1) {
      if (stopped) return null;
      discard(DISCARD_SESSION_FAILED);
      return null;
    }
    const plaintext = readField(opened.value, 'plaintext');
    /* C-SDK section 8 gives `open` a `Uint8Array` and no non-empty rule
     * of the kind it gives `seal`, so the empty one is a success. */
    if (!plaintext.ok || !(plaintext.value instanceof Uint8Array)) {
      discard(DISCARD_SESSION_FAILED);
      return null;
    }
    /* C-DLV section 4.6 step (1): no event begins after the stop. */
    if (stopped) return null;
    emit({
      kind: EVENT_KIND_MESSAGE_RECEIVED,
      sender: event.pubkey,
      payload: new Uint8Array(plaintext.value),
    });
    return event.pubkey;
  }

  /**
   * C-DLV section 7.3: hand one validated kind-4742 acknowledgement to the
   * item-side seam, which owns every item condition and the transition. The
   * seam's refusal is ignored without an event, exactly as the last sentence
   * of section 7.3 states. Its result is read only for the unknown-value rule
   * of C-DLV section 4.5: a code outside C-SDK section 5.2's closed set, and a
   * seam that is absent, is not a function, throws or answers outside the
   * envelope shape of C-SDK section 5.1, are `E_SDK_UNKNOWN_CODE`.
   *
   * @param {object} event the validated kind-4742 event
   */
  async function acknowledge(event) {
    let seam;
    try {
      seam = read === null ? undefined : read.acceptReceipt;
    } catch {
      discard(DISCARD_UNKNOWN_CODE);
      return;
    }
    if (typeof seam !== 'function') {
      discard(DISCARD_UNKNOWN_CODE);
      return;
    }
    /* C-DLV section 4.6 step (1): no seam call starts after the stop. */
    if (stopped) return;
    const called = await callPort({ acceptReceipt: seam }, 'acceptReceipt',
      [{ eventId: event.tags[1][1], recipient: event.pubkey }], portCallTimeoutMs, () => stopped);
    /* ... and no event follows it either. */
    if (stopped) return;
    if (!called.ok) {
      discard(DISCARD_UNKNOWN_CODE);
      return;
    }
    const envelope = called.value;
    /* C-SDK section 5.1: two envelopes, and exactly their own keys — the
     * acceptance `{ ok: true, value }` and the refusal `{ ok: false, code }`
     * — and C-DLV section 4.5 makes a return that is not that exact shape a
     * malformed value, so the freeze C-SDK section 5.1 requires is read. */
    let frozen;
    try {
      frozen = Object.isFrozen(envelope) === true;
    } catch {
      frozen = false;
    }
    if (!frozen) {
      if (stopped) return;
      discard(DISCARD_UNKNOWN_CODE);
      return;
    }
    let keys;
    try {
      keys = isPlainObject(envelope) ? Object.keys(envelope).slice().sort().join(',') : null;
    } catch {
      keys = null;
    }
    const okField = keys === null ? { ok: false } : readField(envelope, 'ok');
    if (!okField.ok || typeof okField.value !== 'boolean') {
      if (stopped) return;
      discard(DISCARD_UNKNOWN_CODE);
      return;
    }
    if (okField.value === true) {
      if (keys !== 'ok,value') {
        if (stopped) return;
        discard(DISCARD_UNKNOWN_CODE);
        return;
      }
      /* An acceptance envelope that also carries a closed slot outside its
       * closed set is an unknown value (C-DLV section 4.5). */
      const violation = closedSlotViolation(envelope);
      if (stopped) return;
      if (violation !== null) discard(DISCARD_UNKNOWN_CODE);
      return;
    }
    if (keys !== 'code,ok') {
      if (stopped) return;
      discard(DISCARD_UNKNOWN_CODE);
      return;
    }
    const codeField = readField(envelope, 'code');
    if (!codeField.ok || typeof codeField.value !== 'string' || !SDK_RESULT_CODES.has(codeField.value)) {
      if (stopped) return;
      discard(DISCARD_UNKNOWN_CODE);
    }
  }

  /**
   * C-DLV sections 7.1, 7.2, 7.3 and 8: process one frame that is already out
   * of the queue. Validation first, the duplicate check of section 8 next, the
   * window insertion before the session-port call, then the message path or
   * the acknowledgement path.
   *
   * @param {object} frame
   */
  async function processFrame(frame) {
    let data;
    try {
      data = frame === null || frame === undefined ? undefined : frame.data;
    } catch {
      return;
    }
    /* The array accesses below are themselves untrusted (a proxy may throw on
     * `length` or on an index), so they are read guarded: a frame that cannot
     * be read is not queued and not validated. */
    let bar;
    try {
      bar = Array.isArray(data) && data.length >= 3 ? data[0] : null;
    } catch {
      return;
    }
    if (bar !== FRAME_KIND_EVENT) return;
    let event;
    try {
      event = data[2];
    } catch {
      return;
    }

    const validated = await validateEvent(event);
    /* C-DLV section 4.6 step (1): a stop that landed while `validateEvent`
     * awaited the identity-key reading ends this frame here. */
    if (stopped) return;
    if (!validated.ok) {
      /* C-DLV section 4.5: an unknown closed slot of the identity-key return
       * keeps its own code ahead of the step-3 failure. */
      if (stopped) return;
      discard(validated.unknown === true ? DISCARD_UNKNOWN_CODE : DISCARD_INVALID);
      return;
    }
    /* C-DLV section 8: the duplicate check runs after the checks of 7.1, and
     * an id enters the window when its event passed them, before the session
     * port call. */
    if (isDuplicate(validated.event.id)) return;
    remember(validated.event.id);

    if (validated.kind === EVENT_KIND_RECEIPT) {
      await acknowledge(validated.event);
      return;
    }

    const sender = await openMessage(validated.event);
    if (sender === null) return;
    /* C-DLV section 7.2: the receipt is sent only for a message event that
     * carries the `r` tag, at most once per event id while that id is in the
     * window; section 4.6 step (1): no receipt starts after the stop. */
    if (validated.event.tags.length !== 4) return;
    if (stopped) return;
    const own = publicKey;
    if (own === null) return;
    const built = await buildAndSignReceipt({ sender, eventId: validated.event.id }, own);
    if (stopped) return;
    if (built.unknown === true) {
      /* C-DLV section 4.5: an unknown closed slot in the signature return is
       * `E_SDK_UNKNOWN_CODE`; the message event emitted above stands, because
       * section 7.2 emits the message before the receipt is built, and this is
       * the structure's one terminal event, never a second. */
      discard(DISCARD_UNKNOWN_CODE);
      return;
    }
    if (built.ok !== true) return;
    if (stopped) return;
    publishReceipt(built.receipt);
  }

  /* --- the per-client queue of C-DLV section 7.1 ------------------------ */

  /** C-DLV section 7.1: process queued frames one at a time, arrival order. */
  async function drain() {
    if (processing) return;
    processing = true;
    try {
      while (queue.length > 0 && !stopped) {
        const frame = queue.shift();
        try {
          await processFrame(frame);
        } catch {
          // A fault of one frame never stalls the queue (C-DLV section 7.1).
        }
      }
    } finally {
      processing = false;
    }
  }

  /* --- the public surface ----------------------------------------------- */

  /**
   * C-DLV section 7.1: queue one decoded inbound frame. At most 1 024 decoded
   * `EVENT` frames wait; a frame that arrives when the bound is full is
   * dropped before any validation and before any session-port call. A frame
   * that is not a decoded `EVENT` frame of this client's subscription, and a
   * frame that arrives after the stop, are not queued either.
   *
   * @param {{ relayIndex: number, relay: string, data: unknown }} frame
   * @returns {object} the frozen envelope of C-SDK section 5.1
   */
  function ingest(frame) {
    if (stopped) return success({ queued: false });
    let data;
    try {
      data = frame === null || frame === undefined ? undefined : frame.data;
    } catch {
      return success({ queued: false });
    }
    /* C-DLV section 7.1: a frame that is not a decoded `EVENT` array of this
     * module's shape is not queued. The reads are guarded, so an array whose
     * `length` getter or index getter throws never escapes `ingest`. */
    let bar;
    try {
      bar = Array.isArray(data) && data.length >= 3 ? data[0] : null;
    } catch {
      return success({ queued: false });
    }
    if (bar !== FRAME_KIND_EVENT) {
      return success({ queued: false });
    }
    if (queue.length >= INBOUND_PENDING_BOUND) return success({ queued: false });
    queue.push(frame);
    /* The drain is asynchronous, so `ingest` stays synchronous and the queue
     * keeps the arrival order (C-DLV section 7.1). */
    Promise.resolve().then(drain);
    return success({ queued: true });
  }

  /**
   * C-DLV section 4.6 step (1): drop the inbound frame queue, so no queued
   * frame is parsed or opened afterwards. A second call is
   * `E_SDK_CLIENT_STOPPED` (C-SDK section 5.2).
   *
   * @returns {object} the frozen envelope of C-SDK section 5.1
   */
  function shutdown() {
    if (stopped) return failure(CODE_CLIENT_STOPPED);
    stopped = true;
    const dropped = queue.length;
    queue.length = 0;
    return success({ dropped });
  }

  return Object.freeze({ ingest, shutdown });
}

/**
 * C-DLV section 7.1 step 3: one fixed tag exactly as sections 6.2 and 6.3 give
 * it.
 *
 * @param {unknown} tag
 * @param {string} name
 * @param {string} expected
 * @returns {boolean}
 */
function tagIs(tag, name, expected) {
  return Array.isArray(tag) && tag.length === 2 && tag[0] === name && tag[1] === expected;
}

/**
 * C-DLV section 7.1 step 3: a tag of exactly two strings whose first element is
 * the fixed name, its value checked by the caller (sections 6.2 and 6.3 give
 * every tag exactly two elements).
 *
 * @param {unknown} tag
 * @param {string} name
 * @returns {boolean}
 */
function namedPair(tag, name) {
  return Array.isArray(tag) && tag.length === 2 && tag[0] === name && typeof tag[1] === 'string';
}
