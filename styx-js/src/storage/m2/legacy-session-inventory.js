// M2 legacy session inventory. Internal-only: no barrel export.
//
// Read-only, value-free physical inventory of an already-enumerated storage key space.
// The module recognises the exact M2 fixed locator tuple and the exact M2 record-key
// tuple (C-FMT `recordKeyGrammar`) by magic and version pin, classifies every other
// enumerated key as the disjoint legacy domain, and returns only counts and booleans.
// It reuses `./session-codec.js` unchanged for the canonical locator recognition.
//
// It never reads or writes a stored value, never imports, decrypts, translates,
// copies, selects, decodes as M2 or falls back to legacy, and exposes no byte, no
// key, no context identifier and no authority.
//
// Totality: the caller's key space is untrusted. A key is accepted only if it passes
// the merged `%TypedArray%` brand check, each element is read exactly once through its
// own property descriptor (no accessor is ever invoked), the array length is read
// exactly once through its own descriptor, and the copy is made without consulting
// `Symbol.species` or an own `constructor`, so a caller cannot redirect or alias it.
// Every failure path — hostile proxy, throwing trap, species subclass, detached or
// forged view, foreign decoder error — leaves through `M2LegacyInventoryError` with one
// of the four closed C-REST codes.

import { decodeRecordKey, decodeSelectorKey, M2StorageCodecError } from './session-codec.js';

const TE = new TextEncoder();
const ASCII = (s) => TE.encode(s);

const SELECTOR_MAGIC = ASCII('STYXSEL1');
const RECORD_MAGIC = ASCII('STYXKEY1');
const MAGIC_LENGTH = 8;
const VERSION_OFFSET = MAGIC_LENGTH;
const SELECTOR_LENGTH = 42;

const CLASS_SELECTOR = 'SELECTOR';
const CLASS_RECORD = 'RECORD';
const CLASS_LEGACY = 'LEGACY';

const CLASSES = Object.freeze([CLASS_SELECTOR, CLASS_RECORD, CLASS_LEGACY]);
const INVENTORY_OUTCOMES = Object.freeze(['NO_M2_STATE', 'LEGACY_ONLY']);
const FAILURE_CODES = Object.freeze([
  'INCOMPATIBLE_FORMAT', 'UNSUPPORTED_VERSION', 'SELECTOR_INVALID', 'RECORD_INVALID',
]);

// The `%TypedArray%.prototype[Symbol.toStringTag]` getter is the brand check used by
// the merged M2 adapter (`crypto/mls/m2/state-machine.js`): it reads the internal slot,
// so a proxy, a forged `Uint8Array.prototype` object or another view type is refused.
// A `Buffer` or a benign subclass is a genuine `Uint8Array` view and is accepted, like
// the merged `session-codec.js` accepts it through `instanceof`; what is refused is only
// a view whose bytes cannot be read.
const TYPED_ARRAY_TAG = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype), Symbol.toStringTag,
).get;

export class M2LegacyInventoryError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'M2LegacyInventoryError';
    this.code = code;
  }
}

const fail = (code, message) => { throw new M2LegacyInventoryError(code, message); };

// A foreign exception must never escape, and it must never be able to choose the code:
// no guarded block can raise a module error itself (every `fail(...)` sits outside a
// `try`), so whatever a caller's trap or getter threw is discarded here and the block's
// own closed code is raised instead.
const mapFailure = (code, message) => fail(code, message);

// `instanceof` is itself a caller-controllable operation on a hostile value, so it is
// guarded too: only a real typed codec refusal may be reported as noncanonicity.
function isCodecRefusal(error) {
  try {
    return error instanceof M2StorageCodecError;
  } catch {
    return false;
  }
}

export const M2_LEGACY_INVENTORY = Object.freeze({
  SCHEMA: 'styx-m2-legacy-inventory/v1',
  LOCATOR_VERSION: 1,
  SELECTOR_MAGIC: 'STYXSEL1',
  RECORD_MAGIC: 'STYXKEY1',
  SELECTOR_LENGTH,
  MAX_KEYS: 4096,
  CLASSES,
  INVENTORY_OUTCOMES,
  FAILURE_CODES,
  // C-REC `/legacy/*`: the inventory is abstract, preserved and non-authoritative.
  PHYSICAL_INVENTORY_OWNER: 'L-INV',
  IMPORT: false,
  DECRYPT: false,
  TRANSLATE: false,
  FALLBACK: false,
  SELECTED_AUTHORITY: false,
  PRESERVE_BYTES: true,
  CLEANUP: 'DEFERRED',
  // The exact recognised tuple, copied verbatim from C-FMT `recordKeyGrammar`.
  SELECTOR_LOCATOR_TUPLE: 'STYXSEL1 || u16be(version=1) || localContextId[32]',
  RECORD_KEY_TUPLE:
    'STYXKEY1 || u16be(version=1) || scope:u8 || localContextId[32]'
    + ' || (secureSessionIdentity[32] iff scope=SESSION) || writeGeneration:u64be'
    + ' || recordKind:u16be || objectIdLength:u8 || objectId',
});

function strictObject(value, keys, name = 'value') {
  let plain = false;
  let own = null;
  try {
    plain = value !== null && typeof value === 'object' && !Array.isArray(value)
      && Object.getPrototypeOf(value) === Object.prototype;
    if (plain) own = Reflect.ownKeys(value);
  } catch {
    mapFailure('INCOMPATIBLE_FORMAT', `${name} could not be inspected`);
  }
  if (!plain) fail('INCOMPATIBLE_FORMAT', `${name} must be a plain object`);
  if (own.length !== keys.length || own.some((k) => typeof k !== 'string' || !keys.includes(k))) {
    fail('INCOMPATIBLE_FORMAT', `${name} has an unknown, missing, or symbol property`);
  }
  const out = {};
  for (const key of keys) {
    let d = null;
    try {
      d = Object.getOwnPropertyDescriptor(value, key);
    } catch {
      mapFailure('INCOMPATIBLE_FORMAT', `${name}.${key} could not be inspected`);
    }
    if (!d || !d.enumerable || !Object.hasOwn(d, 'value')) {
      fail('INCOMPATIBLE_FORMAT', `${name}.${key} must be enumerable data`);
    }
    out[key] = d.value;
  }
  return out;
}

function isByteSequence(value) {
  try {
    return ArrayBuffer.isView(value) && TYPED_ARRAY_TAG.call(value) === 'Uint8Array';
  } catch (error) {
    return false;
  }
}

// The length is read from the `%TypedArray%` internal slot, so an own `length`/`buffer`
// property on a subclass or an instance cannot shorten, extend or substitute what is
// copied.
function slotGetter(name) {
  return Object.getOwnPropertyDescriptor(
    Object.getPrototypeOf(Uint8Array.prototype), name,
  ).get;
}
const TYPED_ARRAY_LENGTH = slotGetter('length');

// One snapshot per locator, and it is the only bytes any later step reads.
// `new Uint8Array(length)` plus `set` consult neither `Symbol.species` nor an own
// `constructor` or `length`, so a caller cannot redirect, shorten or alias the copy.
// A detached view needs no separate test: `%TypedArray%.prototype.set` throws on a
// detached source buffer on every supported runtime, and that lands in the `catch`
// below. Testing "is it detached?" instead would mean calling into the caller's own
// buffer, whose prototype chain is caller-controlled.
function snapshotGuarded(value, name) {
  if (!isByteSequence(value)) fail('INCOMPATIBLE_FORMAT', `${name} must be a Uint8Array`);
  let copy = null;
  try {
    copy = new Uint8Array(TYPED_ARRAY_LENGTH.call(value));
    Uint8Array.prototype.set.call(copy, value);
  } catch {
    mapFailure('INCOMPATIBLE_FORMAT', `${name} could not be read as a byte sequence`);
  }
  return copy;
}

// Element reads go through the own property descriptor, so an accessor element is
// rejected without ever being invoked, and a hostile proxy is caught.
function readKeyElement(keys, index) {
  let d = null;
  try {
    d = Object.getOwnPropertyDescriptor(keys, String(index));
  } catch {
    mapFailure('INCOMPATIBLE_FORMAT', 'inventory source key could not be inspected');
  }
  if (!d || !d.enumerable || !Object.hasOwn(d, 'value')) {
    fail('INCOMPATIBLE_FORMAT', 'inventory source key must be an enumerable data element');
  }
  return snapshotGuarded(d.value, 'inventory source key');
}

// The array length is read exactly once, through its own descriptor, so a proxy with a
// lying or throwing `length` can neither escape nor grow the loop.
function readArrayLength(keys) {
  let d = null;
  try {
    d = Object.getOwnPropertyDescriptor(keys, 'length');
  } catch {
    mapFailure('INCOMPATIBLE_FORMAT', 'inventory source length could not be inspected');
  }
  if (!d || !Object.hasOwn(d, 'value') || typeof d.value !== 'number'
      || !Number.isSafeInteger(d.value) || d.value < 0) {
    fail('INCOMPATIBLE_FORMAT', 'inventory source length is not a plain count');
  }
  return d.value;
}

const startsWith = (b, magic) => {
  if (b.length < magic.length) return false;
  for (let i = 0; i < magic.length; i += 1) if (b[i] !== magic[i]) return false;
  return true;
};
const hex = (b) => {
  let out = '';
  for (const v of b) out += v.toString(16).padStart(2, '0');
  return out;
};

// Recognise the version pin of an M2-magic key without decoding any value.
function versionPin(b, code) {
  if (b.length < VERSION_OFFSET + 2) fail(code, 'truncated version pin');
  const version = b[VERSION_OFFSET] * 256 + b[VERSION_OFFSET + 1];
  if (version !== M2_LEGACY_INVENTORY.LOCATOR_VERSION) fail('UNSUPPORTED_VERSION', 'unknown locator version');
}

// Classify one already-snapshotted locator and return its decoded context, which is
// used only to decide `orphanGeneration` and is never exposed. Total: every failure
// leaves as one of the four closed codes.
function recognize(b) {
  if (startsWith(b, SELECTOR_MAGIC)) {
    versionPin(b, 'SELECTOR_INVALID');
    if (b.length !== SELECTOR_LENGTH) fail('SELECTOR_INVALID', 'selector locator is not canonical');
    let decoded = null;
    try {
      decoded = decodeSelectorKey(b);
    } catch (error) {
      if (isCodecRefusal(error)) fail('SELECTOR_INVALID', 'selector locator is not canonical');
      mapFailure('INCOMPATIBLE_FORMAT', 'selector locator could not be decoded');
    }
    return { locatorClass: CLASS_SELECTOR, context: hex(decoded.localContextId) };
  }
  if (startsWith(b, RECORD_MAGIC)) {
    versionPin(b, 'RECORD_INVALID');
    let decoded = null;
    try {
      decoded = decodeRecordKey(b);
    } catch (error) {
      if (isCodecRefusal(error)) fail('RECORD_INVALID', 'record key is not canonical');
      mapFailure('INCOMPATIBLE_FORMAT', 'record key could not be decoded');
    }
    return { locatorClass: CLASS_RECORD, context: hex(decoded.localContextId) };
  }
  return { locatorClass: CLASS_LEGACY, context: null };
}

export function classifyLegacyLocator(value) {
  return recognize(snapshotGuarded(value, 'locator')).locatorClass;
}

export function inventoryLegacySessions(source) {
  const s = strictObject(source, ['keys'], 'inventory source');
  const keys = s.keys;
  let plainArray = false;
  try {
    plainArray = Array.isArray(keys) && Object.getPrototypeOf(keys) === Array.prototype;
  } catch {
    mapFailure('INCOMPATIBLE_FORMAT', 'inventory source keys could not be inspected');
  }
  if (!plainArray) fail('INCOMPATIBLE_FORMAT', 'inventory source keys must be a plain array');
  const keyCount = readArrayLength(keys);
  if (keyCount > M2_LEGACY_INVENTORY.MAX_KEYS) {
    fail('INCOMPATIBLE_FORMAT', 'inventory source exceeds the key bound');
  }

  let selectorCount = 0;
  let recordCount = 0;
  let legacyCount = 0;
  let selectorContext = null;
  const recordContexts = new Set();
  const seen = new Set();

  for (let i = 0; i < keyCount; i += 1) {
    // One own-descriptor read and one snapshot per element. The module never writes
    // the source array or its elements, and never reads an element twice.
    const locator = readKeyElement(keys, i);
    const { locatorClass, context } = recognize(locator);
    if (locatorClass === CLASS_LEGACY) {
      // A legacy locator is opaque: counted, never fingerprinted and never decoded.
      // Repeated legacy bytes are counted as enumerated; the module does not police
      // legacy duplication, because a legacy locator carries no canonical M2 identity.
      legacyCount += 1;
      continue;
    }
    const fingerprint = hex(locator);
    if (locatorClass === CLASS_SELECTOR) {
      // C-REST `inventoryRules.multipleSelectorCandidates`: at most one fixed locator.
      if (selectorCount > 0) fail('SELECTOR_INVALID', 'multiple selector candidates');
      if (seen.has(fingerprint)) fail('SELECTOR_INVALID', 'duplicate M2 locator');
      seen.add(fingerprint);
      selectorContext = context;
      selectorCount += 1;
    } else {
      if (seen.has(fingerprint)) fail('RECORD_INVALID', 'duplicate M2 locator');
      seen.add(fingerprint);
      recordContexts.add(context);
      recordCount += 1;
    }
  }

  const m2Present = selectorCount > 0 || recordCount > 0;
  const legacyPresent = legacyCount > 0;
  const noM2State = !m2Present;
  // C-REST `inventoryRules.orphanGeneration`: a generation artifact that belongs to no
  // fixed locator — because there is no selector at all, or because a record key does
  // not share the single selector's local context — is an orphan generation.
  const orphanGeneration = recordCount > 0
    && (selectorCount === 0 || [...recordContexts].some((c) => c !== selectorContext));
  const inventoryOutcome = m2Present ? null : (legacyPresent ? 'LEGACY_ONLY' : 'NO_M2_STATE');

  return Object.freeze({
    schema: M2_LEGACY_INVENTORY.SCHEMA,
    keyCount,
    selectorCount,
    recordCount,
    legacyCount,
    legacyPresent,
    m2Present,
    noM2State,
    orphanGeneration,
    inventoryOutcome,
  });
}
