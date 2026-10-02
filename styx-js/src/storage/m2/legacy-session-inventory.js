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

export class M2LegacyInventoryError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'M2LegacyInventoryError';
    this.code = code;
  }
}

const fail = (code, message) => { throw new M2LegacyInventoryError(code, message); };

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
  if (value === null || typeof value !== 'object' || Array.isArray(value)
      || Object.getPrototypeOf(value) !== Object.prototype) {
    fail('INCOMPATIBLE_FORMAT', `${name} must be a plain object`);
  }
  const own = Reflect.ownKeys(value);
  if (own.length !== keys.length || own.some((k) => typeof k !== 'string' || !keys.includes(k))) {
    fail('INCOMPATIBLE_FORMAT', `${name} has an unknown, missing, or symbol property`);
  }
  const out = {};
  for (const key of keys) {
    const d = Object.getOwnPropertyDescriptor(value, key);
    if (!d || !d.enumerable || !Object.hasOwn(d, 'value')) {
      fail('INCOMPATIBLE_FORMAT', `${name}.${key} must be enumerable data`);
    }
    out[key] = d.value;
  }
  return out;
}

// Uint8Array.prototype.slice, never value.slice(): subclasses such as Node Buffer
// override slice() to return a view, which would alias caller memory.
const snapshot = (value) => Uint8Array.prototype.slice.call(value);
const isBytes = (value) => value instanceof Uint8Array;
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

function classify(value) {
  if (!isBytes(value)) fail('INCOMPATIBLE_FORMAT', 'key must be a byte sequence');
  const b = snapshot(value);
  if (startsWith(b, SELECTOR_MAGIC)) {
    versionPin(b, 'SELECTOR_INVALID');
    if (b.length !== SELECTOR_LENGTH) fail('SELECTOR_INVALID', 'selector locator is not canonical');
    try {
      decodeSelectorKey(b);
    } catch (error) {
      if (!(error instanceof M2StorageCodecError)) throw error;
      fail('SELECTOR_INVALID', 'selector locator is not canonical');
    }
    return CLASS_SELECTOR;
  }
  if (startsWith(b, RECORD_MAGIC)) {
    versionPin(b, 'RECORD_INVALID');
    try {
      decodeRecordKey(b);
    } catch (error) {
      if (!(error instanceof M2StorageCodecError)) throw error;
      fail('RECORD_INVALID', 'record key is not canonical');
    }
    return CLASS_RECORD;
  }
  return CLASS_LEGACY;
}

export function classifyLegacyLocator(value) {
  return classify(value);
}

export function inventoryLegacySessions(source) {
  const s = strictObject(source, ['keys'], 'inventory source');
  const keys = s.keys;
  if (!Array.isArray(keys) || Object.getPrototypeOf(keys) !== Array.prototype) {
    fail('INCOMPATIBLE_FORMAT', 'inventory source keys must be a plain array');
  }
  if (keys.length > M2_LEGACY_INVENTORY.MAX_KEYS) {
    fail('INCOMPATIBLE_FORMAT', 'inventory source exceeds the key bound');
  }

  let selectorCount = 0;
  let recordCount = 0;
  let legacyCount = 0;
  const seen = new Set();

  for (let i = 0; i < keys.length; i += 1) {
    // Indexed read only. The source array and its elements are never written.
    const locatorClass = classify(keys[i]);
    const fingerprint = hex(snapshot(keys[i]));
    if (locatorClass === CLASS_SELECTOR) {
      // C-REST `inventoryRules.multipleSelectorCandidates`: at most one fixed locator.
      if (selectorCount > 0) fail('SELECTOR_INVALID', 'multiple selector candidates');
      if (seen.has(fingerprint)) fail('SELECTOR_INVALID', 'duplicate M2 locator');
      seen.add(fingerprint);
      selectorCount += 1;
    } else if (locatorClass === CLASS_RECORD) {
      if (seen.has(fingerprint)) fail('RECORD_INVALID', 'duplicate M2 locator');
      seen.add(fingerprint);
      recordCount += 1;
    } else {
      legacyCount += 1;
    }
  }

  const m2Present = selectorCount > 0 || recordCount > 0;
  const legacyPresent = legacyCount > 0;
  const noM2State = !m2Present;
  const orphanGeneration = recordCount > 0 && selectorCount === 0;
  const inventoryOutcome = m2Present ? null : (legacyPresent ? 'LEGACY_ONLY' : 'NO_M2_STATE');

  return Object.freeze({
    schema: M2_LEGACY_INVENTORY.SCHEMA,
    keyCount: keys.length,
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
