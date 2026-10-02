import { describe, expect, test } from '@jest/globals';
import { readFileSync } from 'node:fs';
import fc from 'fast-check';
import {
  M2_KIND, M2_SCOPE, decodeRecordKey, decodeSelectorKey,
  encodeRecordKey, encodeSelectorKey,
} from '../../../src/storage/m2/session-codec.js';
import {
  M2_LEGACY_INVENTORY, M2LegacyInventoryError,
  classifyLegacyLocator, inventoryLegacySessions,
} from '../../../src/storage/m2/legacy-session-inventory.js';
import * as inventoryModule from '../../../src/storage/m2/legacy-session-inventory.js';

const TE = new TextEncoder();
const ascii = (s) => TE.encode(s);
const hex = (b) => Array.from(b, (v) => v.toString(16).padStart(2, '0')).join('');
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const part of parts) { out.set(part, at); at += part.length; }
  return out;
};

const CONTEXT = new Uint8Array(32).fill(0x21);
const SESSION = new Uint8Array(32).fill(0x42);
const ALT_CONTEXT = new Uint8Array(32).fill(0x37);

const selectorKey = (context = CONTEXT) => encodeSelectorKey({ localContextId: context });
const recordKey = (overrides = {}) => encodeRecordKey({
  scope: M2_SCOPE.CONTEXT_PRESESSION,
  localContextId: CONTEXT,
  secureSessionIdentity: null,
  writeGeneration: 1n,
  recordKind: M2_KIND.SLOT_REGISTRATION,
  ...overrides,
});

// Legacy-domain locators: the shipping envelope/ciphersuite names and any other
// byte sequence that carries neither M2 magic. They are opaque; nothing decodes them.
const LEGACY_KEYS = [
  ascii('styx-vault-wrapper'),
  ascii('styx/vault/v1/record'),
  ascii('mls-state-v1'),
  ascii('styx-shipping-ciphersuite-XCHACHA'),
  Uint8Array.of(0x00),
  Uint8Array.of(0xff, 0xee, 0xdd),
  ascii('{"legacy":"json"}'),
];

const errorOf = (fn) => {
  try {
    fn();
  } catch (error) {
    return error;
  }
  throw new Error('expected the call to throw');
};

describe('legacy-session-inventory: closed recogniser', () => {
  test('publishes the exact C-FMT tuple strings and the closed metadata', () => {
    expect(M2_LEGACY_INVENTORY.SCHEMA).toBe('styx-m2-legacy-inventory/v1');
    expect(M2_LEGACY_INVENTORY.LOCATOR_VERSION).toBe(1);
    expect(M2_LEGACY_INVENTORY.SELECTOR_MAGIC).toBe('STYXSEL1');
    expect(M2_LEGACY_INVENTORY.RECORD_MAGIC).toBe('STYXKEY1');
    expect(M2_LEGACY_INVENTORY.SELECTOR_LENGTH).toBe(42);
    expect(M2_LEGACY_INVENTORY.SELECTOR_LOCATOR_TUPLE)
      .toBe('STYXSEL1 || u16be(version=1) || localContextId[32]');
    expect(M2_LEGACY_INVENTORY.RECORD_KEY_TUPLE)
      .toBe('STYXKEY1 || u16be(version=1) || scope:u8 || localContextId[32]'
        + ' || (secureSessionIdentity[32] iff scope=SESSION) || writeGeneration:u64be'
        + ' || recordKind:u16be || objectIdLength:u8 || objectId');
    expect(Object.isFrozen(M2_LEGACY_INVENTORY)).toBe(true);
    expect(M2_LEGACY_INVENTORY.CLASSES).toEqual(['SELECTOR', 'RECORD', 'LEGACY']);
    expect(M2_LEGACY_INVENTORY.INVENTORY_OUTCOMES).toEqual(['NO_M2_STATE', 'LEGACY_ONLY']);
    expect([...M2_LEGACY_INVENTORY.FAILURE_CODES].sort())
      .toEqual(['INCOMPATIBLE_FORMAT', 'RECORD_INVALID', 'SELECTOR_INVALID', 'UNSUPPORTED_VERSION']);
  });

  test('the module surface is closed: no import, decrypt, translate, fallback or selection API', () => {
    expect(Object.keys(inventoryModule).sort()).toEqual([
      'M2LegacyInventoryError', 'M2_LEGACY_INVENTORY',
      'classifyLegacyLocator', 'inventoryLegacySessions',
    ]);
    expect(M2_LEGACY_INVENTORY.PHYSICAL_INVENTORY_OWNER).toBe('L-INV');
    expect(M2_LEGACY_INVENTORY.IMPORT).toBe(false);
    expect(M2_LEGACY_INVENTORY.DECRYPT).toBe(false);
    expect(M2_LEGACY_INVENTORY.TRANSLATE).toBe(false);
    expect(M2_LEGACY_INVENTORY.FALLBACK).toBe(false);
    expect(M2_LEGACY_INVENTORY.SELECTED_AUTHORITY).toBe(false);
    expect(M2_LEGACY_INVENTORY.PRESERVE_BYTES).toBe(true);
    expect(M2_LEGACY_INVENTORY.CLEANUP).toBe('DEFERRED');
  });

  test('the published selector tuple equals the merged session-codec encoding', () => {
    const key = selectorKey();
    expect(key.length).toBe(M2_LEGACY_INVENTORY.SELECTOR_LENGTH);
    expect(hex(key.slice(0, 8))).toBe(hex(ascii('STYXSEL1')));
    expect(hex(key.slice(8, 10))).toBe('0001');
    expect(classifyLegacyLocator(key)).toBe('SELECTOR');
    expect(decodeSelectorKey(key).localContextId).toEqual(CONTEXT);
  });

  test('recognises an exact canonical record key for both scopes and every data kind', () => {
    for (const recordKind of [M2_KIND.SLOT_REGISTRATION, M2_KIND.KEY_PACKAGE, M2_KIND.MANIFEST]) {
      expect(classifyLegacyLocator(recordKey({ recordKind }))).toBe('RECORD');
      expect(classifyLegacyLocator(recordKey({
        scope: M2_SCOPE.SESSION,
        secureSessionIdentity: SESSION,
        writeGeneration: 7n,
        recordKind,
      }))).toBe('RECORD');
    }
    expect(decodeRecordKey(recordKey()).recordKind).toBe(M2_KIND.SLOT_REGISTRATION);
  });

  test('classifies every non-M2-magic locator as LEGACY without decoding it', () => {
    for (const key of LEGACY_KEYS) expect(classifyLegacyLocator(key)).toBe('LEGACY');
  });

  test('the new module is imported by nothing: no barrel export mentions it', () => {
    const storageIndex = readFileSync(
      new URL('../../../src/storage/index.js', import.meta.url), 'utf8',
    );
    expect(storageIndex).not.toContain('legacy-session-inventory');
    expect(storageIndex).not.toContain('LEGACY_INVENTORY');
  });
});

describe('legacy-session-inventory: value-free inventory facts', () => {
  test('an empty key space is NO_M2_STATE with no legacy', () => {
    const record = inventoryLegacySessions({ keys: [] });
    expect(record).toEqual({
      schema: 'styx-m2-legacy-inventory/v1',
      keyCount: 0,
      selectorCount: 0,
      recordCount: 0,
      legacyCount: 0,
      legacyPresent: false,
      m2Present: false,
      noM2State: true,
      orphanGeneration: false,
      inventoryOutcome: 'NO_M2_STATE',
    });
    expect(Object.isFrozen(record)).toBe(true);
  });

  test('a legacy-only key space is LEGACY_ONLY with legacyPresent and noM2State', () => {
    const record = inventoryLegacySessions({ keys: [...LEGACY_KEYS] });
    expect(record.legacyCount).toBe(LEGACY_KEYS.length);
    expect(record.legacyPresent).toBe(true);
    expect(record.noM2State).toBe(true);
    expect(record.m2Present).toBe(false);
    expect(record.inventoryOutcome).toBe('LEGACY_ONLY');
  });

  test('M2 presence suppresses the inventory outcome and keeps legacy facts', () => {
    const record = inventoryLegacySessions({ keys: [selectorKey(), recordKey(), ascii('legacy-x')] });
    expect(record.selectorCount).toBe(1);
    expect(record.recordCount).toBe(1);
    expect(record.legacyCount).toBe(1);
    expect(record.m2Present).toBe(true);
    expect(record.noM2State).toBe(false);
    expect(record.inventoryOutcome).toBeNull();
  });

  test('a record key without its fixed locator is an orphan generation', () => {
    const record = inventoryLegacySessions({ keys: [recordKey()] });
    expect(record.orphanGeneration).toBe(true);
    expect(record.noM2State).toBe(false);
    expect(record.inventoryOutcome).toBeNull();
  });

  test('the inventory record is value-free: only the closed scalar keys, no bytes', () => {
    const record = inventoryLegacySessions({ keys: [selectorKey(), ...LEGACY_KEYS] });
    expect(Object.keys(record).sort()).toEqual([
      'inventoryOutcome', 'keyCount', 'legacyCount', 'legacyPresent',
      'm2Present', 'noM2State', 'orphanGeneration', 'recordCount',
      'schema', 'selectorCount',
    ]);
    for (const value of Object.values(record)) {
      expect(value instanceof Uint8Array).toBe(false);
    }
    expect(JSON.stringify(record)).not.toContain(hex(CONTEXT));
  });

  test('legacyCount is bounded by the closed key bound', () => {
    const keys = Array.from({ length: M2_LEGACY_INVENTORY.MAX_KEYS }, (_, i) => ascii(`legacy-${i}`));
    const record = inventoryLegacySessions({ keys });
    expect(record.legacyCount).toBe(M2_LEGACY_INVENTORY.MAX_KEYS);
    expect(record.keyCount).toBe(M2_LEGACY_INVENTORY.MAX_KEYS);
  });
});

describe('legacy-session-inventory: malformed source writes nothing and imports nothing', () => {
  const malformedCases = [
    { name: 'a source that is not a plain object', source: [] },
    { name: 'a source missing the keys field', source: {} },
    { name: 'a source with an extra field', source: { keys: [], extra: 1 } },
    { name: 'keys that is not a plain array', source: { keys: 'nope' } },
    { name: 'a key that is not a byte sequence', source: { keys: [ascii('ok'), 7] } },
    { name: 'a null key', source: { keys: [null] } },
  ];

  test.each(malformedCases)('$name rejects with INCOMPATIBLE_FORMAT and mutates nothing', ({ source }) => {
    const before = JSON.stringify(source, (k, v) => (v instanceof Uint8Array ? hex(v) : v));
    const error = errorOf(() => inventoryLegacySessions(source));
    expect(error).toBeInstanceOf(M2LegacyInventoryError);
    expect(error.code).toBe('INCOMPATIBLE_FORMAT');
    const after = JSON.stringify(source, (k, v) => (v instanceof Uint8Array ? hex(v) : v));
    expect(after).toBe(before);
  });

  test('an M2-magic selector key with an unknown version pin is recognised but not imported', () => {
    const key = selectorKey();
    const bumped = Uint8Array.prototype.slice.call(key);
    bumped[9] = 2;
    const error = errorOf(() => classifyLegacyLocator(bumped));
    expect(error).toBeInstanceOf(M2LegacyInventoryError);
    expect(error.code).toBe('UNSUPPORTED_VERSION');
  });

  test('an M2-magic record key with an unknown version pin is recognised but not imported', () => {
    const key = recordKey();
    const bumped = Uint8Array.prototype.slice.call(key);
    bumped[9] = 9;
    expect(errorOf(() => classifyLegacyLocator(bumped)).code).toBe('UNSUPPORTED_VERSION');
  });

  test('an M2-shaped selector locator that is not canonical rejects SELECTOR_INVALID', () => {
    const key = selectorKey();
    const truncated = key.slice(0, key.length - 1);
    expect(errorOf(() => classifyLegacyLocator(truncated)).code).toBe('SELECTOR_INVALID');
    const zeroContext = new Uint8Array(42);
    zeroContext.set(ascii('STYXSEL1'), 0);
    zeroContext[9] = 1;
    expect(errorOf(() => classifyLegacyLocator(zeroContext)).code).toBe('SELECTOR_INVALID');
  });

  test('an M2-shaped record key that is not canonical rejects RECORD_INVALID', () => {
    const key = recordKey();
    const trailing = new Uint8Array(key.length + 1);
    trailing.set(key); trailing[key.length] = 0x00;
    expect(errorOf(() => classifyLegacyLocator(trailing)).code).toBe('RECORD_INVALID');
  });

  test('two distinct selector locators reject SELECTOR_INVALID (C-REST multipleSelectorCandidates)', () => {
    const source = { keys: [selectorKey(CONTEXT), selectorKey(ALT_CONTEXT)] };
    const before = source.keys.map(hex);
    const error = errorOf(() => inventoryLegacySessions(source));
    expect(error.code).toBe('SELECTOR_INVALID');
    expect(source.keys.map(hex)).toEqual(before);
  });

  test('a duplicate M2 record key rejects RECORD_INVALID', () => {
    expect(errorOf(() => inventoryLegacySessions({ keys: [recordKey(), recordKey()] })).code)
      .toBe('RECORD_INVALID');
  });

  test('an over-bound key space rejects INCOMPATIBLE_FORMAT', () => {
    const keys = Array.from(
      { length: M2_LEGACY_INVENTORY.MAX_KEYS + 1 }, (_, i) => ascii(`k${i}`),
    );
    expect(errorOf(() => inventoryLegacySessions({ keys })).code).toBe('INCOMPATIBLE_FORMAT');
  });

  test('a malformed source is never decoded as M2 and never selects authority', () => {
    // Only the exact tuple is M2-recognised. Anything else stays legacy, and an
    // M2-magic key that is not canonical is rejected instead of imported.
    expect(classifyLegacyLocator(ascii('STYXSEL'))).toBe('LEGACY');
    expect(classifyLegacyLocator(ascii('STYXKEY'))).toBe('LEGACY');
    expect(classifyLegacyLocator(ascii('STYXSELLEGACYSHIPPING'))).toBe('LEGACY');
    const error = errorOf(() => classifyLegacyLocator(ascii('STYXKEY1')));
    expect(error).toBeInstanceOf(M2LegacyInventoryError);
    expect(error.code).toBe('RECORD_INVALID');
  });

  test('every rejection is an M2LegacyInventoryError with a closed code and no echoed key', () => {
    const sources = [
      { keys: [selectorKey(), selectorKey(ALT_CONTEXT)] },
      { keys: [recordKey(), recordKey()] },
      { keys: [7] },
      { keys: 'nope' },
    ];
    for (const source of sources) {
      const error = errorOf(() => inventoryLegacySessions(source));
      expect(error).toBeInstanceOf(M2LegacyInventoryError);
      expect(M2_LEGACY_INVENTORY.FAILURE_CODES).toContain(error.code);
      for (const key of Array.isArray(source.keys) ? source.keys : []) {
        if (key instanceof Uint8Array) expect(error.message).not.toContain(hex(key));
      }
    }
  });

  test('a write-trapped source proves the module never writes and never calls a method', () => {
    const calls = [];
    const trap = {
      set: (t, k, v) => { calls.push(['set', String(k)]); return Reflect.set(t, k, v); },
      deleteProperty: (t, k) => { calls.push(['delete', String(k)]); return Reflect.deleteProperty(t, k); },
      defineProperty: (t, k, d) => { calls.push(['define', String(k)]); return Reflect.defineProperty(t, k, d); },
    };
    const target = [selectorKey(), ascii('legacy')];
    const record = inventoryLegacySessions({ keys: new Proxy(target, trap) });
    expect(calls).toEqual([]);
    expect(record.selectorCount).toBe(1);
    expect(record.legacyCount).toBe(1);
    expect(target.length).toBe(2);
  });

  test('a frozen source is accepted and left byte-identical', () => {
    const key = selectorKey();
    const legacy = ascii('legacy-legacy');
    const keys = Object.freeze([key, legacy]);
    const before = keys.map(hex);
    const record = inventoryLegacySessions({ keys });
    expect(record.selectorCount).toBe(1);
    expect(keys.map(hex)).toEqual(before);
    expect(hex(key)).not.toBe('');
    expect(hex(legacy)).not.toBe('');
  });

  test('the module does not retain or alias caller memory', () => {
    const key = recordKey();
    const keys = [key];
    const record = inventoryLegacySessions({ keys });
    expect(record.recordCount).toBe(1);
    expect(hex(key)).toBe(hex(recordKey()));
    key.fill(0);
    // No snapshot was retained: the same source now inventories as legacy only.
    const after = inventoryLegacySessions({ keys });
    expect(after).toMatchObject({ recordCount: 0, selectorCount: 0, legacyCount: 1 });
    expect(after.legacyPresent).toBe(true);
    expect(record.recordCount).toBe(1);
  });
});

describe('legacy-session-inventory: hostile-source totality (regression)', () => {
  test('a throwing accessor element is never invoked and rejects INCOMPATIBLE_FORMAT', () => {
    let calls = 0;
    const arr = [selectorKey()];
    Object.defineProperty(arr, '0', {
      enumerable: true,
      configurable: true,
      get() { calls += 1; throw new TypeError('getter boom'); },
    });
    const before = Object.getOwnPropertyNames(arr);
    const error = errorOf(() => inventoryLegacySessions({ keys: arr }));
    expect(error).toBeInstanceOf(M2LegacyInventoryError);
    expect(error.code).toBe('INCOMPATIBLE_FORMAT');
    expect(calls).toBe(0);
    expect(Object.getOwnPropertyNames(arr)).toEqual(before);
  });

  test('a Proxy-wrapped Uint8Array key rejects INCOMPATIBLE_FORMAT, never a raw engine error', () => {
    const proxied = new Proxy(new Uint8Array([9, 9, 9]), {
      get() { throw new RangeError('trap boom'); },
    });
    for (const call of [
      () => classifyLegacyLocator(proxied),
      () => inventoryLegacySessions({ keys: [proxied] }),
    ]) {
      const error = errorOf(call);
      expect(error).toBeInstanceOf(M2LegacyInventoryError);
      expect(error.code).toBe('INCOMPATIBLE_FORMAT');
    }
  });

  test('a hostile Proxy keys array rejects INCOMPATIBLE_FORMAT for every read the module makes', () => {
    const base = [ascii('legacy-legacy')];
    const traps = {
      lengthDescriptor(target, key) {
        if (key === 'length') throw new TypeError('length descriptor boom');
        return Reflect.getOwnPropertyDescriptor(target, key);
      },
      elementDescriptor(target, key) {
        if (key === '0') throw new TypeError('element descriptor boom');
        return Reflect.getOwnPropertyDescriptor(target, key);
      },
      prototype() { throw new TypeError('proto boom'); },
    };
    for (const [name, trap] of Object.entries(traps)) {
      const handler = {
        lengthDescriptor: { getOwnPropertyDescriptor: trap },
        elementDescriptor: { getOwnPropertyDescriptor: trap },
        prototype: { getPrototypeOf: trap },
      }[name];
      const keys = new Proxy(base, handler);
      const error = errorOf(() => inventoryLegacySessions({ keys }));
      expect(error).toBeInstanceOf(M2LegacyInventoryError);
      expect(error.code).toBe('INCOMPATIBLE_FORMAT');
    }
    expect(base).toEqual([ascii('legacy-legacy')]);
  });

  test('the module never performs a plain indexed get, only descriptor reads', () => {
    const base = [ascii('legacy-legacy')];
    let gets = 0;
    const keys = new Proxy(base, {
      get(target, key) { gets += 1; return Reflect.get(target, key); },
    });
    const record = inventoryLegacySessions({ keys });
    expect(record.legacyCount).toBe(1);
    expect(gets).toBe(0);
  });

  test('length and each element are read exactly once, through their descriptors', () => {
    const base = [ascii('legacy-legacy'), selectorKey(), recordKey()];
    const reads = [];
    let indexGets = 0;
    const keys = new Proxy(base, {
      get(target, key) {
        if (/^(0|[1-9][0-9]*)$/.test(String(key))) indexGets += 1;
        return Reflect.get(target, key);
      },
      getOwnPropertyDescriptor(target, key) {
        reads.push(String(key));
        return Reflect.getOwnPropertyDescriptor(target, key);
      },
    });
    const record = inventoryLegacySessions({ keys });
    expect(record).toMatchObject({ keyCount: 3, selectorCount: 1, recordCount: 1, legacyCount: 1 });
    // One descriptor read for the length, one per element, and no indexed get at all.
    expect(reads).toEqual(['length', '0', '1', '2']);
    expect(indexGets).toBe(0);
  });

  test('an element that changes between reads is classified from one snapshot', () => {
    const target = [ascii('legacy-legacy'), ascii('legacy-legacy')];
    let reads = 0;
    const keys = new Proxy(target, {
      getOwnPropertyDescriptor(t, key) {
        if (key === '1') reads += 1;
        return Reflect.getOwnPropertyDescriptor(t, key);
      },
    });
    const record = inventoryLegacySessions({ keys });
    expect(record.legacyCount).toBe(2);
    expect(reads).toBe(1);
  });

  test('a forged module error thrown by a trap cannot choose the failure code', () => {
    for (const thrown of [
      new M2LegacyInventoryError('NOT_A_CLOSED_CODE', 'forged'),
      'a primitive',
      new Proxy({}, { getPrototypeOf() { throw new RangeError('hostile'); } }),
    ]) {
      const keys = new Proxy([ascii('legacy')], {
        getOwnPropertyDescriptor() { throw thrown; },
      });
      const error = errorOf(() => inventoryLegacySessions({ keys }));
      expect(error).toBeInstanceOf(M2LegacyInventoryError);
      expect(M2_LEGACY_INVENTORY.FAILURE_CODES).toContain(error.code);
      expect(error.code).toBe('INCOMPATIBLE_FORMAT');
    }
  });

  test('a hostile Proxy source object rejects INCOMPATIBLE_FORMAT, never a raw engine error', () => {
    const source = new Proxy({ keys: [] }, {
      ownKeys() { throw new TypeError('ownKeys boom'); },
    });
    const error = errorOf(() => inventoryLegacySessions(source));
    expect(error).toBeInstanceOf(M2LegacyInventoryError);
    expect(error.code).toBe('INCOMPATIBLE_FORMAT');
  });

  test('each element is read once and snapshotted once: later mutation cannot change the result', () => {
    const key = recordKey();
    const legacy = ascii('legacy-legacy');
    const keys = [key, legacy];
    const record = inventoryLegacySessions({ keys });
    expect(record).toMatchObject({ keyCount: 2, recordCount: 1, legacyCount: 1 });
    key.fill(0);
    legacy.fill(0);
    expect(record.recordCount).toBe(1);
    expect(record.legacyCount).toBe(1);
  });

  test('an M2-magic locator that is not canonical is rejected, never counted as legacy', () => {
    const truncated = concat(recordKey(), Uint8Array.of(0));
    const error = errorOf(() => inventoryLegacySessions({ keys: [truncated] }));
    expect(error).toBeInstanceOf(M2LegacyInventoryError);
    expect(error.code).toBe('RECORD_INVALID');
  });

  test('only a locator without an M2 magic is legacy-counted', () => {
    const record = inventoryLegacySessions({ keys: [ascii('STYXKEY'), ascii('legacy-legacy')] });
    expect(record).toMatchObject({
      keyCount: 2, selectorCount: 0, recordCount: 0, legacyCount: 2,
      legacyPresent: true, m2Present: false, noM2State: true, inventoryOutcome: 'LEGACY_ONLY',
    });
  });
});

describe('legacy-session-inventory: correction round 1 (species, forgery, context)', () => {
  test('a species-redirecting subclass key classifies its true bytes, never the redirect', () => {
    class Redirecting extends Uint8Array {
      static get [Symbol.species]() {
        return function Redirect() { return selectorKey(); };
      }
    }
    const canonical = selectorKey();
    const subclassSelector = new Redirecting(canonical);
    expect(classifyLegacyLocator(subclassSelector)).toBe('SELECTOR');
    expect(decodeSelectorKey(subclassSelector).localContextId).toEqual(CONTEXT);
    expect(classifyLegacyLocator(new Redirecting(1))).toBe('LEGACY');
    const record = recordKey();
    const subclassRecord = new Redirecting(record);
    expect(classifyLegacyLocator(subclassRecord)).toBe('RECORD');
    expect(hex(subclassSelector)).toBe(hex(canonical));
    expect(hex(subclassRecord)).toBe(hex(record));
  });

  test('a Node Buffer key carrying canonical bytes is accepted like the merged codec', () => {
    const bufferSelector = Buffer.from(selectorKey());
    const bufferRecord = Buffer.from(recordKey());
    expect(classifyLegacyLocator(bufferSelector)).toBe('SELECTOR');
    expect(classifyLegacyLocator(bufferRecord)).toBe('RECORD');
    expect(decodeRecordKey(bufferRecord).recordKind).toBe(M2_KIND.SLOT_REGISTRATION);
    const record = inventoryLegacySessions({ keys: [bufferSelector, bufferRecord] });
    expect(record).toMatchObject({ selectorCount: 1, recordCount: 1, m2Present: true });
  });

  test('an own length or buffer override cannot shorten, extend or substitute the copy', () => {
    class LyingLength extends Uint8Array {
      get length() { return 1; }
    }
    const canonical = recordKey();
    const lying = new LyingLength(canonical);
    expect(lying.length).toBe(1);
    // The internal slot decides, not the own getter.
    expect(classifyLegacyLocator(lying)).toBe('RECORD');
    expect(hex(lying)).toBe(hex(canonical));
    expect(classifyLegacyLocator(new LyingLength(Uint8Array.of(0x53)))).toBe('LEGACY');
    const substituted = Uint8Array.of(0x53);
    Object.defineProperty(substituted, 'buffer', {
      value: selectorKey().buffer,
      configurable: true,
    });
    expect(classifyLegacyLocator(substituted)).toBe('LEGACY');
  });

  test('an own length carrying typed bytes or another buffer cannot redirect the copy', () => {
    // Own `length` holding the canonical selector bytes: the true key bytes still decide.
    const lying = Uint8Array.of(0x53);
    Object.defineProperty(lying, 'length', { value: selectorKey(), configurable: true });
    expect(classifyLegacyLocator(lying)).toBe('LEGACY');

    // Own `length` holding another source element's buffer: the module must neither write
    // into that buffer nor adopt its bytes.
    const victim = selectorKey();
    const victimBefore = hex(victim);
    const attacker = Uint8Array.of(0xaa, 0xbb, 0xcc);
    Object.defineProperty(attacker, 'length', { value: victim.buffer, configurable: true });
    const inventory = inventoryLegacySessions({ keys: [attacker, victim] });
    expect(inventory).toMatchObject({ selectorCount: 1, recordCount: 0, legacyCount: 1 });
    expect(hex(victim)).toBe(victimBefore);
    expect(hex(attacker)).toBe('aabbcc');

    // An own `length` accessor must never be invoked.
    let calls = 0;
    const accessed = Uint8Array.of(0x53);
    Object.defineProperty(accessed, 'length', {
      configurable: true,
      get() { calls += 1; return 42; },
    });
    expect(classifyLegacyLocator(accessed)).toBe('LEGACY');
    expect(calls).toBe(0);
  });

  test('an own constructor with a species getter cannot redirect the copy', () => {
    const key = Uint8Array.of(0x01, 0x02, 0x03);
    const before = hex(key);
    key.constructor = {
      get [Symbol.species]() {
        return function Redirect() { return selectorKey(); };
      },
    };
    // The true bytes decide: no species consult, no redirect, no aliasing.
    expect(classifyLegacyLocator(key)).toBe('LEGACY');
    expect(hex(key)).toBe(before);
  });

  test('a detached or forged view is refused; an empty byte sequence stays legacy', () => {
    const buffer = new ArrayBuffer(4);
    const view = new Uint8Array(buffer);
    // `ArrayBuffer.prototype.transfer` does not exist on the CI runtime (Node 20), so the
    // detach is done with `structuredClone`, which is what the review asked for.
    structuredClone(buffer, { transfer: [buffer] });
    expect(view.length).toBe(0);
    expect(view.byteLength).toBe(0);
    const refused = {
      detached: view,
      forged: Object.create(Uint8Array.prototype),
    };
    for (const [name, key] of Object.entries(refused)) {
      const error = errorOf(() => classifyLegacyLocator(key));
      expect(error).toBeInstanceOf(M2LegacyInventoryError);
      expect(error.code).toBe('INCOMPATIBLE_FORMAT');
    }
    // An empty Uint8Array carries no M2 magic, so it is a legacy locator, counted.
    expect(classifyLegacyLocator(new Uint8Array(0))).toBe('LEGACY');
    expect(inventoryLegacySessions({ keys: [new Uint8Array(0)] }))
      .toMatchObject({ legacyCount: 1, legacyPresent: true, m2Present: false });
  });

  test('a shared-buffer-backed key is a byte sequence, not a detached view', () => {
    const selector = selectorKey();
    const shared = new Uint8Array(new SharedArrayBuffer(selector.length));
    shared.set(selector);
    expect(classifyLegacyLocator(shared)).toBe('SELECTOR');
    const record = recordKey();
    const sharedRecord = new Uint8Array(new SharedArrayBuffer(record.length));
    sharedRecord.set(record);
    expect(classifyLegacyLocator(sharedRecord)).toBe('RECORD');
    const inventory = inventoryLegacySessions({ keys: [shared, sharedRecord] });
    expect(inventory).toMatchObject({ selectorCount: 1, recordCount: 1, m2Present: true });
  });

  test('a revoked proxy keys array rejects INCOMPATIBLE_FORMAT', () => {
    const revocable = Proxy.revocable([ascii('legacy-legacy')], {});
    revocable.revoke();
    const error = errorOf(() => inventoryLegacySessions({ keys: revocable.proxy }));
    expect(error).toBeInstanceOf(M2LegacyInventoryError);
    expect(error.code).toBe('INCOMPATIBLE_FORMAT');
  });

  test('a record key in another context cannot mask an orphan generation', () => {
    const sameContext = inventoryLegacySessions({ keys: [selectorKey(CONTEXT), recordKey()] });
    expect(sameContext).toMatchObject({ selectorCount: 1, recordCount: 1, orphanGeneration: false });
    const crossContext = inventoryLegacySessions({
      keys: [selectorKey(CONTEXT), recordKey({ localContextId: ALT_CONTEXT })],
    });
    expect(crossContext).toMatchObject({
      selectorCount: 1, recordCount: 1, m2Present: true, orphanGeneration: true,
    });
    expect(JSON.stringify(crossContext)).not.toContain(hex(ALT_CONTEXT));
    // A matched pair cannot hide a foreign-context generation behind it.
    const mixed = inventoryLegacySessions({
      keys: [
        selectorKey(CONTEXT), recordKey(), recordKey({ localContextId: ALT_CONTEXT }),
      ],
    });
    expect(mixed).toMatchObject({
      selectorCount: 1, recordCount: 2, m2Present: true, orphanGeneration: true,
    });
    expect(JSON.stringify(mixed)).not.toContain(hex(ALT_CONTEXT));
    expect(JSON.stringify(mixed)).not.toContain(hex(CONTEXT));
  });

  test('mutated canonical locators reach SELECTOR, RECORD and all four failure codes', () => {
    const classes = new Set();
    const codes = new Set();
    const observe = (key) => {
      try {
        classes.add(classifyLegacyLocator(key));
      } catch (error) {
        expect(error).toBeInstanceOf(M2LegacyInventoryError);
        codes.add(error.code);
      }
    };
    const selector = selectorKey();
    const record = recordKey();
    observe(selector);
    observe(record);
    observe(ascii('plain-legacy-locator'));
    observe(Object.create(Uint8Array.prototype));
    for (const base of [selector, record]) {
      for (let i = 0; i < base.length; i += 1) {
        const flip = Uint8Array.prototype.slice.call(base);
        flip[i] ^= 0xff;
        observe(flip);
      }
      observe(base.slice(0, base.length - 1));
      observe(concat(base, Uint8Array.of(0)));
      const versionBump = Uint8Array.prototype.slice.call(base);
      versionBump[9] = 2;
      observe(versionBump);
    }
    expect(classes).toContain('SELECTOR');
    expect(classes).toContain('RECORD');
    expect(classes).toContain('LEGACY');
    expect([...codes].sort()).toEqual([
      'INCOMPATIBLE_FORMAT', 'RECORD_INVALID', 'SELECTOR_INVALID', 'UNSUPPORTED_VERSION',
    ]);
  });
});

describe('legacy-session-inventory: seeded property tests', () => {
  const SEED = 20261002;

  test('any canonical locator built by the merged encoder is recognised', () => {
    fc.assert(fc.property(
      fc.uint8Array({ minLength: 32, maxLength: 32 }),
      fc.uint8Array({ minLength: 32, maxLength: 32 }),
      fc.integer({ min: 1, max: 16 }),
      (rawContext, rawSession, recordKind) => {
        const context = rawContext.some((b) => b !== 0) ? rawContext : CONTEXT;
        const session = rawSession.some((b) => b !== 0) ? rawSession : SESSION;
        const selector = encodeSelectorKey({ localContextId: context });
        expect(classifyLegacyLocator(selector)).toBe('SELECTOR');
        const record = encodeRecordKey({
          scope: M2_SCOPE.SESSION,
          localContextId: context,
          secureSessionIdentity: session,
          writeGeneration: 1n,
          recordKind,
        });
        expect(classifyLegacyLocator(record)).toBe('RECORD');
      },
    ), { seed: SEED, numRuns: 200 });
  });

  test('a random byte sequence is LEGACY or a closed rejection, never another exception', () => {
    fc.assert(fc.property(fc.uint8Array({ maxLength: 96 }), (key) => {
      let outcome;
      try {
        outcome = classifyLegacyLocator(key);
      } catch (error) {
        expect(error).toBeInstanceOf(M2LegacyInventoryError);
        expect(M2_LEGACY_INVENTORY.FAILURE_CODES).toContain(error.code);
        return;
      }
      expect(M2_LEGACY_INVENTORY.CLASSES).toContain(outcome);
    }), { seed: SEED, numRuns: 1000 });
  });

  test('the seeded properties themselves observe both M2 classes and all four codes', () => {
    const classes = new Set();
    const codes = new Set();
    const observe = (key) => {
      try {
        classes.add(classifyLegacyLocator(key));
      } catch (error) {
        expect(error).toBeInstanceOf(M2LegacyInventoryError);
        codes.add(error.code);
      }
    };
    const mutate = (base, raw) => {
      const mutated = Uint8Array.prototype.slice.call(base);
      mutated[raw % mutated.length] ^= 0xff;
      return mutated;
    };
    fc.assert(fc.property(
      fc.uint8Array({ maxLength: 96 }),
      fc.integer({ min: 0, max: 1 }),
      fc.integer({ min: 0, max: 4095 }),
      (key, kind, raw) => {
        observe(key);
        const base = kind === 0
          ? encodeSelectorKey({ localContextId: CONTEXT })
          : encodeRecordKey({
            scope: M2_SCOPE.SESSION,
            localContextId: CONTEXT,
            secureSessionIdentity: SESSION,
            writeGeneration: 1n,
            recordKind: M2_KIND.SLOT_REGISTRATION,
          });
        observe(base);
        observe(mutate(base, raw));
        observe(base.slice(0, base.length - 1));
        observe(concat(base, Uint8Array.of(0x00)));
        const bumped = Uint8Array.prototype.slice.call(base);
        bumped[9] = 2;
        observe(bumped);
        observe(Object.create(Uint8Array.prototype));
      },
    ), { seed: SEED, numRuns: 300 });
    expect([...classes].sort()).toEqual(['LEGACY', 'RECORD', 'SELECTOR']);
    expect([...codes].sort()).toEqual([
      'INCOMPATIBLE_FORMAT', 'RECORD_INVALID', 'SELECTOR_INVALID', 'UNSUPPORTED_VERSION',
    ]);
  });

  test('a mutated source always rejects or returns a frozen value-free record', () => {
    fc.assert(fc.property(
      fc.array(fc.uint8Array({ maxLength: 96 }), { maxLength: 24 }),
      (rawKeys) => {
        const keys = rawKeys.map((k) => Uint8Array.prototype.slice.call(k));
        const before = keys.map(hex);
        let record;
        try {
          record = inventoryLegacySessions({ keys });
        } catch (error) {
          expect(error).toBeInstanceOf(M2LegacyInventoryError);
          expect(keys.map(hex)).toEqual(before);
          return;
        }
        expect(Object.isFrozen(record)).toBe(true);
        expect(record.legacyCount + record.recordCount + record.selectorCount).toBe(keys.length);
        expect(keys.map(hex)).toEqual(before);
        for (const value of Object.values(record)) expect(value instanceof Uint8Array).toBe(false);
      },
    ), { seed: SEED, numRuns: 300 });
  });

  test('the same seed replays to identical outcomes', () => {
    const run = () => {
      const outcomes = [];
      fc.assert(fc.property(fc.uint8Array({ maxLength: 48 }), (key) => {
        let outcome;
        try {
          outcome = classifyLegacyLocator(key);
        } catch (error) {
          outcome = error.code;
        }
        outcomes.push(outcome);
      }), { seed: SEED, numRuns: 200 });
      return outcomes.join(',');
    };
    expect(run()).toBe(run());
  });
});
