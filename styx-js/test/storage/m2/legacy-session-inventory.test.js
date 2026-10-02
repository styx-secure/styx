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
    inventoryLegacySessions({ keys });
    key.fill(0);
    // A later classification of the mutated buffer is LEGACY, proving no snapshot
    // was installed into the caller's buffer and no state was kept.
    expect(classifyLegacyLocator(key)).toBe('LEGACY');
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
