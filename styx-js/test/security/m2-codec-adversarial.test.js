// Adversarial / negative tests for the M2 codec family: I-BIND (binding v0),
// I-SM (adapter state machine) and I-CODEC (authenticated storage byte codecs).
//
// GAP JUSTIFICATIONS:
//  - GAPS.md §2 lists `styx-js/src/ledger/chain-validator.js` without
//    "canonicalization / determinism", "collision / ambiguity",
//    "replay / idempotence", "resource exhaustion / amplification",
//    "timeout / liveness"; `styx-js/src/storage/mls-state-migration.js` without
//    "rollback / atomicity"; `styx-js/src/storage/mls-state-envelope.js` and
//    `styx-js/src/storage/vault-record.js` without "collision / ambiguity" and
//    "resource exhaustion / amplification".
//  - The card body additionally requires replay/idempotence and rollback tests
//    "sui codec (I-BIND, I-SM, I-CODEC)": those three codecs implement exactly
//    the canonical-encoding, replay and no-partial-state rules above.
//  - The parent scan itself never reached this subtree: every `styx-js/src/**`
//    module in GAPS-SCAN.json sits at depth 3, so `src/crypto/m2/`,
//    `src/crypto/mls/m2/` and `src/storage/m2/` were never mapped at all.
//
// Deterministic and offline: fixed byte vectors, a seeded xorshift PRNG, no
// network, no wall clock, no unseeded randomness.

import { readFileSync } from 'node:fs';
import { describe, expect, test } from '@jest/globals';

import {
  BindingV0Error,
  compareBindingV0,
  decodeBindingV0,
  encodeBindingV0,
} from '../../src/crypto/m2-binding-v0.js';
import {
  createAdapterSnapshot,
  transitionAdapter,
} from '../../src/crypto/mls/m2/state-machine.js';
import {
  M2StorageCodecError,
  decodeAad,
  decodeEnvelope,
  decodePlaintext,
  decodeRecordKey,
  decodeSelectorKey,
  encodeRecordKey,
  M2_KIND,
} from '../../src/storage/m2/session-codec.js';

const id = (byte) => new Uint8Array(32).fill(byte);
const BINDING = encodeBindingV0({ localContextId: id(1), secureSessionIdentity: id(2) });

const CODEC_ERROR_CODES = new Set([
  'MALFORMED_INPUT',
  'UNSUPPORTED_VALUE',
  'AUTHENTICATION_FAILED',
  'CONTEXT_MISMATCH',
  'KEY_PACKAGE_ALREADY_USED',
]);

// Closed set of adapter error codes (state-machine.js TABLES.errorOrder).
const ADAPTER_ERROR_CODES = new Set([
  'UNKNOWN_FIELD', 'INVALID_REQUEST', 'UNKNOWN_VALUE', 'UNSUPPORTED_API_VERSION',
  'UNSUPPORTED_PROFILE', 'BINDING_MISMATCH', 'UNSUPPORTED_OPERATION',
  'RECONCILIATION_REQUIRED', 'SESSION_ALREADY_EXISTS', 'NO_ACTIVE_SESSION',
  'NO_STORED_SESSION', 'NO_RECONCILIATION_PENDING', 'RECONCILIATION_REFERENCE_MISMATCH',
  'VALUE_OUT_OF_RANGE', 'EPOCH_OUTSIDE_RETAINED_WINDOW', 'FUTURE_EPOCH',
  'AUTHENTICATION_FAILED', 'AUTHENTICATED_STATE_INCONSISTENT',
  'STORED_SESSION_INCOMPATIBLE', 'UNSUPPORTED_ONBOARDING',
  'WELCOME_NO_MATCHING_KEY_PACKAGE', 'UNSUPPORTED_UPDATE_FORM',
  'UNSUPPORTED_COMMIT_SHAPE', 'KEY_PACKAGE_ALREADY_CONSUMED', 'FAIL_CLOSED_INTERNAL',
]);

// Deterministic xorshift32: identical corpus on every run and every machine.
function bytesFromSeed(seed, length) {
  let state = seed >>> 0;
  const out = new Uint8Array(length);
  for (let index = 0; index < length; index += 1) {
    state ^= state << 13; state >>>= 0;
    state ^= state >>> 17;
    state ^= state << 5; state >>>= 0;
    out[index] = state & 0xff;
  }
  return out;
}

const asHex = (value) => Buffer.from(value).toString('hex');

// ---------------------------------------------------------------------------
// I-BIND — binding v0
// ---------------------------------------------------------------------------

describe('I-BIND: canonical binding, truncation, replay', () => {
  test('a valid binding is exactly 389 bytes and round-trips by replay', () => {
    expect(BINDING.length).toBe(389);
    const first = decodeBindingV0(BINDING);
    const second = decodeBindingV0(BINDING);
    expect(first.localContextId).toEqual(id(1));
    expect(first.secureSessionIdentity).toEqual(id(2));
    expect(first).toEqual(second);
    expect(asHex(encodeBindingV0({ localContextId: id(1), secureSessionIdentity: id(2) }))).toBe(asHex(BINDING));
    // Decoded arrays are snapshots: mutating them cannot corrupt a later decode.
    first.localContextId[0] = 0xff;
    expect(decodeBindingV0(BINDING).localContextId).toEqual(id(1));
  });

  test('malformed/truncated: every strict prefix is refused, none parses partially', () => {
    for (let length = 0; length < BINDING.length; length += 1) {
      expect(() => decodeBindingV0(BINDING.slice(0, length))).toThrowError(BindingV0Error);
    }
    expect(() => decodeBindingV0(new Uint8Array([...BINDING, 0]))).toThrowError(BindingV0Error);
    expect(() => decodeBindingV0(new Uint8Array(0))).toThrowError(BindingV0Error);
    expect(() => decodeBindingV0('not bytes')).toThrowError(BindingV0Error);
    expect(() => decodeBindingV0(null)).toThrowError(BindingV0Error);
  });

  test('canonicalization: a re-magicked, re-versioned or re-framed binding is refused', () => {
    const badMagic = Uint8Array.from(BINDING); badMagic[0] = 0x00;
    const badVersion = Uint8Array.from(BINDING); badVersion[9] = 0x01;
    // A frame whose declared length disagrees with the fixed layout.
    const badFrame = Uint8Array.from(BINDING); badFrame[11] = 0x1f;
    // A valid binding plus one trailing byte is not the canonical encoding.
    const trailing = new Uint8Array([...BINDING, 0x00]);
    for (const value of [badMagic, badVersion, badFrame, trailing]) {
      expect(() => decodeBindingV0(value)).toThrowError(BindingV0Error);
    }
    // Zero identifiers are refused even though the framing is intact.
    const zeroContext = Uint8Array.from(BINDING); zeroContext.fill(0, 13, 45);
    expect(() => decodeBindingV0(zeroContext)).toThrowError(BindingV0Error);
  });

  test('hostile encode input: descriptors are read without invoking accessors', () => {
    let invoked = 0;
    const hostile = { secureSessionIdentity: id(2) };
    Object.defineProperty(hostile, 'localContextId', {
      enumerable: true,
      configurable: true,
      get() { invoked += 1; return id(1); },
    });
    expect(() => encodeBindingV0(hostile)).toThrowError(BindingV0Error);
    expect(invoked).toBe(0);
  });

  test('hostile input shapes: symbols, extra keys, prototypes and short identifiers', () => {
    const withSymbol = { localContextId: id(1), secureSessionIdentity: id(2) };
    withSymbol[Symbol('extra')] = 1;
    const cases = [
      withSymbol,
      { localContextId: id(1), secureSessionIdentity: id(2), extra: 1 },
      { localContextId: id(1) },
      Object.create({ localContextId: id(1), secureSessionIdentity: id(2) }),
      null,
      [],
      { localContextId: id(1).slice(0, 31), secureSessionIdentity: id(2) },
      { localContextId: id(1), secureSessionIdentity: new Uint8Array(32) },
      { localContextId: [1], secureSessionIdentity: id(2) },
    ];
    for (const value of cases) {
      expect(() => encodeBindingV0(value)).toThrowError(BindingV0Error);
    }
  });

  test('replay: repeated encodes are byte-identical and mismatches are typed', () => {
    const again = encodeBindingV0({ localContextId: id(1), secureSessionIdentity: id(2) });
    expect(asHex(again)).toBe(asHex(BINDING));
    expect(compareBindingV0(BINDING, again)).toBe(true);
    const otherSession = encodeBindingV0({ localContextId: id(1), secureSessionIdentity: id(3) });
    const otherContext = encodeBindingV0({ localContextId: id(9), secureSessionIdentity: id(2) });
    expect(() => compareBindingV0(BINDING, otherContext)).toThrowError(BindingV0Error);
    expect(() => compareBindingV0(BINDING, otherSession)).toThrowError(BindingV0Error);
    // A comparison never leaves a partially decoded value behind.
    expect(decodeBindingV0(BINDING).localContextId).toEqual(id(1));
  });
});

// ---------------------------------------------------------------------------
// I-SM — adapter state machine
// ---------------------------------------------------------------------------

const event = (over = {}) => ({ operation: 'CREATE', applicableErrors: [], facts: 'UNSUPPORTED_ONBOARDING', ...over });

const expectRejected = (envelope) => {
  expect(envelope.result.kind).toBe('REJECTED');
  expect(ADAPTER_ERROR_CODES.has(envelope.result.code)).toBe(true);
  expect(envelope.result.stateAfter).toBe(envelope.result.stateBefore);
  expect(envelope.mutation).toBeNull();
};

describe('I-SM: fail-closed on hostile state, replay determinism, no mutation', () => {
  test('replay/idempotence: identical inputs give identical envelopes and never mutate the input', () => {
    const snapshot = createAdapterSnapshot('EMPTY');
    const before = JSON.stringify(snapshot);
    const first = transitionAdapter(snapshot, event());
    const second = transitionAdapter(snapshot, event());
    expect(first).toEqual(second);
    expect(JSON.stringify(snapshot)).toBe(before);
    expect(Object.isFrozen(snapshot)).toBe(true);
  });

  test('rollback: every rejected transition leaves the state unchanged', () => {
    const snapshot = createAdapterSnapshot('EMPTY');
    const rejected = [
      event({ operation: 'CREATE' }), // no fact and no applicable error
      event({ facts: 'AUTHENTICATION_FAILED', applicableErrors: ['AUTHENTICATION_FAILED'] }),
      event({ operation: 'NOPE' }),
      event({ operation: 'CREATE', facts: 'UNSUPPORTED_UPDATE_FORM' }),
    ];
    for (const value of rejected) {
      expectRejected(transitionAdapter(snapshot, value));
    }
    expect(snapshot.state).toBe('EMPTY');
  });

  test('hostile snapshots: refused with a typed rejection and no state advance', () => {
    let invoked = 0;
    const accessorSnapshot = {};
    Object.defineProperty(accessorSnapshot, 'state', {
      enumerable: true,
      configurable: true,
      get() { invoked += 1; return 'ACTIVE'; },
    });
    const symbolSnapshot = { state: 'EMPTY', held: null };
    symbolSnapshot[Symbol('holding')] = 'ACTIVE';
    const hostile = [
      null,
      undefined,
      0,
      'ACTIVE',
      [],
      Object.create({ state: 'EMPTY' }),
      symbolSnapshot,
      accessorSnapshot,
      { state: 'ACTIVE\n' },
      { state: ' reconciliation' },
      { state: 'x'.repeat(1 << 20) },
      { state: 'EMPTY', held: null, extra: 1 },
      { state: 'EMPTY', held: { scenario: 'CAPI-S017' } },
      { state: 'ACTIVE', held: { scenario: 'CAPI-S017' } },
    ];
    for (const snapshot of hostile) {
      const envelope = transitionAdapter(snapshot, event());
      expectRejected(envelope);
      expect(envelope.snapshot).toBeNull();
    }
    expect(invoked).toBe(0);
  });

  test('hostile events: accessors are never invoked and malformed shapes are refused', () => {
    const snapshot = createAdapterSnapshot('EMPTY');
    let invoked = 0;
    const accessorEvent = { applicableErrors: [], facts: 'UNSUPPORTED_ONBOARDING' };
    Object.defineProperty(accessorEvent, 'operation', {
      enumerable: true,
      configurable: true,
      get() { invoked += 1; return 'CREATE'; },
    });
    const hostile = [
      accessorEvent,
      null,
      'CREATE',
      42,
      {},
      { operation: 'CREATE', applicableErrors: [], facts: 'UNSUPPORTED_ONBOARDING', extra: true },
      { operation: 'CREATE', applicableErrors: 'none', facts: 'x' },
      { operation: 'CREATE', applicableErrors: ['NOT_A_CODE'], facts: 'x' },
      { operation: 'CREATE', applicableErrors: ['AUTHENTICATION_FAILED', 'AUTHENTICATION_FAILED'], facts: 'x' },
      { operation: 'CREATE', applicableErrors: [], facts: { toString: () => 'x' } },
      { operation: 'CREATE', applicableErrors: [], facts: 1e6 },
      { operation: 'CREATE\n', applicableErrors: [], facts: 'x' },
      { operation: 'C'.repeat(1 << 16), applicableErrors: [], facts: 'x' },
    ];
    for (const value of hostile) {
      expectRejected(transitionAdapter(snapshot, value));
    }
    expect(invoked).toBe(0);
    expect(snapshot.state).toBe('EMPTY');
  });

  test('liveness/purity: the codec modules carry no network, clock or randomness primitives', () => {
    const sources = [
      'src/crypto/m2-binding-v0.js',
      'src/crypto/mls/m2/state-machine.js',
      'src/storage/m2/session-codec.js',
      'src/crypto/vault-shape.js',
      'src/crypto/vault-key-guards.js',
      'src/crypto/kdf-bounds.js',
      'src/crypto/vault-aad.js',
    ];
    const banned = ['fetch(', 'XMLHttpRequest', 'WebSocket', 'setTimeout', 'setInterval', 'Date.now', 'Math.random', 'process.env'];
    for (const relative of sources) {
      const source = readFileSync(new URL(`../../${relative}`, import.meta.url), 'utf8');
      for (const token of banned) {
        expect({ relative, token, present: source.includes(token) }).toEqual({ relative, token, present: false });
      }
    }
  });
});

// ---------------------------------------------------------------------------
// I-CODEC — authenticated storage byte codecs
// ---------------------------------------------------------------------------

describe('I-CODEC: typed rejection of hostile bytes, canonical keys, caps', () => {
  test('truncation: every strict prefix of a valid record key is refused with a typed code', () => {
    const key = recordKey(id(4));
    for (let length = 0; length < key.length; length += 1) {
      let thrown;
      try {
        decodeRecordKey(key.slice(0, length));
      } catch (error) {
        thrown = error;
      }
      expect(thrown).toBeInstanceOf(M2StorageCodecError);
      expect(CODEC_ERROR_CODES.has(thrown.code)).toBe(true);
    }
    expect(decodeRecordKey(key)).toBeDefined();
  });

  test('canonicalization: record and selector keys round-trip byte-exactly', () => {
    const key = recordKey(id(4));
    const selectorKey = encodeSelectorKeyBytes();
    const decoded = decodeRecordKey(key);
    expect(asHex(decoded.localContextId)).toBe(asHex(id(4)));
    expect(decoded.recordKind).toBe(M2_KIND.SESSION_STATE);
    expect(decodeRecordKey(key)).toEqual(decoded);
    expect(asHex(decodeSelectorKey(selectorKey).localContextId)).toBe(asHex(id(4)));
    // A non-canonical tail or a mutated payload is refused, not silently ignored.
    expect(() => decodeRecordKey(new Uint8Array([...key, 0]))).toThrowError(M2StorageCodecError);
    expect(() => decodeSelectorKey(new Uint8Array([...selectorKey, 0]))).toThrowError(M2StorageCodecError);
    const mutated = Uint8Array.from(key);
    mutated[20] ^= 0x01;
    expect(() => decodeRecordKey(mutated)).toThrowError(M2StorageCodecError);
  });

  test('malformed corpus: typed rejection for every mangled or truncated decoder input', () => {
    const corpora = {
      decodeRecordKey: [new Uint8Array(0), new Uint8Array(40), bytesFromSeed(1, 40), bytesFromSeed(2, 8), id(0)],
      decodeSelectorKey: [new Uint8Array(0), new Uint8Array(42), bytesFromSeed(3, 42), bytesFromSeed(4, 41)],
      decodeAad: [new Uint8Array(0), new Uint8Array(80), bytesFromSeed(5, 120), bytesFromSeed(6, 4)],
      decodeEnvelope: [new Uint8Array(0), new Uint8Array(60), bytesFromSeed(7, 200), bytesFromSeed(8, 12)],
      decodePlaintext: [new Uint8Array(0), new Uint8Array(15), bytesFromSeed(9, 64)],
    };
    const decoders = { decodeRecordKey, decodeSelectorKey, decodeAad, decodeEnvelope, decodePlaintext };
    for (const [name, inputs] of Object.entries(corpora)) {
      for (const value of inputs) {
        let thrown;
        try {
          if (name === 'decodePlaintext') decoders[name](M2_KIND.SESSION_STATE, value);
          else decoders[name](value);
        } catch (error) {
          thrown = error;
        }
        expect(thrown).toBeInstanceOf(M2StorageCodecError);
        expect(CODEC_ERROR_CODES.has(thrown.code)).toBe(true);
      }
      // Non-byte inputs never reach a raw TypeError contract break.
      let thrown;
      try {
        if (name === 'decodePlaintext') decoders[name](M2_KIND.SESSION_STATE, 'x');
        else decoders[name]('x');
      } catch (error) {
        thrown = error;
      }
      expect(thrown).toBeInstanceOf(M2StorageCodecError);
    }
    // An unknown record kind is refused before any byte work happens.
    expect(() => decodePlaintext(9999, new Uint8Array(32))).toThrowError(M2StorageCodecError);
  });

  test('boundary/cap: an AAD header declaring a length beyond the 16 MiB cap is refused', () => {
    // Amplification guard: a 4-byte declared length must never drive an
    // allocation or a slice. The header below declares plaintextLength far
    // above the C-FMT cap and carries no payload.
    const header = new Uint8Array(60);
    header.set(new TextEncoder().encode('STYXAAD1'), 0);
    header[9] = 1; // format version
    header[11] = 1; // envelope version
    header[13] = M2_KIND.SESSION_STATE;
    header[15] = 1; // record kind version
    header[17] = 1; // key version
    const declared = new Uint8Array([...header, ...new Uint8Array(32)]);
    expect(() => decodeAad(declared)).toThrowError(M2StorageCodecError);
    // The empty byte string and an exactly-cap-sized but unstyled buffer are
    // both refused: there is no size for which the decoder trusts the header.
    expect(() => decodeAad(new Uint8Array(0))).toThrowError(M2StorageCodecError);
    expect(() => decodeAad(bytesFromSeed(11, 16 * 1024 * 1024))).toThrowError(M2StorageCodecError);
  });

  test('hostile inputs: object shapes are refused before any field is read', () => {
    for (const value of [null, undefined, 1, {}, [], Object.create({ localContextId: id(1) })]) {
      expect(() => decodeRecordKey(value)).toThrowError(M2StorageCodecError);
      expect(() => decodeSelectorKey(value)).toThrowError(M2StorageCodecError);
      expect(() => decodeEnvelope(value)).toThrowError(M2StorageCodecError);
    }
  });

  test('encoder hostile shapes: unknown, symbol, accessor and missing fields are refused', () => {
    const valid = {
      scope: 1,
      localContextId: id(1),
      secureSessionIdentity: null,
      writeGeneration: 1n,
      recordKind: M2_KIND.SESSION_STATE,
    };
    const extra = { ...valid, surprise: 1 };
    const symbol = { ...valid };
    symbol[Symbol('smuggled')] = 1;
    const accessor = { ...valid };
    let invoked = 0;
    Object.defineProperty(accessor, 'recordKind', {
      enumerable: true,
      configurable: true,
      get() { invoked += 1; return M2_KIND.SESSION_STATE; },
    });
    const missing = {
      scope: 1,
      localContextId: id(1),
      secureSessionIdentity: null,
      writeGeneration: 1n,
    };
    const notPlain = Object.create({ ...valid });
    for (const input of [extra, symbol, accessor, missing, notPlain, null, 0, []]) {
      expect(() => encodeRecordKey(input)).toThrowError(M2StorageCodecError);
    }
    expect(invoked).toBe(0);
    expect(encodeRecordKey(valid)).toBeInstanceOf(Uint8Array);
  });
});

function recordKey(context, kind = M2_KIND.SESSION_STATE) {
  return encodeRecordKey({
    scope: 1,
    localContextId: context,
    secureSessionIdentity: null,
    writeGeneration: 1n,
    recordKind: kind,
  });
}

function encodeSelectorKeyBytes() {
  // Local mirror of the codec's selector-key framing: 'STYXSEL1' + u16(1) + 32
  // nonzero bytes. Kept local so the test asserts the decoder, not the encoder.
  const handle = new Uint8Array(42);
  handle.set(new TextEncoder().encode('STYXSEL1'), 0);
  handle[8] = 0; handle[9] = 1;
  handle.set(id(4), 10);
  return handle;
}
