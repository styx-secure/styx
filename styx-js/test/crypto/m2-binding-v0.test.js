import { createHash } from 'node:crypto';

import {
  BindingV0Error,
  compareBindingV0,
  decodeBindingV0,
  encodeBindingV0,
} from '../../src/crypto/m2-binding-v0.js';

const PROFILE_HEX =
  '01001a737479782d6d322d73657373696f6e2d616461707465722f7631' +
  '0200146d322d6f70617175652d62696e64696e672f7630' +
  '03000773657373696f6e' +
  '0400036d6c73' +
  '05000c746573742d70726f66696c65' +
  '06001174776f2d6d656d6265722d646972656374' +
  '07001409e92777dba0528d3d29e2e5e681b7e91637c7be' +
  '080030737479782d6a732f76656e646f722f6f70656e6d6c732d7761736d2f' +
  '6f70656e6d6c735f7761736d5f62672e7761736d' +
  '090020fef05368f143de044274f8804d2ba195a1f886bc528651e98bd9c393fde4650e' +
  '0a00020001' +
  '0b002c4d4c535f3132385f44484b454d5832353531395f41455331323847434d' +
  '5f5348413235365f45643235353139' +
  '0c0020235bcb86f9dd25e3c3cb56ed3a0b4820214821cf78ea881547c824db831eba07' +
  '0d000400000005';
const PREFIX_HEX = '535459584d424e440000';

const KATS = [
  {
    id: 'BIND-KAT-001',
    context: '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
    session: '2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40',
    sha256: 'b0960b281efff7e2fbc8a4c0aa406d9a32048d585d881d5bf5b93eeda480aba0',
  },
  {
    id: 'BIND-KAT-002',
    context: '4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60',
    session: '6162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80',
    sha256: '94fda7db9ebb262d72a4e43f679feab6421bd40ac3ce03067f69b2ca5ac111ad',
  },
  {
    id: 'BIND-KAT-003',
    context: 'f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f00f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f',
    session: 'aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55',
    sha256: '12668f36719fa39bb132886e5b94165697a491ebb8608f1a6441a95114319205',
  },
].map((vector) => ({
  ...vector,
  canonicalHex: `${PREFIX_HEX}010020${vector.context}020020${vector.session}030132${PROFILE_HEX}`,
}));

const bytes = (hex) => Uint8Array.from(Buffer.from(hex, 'hex'));
const hex = (value) => Buffer.from(value).toString('hex');
const digest = (value) => createHash('sha256').update(value).digest('hex');
const copy = (value) => Uint8Array.from(value);
const replace = (value, offset, replacement) => {
  const out = copy(value);
  out.set(replacement, offset);
  return out;
};
const removeRange = (value, start, end) =>
  Uint8Array.from([...value.slice(0, start), ...value.slice(end)]);
const insert = (value, offset, addition) =>
  Uint8Array.from([...value.slice(0, offset), ...addition, ...value.slice(offset)]);

function expectCode(fn, code) {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(BindingV0Error);
    expect(error.code).toBe(code);
    return;
  }
  throw new Error(`expected ${code}`);
}

function profileFieldValueOffsets(binding) {
  const offsets = [];
  let cursor = 83;
  for (let tag = 1; tag <= 13; tag += 1) {
    expect(binding[cursor]).toBe(tag);
    const length = (binding[cursor + 1] << 8) | binding[cursor + 2];
    offsets.push(cursor + 3);
    cursor += 3 + length;
  }
  expect(cursor).toBe(389);
  return offsets;
}

const katBytes = KATS.map((vector) => bytes(vector.canonicalHex));

describe('m2-opaque-binding/v0 known-answer vectors', () => {
  test.each(KATS)('$id encodes exact canonical bytes and digest', (vector) => {
    const context = bytes(vector.context);
    const session = bytes(vector.session);
    const first = encodeBindingV0({
      localContextId: context,
      secureSessionIdentity: session,
    });
    const second = encodeBindingV0({
      localContextId: context,
      secureSessionIdentity: session,
    });
    expect(first).toHaveLength(389);
    expect(hex(first)).toBe(vector.canonicalHex);
    expect(digest(first)).toBe(vector.sha256);
    expect(first).toEqual(second);
    expect(first).not.toBe(second);
  });

  test.each(KATS)('$id decodes and re-encodes byte-identically', (vector) => {
    const canonical = bytes(vector.canonicalHex);
    const decoded = decodeBindingV0(canonical);
    expect(hex(decoded.localContextId)).toBe(vector.context);
    expect(hex(decoded.secureSessionIdentity)).toBe(vector.session);
    expect(hex(decoded.productProfile)).toBe(PROFILE_HEX);
    expect(encodeBindingV0({
      localContextId: decoded.localContextId,
      secureSessionIdentity: decoded.secureSessionIdentity,
    })).toEqual(canonical);
  });

  test('the three bindings are pairwise unequal', () => {
    for (let left = 0; left < katBytes.length; left += 1) {
      for (let right = left + 1; right < katBytes.length; right += 1) {
        expect(katBytes[left]).not.toEqual(katBytes[right]);
      }
    }
  });
});

describe('m2-opaque-binding/v0 malformed fixtures', () => {
  const base = katBytes[0];
  const field1 = base.slice(10, 45);
  const field2 = base.slice(45, 80);
  const malformed = [
    ['NEG-GRAMMAR-WRONG-MAGIC', replace(base, 0, Uint8Array.of(0))],
    ['NEG-GRAMMAR-UNKNOWN-VERSION', replace(base, 8, Uint8Array.of(0, 1))],
    ['NEG-GRAMMAR-UNKNOWN-TAG', replace(base, 10, Uint8Array.of(4))],
    ['NEG-GRAMMAR-MISSING-FIELD', removeRange(base, 45, 80)],
    ['NEG-GRAMMAR-DUPLICATE-FIELD', insert(base, 45, field1)],
    [
      'NEG-GRAMMAR-REORDERED-FIELD',
      Uint8Array.from([...base.slice(0, 10), ...field2, ...field1, ...base.slice(80)]),
    ],
    ['NEG-GRAMMAR-TRUNCATED', base.slice(0, 388)],
    ['NEG-GRAMMAR-TRAILING', Uint8Array.from([...base, 0])],
    ['NEG-GRAMMAR-LENGTH-UNDERFLOW', replace(base, 11, Uint8Array.of(0, 31))],
    ['NEG-GRAMMAR-LENGTH-OVERFLOW', replace(base, 11, Uint8Array.of(0, 33))],
    ['NEG-GRAMMAR-WRONG-ENDIAN', replace(base, 11, Uint8Array.of(32, 0))],
    ['NEG-GRAMMAR-NONASCII', replace(base, 86, Uint8Array.of(0xff))],
    [
      'NEG-GRAMMAR-NUL-SUFFIX',
      insert(replace(replace(base, 81, Uint8Array.of(1, 51)), 84, Uint8Array.of(0, 27)), 112, Uint8Array.of(0)),
    ],
    ['NEG-GRAMMAR-ZERO-CONTEXT', replace(base, 13, new Uint8Array(32))],
    ['NEG-GRAMMAR-ZERO-SESSION', replace(base, 48, new Uint8Array(32))],
    ['NEG-OUTER-VERSION-SWAP', replace(base, 8, Uint8Array.of(1, 0))],
  ];

  test.each(malformed)('%s rejects as MALFORMED_BINDING', (_id, candidate) => {
    expectCode(() => decodeBindingV0(candidate), 'MALFORMED_BINDING');
  });

  test('a same-length embedded NUL reaches the ASCII wire-type guard', () => {
    expectCode(() => decodeBindingV0(replace(base, 86, Uint8Array.of(0))), 'MALFORMED_BINDING');
  });

  test.each([
    [null], [undefined], ['not bytes'], [[...base]], [new DataView(base.buffer)],
  ])('rejects non-Uint8Array input %#', (candidate) => {
    expectCode(() => decodeBindingV0(candidate), 'MALFORMED_BINDING');
  });
});

describe('m2-opaque-binding/v0 fail-closed comparisons', () => {
  const authoritative = katBytes[0];
  const other = katBytes[1];

  test('cross-context swap is BINDING_MISMATCH', () => {
    const candidate = replace(authoritative, 13, other.slice(13, 45));
    expectCode(() => compareBindingV0(authoritative, candidate), 'BINDING_MISMATCH');
  });

  test('cross-session swap is AUTHENTICATED_STATE_INCONSISTENT', () => {
    const candidate = replace(authoritative, 48, other.slice(48, 80));
    expectCode(
      () => compareBindingV0(authoritative, candidate),
      'AUTHENTICATED_STATE_INCONSISTENT',
    );
  });

  test('context mismatch precedes a simultaneous session mismatch', () => {
    const candidate = replace(
      replace(authoritative, 13, other.slice(13, 45)),
      48,
      other.slice(48, 80),
    );
    expectCode(() => compareBindingV0(authoritative, candidate), 'BINDING_MISMATCH');
  });

  test.each(profileFieldValueOffsets(authoritative).map((offset, index) => [index + 1, offset]))(
    'profile field %i swap is UNSUPPORTED_PROFILE',
    (_tag, offset) => {
      const candidate = copy(authoritative);
      candidate[offset] ^= 1;
      expectCode(() => compareBindingV0(authoritative, candidate), 'UNSUPPORTED_PROFILE');
    },
  );

  test('equal bindings compare true without mutating either input', () => {
    const left = copy(authoritative);
    const right = copy(authoritative);
    const leftBefore = copy(left);
    const rightBefore = copy(right);
    expect(compareBindingV0(left, right)).toBe(true);
    expect(left).toEqual(leftBefore);
    expect(right).toEqual(rightBefore);
  });
});

describe('m2-opaque-binding/v0 defensive ownership', () => {
  const context = bytes(KATS[0].context);
  const session = bytes(KATS[0].session);

  test.each([
    ['missing key', { localContextId: context }],
    ['unknown key', { localContextId: context, secureSessionIdentity: session, extra: true }],
    ['wrong context width', { localContextId: new Uint8Array(31), secureSessionIdentity: session }],
    ['wrong session width', { localContextId: context, secureSessionIdentity: new Uint8Array(33) }],
    ['zero context', { localContextId: new Uint8Array(32), secureSessionIdentity: session }],
    ['zero session', { localContextId: context, secureSessionIdentity: new Uint8Array(32) }],
    ['wrong context type', { localContextId: [...context], secureSessionIdentity: session }],
  ])('encode rejects %s', (_name, input) => {
    expectCode(() => encodeBindingV0(input), 'MALFORMED_BINDING');
  });

  test('encode rejects accessors and inherited keys', () => {
    const accessor = { secureSessionIdentity: session };
    Object.defineProperty(accessor, 'localContextId', { enumerable: true, get: () => context });
    const inherited = Object.create({ extra: true });
    inherited.localContextId = context;
    inherited.secureSessionIdentity = session;
    expectCode(() => encodeBindingV0(accessor), 'MALFORMED_BINDING');
    expectCode(() => encodeBindingV0(inherited), 'MALFORMED_BINDING');
  });

  test('encoded and decoded arrays never alias caller or each other', () => {
    const localContextId = copy(context);
    const secureSessionIdentity = copy(session);
    const encoded = encodeBindingV0({ localContextId, secureSessionIdentity });
    const original = copy(encoded);
    localContextId[0] ^= 1;
    secureSessionIdentity[0] ^= 1;
    expect(encoded).toEqual(original);

    const decoded = decodeBindingV0(encoded);
    decoded.localContextId[0] ^= 1;
    decoded.secureSessionIdentity[0] ^= 1;
    decoded.productProfile[0] ^= 1;
    expect(encoded).toEqual(original);
    expect(decoded.localContextId.buffer).not.toBe(decoded.secureSessionIdentity.buffer);
    expect(decoded.localContextId.buffer).not.toBe(decoded.productProfile.buffer);
  });

  test('BindingV0Error has a closed code surface', () => {
    const error = new BindingV0Error('MALFORMED_BINDING');
    expect(error).toBeInstanceOf(Error);
    expect(Object.keys(error)).toEqual(['code']);
    expect(error.code).toBe('MALFORMED_BINDING');
  });
});
