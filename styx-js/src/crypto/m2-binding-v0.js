const MAGIC = Uint8Array.of(0x53, 0x54, 0x59, 0x58, 0x4d, 0x42, 0x4e, 0x44);
const ENCODING_VERSION = 0;
const IDENTIFIER_LENGTH = 32;
const PROFILE_LENGTH = 306;
const BINDING_LENGTH = 389;

const ERROR_CODES = new Set([
  'MALFORMED_BINDING',
  'UNSUPPORTED_PROFILE',
  'BINDING_MISMATCH',
  'AUTHENTICATED_STATE_INCONSISTENT',
]);

const ascii = (value) => Uint8Array.from([...value].map((character) => character.charCodeAt(0)));
const raw = (value) => {
  const result = new Uint8Array(value.length / 2);
  for (let index = 0; index < result.length; index += 1) {
    result[index] = Number.parseInt(value.slice(index * 2, (index * 2) + 2), 16);
  }
  return result;
};

const PROFILE_FIELDS = Object.freeze([
  [1, 'ascii', ascii('styx-m2-session-adapter/v1')],
  [2, 'ascii', ascii('m2-opaque-binding/v0')],
  [3, 'ascii', ascii('session')],
  [4, 'ascii', ascii('mls')],
  [5, 'ascii', ascii('test-profile')],
  [6, 'ascii', ascii('two-member-direct')],
  [7, 'hex20', raw('09e92777dba0528d3d29e2e5e681b7e91637c7be')],
  [8, 'ascii', ascii('styx-js/vendor/openmls-wasm/openmls_wasm_bg.wasm')],
  [9, 'hex32', raw('fef05368f143de044274f8804d2ba195a1f886bc528651e98bd9c393fde4650e')],
  [10, 'u16be', Uint8Array.of(0, 1)],
  [11, 'ascii', ascii('MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519')],
  [12, 'hex32', raw('235bcb86f9dd25e3c3cb56ed3a0b4820214821cf78ea881547c824db831eba07')],
  [13, 'u32be', Uint8Array.of(0, 0, 0, 5)],
]);

function frame(tag, value) {
  const result = new Uint8Array(3 + value.length);
  result[0] = tag;
  result[1] = value.length >>> 8;
  result[2] = value.length & 0xff;
  result.set(value, 3);
  return result;
}

function concat(parts) {
  const length = parts.reduce((total, part) => total + part.length, 0);
  const result = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

const PRODUCT_PROFILE = concat(PROFILE_FIELDS.map(([tag, _wireType, value]) => frame(tag, value)));
if (PRODUCT_PROFILE.length !== PROFILE_LENGTH) {
  throw new Error('invalid fixed M2 binding profile');
}

function equal(left, right) {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function isZero(value) {
  let aggregate = 0;
  for (const byte of value) aggregate |= byte;
  return aggregate === 0;
}

function fail(code, message) {
  throw new BindingV0Error(code, message);
}

function requireIdentifier(value, name) {
  if (!(value instanceof Uint8Array) || value.length !== IDENTIFIER_LENGTH || isZero(value)) {
    fail('MALFORMED_BINDING', `${name} must be 32 nonzero bytes`);
  }
}

function requireEncodeInput(input) {
  if (input === null || typeof input !== 'object' || Object.getPrototypeOf(input) !== Object.prototype) {
    fail('MALFORMED_BINDING', 'binding input must be a plain object');
  }
  const names = Reflect.ownKeys(input);
  if (
    names.length !== 2 ||
    !names.includes('localContextId') ||
    !names.includes('secureSessionIdentity')
  ) {
    fail('MALFORMED_BINDING', 'binding input has unknown or missing keys');
  }
  for (const name of names) {
    const descriptor = Object.getOwnPropertyDescriptor(input, name);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
      fail('MALFORMED_BINDING', 'binding input keys must be enumerable data properties');
    }
  }
  requireIdentifier(input.localContextId, 'localContextId');
  requireIdentifier(input.secureSessionIdentity, 'secureSessionIdentity');
}

function readField(bytes, offset, expectedTag, expectedLength) {
  if (offset + 3 > bytes.length || bytes[offset] !== expectedTag) {
    fail('MALFORMED_BINDING', 'binding field tag or header is invalid');
  }
  const length = (bytes[offset + 1] << 8) | bytes[offset + 2];
  if (length !== expectedLength || offset + 3 + length > bytes.length) {
    fail('MALFORMED_BINDING', 'binding field length is invalid');
  }
  return {
    nextOffset: offset + 3 + length,
    value: bytes.slice(offset + 3, offset + 3 + length),
  };
}

function validateWireType(value, wireType) {
  if (wireType === 'ascii') {
    for (const byte of value) {
      if (byte === 0 || byte > 0x7f) {
        fail('MALFORMED_BINDING', 'profile ASCII field is invalid');
      }
    }
    return;
  }
  const requiredLength = { hex20: 20, hex32: 32, u16be: 2, u32be: 4 }[wireType];
  if (value.length !== requiredLength) {
    fail('MALFORMED_BINDING', 'profile wire width is invalid');
  }
}

function validateProductProfile(profile) {
  let offset = 0;
  for (const [tag, wireType, expected] of PROFILE_FIELDS) {
    const field = readField(profile, offset, tag, expected.length);
    validateWireType(field.value, wireType);
    offset = field.nextOffset;
  }
  if (offset !== profile.length) {
    fail('MALFORMED_BINDING', 'profile has trailing bytes');
  }
  if (!equal(profile, PRODUCT_PROFILE)) {
    fail('UNSUPPORTED_PROFILE', 'binding product profile is unsupported');
  }
}

function encodeCanonical(localContextId, secureSessionIdentity) {
  return concat([
    MAGIC,
    Uint8Array.of(ENCODING_VERSION >>> 8, ENCODING_VERSION & 0xff),
    frame(1, localContextId),
    frame(2, secureSessionIdentity),
    frame(3, PRODUCT_PROFILE),
  ]);
}

export class BindingV0Error extends Error {
  constructor(code, message = code) {
    if (!ERROR_CODES.has(code)) throw new TypeError('unknown binding-v0 error code');
    super(message);
    Object.defineProperty(this, 'code', {
      configurable: false,
      enumerable: true,
      value: code,
      writable: false,
    });
  }
}

export function encodeBindingV0(input) {
  requireEncodeInput(input);
  return encodeCanonical(input.localContextId, input.secureSessionIdentity);
}

export function decodeBindingV0(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== BINDING_LENGTH) {
    fail('MALFORMED_BINDING', 'binding must be exactly 389 bytes');
  }
  if (!equal(bytes.slice(0, MAGIC.length), MAGIC)) {
    fail('MALFORMED_BINDING', 'binding magic is invalid');
  }
  const version = (bytes[8] << 8) | bytes[9];
  if (version !== ENCODING_VERSION) {
    fail('MALFORMED_BINDING', 'binding encoding version is invalid');
  }

  const context = readField(bytes, 10, 1, IDENTIFIER_LENGTH);
  const session = readField(bytes, context.nextOffset, 2, IDENTIFIER_LENGTH);
  const profile = readField(bytes, session.nextOffset, 3, PROFILE_LENGTH);
  if (profile.nextOffset !== bytes.length) {
    fail('MALFORMED_BINDING', 'binding has trailing bytes');
  }
  requireIdentifier(context.value, 'localContextId');
  requireIdentifier(session.value, 'secureSessionIdentity');
  validateProductProfile(profile.value);

  const canonical = encodeCanonical(context.value, session.value);
  if (!equal(bytes, canonical)) {
    fail('MALFORMED_BINDING', 'binding is not canonical');
  }
  return {
    localContextId: context.value.slice(),
    productProfile: profile.value.slice(),
    secureSessionIdentity: session.value.slice(),
  };
}

export function compareBindingV0(authoritative, candidate) {
  const left = decodeBindingV0(authoritative);
  const right = decodeBindingV0(candidate);
  if (!equal(left.localContextId, right.localContextId)) {
    fail('BINDING_MISMATCH', 'binding context does not match');
  }
  if (!equal(left.secureSessionIdentity, right.secureSessionIdentity)) {
    fail('AUTHENTICATED_STATE_INCONSISTENT', 'binding session does not match');
  }
  return true;
}
