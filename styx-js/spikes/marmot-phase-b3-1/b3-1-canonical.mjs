export const B31_GROUP_PROFILE_COMPONENT_ID = 0x8001;
export const B31_SUPPORTED_COMPONENT_IDS = Object.freeze([0x8001, 0x8003, 0x8009, 0x800c]);
export const B31_REQUIRED_COMPONENT_IDS = Object.freeze([0x8001, 0x8003, 0x8009, 0x800c]);
export const B31_GROUP_CONTEXT_COMPONENT_IDS = Object.freeze([1, 0x8001, 0x8003, 0x800c]);
export const B31_LEAF_COMPONENT_IDS = Object.freeze([1, 0x8009]);
export const B31_GROUP_PROFILE_LIMITS = Object.freeze({
  descriptionBytes: 4096,
  nameBytes: 256,
});

const fatalDecoder = new TextDecoder('utf-8', { fatal: true });

export class B31CanonicalError extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.name = 'B31CanonicalError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new B31CanonicalError(code, message);
}

export function assertBytes(value, label) {
  if (!(value instanceof Uint8Array)) fail('B31_INVALID', `${label} must be Uint8Array`);
  return value;
}

export function bytesEqual(left, right) {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

export function encodeCanonicalQuicVarint(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value >= 2 ** 53) {
    fail('B31_INVALID', 'QUIC varint must be a non-negative safe integer');
  }
  const numeric = BigInt(value);
  let width;
  let prefix;
  if (numeric < 2n ** 6n) {
    width = 1;
    prefix = 0n;
  } else if (numeric < 2n ** 14n) {
    width = 2;
    prefix = 1n << 14n;
  } else if (numeric < 2n ** 30n) {
    width = 4;
    prefix = 2n << 30n;
  } else if (numeric < 2n ** 62n) {
    width = 8;
    prefix = 3n << 62n;
  } else {
    fail('B31_RESOURCE_LIMIT', 'QUIC varint exceeds 62 bits');
  }
  let encoded = numeric | prefix;
  const bytes = new Uint8Array(width);
  for (let index = width - 1; index >= 0; index -= 1) {
    bytes[index] = Number(encoded & 0xffn);
    encoded >>= 8n;
  }
  return bytes;
}

export function decodeCanonicalQuicVarint(bytes, start = 0) {
  assertBytes(bytes, 'QUIC-varint input');
  if (!Number.isSafeInteger(start) || start < 0 || start >= bytes.length) {
    fail('B31_MALFORMED', 'truncated QUIC varint');
  }
  const width = 1 << (bytes[start] >> 6);
  if (start + width > bytes.length) fail('B31_MALFORMED', 'truncated QUIC varint');
  let value = BigInt(bytes[start] & 0x3f);
  for (let index = start + 1; index < start + width; index += 1) {
    value = (value << 8n) | BigInt(bytes[index]);
  }
  const minimum = width === 1 ? 0n : 2n ** BigInt(width === 2 ? 6 : width === 4 ? 14 : 30);
  if (value < minimum) fail('B31_NON_CANONICAL', 'QUIC varint is not minimally encoded');
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) fail('B31_RESOURCE_LIMIT', 'QUIC varint is unsafe');
  return Object.freeze({ nextOffset: start + width, value: Number(value), width });
}

function validateUtf8Field(bytes, maximum, label) {
  assertBytes(bytes, label);
  if (bytes.length > maximum) fail('B31_RESOURCE_LIMIT', `${label} exceeds ${maximum} bytes`);
  try {
    fatalDecoder.decode(bytes);
  } catch {
    fail('B31_MALFORMED', `${label} is not strict UTF-8`);
  }
}

export function encodeGroupProfileBytes(name, description) {
  validateUtf8Field(name, B31_GROUP_PROFILE_LIMITS.nameBytes, 'group-profile name');
  validateUtf8Field(
    description,
    B31_GROUP_PROFILE_LIMITS.descriptionBytes,
    'group-profile description',
  );
  const nameLength = encodeCanonicalQuicVarint(name.length);
  const descriptionLength = encodeCanonicalQuicVarint(description.length);
  const output = new Uint8Array(
    nameLength.length + name.length + descriptionLength.length + description.length,
  );
  let offset = 0;
  output.set(nameLength, offset);
  offset += nameLength.length;
  output.set(name, offset);
  offset += name.length;
  output.set(descriptionLength, offset);
  offset += descriptionLength.length;
  output.set(description, offset);
  return output;
}

export function decodeGroupProfileBytes(bytes) {
  assertBytes(bytes, 'group-profile payload');
  const nameLength = decodeCanonicalQuicVarint(bytes, 0);
  if (nameLength.value > B31_GROUP_PROFILE_LIMITS.nameBytes) {
    fail('B31_RESOURCE_LIMIT', 'group-profile name exceeds 256 bytes');
  }
  const nameEnd = nameLength.nextOffset + nameLength.value;
  if (nameEnd > bytes.length) fail('B31_MALFORMED', 'group-profile name is truncated');
  const name = bytes.slice(nameLength.nextOffset, nameEnd);
  validateUtf8Field(name, B31_GROUP_PROFILE_LIMITS.nameBytes, 'group-profile name');

  const descriptionLength = decodeCanonicalQuicVarint(bytes, nameEnd);
  if (descriptionLength.value > B31_GROUP_PROFILE_LIMITS.descriptionBytes) {
    fail('B31_RESOURCE_LIMIT', 'group-profile description exceeds 4096 bytes');
  }
  const descriptionEnd = descriptionLength.nextOffset + descriptionLength.value;
  if (descriptionEnd > bytes.length) {
    fail('B31_MALFORMED', 'group-profile description is truncated');
  }
  if (descriptionEnd !== bytes.length) fail('B31_MALFORMED', 'group-profile has trailing bytes');
  const description = bytes.slice(descriptionLength.nextOffset, descriptionEnd);
  validateUtf8Field(
    description,
    B31_GROUP_PROFILE_LIMITS.descriptionBytes,
    'group-profile description',
  );
  return Object.freeze({ description, name });
}

export function assertExactComponentIds(actual, expected, label) {
  if (!Array.isArray(actual) || actual.some((value) => !Number.isInteger(value))) {
    fail('B31_INVALID', `${label} must be an integer array`);
  }
  if (actual.length !== expected.length || actual.some((value, index) => value !== expected[index])) {
    fail('B31_PROFILE_MISMATCH', `${label} does not match the exact B3.1 profile`);
  }
  if (actual.some((value, index) => index > 0 && actual[index - 1] >= value)) {
    fail('B31_NON_CANONICAL', `${label} must be strictly ascending and unique`);
  }
  return Object.freeze([...actual]);
}
