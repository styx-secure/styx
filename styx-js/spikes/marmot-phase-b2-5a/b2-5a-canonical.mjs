// STYX_SPIKE_PROTOTYPE — Phase B2.5a deterministic same-parent branch kernel.

import {
  B23_ERROR,
  B23_LIMITS,
  B23_RUNTIME,
  assertBytes,
  assertGroupIdHex,
  assertHex64,
  assertSafeInteger,
  assertString,
  bytesEqual,
  bytesToHex,
  canonicalBytes,
  copyBytes,
  digestHex,
  hexToBytes,
  parseEpochDecimal,
  snapshotClosedObject,
  validateProviderSnapshot,
} from '../marmot-phase-b2-3/b2-3-canonical.mjs';

export const B25_FORMAT = 'styx-marmot-b2-5a';
export const B25_VERSION = 1;
export const B25_PROFILE = 'same-parent-one-commit-branch-selection-poc';
export const B25_DB_PREFIX = 'styx-b2-5a-poc-v1-';
export const B25_MARMOT_REVISION = '4ad4ae21479c3f3fa9950c6fc4556a76941a62e1';

export const B25_LIMITS = Object.freeze({
  maxBatchCommits: 16,
  maxMembers: B23_LIMITS.maxMembers,
  maxCommitBytes: B23_LIMITS.maxCommitBytes,
  maxSnapshotBytes: B23_LIMITS.maxSnapshotBytes,
});

export const B25_STORES = Object.freeze({
  head: 'head',
  retained: 'retained-state',
  input: 'input',
  batch: 'frozen-batch',
  candidate: 'candidate-evidence',
  transition: 'transition',
});
export const B25_STORE_NAMES = Object.freeze(Object.values(B25_STORES));

export const B25_ERROR = Object.freeze({
  INVALID: 'B25_INVALID',
  CORRUPT: 'B25_CORRUPT',
  INCOMPATIBLE: 'B25_INCOMPATIBLE',
  NOT_FOUND: 'B25_NOT_FOUND',
  STATE_CONFLICT: 'B25_STATE_CONFLICT',
  CAS_CONFLICT: 'B25_CAS_CONFLICT',
  RESOURCE_LIMIT: 'B25_RESOURCE_LIMIT',
  ENGINE_REJECTED: 'B25_ENGINE_REJECTED',
  UNRECOVERABLE: 'B25_UNRECOVERABLE',
});

export const B25_HEAD_STATE = Object.freeze({
  STABLE: 'STABLE',
  UNRECOVERABLE: 'UNRECOVERABLE',
});
export const B25_BATCH_STATE = Object.freeze({ FROZEN: 'FROZEN', RESOLVED: 'RESOLVED' });
export const B25_CANDIDATE_STATE = Object.freeze({
  PENDING: 'PENDING',
  AUTHORIZED: 'AUTHORIZED',
  REJECTED: 'REJECTED',
  NOT_CANDIDATE: 'NOT_CANDIDATE',
});
export const B25_DISPOSITION = Object.freeze({
  COLLECTED: 'COLLECTED',
  FROZEN: 'FROZEN',
  SELECTED: 'SELECTED',
  LOSING: 'LOSING',
  REJECTED: 'REJECTED',
  NOT_CANDIDATE: 'NOT_CANDIDATE',
});
export const B25_REASON = Object.freeze({
  PENDING: 'B25_PENDING',
  SELECTED: 'B25_SELECTED',
  LOWER_PRIORITY: 'B25_LOWER_PRIORITY',
  NOT_CANDIDATE_FOR_RETAINED_PARENT: 'B25_NOT_CANDIDATE_FOR_RETAINED_PARENT',
});

export class B25Error extends Error {
  constructor(code, message, details = {}, options = {}) {
    super(`${code}: ${message}`, 'cause' in options ? { cause: options.cause } : undefined);
    this.name = 'B25Error';
    this.code = code;
    this.details = Object.freeze({ ...details });
  }
}

export function failB25(code, message, details, cause) {
  throw new B25Error(code, message, details, cause === undefined ? {} : { cause });
}

export function assertB25DirectObject(value, fields, label) {
  try {
    return snapshotClosedObject(value, fields, label);
  } catch (error) {
    if (error?.code === B23_ERROR.INVALID) {
      failB25(B25_ERROR.INVALID, `${label} has a non-canonical field set`, {}, error);
    }
    throw error;
  }
}

export function assertNullableHex64(name, value) {
  if (value !== null) assertHex64(name, value);
  return value;
}

export function assertNullableString(name, value, options) {
  if (value !== null) assertString(name, value, options);
  return value;
}

export function assertB25Runtime(value) {
  const safe = assertB25DirectObject(
    value,
    ['openMlsRevision', 'wasmArtifactSha256', 'ciphersuite', 'marmotRevision'],
    'B2.5a runtime',
  );
  if (safe.openMlsRevision !== B23_RUNTIME.openMlsRevision
    || safe.wasmArtifactSha256 !== B23_RUNTIME.wasmArtifactSha256
    || safe.ciphersuite !== B23_RUNTIME.ciphersuite
    || safe.marmotRevision !== B25_MARMOT_REVISION) {
    failB25(B25_ERROR.INCOMPATIBLE, 'runtime tuple does not match the approved B2.5a tuple');
  }
  return Object.freeze({ ...safe });
}

export const B25_RUNTIME = Object.freeze({ ...B23_RUNTIME, marmotRevision: B25_MARMOT_REVISION });

export function canonicalB25Bytes(domain, values) {
  return canonicalBytes(`STYX-B2-5A-${domain}-V1`, values);
}

export function digestB25(domain, values) {
  return digestHex(canonicalB25Bytes(domain, values));
}

export function assertSortedUniqueHex64(name, value, { min = 0, max = B25_LIMITS.maxBatchCommits } = {}) {
  if (!Array.isArray(value) || value.length < min || value.length > max) {
    failB25(B25_ERROR.INVALID, `${name} has an invalid count`);
  }
  let prior = null;
  const out = value.map((item) => {
    assertHex64(name, item);
    if (prior !== null && item <= prior) {
      failB25(B25_ERROR.INVALID, `${name} must be strictly sorted and unique`);
    }
    prior = item;
    return item;
  });
  return Object.freeze(out);
}

export function inputKey(groupIdHex, commitDigestHex) {
  assertGroupIdHex(groupIdHex);
  assertHex64('commitDigestHex', commitDigestHex);
  return `${groupIdHex}:${commitDigestHex}`;
}

export function candidateKey(batchDigestHex, commitDigestHex) {
  assertHex64('batchDigestHex', batchDigestHex);
  assertHex64('commitDigestHex', commitDigestHex);
  return `${batchDigestHex}:${commitDigestHex}`;
}

export function protocolBatchDigest({ groupIdHex, baseEpochDec, baseGroupContextDigestHex, commitDigests }) {
  assertGroupIdHex(groupIdHex);
  parseEpochDecimal(baseEpochDec, 'baseEpochDec');
  assertHex64('baseGroupContextDigestHex', baseGroupContextDigestHex);
  const sorted = assertSortedUniqueHex64('commitDigests', [...commitDigests].sort(), { min: 1 });
  return digestB25('PROTOCOL-BATCH', [
    groupIdHex, baseEpochDec, baseGroupContextDigestHex, sorted,
  ]);
}

export function comparisonTupleDigest({ priority, committerIdentityHex, commitDigestHex }) {
  assertSafeInteger('priority', priority, 0, 1);
  assertHex64('committerIdentityHex', committerIdentityHex);
  assertHex64('commitDigestHex', commitDigestHex);
  return digestB25('COMPARISON-TUPLE', [priority, committerIdentityHex, commitDigestHex]);
}

export function compareCandidates(left, right) {
  for (const candidate of [left, right]) {
    assertSafeInteger('priority', candidate?.priority, 0, 1);
    assertHex64('committerIdentityHex', candidate?.committerIdentityHex);
    assertHex64('commitDigestHex', candidate?.commitDigestHex);
  }
  if (left.priority !== right.priority) return left.priority - right.priority;
  if (left.committerIdentityHex !== right.committerIdentityHex) {
    return left.committerIdentityHex < right.committerIdentityHex ? -1 : 1;
  }
  if (left.commitDigestHex !== right.commitDigestHex) {
    return left.commitDigestHex < right.commitDigestHex ? -1 : 1;
  }
  return 0;
}

function readU64(bytes, state, label) {
  if (state.offset + 8 > bytes.length) failB25(B25_ERROR.INVALID, `${label} is truncated`);
  let value = 0n;
  for (let index = 0; index < 8; index += 1) {
    value = (value << 8n) | BigInt(bytes[state.offset + index]);
  }
  state.offset += 8;
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    failB25(B25_ERROR.RESOURCE_LIMIT, `${label} exceeds the safe runtime bound`);
  }
  return Number(value);
}

const MESSAGE_SECRETS_KEY_PREFIX = new TextEncoder().encode('MessageSecrets');
const UTF8_FATAL = new TextDecoder('utf-8', { fatal: true });

function startsWithBytes(bytes, prefix) {
  if (bytes.length < prefix.length) return false;
  return prefix.every((value, index) => bytes[index] === value);
}

function semanticProviderValue(key, value) {
  if (!startsWithBytes(key, MESSAGE_SECRETS_KEY_PREFIX)) return copyBytes(value);

  let record;
  try {
    record = JSON.parse(UTF8_FATAL.decode(value));
  } catch (error) {
    failB25(B25_ERROR.CORRUPT, 'OpenMLS MessageSecrets value is not canonical JSON', {}, error);
  }
  if (record === null || typeof record !== 'object' || Array.isArray(record)) {
    failB25(B25_ERROR.CORRUPT, 'OpenMLS MessageSecrets value is not an object');
  }
  const messageSecrets = record.message_secrets;
  if (messageSecrets === null || typeof messageSecrets !== 'object'
    || Array.isArray(messageSecrets) || !Object.hasOwn(messageSecrets, 'added_at')
    || messageSecrets.added_at === null || typeof messageSecrets.added_at !== 'object'
    || Array.isArray(messageSecrets.added_at)) {
    return copyBytes(value);
  }
  const addedAt = assertB25DirectObject(
    messageSecrets.added_at,
    ['secs_since_epoch', 'nanos_since_epoch'],
    'OpenMLS MessageSecrets added_at',
  );
  assertSafeInteger('OpenMLS MessageSecrets added_at.secs_since_epoch', addedAt.secs_since_epoch, 0);
  assertSafeInteger(
    'OpenMLS MessageSecrets added_at.nanos_since_epoch',
    addedAt.nanos_since_epoch,
    0,
    999_999_999,
  );

  // `added_at` is local retention metadata generated at merge time. It is not
  // protocol state and legitimately differs across same-member replicas. This
  // normalization is used only for semantic comparison; the exact provider
  // snapshot bytes remain retained and are never rewritten.
  return canonicalB25Bytes('PROVIDER-MESSAGE-SECRETS-SEMANTIC', [{
    ...record,
    message_secrets: {
      ...messageSecrets,
      added_at: { secs_since_epoch: 0, nanos_since_epoch: 0 },
    },
  }]);
}

/** Decode and sort the provider map, excluding only known volatile local metadata. */
export function canonicalProviderEntries(snapshotBytes) {
  validateProviderSnapshot(snapshotBytes);
  const bytes = copyBytes(snapshotBytes);
  const state = { offset: 0 };
  const count = readU64(bytes, state, 'Provider entry count');
  const entries = [];
  for (let index = 0; index < count; index += 1) {
    const keyLength = readU64(bytes, state, 'Provider key length');
    const valueLength = readU64(bytes, state, 'Provider value length');
    const key = bytes.subarray(state.offset, state.offset + keyLength);
    state.offset += keyLength;
    const value = bytes.subarray(state.offset, state.offset + valueLength);
    state.offset += valueLength;
    entries.push(Object.freeze({
      keyHex: bytesToHex(key),
      valueHex: bytesToHex(semanticProviderValue(key, value)),
    }));
  }
  entries.sort((left, right) => left.keyHex.localeCompare(right.keyHex));
  return Object.freeze(entries);
}

export {
  assertBytes,
  assertGroupIdHex,
  assertHex64,
  assertSafeInteger,
  assertString,
  bytesEqual,
  bytesToHex,
  copyBytes,
  digestHex,
  hexToBytes,
  parseEpochDecimal,
  validateProviderSnapshot,
};
