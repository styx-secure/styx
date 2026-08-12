// STYX_SPIKE_PROTOTYPE — Phase B2.5b local-publisher canonical boundary.

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
import {
  canonicalProviderEntries,
  compareCandidates,
  comparisonTupleDigest,
  protocolBatchDigest,
} from '../marmot-phase-b2-5a/b2-5a-canonical.mjs';

export const B25B_FORMAT = 'styx-marmot-b2-5b';
export const B25B_VERSION = 1;
export const B25B_PROFILE = 'same-parent-local-publisher-poc';
export const B25B_DB_PREFIX = 'styx-b2-5b-poc-v1-';
export const B25B_MARMOT_REVISION = '4ad4ae21479c3f3fa9950c6fc4556a76941a62e1';
export const B25B_RUNTIME = Object.freeze({ ...B23_RUNTIME,
  marmotRevision: B25B_MARMOT_REVISION });

export const B25B_LIMITS = Object.freeze({
  maxBatchCommits: 16,
  maxMembers: B23_LIMITS.maxMembers,
  maxCommitBytes: B23_LIMITS.maxCommitBytes,
  maxSnapshotBytes: B23_LIMITS.maxSnapshotBytes,
});

export const B25B_STORES = Object.freeze({
  head: 'head',
  retained: 'retained-state',
  input: 'input',
  batch: 'frozen-batch',
  candidate: 'candidate-evidence',
  transition: 'transition',
  local: 'local-pending',
  publication: 'publication-evidence',
});
export const B25B_STORE_NAMES = Object.freeze(Object.values(B25B_STORES));

export const B25B_ERROR = Object.freeze({
  INVALID: 'B25B_INVALID', CORRUPT: 'B25B_CORRUPT',
  INCOMPATIBLE: 'B25B_INCOMPATIBLE', NOT_FOUND: 'B25B_NOT_FOUND',
  STATE_CONFLICT: 'B25B_STATE_CONFLICT', CAS_CONFLICT: 'B25B_CAS_CONFLICT',
  RESOURCE_LIMIT: 'B25B_RESOURCE_LIMIT', ENGINE_REJECTED: 'B25B_ENGINE_REJECTED',
  UNRECOVERABLE: 'B25B_UNRECOVERABLE',
});
export const B25B_HEAD_STATE = Object.freeze({ STABLE: 'STABLE',
  UNRECOVERABLE: 'UNRECOVERABLE' });
export const B25B_BATCH_STATE = Object.freeze({ FROZEN: 'FROZEN', RESOLVED: 'RESOLVED' });
export const B25B_CANDIDATE_STATE = Object.freeze({
  PENDING: 'PENDING', AUTHORIZED: 'AUTHORIZED', REJECTED: 'REJECTED',
  NOT_CANDIDATE: 'NOT_CANDIDATE',
});
export const B25B_DISPOSITION = Object.freeze({
  COLLECTED: 'COLLECTED', FROZEN: 'FROZEN', SELECTED: 'SELECTED', LOSING: 'LOSING',
  REJECTED: 'REJECTED', NOT_CANDIDATE: 'NOT_CANDIDATE',
});
export const B25B_REASON = Object.freeze({
  PENDING: 'B25B_PENDING', SELECTED: 'B25B_SELECTED',
  LOWER_PRIORITY: 'B25B_LOWER_PRIORITY',
  NOT_CANDIDATE_FOR_RETAINED_PARENT: 'B25B_NOT_CANDIDATE_FOR_RETAINED_PARENT',
});
export const B25B_LOCAL_STATE = Object.freeze({
  QUEUED: 'QUEUED', PREPARED: 'PREPARED', PUBLISHING: 'PUBLISHING',
  ACKNOWLEDGED: 'ACKNOWLEDGED', CANCELLED: 'CANCELLED', DISCARDED: 'DISCARDED',
  CONFIRMED: 'CONFIRMED', CLEARED_LOST: 'CLEARED_LOST',
  CLEARED_REJECTED: 'CLEARED_REJECTED',
});
export const B25B_TERMINAL_DISPOSITION = Object.freeze({
  CANCELLED: 'CANCELLED', PREPARATION_FAILED: 'PREPARATION_FAILED',
  DISCARDED_AFTER_FAILURE: 'DISCARDED_AFTER_FAILURE', SELECTED: 'SELECTED',
  LOSING: 'LOSING', LOSING_OUTSIDE_BATCH: 'LOSING_OUTSIDE_BATCH',
  REJECTED: 'REJECTED',
});
export const B25B_PUBLICATION_KIND = Object.freeze({
  ATTEMPT: 'ATTEMPT', ACK: 'ACK', FAILURE: 'FAILURE', LATE_ACK: 'LATE_ACK',
});

export class B25BError extends Error {
  constructor(code, message, details = {}, options = {}) {
    super(`${code}: ${message}`, 'cause' in options ? { cause: options.cause } : undefined);
    this.name = 'B25BError';
    this.code = code;
    this.details = Object.freeze({ ...details });
  }
}

export function failB25B(code, message, details, cause) {
  throw new B25BError(code, message, details, cause === undefined ? {} : { cause });
}

export function assertB25BDirectObject(value, fields, label) {
  try {
    return snapshotClosedObject(value, fields, label);
  } catch (error) {
    if (error?.code === B23_ERROR.INVALID) {
      failB25B(B25B_ERROR.INVALID, `${label} has a non-canonical field set`, {}, error);
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

export function assertB25BRuntime(value) {
  const safe = assertB25BDirectObject(value,
    ['openMlsRevision', 'wasmArtifactSha256', 'ciphersuite', 'marmotRevision'],
    'B2.5b runtime');
  if (safe.openMlsRevision !== B25B_RUNTIME.openMlsRevision
    || safe.wasmArtifactSha256 !== B25B_RUNTIME.wasmArtifactSha256
    || safe.ciphersuite !== B25B_RUNTIME.ciphersuite
    || safe.marmotRevision !== B25B_RUNTIME.marmotRevision) {
    failB25B(B25B_ERROR.INCOMPATIBLE, 'runtime tuple differs from the approved B2.5b tuple');
  }
  return Object.freeze({ ...safe });
}

export function canonicalB25BBytes(domain, values) {
  return canonicalBytes(`STYX-B2-5B-${domain}-V1`, values);
}

export function digestB25B(domain, values) {
  return digestHex(canonicalB25BBytes(domain, values));
}

export function assertSortedUniqueHex64(name, value,
  { min = 0, max = B25B_LIMITS.maxBatchCommits } = {}) {
  if (!Array.isArray(value) || value.length < min || value.length > max) {
    failB25B(B25B_ERROR.INVALID, `${name} has an invalid count`);
  }
  const sorted = [...value];
  for (let index = 0; index < sorted.length; index += 1) {
    assertHex64(name, sorted[index]);
    if (index > 0 && sorted[index - 1] >= sorted[index]) {
      failB25B(B25B_ERROR.INVALID, `${name} must be strictly sorted and unique`);
    }
  }
  return Object.freeze(sorted);
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

export function localKey(groupIdHex) {
  assertGroupIdHex(groupIdHex);
  return groupIdHex;
}

export function publicationKey(groupIdHex, sequence) {
  assertGroupIdHex(groupIdHex);
  assertSafeInteger('publication sequence', sequence, 1, 64);
  return `${groupIdHex}:${String(sequence).padStart(2, '0')}`;
}

export {
  assertBytes, assertGroupIdHex, assertHex64, assertSafeInteger, assertString,
  bytesEqual, bytesToHex, canonicalProviderEntries, compareCandidates,
  comparisonTupleDigest, copyBytes, digestHex, hexToBytes, parseEpochDecimal,
  protocolBatchDigest, validateProviderSnapshot,
};
