// STYX_SPIKE_PROTOTYPE — bounded retained-history convergence primitives for B2.5c.

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

export const B25C_FORMAT = 'styx-marmot-b2-5c';
export const B25C_VERSION = 1;
export const B25C_PROFILE = 'bounded-retained-history-poc';
export const B25C_DB_PREFIX = 'styx-b2-5c-poc-v1-';
export const B25C_MARMOT_REVISION = '4ad4ae21479c3f3fa9950c6fc4556a76941a62e1';
export const B25C_RUNTIME = Object.freeze({
  ...B23_RUNTIME,
  marmotRevision: B25C_MARMOT_REVISION,
});

export const B25C_LIMITS = Object.freeze({
  rewindCommits: 5,
  maxInputs: 16,
  maxEdges: 16,
  maxStates: 17,
  maxMembers: 16,
  maxCommitBytes: B23_LIMITS.maxCommitBytes,
  maxSnapshotBytes: B23_LIMITS.maxSnapshotBytes,
  maxPasses: 64,
  maxTransitions: 64,
  maxGenerations: 16,
  maxPublicationRecordsPerGeneration: 64,
  maxPublicationAttempts: 64,
  maxPublicationPayloadBytes: 4096,
  maxProbeReservations: 16,
  maxProbePayloadBytes: 4096,
});

export const B25C_STORES = Object.freeze({
  head: 'canonical-head',
  retained: 'retained-state',
  released: 'released-state',
  input: 'commit-input',
  edge: 'replay-edge',
  pass: 'settlement-pass',
  transition: 'canonical-transition',
  invalidation: 'invalidation-evidence',
  generation: 'local-generation',
  generationTruncation: 'generation-truncation',
  activeLocal: 'active-local',
  publication: 'publication-evidence',
  probeReservation: 'probe-reservation',
  probeCompletion: 'probe-completion',
});
export const B25C_STORE_NAMES = Object.freeze(Object.values(B25C_STORES));

export const B25C_ERROR = Object.freeze({
  INVALID: 'B25C_INVALID',
  CORRUPT: 'B25C_CORRUPT',
  INCOMPATIBLE: 'B25C_INCOMPATIBLE',
  NOT_FOUND: 'B25C_NOT_FOUND',
  STATE_CONFLICT: 'B25C_STATE_CONFLICT',
  CAS_CONFLICT: 'B25C_CAS_CONFLICT',
  RESOURCE_LIMIT: 'B25C_RESOURCE_LIMIT',
  ENGINE_REJECTED: 'B25C_ENGINE_REJECTED',
  UNRECOVERABLE: 'B25C_UNRECOVERABLE',
  RELEASED: 'B25C_RELEASED',
  STALE: 'B25C_STALE',
  AMBIGUOUS_PARENT: 'B25C_AMBIGUOUS_PARENT',
  PROBE_ALREADY_RESERVED: 'B25C_PROBE_ALREADY_RESERVED',
  PROBE_INCOMPLETE: 'B25C_PROBE_INCOMPLETE',
  UNKNOWN_GENERATION: 'B25C_UNKNOWN_GENERATION',
});

export const B25C_HEAD_STATE = Object.freeze({
  STABLE: 'STABLE',
  UNRECOVERABLE: 'UNRECOVERABLE',
});
export const B25C_PASS_STATE = Object.freeze({ FROZEN: 'FROZEN', SETTLED: 'SETTLED' });
export const B25C_INPUT_STATE = Object.freeze({
  UNBOUND: 'UNBOUND', DEFERRED: 'DEFERRED', EDGE: 'EDGE', REJECTED: 'REJECTED',
  AMBIGUOUS: 'AMBIGUOUS', STALE: 'STALE',
});
export const B25C_EDGE_ORIGIN = Object.freeze({ INBOUND: 'INBOUND', LOCAL: 'LOCAL' });
export const B25C_GENERATION_STATE = Object.freeze({
  PREPARED: 'PREPARED', PUBLISHING: 'PUBLISHING', ACKNOWLEDGED: 'ACKNOWLEDGED',
  CANCELLED: 'CANCELLED', DISCARDED: 'DISCARDED', SELECTED: 'SELECTED',
  LOSING: 'LOSING', REJECTED: 'REJECTED',
});
export const B25C_PUBLICATION_KIND = Object.freeze({
  ATTEMPT: 'ATTEMPT', ACK: 'ACK', FAILURE: 'FAILURE', LATE_ACK: 'LATE_ACK',
  CONTRADICTION: 'CONTRADICTION',
});
export const B25C_PROBE_STATE = Object.freeze({ RESERVED: 'RESERVED', COMPLETED: 'COMPLETED' });

export class B25CError extends Error {
  constructor(code, message, details = {}, options = {}) {
    super(`${code}: ${message}`, 'cause' in options ? { cause: options.cause } : undefined);
    this.name = 'B25CError';
    this.code = code;
    this.details = Object.freeze({ ...details });
  }
}

export function failB25C(code, message, details, cause) {
  throw new B25CError(code, message, details, cause === undefined ? {} : { cause });
}

export function assertB25CDirectObject(value, fields, label) {
  try {
    return snapshotClosedObject(value, fields, label);
  } catch (error) {
    if (error?.code === B23_ERROR.INVALID) {
      failB25C(B25C_ERROR.INVALID, `${label} has a non-canonical field set`, {}, error);
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

export function assertB25CRuntime(value) {
  const safe = assertB25CDirectObject(value,
    ['openMlsRevision', 'wasmArtifactSha256', 'ciphersuite', 'marmotRevision'],
    'B2.5c runtime');
  if (safe.openMlsRevision !== B25C_RUNTIME.openMlsRevision
    || safe.wasmArtifactSha256 !== B25C_RUNTIME.wasmArtifactSha256
    || safe.ciphersuite !== B25C_RUNTIME.ciphersuite
    || safe.marmotRevision !== B25C_RUNTIME.marmotRevision) {
    failB25C(B25C_ERROR.INCOMPATIBLE, 'runtime tuple differs from the approved B2.5c tuple');
  }
  return Object.freeze({ ...safe });
}

export function canonicalB25CBytes(domain, values) {
  return canonicalBytes(`STYX-B2-5C-${domain}-V1`, values);
}

export function digestB25C(domain, values) {
  return digestHex(canonicalB25CBytes(domain, values));
}

export function assertSortedUniqueHex64(name, value, { min = 0, max = 16 } = {}) {
  if (!Array.isArray(value) || value.length < min || value.length > max) {
    failB25C(B25C_ERROR.INVALID, `${name} has an invalid count`);
  }
  const exact = [...value];
  for (let index = 0; index < exact.length; index += 1) {
    assertHex64(name, exact[index]);
    if (index > 0 && exact[index - 1] >= exact[index]) {
      failB25C(B25C_ERROR.INVALID, `${name} must be strictly sorted and unique`);
    }
  }
  return Object.freeze(exact);
}

export function assertDigestPath(name, value, { max = B25C_LIMITS.rewindCommits } = {}) {
  if (!Array.isArray(value) || value.length > max) {
    failB25C(B25C_ERROR.INVALID, `${name} has an invalid length`);
  }
  const exact = [...value];
  exact.forEach((item) => assertHex64(name, item));
  if (new Set(exact).size !== exact.length) {
    failB25C(B25C_ERROR.INVALID, `${name} contains a cycle or duplicate`);
  }
  return Object.freeze(exact);
}

export function compareTipTuples(left, right) {
  if (left.priority !== right.priority) return left.priority - right.priority;
  if (left.committerIdentityHex !== right.committerIdentityHex) {
    return left.committerIdentityHex < right.committerIdentityHex ? -1 : 1;
  }
  if (left.commitDigestHex !== right.commitDigestHex) {
    return left.commitDigestHex < right.commitDigestHex ? -1 : 1;
  }
  return 0;
}

export function compareBranches(left, right) {
  if (left.path.length !== right.path.length) return right.path.length - left.path.length;
  if (left.path.length === 0) return 0;
  return compareTipTuples(left.tip, right.tip);
}

export function inputKey(groupIdHex, commitDigestHex) {
  assertGroupIdHex(groupIdHex);
  assertHex64('commitDigestHex', commitDigestHex);
  return `${groupIdHex}:${commitDigestHex}`;
}

export function edgeKey(groupIdHex, parentSnapshotDigestHex, commitDigestHex) {
  assertGroupIdHex(groupIdHex);
  assertHex64('parentSnapshotDigestHex', parentSnapshotDigestHex);
  assertHex64('commitDigestHex', commitDigestHex);
  return `${groupIdHex}:${parentSnapshotDigestHex}:${commitDigestHex}`;
}

export function generationKey(groupIdHex, commitDigestHex) {
  return inputKey(groupIdHex, commitDigestHex);
}

export function generationAuthorityDigest(record) {
  return digestB25C('LOCAL-GENERATION-AUTHORITY', [
    record.groupIdHex,
    record.generation,
    record.parentHeadDigestHex,
    record.parentSnapshotDigestHex,
    record.pendingSnapshotDigestHex,
    record.commitDigestHex,
  ]);
}

export function publicationKey(groupIdHex, commitDigestHex, sequence) {
  assertGroupIdHex(groupIdHex);
  assertHex64('commitDigestHex', commitDigestHex);
  assertSafeInteger('publication sequence', sequence, 1,
    B25C_LIMITS.maxPublicationRecordsPerGeneration);
  return `${groupIdHex}:${commitDigestHex}:${String(sequence).padStart(2, '0')}`;
}

export function probeKey({ groupIdHex, tipCommitDigestHex, epochDec,
  groupContextDigestHex, localMemberIdentityHex }) {
  assertGroupIdHex(groupIdHex);
  assertNullableHex64('tipCommitDigestHex', tipCommitDigestHex);
  parseEpochDecimal(epochDec, 'probe epoch');
  assertHex64('groupContextDigestHex', groupContextDigestHex);
  assertHex64('localMemberIdentityHex', localMemberIdentityHex);
  return digestB25C('PROBE-INSTANCE', [groupIdHex, tipCommitDigestHex, epochDec,
    groupContextDigestHex, localMemberIdentityHex]);
}

export {
  assertBytes, assertGroupIdHex, assertHex64, assertSafeInteger, assertString,
  bytesEqual, bytesToHex, copyBytes, digestHex, hexToBytes, parseEpochDecimal,
  validateProviderSnapshot,
};
