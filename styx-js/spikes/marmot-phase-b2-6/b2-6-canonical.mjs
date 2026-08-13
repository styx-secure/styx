// STYX_SPIKE_PROTOTYPE — crash-safe application-message persistence for B2.6.

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

export const B26_FORMAT = 'styx-marmot-b2-6';
export const B26_VERSION = 2;
export const B26_PROFILE = 'crash-safe-message-ratchet-poc';
export const B26_DB_PREFIX = 'styx-b2-6-poc-v2-';
export const B26_MARMOT_REVISION = '4ad4ae21479c3f3fa9950c6fc4556a76941a62e1';
export const B26_RUNTIME = Object.freeze({
  ...B23_RUNTIME,
  marmotRevision: B26_MARMOT_REVISION,
});

export const B26_LIMITS = Object.freeze({
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
  maxMessageStates: 17,
  maxOutboxPerInstance: 16,
  maxOutboxRecordsPerInstance: 128,
  maxInboundPerInstance: 64,
  maxMessagePublicationRecords: 64,
  maxRequestIdBytes: 128,
  maxApplicationPayloadBytes: 4096,
  maxApplicationCiphertextBytes: 8192,
});

export const B26_STORES = Object.freeze({
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
  messageState: 'message-state',
  messageSnapshot: 'message-snapshot',
  appOutbox: 'app-outbox',
  appInbound: 'app-inbound',
  appPublication: 'app-publication-evidence',
  messageRelease: 'message-release',
  inboundTruncation: 'inbound-truncation',
});
export const B26_STORE_NAMES = Object.freeze(Object.values(B26_STORES));

export const B26_ERROR = Object.freeze({
  INVALID: 'B26_INVALID',
  CORRUPT: 'B26_CORRUPT',
  INCOMPATIBLE: 'B26_INCOMPATIBLE',
  NOT_FOUND: 'B26_NOT_FOUND',
  STATE_CONFLICT: 'B26_STATE_CONFLICT',
  CAS_CONFLICT: 'B26_CAS_CONFLICT',
  RESOURCE_LIMIT: 'B26_RESOURCE_LIMIT',
  ENGINE_REJECTED: 'B26_ENGINE_REJECTED',
  UNRECOVERABLE: 'B26_UNRECOVERABLE',
  RELEASED: 'B26_RELEASED',
  STALE: 'B26_STALE',
  AMBIGUOUS_PARENT: 'B26_AMBIGUOUS_PARENT',
  PROBE_ALREADY_RESERVED: 'B26_PROBE_ALREADY_RESERVED',
  PROBE_INCOMPLETE: 'B26_PROBE_INCOMPLETE',
  UNKNOWN_GENERATION: 'B26_UNKNOWN_GENERATION',
  DUPLICATE: 'B26_DUPLICATE',
  REQUEST_CONFLICT: 'B26_REQUEST_CONFLICT',
  OUTBOX_SUSPENDED: 'B26_OUTBOX_SUSPENDED',
  OUTBOX_TERMINAL: 'B26_OUTBOX_TERMINAL',
});

export const B26_HEAD_STATE = Object.freeze({
  STABLE: 'STABLE',
  UNRECOVERABLE: 'UNRECOVERABLE',
});
export const B26_PASS_STATE = Object.freeze({ FROZEN: 'FROZEN', SETTLED: 'SETTLED' });
export const B26_INPUT_STATE = Object.freeze({
  UNBOUND: 'UNBOUND', DEFERRED: 'DEFERRED', EDGE: 'EDGE', REJECTED: 'REJECTED',
  AMBIGUOUS: 'AMBIGUOUS', STALE: 'STALE',
});
export const B26_EDGE_ORIGIN = Object.freeze({ INBOUND: 'INBOUND', LOCAL: 'LOCAL' });
export const B26_GENERATION_STATE = Object.freeze({
  PREPARED: 'PREPARED', PUBLISHING: 'PUBLISHING', ACKNOWLEDGED: 'ACKNOWLEDGED',
  CANCELLED: 'CANCELLED', DISCARDED: 'DISCARDED', SELECTED: 'SELECTED',
  LOSING: 'LOSING', REJECTED: 'REJECTED',
});
export const B26_PUBLICATION_KIND = Object.freeze({
  ATTEMPT: 'ATTEMPT', ACK: 'ACK', FAILURE: 'FAILURE', LATE_ACK: 'LATE_ACK',
  CONTRADICTION: 'CONTRADICTION',
});
export const B26_PROBE_STATE = Object.freeze({ RESERVED: 'RESERVED', COMPLETED: 'COMPLETED' });
export const B26_MESSAGE_STATE = Object.freeze({
  ACTIVE: 'ACTIVE', SUSPENDED: 'SUSPENDED',
});
export const B26_OUTBOX_STATE = Object.freeze({
  DURABLE: 'DURABLE', ATTEMPTED: 'ATTEMPTED', ACKNOWLEDGED: 'ACKNOWLEDGED',
  FAILED_DISCARDED: 'FAILED_DISCARDED', SUSPENDED: 'SUSPENDED',
  INVALIDATED: 'INVALIDATED',
});
export const B26_INBOUND_STATE = Object.freeze({
  ACCEPTED: 'ACCEPTED', DEFERRED: 'DEFERRED', INVALIDATED: 'INVALIDATED',
  REJECTED: 'REJECTED', STALE: 'STALE',
});
export const B26_APP_PUBLICATION_KIND = Object.freeze({
  ATTEMPT: 'ATTEMPT', ACK: 'ACK', FAILURE: 'FAILURE', LATE_ACK: 'LATE_ACK',
});

export class B26Error extends Error {
  constructor(code, message, details = {}, options = {}) {
    super(`${code}: ${message}`, 'cause' in options ? { cause: options.cause } : undefined);
    this.name = 'B26Error';
    this.code = code;
    this.details = Object.freeze({ ...details });
  }
}

export function failB26(code, message, details, cause) {
  throw new B26Error(code, message, details, cause === undefined ? {} : { cause });
}

export function assertB26DirectObject(value, fields, label) {
  try {
    return snapshotClosedObject(value, fields, label);
  } catch (error) {
    if (error?.code === B23_ERROR.INVALID) {
      failB26(B26_ERROR.INVALID, `${label} has a non-canonical field set`, {}, error);
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

export function assertB26Runtime(value) {
  const safe = assertB26DirectObject(value,
    ['openMlsRevision', 'wasmArtifactSha256', 'ciphersuite', 'marmotRevision'],
    'B2.6 runtime');
  if (safe.openMlsRevision !== B26_RUNTIME.openMlsRevision
    || safe.wasmArtifactSha256 !== B26_RUNTIME.wasmArtifactSha256
    || safe.ciphersuite !== B26_RUNTIME.ciphersuite
    || safe.marmotRevision !== B26_RUNTIME.marmotRevision) {
    failB26(B26_ERROR.INCOMPATIBLE, 'runtime tuple differs from the approved B2.6 tuple');
  }
  return Object.freeze({ ...safe });
}

export function canonicalB26Bytes(domain, values) {
  return canonicalBytes(`STYX-B2-6-${domain}-V1`, values);
}

export function digestB26(domain, values) {
  return digestHex(canonicalB26Bytes(domain, values));
}

export function assertSortedUniqueHex64(name, value, { min = 0, max = 16 } = {}) {
  if (!Array.isArray(value) || value.length < min || value.length > max) {
    failB26(B26_ERROR.INVALID, `${name} has an invalid count`);
  }
  const exact = [...value];
  for (let index = 0; index < exact.length; index += 1) {
    assertHex64(name, exact[index]);
    if (index > 0 && exact[index - 1] >= exact[index]) {
      failB26(B26_ERROR.INVALID, `${name} must be strictly sorted and unique`);
    }
  }
  return Object.freeze(exact);
}

export function assertDigestPath(name, value, { max = B26_LIMITS.rewindCommits } = {}) {
  if (!Array.isArray(value) || value.length > max) {
    failB26(B26_ERROR.INVALID, `${name} has an invalid length`);
  }
  const exact = [...value];
  exact.forEach((item) => assertHex64(name, item));
  if (new Set(exact).size !== exact.length) {
    failB26(B26_ERROR.INVALID, `${name} contains a cycle or duplicate`);
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
  return digestB26('LOCAL-GENERATION-AUTHORITY', [
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
    B26_LIMITS.maxPublicationRecordsPerGeneration);
  return `${groupIdHex}:${commitDigestHex}:${String(sequence).padStart(2, '0')}`;
}

export function probeKey({ groupIdHex, tipCommitDigestHex, epochDec,
  groupContextDigestHex, localMemberIdentityHex }) {
  assertGroupIdHex(groupIdHex);
  assertNullableHex64('tipCommitDigestHex', tipCommitDigestHex);
  parseEpochDecimal(epochDec, 'probe epoch');
  assertHex64('groupContextDigestHex', groupContextDigestHex);
  assertHex64('localMemberIdentityHex', localMemberIdentityHex);
  return digestB26('PROBE-INSTANCE', [groupIdHex, tipCommitDigestHex, epochDec,
    groupContextDigestHex, localMemberIdentityHex]);
}

export function messageInstanceKey(fields) {
  return probeKey(fields);
}

export function messageStateKey(groupIdHex, instanceKeyHex) {
  assertGroupIdHex(groupIdHex);
  assertHex64('instanceKeyHex', instanceKeyHex);
  return `${groupIdHex}:${instanceKeyHex}`;
}

export function messageSnapshotKey(instanceKeyHex, snapshotDigestHex) {
  assertHex64('instanceKeyHex', instanceKeyHex);
  assertHex64('snapshotDigestHex', snapshotDigestHex);
  return `${instanceKeyHex}:${snapshotDigestHex}`;
}

export function outboxKey(instanceKeyHex, ordinal) {
  assertHex64('instanceKeyHex', instanceKeyHex);
  assertSafeInteger('outbox ordinal', ordinal, 1, Number.MAX_SAFE_INTEGER);
  return `${instanceKeyHex}:${String(ordinal).padStart(16, '0')}`;
}

export function inboundKey(instanceKeyHex, ciphertextDigestHex) {
  assertHex64('instanceKeyHex', instanceKeyHex);
  assertHex64('ciphertextDigestHex', ciphertextDigestHex);
  return `${instanceKeyHex}:${ciphertextDigestHex}`;
}

export function requestKey(instanceKeyHex, requestId) {
  assertHex64('instanceKeyHex', instanceKeyHex);
  assertString('requestId', requestId, { min: 1, max: B26_LIMITS.maxRequestIdBytes });
  return digestB26('REQUEST-ID', [instanceKeyHex, requestId]);
}

export {
  assertBytes, assertGroupIdHex, assertHex64, assertSafeInteger, assertString,
  bytesEqual, bytesToHex, copyBytes, digestHex, hexToBytes, parseEpochDecimal,
  validateProviderSnapshot,
};
