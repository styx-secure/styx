// STYX_SPIKE_PROTOTYPE — crash-safe application-message persistence for B2.7.

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

export const B27_FORMAT = 'styx-marmot-b2-7';
export const B27_VERSION = 1;
export const B27_PROFILE = 'sender-attributed-message-ratchet-poc';
export const B27_DB_PREFIX = 'styx-b2-7-poc-v1-';
export const B27_MARMOT_REVISION = '4ad4ae21479c3f3fa9950c6fc4556a76941a62e1';
export const B27_RUNTIME = Object.freeze({
  ...B23_RUNTIME,
  wasmArtifactSha256: '26a41d86d7fd2c9ab4184344e4ff00f5eebb5bc7609ba22e98b12ce903d4a4dd',
  marmotRevision: B27_MARMOT_REVISION,
});

export const B27_LIMITS = Object.freeze({
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

export const B27_STORES = Object.freeze({
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
export const B27_STORE_NAMES = Object.freeze(Object.values(B27_STORES));

export const B27_ERROR = Object.freeze({
  INVALID: 'B27_INVALID',
  CORRUPT: 'B27_CORRUPT',
  INCOMPATIBLE: 'B27_INCOMPATIBLE',
  NOT_FOUND: 'B27_NOT_FOUND',
  STATE_CONFLICT: 'B27_STATE_CONFLICT',
  CAS_CONFLICT: 'B27_CAS_CONFLICT',
  RESOURCE_LIMIT: 'B27_RESOURCE_LIMIT',
  ENGINE_REJECTED: 'B27_ENGINE_REJECTED',
  UNRECOVERABLE: 'B27_UNRECOVERABLE',
  RELEASED: 'B27_RELEASED',
  STALE: 'B27_STALE',
  AMBIGUOUS_PARENT: 'B27_AMBIGUOUS_PARENT',
  PROBE_ALREADY_RESERVED: 'B27_PROBE_ALREADY_RESERVED',
  PROBE_INCOMPLETE: 'B27_PROBE_INCOMPLETE',
  UNKNOWN_GENERATION: 'B27_UNKNOWN_GENERATION',
  DUPLICATE: 'B27_DUPLICATE',
  REQUEST_CONFLICT: 'B27_REQUEST_CONFLICT',
  OUTBOX_SUSPENDED: 'B27_OUTBOX_SUSPENDED',
  OUTBOX_TERMINAL: 'B27_OUTBOX_TERMINAL',
});

export const B27_HEAD_STATE = Object.freeze({
  STABLE: 'STABLE',
  UNRECOVERABLE: 'UNRECOVERABLE',
});
export const B27_PASS_STATE = Object.freeze({ FROZEN: 'FROZEN', SETTLED: 'SETTLED' });
export const B27_INPUT_STATE = Object.freeze({
  UNBOUND: 'UNBOUND', DEFERRED: 'DEFERRED', EDGE: 'EDGE', REJECTED: 'REJECTED',
  AMBIGUOUS: 'AMBIGUOUS', STALE: 'STALE',
});
export const B27_EDGE_ORIGIN = Object.freeze({ INBOUND: 'INBOUND', LOCAL: 'LOCAL' });
export const B27_GENERATION_STATE = Object.freeze({
  PREPARED: 'PREPARED', PUBLISHING: 'PUBLISHING', ACKNOWLEDGED: 'ACKNOWLEDGED',
  CANCELLED: 'CANCELLED', DISCARDED: 'DISCARDED', SELECTED: 'SELECTED',
  LOSING: 'LOSING', REJECTED: 'REJECTED',
});
export const B27_PUBLICATION_KIND = Object.freeze({
  ATTEMPT: 'ATTEMPT', ACK: 'ACK', FAILURE: 'FAILURE', LATE_ACK: 'LATE_ACK',
  CONTRADICTION: 'CONTRADICTION',
});
export const B27_PROBE_STATE = Object.freeze({ RESERVED: 'RESERVED', COMPLETED: 'COMPLETED' });
export const B27_MESSAGE_STATE = Object.freeze({
  ACTIVE: 'ACTIVE', SUSPENDED: 'SUSPENDED',
});
export const B27_OUTBOX_STATE = Object.freeze({
  DURABLE: 'DURABLE', ATTEMPTED: 'ATTEMPTED', ACKNOWLEDGED: 'ACKNOWLEDGED',
  FAILED_DISCARDED: 'FAILED_DISCARDED', SUSPENDED: 'SUSPENDED',
  INVALIDATED: 'INVALIDATED',
});
export const B27_INBOUND_STATE = Object.freeze({
  ACCEPTED: 'ACCEPTED', DEFERRED: 'DEFERRED', INVALIDATED: 'INVALIDATED',
  REJECTED: 'REJECTED', STALE: 'STALE',
});
export const B27_APP_PUBLICATION_KIND = Object.freeze({
  ATTEMPT: 'ATTEMPT', ACK: 'ACK', FAILURE: 'FAILURE', LATE_ACK: 'LATE_ACK',
});

export class B27Error extends Error {
  constructor(code, message, details = {}, options = {}) {
    super(`${code}: ${message}`, 'cause' in options ? { cause: options.cause } : undefined);
    this.name = 'B27Error';
    this.code = code;
    this.details = Object.freeze({ ...details });
  }
}

export function failB27(code, message, details, cause) {
  throw new B27Error(code, message, details, cause === undefined ? {} : { cause });
}

export function assertB27DirectObject(value, fields, label) {
  try {
    return snapshotClosedObject(value, fields, label);
  } catch (error) {
    if (error?.code === B23_ERROR.INVALID) {
      failB27(B27_ERROR.INVALID, `${label} has a non-canonical field set`, {}, error);
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

export function assertB27Runtime(value) {
  const safe = assertB27DirectObject(value,
    ['openMlsRevision', 'wasmArtifactSha256', 'ciphersuite', 'marmotRevision'],
    'B2.7 runtime');
  if (safe.openMlsRevision !== B27_RUNTIME.openMlsRevision
    || safe.wasmArtifactSha256 !== B27_RUNTIME.wasmArtifactSha256
    || safe.ciphersuite !== B27_RUNTIME.ciphersuite
    || safe.marmotRevision !== B27_RUNTIME.marmotRevision) {
    failB27(B27_ERROR.INCOMPATIBLE, 'runtime tuple differs from the approved B2.7 tuple');
  }
  return Object.freeze({ ...safe });
}

export function canonicalB27Bytes(domain, values) {
  return canonicalBytes(`STYX-B2-7-${domain}-V1`, values);
}

export function digestB27(domain, values) {
  return digestHex(canonicalB27Bytes(domain, values));
}

export function assertSortedUniqueHex64(name, value, { min = 0, max = 16 } = {}) {
  if (!Array.isArray(value) || value.length < min || value.length > max) {
    failB27(B27_ERROR.INVALID, `${name} has an invalid count`);
  }
  const exact = [...value];
  for (let index = 0; index < exact.length; index += 1) {
    assertHex64(name, exact[index]);
    if (index > 0 && exact[index - 1] >= exact[index]) {
      failB27(B27_ERROR.INVALID, `${name} must be strictly sorted and unique`);
    }
  }
  return Object.freeze(exact);
}

export function assertDigestPath(name, value, { max = B27_LIMITS.rewindCommits } = {}) {
  if (!Array.isArray(value) || value.length > max) {
    failB27(B27_ERROR.INVALID, `${name} has an invalid length`);
  }
  const exact = [...value];
  exact.forEach((item) => assertHex64(name, item));
  if (new Set(exact).size !== exact.length) {
    failB27(B27_ERROR.INVALID, `${name} contains a cycle or duplicate`);
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
  return digestB27('LOCAL-GENERATION-AUTHORITY', [
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
    B27_LIMITS.maxPublicationRecordsPerGeneration);
  return `${groupIdHex}:${commitDigestHex}:${String(sequence).padStart(2, '0')}`;
}

export function probeKey({ groupIdHex, tipCommitDigestHex, epochDec,
  groupContextDigestHex, localMemberIdentityHex }) {
  assertGroupIdHex(groupIdHex);
  assertNullableHex64('tipCommitDigestHex', tipCommitDigestHex);
  parseEpochDecimal(epochDec, 'probe epoch');
  assertHex64('groupContextDigestHex', groupContextDigestHex);
  assertHex64('localMemberIdentityHex', localMemberIdentityHex);
  return digestB27('PROBE-INSTANCE', [groupIdHex, tipCommitDigestHex, epochDec,
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
  assertString('requestId', requestId, { min: 1, max: B27_LIMITS.maxRequestIdBytes });
  return digestB27('REQUEST-ID', [instanceKeyHex, requestId]);
}

export {
  assertBytes, assertGroupIdHex, assertHex64, assertSafeInteger, assertString,
  bytesEqual, bytesToHex, copyBytes, digestHex, hexToBytes, parseEpochDecimal,
  validateProviderSnapshot,
};
