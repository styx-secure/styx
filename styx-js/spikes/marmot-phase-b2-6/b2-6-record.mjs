// STYX_SPIKE_PROTOTYPE — strict B2.6 durable record codecs.

import {
  B26_EDGE_ORIGIN,
  B26_ERROR,
  B26_FORMAT,
  B26_GENERATION_STATE,
  B26_HEAD_STATE,
  B26_INPUT_STATE,
  B26_INBOUND_STATE,
  B26_LIMITS,
  B26_MESSAGE_STATE,
  B26_OUTBOX_STATE,
  B26_PASS_STATE,
  B26_PROBE_STATE,
  B26_PROFILE,
  B26_PUBLICATION_KIND,
  B26_APP_PUBLICATION_KIND,
  B26_RUNTIME,
  B26_VERSION,
  assertB26DirectObject,
  assertB26Runtime,
  assertBytes,
  assertDigestPath,
  assertGroupIdHex,
  assertHex64,
  assertNullableHex64,
  assertNullableString,
  assertSafeInteger,
  assertSortedUniqueHex64,
  assertString,
  canonicalB26Bytes,
  copyBytes,
  digestHex,
  failB26,
  parseEpochDecimal,
  probeKey,
  messageInstanceKey,
  requestKey,
  validateProviderSnapshot,
} from './b2-6-canonical.mjs';

const HEAD_STATES = new Set(Object.values(B26_HEAD_STATE));
const INPUT_STATES = new Set(Object.values(B26_INPUT_STATE));
const PASS_STATES = new Set(Object.values(B26_PASS_STATE));
const EDGE_ORIGINS = new Set(Object.values(B26_EDGE_ORIGIN));
const GENERATION_STATES = new Set(Object.values(B26_GENERATION_STATE));
const PUBLICATION_KINDS = new Set(Object.values(B26_PUBLICATION_KIND));
const PROBE_STATES = new Set(Object.values(B26_PROBE_STATE));
const MESSAGE_STATES = new Set(Object.values(B26_MESSAGE_STATE));
const OUTBOX_STATES = new Set(Object.values(B26_OUTBOX_STATE));
const INBOUND_STATES = new Set(Object.values(B26_INBOUND_STATE));
const APP_PUBLICATION_KINDS = new Set(Object.values(B26_APP_PUBLICATION_KIND));

function magic(kind) { return `${B26_FORMAT}-${kind}`; }

function digestRecord(domain, values) {
  return digestHex(canonicalB26Bytes(domain, values));
}

function exact(raw, fields, kind) {
  const value = assertB26DirectObject(raw, fields, `B2.6 ${kind}`);
  if (value.format !== magic(kind) || value.version !== B26_VERSION) {
    failB26(B26_ERROR.INVALID, `${kind} magic or version is invalid`);
  }
  return value;
}

function verifyDigest(record, field, domain, values) {
  assertHex64(field, record[field]);
  if (digestRecord(domain, values) !== record[field]) {
    failB26(B26_ERROR.CORRUPT, `${field} mismatch`);
  }
  return record;
}

export const HEAD_FIELDS = Object.freeze([
  'format', 'version', 'profile', 'runtime', 'groupIdHex', 'accountKeyHex',
  'signatureKeyHex', 'seq', 'state', 'epochDec', 'groupContextDigestHex',
  'snapshotDigestHex', 'anchorSnapshotDigestHex', 'canonicalPath',
  'priorHeadDigestHex', 'transitionDigestHex', 'selectedCommitDigestHex', 'headDigestHex',
]);

function headValues(value) {
  return [value.format, value.version, value.profile, value.runtime, value.groupIdHex,
    value.accountKeyHex, value.signatureKeyHex, value.seq, value.state, value.epochDec,
    value.groupContextDigestHex, value.snapshotDigestHex, value.anchorSnapshotDigestHex,
    value.canonicalPath, value.priorHeadDigestHex, value.transitionDigestHex,
    value.selectedCommitDigestHex];
}

export function buildHead(fields) {
  const safe = assertB26DirectObject(fields, [
    'groupIdHex', 'accountKeyHex', 'signatureKeyHex', 'seq', 'state', 'epochDec',
    'groupContextDigestHex', 'snapshotDigestHex', 'anchorSnapshotDigestHex',
    'canonicalPath', 'priorHeadDigestHex', 'transitionDigestHex', 'selectedCommitDigestHex',
  ], 'head fields');
  const draft = { format: magic('head'), version: B26_VERSION, profile: B26_PROFILE,
    runtime: B26_RUNTIME, ...safe, headDigestHex: '0'.repeat(64) };
  parseHeadShape(draft);
  draft.headDigestHex = digestRecord('HEAD', headValues(draft));
  return parseHead(draft);
}

function parseHeadShape(value) {
  if (value.profile !== B26_PROFILE) failB26(B26_ERROR.INCOMPATIBLE, 'head profile differs');
  assertB26Runtime(value.runtime);
  assertGroupIdHex(value.groupIdHex);
  assertHex64('accountKeyHex', value.accountKeyHex);
  assertHex64('signatureKeyHex', value.signatureKeyHex);
  assertSafeInteger('head seq', value.seq, 1, B26_LIMITS.maxTransitions);
  if (!HEAD_STATES.has(value.state)) failB26(B26_ERROR.INVALID, 'head state is invalid');
  parseEpochDecimal(value.epochDec, 'head epoch');
  assertHex64('groupContextDigestHex', value.groupContextDigestHex);
  assertHex64('snapshotDigestHex', value.snapshotDigestHex);
  assertHex64('anchorSnapshotDigestHex', value.anchorSnapshotDigestHex);
  assertDigestPath('canonicalPath', value.canonicalPath);
  assertNullableHex64('priorHeadDigestHex', value.priorHeadDigestHex);
  assertHex64('transitionDigestHex', value.transitionDigestHex);
  assertNullableHex64('selectedCommitDigestHex', value.selectedCommitDigestHex);
  if ((value.canonicalPath.at(-1) ?? null) !== value.selectedCommitDigestHex) {
    failB26(B26_ERROR.INVALID, 'selected Commit does not match canonical path tip');
  }
  return value;
}

export function parseHead(raw) {
  const value = parseHeadShape(exact(raw, HEAD_FIELDS, 'head'));
  verifyDigest(value, 'headDigestHex', 'HEAD', headValues(value));
  return Object.freeze({ ...value, runtime: Object.freeze({ ...value.runtime }),
    canonicalPath: Object.freeze([...value.canonicalPath]) });
}

export const RETAINED_FIELDS = Object.freeze([
  'format', 'version', 'runtime', 'groupIdHex', 'accountKeyHex', 'signatureKeyHex',
  'epochDec', 'groupContextDigestHex', 'snapshotDigestHex', 'snapshotByteLength',
  'snapshotBytes', 'retainedDigestHex',
]);

function retainedValues(value) {
  return [value.format, value.version, value.runtime, value.groupIdHex, value.accountKeyHex,
    value.signatureKeyHex, value.epochDec, value.groupContextDigestHex,
    value.snapshotDigestHex, value.snapshotByteLength];
}

export function buildRetainedState(fields) {
  const safe = assertB26DirectObject(fields, [
    'groupIdHex', 'accountKeyHex', 'signatureKeyHex', 'epochDec',
    'groupContextDigestHex', 'snapshotBytes',
  ], 'retained-state fields');
  const snapshotBytes = copyBytes(safe.snapshotBytes);
  const draft = { format: magic('retained-state'), version: B26_VERSION, runtime: B26_RUNTIME,
    groupIdHex: safe.groupIdHex, accountKeyHex: safe.accountKeyHex,
    signatureKeyHex: safe.signatureKeyHex, epochDec: safe.epochDec,
    groupContextDigestHex: safe.groupContextDigestHex,
    snapshotDigestHex: digestHex(snapshotBytes), snapshotByteLength: snapshotBytes.length,
    snapshotBytes, retainedDigestHex: '0'.repeat(64) };
  parseRetainedShape(draft);
  draft.retainedDigestHex = digestRecord('RETAINED-STATE', retainedValues(draft));
  return parseRetainedState(draft);
}

function parseRetainedShape(value) {
  assertB26Runtime(value.runtime);
  assertGroupIdHex(value.groupIdHex);
  assertHex64('accountKeyHex', value.accountKeyHex);
  assertHex64('signatureKeyHex', value.signatureKeyHex);
  parseEpochDecimal(value.epochDec, 'retained epoch');
  assertHex64('groupContextDigestHex', value.groupContextDigestHex);
  assertHex64('snapshotDigestHex', value.snapshotDigestHex);
  assertSafeInteger('snapshotByteLength', value.snapshotByteLength, 8,
    B26_LIMITS.maxSnapshotBytes);
  assertBytes('snapshotBytes', value.snapshotBytes, { min: 8, max: B26_LIMITS.maxSnapshotBytes });
  validateProviderSnapshot(value.snapshotBytes);
  if (value.snapshotBytes.length !== value.snapshotByteLength
    || digestHex(value.snapshotBytes) !== value.snapshotDigestHex) {
    failB26(B26_ERROR.CORRUPT, 'retained snapshot binding mismatch');
  }
  return value;
}

export function parseRetainedState(raw) {
  const value = parseRetainedShape(exact(raw, RETAINED_FIELDS, 'retained-state'));
  verifyDigest(value, 'retainedDigestHex', 'RETAINED-STATE', retainedValues(value));
  return Object.freeze({ ...value, runtime: Object.freeze({ ...value.runtime }),
    snapshotBytes: copyBytes(value.snapshotBytes) });
}

export const INPUT_FIELDS = Object.freeze([
  'format', 'version', 'groupIdHex', 'commitDigestHex', 'commitByteLength',
  'commitBytes', 'state', 'edgeDigestHex', 'reason', 'inputDigestHex',
]);

function inputValues(value) {
  return [value.format, value.version, value.groupIdHex, value.commitDigestHex,
    value.commitByteLength, value.state, value.edgeDigestHex, value.reason];
}

export function buildInput({ groupIdHex, commitBytes, state = B26_INPUT_STATE.UNBOUND,
  edgeDigestHex = null, reason = null }) {
  const exactBytes = copyBytes(commitBytes);
  const draft = { format: magic('input'), version: B26_VERSION, groupIdHex,
    commitDigestHex: digestHex(exactBytes), commitByteLength: exactBytes.length,
    commitBytes: exactBytes, state, edgeDigestHex, reason, inputDigestHex: '0'.repeat(64) };
  parseInputShape(draft);
  draft.inputDigestHex = digestRecord('INPUT', inputValues(draft));
  return parseInput(draft);
}

function parseInputShape(value) {
  assertGroupIdHex(value.groupIdHex);
  assertHex64('commitDigestHex', value.commitDigestHex);
  assertSafeInteger('commitByteLength', value.commitByteLength, 1, B26_LIMITS.maxCommitBytes);
  assertBytes('commitBytes', value.commitBytes, { min: 1, max: B26_LIMITS.maxCommitBytes });
  if (value.commitBytes.length !== value.commitByteLength
    || digestHex(value.commitBytes) !== value.commitDigestHex) {
    failB26(B26_ERROR.CORRUPT, 'input Commit binding mismatch');
  }
  if (!INPUT_STATES.has(value.state)) failB26(B26_ERROR.INVALID, 'input state is invalid');
  assertNullableHex64('edgeDigestHex', value.edgeDigestHex);
  assertNullableString('reason', value.reason, { min: 1, max: 96 });
  if ((value.state === B26_INPUT_STATE.EDGE) !== (value.edgeDigestHex !== null)) {
    failB26(B26_ERROR.INVALID, 'input edge binding is invalid');
  }
  return value;
}

export function parseInput(raw) {
  const value = parseInputShape(exact(raw, INPUT_FIELDS, 'input'));
  verifyDigest(value, 'inputDigestHex', 'INPUT', inputValues(value));
  return Object.freeze({ ...value, commitBytes: copyBytes(value.commitBytes) });
}

export const EDGE_FIELDS = Object.freeze([
  'format', 'version', 'groupIdHex', 'commitDigestHex', 'parentSnapshotDigestHex',
  'successorSnapshotDigestHex', 'parentEpochDec', 'parentGroupContextDigestHex',
  'successorEpochDec', 'successorGroupContextDigestHex', 'projectionDigestHex',
  'verifiedLeafDigestHex', 'operationKind', 'priority', 'committerIdentityHex',
  'authorizationContextDigestHex', 'authorizationResultDigestHex', 'origin',
  'localGenerationDigestHex', 'edgeDigestHex',
]);

function edgeValues(value) {
  return EDGE_FIELDS.slice(0, -1).map((field) => value[field]);
}

export function buildEdge(fields) {
  const safe = assertB26DirectObject(fields, EDGE_FIELDS.slice(2, -1), 'edge fields');
  const draft = { format: magic('edge'), version: B26_VERSION, ...safe,
    edgeDigestHex: '0'.repeat(64) };
  parseEdgeShape(draft);
  draft.edgeDigestHex = digestRecord('EDGE', edgeValues(draft));
  return parseEdge(draft);
}

function parseEdgeShape(value) {
  assertGroupIdHex(value.groupIdHex);
  ['commitDigestHex', 'parentSnapshotDigestHex', 'successorSnapshotDigestHex',
    'parentGroupContextDigestHex', 'successorGroupContextDigestHex',
    'projectionDigestHex', 'verifiedLeafDigestHex', 'committerIdentityHex',
    'authorizationContextDigestHex', 'authorizationResultDigestHex']
    .forEach((field) => assertHex64(field, value[field]));
  parseEpochDecimal(value.parentEpochDec, 'edge parent epoch');
  parseEpochDecimal(value.successorEpochDec, 'edge successor epoch');
  if (BigInt(value.successorEpochDec) !== BigInt(value.parentEpochDec) + 1n) {
    failB26(B26_ERROR.INVALID, 'edge must advance exactly one epoch');
  }
  assertString('operationKind', value.operationKind, { min: 1, max: 32 });
  assertSafeInteger('priority', value.priority, 0, 255);
  if (!EDGE_ORIGINS.has(value.origin)) failB26(B26_ERROR.INVALID, 'edge origin is invalid');
  assertNullableHex64('localGenerationDigestHex', value.localGenerationDigestHex);
  if ((value.origin === B26_EDGE_ORIGIN.LOCAL) !== (value.localGenerationDigestHex !== null)) {
    failB26(B26_ERROR.INVALID, 'local edge lacks generation authority');
  }
  return value;
}

export function parseEdge(raw) {
  const value = parseEdgeShape(exact(raw, EDGE_FIELDS, 'edge'));
  verifyDigest(value, 'edgeDigestHex', 'EDGE', edgeValues(value));
  return Object.freeze({ ...value });
}

export const PASS_FIELDS = Object.freeze([
  'format', 'version', 'groupIdHex', 'baseHeadDigestHex', 'closureCommitDigests',
  'state', 'rounds', 'selectedPath', 'passDigestHex', 'passRecordDigestHex',
]);

function passProtocolValues(value) {
  return [value.groupIdHex, value.baseHeadDigestHex, value.closureCommitDigests];
}

function passRecordValues(value) {
  return [value.format, value.version, ...passProtocolValues(value), value.state,
    value.rounds, value.selectedPath, value.passDigestHex];
}

export function buildPass({ groupIdHex, baseHeadDigestHex, closureCommitDigests,
  state = B26_PASS_STATE.FROZEN, rounds = 0, selectedPath = [] }) {
  const draft = { format: magic('pass'), version: B26_VERSION, groupIdHex,
    baseHeadDigestHex, closureCommitDigests: [...closureCommitDigests], state, rounds,
    selectedPath: [...selectedPath], passDigestHex: '0'.repeat(64),
    passRecordDigestHex: '0'.repeat(64) };
  parsePassShape(draft);
  draft.passDigestHex = digestRecord('PASS-ID', passProtocolValues(draft));
  draft.passRecordDigestHex = digestRecord('PASS-RECORD', passRecordValues(draft));
  return parsePass(draft);
}

function parsePassShape(value) {
  assertGroupIdHex(value.groupIdHex);
  assertHex64('baseHeadDigestHex', value.baseHeadDigestHex);
  assertSortedUniqueHex64('closureCommitDigests', value.closureCommitDigests,
    { max: B26_LIMITS.maxInputs });
  if (!PASS_STATES.has(value.state)) failB26(B26_ERROR.INVALID, 'pass state is invalid');
  assertSafeInteger('rounds', value.rounds, 0, B26_LIMITS.maxEdges + 1);
  assertDigestPath('selectedPath', value.selectedPath);
  if (value.state === B26_PASS_STATE.FROZEN
    && (value.rounds !== 0 || value.selectedPath.length !== 0)) {
    failB26(B26_ERROR.INVALID, 'frozen pass carries settlement output');
  }
  return value;
}

export function parsePass(raw) {
  const value = parsePassShape(exact(raw, PASS_FIELDS, 'pass'));
  verifyDigest(value, 'passDigestHex', 'PASS-ID', passProtocolValues(value));
  verifyDigest(value, 'passRecordDigestHex', 'PASS-RECORD', passRecordValues(value));
  return Object.freeze({ ...value,
    closureCommitDigests: Object.freeze([...value.closureCommitDigests]),
    selectedPath: Object.freeze([...value.selectedPath]) });
}

export const INVALIDATION_FIELDS = Object.freeze([
  'format', 'version', 'groupIdHex', 'predecessorHeadDigestHex',
  'successorSnapshotDigestHex', 'commonAncestorSnapshotDigestHex', 'displacedPath',
  'selectedPath', 'invalidationDigestHex',
]);

function invalidationValues(value) { return INVALIDATION_FIELDS.slice(0, -1).map((f) => value[f]); }

export function buildInvalidation(fields) {
  const safe = assertB26DirectObject(fields, INVALIDATION_FIELDS.slice(2, -1),
    'invalidation fields');
  const draft = { format: magic('invalidation'), version: B26_VERSION, ...safe,
    invalidationDigestHex: '0'.repeat(64) };
  parseInvalidationShape(draft);
  draft.invalidationDigestHex = digestRecord('INVALIDATION', invalidationValues(draft));
  return parseInvalidation(draft);
}

function parseInvalidationShape(value) {
  assertGroupIdHex(value.groupIdHex);
  ['predecessorHeadDigestHex', 'successorSnapshotDigestHex', 'commonAncestorSnapshotDigestHex']
    .forEach((field) => assertHex64(field, value[field]));
  assertDigestPath('displacedPath', value.displacedPath);
  assertDigestPath('selectedPath', value.selectedPath);
  return value;
}

export function parseInvalidation(raw) {
  const value = parseInvalidationShape(exact(raw, INVALIDATION_FIELDS, 'invalidation'));
  verifyDigest(value, 'invalidationDigestHex', 'INVALIDATION', invalidationValues(value));
  return Object.freeze({ ...value, displacedPath: Object.freeze([...value.displacedPath]),
    selectedPath: Object.freeze([...value.selectedPath]) });
}

export const TRANSITION_FIELDS = Object.freeze([
  'format', 'version', 'groupIdHex', 'seq', 'kind', 'predecessorHeadDigestHex',
  'successorSnapshotDigestHex', 'anchorSnapshotDigestHex', 'selectedPath',
  'displacedPath', 'passDigestHex', 'invalidationDigestHex', 'releasedStateDigests',
  'epochDec', 'groupContextDigestHex', 'transitionDigestHex',
]);

function transitionValues(value) { return TRANSITION_FIELDS.slice(0, -1).map((f) => value[f]); }

export function buildTransition(fields) {
  const safe = assertB26DirectObject(fields, TRANSITION_FIELDS.slice(2, -1),
    'transition fields');
  const draft = { format: magic('transition'), version: B26_VERSION, ...safe,
    transitionDigestHex: '0'.repeat(64) };
  parseTransitionShape(draft);
  draft.transitionDigestHex = digestRecord('TRANSITION', transitionValues(draft));
  return parseTransition(draft);
}

function parseTransitionShape(value) {
  assertGroupIdHex(value.groupIdHex);
  assertSafeInteger('transition seq', value.seq, 1, B26_LIMITS.maxTransitions);
  assertString('transition kind', value.kind, { min: 1, max: 32 });
  assertNullableHex64('predecessorHeadDigestHex', value.predecessorHeadDigestHex);
  ['successorSnapshotDigestHex', 'anchorSnapshotDigestHex', 'passDigestHex',
    'invalidationDigestHex', 'groupContextDigestHex']
    .forEach((field) => assertNullableHex64(field, value[field]));
  assertDigestPath('selectedPath', value.selectedPath);
  assertDigestPath('displacedPath', value.displacedPath);
  assertSortedUniqueHex64('releasedStateDigests', value.releasedStateDigests,
    { max: B26_LIMITS.maxStates });
  parseEpochDecimal(value.epochDec, 'transition epoch');
  return value;
}

export function parseTransition(raw) {
  const value = parseTransitionShape(exact(raw, TRANSITION_FIELDS, 'transition'));
  verifyDigest(value, 'transitionDigestHex', 'TRANSITION', transitionValues(value));
  return Object.freeze({ ...value, selectedPath: Object.freeze([...value.selectedPath]),
    displacedPath: Object.freeze([...value.displacedPath]),
    releasedStateDigests: Object.freeze([...value.releasedStateDigests]) });
}

export const RELEASE_FIELDS = Object.freeze([
  'format', 'version', 'groupIdHex', 'snapshotDigestHex', 'epochDec',
  'groupContextDigestHex', 'retainedDigestHex', 'releaseAuthorityDigestHex',
  'releaseDigestHex',
]);

function releaseValues(value) { return RELEASE_FIELDS.slice(0, -1).map((f) => value[f]); }

export function buildRelease(fields) {
  const safe = assertB26DirectObject(fields, RELEASE_FIELDS.slice(2, -1), 'release fields');
  const draft = { format: magic('release'), version: B26_VERSION, ...safe,
    releaseDigestHex: '0'.repeat(64) };
  assertGroupIdHex(draft.groupIdHex);
  ['snapshotDigestHex', 'groupContextDigestHex', 'retainedDigestHex',
    'releaseAuthorityDigestHex'].forEach((field) => assertHex64(field, draft[field]));
  parseEpochDecimal(draft.epochDec, 'release epoch');
  draft.releaseDigestHex = digestRecord('RELEASE', releaseValues(draft));
  return parseRelease(draft);
}

export function parseRelease(raw) {
  const value = exact(raw, RELEASE_FIELDS, 'release');
  assertGroupIdHex(value.groupIdHex);
  ['snapshotDigestHex', 'groupContextDigestHex', 'retainedDigestHex',
    'releaseAuthorityDigestHex'].forEach((field) => assertHex64(field, value[field]));
  parseEpochDecimal(value.epochDec, 'release epoch');
  verifyDigest(value, 'releaseDigestHex', 'RELEASE', releaseValues(value));
  return Object.freeze({ ...value });
}

export const GENERATION_TRUNCATION_FIELDS = Object.freeze([
  'format', 'version', 'groupIdHex', 'throughGeneration',
  'evictedCommitDigestHex', 'evictedGenerationAuthorityDigestHex',
  'evictedGenerationDigestHex', 'priorMarkerDigestHex', 'markerDigestHex',
]);

function generationTruncationValues(value) {
  return GENERATION_TRUNCATION_FIELDS.slice(0, -1).map((field) => value[field]);
}

export function buildGenerationTruncation(fields) {
  const safe = assertB26DirectObject(fields,
    GENERATION_TRUNCATION_FIELDS.slice(2, -1), 'generation-truncation fields');
  const draft = { format: magic('generation-truncation'), version: B26_VERSION,
    ...safe, markerDigestHex: '0'.repeat(64) };
  parseGenerationTruncationShape(draft);
  draft.markerDigestHex = digestRecord(
    'GENERATION-TRUNCATION', generationTruncationValues(draft));
  return parseGenerationTruncation(draft);
}

function parseGenerationTruncationShape(value) {
  assertGroupIdHex(value.groupIdHex);
  assertSafeInteger('truncation generation', value.throughGeneration,
    1, Number.MAX_SAFE_INTEGER);
  ['evictedCommitDigestHex', 'evictedGenerationAuthorityDigestHex',
    'evictedGenerationDigestHex'].forEach((field) => assertHex64(field, value[field]));
  assertNullableHex64('priorMarkerDigestHex', value.priorMarkerDigestHex);
  return value;
}

export function parseGenerationTruncation(raw) {
  const value = parseGenerationTruncationShape(exact(
    raw, GENERATION_TRUNCATION_FIELDS, 'generation-truncation'));
  verifyDigest(value, 'markerDigestHex',
    'GENERATION-TRUNCATION', generationTruncationValues(value));
  return Object.freeze({ ...value });
}

export const GENERATION_FIELDS = Object.freeze([
  'format', 'version', 'groupIdHex', 'generation', 'state', 'operationKind',
  'parentHeadDigestHex', 'parentSnapshotDigestHex', 'parentEpochDec',
  'parentGroupContextDigestHex', 'pendingSnapshotDigestHex', 'commitDigestHex',
  'commitBytes', 'commitByteLength', 'verifiedLeafDigestHex', 'projectionDigestHex',
  'candidateEpochDec', 'candidateGroupContextDigestHex', 'priority',
  'committerIdentityHex', 'authorizationContextDigestHex',
  'authorizationResultDigestHex', 'recipientScope', 'publishAttempts', 'ackCount',
  'failureCount', 'contradiction', 'generationDigestHex',
]);

function generationValues(value) {
  return GENERATION_FIELDS.slice(0, -1).filter((f) => f !== 'commitBytes').map((f) => value[f]);
}

export function buildGeneration(fields) {
  const safe = assertB26DirectObject(fields, GENERATION_FIELDS.slice(2, -1),
    'generation fields');
  const draft = { format: magic('generation'), version: B26_VERSION, ...safe,
    commitBytes: copyBytes(safe.commitBytes), recipientScope: [...safe.recipientScope],
    generationDigestHex: '0'.repeat(64) };
  parseGenerationShape(draft);
  draft.generationDigestHex = digestRecord('GENERATION', generationValues(draft));
  return parseGeneration(draft);
}

function parseGenerationShape(value) {
  assertGroupIdHex(value.groupIdHex);
  assertSafeInteger('generation', value.generation, 1, Number.MAX_SAFE_INTEGER);
  if (!GENERATION_STATES.has(value.state)) failB26(B26_ERROR.INVALID, 'generation state invalid');
  assertString('operationKind', value.operationKind, { min: 1, max: 32 });
  ['parentHeadDigestHex', 'parentSnapshotDigestHex', 'parentGroupContextDigestHex',
    'pendingSnapshotDigestHex', 'commitDigestHex', 'verifiedLeafDigestHex',
    'projectionDigestHex', 'candidateGroupContextDigestHex', 'committerIdentityHex',
    'authorizationContextDigestHex', 'authorizationResultDigestHex']
    .forEach((field) => assertHex64(field, value[field]));
  parseEpochDecimal(value.parentEpochDec, 'generation parent epoch');
  parseEpochDecimal(value.candidateEpochDec, 'generation candidate epoch');
  assertSafeInteger('commitByteLength', value.commitByteLength, 1, B26_LIMITS.maxCommitBytes);
  assertBytes('commitBytes', value.commitBytes, { min: 1, max: B26_LIMITS.maxCommitBytes });
  if (value.commitBytes.length !== value.commitByteLength
    || digestHex(value.commitBytes) !== value.commitDigestHex) {
    failB26(B26_ERROR.CORRUPT, 'generation Commit binding mismatch');
  }
  assertSafeInteger('priority', value.priority, 0, 255);
  assertSortedUniqueHex64('recipientScope', value.recipientScope,
    { min: 1, max: B26_LIMITS.maxMembers - 1 });
  assertSafeInteger('publishAttempts', value.publishAttempts, 0,
    B26_LIMITS.maxPublicationAttempts);
  assertSafeInteger('ackCount', value.ackCount, 0,
    B26_LIMITS.maxPublicationRecordsPerGeneration);
  assertSafeInteger('failureCount', value.failureCount, 0,
    B26_LIMITS.maxPublicationRecordsPerGeneration);
  if (typeof value.contradiction !== 'boolean') {
    failB26(B26_ERROR.INVALID, 'generation contradiction must be boolean');
  }
  return value;
}

export function parseGeneration(raw) {
  const value = parseGenerationShape(exact(raw, GENERATION_FIELDS, 'generation'));
  verifyDigest(value, 'generationDigestHex', 'GENERATION', generationValues(value));
  return Object.freeze({ ...value, commitBytes: copyBytes(value.commitBytes),
    recipientScope: Object.freeze([...value.recipientScope]) });
}

export const ACTIVE_LOCAL_FIELDS = Object.freeze([
  'format', 'version', 'groupIdHex', 'generationDigestHex', 'pointerDigestHex',
]);

function activeLocalValues(value) {
  return ACTIVE_LOCAL_FIELDS.slice(0, -1).map((field) => value[field]);
}

export function buildActiveLocal({ groupIdHex, generationDigestHex }) {
  const draft = { format: magic('active-local'), version: B26_VERSION, groupIdHex,
    generationDigestHex, pointerDigestHex: '0'.repeat(64) };
  assertGroupIdHex(groupIdHex);
  assertNullableHex64('generationDigestHex', generationDigestHex);
  draft.pointerDigestHex = digestRecord('ACTIVE-LOCAL', activeLocalValues(draft));
  return parseActiveLocal(draft);
}

export function parseActiveLocal(raw) {
  const value = exact(raw, ACTIVE_LOCAL_FIELDS, 'active-local');
  assertGroupIdHex(value.groupIdHex);
  assertNullableHex64('generationDigestHex', value.generationDigestHex);
  verifyDigest(value, 'pointerDigestHex', 'ACTIVE-LOCAL', activeLocalValues(value));
  return Object.freeze({ ...value });
}

export const PUBLICATION_FIELDS = Object.freeze([
  'format', 'version', 'groupIdHex', 'generationDigestHex', 'sequence', 'kind',
  'attemptOrdinal', 'artifactDigestHex', 'recipientIdentityHex', 'payloadDigestHex',
  'payloadBytes', 'evidenceDigestHex',
]);

function publicationValues(value) {
  return PUBLICATION_FIELDS.slice(0, -1).filter((f) => f !== 'payloadBytes').map((f) => value[f]);
}

export function buildPublication(fields) {
  const safe = assertB26DirectObject(fields, [
    'groupIdHex', 'generationDigestHex', 'sequence', 'kind', 'attemptOrdinal',
    'artifactDigestHex', 'recipientIdentityHex', 'payloadBytes',
  ],
    'publication fields');
  const payloadBytes = copyBytes(safe.payloadBytes);
  const draft = { format: magic('publication'), version: B26_VERSION, ...safe,
    payloadBytes, payloadDigestHex: digestHex(payloadBytes), evidenceDigestHex: '0'.repeat(64) };
  parsePublicationShape(draft);
  draft.evidenceDigestHex = digestRecord('PUBLICATION', publicationValues(draft));
  return parsePublication(draft);
}

function parsePublicationShape(value) {
  assertGroupIdHex(value.groupIdHex);
  ['generationDigestHex', 'artifactDigestHex', 'payloadDigestHex']
    .forEach((field) => assertHex64(field, value[field]));
  assertSafeInteger('publication sequence', value.sequence, 1,
    B26_LIMITS.maxPublicationRecordsPerGeneration);
  if (!PUBLICATION_KINDS.has(value.kind)) failB26(B26_ERROR.INVALID, 'publication kind invalid');
  assertSafeInteger('attemptOrdinal', value.attemptOrdinal, 1,
    B26_LIMITS.maxPublicationAttempts);
  assertNullableHex64('recipientIdentityHex', value.recipientIdentityHex);
  if ((value.kind === B26_PUBLICATION_KIND.ATTEMPT)
    !== (value.recipientIdentityHex === null)) {
    failB26(B26_ERROR.INVALID, 'publication recipient binding is invalid');
  }
  assertBytes('payloadBytes', value.payloadBytes,
    { min: 0, max: B26_LIMITS.maxPublicationPayloadBytes });
  if (digestHex(value.payloadBytes) !== value.payloadDigestHex) {
    failB26(B26_ERROR.CORRUPT, 'publication payload binding mismatch');
  }
  return value;
}

export function parsePublication(raw) {
  const value = parsePublicationShape(exact(raw, PUBLICATION_FIELDS, 'publication'));
  verifyDigest(value, 'evidenceDigestHex', 'PUBLICATION', publicationValues(value));
  return Object.freeze({ ...value, payloadBytes: copyBytes(value.payloadBytes) });
}

export const PROBE_RESERVATION_FIELDS = Object.freeze([
  'format', 'version', 'groupIdHex', 'headDigestHex', 'tipCommitDigestHex', 'epochDec',
  'groupContextDigestHex', 'localMemberIdentityHex', 'probeKeyHex', 'state',
  'reservationDigestHex',
]);

function reservationValues(value) {
  return PROBE_RESERVATION_FIELDS.slice(0, -1).map((f) => value[f]);
}

export function buildProbeReservation(fields) {
  const safe = assertB26DirectObject(fields, PROBE_RESERVATION_FIELDS.slice(2, -2),
    'probe reservation fields');
  const draft = { format: magic('probe-reservation'), version: B26_VERSION, ...safe,
    state: B26_PROBE_STATE.RESERVED, reservationDigestHex: '0'.repeat(64) };
  parseProbeReservationShape(draft);
  draft.reservationDigestHex = digestRecord('PROBE-RESERVATION', reservationValues(draft));
  return parseProbeReservation(draft);
}

function parseProbeReservationShape(value) {
  assertGroupIdHex(value.groupIdHex);
  assertHex64('headDigestHex', value.headDigestHex);
  assertNullableHex64('tipCommitDigestHex', value.tipCommitDigestHex);
  parseEpochDecimal(value.epochDec, 'probe epoch');
  assertHex64('groupContextDigestHex', value.groupContextDigestHex);
  assertHex64('localMemberIdentityHex', value.localMemberIdentityHex);
  assertHex64('probeKeyHex', value.probeKeyHex);
  if (probeKey(value) !== value.probeKeyHex) failB26(B26_ERROR.CORRUPT, 'probe key mismatch');
  if (!PROBE_STATES.has(value.state) || value.state !== B26_PROBE_STATE.RESERVED) {
    failB26(B26_ERROR.INVALID, 'probe reservation state is invalid');
  }
  return value;
}

export function parseProbeReservation(raw) {
  const value = parseProbeReservationShape(exact(raw, PROBE_RESERVATION_FIELDS,
    'probe-reservation'));
  verifyDigest(value, 'reservationDigestHex', 'PROBE-RESERVATION', reservationValues(value));
  return Object.freeze({ ...value });
}

export const PROBE_COMPLETION_FIELDS = Object.freeze([
  'format', 'version', 'probeKeyHex', 'reservationDigestHex', 'ciphertextDigestHex',
  'plaintextDigestHex', 'peerIdentityHex', 'completionDigestHex',
]);

function completionValues(value) {
  return PROBE_COMPLETION_FIELDS.slice(0, -1).map((f) => value[f]);
}

export function buildProbeCompletion(fields) {
  const safe = assertB26DirectObject(fields, PROBE_COMPLETION_FIELDS.slice(2, -1),
    'probe completion fields');
  const draft = { format: magic('probe-completion'), version: B26_VERSION, ...safe,
    completionDigestHex: '0'.repeat(64) };
  ['probeKeyHex', 'reservationDigestHex', 'ciphertextDigestHex', 'plaintextDigestHex',
    'peerIdentityHex'].forEach((field) => assertHex64(field, draft[field]));
  draft.completionDigestHex = digestRecord('PROBE-COMPLETION', completionValues(draft));
  return parseProbeCompletion(draft);
}

export function parseProbeCompletion(raw) {
  const value = exact(raw, PROBE_COMPLETION_FIELDS, 'probe-completion');
  ['probeKeyHex', 'reservationDigestHex', 'ciphertextDigestHex', 'plaintextDigestHex',
    'peerIdentityHex'].forEach((field) => assertHex64(field, value[field]));
  verifyDigest(value, 'completionDigestHex', 'PROBE-COMPLETION', completionValues(value));
  return Object.freeze({ ...value });
}

export const MESSAGE_STATE_FIELDS = Object.freeze([
  'format', 'version', 'profile', 'runtime', 'groupIdHex', 'instanceKeyHex',
  'baseHeadDigestHex', 'tipCommitDigestHex', 'epochDec', 'groupContextDigestHex',
  'localMemberIdentityHex', 'baseRetainedSnapshotDigestHex', 'sequence', 'sentCount',
  'receivedCount', 'snapshotDigestHex', 'priorStateDigestHex', 'state', 'stateDigestHex',
]);

function messageStateValues(value) {
  return MESSAGE_STATE_FIELDS.slice(0, -1).map((field) => value[field]);
}

export function buildMessageState(fields) {
  const safe = assertB26DirectObject(fields, MESSAGE_STATE_FIELDS.slice(4, -1),
    'message-state fields');
  const draft = { format: magic('message-state'), version: B26_VERSION,
    profile: B26_PROFILE, runtime: B26_RUNTIME, ...safe,
    stateDigestHex: '0'.repeat(64) };
  parseMessageStateShape(draft);
  draft.stateDigestHex = digestRecord('MESSAGE-STATE', messageStateValues(draft));
  return parseMessageState(draft);
}

function parseMessageStateShape(value) {
  if (value.profile !== B26_PROFILE) failB26(B26_ERROR.INCOMPATIBLE,
    'message-state profile differs');
  assertB26Runtime(value.runtime);
  assertGroupIdHex(value.groupIdHex);
  assertHex64('instanceKeyHex', value.instanceKeyHex);
  assertHex64('baseHeadDigestHex', value.baseHeadDigestHex);
  assertNullableHex64('tipCommitDigestHex', value.tipCommitDigestHex);
  parseEpochDecimal(value.epochDec, 'message-state epoch');
  assertHex64('groupContextDigestHex', value.groupContextDigestHex);
  assertHex64('localMemberIdentityHex', value.localMemberIdentityHex);
  assertHex64('baseRetainedSnapshotDigestHex', value.baseRetainedSnapshotDigestHex);
  assertSafeInteger('message sequence', value.sequence, 0, Number.MAX_SAFE_INTEGER);
  assertSafeInteger('sent count', value.sentCount, 0, Number.MAX_SAFE_INTEGER);
  assertSafeInteger('received count', value.receivedCount, 0, Number.MAX_SAFE_INTEGER);
  if (value.sequence !== value.sentCount + value.receivedCount) {
    failB26(B26_ERROR.INVALID, 'message-state counters do not sum to sequence');
  }
  assertHex64('snapshotDigestHex', value.snapshotDigestHex);
  assertNullableHex64('priorStateDigestHex', value.priorStateDigestHex);
  if (!MESSAGE_STATES.has(value.state)) failB26(B26_ERROR.INVALID,
    'message-state disposition is invalid');
  if (messageInstanceKey({ groupIdHex: value.groupIdHex,
    tipCommitDigestHex: value.tipCommitDigestHex, epochDec: value.epochDec,
    groupContextDigestHex: value.groupContextDigestHex,
    localMemberIdentityHex: value.localMemberIdentityHex }) !== value.instanceKeyHex) {
    failB26(B26_ERROR.CORRUPT, 'message-state instance identity mismatch');
  }
  return value;
}

export function parseMessageState(raw) {
  const value = parseMessageStateShape(exact(raw, MESSAGE_STATE_FIELDS, 'message-state'));
  verifyDigest(value, 'stateDigestHex', 'MESSAGE-STATE', messageStateValues(value));
  return Object.freeze({ ...value, runtime: Object.freeze({ ...value.runtime }) });
}

export const MESSAGE_SNAPSHOT_FIELDS = Object.freeze([
  'format', 'version', 'runtime', 'groupIdHex', 'instanceKeyHex', 'epochDec',
  'groupContextDigestHex', 'snapshotBytes', 'snapshotDigestHex', 'recordDigestHex',
]);

function messageSnapshotValues(value) {
  return [value.format, value.version, value.runtime, value.groupIdHex, value.instanceKeyHex,
    value.epochDec, value.groupContextDigestHex, value.snapshotDigestHex];
}

export function buildMessageSnapshot(fields) {
  const safe = assertB26DirectObject(fields,
    ['groupIdHex', 'instanceKeyHex', 'epochDec', 'groupContextDigestHex', 'snapshotBytes'],
    'message-snapshot fields');
  validateProviderSnapshot(safe.snapshotBytes);
  const bytes = copyBytes(safe.snapshotBytes);
  const draft = { format: magic('message-snapshot'), version: B26_VERSION,
    runtime: B26_RUNTIME, ...safe, snapshotBytes: bytes,
    snapshotDigestHex: digestHex(bytes), recordDigestHex: '0'.repeat(64) };
  parseMessageSnapshotShape(draft);
  draft.recordDigestHex = digestRecord('MESSAGE-SNAPSHOT', messageSnapshotValues(draft));
  return parseMessageSnapshot(draft);
}

function parseMessageSnapshotShape(value) {
  assertB26Runtime(value.runtime);
  assertGroupIdHex(value.groupIdHex);
  assertHex64('instanceKeyHex', value.instanceKeyHex);
  parseEpochDecimal(value.epochDec, 'message-snapshot epoch');
  assertHex64('groupContextDigestHex', value.groupContextDigestHex);
  validateProviderSnapshot(value.snapshotBytes);
  assertHex64('snapshotDigestHex', value.snapshotDigestHex);
  if (digestHex(value.snapshotBytes) !== value.snapshotDigestHex) failB26(B26_ERROR.CORRUPT,
    'message-snapshot byte digest mismatch');
  return value;
}

export function parseMessageSnapshot(raw) {
  const value = parseMessageSnapshotShape(exact(raw, MESSAGE_SNAPSHOT_FIELDS,
    'message-snapshot'));
  verifyDigest(value, 'recordDigestHex', 'MESSAGE-SNAPSHOT', messageSnapshotValues(value));
  return Object.freeze({ ...value, runtime: Object.freeze({ ...value.runtime }),
    snapshotBytes: copyBytes(value.snapshotBytes) });
}

export const OUTBOX_FIELDS = Object.freeze([
  'format', 'version', 'groupIdHex', 'instanceKeyHex', 'requestId', 'requestKeyHex',
  'ordinal', 'payloadDigestHex', 'recipientScope', 'ciphertextBytes',
  'ciphertextDigestHex', 'state', 'attemptCount', 'ackCount', 'failureCount',
  'outboxDigestHex',
]);

function outboxValues(value) {
  return OUTBOX_FIELDS.slice(0, -1).map((field) => value[field]);
}

export function buildOutbox(fields) {
  const safe = assertB26DirectObject(fields, OUTBOX_FIELDS.slice(2, -1), 'outbox fields');
  const draft = { format: magic('app-outbox'), version: B26_VERSION, ...safe,
    outboxDigestHex: '0'.repeat(64) };
  parseOutboxShape(draft);
  draft.outboxDigestHex = digestRecord('APP-OUTBOX', outboxValues(draft));
  return parseOutbox(draft);
}

function parseOutboxShape(value) {
  assertGroupIdHex(value.groupIdHex);
  assertHex64('instanceKeyHex', value.instanceKeyHex);
  assertString('requestId', value.requestId,
    { min: 1, max: B26_LIMITS.maxRequestIdBytes, pattern: /^[\x21-\x7e]+$/ });
  assertHex64('requestKeyHex', value.requestKeyHex);
  if (requestKey(value.instanceKeyHex, value.requestId) !== value.requestKeyHex) {
    failB26(B26_ERROR.CORRUPT, 'outbox request binding mismatch');
  }
  assertSafeInteger('outbox ordinal', value.ordinal, 1, Number.MAX_SAFE_INTEGER);
  assertHex64('payloadDigestHex', value.payloadDigestHex);
  assertSortedUniqueHex64('recipientScope', value.recipientScope,
    { min: 1, max: B26_LIMITS.maxMembers });
  assertBytes('ciphertextBytes', value.ciphertextBytes,
    { min: 1, max: B26_LIMITS.maxApplicationCiphertextBytes });
  assertHex64('ciphertextDigestHex', value.ciphertextDigestHex);
  if (digestHex(value.ciphertextBytes) !== value.ciphertextDigestHex) {
    failB26(B26_ERROR.CORRUPT, 'outbox ciphertext binding mismatch');
  }
  if (!OUTBOX_STATES.has(value.state)) failB26(B26_ERROR.INVALID,
    'outbox state is invalid');
  assertSafeInteger('attemptCount', value.attemptCount, 0,
    B26_LIMITS.maxMessagePublicationRecords);
  assertSafeInteger('ackCount', value.ackCount, 0,
    B26_LIMITS.maxMessagePublicationRecords);
  assertSafeInteger('failureCount', value.failureCount, 0,
    B26_LIMITS.maxMessagePublicationRecords);
  if (value.ackCount > value.attemptCount || value.failureCount > value.attemptCount) {
    failB26(B26_ERROR.INVALID, 'outbox evidence counters exceed attempts');
  }
  return value;
}

export function parseOutbox(raw) {
  const value = parseOutboxShape(exact(raw, OUTBOX_FIELDS, 'app-outbox'));
  verifyDigest(value, 'outboxDigestHex', 'APP-OUTBOX', outboxValues(value));
  return Object.freeze({ ...value, recipientScope: Object.freeze([...value.recipientScope]),
    ciphertextBytes: copyBytes(value.ciphertextBytes) });
}

export const APP_PUBLICATION_FIELDS = Object.freeze([
  'format', 'version', 'groupIdHex', 'instanceKeyHex', 'ordinal', 'sequence', 'kind',
  'attemptOrdinal', 'recipientIdentityHex', 'payloadBytes', 'payloadDigestHex',
  'evidenceDigestHex',
]);

function appPublicationValues(value) {
  return APP_PUBLICATION_FIELDS.slice(0, -1).map((field) => value[field]);
}

export function buildAppPublication(fields) {
  const safe = assertB26DirectObject(fields, APP_PUBLICATION_FIELDS.slice(2, -1),
    'application publication fields');
  const draft = { format: magic('app-publication'), version: B26_VERSION, ...safe,
    evidenceDigestHex: '0'.repeat(64) };
  parseAppPublicationShape(draft);
  draft.evidenceDigestHex = digestRecord('APP-PUBLICATION', appPublicationValues(draft));
  return parseAppPublication(draft);
}

function parseAppPublicationShape(value) {
  assertGroupIdHex(value.groupIdHex);
  assertHex64('instanceKeyHex', value.instanceKeyHex);
  assertSafeInteger('outbox ordinal', value.ordinal, 1, Number.MAX_SAFE_INTEGER);
  assertSafeInteger('publication sequence', value.sequence, 1,
    B26_LIMITS.maxMessagePublicationRecords);
  if (!APP_PUBLICATION_KINDS.has(value.kind)) failB26(B26_ERROR.INVALID,
    'application publication kind is invalid');
  assertSafeInteger('attemptOrdinal', value.attemptOrdinal, 1,
    B26_LIMITS.maxMessagePublicationRecords);
  assertHex64('recipientIdentityHex', value.recipientIdentityHex);
  assertBytes('publication payload', value.payloadBytes,
    { min: 0, max: B26_LIMITS.maxPublicationPayloadBytes });
  assertHex64('payloadDigestHex', value.payloadDigestHex);
  if (digestHex(value.payloadBytes) !== value.payloadDigestHex) failB26(B26_ERROR.CORRUPT,
    'application publication payload mismatch');
  return value;
}

export function parseAppPublication(raw) {
  const value = parseAppPublicationShape(exact(raw, APP_PUBLICATION_FIELDS,
    'app-publication'));
  verifyDigest(value, 'evidenceDigestHex', 'APP-PUBLICATION', appPublicationValues(value));
  return Object.freeze({ ...value, payloadBytes: copyBytes(value.payloadBytes) });
}

export const INBOUND_FIELDS = Object.freeze([
  'format', 'version', 'groupIdHex', 'instanceKeyHex', 'ciphertextBytes',
  'ciphertextDigestHex', 'disposition', 'receivedOrdinal', 'plaintextBytes',
  'plaintextDigestHex', 'inboundDigestHex',
]);

function inboundValues(value) {
  return INBOUND_FIELDS.slice(0, -1).map((field) => value[field]);
}

export function buildInbound(fields) {
  const safe = assertB26DirectObject(fields, INBOUND_FIELDS.slice(2, -1), 'inbound fields');
  const draft = { format: magic('app-inbound'), version: B26_VERSION, ...safe,
    inboundDigestHex: '0'.repeat(64) };
  parseInboundShape(draft);
  draft.inboundDigestHex = digestRecord('APP-INBOUND', inboundValues(draft));
  return parseInbound(draft);
}

function parseInboundShape(value) {
  assertGroupIdHex(value.groupIdHex);
  assertHex64('instanceKeyHex', value.instanceKeyHex);
  assertBytes('inbound ciphertext', value.ciphertextBytes,
    { min: 1, max: B26_LIMITS.maxApplicationCiphertextBytes });
  assertHex64('ciphertextDigestHex', value.ciphertextDigestHex);
  if (digestHex(value.ciphertextBytes) !== value.ciphertextDigestHex) {
    failB26(B26_ERROR.CORRUPT, 'inbound ciphertext binding mismatch');
  }
  if (!INBOUND_STATES.has(value.disposition)) failB26(B26_ERROR.INVALID,
    'inbound disposition is invalid');
  assertSafeInteger('receivedOrdinal', value.receivedOrdinal, 0, Number.MAX_SAFE_INTEGER);
  assertBytes('inbound plaintext', value.plaintextBytes,
    { min: 0, max: B26_LIMITS.maxApplicationPayloadBytes });
  assertNullableHex64('plaintextDigestHex', value.plaintextDigestHex);
  if (value.disposition === B26_INBOUND_STATE.ACCEPTED) {
    if (value.plaintextDigestHex === null
      || digestHex(value.plaintextBytes) !== value.plaintextDigestHex) {
      failB26(B26_ERROR.CORRUPT, 'accepted inbound record lacks bound delivery data');
    }
  } else if (value.plaintextDigestHex !== null || value.plaintextBytes.length !== 0) {
    failB26(B26_ERROR.INVALID, 'non-accepted inbound record contains delivery data');
  }
  return value;
}

export function parseInbound(raw) {
  const value = parseInboundShape(exact(raw, INBOUND_FIELDS, 'app-inbound'));
  verifyDigest(value, 'inboundDigestHex', 'APP-INBOUND', inboundValues(value));
  return Object.freeze({ ...value, ciphertextBytes: copyBytes(value.ciphertextBytes),
    plaintextBytes: copyBytes(value.plaintextBytes) });
}

export const INBOUND_TRUNCATION_FIELDS = Object.freeze([
  'format', 'version', 'groupIdHex', 'instanceKeyHex', 'throughReceivedOrdinal',
  'evictedCiphertextDigestHex', 'evictedInboundDigestHex', 'priorMarkerDigestHex',
  'markerDigestHex',
]);

function inboundTruncationValues(value) {
  return INBOUND_TRUNCATION_FIELDS.slice(0, -1).map((field) => value[field]);
}

export function buildInboundTruncation(fields) {
  const safe = assertB26DirectObject(
    fields, INBOUND_TRUNCATION_FIELDS.slice(2, -1), 'inbound truncation fields');
  const draft = { format: magic('inbound-truncation'), version: B26_VERSION,
    ...safe, markerDigestHex: '0'.repeat(64) };
  parseInboundTruncationShape(draft);
  draft.markerDigestHex = digestRecord(
    'INBOUND-TRUNCATION', inboundTruncationValues(draft));
  return parseInboundTruncation(draft);
}

function parseInboundTruncationShape(value) {
  assertGroupIdHex(value.groupIdHex);
  assertHex64('instanceKeyHex', value.instanceKeyHex);
  assertSafeInteger('throughReceivedOrdinal', value.throughReceivedOrdinal,
    0, Number.MAX_SAFE_INTEGER);
  assertHex64('evictedCiphertextDigestHex', value.evictedCiphertextDigestHex);
  assertHex64('evictedInboundDigestHex', value.evictedInboundDigestHex);
  assertNullableHex64('priorMarkerDigestHex', value.priorMarkerDigestHex);
  return value;
}

export function parseInboundTruncation(raw) {
  const value = parseInboundTruncationShape(exact(
    raw, INBOUND_TRUNCATION_FIELDS, 'inbound-truncation'));
  verifyDigest(value, 'markerDigestHex',
    'INBOUND-TRUNCATION', inboundTruncationValues(value));
  return Object.freeze({ ...value });
}

export const MESSAGE_RELEASE_FIELDS = Object.freeze([
  'format', 'version', 'groupIdHex', 'instanceKeyHex', 'stateDigestHex',
  'snapshotDigestHex', 'releaseAuthorityDigestHex', 'releaseDigestHex',
]);

export function buildMessageRelease(fields) {
  const safe = assertB26DirectObject(fields, MESSAGE_RELEASE_FIELDS.slice(2, -1),
    'message release fields');
  const draft = { format: magic('message-release'), version: B26_VERSION, ...safe,
    releaseDigestHex: '0'.repeat(64) };
  parseMessageReleaseShape(draft);
  draft.releaseDigestHex = digestRecord('MESSAGE-RELEASE',
    MESSAGE_RELEASE_FIELDS.slice(0, -1).map((field) => draft[field]));
  return parseMessageRelease(draft);
}

function parseMessageReleaseShape(value) {
  assertGroupIdHex(value.groupIdHex);
  ['instanceKeyHex', 'stateDigestHex', 'snapshotDigestHex', 'releaseAuthorityDigestHex']
    .forEach((field) => assertHex64(field, value[field]));
  return value;
}

export function parseMessageRelease(raw) {
  const value = parseMessageReleaseShape(exact(raw, MESSAGE_RELEASE_FIELDS,
    'message-release'));
  verifyDigest(value, 'releaseDigestHex', 'MESSAGE-RELEASE',
    MESSAGE_RELEASE_FIELDS.slice(0, -1).map((field) => value[field]));
  return Object.freeze({ ...value });
}
