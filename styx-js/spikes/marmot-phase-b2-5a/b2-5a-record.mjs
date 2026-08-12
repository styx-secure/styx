// STYX_SPIKE_PROTOTYPE — strict durable record codec for Phase B2.5a.

import { canonicalProjectionBytes } from '../marmot-phase-b2-3/b2-3-record.mjs';
import {
  B25_BATCH_STATE,
  B25_CANDIDATE_STATE,
  B25_DISPOSITION,
  B25_ERROR,
  B25_FORMAT,
  B25_HEAD_STATE,
  B25_LIMITS,
  B25_PROFILE,
  B25_REASON,
  B25_RUNTIME,
  B25_VERSION,
  assertB25DirectObject,
  assertB25Runtime,
  assertBytes,
  assertGroupIdHex,
  assertHex64,
  assertNullableHex64,
  assertNullableString,
  assertSafeInteger,
  assertSortedUniqueHex64,
  assertString,
  canonicalB25Bytes,
  comparisonTupleDigest,
  copyBytes,
  digestHex,
  failB25,
  parseEpochDecimal,
  protocolBatchDigest,
  validateProviderSnapshot,
} from './b2-5a-canonical.mjs';

export const HEAD_FIELDS = Object.freeze([
  'format', 'version', 'profile', 'runtime', 'groupIdHex', 'accountKeyHex',
  'signatureKeyHex', 'seq', 'state', 'epochDec', 'groupContextDigestHex',
  'snapshotDigestHex', 'priorHeadDigestHex', 'transitionDigestHex',
  'selectedCommitDigestHex', 'headDigestHex',
]);
export const RETAINED_FIELDS = Object.freeze([
  'format', 'version', 'runtime', 'groupIdHex', 'accountKeyHex', 'signatureKeyHex',
  'epochDec', 'groupContextDigestHex', 'snapshotDigestHex', 'snapshotByteLength',
  'snapshotBytes', 'retainedDigestHex',
]);
export const INPUT_FIELDS = Object.freeze([
  'format', 'version', 'groupIdHex', 'batchDigestHex', 'commitDigestHex',
  'commitByteLength', 'commitBytes', 'disposition', 'inputDigestHex',
]);
export const BATCH_FIELDS = Object.freeze([
  'format', 'version', 'groupIdHex', 'baseEpochDec', 'baseGroupContextDigestHex',
  'localBaseHeadDigestHex', 'commitDigests', 'state', 'winnerCommitDigestHex',
  'outcomes', 'protocolBatchDigestHex', 'batchRecordDigestHex',
]);
export const CANDIDATE_FIELDS = Object.freeze([
  'format', 'version', 'groupIdHex', 'batchDigestHex', 'commitDigestHex', 'state',
  'reason', 'parentEpochDec', 'parentGroupContextDigestHex', 'projectionDigestHex',
  'candidateEpochDec', 'candidateGroupContextDigestHex', 'verifiedLeafDigestHex',
  'operationKind', 'priority', 'committerIdentityHex', 'authorizationContextDigestHex',
  'authorizationResultDigestHex', 'comparisonTupleDigestHex', 'evidenceDigestHex',
]);
export const TRANSITION_FIELDS = Object.freeze([
  'format', 'version', 'runtime', 'groupIdHex', 'seq', 'kind',
  'priorHeadDigestHex', 'batchDigestHex', 'winnerCommitDigestHex',
  'snapshotDigestHex', 'epochDec', 'groupContextDigestHex', 'outcomesDigestHex',
  'transitionDigestHex',
]);
export const OUTCOME_FIELDS = Object.freeze([
  'commitDigestHex', 'disposition', 'candidateEvidenceDigestHex',
]);

const HEAD_STATES = new Set(Object.values(B25_HEAD_STATE));
const BATCH_STATES = new Set(Object.values(B25_BATCH_STATE));
const CANDIDATE_STATES = new Set(Object.values(B25_CANDIDATE_STATE));
const DISPOSITIONS = new Set(Object.values(B25_DISPOSITION));

function magic(kind) { return `${B25_FORMAT}-${kind}`; }

function assertMagic(record, kind) {
  if (record.format !== magic(kind) || record.version !== B25_VERSION) {
    failB25(B25_ERROR.INVALID, `${kind} magic or version is invalid`);
  }
}

function headValues(record) {
  return [
    record.format, record.version, record.profile, record.runtime, record.groupIdHex,
    record.accountKeyHex, record.signatureKeyHex, record.seq, record.state,
    record.epochDec, record.groupContextDigestHex, record.snapshotDigestHex,
    record.priorHeadDigestHex, record.transitionDigestHex,
    record.selectedCommitDigestHex,
  ];
}

function assertHead(record) {
  assertMagic(record, 'head');
  if (record.profile !== B25_PROFILE) failB25(B25_ERROR.INCOMPATIBLE, 'head profile differs');
  assertB25Runtime(record.runtime);
  assertGroupIdHex(record.groupIdHex);
  assertHex64('accountKeyHex', record.accountKeyHex);
  assertHex64('signatureKeyHex', record.signatureKeyHex);
  assertSafeInteger('seq', record.seq, 1);
  if (!HEAD_STATES.has(record.state)) failB25(B25_ERROR.INVALID, 'head state is invalid');
  parseEpochDecimal(record.epochDec, 'head epoch');
  assertHex64('groupContextDigestHex', record.groupContextDigestHex);
  assertHex64('snapshotDigestHex', record.snapshotDigestHex);
  assertNullableHex64('priorHeadDigestHex', record.priorHeadDigestHex);
  assertHex64('transitionDigestHex', record.transitionDigestHex);
  assertNullableHex64('selectedCommitDigestHex', record.selectedCommitDigestHex);
  if (record.state === B25_HEAD_STATE.UNRECOVERABLE
    && record.selectedCommitDigestHex !== null) {
    failB25(B25_ERROR.INVALID, 'unrecoverable head cannot select a Commit');
  }
  assertHex64('headDigestHex', record.headDigestHex);
  return record;
}

export function buildHead(fields) {
  const safe = assertB25DirectObject(fields, [
    'groupIdHex', 'accountKeyHex', 'signatureKeyHex', 'seq', 'state', 'epochDec',
    'groupContextDigestHex', 'snapshotDigestHex', 'priorHeadDigestHex',
    'transitionDigestHex', 'selectedCommitDigestHex',
  ], 'B2.5a head fields');
  const draft = {
    format: magic('head'), version: B25_VERSION, profile: B25_PROFILE,
    runtime: B25_RUNTIME, ...safe, headDigestHex: '0'.repeat(64),
  };
  assertHead(draft);
  draft.headDigestHex = digestHex(canonicalB25Bytes('HEAD', headValues(draft)));
  return Object.freeze(draft);
}

export function parseHead(raw) {
  const record = assertHead(assertB25DirectObject(raw, HEAD_FIELDS, 'B2.5a head'));
  if (digestHex(canonicalB25Bytes('HEAD', headValues(record))) !== record.headDigestHex) {
    failB25(B25_ERROR.CORRUPT, 'head digest mismatch');
  }
  return Object.freeze({ ...record, runtime: Object.freeze({ ...record.runtime }) });
}

function retainedValues(record) {
  return [record.format, record.version, record.runtime, record.groupIdHex,
    record.accountKeyHex, record.signatureKeyHex, record.epochDec,
    record.groupContextDigestHex, record.snapshotDigestHex, record.snapshotByteLength];
}

function assertRetained(record) {
  assertMagic(record, 'retained-state');
  assertB25Runtime(record.runtime);
  assertGroupIdHex(record.groupIdHex);
  assertHex64('accountKeyHex', record.accountKeyHex);
  assertHex64('signatureKeyHex', record.signatureKeyHex);
  parseEpochDecimal(record.epochDec, 'retained epoch');
  assertHex64('groupContextDigestHex', record.groupContextDigestHex);
  assertHex64('snapshotDigestHex', record.snapshotDigestHex);
  assertSafeInteger('snapshotByteLength', record.snapshotByteLength, 8, B25_LIMITS.maxSnapshotBytes);
  assertBytes('snapshotBytes', record.snapshotBytes, { min: 8, max: B25_LIMITS.maxSnapshotBytes });
  validateProviderSnapshot(record.snapshotBytes);
  if (record.snapshotBytes.length !== record.snapshotByteLength
    || digestHex(record.snapshotBytes) !== record.snapshotDigestHex) {
    failB25(B25_ERROR.CORRUPT, 'retained snapshot binding mismatch');
  }
  assertHex64('retainedDigestHex', record.retainedDigestHex);
  return record;
}

export function buildRetainedState(fields) {
  const safe = assertB25DirectObject(fields, [
    'groupIdHex', 'accountKeyHex', 'signatureKeyHex', 'epochDec',
    'groupContextDigestHex', 'snapshotBytes',
  ], 'retained-state fields');
  const snapshotBytes = copyBytes(safe.snapshotBytes);
  const draft = {
    format: magic('retained-state'), version: B25_VERSION, runtime: B25_RUNTIME,
    groupIdHex: safe.groupIdHex, accountKeyHex: safe.accountKeyHex,
    signatureKeyHex: safe.signatureKeyHex, epochDec: safe.epochDec,
    groupContextDigestHex: safe.groupContextDigestHex,
    snapshotDigestHex: digestHex(snapshotBytes), snapshotByteLength: snapshotBytes.length,
    snapshotBytes, retainedDigestHex: '0'.repeat(64),
  };
  assertRetained(draft);
  draft.retainedDigestHex = digestHex(canonicalB25Bytes('RETAINED-STATE', retainedValues(draft)));
  return Object.freeze(draft);
}

export function parseRetainedState(raw) {
  const record = assertRetained(assertB25DirectObject(raw, RETAINED_FIELDS, 'retained state'));
  if (digestHex(canonicalB25Bytes('RETAINED-STATE', retainedValues(record)))
      !== record.retainedDigestHex) failB25(B25_ERROR.CORRUPT, 'retained-state digest mismatch');
  return Object.freeze({ ...record, runtime: Object.freeze({ ...record.runtime }),
    snapshotBytes: copyBytes(record.snapshotBytes) });
}

function inputValues(record) {
  return [record.format, record.version, record.groupIdHex, record.batchDigestHex,
    record.commitDigestHex, record.commitByteLength, record.disposition];
}

function assertInput(record) {
  assertMagic(record, 'input');
  assertGroupIdHex(record.groupIdHex);
  assertNullableHex64('batchDigestHex', record.batchDigestHex);
  assertHex64('commitDigestHex', record.commitDigestHex);
  assertSafeInteger('commitByteLength', record.commitByteLength, 1, B25_LIMITS.maxCommitBytes);
  assertBytes('commitBytes', record.commitBytes, { min: 1, max: B25_LIMITS.maxCommitBytes });
  if (record.commitBytes.length !== record.commitByteLength
    || digestHex(record.commitBytes) !== record.commitDigestHex) {
    failB25(B25_ERROR.CORRUPT, 'input Commit binding mismatch');
  }
  if (!DISPOSITIONS.has(record.disposition)) failB25(B25_ERROR.INVALID, 'input disposition is invalid');
  if ((record.batchDigestHex === null) !== (record.disposition === B25_DISPOSITION.COLLECTED)) {
    failB25(B25_ERROR.INVALID, 'input batch/disposition binding is invalid');
  }
  assertHex64('inputDigestHex', record.inputDigestHex);
  return record;
}

export function buildInput({ groupIdHex, batchDigestHex = null, commitBytes,
  disposition = B25_DISPOSITION.COLLECTED }) {
  const exact = copyBytes(commitBytes);
  const draft = {
    format: magic('input'), version: B25_VERSION, groupIdHex, batchDigestHex,
    commitDigestHex: digestHex(exact), commitByteLength: exact.length,
    commitBytes: exact, disposition, inputDigestHex: '0'.repeat(64),
  };
  assertInput(draft);
  draft.inputDigestHex = digestHex(canonicalB25Bytes('INPUT', inputValues(draft)));
  return Object.freeze(draft);
}

export function parseInput(raw) {
  const record = assertInput(assertB25DirectObject(raw, INPUT_FIELDS, 'B2.5a input'));
  if (digestHex(canonicalB25Bytes('INPUT', inputValues(record))) !== record.inputDigestHex) {
    failB25(B25_ERROR.CORRUPT, 'input digest mismatch');
  }
  return Object.freeze({ ...record, commitBytes: copyBytes(record.commitBytes) });
}

export function buildOutcome(fields) {
  const safe = assertB25DirectObject(fields, OUTCOME_FIELDS, 'batch outcome');
  assertHex64('commitDigestHex', safe.commitDigestHex);
  if (!DISPOSITIONS.has(safe.disposition)
    || safe.disposition === B25_DISPOSITION.FROZEN
    || safe.disposition === B25_DISPOSITION.COLLECTED) {
    failB25(B25_ERROR.INVALID, 'resolved outcome disposition is invalid');
  }
  assertHex64('candidateEvidenceDigestHex', safe.candidateEvidenceDigestHex);
  return Object.freeze({ ...safe });
}

function normalizeOutcomes(value, state, commitDigests) {
  if (!Array.isArray(value)) failB25(B25_ERROR.INVALID, 'batch outcomes must be an array');
  if (state === B25_BATCH_STATE.FROZEN && value.length !== 0) {
    failB25(B25_ERROR.INVALID, 'frozen batch contains outcomes');
  }
  if (state === B25_BATCH_STATE.RESOLVED && value.length !== commitDigests.length) {
    failB25(B25_ERROR.INVALID, 'resolved batch outcome count differs from inputs');
  }
  const outcomes = value.map(buildOutcome);
  for (let index = 0; index < outcomes.length; index += 1) {
    if (outcomes[index].commitDigestHex !== commitDigests[index]) {
      failB25(B25_ERROR.INVALID, 'batch outcomes are not aligned with sorted inputs');
    }
  }
  return Object.freeze(outcomes);
}

function batchValues(record) {
  return [record.format, record.version, record.groupIdHex, record.baseEpochDec,
    record.baseGroupContextDigestHex, record.localBaseHeadDigestHex,
    record.commitDigests, record.state, record.winnerCommitDigestHex,
    record.outcomes.map((item) => [item.commitDigestHex, item.disposition,
      item.candidateEvidenceDigestHex]), record.protocolBatchDigestHex];
}

function assertBatch(record) {
  assertMagic(record, 'batch');
  assertGroupIdHex(record.groupIdHex);
  parseEpochDecimal(record.baseEpochDec, 'batch base epoch');
  assertHex64('baseGroupContextDigestHex', record.baseGroupContextDigestHex);
  assertHex64('localBaseHeadDigestHex', record.localBaseHeadDigestHex);
  record.commitDigests = assertSortedUniqueHex64('commitDigests', record.commitDigests, { min: 1 });
  if (!BATCH_STATES.has(record.state)) failB25(B25_ERROR.INVALID, 'batch state is invalid');
  assertNullableHex64('winnerCommitDigestHex', record.winnerCommitDigestHex);
  record.outcomes = normalizeOutcomes(record.outcomes, record.state, record.commitDigests);
  assertHex64('protocolBatchDigestHex', record.protocolBatchDigestHex);
  const protocolDigest = protocolBatchDigest({
    groupIdHex: record.groupIdHex, baseEpochDec: record.baseEpochDec,
    baseGroupContextDigestHex: record.baseGroupContextDigestHex,
    commitDigests: record.commitDigests,
  });
  if (protocolDigest !== record.protocolBatchDigestHex) {
    failB25(B25_ERROR.CORRUPT, 'protocol batch digest mismatch');
  }
  if (record.state === B25_BATCH_STATE.FROZEN && record.winnerCommitDigestHex !== null) {
    failB25(B25_ERROR.INVALID, 'frozen batch has a winner');
  }
  if (record.winnerCommitDigestHex !== null
    && !record.commitDigests.includes(record.winnerCommitDigestHex)) {
    failB25(B25_ERROR.INVALID, 'batch winner is not an input');
  }
  assertHex64('batchRecordDigestHex', record.batchRecordDigestHex);
  return record;
}

export function buildBatch(fields) {
  const safe = assertB25DirectObject(fields, [
    'groupIdHex', 'baseEpochDec', 'baseGroupContextDigestHex',
    'localBaseHeadDigestHex', 'commitDigests', 'state', 'winnerCommitDigestHex',
    'outcomes',
  ], 'batch fields');
  const digest = protocolBatchDigest({
    groupIdHex: safe.groupIdHex, baseEpochDec: safe.baseEpochDec,
    baseGroupContextDigestHex: safe.baseGroupContextDigestHex,
    commitDigests: safe.commitDigests,
  });
  const draft = { format: magic('batch'), version: B25_VERSION, ...safe,
    commitDigests: [...safe.commitDigests].sort(), protocolBatchDigestHex: digest,
    batchRecordDigestHex: '0'.repeat(64) };
  assertBatch(draft);
  draft.batchRecordDigestHex = digestHex(canonicalB25Bytes('BATCH', batchValues(draft)));
  return Object.freeze(draft);
}

export function parseBatch(raw) {
  const record = assertBatch(assertB25DirectObject(raw, BATCH_FIELDS, 'B2.5a batch'));
  if (digestHex(canonicalB25Bytes('BATCH', batchValues(record))) !== record.batchRecordDigestHex) {
    failB25(B25_ERROR.CORRUPT, 'batch record digest mismatch');
  }
  return Object.freeze({ ...record, commitDigests: Object.freeze([...record.commitDigests]),
    outcomes: Object.freeze(record.outcomes.map((item) => Object.freeze({ ...item }))) });
}

function candidateValues(record) {
  return CANDIDATE_FIELDS.slice(0, -1).map((field) => record[field]);
}

function assertCandidate(record) {
  assertMagic(record, 'candidate');
  assertGroupIdHex(record.groupIdHex);
  assertHex64('batchDigestHex', record.batchDigestHex);
  assertHex64('commitDigestHex', record.commitDigestHex);
  if (!CANDIDATE_STATES.has(record.state)) failB25(B25_ERROR.INVALID, 'candidate state is invalid');
  assertString('candidate reason', record.reason, { min: 1, max: 96, pattern: /^[A-Z0-9_]+$/ });
  parseEpochDecimal(record.parentEpochDec, 'candidate parent epoch');
  assertHex64('parentGroupContextDigestHex', record.parentGroupContextDigestHex);
  for (const [name, value] of [
    ['projectionDigestHex', record.projectionDigestHex],
    ['candidateGroupContextDigestHex', record.candidateGroupContextDigestHex],
    ['verifiedLeafDigestHex', record.verifiedLeafDigestHex],
    ['committerIdentityHex', record.committerIdentityHex],
    ['authorizationContextDigestHex', record.authorizationContextDigestHex],
    ['authorizationResultDigestHex', record.authorizationResultDigestHex],
    ['comparisonTupleDigestHex', record.comparisonTupleDigestHex],
  ]) assertNullableHex64(name, value);
  if (record.candidateEpochDec !== null) parseEpochDecimal(record.candidateEpochDec, 'candidate epoch');
  assertNullableString('operationKind', record.operationKind, { min: 1, max: 32, pattern: /^[a-z-]+$/ });
  if (record.priority !== null) assertSafeInteger('priority', record.priority, 0, 1);
  if (record.state === B25_CANDIDATE_STATE.PENDING) {
    for (const field of CANDIDATE_FIELDS.slice(9, -1)) {
      if (record[field] !== null) failB25(B25_ERROR.INVALID, 'pending evidence contains a decision field');
    }
    if (record.reason !== B25_REASON.PENDING) {
      failB25(B25_ERROR.INVALID, 'pending evidence has a terminal reason');
    }
  } else if (record.state === B25_CANDIDATE_STATE.NOT_CANDIDATE) {
    for (const field of CANDIDATE_FIELDS.slice(9, -1)) {
      if (record[field] !== null) {
        failB25(B25_ERROR.INVALID, 'non-candidate evidence contains a projected decision field');
      }
    }
    if (record.reason !== B25_REASON.NOT_CANDIDATE_FOR_RETAINED_PARENT) {
      failB25(B25_ERROR.INVALID, 'non-candidate evidence has an invalid reason');
    }
  } else if (record.state === B25_CANDIDATE_STATE.REJECTED) {
    for (const field of [
      'projectionDigestHex', 'candidateEpochDec', 'candidateGroupContextDigestHex',
      'verifiedLeafDigestHex', 'operationKind', 'authorizationContextDigestHex',
      'authorizationResultDigestHex',
    ]) {
      if (record[field] === null) failB25(B25_ERROR.INVALID, 'rejected evidence lacks policy binding');
    }
    for (const field of ['priority', 'committerIdentityHex', 'comparisonTupleDigestHex']) {
      if (record[field] !== null) failB25(B25_ERROR.INVALID, 'rejected evidence contains ordering authority');
    }
  } else if (record.state === B25_CANDIDATE_STATE.AUTHORIZED) {
    for (const field of CANDIDATE_FIELDS.slice(9, -1)) {
      if (record[field] === null) failB25(B25_ERROR.INVALID, 'authorized evidence lacks a decision field');
    }
    if (comparisonTupleDigest(record) !== record.comparisonTupleDigestHex) {
      failB25(B25_ERROR.CORRUPT, 'comparison tuple digest mismatch');
    }
  }
  if (record.candidateEpochDec !== null
    && BigInt(record.candidateEpochDec) !== BigInt(record.parentEpochDec) + 1n) {
    failB25(B25_ERROR.INVALID, 'candidate epoch is not the direct child of its retained parent');
  }
  assertHex64('evidenceDigestHex', record.evidenceDigestHex);
  return record;
}

export function buildCandidateEvidence(fields) {
  const safe = assertB25DirectObject(fields, CANDIDATE_FIELDS.filter((field) => ![
    'format', 'version', 'evidenceDigestHex',
  ].includes(field)), 'candidate evidence fields');
  const draft = { format: magic('candidate'), version: B25_VERSION, ...safe,
    evidenceDigestHex: '0'.repeat(64) };
  assertCandidate(draft);
  draft.evidenceDigestHex = digestHex(canonicalB25Bytes('CANDIDATE-EVIDENCE', candidateValues(draft)));
  return Object.freeze(draft);
}

export function buildPendingCandidate({ groupIdHex, batchDigestHex, commitDigestHex, parentEpochDec,
  parentGroupContextDigestHex }) {
  return buildCandidateEvidence({
    groupIdHex, batchDigestHex, commitDigestHex, state: B25_CANDIDATE_STATE.PENDING,
    reason: 'B25_PENDING', parentEpochDec, parentGroupContextDigestHex,
    projectionDigestHex: null, candidateEpochDec: null,
    candidateGroupContextDigestHex: null, verifiedLeafDigestHex: null,
    operationKind: null, priority: null, committerIdentityHex: null,
    authorizationContextDigestHex: null, authorizationResultDigestHex: null,
    comparisonTupleDigestHex: null,
  });
}

export function parseCandidateEvidence(raw) {
  const record = assertCandidate(assertB25DirectObject(raw, CANDIDATE_FIELDS, 'candidate evidence'));
  if (digestHex(canonicalB25Bytes('CANDIDATE-EVIDENCE', candidateValues(record)))
      !== record.evidenceDigestHex) failB25(B25_ERROR.CORRUPT, 'candidate evidence digest mismatch');
  return Object.freeze({ ...record });
}

export function projectionDigestHex(projection) {
  return digestHex(canonicalProjectionBytes(projection));
}

function transitionValues(record) {
  return TRANSITION_FIELDS.slice(0, -1).map((field) => record[field]);
}

function assertTransition(record) {
  assertMagic(record, 'transition');
  assertB25Runtime(record.runtime);
  assertGroupIdHex(record.groupIdHex);
  assertSafeInteger('transition seq', record.seq, 1);
  if (!['INITIALIZE', 'RESOLVE', 'UNRECOVERABLE'].includes(record.kind)) {
    failB25(B25_ERROR.INVALID, 'transition kind is invalid');
  }
  for (const [name, value] of [
    ['priorHeadDigestHex', record.priorHeadDigestHex], ['batchDigestHex', record.batchDigestHex],
    ['winnerCommitDigestHex', record.winnerCommitDigestHex], ['outcomesDigestHex', record.outcomesDigestHex],
  ]) assertNullableHex64(name, value);
  assertHex64('snapshotDigestHex', record.snapshotDigestHex);
  parseEpochDecimal(record.epochDec, 'transition epoch');
  assertHex64('groupContextDigestHex', record.groupContextDigestHex);
  assertHex64('transitionDigestHex', record.transitionDigestHex);
  if (record.kind === 'INITIALIZE'
    && [record.priorHeadDigestHex, record.batchDigestHex, record.winnerCommitDigestHex,
      record.outcomesDigestHex].some((value) => value !== null)) {
    failB25(B25_ERROR.INVALID, 'initial transition contains successor fields');
  }
  if (record.kind === 'RESOLVE'
    && [record.priorHeadDigestHex, record.batchDigestHex, record.winnerCommitDigestHex,
      record.outcomesDigestHex].some((value) => value === null)) {
    failB25(B25_ERROR.INVALID, 'resolution transition lacks a successor binding');
  }
  if (record.kind === 'UNRECOVERABLE'
    && (record.priorHeadDigestHex === null || record.batchDigestHex === null
      || record.winnerCommitDigestHex !== null || record.outcomesDigestHex !== null)) {
    failB25(B25_ERROR.INVALID, 'unrecoverable transition has an invalid terminal binding');
  }
  return record;
}

export function buildTransition(fields) {
  const safe = assertB25DirectObject(fields, [
    'groupIdHex', 'seq', 'kind', 'priorHeadDigestHex', 'batchDigestHex',
    'winnerCommitDigestHex', 'snapshotDigestHex', 'epochDec',
    'groupContextDigestHex', 'outcomesDigestHex',
  ], 'transition fields');
  const draft = { format: magic('transition'), version: B25_VERSION, runtime: B25_RUNTIME,
    ...safe, transitionDigestHex: '0'.repeat(64) };
  assertTransition(draft);
  draft.transitionDigestHex = digestHex(canonicalB25Bytes('TRANSITION', transitionValues(draft)));
  return Object.freeze(draft);
}

export function parseTransition(raw) {
  const record = assertTransition(assertB25DirectObject(raw, TRANSITION_FIELDS, 'B2.5a transition'));
  if (digestHex(canonicalB25Bytes('TRANSITION', transitionValues(record)))
      !== record.transitionDigestHex) failB25(B25_ERROR.CORRUPT, 'transition digest mismatch');
  return Object.freeze({ ...record, runtime: Object.freeze({ ...record.runtime }) });
}

export function outcomesDigest(outcomes) {
  return digestHex(canonicalB25Bytes('OUTCOMES', outcomes.map((item) => [
    item.commitDigestHex, item.disposition, item.candidateEvidenceDigestHex,
  ])));
}
