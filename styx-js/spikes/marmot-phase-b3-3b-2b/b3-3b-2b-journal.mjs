// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — durable bounded concurrent-fork settlement journal.

import {
  B33B1_PROVIDER_FORMAT,
  canonicalJsonBytes,
  clearBytes,
  sha256Hex,
} from '../marmot-phase-b3-3b-1/b3-3b-1-canonical.mjs';
import {
  FileB33b1Store,
} from '../marmot-phase-b3-3b-1/b3-3b-1-journal.mjs';
import {
  B33B2B_ERROR,
  B33B2B_LIMITS,
  B33B2B_STATE,
  B33b2bError,
  compareIdentityHex,
  failB33b2b,
} from './b3-3b-2b-canonical.mjs';

const HEAD_DOMAIN = 'STYX-B33B2B-JOURNAL-HEAD-v1';
const JOURNAL_ID_DOMAIN = 'STYX-B33B2B-JOURNAL-ID-v1';
const FROZEN_SET_DOMAIN = 'STYX-B33B2B-FROZEN-SET-v1';
const EFFECT_DOMAIN = 'STYX-B33B2B-SETTLEMENT-EFFECT-v1';

const HEAD_FIELDS = Object.freeze([
  'domain', 'journalIdHex', 'sequence', 'state', 'previousHeadDigestHex',
  'providerFormat', 'forkEpoch', 'groupIdDigestHex', 'rosterDigestHex',
  'canonical', 'retainedParent', 'localCandidate', 'rivalCandidate',
  'frozenSetDigestHex', 'selectedCommitSha256Hex', 'successorStateBlobSha256Hex',
  'settlement', 'unrecoverableReasonDigestHex', 'transitions', 'headDigestHex',
]);
const AUTHORITY_FIELDS = Object.freeze([
  'epoch', 'groupContextSha256Hex', 'rosterDigestHex', 'stateBlobSha256Hex',
  'commitSha256Hex',
]);
const PARENT_FIELDS = Object.freeze([
  'epoch', 'groupContextSha256Hex', 'rosterDigestHex', 'stateBlobSha256Hex',
]);
const CANDIDATE_FIELDS = Object.freeze([
  'role', 'commitBlobSha256Hex', 'authoritySha256Hex', 'projection',
]);
const PROJECTION_FIELDS = Object.freeze([
  'authoritySha256Hex', 'candidateGroupContextSha256Hex', 'commitSha256Hex',
  'committerAccountHex', 'committerLeafIndex', 'committerSignatureKeyHex', 'domain',
  'groupIdHex', 'orderingPriority', 'parentGroupContextSha256Hex',
  'parentStateSha256Hex', 'sourceEpoch', 'targetEpoch', 'verifiedLeafDigestHex',
]);
const SETTLEMENT_FIELDS = Object.freeze([
  'effectIdHex', 'effectKind', 'effectDelivered', 'recordBlobSha256Hex',
  'losingCommitSha256Hex', 'losingDisposition', 'selectionTraceDigestHex',
]);
const TRANSITION_FIELDS = Object.freeze([
  'ordinal', 'from', 'to', 'headDigestBeforeHex', 'forkEpoch',
]);
const VALID_TRANSITIONS = Object.freeze({
  [B33B2B_STATE.ACTIVATED]: Object.freeze([
    B33B2B_STATE.LOCAL_BRANCH_DURABLE, B33B2B_STATE.UNRECOVERABLE,
  ]),
  [B33B2B_STATE.LOCAL_BRANCH_DURABLE]: Object.freeze([
    B33B2B_STATE.RIVAL_RECORDED, B33B2B_STATE.UNRECOVERABLE,
  ]),
  [B33B2B_STATE.RIVAL_RECORDED]: Object.freeze([
    B33B2B_STATE.RACE_FROZEN, B33B2B_STATE.UNRECOVERABLE,
  ]),
  [B33B2B_STATE.RACE_FROZEN]: Object.freeze([
    B33B2B_STATE.SETTLEMENT_PREPARED, B33B2B_STATE.UNRECOVERABLE,
  ]),
  [B33B2B_STATE.SETTLEMENT_PREPARED]: Object.freeze([
    B33B2B_STATE.STABLE, B33B2B_STATE.UNRECOVERABLE,
  ]),
  [B33B2B_STATE.STABLE]: Object.freeze([B33B2B_STATE.STABLE]),
  [B33B2B_STATE.UNRECOVERABLE]: Object.freeze([]),
});

function isDigest(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function isOrdinaryObjectPrototype(prototype) {
  if (prototype === null || prototype === Object.prototype) return true;
  if (Object.getPrototypeOf(prototype) !== null) return false;
  const constructor = Object.getOwnPropertyDescriptor(prototype, 'constructor');
  return constructor !== undefined
    && Object.hasOwn(constructor, 'value')
    && typeof constructor.value === 'function'
    && constructor.value.name === 'Object'
    && Function.prototype.toString.call(constructor.value)
      === 'function Object() { [native code] }';
}

function exactFields(value, fields, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)
    || !isOrdinaryObjectPrototype(Object.getPrototypeOf(value))) {
    failB33b2b(B33B2B_ERROR.CORRUPT, `${label} is not a plain object`);
  }
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== 'string')) {
    failB33b2b(B33B2B_ERROR.CORRUPT, `${label} contains symbol fields`);
  }
  const actual = [...keys].sort();
  const expected = [...fields].sort();
  if (actual.length !== expected.length
    || actual.some((field, index) => field !== expected[index])) {
    failB33b2b(B33B2B_ERROR.CORRUPT, `${label} fields are not exact`);
  }
  const result = {};
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) {
      failB33b2b(B33B2B_ERROR.CORRUPT, `${label} contains an accessor`);
    }
    result[field] = descriptor.value;
  }
  return result;
}

function requireDigest(label, value, nullable = false) {
  if (nullable && value === null) return value;
  if (!isDigest(value)) {
    failB33b2b(B33B2B_ERROR.CORRUPT, `${label} is not a SHA-256 digest`);
  }
  return value;
}

function requireHex(label, value, bytes = undefined) {
  if (typeof value !== 'string' || value.length === 0 || value.length % 2 !== 0
    || !/^[0-9a-f]+$/.test(value) || (bytes !== undefined && value.length !== bytes * 2)) {
    failB33b2b(B33B2B_ERROR.CORRUPT, `${label} is not canonical lowercase hex`);
  }
  return value;
}

function requireEpoch(label, value) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) {
    failB33b2b(B33B2B_ERROR.CORRUPT, `${label} is not a canonical decimal epoch`);
  }
  return value;
}

function requireBytes(label, value, maximum = B33B2B_LIMITS.maxBlobBytes) {
  if (!(value instanceof Uint8Array) || value.byteLength < 1 || value.byteLength > maximum) {
    failB33b2b(B33B2B_ERROR.INVALID, `${label} is outside its byte envelope`);
  }
}

function parseAuthority(value) {
  const authority = exactFields(value, AUTHORITY_FIELDS, 'B3.3b-2b canonical authority');
  requireEpoch('canonical epoch', authority.epoch);
  requireDigest('canonical GroupContext', authority.groupContextSha256Hex);
  requireDigest('canonical roster', authority.rosterDigestHex);
  requireDigest('canonical state blob', authority.stateBlobSha256Hex);
  requireDigest('canonical Commit', authority.commitSha256Hex, true);
  return Object.freeze({ ...authority });
}

function parseParent(value) {
  const parent = exactFields(value, PARENT_FIELDS, 'B3.3b-2b retained parent');
  requireEpoch('parent epoch', parent.epoch);
  requireDigest('parent GroupContext', parent.groupContextSha256Hex);
  requireDigest('parent roster', parent.rosterDigestHex);
  requireDigest('parent state blob', parent.stateBlobSha256Hex);
  return Object.freeze({ ...parent });
}

function parseProjection(value) {
  const projection = exactFields(value, PROJECTION_FIELDS, 'B3.3b-2b projection');
  requireDigest('projection authority', projection.authoritySha256Hex);
  requireDigest('candidate GroupContext', projection.candidateGroupContextSha256Hex);
  requireDigest('candidate Commit', projection.commitSha256Hex);
  requireHex('candidate committer account', projection.committerAccountHex, 32);
  if (!Number.isSafeInteger(projection.committerLeafIndex)
    || projection.committerLeafIndex < 0) {
    failB33b2b(B33B2B_ERROR.CORRUPT, 'candidate committer leaf index is invalid');
  }
  requireHex('candidate committer signature key', projection.committerSignatureKeyHex, 32);
  if (projection.domain !== 'STYX-B33B1-COMMIT-PROJECTION-v1'
    || projection.orderingPriority !== 'ordinary') {
    failB33b2b(B33B2B_ERROR.CORRUPT, 'candidate profile or priority drifted');
  }
  requireHex('candidate group id', projection.groupIdHex);
  requireDigest('candidate parent GroupContext', projection.parentGroupContextSha256Hex);
  requireDigest('candidate parent state', projection.parentStateSha256Hex);
  requireEpoch('candidate source epoch', projection.sourceEpoch);
  requireEpoch('candidate target epoch', projection.targetEpoch);
  if (BigInt(projection.targetEpoch) !== BigInt(projection.sourceEpoch) + 1n) {
    failB33b2b(B33B2B_ERROR.CORRUPT, 'candidate is not exactly depth one');
  }
  requireDigest('candidate verified leaf', projection.verifiedLeafDigestHex);
  return Object.freeze({ ...projection });
}

function parseCandidate(value, expectedRole = undefined) {
  if (value === null) return null;
  const candidate = exactFields(value, CANDIDATE_FIELDS, 'B3.3b-2b candidate');
  if (!['LOCAL', 'RIVAL'].includes(candidate.role)
    || (expectedRole !== undefined && candidate.role !== expectedRole)) {
    failB33b2b(B33B2B_ERROR.CORRUPT, 'candidate role is invalid');
  }
  requireDigest('candidate Commit blob', candidate.commitBlobSha256Hex);
  requireDigest('candidate authority', candidate.authoritySha256Hex);
  const projection = parseProjection(candidate.projection);
  if (candidate.commitBlobSha256Hex !== projection.commitSha256Hex
    || candidate.authoritySha256Hex !== projection.authoritySha256Hex) {
    failB33b2b(B33B2B_ERROR.CORRUPT, 'candidate content bindings disagree');
  }
  return Object.freeze({ ...candidate, projection });
}

function parseSettlement(value) {
  if (value === null) return null;
  const settlement = exactFields(value, SETTLEMENT_FIELDS, 'B3.3b-2b settlement');
  requireDigest('settlement effect id', settlement.effectIdHex);
  if (!['canonical-selected', 'local-branch-superseded'].includes(settlement.effectKind)
    || typeof settlement.effectDelivered !== 'boolean') {
    failB33b2b(B33B2B_ERROR.CORRUPT, 'settlement effect fields are invalid');
  }
  requireDigest('settlement record blob', settlement.recordBlobSha256Hex);
  requireDigest('losing Commit', settlement.losingCommitSha256Hex);
  if (settlement.losingDisposition !== 'deferred') {
    failB33b2b(B33B2B_ERROR.CORRUPT, 'losing Commit disposition is not deferred');
  }
  requireDigest('selection trace', settlement.selectionTraceDigestHex);
  return Object.freeze({ ...settlement });
}

function transition(from, to, previousHead, forkEpoch, ordinal) {
  return Object.freeze({
    ordinal,
    from,
    to,
    headDigestBeforeHex: previousHead,
    forkEpoch,
  });
}

function parseTransition(value, ordinal) {
  const item = exactFields(value, TRANSITION_FIELDS, 'B3.3b-2b transition');
  if (item.ordinal !== ordinal
    || !Object.values(B33B2B_STATE).includes(item.from)
    || !Object.values(B33B2B_STATE).includes(item.to)) {
    failB33b2b(B33B2B_ERROR.CORRUPT, 'transition discriminator is invalid');
  }
  requireDigest('transition prior head', item.headDigestBeforeHex);
  requireEpoch('transition fork epoch', item.forkEpoch);
  return Object.freeze({ ...item });
}

function payload(head) {
  const { headDigestHex: ignored, ...value } = head;
  return value;
}

function buildHead(fields) {
  const source = { domain: HEAD_DOMAIN, ...fields };
  const value = Object.fromEntries(
    HEAD_FIELDS.filter((field) => field !== 'headDigestHex')
      .map((field) => [field, source[field]]),
  );
  return Object.freeze({ ...value, headDigestHex: sha256Hex(canonicalJsonBytes(value)) });
}

function candidateSetDigest(localCandidate, rivalCandidate, forkEpoch) {
  const ordered = [localCandidate, rivalCandidate]
    .sort((left, right) => left.projection.commitSha256Hex
      .localeCompare(right.projection.commitSha256Hex))
    .map((candidate) => ({
      authoritySha256Hex: candidate.authoritySha256Hex,
      commitSha256Hex: candidate.projection.commitSha256Hex,
      committerAccountHex: candidate.projection.committerAccountHex,
      priority: candidate.projection.orderingPriority,
      sourceEpoch: candidate.projection.sourceEpoch,
      targetEpoch: candidate.projection.targetEpoch,
    }));
  return sha256Hex(canonicalJsonBytes({ domain: FROZEN_SET_DOMAIN, forkEpoch, ordered }));
}

function expectedWinner(localCandidate, rivalCandidate) {
  return compareIdentityHex(
    localCandidate.projection.committerAccountHex,
    rivalCandidate.projection.committerAccountHex,
  ) < 0 ? localCandidate : rivalCandidate;
}

export function parseB33b2bHead(value) {
  const head = exactFields(value, HEAD_FIELDS, 'B3.3b-2b journal head');
  if (head.domain !== HEAD_DOMAIN || head.providerFormat !== B33B1_PROVIDER_FORMAT
    || !Object.values(B33B2B_STATE).includes(head.state)
    || !Number.isSafeInteger(head.sequence) || head.sequence < 1) {
    failB33b2b(B33B2B_ERROR.CORRUPT, 'journal head discriminator is invalid');
  }
  requireDigest('journal id', head.journalIdHex);
  requireDigest('previous head', head.previousHeadDigestHex, true);
  requireEpoch('fork epoch', head.forkEpoch);
  requireDigest('group id digest', head.groupIdDigestHex);
  requireDigest('roster digest', head.rosterDigestHex);
  const canonical = parseAuthority(head.canonical);
  const retainedParent = parseParent(head.retainedParent);
  const localCandidate = parseCandidate(head.localCandidate, 'LOCAL');
  const rivalCandidate = parseCandidate(head.rivalCandidate, 'RIVAL');
  requireDigest('frozen candidate set', head.frozenSetDigestHex, true);
  requireDigest('selected Commit', head.selectedCommitSha256Hex, true);
  requireDigest('successor state blob', head.successorStateBlobSha256Hex, true);
  const settlement = parseSettlement(head.settlement);
  requireDigest('unrecoverable reason', head.unrecoverableReasonDigestHex, true);
  if (!Array.isArray(head.transitions) || head.transitions.length > B33B2B_LIMITS.maxTransitions) {
    failB33b2b(B33B2B_ERROR.CORRUPT, 'transition history exceeds its bound');
  }
  const transitions = head.transitions.map((item, index) => parseTransition(item, index + 1));
  const expectedSequence = transitions.length + 1;
  if (head.sequence !== expectedSequence
    || retainedParent.epoch !== head.forkEpoch
    || retainedParent.rosterDigestHex !== head.rosterDigestHex
    || BigInt(canonical.epoch) < BigInt(head.forkEpoch)
    || (localCandidate !== null && localCandidate.projection.sourceEpoch !== head.forkEpoch)
    || (rivalCandidate !== null && rivalCandidate.projection.sourceEpoch !== head.forkEpoch)) {
    failB33b2b(B33B2B_ERROR.CORRUPT, 'journal epoch, sequence or authority bindings disagree');
  }
  let priorState = B33B2B_STATE.ACTIVATED;
  for (const item of transitions) {
    if (item.from !== priorState || item.forkEpoch !== head.forkEpoch
      || !VALID_TRANSITIONS[item.from]?.includes(item.to)) {
      failB33b2b(B33B2B_ERROR.CORRUPT,
        'journal transition history is not a valid append-only state path');
    }
    priorState = item.to;
  }
  if ((transitions.length === 0 && (head.state !== B33B2B_STATE.ACTIVATED
      || head.previousHeadDigestHex !== null))
    || (transitions.length > 0 && (priorState !== head.state
      || transitions.at(-1).headDigestBeforeHex !== head.previousHeadDigestHex))) {
    failB33b2b(B33B2B_ERROR.CORRUPT,
      'journal head is not bound to the end of its transition history');
  }
  const phaseRequirements = Object.freeze({
    [B33B2B_STATE.ACTIVATED]: [false, false, false, false],
    [B33B2B_STATE.LOCAL_BRANCH_DURABLE]: [true, false, false, false],
    [B33B2B_STATE.RIVAL_RECORDED]: [true, true, false, false],
    [B33B2B_STATE.RACE_FROZEN]: [true, true, true, false],
    [B33B2B_STATE.SETTLEMENT_PREPARED]: [true, true, true, true],
    [B33B2B_STATE.STABLE]: [true, true, true, true],
  });
  const [requireLocal, requireRival, requireFrozen, requireSettlement] =
    phaseRequirements[head.state] ?? [
      localCandidate !== null,
      rivalCandidate !== null,
      head.frozenSetDigestHex !== null,
      false,
    ];
  if ((requireLocal && localCandidate === null) || (!requireLocal && localCandidate !== null)
    || (requireRival && rivalCandidate === null) || (!requireRival && rivalCandidate !== null)
    || (requireFrozen !== (head.frozenSetDigestHex !== null))
    || (requireSettlement !== (head.selectedCommitSha256Hex !== null
      && head.successorStateBlobSha256Hex !== null && settlement !== null))) {
    failB33b2b(B33B2B_ERROR.CORRUPT, 'journal phase and durable records disagree');
  }
  if (head.state === B33B2B_STATE.UNRECOVERABLE
    && (head.selectedCommitSha256Hex !== null
      || head.successorStateBlobSha256Hex !== null || settlement !== null)) {
    failB33b2b(B33B2B_ERROR.CORRUPT,
      'unrecoverable head retained a success settlement');
  }
  if ((head.state === B33B2B_STATE.UNRECOVERABLE)
    !== (head.unrecoverableReasonDigestHex !== null)) {
    failB33b2b(B33B2B_ERROR.CORRUPT,
      'unrecoverable state and reason digest disagree');
  }
  if (requireFrozen
    && head.frozenSetDigestHex !== candidateSetDigest(localCandidate, rivalCandidate, head.forkEpoch)) {
    failB33b2b(B33B2B_ERROR.CORRUPT, 'frozen candidate set digest is invalid');
  }
  if (requireSettlement
    && head.selectedCommitSha256Hex
      !== expectedWinner(localCandidate, rivalCandidate).projection.commitSha256Hex) {
    failB33b2b(B33B2B_ERROR.CORRUPT, 'selected Commit violates authenticated ordering');
  }
  if (head.state === B33B2B_STATE.STABLE
    && (canonical.stateBlobSha256Hex !== head.successorStateBlobSha256Hex
      || canonical.commitSha256Hex !== head.selectedCommitSha256Hex
      || canonical.epoch !== localCandidate.projection.targetEpoch)) {
    failB33b2b(B33B2B_ERROR.CORRUPT, 'stable canonical authority disagrees with settlement');
  }
  const expectedDigest = sha256Hex(canonicalJsonBytes(payload(head)));
  if (head.headDigestHex !== expectedDigest) {
    failB33b2b(B33B2B_ERROR.CORRUPT, 'journal head digest is invalid', {
      actual: head.headDigestHex,
      expected: expectedDigest,
    });
  }
  return Object.freeze({
    ...head,
    canonical,
    retainedParent,
    localCandidate,
    rivalCandidate,
    settlement,
    transitions: Object.freeze(transitions),
  });
}

function copyBytes(value) { return Uint8Array.from(value); }

export class MemoryB33b2bStore {
  constructor() {
    this.head = null;
    this.blobs = new Map();
    this.beforeWrite = null;
    this.writeOrdinal = 0;
  }

  async readHead() {
    return this.head === null ? null : structuredClone(this.head);
  }

  async readBlob(digest) {
    const value = this.blobs.get(digest);
    return value === undefined ? null : copyBytes(value);
  }

  async compareAndSwap(expectedDigest, nextHead, blobs) {
    if ((this.head?.headDigestHex ?? null) !== expectedDigest) return false;
    for (const blob of blobs) {
      this.writeOrdinal += 1;
      await this.beforeWrite?.({
        kind: 'blob', ordinal: this.writeOrdinal, digest: sha256Hex(blob),
      });
      this.blobs.set(sha256Hex(blob), copyBytes(blob));
    }
    this.writeOrdinal += 1;
    await this.beforeWrite?.({
      kind: 'head', ordinal: this.writeOrdinal, digest: nextHead.headDigestHex,
    });
    if ((this.head?.headDigestHex ?? null) !== expectedDigest) return false;
    this.head = structuredClone(nextHead);
    return true;
  }
}

export class B33b2bJournal {
  constructor(store) {
    if (!store || typeof store.readHead !== 'function' || typeof store.readBlob !== 'function'
      || typeof store.compareAndSwap !== 'function') {
      failB33b2b(B33B2B_ERROR.INVALID, 'journal store lacks the closed CAS interface');
    }
    this.store = store;
  }

  async #head(required = true) {
    try {
      const value = await this.store.readHead();
      if (value === null && required) {
        failB33b2b(B33B2B_ERROR.STATE_CONFLICT, 'B3.3b-2b journal is not active');
      }
      return value === null ? null : parseB33b2bHead(value);
    } catch (error) {
      if (error instanceof B33b2bError) throw error;
      failB33b2b(B33B2B_ERROR.PERSISTENCE_FAILED, 'journal head read failed', {
        cause: error instanceof Error ? error.message : `${error}`,
      });
    }
  }

  async #blob(digest, label, maximum = B33B2B_LIMITS.maxBlobBytes) {
    let value;
    try { value = await this.store.readBlob(digest); } catch (error) {
      failB33b2b(B33B2B_ERROR.PERSISTENCE_FAILED, `${label} read failed`, {
        cause: error instanceof Error ? error.message : `${error}`,
      });
    }
    if (!(value instanceof Uint8Array) || value.byteLength < 1
      || value.byteLength > maximum || sha256Hex(value) !== digest) {
      clearBytes(value);
      failB33b2b(B33B2B_ERROR.CORRUPT, `${label} is absent, oversized or corrupt`);
    }
    return value;
  }

  async #cas(expected, fields, blobs, initialization = false) {
    const nextTransition = expected === null ? [] : [
      ...expected.transitions,
      transition(expected.state, fields.state, expected.headDigestHex,
        expected.forkEpoch, expected.transitions.length + 1),
    ];
    if (nextTransition.length > B33B2B_LIMITS.maxTransitions) {
      failB33b2b(B33B2B_ERROR.RESOURCE_LIMIT, 'journal transition bound exhausted');
    }
    const next = buildHead({
      ...fields,
      sequence: nextTransition.length + 1,
      previousHeadDigestHex: expected?.headDigestHex ?? null,
      transitions: nextTransition,
    });
    try {
      const changed = await this.store.compareAndSwap(
        expected?.headDigestHex ?? null, next, blobs,
      );
      if (!changed) {
        failB33b2b(
          initialization ? B33B2B_ERROR.DUPLICATE_INITIALIZATION : B33B2B_ERROR.CAS_CONFLICT,
          initialization ? 'journal was already initialized' : 'journal CAS lost',
        );
      }
    } catch (error) {
      if (error instanceof B33b2bError) throw error;
      failB33b2b(B33B2B_ERROR.PERSISTENCE_FAILED, 'journal write failed closed', {
        cause: error instanceof Error ? error.message : `${error}`,
      });
    }
    return parseB33b2bHead(next);
  }

  async activate(fields) {
    requireBytes('retained parent state', fields.parentStateBytes);
    requireDigest('group id digest', fields.groupIdDigestHex);
    requireDigest('roster digest', fields.rosterDigestHex);
    requireEpoch('fork epoch', fields.forkEpoch);
    requireDigest('parent GroupContext', fields.parentGroupContextSha256Hex);
    if (await this.#head(false) !== null) {
      failB33b2b(B33B2B_ERROR.DUPLICATE_INITIALIZATION,
        'journal was already initialized');
    }
    const parentDigest = sha256Hex(fields.parentStateBytes);
    const journalIdHex = sha256Hex(canonicalJsonBytes({
      domain: JOURNAL_ID_DOMAIN,
      forkEpoch: fields.forkEpoch,
      groupIdDigestHex: fields.groupIdDigestHex,
      parentDigest,
    }));
    const authority = Object.freeze({
      epoch: fields.forkEpoch,
      groupContextSha256Hex: fields.parentGroupContextSha256Hex,
      rosterDigestHex: fields.rosterDigestHex,
      stateBlobSha256Hex: parentDigest,
      commitSha256Hex: null,
    });
    return this.#cas(null, {
      domain: HEAD_DOMAIN,
      journalIdHex,
      state: B33B2B_STATE.ACTIVATED,
      providerFormat: B33B1_PROVIDER_FORMAT,
      forkEpoch: fields.forkEpoch,
      groupIdDigestHex: fields.groupIdDigestHex,
      rosterDigestHex: fields.rosterDigestHex,
      canonical: authority,
      retainedParent: Object.freeze({
        epoch: fields.forkEpoch,
        groupContextSha256Hex: fields.parentGroupContextSha256Hex,
        rosterDigestHex: fields.rosterDigestHex,
        stateBlobSha256Hex: parentDigest,
      }),
      localCandidate: null,
      rivalCandidate: null,
      frozenSetDigestHex: null,
      selectedCommitSha256Hex: null,
      successorStateBlobSha256Hex: null,
      settlement: null,
      unrecoverableReasonDigestHex: null,
    }, [copyBytes(fields.parentStateBytes)], true);
  }

  async readHead() {
    return this.#head();
  }

  async recordLocalBranch(expectedHeadDigestHex, fields) {
    const head = await this.#head();
    if (head.headDigestHex !== expectedHeadDigestHex || head.state !== B33B2B_STATE.ACTIVATED) {
      failB33b2b(B33B2B_ERROR.CAS_CONFLICT,
        'local branch did not start from the activated parent');
    }
    requireBytes('local branch state', fields.stateBytes);
    requireBytes('local Commit', fields.commitBytes, B33B2B_LIMITS.maxCommitBytes);
    const localCandidate = parseCandidate({
      role: 'LOCAL',
      commitBlobSha256Hex: sha256Hex(fields.commitBytes),
      authoritySha256Hex: fields.authoritySha256Hex,
      projection: fields.projection,
    }, 'LOCAL');
    if (localCandidate.projection.parentStateSha256Hex
        !== head.retainedParent.stateBlobSha256Hex
      || localCandidate.projection.parentGroupContextSha256Hex
        !== head.retainedParent.groupContextSha256Hex) {
      failB33b2b(B33B2B_ERROR.STATE_CONFLICT,
        'local branch is not bound to the retained parent');
    }
    const stateDigest = sha256Hex(fields.stateBytes);
    return this.#cas(head, {
      ...payload(head),
      state: B33B2B_STATE.LOCAL_BRANCH_DURABLE,
      canonical: Object.freeze({
        epoch: localCandidate.projection.targetEpoch,
        groupContextSha256Hex: localCandidate.projection.candidateGroupContextSha256Hex,
        rosterDigestHex: head.rosterDigestHex,
        stateBlobSha256Hex: stateDigest,
        commitSha256Hex: localCandidate.projection.commitSha256Hex,
      }),
      localCandidate,
    }, [copyBytes(fields.stateBytes), copyBytes(fields.commitBytes)]);
  }

  async recordRival(expectedHeadDigestHex, fields) {
    const head = await this.#head();
    if (head.headDigestHex !== expectedHeadDigestHex
      || head.state !== B33B2B_STATE.LOCAL_BRANCH_DURABLE) {
      failB33b2b(B33B2B_ERROR.CAS_CONFLICT,
        'rival admission did not start from the durable local branch');
    }
    requireBytes('rival Commit', fields.commitBytes, B33B2B_LIMITS.maxCommitBytes);
    const rivalCandidate = parseCandidate({
      role: 'RIVAL',
      commitBlobSha256Hex: sha256Hex(fields.commitBytes),
      authoritySha256Hex: fields.authoritySha256Hex,
      projection: fields.projection,
    }, 'RIVAL');
    if (rivalCandidate.projection.parentStateSha256Hex
        !== head.retainedParent.stateBlobSha256Hex
      || rivalCandidate.projection.parentGroupContextSha256Hex
        !== head.retainedParent.groupContextSha256Hex
      || rivalCandidate.projection.groupIdHex !== head.localCandidate.projection.groupIdHex
      || rivalCandidate.projection.verifiedLeafDigestHex
        !== head.localCandidate.projection.verifiedLeafDigestHex
      || rivalCandidate.projection.commitSha256Hex
        === head.localCandidate.projection.commitSha256Hex
      || rivalCandidate.projection.committerAccountHex
        === head.localCandidate.projection.committerAccountHex) {
      failB33b2b(B33B2B_ERROR.STATE_CONFLICT,
        'rival is not the distinct authenticated same-parent candidate');
    }
    return this.#cas(head, {
      ...payload(head),
      state: B33B2B_STATE.RIVAL_RECORDED,
      rivalCandidate,
    }, [copyBytes(fields.commitBytes)]);
  }

  async freezeRace(expectedHeadDigestHex) {
    const head = await this.#head();
    if (head.headDigestHex !== expectedHeadDigestHex
      || head.state !== B33B2B_STATE.RIVAL_RECORDED) {
      failB33b2b(B33B2B_ERROR.CAS_CONFLICT,
        'race freeze did not bind the two-candidate head');
    }
    return this.#cas(head, {
      ...payload(head),
      state: B33B2B_STATE.RACE_FROZEN,
      frozenSetDigestHex: candidateSetDigest(
        head.localCandidate, head.rivalCandidate, head.forkEpoch,
      ),
    }, []);
  }

  async prepareSettlement(expectedHeadDigestHex, fields) {
    const head = await this.#head();
    if (head.headDigestHex !== expectedHeadDigestHex
      || head.state !== B33B2B_STATE.RACE_FROZEN) {
      failB33b2b(B33B2B_ERROR.CAS_CONFLICT,
        'settlement preparation did not bind the frozen race');
    }
    requireBytes('winning successor state', fields.successorStateBytes);
    requireBytes('settlement record', fields.settlementRecordBytes,
      B33B2B_LIMITS.maxCommitBytes);
    requireDigest('selection trace', fields.selectionTraceDigestHex);
    const winner = expectedWinner(head.localCandidate, head.rivalCandidate);
    const loser = winner.role === 'LOCAL' ? head.rivalCandidate : head.localCandidate;
    if (fields.selectedCommitSha256Hex !== winner.projection.commitSha256Hex
      || fields.selectedGroupContextSha256Hex
        !== winner.projection.candidateGroupContextSha256Hex
      || fields.losingCommitSha256Hex !== loser.projection.commitSha256Hex
      || fields.losingDisposition !== 'deferred') {
      failB33b2b(B33B2B_ERROR.STATE_CONFLICT,
        'settlement does not match authenticated candidate ordering');
    }
    const successorDigest = sha256Hex(fields.successorStateBytes);
    const recordDigest = sha256Hex(fields.settlementRecordBytes);
    const effectKind = winner.role === 'LOCAL'
      ? 'canonical-selected' : 'local-branch-superseded';
    const effectIdHex = sha256Hex(canonicalJsonBytes({
      domain: EFFECT_DOMAIN,
      journalIdHex: head.journalIdHex,
      forkEpoch: head.forkEpoch,
      frozenSetDigestHex: head.frozenSetDigestHex,
      selectedCommitSha256Hex: winner.projection.commitSha256Hex,
      effectKind,
    }));
    return this.#cas(head, {
      ...payload(head),
      state: B33B2B_STATE.SETTLEMENT_PREPARED,
      selectedCommitSha256Hex: winner.projection.commitSha256Hex,
      successorStateBlobSha256Hex: successorDigest,
      settlement: Object.freeze({
        effectIdHex,
        effectKind,
        effectDelivered: false,
        recordBlobSha256Hex: recordDigest,
        losingCommitSha256Hex: loser.projection.commitSha256Hex,
        losingDisposition: 'deferred',
        selectionTraceDigestHex: fields.selectionTraceDigestHex,
      }),
      unrecoverableReasonDigestHex: null,
    }, [copyBytes(fields.successorStateBytes), copyBytes(fields.settlementRecordBytes)]);
  }

  async commitStable(expectedHeadDigestHex) {
    const head = await this.#head();
    if (head.headDigestHex !== expectedHeadDigestHex
      || head.state !== B33B2B_STATE.SETTLEMENT_PREPARED) {
      failB33b2b(B33B2B_ERROR.CAS_CONFLICT,
        'stable head switch did not bind prepared settlement');
    }
    const winner = expectedWinner(head.localCandidate, head.rivalCandidate);
    return this.#cas(head, {
      ...payload(head),
      state: B33B2B_STATE.STABLE,
      canonical: Object.freeze({
        epoch: winner.projection.targetEpoch,
        groupContextSha256Hex: winner.projection.candidateGroupContextSha256Hex,
        rosterDigestHex: head.rosterDigestHex,
        stateBlobSha256Hex: head.successorStateBlobSha256Hex,
        commitSha256Hex: winner.projection.commitSha256Hex,
      }),
    }, []);
  }

  async markEffectDelivered(expectedHeadDigestHex, effectIdHex) {
    const head = await this.#head();
    if (head.headDigestHex !== expectedHeadDigestHex || head.state !== B33B2B_STATE.STABLE
      || head.settlement.effectIdHex !== effectIdHex || head.settlement.effectDelivered) {
      failB33b2b(B33B2B_ERROR.CAS_CONFLICT,
        'effect acknowledgement did not bind one pending stable effect');
    }
    return this.#cas(head, {
      ...payload(head),
      state: B33B2B_STATE.STABLE,
      settlement: Object.freeze({ ...head.settlement, effectDelivered: true }),
    }, []);
  }

  async readRecovery() {
    const head = await this.#head();
    const canonicalStateBytes = await this.#blob(
      head.canonical.stateBlobSha256Hex, 'canonical state',
    );
    const parentStateBytes = await this.#blob(
      head.retainedParent.stateBlobSha256Hex, 'retained parent state',
    );
    const result = { head, canonicalStateBytes, parentStateBytes };
    if (head.localCandidate !== null) {
      result.localCommitBytes = await this.#blob(
        head.localCandidate.commitBlobSha256Hex, 'local Commit',
        B33B2B_LIMITS.maxCommitBytes,
      );
    }
    if (head.rivalCandidate !== null) {
      result.rivalCommitBytes = await this.#blob(
        head.rivalCandidate.commitBlobSha256Hex, 'rival Commit',
        B33B2B_LIMITS.maxCommitBytes,
      );
    }
    if (head.successorStateBlobSha256Hex !== null) {
      result.successorStateBytes = await this.#blob(
        head.successorStateBlobSha256Hex, 'winning successor state',
      );
      result.settlementRecordBytes = await this.#blob(
        head.settlement.recordBlobSha256Hex, 'settlement record',
        B33B2B_LIMITS.maxCommitBytes,
      );
    }
    return Object.freeze(result);
  }

  async markUnrecoverable(expectedHeadDigestHex, reasonDigestHex) {
    const head = await this.#head();
    if (head.headDigestHex !== expectedHeadDigestHex
      || head.state === B33B2B_STATE.STABLE
      || head.state === B33B2B_STATE.UNRECOVERABLE) {
      failB33b2b(B33B2B_ERROR.CAS_CONFLICT,
        'unrecoverable transition did not bind a recoverable head');
    }
    requireDigest('unrecoverable reason', reasonDigestHex);
    return this.#cas(head, {
      ...payload(head),
      state: B33B2B_STATE.UNRECOVERABLE,
      settlement: null,
      selectedCommitSha256Hex: null,
      successorStateBlobSha256Hex: null,
      unrecoverableReasonDigestHex: reasonDigestHex,
    }, []);
  }
}

export function memoryB33b2bJournal() {
  return new B33b2bJournal(new MemoryB33b2bStore());
}

export function openB33b2bFileJournal(directory, approvedRoot) {
  return new B33b2bJournal(new FileB33b1Store(directory, approvedRoot));
}
