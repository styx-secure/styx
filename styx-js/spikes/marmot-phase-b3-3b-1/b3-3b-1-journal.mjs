// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — durable B3.3b-1 epoch-transition journal.

import {
  closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync,
  statSync, writeFileSync,
} from 'node:fs';
import { basename, dirname, resolve } from 'node:path';
import {
  B33B1_DISPOSITION,
  B33B1_ERROR,
  B33B1_LIMITS,
  B33B1_PRIVATE_ROOT,
  B33B1_PROVIDER_FORMAT,
  B33B1_RECOVERY,
  B33B1_STATE,
  B33b1Error,
  canonicalJsonBytes,
  clearBytes,
  exactFields,
  failB33b1,
  sha256Hex,
} from './b3-3b-1-canonical.mjs';

const HEAD_DOMAIN = 'STYX-B33B1-JOURNAL-HEAD-v1';
const JOURNAL_ID_DOMAIN = 'STYX-B33B1-JOURNAL-ID-v1';
const HEAD_FIELDS = Object.freeze([
  'domain', 'journalIdHex', 'sequence', 'state', 'previousHeadDigestHex',
  'sourceB32aHeadDigestHex', 'providerFormat', 'groupIdHex', 'accountIdentityHex',
  'leafSignatureKeyHex', 'epochDec', 'groupContextSha256Hex', 'rosterSha256Hex',
  'stateBlobSha256Hex', 'committedCommitSha256Hex', 'pendingLocal', 'stagedInbound',
  'applicationRecords', 'transitions', 'headDigestHex',
]);
const PROJECTION_FIELDS = Object.freeze([
  'authoritySha256Hex', 'candidateGroupContextSha256Hex', 'commitSha256Hex',
  'committerAccountHex', 'committerLeafIndex', 'committerSignatureKeyHex', 'domain',
  'groupIdHex', 'orderingPriority', 'parentGroupContextSha256Hex',
  'parentStateSha256Hex', 'sourceEpoch', 'targetEpoch', 'verifiedLeafDigestHex',
]);
const LOCAL_FIELDS = Object.freeze([
  'parentStateBlobSha256Hex', 'pendingStateBlobSha256Hex', 'commitBlobSha256Hex',
  'authoritySha256Hex', 'projection', 'peerAcceptance',
]);
const ACCEPTANCE_FIELDS = Object.freeze([
  'commitSha256Hex', 'peerGroupContextSha256Hex', 'evidenceSha256Hex',
]);
const INBOUND_FIELDS = Object.freeze([
  'parentStateBlobSha256Hex', 'commitBlobSha256Hex', 'authoritySha256Hex',
  'projection',
]);
const TRANSITION_FIELDS = Object.freeze([
  'ordinal', 'direction', 'commitSha256Hex', 'sourceEpoch', 'targetEpoch',
  'authoritySha256Hex', 'disposition',
]);
const APPLICATION_FIELDS = Object.freeze([
  'ordinal', 'direction', 'stateBlobSha256Hex', 'ciphertextBlobSha256Hex',
  'plaintextBlobSha256Hex', 'messageEpoch', 'senderLeafIndex', 'senderIdentityHex',
  'senderSignatureKeyHex',
]);

function isDigest(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function requireDigest(label, value, nullable = false) {
  if (nullable && value === null) return value;
  if (!isDigest(value)) failB33b1(B33B1_ERROR.CORRUPT, `${label} is not a SHA-256 digest`);
  return value;
}

function requireHex(label, value, bytes = undefined) {
  if (typeof value !== 'string' || value.length === 0 || value.length % 2 !== 0
    || !/^[0-9a-f]+$/.test(value) || (bytes !== undefined && value.length !== bytes * 2)) {
    failB33b1(B33B1_ERROR.CORRUPT, `${label} is not canonical lowercase hex`);
  }
  return value;
}

function requireEpoch(label, value) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) {
    failB33b1(B33B1_ERROR.CORRUPT, `${label} is not a canonical decimal epoch`);
  }
  return value;
}

function requireBytes(label, value, maximum) {
  if (!(value instanceof Uint8Array) || value.byteLength < 1 || value.byteLength > maximum) {
    failB33b1(B33B1_ERROR.INVALID, `${label} is absent or outside its byte envelope`);
  }
}

function parseProjection(value) {
  const projection = exactFields(value, PROJECTION_FIELDS, 'B3.3b-1 projection');
  requireDigest('projection authority', projection.authoritySha256Hex);
  requireDigest('candidate GroupContext', projection.candidateGroupContextSha256Hex);
  requireDigest('Commit', projection.commitSha256Hex);
  requireHex('committer account', projection.committerAccountHex, 32);
  if (!Number.isSafeInteger(projection.committerLeafIndex) || projection.committerLeafIndex < 0) {
    failB33b1(B33B1_ERROR.CORRUPT, 'committer leaf index is invalid');
  }
  requireHex('committer signature key', projection.committerSignatureKeyHex, 32);
  if (typeof projection.domain !== 'string' || projection.domain.length === 0
    || projection.domain.length > 128) {
    failB33b1(B33B1_ERROR.CORRUPT, 'projection domain is invalid');
  }
  requireHex('projection group id', projection.groupIdHex);
  if (projection.orderingPriority !== 'ordinary') {
    failB33b1(B33B1_ERROR.CORRUPT, 'self-update priority is not ordinary');
  }
  requireDigest('parent GroupContext', projection.parentGroupContextSha256Hex);
  requireDigest('parent state', projection.parentStateSha256Hex);
  requireEpoch('source epoch', projection.sourceEpoch);
  requireEpoch('target epoch', projection.targetEpoch);
  if (BigInt(projection.targetEpoch) !== BigInt(projection.sourceEpoch) + 1n) {
    failB33b1(B33B1_ERROR.CORRUPT, 'self-update does not advance exactly one epoch');
  }
  requireDigest('verified leaf', projection.verifiedLeafDigestHex);
  return Object.freeze({ ...projection });
}

function parseAcceptance(value, projection) {
  const acceptance = exactFields(value, ACCEPTANCE_FIELDS, 'peer acceptance');
  requireDigest('accepted Commit', acceptance.commitSha256Hex);
  requireDigest('peer GroupContext', acceptance.peerGroupContextSha256Hex);
  requireDigest('acceptance evidence', acceptance.evidenceSha256Hex);
  if (acceptance.commitSha256Hex !== projection.commitSha256Hex
    || acceptance.peerGroupContextSha256Hex !== projection.candidateGroupContextSha256Hex) {
    failB33b1(B33B1_ERROR.CORRUPT, 'peer acceptance is not bound to the pending Commit');
  }
  return Object.freeze({ ...acceptance });
}

function parseLocal(value, state) {
  if (value === null) return null;
  const pending = exactFields(value, LOCAL_FIELDS, 'pending local Commit');
  requireDigest('local parent state blob', pending.parentStateBlobSha256Hex);
  requireDigest('local pending state blob', pending.pendingStateBlobSha256Hex);
  requireDigest('local Commit blob', pending.commitBlobSha256Hex);
  requireDigest('local authority', pending.authoritySha256Hex);
  const projection = parseProjection(pending.projection);
  if (pending.commitBlobSha256Hex !== projection.commitSha256Hex
    || pending.parentStateBlobSha256Hex !== projection.parentStateSha256Hex
    || pending.authoritySha256Hex !== projection.authoritySha256Hex) {
    failB33b1(B33B1_ERROR.CORRUPT, 'pending local bindings disagree');
  }
  const peerAcceptance = pending.peerAcceptance === null
    ? null : parseAcceptance(pending.peerAcceptance, projection);
  if ((state === B33B1_STATE.LOCAL_PENDING && peerAcceptance !== null)
    || (state === B33B1_STATE.LOCAL_ACCEPTED && peerAcceptance === null)) {
    failB33b1(B33B1_ERROR.CORRUPT, 'local state and acceptance evidence disagree');
  }
  return Object.freeze({ ...pending, projection, peerAcceptance });
}

function parseInbound(value) {
  if (value === null) return null;
  const staged = exactFields(value, INBOUND_FIELDS, 'staged inbound Commit');
  requireDigest('inbound parent state blob', staged.parentStateBlobSha256Hex);
  requireDigest('inbound Commit blob', staged.commitBlobSha256Hex);
  requireDigest('inbound authority', staged.authoritySha256Hex);
  const projection = parseProjection(staged.projection);
  if (staged.commitBlobSha256Hex !== projection.commitSha256Hex
    || staged.parentStateBlobSha256Hex !== projection.parentStateSha256Hex
    || staged.authoritySha256Hex !== projection.authoritySha256Hex) {
    failB33b1(B33B1_ERROR.CORRUPT, 'staged inbound bindings disagree');
  }
  return Object.freeze({ ...staged, projection });
}

function parseTransition(value, ordinal) {
  const transition = exactFields(value, TRANSITION_FIELDS, 'epoch transition');
  if (transition.ordinal !== ordinal
    || !['LOCAL', 'INBOUND'].includes(transition.direction)) {
    failB33b1(B33B1_ERROR.CORRUPT, 'transition ordinal or direction is invalid');
  }
  requireDigest('transition Commit', transition.commitSha256Hex);
  requireEpoch('transition source epoch', transition.sourceEpoch);
  requireEpoch('transition target epoch', transition.targetEpoch);
  requireDigest('transition authority', transition.authoritySha256Hex);
  const expected = transition.direction === 'LOCAL'
    ? B33B1_DISPOSITION.LOCAL_COMMITTED : B33B1_DISPOSITION.INBOUND_COMMITTED;
  if (transition.disposition !== expected) {
    failB33b1(B33B1_ERROR.CORRUPT, 'transition disposition is invalid');
  }
  return Object.freeze({ ...transition });
}

function parseApplication(value, ordinal) {
  const record = exactFields(value, APPLICATION_FIELDS, 'application record');
  if (record.ordinal !== ordinal || !['OUTBOUND', 'INBOUND'].includes(record.direction)) {
    failB33b1(B33B1_ERROR.CORRUPT, 'application ordinal or direction is invalid');
  }
  requireDigest('application state blob', record.stateBlobSha256Hex);
  requireDigest('application ciphertext blob', record.ciphertextBlobSha256Hex);
  requireDigest('application plaintext blob', record.plaintextBlobSha256Hex, true);
  requireEpoch('application message epoch', record.messageEpoch);
  if (!Number.isSafeInteger(record.senderLeafIndex) || record.senderLeafIndex < 0) {
    failB33b1(B33B1_ERROR.CORRUPT, 'application sender leaf index is invalid');
  }
  requireHex('application sender identity', record.senderIdentityHex, 32);
  requireHex('application sender signature key', record.senderSignatureKeyHex, 32);
  if ((record.direction === 'OUTBOUND' && record.plaintextBlobSha256Hex !== null)
    || (record.direction === 'INBOUND' && record.plaintextBlobSha256Hex === null)) {
    failB33b1(B33B1_ERROR.CORRUPT, 'application direction and plaintext binding disagree');
  }
  return Object.freeze({ ...record });
}

function payload(head) {
  const { headDigestHex: ignored, ...value } = head;
  return value;
}

function buildHead(fields) {
  const value = { domain: HEAD_DOMAIN, ...fields };
  return Object.freeze({ ...value, headDigestHex: sha256Hex(canonicalJsonBytes(value)) });
}

export function parseB33b1Head(value) {
  const head = exactFields(value, HEAD_FIELDS, 'B3.3b-1 journal head');
  if (head.domain !== HEAD_DOMAIN || !Object.values(B33B1_STATE).includes(head.state)
    || head.providerFormat !== B33B1_PROVIDER_FORMAT
    || !Number.isSafeInteger(head.sequence) || head.sequence < 1) {
    failB33b1(B33B1_ERROR.CORRUPT, 'journal head discriminator is invalid');
  }
  requireDigest('journal id', head.journalIdHex);
  requireDigest('previous head', head.previousHeadDigestHex, true);
  requireDigest('source B3.2a head', head.sourceB32aHeadDigestHex);
  requireHex('group id', head.groupIdHex);
  requireHex('account identity', head.accountIdentityHex, 32);
  requireHex('leaf signature key', head.leafSignatureKeyHex, 32);
  requireEpoch('active epoch', head.epochDec);
  requireDigest('active GroupContext', head.groupContextSha256Hex);
  requireDigest('roster', head.rosterSha256Hex);
  requireDigest('active state blob', head.stateBlobSha256Hex);
  requireDigest('committed Commit', head.committedCommitSha256Hex, true);
  if (!Array.isArray(head.transitions) || head.transitions.length > B33B1_LIMITS.maxJournalTransitions) {
    failB33b1(B33B1_ERROR.CORRUPT, 'transition history is outside its envelope');
  }
  const transitions = head.transitions.map((entry, index) => parseTransition(entry, index + 1));
  if (!Array.isArray(head.applicationRecords)
    || head.applicationRecords.length > B33B1_LIMITS.maxJournalTransitions * 2) {
    failB33b1(B33B1_ERROR.CORRUPT, 'application history is outside its envelope');
  }
  const applicationRecords = head.applicationRecords.map(
    (entry, index) => parseApplication(entry, index + 1),
  );
  const pendingLocal = parseLocal(head.pendingLocal, head.state);
  const stagedInbound = parseInbound(head.stagedInbound);
  const isActive = head.state === B33B1_STATE.ACTIVE;
  if ((isActive && (pendingLocal !== null || stagedInbound !== null))
    || (!isActive && head.state.startsWith('LOCAL') && (pendingLocal === null || stagedInbound !== null))
    || (head.state === B33B1_STATE.INBOUND_STAGED
      && (stagedInbound === null || pendingLocal !== null))
    || head.sequence !== 1 + transitions.length + applicationRecords.length
      + (head.state === B33B1_STATE.ACTIVE ? 0 : 1)) {
    failB33b1(B33B1_ERROR.CORRUPT, 'journal state, payload and sequence disagree');
  }
  const expectedDigest = sha256Hex(canonicalJsonBytes(payload(head)));
  if (head.headDigestHex !== expectedDigest) {
    failB33b1(B33B1_ERROR.CORRUPT, 'journal head digest is invalid');
  }
  return Object.freeze({ ...head, transitions: Object.freeze(transitions),
    applicationRecords: Object.freeze(applicationRecords), pendingLocal, stagedInbound });
}

function copyBytes(value) { return Uint8Array.from(value); }

export class MemoryB33b1Store {
  constructor() {
    this.head = null;
    this.blobs = new Map();
    this.beforeWrite = null;
    this.writeOrdinal = 0;
  }

  async readHead() { return this.head === null ? null : structuredClone(this.head); }

  async readBlob(digest) {
    const value = this.blobs.get(digest);
    return value === undefined ? null : copyBytes(value);
  }

  async compareAndSwap(expectedDigest, nextHead, blobs) {
    if ((this.head?.headDigestHex ?? null) !== expectedDigest) return false;
    for (const blob of blobs) {
      this.writeOrdinal += 1;
      await this.beforeWrite?.({ kind: 'blob', ordinal: this.writeOrdinal,
        digest: sha256Hex(blob) });
      this.blobs.set(sha256Hex(blob), copyBytes(blob));
    }
    this.writeOrdinal += 1;
    await this.beforeWrite?.({ kind: 'head', ordinal: this.writeOrdinal,
      digest: nextHead.headDigestHex });
    this.head = structuredClone(nextHead);
    return true;
  }
}

export class B33b1Journal {
  constructor(store) {
    if (!store || typeof store.readHead !== 'function' || typeof store.readBlob !== 'function'
      || typeof store.compareAndSwap !== 'function') {
      failB33b1(B33B1_ERROR.INVALID, 'journal store lacks the closed CAS interface');
    }
    this.store = store;
  }

  async #head(required = true) {
    try {
      const value = await this.store.readHead();
      if (value === null && required) {
        failB33b1(B33B1_ERROR.STATE_CONFLICT, 'B3.3b-1 journal is not active');
      }
      return value === null ? null : parseB33b1Head(value);
    } catch (error) {
      if (error instanceof B33b1Error) throw error;
      failB33b1(B33B1_ERROR.PERSISTENCE_FAILED, 'journal head read failed');
    }
  }

  async #blob(digest, label, maximum = B33B1_LIMITS.maxProviderBytes) {
    let value;
    try { value = await this.store.readBlob(digest); } catch {
      failB33b1(B33B1_ERROR.PERSISTENCE_FAILED, `${label} read failed`);
    }
    if (!(value instanceof Uint8Array) || value.byteLength < 1
      || value.byteLength > maximum || sha256Hex(value) !== digest) {
      clearBytes(value);
      failB33b1(B33B1_ERROR.CORRUPT, `${label} is absent, oversized or corrupt`);
    }
    return value;
  }

  async #cas(expected, next, blobs, initialization = false) {
    try {
      const changed = await this.store.compareAndSwap(
        expected?.headDigestHex ?? null, next, blobs,
      );
      if (!changed) failB33b1(
        initialization ? B33B1_ERROR.DUPLICATE_INITIALIZATION : B33B1_ERROR.CAS_CONFLICT,
        initialization ? 'B3.2a state was already activated' : 'journal CAS lost',
      );
    } catch (error) {
      if (error instanceof B33b1Error) throw error;
      failB33b1(B33B1_ERROR.PERSISTENCE_FAILED, 'journal write failed closed');
    }
    return next;
  }

  async activate(fields) {
    requireBytes('activated state', fields.stateBytes, B33B1_LIMITS.maxProviderBytes);
    requireDigest('source B3.2a head', fields.sourceB32aHeadDigestHex);
    requireHex('group id', fields.groupIdHex);
    requireHex('account identity', fields.accountIdentityHex, 32);
    requireHex('leaf signature key', fields.leafSignatureKeyHex, 32);
    requireEpoch('activation epoch', fields.epochDec);
    requireDigest('activation GroupContext', fields.groupContextSha256Hex);
    requireDigest('activation roster', fields.rosterSha256Hex);
    if (await this.#head(false) !== null) {
      failB33b1(B33B1_ERROR.DUPLICATE_INITIALIZATION, 'B3.2a state was already activated');
    }
    const stateDigest = sha256Hex(fields.stateBytes);
    const journalIdHex = sha256Hex(canonicalJsonBytes({
      domain: JOURNAL_ID_DOMAIN,
      sourceB32aHeadDigestHex: fields.sourceB32aHeadDigestHex,
      activatedStateSha256Hex: stateDigest,
    }));
    const next = buildHead({
      journalIdHex,
      sequence: 1,
      state: B33B1_STATE.ACTIVE,
      previousHeadDigestHex: null,
      sourceB32aHeadDigestHex: fields.sourceB32aHeadDigestHex,
      providerFormat: B33B1_PROVIDER_FORMAT,
      groupIdHex: fields.groupIdHex,
      accountIdentityHex: fields.accountIdentityHex,
      leafSignatureKeyHex: fields.leafSignatureKeyHex,
      epochDec: fields.epochDec,
      groupContextSha256Hex: fields.groupContextSha256Hex,
      rosterSha256Hex: fields.rosterSha256Hex,
      stateBlobSha256Hex: stateDigest,
      committedCommitSha256Hex: null,
      pendingLocal: null,
      stagedInbound: null,
      applicationRecords: [],
      transitions: [],
    });
    await this.#cas(null, next, [copyBytes(fields.stateBytes)], true);
    return this.readRecovery();
  }

  async readRecovery() {
    const head = await this.#head();
    const stateBytes = await this.#blob(head.stateBlobSha256Hex, 'authoritative state');
    if (head.state === B33B1_STATE.ACTIVE) {
      return Object.freeze({ action: B33B1_RECOVERY.STABLE, head, stateBytes });
    }
    const candidate = head.pendingLocal ?? head.stagedInbound;
    const parentStateBytes = await this.#blob(
      candidate.parentStateBlobSha256Hex, 'clean parent state',
    );
    const commitBytes = await this.#blob(
      candidate.commitBlobSha256Hex, 'exact Commit', B33B1_LIMITS.maxCommitBytes,
    );
    if (head.state === B33B1_STATE.INBOUND_STAGED) {
      return Object.freeze({ action: B33B1_RECOVERY.RESTAGE_INBOUND, head, stateBytes,
        parentStateBytes, commitBytes });
    }
    const pendingStateBytes = await this.#blob(
      candidate.pendingStateBlobSha256Hex, 'pending provider state',
    );
    return Object.freeze({
      action: head.state === B33B1_STATE.LOCAL_ACCEPTED
        ? B33B1_RECOVERY.MERGE_ACCEPTED_LOCAL : B33B1_RECOVERY.REPUBLISH_LOCAL,
      head, stateBytes, parentStateBytes, pendingStateBytes, commitBytes,
    });
  }

  async committedTransition(commitSha256Hex) {
    requireDigest('Commit digest', commitSha256Hex);
    const head = await this.#head();
    return head.transitions.find(
      (transition) => transition.commitSha256Hex === commitSha256Hex,
    ) ?? null;
  }

  async commitApplication(expectedHeadDigestHex, fields) {
    const head = await this.#head();
    if (head.headDigestHex !== expectedHeadDigestHex || head.state !== B33B1_STATE.ACTIVE) {
      failB33b1(B33B1_ERROR.CAS_CONFLICT, 'application operation did not start from active head');
    }
    if (!['OUTBOUND', 'INBOUND'].includes(fields.direction)) {
      failB33b1(B33B1_ERROR.INVALID, 'application direction is invalid');
    }
    requireBytes('application state', fields.stateBytes, B33B1_LIMITS.maxProviderBytes);
    requireBytes('application ciphertext', fields.ciphertextBytes, B33B1_LIMITS.maxCommitBytes);
    if (fields.direction === 'INBOUND') {
      requireBytes('application plaintext', fields.plaintextBytes, B33B1_LIMITS.maxCommitBytes);
      if (head.applicationRecords.some((record) => record.direction === 'INBOUND'
        && record.ciphertextBlobSha256Hex === sha256Hex(fields.ciphertextBytes))) {
        failB33b1(B33B1_ERROR.STATE_CONFLICT, 'inbound application ciphertext already committed');
      }
    } else if (fields.plaintextBytes !== undefined && fields.plaintextBytes !== null) {
      failB33b1(B33B1_ERROR.INVALID, 'outbound plaintext must not be journalled');
    }
    const record = parseApplication({
      ordinal: head.applicationRecords.length + 1,
      direction: fields.direction,
      stateBlobSha256Hex: sha256Hex(fields.stateBytes),
      ciphertextBlobSha256Hex: sha256Hex(fields.ciphertextBytes),
      plaintextBlobSha256Hex: fields.direction === 'INBOUND'
        ? sha256Hex(fields.plaintextBytes) : null,
      messageEpoch: fields.messageEpoch,
      senderLeafIndex: fields.senderLeafIndex,
      senderIdentityHex: fields.senderIdentityHex,
      senderSignatureKeyHex: fields.senderSignatureKeyHex,
    }, head.applicationRecords.length + 1);
    if (fields.currentEpochDec !== head.epochDec || fields.groupIdHex !== head.groupIdHex) {
      failB33b1(B33B1_ERROR.STATE_CONFLICT, 'application result changed active group authority');
    }
    const next = buildHead({ ...payload(head), sequence: head.sequence + 1,
      previousHeadDigestHex: head.headDigestHex,
      stateBlobSha256Hex: record.stateBlobSha256Hex,
      applicationRecords: [...head.applicationRecords, record] });
    const blobs = [copyBytes(fields.stateBytes), copyBytes(fields.ciphertextBytes)];
    if (fields.direction === 'INBOUND') blobs.push(copyBytes(fields.plaintextBytes));
    await this.#cas(head, next, blobs);
    const durable = await this.readRecovery();
    const ciphertextBytes = await this.#blob(
      record.ciphertextBlobSha256Hex, 'durable application ciphertext',
      B33B1_LIMITS.maxCommitBytes,
    );
    const plaintextBytes = record.plaintextBlobSha256Hex === null ? null : await this.#blob(
      record.plaintextBlobSha256Hex, 'durable application plaintext',
      B33B1_LIMITS.maxCommitBytes,
    );
    return Object.freeze({ ...durable, record, ciphertextBytes, plaintextBytes });
  }

  async prepareLocal(expectedHeadDigestHex, fields) {
    const head = await this.#head();
    if (head.headDigestHex !== expectedHeadDigestHex || head.state !== B33B1_STATE.ACTIVE) {
      failB33b1(B33B1_ERROR.CAS_CONFLICT, 'local preparation did not start from active head');
    }
    requireBytes('clean parent state', fields.parentStateBytes, B33B1_LIMITS.maxProviderBytes);
    requireBytes('pending provider state', fields.pendingStateBytes, B33B1_LIMITS.maxProviderBytes);
    requireBytes('Commit', fields.commitBytes, B33B1_LIMITS.maxCommitBytes);
    const projection = parseProjection(fields.projection);
    const pendingLocal = parseLocal({
      parentStateBlobSha256Hex: sha256Hex(fields.parentStateBytes),
      pendingStateBlobSha256Hex: sha256Hex(fields.pendingStateBytes),
      commitBlobSha256Hex: sha256Hex(fields.commitBytes),
      authoritySha256Hex: fields.authoritySha256Hex,
      projection,
      peerAcceptance: null,
    }, B33B1_STATE.LOCAL_PENDING);
    if (pendingLocal.parentStateBlobSha256Hex !== head.stateBlobSha256Hex
      || projection.groupIdHex !== head.groupIdHex
      || projection.sourceEpoch !== head.epochDec
      || projection.parentGroupContextSha256Hex !== head.groupContextSha256Hex) {
      failB33b1(B33B1_ERROR.STATE_CONFLICT, 'local preparation is not bound to active parent');
    }
    const next = buildHead({ ...payload(head), sequence: head.sequence + 1,
      state: B33B1_STATE.LOCAL_PENDING, previousHeadDigestHex: head.headDigestHex,
      pendingLocal, stagedInbound: null });
    await this.#cas(head, next, [copyBytes(fields.parentStateBytes),
      copyBytes(fields.pendingStateBytes), copyBytes(fields.commitBytes)]);
    return this.readRecovery();
  }

  async acceptLocal(expectedHeadDigestHex, fields) {
    const head = await this.#head();
    if (head.headDigestHex !== expectedHeadDigestHex || head.state !== B33B1_STATE.LOCAL_PENDING) {
      failB33b1(B33B1_ERROR.CAS_CONFLICT, 'peer acceptance did not bind pending head');
    }
    const acceptance = parseAcceptance(fields, head.pendingLocal.projection);
    const pendingLocal = Object.freeze({ ...head.pendingLocal, peerAcceptance: acceptance });
    const next = buildHead({ ...payload(head), state: B33B1_STATE.LOCAL_ACCEPTED,
      previousHeadDigestHex: head.headDigestHex, pendingLocal });
    await this.#cas(head, next, []);
    return this.readRecovery();
  }

  async commitAcceptedLocal(expectedHeadDigestHex, fields) {
    return this.#commitStable(expectedHeadDigestHex, fields, 'LOCAL');
  }

  async stageInbound(expectedHeadDigestHex, fields) {
    const head = await this.#head();
    if (head.headDigestHex !== expectedHeadDigestHex || head.state !== B33B1_STATE.ACTIVE) {
      failB33b1(B33B1_ERROR.CAS_CONFLICT, 'inbound stage did not start from active head');
    }
    requireBytes('clean parent state', fields.parentStateBytes, B33B1_LIMITS.maxProviderBytes);
    requireBytes('inbound Commit', fields.commitBytes, B33B1_LIMITS.maxCommitBytes);
    const projection = parseProjection(fields.projection);
    const stagedInbound = parseInbound({
      parentStateBlobSha256Hex: sha256Hex(fields.parentStateBytes),
      commitBlobSha256Hex: sha256Hex(fields.commitBytes),
      authoritySha256Hex: fields.authoritySha256Hex,
      projection,
    });
    if (stagedInbound.parentStateBlobSha256Hex !== head.stateBlobSha256Hex
      || projection.groupIdHex !== head.groupIdHex
      || projection.sourceEpoch !== head.epochDec
      || projection.parentGroupContextSha256Hex !== head.groupContextSha256Hex) {
      failB33b1(B33B1_ERROR.STATE_CONFLICT, 'inbound stage is not bound to active parent');
    }
    const next = buildHead({ ...payload(head), sequence: head.sequence + 1,
      state: B33B1_STATE.INBOUND_STAGED, previousHeadDigestHex: head.headDigestHex,
      pendingLocal: null, stagedInbound });
    await this.#cas(head, next,
      [copyBytes(fields.parentStateBytes), copyBytes(fields.commitBytes)]);
    return this.readRecovery();
  }

  async commitStagedInbound(expectedHeadDigestHex, fields) {
    return this.#commitStable(expectedHeadDigestHex, fields, 'INBOUND');
  }

  async #commitStable(expectedHeadDigestHex, fields, direction) {
    const head = await this.#head();
    const required = direction === 'LOCAL'
      ? B33B1_STATE.LOCAL_ACCEPTED : B33B1_STATE.INBOUND_STAGED;
    const candidate = direction === 'LOCAL' ? head.pendingLocal : head.stagedInbound;
    if (head.headDigestHex !== expectedHeadDigestHex || head.state !== required) {
      failB33b1(B33B1_ERROR.CAS_CONFLICT, 'stable commit did not bind recoverable head');
    }
    requireBytes('committed provider state', fields.committedStateBytes,
      B33B1_LIMITS.maxProviderBytes);
    requireDigest('committed GroupContext', fields.groupContextSha256Hex);
    requireDigest('committed roster', fields.rosterSha256Hex);
    if (sha256Hex(fields.committedStateBytes) !== fields.committedStateSha256Hex
      || fields.groupContextSha256Hex !== candidate.projection.candidateGroupContextSha256Hex
      || fields.epochDec !== candidate.projection.targetEpoch
      || fields.commitSha256Hex !== candidate.projection.commitSha256Hex
      || fields.authoritySha256Hex !== candidate.authoritySha256Hex) {
      failB33b1(B33B1_ERROR.STATE_CONFLICT, 'committed state evidence does not match stage');
    }
    if (head.transitions.length >= B33B1_LIMITS.maxJournalTransitions) {
      failB33b1(B33B1_ERROR.RESOURCE_LIMIT, 'transition history is full');
    }
    const disposition = direction === 'LOCAL'
      ? B33B1_DISPOSITION.LOCAL_COMMITTED : B33B1_DISPOSITION.INBOUND_COMMITTED;
    const transition = parseTransition({
      ordinal: head.transitions.length + 1,
      direction,
      commitSha256Hex: fields.commitSha256Hex,
      sourceEpoch: candidate.projection.sourceEpoch,
      targetEpoch: candidate.projection.targetEpoch,
      authoritySha256Hex: fields.authoritySha256Hex,
      disposition,
    }, head.transitions.length + 1);
    const next = buildHead({ ...payload(head), sequence: head.sequence,
      state: B33B1_STATE.ACTIVE, previousHeadDigestHex: head.headDigestHex,
      epochDec: fields.epochDec, groupContextSha256Hex: fields.groupContextSha256Hex,
      rosterSha256Hex: fields.rosterSha256Hex,
      stateBlobSha256Hex: fields.committedStateSha256Hex,
      committedCommitSha256Hex: fields.commitSha256Hex,
      pendingLocal: null, stagedInbound: null,
      transitions: [...head.transitions, transition] });
    await this.#cas(head, next, [copyBytes(fields.committedStateBytes)]);
    return this.readRecovery();
  }
}

function assertPrivateDirectory(directory, approvedRoot) {
  const root = resolve(approvedRoot);
  const target = resolve(directory);
  if (target === root || !target.startsWith(`${root}/`) || basename(target).length < 1) {
    failB33b1(B33B1_ERROR.INVALID, 'journal path is outside its approved private root');
  }
  return target;
}

function fsyncDirectory(path) {
  const descriptor = openSync(path, 'r');
  try { fsyncSync(descriptor); } finally { closeSync(descriptor); }
}

function durableReplace(path, bytes) {
  const temporary = `${path}.tmp-${process.pid}-${Date.now()}`;
  writeFileSync(temporary, bytes, { mode: 0o600, flag: 'wx' });
  const descriptor = openSync(temporary, 'r');
  try { fsyncSync(descriptor); } finally { closeSync(descriptor); }
  renameSync(temporary, path);
  fsyncDirectory(dirname(path));
}

export class FileB33b1Store {
  constructor(directory, approvedRoot = B33B1_PRIVATE_ROOT) {
    this.directory = assertPrivateDirectory(directory, approvedRoot);
    this.headPath = resolve(this.directory, 'head.json');
    this.blobDirectory = resolve(this.directory, 'blobs');
    mkdirSync(this.blobDirectory, { recursive: true, mode: 0o700 });
    if ((statSync(this.directory).mode & 0o077) !== 0
      || (statSync(this.blobDirectory).mode & 0o077) !== 0) {
      failB33b1(B33B1_ERROR.INVALID, 'journal directories are not owner-only');
    }
  }

  async readHead() {
    if (!existsSync(this.headPath)) return null;
    const bytes = readFileSync(this.headPath);
    if (bytes.byteLength > 1024 * 1024) {
      failB33b1(B33B1_ERROR.CORRUPT, 'journal head exceeds its byte envelope');
    }
    try { return JSON.parse(bytes.toString('utf8')); } catch {
      failB33b1(B33B1_ERROR.CORRUPT, 'journal head is not JSON');
    }
  }

  async readBlob(digest) {
    requireDigest('blob digest', digest);
    const path = resolve(this.blobDirectory, digest);
    if (!existsSync(path)) return null;
    return Uint8Array.from(readFileSync(path));
  }

  async compareAndSwap(expectedDigest, nextHead, blobs) {
    const current = await this.readHead();
    if ((current?.headDigestHex ?? null) !== expectedDigest) return false;
    for (const blob of blobs) {
      const digest = sha256Hex(blob);
      const path = resolve(this.blobDirectory, digest);
      if (!existsSync(path)) durableReplace(path, blob);
      const reread = readFileSync(path);
      if (sha256Hex(reread) !== digest) {
        failB33b1(B33B1_ERROR.CORRUPT, 'durable blob read-back failed');
      }
    }
    durableReplace(this.headPath, canonicalJsonBytes(nextHead));
    return true;
  }
}

export function openB33b1FileJournal(directory, approvedRoot = B33B1_PRIVATE_ROOT) {
  return new B33b1Journal(new FileB33b1Store(directory, approvedRoot));
}
