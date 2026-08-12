// STYX_SPIKE_PROTOTYPE — eight-store atomic journal for Phase B2.5b only.

import { openVaultDb } from '../../src/storage/vault-db.js';
import {
  B25B_BATCH_STATE,
  B25B_CANDIDATE_STATE,
  B25B_DB_PREFIX,
  B25B_DISPOSITION,
  B25B_ERROR,
  B25B_HEAD_STATE,
  B25B_LIMITS,
  B25B_LOCAL_STATE,
  B25B_PUBLICATION_KIND,
  B25B_STORES,
  B25B_STORE_NAMES,
  B25B_TERMINAL_DISPOSITION,
  assertBytes,
  assertGroupIdHex,
  assertHex64,
  assertString,
  bytesEqual,
  candidateKey,
  compareCandidates,
  copyBytes,
  failB25B,
  inputKey,
  localKey,
  publicationKey,
} from './b2-5b-canonical.mjs';
import {
  LOCAL_FIELDS,
  buildBatch,
  buildCandidateEvidence,
  buildHead,
  buildInput,
  buildLocal,
  buildPendingCandidate,
  buildPublication,
  buildRetainedState,
  buildTransition,
  outcomesDigest,
  parseBatch,
  parseCandidateEvidence,
  parseHead,
  parseInput,
  parseLocal,
  parsePublication,
  parseRetainedState,
  parseTransition,
} from './b2-5b-record.mjs';
import { createBoundB25BEngineAdapter } from './b2-5b-engine-adapter.mjs';

const JOURNAL_TOKEN = Symbol('B25B_JOURNAL_TOKEN');

function migrationV1(db) {
  for (const name of B25B_STORE_NAMES) db.createObjectStore(name);
}

function sameHead(left, right) {
  return left.headDigestHex === right.headDigestHex && left.seq === right.seq;
}

function sameInput(left, right) {
  return left.inputDigestHex === right.inputDigestHex
    && bytesEqual(left.commitBytes, right.commitBytes);
}

function sameCandidate(left, right) {
  return left.evidenceDigestHex === right.evidenceDigestHex;
}

function mutateLocal(record, changes) {
  const fields = {};
  for (const field of LOCAL_FIELDS) {
    if (!['format', 'version', 'localPendingDigestHex'].includes(field)) fields[field] = record[field];
  }
  return buildLocal({ ...fields, ...changes });
}

async function getRequired(ops, store, key, label) {
  const value = await ops.get(store, key);
  if (value === undefined) failB25B(B25B_ERROR.CORRUPT, `${label} is missing`);
  return value;
}

async function listGroupInputs(ops, groupIdHex) {
  const prefix = `${groupIdHex}:`;
  const keys = (await ops.list(B25B_STORES.input))
    .filter((key) => typeof key === 'string' && key.startsWith(prefix)).sort();
  const records = [];
  for (const key of keys) records.push(parseInput(await getRequired(
    ops, B25B_STORES.input, key, 'listed input',
  )));
  return records;
}

function validateFrozenBundle({ head, batch, retained, inputs, candidates, local = null }) {
  if (batch.state !== B25B_BATCH_STATE.FROZEN) {
    failB25B(B25B_ERROR.STATE_CONFLICT, 'resolution requires a frozen batch');
  }
  if (head.state !== B25B_HEAD_STATE.STABLE
    || head.headDigestHex !== batch.localBaseHeadDigestHex
    || head.groupIdHex !== batch.groupIdHex
    || head.epochDec !== batch.baseEpochDec
    || head.groupContextDigestHex !== batch.baseGroupContextDigestHex) {
    failB25B(B25B_ERROR.CAS_CONFLICT, 'frozen batch no longer binds the canonical base head');
  }
  if (retained.snapshotDigestHex !== head.snapshotDigestHex
    || retained.groupIdHex !== head.groupIdHex
    || retained.epochDec !== head.epochDec
    || retained.groupContextDigestHex !== head.groupContextDigestHex
    || retained.accountKeyHex !== head.accountKeyHex
    || retained.signatureKeyHex !== head.signatureKeyHex) {
    failB25B(B25B_ERROR.CORRUPT, 'retained parent does not bind the base head');
  }
  const localDigest = local?.activeBatchDigestHex === batch.protocolBatchDigestHex
    ? local.commitDigestHex : null;
  const inputDigests = batch.commitDigests.filter((digest) => digest !== localDigest);
  if (inputs.length !== inputDigests.length || candidates.length !== batch.commitDigests.length) {
    failB25B(B25B_ERROR.CORRUPT, 'frozen batch references an incomplete decision set');
  }
  if (localDigest !== null && (local.state !== B25B_LOCAL_STATE.ACKNOWLEDGED
    || local.parentHeadDigestHex !== head.headDigestHex)) {
    failB25B(B25B_ERROR.CORRUPT, 'frozen local candidate is not acknowledged or parent-bound');
  }
  for (let index = 0; index < batch.commitDigests.length; index += 1) {
    const digest = batch.commitDigests[index];
    const candidate = candidates[index];
    if (candidate.commitDigestHex !== digest
      || candidate.batchDigestHex !== batch.protocolBatchDigestHex
      || candidate.groupIdHex !== batch.groupIdHex
      || candidate.state !== B25B_CANDIDATE_STATE.PENDING
      || candidate.parentEpochDec !== batch.baseEpochDec
      || candidate.parentGroupContextDigestHex !== batch.baseGroupContextDigestHex) {
      failB25B(B25B_ERROR.CORRUPT, 'frozen decision record binding is incoherent');
    }
  }
  for (let index = 0; index < inputDigests.length; index += 1) {
    const input = inputs[index];
    if (input.commitDigestHex !== inputDigests[index] || input.groupIdHex !== batch.groupIdHex
      || input.batchDigestHex !== batch.protocolBatchDigestHex
      || input.disposition !== B25B_DISPOSITION.FROZEN) {
      failB25B(B25B_ERROR.CORRUPT, 'frozen inbound input binding is incoherent');
    }
  }
  return { head, batch, retained, inputs, candidates };
}

function headProducedByTransition(identityHead, transition) {
  if (transition.groupIdHex !== identityHead.groupIdHex) {
    failB25B(B25B_ERROR.CORRUPT, 'historical transition belongs to another group');
  }
  return buildHead({
    groupIdHex: transition.groupIdHex,
    accountKeyHex: identityHead.accountKeyHex,
    signatureKeyHex: identityHead.signatureKeyHex,
    seq: transition.seq,
    state: transition.kind === 'UNRECOVERABLE'
      ? B25B_HEAD_STATE.UNRECOVERABLE : B25B_HEAD_STATE.STABLE,
    epochDec: transition.epochDec,
    groupContextDigestHex: transition.groupContextDigestHex,
    snapshotDigestHex: transition.snapshotDigestHex,
    priorHeadDigestHex: transition.priorHeadDigestHex,
    transitionDigestHex: transition.transitionDigestHex,
    selectedCommitDigestHex: transition.winnerCommitDigestHex,
  });
}

async function readGroupTransitionHistory(ops, identityHead) {
  const records = [];
  const keys = (await ops.list(B25B_STORES.transition))
    .filter((key) => typeof key === 'string').sort();
  for (const key of keys) {
    const transition = parseTransition(await getRequired(
      ops, B25B_STORES.transition, key, 'historical transition',
    ));
    if (transition.transitionDigestHex !== key) {
      failB25B(B25B_ERROR.CORRUPT, 'transition storage key does not bind its content');
    }
    if (transition.groupIdHex === identityHead.groupIdHex) {
      records.push(Object.freeze({
        transition,
        head: headProducedByTransition(identityHead, transition),
      }));
    }
  }
  return records;
}

export class B25BJournal {
  #db;

  constructor(db, token) {
    if (token !== JOURNAL_TOKEN) {
      failB25B(B25B_ERROR.INVALID, 'B2.5b journals must be created by the namespace factory');
    }
    this.#db = db;
    Object.freeze(this);
  }

  async #initialize({ groupIdHex, accountKeyHex, signatureKeyHex, epochDec,
    groupContextDigestHex, snapshotBytes }) {
    const retained = buildRetainedState({
      groupIdHex, accountKeyHex, signatureKeyHex, epochDec,
      groupContextDigestHex, snapshotBytes,
    });
    const transition = buildTransition({
      groupIdHex, seq: 1, kind: 'INITIALIZE', priorHeadDigestHex: null,
      batchDigestHex: null, winnerCommitDigestHex: null,
      snapshotDigestHex: retained.snapshotDigestHex, epochDec,
      groupContextDigestHex, outcomesDigestHex: null,
    });
    const head = buildHead({
      groupIdHex, accountKeyHex, signatureKeyHex, seq: 1,
      state: B25B_HEAD_STATE.STABLE, epochDec, groupContextDigestHex,
      snapshotDigestHex: retained.snapshotDigestHex, priorHeadDigestHex: null,
      transitionDigestHex: transition.transitionDigestHex,
      selectedCommitDigestHex: null,
    });
    await this.#db.transaction(B25B_STORE_NAMES, async (ops) => {
      for (const store of B25B_STORE_NAMES) {
        if ((await ops.list(store)).length !== 0) {
          failB25B(B25B_ERROR.CAS_CONFLICT, 'private one-group B2.5b journal is not empty');
        }
      }
      await Promise.all([
        ops.put(B25B_STORES.retained, retained.snapshotDigestHex, retained),
        ops.put(B25B_STORES.transition, transition.transitionDigestHex, transition),
        ops.put(B25B_STORES.head, groupIdHex, head),
      ]);
    });
    return head;
  }

  async readHead(groupIdHex) {
    assertGroupIdHex(groupIdHex);
    return this.#db.transaction(B25B_STORE_NAMES, async (ops) => {
      const head = parseHead(await getRequired(ops, B25B_STORES.head, groupIdHex, 'canonical head'));
      const transition = parseTransition(await getRequired(
        ops, B25B_STORES.transition, head.transitionDigestHex, 'canonical transition',
      ));
      const rawRetained = await ops.get(B25B_STORES.retained, head.snapshotDigestHex);
      if (rawRetained === undefined && head.state !== B25B_HEAD_STATE.UNRECOVERABLE) {
        failB25B(B25B_ERROR.CORRUPT, 'canonical retained state is missing');
      }
      const retained = rawRetained === undefined ? null : parseRetainedState(rawRetained);
      if (transition.groupIdHex !== head.groupIdHex || transition.seq !== head.seq
        || transition.snapshotDigestHex !== head.snapshotDigestHex
        || transition.epochDec !== head.epochDec
        || transition.groupContextDigestHex !== head.groupContextDigestHex) {
        failB25B(B25B_ERROR.CORRUPT, 'head, retained state and transition are incoherent');
      }
      if (head.state === B25B_HEAD_STATE.UNRECOVERABLE
        && transition.kind !== B25B_HEAD_STATE.UNRECOVERABLE) {
        failB25B(B25B_ERROR.CORRUPT, 'unrecoverable head lacks its terminal transition');
      }
      return { head, retained, transition };
    });
  }

  async queueLocal(groupIdHex, operationKind, operationPayloadBytes = new Uint8Array()) {
    assertGroupIdHex(groupIdHex);
    if (!['self-update', 'add', 'remove'].includes(operationKind)) {
      failB25B(B25B_ERROR.INVALID, 'unsupported local operation');
    }
    assertBytes('operationPayloadBytes', operationPayloadBytes,
      { min: 0, max: B25B_LIMITS.maxCommitBytes });
    const queued = buildLocal({
      groupIdHex, state: B25B_LOCAL_STATE.QUEUED, operationKind,
      operationPayloadBytes: copyBytes(operationPayloadBytes),
      parentHeadDigestHex: null, parentEpochDec: null,
      parentGroupContextDigestHex: null, cleanSnapshotDigestHex: null,
      pendingSnapshotDigestHex: null, commitDigestHex: null,
      commitBytes: new Uint8Array(), welcomeBytes: new Uint8Array(),
      candidateEpochDec: null, candidateGroupContextDigestHex: null,
      verifiedLeafDigestHex: null, projectionDigestHex: null, priority: null,
      committerIdentityHex: null, authorizationContextDigestHex: null,
      authorizationResultDigestHex: null, recipientScope: [],
      recipientScopeDigestHex: null, publishAttempts: 0, ackCount: 0,
      failureCount: 0, activeBatchDigestHex: null, terminalDisposition: null,
    });
    return this.#db.transaction(B25B_STORE_NAMES, async (ops) => {
      const head = parseHead(await getRequired(ops, B25B_STORES.head, groupIdHex,
        'canonical head'));
      if (head.state !== B25B_HEAD_STATE.STABLE) {
        failB25B(B25B_ERROR.STATE_CONFLICT, 'local intent requires a stable head');
      }
      const priorRaw = await ops.get(B25B_STORES.local, localKey(groupIdHex));
      if (priorRaw !== undefined) {
        const prior = parseLocal(priorRaw);
        if (![B25B_LOCAL_STATE.CANCELLED, B25B_LOCAL_STATE.DISCARDED,
          B25B_LOCAL_STATE.CONFIRMED, B25B_LOCAL_STATE.CLEARED_LOST,
          B25B_LOCAL_STATE.CLEARED_REJECTED].includes(prior.state)) {
          failB25B(B25B_ERROR.STATE_CONFLICT, 'one local intent is already active');
        }
      }
      const collected = (await listGroupInputs(ops, groupIdHex))
        .filter((item) => item.batchDigestHex === null);
      if (collected.length >= B25B_LIMITS.maxBatchCommits) {
        failB25B(B25B_ERROR.RESOURCE_LIMIT,
          'local intent cannot reserve a bounded arbitration slot');
      }
      await ops.put(B25B_STORES.local, localKey(groupIdHex), queued);
      return queued;
    });
  }

  async readLocal(groupIdHex) {
    assertGroupIdHex(groupIdHex);
    return this.#db.transaction(B25B_STORE_NAMES, async (ops) => {
      const raw = await ops.get(B25B_STORES.local, localKey(groupIdHex));
      return raw === undefined ? null : parseLocal(raw);
    });
  }

  async readRetained(snapshotDigestHex) {
    assertHex64('snapshotDigestHex', snapshotDigestHex);
    return this.#db.transaction(B25B_STORE_NAMES, async (ops) => parseRetainedState(
      await getRequired(ops, B25B_STORES.retained, snapshotDigestHex, 'retained state')));
  }

  async readPublication(groupIdHex) {
    assertGroupIdHex(groupIdHex);
    return this.#db.transaction(B25B_STORE_NAMES, async (ops) => {
      const prefix = `${groupIdHex}:`;
      const keys = (await ops.list(B25B_STORES.publication))
        .filter((key) => typeof key === 'string' && key.startsWith(prefix)).sort();
      const result = [];
      for (const key of keys) result.push(parsePublication(await getRequired(
        ops, B25B_STORES.publication, key, 'publication evidence')));
      return Object.freeze(result);
    });
  }

  async #commitPrepared({ expectedHead, expectedIntent, pending, pendingRetained }) {
    const head = parseHead(expectedHead);
    const intent = parseLocal(expectedIntent);
    const next = parseLocal(pending);
    const retained = parseRetainedState(pendingRetained);
    if (intent.state !== B25B_LOCAL_STATE.QUEUED
      || next.state !== B25B_LOCAL_STATE.PREPARED
      || next.groupIdHex !== head.groupIdHex
      || next.parentHeadDigestHex !== head.headDigestHex
      || next.cleanSnapshotDigestHex !== head.snapshotDigestHex
      || next.pendingSnapshotDigestHex !== retained.snapshotDigestHex
      || next.parentEpochDec !== head.epochDec
      || next.parentGroupContextDigestHex !== head.groupContextDigestHex) {
      failB25B(B25B_ERROR.INVALID, 'prepared local state does not bind the queued intent');
    }
    await this.#db.transaction(B25B_STORE_NAMES, async (ops) => {
      const currentHead = parseHead(await getRequired(ops, B25B_STORES.head,
        head.groupIdHex, 'canonical head'));
      const currentIntent = parseLocal(await getRequired(ops, B25B_STORES.local,
        localKey(head.groupIdHex), 'queued local intent'));
      if (!sameHead(currentHead, head)
        || currentIntent.localPendingDigestHex !== intent.localPendingDigestHex) {
        failB25B(B25B_ERROR.CAS_CONFLICT, 'head or local intent changed during preparation');
      }
      const existing = await ops.get(B25B_STORES.retained, retained.snapshotDigestHex);
      if (existing !== undefined
        && parseRetainedState(existing).retainedDigestHex !== retained.retainedDigestHex) {
        failB25B(B25B_ERROR.CORRUPT, 'pending snapshot content-address collision');
      }
      await ops.put(B25B_STORES.retained, retained.snapshotDigestHex, retained);
      await ops.put(B25B_STORES.local, localKey(head.groupIdHex), next);
    });
    return next;
  }

  async #appendPublication({ expectedLocal, evidence, nextLocal }) {
    const prior = parseLocal(expectedLocal);
    const record = parsePublication(evidence);
    const next = parseLocal(nextLocal);
    if (record.groupIdHex !== prior.groupIdHex || next.groupIdHex !== prior.groupIdHex
      || record.artifactDigestHex !== prior.commitDigestHex
      || !bytesEqual(record.artifactBytes, prior.commitBytes)) {
      failB25B(B25B_ERROR.INVALID, 'publication evidence does not bind the exact Commit');
    }
    return this.#db.transaction(B25B_STORE_NAMES, async (ops) => {
      const current = parseLocal(await getRequired(ops, B25B_STORES.local,
        localKey(prior.groupIdHex), 'local pending state'));
      if (current.localPendingDigestHex !== prior.localPendingDigestHex) {
        failB25B(B25B_ERROR.CAS_CONFLICT, 'local pending state changed');
      }
      const keys = (await ops.list(B25B_STORES.publication))
        .filter((key) => typeof key === 'string' && key.startsWith(`${prior.groupIdHex}:`));
      if (record.sequence !== keys.length + 1) {
        failB25B(B25B_ERROR.CAS_CONFLICT, 'publication evidence sequence changed');
      }
      await ops.put(B25B_STORES.publication,
        publicationKey(prior.groupIdHex, record.sequence), record);
      await ops.put(B25B_STORES.local, localKey(prior.groupIdHex), next);
      return Object.freeze({ evidence: record, local: next });
    });
  }

  async #replaceLocal(expectedLocal, nextLocal) {
    const prior = parseLocal(expectedLocal);
    const next = parseLocal(nextLocal);
    if (prior.groupIdHex !== next.groupIdHex) {
      failB25B(B25B_ERROR.INVALID, 'local replacement changes group identity');
    }
    await this.#db.transaction(B25B_STORE_NAMES, async (ops) => {
      const current = parseLocal(await getRequired(ops, B25B_STORES.local,
        localKey(prior.groupIdHex), 'local pending state'));
      if (current.localPendingDigestHex !== prior.localPendingDigestHex) {
        failB25B(B25B_ERROR.CAS_CONFLICT, 'local pending state changed');
      }
      await ops.put(B25B_STORES.local, localKey(prior.groupIdHex), next);
    });
    return next;
  }

  async retainCommit(groupIdHex, commitBytes) {
    assertGroupIdHex(groupIdHex);
    assertBytes('Commit bytes', commitBytes, { min: 1, max: B25B_LIMITS.maxCommitBytes });
    const proposed = buildInput({ groupIdHex, commitBytes });
    return this.#db.transaction(B25B_STORE_NAMES, async (ops) => {
      const head = parseHead(await getRequired(ops, B25B_STORES.head, groupIdHex, 'canonical head'));
      if (head.state !== B25B_HEAD_STATE.STABLE) {
        failB25B(B25B_ERROR.STATE_CONFLICT, 'Commit collection requires a stable head');
      }
      const localRaw = await ops.get(B25B_STORES.local, localKey(groupIdHex));
      if (localRaw !== undefined) {
        const local = parseLocal(localRaw);
        if (local.commitDigestHex === proposed.commitDigestHex) {
          if (!bytesEqual(local.commitBytes, proposed.commitBytes)) {
            failB25B(B25B_ERROR.CORRUPT, 'local Commit digest collision at own-echo boundary');
          }
          return Object.freeze({ status: 'own_echo', localState: local.state,
            commitDigestHex: proposed.commitDigestHex });
        }
      }
      const key = inputKey(groupIdHex, proposed.commitDigestHex);
      const raw = await ops.get(B25B_STORES.input, key);
      if (raw !== undefined) {
        const existing = parseInput(raw);
        if (!bytesEqual(existing.commitBytes, proposed.commitBytes)) {
          failB25B(B25B_ERROR.CORRUPT, 'Commit digest collision at the storage boundary');
        }
        return Object.freeze({ status: 'duplicate', input: existing });
      }
      const collected = (await listGroupInputs(ops, groupIdHex))
        .filter((item) => item.batchDigestHex === null);
      const activeLocal = localRaw === undefined ? null : parseLocal(localRaw);
      const reservedLocalSlot = activeLocal !== null && [
        B25B_LOCAL_STATE.QUEUED, B25B_LOCAL_STATE.PREPARED,
        B25B_LOCAL_STATE.PUBLISHING, B25B_LOCAL_STATE.ACKNOWLEDGED,
      ].includes(activeLocal.state) ? 1 : 0;
      if (collected.length >= B25B_LIMITS.maxBatchCommits - reservedLocalSlot) {
        failB25B(B25B_ERROR.RESOURCE_LIMIT, 'unfrozen Commit input cap is exhausted');
      }
      await ops.put(B25B_STORES.input, key, proposed);
      return Object.freeze({ status: 'retained', input: proposed });
    });
  }

  async freeze(groupIdHex) {
    assertGroupIdHex(groupIdHex);
    return this.#db.transaction(B25B_STORE_NAMES, async (ops) => {
      const head = parseHead(await getRequired(ops, B25B_STORES.head, groupIdHex, 'canonical head'));
      if (head.state !== B25B_HEAD_STATE.STABLE) {
        failB25B(B25B_ERROR.STATE_CONFLICT, 'batch freeze requires a stable head');
      }
      const unresolvedKeys = await ops.list(B25B_STORES.batch);
      for (const key of unresolvedKeys) {
        const prior = parseBatch(await getRequired(ops, B25B_STORES.batch, key, 'listed batch'));
        if (prior.groupIdHex === groupIdHex && prior.state === B25B_BATCH_STATE.FROZEN) {
          failB25B(B25B_ERROR.STATE_CONFLICT, 'a frozen batch already awaits resolution');
        }
      }
      const collected = (await listGroupInputs(ops, groupIdHex))
        .filter((item) => item.batchDigestHex === null)
        .sort((left, right) => (left.commitDigestHex < right.commitDigestHex
          ? -1 : left.commitDigestHex > right.commitDigestHex ? 1 : 0));
      const localRaw = await ops.get(B25B_STORES.local, localKey(groupIdHex));
      const local = localRaw === undefined ? null : parseLocal(localRaw);
      const eligibleLocal = local?.state === B25B_LOCAL_STATE.ACKNOWLEDGED
        && local.parentHeadDigestHex === head.headDigestHex
        && local.activeBatchDigestHex === null ? local : null;
      const commitDigests = collected.map((item) => item.commitDigestHex);
      if (eligibleLocal !== null) commitDigests.push(eligibleLocal.commitDigestHex);
      commitDigests.sort();
      if (new Set(commitDigests).size !== commitDigests.length) {
        failB25B(B25B_ERROR.CORRUPT, 'local and inbound candidate identities collide');
      }
      if (commitDigests.length === 0) {
        failB25B(B25B_ERROR.STATE_CONFLICT, 'cannot freeze an empty batch');
      }
      if (commitDigests.length > B25B_LIMITS.maxBatchCommits) {
        failB25B(B25B_ERROR.RESOURCE_LIMIT, 'frozen candidate cap is exhausted');
      }
      const batch = buildBatch({
        groupIdHex, baseEpochDec: head.epochDec,
        baseGroupContextDigestHex: head.groupContextDigestHex,
        localBaseHeadDigestHex: head.headDigestHex,
        commitDigests,
        state: B25B_BATCH_STATE.FROZEN, winnerCommitDigestHex: null, outcomes: [],
      });
      if (await ops.get(B25B_STORES.batch, batch.protocolBatchDigestHex) !== undefined) {
        failB25B(B25B_ERROR.CAS_CONFLICT, 'protocol batch identifier already exists');
      }
      const writes = [ops.put(B25B_STORES.batch, batch.protocolBatchDigestHex, batch)];
      for (const input of collected) {
        const frozen = buildInput({
          groupIdHex, batchDigestHex: batch.protocolBatchDigestHex,
          commitBytes: input.commitBytes, disposition: B25B_DISPOSITION.FROZEN,
        });
        const pending = buildPendingCandidate({
          groupIdHex, batchDigestHex: batch.protocolBatchDigestHex,
          commitDigestHex: input.commitDigestHex, parentEpochDec: head.epochDec,
          parentGroupContextDigestHex: head.groupContextDigestHex,
        });
        const candidateStoreKey = candidateKey(batch.protocolBatchDigestHex, input.commitDigestHex);
        if (await ops.get(B25B_STORES.candidate, candidateStoreKey) !== undefined) {
          failB25B(B25B_ERROR.CAS_CONFLICT, 'candidate placeholder already exists');
        }
        writes.push(ops.put(B25B_STORES.input, inputKey(groupIdHex, input.commitDigestHex), frozen));
        writes.push(ops.put(B25B_STORES.candidate, candidateStoreKey, pending));
      }
      if (eligibleLocal !== null) {
        const pending = buildPendingCandidate({
          groupIdHex, batchDigestHex: batch.protocolBatchDigestHex,
          commitDigestHex: eligibleLocal.commitDigestHex, parentEpochDec: head.epochDec,
          parentGroupContextDigestHex: head.groupContextDigestHex,
        });
        writes.push(ops.put(B25B_STORES.candidate,
          candidateKey(batch.protocolBatchDigestHex, eligibleLocal.commitDigestHex), pending));
        writes.push(ops.put(B25B_STORES.local, localKey(groupIdHex), mutateLocal(eligibleLocal,
          { activeBatchDigestHex: batch.protocolBatchDigestHex })));
      }
      await Promise.all(writes);
      return batch;
    });
  }

  async readFrozen(batchDigestHex) {
    assertHex64('batchDigestHex', batchDigestHex);
    const result = await this.#db.transaction(B25B_STORE_NAMES, async (ops) => {
      const batch = parseBatch(await getRequired(ops, B25B_STORES.batch, batchDigestHex, 'frozen batch'));
      const head = parseHead(await getRequired(ops, B25B_STORES.head, batch.groupIdHex, 'canonical head'));
      const rawRetained = await ops.get(B25B_STORES.retained, head.snapshotDigestHex);
      if (rawRetained === undefined) {
        if (head.state === B25B_HEAD_STATE.UNRECOVERABLE) {
          return Object.freeze({ unrecoverable: true, head, batch });
        }
        if (batch.state !== B25B_BATCH_STATE.FROZEN
          || head.state !== B25B_HEAD_STATE.STABLE
          || head.headDigestHex !== batch.localBaseHeadDigestHex
          || head.epochDec !== batch.baseEpochDec
          || head.groupContextDigestHex !== batch.baseGroupContextDigestHex) {
          failB25B(B25B_ERROR.CORRUPT, 'missing retained state has an incoherent frozen base');
        }
        const transition = buildTransition({
          groupIdHex: head.groupIdHex, seq: head.seq + 1, kind: B25B_HEAD_STATE.UNRECOVERABLE,
          priorHeadDigestHex: head.headDigestHex, batchDigestHex,
          winnerCommitDigestHex: null, snapshotDigestHex: head.snapshotDigestHex,
          epochDec: head.epochDec, groupContextDigestHex: head.groupContextDigestHex,
          outcomesDigestHex: null,
        });
        const terminalHead = buildHead({
          groupIdHex: head.groupIdHex, accountKeyHex: head.accountKeyHex,
          signatureKeyHex: head.signatureKeyHex, seq: head.seq + 1,
          state: B25B_HEAD_STATE.UNRECOVERABLE, epochDec: head.epochDec,
          groupContextDigestHex: head.groupContextDigestHex,
          snapshotDigestHex: head.snapshotDigestHex, priorHeadDigestHex: head.headDigestHex,
          transitionDigestHex: transition.transitionDigestHex, selectedCommitDigestHex: null,
        });
        await Promise.all([
          ops.put(B25B_STORES.transition, transition.transitionDigestHex, transition),
          ops.put(B25B_STORES.head, head.groupIdHex, terminalHead),
        ]);
        return Object.freeze({ unrecoverable: true, head: terminalHead, batch });
      }
      const retained = parseRetainedState(rawRetained);
      const localRaw = await ops.get(B25B_STORES.local, localKey(batch.groupIdHex));
      const local = localRaw === undefined ? null : parseLocal(localRaw);
      const localDigest = local?.activeBatchDigestHex === batch.protocolBatchDigestHex
        ? local.commitDigestHex : null;
      const inputs = [];
      const candidates = [];
      for (const digest of batch.commitDigests) {
        if (digest !== localDigest) inputs.push(parseInput(await getRequired(
          ops, B25B_STORES.input, inputKey(batch.groupIdHex, digest), 'batch input',
        )));
        candidates.push(parseCandidateEvidence(await getRequired(
          ops, B25B_STORES.candidate, candidateKey(batchDigestHex, digest), 'candidate placeholder',
        )));
      }
      return { ...validateFrozenBundle({ head, batch, retained, inputs, candidates, local }), local };
    });
    if (result.unrecoverable === true) {
      failB25B(B25B_ERROR.UNRECOVERABLE, 'retained parent state is missing', {
        batchDigestHex, snapshotDigestHex: result.head.snapshotDigestHex,
      });
    }
    return result;
  }

  async #commitResolution({ expectedHead, frozenBatch, expectedInputs,
    expectedCandidates, expectedLocal, candidates, successorRetained }) {
    const head = parseHead(expectedHead);
    const batch = parseBatch(frozenBatch);
    if (batch.state !== B25B_BATCH_STATE.FROZEN || batch.localBaseHeadDigestHex !== head.headDigestHex) {
      failB25B(B25B_ERROR.INVALID, 'resolution does not bind the frozen base');
    }
    if (!Array.isArray(expectedInputs) || !Array.isArray(expectedCandidates)
      || !Array.isArray(candidates) || candidates.length !== batch.commitDigests.length
      || expectedCandidates.length !== candidates.length) {
      failB25B(B25B_ERROR.INVALID, 'resolution decision set has an invalid count');
    }
    const safeLocal = expectedLocal === null ? null : parseLocal(expectedLocal);
    const localDigest = safeLocal?.activeBatchDigestHex === batch.protocolBatchDigestHex
      ? safeLocal.commitDigestHex : null;
    if (expectedInputs.length !== batch.commitDigests.length - (localDigest === null ? 0 : 1)) {
      failB25B(B25B_ERROR.INVALID, 'inbound decision set has an invalid count');
    }
    const safeInputs = expectedInputs.map(parseInput);
    const inputByDigest = new Map(safeInputs.map((item) => [item.commitDigestHex, item]));
    const safePending = expectedCandidates.map(parseCandidateEvidence);
    const safeCandidates = candidates.map(parseCandidateEvidence)
      .sort((left, right) => (left.commitDigestHex < right.commitDigestHex
        ? -1 : left.commitDigestHex > right.commitDigestHex ? 1 : 0));
    for (let index = 0; index < batch.commitDigests.length; index += 1) {
      const digest = batch.commitDigests[index];
      const pending = safePending[index];
      const candidate = safeCandidates[index];
      const input = inputByDigest.get(digest);
      if ((digest !== localDigest && (input === undefined
          || input.groupIdHex !== batch.groupIdHex
          || input.batchDigestHex !== batch.protocolBatchDigestHex
          || input.disposition !== B25B_DISPOSITION.FROZEN))
        || (digest === localDigest && input !== undefined)
        || pending.commitDigestHex !== digest || pending.groupIdHex !== batch.groupIdHex
        || pending.batchDigestHex !== batch.protocolBatchDigestHex
        || pending.state !== B25B_CANDIDATE_STATE.PENDING
        || candidate.commitDigestHex !== digest || candidate.groupIdHex !== batch.groupIdHex
        || candidate.batchDigestHex !== batch.protocolBatchDigestHex
        || candidate.parentEpochDec !== batch.baseEpochDec
        || candidate.parentGroupContextDigestHex !== batch.baseGroupContextDigestHex
        || candidate.state === B25B_CANDIDATE_STATE.PENDING) {
        failB25B(B25B_ERROR.INVALID, 'resolution evidence does not bind the frozen decision set');
      }
    }
    // Candidate records intentionally do not carry mutable disposition. The journal
    // independently derives the canonical winner rather than trusting its caller.
    const authorized = safeCandidates
      .filter((item) => item.state === B25B_CANDIDATE_STATE.AUTHORIZED)
      .sort(compareCandidates);
    const winnerRecord = authorized[0] ?? null;
    if ((successorRetained === null) !== (winnerRecord === null)) {
      failB25B(B25B_ERROR.INVALID, 'successor presence differs from the canonical decision');
    }
    if (successorRetained !== null) {
      const successor = parseRetainedState(successorRetained);
      if (winnerRecord.candidateEpochDec !== successor.epochDec
        || winnerRecord.candidateGroupContextDigestHex !== successor.groupContextDigestHex
        || successor.groupIdHex !== head.groupIdHex
        || successor.accountKeyHex !== head.accountKeyHex
        || successor.signatureKeyHex !== head.signatureKeyHex) {
        failB25B(B25B_ERROR.INVALID, 'successor does not bind the canonical candidate');
      }
    }
    const selectedDigest = winnerRecord?.commitDigestHex ?? null;
    const outcomes = safeCandidates.map((candidate) => {
      let disposition;
      if (candidate.state === B25B_CANDIDATE_STATE.AUTHORIZED) {
        disposition = candidate.commitDigestHex === selectedDigest
          ? B25B_DISPOSITION.SELECTED : B25B_DISPOSITION.LOSING;
      } else if (candidate.state === B25B_CANDIDATE_STATE.REJECTED) disposition = B25B_DISPOSITION.REJECTED;
      else if (candidate.state === B25B_CANDIDATE_STATE.NOT_CANDIDATE) {
        disposition = B25B_DISPOSITION.NOT_CANDIDATE;
      } else failB25B(B25B_ERROR.STATE_CONFLICT, 'pending candidate cannot be resolved');
      return Object.freeze({ commitDigestHex: candidate.commitDigestHex, disposition,
        candidateEvidenceDigestHex: candidate.evidenceDigestHex });
    });
    const resolvedBatch = buildBatch({
      groupIdHex: batch.groupIdHex, baseEpochDec: batch.baseEpochDec,
      baseGroupContextDigestHex: batch.baseGroupContextDigestHex,
      localBaseHeadDigestHex: batch.localBaseHeadDigestHex,
      commitDigests: batch.commitDigests, state: B25B_BATCH_STATE.RESOLVED,
      winnerCommitDigestHex: selectedDigest, outcomes,
    });
    let terminalLocal = safeLocal;
    let localTerminalChanged = false;
    if (localDigest !== null) {
      const localCandidate = safeCandidates.find((item) => item.commitDigestHex === localDigest);
      let state = B25B_LOCAL_STATE.CLEARED_REJECTED;
      let terminalDisposition = B25B_TERMINAL_DISPOSITION.REJECTED;
      if (selectedDigest === localDigest) {
        state = B25B_LOCAL_STATE.CONFIRMED;
        terminalDisposition = B25B_TERMINAL_DISPOSITION.SELECTED;
      } else if (localCandidate.state === B25B_CANDIDATE_STATE.AUTHORIZED) {
        state = B25B_LOCAL_STATE.CLEARED_LOST;
        terminalDisposition = B25B_TERMINAL_DISPOSITION.LOSING;
      }
      terminalLocal = mutateLocal(safeLocal, { state, activeBatchDigestHex: null,
        terminalDisposition });
      localTerminalChanged = true;
    } else if (safeLocal !== null && selectedDigest !== null
      && safeLocal.parentHeadDigestHex === head.headDigestHex
      && [B25B_LOCAL_STATE.PREPARED, B25B_LOCAL_STATE.PUBLISHING,
        B25B_LOCAL_STATE.ACKNOWLEDGED].includes(safeLocal.state)) {
      terminalLocal = mutateLocal(safeLocal, { state: B25B_LOCAL_STATE.CLEARED_LOST,
        activeBatchDigestHex: null,
        terminalDisposition: B25B_TERMINAL_DISPOSITION.LOSING_OUTSIDE_BATCH });
      localTerminalChanged = true;
    }
    let transition = null;
    let nextHead = head;
    let safeSuccessor = null;
    if (selectedDigest !== null) {
      safeSuccessor = parseRetainedState(successorRetained);
      transition = buildTransition({
        groupIdHex: head.groupIdHex, seq: head.seq + 1, kind: 'RESOLVE',
        priorHeadDigestHex: head.headDigestHex, batchDigestHex: batch.protocolBatchDigestHex,
        winnerCommitDigestHex: selectedDigest,
        snapshotDigestHex: safeSuccessor.snapshotDigestHex,
        epochDec: safeSuccessor.epochDec,
        groupContextDigestHex: safeSuccessor.groupContextDigestHex,
        outcomesDigestHex: outcomesDigest(outcomes),
      });
      nextHead = buildHead({
        groupIdHex: head.groupIdHex, accountKeyHex: head.accountKeyHex,
        signatureKeyHex: head.signatureKeyHex, seq: head.seq + 1,
        state: B25B_HEAD_STATE.STABLE, epochDec: safeSuccessor.epochDec,
        groupContextDigestHex: safeSuccessor.groupContextDigestHex,
        snapshotDigestHex: safeSuccessor.snapshotDigestHex,
        priorHeadDigestHex: head.headDigestHex,
        transitionDigestHex: transition.transitionDigestHex,
        selectedCommitDigestHex: selectedDigest,
      });
    }

    await this.#db.transaction(B25B_STORE_NAMES, async (ops) => {
      const currentHead = parseHead(await getRequired(
        ops, B25B_STORES.head, head.groupIdHex, 'canonical head',
      ));
      if (!sameHead(currentHead, head)) failB25B(B25B_ERROR.CAS_CONFLICT, 'canonical head changed');
      const currentTransition = parseTransition(await getRequired(
        ops, B25B_STORES.transition, currentHead.transitionDigestHex, 'canonical transition',
      ));
      if (currentTransition.groupIdHex !== currentHead.groupIdHex
        || currentTransition.seq !== currentHead.seq
        || currentTransition.snapshotDigestHex !== currentHead.snapshotDigestHex
        || currentTransition.epochDec !== currentHead.epochDec
        || currentTransition.groupContextDigestHex !== currentHead.groupContextDigestHex) {
        failB25B(B25B_ERROR.CORRUPT, 'canonical transition changed before resolution');
      }
      const currentBatch = parseBatch(await getRequired(
        ops, B25B_STORES.batch, batch.protocolBatchDigestHex, 'frozen batch',
      ));
      if (currentBatch.batchRecordDigestHex !== batch.batchRecordDigestHex) {
        failB25B(B25B_ERROR.CAS_CONFLICT, 'frozen batch changed before resolution');
      }
      const parent = parseRetainedState(await getRequired(
        ops, B25B_STORES.retained, currentHead.snapshotDigestHex, 'retained parent',
      ));
      let currentLocal = null;
      if (safeLocal !== null) {
        currentLocal = parseLocal(await getRequired(ops, B25B_STORES.local,
          localKey(head.groupIdHex), 'frozen local pending'));
        if (currentLocal.localPendingDigestHex !== safeLocal.localPendingDigestHex) {
          failB25B(B25B_ERROR.CAS_CONFLICT, 'local pending changed before resolution');
        }
        const publicationKeys = (await ops.list(B25B_STORES.publication))
          .filter((key) => typeof key === 'string' && key.startsWith(`${head.groupIdHex}:`));
        let acknowledged = false;
        for (const key of publicationKeys) {
          const evidence = parsePublication(await getRequired(ops, B25B_STORES.publication,
            key, 'publication evidence'));
          if (evidence.kind === B25B_PUBLICATION_KIND.ACK
            && evidence.artifactDigestHex === safeLocal.commitDigestHex
            && bytesEqual(evidence.artifactBytes, safeLocal.commitBytes)) acknowledged = true;
        }
        if (localDigest !== null && !acknowledged) {
          failB25B(B25B_ERROR.CORRUPT, 'frozen local candidate lacks durable acknowledgement');
        }
      } else if (await ops.get(B25B_STORES.local, localKey(head.groupIdHex)) !== undefined) {
        failB25B(B25B_ERROR.CAS_CONFLICT,
          'local pending appeared after the frozen decision read-set');
      }
      const currentInputs = [];
      const currentCandidates = [];
      for (let index = 0; index < batch.commitDigests.length; index += 1) {
        const digest = batch.commitDigests[index];
        const currentCandidate = parseCandidateEvidence(await getRequired(
          ops, B25B_STORES.candidate, candidateKey(batch.protocolBatchDigestHex, digest),
          'candidate placeholder',
        ));
        currentCandidates.push(currentCandidate);
        if (digest !== localDigest) {
          const currentInput = parseInput(await getRequired(
            ops, B25B_STORES.input, inputKey(head.groupIdHex, digest), 'decision input',
          ));
          currentInputs.push(currentInput);
          if (!sameInput(currentInput, inputByDigest.get(digest))) {
            failB25B(B25B_ERROR.CAS_CONFLICT, 'decision input changed before resolution');
          }
        }
        if (!sameCandidate(currentCandidate, safePending[index])) {
          failB25B(B25B_ERROR.CAS_CONFLICT, 'decision read-set changed before resolution');
        }
      }
      validateFrozenBundle({ head: currentHead, batch: currentBatch, retained: parent,
        inputs: currentInputs, candidates: currentCandidates, local: currentLocal });
      const writes = [];
      for (let index = 0; index < safeCandidates.length; index += 1) {
        const candidate = safeCandidates[index];
        const outcome = outcomes[index];
        writes.push(ops.put(B25B_STORES.candidate,
          candidateKey(batch.protocolBatchDigestHex, candidate.commitDigestHex), candidate));
        if (candidate.commitDigestHex !== localDigest) {
          const currentInput = inputByDigest.get(candidate.commitDigestHex);
          const resolvedInput = buildInput({
            groupIdHex: head.groupIdHex, batchDigestHex: batch.protocolBatchDigestHex,
            commitBytes: currentInput.commitBytes, disposition: outcome.disposition,
          });
          writes.push(ops.put(B25B_STORES.input,
            inputKey(head.groupIdHex, candidate.commitDigestHex), resolvedInput));
        }
      }
      writes.push(ops.put(B25B_STORES.batch, batch.protocolBatchDigestHex, resolvedBatch));
      if (terminalLocal !== null && localTerminalChanged) {
        writes.push(ops.put(B25B_STORES.local, localKey(head.groupIdHex), terminalLocal));
      }
      if (safeSuccessor !== null) {
        const existingState = await ops.get(B25B_STORES.retained, safeSuccessor.snapshotDigestHex);
        if (existingState !== undefined
          && parseRetainedState(existingState).retainedDigestHex !== safeSuccessor.retainedDigestHex) {
          failB25B(B25B_ERROR.CORRUPT, 'retained-state content-address collision');
        }
        if (await ops.get(B25B_STORES.transition, transition.transitionDigestHex) !== undefined) {
          failB25B(B25B_ERROR.CAS_CONFLICT, 'transition identifier already exists');
        }
        writes.push(ops.put(B25B_STORES.retained, safeSuccessor.snapshotDigestHex, safeSuccessor));
        writes.push(ops.put(B25B_STORES.transition, transition.transitionDigestHex, transition));
        writes.push(ops.put(B25B_STORES.head, head.groupIdHex, nextHead));
      }
      await Promise.all(writes);
    });
    return Object.freeze({ head: nextHead, batch: resolvedBatch, transition,
      retained: safeSuccessor, candidates: Object.freeze(safeCandidates),
      outcomes: Object.freeze(outcomes), local: terminalLocal });
  }

  async readResolved(batchDigestHex) {
    assertHex64('batchDigestHex', batchDigestHex);
    return this.#db.transaction(B25B_STORE_NAMES, async (ops) => {
      const batch = parseBatch(await getRequired(ops, B25B_STORES.batch, batchDigestHex, 'batch'));
      if (batch.state !== B25B_BATCH_STATE.RESOLVED) {
        failB25B(B25B_ERROR.STATE_CONFLICT, 'batch has not resolved');
      }
      const candidates = [];
      for (const digest of batch.commitDigests) candidates.push(parseCandidateEvidence(
        await getRequired(ops, B25B_STORES.candidate, candidateKey(batchDigestHex, digest),
          'resolved candidate'),
      ));
      const currentHead = parseHead(await getRequired(
        ops, B25B_STORES.head, batch.groupIdHex, 'canonical head',
      ));
      if (batch.winnerCommitDigestHex === null) {
        const history = await readGroupTransitionHistory(ops, currentHead);
        if (history.some((item) =>
          item.transition.batchDigestHex === batch.protocolBatchDigestHex)) {
          failB25B(B25B_ERROR.CORRUPT, 'null-winner batch has a successor transition');
        }
        if (currentHead.headDigestHex === batch.localBaseHeadDigestHex) {
          return Object.freeze({
            head: currentHead, batch, transition: null, retained: null, candidates,
          });
        }
        const matches = history.filter((item) =>
          item.head.headDigestHex === batch.localBaseHeadDigestHex);
        if (matches.length !== 1) {
          failB25B(B25B_ERROR.CORRUPT, 'null-winner base head is absent or ambiguous');
        }
        return Object.freeze({
          head: matches[0].head, batch, transition: null, retained: null, candidates,
        });
      }
      let head = currentHead;
      let transition;
      if (head.selectedCommitDigestHex === batch.winnerCommitDigestHex
        && head.priorHeadDigestHex === batch.localBaseHeadDigestHex) {
        transition = parseTransition(await getRequired(
          ops, B25B_STORES.transition, head.transitionDigestHex, 'resolution transition',
        ));
      } else {
        const history = await readGroupTransitionHistory(ops, currentHead);
        const matches = history.filter((item) => item.transition.kind === 'RESOLVE'
          && item.transition.batchDigestHex === batch.protocolBatchDigestHex
          && item.transition.winnerCommitDigestHex === batch.winnerCommitDigestHex
          && item.transition.priorHeadDigestHex === batch.localBaseHeadDigestHex);
        if (matches.length !== 1) {
          failB25B(B25B_ERROR.CORRUPT, 'resolved winner transition is absent or ambiguous');
        }
        ({ head, transition } = matches[0]);
      }
      if (transition.kind !== 'RESOLVE'
        || transition.batchDigestHex !== batch.protocolBatchDigestHex
        || transition.winnerCommitDigestHex !== batch.winnerCommitDigestHex
        || transition.priorHeadDigestHex !== batch.localBaseHeadDigestHex
        || transition.outcomesDigestHex !== outcomesDigest(batch.outcomes)
        || head.transitionDigestHex !== transition.transitionDigestHex) {
        failB25B(B25B_ERROR.CORRUPT, 'resolved winner does not bind its historical head');
      }
      const retained = parseRetainedState(await getRequired(
        ops, B25B_STORES.retained, head.snapshotDigestHex, 'successor retained state',
      ));
      return Object.freeze({ head, batch, transition, retained, candidates });
    });
  }

  createEngineAdapter({ wasm, beforeCandidate = async () => {} } = {}) {
    return createBoundB25BEngineAdapter({
      wasm,
      journal: this,
      initializeJournal: this.#initialize.bind(this),
      commitPrepared: this.#commitPrepared.bind(this),
      appendPublication: this.#appendPublication.bind(this),
      replaceLocal: this.#replaceLocal.bind(this),
      commitResolution: this.#commitResolution.bind(this),
      beforeCandidate,
    });
  }

  close() { this.#db.close?.(); }

  destroy() { return this.#db.destroy(); }
}

export function createB25BJournalForDb(db) {
  if (typeof db?.name !== 'string' || !db.name.startsWith(B25B_DB_PREFIX)) {
    failB25B(B25B_ERROR.INVALID, 'database is outside the B2.5b namespace');
  }
  return new B25BJournal(db, JOURNAL_TOKEN);
}

export async function openB25BJournal({
  databaseTag,
  indexedDBImpl = globalThis.indexedDB,
  setTimeoutImpl = globalThis.setTimeout.bind(globalThis),
  clearTimeoutImpl = globalThis.clearTimeout.bind(globalThis),
} = {}) {
  assertString('databaseTag', databaseTag, { min: 1, max: 64, pattern: /^[a-z0-9-]+$/ });
  const db = await openVaultDb({
    name: `${B25B_DB_PREFIX}${databaseTag}`,
    version: 1,
    migrations: { 1: migrationV1 },
    indexedDBImpl,
    setTimeoutImpl,
    clearTimeoutImpl,
  });
  return createB25BJournalForDb(db);
}
