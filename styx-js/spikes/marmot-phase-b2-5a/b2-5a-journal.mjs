// STYX_SPIKE_PROTOTYPE — six-store atomic journal for Phase B2.5a only.

import { openVaultDb } from '../../src/storage/vault-db.js';
import {
  B25_BATCH_STATE,
  B25_CANDIDATE_STATE,
  B25_DB_PREFIX,
  B25_DISPOSITION,
  B25_ERROR,
  B25_HEAD_STATE,
  B25_LIMITS,
  B25_STORES,
  B25_STORE_NAMES,
  assertBytes,
  assertGroupIdHex,
  assertHex64,
  assertString,
  bytesEqual,
  candidateKey,
  compareCandidates,
  copyBytes,
  failB25,
  inputKey,
} from './b2-5a-canonical.mjs';
import {
  buildBatch,
  buildCandidateEvidence,
  buildHead,
  buildInput,
  buildPendingCandidate,
  buildRetainedState,
  buildTransition,
  outcomesDigest,
  parseBatch,
  parseCandidateEvidence,
  parseHead,
  parseInput,
  parseRetainedState,
  parseTransition,
} from './b2-5a-record.mjs';

const JOURNAL_TOKEN = Symbol('B25_JOURNAL_TOKEN');

function migrationV1(db) {
  for (const name of B25_STORE_NAMES) db.createObjectStore(name);
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

async function getRequired(ops, store, key, label) {
  const value = await ops.get(store, key);
  if (value === undefined) failB25(B25_ERROR.CORRUPT, `${label} is missing`);
  return value;
}

async function listGroupInputs(ops, groupIdHex) {
  const prefix = `${groupIdHex}:`;
  const keys = (await ops.list(B25_STORES.input))
    .filter((key) => typeof key === 'string' && key.startsWith(prefix)).sort();
  const records = [];
  for (const key of keys) records.push(parseInput(await getRequired(
    ops, B25_STORES.input, key, 'listed input',
  )));
  return records;
}

function validateFrozenBundle({ head, batch, retained, inputs, candidates }) {
  if (batch.state !== B25_BATCH_STATE.FROZEN) {
    failB25(B25_ERROR.STATE_CONFLICT, 'resolution requires a frozen batch');
  }
  if (head.state !== B25_HEAD_STATE.STABLE
    || head.headDigestHex !== batch.localBaseHeadDigestHex
    || head.groupIdHex !== batch.groupIdHex
    || head.epochDec !== batch.baseEpochDec
    || head.groupContextDigestHex !== batch.baseGroupContextDigestHex) {
    failB25(B25_ERROR.CAS_CONFLICT, 'frozen batch no longer binds the canonical base head');
  }
  if (retained.snapshotDigestHex !== head.snapshotDigestHex
    || retained.groupIdHex !== head.groupIdHex
    || retained.epochDec !== head.epochDec
    || retained.groupContextDigestHex !== head.groupContextDigestHex
    || retained.accountKeyHex !== head.accountKeyHex
    || retained.signatureKeyHex !== head.signatureKeyHex) {
    failB25(B25_ERROR.CORRUPT, 'retained parent does not bind the base head');
  }
  if (inputs.length !== batch.commitDigests.length || candidates.length !== inputs.length) {
    failB25(B25_ERROR.CORRUPT, 'frozen batch references an incomplete decision set');
  }
  for (let index = 0; index < batch.commitDigests.length; index += 1) {
    const digest = batch.commitDigests[index];
    const input = inputs[index];
    const candidate = candidates[index];
    if (input.commitDigestHex !== digest || input.groupIdHex !== batch.groupIdHex
      || input.batchDigestHex !== batch.protocolBatchDigestHex
      || input.disposition !== B25_DISPOSITION.FROZEN
      || candidate.commitDigestHex !== digest
      || candidate.batchDigestHex !== batch.protocolBatchDigestHex
      || candidate.groupIdHex !== batch.groupIdHex
      || candidate.state !== B25_CANDIDATE_STATE.PENDING
      || candidate.parentEpochDec !== batch.baseEpochDec
      || candidate.parentGroupContextDigestHex !== batch.baseGroupContextDigestHex) {
      failB25(B25_ERROR.CORRUPT, 'frozen decision record binding is incoherent');
    }
  }
  return { head, batch, retained, inputs, candidates };
}

export class B25Journal {
  #db;

  constructor(db, token) {
    if (token !== JOURNAL_TOKEN) {
      failB25(B25_ERROR.INVALID, 'B2.5a journals must be created by the namespace factory');
    }
    this.#db = db;
    Object.freeze(this);
  }

  async initialize({ groupIdHex, accountKeyHex, signatureKeyHex, epochDec,
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
      state: B25_HEAD_STATE.STABLE, epochDec, groupContextDigestHex,
      snapshotDigestHex: retained.snapshotDigestHex, priorHeadDigestHex: null,
      transitionDigestHex: transition.transitionDigestHex,
      selectedCommitDigestHex: null,
    });
    await this.#db.transaction(B25_STORE_NAMES, async (ops) => {
      for (const store of B25_STORE_NAMES) {
        if ((await ops.list(store)).length !== 0) {
          failB25(B25_ERROR.CAS_CONFLICT, 'private one-group B2.5a journal is not empty');
        }
      }
      await Promise.all([
        ops.put(B25_STORES.retained, retained.snapshotDigestHex, retained),
        ops.put(B25_STORES.transition, transition.transitionDigestHex, transition),
        ops.put(B25_STORES.head, groupIdHex, head),
      ]);
    });
    return head;
  }

  async readHead(groupIdHex) {
    assertGroupIdHex(groupIdHex);
    return this.#db.transaction(B25_STORE_NAMES, async (ops) => {
      const head = parseHead(await getRequired(ops, B25_STORES.head, groupIdHex, 'canonical head'));
      const transition = parseTransition(await getRequired(
        ops, B25_STORES.transition, head.transitionDigestHex, 'canonical transition',
      ));
      const rawRetained = await ops.get(B25_STORES.retained, head.snapshotDigestHex);
      if (rawRetained === undefined && head.state !== B25_HEAD_STATE.UNRECOVERABLE) {
        failB25(B25_ERROR.CORRUPT, 'canonical retained state is missing');
      }
      const retained = rawRetained === undefined ? null : parseRetainedState(rawRetained);
      if (transition.groupIdHex !== head.groupIdHex || transition.seq !== head.seq
        || transition.snapshotDigestHex !== head.snapshotDigestHex
        || transition.epochDec !== head.epochDec
        || transition.groupContextDigestHex !== head.groupContextDigestHex) {
        failB25(B25_ERROR.CORRUPT, 'head, retained state and transition are incoherent');
      }
      if (head.state === B25_HEAD_STATE.UNRECOVERABLE
        && transition.kind !== B25_HEAD_STATE.UNRECOVERABLE) {
        failB25(B25_ERROR.CORRUPT, 'unrecoverable head lacks its terminal transition');
      }
      return { head, retained, transition };
    });
  }

  async retainCommit(groupIdHex, commitBytes) {
    assertGroupIdHex(groupIdHex);
    assertBytes('Commit bytes', commitBytes, { min: 1, max: B25_LIMITS.maxCommitBytes });
    const proposed = buildInput({ groupIdHex, commitBytes });
    return this.#db.transaction(B25_STORE_NAMES, async (ops) => {
      const head = parseHead(await getRequired(ops, B25_STORES.head, groupIdHex, 'canonical head'));
      if (head.state !== B25_HEAD_STATE.STABLE) {
        failB25(B25_ERROR.STATE_CONFLICT, 'Commit collection requires a stable head');
      }
      const key = inputKey(groupIdHex, proposed.commitDigestHex);
      const raw = await ops.get(B25_STORES.input, key);
      if (raw !== undefined) {
        const existing = parseInput(raw);
        if (!bytesEqual(existing.commitBytes, proposed.commitBytes)) {
          failB25(B25_ERROR.CORRUPT, 'Commit digest collision at the storage boundary');
        }
        return Object.freeze({ status: 'duplicate', input: existing });
      }
      const collected = (await listGroupInputs(ops, groupIdHex))
        .filter((item) => item.batchDigestHex === null);
      if (collected.length >= B25_LIMITS.maxBatchCommits) {
        failB25(B25_ERROR.RESOURCE_LIMIT, 'unfrozen Commit input cap is exhausted');
      }
      await ops.put(B25_STORES.input, key, proposed);
      return Object.freeze({ status: 'retained', input: proposed });
    });
  }

  async freeze(groupIdHex) {
    assertGroupIdHex(groupIdHex);
    return this.#db.transaction(B25_STORE_NAMES, async (ops) => {
      const head = parseHead(await getRequired(ops, B25_STORES.head, groupIdHex, 'canonical head'));
      if (head.state !== B25_HEAD_STATE.STABLE) {
        failB25(B25_ERROR.STATE_CONFLICT, 'batch freeze requires a stable head');
      }
      const unresolvedKeys = await ops.list(B25_STORES.batch);
      for (const key of unresolvedKeys) {
        const prior = parseBatch(await getRequired(ops, B25_STORES.batch, key, 'listed batch'));
        if (prior.groupIdHex === groupIdHex && prior.state === B25_BATCH_STATE.FROZEN) {
          failB25(B25_ERROR.STATE_CONFLICT, 'a frozen batch already awaits resolution');
        }
      }
      const collected = (await listGroupInputs(ops, groupIdHex))
        .filter((item) => item.batchDigestHex === null)
        .sort((left, right) => left.commitDigestHex.localeCompare(right.commitDigestHex));
      if (collected.length === 0) failB25(B25_ERROR.STATE_CONFLICT, 'cannot freeze an empty batch');
      const batch = buildBatch({
        groupIdHex, baseEpochDec: head.epochDec,
        baseGroupContextDigestHex: head.groupContextDigestHex,
        localBaseHeadDigestHex: head.headDigestHex,
        commitDigests: collected.map((item) => item.commitDigestHex),
        state: B25_BATCH_STATE.FROZEN, winnerCommitDigestHex: null, outcomes: [],
      });
      if (await ops.get(B25_STORES.batch, batch.protocolBatchDigestHex) !== undefined) {
        failB25(B25_ERROR.CAS_CONFLICT, 'protocol batch identifier already exists');
      }
      const writes = [ops.put(B25_STORES.batch, batch.protocolBatchDigestHex, batch)];
      for (const input of collected) {
        const frozen = buildInput({
          groupIdHex, batchDigestHex: batch.protocolBatchDigestHex,
          commitBytes: input.commitBytes, disposition: B25_DISPOSITION.FROZEN,
        });
        const pending = buildPendingCandidate({
          groupIdHex, batchDigestHex: batch.protocolBatchDigestHex,
          commitDigestHex: input.commitDigestHex, parentEpochDec: head.epochDec,
          parentGroupContextDigestHex: head.groupContextDigestHex,
        });
        const candidateStoreKey = candidateKey(batch.protocolBatchDigestHex, input.commitDigestHex);
        if (await ops.get(B25_STORES.candidate, candidateStoreKey) !== undefined) {
          failB25(B25_ERROR.CAS_CONFLICT, 'candidate placeholder already exists');
        }
        writes.push(ops.put(B25_STORES.input, inputKey(groupIdHex, input.commitDigestHex), frozen));
        writes.push(ops.put(B25_STORES.candidate, candidateStoreKey, pending));
      }
      await Promise.all(writes);
      return batch;
    });
  }

  async readFrozen(batchDigestHex) {
    assertHex64('batchDigestHex', batchDigestHex);
    const result = await this.#db.transaction(B25_STORE_NAMES, async (ops) => {
      const batch = parseBatch(await getRequired(ops, B25_STORES.batch, batchDigestHex, 'frozen batch'));
      const head = parseHead(await getRequired(ops, B25_STORES.head, batch.groupIdHex, 'canonical head'));
      const rawRetained = await ops.get(B25_STORES.retained, head.snapshotDigestHex);
      if (rawRetained === undefined) {
        if (head.state === B25_HEAD_STATE.UNRECOVERABLE) {
          return Object.freeze({ unrecoverable: true, head, batch });
        }
        if (batch.state !== B25_BATCH_STATE.FROZEN
          || head.state !== B25_HEAD_STATE.STABLE
          || head.headDigestHex !== batch.localBaseHeadDigestHex
          || head.epochDec !== batch.baseEpochDec
          || head.groupContextDigestHex !== batch.baseGroupContextDigestHex) {
          failB25(B25_ERROR.CORRUPT, 'missing retained state has an incoherent frozen base');
        }
        const transition = buildTransition({
          groupIdHex: head.groupIdHex, seq: head.seq + 1, kind: B25_HEAD_STATE.UNRECOVERABLE,
          priorHeadDigestHex: head.headDigestHex, batchDigestHex,
          winnerCommitDigestHex: null, snapshotDigestHex: head.snapshotDigestHex,
          epochDec: head.epochDec, groupContextDigestHex: head.groupContextDigestHex,
          outcomesDigestHex: null,
        });
        const terminalHead = buildHead({
          groupIdHex: head.groupIdHex, accountKeyHex: head.accountKeyHex,
          signatureKeyHex: head.signatureKeyHex, seq: head.seq + 1,
          state: B25_HEAD_STATE.UNRECOVERABLE, epochDec: head.epochDec,
          groupContextDigestHex: head.groupContextDigestHex,
          snapshotDigestHex: head.snapshotDigestHex, priorHeadDigestHex: head.headDigestHex,
          transitionDigestHex: transition.transitionDigestHex, selectedCommitDigestHex: null,
        });
        await Promise.all([
          ops.put(B25_STORES.transition, transition.transitionDigestHex, transition),
          ops.put(B25_STORES.head, head.groupIdHex, terminalHead),
        ]);
        return Object.freeze({ unrecoverable: true, head: terminalHead, batch });
      }
      const retained = parseRetainedState(rawRetained);
      const inputs = [];
      const candidates = [];
      for (const digest of batch.commitDigests) {
        inputs.push(parseInput(await getRequired(
          ops, B25_STORES.input, inputKey(batch.groupIdHex, digest), 'batch input',
        )));
        candidates.push(parseCandidateEvidence(await getRequired(
          ops, B25_STORES.candidate, candidateKey(batchDigestHex, digest), 'candidate placeholder',
        )));
      }
      return validateFrozenBundle({ head, batch, retained, inputs, candidates });
    });
    if (result.unrecoverable === true) {
      failB25(B25_ERROR.UNRECOVERABLE, 'retained parent state is missing', {
        batchDigestHex, snapshotDigestHex: result.head.snapshotDigestHex,
      });
    }
    return result;
  }

  async commitResolution({ expectedHead, frozenBatch, expectedInputs,
    expectedCandidates, candidates, successorRetained }) {
    const head = parseHead(expectedHead);
    const batch = parseBatch(frozenBatch);
    if (batch.state !== B25_BATCH_STATE.FROZEN || batch.localBaseHeadDigestHex !== head.headDigestHex) {
      failB25(B25_ERROR.INVALID, 'resolution does not bind the frozen base');
    }
    if (!Array.isArray(expectedInputs) || !Array.isArray(expectedCandidates)
      || !Array.isArray(candidates) || candidates.length !== batch.commitDigests.length
      || expectedInputs.length !== candidates.length || expectedCandidates.length !== candidates.length) {
      failB25(B25_ERROR.INVALID, 'resolution decision set has an invalid count');
    }
    const safeInputs = expectedInputs.map(parseInput);
    const safePending = expectedCandidates.map(parseCandidateEvidence);
    const safeCandidates = candidates.map(parseCandidateEvidence)
      .sort((left, right) => left.commitDigestHex.localeCompare(right.commitDigestHex));
    for (let index = 0; index < batch.commitDigests.length; index += 1) {
      const digest = batch.commitDigests[index];
      const input = safeInputs[index];
      const pending = safePending[index];
      const candidate = safeCandidates[index];
      if (input.commitDigestHex !== digest || input.groupIdHex !== batch.groupIdHex
        || input.batchDigestHex !== batch.protocolBatchDigestHex
        || input.disposition !== B25_DISPOSITION.FROZEN
        || pending.commitDigestHex !== digest || pending.groupIdHex !== batch.groupIdHex
        || pending.batchDigestHex !== batch.protocolBatchDigestHex
        || pending.state !== B25_CANDIDATE_STATE.PENDING
        || candidate.commitDigestHex !== digest || candidate.groupIdHex !== batch.groupIdHex
        || candidate.batchDigestHex !== batch.protocolBatchDigestHex
        || candidate.parentEpochDec !== batch.baseEpochDec
        || candidate.parentGroupContextDigestHex !== batch.baseGroupContextDigestHex
        || candidate.state === B25_CANDIDATE_STATE.PENDING) {
        failB25(B25_ERROR.INVALID, 'resolution evidence does not bind the frozen decision set');
      }
    }
    // Candidate records intentionally do not carry mutable disposition. The journal
    // independently derives the canonical winner rather than trusting its caller.
    const authorized = safeCandidates
      .filter((item) => item.state === B25_CANDIDATE_STATE.AUTHORIZED)
      .sort(compareCandidates);
    const winnerRecord = authorized[0] ?? null;
    if ((successorRetained === null) !== (winnerRecord === null)) {
      failB25(B25_ERROR.INVALID, 'successor presence differs from the canonical decision');
    }
    if (successorRetained !== null) {
      const successor = parseRetainedState(successorRetained);
      if (winnerRecord.candidateEpochDec !== successor.epochDec
        || winnerRecord.candidateGroupContextDigestHex !== successor.groupContextDigestHex
        || successor.groupIdHex !== head.groupIdHex
        || successor.accountKeyHex !== head.accountKeyHex
        || successor.signatureKeyHex !== head.signatureKeyHex) {
        failB25(B25_ERROR.INVALID, 'successor does not bind the canonical candidate');
      }
    }
    const selectedDigest = winnerRecord?.commitDigestHex ?? null;
    const outcomes = safeCandidates.map((candidate) => {
      let disposition;
      if (candidate.state === B25_CANDIDATE_STATE.AUTHORIZED) {
        disposition = candidate.commitDigestHex === selectedDigest
          ? B25_DISPOSITION.SELECTED : B25_DISPOSITION.LOSING;
      } else if (candidate.state === B25_CANDIDATE_STATE.REJECTED) disposition = B25_DISPOSITION.REJECTED;
      else if (candidate.state === B25_CANDIDATE_STATE.NOT_CANDIDATE) {
        disposition = B25_DISPOSITION.NOT_CANDIDATE;
      } else failB25(B25_ERROR.STATE_CONFLICT, 'pending candidate cannot be resolved');
      return Object.freeze({ commitDigestHex: candidate.commitDigestHex, disposition,
        candidateEvidenceDigestHex: candidate.evidenceDigestHex });
    });
    const resolvedBatch = buildBatch({
      groupIdHex: batch.groupIdHex, baseEpochDec: batch.baseEpochDec,
      baseGroupContextDigestHex: batch.baseGroupContextDigestHex,
      localBaseHeadDigestHex: batch.localBaseHeadDigestHex,
      commitDigests: batch.commitDigests, state: B25_BATCH_STATE.RESOLVED,
      winnerCommitDigestHex: selectedDigest, outcomes,
    });
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
        state: B25_HEAD_STATE.STABLE, epochDec: safeSuccessor.epochDec,
        groupContextDigestHex: safeSuccessor.groupContextDigestHex,
        snapshotDigestHex: safeSuccessor.snapshotDigestHex,
        priorHeadDigestHex: head.headDigestHex,
        transitionDigestHex: transition.transitionDigestHex,
        selectedCommitDigestHex: selectedDigest,
      });
    }

    await this.#db.transaction(B25_STORE_NAMES, async (ops) => {
      const currentHead = parseHead(await getRequired(
        ops, B25_STORES.head, head.groupIdHex, 'canonical head',
      ));
      if (!sameHead(currentHead, head)) failB25(B25_ERROR.CAS_CONFLICT, 'canonical head changed');
      const currentBatch = parseBatch(await getRequired(
        ops, B25_STORES.batch, batch.protocolBatchDigestHex, 'frozen batch',
      ));
      if (currentBatch.batchRecordDigestHex !== batch.batchRecordDigestHex) {
        failB25(B25_ERROR.CAS_CONFLICT, 'frozen batch changed before resolution');
      }
      const parent = parseRetainedState(await getRequired(
        ops, B25_STORES.retained, head.snapshotDigestHex, 'retained parent',
      ));
      const currentInputs = [];
      const currentCandidates = [];
      for (let index = 0; index < batch.commitDigests.length; index += 1) {
        const digest = batch.commitDigests[index];
        const currentInput = parseInput(await getRequired(
          ops, B25_STORES.input, inputKey(head.groupIdHex, digest), 'decision input',
        ));
        const currentCandidate = parseCandidateEvidence(await getRequired(
          ops, B25_STORES.candidate, candidateKey(batch.protocolBatchDigestHex, digest),
          'candidate placeholder',
        ));
        currentInputs.push(currentInput);
        currentCandidates.push(currentCandidate);
        if (!sameInput(currentInput, safeInputs[index])
          || !sameCandidate(currentCandidate, safePending[index])) {
          failB25(B25_ERROR.CAS_CONFLICT, 'decision read-set changed before resolution');
        }
      }
      validateFrozenBundle({ head: currentHead, batch: currentBatch, retained: parent,
        inputs: currentInputs, candidates: currentCandidates });
      const writes = [];
      for (let index = 0; index < safeCandidates.length; index += 1) {
        const candidate = safeCandidates[index];
        const outcome = outcomes[index];
        const currentInput = safeInputs[index];
        const resolvedInput = buildInput({
          groupIdHex: head.groupIdHex, batchDigestHex: batch.protocolBatchDigestHex,
          commitBytes: currentInput.commitBytes, disposition: outcome.disposition,
        });
        writes.push(ops.put(B25_STORES.candidate,
          candidateKey(batch.protocolBatchDigestHex, candidate.commitDigestHex), candidate));
        writes.push(ops.put(B25_STORES.input,
          inputKey(head.groupIdHex, candidate.commitDigestHex), resolvedInput));
      }
      writes.push(ops.put(B25_STORES.batch, batch.protocolBatchDigestHex, resolvedBatch));
      if (safeSuccessor !== null) {
        const existingState = await ops.get(B25_STORES.retained, safeSuccessor.snapshotDigestHex);
        if (existingState !== undefined
          && parseRetainedState(existingState).retainedDigestHex !== safeSuccessor.retainedDigestHex) {
          failB25(B25_ERROR.CORRUPT, 'retained-state content-address collision');
        }
        if (await ops.get(B25_STORES.transition, transition.transitionDigestHex) !== undefined) {
          failB25(B25_ERROR.CAS_CONFLICT, 'transition identifier already exists');
        }
        writes.push(ops.put(B25_STORES.retained, safeSuccessor.snapshotDigestHex, safeSuccessor));
        writes.push(ops.put(B25_STORES.transition, transition.transitionDigestHex, transition));
        writes.push(ops.put(B25_STORES.head, head.groupIdHex, nextHead));
      }
      await Promise.all(writes);
    });
    return Object.freeze({ head: nextHead, batch: resolvedBatch, transition,
      retained: safeSuccessor, candidates: Object.freeze(safeCandidates),
      outcomes: Object.freeze(outcomes) });
  }

  async readResolved(batchDigestHex) {
    assertHex64('batchDigestHex', batchDigestHex);
    return this.#db.transaction(B25_STORE_NAMES, async (ops) => {
      const batch = parseBatch(await getRequired(ops, B25_STORES.batch, batchDigestHex, 'batch'));
      if (batch.state !== B25_BATCH_STATE.RESOLVED) {
        failB25(B25_ERROR.STATE_CONFLICT, 'batch has not resolved');
      }
      const candidates = [];
      for (const digest of batch.commitDigests) candidates.push(parseCandidateEvidence(
        await getRequired(ops, B25_STORES.candidate, candidateKey(batchDigestHex, digest),
          'resolved candidate'),
      ));
      const head = parseHead(await getRequired(ops, B25_STORES.head, batch.groupIdHex, 'canonical head'));
      if (batch.winnerCommitDigestHex === null) {
        if (head.headDigestHex !== batch.localBaseHeadDigestHex) {
          failB25(B25_ERROR.CORRUPT, 'null-winner batch changed the canonical head');
        }
        return Object.freeze({ head, batch, transition: null, retained: null, candidates });
      }
      if (head.selectedCommitDigestHex !== batch.winnerCommitDigestHex
        || head.priorHeadDigestHex !== batch.localBaseHeadDigestHex) {
        failB25(B25_ERROR.CORRUPT, 'resolved winner does not bind the canonical head');
      }
      const transition = parseTransition(await getRequired(
        ops, B25_STORES.transition, head.transitionDigestHex, 'resolution transition',
      ));
      const retained = parseRetainedState(await getRequired(
        ops, B25_STORES.retained, head.snapshotDigestHex, 'successor retained state',
      ));
      return Object.freeze({ head, batch, transition, retained, candidates });
    });
  }

  close() { this.#db.close?.(); }

  destroy() { return this.#db.destroy(); }
}

export function createB25JournalForDb(db) {
  if (typeof db?.name !== 'string' || !db.name.startsWith(B25_DB_PREFIX)) {
    failB25(B25_ERROR.INVALID, 'database is outside the B2.5a namespace');
  }
  return new B25Journal(db, JOURNAL_TOKEN);
}

export async function openB25Journal({
  databaseTag,
  indexedDBImpl = globalThis.indexedDB,
  setTimeoutImpl = globalThis.setTimeout.bind(globalThis),
  clearTimeoutImpl = globalThis.clearTimeout.bind(globalThis),
} = {}) {
  assertString('databaseTag', databaseTag, { min: 1, max: 64, pattern: /^[a-z0-9-]+$/ });
  const db = await openVaultDb({
    name: `${B25_DB_PREFIX}${databaseTag}`,
    version: 1,
    migrations: { 1: migrationV1 },
    indexedDBImpl,
    setTimeoutImpl,
    clearTimeoutImpl,
  });
  return createB25JournalForDb(db);
}
