// STYX_SPIKE_PROTOTYPE — private IndexedDB CAS journal for Phase B2.3.

import { openVaultDb } from '../../src/storage/vault-db.js';
import {
  B23_DB_PREFIX,
  B23_ERROR,
  B23_LIMITS,
  B23_RUNTIME,
  B23_STORES,
  B23_STORE_NAMES,
  assertBytes,
  assertGroupIdHex,
  assertHex64,
  assertSafeInteger,
  assertString,
  bytesEqual,
  copyBytes,
  digestHex,
  fail,
  parseEpochDecimal,
  randomHex256,
  snapshotClosedObject,
} from './b2-3-canonical.mjs';
import {
  HEAD_PREPARED,
  HEAD_STABLE,
  buildEvidence,
  buildHead,
  buildTransition,
  canonicalProjectionBytes,
  parseHead,
  parseTransition,
} from './b2-3-record.mjs';

function migrationV1(db) {
  for (const name of B23_STORE_NAMES) db.createObjectStore(name);
}

const ADAPTER_TRANSITION_FIELDS = Object.freeze([
  'kind', 'state', 'epochDec', 'epochDigestHex', 'commitBytes', 'welcomeBytes',
  'projection', 'projectionDigestHex', 'candidateEpochDec',
  'candidateEpochDigestHex', 'verifiedLeafDigestHex', 'artifactId',
  'artifactBytes', 'artifactDigestHex', 'publishAttempts', 'evidenceCount',
  'appliedCommitDigestHex',
]);

const ADAPTER_HEAD_FIELDS = Object.freeze([
  'state', 'epochDec', 'epochDigestHex', 'pendingCommitDigestHex',
  'pendingWelcomeDigestHex', 'candidateEpochDec', 'candidateEpochDigestHex',
  'verifiedLeafDigestHex', 'artifactId', 'artifactDigestHex', 'publishAttempts',
  'evidenceCount', 'lastAppliedCommitDigestHex',
]);

function assertSuccessorEpoch(expected, transition, nextHead) {
  const parentEpoch = parseEpochDecimal(expected.epochDec, 'expectedHead.epochDec');
  const successorEpoch = parseEpochDecimal(nextHead.epochDec, 'nextHead.epochDec');
  if (transition.epochDec !== nextHead.epochDec) {
    fail(B23_ERROR.INVALID, 'head and transition successor epochs differ');
  }
  const advances = transition.kind === 'confirm' || transition.kind === 'inbound-accept';
  const expectedSuccessor = advances ? parentEpoch + 1n : parentEpoch;
  if (successorEpoch !== expectedSuccessor) {
    fail(B23_ERROR.INVALID, advances
      ? 'durable successor must advance exactly one epoch'
      : 'durable successor must retain the parent epoch');
  }
}

function assertBindings(bindings) {
  const safe = snapshotClosedObject(
    bindings, ['groupIdHex', 'accountKeyHex', 'signatureKeyHex'], 'bindings',
  );
  assertGroupIdHex(safe.groupIdHex);
  assertHex64('accountKeyHex', safe.accountKeyHex);
  assertHex64('signatureKeyHex', safe.signatureKeyHex);
  return safe;
}

function transitionPayloadFrom(record) {
  return {
    commitBytes: copyBytes(record.commitBytes),
    welcomeBytes: copyBytes(record.welcomeBytes),
    projection: record.projection,
    projectionDigestHex: record.projectionDigestHex,
    candidateEpochDec: record.candidateEpochDec,
    candidateEpochDigestHex: record.candidateEpochDigestHex,
    verifiedLeafDigestHex: record.verifiedLeafDigestHex,
    artifactId: record.artifactId,
    artifactBytes: copyBytes(record.artifactBytes),
    artifactDigestHex: record.artifactDigestHex,
    publishAttempts: record.publishAttempts,
    evidenceCount: record.evidenceCount,
    appliedCommitDigestHex: record.appliedCommitDigestHex,
  };
}

function headPendingFieldsFromTransition(transition) {
  return {
    pendingCommitDigestHex: digestHex(transition.commitBytes),
    pendingWelcomeDigestHex: transition.welcomeBytes === null ? null : digestHex(transition.welcomeBytes),
    candidateEpochDec: transition.candidateEpochDec,
    candidateEpochDigestHex: transition.candidateEpochDigestHex,
    verifiedLeafDigestHex: transition.verifiedLeafDigestHex,
    artifactId: transition.artifactId,
    artifactDigestHex: transition.artifactDigestHex,
    publishAttempts: transition.publishAttempts,
    evidenceCount: transition.evidenceCount,
  };
}

function stableFields() {
  return {
    pendingCommitDigestHex: null,
    pendingWelcomeDigestHex: null,
    candidateEpochDec: null,
    candidateEpochDigestHex: null,
    verifiedLeafDigestHex: null,
    artifactId: null,
    artifactDigestHex: null,
    publishAttempts: 0,
    evidenceCount: 0,
  };
}

function assertBundleCoherence(head, transition, snapshotBytes) {
  if (transition.idHex !== head.transitionIdHex || transition.groupIdHex !== head.groupIdHex
    || transition.seq !== head.seq || transition.state !== head.state
    || transition.epochDec !== head.epochDec || transition.epochDigestHex !== head.epochDigestHex
    || transition.snapshotKeyHex !== head.snapshotKeyHex
    || transition.priorHeadDigestHex !== head.priorHeadDigestHex) {
    fail(B23_ERROR.CORRUPT, 'head and transition do not describe the same durable successor');
  }
  assertBytes('snapshotBytes', snapshotBytes, { min: 1, max: B23_LIMITS.maxSnapshotBytes });
  if (snapshotBytes.length !== head.snapshotBytes || digestHex(snapshotBytes) !== head.snapshotKeyHex) {
    fail(B23_ERROR.CORRUPT, 'referenced snapshot does not match the head');
  }
  if (head.state === HEAD_PREPARED) {
    const pending = headPendingFieldsFromTransition(transition);
    for (const [key, value] of Object.entries(pending)) {
      if (head[key] !== value) fail(B23_ERROR.CORRUPT, 'prepared head and transition are incoherent');
    }
  } else if (transition.kind === 'initialize' && head.lastAppliedCommitDigestHex !== null) {
    fail(B23_ERROR.CORRUPT, 'initial head contains an applied Commit identity');
  } else if ((transition.kind === 'confirm' || transition.kind === 'inbound-accept')
    && head.lastAppliedCommitDigestHex !== transition.appliedCommitDigestHex) {
    fail(B23_ERROR.CORRUPT, 'stable successor and transition applied-Commit identity differ');
  }
}

export class B23Journal {
  constructor(db, { randomBytes = globalThis.crypto?.getRandomValues?.bind(globalThis.crypto) } = {}) {
    this.db = db;
    this.randomBytes = randomBytes;
  }

  async initialize({ bindings, snapshotBytes, epochDec, epochDigestHex }) {
    const safeBindings = assertBindings(bindings);
    assertBytes('snapshotBytes', snapshotBytes, { min: 1, max: B23_LIMITS.maxSnapshotBytes });
    assertHex64('epochDigestHex', epochDigestHex);
    const snapshot = copyBytes(snapshotBytes);
    const snapshotKeyHex = digestHex(snapshot);
    const transitionIdHex = randomHex256(this.randomBytes);
    const transition = buildTransition({
      idHex: transitionIdHex,
      kind: 'initialize',
      groupIdHex: safeBindings.groupIdHex,
      seq: 1,
      priorHeadDigestHex: null,
      state: HEAD_STABLE,
      epochDec,
      epochDigestHex,
      snapshotKeyHex,
      commitBytes: null,
      welcomeBytes: null,
      projection: null,
      projectionDigestHex: null,
      candidateEpochDec: null,
      candidateEpochDigestHex: null,
      verifiedLeafDigestHex: null,
      artifactId: null,
      artifactBytes: null,
      artifactDigestHex: null,
      publishAttempts: 0,
      evidenceCount: 0,
      appliedCommitDigestHex: null,
    });
    const head = buildHead({
      ...safeBindings,
      seq: 1,
      state: HEAD_STABLE,
      epochDec,
      epochDigestHex,
      snapshotKeyHex,
      snapshotBytes: snapshot.length,
      transitionIdHex,
      priorHeadDigestHex: null,
      ...stableFields(),
      lastAppliedCommitDigestHex: null,
    });

    await this.db.transaction(B23_STORE_NAMES, async (ops) => {
      const existingHeads = await ops.list(B23_STORES.head);
      const existingSnapshots = await ops.list(B23_STORES.snapshot);
      const existingTransitions = await ops.list(B23_STORES.transition);
      const existingEvidence = await ops.list(B23_STORES.evidence);
      if (existingHeads.length !== 0 || existingSnapshots.length !== 0
        || existingTransitions.length !== 0 || existingEvidence.length !== 0) {
        fail(B23_ERROR.CAS_CONFLICT, 'private one-group journal is not empty');
      }
      if (await ops.get(B23_STORES.transition, transitionIdHex) !== undefined) {
        fail(B23_ERROR.CAS_CONFLICT, 'transition identifier already exists');
      }
      await Promise.all([
        ops.put(B23_STORES.snapshot, snapshotKeyHex, snapshot),
        ops.put(B23_STORES.transition, transitionIdHex, transition),
        ops.put(B23_STORES.head, safeBindings.groupIdHex, head),
      ]);
    });
    return head;
  }

  async read(groupIdHex) {
    assertGroupIdHex(groupIdHex);
    return this.db.transaction(B23_STORE_NAMES, async (ops) => {
      const rawHead = await ops.get(B23_STORES.head, groupIdHex);
      if (rawHead === undefined) fail(B23_ERROR.NOT_FOUND, 'group head is absent');
      const head = parseHead(rawHead);
      const rawSnapshot = await ops.get(B23_STORES.snapshot, head.snapshotKeyHex);
      if (rawSnapshot === undefined) fail(B23_ERROR.CORRUPT, 'head references a missing snapshot');
      const snapshotKeys = await ops.list(B23_STORES.snapshot);
      if (snapshotKeys.length !== 1 || snapshotKeys[0] !== head.snapshotKeyHex) {
        fail(B23_ERROR.CORRUPT, 'snapshot store contains an orphan or split canonical snapshot');
      }
      const rawTransition = await ops.get(B23_STORES.transition, head.transitionIdHex);
      if (rawTransition === undefined) fail(B23_ERROR.CORRUPT, 'head references a missing transition');
      const transition = parseTransition(rawTransition);
      const snapshotBytes = copyBytes(rawSnapshot);
      assertBundleCoherence(head, transition, snapshotBytes);
      return { head, transition, snapshotBytes };
    });
  }

  async cas({ expectedHead, snapshotBytes, transitionFields, headFields, evidence = [] }) {
    const expected = parseHead(expectedHead);
    const safeTransitionFields = snapshotClosedObject(
      transitionFields, ADAPTER_TRANSITION_FIELDS, 'adapter transition fields',
    );
    const safeHeadFields = snapshotClosedObject(
      headFields, ADAPTER_HEAD_FIELDS, 'adapter head fields',
    );
    assertBytes('snapshotBytes', snapshotBytes, { min: 1, max: B23_LIMITS.maxSnapshotBytes });
    if (!Array.isArray(evidence) || evidence.length > B23_LIMITS.maxEvidence) {
      fail(B23_ERROR.INVALID, 'evidence batch is invalid');
    }
    const snapshot = copyBytes(snapshotBytes);
    const snapshotKeyHex = digestHex(snapshot);
    const seq = expected.seq + 1;
    assertSafeInteger('next seq', seq, 2);
    const transitionIdHex = randomHex256(this.randomBytes);
    const transition = buildTransition({
      ...safeTransitionFields,
      idHex: transitionIdHex,
      groupIdHex: expected.groupIdHex,
      seq,
      priorHeadDigestHex: expected.headDigestHex,
      snapshotKeyHex,
    });
    const nextHead = buildHead({
      ...safeHeadFields,
      groupIdHex: expected.groupIdHex,
      accountKeyHex: expected.accountKeyHex,
      signatureKeyHex: expected.signatureKeyHex,
      seq,
      snapshotKeyHex,
      snapshotBytes: snapshot.length,
      transitionIdHex,
      priorHeadDigestHex: expected.headDigestHex,
    });
    assertSuccessorEpoch(expected, transition, nextHead);
    const evidenceRecords = evidence.map((item) => buildEvidence({
      idHex: randomHex256(this.randomBytes),
      groupIdHex: expected.groupIdHex,
      transitionIdHex,
      artifactDigestHex: transition.artifactDigestHex,
      payload: item,
      payloadDigestHex: digestHex(item),
    }));

    await this.db.transaction(B23_STORE_NAMES, async (ops) => {
      const rawCurrent = await ops.get(B23_STORES.head, expected.groupIdHex);
      if (rawCurrent === undefined) fail(B23_ERROR.CAS_CONFLICT, 'canonical head disappeared');
      const current = parseHead(rawCurrent);
      if (current.seq !== expected.seq || current.headDigestHex !== expected.headDigestHex) {
        fail(B23_ERROR.CAS_CONFLICT, 'canonical head changed before commit');
      }
      if (await ops.get(B23_STORES.transition, transitionIdHex) !== undefined) {
        fail(B23_ERROR.CAS_CONFLICT, 'transition identifier collision');
      }
      const existingSnapshot = await ops.get(B23_STORES.snapshot, snapshotKeyHex);
      if (existingSnapshot !== undefined && !bytesEqual(existingSnapshot, snapshot)) {
        fail(B23_ERROR.CORRUPT, 'snapshot content-address collision');
      }
      for (const record of evidenceRecords) {
        if (await ops.get(B23_STORES.evidence, record.idHex) !== undefined) {
          fail(B23_ERROR.CAS_CONFLICT, 'evidence identifier collision');
        }
      }
      const writes = [];
      if (existingSnapshot === undefined) writes.push(ops.put(B23_STORES.snapshot, snapshotKeyHex, snapshot));
      writes.push(ops.put(B23_STORES.transition, transitionIdHex, transition));
      for (const record of evidenceRecords) writes.push(ops.put(B23_STORES.evidence, record.idHex, record));
      writes.push(ops.put(B23_STORES.head, expected.groupIdHex, nextHead));
      if (expected.snapshotKeyHex !== snapshotKeyHex) {
        writes.push(ops.delete(B23_STORES.snapshot, expected.snapshotKeyHex));
      }
      await Promise.all(writes);
    });
    return { head: nextHead, transition, snapshotBytes: snapshot, evidence: evidenceRecords };
  }

  async recordPublishIntent(groupIdHex, artifact) {
    const bundle = await this.read(groupIdHex);
    const { head, transition } = bundle;
    if (head.state !== HEAD_PREPARED) fail(B23_ERROR.STATE_CONFLICT, 'publication intent requires a prepared head');
    const safeArtifact = snapshotClosedObject(artifact, ['id', 'bytes'], 'artifact');
    assertString('artifact.id', safeArtifact.id, { min: 1, max: 256, pattern: /^[\x21-\x7e]+$/ });
    assertBytes('artifact.bytes', safeArtifact.bytes, { min: 1, max: B23_LIMITS.maxArtifactBytes });
    const artifactBytes = copyBytes(safeArtifact.bytes);
    const artifactDigestHex = digestHex(artifactBytes);
    if (head.publishAttempts > 0
      && (head.artifactId !== safeArtifact.id || head.artifactDigestHex !== artifactDigestHex
        || transition.artifactId !== safeArtifact.id || !bytesEqual(transition.artifactBytes, artifactBytes))) {
      fail(B23_ERROR.STATE_CONFLICT, 'a retry must use the exact frozen artifact');
    }
    const nextAttempts = head.publishAttempts + 1;
    if (nextAttempts > B23_LIMITS.maxPublishAttempts) {
      fail(B23_ERROR.RESOURCE_LIMIT, 'publication attempt count is exhausted');
    }
    const payload = transitionPayloadFrom(transition);
    payload.artifactId = safeArtifact.id;
    payload.artifactBytes = artifactBytes;
    payload.artifactDigestHex = artifactDigestHex;
    payload.publishAttempts = nextAttempts;
    return this.cas({
      expectedHead: head,
      snapshotBytes: bundle.snapshotBytes,
      transitionFields: {
        kind: 'publish-intent', state: HEAD_PREPARED,
        epochDec: head.epochDec, epochDigestHex: head.epochDigestHex,
        ...payload,
      },
      headFields: {
        state: HEAD_PREPARED,
        epochDec: head.epochDec,
        epochDigestHex: head.epochDigestHex,
        ...headPendingFieldsFromTransition({ ...transition, ...payload }),
        lastAppliedCommitDigestHex: head.lastAppliedCommitDigestHex,
      },
    });
  }

  async appendPublicationEvidence(groupIdHex, payloadBytes) {
    const bundle = await this.read(groupIdHex);
    const { head, transition } = bundle;
    if (head.state !== HEAD_PREPARED || head.publishAttempts < 1 || transition.artifactBytes === null) {
      fail(B23_ERROR.STATE_CONFLICT, 'publication evidence requires an attempted frozen artifact');
    }
    assertBytes('evidence payload', payloadBytes, { min: 1, max: B23_LIMITS.maxEvidenceBytes });
    const nextEvidenceCount = head.evidenceCount + 1;
    if (nextEvidenceCount > B23_LIMITS.maxEvidence) fail(B23_ERROR.RESOURCE_LIMIT, 'evidence count is exhausted');
    const carried = transitionPayloadFrom(transition);
    carried.evidenceCount = nextEvidenceCount;
    return this.cas({
      expectedHead: head,
      snapshotBytes: bundle.snapshotBytes,
      transitionFields: {
        kind: 'publication-evidence', state: HEAD_PREPARED,
        epochDec: head.epochDec, epochDigestHex: head.epochDigestHex,
        ...carried,
      },
      headFields: {
        state: HEAD_PREPARED,
        epochDec: head.epochDec,
        epochDigestHex: head.epochDigestHex,
        ...headPendingFieldsFromTransition({ ...transition, ...carried }),
        lastAppliedCommitDigestHex: head.lastAppliedCommitDigestHex,
      },
      evidence: [copyBytes(payloadBytes)],
    });
  }

  close() { this.db.close(); }

  async destroy() { return this.db.destroy(); }
}

export async function openB23Journal({
  databaseTag,
  indexedDBImpl = globalThis.indexedDB,
  setTimeoutImpl = globalThis.setTimeout.bind(globalThis),
  clearTimeoutImpl = globalThis.clearTimeout.bind(globalThis),
  randomBytes = globalThis.crypto?.getRandomValues?.bind(globalThis.crypto),
} = {}) {
  assertString('databaseTag', databaseTag, { min: 1, max: 64, pattern: /^[a-z0-9-]+$/ });
  const db = await openVaultDb({
    name: `${B23_DB_PREFIX}${databaseTag}`,
    version: 1,
    migrations: { 1: migrationV1 },
    indexedDBImpl,
    setTimeoutImpl,
    clearTimeoutImpl,
  });
  return new B23Journal(db, { randomBytes });
}

export function createB23JournalForDb(db, options) {
  return new B23Journal(db, options);
}

export const B23_JOURNAL_RUNTIME = B23_RUNTIME;
export const B23_JOURNAL_STATES = Object.freeze({ stable: HEAD_STABLE, prepared: HEAD_PREPARED });
export const B23_JOURNAL_HELPERS = Object.freeze({ stableFields, headPendingFieldsFromTransition });
