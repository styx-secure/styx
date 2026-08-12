// STYX_SPIKE_PROTOTYPE — atomic retained-graph journal for Phase B2.6 only.

import { openVaultDb } from '../../src/storage/vault-db.js';
import {
  B26_DB_PREFIX,
  B26_APP_PUBLICATION_KIND,
  B26_ERROR,
  B26_GENERATION_STATE,
  B26_HEAD_STATE,
  B26_INPUT_STATE,
  B26_INBOUND_STATE,
  B26_LIMITS,
  B26_MESSAGE_STATE,
  B26_OUTBOX_STATE,
  B26_PASS_STATE,
  B26_STORES,
  B26_STORE_NAMES,
  assertBytes,
  assertGroupIdHex,
  assertHex64,
  assertSafeInteger,
  assertString,
  bytesEqual,
  canonicalB26Bytes,
  digestHex,
  edgeKey,
  failB26,
  generationKey,
  generationAuthorityDigest,
  inboundKey,
  inputKey,
  messageInstanceKey,
  messageSnapshotKey,
  messageStateKey,
  outboxKey,
  probeKey,
  publicationKey,
} from './b2-6-canonical.mjs';
import {
  GENERATION_FIELDS,
  MESSAGE_STATE_FIELDS,
  OUTBOX_FIELDS,
  buildGenerationTruncation,
  INPUT_FIELDS,
  buildActiveLocal,
  buildGeneration,
  buildHead,
  buildAppPublication,
  buildInbound,
  buildMessageRelease,
  buildMessageSnapshot,
  buildMessageState,
  buildOutbox,
  buildInput,
  buildPass,
  buildProbeCompletion,
  buildProbeReservation,
  buildRelease,
  buildRetainedState,
  buildTransition,
  parseActiveLocal,
  parseEdge,
  parseGeneration,
  parseGenerationTruncation,
  parseHead,
  parseAppPublication,
  parseInbound,
  parseInput,
  parseInvalidation,
  parseMessageRelease,
  parseMessageSnapshot,
  parseMessageState,
  parseOutbox,
  parsePass,
  parseProbeCompletion,
  parseProbeReservation,
  parsePublication,
  parseRelease,
  parseRetainedState,
  parseTransition,
} from './b2-6-record.mjs';
import { createBoundB26EngineAdapter } from './b2-6-engine-adapter.mjs';

const JOURNAL_TOKEN = Symbol('B26_JOURNAL_TOKEN');
const SNAPSHOT_STORES = Object.freeze([
  B26_STORES.head, B26_STORES.retained, B26_STORES.released,
  B26_STORES.input, B26_STORES.edge, B26_STORES.pass,
  B26_STORES.transition, B26_STORES.invalidation, B26_STORES.generation,
  B26_STORES.generationTruncation, B26_STORES.activeLocal, B26_STORES.publication,
]);
const MESSAGE_TRANSACTION_STORES = Object.freeze([
  B26_STORES.head, B26_STORES.retained, B26_STORES.released,
  B26_STORES.messageState, B26_STORES.messageSnapshot, B26_STORES.appOutbox,
  B26_STORES.appInbound, B26_STORES.appPublication, B26_STORES.messageRelease,
  B26_STORES.inboundTruncation,
]);
const SETTLEMENT_TRANSACTION_STORES = Object.freeze(
  [...new Set([...SNAPSHOT_STORES, ...MESSAGE_TRANSACTION_STORES])]);

function migrationV1(db) {
  for (const name of B26_STORE_NAMES) db.createObjectStore(name);
}

async function required(ops, store, key, label) {
  const value = await ops.get(store, key);
  if (value === undefined) failB26(B26_ERROR.CORRUPT, `${label} is missing`);
  return value;
}

function recordDigest(store, record) {
  const fields = {
    [B26_STORES.head]: 'headDigestHex',
    [B26_STORES.retained]: 'retainedDigestHex',
    [B26_STORES.released]: 'releaseDigestHex',
    [B26_STORES.input]: 'inputDigestHex',
    [B26_STORES.edge]: 'edgeDigestHex',
    [B26_STORES.pass]: 'passRecordDigestHex',
    [B26_STORES.transition]: 'transitionDigestHex',
    [B26_STORES.invalidation]: 'invalidationDigestHex',
    [B26_STORES.generation]: 'generationDigestHex',
    [B26_STORES.generationTruncation]: 'markerDigestHex',
    [B26_STORES.activeLocal]: 'pointerDigestHex',
    [B26_STORES.publication]: 'evidenceDigestHex',
    [B26_STORES.messageState]: 'stateDigestHex',
    [B26_STORES.messageSnapshot]: 'recordDigestHex',
    [B26_STORES.appOutbox]: 'outboxDigestHex',
    [B26_STORES.appInbound]: 'inboundDigestHex',
    [B26_STORES.appPublication]: 'evidenceDigestHex',
    [B26_STORES.messageRelease]: 'releaseDigestHex',
  };
  const field = fields[store];
  if (field === undefined || record[field] === undefined) {
    failB26(B26_ERROR.CORRUPT, 'record lacks a content digest');
  }
  return record[field];
}

function parseStoreRecord(store, raw) {
  if (store === B26_STORES.head) return parseHead(raw);
  if (store === B26_STORES.retained) return parseRetainedState(raw);
  if (store === B26_STORES.released) return parseRelease(raw);
  if (store === B26_STORES.input) return parseInput(raw);
  if (store === B26_STORES.edge) return parseEdge(raw);
  if (store === B26_STORES.pass) return parsePass(raw);
  if (store === B26_STORES.transition) return parseTransition(raw);
  if (store === B26_STORES.invalidation) return parseInvalidation(raw);
  if (store === B26_STORES.generation) return parseGeneration(raw);
  if (store === B26_STORES.generationTruncation) return parseGenerationTruncation(raw);
  if (store === B26_STORES.activeLocal) return parseActiveLocal(raw);
  if (store === B26_STORES.publication) return parsePublication(raw);
  if (store === B26_STORES.messageState) return parseMessageState(raw);
  if (store === B26_STORES.messageSnapshot) return parseMessageSnapshot(raw);
  if (store === B26_STORES.appOutbox) return parseOutbox(raw);
  if (store === B26_STORES.appInbound) return parseInbound(raw);
  if (store === B26_STORES.appPublication) return parseAppPublication(raw);
  if (store === B26_STORES.messageRelease) return parseMessageRelease(raw);
  failB26(B26_ERROR.CORRUPT, 'unexpected snapshot store');
}

async function readStore(ops, store) {
  const keys = (await ops.list(store)).filter((key) => typeof key === 'string').sort();
  const values = [];
  for (const key of keys) {
    const record = parseStoreRecord(store, await required(ops, store, key, `${store} record`));
    values.push(Object.freeze({ key, record }));
  }
  return Object.freeze(values);
}

async function readSnapshotFromOps(ops, groupIdHex) {
  const stores = {};
  const readSet = [];
  for (const store of SNAPSHOT_STORES) {
    const entries = await readStore(ops, store);
    stores[store] = entries;
    for (const { key, record } of entries) readSet.push([store, key, recordDigest(store, record)]);
  }
  const headEntry = stores[B26_STORES.head].find(({ key }) => key === groupIdHex);
  if (headEntry === undefined) failB26(B26_ERROR.NOT_FOUND, 'canonical head is absent');
  const head = headEntry.record;
  const groupEntries = (store) => stores[store]
    .filter(({ record }) => record.groupIdHex === undefined || record.groupIdHex === groupIdHex)
    .map(({ record }) => record);
  return Object.freeze({
    head,
    retained: Object.freeze(groupEntries(B26_STORES.retained)),
    released: Object.freeze(groupEntries(B26_STORES.released)),
    inputs: Object.freeze(groupEntries(B26_STORES.input)),
    edges: Object.freeze(groupEntries(B26_STORES.edge)),
    passes: Object.freeze(groupEntries(B26_STORES.pass)),
    transitions: Object.freeze(groupEntries(B26_STORES.transition)),
    invalidations: Object.freeze(groupEntries(B26_STORES.invalidation)),
    generations: Object.freeze(groupEntries(B26_STORES.generation)),
    generationTruncation: groupEntries(B26_STORES.generationTruncation)[0] ?? null,
    activeLocal: groupEntries(B26_STORES.activeLocal)[0] ?? null,
    publications: Object.freeze(groupEntries(B26_STORES.publication)),
    readSetDigestHex: digestHex(canonicalB26Bytes('JOURNAL-READ-SET', readSet)),
  });
}

function rebuildInput(record, changes) {
  const fields = {};
  for (const field of INPUT_FIELDS) {
    if (!['format', 'version', 'inputDigestHex', 'commitDigestHex',
      'commitByteLength'].includes(field)) fields[field] = record[field];
  }
  return buildInput({ ...fields, ...changes });
}

function rebuildGeneration(record, changes) {
  const fields = {};
  for (const field of GENERATION_FIELDS) {
    if (!['format', 'version', 'generationDigestHex'].includes(field)) fields[field] = record[field];
  }
  return buildGeneration({ ...fields, ...changes });
}

function rebuildMessageState(record, changes) {
  const fields = {};
  for (const field of MESSAGE_STATE_FIELDS) {
    if (!['format', 'version', 'profile', 'runtime', 'stateDigestHex'].includes(field)) {
      fields[field] = record[field];
    }
  }
  return buildMessageState({ ...fields, ...changes });
}

function rebuildOutbox(record, changes) {
  const fields = {};
  for (const field of OUTBOX_FIELDS) {
    if (!['format', 'version', 'outboxDigestHex'].includes(field)) fields[field] = record[field];
  }
  return buildOutbox({ ...fields, ...changes });
}

function appPublicationKey(instanceKeyHex, ordinal, sequence) {
  assertHex64('instanceKeyHex', instanceKeyHex);
  assertSafeInteger('outbox ordinal', ordinal, 1, Number.MAX_SAFE_INTEGER);
  assertSafeInteger('publication sequence', sequence, 1,
    B26_LIMITS.maxMessagePublicationRecords);
  return `${instanceKeyHex}:${String(ordinal).padStart(16, '0')}:`+
    `${String(sequence).padStart(3, '0')}`;
}

export class B26Journal {
  #db;

  constructor(db, token) {
    if (token !== JOURNAL_TOKEN) {
      failB26(B26_ERROR.INVALID, 'B2.6 journals must be created by the namespace factory');
    }
    this.#db = db;
    Object.freeze(this);
  }

  async #initialize({ groupIdHex, accountKeyHex, signatureKeyHex, epochDec,
    groupContextDigestHex, snapshotBytes }) {
    const retained = buildRetainedState({ groupIdHex, accountKeyHex, signatureKeyHex,
      epochDec, groupContextDigestHex, snapshotBytes });
    const transition = buildTransition({
      groupIdHex, seq: 1, kind: 'INITIALIZE', predecessorHeadDigestHex: null,
      successorSnapshotDigestHex: retained.snapshotDigestHex,
      anchorSnapshotDigestHex: retained.snapshotDigestHex, selectedPath: [], displacedPath: [],
      passDigestHex: null, invalidationDigestHex: null, releasedStateDigests: [],
      epochDec, groupContextDigestHex,
    });
    const head = buildHead({
      groupIdHex, accountKeyHex, signatureKeyHex, seq: 1, state: B26_HEAD_STATE.STABLE,
      epochDec, groupContextDigestHex, snapshotDigestHex: retained.snapshotDigestHex,
      anchorSnapshotDigestHex: retained.snapshotDigestHex, canonicalPath: [],
      priorHeadDigestHex: null, transitionDigestHex: transition.transitionDigestHex,
      selectedCommitDigestHex: null,
    });
    await this.#db.transaction(B26_STORE_NAMES, async (ops) => {
      for (const store of B26_STORE_NAMES) {
        if ((await ops.list(store)).length !== 0) {
          failB26(B26_ERROR.CAS_CONFLICT, 'private one-group B2.6 journal is not empty');
        }
      }
      await Promise.all([
        ops.put(B26_STORES.retained, retained.snapshotDigestHex, retained),
        ops.put(B26_STORES.transition, transition.transitionDigestHex, transition),
        ops.put(B26_STORES.head, groupIdHex, head),
        ops.put(B26_STORES.activeLocal, groupIdHex,
          buildActiveLocal({ groupIdHex, generationDigestHex: null })),
      ]);
    });
    return head;
  }

  async snapshot(groupIdHex) {
    assertGroupIdHex(groupIdHex);
    return this.#db.transaction(SNAPSHOT_STORES,
      async (ops) => readSnapshotFromOps(ops, groupIdHex));
  }

  async readHead(groupIdHex) {
    const snapshot = await this.snapshot(groupIdHex);
    const retained = snapshot.retained.find((item) =>
      item.snapshotDigestHex === snapshot.head.snapshotDigestHex);
    if (retained === undefined && snapshot.head.state !== B26_HEAD_STATE.UNRECOVERABLE) {
      const released = snapshot.released.find((item) =>
        item.snapshotDigestHex === snapshot.head.snapshotDigestHex);
      if (released !== undefined) {
        failB26(B26_ERROR.RELEASED, 'canonical state was logically released', { released });
      }
      failB26(B26_ERROR.CORRUPT, 'canonical retained state is missing');
    }
    return Object.freeze({ head: snapshot.head, retained: retained ?? null,
      transition: snapshot.transitions.find((item) =>
        item.transitionDigestHex === snapshot.head.transitionDigestHex) ?? null });
  }

  async readRetained(snapshotDigestHex) {
    assertHex64('snapshotDigestHex', snapshotDigestHex);
    return this.#db.transaction([B26_STORES.retained, B26_STORES.released], async (ops) => {
      const raw = await ops.get(B26_STORES.retained, snapshotDigestHex);
      if (raw !== undefined) return parseRetainedState(raw);
      const released = await ops.get(B26_STORES.released, snapshotDigestHex);
      if (released !== undefined) {
        const tombstone = parseRelease(released);
        failB26(B26_ERROR.RELEASED, 'retained state was logically released', { tombstone });
      }
      failB26(B26_ERROR.NOT_FOUND, 'retained state is absent', { snapshotDigestHex });
    });
  }

  async admitCommit(groupIdHex, commitBytes) {
    assertGroupIdHex(groupIdHex);
    assertBytes('Commit bytes', commitBytes, { min: 1, max: B26_LIMITS.maxCommitBytes });
    const proposed = buildInput({ groupIdHex, commitBytes });
    return this.#db.transaction(SNAPSHOT_STORES, async (ops) => {
      const view = await readSnapshotFromOps(ops, groupIdHex);
      if (view.head.state !== B26_HEAD_STATE.STABLE) {
        failB26(B26_ERROR.UNRECOVERABLE, 'input admission requires a stable group');
      }
      const generation = view.generations.find((item) =>
        item.commitDigestHex === proposed.commitDigestHex);
      if (generation !== undefined) {
        if (!bytesEqual(generation.commitBytes, proposed.commitBytes)) {
          failB26(B26_ERROR.CORRUPT, 'local generation digest collision');
        }
        return Object.freeze({ status: 'own_echo', generation });
      }
      const existing = view.inputs.find((item) =>
        item.commitDigestHex === proposed.commitDigestHex);
      if (existing !== undefined) {
        if (!bytesEqual(existing.commitBytes, proposed.commitBytes)) {
          failB26(B26_ERROR.CORRUPT, 'Commit digest collision');
        }
        return Object.freeze({ status: 'duplicate', input: existing });
      }
      if (view.inputs.length >= B26_LIMITS.maxInputs) {
        failB26(B26_ERROR.RESOURCE_LIMIT, 'retained raw-input cap is exhausted');
      }
      await ops.put(B26_STORES.input,
        inputKey(groupIdHex, proposed.commitDigestHex), proposed);
      return Object.freeze({ status: 'retained', input: proposed });
    });
  }

  async freeze(groupIdHex) {
    assertGroupIdHex(groupIdHex);
    return this.#db.transaction(SNAPSHOT_STORES, async (ops) => {
      const view = await readSnapshotFromOps(ops, groupIdHex);
      if (view.head.state !== B26_HEAD_STATE.STABLE) {
        failB26(B26_ERROR.UNRECOVERABLE, 'pass freeze requires a stable group');
      }
      if (view.passes.some((item) => item.state === B26_PASS_STATE.FROZEN)) {
        failB26(B26_ERROR.STATE_CONFLICT, 'one frozen pass already awaits settlement');
      }
      if (view.passes.length >= B26_LIMITS.maxPasses) {
        failB26(B26_ERROR.RESOURCE_LIMIT, 'pass history cap is exhausted');
      }
      const eligibleLocal = view.generations.filter((item) => [
        B26_GENERATION_STATE.ACKNOWLEDGED,
        B26_GENERATION_STATE.SELECTED,
        B26_GENERATION_STATE.LOSING,
      ].includes(item.state) && !item.contradiction);
      const closure = [...view.inputs.map((item) => item.commitDigestHex),
        ...eligibleLocal.map((item) => item.commitDigestHex)].sort();
      const unique = [...new Set(closure)];
      if (unique.length !== closure.length) failB26(B26_ERROR.CORRUPT, 'input closure collides');
      if (unique.length === 0) failB26(B26_ERROR.STATE_CONFLICT, 'cannot freeze an empty pass');
      if (unique.length > B26_LIMITS.maxInputs) {
        failB26(B26_ERROR.RESOURCE_LIMIT, 'frozen input closure exceeds its cap');
      }
      const pass = buildPass({ groupIdHex, baseHeadDigestHex: view.head.headDigestHex,
        closureCommitDigests: unique });
      if (await ops.get(B26_STORES.pass, pass.passDigestHex) !== undefined) {
        failB26(B26_ERROR.CAS_CONFLICT, 'identical frozen pass already exists');
      }
      await ops.put(B26_STORES.pass, pass.passDigestHex, pass);
      return pass;
    });
  }

  async readFrozen(passDigestHex) {
    assertHex64('passDigestHex', passDigestHex);
    return this.#db.transaction(SNAPSHOT_STORES, async (ops) => {
      const pass = parsePass(await required(ops, B26_STORES.pass, passDigestHex, 'pass'));
      if (pass.state !== B26_PASS_STATE.FROZEN) {
        failB26(B26_ERROR.STATE_CONFLICT, 'pass is already settled');
      }
      const view = await readSnapshotFromOps(ops, pass.groupIdHex);
      if (view.head.headDigestHex !== pass.baseHeadDigestHex) {
        failB26(B26_ERROR.CAS_CONFLICT, 'frozen pass no longer binds the canonical head');
      }
      const actual = [...view.inputs.map((item) => item.commitDigestHex),
        ...view.generations.filter((item) => [
          B26_GENERATION_STATE.ACKNOWLEDGED,
          B26_GENERATION_STATE.SELECTED,
          B26_GENERATION_STATE.LOSING,
        ].includes(item.state) && !item.contradiction)
          .map((item) => item.commitDigestHex)].sort();
      if (actual.length !== pass.closureCommitDigests.length
        || actual.some((item, index) => item !== pass.closureCommitDigests[index])) {
        failB26(B26_ERROR.CAS_CONFLICT, 'frozen input closure changed');
      }
      return Object.freeze({ ...view, pass });
    });
  }

  async #commitSettlement(decision) {
    const expectedHead = parseHead(decision.expectedHead);
    const settledPass = parsePass(decision.settledPass);
    const nextHead = parseHead(decision.nextHead);
    const transition = parseTransition(decision.transition);
    const invalidation = parseInvalidation(decision.invalidation);
    const states = decision.states.map(parseRetainedState);
    const edges = decision.edges.map(parseEdge);
    const inputs = decision.inputs.map(parseInput);
    const releases = decision.releases.map(parseRelease);
    const generations = decision.generations.map(parseGeneration);
    if (settledPass.state !== B26_PASS_STATE.SETTLED
      || nextHead.groupIdHex !== expectedHead.groupIdHex
      || nextHead.priorHeadDigestHex !== expectedHead.headDigestHex
      || nextHead.transitionDigestHex !== transition.transitionDigestHex
      || transition.predecessorHeadDigestHex !== expectedHead.headDigestHex
      || transition.passDigestHex !== settledPass.passDigestHex
      || transition.invalidationDigestHex !== invalidation.invalidationDigestHex
      || invalidation.predecessorHeadDigestHex !== expectedHead.headDigestHex
      || invalidation.successorSnapshotDigestHex !== nextHead.snapshotDigestHex) {
      failB26(B26_ERROR.INVALID, 'settlement output has incoherent authority bindings');
    }
    return this.#db.transaction(SETTLEMENT_TRANSACTION_STORES, async (ops) => {
      const current = await readSnapshotFromOps(ops, expectedHead.groupIdHex);
      if (current.head.headDigestHex !== expectedHead.headDigestHex
        || current.readSetDigestHex !== decision.expectedReadSetDigestHex) {
        failB26(B26_ERROR.CAS_CONFLICT, 'complete settlement read set changed');
      }
      const currentPass = current.passes.find((item) =>
        item.passDigestHex === settledPass.passDigestHex);
      if (currentPass?.state !== B26_PASS_STATE.FROZEN) {
        failB26(B26_ERROR.CAS_CONFLICT, 'frozen pass disappeared or changed');
      }
      const writes = [];
      const releasedSnapshots = new Set(releases.map((release) => release.snapshotDigestHex));
      const canonicalSnapshots = new Set([nextHead.anchorSnapshotDigestHex]);
      for (const commitDigestHex of nextHead.canonicalPath) {
        const edge = edges.find((candidate) =>
          candidate.commitDigestHex === commitDigestHex);
        if (edge === undefined) {
          failB26(B26_ERROR.CORRUPT,
            'canonical settlement path lacks its retained replay edge');
        }
        canonicalSnapshots.add(edge.successorSnapshotDigestHex);
      }
      const messageStateEntries = [];
      for (const key of await ops.list(B26_STORES.messageState)) {
        if (typeof key !== 'string') continue;
        const state = parseMessageState(await required(
          ops, B26_STORES.messageState, key, 'message-state record'));
        if (state.groupIdHex === expectedHead.groupIdHex) {
          messageStateEntries.push({ key, state });
        }
      }
      for (const { key, state } of messageStateEntries) {
        const mustRelease = releasedSnapshots.has(state.baseRetainedSnapshotDigestHex);
        if (mustRelease) {
          const marker = buildMessageRelease({
            groupIdHex: state.groupIdHex,
            instanceKeyHex: state.instanceKeyHex,
            stateDigestHex: state.stateDigestHex,
            snapshotDigestHex: state.snapshotDigestHex,
            releaseAuthorityDigestHex: transition.transitionDigestHex,
          });
          writes.push(ops.put(B26_STORES.messageRelease, key, marker));
          writes.push(ops.delete(B26_STORES.messageState, key));
          writes.push(ops.delete(B26_STORES.messageSnapshot,
            messageSnapshotKey(state.instanceKeyHex, state.snapshotDigestHex)));
        } else if (canonicalSnapshots.has(state.baseRetainedSnapshotDigestHex)
          && state.state === B26_MESSAGE_STATE.SUSPENDED) {
          writes.push(ops.put(B26_STORES.messageState, key,
            rebuildMessageState(state, { state: B26_MESSAGE_STATE.ACTIVE })));
        } else if (!canonicalSnapshots.has(state.baseRetainedSnapshotDigestHex)
          && state.state === B26_MESSAGE_STATE.ACTIVE) {
          writes.push(ops.put(B26_STORES.messageState, key,
            rebuildMessageState(state, { state: B26_MESSAGE_STATE.SUSPENDED })));
        }
        if (mustRelease || state.state !== (canonicalSnapshots
          .has(state.baseRetainedSnapshotDigestHex)
          ? B26_MESSAGE_STATE.ACTIVE : B26_MESSAGE_STATE.SUSPENDED)) {
          for (const outboxKeyValue of await ops.list(B26_STORES.appOutbox)) {
            if (typeof outboxKeyValue !== 'string'
              || !outboxKeyValue.startsWith(state.instanceKeyHex + ':')) continue;
            const outbox = parseOutbox(await required(
              ops, B26_STORES.appOutbox, outboxKeyValue, 'outbox record'));
            if ([B26_OUTBOX_STATE.ACKNOWLEDGED, B26_OUTBOX_STATE.FAILED_DISCARDED,
              B26_OUTBOX_STATE.INVALIDATED].includes(outbox.state)) continue;
            let outboxState = outbox.state;
            if (mustRelease) outboxState = B26_OUTBOX_STATE.INVALIDATED;
            else if (!canonicalSnapshots.has(state.baseRetainedSnapshotDigestHex)) {
              outboxState = B26_OUTBOX_STATE.SUSPENDED;
            } else if (outbox.state === B26_OUTBOX_STATE.SUSPENDED) {
              outboxState = outbox.attemptCount === 0
                ? B26_OUTBOX_STATE.DURABLE : B26_OUTBOX_STATE.ATTEMPTED;
            }
            if (outboxState !== outbox.state) {
              writes.push(ops.put(B26_STORES.appOutbox, outboxKeyValue,
                rebuildOutbox(outbox, { state: outboxState })));
            }
          }
        }
      }
      for (const state of states) {
        const prior = await ops.get(B26_STORES.retained, state.snapshotDigestHex);
        if (prior !== undefined
          && parseRetainedState(prior).retainedDigestHex !== state.retainedDigestHex) {
          failB26(B26_ERROR.CORRUPT, 'retained-state content-address collision');
        }
        writes.push(ops.put(B26_STORES.retained, state.snapshotDigestHex, state));
      }
      for (const edge of edges) {
        const key = edgeKey(edge.groupIdHex, edge.parentSnapshotDigestHex, edge.commitDigestHex);
        const prior = await ops.get(B26_STORES.edge, key);
        if (prior !== undefined && parseEdge(prior).edgeDigestHex !== edge.edgeDigestHex) {
          failB26(B26_ERROR.CORRUPT, 'replay-edge identity collision');
        }
        writes.push(ops.put(B26_STORES.edge, key, edge));
      }
      const retainedEdgeKeys = new Set(edges.map((edge) =>
        edgeKey(edge.groupIdHex, edge.parentSnapshotDigestHex, edge.commitDigestHex)));
      for (const priorEdge of current.edges) {
        const key = edgeKey(priorEdge.groupIdHex,
          priorEdge.parentSnapshotDigestHex, priorEdge.commitDigestHex);
        if (!retainedEdgeKeys.has(key)) writes.push(ops.delete(B26_STORES.edge, key));
      }
      for (const input of inputs) writes.push(ops.put(B26_STORES.input,
        inputKey(input.groupIdHex, input.commitDigestHex), input));
      for (const generation of generations) writes.push(ops.put(B26_STORES.generation,
        generationKey(generation.groupIdHex, generation.commitDigestHex), generation));
      const activePointer = current.activeLocal;
      if (activePointer?.generationDigestHex !== null) {
        const priorActive = current.generations.find((item) =>
          item.generationDigestHex === activePointer.generationDigestHex);
        const nextActive = generations.find((item) =>
          item.commitDigestHex === priorActive?.commitDigestHex);
        if (nextActive !== undefined && [B26_GENERATION_STATE.SELECTED,
          B26_GENERATION_STATE.LOSING, B26_GENERATION_STATE.REJECTED]
          .includes(nextActive.state)) {
          writes.push(ops.put(B26_STORES.activeLocal, nextActive.groupIdHex,
            buildActiveLocal({ groupIdHex: nextActive.groupIdHex,
              generationDigestHex: null })));
        }
      }
      writes.push(ops.put(B26_STORES.pass, settledPass.passDigestHex, settledPass));
      writes.push(ops.put(B26_STORES.invalidation,
        invalidation.invalidationDigestHex, invalidation));
      writes.push(ops.put(B26_STORES.transition, transition.transitionDigestHex, transition));
      for (const release of releases) {
        const retainedRaw = await ops.get(B26_STORES.retained, release.snapshotDigestHex);
        if (retainedRaw === undefined
          || parseRetainedState(retainedRaw).retainedDigestHex !== release.retainedDigestHex) {
          failB26(B26_ERROR.CAS_CONFLICT, 'logical release target changed');
        }
        writes.push(ops.put(B26_STORES.released, release.snapshotDigestHex, release));
        writes.push(ops.delete(B26_STORES.retained, release.snapshotDigestHex));
      }
      writes.push(ops.put(B26_STORES.head, nextHead.groupIdHex, nextHead));
      await Promise.all(writes);
      return Object.freeze({ head: nextHead, pass: settledPass, transition, invalidation,
        states: Object.freeze(states), edges: Object.freeze(edges),
        inputs: Object.freeze(inputs), releases: Object.freeze(releases) });
    });
  }

  async #markUnrecoverable(expectedHead) {
    const prior = parseHead(expectedHead);
    if (prior.state !== B26_HEAD_STATE.STABLE) {
      failB26(B26_ERROR.UNRECOVERABLE, 'group is already unrecoverable');
    }
    const transition = buildTransition({
      groupIdHex: prior.groupIdHex,
      seq: prior.seq + 1,
      kind: 'MARK_UNRECOVERABLE',
      predecessorHeadDigestHex: prior.headDigestHex,
      successorSnapshotDigestHex: prior.snapshotDigestHex,
      anchorSnapshotDigestHex: prior.anchorSnapshotDigestHex,
      selectedPath: prior.canonicalPath,
      displacedPath: [],
      passDigestHex: null,
      invalidationDigestHex: null,
      releasedStateDigests: [],
      epochDec: prior.epochDec,
      groupContextDigestHex: prior.groupContextDigestHex,
    });
    const next = buildHead({
      groupIdHex: prior.groupIdHex,
      accountKeyHex: prior.accountKeyHex,
      signatureKeyHex: prior.signatureKeyHex,
      seq: prior.seq + 1,
      state: B26_HEAD_STATE.UNRECOVERABLE,
      epochDec: prior.epochDec,
      groupContextDigestHex: prior.groupContextDigestHex,
      snapshotDigestHex: prior.snapshotDigestHex,
      anchorSnapshotDigestHex: prior.anchorSnapshotDigestHex,
      canonicalPath: prior.canonicalPath,
      priorHeadDigestHex: prior.headDigestHex,
      transitionDigestHex: transition.transitionDigestHex,
      selectedCommitDigestHex: prior.selectedCommitDigestHex,
    });
    return this.#db.transaction(SNAPSHOT_STORES, async (ops) => {
      const current = await readSnapshotFromOps(ops, prior.groupIdHex);
      if (current.head.headDigestHex !== prior.headDigestHex) {
        failB26(B26_ERROR.CAS_CONFLICT,
          'canonical head changed before unrecoverable transition');
      }
      await Promise.all([
        ops.put(B26_STORES.transition, transition.transitionDigestHex, transition),
        ops.put(B26_STORES.head, next.groupIdHex, next),
      ]);
      return Object.freeze({ head: next, transition });
    });
  }

  async #commitPrepared({ expectedHead, generation, pendingRetained }) {
    const head = parseHead(expectedHead);
    const next = parseGeneration(generation);
    const retained = parseRetainedState(pendingRetained);
    if (next.parentHeadDigestHex !== head.headDigestHex
      || next.parentSnapshotDigestHex !== head.snapshotDigestHex
      || next.pendingSnapshotDigestHex !== retained.snapshotDigestHex) {
      failB26(B26_ERROR.INVALID, 'local generation does not bind its parent');
    }
    return this.#db.transaction(SNAPSHOT_STORES, async (ops) => {
      const view = await readSnapshotFromOps(ops, head.groupIdHex);
      if (view.head.headDigestHex !== head.headDigestHex
        || view.activeLocal?.generationDigestHex !== null) {
        failB26(B26_ERROR.CAS_CONFLICT, 'head or active-local pointer changed');
      }
      if (view.passes.some((item) => item.state === B26_PASS_STATE.FROZEN)) {
        failB26(B26_ERROR.STATE_CONFLICT,
          'local preparation is excluded while a settlement pass is frozen');
      }
      const generationFloor = Math.max(view.generationTruncation?.throughGeneration ?? 0,
        ...view.generations.map((item) => item.generation));
      if (next.generation !== generationFloor + 1) {
        failB26(B26_ERROR.CAS_CONFLICT, 'local generation ordinal changed');
      }
      const writes = [
        ops.put(B26_STORES.retained, retained.snapshotDigestHex, retained),
        ops.put(B26_STORES.generation,
          generationKey(next.groupIdHex, next.commitDigestHex), next),
        ops.put(B26_STORES.activeLocal, next.groupIdHex,
          buildActiveLocal({ groupIdHex: next.groupIdHex,
            generationDigestHex: next.generationDigestHex })),
      ];
      if (view.generations.length >= B26_LIMITS.maxGenerations) {
        const evictableStates = new Set([
          B26_GENERATION_STATE.CANCELLED,
          B26_GENERATION_STATE.DISCARDED,
          B26_GENERATION_STATE.REJECTED,
        ]);
        const evicted = [...view.generations]
          .sort((left, right) => left.generation - right.generation)
          .find((candidate) => evictableStates.has(candidate.state)
            && !candidate.contradiction
            && !view.edges.some((edge) => edge.localGenerationDigestHex
              === generationAuthorityDigest(candidate)));
        if (evicted === undefined) {
          failB26(B26_ERROR.RESOURCE_LIMIT,
            'local generation history cap has no safely evictable terminal record');
        }
        const pendingRequired = view.head.snapshotDigestHex === evicted.pendingSnapshotDigestHex
          || view.head.anchorSnapshotDigestHex === evicted.pendingSnapshotDigestHex
          || view.edges.some((edge) => edge.parentSnapshotDigestHex
            === evicted.pendingSnapshotDigestHex
            || edge.successorSnapshotDigestHex === evicted.pendingSnapshotDigestHex)
          || view.generations.some((candidate) => candidate.commitDigestHex
            !== evicted.commitDigestHex
            && candidate.pendingSnapshotDigestHex === evicted.pendingSnapshotDigestHex);
        const marker = buildGenerationTruncation({
          groupIdHex: evicted.groupIdHex,
          throughGeneration: evicted.generation,
          evictedCommitDigestHex: evicted.commitDigestHex,
          evictedGenerationAuthorityDigestHex: generationAuthorityDigest(evicted),
          evictedGenerationDigestHex: evicted.generationDigestHex,
          priorMarkerDigestHex: view.generationTruncation?.markerDigestHex ?? null,
        });
        writes.push(
          ops.delete(B26_STORES.generation,
            generationKey(evicted.groupIdHex, evicted.commitDigestHex)),
          ops.put(B26_STORES.generationTruncation, evicted.groupIdHex, marker),
        );
        const publicationPrefix = `${evicted.groupIdHex}:${evicted.commitDigestHex}:`;
        for (const key of await ops.list(B26_STORES.publication)) {
          if (typeof key === 'string' && key.startsWith(publicationPrefix)) {
            writes.push(ops.delete(B26_STORES.publication, key));
          }
        }
        if (!pendingRequired) {
          writes.push(ops.delete(B26_STORES.retained, evicted.pendingSnapshotDigestHex));
        }
      }
      await Promise.all(writes);
      return next;
    });
  }

  async #replaceGeneration(expectedGeneration, nextGeneration, { clearActive = false } = {}) {
    const prior = parseGeneration(expectedGeneration);
    const next = parseGeneration(nextGeneration);
    if (prior.groupIdHex !== next.groupIdHex || prior.commitDigestHex !== next.commitDigestHex) {
      failB26(B26_ERROR.INVALID, 'generation replacement changes identity');
    }
    return this.#db.transaction(SNAPSHOT_STORES, async (ops) => {
      const raw = await required(ops, B26_STORES.generation,
        generationKey(prior.groupIdHex, prior.commitDigestHex), 'local generation');
      if (parseGeneration(raw).generationDigestHex !== prior.generationDigestHex) {
        failB26(B26_ERROR.CAS_CONFLICT, 'local generation changed');
      }
      await ops.put(B26_STORES.generation,
        generationKey(next.groupIdHex, next.commitDigestHex), next);
      if (clearActive) {
        const pointer = parseActiveLocal(await required(ops, B26_STORES.activeLocal,
          prior.groupIdHex, 'active-local pointer'));
        if (pointer.generationDigestHex !== prior.generationDigestHex) {
          failB26(B26_ERROR.CAS_CONFLICT, 'active-local pointer changed');
        }
        await ops.put(B26_STORES.activeLocal, prior.groupIdHex,
          buildActiveLocal({ groupIdHex: prior.groupIdHex, generationDigestHex: null }));
        if ([B26_GENERATION_STATE.CANCELLED, B26_GENERATION_STATE.DISCARDED,
          B26_GENERATION_STATE.REJECTED].includes(next.state)) {
          const retainedRaw = await ops.get(
            B26_STORES.retained, next.pendingSnapshotDigestHex);
          if (retainedRaw !== undefined) {
            const retained = parseRetainedState(retainedRaw);
            const release = buildRelease({
              groupIdHex: retained.groupIdHex,
              snapshotDigestHex: retained.snapshotDigestHex,
              epochDec: retained.epochDec,
              groupContextDigestHex: retained.groupContextDigestHex,
              retainedDigestHex: retained.retainedDigestHex,
              releaseAuthorityDigestHex: next.generationDigestHex,
            });
            await Promise.all([
              ops.put(B26_STORES.released, release.snapshotDigestHex, release),
              ops.delete(B26_STORES.retained, release.snapshotDigestHex),
            ]);
          }
        }
      } else {
        const pointer = parseActiveLocal(await required(ops, B26_STORES.activeLocal,
          prior.groupIdHex, 'active-local pointer'));
        if (pointer.generationDigestHex === prior.generationDigestHex) {
          await ops.put(B26_STORES.activeLocal, prior.groupIdHex,
            buildActiveLocal({ groupIdHex: prior.groupIdHex,
              generationDigestHex: next.generationDigestHex }));
        }
      }
      return next;
    });
  }

  async #appendPublication({ expectedGeneration, evidence, nextGeneration }) {
    const prior = parseGeneration(expectedGeneration);
    const record = parsePublication(evidence);
    const next = parseGeneration(nextGeneration);
    if (record.groupIdHex !== prior.groupIdHex
      || record.generationDigestHex !== prior.generationDigestHex
      || record.artifactDigestHex !== prior.commitDigestHex) {
      failB26(B26_ERROR.INVALID, 'publication evidence lacks exact generation authority');
    }
    return this.#db.transaction(SNAPSHOT_STORES, async (ops) => {
      const current = parseGeneration(await required(ops, B26_STORES.generation,
        generationKey(prior.groupIdHex, prior.commitDigestHex), 'local generation'));
      if (current.generationDigestHex !== prior.generationDigestHex) {
        failB26(B26_ERROR.CAS_CONFLICT, 'local generation changed before evidence append');
      }
      const prefix = `${prior.groupIdHex}:${prior.commitDigestHex}:`;
      const keys = (await ops.list(B26_STORES.publication))
        .filter((key) => typeof key === 'string' && key.startsWith(prefix)).sort();
      if (record.sequence !== keys.length + 1) {
        failB26(B26_ERROR.CAS_CONFLICT, 'publication sequence changed');
      }
      await Promise.all([
        ops.put(B26_STORES.publication,
          publicationKey(prior.groupIdHex, prior.commitDigestHex, record.sequence), record),
        ops.put(B26_STORES.generation,
          generationKey(next.groupIdHex, next.commitDigestHex), next),
      ]);
      const pointer = parseActiveLocal(await required(ops, B26_STORES.activeLocal,
        prior.groupIdHex, 'active-local pointer'));
      if (pointer.generationDigestHex === prior.generationDigestHex) {
        await ops.put(B26_STORES.activeLocal, prior.groupIdHex,
          buildActiveLocal({ groupIdHex: prior.groupIdHex,
            generationDigestHex: next.generationDigestHex }));
      }
      return Object.freeze({ evidence: record, generation: next });
    });
  }

  async reserveProbe(groupIdHex) {
    assertGroupIdHex(groupIdHex);
    return this.#db.transaction([
      B26_STORES.head, B26_STORES.retained, B26_STORES.probeReservation,
      B26_STORES.probeCompletion,
    ], async (ops) => {
      const head = parseHead(await required(ops, B26_STORES.head, groupIdHex, 'canonical head'));
      if (head.state !== B26_HEAD_STATE.STABLE) {
        failB26(B26_ERROR.UNRECOVERABLE, 'probe requires a stable canonical head');
      }
      const retained = parseRetainedState(await required(ops, B26_STORES.retained,
        head.snapshotDigestHex, 'canonical retained state'));
      const key = probeKey({ groupIdHex, tipCommitDigestHex: head.selectedCommitDigestHex,
        epochDec: head.epochDec, groupContextDigestHex: head.groupContextDigestHex,
        localMemberIdentityHex: head.accountKeyHex });
      const existing = await ops.get(B26_STORES.probeReservation, key);
      if (existing !== undefined) {
        const reservation = parseProbeReservation(existing);
        const completionRaw = await ops.get(B26_STORES.probeCompletion, key);
        const completion = completionRaw === undefined ? null : parseProbeCompletion(completionRaw);
        failB26(B26_ERROR.PROBE_ALREADY_RESERVED,
          completion === null ? 'epoch instance is reserved without completion'
            : 'epoch instance already has completed liveness evidence',
          { probeKeyHex: key, completed: completion !== null, reservation, completion });
      }
      const count = (await ops.list(B26_STORES.probeReservation)).length;
      if (count >= B26_LIMITS.maxProbeReservations) {
        failB26(B26_ERROR.RESOURCE_LIMIT, 'probe reservation ledger is full');
      }
      const reservation = buildProbeReservation({
        groupIdHex, headDigestHex: head.headDigestHex,
        tipCommitDigestHex: head.selectedCommitDigestHex, epochDec: head.epochDec,
        groupContextDigestHex: head.groupContextDigestHex,
        localMemberIdentityHex: head.accountKeyHex, probeKeyHex: key,
      });
      await ops.put(B26_STORES.probeReservation, key, reservation);
      return Object.freeze({ reservation, retained });
    });
  }

  async completeProbe({ probeKeyHex, ciphertextDigestHex, plaintextDigestHex,
    peerIdentityHex }) {
    assertHex64('probeKeyHex', probeKeyHex);
    return this.#db.transaction([
      B26_STORES.probeReservation, B26_STORES.probeCompletion,
    ], async (ops) => {
      const reservation = parseProbeReservation(await required(ops,
        B26_STORES.probeReservation, probeKeyHex, 'probe reservation'));
      const completion = buildProbeCompletion({ probeKeyHex,
        reservationDigestHex: reservation.reservationDigestHex, ciphertextDigestHex,
        plaintextDigestHex, peerIdentityHex });
      const existing = await ops.get(B26_STORES.probeCompletion, probeKeyHex);
      if (existing !== undefined) {
        const prior = parseProbeCompletion(existing);
        if (prior.completionDigestHex !== completion.completionDigestHex) {
          failB26(B26_ERROR.CORRUPT, 'probe completion cannot be replaced');
        }
        return Object.freeze({ status: 'duplicate', reservation, completion: prior });
      }
      await ops.put(B26_STORES.probeCompletion, probeKeyHex, completion);
      return Object.freeze({ status: 'completed', reservation, completion });
    });
  }

  async readProbe(probeKeyHex) {
    assertHex64('probeKeyHex', probeKeyHex);
    return this.#db.transaction([
      B26_STORES.probeReservation, B26_STORES.probeCompletion,
    ], async (ops) => {
      const raw = await ops.get(B26_STORES.probeReservation, probeKeyHex);
      if (raw === undefined) return null;
      const completionRaw = await ops.get(B26_STORES.probeCompletion, probeKeyHex);
      return Object.freeze({ reservation: parseProbeReservation(raw),
        completion: completionRaw === undefined ? null : parseProbeCompletion(completionRaw) });
    });
  }

  async readMessageContext(groupIdHex) {
    assertGroupIdHex(groupIdHex);
    return this.#db.transaction(MESSAGE_TRANSACTION_STORES, async (ops) => {
      const head = parseHead(await required(ops, B26_STORES.head, groupIdHex,
        'canonical head'));
      if (head.state !== B26_HEAD_STATE.STABLE) {
        failB26(B26_ERROR.UNRECOVERABLE, 'application messages require a stable head');
      }
      const retained = parseRetainedState(await required(ops, B26_STORES.retained,
        head.snapshotDigestHex, 'canonical retained state'));
      const instanceKeyHex = messageInstanceKey({ groupIdHex,
        tipCommitDigestHex: head.selectedCommitDigestHex, epochDec: head.epochDec,
        groupContextDigestHex: head.groupContextDigestHex,
        localMemberIdentityHex: head.accountKeyHex });
      const key = messageStateKey(groupIdHex, instanceKeyHex);
      const releaseRaw = await ops.get(B26_STORES.messageRelease, key);
      if (releaseRaw !== undefined) {
        failB26(B26_ERROR.RELEASED, 'message instance was logically released',
          { release: parseMessageRelease(releaseRaw) });
      }
      const stateRaw = await ops.get(B26_STORES.messageState, key);
      if (stateRaw === undefined) {
        return Object.freeze({ head, retained, instanceKeyHex, state: null, snapshot: null });
      }
      const state = parseMessageState(stateRaw);
      if (state.instanceKeyHex !== instanceKeyHex
        || state.groupContextDigestHex !== head.groupContextDigestHex
        || state.epochDec !== head.epochDec) {
        failB26(B26_ERROR.CORRUPT, 'message-state does not bind the canonical instance');
      }
      const snapshot = parseMessageSnapshot(await required(ops,
        B26_STORES.messageSnapshot,
        messageSnapshotKey(instanceKeyHex, state.snapshotDigestHex),
        'current message snapshot'));
      if (snapshot.instanceKeyHex !== instanceKeyHex
        || snapshot.snapshotDigestHex !== state.snapshotDigestHex) {
        failB26(B26_ERROR.CORRUPT, 'message snapshot lacks current-state authority');
      }
      return Object.freeze({ head, retained, instanceKeyHex, state, snapshot });
    });
  }

  async findOutboxRequest(instanceKeyHex, requestId) {
    assertHex64('instanceKeyHex', instanceKeyHex);
    assertString('requestId', requestId,
      { min: 1, max: B26_LIMITS.maxRequestIdBytes, pattern: /^[\x21-\x7e]+$/ });
    return this.#db.transaction([B26_STORES.appOutbox], async (ops) => {
      for (const key of await ops.list(B26_STORES.appOutbox)) {
        if (typeof key !== 'string' || !key.startsWith(`${instanceKeyHex}:`)) continue;
        const record = parseOutbox(await required(ops, B26_STORES.appOutbox, key,
          'outbox record'));
        if (record.requestId === requestId) return record;
      }
      return null;
    });
  }

  async readOutbox(instanceKeyHex, ordinal) {
    const raw = await this.#db.transaction([B26_STORES.appOutbox], (ops) =>
      ops.get(B26_STORES.appOutbox, outboxKey(instanceKeyHex, ordinal)));
    if (raw === undefined) failB26(B26_ERROR.NOT_FOUND, 'outbox record is absent');
    return parseOutbox(raw);
  }

  async readInbound(instanceKeyHex, ciphertextDigestHex) {
    const raw = await this.#db.transaction([B26_STORES.appInbound], (ops) =>
      ops.get(B26_STORES.appInbound, inboundKey(instanceKeyHex, ciphertextDigestHex)));
    return raw === undefined ? null : parseInbound(raw);
  }

  async readAppPublications(instanceKeyHex, ordinal) {
    assertHex64('instanceKeyHex', instanceKeyHex);
    assertSafeInteger('outbox ordinal', ordinal, 1, Number.MAX_SAFE_INTEGER);
    const prefix = instanceKeyHex + ':' + String(ordinal).padStart(16, '0') + ':';
    return this.#db.transaction([B26_STORES.appPublication], async (ops) => {
      const records = [];
      for (const key of (await ops.list(B26_STORES.appPublication)).sort()) {
        if (typeof key !== 'string' || !key.startsWith(prefix)) continue;
        records.push(parseAppPublication(await required(
          ops, B26_STORES.appPublication, key, 'application publication record')));
      }
      return Object.freeze(records);
    });
  }

  async #commitOutbound({ expectedHead, expectedMessageState, nextMessageState,
    nextSnapshot, outbox }) {
    const head = parseHead(expectedHead);
    const prior = expectedMessageState === null ? null : parseMessageState(expectedMessageState);
    const next = parseMessageState(nextMessageState);
    const snapshot = parseMessageSnapshot(nextSnapshot);
    const queued = parseOutbox(outbox);
    if (next.groupIdHex !== head.groupIdHex || queued.groupIdHex !== head.groupIdHex
      || next.instanceKeyHex !== queued.instanceKeyHex
      || snapshot.instanceKeyHex !== next.instanceKeyHex
      || snapshot.snapshotDigestHex !== next.snapshotDigestHex
      || next.priorStateDigestHex !== (prior?.stateDigestHex ?? null)
      || next.sequence !== (prior?.sequence ?? 0) + 1
      || next.sentCount !== (prior?.sentCount ?? 0) + 1
      || next.receivedCount !== (prior?.receivedCount ?? 0)
      || queued.ordinal !== next.sentCount) {
      failB26(B26_ERROR.INVALID, 'outbound successor bindings are incoherent');
    }
    return this.#db.transaction(MESSAGE_TRANSACTION_STORES, async (ops) => {
      const currentHead = parseHead(await required(ops, B26_STORES.head,
        head.groupIdHex, 'canonical head'));
      if (currentHead.headDigestHex !== head.headDigestHex) {
        failB26(B26_ERROR.CAS_CONFLICT, 'canonical head changed before outbound commit');
      }
      const stateKey = messageStateKey(head.groupIdHex, next.instanceKeyHex);
      if (await ops.get(B26_STORES.messageRelease, stateKey) !== undefined) {
        failB26(B26_ERROR.RELEASED, 'message instance was released before outbound commit');
      }
      const currentRaw = await ops.get(B26_STORES.messageState, stateKey);
      const current = currentRaw === undefined ? null : parseMessageState(currentRaw);
      if ((current?.stateDigestHex ?? null) !== (prior?.stateDigestHex ?? null)) {
        failB26(B26_ERROR.CAS_CONFLICT, 'message position changed before outbound commit');
      }
      for (const key of await ops.list(B26_STORES.appOutbox)) {
        if (typeof key !== 'string' || !key.startsWith(`${next.instanceKeyHex}:`)) continue;
        const existing = parseOutbox(await required(ops, B26_STORES.appOutbox, key,
          'outbox record'));
        if (existing.requestId !== queued.requestId) continue;
        if (existing.payloadDigestHex !== queued.payloadDigestHex
          || existing.recipientScope.length !== queued.recipientScope.length
          || existing.recipientScope.some((item, index) => item !== queued.recipientScope[index])) {
          failB26(B26_ERROR.REQUEST_CONFLICT, 'request id was reused with different inputs');
        }
        return Object.freeze({ status: 'duplicate', state: current, outbox: existing });
      }
      const records = [];
      for (const key of await ops.list(B26_STORES.appOutbox)) {
        if (typeof key === 'string' && key.startsWith(`${next.instanceKeyHex}:`)) {
          records.push(parseOutbox(await required(ops, B26_STORES.appOutbox, key,
            'outbox record')));
        }
      }
      const nonTerminal = records.filter((record) => ![
        B26_OUTBOX_STATE.ACKNOWLEDGED, B26_OUTBOX_STATE.FAILED_DISCARDED,
        B26_OUTBOX_STATE.INVALIDATED,
      ].includes(record.state));
      if (nonTerminal.length >= B26_LIMITS.maxOutboxPerInstance) {
        failB26(B26_ERROR.RESOURCE_LIMIT, 'non-terminal outbox cap is exhausted');
      }
      await Promise.all([
        ops.put(B26_STORES.messageSnapshot,
          messageSnapshotKey(next.instanceKeyHex, snapshot.snapshotDigestHex), snapshot),
        ops.put(B26_STORES.messageState, stateKey, next),
        ops.put(B26_STORES.appOutbox, outboxKey(next.instanceKeyHex, queued.ordinal), queued),
      ]);
      if (prior !== null && prior.snapshotDigestHex !== snapshot.snapshotDigestHex) {
        await ops.delete(B26_STORES.messageSnapshot,
          messageSnapshotKey(prior.instanceKeyHex, prior.snapshotDigestHex));
      }
      return Object.freeze({ status: 'committed', state: next, outbox: queued });
    });
  }

  async #commitInbound({ expectedHead, expectedMessageState, nextMessageState,
    nextSnapshot, inbound }) {
    const head = parseHead(expectedHead);
    const prior = expectedMessageState === null ? null : parseMessageState(expectedMessageState);
    const next = parseMessageState(nextMessageState);
    const snapshot = parseMessageSnapshot(nextSnapshot);
    const delivery = parseInbound(inbound);
    if (delivery.disposition !== B26_INBOUND_STATE.ACCEPTED
      || next.groupIdHex !== head.groupIdHex || delivery.groupIdHex !== head.groupIdHex
      || next.instanceKeyHex !== delivery.instanceKeyHex
      || snapshot.instanceKeyHex !== next.instanceKeyHex
      || snapshot.snapshotDigestHex !== next.snapshotDigestHex
      || next.priorStateDigestHex !== (prior?.stateDigestHex ?? null)
      || next.sequence !== (prior?.sequence ?? 0) + 1
      || next.sentCount !== (prior?.sentCount ?? 0)
      || next.receivedCount !== (prior?.receivedCount ?? 0) + 1
      || delivery.receivedOrdinal !== next.receivedCount) {
      failB26(B26_ERROR.INVALID, 'inbound successor bindings are incoherent');
    }
    return this.#db.transaction(MESSAGE_TRANSACTION_STORES, async (ops) => {
      const currentHead = parseHead(await required(ops, B26_STORES.head,
        head.groupIdHex, 'canonical head'));
      if (currentHead.headDigestHex !== head.headDigestHex) {
        failB26(B26_ERROR.CAS_CONFLICT, 'canonical head changed before inbound commit');
      }
      const stateKey = messageStateKey(head.groupIdHex, next.instanceKeyHex);
      const existingInbound = await ops.get(B26_STORES.appInbound,
        inboundKey(next.instanceKeyHex, delivery.ciphertextDigestHex));
      if (existingInbound !== undefined) {
        return Object.freeze({ status: 'duplicate', state: prior,
          inbound: parseInbound(existingInbound) });
      }
      const currentRaw = await ops.get(B26_STORES.messageState, stateKey);
      const current = currentRaw === undefined ? null : parseMessageState(currentRaw);
      if ((current?.stateDigestHex ?? null) !== (prior?.stateDigestHex ?? null)) {
        failB26(B26_ERROR.CAS_CONFLICT, 'message position changed before inbound commit');
      }
      const inboundCount = (await ops.list(B26_STORES.appInbound))
        .filter((key) => typeof key === 'string' && key.startsWith(`${next.instanceKeyHex}:`))
        .length;
      if (inboundCount >= B26_LIMITS.maxInboundPerInstance) {
        failB26(B26_ERROR.RESOURCE_LIMIT, 'inbound history cap is exhausted');
      }
      await Promise.all([
        ops.put(B26_STORES.messageSnapshot,
          messageSnapshotKey(next.instanceKeyHex, snapshot.snapshotDigestHex), snapshot),
        ops.put(B26_STORES.messageState, stateKey, next),
        ops.put(B26_STORES.appInbound,
          inboundKey(next.instanceKeyHex, delivery.ciphertextDigestHex), delivery),
      ]);
      if (prior !== null && prior.snapshotDigestHex !== snapshot.snapshotDigestHex) {
        await ops.delete(B26_STORES.messageSnapshot,
          messageSnapshotKey(prior.instanceKeyHex, prior.snapshotDigestHex));
      }
      return Object.freeze({ status: 'accepted', state: next, inbound: delivery });
    });
  }

  async #appendAppPublication({ expectedOutbox, nextOutbox, evidence }) {
    const prior = parseOutbox(expectedOutbox);
    const next = parseOutbox(nextOutbox);
    const record = parseAppPublication(evidence);
    if (prior.instanceKeyHex !== next.instanceKeyHex || prior.ordinal !== next.ordinal
      || record.instanceKeyHex !== prior.instanceKeyHex || record.ordinal !== prior.ordinal) {
      failB26(B26_ERROR.INVALID, 'application publication changes outbox identity');
    }
    return this.#db.transaction([B26_STORES.appOutbox, B26_STORES.appPublication],
      async (ops) => {
        const key = outboxKey(prior.instanceKeyHex, prior.ordinal);
        const current = parseOutbox(await required(ops, B26_STORES.appOutbox, key,
          'outbox record'));
        if (current.outboxDigestHex !== prior.outboxDigestHex) {
          failB26(B26_ERROR.CAS_CONFLICT, 'outbox changed before evidence append');
        }
        const prefix = `${prior.instanceKeyHex}:${String(prior.ordinal).padStart(16, '0')}:`;
        const count = (await ops.list(B26_STORES.appPublication))
          .filter((item) => typeof item === 'string' && item.startsWith(prefix)).length;
        if (record.sequence !== count + 1) {
          failB26(B26_ERROR.CAS_CONFLICT, 'application publication sequence changed');
        }
        await Promise.all([
          ops.put(B26_STORES.appPublication,
            appPublicationKey(record.instanceKeyHex, record.ordinal, record.sequence), record),
          ops.put(B26_STORES.appOutbox, key, next),
        ]);
        return Object.freeze({ outbox: next, evidence: record });
      });
  }

  createEngineAdapter({ wasm, beforeReplay = async () => {},
    afterProbeReservation = async () => {},
    beforeOutboundCommit = async () => {},
    beforeInboundCommit = async () => {} } = {}) {
    return createBoundB26EngineAdapter({
      wasm, journal: this,
      initializeJournal: this.#initialize.bind(this),
      commitSettlement: this.#commitSettlement.bind(this),
      markUnrecoverable: this.#markUnrecoverable.bind(this),
      commitPrepared: this.#commitPrepared.bind(this),
      replaceGeneration: this.#replaceGeneration.bind(this),
      appendPublication: this.#appendPublication.bind(this),
      commitOutbound: this.#commitOutbound.bind(this),
      commitInbound: this.#commitInbound.bind(this),
      appendAppPublication: this.#appendAppPublication.bind(this),
      beforeReplay, afterProbeReservation, beforeOutboundCommit, beforeInboundCommit,
    });
  }

  close() { this.#db.close?.(); }

  destroy() { return this.#db.destroy(); }
}

export function createB26JournalForDb(db) {
  if (typeof db?.name !== 'string' || !db.name.startsWith(B26_DB_PREFIX)) {
    failB26(B26_ERROR.INVALID, 'database is outside the B2.6 namespace');
  }
  return new B26Journal(db, JOURNAL_TOKEN);
}

export async function openB26Journal({
  databaseTag,
  indexedDBImpl = globalThis.indexedDB,
  setTimeoutImpl = globalThis.setTimeout.bind(globalThis),
  clearTimeoutImpl = globalThis.clearTimeout.bind(globalThis),
} = {}) {
  assertString('databaseTag', databaseTag, { min: 1, max: 64, pattern: /^[a-z0-9-]+$/ });
  const db = await openVaultDb({
    name: `${B26_DB_PREFIX}${databaseTag}`,
    version: 1,
    migrations: { 1: migrationV1 },
    indexedDBImpl,
    setTimeoutImpl,
    clearTimeoutImpl,
  });
  return createB26JournalForDb(db);
}

export { rebuildGeneration, rebuildInput };
