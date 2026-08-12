// STYX_SPIKE_PROTOTYPE — atomic retained-graph journal for Phase B2.5c only.

import { openVaultDb } from '../../src/storage/vault-db.js';
import {
  B25C_DB_PREFIX,
  B25C_ERROR,
  B25C_GENERATION_STATE,
  B25C_HEAD_STATE,
  B25C_INPUT_STATE,
  B25C_LIMITS,
  B25C_PASS_STATE,
  B25C_STORES,
  B25C_STORE_NAMES,
  assertBytes,
  assertGroupIdHex,
  assertHex64,
  assertString,
  bytesEqual,
  canonicalB25CBytes,
  digestHex,
  edgeKey,
  failB25C,
  generationKey,
  generationAuthorityDigest,
  inputKey,
  probeKey,
  publicationKey,
} from './b2-5c-canonical.mjs';
import {
  GENERATION_FIELDS,
  buildGenerationTruncation,
  INPUT_FIELDS,
  buildActiveLocal,
  buildGeneration,
  buildHead,
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
  parseInput,
  parseInvalidation,
  parsePass,
  parseProbeCompletion,
  parseProbeReservation,
  parsePublication,
  parseRelease,
  parseRetainedState,
  parseTransition,
} from './b2-5c-record.mjs';
import { createBoundB25CEngineAdapter } from './b2-5c-engine-adapter.mjs';

const JOURNAL_TOKEN = Symbol('B25C_JOURNAL_TOKEN');
const SNAPSHOT_STORES = Object.freeze([
  B25C_STORES.head, B25C_STORES.retained, B25C_STORES.released,
  B25C_STORES.input, B25C_STORES.edge, B25C_STORES.pass,
  B25C_STORES.transition, B25C_STORES.invalidation, B25C_STORES.generation,
  B25C_STORES.generationTruncation, B25C_STORES.activeLocal, B25C_STORES.publication,
]);

function migrationV1(db) {
  for (const name of B25C_STORE_NAMES) db.createObjectStore(name);
}

async function required(ops, store, key, label) {
  const value = await ops.get(store, key);
  if (value === undefined) failB25C(B25C_ERROR.CORRUPT, `${label} is missing`);
  return value;
}

function recordDigest(store, record) {
  const fields = {
    [B25C_STORES.head]: 'headDigestHex',
    [B25C_STORES.retained]: 'retainedDigestHex',
    [B25C_STORES.released]: 'releaseDigestHex',
    [B25C_STORES.input]: 'inputDigestHex',
    [B25C_STORES.edge]: 'edgeDigestHex',
    [B25C_STORES.pass]: 'passRecordDigestHex',
    [B25C_STORES.transition]: 'transitionDigestHex',
    [B25C_STORES.invalidation]: 'invalidationDigestHex',
    [B25C_STORES.generation]: 'generationDigestHex',
    [B25C_STORES.generationTruncation]: 'markerDigestHex',
    [B25C_STORES.activeLocal]: 'pointerDigestHex',
    [B25C_STORES.publication]: 'evidenceDigestHex',
  };
  const field = fields[store];
  if (field === undefined || record[field] === undefined) {
    failB25C(B25C_ERROR.CORRUPT, 'record lacks a content digest');
  }
  return record[field];
}

function parseStoreRecord(store, raw) {
  if (store === B25C_STORES.head) return parseHead(raw);
  if (store === B25C_STORES.retained) return parseRetainedState(raw);
  if (store === B25C_STORES.released) return parseRelease(raw);
  if (store === B25C_STORES.input) return parseInput(raw);
  if (store === B25C_STORES.edge) return parseEdge(raw);
  if (store === B25C_STORES.pass) return parsePass(raw);
  if (store === B25C_STORES.transition) return parseTransition(raw);
  if (store === B25C_STORES.invalidation) return parseInvalidation(raw);
  if (store === B25C_STORES.generation) return parseGeneration(raw);
  if (store === B25C_STORES.generationTruncation) return parseGenerationTruncation(raw);
  if (store === B25C_STORES.activeLocal) return parseActiveLocal(raw);
  if (store === B25C_STORES.publication) return parsePublication(raw);
  failB25C(B25C_ERROR.CORRUPT, 'unexpected snapshot store');
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
  const headEntry = stores[B25C_STORES.head].find(({ key }) => key === groupIdHex);
  if (headEntry === undefined) failB25C(B25C_ERROR.NOT_FOUND, 'canonical head is absent');
  const head = headEntry.record;
  const groupEntries = (store) => stores[store]
    .filter(({ record }) => record.groupIdHex === undefined || record.groupIdHex === groupIdHex)
    .map(({ record }) => record);
  return Object.freeze({
    head,
    retained: Object.freeze(groupEntries(B25C_STORES.retained)),
    released: Object.freeze(groupEntries(B25C_STORES.released)),
    inputs: Object.freeze(groupEntries(B25C_STORES.input)),
    edges: Object.freeze(groupEntries(B25C_STORES.edge)),
    passes: Object.freeze(groupEntries(B25C_STORES.pass)),
    transitions: Object.freeze(groupEntries(B25C_STORES.transition)),
    invalidations: Object.freeze(groupEntries(B25C_STORES.invalidation)),
    generations: Object.freeze(groupEntries(B25C_STORES.generation)),
    generationTruncation: groupEntries(B25C_STORES.generationTruncation)[0] ?? null,
    activeLocal: groupEntries(B25C_STORES.activeLocal)[0] ?? null,
    publications: Object.freeze(groupEntries(B25C_STORES.publication)),
    readSetDigestHex: digestHex(canonicalB25CBytes('JOURNAL-READ-SET', readSet)),
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

export class B25CJournal {
  #db;

  constructor(db, token) {
    if (token !== JOURNAL_TOKEN) {
      failB25C(B25C_ERROR.INVALID, 'B2.5c journals must be created by the namespace factory');
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
      groupIdHex, accountKeyHex, signatureKeyHex, seq: 1, state: B25C_HEAD_STATE.STABLE,
      epochDec, groupContextDigestHex, snapshotDigestHex: retained.snapshotDigestHex,
      anchorSnapshotDigestHex: retained.snapshotDigestHex, canonicalPath: [],
      priorHeadDigestHex: null, transitionDigestHex: transition.transitionDigestHex,
      selectedCommitDigestHex: null,
    });
    await this.#db.transaction(B25C_STORE_NAMES, async (ops) => {
      for (const store of B25C_STORE_NAMES) {
        if ((await ops.list(store)).length !== 0) {
          failB25C(B25C_ERROR.CAS_CONFLICT, 'private one-group B2.5c journal is not empty');
        }
      }
      await Promise.all([
        ops.put(B25C_STORES.retained, retained.snapshotDigestHex, retained),
        ops.put(B25C_STORES.transition, transition.transitionDigestHex, transition),
        ops.put(B25C_STORES.head, groupIdHex, head),
        ops.put(B25C_STORES.activeLocal, groupIdHex,
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
    if (retained === undefined && snapshot.head.state !== B25C_HEAD_STATE.UNRECOVERABLE) {
      const released = snapshot.released.find((item) =>
        item.snapshotDigestHex === snapshot.head.snapshotDigestHex);
      if (released !== undefined) {
        failB25C(B25C_ERROR.RELEASED, 'canonical state was logically released', { released });
      }
      failB25C(B25C_ERROR.CORRUPT, 'canonical retained state is missing');
    }
    return Object.freeze({ head: snapshot.head, retained: retained ?? null,
      transition: snapshot.transitions.find((item) =>
        item.transitionDigestHex === snapshot.head.transitionDigestHex) ?? null });
  }

  async readRetained(snapshotDigestHex) {
    assertHex64('snapshotDigestHex', snapshotDigestHex);
    return this.#db.transaction([B25C_STORES.retained, B25C_STORES.released], async (ops) => {
      const raw = await ops.get(B25C_STORES.retained, snapshotDigestHex);
      if (raw !== undefined) return parseRetainedState(raw);
      const released = await ops.get(B25C_STORES.released, snapshotDigestHex);
      if (released !== undefined) {
        const tombstone = parseRelease(released);
        failB25C(B25C_ERROR.RELEASED, 'retained state was logically released', { tombstone });
      }
      failB25C(B25C_ERROR.NOT_FOUND, 'retained state is absent', { snapshotDigestHex });
    });
  }

  async admitCommit(groupIdHex, commitBytes) {
    assertGroupIdHex(groupIdHex);
    assertBytes('Commit bytes', commitBytes, { min: 1, max: B25C_LIMITS.maxCommitBytes });
    const proposed = buildInput({ groupIdHex, commitBytes });
    return this.#db.transaction(SNAPSHOT_STORES, async (ops) => {
      const view = await readSnapshotFromOps(ops, groupIdHex);
      if (view.head.state !== B25C_HEAD_STATE.STABLE) {
        failB25C(B25C_ERROR.UNRECOVERABLE, 'input admission requires a stable group');
      }
      const generation = view.generations.find((item) =>
        item.commitDigestHex === proposed.commitDigestHex);
      if (generation !== undefined) {
        if (!bytesEqual(generation.commitBytes, proposed.commitBytes)) {
          failB25C(B25C_ERROR.CORRUPT, 'local generation digest collision');
        }
        return Object.freeze({ status: 'own_echo', generation });
      }
      const existing = view.inputs.find((item) =>
        item.commitDigestHex === proposed.commitDigestHex);
      if (existing !== undefined) {
        if (!bytesEqual(existing.commitBytes, proposed.commitBytes)) {
          failB25C(B25C_ERROR.CORRUPT, 'Commit digest collision');
        }
        return Object.freeze({ status: 'duplicate', input: existing });
      }
      if (view.inputs.length >= B25C_LIMITS.maxInputs) {
        failB25C(B25C_ERROR.RESOURCE_LIMIT, 'retained raw-input cap is exhausted');
      }
      await ops.put(B25C_STORES.input,
        inputKey(groupIdHex, proposed.commitDigestHex), proposed);
      return Object.freeze({ status: 'retained', input: proposed });
    });
  }

  async freeze(groupIdHex) {
    assertGroupIdHex(groupIdHex);
    return this.#db.transaction(SNAPSHOT_STORES, async (ops) => {
      const view = await readSnapshotFromOps(ops, groupIdHex);
      if (view.head.state !== B25C_HEAD_STATE.STABLE) {
        failB25C(B25C_ERROR.UNRECOVERABLE, 'pass freeze requires a stable group');
      }
      if (view.passes.some((item) => item.state === B25C_PASS_STATE.FROZEN)) {
        failB25C(B25C_ERROR.STATE_CONFLICT, 'one frozen pass already awaits settlement');
      }
      if (view.passes.length >= B25C_LIMITS.maxPasses) {
        failB25C(B25C_ERROR.RESOURCE_LIMIT, 'pass history cap is exhausted');
      }
      const eligibleLocal = view.generations.filter((item) => [
        B25C_GENERATION_STATE.ACKNOWLEDGED,
        B25C_GENERATION_STATE.SELECTED,
        B25C_GENERATION_STATE.LOSING,
      ].includes(item.state) && !item.contradiction);
      const closure = [...view.inputs.map((item) => item.commitDigestHex),
        ...eligibleLocal.map((item) => item.commitDigestHex)].sort();
      const unique = [...new Set(closure)];
      if (unique.length !== closure.length) failB25C(B25C_ERROR.CORRUPT, 'input closure collides');
      if (unique.length === 0) failB25C(B25C_ERROR.STATE_CONFLICT, 'cannot freeze an empty pass');
      if (unique.length > B25C_LIMITS.maxInputs) {
        failB25C(B25C_ERROR.RESOURCE_LIMIT, 'frozen input closure exceeds its cap');
      }
      const pass = buildPass({ groupIdHex, baseHeadDigestHex: view.head.headDigestHex,
        closureCommitDigests: unique });
      if (await ops.get(B25C_STORES.pass, pass.passDigestHex) !== undefined) {
        failB25C(B25C_ERROR.CAS_CONFLICT, 'identical frozen pass already exists');
      }
      await ops.put(B25C_STORES.pass, pass.passDigestHex, pass);
      return pass;
    });
  }

  async readFrozen(passDigestHex) {
    assertHex64('passDigestHex', passDigestHex);
    return this.#db.transaction(SNAPSHOT_STORES, async (ops) => {
      const pass = parsePass(await required(ops, B25C_STORES.pass, passDigestHex, 'pass'));
      if (pass.state !== B25C_PASS_STATE.FROZEN) {
        failB25C(B25C_ERROR.STATE_CONFLICT, 'pass is already settled');
      }
      const view = await readSnapshotFromOps(ops, pass.groupIdHex);
      if (view.head.headDigestHex !== pass.baseHeadDigestHex) {
        failB25C(B25C_ERROR.CAS_CONFLICT, 'frozen pass no longer binds the canonical head');
      }
      const actual = [...view.inputs.map((item) => item.commitDigestHex),
        ...view.generations.filter((item) => [
          B25C_GENERATION_STATE.ACKNOWLEDGED,
          B25C_GENERATION_STATE.SELECTED,
          B25C_GENERATION_STATE.LOSING,
        ].includes(item.state) && !item.contradiction)
          .map((item) => item.commitDigestHex)].sort();
      if (actual.length !== pass.closureCommitDigests.length
        || actual.some((item, index) => item !== pass.closureCommitDigests[index])) {
        failB25C(B25C_ERROR.CAS_CONFLICT, 'frozen input closure changed');
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
    if (settledPass.state !== B25C_PASS_STATE.SETTLED
      || nextHead.groupIdHex !== expectedHead.groupIdHex
      || nextHead.priorHeadDigestHex !== expectedHead.headDigestHex
      || nextHead.transitionDigestHex !== transition.transitionDigestHex
      || transition.predecessorHeadDigestHex !== expectedHead.headDigestHex
      || transition.passDigestHex !== settledPass.passDigestHex
      || transition.invalidationDigestHex !== invalidation.invalidationDigestHex
      || invalidation.predecessorHeadDigestHex !== expectedHead.headDigestHex
      || invalidation.successorSnapshotDigestHex !== nextHead.snapshotDigestHex) {
      failB25C(B25C_ERROR.INVALID, 'settlement output has incoherent authority bindings');
    }
    return this.#db.transaction(SNAPSHOT_STORES, async (ops) => {
      const current = await readSnapshotFromOps(ops, expectedHead.groupIdHex);
      if (current.head.headDigestHex !== expectedHead.headDigestHex
        || current.readSetDigestHex !== decision.expectedReadSetDigestHex) {
        failB25C(B25C_ERROR.CAS_CONFLICT, 'complete settlement read set changed');
      }
      const currentPass = current.passes.find((item) =>
        item.passDigestHex === settledPass.passDigestHex);
      if (currentPass?.state !== B25C_PASS_STATE.FROZEN) {
        failB25C(B25C_ERROR.CAS_CONFLICT, 'frozen pass disappeared or changed');
      }
      const writes = [];
      for (const state of states) {
        const prior = await ops.get(B25C_STORES.retained, state.snapshotDigestHex);
        if (prior !== undefined
          && parseRetainedState(prior).retainedDigestHex !== state.retainedDigestHex) {
          failB25C(B25C_ERROR.CORRUPT, 'retained-state content-address collision');
        }
        writes.push(ops.put(B25C_STORES.retained, state.snapshotDigestHex, state));
      }
      for (const edge of edges) {
        const key = edgeKey(edge.groupIdHex, edge.parentSnapshotDigestHex, edge.commitDigestHex);
        const prior = await ops.get(B25C_STORES.edge, key);
        if (prior !== undefined && parseEdge(prior).edgeDigestHex !== edge.edgeDigestHex) {
          failB25C(B25C_ERROR.CORRUPT, 'replay-edge identity collision');
        }
        writes.push(ops.put(B25C_STORES.edge, key, edge));
      }
      const retainedEdgeKeys = new Set(edges.map((edge) =>
        edgeKey(edge.groupIdHex, edge.parentSnapshotDigestHex, edge.commitDigestHex)));
      for (const priorEdge of current.edges) {
        const key = edgeKey(priorEdge.groupIdHex,
          priorEdge.parentSnapshotDigestHex, priorEdge.commitDigestHex);
        if (!retainedEdgeKeys.has(key)) writes.push(ops.delete(B25C_STORES.edge, key));
      }
      for (const input of inputs) writes.push(ops.put(B25C_STORES.input,
        inputKey(input.groupIdHex, input.commitDigestHex), input));
      for (const generation of generations) writes.push(ops.put(B25C_STORES.generation,
        generationKey(generation.groupIdHex, generation.commitDigestHex), generation));
      const activePointer = current.activeLocal;
      if (activePointer?.generationDigestHex !== null) {
        const priorActive = current.generations.find((item) =>
          item.generationDigestHex === activePointer.generationDigestHex);
        const nextActive = generations.find((item) =>
          item.commitDigestHex === priorActive?.commitDigestHex);
        if (nextActive !== undefined && [B25C_GENERATION_STATE.SELECTED,
          B25C_GENERATION_STATE.LOSING, B25C_GENERATION_STATE.REJECTED]
          .includes(nextActive.state)) {
          writes.push(ops.put(B25C_STORES.activeLocal, nextActive.groupIdHex,
            buildActiveLocal({ groupIdHex: nextActive.groupIdHex,
              generationDigestHex: null })));
        }
      }
      writes.push(ops.put(B25C_STORES.pass, settledPass.passDigestHex, settledPass));
      writes.push(ops.put(B25C_STORES.invalidation,
        invalidation.invalidationDigestHex, invalidation));
      writes.push(ops.put(B25C_STORES.transition, transition.transitionDigestHex, transition));
      for (const release of releases) {
        const retainedRaw = await ops.get(B25C_STORES.retained, release.snapshotDigestHex);
        if (retainedRaw === undefined
          || parseRetainedState(retainedRaw).retainedDigestHex !== release.retainedDigestHex) {
          failB25C(B25C_ERROR.CAS_CONFLICT, 'logical release target changed');
        }
        writes.push(ops.put(B25C_STORES.released, release.snapshotDigestHex, release));
        writes.push(ops.delete(B25C_STORES.retained, release.snapshotDigestHex));
      }
      writes.push(ops.put(B25C_STORES.head, nextHead.groupIdHex, nextHead));
      await Promise.all(writes);
      return Object.freeze({ head: nextHead, pass: settledPass, transition, invalidation,
        states: Object.freeze(states), edges: Object.freeze(edges),
        inputs: Object.freeze(inputs), releases: Object.freeze(releases) });
    });
  }

  async #markUnrecoverable(expectedHead) {
    const prior = parseHead(expectedHead);
    if (prior.state !== B25C_HEAD_STATE.STABLE) {
      failB25C(B25C_ERROR.UNRECOVERABLE, 'group is already unrecoverable');
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
      state: B25C_HEAD_STATE.UNRECOVERABLE,
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
        failB25C(B25C_ERROR.CAS_CONFLICT,
          'canonical head changed before unrecoverable transition');
      }
      await Promise.all([
        ops.put(B25C_STORES.transition, transition.transitionDigestHex, transition),
        ops.put(B25C_STORES.head, next.groupIdHex, next),
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
      failB25C(B25C_ERROR.INVALID, 'local generation does not bind its parent');
    }
    return this.#db.transaction(SNAPSHOT_STORES, async (ops) => {
      const view = await readSnapshotFromOps(ops, head.groupIdHex);
      if (view.head.headDigestHex !== head.headDigestHex
        || view.activeLocal?.generationDigestHex !== null) {
        failB25C(B25C_ERROR.CAS_CONFLICT, 'head or active-local pointer changed');
      }
      if (view.passes.some((item) => item.state === B25C_PASS_STATE.FROZEN)) {
        failB25C(B25C_ERROR.STATE_CONFLICT,
          'local preparation is excluded while a settlement pass is frozen');
      }
      const generationFloor = Math.max(view.generationTruncation?.throughGeneration ?? 0,
        ...view.generations.map((item) => item.generation));
      if (next.generation !== generationFloor + 1) {
        failB25C(B25C_ERROR.CAS_CONFLICT, 'local generation ordinal changed');
      }
      const writes = [
        ops.put(B25C_STORES.retained, retained.snapshotDigestHex, retained),
        ops.put(B25C_STORES.generation,
          generationKey(next.groupIdHex, next.commitDigestHex), next),
        ops.put(B25C_STORES.activeLocal, next.groupIdHex,
          buildActiveLocal({ groupIdHex: next.groupIdHex,
            generationDigestHex: next.generationDigestHex })),
      ];
      if (view.generations.length >= B25C_LIMITS.maxGenerations) {
        const evictableStates = new Set([
          B25C_GENERATION_STATE.CANCELLED,
          B25C_GENERATION_STATE.DISCARDED,
          B25C_GENERATION_STATE.REJECTED,
        ]);
        const evicted = [...view.generations]
          .sort((left, right) => left.generation - right.generation)
          .find((candidate) => evictableStates.has(candidate.state)
            && !view.edges.some((edge) => edge.localGenerationDigestHex
              === generationAuthorityDigest(candidate)));
        if (evicted === undefined) {
          failB25C(B25C_ERROR.RESOURCE_LIMIT,
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
          ops.delete(B25C_STORES.generation,
            generationKey(evicted.groupIdHex, evicted.commitDigestHex)),
          ops.put(B25C_STORES.generationTruncation, evicted.groupIdHex, marker),
        );
        const publicationPrefix = `${evicted.groupIdHex}:${evicted.commitDigestHex}:`;
        for (const key of await ops.list(B25C_STORES.publication)) {
          if (typeof key === 'string' && key.startsWith(publicationPrefix)) {
            writes.push(ops.delete(B25C_STORES.publication, key));
          }
        }
        if (!pendingRequired) {
          writes.push(ops.delete(B25C_STORES.retained, evicted.pendingSnapshotDigestHex));
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
      failB25C(B25C_ERROR.INVALID, 'generation replacement changes identity');
    }
    return this.#db.transaction(SNAPSHOT_STORES, async (ops) => {
      const raw = await required(ops, B25C_STORES.generation,
        generationKey(prior.groupIdHex, prior.commitDigestHex), 'local generation');
      if (parseGeneration(raw).generationDigestHex !== prior.generationDigestHex) {
        failB25C(B25C_ERROR.CAS_CONFLICT, 'local generation changed');
      }
      await ops.put(B25C_STORES.generation,
        generationKey(next.groupIdHex, next.commitDigestHex), next);
      if (clearActive) {
        const pointer = parseActiveLocal(await required(ops, B25C_STORES.activeLocal,
          prior.groupIdHex, 'active-local pointer'));
        if (pointer.generationDigestHex !== prior.generationDigestHex) {
          failB25C(B25C_ERROR.CAS_CONFLICT, 'active-local pointer changed');
        }
        await ops.put(B25C_STORES.activeLocal, prior.groupIdHex,
          buildActiveLocal({ groupIdHex: prior.groupIdHex, generationDigestHex: null }));
        if ([B25C_GENERATION_STATE.CANCELLED, B25C_GENERATION_STATE.DISCARDED,
          B25C_GENERATION_STATE.REJECTED].includes(next.state)) {
          const retainedRaw = await ops.get(
            B25C_STORES.retained, next.pendingSnapshotDigestHex);
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
              ops.put(B25C_STORES.released, release.snapshotDigestHex, release),
              ops.delete(B25C_STORES.retained, release.snapshotDigestHex),
            ]);
          }
        }
      } else {
        const pointer = parseActiveLocal(await required(ops, B25C_STORES.activeLocal,
          prior.groupIdHex, 'active-local pointer'));
        if (pointer.generationDigestHex === prior.generationDigestHex) {
          await ops.put(B25C_STORES.activeLocal, prior.groupIdHex,
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
      failB25C(B25C_ERROR.INVALID, 'publication evidence lacks exact generation authority');
    }
    return this.#db.transaction(SNAPSHOT_STORES, async (ops) => {
      const current = parseGeneration(await required(ops, B25C_STORES.generation,
        generationKey(prior.groupIdHex, prior.commitDigestHex), 'local generation'));
      if (current.generationDigestHex !== prior.generationDigestHex) {
        failB25C(B25C_ERROR.CAS_CONFLICT, 'local generation changed before evidence append');
      }
      const prefix = `${prior.groupIdHex}:${prior.commitDigestHex}:`;
      const keys = (await ops.list(B25C_STORES.publication))
        .filter((key) => typeof key === 'string' && key.startsWith(prefix)).sort();
      if (record.sequence !== keys.length + 1) {
        failB25C(B25C_ERROR.CAS_CONFLICT, 'publication sequence changed');
      }
      await Promise.all([
        ops.put(B25C_STORES.publication,
          publicationKey(prior.groupIdHex, prior.commitDigestHex, record.sequence), record),
        ops.put(B25C_STORES.generation,
          generationKey(next.groupIdHex, next.commitDigestHex), next),
      ]);
      const pointer = parseActiveLocal(await required(ops, B25C_STORES.activeLocal,
        prior.groupIdHex, 'active-local pointer'));
      if (pointer.generationDigestHex === prior.generationDigestHex) {
        await ops.put(B25C_STORES.activeLocal, prior.groupIdHex,
          buildActiveLocal({ groupIdHex: prior.groupIdHex,
            generationDigestHex: next.generationDigestHex }));
      }
      return Object.freeze({ evidence: record, generation: next });
    });
  }

  async reserveProbe(groupIdHex) {
    assertGroupIdHex(groupIdHex);
    return this.#db.transaction([
      B25C_STORES.head, B25C_STORES.retained, B25C_STORES.probeReservation,
      B25C_STORES.probeCompletion,
    ], async (ops) => {
      const head = parseHead(await required(ops, B25C_STORES.head, groupIdHex, 'canonical head'));
      if (head.state !== B25C_HEAD_STATE.STABLE) {
        failB25C(B25C_ERROR.UNRECOVERABLE, 'probe requires a stable canonical head');
      }
      const retained = parseRetainedState(await required(ops, B25C_STORES.retained,
        head.snapshotDigestHex, 'canonical retained state'));
      const key = probeKey({ groupIdHex, tipCommitDigestHex: head.selectedCommitDigestHex,
        epochDec: head.epochDec, groupContextDigestHex: head.groupContextDigestHex,
        localMemberIdentityHex: head.accountKeyHex });
      const existing = await ops.get(B25C_STORES.probeReservation, key);
      if (existing !== undefined) {
        const reservation = parseProbeReservation(existing);
        const completionRaw = await ops.get(B25C_STORES.probeCompletion, key);
        const completion = completionRaw === undefined ? null : parseProbeCompletion(completionRaw);
        failB25C(B25C_ERROR.PROBE_ALREADY_RESERVED,
          completion === null ? 'epoch instance is reserved without completion'
            : 'epoch instance already has completed liveness evidence',
          { probeKeyHex: key, completed: completion !== null, reservation, completion });
      }
      const count = (await ops.list(B25C_STORES.probeReservation)).length;
      if (count >= B25C_LIMITS.maxProbeReservations) {
        failB25C(B25C_ERROR.RESOURCE_LIMIT, 'probe reservation ledger is full');
      }
      const reservation = buildProbeReservation({
        groupIdHex, headDigestHex: head.headDigestHex,
        tipCommitDigestHex: head.selectedCommitDigestHex, epochDec: head.epochDec,
        groupContextDigestHex: head.groupContextDigestHex,
        localMemberIdentityHex: head.accountKeyHex, probeKeyHex: key,
      });
      await ops.put(B25C_STORES.probeReservation, key, reservation);
      return Object.freeze({ reservation, retained });
    });
  }

  async completeProbe({ probeKeyHex, ciphertextDigestHex, plaintextDigestHex,
    peerIdentityHex }) {
    assertHex64('probeKeyHex', probeKeyHex);
    return this.#db.transaction([
      B25C_STORES.probeReservation, B25C_STORES.probeCompletion,
    ], async (ops) => {
      const reservation = parseProbeReservation(await required(ops,
        B25C_STORES.probeReservation, probeKeyHex, 'probe reservation'));
      const completion = buildProbeCompletion({ probeKeyHex,
        reservationDigestHex: reservation.reservationDigestHex, ciphertextDigestHex,
        plaintextDigestHex, peerIdentityHex });
      const existing = await ops.get(B25C_STORES.probeCompletion, probeKeyHex);
      if (existing !== undefined) {
        const prior = parseProbeCompletion(existing);
        if (prior.completionDigestHex !== completion.completionDigestHex) {
          failB25C(B25C_ERROR.CORRUPT, 'probe completion cannot be replaced');
        }
        return Object.freeze({ status: 'duplicate', reservation, completion: prior });
      }
      await ops.put(B25C_STORES.probeCompletion, probeKeyHex, completion);
      return Object.freeze({ status: 'completed', reservation, completion });
    });
  }

  async readProbe(probeKeyHex) {
    assertHex64('probeKeyHex', probeKeyHex);
    return this.#db.transaction([
      B25C_STORES.probeReservation, B25C_STORES.probeCompletion,
    ], async (ops) => {
      const raw = await ops.get(B25C_STORES.probeReservation, probeKeyHex);
      if (raw === undefined) return null;
      const completionRaw = await ops.get(B25C_STORES.probeCompletion, probeKeyHex);
      return Object.freeze({ reservation: parseProbeReservation(raw),
        completion: completionRaw === undefined ? null : parseProbeCompletion(completionRaw) });
    });
  }

  createEngineAdapter({ wasm, beforeReplay = async () => {},
    afterProbeReservation = async () => {} } = {}) {
    return createBoundB25CEngineAdapter({
      wasm, journal: this,
      initializeJournal: this.#initialize.bind(this),
      commitSettlement: this.#commitSettlement.bind(this),
      markUnrecoverable: this.#markUnrecoverable.bind(this),
      commitPrepared: this.#commitPrepared.bind(this),
      replaceGeneration: this.#replaceGeneration.bind(this),
      appendPublication: this.#appendPublication.bind(this),
      beforeReplay, afterProbeReservation,
    });
  }

  close() { this.#db.close?.(); }

  destroy() { return this.#db.destroy(); }
}

export function createB25CJournalForDb(db) {
  if (typeof db?.name !== 'string' || !db.name.startsWith(B25C_DB_PREFIX)) {
    failB25C(B25C_ERROR.INVALID, 'database is outside the B2.5c namespace');
  }
  return new B25CJournal(db, JOURNAL_TOKEN);
}

export async function openB25CJournal({
  databaseTag,
  indexedDBImpl = globalThis.indexedDB,
  setTimeoutImpl = globalThis.setTimeout.bind(globalThis),
  clearTimeoutImpl = globalThis.clearTimeout.bind(globalThis),
} = {}) {
  assertString('databaseTag', databaseTag, { min: 1, max: 64, pattern: /^[a-z0-9-]+$/ });
  const db = await openVaultDb({
    name: `${B25C_DB_PREFIX}${databaseTag}`,
    version: 1,
    migrations: { 1: migrationV1 },
    indexedDBImpl,
    setTimeoutImpl,
    clearTimeoutImpl,
  });
  return createB25CJournalForDb(db);
}

export { rebuildGeneration, rebuildInput };
