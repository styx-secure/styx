// SPDX-License-Identifier: AGPL-3.0-or-later

import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  B32A_ERROR,
  B32A_PREPARATION,
  B32A_STATE,
  sha256Hex,
} from '../../spikes/marmot-phase-b3-2a/b3-2a-canonical.mjs';
import {
  B32aJournal,
  FileB32aStore,
  MemoryB32aStore,
} from '../../spikes/marmot-phase-b3-2a/b3-2a-journal.mjs';
import { B32aDurableJoinDriver } from '../../spikes/marmot-phase-b3-2a/b3-2a-driver.mjs';
import {
  b32aFixture,
  fakeNativeProjection,
} from '../../spikes/marmot-phase-b3-2a/b3-2a-test-support.mjs';

const bytes = (hex) => Uint8Array.from(Buffer.from(hex, 'hex'));

class FakeB32aEngine {
  constructor(values, mutateProjection = null) {
    this.values = values;
    this.mutateProjection = mutateProjection;
    this.prepareInputs = [];
    this.releasedCandidates = [];
    this.discards = 0;
  }

  prepare(inputs) {
    this.prepareInputs.push(Object.values(inputs));
    const projection = structuredClone(this.values.projection);
    this.mutateProjection?.(projection);
    let consumed = false;
    return {
      projection: () => fakeNativeProjection(projection),
      preparation_classification: () => B32A_PREPARATION.BYTE_IDENTICAL,
      second_candidate_state_sha256: () => bytes(projection.candidateStateSha256Hex),
      differing_storage_key: () => new Uint8Array(),
      release_candidate_state: (projectionDigest, expectedAuthor) => {
        if (consumed) throw new Error('PHASE_B32A_HANDLE_CONSUMED');
        if (!Buffer.from(projectionDigest).equals(bytes(projection.nativeProjectionSha256Hex))
          || !Buffer.from(expectedAuthor).equals(bytes(projection.welcomeAuthor.identityHex))) {
          throw new Error('PHASE_B32A_BINDING_MISMATCH');
        }
        consumed = true;
        const candidate = Uint8Array.from(this.values.candidate);
        this.releasedCandidates.push(candidate);
        return candidate;
      },
      is_consumed: () => consumed,
      discard: () => {
        if (consumed) throw new Error('PHASE_B32A_HANDLE_CONSUMED');
        consumed = true;
        this.discards += 1;
      },
      free() {},
    };
  }

  load(candidateState, groupId) {
    if (!Buffer.from(candidateState).equals(Buffer.from(this.values.candidate))
      || !Buffer.from(groupId).equals(bytes(this.values.projection.groupIdHex))) return null;
    return {
      canonical_state: () => Uint8Array.from(candidateState),
      projection: () => fakeNativeProjection(this.values.projection),
      free() {},
    };
  }
}

async function stableJournal(values, store = new MemoryB32aStore()) {
  const journal = new B32aJournal(store);
  await journal.initializeStable({
    predecessorState: values.predecessor,
    keyPackage: values.keyPackage,
    accountIdentityHex: values.joiner.identityHex,
    leafSignatureKeyHex: values.joiner.signatureKeyHex,
    expectedAuthorHex: values.founder.identityHex,
  });
  return { journal, store };
}

async function recordedJournal(values, store = new MemoryB32aStore()) {
  const result = await stableJournal(values, store);
  await result.journal.recordWelcome(values.welcome);
  return result;
}

function allZero(values) {
  return values.every((value) => !(value instanceof Uint8Array) || value.every((byte) => byte === 0));
}

describe('Phase B3.2a closed durable journal', () => {
  test('selects predecessor until the sole JOINED CAS selects the exact candidate', async () => {
    const values = b32aFixture();
    const { journal } = await stableJournal(values);
    expect((await journal.activationState()).state).toBe(B32A_STATE.STABLE_ADVERTISED);
    await journal.recordWelcome(values.welcome);
    expect((await journal.activationState()).state).toBe(B32A_STATE.WELCOME_RECORDED);
    const evidence = {
      classification: B32A_PREPARATION.BYTE_IDENTICAL,
      secondCandidateStateSha256Hex: values.projection.candidateStateSha256Hex,
      differingStorageKeyHex: '',
    };
    const head = await journal.commitJoined(values.candidate, values.projection, evidence);
    expect(head.state).toBe(B32A_STATE.JOINED);
    const activation = await journal.activationState();
    expect(activation.bytes).toEqual(values.candidate);
    expect(activation.head.preparationEvidence).toEqual(evidence);
  });

  test('persistence failure preserves exact retryable WELCOME_RECORDED inputs', async () => {
    const values = b32aFixture();
    const { journal, store } = await recordedJournal(values);
    store.failNext = new Error('synthetic disk failure');
    await expect(journal.commitJoined(values.candidate, values.projection, {
      classification: B32A_PREPARATION.BYTE_IDENTICAL,
      secondCandidateStateSha256Hex: values.projection.candidateStateSha256Hex,
      differingStorageKeyHex: '',
    })).rejects.toMatchObject({ code: B32A_ERROR.PERSISTENCE_FAILED });
    const activation = await journal.activationState();
    expect(activation.state).toBe(B32A_STATE.WELCOME_RECORDED);
    expect(activation.bytes).toEqual(values.predecessor);
  });

  test('corrupt head, corrupt blob and evidence rebinding fail closed', async () => {
    const first = b32aFixture();
    const one = await stableJournal(first);
    one.store.head = { ...one.store.head, sequence: 99 };
    await expect(one.journal.read()).rejects.toMatchObject({ code: B32A_ERROR.CORRUPT });

    const second = b32aFixture();
    const two = await stableJournal(second);
    two.store.blobs.set(sha256Hex(second.predecessor), Uint8Array.of(1, 2, 3));
    await expect(two.journal.read()).rejects.toMatchObject({ code: B32A_ERROR.CORRUPT });

    const third = b32aFixture();
    const three = await recordedJournal(third);
    await expect(three.journal.commitJoined(third.candidate, third.projection, {
      classification: B32A_PREPARATION.BYTE_IDENTICAL,
      secondCandidateStateSha256Hex: '44'.repeat(32),
      differingStorageKeyHex: '',
    })).rejects.toMatchObject({ code: B32A_ERROR.PREPARATION_EVIDENCE_INVALID });
  });

  test('a forged content-address collision cannot be committed', async () => {
    const values = b32aFixture();
    const { journal, store } = await recordedJournal(values);
    store.blobs.set(values.projection.candidateStateSha256Hex, Uint8Array.of(9, 9, 9));
    await expect(journal.commitJoined(values.candidate, values.projection, {
      classification: B32A_PREPARATION.BYTE_IDENTICAL,
      secondCandidateStateSha256Hex: values.projection.candidateStateSha256Hex,
      differingStorageKeyHex: '',
    })).rejects.toMatchObject({ code: B32A_ERROR.CORRUPT });
    expect(store.head.state).toBe(B32A_STATE.WELCOME_RECORDED);
  });

  test('head validation does not invoke hostile nested accessors', async () => {
    const values = b32aFixture();
    const { journal, store } = await recordedJournal(values);
    await journal.commitJoined(values.candidate, values.projection, {
      classification: B32A_PREPARATION.BYTE_IDENTICAL,
      secondCandidateStateSha256Hex: values.projection.candidateStateSha256Hex,
      differingStorageKeyHex: '',
    });
    const projection = { ...store.head.projection };
    let invoked = false;
    Object.defineProperty(projection, 'groupIdHex', {
      get() { invoked = true; return values.projection.groupIdHex; },
    });
    store.head = { ...store.head, projection };
    await expect(journal.read()).rejects.toMatchObject({ code: B32A_ERROR.INVALID });
    expect(invoked).toBe(false);
  });

  test('file store rejects non-canonical head JSON before journal parsing', async () => {
    const root = mkdtempSync(join(tmpdir(), 'styx-b32a-root-'));
    try {
      const values = b32aFixture();
      const store = new FileB32aStore(join(root, 'journal'), root);
      const journal = new B32aJournal(store);
      await journal.initializeStable({
        predecessorState: values.predecessor,
        keyPackage: values.keyPackage,
        accountIdentityHex: values.joiner.identityHex,
        leafSignatureKeyHex: values.joiner.signatureKeyHex,
        expectedAuthorHex: values.founder.identityHex,
      });
      const headPath = join(root, 'journal', 'head.json');
      writeFileSync(headPath, ` ${readFileSync(headPath, 'utf8')}`);
      await expect(journal.read()).rejects.toMatchObject({ code: B32A_ERROR.CORRUPT });
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test('a Welcome CAS race has one winner and one canonical head', async () => {
    const values = b32aFixture();
    const { journal } = await stableJournal(values);
    const outcomes = await Promise.allSettled([
      journal.recordWelcome(values.welcome),
      journal.recordWelcome(Uint8Array.from(randomBytes(512))),
    ]);
    expect(outcomes.filter((value) => value.status === 'fulfilled')).toHaveLength(1);
    expect(outcomes.filter((value) => value.status === 'rejected')).toHaveLength(1);
    expect((await journal.read()).head.state).toBe(B32A_STATE.WELCOME_RECORDED);
  });
});

describe('Phase B3.2a artifact-independent durable-input driver', () => {
  test('binds exact durable inputs, scratch-restores, commits once and clears transients', async () => {
    const values = b32aFixture();
    const { journal } = await recordedJournal(values);
    const engine = new FakeB32aEngine(values);
    const result = await new B32aDurableJoinDriver(journal, engine).joinRecordedWelcome();
    expect(result.head.state).toBe(B32A_STATE.JOINED);
    expect(result.restartedProjectionRecordSha256Hex).toBe(result.head.projectionRecordSha256Hex);
    expect(engine.prepareInputs).toHaveLength(1);
    expect(allZero(engine.prepareInputs.flat())).toBe(true);
    expect(allZero(engine.releasedCandidates)).toBe(true);
    expect((await journal.activationState()).bytes).toEqual(values.candidate);
  });

  test('projection rebinding discards pending state, clears inputs and keeps predecessor authoritative', async () => {
    const values = b32aFixture();
    const { journal } = await recordedJournal(values);
    const engine = new FakeB32aEngine(values, (projection) => {
      projection.predecessorStateSha256Hex = '55'.repeat(32);
    });
    await expect(new B32aDurableJoinDriver(journal, engine).joinRecordedWelcome())
      .rejects.toMatchObject({ code: B32A_ERROR.PROJECTION_MISMATCH });
    expect(engine.discards).toBe(1);
    expect(allZero(engine.prepareInputs.flat())).toBe(true);
    expect((await journal.activationState()).state).toBe(B32A_STATE.WELCOME_RECORDED);
  });

  test('failed JOINED persistence clears the released candidate and remains retryable', async () => {
    const values = b32aFixture();
    const { journal, store } = await recordedJournal(values);
    store.failNext = new Error('synthetic CAS persistence failure');
    const failedEngine = new FakeB32aEngine(values);
    await expect(new B32aDurableJoinDriver(journal, failedEngine).joinRecordedWelcome())
      .rejects.toMatchObject({ code: B32A_ERROR.PERSISTENCE_FAILED });
    expect(allZero(failedEngine.releasedCandidates)).toBe(true);
    expect((await journal.activationState()).state).toBe(B32A_STATE.WELCOME_RECORDED);
    await expect(new B32aDurableJoinDriver(journal, new FakeB32aEngine(values))
      .joinRecordedWelcome()).resolves.toMatchObject({ head: { state: B32A_STATE.JOINED } });
  });

  test('concurrent durable joins produce one JOINED winner and clear both candidates', async () => {
    const values = b32aFixture();
    const { journal } = await recordedJournal(values);
    const first = new FakeB32aEngine(values);
    const second = new FakeB32aEngine(values);
    const outcomes = await Promise.allSettled([
      new B32aDurableJoinDriver(journal, first).joinRecordedWelcome(),
      new B32aDurableJoinDriver(journal, second).joinRecordedWelcome(),
    ]);
    expect(outcomes.filter((value) => value.status === 'fulfilled')).toHaveLength(1);
    expect(outcomes.filter((value) => value.status === 'rejected')).toHaveLength(1);
    expect((await journal.read()).head.state).toBe(B32A_STATE.JOINED);
    expect(allZero([...first.releasedCandidates, ...second.releasedCandidates])).toBe(true);
  });
});
