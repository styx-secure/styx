// SPDX-License-Identifier: AGPL-3.0-or-later

import { B32A_PREPARATION } from '../../spikes/marmot-phase-b3-2a/b3-2a-canonical.mjs';
import {
  mkdtempSync, readFileSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';

import {
  B32aJournal,
  MemoryB32aStore,
} from '../../spikes/marmot-phase-b3-2a/b3-2a-journal.mjs';
import { b32aFixture }
  from '../../spikes/marmot-phase-b3-2a/b3-2a-test-support.mjs';
import {
  B33A_ERROR,
  B33A_OUTCOME,
  bytesToHex,
  encodeMarmotAppEvent,
  hexToBytes,
  sha256Hex,
} from '../../spikes/marmot-phase-b3-3a/b3-3a-canonical.mjs';
import { B33aApplicationAdapter }
  from '../../spikes/marmot-phase-b3-3a/b3-3a-engine-adapter.mjs';
import {
  B33aJournal,
  FileB33aStore,
  MemoryB33aStore,
} from '../../spikes/marmot-phase-b3-3a/b3-3a-journal.mjs';

function digestBytes(value) {
  return hexToBytes('digest', sha256Hex(value), 32);
}

function advanceState(value, marker) {
  const next = Uint8Array.from(value);
  next[next.length - 1] ^= marker;
  return next;
}

class FakeRelease {
  constructor(values) {
    this.values = values;
  }

  #take(name) {
    if (this.values[name] === null) throw new Error(`${name} already taken`);
    const value = this.values[name];
    this.values[name] = null;
    return Uint8Array.from(value);
  }

  take_canonical_state() { return this.#take('state'); }
  take_ciphertext() { return this.#take('ciphertext'); }
  take_plaintext() { return this.#take('plaintext'); }
  free() {}
}

class FakePending {
  constructor(values) {
    this.values = values;
    this.consumed = false;
  }

  #open() {
    if (this.consumed) throw new Error('pending handle consumed');
  }

  is_consumed() { return this.consumed; }
  group_id() { this.#open(); return Uint8Array.from(this.values.groupId); }
  epoch() { this.#open(); return BigInt(this.values.epochDec); }
  sender_leaf_index() { this.#open(); return this.values.senderLeafIndex; }
  sender_credential_identity() { this.#open(); return Uint8Array.from(this.values.senderIdentity); }
  sender_signature_key() { this.#open(); return Uint8Array.from(this.values.senderSignatureKey); }
  canonical_state_sha256() { this.#open(); return digestBytes(this.values.state); }
  ciphertext_sha256() { this.#open(); return digestBytes(this.values.ciphertext); }
  plaintext_sha256() { this.#open(); return digestBytes(this.values.plaintext); }

  release(stateDigest, ciphertextDigest, plaintextDigest = null) {
    this.#open();
    if (bytesToHex(stateDigest) !== sha256Hex(this.values.state)
      || bytesToHex(ciphertextDigest) !== sha256Hex(this.values.ciphertext)
      || (plaintextDigest !== null
        && bytesToHex(plaintextDigest) !== sha256Hex(this.values.plaintext))) {
      this.consumed = true;
      throw new Error('binding mismatch');
    }
    this.consumed = true;
    return new FakeRelease({
      state: this.values.state,
      ciphertext: this.values.ciphertext,
      plaintext: plaintextDigest === null ? null : this.values.plaintext,
    });
  }

  discard() { this.#open(); this.consumed = true; }
  free() {}
}

function fakeWasm(projection) {
  const inbound = new Map();
  let sendOrdinal = 0;
  class PhaseB33aGroup {
    static load_canonical_state(state, groupId, identity, signatureKey) {
      return new PhaseB33aGroup(state, groupId, identity, signatureKey);
    }

    constructor(state, groupId, identity, signatureKey) {
      this.state = Uint8Array.from(state);
      this.groupId = Uint8Array.from(groupId);
      this.identity = Uint8Array.from(identity);
      this.signatureKey = Uint8Array.from(signatureKey);
      this.consumed = false;
    }

    prepare_outbound(plaintext) {
      if (this.consumed) throw new Error('group consumed');
      this.consumed = true;
      sendOrdinal += 1;
      const ciphertext = Uint8Array.from([0x33, sendOrdinal, ...plaintext]);
      inbound.set(sha256Hex(ciphertext), {
        plaintext: Uint8Array.from(plaintext),
        senderLeafIndex: projection.ownLeafIndex,
        senderIdentity: Uint8Array.from(this.identity),
        senderSignatureKey: Uint8Array.from(this.signatureKey),
      });
      return new FakePending({
        state: advanceState(this.state, 0x01),
        ciphertext,
        plaintext: Uint8Array.from(plaintext),
        groupId: this.groupId,
        epochDec: projection.epochDec,
        senderLeafIndex: projection.ownLeafIndex,
        senderIdentity: this.identity,
        senderSignatureKey: this.signatureKey,
      });
    }

    prepare_inbound(ciphertext) {
      if (this.consumed) throw new Error('group consumed');
      this.consumed = true;
      const message = inbound.get(sha256Hex(ciphertext));
      if (!message) throw new Error('malformed or replayed ciphertext');
      return new FakePending({
        ...message,
        state: advanceState(this.state, 0x02),
        ciphertext: Uint8Array.from(ciphertext),
        groupId: this.groupId,
        epochDec: projection.epochDec,
      });
    }

    free() {}
  }
  return {
    PhaseB33aGroup,
    seedInbound(ciphertext, plaintext, member) {
      inbound.set(sha256Hex(ciphertext), {
        plaintext: Uint8Array.from(plaintext),
        senderLeafIndex: member.leafIndex,
        senderIdentity: hexToBytes('sender identity', member.identityHex, 32),
        senderSignatureKey: hexToBytes('sender signature key', member.signatureKeyHex, 32),
      });
    },
  };
}

async function joinedFixture(store = new MemoryB33aStore()) {
  const values = b32aFixture();
  const b32a = new B32aJournal(new MemoryB32aStore());
  await b32a.initializeStable({
    predecessorState: values.predecessor,
    keyPackage: values.keyPackage,
    accountIdentityHex: values.joiner.identityHex,
    leafSignatureKeyHex: values.joiner.signatureKeyHex,
    expectedAuthorHex: values.founder.identityHex,
  });
  await b32a.recordWelcome(values.welcome);
  const joinedHead = await b32a.commitJoined(values.candidate, values.projection, {
    classification: B32A_PREPARATION.BYTE_IDENTICAL,
    secondCandidateStateSha256Hex: values.projection.candidateStateSha256Hex,
    differingStorageKeyHex: '',
  });
  const journal = new B33aJournal(store);
  const wasm = fakeWasm(values.projection);
  const adapter = new B33aApplicationAdapter({ journal, wasm });
  await adapter.initializeFromB32a(joinedHead, values.candidate);
  return { values, joinedHead, store, journal, wasm, adapter };
}

function eventBytes(pubkey, marker) {
  return encodeMarmotAppEvent({
    pubkey,
    created_at: 1_786_680_100 + marker,
    kind: 9,
    tags: [['h', `synthetic-${marker}`]],
    content: `synthetic application event ${marker}`,
  });
}

describe('Phase B3.3a isolated durable application journal', () => {
  test('activates once from the exact B3.2a JOINED head', async () => {
    const { joinedHead, values, journal } = await joinedFixture();
    await expect(journal.initializeFromB32a(joinedHead, values.candidate))
      .rejects.toMatchObject({ code: B33A_ERROR.DUPLICATE_INITIALIZATION });
    const current = await journal.readCurrent();
    expect(current.head.sourceB32aHeadDigestHex).toBe(joinedHead.headDigestHex);
    expect(current.head.stateBlobSha256Hex).toBe(sha256Hex(values.candidate));
    current.stateBytes.fill(0);
  });

  test('commits state and ciphertext before outbound release, restart and deduplication', async () => {
    const { values, adapter, store, wasm } = await joinedFixture();
    const event = eventBytes(values.joiner.identityHex, 1);
    let casObserved = false;
    store.beforeCas = async ({ nextHead }) => {
      if (nextHead.sequence === 2) casObserved = true;
    };
    const sent = await adapter.send('request-1', event);
    expect(casObserved).toBe(true);
    expect(sent.status).toBe(B33A_OUTCOME.COMMITTED);
    expect(sent.ciphertextBytes).toBeInstanceOf(Uint8Array);
    const duplicate = await adapter.send('request-1', event);
    expect(duplicate).toEqual(expect.objectContaining({
      status: B33A_OUTCOME.DUPLICATE,
      requestId: 'request-1',
    }));
    expect(duplicate).not.toHaveProperty('ciphertextBytes');
    const restarted = new B33aApplicationAdapter({
      journal: new B33aJournal(store),
      wasm,
    });
    const afterRestart = await restarted.send(
      'request-after-restart', eventBytes(values.joiner.identityHex, 8),
    );
    expect(afterRestart.status).toBe(B33A_OUTCOME.COMMITTED);
    const durable = await new B33aJournal(store).readCurrent();
    expect(durable.head.sequence).toBe(3);
    durable.stateBytes.fill(0);
  });

  test('reopens a private file journal and continues from its durable ratchet state', async () => {
    const root = mkdtempSync(resolve(tmpdir(), 'styx-b33a-root-'));
    const directory = resolve(root, 'journal');
    try {
      const firstStore = new FileB33aStore(directory, root);
      const { values, adapter, wasm, joinedHead } = await joinedFixture(firstStore);
      const first = await adapter.send(
        'file-request-1', eventBytes(values.joiner.identityHex, 9),
      );
      expect(first.status).toBe(B33A_OUTCOME.COMMITTED);

      const restartedJournal = new B33aJournal(new FileB33aStore(directory, root));
      const restarted = new B33aApplicationAdapter({ journal: restartedJournal, wasm });
      const duplicate = await restarted.send(
        'file-request-1', eventBytes(values.joiner.identityHex, 9),
      );
      expect(duplicate).toEqual(expect.objectContaining({
        status: B33A_OUTCOME.DUPLICATE,
        requestId: 'file-request-1',
      }));
      const second = await restarted.send(
        'file-request-2', eventBytes(values.joiner.identityHex, 10),
      );
      expect(second.status).toBe(B33A_OUTCOME.COMMITTED);

      const durable = await restartedJournal.readCurrent();
      expect(durable.head.sequence).toBe(3);
      expect(durable.head.sourceB32aHeadDigestHex).toBe(joinedHead.headDigestHex);
      durable.stateBytes.fill(0);
      expect(statSync(directory).mode & 0o777).toBe(0o700);
      expect(statSync(resolve(directory, 'head.json')).mode & 0o777).toBe(0o600);
      expect(statSync(resolve(directory, 'blobs')).mode & 0o777).toBe(0o700);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test('file journal rejects escaping paths and non-canonical durable heads', async () => {
    const root = mkdtempSync(resolve(tmpdir(), 'styx-b33a-root-'));
    try {
      expect(() => new FileB33aStore(resolve(root, '..', 'escape'), root))
        .toThrow(expect.objectContaining({ code: B33A_ERROR.INVALID }));
      const directory = resolve(root, 'journal');
      const { journal } = await joinedFixture(new FileB33aStore(directory, root));
      const headPath = resolve(directory, 'head.json');
      writeFileSync(headPath, ` ${readFileSync(headPath, 'utf8')}`);
      await expect(journal.readCurrent())
        .rejects.toMatchObject({ code: B33A_ERROR.CORRUPT });
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test('releases plaintext once only after inbound CAS and durable read-back', async () => {
    const { values, adapter, wasm } = await joinedFixture();
    const plaintext = eventBytes(values.founder.identityHex, 2);
    const ciphertext = Uint8Array.from([0x44, 0x02, ...plaintext]);
    wasm.seedInbound(ciphertext, plaintext, values.founder);
    const received = await adapter.receive(ciphertext);
    expect(received.status).toBe(B33A_OUTCOME.COMMITTED);
    expect(received.plaintextBytes).toEqual(plaintext);
    expect(received.senderIdentityHex).toBe(values.founder.identityHex);
    const replay = await adapter.receive(ciphertext);
    expect(replay).toEqual(expect.objectContaining({ status: B33A_OUTCOME.DUPLICATE }));
    expect(replay).not.toHaveProperty('plaintextBytes');
  });

  test('rejects inner event id and authenticated-pubkey mismatch without advancing durable state',
    async () => {
      const { values, adapter, journal, wasm } = await joinedFixture();
      const before = await journal.readCurrent();
      const validForLocal = eventBytes(values.joiner.identityHex, 3);
      const wrongSenderCiphertext = Uint8Array.from([0x55, ...validForLocal]);
      wasm.seedInbound(wrongSenderCiphertext, validForLocal, values.founder);
      await expect(adapter.receive(wrongSenderCiphertext))
        .rejects.toMatchObject({ code: B33A_ERROR.INNER_EVENT_REJECTED });
      const malformed = JSON.parse(Buffer.from(eventBytes(values.founder.identityHex, 4))
        .toString('utf8'));
      malformed.id = '00'.repeat(32);
      const malformedBytes = Uint8Array.from(Buffer.from(JSON.stringify(malformed)));
      const malformedCiphertext = Uint8Array.from([0x56, ...malformedBytes]);
      wasm.seedInbound(malformedCiphertext, malformedBytes, values.founder);
      await expect(adapter.receive(malformedCiphertext))
        .rejects.toMatchObject({ code: B33A_ERROR.INNER_EVENT_REJECTED });
      const after = await journal.readCurrent();
      expect(after.head.headDigestHex).toBe(before.head.headDigestHex);
      expect(after.stateBytes).toEqual(before.stateBytes);
      before.stateBytes.fill(0);
      after.stateBytes.fill(0);
    });

  test('persistence failure and a concurrent CAS loser release no transport payload', async () => {
    const { values, adapter, store, journal, wasm } = await joinedFixture();
    store.failNext = new Error('synthetic disk failure');
    await expect(adapter.send('persistence-failure', eventBytes(values.joiner.identityHex, 5)))
      .rejects.toMatchObject({ code: B33A_ERROR.PERSISTENCE_FAILED });
    const afterFailure = await journal.readCurrent();
    expect(afterFailure.head.sequence).toBe(1);
    afterFailure.stateBytes.fill(0);

    const inboundPlaintext = eventBytes(values.founder.identityHex, 11);
    const inboundCiphertext = Uint8Array.from([0x57, ...inboundPlaintext]);
    wasm.seedInbound(inboundCiphertext, inboundPlaintext, values.founder);
    store.failNext = new Error('synthetic inbound disk failure');
    await expect(adapter.receive(inboundCiphertext))
      .rejects.toMatchObject({ code: B33A_ERROR.PERSISTENCE_FAILED });
    const afterInboundFailure = await journal.readCurrent();
    expect(afterInboundFailure.head.sequence).toBe(1);
    afterInboundFailure.stateBytes.fill(0);

    let arrivals = 0;
    let releaseBarrier;
    const barrier = new Promise((resolve) => { releaseBarrier = resolve; });
    store.beforeCas = async ({ nextHead }) => {
      if (nextHead.sequence !== 2) return;
      arrivals += 1;
      if (arrivals === 2) releaseBarrier();
      await barrier;
    };
    const results = await Promise.allSettled([
      adapter.send('race-a', eventBytes(values.joiner.identityHex, 6)),
      adapter.send('race-b', eventBytes(values.joiner.identityHex, 7)),
    ]);
    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    const rejected = results.find((result) => result.status === 'rejected');
    expect(rejected.reason).toMatchObject({ code: B33A_ERROR.CAS_CONFLICT });
    expect(rejected.reason).not.toHaveProperty('ciphertextBytes');
  });
});
