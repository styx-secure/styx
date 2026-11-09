// M3-RECEIVE-2: the reference receiver over the real MlsEngine and the
// immutable vendored WASM, one process, successive instances standing for
// successive process runs. Real process kills are in crash.test.js.
import { describe, test, expect, beforeAll, afterAll } from '@jest/globals';
import { readdirSync, readFileSync, writeFileSync, symlinkSync, renameSync, truncateSync } from 'node:fs';
import { join } from 'node:path';
import { MlsEngine } from '../../src/crypto/mls/mls-engine.js';
import {
  SNAPSHOT_NAME, TEMP_PREFIX, headerGroupId, sameProviderState, storedBytesOf, createReferenceReceiver,
} from '../../reference/receive-state/index.js';
import {
  SCOPE, WASM, initWasm, tempRoot, removeTempRoots, party, loaded, invite, opId, eventId, text, untext,
} from './helpers.js';

beforeAll(initWasm);
afterAll(removeTempRoots);

const FAILED = 'E_SDK_RECEIVE_STATE_FAILED';
const INCOMPATIBLE = 'E_SDK_RECEIVE_STATE_INCOMPATIBLE';

/** Alice (inviter) and Bob (invitee), each with a loaded receiver. */
async function pair(options = {}) {
  const root = tempRoot();
  const alice = party(root, 'alice');
  const bob = party(root, 'bob', options.bob);
  const a = alice.instance();
  const b = bob.instance();
  await loaded(a, alice.identity);
  await loaded(b, bob.identity);
  await invite(alice, a, bob, b);
  return { root, alice, bob, a, b };
}

/** Stage, open and commit one ciphertext; returns the commit result and the candidate. */
async function receive(receiver, revision, sender, ciphertext, { receiptRequested = false } = {}) {
  const id = eventId();
  const staged = await receiver.receiveState.stage({
    operationId: opId(), revision, event: { eventId: id, sender, ciphertext, receiptRequested },
  });
  expect(staged.revision).toBe(revision + 1);
  const opened = await receiver.session.openCandidate({ sender, ciphertext });
  let committed = null;
  if (opened.receiveOutcome !== 'retry') {
    const result = opened.receiveOutcome === 'application'
      ? { type: 'application', sender, payload: opened.plaintext, receiptDue: receiptRequested }
      : { type: 'rejected' };
    committed = await receiver.receiveState.commit({
      operationId: opId(), revision: staged.revision, eventId: id, ticket: opened.ticket, result,
    });
  }
  return { id, staged, opened, committed };
}

describe('archive: creation, load, at-rest protection (G1, G2)', () => {
  test('a new archive loads as an explicit empty state; a second instance opens it', async () => {
    const root = tempRoot();
    const alice = party(root, 'alice');
    const first = await loaded(alice.instance(), alice.identity);
    expect(first).toEqual({
      schema: 'styx-m3-receive-state/v1', identity: alice.identity, scope: SCOPE, revision: 0,
      storedBytes: expect.any(Number), cursors: [], pending: [], ready: [], acknowledged: [], receiptsDue: [], seen: [],
    });
    expect(first.storedBytes).toBeGreaterThan(0); // the MLS checkpoint is counted
    const again = await loaded(alice.instance(), alice.identity);
    expect(again.revision).toBe(0);
    expect(readdirSync(alice.directory)).toEqual([SNAPSHOT_NAME]);
  });

  test("'create' over an existing archive and 'open' without one are refused, never reset", async () => {
    const root = tempRoot();
    const alice = party(root, 'alice');
    await loaded(alice.instance(), alice.identity);
    const before = readFileSync(join(alice.directory, SNAPSHOT_NAME));
    const recreate = createReferenceReceiver({
      directory: alice.directory, atRestKey: alice.atRestKey, identity: alice.identity, mode: 'create', wasmBytes: WASM,
    });
    expect(await recreate.receiveState.load({ identity: alice.identity, scope: SCOPE })).toEqual({ code: INCOMPATIBLE });
    expect(readFileSync(join(alice.directory, SNAPSHOT_NAME))).toEqual(before);
    const missing = createReferenceReceiver({
      directory: join(root, 'nobody'), atRestKey: alice.atRestKey, identity: alice.identity, mode: 'open', wasmBytes: WASM,
    });
    expect(await missing.receiveState.load({ identity: alice.identity, scope: SCOPE })).toEqual({ code: INCOMPATIBLE });
  });

  test('atRestKey is mandatory and exactly 32 bytes; there is no plaintext mode', () => {
    const base = { directory: '/nonexistent', identity: 'a'.repeat(64), mode: 'open' };
    for (const atRestKey of [undefined, null, new Uint8Array(16), new Uint8Array(33), 'k'.repeat(32), Buffer.alloc(31)]) {
      expect(() => createReferenceReceiver({ ...base, atRestKey })).toThrow(TypeError);
    }
  });

  test('a wrong key, another identity, a modified byte, a truncation or a foreign file are INCOMPATIBLE', async () => {
    const root = tempRoot();
    const alice = party(root, 'alice');
    await loaded(alice.instance(), alice.identity);
    const path = join(alice.directory, SNAPSHOT_NAME);
    const good = readFileSync(path);
    const open = (extra = {}) => createReferenceReceiver({
      directory: alice.directory, atRestKey: alice.atRestKey, identity: alice.identity, mode: 'open', wasmBytes: WASM, ...extra,
    });
    const wrongKey = new Uint8Array(alice.atRestKey);
    wrongKey[0] ^= 1;
    expect(await open({ atRestKey: wrongKey }).receiveState.load({ identity: alice.identity, scope: SCOPE }))
      .toEqual({ code: INCOMPATIBLE });
    const other = 'b'.repeat(64);
    expect(await open({ identity: other }).receiveState.load({ identity: other, scope: SCOPE })).toEqual({ code: INCOMPATIBLE });
    expect(await open().receiveState.load({ identity: alice.identity, scope: 'other' })).toEqual({ code: INCOMPATIBLE });
    for (const offset of [0, 9, 20, 50, 60, 70, good.length - 1]) {
      const bad = Buffer.from(good);
      bad[offset] ^= 0x01;
      writeFileSync(path, bad);
      expect(await open().receiveState.load({ identity: alice.identity, scope: SCOPE })).toEqual({ code: INCOMPATIBLE });
    }
    writeFileSync(path, good);
    truncateSync(path, good.length - 3);
    expect(await open().receiveState.load({ identity: alice.identity, scope: SCOPE })).toEqual({ code: INCOMPATIBLE });
    writeFileSync(path, Buffer.concat([good, Buffer.from([0])]));
    expect(await open().receiveState.load({ identity: alice.identity, scope: SCOPE })).toEqual({ code: INCOMPATIBLE });
    writeFileSync(path, Buffer.from('not a snapshot at all, but long enough to have a header and a tag.'));
    expect(await open().receiveState.load({ identity: alice.identity, scope: SCOPE })).toEqual({ code: INCOMPATIBLE });
    writeFileSync(path, good);
    expect((await open().receiveState.load({ identity: alice.identity, scope: SCOPE })).revision).toBe(0);
  });

  test('the snapshot holds no plaintext of the state; every rewrite draws a fresh salt and nonce', async () => {
    const { alice, a, b, bob } = await pair();
    const before = readFileSync(join(alice.directory, SNAPSHOT_NAME));
    const marker = 'PLAINTEXT-MARKER-0123456789';
    const sealed = await b.session.seal({ recipient: alice.identity, plaintext: text(marker) });
    expect(sealed.ciphertext).toBeInstanceOf(Uint8Array); // in the run of the join the invitee can seal
    const ciphertext = (await a.session.seal({ recipient: bob.identity, plaintext: text(marker) })).ciphertext;
    const got = await receive(b, 0, alice.identity, ciphertext);
    expect(untext(got.opened.plaintext)).toBe(marker);
    const after = readFileSync(join(alice.directory, SNAPSHOT_NAME));
    const headers = [before, after];
    for (let i = 0; i < 3; i += 1) {
      await a.session.seal({ recipient: bob.identity, plaintext: text(`rewrite ${i}`) });
      headers.push(readFileSync(join(alice.directory, SNAPSHOT_NAME)));
    }
    const salts = new Set(headers.map((file) => Buffer.from(file.subarray(10, 42)).toString('hex')));
    const nonces = new Set(headers.map((file) => Buffer.from(file.subarray(42, 54)).toString('hex')));
    expect(salts.size).toBe(headers.length);
    expect(nonces.size).toBe(headers.length);
    const bobFile = readFileSync(join(bob.directory, SNAPSHOT_NAME));
    expect(bobFile.includes(Buffer.from(marker))).toBe(false);
    expect(bobFile.includes(Buffer.from(alice.identity))).toBe(false);
    expect(bobFile.includes(Buffer.from(alice.identity, 'hex'))).toBe(false);
  });

  test('orphan temporary files are removed at load and never read; symbolic links are refused', async () => {
    const root = tempRoot();
    const alice = party(root, 'alice');
    await loaded(alice.instance(), alice.identity);
    writeFileSync(join(alice.directory, TEMP_PREFIX + 'deadbeefdeadbeef'), Buffer.from('garbage'));
    expect((await loaded(alice.instance(), alice.identity)).revision).toBe(0);
    expect(readdirSync(alice.directory)).toEqual([SNAPSHOT_NAME]);
    const path = join(alice.directory, SNAPSHOT_NAME);
    renameSync(path, join(root, 'moved'));
    symlinkSync(join(root, 'moved'), path);
    const linked = createReferenceReceiver({
      directory: alice.directory, atRestKey: alice.atRestKey, identity: alice.identity, mode: 'open', wasmBytes: WASM,
    });
    expect(await linked.receiveState.load({ identity: alice.identity, scope: SCOPE })).toEqual({ code: INCOMPATIBLE });
  });
});

describe('the receive state with the real engine', () => {
  test('stage, application commit, ack and receiptDone survive a restart; storedBytes follows the formula', async () => {
    const { alice, bob, a, b } = await pair();
    const ciphertext = (await a.session.seal({ recipient: bob.identity, plaintext: text('m1') })).ciphertext;
    const got = await receive(b, 0, alice.identity, ciphertext, { receiptRequested: true });
    expect(got.opened.receiveOutcome).toBe('application');
    expect(got.committed.revision).toBe(2);
    let snapshot = await loaded(bob.instance(), bob.identity);
    expect(snapshot.ready).toEqual([{ eventId: got.id, sender: alice.identity, payload: text('m1'), receiptDue: true }]);
    expect(snapshot.receiptsDue).toEqual([{ eventId: got.id, sender: alice.identity }]);
    expect(snapshot.seen).toEqual([got.id]);
    const b2 = bob.instance();
    snapshot = await loaded(b2, bob.identity);
    const acked = await b2.receiveState.ack({ operationId: opId(), revision: snapshot.revision, eventId: got.id });
    const done = await b2.receiveState.receiptDone({ operationId: opId(), revision: acked.revision, eventId: got.id });
    const cursor = await b2.receiveState.commitCursor({
      operationId: opId(), revision: done.revision, relay: 'ws://127.0.0.1:1', generation: 1, syncedUntil: 1_800_000_000,
    });
    snapshot = await loaded(bob.instance(), bob.identity);
    expect(snapshot).toMatchObject({
      revision: cursor.revision, ready: [], acknowledged: [got.id], receiptsDue: [], seen: [got.id],
      cursors: [{ relay: 'ws://127.0.0.1:1', syncedUntil: 1_800_000_000 }],
    });
    expect(snapshot.storedBytes).toBe(cursor.storedBytes);
  });

  test('a write against another revision is CONFLICT and changes nothing', async () => {
    const { alice, bob, b } = await pair();
    const event = { eventId: eventId(), sender: alice.identity, ciphertext: text('x'), receiptRequested: false };
    expect(await b.receiveState.stage({ operationId: opId(), revision: 7, event })).toEqual({ code: 'E_SDK_RECEIVE_STATE_CONFLICT' });
    expect((await loaded(bob.instance(), bob.identity)).seen).toEqual([]);
  });

  test('stage is idempotent per event id', async () => {
    const { alice, b } = await pair();
    const event = { eventId: eventId(), sender: alice.identity, ciphertext: text('x'), receiptRequested: false };
    const first = await b.receiveState.stage({ operationId: opId(), revision: 0, event });
    const second = await b.receiveState.stage({ operationId: opId(), revision: first.revision, event });
    expect(second).toEqual(first);
  });

  test('a commit over the adapter bound is CAPACITY and writes nothing', async () => {
    const { alice, bob, a, b } = await pair();
    const ciphertext = (await a.session.seal({ recipient: bob.identity, plaintext: new Uint8Array(30_000).fill(7) })).ciphertext;
    const id = eventId();
    const staged = await b.receiveState.stage({
      operationId: opId(), revision: 0, event: { eventId: id, sender: alice.identity, ciphertext, receiptRequested: true },
    });
    // A later run with a bound just above the staged state: the commit adds a receipt obligation.
    const tight = bob.instance({ maxStoredBytes: staged.storedBytes + 10 });
    await loaded(tight, bob.identity);
    const opened = await tight.session.openCandidate({ sender: alice.identity, ciphertext });
    expect(opened.receiveOutcome).toBe('application');
    const committed = await tight.receiveState.commit({
      operationId: opId(), revision: staged.revision, eventId: id, ticket: opened.ticket,
      result: { type: 'application', sender: alice.identity, payload: opened.plaintext, receiptDue: true },
    });
    expect(committed).toEqual({ code: 'E_SDK_RECEIVE_STATE_CAPACITY' });
    const snapshot = await loaded(bob.instance(), bob.identity);
    expect(snapshot.pending.map((e) => e.eventId)).toEqual([id]);
    expect(snapshot.ready).toEqual([]);
  });

  test('a ciphertext that is not an MLS application PrivateMessage is reject; the commit keeps a tombstone', async () => {
    const { alice, bob, b } = await pair();
    const got = await receive(b, 0, alice.identity, text('not mls at all'));
    expect(got.opened.receiveOutcome).toBe('reject');
    expect(got.opened.plaintext).toBeUndefined();
    const snapshot = await loaded(bob.instance(), bob.identity);
    expect(snapshot).toMatchObject({ pending: [], ready: [], acknowledged: [], seen: [got.id] });
  });

  test('an unknown sender is retry, never reject; isKnownSender is true only for a durable binding', async () => {
    const { alice, bob, a, b } = await pair();
    expect(await b.session.isKnownSender({ sender: alice.identity })).toBe(true);
    expect(await b.session.isKnownSender({ sender: 'c'.repeat(64) })).toBe(false);
    const ciphertext = (await a.session.seal({ recipient: bob.identity, plaintext: text('m') })).ciphertext;
    expect((await b.session.openCandidate({ sender: 'c'.repeat(64), ciphertext })).receiveOutcome).toBe('retry');
    const restarted = bob.instance();
    await loaded(restarted, bob.identity);
    expect(await restarted.session.isKnownSender({ sender: alice.identity })).toBe(true);
  });
});

describe('D7: invitee binding by exporter value (criterion 14)', () => {
  test('invitee restarts before any message: first message verified, committed once; a further restart loads it', async () => {
    const { alice, bob, a, b } = await pair();
    expect(b.inspect().bindings).toEqual([{ peer: alice.identity, groupId: null }]);
    const b2 = bob.instance();
    await loaded(b2, bob.identity);
    expect(await b2.session.isKnownSender({ sender: alice.identity })).toBe(true);
    await expect(b2.session.seal({ recipient: alice.identity, plaintext: text('early') })).rejects.toThrow('invitee binding');
    const ciphertext = (await a.session.seal({ recipient: bob.identity, plaintext: text('hello') })).ciphertext;
    const groupId = headerGroupId(ciphertext);
    expect(groupId).toMatch(/^styx:/);
    const got = await receive(b2, 0, alice.identity, ciphertext);
    expect(untext(got.opened.plaintext)).toBe('hello');
    expect(b2.inspect().bindings).toEqual([{ peer: alice.identity, groupId }]);
    const b3 = bob.instance();
    const snapshot = await loaded(b3, bob.identity);
    expect(snapshot.ready.map((e) => untext(e.payload))).toEqual(['hello']);
    expect(b3.inspect().bindings).toEqual([{ peer: alice.identity, groupId }]);
    // The completed binding was loaded with loadSession: Bob can now reply.
    const reply = (await b3.session.seal({ recipient: alice.identity, plaintext: text('back') })).ciphertext;
    const back = await receive(a, 0, bob.identity, reply);
    expect(untext(back.opened.plaintext)).toBe('back');
  });

  test('in the run of the join the invitee can seal at once and opening is unaffected', async () => {
    const { alice, bob, a, b } = await pair();
    const reply = (await b.session.seal({ recipient: alice.identity, plaintext: text('first from bob') })).ciphertext;
    expect(untext((await receive(a, 0, bob.identity, reply)).opened.plaintext)).toBe('first from bob');
    const ciphertext = (await a.session.seal({ recipient: bob.identity, plaintext: text('hi') })).ciphertext;
    expect(untext((await receive(b, 0, alice.identity, ciphertext)).opened.plaintext)).toBe('hi');
  });

  test('a header naming an orphan group of the same peer, or a missing group, is reject and leaves the binding unchanged', async () => {
    const { root, alice, bob, a, b } = await pair();
    // An orphan: a second group with the same peer, joined into Bob's provider
    // outside the receiver (as after a refused re-pairing), never bound.
    const bobEngine = b.inspect().engine;
    const other = await MlsEngine.restore({
      name: alice.identity, stateBytes: a.inspect().engine.serializeState(), identityPubKey: a.inspect().engine.identityPublicKey(),
    });
    const orphan = other.startSession('orphan', bobEngine.keyPackageBytes(), { expectedPeer: bob.identity });
    bobEngine.joinSession('orphan', orphan.welcome, orphan.ratchetTree, { expectedPeer: alice.identity });
    bobEngine.removeSession('orphan');
    await b.session.createKeyPackage(); // checkpoint the provider that now holds the orphan group
    const b2 = bob.instance();
    await loaded(b2, bob.identity);
    const fromOrphan = other.session('orphan').encrypt(text('from the orphan'));
    expect(headerGroupId(fromOrphan)).toBe(orphan.groupId);
    const got = await receive(b2, 0, alice.identity, fromOrphan);
    expect(got.opened.receiveOutcome).toBe('reject');
    expect(b2.inspect().bindings).toEqual([{ peer: alice.identity, groupId: null }]);
    // A header naming a group that does not exist: same classification.
    const real = (await a.session.seal({ recipient: bob.identity, plaintext: text('real') })).ciphertext;
    const forged = new Uint8Array(real);
    const start = 5; // 1-byte varint length of a 41-character 'styx:<uuid>'
    expect(forged[4]).toBe(41);
    forged[start + 6] = forged[start + 6] === 0x30 ? 0x31 : 0x30;
    const ghost = await receive(b2, got.committed.revision, alice.identity, forged);
    expect(ghost.opened.receiveOutcome).toBe('reject');
    expect(b2.inspect().bindings).toEqual([{ peer: alice.identity, groupId: null }]);
    // The genuine message still completes the binding afterwards.
    const ok = await receive(b2, ghost.committed.revision, alice.identity, real);
    expect(untext(ok.opened.plaintext)).toBe('real');
    expect(b2.inspect().bindings[0].groupId).toBe(headerGroupId(real));
    expect(root).toBeTruthy();
  });

  test('a fault in the verification after restart is retry: the entry stays PENDING, a later retry completes the binding', async () => {
    let fail = true;
    const { alice, bob, a } = await pair({ bob: { hooks: { beforeCandidate: () => { if (fail) throw new Error('injected'); } } } });
    const b2 = bob.instance();
    await loaded(b2, bob.identity);
    const ciphertext = (await a.session.seal({ recipient: bob.identity, plaintext: text('later') })).ciphertext;
    const got = await receive(b2, 0, alice.identity, ciphertext);
    expect(got.opened.receiveOutcome).toBe('retry');
    expect(got.committed).toBeNull();
    expect(b2.inspect().bindings).toEqual([{ peer: alice.identity, groupId: null }]);
    const b3 = bob.instance();
    let snapshot = await loaded(b3, bob.identity);
    expect(snapshot.pending.map((e) => e.eventId)).toEqual([got.id]);
    fail = false;
    const again = await b3.session.openCandidate({ sender: alice.identity, ciphertext });
    expect(untext(again.plaintext)).toBe('later');
    await b3.receiveState.commit({
      operationId: opId(), revision: snapshot.revision, eventId: got.id, ticket: again.ticket,
      result: { type: 'application', sender: alice.identity, payload: again.plaintext, receiptDue: false },
    });
    snapshot = await loaded(bob.instance(), bob.identity);
    expect(snapshot.pending).toEqual([]);
    expect(snapshot.ready.map((e) => untext(e.payload))).toEqual(['later']);
  });

  test('header group ids must be strict, canonical UTF-8 of a well-formed application PrivateMessage', () => {
    const make = (groupBytes) => Uint8Array.from([0x00, 0x01, 0x00, 0x02, groupBytes.length, ...groupBytes, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 9, 9]);
    expect(headerGroupId(make([...Buffer.from('styx:abc')]))).toBe('styx:abc');
    expect(headerGroupId(make([0xc0, 0x80]))).toBeNull(); // overlong encoding
    expect(headerGroupId(make([0xff]))).toBeNull();
    const handshake = make([...Buffer.from('g')]);
    handshake[handshake.length - 3] = 0x02;
    expect(headerGroupId(handshake)).toBeNull();
    expect(headerGroupId(Uint8Array.from([0, 1, 0, 1, 1, 0x61]))).toBeNull();
  });
});

describe('candidate copy, coordinator and rollback (criteria 7, 12)', () => {
  test('a transient fault in openCandidate leaves the entry PENDING and the authoritative MLS state unchanged', async () => {
    let fail = false;
    const { alice, bob, a } = await pair({ bob: { hooks: { beforeCandidate: () => { if (fail) throw new Error('fault'); } } } });
    const b2 = bob.instance();
    await loaded(b2, bob.identity);
    // complete the binding first so the established path is exercised
    const first = (await a.session.seal({ recipient: bob.identity, plaintext: text('one') })).ciphertext;
    const one = await receive(b2, 0, alice.identity, first);
    const before = b2.inspect().engine.serializeState();
    fail = true;
    const second = (await a.session.seal({ recipient: bob.identity, plaintext: text('two') })).ciphertext;
    const two = await receive(b2, one.committed.revision, alice.identity, second);
    expect(two.opened.receiveOutcome).toBe('retry');
    expect(sameProviderState(b2.inspect().engine.serializeState(), before)).toBe(true);
    fail = false;
    const again = await b2.session.openCandidate({ sender: alice.identity, ciphertext: second });
    expect(untext(again.plaintext)).toBe('two');
  });

  test('a seal completed after the candidate was made survives the commit (criterion 12)', async () => {
    const { alice, bob, a, b } = await pair();
    const first = (await a.session.seal({ recipient: bob.identity, plaintext: text('one') })).ciphertext;
    const one = await receive(b, 0, alice.identity, first);
    const m2 = (await a.session.seal({ recipient: bob.identity, plaintext: text('two') })).ciphertext;
    const id = eventId();
    const staged = await b.receiveState.stage({
      operationId: opId(), revision: one.committed.revision, event: { eventId: id, sender: alice.identity, ciphertext: m2, receiptRequested: false },
    });
    const opened = await b.session.openCandidate({ sender: alice.identity, ciphertext: m2 });
    const sealed = (await b.session.seal({ recipient: alice.identity, plaintext: text('bob-1') })).ciphertext;
    await b.receiveState.commit({
      operationId: opId(), revision: staged.revision, eventId: id, ticket: opened.ticket,
      result: { type: 'application', sender: alice.identity, payload: opened.plaintext, receiptDue: false },
    });
    const b2 = bob.instance();
    await loaded(b2, bob.identity);
    const sealed2 = (await b2.session.seal({ recipient: alice.identity, plaintext: text('bob-2') })).ciphertext;
    const r1 = await receive(a, 0, bob.identity, sealed);
    const r2 = await receive(a, r1.committed.revision, bob.identity, sealed2);
    expect([untext(r1.opened.plaintext), untext(r2.opened.plaintext)]).toEqual(['bob-1', 'bob-2']);
  });

  test('a seal completed after the last receive commit survives an aborted (never committed) candidate', async () => {
    const { alice, bob, a, b } = await pair();
    const first = (await a.session.seal({ recipient: bob.identity, plaintext: text('one') })).ciphertext;
    await receive(b, 0, alice.identity, first);
    const m2 = (await a.session.seal({ recipient: bob.identity, plaintext: text('two') })).ciphertext;
    await b.session.openCandidate({ sender: alice.identity, ciphertext: m2 }); // abandoned
    const sealed = (await b.session.seal({ recipient: alice.identity, plaintext: text('bob-1') })).ciphertext;
    const b2 = bob.instance();
    await loaded(b2, bob.identity);
    const sealed2 = (await b2.session.seal({ recipient: alice.identity, plaintext: text('bob-2') })).ciphertext;
    const r1 = await receive(a, 0, bob.identity, sealed);
    const r2 = await receive(a, r1.committed.revision, bob.identity, sealed2);
    expect([untext(r1.opened.plaintext), untext(r2.opened.plaintext)]).toEqual(['bob-1', 'bob-2']);
    // the abandoned candidate never became authoritative: m2 still opens after restart
    const again = await b2.session.openCandidate({ sender: alice.identity, ciphertext: m2 });
    expect(untext(again.plaintext)).toBe('two');
  });

  test('a joinSession completed while a candidate is open survives its commit; both peers stay usable after restart', async () => {
    const { root, alice, bob, a, b } = await pair();
    const carol = party(root, 'carol');
    const c = carol.instance();
    await loaded(c, carol.identity);
    const m1 = (await a.session.seal({ recipient: bob.identity, plaintext: text('from alice') })).ciphertext;
    const id = eventId();
    const staged = await b.receiveState.stage({
      operationId: opId(), revision: 0, event: { eventId: id, sender: alice.identity, ciphertext: m1, receiptRequested: false },
    });
    const opened = await b.session.openCandidate({ sender: alice.identity, ciphertext: m1 });
    await invite(carol, c, bob, b); // Bob joins Carol's group between openCandidate and commit
    const committed = await b.receiveState.commit({
      operationId: opId(), revision: staged.revision, eventId: id, ticket: opened.ticket,
      result: { type: 'application', sender: alice.identity, payload: opened.plaintext, receiptDue: false },
    });
    expect(committed.revision).toBe(staged.revision + 1);
    const b2 = bob.instance();
    const snapshot = await loaded(b2, bob.identity);
    expect(snapshot.ready.map((e) => untext(e.payload))).toEqual(['from alice']);
    expect(await b2.session.isKnownSender({ sender: carol.identity })).toBe(true);
    const fromCarol = (await c.session.seal({ recipient: bob.identity, plaintext: text('from carol') })).ciphertext;
    expect(untext((await receive(b2, snapshot.revision, carol.identity, fromCarol)).opened.plaintext)).toBe('from carol');
  });

  test('only the latest candidate can be committed; a ticket is single use', async () => {
    const { alice, bob, a, b } = await pair();
    const m1 = (await a.session.seal({ recipient: bob.identity, plaintext: text('one') })).ciphertext;
    const id = eventId();
    const staged = await b.receiveState.stage({
      operationId: opId(), revision: 0, event: { eventId: id, sender: alice.identity, ciphertext: m1, receiptRequested: false },
    });
    const old = await b.session.openCandidate({ sender: alice.identity, ciphertext: m1 });
    const fresh = await b.session.openCandidate({ sender: alice.identity, ciphertext: m1 });
    const result = { type: 'application', sender: alice.identity, payload: old.plaintext, receiptDue: false };
    expect(await b.receiveState.commit({ operationId: opId(), revision: staged.revision, eventId: id, ticket: old.ticket, result }))
      .toEqual({ code: FAILED });
    const ok = await b.receiveState.commit({ operationId: opId(), revision: staged.revision, eventId: id, ticket: fresh.ticket, result });
    expect(ok.revision).toBe(staged.revision + 1);
  });
});

describe('uncertain and failed commits; resolve is read-only and repeatable', () => {
  async function setup(step) {
    const armed = { on: false };
    const hooks = {
      beforeStep: (name, operation) => {
        if (armed.on && operation === 'commit' && name === step) throw new Error(`injected at ${name}`);
      },
    };
    const { alice, bob, a } = await pair({ bob: { hooks } });
    const b2 = bob.instance({ hooks });
    await loaded(b2, bob.identity);
    const m1 = (await a.session.seal({ recipient: bob.identity, plaintext: text('one') })).ciphertext;
    const id = eventId();
    const staged = await b2.receiveState.stage({
      operationId: opId(), revision: 0, event: { eventId: id, sender: alice.identity, ciphertext: m1, receiptRequested: true },
    });
    const opened = await b2.session.openCandidate({ sender: alice.identity, ciphertext: m1 });
    armed.on = true;
    const operationId = opId();
    const argument = {
      operationId, revision: staged.revision, eventId: id, ticket: opened.ticket,
      result: { type: 'application', sender: alice.identity, payload: opened.plaintext, receiptDue: true },
    };
    return { alice, bob, b2, id, argument, operationId };
  }

  test('a failure before the rename is a definite FAILED; resolve then answers aborted and a late commit is refused', async () => {
    const { bob, b2, id, argument, operationId } = await setup('temp-fsync');
    expect(await b2.receiveState.commit(argument)).toEqual({ code: FAILED });
    const resolved = await b2.receiveState.resolve({ operationId });
    expect(resolved).toEqual({ status: 'aborted', revision: argument.revision, storedBytes: expect.any(Number) });
    expect(await b2.receiveState.resolve({ operationId })).toEqual(resolved);
    expect(await b2.receiveState.commit(argument)).toEqual({ code: FAILED });
    const snapshot = await loaded(bob.instance(), bob.identity);
    expect(snapshot.pending.map((e) => e.eventId)).toEqual([id]);
  });

  test('a failure of the directory fsync is uncertain: resolve fails until a new load, which shows the outcome', async () => {
    const { bob, b2, id, argument, operationId } = await setup('directory-fsync');
    await expect(b2.receiveState.commit(argument)).rejects.toThrow('outcome unknown');
    expect(await b2.receiveState.resolve({ operationId })).toEqual({ code: FAILED });
    expect(await b2.receiveState.resolve({ operationId })).toEqual({ code: FAILED });
    await expect(b2.session.seal({ recipient: 'a'.repeat(64), plaintext: text('x') })).rejects.toThrow('not usable');
    const snapshot = await loaded(bob.instance(), bob.identity);
    expect(snapshot.ready.map((e) => e.eventId)).toEqual([id]); // the rename had happened
  });

  test('resolve of the last durable commit answers committed with its exact result, repeatedly', async () => {
    const { b2, argument, operationId } = await setup('none');
    const committed = await b2.receiveState.commit(argument);
    const resolved = await b2.receiveState.resolve({ operationId });
    expect(resolved).toEqual({ status: 'committed', revision: committed.revision, storedBytes: committed.storedBytes, result: argument.result });
    expect(await b2.receiveState.resolve({ operationId })).toEqual(resolved);
  });
});

describe('review cycle 1: installation, resolution, cursors, header bounds, verification faults', () => {
  async function staged(b, alice, a, bob, plaintext, receiptRequested = true) {
    const ciphertext = (await a.session.seal({ recipient: bob.identity, plaintext: text(plaintext) })).ciphertext;
    const id = eventId();
    const done = await b.receiveState.stage({
      operationId: opId(), revision: (b.inspect().revision), event: { eventId: id, sender: alice.identity, ciphertext, receiptRequested },
    });
    return { id, ciphertext, revision: done.revision };
  }

  test('a failed installation after a durable commit stops the adapter: commit is uncertain, resolve fails, nothing is checkpointed', async () => {
    const hooks = { beforeReapply: () => { throw new Error('re-apply fault'); }, beforeSwap: () => { throw new Error('swap fault'); } };
    const { alice, bob, a } = await pair();
    const b2 = bob.instance({ hooks: {} });
    await loaded(b2, bob.identity);
    const first = await staged(b2, alice, a, bob, 'one');
    const opened1 = await b2.session.openCandidate({ sender: alice.identity, ciphertext: first.ciphertext });
    await b2.receiveState.commit({
      operationId: opId(), revision: first.revision, eventId: first.id, ticket: opened1.ticket,
      result: { type: 'application', sender: alice.identity, payload: opened1.plaintext, receiptDue: true },
    });
    const b3 = bob.instance({ hooks });
    await loaded(b3, bob.identity);
    const second = await staged(b3, alice, a, bob, 'two');
    const opened = await b3.session.openCandidate({ sender: alice.identity, ciphertext: second.ciphertext });
    const operationId = opId();
    await expect(b3.receiveState.commit({
      operationId, revision: second.revision, eventId: second.id, ticket: opened.ticket,
      result: { type: 'application', sender: alice.identity, payload: opened.plaintext, receiptDue: true },
    })).rejects.toThrow('could not be installed');
    expect(await b3.receiveState.resolve({ operationId })).toEqual({ code: FAILED });
    await expect(b3.session.seal({ recipient: alice.identity, plaintext: text('x') })).rejects.toThrow('not usable');
    const b4 = bob.instance();
    const snapshot = await loaded(b4, bob.identity);
    expect(snapshot.ready.map((e) => untext(e.payload))).toEqual(['one', 'two']);
    const reply = (await b4.session.seal({ recipient: alice.identity, plaintext: text('after') })).ciphertext;
    expect(untext((await receive(a, 0, bob.identity, reply)).opened.plaintext)).toBe('after');
  });

  test('when the re-applied state cannot be used, the committed state replaces the authoritative engine', async () => {
    let fault = false;
    const { alice, bob, a } = await pair();
    const b2 = bob.instance({ hooks: { beforeReapply: () => { if (fault) throw new Error('re-apply fault'); } } });
    await loaded(b2, bob.identity);
    const first = await staged(b2, alice, a, bob, 'one');
    const o1 = await b2.session.openCandidate({ sender: alice.identity, ciphertext: first.ciphertext });
    const c1 = await b2.receiveState.commit({
      operationId: opId(), revision: first.revision, eventId: first.id, ticket: o1.ticket,
      result: { type: 'application', sender: alice.identity, payload: o1.plaintext, receiptDue: true },
    });
    fault = true;
    const m2 = (await a.session.seal({ recipient: bob.identity, plaintext: text('two') })).ciphertext;
    const two = await receive(b2, c1.revision, alice.identity, m2);
    expect(two.committed.revision).toBe(c1.revision + 2);
    expect(b2.inspect().swaps).toBe(1);
    fault = false;
    const m3 = (await a.session.seal({ recipient: bob.identity, plaintext: text('three') })).ciphertext;
    expect(untext((await receive(b2, two.committed.revision, alice.identity, m3)).opened.plaintext)).toBe('three');
    // the replaced engine never opens a committed message again
    expect((await b2.session.openCandidate({ sender: alice.identity, ciphertext: m2 })).receiveOutcome).toBe('retry');
  });

  test('resolve keeps the exact result after ack, receiptDone and commitCursor, until the next load', async () => {
    const { alice, bob, a, b } = await pair();
    const one = await staged(b, alice, a, bob, 'kept');
    const opened = await b.session.openCandidate({ sender: alice.identity, ciphertext: one.ciphertext });
    const operationId = opId();
    const result = { type: 'application', sender: alice.identity, payload: opened.plaintext, receiptDue: true };
    const committed = await b.receiveState.commit({ operationId, revision: one.revision, eventId: one.id, ticket: opened.ticket, result });
    const acked = await b.receiveState.ack({ operationId: opId(), revision: committed.revision, eventId: one.id });
    const done = await b.receiveState.receiptDone({ operationId: opId(), revision: acked.revision, eventId: one.id });
    const cursor = await b.receiveState.commitCursor({
      operationId: opId(), revision: done.revision, relay: 'ws://127.0.0.1:2', generation: 1, syncedUntil: 5,
    });
    const resolved = await b.receiveState.resolve({ operationId });
    expect(resolved).toEqual({ status: 'committed', revision: cursor.revision, storedBytes: cursor.storedBytes, result });
    expect(await b.receiveState.resolve({ operationId })).toEqual(resolved);
    // after a load the record is no longer answered, and the next write drops it
    const b2 = bob.instance();
    const snapshot = await loaded(b2, bob.identity);
    expect(b2.inspect().loadedResolution).toBe(true);
    expect((await b2.receiveState.resolve({ operationId })).status).toBe('aborted');
    const write = await b2.receiveState.commitCursor({
      operationId: opId(), revision: snapshot.revision, relay: 'ws://127.0.0.1:2', generation: 2, syncedUntil: 6,
    });
    expect(write.storedBytes).toBe(snapshot.storedBytes);
    const b3 = bob.instance();
    await loaded(b3, bob.identity);
    expect(b3.inspect().loadedResolution).toBe(false);
  });

  test('an aborted operation id stays refused after more than 4 096 other resolutions, even with a fresh candidate', async () => {
    const armed = { on: true };
    const hooks = { beforeStep: (name, operation) => { if (armed.on && operation === 'commit' && name === 'temp-write') throw new Error('injected'); } };
    const { alice, bob, a } = await pair();
    const b2 = bob.instance({ hooks });
    await loaded(b2, bob.identity);
    const one = await staged(b2, alice, a, bob, 'late');
    let opened = await b2.session.openCandidate({ sender: alice.identity, ciphertext: one.ciphertext });
    const operationId = opId();
    const argument = () => ({
      operationId, revision: one.revision, eventId: one.id, ticket: opened.ticket,
      result: { type: 'application', sender: alice.identity, payload: opened.plaintext, receiptDue: true },
    });
    expect(await b2.receiveState.commit(argument())).toEqual({ code: FAILED });
    expect((await b2.receiveState.resolve({ operationId })).status).toBe('aborted');
    for (let i = 0; i < 4_100; i += 1) await b2.receiveState.resolve({ operationId: opId() });
    armed.on = false;
    opened = await b2.session.openCandidate({ sender: alice.identity, ciphertext: one.ciphertext });
    expect(await b2.receiveState.commit(argument())).toEqual({ code: FAILED });
    const snapshot = await loaded(bob.instance(), bob.identity);
    expect(snapshot.pending.map((e) => e.eventId)).toEqual([one.id]);
  });

  test('cursors: a seventeenth and a 257th cursor keep the archive readable; the least recently committed is dropped', async () => {
    const { bob, b } = await pair();
    let revision = 0;
    for (let i = 0; i < 257; i += 1) {
      ({ revision } = await b.receiveState.commitCursor({
        operationId: opId(), revision, relay: `ws://127.0.0.1:${1000 + i}`, generation: 1, syncedUntil: i,
      }));
      if (i === 16) expect((await loaded(bob.instance(), bob.identity)).cursors).toHaveLength(17);
    }
    const snapshot = await loaded(bob.instance(), bob.identity);
    expect(snapshot.cursors).toHaveLength(256);
    expect(snapshot.cursors[0]).toEqual({ relay: 'ws://127.0.0.1:1001', syncedUntil: 1 });
    expect(snapshot.cursors[255]).toEqual({ relay: 'ws://127.0.0.1:1256', syncedUntil: 256 });
  });

  test('a canonical group id longer than the adapter stores is retry for an invitee binding, reject for an established one', async () => {
    const { alice, bob, a, b } = await pair();
    const long = Buffer.alloc(256, 0x61);
    const ciphertext = Uint8Array.from([0x00, 0x01, 0x00, 0x02, 0x41, 0x00, ...long, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 9, 9, 9]);
    const got = await receive(b, 0, alice.identity, ciphertext);
    expect(got.opened.receiveOutcome).toBe('retry');
    expect((await loaded(bob.instance(), bob.identity)).pending.map((e) => e.eventId)).toEqual([got.id]);
    // Alice's binding is established (she started the group): the same header is a different group.
    const fromBob = await receive(a, 0, bob.identity, ciphertext);
    expect(fromBob.opened.receiveOutcome).toBe('reject');
    expect(fromBob.committed.revision).toBe(2);
  });

  test.each([['group-load'], ['export-key'], ['load-session'], ['malformed exporter value']])(
    'a fault at %s of the invitee verification is retry; the binding is unchanged and a later retry completes it',
    async (where) => {
      let fail = true;
      const hooks = {
        beforeVerification: (step) => { if (fail && step === where) throw new Error(`fault at ${step}`); },
        afterExport: (value) => (fail && where === 'malformed exporter value' ? value.subarray(0, 16) : value),
      };
      const { alice, bob, a } = await pair();
      const b2 = bob.instance({ hooks });
      await loaded(b2, bob.identity);
      const one = await staged(b2, alice, a, bob, 'verified later', false);
      const first = await b2.session.openCandidate({ sender: alice.identity, ciphertext: one.ciphertext });
      expect(first.receiveOutcome).toBe('retry');
      expect(b2.inspect().bindings).toEqual([{ peer: alice.identity, groupId: null }]);
      fail = false;
      const again = await b2.session.openCandidate({ sender: alice.identity, ciphertext: one.ciphertext });
      expect(untext(again.plaintext)).toBe('verified later');
      await b2.receiveState.commit({
        operationId: opId(), revision: one.revision, eventId: one.id, ticket: again.ticket,
        result: { type: 'application', sender: alice.identity, payload: again.plaintext, receiptDue: false },
      });
      expect(b2.inspect().bindings[0].groupId).toBe(headerGroupId(one.ciphertext));
    },
  );

  test('a failure at the reported step (after the rename and the directory fsync) is uncertain, not FAILED', async () => {
    const armed = { on: false };
    const hooks = { beforeStep: (name, operation) => { if (armed.on && operation === 'commit' && name === 'reported') throw new Error('injected'); } };
    const { alice, bob, a } = await pair();
    const b2 = bob.instance({ hooks });
    await loaded(b2, bob.identity);
    const one = await staged(b2, alice, a, bob, 'reported');
    const opened = await b2.session.openCandidate({ sender: alice.identity, ciphertext: one.ciphertext });
    armed.on = true;
    const operationId = opId();
    await expect(b2.receiveState.commit({
      operationId, revision: one.revision, eventId: one.id, ticket: opened.ticket,
      result: { type: 'application', sender: alice.identity, payload: opened.plaintext, receiptDue: true },
    })).rejects.toThrow('outcome unknown');
    expect(await b2.receiveState.resolve({ operationId })).toEqual({ code: FAILED });
    expect((await loaded(bob.instance(), bob.identity)).ready.map((e) => e.eventId)).toEqual([one.id]);
  });
});

describe('storedBytes', () => {
  test('is the canonical formula, not the file size', async () => {
    const { bob, a, alice, b } = await pair();
    const ciphertext = (await a.session.seal({ recipient: bob.identity, plaintext: text('abc') })).ciphertext;
    const got = await receive(b, 0, alice.identity, ciphertext, { receiptRequested: true });
    const snapshot = await loaded(bob.instance(), bob.identity);
    const mls = b.inspect().engine.serializeState().length;
    expect(snapshot.storedBytes).toBe(storedBytesOf({
      mlsState: { length: mls }, pending: [], ready: [{ payload: text('abc') }], seen: [got.id], acknowledged: [],
      receiptsDue: [{}], cursors: [], bindings: [{ groupId: headerGroupId(ciphertext) }],
    }));
    // Until the next load the resolution record of the last commit (65 + payload) is counted too.
    expect(got.committed.storedBytes).toBe(snapshot.storedBytes + 65 + 3);
  });
});
