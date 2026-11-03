// test/crypto/mls-one-to-one-invariant.test.js
//
// A 1:1 session is an MLS group of exactly two members: us and one peer. Two
// properties keep it that way:
//   1. Only application messages are processed. Any other MLS message (a proposal
//      or a commit, even one validly sent by the legitimate peer) is rejected before
//      it reaches the engine, so membership, epoch and pending proposals are left
//      unchanged.
//   2. A group is only accepted as 1:1 when it has exactly two leaves: one with our
//      own credential and one with the expected peer's credential. The engine
//      refuses any other group before registering it, and the session re-checks the
//      invariant before every later use.
// Every rejection test also counts calls into the engine group: a rejected input
// must never reach the state-mutating binding call.
import { describe, test, expect, beforeAll } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { MlsEngine } from '../../src/crypto/mls/mls-engine.js';
import * as sessionModule from '../../src/crypto/mls/mls-session.js';
import { Group, KeyPackage } from '../../vendor/openmls-wasm/openmls_wasm.js';

const wasmPath = fileURLToPath(
  new URL('../../vendor/openmls-wasm/openmls_wasm_bg.wasm', import.meta.url),
);
const wasmBytes = readFileSync(wasmPath);

const enc = (s) => new TextEncoder().encode(s);
const dec = (b) => new TextDecoder().decode(b);

const A = 'a'.repeat(64);
const B = 'b'.repeat(64);
const C = 'c'.repeat(64);
const LABEL = 'styx-test-epoch-probe';
const CTX = new Uint8Array([1, 2, 3]);

async function paired() {
  const a = await MlsEngine.create({ name: A });
  const b = await MlsEngine.create({ name: B });
  const { welcome, ratchetTree } = a.startSession('b', b.keyPackageBytes());
  b.joinSession('a', welcome, ratchetTree);
  return { a, b };
}

/**
 * Observable state of one side: membership, an epoch-bound exporter value, and the
 * complete serialized provider storage (which includes any stored pending proposal).
 * Read straight from the engine, bypassing the session wrapper.
 */
function stateOf(engine, contactId) {
  const group = engine.session(contactId)._group;
  return {
    members: [...group.member_identities()].sort(),
    exporter: Array.from(group.export_key(engine.provider, LABEL, CTX, 32)),
    storage: Array.from(engine.serializeState()),
  };
}

/** Count calls into one method of an engine group handle. */
function spy(group, name) {
  const counter = { calls: 0 };
  const original = group[name].bind(group);
  group[name] = (...args) => { counter.calls += 1; return original(...args); };
  return counter;
}

/** Peer A, legitimately in the group, builds a proposal + commit adding a third member. */
async function peerBuildsAdd(a) {
  const c = await MlsEngine.create({ name: C });
  return a.session('b')._group.propose_and_commit_add(
    a.provider,
    a.identity,
    KeyPackage.from_bytes(c.keyPackageBytes()),
  );
}

/**
 * A group handed to B as "1:1 with A" that actually has three leaves: A, B, and a
 * second leaf carrying B's own credential under a key A controls.
 */
async function threeLeafWelcomeForB() {
  const a = await MlsEngine.create({ name: A });
  const b = await MlsEngine.create({ name: B });
  const shadow = await MlsEngine.create({ name: B });
  const group = Group.create_new(a.provider, a.identity, 'styx:three-leaf-test');
  group.propose_and_commit_add(a.provider, a.identity, KeyPackage.from_bytes(shadow.keyPackageBytes()));
  group.merge_pending_commit(a.provider);
  const add = group.propose_and_commit_add(a.provider, a.identity, KeyPackage.from_bytes(b.keyPackageBytes()));
  group.merge_pending_commit(a.provider);
  return { a, b, group, welcome: add.welcome, ratchetTree: group.export_ratchet_tree().to_bytes() };
}

function mulberry32(seed) {
  let t = seed >>> 0;
  return () => {
    t = (t + 0x6d2b79f5) >>> 0;
    let x = Math.imul(t ^ (t >>> 15), 1 | t);
    x = (x + Math.imul(x ^ (x >>> 7), 61 | x)) ^ x;
    return ((x ^ (x >>> 14)) >>> 0) / 4294967296;
  };
}

describe('MLS 1:1 sessions process application messages only', () => {
  beforeAll(async () => {
    await MlsEngine.initWasm({ wasmBytes });
  });

  test('a proposal then a commit from the legitimate peer are rejected and change no state', async () => {
    const { a, b } = await paired();
    const earlier = a.session('b').encrypt(enc('sent before the commit'));
    const before = stateOf(b, 'a');
    const { proposal, commit } = await peerBuildsAdd(a);
    const calls = spy(b.session('a')._group, 'process_message');

    expect(() => b.session('a').decrypt(proposal)).toThrow();
    expect(() => b.session('a').decrypt(commit)).toThrow();

    expect(calls.calls).toBe(0);
    expect(stateOf(b, 'a')).toEqual(before);
    expect(before.members).toEqual([A, B].sort());
    expect(b.peerIdentity('a')).toBe(A);
    // Same epoch: a message encrypted before the commit still opens.
    const out = b.session('a').decrypt(earlier);
    expect(out.kind).toBe('application');
    expect(dec(out.plaintext)).toBe('sent before the commit');

    // The exact bytes rejected above are valid: fed directly to the engine group,
    // bypassing the session wrapper, they change the membership and the epoch.
    const raw = b.session('a')._group;
    raw.process_message(b.provider, proposal);
    raw.process_message(b.provider, commit);
    expect(raw.member_identities().length).toBe(3);
    expect(Array.from(raw.export_key(b.provider, LABEL, CTX, 32))).not.toEqual(before.exporter);
  });

  test('a valid commit from the legitimate peer is rejected and changes no state', async () => {
    // The commit's proposal is already stored (applied straight to the engine
    // group), so the commit itself is valid: only the session can stop it.
    const { a, b } = await paired();
    const { proposal, commit } = await peerBuildsAdd(a);
    b.session('a')._group.process_message(b.provider, proposal);
    const before = stateOf(b, 'a');
    const calls = spy(b.session('a')._group, 'process_message');

    expect(() => b.session('a').decrypt(commit)).toThrow();
    expect(calls.calls).toBe(0);
    expect(stateOf(b, 'a')).toEqual(before);
    expect(b.peerIdentity('a')).toBe(A);

    // Control: the same commit applied straight to the engine group adds a member.
    b.session('a')._group.process_message(b.provider, commit);
    expect(b.session('a')._group.member_identities().length).toBe(3);
  });

  test('a proposal from the legitimate peer is rejected and stores no pending proposal', async () => {
    const { a, b } = await paired();
    const before = stateOf(b, 'a');
    const { proposal } = await peerBuildsAdd(a);
    const calls = spy(b.session('a')._group, 'process_message');

    expect(() => b.session('a').decrypt(proposal)).toThrow();
    expect(calls.calls).toBe(0);
    // The provider storage is byte-identical: no pending proposal was stored.
    expect(stateOf(b, 'a')).toEqual(before);
    // The session still works in both directions at the same epoch.
    expect(dec(a.session('b').decrypt(b.session('a').encrypt(enc('still two of us'))).plaintext))
      .toBe('still two of us');

    // The exact proposal rejected above is valid: the raw engine group stores it.
    const storageBefore = Array.from(b.serializeState());
    b.session('a')._group.process_message(b.provider, proposal);
    expect(Array.from(b.serializeState())).not.toEqual(storageBefore);
  });

  test('our own application message echoed back yields no application plaintext', async () => {
    // OpenMLS reports our own private message as OwnPrivateMessage and the binding
    // returns no bytes: that is not a message from the peer.
    const { a, b } = await paired();
    const wire = a.session('b').encrypt(enc('mine'));
    const before = stateOf(a, 'b');
    expect(() => a.session('b').decrypt(wire)).toThrow();
    expect(stateOf(a, 'b')).toEqual(before);
    expect(dec(b.session('a').decrypt(wire).plaintext)).toBe('mine');
  });

  test('the header check accepts application messages and refuses control and malformed input', async () => {
    const { isMlsApplicationMessage } = sessionModule;
    expect(typeof isMlsApplicationMessage).toBe('function');
    const { a } = await paired();
    const app = a.session('b').encrypt(enc('x'));
    const { proposal, commit, welcome } = await peerBuildsAdd(a);
    expect(isMlsApplicationMessage(app)).toBe(true);
    expect(isMlsApplicationMessage(commit)).toBe(false);
    expect(isMlsApplicationMessage(proposal)).toBe(false);
    expect(isMlsApplicationMessage(welcome)).toBe(false);
    expect(isMlsApplicationMessage(new Uint8Array(0))).toBe(false);
    expect(isMlsApplicationMessage(app.subarray(0, 6))).toBe(false);
    expect(isMlsApplicationMessage(Array.from(app))).toBe(false);
    expect(isMlsApplicationMessage(null)).toBe(false);
    const publicWire = Uint8Array.from(app);
    publicWire[3] = 1; // public-message wire format
    expect(isMlsApplicationMessage(publicWire)).toBe(false);
    const otherVersion = Uint8Array.from(app);
    otherVersion[1] = 2; // not MLS 1.0
    expect(isMlsApplicationMessage(otherVersion)).toBe(false);
    const badVarint = Uint8Array.from(app);
    badVarint[4] = 0xc0; // reserved 8-byte varint prefix
    expect(isMlsApplicationMessage(badVarint)).toBe(false);
  });

  test('the header check reads 2- and 4-byte group id lengths and refuses non-minimal ones', async () => {
    const { isMlsApplicationMessage } = sessionModule;
    const header = (lengthBytes, groupIdLength, contentType) => {
      const bytes = new Uint8Array(4 + lengthBytes.length + groupIdLength + 8 + 2);
      bytes.set([0, 1, 0, 2, ...lengthBytes]);
      bytes[4 + lengthBytes.length + groupIdLength + 8] = contentType;
      return bytes;
    };
    // Minimal encodings: 2 bytes for 64..16383, 4 bytes from 16384.
    expect(isMlsApplicationMessage(header([0x40, 0x40], 64, 1))).toBe(true);
    expect(isMlsApplicationMessage(header([0x40, 0x40], 64, 3))).toBe(false);
    expect(isMlsApplicationMessage(header([0x80, 0x00, 0x40, 0x00], 16384, 1))).toBe(true);
    expect(isMlsApplicationMessage(header([0x80, 0x00, 0x40, 0x00], 16384, 2))).toBe(false);
    // Non-minimal encodings of small lengths are refused.
    expect(isMlsApplicationMessage(header([0x40, 0x05], 5, 1))).toBe(false);
    expect(isMlsApplicationMessage(header([0x80, 0x00, 0x00, 0x05], 5, 1))).toBe(false);
    expect(isMlsApplicationMessage(header([0x80, 0x00, 0x3f, 0xff], 16383, 1))).toBe(false);
    // Truncated multi-byte lengths and a header cut before the content type.
    expect(isMlsApplicationMessage(new Uint8Array([0, 1, 0, 2, 0x40]))).toBe(false);
    expect(isMlsApplicationMessage(new Uint8Array([0, 1, 0, 2, 0x80, 0x00, 0x40]))).toBe(false);
    expect(isMlsApplicationMessage(header([0x40, 0x40], 64, 1).subarray(0, 4 + 2 + 64 + 8))).toBe(false);
  });

  test('real messages with 2- and 4-byte group ids round-trip through the session', async () => {
    for (const length of [100, 20000]) {
      const a = await MlsEngine.create({ name: A });
      const b = await MlsEngine.create({ name: B });
      const { group, welcome, ratchetTree } = await (async () => {
        const g = Group.create_new(a.provider, a.identity, `styx:${'x'.repeat(length)}`);
        const add = g.propose_and_commit_add(a.provider, a.identity, KeyPackage.from_bytes(b.keyPackageBytes()));
        g.merge_pending_commit(a.provider);
        return { group: g, welcome: add.welcome, ratchetTree: g.export_ratchet_tree().to_bytes() };
      })();
      b.joinSession('a', welcome, ratchetTree, { expectedPeer: A });
      const wire = group.create_message(a.provider, a.identity, enc(`group id of ${length + 5} bytes`));
      expect(wire[4] >> 6).toBe(length < 16000 ? 1 : 2);
      expect(sessionModule.isMlsApplicationMessage(wire)).toBe(true);
      expect(dec(b.session('a').decrypt(wire).plaintext)).toBe(`group id of ${length + 5} bytes`);
    }
  });

  test('malformed and non-application input changes no state and the session survives', async () => {
    const { a, b } = await paired();
    const keyPackage = b.keyPackageBytes(); // creating it writes to b's storage: do it first
    const before = stateOf(b, 'a');
    const app = a.session('b').encrypt(enc('relabel me'));
    const relabelled = Uint8Array.from(app);
    // Rewrite the content type of a private message to "proposal": refused by the
    // header check without reaching the engine.
    const groupIdLen = relabelled[4] & 0x3f; // short group ids use a 1-byte varint
    relabelled[5 + groupIdLen + 8] = 2;
    const calls = spy(b.session('a')._group, 'process_message');
    for (const input of [new Uint8Array(0), new Uint8Array([0, 1, 0, 2]), relabelled, keyPackage]) {
      expect(() => b.session('a').decrypt(input)).toThrow();
    }
    expect(calls.calls).toBe(0);
    expect(stateOf(b, 'a')).toEqual(before);
    expect(dec(b.session('a').decrypt(app).plaintext)).toBe('relabel me');
  });

  test('random bodies fail closed; only application-typed headers reach the engine', async () => {
    const { a, b } = await paired();
    const app = a.session('b').encrypt(enc('header donor'));
    const groupIdLen = app[4] & 0x3f;
    const contentTypeOffset = 5 + groupIdLen + 8;
    const headerLength = contentTypeOffset + 1;
    const calls = spy(b.session('a')._group, 'process_message');
    const rnd = mulberry32(7);
    let applicationTyped = 0;
    for (let i = 0; i < 150; i += 1) {
      const tail = Math.floor(rnd() * 257);
      const buf = new Uint8Array(headerLength + tail);
      buf.set(app.subarray(0, headerLength));
      buf[contentTypeOffset] = 1 + (i % 3); // application, proposal, commit
      if (buf[contentTypeOffset] === 1) applicationTyped += 1;
      for (let j = headerLength; j < buf.length; j += 1) buf[j] = Math.floor(rnd() * 256);
      let caught;
      try { b.session('a').decrypt(buf); } catch (e) { caught = e; }
      expect(caught).toBeDefined();
      expect(caught).not.toBeInstanceOf(WebAssembly.RuntimeError);
    }
    expect(applicationTyped).toBe(50);
    expect(calls.calls).toBe(applicationTyped);
    expect(dec(b.session('a').decrypt(app).plaintext)).toBe('header donor');
  });

  test('non-PrivateMessage MLS messages never reach the engine', async () => {
    const { a, b } = await paired();
    const app = a.session('b').encrypt(enc('x'));
    const { welcome } = await peerBuildsAdd(a);
    const publicWire = Uint8Array.from(app);
    publicWire[3] = 1; // the public-message wire format, otherwise identical bytes
    const before = stateOf(b, 'a');
    const calls = spy(b.session('a')._group, 'process_message');
    for (const input of [publicWire, welcome, b.keyPackageBytes()]) {
      expect(() => b.session('a').decrypt(input)).toThrow();
    }
    expect(calls.calls).toBe(0);
    expect(stateOf(b, 'a').members).toEqual(before.members);
    expect(stateOf(b, 'a').exporter).toEqual(before.exporter);
  });

  test('control: application messages still round-trip in both directions', async () => {
    const { a, b } = await paired();
    for (let i = 0; i < 5; i += 1) {
      expect(dec(b.session('a').decrypt(a.session('b').encrypt(enc(`a->b ${i}`))).plaintext)).toBe(`a->b ${i}`);
      expect(dec(a.session('b').decrypt(b.session('a').encrypt(enc(`b->a ${i}`))).plaintext)).toBe(`b->a ${i}`);
    }
  });
});

describe('MLS 1:1 sessions have exactly two members', () => {
  beforeAll(async () => {
    await MlsEngine.initWasm({ wasmBytes });
  });

  test('a join of a group with a third leaf duplicating our own credential is refused', async () => {
    const { b, welcome, ratchetTree } = await threeLeafWelcomeForB();
    expect(() => b.joinSession('a', welcome, ratchetTree)).toThrow();
    expect(b.session('a')).toBeUndefined();
    expect(b.peerIdentity('a')).toBeNull();
  });

  test('a session that is no longer exactly two members cannot encrypt, decrypt or export', async () => {
    // A genuine session whose group grows to three members behind the session's
    // back (the peer's add applied straight to the engine group).
    const { a, b } = await paired();
    const fromA = a.session('b').encrypt(enc('hello'));
    const { proposal, commit } = await peerBuildsAdd(a);
    b.session('a')._group.process_message(b.provider, proposal);
    b.session('a')._group.process_message(b.provider, commit);
    const session = b.session('a');
    expect(session.memberIdentities().length).toBe(3);
    expect(b.peerIdentity('a')).toBeNull();
    const before = Array.from(b.serializeState());
    // Count every call into the engine group operations the guards must prevent.
    const calls = { create_message: 0, process_message: 0, export_key: 0 };
    for (const name of Object.keys(calls)) {
      const original = session._group[name].bind(session._group);
      session._group[name] = (...args) => { calls[name] += 1; return original(...args); };
    }
    expect(() => session.encrypt(enc('must not be readable by the third leaf'))).toThrow();
    expect(() => session.exportSecret(LABEL, CTX, 32)).toThrow();
    expect(() => session.decrypt(fromA)).toThrow();
    expect(calls).toEqual({ create_message: 0, process_message: 0, export_key: 0 });
    expect(Array.from(b.serializeState())).toEqual(before);
  });

  test('control: a genuine pairing binds each side to the other', async () => {
    const { a, b } = await paired();
    expect(a.peerIdentity('b')).toBe(B);
    expect(b.peerIdentity('a')).toBe(A);
    expect(a.session('b').memberIdentities().length).toBe(2);
    expect(b.session('a').memberIdentities().length).toBe(2);
  });

  test('a group whose other member carries our own credential is never registered', async () => {
    const a = await MlsEngine.create({ name: A });
    const twin = await MlsEngine.create({ name: A });
    expect(() => a.startSession('twin', twin.keyPackageBytes())).toThrow();
    expect(a.session('twin')).toBeUndefined();
    expect(a.peerIdentity('twin')).toBeNull();
  });
});
