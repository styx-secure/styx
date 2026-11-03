// test/crypto/mls-session-binding.test.js
//
// Every 1:1 session is bound to one expected peer, and the engine checks that
// binding itself, before it registers a session:
//   - startSession, joinSession and loadSession register a group only if it is
//     exactly {us, one peer} — and exactly the expected peer when one is named;
//   - joinSession, given the group id the caller will later reload the session
//     with, registers the group only if that id names this very group;
//   - loadSession never replaces an existing session and never registers a group
//     that is already another contact's session;
//   - a refused group is never registered, so it neither becomes usable nor blocks
//     a later legitimate session for the same contact.
// A registered session stays bound to its peer for every later use. Two small
// hardening rules close the boundary: encrypt refuses an empty payload, and
// decrypt only processes a private copy of a genuine Uint8Array.
import { describe, test, expect, beforeAll } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { MlsEngine } from '../../src/crypto/mls/mls-engine.js';
import * as sessionModule from '../../src/crypto/mls/mls-session.js';
import { Group, KeyPackage } from '../../vendor/openmls-wasm/openmls_wasm.js';

const wasmBytes = readFileSync(
  fileURLToPath(new URL('../../vendor/openmls-wasm/openmls_wasm_bg.wasm', import.meta.url)),
);

const enc = (s) => new TextEncoder().encode(s);
const dec = (b) => new TextDecoder().decode(b);

const A = 'a'.repeat(64);
const B = 'b'.repeat(64);
const C = 'c'.repeat(64);
const M = 'd'.repeat(64);

/** The binding error class, or a sentinel that matches nothing when it is absent. */
const BindingError = sessionModule.MlsBindingError || class NoBindingErrorExported {};

function storage(engine) {
  return Array.from(engine.serializeState());
}

/** Count calls into one method of an engine group handle. */
function spy(group, name) {
  const counter = { calls: 0, args: [] };
  const original = group[name].bind(group);
  group[name] = (...args) => {
    counter.calls += 1;
    counter.args.push(args);
    return original(...args);
  };
  return counter;
}

async function paired() {
  const a = await MlsEngine.create({ name: A });
  const b = await MlsEngine.create({ name: B });
  const started = a.startSession('b', b.keyPackageBytes(), { expectedPeer: B });
  b.joinSession('a', started.welcome, started.ratchetTree, { expectedPeer: A, groupId: started.groupId });
  return { a, b, groupId: started.groupId };
}

/** A Welcome for `joiner` into a group created by `founder` with `others` added first. */
async function welcomeInto(founder, joiner, others, groupId) {
  const group = Group.create_new(founder.provider, founder.identity, groupId);
  for (const other of others) {
    group.propose_and_commit_add(founder.provider, founder.identity, KeyPackage.from_bytes(other.keyPackageBytes()));
    group.merge_pending_commit(founder.provider);
  }
  const add = group.propose_and_commit_add(
    founder.provider, founder.identity, KeyPackage.from_bytes(joiner.keyPackageBytes()),
  );
  group.merge_pending_commit(founder.provider);
  return { group, welcome: add.welcome, ratchetTree: group.export_ratchet_tree().to_bytes() };
}

describe('the engine binds every session to the expected peer before registering it', () => {
  beforeAll(async () => {
    await MlsEngine.initWasm({ wasmBytes });
  });

  test('startSession refuses a KeyPackage whose credential is not the expected peer', async () => {
    const us = await MlsEngine.create({ name: B });
    const other = await MlsEngine.create({ name: M });
    expect(() => us.startSession('alice', other.keyPackageBytes(), { expectedPeer: A })).toThrow(BindingError);
    expect(us.session('alice')).toBeUndefined();
    expect(us.peerIdentity('alice')).toBeNull();
    // Nothing was registered, so the genuine contact can still be started.
    const alice = await MlsEngine.create({ name: A });
    const started = us.startSession('alice', alice.keyPackageBytes(), { expectedPeer: A });
    expect(us.peerIdentity('alice')).toBe(A);
    alice.joinSession('b', started.welcome, started.ratchetTree, { expectedPeer: B, groupId: started.groupId });
    expect(dec(alice.session('b').decrypt(us.session('alice').encrypt(enc('hi'))).plaintext)).toBe('hi');
  });

  test('startSession refuses a KeyPackage carrying our own credential', async () => {
    const us = await MlsEngine.create({ name: A });
    const twin = await MlsEngine.create({ name: A });
    expect(() => us.startSession('twin', twin.keyPackageBytes())).toThrow(BindingError);
    expect(us.session('twin')).toBeUndefined();
  });

  test('joinSession refuses a two-member group whose peer is not the expected peer', async () => {
    const us = await MlsEngine.create({ name: B });
    const other = await MlsEngine.create({ name: C });
    const started = other.startSession('b', us.keyPackageBytes());
    expect(() => us.joinSession('alice', started.welcome, started.ratchetTree, { expectedPeer: A }))
      .toThrow(BindingError);
    expect(us.session('alice')).toBeUndefined();
    expect(us.peerIdentity('alice')).toBeNull();
  });

  test('joinSession refuses three members duplicating our credential and registers nothing', async () => {
    const a = await MlsEngine.create({ name: A });
    const b = await MlsEngine.create({ name: B });
    const shadow = await MlsEngine.create({ name: B });
    const { welcome, ratchetTree } = await welcomeInto(a, b, [shadow], 'styx:binding-aab');
    expect(() => b.joinSession('a', welcome, ratchetTree)).toThrow(BindingError);
    expect(b.session('a')).toBeUndefined();
    // The refused group does not block the genuine pairing for the same contact.
    const a2 = await MlsEngine.create({ name: A });
    const started = a2.startSession('b', b.keyPackageBytes());
    b.joinSession('a', started.welcome, started.ratchetTree, { expectedPeer: A, groupId: started.groupId });
    expect(b.peerIdentity('a')).toBe(A);
  });

  test('joinSession refuses three distinct members', async () => {
    const a = await MlsEngine.create({ name: A });
    const b = await MlsEngine.create({ name: B });
    const c = await MlsEngine.create({ name: C });
    const { welcome, ratchetTree } = await welcomeInto(a, b, [c], 'styx:binding-abc');
    expect(() => b.joinSession('a', welcome, ratchetTree, { expectedPeer: A })).toThrow(BindingError);
    expect(b.session('a')).toBeUndefined();
  });

  test('joinSession refuses a declared group id that does not name the joined group', async () => {
    const a = await MlsEngine.create({ name: A });
    const b = await MlsEngine.create({ name: B });
    const c = await MlsEngine.create({ name: C });
    // b already has a session with c: its group id is stored in b's provider.
    const withC = c.startSession('b', b.keyPackageBytes());
    b.joinSession('c', withC.welcome, withC.ratchetTree, { expectedPeer: C, groupId: withC.groupId });
    const started = a.startSession('b', b.keyPackageBytes());
    // Declaring the id of another stored group, or of no stored group, is refused.
    expect(() => b.joinSession('a', started.welcome, started.ratchetTree, { expectedPeer: A, groupId: withC.groupId }))
      .toThrow(BindingError);
    expect(b.session('a')).toBeUndefined();
    const a2 = await MlsEngine.create({ name: A });
    const again = a2.startSession('b', b.keyPackageBytes());
    expect(() => b.joinSession('a', again.welcome, again.ratchetTree, { expectedPeer: A, groupId: 'styx:not-stored' }))
      .toThrow(BindingError);
    expect(b.session('a')).toBeUndefined();
    // c's session is untouched.
    expect(b.peerIdentity('c')).toBe(C);
    expect(dec(b.session('c').decrypt(c.session('b').encrypt(enc('still c'))).plaintext)).toBe('still c');
  });

  test('control: a genuine pairing with expected peers and group id binds both sides', async () => {
    const { a, b } = await paired();
    expect(a.peerIdentity('b')).toBe(B);
    expect(b.peerIdentity('a')).toBe(A);
    expect(dec(b.session('a').decrypt(a.session('b').encrypt(enc('a->b'))).plaintext)).toBe('a->b');
    expect(dec(a.session('b').decrypt(b.session('a').encrypt(enc('b->a'))).plaintext)).toBe('b->a');
  });

  test('control: sessions started and joined without options still bind the one peer', async () => {
    const a = await MlsEngine.create({ name: A });
    const b = await MlsEngine.create({ name: B });
    const started = a.startSession('b', b.keyPackageBytes());
    b.joinSession('a', started.welcome, started.ratchetTree);
    expect(a.peerIdentity('b')).toBe(B);
    expect(b.peerIdentity('a')).toBe(A);
  });
});

describe('loadSession re-binds a stored group before registering it', () => {
  beforeAll(async () => {
    await MlsEngine.initWasm({ wasmBytes });
  });

  test('loadSession never replaces an existing session', async () => {
    const { a } = await paired();
    const c = await MlsEngine.create({ name: C });
    const withC = a.startSession('c', c.keyPackageBytes());
    const before = a.session('b');
    expect(() => a.loadSession('b', withC.groupId)).toThrow();
    expect(a.session('b')).toBe(before);
    expect(a.peerIdentity('b')).toBe(B);
  });

  test('loadSession refuses a group that is already another contact\'s session', async () => {
    const { a, groupId } = await paired();
    expect(() => a.loadSession('b-again', groupId)).toThrow(BindingError);
    expect(a.session('b-again')).toBeUndefined();
  });

  test('loadSession refuses a stored group whose peer is not the expected peer', async () => {
    const { a, groupId } = await paired();
    const restored = await MlsEngine.restore({
      name: A, stateBytes: a.serializeState(), identityPubKey: a.identityPublicKey(),
    });
    expect(() => restored.loadSession(C, groupId, { expectedPeer: C })).toThrow(BindingError);
    expect(restored.session(C)).toBeUndefined();
    // The same stored group still reloads for its real peer.
    expect(restored.loadSession('b', groupId, { expectedPeer: B })).toBeTruthy();
    expect(restored.peerIdentity('b')).toBe(B);
  });

  test('a group refused at join cannot be reloaded for that contact after a restore', async () => {
    const b = await MlsEngine.create({ name: B });
    const c = await MlsEngine.create({ name: C });
    const started = c.startSession('b', b.keyPackageBytes());
    expect(() => b.joinSession(A, started.welcome, started.ratchetTree, { expectedPeer: A })).toThrow(BindingError);
    const restored = await MlsEngine.restore({
      name: B, stateBytes: b.serializeState(), identityPubKey: b.identityPublicKey(),
    });
    expect(() => restored.loadSession(A, started.groupId, { expectedPeer: A })).toThrow(BindingError);
    expect(restored.session(A)).toBeUndefined();
  });

  test('loadSession refuses a stored group that has only our own member', async () => {
    const a = await MlsEngine.create({ name: A });
    Group.create_new(a.provider, a.identity, 'styx:binding-solo');
    expect(() => a.loadSession('solo', 'styx:binding-solo')).toThrow(BindingError);
    expect(a.session('solo')).toBeUndefined();
  });

  test('control: a restored session reloads, stays bound and keeps working', async () => {
    const { a, b, groupId } = await paired();
    const restored = await MlsEngine.restore({
      name: B, stateBytes: b.serializeState(), identityPubKey: b.identityPublicKey(),
    });
    expect(restored.loadSession('a', groupId, { expectedPeer: A })).toBeTruthy();
    expect(restored.peerIdentity('a')).toBe(A);
    expect(dec(restored.session('a').decrypt(a.session('b').encrypt(enc('after reload'))).plaintext))
      .toBe('after reload');
    expect(dec(a.session('b').decrypt(restored.session('a').encrypt(enc('reply'))).plaintext)).toBe('reply');
    expect(restored.loadSession('missing', 'styx:not-stored')).toBeNull();
  });
});

describe('a failure while checking a group frees it once and registers nothing', () => {
  beforeAll(async () => {
    await MlsEngine.initWasm({ wasmBytes });
  });

  /** Run `body` while Group.join wraps every joined handle to count its free() calls. */
  async function withJoinedHandles(body) {
    const originalJoin = Group.join;
    const handles = [];
    Group.join = (...args) => {
      const group = originalJoin.apply(Group, args);
      const entry = { group, frees: 0 };
      const originalFree = group.free.bind(group);
      group.free = () => { entry.frees += 1; return originalFree(); };
      handles.push(entry);
      return group;
    };
    try {
      return await body(handles);
    } finally {
      Group.join = originalJoin;
    }
  }

  test('a failing check of the declared group id is a binding refusal', async () => {
    const a = await MlsEngine.create({ name: A });
    const b = await MlsEngine.create({ name: B });
    const started = a.startSession('b', b.keyPackageBytes());
    const originalLoad = Group.load;
    Group.load = () => { throw new Error('storage unavailable'); };
    try {
      await withJoinedHandles(async (handles) => {
        expect(() => b.joinSession('a', started.welcome, started.ratchetTree, { expectedPeer: A, groupId: started.groupId }))
          .toThrow(BindingError);
        expect(handles.length).toBe(1);
        expect(handles[0].frees).toBe(1);
      });
    } finally {
      Group.load = originalLoad;
    }
    expect(b.session('a')).toBeUndefined();
  });

  test('a failing membership or same-group check is a binding refusal', async () => {
    const a = await MlsEngine.create({ name: A });
    const b = await MlsEngine.create({ name: B });
    const started = a.startSession('b', b.keyPackageBytes());
    const originalJoin = Group.join;
    await withJoinedHandles(async (handles) => {
      const counting = Group.join;
      Group.join = (...args) => {
        const group = counting(...args);
        group.export_key = () => { throw new Error('exporter unavailable'); };
        return group;
      };
      try {
        expect(() => b.joinSession('a', started.welcome, started.ratchetTree, { expectedPeer: A }))
          .toThrow(BindingError);
      } finally {
        Group.join = counting;
      }
      expect(handles.length).toBe(1);
      expect(handles[0].frees).toBe(1);
    });
    expect(Group.join).toBe(originalJoin);
    expect(b.session('a')).toBeUndefined();
  });

  test('loadSession returns null for a missing group even when the contact has a session', async () => {
    const { a } = await paired();
    const before = a.session('b');
    expect(a.loadSession('b', 'styx:not-stored')).toBeNull();
    expect(a.session('b')).toBe(before);
    expect(a.peerIdentity('b')).toBe(B);
  });
});

describe('payload and buffer hardening at the session boundary', () => {
  beforeAll(async () => {
    await MlsEngine.initWasm({ wasmBytes });
  });

  test('encrypt refuses an empty payload without calling the engine', async () => {
    const { a } = await paired();
    const calls = spy(a.session('b')._group, 'create_message');
    const before = storage(a);
    expect(() => a.session('b').encrypt(new Uint8Array(0))).toThrow();
    expect(calls.calls).toBe(0);
    expect(storage(a)).toEqual(before);
  });

  test('an empty application message from the peer is refused and the session survives', async () => {
    // Built on the raw engine group: the session API no longer produces one.
    const { a, b } = await paired();
    const empty = a.session('b')._group.create_message(a.provider, a.identity, new Uint8Array(0));
    expect(sessionModule.isMlsApplicationMessage(empty)).toBe(true);
    expect(() => b.session('a').decrypt(empty)).toThrow();
    expect(b.peerIdentity('a')).toBe(A);
    expect(dec(b.session('a').decrypt(a.session('b').encrypt(enc('next'))).plaintext)).toBe('next');
  });

  test('decrypt hands the engine a private copy, not the caller\'s buffer', async () => {
    const { a, b } = await paired();
    const wire = a.session('b').encrypt(enc('shared buffer'));
    const shared = new Uint8Array(new SharedArrayBuffer(wire.length));
    shared.set(wire);
    const calls = spy(b.session('a')._group, 'process_message');
    expect(dec(b.session('a').decrypt(shared).plaintext)).toBe('shared buffer');
    expect(calls.calls).toBe(1);
    const handed = calls.args[0][1];
    expect(handed).not.toBe(shared);
    expect(handed.buffer).not.toBe(shared.buffer);
    expect(handed.buffer instanceof SharedArrayBuffer).toBe(false);
    expect(Array.from(handed)).toEqual(Array.from(wire));
  });

  test('decrypt refuses an object that is not a genuine Uint8Array view', async () => {
    const { a, b } = await paired();
    const wire = a.session('b').encrypt(enc('proxied'));
    const proxied = new Proxy(wire, {
      get(target, property) {
        const value = Reflect.get(target, property, target);
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
    expect(proxied instanceof Uint8Array).toBe(true);
    const calls = spy(b.session('a')._group, 'process_message');
    const before = storage(b);
    expect(() => b.session('a').decrypt(proxied)).toThrow();
    expect(calls.calls).toBe(0);
    expect(storage(b)).toEqual(before);
    expect(dec(b.session('a').decrypt(wire).plaintext)).toBe('proxied');
  });
});
