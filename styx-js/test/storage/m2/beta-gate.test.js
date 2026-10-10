// beta-gate.test.js — card M2-BETA-GATE of #317 G-SCOPE (owner act
// `styx-owner-act:m2-rescope-c-reduced:v1`, #317 comment 6091950328, §3): the M2 single-tab,
// fail-closed Web Lock guard in `src/storage/m2/beta-gate.js`.
//
// Every Web Locks behaviour is driven through a fake locks API that models one lock manager:
// exclusive locks, `ifAvailable` (callback with `null` when held), grant until the callback's
// promise settles, and the request promise settling after release. A recording vault-worker peer
// stands in for the I-IDB production receiver. Node cannot prove real-browser Web Lock semantics
// (multi-tab, context death); those are not claimed here.

import { describe, test, expect, beforeAll } from '@jest/globals';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, relative, sep } from 'node:path';
import initKdf, { argon2id_derive } from '../../../vendor/styx-kdf-wasm/pkg/styx_kdf_wasm.js';
import {
  acquireM2BetaGate, m2LockName, isVaultDbName, recoveryLockHeld,
  M2_LOCK_PREFIX, M2_PRODUCT_VAULT_DB_NAME, M2_GATE_REFUSALS, M2_HELD_REPORT_TYPES, CLOSED_M2_TOKEN,
} from '../../../src/storage/m2/beta-gate.js';
import { evaluateLockAction } from '../../../src/storage/m2/session-lock.js';
import { createVault } from '../../../src/storage/vault.js';
import { FakeVaultDb, seededBytes } from '../../support/fake-vault-db.js';

const PRODUCT_LOCK = 'styx-m2:styx-vault-default';
const flush = async (n = 10) => { for (let i = 0; i < n; i += 1) await Promise.resolve(); };

/** A fake `navigator.locks`: one manager, exclusive locks, `ifAvailable`, full call log. */
function fakeLocks() {
  const held = new Map(); // name -> { free }
  const calls = [];
  const log = [];
  return {
    held,
    calls,
    log,
    request(name, options, callback) {
      calls.push({ name, options: { ...options }, optionKeys: Object.keys(options) });
      if (options.steal === true) throw new Error('steal must never be requested');
      if (held.has(name)) {
        if (options.ifAvailable === true) {
          log.push(`not-available:${name}`);
          return Promise.resolve(callback(null));
        }
        return Promise.reject(new Error('queued requests are not modelled'));
      }
      let free;
      const freed = new Promise((resolve) => { free = resolve; });
      held.set(name, { free });
      log.push(`granted:${name}`);
      const lock = Object.freeze({ name, mode: options.mode ?? 'exclusive' });
      return Promise.resolve()
        .then(() => callback(lock))
        .then((value) => value, (error) => { throw error; })
        .finally(() => {
          held.delete(name);
          log.push(`freed:${name}`);
          free();
        })
        .then(() => freed);
    },
  };
}

/** A recording vault-worker peer. `ack` controls the withdrawal acknowledgement. */
function recordingPeer(locks, { ack = 'valid', report = 'ok' } = {}) {
  const events = [];
  const peer = {
    events,
    pendingAck: null,
    reports: [],
    reportHeld(r) {
      events.push(['reportHeld', r.type, r.lockName, r.epoch, locks.held.has(r.lockName)]);
      peer.reports.push(r);
      if (report === 'throw') throw new Error('postMessage failed');
      if (report === 'reject') return Promise.reject(new Error('worker gone'));
      if (report === 'never') return new Promise(() => {});
      return undefined;
    },
    withdrawHeld(r) {
      events.push(['withdrawHeld', r.type, r.lockName, r.epoch, locks.held.has(r.lockName)]);
      const good = { type: M2_HELD_REPORT_TYPES.WITHDRAWN_ACK, lockName: r.lockName, epoch: r.epoch, nonce: r.nonce };
      if (ack === 'valid') return Promise.resolve(good);
      if (ack === 'deferred') return new Promise((resolve) => { peer.pendingAck = () => resolve(good); });
      if (ack === 'reject') return Promise.reject(new Error('no ack'));
      if (ack === 'wrong-epoch') return Promise.resolve({ ...good, epoch: r.epoch + 1 });
      if (ack === 'wrong-type') return Promise.resolve({ ...good, type: 'M2_LOCK_HELD' });
      if (ack === 'wrong-nonce') return Promise.resolve({ ...good, nonce: `${r.nonce}x` });
      if (ack === 'no-nonce') return Promise.resolve({ type: good.type, lockName: good.lockName, epoch: good.epoch });
      if (ack === 'throwing-getter') {
        return Promise.resolve(Object.defineProperty({}, 'type', { get() { throw new Error('broken ack'); } }));
      }
      if (ack === 'never') return new Promise(() => {});
      throw new Error(`unknown ack mode ${ack}`);
    },
    terminate() {
      events.push(['terminate', [...locks.held.keys()].includes(PRODUCT_LOCK)]);
    },
  };
  return peer;
}

/** A manual timer so the acknowledgement timeout is deterministic. */
function manualTimers() {
  const timers = [];
  return {
    timers,
    setTimer: (fn, ms) => { const t = { fn, ms, cleared: false }; timers.push(t); return t; },
    clearTimer: (t) => { if (t) t.cleared = true; },
    fireAll: () => timers.filter((t) => !t.cleared).forEach((t) => { t.cleared = true; t.fn(); }),
  };
}

const REJECTION = {
  result: 'LOCKED_ELSEWHERE', disposition: 'LOCK_RETRY', authority: 'NONE',
  firstFailingPhase: 'LOCK', markerState: 'UNCHANGED', authorized: false,
};

function expectRefused(gate, reason) {
  expect(gate.entered).toBe(false);
  expect(gate.reason).toBe(reason);
  expect(gate.token.isHeld()).toBe(false);
  expect(gate.token).toBe(CLOSED_M2_TOKEN);
  expect(recoveryLockHeld(gate.token)).toBe(false);
  expect(gate.decision).toMatchObject(REJECTION);
  expect(Object.isFrozen(gate)).toBe(true);
}

// ---------------------------------------------------------------------------------------------
// Lock name and scope.
// ---------------------------------------------------------------------------------------------

describe('canonical lock name (act §3 "Lock name")', () => {
  test('one name per vault database: styx-m2:<db>, separate from the legacy styx-mls lock', () => {
    expect(M2_LOCK_PREFIX).toBe('styx-m2:');
    expect(M2_PRODUCT_VAULT_DB_NAME).toBe('styx-vault-default');
    expect(m2LockName('styx-vault-default')).toBe(PRODUCT_LOCK);
    expect(m2LockName('styx-vault-test-a')).toBe('styx-m2:styx-vault-test-a');
    expect(m2LockName('styx-vault-default').startsWith('styx-mls:')).toBe(false);
  });

  test('the product database name matches the vault worker lifecycle constant', () => {
    const src = readFileSync(fileURLToPath(new URL('../../../src/crypto/vault-worker-lifecycle.js', import.meta.url)), 'utf8');
    expect(src).toContain("export const VAULT_WORKER_PRODUCT_DB_NAME = 'styx-vault-default';");
  });

  test.each([
    ['styx-ledger'], [''], ['styx-vault-test-'], ['styx-vault-default '], ['STYX-VAULT-DEFAULT'],
    ['styx-mls:'], [null], [42], [{ toString: () => 'styx-vault-default' }],
  ])('wrong scope %p: no lock name, and the gate refuses without any request', async (dbName) => {
    expect(isVaultDbName(dbName)).toBe(false);
    expect(() => m2LockName(dbName)).toThrow(TypeError);
    const locks = fakeLocks();
    const gate = await acquireM2BetaGate({ locks, dbName });
    expectRefused(gate, M2_GATE_REFUSALS.WRONG_SCOPE);
    expect(locks.calls).toEqual([]);
  });

  test('the default database is the product one', async () => {
    const locks = fakeLocks();
    const gate = await acquireM2BetaGate({ locks });
    expect(gate.lockName).toBe(PRODUCT_LOCK);
    await gate.release();
  });
});

// ---------------------------------------------------------------------------------------------
// Fail closed.
// ---------------------------------------------------------------------------------------------

describe('fail closed: unavailable', () => {
  const throwingGetter = Object.defineProperty({}, 'request', { get() { throw new Error('boom'); } });
  test.each([
    ['undefined', undefined], ['null', null], ['empty object', {}], ['non-function request', { request: 'yes' }],
    ['throwing getter', throwingGetter],
  ])('Web Locks %s → UNSUPPORTED, nothing reported', async (_label, locks) => {
    const peer = recordingPeer(fakeLocks());
    const gate = await acquireM2BetaGate({ locks, peer });
    expectRefused(gate, M2_GATE_REFUSALS.UNSUPPORTED);
    expect(peer.events).toEqual([]);
    await gate.release(); // a no-op on a refusal
    expect(peer.events).toEqual([]);
  });
});

describe('fail closed: request rejected', () => {
  test('request throws synchronously', async () => {
    const peer = recordingPeer(fakeLocks());
    const gate = await acquireM2BetaGate({ locks: { request() { throw new Error('SecurityError'); } }, peer });
    expectRefused(gate, M2_GATE_REFUSALS.REJECTED);
    expect(peer.events).toEqual([]);
  });

  test('request calls back with a grant and then throws: the grant is void and freed, entry refused', async () => {
    const peer = recordingPeer(fakeLocks());
    let resolvedHolder = null;
    const locks = {
      request(name, options, cb) {
        const held = cb({ name, mode: 'exclusive' });
        resolvedHolder = held; // the promise the gate returned to hold the lock
        throw new Error('request failed after callback');
      },
    };
    const gate = await acquireM2BetaGate({ locks, peer });
    expectRefused(gate, M2_GATE_REFUSALS.REJECTED);
    expect(peer.events).toEqual([]);
    // The holder promise is settled, so a real lock manager would have freed the lock.
    let settled = false;
    resolvedHolder.then(() => { settled = true; });
    await flush();
    expect(settled).toBe(true);
  });

  test('request returns a rejected promise without calling back', async () => {
    const peer = recordingPeer(fakeLocks());
    const gate = await acquireM2BetaGate({ locks: { request: () => Promise.reject(new Error('AbortError')) }, peer });
    expectRefused(gate, M2_GATE_REFUSALS.REJECTED);
    expect(peer.events).toEqual([]);
  });

  test('request settles without ever calling back', async () => {
    const gate = await acquireM2BetaGate({ locks: { request: () => Promise.resolve() } });
    expectRefused(gate, M2_GATE_REFUSALS.REJECTED);
  });

  test('request returns a non-promise without calling back', async () => {
    const gate = await acquireM2BetaGate({ locks: { request: () => undefined } });
    expectRefused(gate, M2_GATE_REFUSALS.REJECTED);
  });

  test.each([
    ['another name', (name) => ({ name: `${name}x`, mode: 'exclusive' })],
    ['shared mode', (name) => ({ name, mode: 'shared' })],
    ['throwing lock', () => Object.defineProperty({}, 'name', { get() { throw new Error('x'); } })],
  ])('a grant that does not match the request (%s) is refused and freed at once', async (_label, makeLock) => {
    let callbackResult = 'unset';
    const locks = {
      request(name, options, callback) {
        callbackResult = callback(makeLock(name));
        return Promise.resolve(callbackResult);
      },
    };
    const gate = await acquireM2BetaGate({ locks });
    expectRefused(gate, M2_GATE_REFUSALS.REJECTED);
    expect(callbackResult).toBeUndefined(); // not held: the callback returned at once
  });
});

describe('fail closed: held elsewhere', () => {
  test('a second context sees the lock held → HELD_ELSEWHERE (the I-LOCK second-tab outcome)', async () => {
    const locks = fakeLocks();
    const first = await acquireM2BetaGate({ locks });
    expect(first.entered).toBe(true);
    const peer = recordingPeer(locks);
    const second = await acquireM2BetaGate({ locks, peer });
    expectRefused(second, M2_GATE_REFUSALS.HELD_ELSEWHERE);
    expect(second.decision).toEqual(evaluateLockAction({
      contextId: 'main', role: 'WRITER', ownership: 'HELD_BY_OTHER', action: 'STATE_CHANGE',
    }));
    expect(peer.events).toEqual([]);
    expect(first.token.isHeld()).toBe(true); // the holder is unaffected
    await first.release();
  });

  test('a lock held by another context under the same name, pre-seeded', async () => {
    const locks = fakeLocks();
    locks.held.set(PRODUCT_LOCK, { free: () => {} });
    const gate = await acquireM2BetaGate({ locks });
    expectRefused(gate, M2_GATE_REFUSALS.HELD_ELSEWHERE);
  });
});

// ---------------------------------------------------------------------------------------------
// Held (ACTIVE), release, use after release.
// ---------------------------------------------------------------------------------------------

describe('held (ACTIVE) and release', () => {
  test('exactly one exclusive ifAvailable request, never steal, then ACTIVE in the I-LOCK core', async () => {
    const locks = fakeLocks();
    const gate = await acquireM2BetaGate({ locks });
    expect(locks.calls).toEqual([{
      name: PRODUCT_LOCK, options: { mode: 'exclusive', ifAvailable: true }, optionKeys: ['mode', 'ifAvailable'],
    }]);
    expect(gate.entered).toBe(true);
    expect(gate.reason).toBeNull();
    expect(gate.token.isHeld()).toBe(true);
    expect(recoveryLockHeld(gate.token)).toBe(true);
    expect(gate.decision).toEqual(evaluateLockAction({
      contextId: 'main', role: 'WRITER', ownership: 'HELD_BY_SELF', action: 'STATE_CHANGE',
    }));
    expect(gate.decision.authorized).toBe(true);
    expect(locks.held.has(PRODUCT_LOCK)).toBe(true);
    expect(Object.keys(gate.token)).toEqual(['isHeld']);
    expect(Object.isFrozen(gate.token)).toBe(true);
    await gate.release();
  });

  test('the source never requests steal and never queues', () => {
    const src = readFileSync(fileURLToPath(new URL('../../../src/storage/m2/beta-gate.js', import.meta.url)), 'utf8');
    const code = src.split('\n').filter((line) => !line.trim().startsWith('//') && !line.trim().startsWith('*')).join('\n');
    expect(code).not.toMatch(/steal/);
    expect(code.match(/\{ mode: 'exclusive', ifAvailable: true \}/g)).toHaveLength(1);
  });

  test('release: isHeld() turns false synchronously; the lock is freed; it can be taken again', async () => {
    const locks = fakeLocks();
    const gate = await acquireM2BetaGate({ locks });
    const p = gate.release();
    expect(gate.token.isHeld()).toBe(false);
    await p;
    expect(locks.held.has(PRODUCT_LOCK)).toBe(false);
    const again = await acquireM2BetaGate({ locks });
    expect(again.entered).toBe(true);
    await again.release();
  });

  test('use after release: the token stays not held, release is idempotent, the gate inputs stay false', async () => {
    const locks = fakeLocks();
    const gate = await acquireM2BetaGate({ locks });
    const p1 = gate.release();
    const p2 = gate.release();
    expect(p2).toBe(p1);
    await p1;
    for (let i = 0; i < 3; i += 1) {
      expect(gate.token.isHeld()).toBe(false);
      expect(recoveryLockHeld(gate.token)).toBe(false);
    }
    // A later holder does not revive the old token.
    const later = await acquireM2BetaGate({ locks });
    expect(later.token.isHeld()).toBe(true);
    expect(gate.token.isHeld()).toBe(false);
    await later.release();
  });

  test('a lock lost without release (request settled) turns the token false, terminates the peer, calls onLost', async () => {
    let settleRequest;
    const locks = {
      held: new Map(),
      request(name, options, callback) {
        callback({ name, mode: 'exclusive' });
        return new Promise((resolve) => { settleRequest = resolve; });
      },
    };
    const peer = recordingPeer(locks);
    let lost = 0;
    const gate = await acquireM2BetaGate({ locks, peer, onLost: () => { lost += 1; } });
    expect(gate.token.isHeld()).toBe(true);
    settleRequest();
    await flush();
    expect(gate.token.isHeld()).toBe(false);
    expect(lost).toBe(1);
    expect(peer.events.at(-1)[0]).toBe('terminate');
  });
});

// ---------------------------------------------------------------------------------------------
// Held report and release order against an injected worker peer.
// ---------------------------------------------------------------------------------------------

describe('held report and release ordering (act §3 "Port in the vault worker", "Release order")', () => {
  test('the held report is sent once, after the grant, before entry resolves', async () => {
    const locks = fakeLocks();
    const peer = recordingPeer(locks);
    const gate = await acquireM2BetaGate({ locks, peer });
    expect(gate.entered).toBe(true);
    expect(peer.events).toEqual([['reportHeld', 'M2_LOCK_HELD', PRODUCT_LOCK, peer.reports[0].epoch, true]]);
    expect(Number.isSafeInteger(peer.reports[0].epoch) && peer.reports[0].epoch > 0).toBe(true);
    expect(peer.reports[0].nonce).toMatch(/^[0-9a-f]{32}$/);
    expect(Object.keys(peer.reports[0]).sort()).toEqual(['epoch', 'lockName', 'nonce', 'type']);
    await gate.release();
  });

  test('release: withdraw first, wait for the ack with the lock still held, then free the lock', async () => {
    const locks = fakeLocks();
    const peer = recordingPeer(locks, { ack: 'deferred' });
    const gate = await acquireM2BetaGate({ locks, peer });
    let done = false;
    const p = gate.release().then(() => { done = true; });
    expect(gate.token.isHeld()).toBe(false);
    await flush();
    expect(peer.events[1]).toEqual(['withdrawHeld', 'M2_LOCK_WITHDRAWN', PRODUCT_LOCK, peer.reports[0].epoch, true]);
    // No ack yet: the lock is still held and release has not completed.
    await flush(20);
    expect(locks.held.has(PRODUCT_LOCK)).toBe(true);
    expect(done).toBe(false);
    peer.pendingAck();
    await p;
    expect(locks.held.has(PRODUCT_LOCK)).toBe(false);
    expect(peer.events.map((e) => e[0])).toEqual(['reportHeld', 'withdrawHeld']); // no terminate on a valid ack
    expect(locks.log).toEqual([`granted:${PRODUCT_LOCK}`, `freed:${PRODUCT_LOCK}`]);
  });

  test('beforeFree (the caller stopping its worker) runs after the ack and before the lock is freed', async () => {
    const locks = fakeLocks();
    const peer = recordingPeer(locks);
    const gate = await acquireM2BetaGate({ locks, peer });
    const order = [];
    await gate.release({ beforeFree: async () => { order.push(['beforeFree', locks.held.has(PRODUCT_LOCK)]); } });
    order.push(['after', locks.held.has(PRODUCT_LOCK)]);
    expect(peer.events.map((e) => e[0])).toEqual(['reportHeld', 'withdrawHeld']);
    expect(order).toEqual([['beforeFree', true], ['after', false]]);
  });

  test('a throwing beforeFree still frees the lock', async () => {
    const locks = fakeLocks();
    const gate = await acquireM2BetaGate({ locks });
    await gate.release({ beforeFree: () => { throw new Error('stop failed'); } });
    expect(locks.held.has(PRODUCT_LOCK)).toBe(false);
  });

  test.each(['reject', 'wrong-epoch', 'wrong-type', 'wrong-nonce', 'no-nonce', 'throwing-getter'])('ack %s: the peer is terminated before the lock is freed', async (ack) => {
    const locks = fakeLocks();
    const peer = recordingPeer(locks, { ack });
    const gate = await acquireM2BetaGate({ locks, peer });
    await gate.release();
    expect(peer.events.map((e) => e[0])).toEqual(['reportHeld', 'withdrawHeld', 'terminate']);
    expect(peer.events[2]).toEqual(['terminate', true]); // the lock was still held at termination
    expect(locks.held.has(PRODUCT_LOCK)).toBe(false);
  });

  test('ack never arrives: the timeout terminates the peer, then the lock is freed', async () => {
    const locks = fakeLocks();
    const peer = recordingPeer(locks, { ack: 'never' });
    const t = manualTimers();
    const gate = await acquireM2BetaGate({ locks, peer, setTimer: t.setTimer, clearTimer: t.clearTimer, withdrawAckTimeoutMs: 1234 });
    const p = gate.release();
    await flush(20);
    expect(locks.held.has(PRODUCT_LOCK)).toBe(true);
    expect(t.timers.filter((x) => !x.cleared).map((x) => x.ms)).toEqual([1234]); // the report timer was cleared
    t.fireAll();
    await p;
    expect(peer.events.map((e) => e[0])).toEqual(['reportHeld', 'withdrawHeld', 'terminate']);
    expect(peer.events[2]).toEqual(['terminate', true]);
    expect(locks.held.has(PRODUCT_LOCK)).toBe(false);
  });

  test.each(['throw', 'reject'])('held report %s: the peer is terminated, the lock freed, entry refused', async (report) => {
    const locks = fakeLocks();
    const peer = recordingPeer(locks, { report });
    const gate = await acquireM2BetaGate({ locks, peer });
    expectRefused(gate, M2_GATE_REFUSALS.REPORT_FAILED);
    expect(peer.events.map((e) => e[0])).toEqual(['reportHeld', 'terminate']);
    expect(peer.events[1]).toEqual(['terminate', true]);
    expect(locks.held.has(PRODUCT_LOCK)).toBe(false);
  });

  test('every acquisition has its own identity: an earlier acquisition\'s ack never satisfies a later one', async () => {
    const locks = fakeLocks();
    let replay = null;
    const events = [];
    const peer = {
      reportHeld(r) { events.push(['held', r.epoch, r.nonce]); },
      withdrawHeld(r) {
        events.push(['withdraw', r.epoch, r.nonce]);
        if (replay === null) replay = { type: M2_HELD_REPORT_TYPES.WITHDRAWN_ACK, lockName: r.lockName, epoch: r.epoch, nonce: r.nonce };
        return replay; // the second release gets the first acquisition's ack
      },
      terminate() { events.push(['terminate', locks.held.has(PRODUCT_LOCK)]); },
    };
    const first = await acquireM2BetaGate({ locks, peer });
    await first.release();
    expect(events.map((e) => e[0])).toEqual(['held', 'withdraw']);
    const second = await acquireM2BetaGate({ locks, peer });
    expect(events[2][1]).not.toBe(events[0][1]);
    expect(events[2][2]).not.toBe(events[0][2]);
    await second.release();
    expect(events.map((e) => e[0])).toEqual(['held', 'withdraw', 'held', 'withdraw', 'terminate']);
    expect(events[4]).toEqual(['terminate', true]);
    expect(locks.held.has(PRODUCT_LOCK)).toBe(false);
  });

  test('a held report that never settles times out: the peer is terminated, the lock freed, entry refused', async () => {
    const locks = fakeLocks();
    const peer = recordingPeer(locks, { report: 'never' });
    const t = manualTimers();
    const p = acquireM2BetaGate({ locks, peer, setTimer: t.setTimer, clearTimer: t.clearTimer, reportTimeoutMs: 777 });
    await flush(20);
    expect(locks.held.has(PRODUCT_LOCK)).toBe(true);
    expect(t.timers.map((x) => x.ms)).toEqual([777]);
    t.fireAll();
    const gate = await p;
    expectRefused(gate, M2_GATE_REFUSALS.REPORT_FAILED);
    expect(peer.events.map((e) => e[0])).toEqual(['reportHeld', 'terminate']);
    expect(peer.events[1]).toEqual(['terminate', true]);
    expect(locks.held.has(PRODUCT_LOCK)).toBe(false);
  });

  test('a delivered held report clears its timer', async () => {
    const locks = fakeLocks();
    const t = manualTimers();
    const gate = await acquireM2BetaGate({ locks, peer: recordingPeer(locks), setTimer: t.setTimer, clearTimer: t.clearTimer });
    expect(gate.entered).toBe(true);
    expect(t.timers.map((x) => x.cleared)).toEqual([true]);
    await gate.release();
  });

  test('release is idempotent: a second call returns the same promise and only the first beforeFree runs', async () => {
    const locks = fakeLocks();
    const gate = await acquireM2BetaGate({ locks, peer: recordingPeer(locks) });
    const calls = [];
    const p1 = gate.release({ beforeFree: () => { calls.push('first'); } });
    const p2 = gate.release({ beforeFree: () => { calls.push('second'); } });
    expect(p2).toBe(p1);
    await p1;
    expect(calls).toEqual(['first']);
  });

  test('no report is ever sent on a refusal path', async () => {
    const locks = fakeLocks();
    locks.held.set(PRODUCT_LOCK, { free: () => {} });
    const cases = [
      { locks: undefined }, { locks: { request() { throw new Error('x'); } } }, { locks }, { locks, dbName: 'styx-ledger' },
      { locks: { request(name, options, cb) { cb({ name, mode: 'exclusive' }); throw new Error('after callback'); } } },
    ];
    for (const c of cases) {
      const peer = recordingPeer(locks);
      const gate = await acquireM2BetaGate({ ...c, peer });
      expect(gate.entered).toBe(false);
      expect(peer.events).toEqual([]);
    }
  });

  test('without a peer nothing is reported and release frees the lock directly', async () => {
    const locks = fakeLocks();
    const gate = await acquireM2BetaGate({ locks });
    await gate.release();
    expect(locks.log).toEqual([`granted:${PRODUCT_LOCK}`, `freed:${PRODUCT_LOCK}`]);
  });
});

// ---------------------------------------------------------------------------------------------
// R-UX reset-gate input: always token.isHeld().
// ---------------------------------------------------------------------------------------------

describe('R-UX reset gate input is token.isHeld() (act §3 "R-UX reset gate")', () => {
  const wasmUrl = new URL('../../../vendor/styx-kdf-wasm/pkg/styx_kdf_wasm_bg.wasm', import.meta.url);
  beforeAll(async () => { await initKdf({ module_or_path: readFileSync(wasmUrl) }); });
  const deriveKek = async (pw, { salt, mKib, t, p, outLen }) => argon2id_derive(pw, salt, mKib, t, p, outLen);
  const PW = 'beta-gate-pass-1';

  async function unlockedVault() {
    const db = new FakeVaultDb();
    const v = createVault({ db, deriveKek, randomBytes: seededBytes(11), todayIso: () => '2026-10-10' });
    await v.createVault(PW, { profile: 'mobile-low-memory' });
    return v;
  }

  test('recoveryLockHeld is exactly token.isHeld(), a boolean', () => {
    expect(recoveryLockHeld({ isHeld: () => true })).toBe(true);
    expect(recoveryLockHeld({ isHeld: () => false })).toBe(false);
    for (const bad of [undefined, null, true, 1, 'true', {}, { isHeld: true }, { isHeld: () => 1 },
      { isHeld: () => 'true' }, { isHeld: () => { throw new Error('x'); } }]) {
      expect(recoveryLockHeld(bad)).toBe(false);
    }
  });

  test('held token → begin accepted; released token → LOCKED_ELSEWHERE; the token object itself is refused', async () => {
    const locks = fakeLocks();
    const gate = await acquireM2BetaGate({ locks });
    const v = await unlockedVault();

    const begun = await v.beginRecoveryReset({ restoreResult: 'MANIFEST_INVALID', lockHeld: recoveryLockHeld(gate.token) });
    expect(begun.confirmation).toBeDefined();
    await v.cancelRecoveryReset();

    await expect(v.beginRecoveryReset({ restoreResult: 'MANIFEST_INVALID', lockHeld: gate.token }))
      .rejects.toThrow(TypeError);

    await gate.release();
    const refused = await v.beginRecoveryReset({ restoreResult: 'MANIFEST_INVALID', lockHeld: recoveryLockHeld(gate.token) });
    expect(refused.reject).toBe('LOCKED_ELSEWHERE');
    expect(refused.agreement).toEqual({
      disposition: 'LOCK_RETRY', authorityIdentity: 'NONE', markerState: 'UNCHANGED', firstFailingPhase: 'LOCK',
    });
    expect(refused.confirmation).toBeUndefined();

    const rewrap = await v.recoveryChangePassword({
      restoreResult: 'RESTORED_ACTIVE', lockHeld: recoveryLockHeld(gate.token),
      currentPassword: PW, newPassword: 'beta-gate-pass-2', profile: 'mobile-low-memory',
    });
    expect(rewrap.reject).toBe('LOCKED_ELSEWHERE');
  });

  test('a refused gate exposes a token whose input is false, so confirm is refused too', async () => {
    const gate = await acquireM2BetaGate({ locks: undefined });
    const v = await unlockedVault();
    const done = await v.confirmRecoveryReset({
      restoreResult: 'MANIFEST_INVALID', lockHeld: recoveryLockHeld(gate.token),
      confirmed: true, disclosure: true, confirmation: {},
    });
    expect(done.reject).toBe('LOCKED_ELSEWHERE');
  });
});

// ---------------------------------------------------------------------------------------------
// Static check: no literal `lockHeld: true` in any non-test file.
// ---------------------------------------------------------------------------------------------

describe('static check: no literal lockHeld true outside tests', () => {
  const root = fileURLToPath(new URL('../../../', import.meta.url)); // styx-js/
  const SKIP_DIRS = new Set(['node_modules', 'test', 'tests', 'e2e', 'dist', 'coverage', 'vendor', '.git', 'spikes']);
  // Key, colon and value may be separated by any whitespace (newlines included) and comments.
  const GAP = String.raw`(?:\s|\/\*[\s\S]*?\*\/|\/\/[^\n]*(?:\n|$))*`;
  const LITERAL_TRUE_SRC = String.raw`["'\x60]?\blockHeld["'\x60]?` + GAP + ':' + GAP + String.raw`(?:true|!0|!!1|!!\s*1)\b`;
  const LITERAL_TRUE = new RegExp(LITERAL_TRUE_SRC);
  /** Every hit in a whole source text, reported as the full line where the key starts. */
  const hitsIn = (text) => {
    const out = [];
    for (const m of text.matchAll(new RegExp(LITERAL_TRUE_SRC, 'g'))) {
      const start = text.lastIndexOf('\n', m.index) + 1;
      const end = text.indexOf('\n', m.index);
      out.push(text.slice(start, end === -1 ? undefined : end));
    }
    return out;
  };

  // The one pre-existing occurrence at base 4a587bc. It is the L-MARK marker input inside the
  // legacy re-establishment module, built only after that module's own lock gate (`lockHeldOf`),
  // not an R-UX gate input. Act §4 forbids any change to that module and I-IDB closure item 5
  // keeps it unreachable from production, so it is pinned here instead of edited: a second
  // occurrence, a move, or any other file fails the check.
  const PINNED = new Map([[
    ['apps', 'chat', 'src', 'm2', 'session-reestablishment', 'session-reestablishment.js'].join(sep),
    ['  const input = { marker: marker.bytes, event, lockHeld: true, restoreResult: evidence.restoreResult, ...extra };'],
  ]]);

  function walk(dir, out) {
    for (const entry of readdirSync(dir)) {
      if (SKIP_DIRS.has(entry)) continue;
      const full = join(dir, entry);
      const st = statSync(full);
      if (st.isDirectory()) walk(full, out);
      else if (/\.(?:m?js|jsx|cjs|ts|tsx)$/.test(entry) && !/\.test\.|\.spec\./.test(entry)) out.push(full);
    }
    return out;
  }

  const scan = () => {
    const hits = new Map();
    for (const dir of ['src', join('apps', 'chat', 'src')]) {
      for (const file of walk(join(root, dir), [])) {
        const lines = hitsIn(readFileSync(file, 'utf8'));
        if (lines.length) hits.set(relative(root, file), lines);
      }
    }
    return hits;
  };

  test('the scanner sees every spelling of the literal', () => {
    for (const s of ['lockHeld: true', "'lockHeld': true", '"lockHeld":true', 'lockHeld:!0', 'lockHeld :  true']) {
      expect(LITERAL_TRUE.test(s)).toBe(true);
    }
    for (const s of ['lockHeld: token.isHeld()', 'lockHeld: recoveryLockHeld(gate.token)', 'lockHeld: false', 'lockHeldOf(input)', 'lockHeld: trueish']) {
      expect(LITERAL_TRUE.test(s)).toBe(false);
    }
  });

  test('the whole-text scanner sees multiline and comment-separated literals', () => {
    for (const text of [
      'const input = { lockHeld:\n  true };',
      'const input = {\n  lockHeld\n  :\n  true,\n};',
      'f({ lockHeld: /* held */ true });',
      'f({ lockHeld: // held\n true });',
      'f({ "lockHeld"\t:\r\n!0 })',
    ]) {
      expect(hitsIn(text)).toHaveLength(1);
    }
    expect(hitsIn('a({ lockHeld: true }); b({ lockHeld: !0 });')).toHaveLength(2);
    for (const text of ['f({ lockHeld: token.isHeld() })', 'f({ lockHeld:\n  recoveryLockHeld(t) })', 'f({ lockHeld: /* true */ false })']) {
      expect(hitsIn(text)).toEqual([]);
    }
  });

  test('only the pinned pre-existing occurrence exists', () => {
    expect(scan()).toEqual(PINNED);
  });
});
