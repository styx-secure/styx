// vault-worker-supervisor.test.js — process lifecycle of the vault worker
// (PR-3, mandate §14/§15/§20). Scripted fake Workers + injected fake
// scheduler; the real-Worker path is covered by the browser spec.

import { createVaultWorkerSupervisor, SUPERVISOR_STATES } from '../../src/crypto/vault-worker-supervisor.js';
import { VaultWorkerError, VaultWorkerErrorCodes as Codes } from '../../src/crypto/vault-worker-errors.js';

const WASM_URL = '/vendor/styx-kdf-wasm/pkg/styx_kdf_wasm_bg.wasm';

class FakeWorker {
  constructor(behavior) {
    this.behavior = behavior;
    this.listeners = { message: [], error: [], messageerror: [] };
    this.terminated = 0;
  }

  addEventListener(type, fn) { this.listeners[type].push(fn); }

  emit(type, event) { for (const fn of [...this.listeners[type]]) fn(event); }

  postMessage(message) {
    if (message.type === 'INIT') {
      if (this.behavior === 'init-crash') {
        // fatal DURING INIT: the error event kills the client AND makes the
        // in-flight INIT request reject — the review-W1 double path
        queueMicrotask(() => this.emit('error', {}));
      } else if (this.behavior === 'init-ok') {
        queueMicrotask(() => this.emit('message', {
          data: { id: message.id, ok: true, result: { protocolVersion: 1, workerState: 'READY', wasmBytes: 42082, digestVerified: true, katVerified: true } },
        }));
      } else if (this.behavior === 'init-fail') {
        queueMicrotask(() => this.emit('message', {
          data: { id: message.id, ok: false, error: { code: 'BAD_REQUEST', details: { phase: 'init', reason: 'digest-mismatch' } } },
        }));
      } // 'silent': never answers
    } else if (message.type === 'STATUS') {
      queueMicrotask(() => this.emit('message', {
        data: { id: message.id, ok: true, result: { workerState: 'READY' } },
      }));
    } // UNLOCK & co.: never answered (long-running)
  }

  terminate() { this.terminated += 1; }
}

function makeFakeTimers() {
  const timers = new Map();
  const delays = [];
  let next = 1;
  return {
    delays,
    setTimeoutImpl: (fn, ms) => { const id = next; next += 1; timers.set(id, fn); delays.push(ms); return id; },
    clearTimeoutImpl: (id) => { timers.delete(id); },
    fireNext: async () => {
      const [id, fn] = [...timers.entries()][0] ?? [];
      if (id === undefined) throw new Error('no timer armed');
      timers.delete(id);
      fn();
      await Promise.resolve(); // let microtask replies land
      await Promise.resolve();
    },
    armed: () => timers.size,
  };
}

function makeSupervisor(behaviors, extra = {}) {
  const workers = [];
  const timers = makeFakeTimers();
  const respawns = [];
  const supervisor = createVaultWorkerSupervisor({
    createWorker: () => {
      const behavior = behaviors[Math.min(workers.length, behaviors.length - 1)];
      const w = new FakeWorker(behavior);
      workers.push(w);
      return w;
    },
    wasmUrl: WASM_URL,
    setTimeoutImpl: timers.setTimeoutImpl,
    clearTimeoutImpl: timers.clearTimeoutImpl,
    jitter: () => 0,
    onRespawn: (info) => respawns.push(info),
    ...extra,
  });
  return { supervisor, workers, timers, respawns };
}

const codeOf = async (promise) => {
  try { await promise; return 'RESOLVED'; } catch (e) {
    expect(e).toBeInstanceOf(VaultWorkerError);
    return e;
  }
};

describe('start / stop / delegation', () => {
  test('start spawns ONE worker, INITs it and reaches RUNNING; double start refused', async () => {
    const { supervisor, workers } = makeSupervisor(['init-ok']);
    await supervisor.start();
    expect(supervisor.getState()).toBe(SUPERVISOR_STATES.RUNNING);
    expect(supervisor.getGeneration()).toBe(1);
    expect(supervisor.getAttempts()).toBe(0);
    expect(workers.length).toBe(1);
    const err = await codeOf(supervisor.start());
    expect(err.code).toBe(Codes.WRONG_STATE);
    expect(err.details.reason).toBe('already-started');
    expect(workers.length).toBe(1); // never two workers
    const status = await supervisor.request('STATUS');
    expect(status.workerState).toBe('READY');
  });

  test('request while not running rejects VAULT_WRONG_STATE', async () => {
    const { supervisor } = makeSupervisor(['init-ok']);
    const err = await codeOf(supervisor.request('STATUS'));
    expect(err.code).toBe(Codes.WRONG_STATE);
  });

  test('stop cancels timers, terminates the worker and invalidates the generation', async () => {
    const { supervisor, workers, timers } = makeSupervisor(['init-ok']);
    await supervisor.start();
    workers[0].emit('error', {}); // fatal → backoff armed
    expect(timers.armed()).toBe(1);
    supervisor.stop();
    expect(timers.armed()).toBe(0);
    expect(supervisor.getState()).toBe(SUPERVISOR_STATES.STOPPED);
    expect(workers[0].terminated).toBeGreaterThan(0);
    // nothing respawns after stop
    expect(workers.length).toBe(1);
  });
});

describe('respawn and backoff (mandate §14)', () => {
  test('a crash after READY respawns with backoff; a verified INIT resets the ladder', async () => {
    const { supervisor, workers, timers } = makeSupervisor(['init-ok', 'init-ok']);
    await supervisor.start();
    workers[0].emit('error', {});
    expect(supervisor.getState()).toBe(SUPERVISOR_STATES.BACKOFF);
    expect(timers.delays).toEqual([100]);
    await timers.fireNext();
    expect(workers.length).toBe(2);
    expect(supervisor.getState()).toBe(SUPERVISOR_STATES.RUNNING);
    expect(supervisor.getGeneration()).toBe(2);
    expect(supervisor.getAttempts()).toBe(0); // reset after the verified INIT
  });

  test('the ladder is 100/200/400/800/1600 and stops FAILED after 5 attempts', async () => {
    const { supervisor, workers, timers, respawns } = makeSupervisor(['init-fail']);
    await codeOf(supervisor.start()); // first spawn fails immediately
    while (timers.armed() > 0) await timers.fireNext(); // eslint-disable-line no-await-in-loop
    expect(timers.delays).toEqual([100, 200, 400, 800, 1600]);
    expect(supervisor.getState()).toBe(SUPERVISOR_STATES.FAILED);
    expect(workers.length).toBe(6); // 1 initial + 5 retries
    expect(respawns.map((r) => r.error.attempt)).toEqual([1, 2, 3, 4, 5]);
  });

  test('a fatal DURING INIT schedules exactly ONE respawn (review W1)', async () => {
    const { supervisor, workers, timers, respawns } = makeSupervisor(['init-crash', 'init-ok']);
    await codeOf(supervisor.start());
    // one crash → one attempt, one timer, one onRespawn — never two
    expect(supervisor.getAttempts()).toBe(1);
    expect(timers.armed()).toBe(1);
    expect(timers.delays).toEqual([100]);
    expect(respawns.length).toBe(1);
    await timers.fireNext();
    expect(supervisor.getState()).toBe(SUPERVISOR_STATES.RUNNING);
    expect(supervisor.getAttempts()).toBe(0);
    expect(workers.length).toBe(2);
  });

  test('the full ladder holds when EVERY init crashes fatally (review W1)', async () => {
    const { supervisor, workers, timers } = makeSupervisor(['init-crash']);
    await codeOf(supervisor.start());
    while (timers.armed() > 0) await timers.fireNext(); // eslint-disable-line no-await-in-loop
    expect(timers.delays).toEqual([100, 200, 400, 800, 1600]); // 5 attempts, not 3
    expect(supervisor.getState()).toBe(SUPERVISOR_STATES.FAILED);
    expect(workers.length).toBe(6);
  });

  test('stop during an init-crash backoff leaves no armed timer (review W1)', async () => {
    const { supervisor, timers } = makeSupervisor(['init-crash']);
    await codeOf(supervisor.start());
    expect(timers.armed()).toBe(1);
    supervisor.stop();
    expect(timers.armed()).toBe(0);
    expect(supervisor.getState()).toBe(SUPERVISOR_STATES.STOPPED);
  });

  test('jitter is injectable and bounded to +10%', async () => {
    const { timers } = { timers: null };
    const s = makeSupervisor(['init-fail'], { jitter: () => 1 });
    await codeOf(s.supervisor.start());
    expect(s.timers.delays[0]).toBe(110); // 100 + 100*0.1*1
  });

  test('events from an old generation are ignored', async () => {
    const { supervisor, workers, timers } = makeSupervisor(['init-ok', 'init-ok']);
    await supervisor.start();
    workers[0].emit('error', {});
    await timers.fireNext(); // gen 2 running
    const attemptsBefore = supervisor.getAttempts();
    workers[0].emit('error', {}); // stale: its client is already closed
    workers[0].emit('message', { data: { id: 99, ok: true, result: 1 } });
    expect(supervisor.getState()).toBe(SUPERVISOR_STATES.RUNNING);
    expect(supervisor.getAttempts()).toBe(attemptsBefore);
    expect(workers.length).toBe(2);
  });
});

describe('cancelUnlock (mandate §15, unit level)', () => {
  test('terminates, rejects the pending UNLOCK with unlock-cancelled, respawns immediately without backoff', async () => {
    const { supervisor, workers, timers } = makeSupervisor(['init-ok', 'init-ok']);
    await supervisor.start();
    const unlock = supervisor.request('UNLOCK', { profile: 'mobile-balanced' });
    const other = supervisor.request('LIST');
    const delaysBefore = timers.delays.length;
    await supervisor.cancelUnlock();
    const unlockErr = await codeOf(unlock);
    expect(unlockErr.code).toBe(Codes.TERMINATED);
    expect(unlockErr.details.reason).toBe('unlock-cancelled');
    const otherErr = await codeOf(other);
    expect(otherErr.code).toBe(Codes.TERMINATED);
    expect(otherErr.details.reason).toBe('unlock-cancelled');
    expect(workers[0].terminated).toBeGreaterThan(0); // old worker definitively gone
    expect(workers.length).toBe(2); // fresh worker
    expect(supervisor.getState()).toBe(SUPERVISOR_STATES.RUNNING);
    expect(supervisor.getGeneration()).toBe(2);
    expect(supervisor.getAttempts()).toBe(0);
    expect(timers.delays.length).toBe(delaysBefore); // NO backoff timer used
    // the new worker answers
    const status = await supervisor.request('STATUS');
    expect(status.workerState).toBe('READY');
  });

  test('cancelUnlock without a worker is VAULT_WRONG_STATE', async () => {
    const { supervisor } = makeSupervisor(['init-ok']);
    const err = await codeOf(supervisor.cancelUnlock());
    expect(err.code).toBe(Codes.WRONG_STATE);
  });
});
