// vault-worker-supervisor.js — lifecycle owner of the vault worker PROCESS
// (Blocco 3, PR-3). Owns the Worker factory, respawns after crash/timeout
// with bounded exponential backoff, isolates stale generations, and offers
// the strong UNLOCK cancellation: Argon2id in WASM is synchronous, so the
// only real cancel is terminate → reject pendings → fresh worker → new
// verified INIT (spec §7.2 / mandate §15).
//
// The supervisor stores ONLY the non-sensitive INIT configuration (the wasm
// deployment path). It never sees or retains passwords or request payloads.

import { createVaultWorkerClient } from './vault-worker-client.js';
import { VaultWorkerError, VaultWorkerErrorCodes as Codes } from './vault-worker-errors.js';

export const SUPERVISOR_STATES = Object.freeze({
  STOPPED: 'STOPPED',
  STARTING: 'STARTING',
  RUNNING: 'RUNNING',
  BACKOFF: 'BACKOFF',
  FAILED: 'FAILED', // max respawn attempts exhausted
});

export const DEFAULT_BACKOFF = Object.freeze({
  baseMs: 100, // 100 → 200 → 400 → 800 → 1600
  maxDelayMs: 1600,
  maxAttempts: 5,
});

const wrongState = (message, details) => new VaultWorkerError(Codes.WRONG_STATE, message, details);

/**
 * @param {object} deps
 * @param {() => Worker} deps.createWorker owned factory (e.g. () => new
 *   Worker(url, { type: 'module' })); the page never supplies it through the
 *   protocol.
 * @param {string} deps.wasmUrl the non-sensitive INIT configuration
 * @param {object} [deps.backoff] {baseMs, maxDelayMs, maxAttempts}
 * @param {number} [deps.requestTimeoutMs]
 * @param {Function} [deps.setTimeoutImpl] injectable scheduler (tests only)
 * @param {Function} [deps.clearTimeoutImpl]
 * @param {() => number} [deps.jitter] injectable 0..1 source for backoff
 *   jitter (tests only; production defaults are module-internal)
 * @param {(info: {generation: number, error: object}) => void} [deps.onRespawn]
 */
export function createVaultWorkerSupervisor({
  createWorker,
  wasmUrl,
  backoff = DEFAULT_BACKOFF,
  requestTimeoutMs,
  setTimeoutImpl = (fn, ms) => setTimeout(fn, ms),
  clearTimeoutImpl = (t) => clearTimeout(t),
  jitter = () => 0,
  onRespawn,
} = {}) {
  if (typeof createWorker !== 'function') throw new TypeError('createWorker factory is required');
  if (typeof wasmUrl !== 'string' || wasmUrl.length === 0) throw new TypeError('wasmUrl is required');

  let state = SUPERVISOR_STATES.STOPPED;
  let generation = 0;
  let client = null;
  let attempts = 0;
  let backoffTimer = null;
  let spawning = null; // in-flight spawn promise: never two workers at once

  function backoffDelay() {
    const raw = backoff.baseMs * 2 ** Math.max(0, attempts - 1);
    const capped = Math.min(raw, backoff.maxDelayMs);
    return Math.round(capped + capped * 0.1 * jitter());
  }

  async function spawn(gen) {
    const worker = createWorker();
    const c = createVaultWorkerClient(worker, {
      defaultTimeoutMs: requestTimeoutMs,
      onFatal: (error) => handleFatal(gen, error),
    });
    client = c;
    const summary = await c.request('INIT', { wasmUrl });
    if (gen !== generation) {
      // A stale spawn lost a race with stop()/cancelUnlock(): discard it.
      c.terminate('stale-generation');
      throw wrongState('stale worker generation', { reason: 'stale-generation' });
    }
    attempts = 0; // a fully verified INIT resets the backoff ladder
    state = SUPERVISOR_STATES.RUNNING;
    return summary;
  }

  function scheduleRespawn(error) {
    attempts += 1;
    if (attempts > backoff.maxAttempts) {
      state = SUPERVISOR_STATES.FAILED;
      return;
    }
    state = SUPERVISOR_STATES.BACKOFF;
    const delay = backoffDelay();
    if (typeof onRespawn === 'function') {
      onRespawn({ generation, error: { code: error?.code ?? Codes.CRASHED, attempt: attempts, delayMs: delay } });
    }
    backoffTimer = setTimeoutImpl(() => {
      backoffTimer = null;
      if (state !== SUPERVISOR_STATES.BACKOFF) return; // stopped meanwhile
      startGeneration();
    }, delay);
  }

  function handleFatal(gen, error) {
    if (gen !== generation) return; // events from old generations are ignored
    if (state === SUPERVISOR_STATES.STOPPED || state === SUPERVISOR_STATES.FAILED) return;
    client = null;
    scheduleRespawn(error);
  }

  function startGeneration() {
    generation += 1;
    const gen = generation;
    state = SUPERVISOR_STATES.STARTING;
    spawning = spawn(gen)
      .catch((error) => {
        if (gen !== generation) return; // superseded
        if (client !== null) { client.terminate('init-failed'); client = null; }
        if (state === SUPERVISOR_STATES.STOPPED || state === SUPERVISOR_STATES.FAILED) return;
        scheduleRespawn(error);
      })
      .finally(() => { if (gen === generation) spawning = null; });
  }

  /** Start the (single) worker. A second start while active is refused. */
  async function start() {
    if (state !== SUPERVISOR_STATES.STOPPED && state !== SUPERVISOR_STATES.FAILED) {
      throw wrongState('supervisor already started', { reason: 'already-started' });
    }
    attempts = 0;
    startGeneration();
    await spawning;
    if (state !== SUPERVISOR_STATES.RUNNING) {
      throw wrongState('worker did not reach RUNNING', { reason: 'start-failed' });
    }
  }

  /** Stop everything: cancel timers, invalidate the generation, terminate. */
  function stop() {
    generation += 1; // everything in flight becomes stale
    if (backoffTimer !== null) { clearTimeoutImpl(backoffTimer); backoffTimer = null; }
    if (client !== null) { client.terminate('supervisor-stopped'); client = null; }
    state = SUPERVISOR_STATES.STOPPED;
  }

  /** Delegate one request to the current worker. */
  function request(type, payload, options) {
    if (state !== SUPERVISOR_STATES.RUNNING || client === null) {
      return Promise.reject(wrongState('no running worker', { reason: `state:${state}` }));
    }
    return client.request(type, payload, options);
  }

  /**
   * Strong cancellation of a synchronous KDF run (mandate §15): terminate the
   * worker so every pending — the UNLOCK included — rejects with
   * WORKER_TERMINATED and details.reason 'unlock-cancelled', then respawn
   * IMMEDIATELY (a user cancel is not a crash: no backoff, no attempt spent).
   */
  async function cancelUnlock() {
    if (client === null) {
      throw wrongState('no worker to cancel', { reason: `state:${state}` });
    }
    if (backoffTimer !== null) { clearTimeoutImpl(backoffTimer); backoffTimer = null; }
    client.terminate('unlock-cancelled');
    client = null;
    attempts = 0;
    startGeneration();
    await spawning;
    if (state !== SUPERVISOR_STATES.RUNNING) {
      throw wrongState('worker did not come back after the cancellation', { reason: 'respawn-failed' });
    }
  }

  return Object.freeze({
    start,
    stop,
    request,
    cancelUnlock,
    getState: () => state,
    getGeneration: () => generation,
    getAttempts: () => attempts,
  });
}
