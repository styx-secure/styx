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

/**
 * How long a worker must stay RUNNING without any fatal before the failure
 * streak resets (review W7). A verified INIT alone must NOT reset it: a
 * worker that reaches READY and then crashes immediately would otherwise
 * respawn forever at the first backoff step, never reaching FAILED.
 */
export const STABILITY_RESET_MS = 30000;

const wrongState = (message, details) => new VaultWorkerError(Codes.WRONG_STATE, message, details);

/**
 * @param {object} deps
 * @param {() => Worker} deps.createWorker owned factory (e.g. () => new
 *   Worker(url, { type: 'module' })); the page never supplies it through the
 *   protocol.
 * @param {string} deps.wasmUrl the non-sensitive INIT configuration
 * @param {object} [deps.backoff] {baseMs, maxDelayMs, maxAttempts}
 * @param {number} [deps.requestTimeoutMs]
 * @param {number} [deps.stabilityResetMs] continuous-RUNNING window after
 *   which the failure streak resets (review W7; tests only)
 * @param {Function} [deps.setTimeoutImpl] injectable scheduler (tests only)
 * @param {Function} [deps.clearTimeoutImpl]
 * @param {Function} [deps.clientSetTimeoutImpl] injectable scheduler for the
 *   INNER client request timeouts (tests only — lets a test drive a fatal
 *   WORKER_TIMEOUT deterministically)
 * @param {Function} [deps.clientClearTimeoutImpl]
 * @param {() => number} [deps.jitter] injectable 0..1 source for backoff
 *   jitter (tests only; production defaults are module-internal)
 * @param {(info: {generation: number, error: object}) => void} [deps.onRespawn]
 */
export function createVaultWorkerSupervisor({
  createWorker,
  wasmUrl,
  backoff = DEFAULT_BACKOFF,
  requestTimeoutMs,
  stabilityResetMs = STABILITY_RESET_MS,
  setTimeoutImpl = (fn, ms) => setTimeout(fn, ms),
  clearTimeoutImpl = (t) => clearTimeout(t),
  clientSetTimeoutImpl,
  clientClearTimeoutImpl,
  jitter = () => 0,
  onRespawn,
} = {}) {
  if (typeof createWorker !== 'function') throw new TypeError('createWorker factory is required');
  if (typeof wasmUrl !== 'string' || wasmUrl.length === 0) throw new TypeError('wasmUrl is required');

  let state = SUPERVISOR_STATES.STOPPED;
  let generation = 0;
  let client = null;
  // Review W7: counts consecutive FAILED GENERATIONS — a generation fails
  // whether INIT never completed OR the worker crashed/timed out after
  // READY. It is NOT reset by a verified INIT (that would let a
  // crash-after-READY loop respawn forever); it resets only after the
  // stability window below, or on a deliberate start() from STOPPED/FAILED.
  let failureStreak = 0;
  let backoffTimer = null;
  let stabilityTimer = null; // review W7: armed on INIT, cleared on any fatal
  let spawning = null; // in-flight spawn promise: never two workers at once
  let respawnScheduledFor = 0; // review W1: one respawn per generation

  function backoffDelay() {
    const raw = backoff.baseMs * 2 ** Math.max(0, failureStreak - 1);
    const capped = Math.min(raw, backoff.maxDelayMs);
    return Math.round(capped + capped * 0.1 * jitter());
  }

  function clearStabilityTimer() {
    if (stabilityTimer !== null) { clearTimeoutImpl(stabilityTimer); stabilityTimer = null; }
  }

  function armStabilityTimer(gen) {
    clearStabilityTimer();
    stabilityTimer = setTimeoutImpl(() => {
      stabilityTimer = null;
      // Reset only if THIS generation is still the current one, still
      // RUNNING, and no fatal happened meanwhile (a fatal clears the timer).
      if (gen !== generation || state !== SUPERVISOR_STATES.RUNNING) return;
      failureStreak = 0;
    }, stabilityResetMs);
  }

  async function spawn(gen) {
    const worker = createWorker();
    const c = createVaultWorkerClient(worker, {
      defaultTimeoutMs: requestTimeoutMs,
      onFatal: (error) => handleFatal(gen, error),
      ...(clientSetTimeoutImpl !== undefined ? { setTimeoutImpl: clientSetTimeoutImpl } : {}),
      ...(clientClearTimeoutImpl !== undefined ? { clearTimeoutImpl: clientClearTimeoutImpl } : {}),
    });
    client = c;
    const summary = await c.request('INIT', { wasmUrl });
    if (gen !== generation) {
      // A stale spawn lost a race with stop()/cancelUnlock(): discard it.
      c.terminate('stale-generation');
      throw wrongState('stale worker generation', { reason: 'stale-generation' });
    }
    state = SUPERVISOR_STATES.RUNNING;
    // The verified INIT does NOT reset the streak (review W7): only a
    // continuous stability window does.
    armStabilityTimer(gen);
    return summary;
  }

  function scheduleRespawn(error) {
    // A fatal DURING INIT reaches here twice (client onFatal + the spawn
    // rejection): exactly one respawn may be scheduled per generation, or a
    // single crash would burn two backoff attempts and arm two timers
    // (review W1).
    if (respawnScheduledFor === generation) return;
    respawnScheduledFor = generation;
    clearStabilityTimer(); // this generation was NOT stable
    failureStreak += 1;
    if (failureStreak > backoff.maxAttempts) {
      state = SUPERVISOR_STATES.FAILED;
      return;
    }
    state = SUPERVISOR_STATES.BACKOFF;
    const delay = backoffDelay();
    if (typeof onRespawn === 'function') {
      onRespawn({ generation, error: { code: error?.code ?? Codes.CRASHED, attempt: failureStreak, delayMs: delay } });
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
    failureStreak = 0; // deliberate fresh start from STOPPED/FAILED
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
    clearStabilityTimer(); // review W7: no late streak reset after stop()
    if (client !== null) { client.terminate('supervisor-stopped'); client = null; }
    state = SUPERVISOR_STATES.STOPPED;
  }

  /** Delegate one request to the current worker. */
  function request(type, payload, options) {
    // Review PR39 F4: the supervisor owns the lifecycle. Letting SHUTDOWN
    // through would close the worker underneath a supervisor still RUNNING,
    // leaving later requests to hang until their timeout.
    if (type === 'SHUTDOWN') {
      return Promise.reject(wrongState('SHUTDOWN must go through supervisor.shutdown()', { reason: 'lifecycle-owner' }));
    }
    if (state !== SUPERVISOR_STATES.RUNNING || client === null) {
      return Promise.reject(wrongState('no running worker', { reason: `state:${state}` }));
    }
    return client.request(type, payload, options);
  }

  /**
   * Graceful stop (review PR39 F4): SHUTDOWN through the client, then the
   * supervisor is STOPPED. If the worker does not answer, fall back to a hard
   * terminate — either way the caller ends with a STOPPED supervisor and no
   * pending state. Never respawns.
   */
  async function shutdown({ timeoutMs } = {}) {
    if (state === SUPERVISOR_STATES.STOPPED) return { closed: true };
    if (state !== SUPERVISOR_STATES.RUNNING || client === null) {
      stop();
      return { closed: true };
    }
    generation += 1; // late fatals from this worker are stale, not respawns
    if (backoffTimer !== null) { clearTimeoutImpl(backoffTimer); backoffTimer = null; }
    clearStabilityTimer();
    const c = client;
    client = null;
    state = SUPERVISOR_STATES.STOPPED;
    try {
      return await c.shutdown({ timeoutMs });
    } catch {
      try { c.terminate('supervisor-stopped'); } catch { /* already gone */ }
      return { closed: true };
    }
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
    clearStabilityTimer();
    client.terminate('unlock-cancelled');
    client = null;
    // A user cancel is deliberate: it neither spends nor resets the crash
    // budget (review W7) — the streak resets only through the stability window.
    startGeneration();
    await spawning;
    if (state !== SUPERVISOR_STATES.RUNNING) {
      throw wrongState('worker did not come back after the cancellation', { reason: 'respawn-failed' });
    }
  }

  return Object.freeze({
    start,
    stop,
    shutdown,
    request,
    cancelUnlock,
    getState: () => state,
    getGeneration: () => generation,
    getAttempts: () => failureStreak,
  });
}
