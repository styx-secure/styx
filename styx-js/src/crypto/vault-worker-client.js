// vault-worker-client.js — page-side correlation layer of the vault worker
// protocol (Blocco 3, PR-3). Pure module around a Worker-like object:
// monotonic request ids, a pending map holding ONLY {resolve, reject, timer,
// type} (never payloads, never passwords), strict response validation, and a
// FATAL view of everything unexpected: a timeout, a protocol violation, an
// error event or a postMessage failure means the worker is no longer
// trustworthy — reject everything, terminate, let the supervisor respawn.

import { MESSAGE_TYPES, validateResponseEnvelope, validateWireValue } from './vault-worker-protocol.js';
import { VaultWorkerError, VaultWorkerErrorCodes as Codes } from './vault-worker-errors.js';

export const DEFAULT_REQUEST_TIMEOUT_MS = 30000;
export const MAX_REQUEST_TIMEOUT_MS = 600000;
export const MAX_TRANSFER_BYTES = 32 * 1024 * 1024;

/**
 * Closed set of termination reasons (review PR39 F2). details.reason in
 * WORKER_TERMINATED may only ever carry one of these constants: free-form
 * caller text could smuggle secrets into errors and logs (plan §11).
 */
export const TERMINATE_REASONS = Object.freeze([
  'terminated',
  'unlock-cancelled',
  'supervisor-stopped',
  'stale-generation',
  'init-failed',
]);

function assertTransferList(transfer) {
  if (transfer === undefined) return [];
  if (!Array.isArray(transfer)) {
    throw new VaultWorkerError(Codes.BAD_REQUEST, 'transfer list must be an array', { reason: 'bad-transfer-list' });
  }
  const seen = new Set();
  let total = 0;
  for (const item of transfer) {
    if (typeof SharedArrayBuffer !== 'undefined' && item instanceof SharedArrayBuffer) {
      throw new VaultWorkerError(Codes.BAD_REQUEST, 'shared memory cannot be transferred', { reason: 'shared-array-buffer' });
    }
    if (!(item instanceof ArrayBuffer)) {
      throw new VaultWorkerError(Codes.BAD_REQUEST, 'only ArrayBuffers can be transferred', { reason: 'bad-transferable' });
    }
    if (seen.has(item)) {
      throw new VaultWorkerError(Codes.BAD_REQUEST, 'duplicate buffer in the transfer list', { reason: 'duplicate-transferable' });
    }
    seen.add(item);
    total += item.byteLength;
  }
  if (total > MAX_TRANSFER_BYTES) {
    throw new VaultWorkerError(Codes.BAD_REQUEST, 'transfer list exceeds the 32 MiB budget', { reason: 'over-transfer-budget' });
  }
  return transfer;
}

/**
 * @param {Worker} worker a live (dedicated, module) Worker-like object
 * @param {object} [options]
 * @param {number} [options.defaultTimeoutMs]
 * @param {(err: VaultWorkerError) => void} [options.onFatal] invoked EXACTLY
 *   once when the client dies spontaneously (timeout, crash, protocol
 *   violation, error event) — NOT on caller-initiated terminate/shutdown.
 *   The supervisor uses this to decide the respawn.
 * @param {Function} [options.setTimeoutImpl] injectable for tests
 * @param {Function} [options.clearTimeoutImpl] injectable for tests
 */
export function createVaultWorkerClient(worker, {
  defaultTimeoutMs = DEFAULT_REQUEST_TIMEOUT_MS,
  onFatal,
  setTimeoutImpl = (fn, ms) => setTimeout(fn, ms),
  clearTimeoutImpl = (t) => clearTimeout(t),
} = {}) {
  const pending = new Map(); // id → { resolve, reject, timer, type } ONLY
  let nextId = 1; // monotonic: an id is never reused, in flight or not
  let closed = false;

  function rejectAll(error) {
    // Executed at most once: the closed flag flips before any rejection runs.
    for (const [, entry] of pending) {
      if (entry.timer !== null) clearTimeoutImpl(entry.timer);
      entry.reject(error);
    }
    pending.clear();
  }

  function die(error, { deliberate = false } = {}) {
    if (closed) return;
    closed = true;
    try { worker.terminate(); } catch { /* already gone */ }
    rejectAll(error);
    if (!deliberate && typeof onFatal === 'function') onFatal(error);
  }

  function handleMessage(event) {
    if (closed) return; // late replies after a fatal cannot resolve anything
    let response;
    try {
      response = validateResponseEnvelope(event.data);
    } catch (e) {
      die(e instanceof VaultWorkerError ? e
        : new VaultWorkerError(Codes.CRASHED, 'response validation failed', { reason: 'protocol-violation' }));
      return;
    }
    const entry = pending.get(response.id);
    if (entry === undefined) {
      // Unknown OR duplicate id: a protocol violation, not a benign stray.
      die(new VaultWorkerError(Codes.CRASHED, 'response for an unknown request id', { reason: 'unknown-response-id' }));
      return;
    }
    pending.delete(response.id);
    if (entry.timer !== null) clearTimeoutImpl(entry.timer);
    if (response.ok === true) {
      entry.resolve(response.result);
    } else {
      entry.reject(new VaultWorkerError(response.error.code, 'worker reported an error', response.error.details));
    }
  }

  const onError = () => die(new VaultWorkerError(Codes.CRASHED, 'worker error event', { reason: 'error-event' }));
  const onMessageError = () => die(new VaultWorkerError(Codes.CRASHED, 'worker message deserialization failed', { reason: 'messageerror' }));

  worker.addEventListener('message', handleMessage);
  worker.addEventListener('error', onError);
  worker.addEventListener('messageerror', onMessageError);

  /**
   * Send one request. A timeout is FATAL for the whole worker (the operation
   * may have side effects in flight): this promise rejects WORKER_TIMEOUT,
   * every other pending rejects WORKER_TERMINATED, the worker is terminated
   * and the supervisor decides the respawn.
   */
  function request(type, payload = null, { timeoutMs = defaultTimeoutMs, transfer } = {}) {
    if (closed) {
      return Promise.reject(new VaultWorkerError(Codes.TERMINATED, 'client is closed', { reason: 'client-closed' }));
    }
    if (typeof type !== 'string' || !MESSAGE_TYPES.includes(type)) {
      return Promise.reject(new VaultWorkerError(Codes.BAD_REQUEST, 'unknown request type', { reason: 'unknown-type' }));
    }
    let transferList;
    try {
      transferList = assertTransferList(transfer);
      // Review PR39 F1: enforce the wire grammar BEFORE the structured clone
      // crosses the boundary — a clonable exotic (SharedArrayBuffer,
      // CryptoKey, Map…) must never reach the worker at all.
      validateWireValue(payload, {});
    } catch (e) {
      return Promise.reject(e);
    }
    const boundedTimeout = Math.min(Math.max(1, timeoutMs), MAX_REQUEST_TIMEOUT_MS);
    const id = nextId;
    nextId += 1;
    return new Promise((resolve, reject) => {
      const timer = setTimeoutImpl(() => {
        const entry = pending.get(id);
        if (entry === undefined) return;
        pending.delete(id);
        entry.reject(new VaultWorkerError(Codes.TIMEOUT, 'worker did not answer in time', { type, reason: 'timeout' }));
        die(new VaultWorkerError(Codes.TERMINATED, 'worker terminated after a timeout', { reason: 'timeout' }));
      }, boundedTimeout);
      pending.set(id, { resolve, reject, timer, type });
      try {
        worker.postMessage({ id, type, payload }, transferList);
      } catch {
        pending.delete(id);
        clearTimeoutImpl(timer);
        const err = new VaultWorkerError(Codes.CRASHED, 'postMessage failed', { type, reason: 'post-failed' });
        reject(err);
        die(err);
      }
    });
  }

  /** Graceful stop: SHUTDOWN → the worker closes itself → client closes. */
  async function shutdown({ timeoutMs } = {}) {
    const result = await request('SHUTDOWN', null, { timeoutMs });
    closed = true;
    rejectAll(new VaultWorkerError(Codes.TERMINATED, 'worker shut down', { reason: 'shutdown' }));
    try { worker.terminate(); } catch { /* already closed itself */ }
    return result;
  }

  /**
   * Hard stop (also the ONLY authorized cancellation of a synchronous
   * Argon2id run, spec §7.2 / mandate §15): terminate the process, reject
   * every pending with WORKER_TERMINATED and the given bounded reason.
   * Caller-initiated: onFatal is NOT invoked.
   */
  function terminate(reason = 'terminated') {
    // Review PR39 F2: the reason is confined to a closed set — the boundary
    // must be secret-free by contract, not by caller discipline. Anything
    // outside the set degrades to the generic reason.
    const safeReason = TERMINATE_REASONS.includes(reason) ? reason : 'terminated';
    die(
      new VaultWorkerError(Codes.TERMINATED, 'worker terminated', { reason: safeReason }),
      { deliberate: true },
    );
  }

  return Object.freeze({
    request,
    shutdown,
    terminate,
    isClosed: () => closed,
    pendingCount: () => pending.size,
  });
}
