// writer-lock.js — a minimal single-writer guard across tabs of the same origin.
//
// Two tabs both load the MLS state and both persist after every ratchet step, so the
// second writer silently clobbers the first with a stale generation and corrupts the
// session (last-writer-wins, no merge). This holds an exclusive Web Lock for the whole
// session lifetime: the first tab is the writer, a second tab is told it cannot be.
//
// The lock auto-releases when the tab closes, so there is no stale-lock problem. If the
// browser lacks Web Locks the guard fails closed (owner act m2-rescope-c-reduced §3, #317
// comment 6091950328): no writer is started and the caller shows an "unsupported browser"
// refusal. There is no degraded writer mode and no IndexedDB lease fallback.

/** Closed refusal reasons. */
export const WRITER_LOCK_REASONS = Object.freeze({
  UNSUPPORTED: 'unsupported', // Web Locks unavailable
  HELD_ELSEWHERE: 'held-elsewhere', // another tab is the writer
  REJECTED: 'rejected', // the request was rejected, threw or settled without a grant
});

/**
 * Try to become the exclusive MLS writer for `name`.
 * @param {Lock-like} locksApi typically `navigator.locks`
 * @param {string} name lock name (per profile namespace)
 * @returns {Promise<{held: boolean, reason?: string, release: () => Promise<void>}>}
 *   held=false means this tab must NOT become a writer; `reason` says why
 *   ('unsupported' when Web Locks are absent, 'held-elsewhere', 'rejected').
 *   `release()` frees the lock and resolves once it is actually free (call on logout; tab close
 *   frees it automatically).
 */
export async function acquireWriterLock(locksApi, name) {
  let request;
  try {
    request = locksApi?.request;
  } catch {
    request = undefined;
  }
  if (typeof request !== 'function') {
    console.warn('[styx] Web Locks unavailable — refusing to start an MLS writer');
    return { held: false, reason: WRITER_LOCK_REASONS.UNSUPPORTED, release: async () => {} }; // fail closed
  }

  let release = () => {};
  let invocationFailed = false;
  let requestEnded = false;
  let requestSettled = Promise.resolve();
  const outcome = await new Promise((resolve) => {
    let settled = false;
    const settle = (value) => {
      if (settled) return false;
      settled = true;
      resolve(value);
      return true;
    };
    let pending;
    try {
      pending = Reflect.apply(request, locksApi, [name, { mode: 'exclusive', ifAvailable: true }, (lock) => {
        if (lock === null || lock === undefined) { settle(WRITER_LOCK_REASONS.HELD_ELSEWHERE); return undefined; } // another tab is the writer
        if (typeof lock !== 'object' && typeof lock !== 'function') { settle(WRITER_LOCK_REASONS.REJECTED); return undefined; }
        if (!settle(null)) return undefined;
        // Hold the lock until release() is called (or the tab closes).
        return new Promise((freeLock) => { release = freeLock; });
      }]);
    } catch {
      // The request threw. A grant it may already have called back with is void: free it at once.
      invocationFailed = true;
      const free = release;
      release = () => {};
      free();
      settle(WRITER_LOCK_REASONS.REJECTED);
      return;
    }
    // The request settles only once the lock is no longer held. Settling (or rejecting) before this
    // function has returned a grant means the grant is gone: it is not held.
    const ended = () => { if (!settle(WRITER_LOCK_REASONS.REJECTED)) requestEnded = true; };
    requestSettled = Promise.resolve(pending).then(ended, ended);
  });

  if (invocationFailed) return { held: false, reason: WRITER_LOCK_REASONS.REJECTED, release: async () => {} };
  if (outcome !== null) return { held: false, reason: outcome, release: async () => {} };
  // Let an already-settled request report itself before the grant is trusted.
  await new Promise((resolve) => { setTimeout(resolve, 0); });
  if (requestEnded) {
    try { release(); } catch { /* ignore */ }
    return { held: false, reason: WRITER_LOCK_REASONS.REJECTED, release: async () => {} };
  }
  // release() frees the lock and resolves once the request has settled, i.e. the lock is actually
  // free: a re-acquisition after awaiting it never meets this tab's own lock.
  const free = release;
  return { held: true, release: () => { try { free(); } catch { /* ignore */ } return requestSettled; } };
}
