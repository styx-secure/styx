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
 * @returns {Promise<{held: boolean, reason?: string, release: () => void}>}
 *   held=false means this tab must NOT become a writer; `reason` says why
 *   ('unsupported' when Web Locks are absent, 'held-elsewhere', 'rejected').
 *   `release()` frees the lock (call on logout; tab close frees it automatically).
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
    return { held: false, reason: WRITER_LOCK_REASONS.UNSUPPORTED, release: () => {} }; // fail closed
  }

  let release = () => {};
  let invocationFailed = false;
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
        if (!lock) { settle(WRITER_LOCK_REASONS.HELD_ELSEWHERE); return undefined; } // another tab is the writer
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
    Promise.resolve(pending).then(
      () => { settle(WRITER_LOCK_REASONS.REJECTED); },
      () => { settle(WRITER_LOCK_REASONS.REJECTED); },
    );
  });

  if (invocationFailed) return { held: false, reason: WRITER_LOCK_REASONS.REJECTED, release: () => {} };
  if (outcome !== null) return { held: false, reason: outcome, release: () => {} };
  return { held: true, release };
}
