// writer-lock.js — a minimal single-writer guard across tabs of the same origin.
//
// Two tabs both load the MLS state and both persist after every ratchet step, so the
// second writer silently clobbers the first with a stale generation and corrupts the
// session (last-writer-wins, no merge). This holds an exclusive Web Lock for the whole
// session lifetime: the first tab is the writer, a second tab is told it cannot be.
//
// The lock auto-releases when the tab closes, so there is no stale-lock problem. If the
// browser lacks Web Locks we degrade with a warning rather than build the IndexedDB
// lease fallback (deferred) — the common two-tab case is what Web Locks already covers.

/**
 * Try to become the exclusive MLS writer for `name`.
 * @param {Lock-like} locksApi typically `navigator.locks`
 * @param {string} name lock name (per profile namespace)
 * @returns {Promise<{held: boolean, release: () => void}>}
 *   held=false means another tab holds the lock — the caller must NOT become a writer.
 *   `release()` frees the lock (call on logout; tab close frees it automatically).
 */
export async function acquireWriterLock(locksApi, name) {
  if (!locksApi?.request) {
    console.warn('[styx] Web Locks unavailable — multi-tab MLS safety is degraded');
    return { held: true, release: () => {} }; // degrade: proceed without the guard
  }

  let release = () => {};
  const held = await new Promise((resolve) => {
    locksApi.request(name, { mode: 'exclusive', ifAvailable: true }, (lock) => {
      if (!lock) { resolve(false); return; }        // another tab is the writer
      resolve(true);
      // Hold the lock until release() is called (or the tab closes).
      return new Promise((freeLock) => { release = freeLock; });
    }).catch(() => resolve(false));
  });

  return { held, release };
}
