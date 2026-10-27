// M3-CATCHUP: local-clock cursors, one per configured relay (not per pool).
// No EVENT field participates in a cursor. Catch-up is best effort and has no
// host timer backstop, unlike publication deadlines and attempt timeouts.
const INTERVAL_MS = 10000;
const MARGIN_SECONDS = 120;
const NOT_ARMED = Symbol('catch-up: no timer armed');

// A faulty synchronous port can return a rejected promise. Observe it without
// waiting or interpreting it as a successful synchronous result (model B).
function ignoreRejection(value) {
  Promise.resolve(value).catch(() => {});
}

export function createCatchUp({ relayCount, subscriptionId, clock, isRunning, resubscribe }) {
  const states = Array.from({ length: relayCount }, () => ({ syncedUntil: null, outstanding: null }));
  let frozen = false;
  let disposed = false;
  let started = false;
  let handle = NOT_ARMED;
  const stateAt = (index) => Number.isInteger(index) && index >= 0 && index < states.length ? states[index] : null;
  const since = (index) => {
    const state = stateAt(index);
    if (state === null || state.syncedUntil === null) return null;
    const value = Math.max(0, state.syncedUntil - MARGIN_SECONDS);
    return Number.isSafeInteger(value) ? value : null;
  };
  // Called immediately before each prepared or connected-pool REQ. Keeping
  // the minimum is equivalent to the outstanding set and bounds memory even
  // when a relay never answers EOSE.
  const subscriptionSince = (index) => {
    const state = stateAt(index);
    if (state === null || frozen || disposed) return null;
    try {
      const now = clock.now();
      ignoreRejection(now);
      if (typeof now === 'number' && Number.isFinite(now)) {
        const issued = Math.floor(now / 1000);
        state.outstanding = state.outstanding === null ? issued : Math.min(state.outstanding, issued);
      }
    } catch {
      // An invalid clock records no issue time.
    }
    return since(index);
  };
  const observe = (frame) => {
    if (frozen || disposed || !frame || !Array.isArray(frame.data)) return;
    if (frame.data[0] !== 'EOSE' || frame.data[1] !== subscriptionId) return;
    const state = stateAt(frame.relayIndex);
    if (state === null || state.outstanding === null) return;
    if (state.syncedUntil === null || state.outstanding > state.syncedUntil) state.syncedUntil = state.outstanding;
    state.outstanding = null;
  };
  const live = () => {
    if (frozen || disposed) return false;
    try { return isRunning() === true; } catch { return false; }
  };
  const arm = () => {
    if (!live() || handle !== NOT_ARMED) return;
    try {
      handle = clock.setTimer(() => {
        // Leave the opaque handle owned until step (4) if step (1) froze us.
        if (!live()) return;
        handle = NOT_ARMED;
        for (let index = 0; index < states.length && live(); index += 1) {
          try { ignoreRejection(resubscribe(index, since(index))); } catch { /* best effort */ }
        }
        arm();
      }, INTERVAL_MS);
      ignoreRejection(handle);
    } catch {
      handle = NOT_ARMED;
    }
  };
  const start = () => {
    if (started || frozen || disposed) return;
    started = true;
    arm();
  };
  const freeze = () => { frozen = true; };
  const dispose = () => {
    if (disposed) return;
    disposed = true;
    frozen = true;
    if (handle !== NOT_ARMED) {
      try { ignoreRejection(clock.clearTimer(handle)); } catch { /* best effort */ }
      handle = NOT_ARMED;
    }
    for (const state of states) state.outstanding = null;
  };
  return { subscriptionSince, since, observe, start, freeze, dispose };
}
