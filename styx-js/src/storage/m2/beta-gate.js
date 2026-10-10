// beta-gate.js — the M2 single-tab beta guard (card M2-BETA-GATE of #317 G-SCOPE; owner act
// `styx-owner-act:m2-rescope-c-reduced:v1`, #317 comment 6091950328, §3).
//
// One canonical Web Lock per vault database, `styx-m2:<vault db name>`, separate from the legacy
// `styx-mls:<ns>` writer lock. On the main thread, before the vault worker receives any M2 request,
// `acquireM2BetaGate` makes exactly one exclusive, non-queued request
// (`navigator.locks.request(name, { mode: 'exclusive', ifAvailable: true }, …)`); `steal` is never
// requested. The observation is classified by the I-LOCK decision core (`session-lock.js`), and M2
// entry is allowed only when that core authorizes a STATE_CHANGE for this context.
//
// Fail closed: Web Locks unavailable, a rejected request, or the lock held elsewhere all refuse
// entry, and this module then sends nothing to the worker peer, so nothing is written.
//
// The held lock is a token with a single `isHeld()` boolean. While held, the main thread reports the
// token as held to the vault-worker peer; on release it first withdraws that report and waits for the
// peer's acknowledgement (or terminates the peer), and only then releases the lock. Tab close kills
// both together. The production receiver of the report in the vault worker belongs to card I-IDB.
//
// R-UX reset gate rule (act §3): the `lockHeld` input of `beginRecoveryReset`, `confirmRecoveryReset`
// and `recoveryChangePassword` is always `token.isHeld()` — a boolean, never the token object and
// never a literal `true`. `recoveryLockHeld(token)` is the one helper that produces it.
//
// Not claimed here: real-browser multi-tab behaviour, `steal`, and context-death release of a real
// Web Lock (deferred to M3 / checked by B-CHR and I-IDB per the act).

import { evaluateLockAction } from './session-lock.js';

/** The canonical lock-name prefix (act §3 "Lock name"). */
export const M2_LOCK_PREFIX = 'styx-m2:';

/** The product vault database name; the product lock is `styx-m2:styx-vault-default`. */
export const M2_PRODUCT_VAULT_DB_NAME = 'styx-vault-default';

/** Test databases follow the vault worker lifecycle rule (`styx-vault-test-*`). */
const TEST_VAULT_DB_PREFIX = 'styx-vault-test-';

/** Closed refusal reasons. */
export const M2_GATE_REFUSALS = Object.freeze({
  UNSUPPORTED: 'UNSUPPORTED', // Web Locks unavailable
  REJECTED: 'REJECTED', // the request was rejected, threw, or granted a lock it did not ask for
  HELD_ELSEWHERE: 'HELD_ELSEWHERE', // another context holds the lock
  WRONG_SCOPE: 'WRONG_SCOPE', // the database name is not a vault database
  REPORT_FAILED: 'REPORT_FAILED', // the held report could not be delivered to the worker peer
});

/** Closed held-report message types (main thread → vault worker, and the acknowledgement). */
export const M2_HELD_REPORT_TYPES = Object.freeze({
  HELD: 'M2_LOCK_HELD',
  WITHDRAWN: 'M2_LOCK_WITHDRAWN',
  WITHDRAWN_ACK: 'M2_LOCK_WITHDRAWN_ACK',
});

/** Default bound on waiting for the withdrawal acknowledgement before the peer is terminated. */
export const DEFAULT_WITHDRAW_ACK_TIMEOUT_MS = 5000;

/** Default bound on delivering the held report; on expiry the peer is terminated and entry refused. */
export const DEFAULT_REPORT_TIMEOUT_MS = 5000;

// Acquisition identity. Every held report and withdrawal of one acquisition carries the same
// `epoch` (a per-realm counter) and `nonce` (random), and an acknowledgement must echo both, so an
// acknowledgement from an earlier acquisition never satisfies a later one.
let acquisitionCounter = 0;
function freshNonce() {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/** A token that is never held: the input every refusal path exposes. */
export const CLOSED_M2_TOKEN = Object.freeze({ isHeld: () => false });

/** True only for a vault database name (the product one, or a `styx-vault-test-*` one). */
export function isVaultDbName(dbName) {
  return typeof dbName === 'string'
    && (dbName === M2_PRODUCT_VAULT_DB_NAME
      || (dbName.startsWith(TEST_VAULT_DB_PREFIX) && dbName.length > TEST_VAULT_DB_PREFIX.length));
}

/** The canonical lock name for one vault database. Throws on a non-vault database name. */
export function m2LockName(dbName) {
  if (!isVaultDbName(dbName)) throw new TypeError('not a vault database name');
  return `${M2_LOCK_PREFIX}${dbName}`;
}

/**
 * The R-UX gate input: exactly `token.isHeld()`, as a boolean. Anything that is not a token with an
 * `isHeld` function, or whose `isHeld()` does not return the boolean `true`, yields `false`.
 */
export function recoveryLockHeld(token) {
  let held;
  try {
    held = typeof token?.isHeld === 'function' ? token.isHeld() : false;
  } catch {
    held = false;
  }
  return held === true;
}

function refusal(reason, decision) {
  return Object.freeze({
    entered: false,
    reason,
    decision,
    token: CLOSED_M2_TOKEN,
    release: async () => {},
  });
}

function observe(ownership) {
  return evaluateLockAction({ contextId: 'main', role: 'WRITER', ownership, action: 'STATE_CHANGE' });
}

/**
 * Try to enter M2 in this tab.
 *
 * @param {object} options
 * @param {{request: Function}|undefined|null} options.locks  typically `navigator.locks`
 * @param {string} [options.dbName]  the vault database name (default: the product database)
 * @param {object|null} [options.peer]  the vault-worker peer:
 *   `reportHeld(report)` (may return a promise), `withdrawHeld(report)` → promise of the ack,
 *   `terminate()`. Without a peer nothing is reported, so the worker stays closed.
 * @param {number} [options.withdrawAckTimeoutMs]
 * @param {number} [options.reportTimeoutMs]
 * @param {(fn: Function, ms: number) => any} [options.setTimer]
 * @param {(handle: any) => void} [options.clearTimer]
 * @param {() => void} [options.onLost]  called once if the held lock is lost without a release
 * @returns {Promise<{entered: boolean, reason: string|null, decision: object, token: {isHeld(): boolean},
 *   release: (opts?: {beforeFree?: () => any}) => Promise<void>, lockName?: string}>}
 *   `release` is idempotent: every call returns the first call's promise, and only the first call's
 *   `beforeFree` runs.
 */
export async function acquireM2BetaGate({
  locks,
  dbName = M2_PRODUCT_VAULT_DB_NAME,
  peer = null,
  withdrawAckTimeoutMs = DEFAULT_WITHDRAW_ACK_TIMEOUT_MS,
  reportTimeoutMs = DEFAULT_REPORT_TIMEOUT_MS,
  setTimer = (fn, ms) => setTimeout(fn, ms),
  clearTimer = (handle) => clearTimeout(handle),
  onLost = () => {},
} = {}) {
  if (!isVaultDbName(dbName)) return refusal(M2_GATE_REFUSALS.WRONG_SCOPE, observe('UNAVAILABLE'));
  const name = m2LockName(dbName);

  let request;
  try {
    request = locks?.request;
  } catch {
    request = undefined;
  }
  if (typeof request !== 'function') return refusal(M2_GATE_REFUSALS.UNSUPPORTED, observe('UNAVAILABLE'));

  // Lock lifecycle: 'PENDING' → 'HELD' → 'RELEASING' → 'RELEASED', or 'PENDING' → 'NOT_GRANTED',
  // or 'HELD' → 'LOST' when the request settles while we still believe we hold it.
  let phase = 'PENDING';
  let freeLock = null;
  let reported = false;
  let peerClosed = false;
  let epoch = 0;
  let nonce = '';
  let invocationFailed = false;
  let peerStopUnproven = false; // a terminate() threw: the peer may still run, so the lock is kept
  let requestSettled = Promise.resolve();

  const token = Object.freeze({ isHeld: () => phase === 'HELD' });

  // Terminate the peer. If terminate() throws, the peer's stop is not established: the lock is then
  // never freed by this module (it stays held until the tab closes, which kills both together).
  const terminatePeer = () => {
    if (peer === null || peerClosed) return;
    peerClosed = true;
    try { peer.terminate(); } catch { peerStopUnproven = true; }
  };

  const grant = await new Promise((resolve) => {
    let settled = false;
    const settle = (value) => {
      if (settled) return false;
      settled = true;
      resolve(value);
      return true;
    };
    let pending;
    try {
      pending = Reflect.apply(request, locks, [name, { mode: 'exclusive', ifAvailable: true }, (lock) => {
        if (lock === null || lock === undefined) {
          settle({ kind: 'HELD_ELSEWHERE' });
          return undefined;
        }
        let grantedName;
        let grantedMode;
        try {
          grantedName = lock.name;
          grantedMode = lock.mode;
        } catch {
          grantedName = undefined;
        }
        if (grantedName !== name || grantedMode !== 'exclusive') {
          settle({ kind: 'REJECTED' }); // fail closed; returning frees the granted lock at once
          return undefined;
        }
        if (!settle({ kind: 'GRANTED' })) return undefined; // a late duplicate grant is not held
        phase = 'HELD';
        return new Promise((free) => { freeLock = free; });
      }]);
    } catch {
      // The request threw. If it had already called back and granted, that grant is void: free it
      // at once and refuse below (the grant promise may already have been settled as GRANTED).
      invocationFailed = true;
      if (phase === 'HELD') phase = 'NOT_GRANTED';
      const free = freeLock;
      freeLock = null;
      if (typeof free === 'function') free();
      settle({ kind: 'REJECTED' });
      return;
    }
    requestSettled = Promise.resolve(pending).then(() => {}, () => {});
    Promise.resolve(pending).then(
      () => {
        if (settle({ kind: 'REJECTED' })) return; // settled without ever calling back
        if (phase === 'HELD') { phase = 'LOST'; terminatePeer(); try { onLost(); } catch { /* ignore */ } }
      },
      () => {
        if (settle({ kind: 'REJECTED' })) return;
        if (phase === 'HELD') { phase = 'LOST'; terminatePeer(); try { onLost(); } catch { /* ignore */ } }
      },
    );
  });

  if (grant.kind !== 'GRANTED' || invocationFailed) {
    phase = 'NOT_GRANTED';
    const elsewhere = grant.kind === 'HELD_ELSEWHERE' && !invocationFailed;
    const reason = elsewhere ? M2_GATE_REFUSALS.HELD_ELSEWHERE : M2_GATE_REFUSALS.REJECTED;
    return refusal(reason, observe(elsewhere ? 'HELD_BY_OTHER' : 'UNAVAILABLE'));
  }

  const decision = observe(token.isHeld() ? 'HELD_BY_SELF' : 'UNAVAILABLE');

  const freeNow = () => {
    if (peerStopUnproven) return false; // fail closed: keep the lock while the peer may still run
    const free = freeLock;
    freeLock = null;
    if (typeof free === 'function') free();
    return true;
  };

  async function withdrawThenTerminateOnFailure() {
    if (peer === null || peerClosed || !reported) return;
    reported = false;
    const report = Object.freeze({ type: M2_HELD_REPORT_TYPES.WITHDRAWN, lockName: name, epoch, nonce });
    let timer = null;
    const timedOut = new Promise((resolve) => { timer = setTimer(() => resolve('TIMEOUT'), withdrawAckTimeoutMs); });
    let ack;
    try {
      ack = await Promise.race([Promise.resolve().then(() => peer.withdrawHeld(report)), timedOut]);
    } catch {
      ack = 'FAILED';
    } finally {
      try { clearTimer(timer); } catch { /* ignore */ }
    }
    let valid;
    try {
      valid = ack !== null && typeof ack === 'object'
        && ack.type === M2_HELD_REPORT_TYPES.WITHDRAWN_ACK && ack.lockName === name
        && ack.epoch === epoch && ack.nonce === nonce;
    } catch {
      valid = false; // a throwing acknowledgement is an invalid one
    }
    if (valid !== true) terminatePeer();
  }

  let releasing = null;
  /**
   * Release in the act §3 order: `isHeld()` turns false synchronously; then the held report is
   * withdrawn and its acknowledgement awaited (or the peer is terminated); then the optional
   * `beforeFree` step runs (the caller stops its vault worker there); only then is the lock freed.
   */
  const release = ({ beforeFree } = {}) => {
    if (releasing) return releasing;
    // Synchronously stop authorizing before anything else: from here `isHeld()` is false.
    const wasHeld = phase === 'HELD';
    if (wasHeld) phase = 'RELEASING';
    releasing = (async () => {
      let freed = false;
      try {
        await withdrawThenTerminateOnFailure();
        if (typeof beforeFree === 'function') {
          try { await beforeFree(); } catch { /* the lock is still freed below */ }
        }
      } finally {
        if (phase === 'RELEASING') phase = 'RELEASED';
        freed = freeNow();
      }
      // Resolve only once the lock manager reports the request settled, i.e. the lock is free. When
      // the peer's stop could not be established the lock is deliberately kept and this resolves now.
      if (freed) await requestSettled;
    })();
    return releasing;
  };

  if (decision.authorized !== true) {
    await release();
    return refusal(M2_GATE_REFUSALS.REJECTED, decision);
  }

  if (peer !== null) {
    acquisitionCounter += 1;
    epoch = acquisitionCounter;
    let timer = null;
    try {
      nonce = freshNonce(); // a failing random source refuses entry and frees the lock (nothing sent yet)
      const report = Object.freeze({ type: M2_HELD_REPORT_TYPES.HELD, lockName: name, epoch, nonce });
      reported = true;
      const timedOut = new Promise((resolve) => { timer = setTimer(() => resolve('TIMEOUT'), reportTimeoutMs); });
      const delivered = await Promise.race([
        Promise.resolve().then(() => peer.reportHeld(report)).then(() => 'DELIVERED'), timedOut,
      ]);
      if (delivered !== 'DELIVERED') throw new Error('held report timed out');
    } catch {
      try { clearTimer(timer); } catch { /* ignore */ }
      terminatePeer(); // its state is unknown: never leave a worker that may believe it holds the lock
      await release();
      return refusal(M2_GATE_REFUSALS.REPORT_FAILED, observe('UNAVAILABLE'));
    }
    try { clearTimer(timer); } catch { /* ignore */ }
    if (phase !== 'HELD') {
      // The lock was lost while the report was in flight.
      terminatePeer();
      await release();
      return refusal(M2_GATE_REFUSALS.REJECTED, observe('UNAVAILABLE'));
    }
  }

  return Object.freeze({ entered: true, reason: null, decision, token, release, lockName: name });
}
