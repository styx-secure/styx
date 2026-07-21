// vault-db.js — production IndexedDB engine of the Styx vault (Blocco 3,
// PR-4 / US-005). Record-oriented keyspace over native IndexedDB, ported from
// the validated spike (spikes/indexeddb-vault, probes P1–P12) with the spike's
// §4 decisions and F1–F9 findings applied.
//
// Boundary and ownership:
// - this module is storage only: it never sees passwords, keys or plaintext
//   semantics — values are opaque structured-clone data (binary Uint8Array
//   stored natively, never base64);
// - single-writer discipline is OWNED BY THE CALLER through the existing Web
//   Lock election (the app's writer lock / the worker supervisor). The engine
//   defends itself anyway: bounded wait on blocked opens and auto-close on
//   `versionchange` (spike F5/F6) so a stale connection can never silently
//   block an upgrade;
// - all failures are structured VaultCryptoError values from the closed code
//   set; a quota failure aborts the transaction and destroys nothing.
//
// Transaction contract (spike F1): a `transaction()` resolves ONLY on
// `oncomplete` — resolved means committed, with `durability: 'strict'` where
// supported. The callback must not await anything that is not one of the
// transaction's own ops: IndexedDB auto-commits at a microtask checkpoint
// with no pending requests.

import { VaultCryptoError, VaultCryptoErrorCodes as Codes } from '../crypto/vault-errors.js';

export const VAULT_DB_SCHEMA_VERSION = 1;

/** The ten frozen namespaces of schema v1 (plan §B3.0.1 — frozen list). */
export const VAULT_NAMESPACES = Object.freeze([
  'meta', 'identity', 'contacts', 'messages', 'mls', 'outbox', 'push',
  'settings', 'migrations', 'canary',
]);

/**
 * Bound for blocked opens/deletes (plan B3.4: bounded, 50 ms granularity).
 * Spike P10 finding: after `onblocked` the underlying request stays PENDING
 * in the browser until the blocker closes, and any NEW open of the same
 * database queues behind it — a reject-and-reopen retry loop therefore
 * deadlocks the tab under a permanent blocker. The production engine waits
 * on the SAME request with this bounded timeout instead: a transient blocker
 * resolves the wait naturally (onsuccess fires when it closes), a permanent
 * one surfaces VAULT_BLOCKED when the bound expires.
 */
export const BLOCKED_RETRY_ATTEMPTS = 5;
export const BLOCKED_RETRY_DELAY_MS = 50;
export const BLOCKED_WAIT_MS = BLOCKED_RETRY_ATTEMPTS * BLOCKED_RETRY_DELAY_MS;

/** Bounded persist()/estimate() probe (spike F8: never await unbounded). */
export const PERSIST_TIMEOUT_MS = 3000;

/**
 * Per-version schema migrations. Version N upgrades a database at N-1; all
 * steps run inside the single `versionchange` transaction, so any throw
 * aborts the WHOLE upgrade and the database stays at the previous version
 * (fail-closed, no partial upgrades).
 */
const SCHEMA_MIGRATIONS = Object.freeze({
  1: (db) => { for (const ns of VAULT_NAMESPACES) db.createObjectStore(ns); },
});

// Detail values are clamped to the allowlist's 64-char bound: a long database
// name must degrade the detail, never make the ERROR construction throw.
const clamp = (v) => (typeof v === 'string' ? v.slice(0, 64) : v);
const err = (code, message, details) => {
  const out = details === undefined ? undefined
    : Object.fromEntries(Object.entries(details).map(([k, v]) => [k, clamp(v)]));
  return new VaultCryptoError(code, message, out);
};

const isQuotaError = (e) => e?.name === 'QuotaExceededError';

function requestToPromise(req) {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function openOnce({
  indexedDBImpl, name, version, migrations, onUpgrade, setTimeoutImpl, clearTimeoutImpl, blockedWaitMs,
}) {
  return new Promise((resolve, reject) => {
    let upgradeError = null;
    let timer = null;
    let settled = false;
    const settle = (fn, value) => {
      if (settled) return false;
      settled = true;
      if (timer !== null) { clearTimeoutImpl(timer); timer = null; }
      fn(value);
      return true;
    };
    const req = indexedDBImpl.open(name, version);
    req.onblocked = () => {
      // Bounded wait on THIS request (see BLOCKED_WAIT_MS): never reopen.
      if (timer === null && !settled) {
        timer = setTimeoutImpl(() => settle(reject, err(Codes.BLOCKED,
          'another connection holds an older version open', { namespace: name, version })), blockedWaitMs);
      }
    };
    req.onupgradeneeded = (ev) => {
      const db = req.result;
      try {
        for (let v = ev.oldVersion + 1; v <= version; v += 1) {
          const migrate = migrations[v];
          if (typeof migrate !== 'function') {
            throw err(Codes.SCHEMA_GAP, 'no migration registered for a version step', {
              namespace: name, version: v, reason: `from:${ev.oldVersion}`,
            });
          }
          migrate(db, req.transaction);
          if (onUpgrade) onUpgrade(v - 1, v);
        }
      } catch (e) {
        // Abort the versionchange transaction: the DB stays at ev.oldVersion.
        // A migrator's own (untyped) exception is wrapped so the caller never
        // sees a raw error from the open path (review PR99 minor).
        upgradeError = e instanceof VaultCryptoError ? e
          : err(Codes.OPEN_FAILED, 'a schema migration step failed', {
            namespace: name, reason: `migration:${e?.name ?? 'Error'}`,
          });
        try { req.transaction.abort(); } catch { /* already aborting */ }
      }
    };
    req.onerror = () => settle(reject, upgradeError || err(Codes.OPEN_FAILED,
      'the database could not be opened', { namespace: name, reason: req.error?.name ?? 'unknown' }));
    req.onsuccess = () => {
      const db = req.result;
      // Spike F5/F6: a later upgrade elsewhere fires versionchange — close so
      // we never block it silently. The owner reopens through its Web Lock.
      db.onversionchange = () => db.close();
      // A success that lands AFTER the bounded-block timeout must not leak a
      // live connection nobody owns.
      if (!settle(resolve, db)) db.close();
    };
  });
}

/**
 * Open (create/upgrade if needed) the vault database, with bounded retry when
 * another connection blocks the open (spike F4).
 *
 * @param {object} [opts]
 * @param {string} opts.name database name (tests use `styx-vault-test-*`)
 * @param {number} [opts.version]
 * @param {object} [opts.migrations] version → (db, tx) => void
 * @param {(oldV:number,newV:number)=>void} [opts.onUpgrade]
 * @param {IDBFactory} [opts.indexedDBImpl] injected for tests
 * @param {Function} [opts.setTimeoutImpl] injected for tests
 * @param {Function} [opts.clearTimeoutImpl] injected for tests
 * @param {number} [opts.blockedWaitMs] bound for blocked opens/deletes
 * @returns {Promise<VaultDb>}
 */
export async function openVaultDb({
  name,
  version = VAULT_DB_SCHEMA_VERSION,
  migrations = SCHEMA_MIGRATIONS,
  onUpgrade,
  indexedDBImpl = globalThis.indexedDB,
  setTimeoutImpl = globalThis.setTimeout.bind(globalThis),
  clearTimeoutImpl = globalThis.clearTimeout.bind(globalThis),
  blockedWaitMs = BLOCKED_WAIT_MS,
} = {}) {
  if (typeof name !== 'string' || name.length === 0) {
    throw err(Codes.OPEN_FAILED, 'a database name is required', { reason: 'missing-name' });
  }
  const db = await openOnce({
    indexedDBImpl, name, version, migrations, onUpgrade, setTimeoutImpl, clearTimeoutImpl, blockedWaitMs,
  });
  return new VaultDb(db, { indexedDBImpl, setTimeoutImpl, clearTimeoutImpl, blockedWaitMs });
}

export class VaultDb {
  constructor(db, env) { this._db = db; this._env = env; }

  get name() { return this._db.name; }

  get version() { return this._db.version; }

  get namespaces() { return Array.from(this._db.objectStoreNames); }

  // Readonly ops wrap every failure (the synchronous transaction() throw
  // included — e.g. InvalidStateError after our own versionchange auto-close)
  // into structured VAULT_TX_ABORTED: the module contract is "all failures
  // are typed", and a recoverable closed-connection read must never surface
  // as a raw DOMException (independent-review minor on PR #99).
  async _read(namespace, run) {
    try {
      const tx = this._db.transaction(namespace, 'readonly');
      return await requestToPromise(run(tx.objectStore(namespace)));
    } catch (e) {
      if (e instanceof VaultCryptoError) throw e;
      throw err(Codes.TX_ABORTED, 'the read transaction failed', {
        namespace, reason: e?.name ?? 'unknown',
      });
    }
  }

  /** Single-record read. @returns {Promise<any>} undefined when absent */
  async get(namespace, key) {
    return this._read(namespace, (store) => store.get(key));
  }

  /** Single-record durable write (its own transaction). */
  async put(namespace, key, value) {
    return this.transaction([namespace], (ops) => ops.put(namespace, key, value));
  }

  /** Single-record delete (its own transaction). */
  async delete(namespace, key) {
    return this.transaction([namespace], (ops) => ops.delete(namespace, key));
  }

  /** All keys of a namespace. @returns {Promise<string[]>} */
  async list(namespace) {
    return this._read(namespace, (store) => store.getAllKeys());
  }

  /** Remove every record of one namespace, atomically, others untouched. */
  async clear(namespace) {
    return this.transaction([namespace], (ops) => ops.clear(namespace));
  }

  /**
   * Run `callback(ops)` inside ONE readwrite transaction over `namespaces`.
   * Resolves only on commit (`oncomplete`); rejects with everything rolled
   * back if the callback throws, aborts, or any request fails. A quota
   * failure maps to VAULT_QUOTA_EXCEEDED — aborted, never destructive.
   */
  transaction(namespaces, callback) {
    return new Promise((resolve, reject) => {
      let tx;
      try {
        tx = this._db.transaction(namespaces, 'readwrite', { durability: 'strict' });
      } catch (e) {
        reject(err(Codes.TX_ABORTED, 'the transaction could not start', { reason: e?.name ?? 'unknown' }));
        return;
      }
      let result;
      let cbError = null;
      tx.oncomplete = () => resolve(result);
      tx.onabort = () => {
        if (cbError !== null) { reject(cbError); return; }
        const reason = tx.error?.name ?? 'abort';
        reject(isQuotaError(tx.error)
          ? err(Codes.QUOTA_EXCEEDED, 'the write exceeded the storage quota — nothing was written', { reason })
          : err(Codes.TX_ABORTED, 'the transaction aborted — nothing was written', { reason }));
      };
      tx.onerror = () => { /* onabort follows and carries tx.error */ };
      const ops = {
        get: (ns, key) => requestToPromise(tx.objectStore(ns).get(key)),
        put: (ns, key, value) => requestToPromise(tx.objectStore(ns).put(value, key)),
        delete: (ns, key) => requestToPromise(tx.objectStore(ns).delete(key)),
        list: (ns) => requestToPromise(tx.objectStore(ns).getAllKeys()),
        clear: (ns) => requestToPromise(tx.objectStore(ns).clear()),
        abort: () => tx.abort(),
      };
      Promise.resolve()
        .then(() => callback(ops))
        .then((r) => { result = r; })
        .catch((e) => {
          cbError = isQuotaError(e)
            ? err(Codes.QUOTA_EXCEEDED, 'the write exceeded the storage quota — nothing was written', { reason: e.name })
            : e;
          try { tx.abort(); } catch { /* already done */ }
        });
    });
  }

  /** Close the connection (idempotent). */
  close() { try { this._db.close(); } catch { /* already closed */ } }

  /**
   * Close and DELETE the whole database (factory-reset building block), with
   * the same bounded wait on blocked deletes as the open path (spike P10:
   * never issue a second delete behind a pending one).
   *
   * CONTRACT on VAULT_BLOCKED (review PR99): the underlying deleteDatabase
   * request cannot be cancelled — after the bounded rejection it stays
   * pending in the browser and WILL complete whenever the blocking
   * connections close. Callers must treat BLOCKED-from-destroy as "deletion
   * still pending", never as "data retained".
   */
  async destroy() {
    const { name } = this._db;
    const { indexedDBImpl, setTimeoutImpl, clearTimeoutImpl, blockedWaitMs } = this._env;
    this.close();
    await new Promise((resolve, reject) => {
      let timer = null;
      let settled = false;
      const settle = (fn, value) => {
        if (settled) return;
        settled = true;
        if (timer !== null) { clearTimeoutImpl(timer); timer = null; }
        fn(value);
      };
      const req = indexedDBImpl.deleteDatabase(name);
      req.onsuccess = () => settle(resolve);
      req.onblocked = () => {
        if (timer === null && !settled) {
          timer = setTimeoutImpl(() => settle(reject, err(Codes.BLOCKED,
            'delete blocked by another open connection', { namespace: name })), blockedWaitMs);
        }
      };
      req.onerror = () => settle(reject, err(Codes.DESTROY_FAILED,
        'the database could not be deleted', { namespace: name, reason: req.error?.name ?? 'unknown' }));
    });
  }
}

/**
 * Storage environment probe: persistence + quota. Advisory only — a denied
 * persist() is never fatal (the vault still works, just evictable). Spike F8:
 * Firefox may show a permission prompt and never settle persist(); every call
 * is raced against a bounded timeout and "no answer" means "not granted yet".
 */
export async function probeStorage({
  storageImpl = globalThis.navigator?.storage,
  setTimeoutImpl = globalThis.setTimeout.bind(globalThis),
  persistTimeoutMs = PERSIST_TIMEOUT_MS,
} = {}) {
  const out = { persisted: null, persistGranted: null, quota: null, usage: null };
  const bounded = (p) => Promise.race([
    p, new Promise((resolve) => { setTimeoutImpl(() => resolve('timeout'), persistTimeoutMs); }),
  ]);
  try {
    if (storageImpl?.persisted) out.persisted = await bounded(storageImpl.persisted());
    if (storageImpl?.persist) out.persistGranted = await bounded(storageImpl.persist());
    if (storageImpl?.estimate) {
      const est = await bounded(storageImpl.estimate());
      if (est !== 'timeout') { out.quota = est.quota; out.usage = est.usage; }
    }
  } catch { /* advisory */ }
  return out;
}
