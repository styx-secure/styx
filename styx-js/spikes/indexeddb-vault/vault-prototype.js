// vault-prototype.js — STYX_SPIKE_PROTOTYPE (spike/indexeddb-vault).
//
// NOT PRODUCTION CODE. This prototype exists to answer the Blocco 3 design
// questions (atomic transactions, schema upgrades, crash consistency, quota,
// multi-tab) against REAL IndexedDB in real browsers. It is never imported by
// the app or the library; the web-gate greps the production bundle for the
// STYX_SPIKE_PROTOTYPE marker to prove it stays out.
//
// Design goals probed here (see docs/superpowers/spikes/2026-07-12-indexeddb-vault.md):
// - record-oriented schema: one object store per namespace, out-of-line string keys,
//   structured-clone values (binary Uint8Array stored natively — no base64);
// - durability: a transaction() resolves only on `oncomplete`, so "resolved" means
//   the commit happened (with durability:'strict' where supported);
// - versioned schema with a per-version migration registry, mirroring the
//   envelope's migration-policy philosophy (fail-closed, no partial upgrades:
//   IndexedDB aborts the whole versionchange transaction if a migrator throws);
// - no dependencies: the API surface the vault needs is thin enough that native
//   IndexedDB wrapped in ~200 lines beats importing idb/Dexie into the
//   security-critical path.

export const VAULT_NAME = 'styx-vault-spike';
export const VAULT_SCHEMA_VERSION = 1;
export const NAMESPACES = Object.freeze([
  'meta', 'identity', 'contacts', 'messages', 'mls', 'outbox', 'migrations',
]);

/**
 * Per-version schema migrations. Version N's entry upgrades a database that is
 * at version N-1. All of it runs inside the single `versionchange` transaction
 * IndexedDB gives us: if any step throws, the WHOLE upgrade aborts and the
 * database stays at the previous version — the fail-closed property we need.
 */
const SCHEMA_MIGRATIONS = {
  1: (db) => { for (const ns of NAMESPACES) db.createObjectStore(ns); },
};

export class VaultError extends Error {
  constructor(code, message, details = {}) {
    super(`${code}: ${message}`);
    this.name = 'VaultError';
    this.code = code;
    this.details = details;
  }
}

function requestToPromise(req) {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

/**
 * Open (and if needed create/upgrade) the vault database.
 * @param {object} [opts]
 * @param {string} [opts.name]
 * @param {number} [opts.version]
 * @param {object} [opts.migrations] version → (db, tx) => void
 * @param {(oldV:number,newV:number)=>void} [opts.onUpgrade] observe upgrades (tests)
 * @returns {Promise<Vault>}
 */
export function openVault({
  name = VAULT_NAME,
  version = VAULT_SCHEMA_VERSION,
  migrations = SCHEMA_MIGRATIONS,
  onUpgrade,
} = {}) {
  return new Promise((resolve, reject) => {
    let upgradeError = null;
    const req = indexedDB.open(name, version);
    req.onblocked = () => reject(new VaultError('VAULT_BLOCKED',
      'another connection holds an older version open', { name, version }));
    req.onupgradeneeded = (ev) => {
      const db = req.result;
      try {
        for (let v = ev.oldVersion + 1; v <= version; v += 1) {
          const migrate = migrations[v];
          if (typeof migrate !== 'function') {
            throw new VaultError('VAULT_SCHEMA_GAP', `no migration registered for version ${v}`, { from: ev.oldVersion, to: version });
          }
          migrate(db, req.transaction);
          if (onUpgrade) onUpgrade(v - 1, v);
        }
      } catch (err) {
        // Abort the versionchange transaction: the DB stays at ev.oldVersion.
        upgradeError = err;
        try { req.transaction.abort(); } catch { /* already aborting */ }
      }
    };
    req.onerror = () => reject(upgradeError || new VaultError('VAULT_OPEN_FAILED',
      'the database could not be opened', { name, reason: req.error?.name }));
    req.onsuccess = () => {
      const db = req.result;
      // A later upgrade elsewhere fires versionchange: close so we never block it
      // silently. The owner must reopen (the app will route this through its
      // single-writer Web Lock).
      db.onversionchange = () => db.close();
      resolve(new Vault(db));
    };
  });
}

export class Vault {
  constructor(db) { this._db = db; }

  get name() { return this._db.name; }
  get version() { return this._db.version; }
  get namespaces() { return Array.from(this._db.objectStoreNames); }

  /** Single-record read. @returns {Promise<any>} undefined when absent */
  async get(namespace, key) {
    const tx = this._db.transaction(namespace, 'readonly');
    return requestToPromise(tx.objectStore(namespace).get(key));
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
    const tx = this._db.transaction(namespace, 'readonly');
    return requestToPromise(tx.objectStore(namespace).getAllKeys());
  }

  /** Remove every record of a namespace, atomically. */
  async clear(namespace) {
    return this.transaction([namespace], (ops) => ops.clear(namespace));
  }

  /**
   * Run `callback(ops)` inside ONE readwrite transaction over `namespaces`.
   * Resolves only when the transaction has actually committed (`oncomplete`);
   * rejects — with everything rolled back — if the callback throws, aborts, or
   * any request fails (quota included). `ops` exposes get/put/delete/list/clear
   * scoped to this transaction.
   *
   * NOTE (spike finding): the callback must not `await` anything that is not one
   * of these ops — IndexedDB auto-commits when the transaction has no pending
   * requests at a microtask checkpoint. That constraint shapes the vault API.
   */
  transaction(namespaces, callback) {
    return new Promise((resolve, reject) => {
      let tx;
      try {
        tx = this._db.transaction(namespaces, 'readwrite', { durability: 'strict' });
      } catch (err) {
        reject(new VaultError('VAULT_TX_FAILED', 'transaction could not start', { reason: err?.name }));
        return;
      }
      let result;
      let cbError = null;
      tx.oncomplete = () => resolve(result);
      tx.onabort = () => reject(cbError || new VaultError('VAULT_TX_ABORTED',
        'transaction aborted — nothing was written', { reason: tx.error?.name }));
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
        .catch((err) => { cbError = err; try { tx.abort(); } catch { /* already done */ } });
    });
  }

  /** Close the connection (idempotent). */
  close() { try { this._db.close(); } catch { /* already closed */ } }

  /** Close and DELETE the whole database. Factory-reset building block. */
  destroy() {
    const { name } = this._db;
    this.close();
    return new Promise((resolve, reject) => {
      const req = indexedDB.deleteDatabase(name);
      req.onsuccess = () => resolve();
      req.onblocked = () => reject(new VaultError('VAULT_BLOCKED',
        'delete blocked by another open connection', { name }));
      req.onerror = () => reject(new VaultError('VAULT_DELETE_FAILED',
        'the database could not be deleted', { name, reason: req.error?.name }));
    });
  }
}

/**
 * Storage environment probe: persistence + quota. Advisory only — a denied
 * persist() must never be fatal (the vault still works, just evictable).
 *
 * SPIKE FINDING: in Firefox, `navigator.storage.persist()` can show a permission
 * prompt and the returned promise simply never settles while the prompt is open
 * (headless: forever). The vault must therefore NEVER await persist() unbounded —
 * race it against a timeout and treat "no answer" as "not granted yet".
 */
export async function probeStorage({ persistTimeoutMs = 3000 } = {}) {
  const out = { persisted: null, persistGranted: null, quota: null, usage: null };
  const bounded = (p) => Promise.race([
    p, new Promise((resolve) => { setTimeout(() => resolve('timeout'), persistTimeoutMs); }),
  ]);
  try {
    if (navigator.storage?.persisted) out.persisted = await bounded(navigator.storage.persisted());
    if (navigator.storage?.persist) out.persistGranted = await bounded(navigator.storage.persist());
    if (navigator.storage?.estimate) {
      const est = await bounded(navigator.storage.estimate());
      if (est !== 'timeout') { out.quota = est.quota; out.usage = est.usage; }
    }
  } catch { /* advisory */ }
  return out;
}
