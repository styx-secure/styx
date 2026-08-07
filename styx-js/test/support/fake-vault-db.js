// fake-vault-db.js — shared in-memory VaultDb double for the vault lifecycle
// suites (US-006 state machine, US-007 canary records). It reproduces the real
// engine's contract that matters to vault.js: multi-store transactions that are
// all-or-nothing, structured-clone semantics on put/get, and a schema version.
// Real IndexedDB behaviour is covered by the browser suites.

/**
 * In-realm structured copy. NOT `structuredClone` on purpose: under Jest's
 * --experimental-vm-modules the Node global builds objects in a different
 * realm, so their Object.prototype !== the module's, and the wrapper's
 * strict-shape guard (correctly) rejects a foreign prototype. Real IndexedDB
 * clones in-realm, so this mirrors production without the harness artifact.
 */
export function deepClone(v) {
  if (v instanceof Uint8Array) return new Uint8Array(v);
  if (Array.isArray(v)) return v.map(deepClone);
  if (v !== null && typeof v === 'object') {
    const out = {};
    for (const k of Object.keys(v)) out[k] = deepClone(v[k]);
    return out;
  }
  return v;
}

/** Deterministic byte source so a test can reproduce keys and salts. */
export function seededBytes(seed) {
  let s = seed >>> 0;
  return (n) => {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i += 1) { s = (s * 1664525 + 1013904223) >>> 0; out[i] = s & 0xff; }
    return out;
  };
}

export class FakeVaultDb {
  constructor({ version = 1 } = {}) {
    this.stores = new Map();
    this.version = version; // schema version, as the real engine reports it
    this.failOn = null; // (ns, key, value) => boolean — simulated crash on a put
    this.failGetOn = null; // (ns, key, value) => boolean — simulated crash on a read
    this.destroyed = 0;
  }

  _store(ns) { if (!this.stores.has(ns)) this.stores.set(ns, new Map()); return this.stores.get(ns); }

  async get(ns, key) {
    const v = this._store(ns).get(key);
    if (this.failGetOn && this.failGetOn(ns, key, v)) throw new Error('injected read crash');
    return v === undefined ? undefined : deepClone(v);
  }

  async list(ns) { return [...this._store(ns).keys()]; }

  async transaction(namespaces, cb) {
    const snap = new Map(namespaces.map((ns) => [ns, new Map(this._store(ns))]));
    const ops = {
      get: (ns, key) => { const v = this._store(ns).get(key); return v === undefined ? undefined : deepClone(v); },
      put: (ns, key, value) => {
        if (this.failOn && this.failOn(ns, key, value)) throw new Error('injected crash');
        this._store(ns).set(key, deepClone(value));
      },
      delete: (ns, key) => this._store(ns).delete(key),
      list: (ns) => [...this._store(ns).keys()],
      clear: (ns) => this._store(ns).clear(),
      abort: () => { throw new Error('aborted'); },
    };
    try {
      return await cb(ops);
    } catch (e) {
      for (const [ns, m] of snap) this.stores.set(ns, m); // roll back
      throw e;
    }
  }

  async destroy() { this.destroyed += 1; this.stores = new Map(); }

  // Convenience accessors for assertions.
  wrapper() { return this._store('meta').get('wrapper'); }

  manifest() { return this._store('meta').get('manifest'); }

  record(ns, key) { return this._store(ns).get(key); }
}
