// local-storage-backend.js — a tiny JSON KV over localStorage, for the browser.
// Used by EncryptedKeyStore and ContactRoster (small data). Values are
// JSON-serialized; keys are namespaced by a prefix.

export class LocalStorageBackend {
  constructor(prefix = 'styxchat:') {
    this._p = prefix;
  }
  async get(key) {
    const raw = localStorage.getItem(this._p + key);
    return raw == null ? null : JSON.parse(raw);
  }
  async set(key, value) {
    localStorage.setItem(this._p + key, JSON.stringify(value));
  }
  async delete(key) {
    localStorage.removeItem(this._p + key);
  }
  /** Delete every key this backend owns (its whole prefix). Used by factory reset. */
  async clear() {
    const doomed = [];
    for (let i = 0; i < localStorage.length; i += 1) {
      const k = localStorage.key(i);
      if (k != null && k.startsWith(this._p)) doomed.push(k);
    }
    doomed.forEach((k) => localStorage.removeItem(k));
  }
}
