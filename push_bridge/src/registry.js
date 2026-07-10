// registry.js — the bridge's only persistent state: a map pubkey → [subscription].
// No messages, no keys — just Web Push routing. Persisted as JSON so it survives
// a restart. Subscriptions are keyed by their endpoint (dedupe).
import { readFile, writeFile } from 'node:fs/promises';

export class Registry {
  constructor({ filePath }) {
    this._filePath = filePath;
    this._map = new Map(); // pubkey → Map(endpoint → subscription)
  }

  async load() {
    try {
      const raw = JSON.parse(await readFile(this._filePath, 'utf8'));
      this._map = new Map(
        Object.entries(raw).map(([pk, subs]) => [pk, new Map(subs.map((s) => [s.endpoint, s]))]),
      );
    } catch (e) {
      if (e.code !== 'ENOENT') throw e; // fresh start if the file doesn't exist yet
    }
  }

  async _save() {
    const obj = {};
    for (const [pk, subs] of this._map) obj[pk] = [...subs.values()];
    await writeFile(this._filePath, JSON.stringify(obj), 'utf8');
  }

  /** @returns {boolean} whether the set changed. */
  async add(pubkey, subscription) {
    const subs = this._map.get(pubkey) || new Map();
    if (subs.has(subscription.endpoint)) return false;
    subs.set(subscription.endpoint, subscription);
    this._map.set(pubkey, subs);
    await this._save();
    return true;
  }

  /** @returns {boolean} whether something was removed. */
  async remove(pubkey, endpoint) {
    const subs = this._map.get(pubkey);
    if (!subs || !subs.delete(endpoint)) return false;
    if (subs.size === 0) this._map.delete(pubkey);
    await this._save();
    return true;
  }

  get(pubkey) { return [...(this._map.get(pubkey)?.values() || [])]; }
  pubkeys() { return [...this._map.keys()]; }
}
