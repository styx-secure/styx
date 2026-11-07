// styx-js/src/chat/contact-roster.js
// Roster of 1:1 chat contacts with per-contact metadata (alias, unread count,
// last-message preview). Persists a compact index through a KV backend; the
// online/presence flag is runtime-only and never persisted.

import { EventEmitter } from '../utils.js';
import { isPlainObject, isValidMessageTs, ownDataProperty } from './inbound-payload.js';

const INDEX_KEY = 'styx:contacts';

/**
 * A persisted contact record with every field of the wrong type replaced by its
 * empty value, or null when the record is not an object at all. Other own data
 * fields are kept as they are; pubkey always comes from the index key.
 * @param {string} pubkey the index key
 * @param {unknown} raw
 * @returns {object|null}
 */
function normalizeContactRecord(pubkey, raw) {
  if (!isPlainObject(raw)) return null;
  const record = {};
  for (const key of Object.keys(raw)) {
    const field = ownDataProperty(raw, key);
    if (field !== undefined) {
      Object.defineProperty(record, key, { value: field, enumerable: true, writable: true, configurable: true });
    }
  }
  const alias = ownDataProperty(raw, 'alias');
  const unread = ownDataProperty(raw, 'unread');
  const lastPreview = ownDataProperty(raw, 'lastPreview');
  const lastTs = ownDataProperty(raw, 'lastTs');
  const verifiedAt = ownDataProperty(raw, 'verifiedAt');
  const verified = ownDataProperty(raw, 'verified') === true;
  delete record.online; // presence is runtime-only, never persisted
  return Object.assign(record, {
    pubkey,
    alias: typeof alias === 'string' ? alias : '',
    unread: Number.isSafeInteger(unread) && unread >= 0 ? unread : 0,
    lastPreview: typeof lastPreview === 'string' ? lastPreview : null,
    lastTs: isValidMessageTs(lastTs) ? lastTs : null,
    verified,
    verifiedAt: verified && isValidMessageTs(verifiedAt) ? verifiedAt : null,
  });
}

/**
 * @typedef {object} Contact
 * @property {string} pubkey
 * @property {string} alias
 * @property {boolean} online
 * @property {number} unread
 * @property {string|null} lastPreview
 * @property {number|null} lastTs
 * @property {boolean} verified safety number compared out-of-band
 * @property {number|null} verifiedAt when it was compared
 */

/**
 * Manages the set of chat contacts and their metadata.
 */
export class ContactRoster {
  /**
   * @param {object} options
   * @param {{get: Function, set: Function, delete: Function}} options.backend
   */
  constructor({ backend }) {
    if (!backend) throw new Error('ContactRoster requires a backend');
    this._backend = backend;
    /** @type {Map<string, object>} persisted fields per pubkey */
    this._contacts = new Map();
    /** @type {Set<string>} runtime online pubkeys */
    this._online = new Set();
    this._emitter = new EventEmitter();
    this._loaded = false;
  }

  /**
   * Load the persisted index into memory. Must be called before use.
   * @returns {Promise<void>}
   */
  async load() {
    const index = (await this._backend.get(INDEX_KEY)) || {};
    // A record written before inbound validation existed may carry a lastTs,
    // preview or counter of the wrong type (for example an object as lastTs),
    // which would make sorting and rendering throw at every start. Such fields
    // are neutralised here; the cleaned index is written back at the next save.
    this._contacts = new Map();
    if (isPlainObject(index)) {
      for (const pubkey of Object.keys(index)) {
        const record = normalizeContactRecord(pubkey, ownDataProperty(index, pubkey));
        if (record) this._contacts.set(pubkey, record);
      }
    }
    this._loaded = true;
  }

  /**
   * Subscribe to roster changes. Callback receives the full contact list.
   * @param {(contacts: Contact[]) => void} callback
   * @returns {() => void} unsubscribe
   */
  onChanged(callback) {
    return this._emitter.on('changed', callback);
  }

  /**
   * Add a contact. Idempotent on pubkey: an existing contact keeps its
   * metadata but its alias is updated.
   * @param {object} options
   * @param {string} options.pubkey
   * @param {string} options.alias
   * @returns {Promise<Contact>}
   */
  async add({ pubkey, alias }) {
    this._assertLoaded();
    const existing = this._contacts.get(pubkey);
    const record = {
      pubkey,
      alias,
      unread: existing?.unread ?? 0,
      lastPreview: existing?.lastPreview ?? null,
      lastTs: existing?.lastTs ?? null,
      verified: existing?.verified ?? false,
      verifiedAt: existing?.verifiedAt ?? null,
    };
    this._contacts.set(pubkey, record);
    await this._persist();
    return this._decorate(record);
  }

  /**
   * @param {string} pubkey
   * @returns {Promise<Contact|null>}
   */
  async get(pubkey) {
    this._assertLoaded();
    const record = this._contacts.get(pubkey);
    return record ? this._decorate(record) : null;
  }

  /**
   * All contacts, most-recently-active first (contacts with no activity last).
   * @returns {Promise<Contact[]>}
   */
  async list() {
    this._assertLoaded();
    return [...this._contacts.values()]
      .map((r) => this._decorate(r))
      .sort((a, b) => (b.lastTs ?? -1) - (a.lastTs ?? -1));
  }

  /**
   * @param {string} pubkey
   * @returns {Promise<void>}
   */
  async remove(pubkey) {
    this._assertLoaded();
    this._contacts.delete(pubkey);
    this._online.delete(pubkey);
    await this._persist();
  }

  /**
   * Merge a partial patch into a contact's persisted fields.
   * @param {string} pubkey
   * @param {Partial<{alias:string, unread:number, lastPreview:string, lastTs:number}>} patch
   * @returns {Promise<Contact>}
   */
  async update(pubkey, patch) {
    const record = this._require(pubkey);
    Object.assign(record, patch);
    await this._persist();
    return this._decorate(record);
  }

  /**
   * Record a newly-seen message as the contact's last activity.
   * @param {string} pubkey
   * @param {object} options
   * @param {string} options.preview
   * @param {number} options.ts
   * @param {boolean} [options.incrementUnread=false]
   * @returns {Promise<Contact>}
   */
  async touch(pubkey, { preview, ts, incrementUnread = false }) {
    const record = this._require(pubkey);
    if (!isValidMessageTs(ts)) throw new TypeError('ContactRoster.touch: ts must be a valid timestamp');
    record.lastPreview = typeof preview === 'string' ? preview : null;
    record.lastTs = ts;
    if (incrementUnread) record.unread += 1;
    await this._persist();
    return this._decorate(record);
  }

  /**
   * Reset the unread counter for a contact.
   * @param {string} pubkey
   * @returns {Promise<Contact>}
   */
  async clearUnread(pubkey) {
    const record = this._require(pubkey);
    record.unread = 0;
    await this._persist();
    return this._decorate(record);
  }

  /**
   * Record whether this contact's safety number has been compared out-of-band.
   * @param {string} pubkey
   * @param {boolean} verified
   * @returns {Promise<Contact>}
   */
  async setVerified(pubkey, verified) {
    const record = this._require(pubkey);
    record.verified = !!verified;
    record.verifiedAt = record.verified ? Date.now() : null;
    await this._persist();
    return this._decorate(record);
  }

  /**
   * Set the runtime presence flag (not persisted).
   * @param {string} pubkey
   * @param {boolean} online
   * @returns {Promise<void>}
   */
  async setOnline(pubkey, online) {
    this._assertLoaded();
    if (!this._contacts.has(pubkey)) return;
    if (online) this._online.add(pubkey);
    else this._online.delete(pubkey);
    await this._emitChanged();
  }

  /** @private */
  _decorate(record) {
    return { ...record, online: this._online.has(record.pubkey) };
  }

  /** @private */
  _require(pubkey) {
    this._assertLoaded();
    const record = this._contacts.get(pubkey);
    if (!record) throw new Error(`Unknown contact: ${pubkey}`);
    return record;
  }

  /** @private */
  async _persist() {
    const index = Object.fromEntries(this._contacts);
    await this._backend.set(INDEX_KEY, index);
    await this._emitChanged();
  }

  /** @private */
  async _emitChanged() {
    this._emitter.emit('changed', await this.list());
  }

  /** @private */
  _assertLoaded() {
    if (!this._loaded) throw new Error('ContactRoster: call load() first');
  }
}
