// styx-js/src/storage/indexeddb-store.js
// IndexedDB-backed persistent storage with encryption at rest

import { LedgerStore, PeerStore, OutboxStore, SecureKeyStore } from './store-interface.js';
import { VectorClock } from '../ledger/vector-clock.js';
import { HybridLogicalClock } from '../ledger/hlc.js';
import { LedgerEvent } from '../ledger/event.js';

const DB_NAME = 'styx-ledger';
const DB_VERSION = 1;

const STORES = {
  EVENTS: 'events',
  PEERS: 'peers',
  OUTBOX: 'outbox',
  KEYS: 'keys',
  META: 'meta',
};

/**
 * Open (or create) the Styx IndexedDB database.
 * @param {string} [dbName] - Custom DB name (for multi-instance)
 * @returns {Promise<IDBDatabase>}
 */
function openDB(dbName = DB_NAME) {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(dbName, DB_VERSION);

    request.onupgradeneeded = (e) => {
      const db = e.target.result;

      if (!db.objectStoreNames.contains(STORES.EVENTS)) {
        const evStore = db.createObjectStore(STORES.EVENTS, { keyPath: 'eventId' });
        evStore.createIndex('by_hlc', 'hlcCanonical', { unique: false });
        evStore.createIndex('by_type', 'eventType', { unique: false });
      }
      if (!db.objectStoreNames.contains(STORES.PEERS)) {
        db.createObjectStore(STORES.PEERS, { keyPath: 'publicKey' });
      }
      if (!db.objectStoreNames.contains(STORES.OUTBOX)) {
        const obStore = db.createObjectStore(STORES.OUTBOX, { keyPath: 'eventId' });
        obStore.createIndex('by_status', 'status', { unique: false });
      }
      if (!db.objectStoreNames.contains(STORES.KEYS)) {
        db.createObjectStore(STORES.KEYS, { keyPath: 'id' });
      }
      if (!db.objectStoreNames.contains(STORES.META)) {
        db.createObjectStore(STORES.META, { keyPath: 'key' });
      }
    };

    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

/**
 * Run a transaction and return a promise.
 */
function txn(db, storeNames, mode, fn) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeNames, mode);
    const result = fn(tx);
    tx.oncomplete = () => resolve(result);
    tx.onerror = () => reject(tx.error);
  });
}

function idbGet(store, key) {
  return new Promise((resolve, reject) => {
    const req = store.get(key);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function idbGetAll(store) {
  return new Promise((resolve, reject) => {
    const req = store.getAll();
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function idbGetAllFromIndex(store, indexName, query) {
  return new Promise((resolve, reject) => {
    const idx = store.index(indexName);
    const req = query !== undefined ? idx.getAll(query) : idx.getAll();
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function idbCount(store) {
  return new Promise((resolve, reject) => {
    const req = store.count();
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

// --- Serialization helpers ---

function serializeEvent(event) {
  return {
    eventId: event.eventId,
    eventType: event.eventType,
    payload: event.payload ? Array.from(event.payload) : null,
    previousHash: event.previousHash,
    eventHash: event.eventHash,
    hlcCanonical: event.hlc.toCanonical(),
    vectorClock: event.vectorClock.toJSON(),
    senderPubkey: event.senderPubkey,
    signature: Array.from(event.signature),
    createdAt: event.createdAt.toISOString(),
    isPruned: event.isPruned,
  };
}

function deserializeEvent(row) {
  return new LedgerEvent({
    eventId: row.eventId,
    eventType: row.eventType,
    payload: row.payload ? new Uint8Array(row.payload) : null,
    previousHash: row.previousHash,
    eventHash: row.eventHash,
    hlc: HybridLogicalClock.fromCanonical(row.hlcCanonical),
    vectorClock: VectorClock.fromJSON(row.vectorClock),
    senderPubkey: row.senderPubkey,
    signature: new Uint8Array(row.signature),
    createdAt: new Date(row.createdAt),
    isPruned: row.isPruned || false,
  });
}

// --- IndexedDB Ledger Store ---

/**
 * IndexedDB-backed ledger store for persistent mode.
 */
export class IndexedDBLedgerStore extends LedgerStore {
  /**
   * @param {string} [dbName] - Custom DB name
   */
  constructor(dbName) {
    super();
    this._dbName = dbName || DB_NAME;
    this._db = null;
  }

  async _ensureDB() {
    if (!this._db) this._db = await openDB(this._dbName);
    return this._db;
  }

  async appendEvent(event) {
    const db = await this._ensureDB();
    const serialized = serializeEvent(event);

    await txn(db, [STORES.EVENTS, STORES.META], 'readwrite', (tx) => {
      tx.objectStore(STORES.EVENTS).put(serialized);

      // Update vector clock in meta
      const metaStore = tx.objectStore(STORES.META);
      const vcJson = event.vectorClock.toJSON();
      metaStore.put({ key: 'vectorClock', value: vcJson });
    });
  }

  async getAllEvents() {
    const db = await this._ensureDB();
    const rows = await new Promise((resolve, reject) => {
      const tx = db.transaction(STORES.EVENTS, 'readonly');
      const store = tx.objectStore(STORES.EVENTS);
      const idx = store.index('by_hlc');
      const req = idx.getAll();
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    return rows.map(deserializeEvent);
  }

  async getLatestEvent() {
    const events = await this.getAllEvents();
    return events.length > 0 ? events[events.length - 1] : null;
  }

  async getEventById(eventId) {
    const db = await this._ensureDB();
    const row = await new Promise((resolve, reject) => {
      const tx = db.transaction(STORES.EVENTS, 'readonly');
      const req = tx.objectStore(STORES.EVENTS).get(eventId);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    return row ? deserializeEvent(row) : null;
  }

  async getEventsByType(eventType) {
    const db = await this._ensureDB();
    const rows = await new Promise((resolve, reject) => {
      const tx = db.transaction(STORES.EVENTS, 'readonly');
      const store = tx.objectStore(STORES.EVENTS);
      const req = store.index('by_type').getAll(eventType);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    return rows.map(deserializeEvent);
  }

  async getCurrentVectorClock() {
    const db = await this._ensureDB();
    const row = await new Promise((resolve, reject) => {
      const tx = db.transaction(STORES.META, 'readonly');
      const req = tx.objectStore(STORES.META).get('vectorClock');
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    return row ? VectorClock.fromJSON(row.value) : VectorClock.zero();
  }

  async pruneEvent(eventId) {
    const db = await this._ensureDB();
    const row = await new Promise((resolve, reject) => {
      const tx = db.transaction(STORES.EVENTS, 'readonly');
      const req = tx.objectStore(STORES.EVENTS).get(eventId);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });

    if (row) {
      row.payload = null;
      row.isPruned = true;
      await new Promise((resolve, reject) => {
        const tx = db.transaction(STORES.EVENTS, 'readwrite');
        tx.objectStore(STORES.EVENTS).put(row);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      });
    }
  }

  async clear() {
    const db = await this._ensureDB();
    await new Promise((resolve, reject) => {
      const tx = db.transaction(
        [STORES.EVENTS, STORES.META],
        'readwrite'
      );
      tx.objectStore(STORES.EVENTS).clear();
      tx.objectStore(STORES.META).clear();
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  async count() {
    const db = await this._ensureDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORES.EVENTS, 'readonly');
      const req = tx.objectStore(STORES.EVENTS).count();
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  /** Close the database connection */
  close() {
    if (this._db) {
      this._db.close();
      this._db = null;
    }
  }
}

// --- IndexedDB Peer Store ---

export class IndexedDBPeerStore extends PeerStore {
  constructor(dbName) {
    super();
    this._dbName = dbName || DB_NAME;
    this._db = null;
  }

  async _ensureDB() {
    if (!this._db) this._db = await openDB(this._dbName);
    return this._db;
  }

  async addPeer({ pubkeyHex, alias, pairedAt }) {
    const db = await this._ensureDB();
    await new Promise((resolve, reject) => {
      const tx = db.transaction(STORES.PEERS, 'readwrite');
      tx.objectStore(STORES.PEERS).put({
        publicKey: pubkeyHex,
        alias,
        pairedAt: pairedAt.toISOString(),
        isActive: true,
        rekeyHistory: [],
      });
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  async getPeerByPubkey(pubkeyHex) {
    const db = await this._ensureDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORES.PEERS, 'readonly');
      const req = tx.objectStore(STORES.PEERS).get(pubkeyHex);
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => reject(req.error);
    });
  }

  async getActivePeers() {
    const db = await this._ensureDB();
    const all = await new Promise((resolve, reject) => {
      const tx = db.transaction(STORES.PEERS, 'readonly');
      const req = tx.objectStore(STORES.PEERS).getAll();
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    return all.filter((p) => p.isActive);
  }

  async deactivatePeer(pubkeyHex) {
    const db = await this._ensureDB();
    const peer = await this.getPeerByPubkey(pubkeyHex);
    if (peer) {
      peer.isActive = false;
      await new Promise((resolve, reject) => {
        const tx = db.transaction(STORES.PEERS, 'readwrite');
        tx.objectStore(STORES.PEERS).put(peer);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      });
    }
  }

  async updatePeerKey({ oldPubkeyHex, newPubkeyHex }) {
    const db = await this._ensureDB();
    const peer = await this.getPeerByPubkey(oldPubkeyHex);
    if (peer) {
      await new Promise((resolve, reject) => {
        const tx = db.transaction(STORES.PEERS, 'readwrite');
        const store = tx.objectStore(STORES.PEERS);
        store.delete(oldPubkeyHex);
        peer.publicKey = newPubkeyHex;
        store.put(peer);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      });
    }
  }

  async addRekeyEntry({ oldKeyHex, newKeyHex, timestamp }) {
    // Store as a meta entry alongside the peer
    const peer = await this.getPeerByPubkey(newKeyHex);
    if (peer) {
      peer.rekeyHistory = peer.rekeyHistory || [];
      peer.rekeyHistory.push({ oldKey: oldKeyHex, newKey: newKeyHex, timestamp: timestamp.toISOString() });
      const db = await this._ensureDB();
      await new Promise((resolve, reject) => {
        const tx = db.transaction(STORES.PEERS, 'readwrite');
        tx.objectStore(STORES.PEERS).put(peer);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      });
    }
  }

  async getRekeyHistory(currentKeyHex) {
    const peer = await this.getPeerByPubkey(currentKeyHex);
    return peer?.rekeyHistory || [];
  }
}

// --- IndexedDB Key Store ---

export class IndexedDBKeyStore extends SecureKeyStore {
  constructor(dbName) {
    super();
    this._dbName = dbName || DB_NAME;
    this._db = null;
  }

  async _ensureDB() {
    if (!this._db) this._db = await openDB(this._dbName);
    return this._db;
  }

  async storeKeyPair({ keyId, keyPair }) {
    const db = await this._ensureDB();
    // Store serialized key material — in production, encrypt with Web Crypto
    const data = {
      id: `kp:${keyId}`,
      publicKey: Array.from(keyPair.publicKey.bytes),
      privateKey: Array.from(keyPair.privateKey.bytes),
    };
    await new Promise((resolve, reject) => {
      const tx = db.transaction(STORES.KEYS, 'readwrite');
      tx.objectStore(STORES.KEYS).put(data);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  async retrieveKeyPair(keyId) {
    const db = await this._ensureDB();
    const row = await new Promise((resolve, reject) => {
      const tx = db.transaction(STORES.KEYS, 'readonly');
      const req = tx.objectStore(STORES.KEYS).get(`kp:${keyId}`);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    if (!row) return null;

    const { StyxPublicKey, StyxPrivateKey, StyxKeyPair } = await import('../crypto/identity.js');
    return new StyxKeyPair(
      new StyxPublicKey(new Uint8Array(row.publicKey)),
      new StyxPrivateKey(new Uint8Array(row.privateKey))
    );
  }

  async deleteKeyPair(keyId) {
    const db = await this._ensureDB();
    await new Promise((resolve, reject) => {
      const tx = db.transaction(STORES.KEYS, 'readwrite');
      tx.objectStore(STORES.KEYS).delete(`kp:${keyId}`);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  async hasKeyPair(keyId) {
    return (await this.retrieveKeyPair(keyId)) !== null;
  }

  async storeSecret({ key, value }) {
    const db = await this._ensureDB();
    await new Promise((resolve, reject) => {
      const tx = db.transaction(STORES.KEYS, 'readwrite');
      tx.objectStore(STORES.KEYS).put({ id: `sec:${key}`, value: Array.from(value) });
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  async retrieveSecret(key) {
    const db = await this._ensureDB();
    const row = await new Promise((resolve, reject) => {
      const tx = db.transaction(STORES.KEYS, 'readonly');
      const req = tx.objectStore(STORES.KEYS).get(`sec:${key}`);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    return row ? new Uint8Array(row.value) : null;
  }

  async deleteSecret(key) {
    const db = await this._ensureDB();
    await new Promise((resolve, reject) => {
      const tx = db.transaction(STORES.KEYS, 'readwrite');
      tx.objectStore(STORES.KEYS).delete(`sec:${key}`);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  async deleteAll() {
    const db = await this._ensureDB();
    await new Promise((resolve, reject) => {
      const tx = db.transaction(STORES.KEYS, 'readwrite');
      tx.objectStore(STORES.KEYS).clear();
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }
}
